import { AhoCorasick } from './matchers/ahoCorasick';
import { CidrTrie } from './matchers/cidrTrie';
import { lowerExpr, collectAtomIds, evalExpr, AtomSpec } from './compile';
import { parsePattern, UnsupportedPattern } from './patternParser';
import { parseCidr, parseV4, parseV6 } from './ipaddr';
import { Atom, CompiledIndicator, SkippedIndicator, StixIndicator } from './types';

const V4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
// permissive candidate extractor; parseV6 validates strictly (rejects MACs, times, ...)
const V6_RE = /(?<![0-9a-fA-F:])[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,}(?![0-9a-fA-F:])/g;
const HASH_RE = /\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{128}\b/g;

const DOMAIN_PREV_OK = /[^a-z0-9-]/;   // '.' allowed: subdomains of an indicator domain match
const DOMAIN_NEXT_OK = /[^a-z0-9.-]/;
const URL_PREV_OK = /[^a-z0-9.-]/;
const URL_NEXT_OK = /[^a-z0-9\-._~:/?#[\]@!$&'()*+,;=%]/;

export interface LineMatch {
  indicator: CompiledIndicator;
  matchedAtoms: Atom[];
}

export class MatchEngine {
  readonly atoms: Atom[] = [];
  private atomIds = new Map<string, number>();
  readonly indicators: CompiledIndicator[] = [];
  readonly skipped: SkippedIndicator[] = [];

  private ipExact4 = new Map<number, number[]>();
  private ipExact6 = new Map<bigint, number[]>();
  private trie4 = new CidrTrie(32);
  private trie6 = new CidrTrie(128);
  private ac = new AhoCorasick();
  private hashSets = new Map<number, Map<string, number[]>>();
  private atomToIndicators: number[][] = [];
  private finalized = false;

  private internAtom(spec: AtomSpec): number {
    const key = `${spec.kind}:${spec.value}`;
    const existing = this.atomIds.get(key);
    if (existing !== undefined) return existing;
    const id = this.atoms.length;
    this.atoms.push({ id, kind: spec.kind, value: spec.value });
    this.atomIds.set(key, id);
    return id;
  }

  addIndicator(ind: StixIndicator): void {
    try {
      const raw = parsePattern(ind.pattern!);
      const expr = lowerExpr(raw, (s) => this.internAtom(s));
      const atomIds = [...new Set(collectAtomIds(expr))];
      this.indicators.push({
        id: ind.id,
        name: typeof ind.name === 'string' ? ind.name : undefined,
        confidence: typeof ind.confidence === 'number' ? ind.confidence : null,
        expr,
        atomIds,
      });
    } catch (e) {
      const reason = e instanceof UnsupportedPattern ? e.message : `parse error: ${(e as Error).message}`;
      this.skipped.push({ id: ind.id ?? '(no id)', reason, pattern: ind.pattern });
    }
  }

  finalize(): void {
    for (const atom of this.atoms) {
      switch (atom.kind) {
        case 'ip': {
          if (atom.value.includes(':')) {
            const key = parseV6(atom.value)!;
            push(this.ipExact6, key, atom.id);
          } else {
            const key = Number(parseV4(atom.value)!);
            push(this.ipExact4, key, atom.id);
          }
          break;
        }
        case 'cidr': {
          const c = parseCidr(atom.value)!;
          (c.bits === 32 ? this.trie4 : this.trie6).insert(c.key, c.prefixLen, atom.id);
          break;
        }
        case 'domain':
        case 'url':
          this.ac.add(atom.value, atom.id, atom.kind);
          break;
        case 'hash': {
          let set = this.hashSets.get(atom.value.length);
          if (!set) { set = new Map(); this.hashSets.set(atom.value.length, set); }
          push(set, atom.value, atom.id);
          break;
        }
      }
    }
    this.ac.build();
    this.atomToIndicators = Array.from({ length: this.atoms.length }, () => []);
    this.indicators.forEach((ind, idx) => {
      for (const a of ind.atomIds) this.atomToIndicators[a].push(idx);
    });
    this.finalized = true;
  }

  /** Match one log line; returns every indicator whose expression is satisfied. */
  matchLine(line: string): LineMatch[] {
    if (!this.finalized) throw new Error('engine not finalized');
    const matched = new Set<number>();

    V4_RE.lastIndex = 0;
    for (const m of line.matchAll(V4_RE)) {
      const key = parseV4(m[0]);
      if (key === null) continue;
      const exact = this.ipExact4.get(Number(key));
      if (exact) for (const id of exact) matched.add(id);
      this.trie4.lookupInto(key, matched);
    }

    if (line.includes(':')) {
      for (const m of line.matchAll(V6_RE)) {
        const key = parseV6(m[0]);
        if (key === null) continue;
        const exact = this.ipExact6.get(key);
        if (exact) for (const id of exact) matched.add(id);
        this.trie6.lookupInto(key, matched);
      }
    }

    if (this.ac.patterns.length > 0) {
      const lower = line.toLowerCase();
      this.ac.scan(lower, (patIdx, end) => {
        const pat = this.ac.patterns[patIdx];
        const start = end - pat.text.length;
        const prev = start > 0 ? lower[start - 1] : '';
        const next = end < lower.length ? lower[end] : '';
        if (pat.kind === 'domain') {
          if (prev !== '' && !DOMAIN_PREV_OK.test(prev)) return;
          if (next !== '' && !DOMAIN_NEXT_OK.test(next)) return;
        } else {
          if (prev !== '' && !URL_PREV_OK.test(prev)) return;
          if (next !== '' && !URL_NEXT_OK.test(next)) return;
        }
        matched.add(pat.atomId);
      });
    }

    if (this.hashSets.size > 0) {
      for (const m of line.matchAll(HASH_RE)) {
        const set = this.hashSets.get(m[0].length);
        if (!set) continue;
        const ids = set.get(m[0].toLowerCase());
        if (ids) for (const id of ids) matched.add(id);
      }
    }

    if (matched.size === 0) return [];
    const hits: LineMatch[] = [];
    const seen = new Set<number>();
    for (const atomId of matched) {
      for (const indIdx of this.atomToIndicators[atomId]) {
        if (seen.has(indIdx)) continue;
        seen.add(indIdx);
        const ind = this.indicators[indIdx];
        if (!evalExpr(ind.expr, matched)) continue;
        hits.push({
          indicator: ind,
          matchedAtoms: ind.atomIds.filter((a) => matched.has(a)).map((a) => this.atoms[a]),
        });
      }
    }
    return hits;
  }

  get stats() {
    return {
      indicators: this.indicators.length,
      skipped: this.skipped.length,
      atoms: this.atoms.length,
      acNodes: this.ac.size,
      trie4Nodes: this.trie4.nodeCount,
      trie6Nodes: this.trie6.nodeCount,
    };
  }
}

function push<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const arr = map.get(key);
  if (arr) arr.push(value);
  else map.set(key, [value]);
}
