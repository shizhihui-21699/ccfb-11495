/**
 * Per-line matching.
 *
 * `LineMatcher` owns all the reusable buffers for one scanning process. For
 * each line it:
 *
 *   1. extracts observables (single byte pass, no strings),
 *   2. asks each index for the atom ids that line satisfies,
 *   3. ORs those atom ids into a bitset,
 *   4. evaluates every indicator program that references any satisfied atom.
 *
 * Step 4 is driven by an inverted atom->program postings list, so a line that
 * matches one atom costs O(programs touching that atom), not O(all programs).
 */

import { Extractor } from "../extract/extractor.ts";
import { HostBuffer, type DomainMatcher } from "../match/domain.ts";
import type { ByteMap } from "../index-file/byte-map.ts";
import type { PrefixTrie } from "../match/trie.ts";
import type { AtomSpec, Expr, HashAlgorithm, ObservableKind } from "../stix/compile.ts";
import { HASH_HEX_LENGTH } from "../stix/compile.ts";

/** Bit i of the bitset belongs to word `i >> 5`, bit `i & 31`. */
export class Bitset {
  readonly words: Uint32Array;

  constructor(size: number) {
    this.words = new Uint32Array((size + 31) >> 5);
  }

  clear(): void {
    this.words.fill(0);
  }

  set(i: number): void {
    this.words[i >> 5] = ((this.words[i >> 5] as number) | (1 << (i & 31))) >>> 0;
  }

  has(i: number): boolean {
    return (((this.words[i >> 5] as number) >>> (i & 31)) & 1) === 1;
  }

  hasAny(): boolean {
    for (let i = 0; i < this.words.length; i++) if (this.words[i] !== 0) return true;
    return false;
  }
}

/** Everything a line satisfies, plus the atom ids in ascending order. */
export interface LineMatches {
  readonly bits: Bitset;
  /** Satisfied atom ids, ascending. */
  readonly atomIds: Int32Array;
  readonly atomCount: number;
}

interface RegexCompiled {
  readonly atomId: number;
  readonly re: RegExp;
}

function evaluate(expr: Expr, bits: Bitset): boolean {
  switch (expr.kind) {
    case "atom":
      return bits.has(expr.atomId);
    case "and": {
      for (let i = 0; i < expr.children.length; i++) {
        if (!evaluate(expr.children[i] as Expr, bits)) return false;
      }
      return true;
    }
    case "or": {
      for (let i = 0; i < expr.children.length; i++) {
        if (evaluate(expr.children[i] as Expr, bits)) return true;
      }
      return false;
    }
  }
}

export interface IndexPorts {
  readonly v4: PrefixTrie;
  readonly v6: PrefixTrie;
  readonly domains: DomainMatcher | null;
  readonly urlMap: ByteMap | null;
  readonly emailMap: ByteMap | null;
  readonly hashMaps: ReadonlyMap<HashAlgorithm, ByteMap>;
  readonly regexes: ReadonlyMap<ObservableKind, readonly RegexCompiled[]>;
  readonly existsAtoms: ReadonlyMap<ObservableKind, readonly number[]>;
  readonly atomSpecs: readonly AtomSpec[];
}

export class LineMatcher {
  readonly #index: IndexPorts;
  readonly #extractor = new Extractor(new Uint8Array(0));
  readonly #hosts = new HostBuffer();
  readonly #bits: Bitset;
  readonly #matchedIds: Int32Array;
  readonly #hexBuf = new Uint8Array(HASH_HEX_LENGTH["SHA-512"] >> 1);
  readonly #v6Scratch = new Uint32Array(4);
  /** Dedupe guard for trie hits: a line can contain the same IP repeatedly. */
  readonly #seen: Uint8Array;


  constructor(index: IndexPorts) {
    this.#index = index;
    this.#bits = new Bitset(index.atomSpecs.length);
    this.#matchedIds = new Int32Array(index.atomSpecs.length);
    this.#seen = new Uint8Array(index.atomSpecs.length);
  }

  get bits(): Bitset {
    return this.#bits;
  }

  /** Match one line. The returned object is reused across calls. */
  match(line: Uint8Array<ArrayBufferLike>): LineMatches {
    const bits = this.#bits;
    bits.clear();
    this.#seen.fill(0);
    const ids = this.#matchedIds;
    let count = 0;

    const addAtom = (atomId: number): void => {
      if (this.#seen[atomId] !== 0) return;
      this.#seen[atomId] = 1;
      bits.set(atomId);
      ids[count++] = atomId;
    };

    const ex = this.#extractor;
    ex.reset(line);
    ex.run();
    const index = this.#index;

    // --- IPv4 / IPv6 ------------------------------------------------------
    for (let i = 0; i < ex.v4count; i++) {
      const ip = ex.v4Value(i);
      index.v4.lookupV4(ip, addAtom);
    }
    for (let i = 0; i < ex.v6count; i++) {
      ex.v6Words(i, this.#v6Scratch);
      index.v6.lookupV6(this.#v6Scratch, addAtom);
    }

    // --- Domains ----------------------------------------------------------
    if (index.domains !== null && ex.domainCount > 0) {
      const hosts = this.#hosts;
      hosts.reset();
      for (let i = 0; i < ex.domainCount; i++) {
        hosts.addHost(line, ex.domainStart(i), ex.domainEnd(i));
      }
      index.domains.scanHosts(hosts.buffer, hosts.starts, (atomId) => addAtom(atomId));
    }

    // --- URLs -------------------------------------------------------------
    if (index.urlMap !== null) {
      for (let i = 0; i < ex.urlCount; i++) {
        const norm = ex.urlNormalised(i);
        const atomId = index.urlMap.lookup(norm, 0, norm.length);
        if (atomId >= 0) addAtom(atomId);
      }
    }

    // --- Emails -----------------------------------------------------------
    if (index.emailMap !== null) {
      for (let i = 0; i < ex.emailCount; i++) {
        const atomId = index.emailMap.lookup(line, ex.emailStart(i), ex.emailEnd(i));
        if (atomId >= 0) addAtom(atomId);
      }
    }

    // --- Hashes -----------------------------------------------------------
    if (index.hashMaps.size > 0) {
      for (let i = 0; i < ex.hashCount; i++) {
        const algo = ex.hashAlgorithm(i);
        if (algo === null) continue;
        const map = index.hashMaps.get(algo);
        if (map === undefined) continue;
        const n = ex.hexDecode(ex.hashStart(i), ex.hashEnd(i), this.#hexBuf);
        const atomId = map.lookup(this.#hexBuf, 0, n);
        if (atomId >= 0) addAtom(atomId);
      }
    }

    // --- Regexes ----------------------------------------------------------
    if (index.regexes.size > 0) {
      this.#matchRegexes(ex, addAtom);
    }

    // --- Existentials -----------------------------------------------------
    if (index.existsAtoms.size > 0) {
      for (const [kind, atomIds] of index.existsAtoms) {
        if (this.#kindPresent(ex, kind)) {
          for (const atomId of atomIds) addAtom(atomId);
        }
      }
    }

    return { bits, atomIds: ids, atomCount: count };
  }

  #matchRegexes(ex: Extractor, addAtom: (atomId: number) => void): void {
    const regexes = this.#index.regexes;
    for (const [kind, entries] of regexes) {
      switch (kind) {
        case "ipv4": {
          for (let i = 0; i < ex.v4count; i++) {
            const v = ex.v4Value(i);
            const s = `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`;
            for (const e of entries) if (e.re.test(s)) addAtom(e.atomId);
          }
          break;
        }
        case "ipv6": {
          for (let i = 0; i < ex.v6count; i++) {
            const s = ex.formatV6(i);
            for (const e of entries) if (e.re.test(s)) addAtom(e.atomId);
          }
          break;
        }
        case "domain": {
          for (let i = 0; i < ex.domainCount; i++) {
            const s = ex.spanLower(ex.domainStart(i), ex.domainEnd(i));
            for (const e of entries) if (e.re.test(s)) addAtom(e.atomId);
          }
          break;
        }
        case "url": {
          for (let i = 0; i < ex.urlCount; i++) {
            const s = Buffer.from(ex.urlNormalised(i)).toString("latin1");
            for (const e of entries) if (e.re.test(s)) addAtom(e.atomId);
          }
          break;
        }
        case "email": {
          for (let i = 0; i < ex.emailCount; i++) {
            const s = ex.spanLower(ex.emailStart(i), ex.emailEnd(i));
            for (const e of entries) if (e.re.test(s)) addAtom(e.atomId);
          }
          break;
        }
        case "hash": {
          for (let i = 0; i < ex.hashCount; i++) {
            const s = ex.spanLower(ex.hashStart(i), ex.hashEnd(i));
            for (const e of entries) if (e.re.test(s)) addAtom(e.atomId);
          }
          break;
        }
        default:
          break;
      }
    }
  }

  #kindPresent(ex: Extractor, kind: ObservableKind): boolean {
    switch (kind) {
      case "ipv4":
        return ex.v4count > 0;
      case "ipv6":
        return ex.v6count > 0;
      case "domain":
        return ex.domainCount > 0;
      case "url":
        return ex.urlCount > 0;
      case "email":
        return ex.emailCount > 0;
      case "hash":
        return ex.hashCount > 0;
      default:
        return false;
    }
  }
}

/** Evaluate one compiled program against satisfied atom ids. */
export function programMatches(expr: Expr, bits: Bitset): boolean {
  return evaluate(expr, bits);
}

export { evaluate as evaluateExpr };
