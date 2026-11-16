import { parsePattern, RawExpr, UnsupportedPattern } from './patternParser';
import { parseCidr, parseV4, parseV6, isV6Address } from './ipaddr';
import { AtomKind, BoolExpr } from './types';

export interface AtomSpec {
  kind: AtomKind;
  value: string;
}

const HASH_ALGOS: Record<string, number> = {
  md5: 32,
  'sha-1': 40,
  sha1: 40,
  'sha-256': 64,
  sha256: 64,
  'sha-512': 128,
  sha512: 128,
};

function requireEq(op: string, path: string): void {
  if (op !== '=') {
    throw new UnsupportedPattern(`operator '${op}' is not supported on ${path} (only '=')`);
  }
}

function lowerComparison(
  path: string,
  op: string,
  value: string | string[],
  intern: (spec: AtomSpec) => number,
): BoolExpr {
  if (Array.isArray(value)) {
    if (op !== '=' && op !== 'IN') {
      throw new UnsupportedPattern(`operator '${op}' cannot take a list value`);
    }
    const args = value.map((v) => lowerComparison(path, '=', v, intern));
    return args.length === 1 ? args[0] : { op: 'or', args };
  }
  if (op === 'IN') throw new UnsupportedPattern('IN requires a parenthesized list');

  const p = path.toLowerCase();

  if (p === 'ipv4-addr:value' || p === 'ipv6-addr:value') {
    const wantV6 = p.startsWith('ipv6');
    if (op === 'ISSUBSET' || (op === '=' && value.includes('/'))) {
      const cidr = parseCidr(value);
      if (!cidr) throw new UnsupportedPattern(`invalid CIDR '${value}'`);
      if ((cidr.bits === 128) !== wantV6) {
        throw new UnsupportedPattern(`address family mismatch in '${value}' vs ${p}`);
      }
      return { op: 'atom', atomId: intern({ kind: 'cidr', value: cidr.canonical }) };
    }
    requireEq(op, p);
    const key = wantV6 ? parseV6(value) : parseV4(value);
    if (key === null || isV6Address(value) !== wantV6) {
      throw new UnsupportedPattern(`invalid IP address '${value}'`);
    }
    return { op: 'atom', atomId: intern({ kind: 'ip', value: value.toLowerCase() }) };
  }

  if (p === 'domain-name:value') {
    requireEq(op, p);
    const d = value.toLowerCase().replace(/\.$/, '');
    if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(d) || d.includes('..')) {
      throw new UnsupportedPattern(`invalid domain name '${value}'`);
    }
    return { op: 'atom', atomId: intern({ kind: 'domain', value: d }) };
  }

  if (p === 'url:value') {
    requireEq(op, p);
    // URLs are matched case-insensitively (see README for the tradeoff).
    return { op: 'atom', atomId: intern({ kind: 'url', value: value.toLowerCase() }) };
  }

  const hashMatch = /^file:hashes\.([a-z0-9-]+)$/.exec(p);
  if (hashMatch) {
    requireEq(op, p);
    const algo = hashMatch[1];
    const hexLen = HASH_ALGOS[algo];
    if (hexLen === undefined) {
      throw new UnsupportedPattern(`hash algorithm '${algo}' is not supported`);
    }
    const h = value.toLowerCase();
    if (!/^[0-9a-f]+$/.test(h)) {
      throw new UnsupportedPattern(`invalid ${algo} hash '${value}'`);
    }
    if (h.length !== hexLen) {
      throw new UnsupportedPattern(
        `hash length ${h.length} does not match ${algo} (expected ${hexLen} hex chars)`,
      );
    }
    return { op: 'atom', atomId: intern({ kind: 'hash', value: h }) };
  }

  throw new UnsupportedPattern(`object path '${path}' is not supported`);
}

/**
 * Lower a parsed pattern into a boolean expression over interned atoms.
 * Throws UnsupportedPattern for anything outside the supported subset.
 */
export function lowerExpr(raw: RawExpr, intern: (spec: AtomSpec) => number): BoolExpr {
  switch (raw.type) {
    case 'and':
    case 'or':
      return { op: raw.type, args: raw.args.map((a) => lowerExpr(a, intern)) };
    case 'not':
      throw new UnsupportedPattern(
        'NOT is not supported (negation is unsafe with line-granularity matching)',
      );
    case 'cmp':
      return lowerComparison(raw.path, raw.op, raw.value, intern);
  }
}

export function collectAtomIds(expr: BoolExpr, acc: number[] = []): number[] {
  if (expr.op === 'atom') acc.push(expr.atomId);
  else for (const a of expr.args) collectAtomIds(a, acc);
  return acc;
}

export function evalExpr(expr: BoolExpr, matched: ReadonlySet<number>): boolean {
  if (expr.op === 'atom') return matched.has(expr.atomId);
  if (expr.op === 'and') return expr.args.every((a) => evalExpr(a, matched));
  return expr.args.some((a) => evalExpr(a, matched));
}

export { parsePattern };
