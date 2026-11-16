/**
 * Recursive-descent parser for the supported subset of STIX 2.1 patterns.
 *
 * Grammar (AND binds tighter than OR; [...] and (...) group):
 *   pattern    := orExpr
 *   orExpr     := andExpr (OR andExpr)*
 *   andExpr    := unary (AND unary)*
 *   unary      := NOT unary | '[' orExpr ']' | '(' orExpr ')' | comparison
 *   comparison := path op value
 *   path       := ident ((':'|'.') (ident|string))*
 *   op         := '=' '!=' '<' '<=' '>' '>=' IN ISSUBSET ISSUPERSET MATCHES LIKE
 *   value      := string | bare | '(' value (',' value)* ')'
 *
 * Anything outside the supported comparison set is rejected by the compiler
 * (compile.ts) with an UnsupportedPattern error; the whole indicator is then
 * skipped and reported.
 */

export class UnsupportedPattern extends Error {}

type Tok =
  | { t: 'punct'; v: string }
  | { t: 'str'; v: string }
  | { t: 'ident'; v: string };

function tokenize(src: string): Tok[] {
  const toks: Tok[] = [];
  const isIdent = (c: string) => /[A-Za-z0-9_-]/.test(c);
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === "'") {
      let j = i + 1;
      let out = '';
      while (j < src.length) {
        if (src[j] === '\\' && j + 1 < src.length) { out += src[j + 1]; j += 2; continue; }
        if (src[j] === "'") break;
        out += src[j++];
      }
      if (j >= src.length) throw new UnsupportedPattern('unterminated string literal');
      toks.push({ t: 'str', v: out });
      i = j + 1;
      continue;
    }
    if ('[](),.:='.includes(c)) { toks.push({ t: 'punct', v: c }); i++; continue; }
    if (c === '!' && src[i + 1] === '=') { toks.push({ t: 'punct', v: '!=' }); i += 2; continue; }
    if (c === '<' || c === '>') {
      if (src[i + 1] === '=') { toks.push({ t: 'punct', v: c + '=' }); i += 2; }
      else { toks.push({ t: 'punct', v: c }); i++; }
      continue;
    }
    if (isIdent(c)) {
      let j = i;
      while (j < src.length && isIdent(src[j])) j++;
      toks.push({ t: 'ident', v: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new UnsupportedPattern(`unexpected character ${JSON.stringify(c)}`);
  }
  return toks;
}

export type RawExpr =
  | { type: 'and' | 'or'; args: RawExpr[] }
  | { type: 'not'; arg: RawExpr }
  | { type: 'cmp'; path: string; op: string; value: string | string[] };

const CMP_KEYWORDS = new Set(['IN', 'ISSUBSET', 'ISSUPERSET', 'MATCHES', 'LIKE']);

export function parsePattern(src: string): RawExpr {
  const toks = tokenize(src);
  if (toks.length === 0) throw new UnsupportedPattern('empty pattern');
  let pos = 0;
  const peek = () => toks[pos] as Tok | undefined;
  const next = () => toks[pos++] as Tok;
  const isKw = (kw: string) => {
    const t = peek();
    return t !== undefined && t.t === 'ident' && t.v.toUpperCase() === kw;
  };
  const eatKw = (kw: string) => { if (isKw(kw)) { pos++; return true; } return false; };
  const expectPunct = (v: string) => {
    const t = next();
    if (!t || t.t !== 'punct' || t.v !== v) {
      throw new UnsupportedPattern(`expected '${v}', got '${t ? t.v : 'EOF'}'`);
    }
  };

  function parseOr(): RawExpr {
    const args = [parseAnd()];
    while (eatKw('OR')) args.push(parseAnd());
    return args.length === 1 ? args[0] : { type: 'or', args };
  }
  function parseAnd(): RawExpr {
    const args = [parseUnary()];
    while (eatKw('AND')) args.push(parseUnary());
    return args.length === 1 ? args[0] : { type: 'and', args };
  }
  function parseUnary(): RawExpr {
    if (eatKw('NOT')) return { type: 'not', arg: parseUnary() };
    const t = peek();
    if (t && t.t === 'punct' && (t.v === '[' || t.v === '(')) {
      const close = t.v === '[' ? ']' : ')';
      next();
      const e = parseOr();
      expectPunct(close);
      return e;
    }
    return parseComparison();
  }
  function parseComparison(): RawExpr {
    const segs: string[] = [];
    const first = next();
    if (!first || first.t !== 'ident') {
      throw new UnsupportedPattern(`expected object path, got '${first ? first.v : 'EOF'}'`);
    }
    segs.push(first.v);
    for (;;) {
      const t = peek();
      if (!t || t.t !== 'punct' || (t.v !== ':' && t.v !== '.')) break;
      next();
      const s = next();
      if (!s || (s.t !== 'ident' && s.t !== 'str')) {
        throw new UnsupportedPattern('malformed property path');
      }
      segs.push(s.v);
    }
    // canonical path: object-type:prop.sub.'Quoted Key'
    const path = segs[0] + ':' + segs.slice(1).join('.');

    const t = next();
    if (!t) throw new UnsupportedPattern('expected comparison operator');
    let op: string;
    if (t.t === 'punct' && ['=', '!=', '<', '<=', '>', '>='].includes(t.v)) op = t.v;
    else if (t.t === 'ident' && CMP_KEYWORDS.has(t.v.toUpperCase())) op = t.v.toUpperCase();
    else throw new UnsupportedPattern(`unsupported operator '${t.v}'`);

    let value: string | string[];
    const p = peek();
    if (p && p.t === 'punct' && p.v === '(') {
      next();
      const vals: string[] = [];
      vals.push(parseValue());
      for (;;) {
        const q = peek();
        if (q && q.t === 'punct' && q.v === ',') { next(); vals.push(parseValue()); continue; }
        break;
      }
      expectPunct(')');
      value = vals;
    } else {
      value = parseValue();
    }
    return { type: 'cmp', path, op, value };
  }
  function parseValue(): string {
    const t = next();
    if (!t) throw new UnsupportedPattern('expected value');
    if (t.t === 'str') return t.v;
    if (t.t === 'ident') {
      // timestamp literal t'...'
      if (t.v.toLowerCase() === 't' && peek() && peek()!.t === 'str') {
        next();
        throw new UnsupportedPattern('timestamp comparisons are not supported');
      }
      return t.v; // bare number / boolean-ish value
    }
    throw new UnsupportedPattern('expected value');
  }

  const expr = parseOr();
  if (pos < toks.length) {
    throw new UnsupportedPattern(
      `unsupported trailing syntax near '${toks[pos].v}' (FOLLOWEDBY/WITHIN/REPEATS/START-STOP are not supported)`,
    );
  }
  return expr;
}
