/**
 * STIX 2.1 pattern parsing.
 *
 * Implements the practical subset of the patterning grammar that makes sense
 * for *line-oriented* IOC scanning:
 *
 *   pattern     := or-expression
 *   or          := and ('OR' and)*
 *   and         := primary ('AND' primary)*
 *   primary     := '[' or ']' | '(' or ')' | comparison
 *   comparison  := object-path operator value | object-path 'IN' list
 *
 * Precedence follows the spec: AND binds tighter than OR.
 *
 * Anything the engine cannot evaluate soundly against a single log line is
 * *not guessed at*. It is parsed, recorded as `unsupported` with a precise
 * reason, and the caller decides what to do (see `compileIndicator`). Silently
 * approximating a pattern is how IOC engines produce false negatives while
 * still looking healthy, so the parser never does it.
 *
 * Unsupported by design (each maps to a reason code):
 *   - qualifiers (WITHIN / REPEATS / START / STOP / FOLLOWEDBY) need
 *     cross-line observation correlation;
 *   - `!=` cannot be evaluated against free text: "no extracted observable
 *     equals x" is true for every line without that observable type, which
 *     would fire on essentially all traffic;
 *   - ordering comparisons (<, >, <=, >=) on strings carry no detection
 *     meaning for the observable types we index;
 *   - observation operators EXISTS / NOT / INSIDE are not supported.
 */

export type CompareOp = "=" | "IN" | "LIKE" | "MATCHES" | "ISSUBSET" | "ISSUPERSET" | "!=" | "<" | ">" | "<=" | ">=";

export interface ObjectPath {
  readonly type: string;
  readonly props: readonly string[];
}

export type PatternValue =
  | { readonly kind: "string"; readonly value: string }
  | { readonly kind: "number"; readonly value: number }
  | { readonly kind: "boolean"; readonly value: boolean }
  | { readonly kind: "list"; readonly items: readonly PatternValue[] };

export interface CompareNode {
  readonly kind: "compare";
  readonly path: ObjectPath;
  readonly op: CompareOp;
  readonly value: PatternValue;
}

export interface BoolNode {
  readonly kind: "and" | "or";
  readonly children: readonly PatternNode[];
}

export interface UnsupportedNode {
  readonly kind: "unsupported";
  readonly reason: string;
  /** The original text of the fragment, for operator-facing diagnostics. */
  readonly text: string;
}

export type PatternNode = CompareNode | BoolNode | UnsupportedNode;

export class PatternParseError extends Error {
  readonly position: number;
  constructor(message: string, position: number) {
    super(`${message} (at offset ${position})`);
    this.name = "PatternParseError";
    this.position = position;
  }
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

type TokenType =
  | "word"
  | "string"
  | "number"
  | "lparen"
  | "rparen"
  | "lbracket"
  | "rbracket"
  | "comma"
  | "op"
  | "eof";

interface Token {
  readonly type: TokenType;
  readonly text: string;
  readonly value?: string;
  readonly pos: number;
}

const KEYWORDS = new Set(["AND", "OR", "NOT", "IN", "LIKE", "MATCHES", "ISSUBSET", "ISSUPERSET", "EXISTS", "FOLLOWEDBY", "WITHIN", "REPEATS", "START", "STOP", "TIMES", "SECONDS", "MINUTES", "HOURS", "DAYS"]);

function isWordChar(c: number): boolean {
  // Letters, digits, `_`, `-`, `.` and `:` all appear in STIX identifiers and
  // object paths. Operators and grouping characters are handled separately.
  return (
    (c >= 97 && c <= 122) ||
    (c >= 65 && c <= 90) ||
    (c >= 48 && c <= 57) ||
    c === 95 /* _ */ ||
    c === 45 /* - */ ||
    c === 46 /* . */ ||
    c === 58 /* : */
  );
}

function isDigit(c: number): boolean {
  return c >= 48 && c <= 57;
}

function tokenize(src: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src.charCodeAt(i);
    if (c === 32 || c === 9 || c === 10 || c === 13) {
      i++;
      continue;
    }
    if (c === 40 /* ( */) {
      out.push({ type: "lparen", text: "(", pos: i++ });
      continue;
    }
    if (c === 41 /* ) */) {
      out.push({ type: "rparen", text: ")", pos: i++ });
      continue;
    }
    if (c === 91 /* [ */) {
      out.push({ type: "lbracket", text: "[", pos: i++ });
      continue;
    }
    if (c === 93 /* ] */) {
      out.push({ type: "rbracket", text: "]", pos: i++ });
      continue;
    }
    if (c === 44 /* , */) {
      out.push({ type: "comma", text: ",", pos: i++ });
      continue;
    }
    if (c === 39 /* ' */) {
      const start = i;
      i++;
      let value = "";
      let closed = false;
      while (i < n) {
        const ch = src[i] as string;
        if (ch === "\\") {
          const next = src[i + 1];
          if (next === undefined) break;
          // STIX string escapes: \\ -> \, \' -> '
          if (next === "\\" || next === "'") {
            value += next;
            i += 2;
            continue;
          }
          value += ch;
          i++;
          continue;
        }
        if (ch === "'") {
          i++;
          closed = true;
          break;
        }
        value += ch;
        i++;
      }
      if (!closed) throw new PatternParseError("unterminated string literal", start);
      out.push({ type: "string", text: src.slice(start, i), value, pos: start });
      continue;
    }
    if (c === 61 /* = */) {
      out.push({ type: "op", text: "=", pos: i++ });
      continue;
    }
    if (c === 33 /* ! */) {
      if (src[i + 1] === "=") {
        out.push({ type: "op", text: "!=", pos: i });
        i += 2;
        continue;
      }
      throw new PatternParseError("unexpected character '!'", i);
    }
    if (c === 60 /* < */ || c === 62 /* > */) {
      const text = src.charCodeAt(i + 1) === 61 /* = */ ? `${src[i]}=` : (src[i] as string);
      out.push({ type: "op", text, pos: i });
      i += text.length;
      continue;
    }
    if (c >= 48 && c <= 57) {
      const start = i;
      while (i < n && isDigit(src.charCodeAt(i))) i++;
      if (src.charCodeAt(i) === 46 /* . */ && isDigit(src.charCodeAt(i + 1))) {
        i++;
        while (i < n && isDigit(src.charCodeAt(i))) i++;
      }
      out.push({ type: "number", text: src.slice(start, i), value: src.slice(start, i), pos: start });
      continue;
    }
    if (isWordChar(c)) {
      const start = i;
      while (i < n && isWordChar(src.charCodeAt(i))) i++;
      out.push({ type: "word", text: src.slice(start, i), pos: start });
      continue;
    }
    throw new PatternParseError(`unexpected character ${JSON.stringify(src[i])}`, i);
  }
  out.push({ type: "eof", text: "", pos: n });
  return out;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

class Parser {
  readonly #tokens: Token[];
  #idx = 0;

  constructor(tokens: Token[]) {
    this.#tokens = tokens;
  }

  #peek(): Token {
    return this.#tokens[this.#idx] as Token;
  }

  #next(): Token {
    return this.#tokens[this.#idx++] as Token;
  }

  #expect(type: TokenType, what: string): Token {
    const t = this.#peek();
    if (t.type !== type) throw new PatternParseError(`expected ${what}`, t.pos);
    return this.#next();
  }

  #isKeyword(t: Token, kw: string): boolean {
    return t.type === "word" && t.text.toUpperCase() === kw;
  }

  parse(): PatternNode {
    // STIX observation expressions are always bracketed; a bare comparison is
    // a common feed bug (someone stripped the brackets) and accepting it
    // would hide the malformation rather than report it.
    const first = this.#peek();
    if (first.type !== "lbracket" && first.type !== "lparen") {
      if (first.type === "word" && KEYWORDS.has(first.text.toUpperCase())) {
        return { kind: "unsupported", reason: `QUALIFIER_UNSUPPORTED:${first.text.toUpperCase()}`, text: first.text };
      }
      throw new PatternParseError("pattern must start with '['", first.pos);
    }
    const node = this.#parseOr();
    const t = this.#peek();
    if (t.type !== "eof") {
      // Observation qualifiers (WITHIN/REPEATS/...) are recognised here so the
      // diagnostic names them instead of reporting a generic syntax error.
      if (t.type === "word" && KEYWORDS.has(t.text.toUpperCase())) {
        return {
          kind: "unsupported",
          reason: `QUALIFIER_UNSUPPORTED:${t.text.toUpperCase()}`,
          text: t.text,
        };
      }
      throw new PatternParseError(`unexpected token ${JSON.stringify(t.text)}`, t.pos);
    }
    return node;
  }

  #parseOr(): PatternNode {
    const first = this.#parseAnd();
    const children: PatternNode[] = [first];
    while (this.#isKeyword(this.#peek(), "OR")) {
      this.#next();
      children.push(this.#parseAnd());
    }
    if (children.length === 1) return first;
    return { kind: "or", children };
  }

  #parseAnd(): PatternNode {
    const first = this.#parsePrimary();
    const children: PatternNode[] = [first];
    while (this.#isKeyword(this.#peek(), "AND")) {
      this.#next();
      children.push(this.#parsePrimary());
    }
    if (children.length === 1) return first;
    return { kind: "and", children };
  }

  #parsePrimary(): PatternNode {
    const t = this.#peek();
    if (t.type === "lbracket") {
      this.#next();
      const inner = this.#parseOr();
      this.#expect("rbracket", "']'");
      return inner;
    }
    if (t.type === "lparen") {
      this.#next();
      const inner = this.#parseOr();
      this.#expect("rparen", "')'");
      return inner;
    }
    if (t.type === "word") {
      const upper = t.text.toUpperCase();
      if (upper === "NOT") {
        // `NOT` negates the observation that follows. Consume the operand so
        // the parser stays in sync, then reject: negation cannot be evaluated
        // against free text (see the module header).
        const tok = this.#next();
        this.#parsePrimary();
        return { kind: "unsupported", reason: `OPERATOR_UNSUPPORTED:${upper}`, text: tok.text };
      }
      if (upper === "EXISTS") {
        // `EXISTS <path>` applies to a bare object path, not a bracketed
        // comparison; consume the path so the diagnostic is about EXISTS and
        // not about a stray token after it.
        const tok = this.#next();
        if (this.#peek().type === "lbracket") this.#parsePrimary();
        else this.#parsePath();
        return { kind: "unsupported", reason: `OPERATOR_UNSUPPORTED:${upper}`, text: tok.text };
      }
    }
    return this.#parseComparison();
  }

  #parseComparison(): PatternNode {
    const startTok = this.#peek();
    const path = this.#parsePath();
    const opTok = this.#peek();
    let op: CompareOp;
    if (opTok.type === "op") {
      op = opTok.text as CompareOp;
      this.#next();
    } else if (opTok.type === "word") {
      const upper = opTok.text.toUpperCase();
      if (upper === "IN" || upper === "LIKE" || upper === "MATCHES" || upper === "ISSUBSET" || upper === "ISSUPERSET") {
        op = upper;
        this.#next();
      } else {
        throw new PatternParseError(`expected a comparison operator, found ${JSON.stringify(opTok.text)}`, opTok.pos);
      }
    } else {
      throw new PatternParseError("expected a comparison operator", opTok.pos);
    }

    let value: PatternValue;
    if (op === "IN") {
      value = this.#parseList();
    } else {
      value = this.#parseValue();
    }

    return { kind: "compare", path, op, value };
  }

  #parsePath(): ObjectPath {
    const first = this.#expect("word", "an object path");
    const colon = first.text.indexOf(":");
    if (colon <= 0) {
      throw new PatternParseError(
        `object path must start with "<type>:<property>", found ${JSON.stringify(first.text)}`,
        first.pos,
      );
    }
    const type = first.text.slice(0, colon);
    // The lexer keeps `.` inside words, so `network-traffic:dst_ref.type`
    // arrives as one token. A quoted component (`file:hashes.'SHA-256'`)
    // splits off as a separate string token.
    const props = first.text
      .slice(colon + 1)
      .split(".")
      .filter((s) => s.length > 0);
    while (this.#peek().type === "string") {
      props.push(this.#next().value as string);
    }
    if (props.length === 0) {
      throw new PatternParseError(`object path ${JSON.stringify(first.text)} has no property`, first.pos);
    }
    return { type, props };
  }

  #parseValue(): PatternValue {
    const t = this.#peek();
    if (t.type === "string") {
      this.#next();
      return { kind: "string", value: t.value as string };
    }
    if (t.type === "number") {
      this.#next();
      return { kind: "number", value: Number(t.value) };
    }
    if (t.type === "word") {
      const upper = t.text.toUpperCase();
      if (upper === "TRUE" || upper === "FALSE") {
        this.#next();
        return { kind: "boolean", value: upper === "TRUE" };
      }
    }
    throw new PatternParseError("expected a literal value", t.pos);
  }

  #parseList(): PatternValue {
    this.#expect("lparen", "'(' to start an IN list");
    const items: PatternValue[] = [];
    if (this.#peek().type !== "rparen") {
      items.push(this.#parseValue());
      while (this.#peek().type === "comma") {
        this.#next();
        items.push(this.#parseValue());
      }
    }
    this.#expect("rparen", "')' to close an IN list");
    return { kind: "list", items };
  }
}

/** Parse a STIX pattern. Throws `PatternParseError` on malformed input. */
export function parsePattern(src: string): PatternNode {
  if (src.trim().length === 0) throw new PatternParseError("empty pattern", 0);
  const parser = new Parser(tokenize(src));
  return parser.parse();
}

/** Render a path back to STIX text (used in diagnostics and hit output). */
export function pathToString(path: ObjectPath): string {
  const parts = path.props.map((p, i) => (i === 0 && /^[A-Za-z0-9_-]+$/.test(p) ? p : `'${p.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`));
  return `${path.type}:${parts.join(".")}`;
}

/** Collect every `unsupported` node's reason, in document order. */
export function unsupportedReasons(node: PatternNode): string[] {
  const out: string[] = [];
  const walk = (n: PatternNode): void => {
    if (n.kind === "unsupported") out.push(n.reason);
    else if (n.kind === "and" || n.kind === "or") for (const c of n.children) walk(c);
  };
  walk(node);
  return out;
}

/** Collect the distinct observable types a pattern touches. */
export function observableTypes(node: PatternNode): string[] {
  const set = new Set<string>();
  const walk = (n: PatternNode): void => {
    if (n.kind === "compare") set.add(n.path.type);
    else if (n.kind === "and" || n.kind === "or") for (const c of n.children) walk(c);
  };
  walk(node);
  return [...set];
}
