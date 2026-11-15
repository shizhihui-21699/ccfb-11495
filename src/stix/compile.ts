/**
 * Lowering from the parsed STIX AST to a *matchable* expression tree.
 *
 * The scanner works on flat, untrusted text lines, so the unit of matching is
 * a single observable value extracted from the line (an IP, a domain, a URL, a
 * hash, ...). A pattern is compiled into a boolean expression over atoms:
 *
 *   - A supported comparison becomes an atom resolved through a prebuilt
 *     index (`ipv4-addr:value = '1.2.3.4'`, `domain-name:value MATCHES ...`).
 *   - `AND` between atoms means both must be observed *on the same line*. That
 *     is the only join a single log line can justify, and it matches what an
 *     analyst means by combining two observables in one pattern.
 *
 * ### Policy for constructs the engine cannot evaluate
 *
 * The engine never approximates. An indicator whose pattern contains anything
 * it cannot evaluate *exactly* at line scope is rejected as a whole, with a
 * machine-readable reason. Partial lowering (dropping the unsupported half of
 * an AND) would silently widen the pattern and manufacture hits, which is
 * worse than a clear skip. The coordinator reports every skip by reason so an
 * operator can see coverage loss instead of inferring it from missing alerts.
 *
 * Rejected by design:
 *   - `!=` — "no extracted observable equals x" is true of every line that
 *     lacks that observable type, so it would fire on nearly all traffic.
 *   - observation operators `NOT`, `EXISTS` on nested paths, and all
 *     qualifiers (`WITHIN`, `REPEATS`, `START`, `STOP`, `FOLLOWEDBY`) — these
 *     need cross-line correlation the line scanner does not have.
 *   - ordering comparisons (`<`, `>`, `<=`, `>=`) on the string-valued
 *     observables this engine indexes.
 *   - `ISSUPERSET` — implies enumerating the address space of a line value.
 */

import {
  type CompareNode,
  type ObjectPath,
  type PatternNode,
  type PatternValue,
  type CompareOp,
  pathToString,
  unsupportedReasons,
} from "./pattern.ts";
import {
  cidrNetwork,
  formatIpv4,
  formatIpv6,
  ipv4Mask,
  parseCidr,
  parseIpv4,
  parseIpv6,
} from "../util/ip.ts";

/** Observable kinds this engine can index from a text line. */
export type ObservableKind = "ipv4" | "ipv6" | "domain" | "url" | "hash" | "email";

export type HashAlgorithm = "MD5" | "SHA-1" | "SHA-256" | "SHA-512";

/** Exact number of hex digits per algorithm. */
export const HASH_HEX_LENGTH: Record<HashAlgorithm, number> = {
  MD5: 32,
  "SHA-1": 40,
  "SHA-256": 64,
  "SHA-512": 128,
};

export type AtomSpec =
  | {
      readonly kind: "cidr";
      readonly observable: "ipv4" | "ipv6";
      readonly version: 4 | 6;
      readonly network: string;
      readonly prefix: number;
      readonly display: string;
    }
  | { readonly kind: "domain"; readonly key: string; readonly display: string }
  | { readonly kind: "url"; readonly key: string; readonly display: string }
  | { readonly kind: "email"; readonly key: string; readonly display: string }
  | {
      readonly kind: "hash";
      readonly algorithm: HashAlgorithm;
      readonly key: string;
      readonly display: string;
    }
  | {
      readonly kind: "regex";
      readonly observable: ObservableKind;
      readonly source: string;
      readonly flags: string;
      readonly display: string;
    }
  | { readonly kind: "exists"; readonly observable: ObservableKind };

export type Expr =
  | { readonly kind: "atom"; readonly atomId: number }
  | { readonly kind: "and"; readonly children: readonly Expr[] }
  | { readonly kind: "or"; readonly children: readonly Expr[] };

export interface CompiledProgram {
  readonly atoms: readonly AtomSpec[];
  readonly root: Expr;
  /** Boolean expression rendered for operator-facing output. */
  readonly summary: string;
  /** Observable kinds referenced anywhere in the program. */
  readonly observables: readonly ObservableKind[];
}

export interface UnsupportedCompile {
  readonly reason: string;
  readonly detail: string;
}

export type CompileResult =
  | { readonly ok: true; readonly program: CompiledProgram }
  | { readonly ok: false; readonly unsupported: UnsupportedCompile };

// ---------------------------------------------------------------------------
// Object path -> observable
// ---------------------------------------------------------------------------

const HASH_PROPERTIES: Record<string, HashAlgorithm> = {
  MD5: "MD5",
  "SHA-1": "SHA-1",
  "SHA-256": "SHA-256",
  "SHA-512": "SHA-512",
  // Feeds in the wild use the un-hyphenated spelling in object paths.
  SHA1: "SHA-1",
  SHA256: "SHA-256",
  SHA512: "SHA-512",
};

interface Resolved {
  readonly observable: ObservableKind;
  readonly algorithm?: HashAlgorithm;
}

function resolveProperty(path: ObjectPath): Resolved | UnsupportedCompile {
  const { type } = path;
  const prop = path.props.join(".");
  switch (type) {
    case "ipv4-addr":
      if (prop === "value") return { observable: "ipv4" };
      break;
    case "ipv6-addr":
      if (prop === "value") return { observable: "ipv6" };
      break;
    case "domain-name":
      if (prop === "value") return { observable: "domain" };
      break;
    case "url":
      if (prop === "value") return { observable: "url" };
      break;
    case "email-addr":
      if (prop === "value") return { observable: "email" };
      break;
    case "file":
    case "artifact": {
      if (prop === "hashes" || prop.startsWith("hashes.")) {
        const tail = prop === "hashes" ? "" : prop.slice("hashes.".length);
        const algorithm = HASH_PROPERTIES[tail.toUpperCase()];
        if (algorithm === undefined) {
          return {
            reason: "HASH_ALGORITHM_UNSUPPORTED",
            detail: `${pathToString(path)} names a hash algorithm the engine does not index`,
          };
        }
        return { observable: "hash", algorithm };
      }
      break;
    }
    default:
      break;
  }
  return {
    reason: "OBSERVABLE_UNSUPPORTED",
    detail: `${pathToString(path)} is not an observable this engine extracts from text`,
  };
}

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------

/** DNS names are case-insensitive; a trailing root dot is insignificant. */
export function normaliseDomain(input: string): string {
  let v = input.trim().toLowerCase();
  if (v.endsWith(".")) v = v.slice(0, -1);
  // Accept the feed-ism `*.example.com` / `.example.com` as a suffix match.
  while (v.startsWith("*.")) v = v.slice(2);
  if (v.startsWith(".")) v = v.slice(1);
  return v;
}

const URL_SCHEME_RE = /^([a-z][a-z0-9+.-]*):\/\//i;

/**
 * Normalise a URL for equality comparison: scheme and host are case
 * insensitive and the default port / a lone trailing slash are insignificant.
 * Path, query and fragment keep their original case and content.
 */
export function normaliseUrl(input: string): string {
  const s = input.trim();
  const m = URL_SCHEME_RE.exec(s);
  if (m === null) return s.toLowerCase();
  const scheme = (m[1] as string).toLowerCase();
  let rest = s.slice(m[0].length);
  let authorityEnd = rest.length;
  for (let i = 0; i < rest.length; i++) {
    const c = rest.charCodeAt(i);
    if (c === 47 /* / */ || c === 63 /* ? */ || c === 35 /* # */) {
      authorityEnd = i;
      break;
    }
  }
  let authority = rest.slice(0, authorityEnd);
  let tail = rest.slice(authorityEnd);
  let userinfo = "";
  const at = authority.lastIndexOf("@");
  if (at >= 0) {
    userinfo = authority.slice(0, at + 1);
    authority = authority.slice(at + 1);
  }
  let port = "";
  // Bracketed IPv6 literal: the colon inside brackets is not a port separator.
  const hostStart = authority.startsWith("[") ? authority.indexOf("]") + 1 : 0;
  const colon = authority.indexOf(":", hostStart);
  if (colon >= 0) {
    port = authority.slice(colon);
    authority = authority.slice(0, colon);
  }
  const host = authority.toLowerCase().replace(/\.$/, "");
  if ((port === ":80" && scheme === "http") || (port === ":443" && scheme === "https")) port = "";
  if (tail === "/") tail = "";
  return `${scheme}://${userinfo}${host}${port}${tail}`;
}

/** Best-effort host extraction from a normalised URL (already lowercased). */
export function urlHost(url: string): string {
  const m = URL_SCHEME_RE.exec(url);
  const rest = m === null ? url : url.slice(m[0].length);
  let end = rest.length;
  for (let i = 0; i < rest.length; i++) {
    const c = rest.charCodeAt(i);
    if (c === 47 || c === 63 || c === 35) {
      end = i;
      break;
    }
  }
  let authority = rest.slice(0, end);
  const at = authority.lastIndexOf("@");
  if (at >= 0) authority = authority.slice(at + 1);
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    return close > 0 ? authority.slice(1, close) : authority;
  }
  const colon = authority.indexOf(":");
  if (colon >= 0) authority = authority.slice(0, colon);
  return authority;
}

/** Convert a STIX LIKE pattern (`%` = any run, `_` = one char) to a RegExp. */
export function likeToRegExp(pattern: string): RegExp {
  let out = "^";
  for (const ch of pattern) {
    if (ch === "%") out += "[\\s\\S]*";
    else if (ch === "_") out += "[\\s\\S]";
    else out += ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  out += "$";
  return new RegExp(out, "u");
}

// ---------------------------------------------------------------------------
// Compiler
// ---------------------------------------------------------------------------

class Compiler {
  readonly atoms: AtomSpec[] = [];
  readonly #byKey = new Map<string, number>();
  readonly observables = new Set<ObservableKind>();

  atomFor(spec: AtomSpec, key: string): number {
    const existing = this.#byKey.get(key);
    if (existing !== undefined) return existing;
    const id = this.atoms.length;
    this.atoms.push(spec);
    this.#byKey.set(key, id);
    if (spec.kind === "cidr") this.observables.add(spec.observable);
    else if (spec.kind === "regex" || spec.kind === "exists") this.observables.add(spec.observable);
    else this.observables.add(spec.kind);
    return id;
  }
}

function valueToString(v: PatternValue): string | null {
  return v.kind === "string" ? v.value : v.kind === "number" ? String(v.value) : v.kind === "boolean" ? String(v.value) : null;
}

/** Validate + normalise a literal for `observable`; returns atom spec or error. */
function literalAtom(
  observable: ObservableKind,
  algorithm: HashAlgorithm | undefined,
  raw: string,
  display: string,
): AtomSpec | UnsupportedCompile {
  switch (observable) {
    case "ipv4": {
      const cidr = raw.includes("/") ? parseCidr(raw) : null;
      if (cidr !== null) {
        if (cidr.addr.version !== 4) return { reason: "VALUE_INVALID", detail: `${raw} is not an IPv4 prefix` };
        const net = cidrNetwork(cidr);
        return {
          kind: "cidr",
          observable: "ipv4",
          version: 4,
          network: formatIpv4(net.addr.version === 4 ? net.addr.n : 0),
          prefix: cidr.prefix,
          display,
        };
      }
      const v4 = parseIpv4(raw);
      if (v4 === null) return { reason: "VALUE_INVALID", detail: `${JSON.stringify(raw)} is not an IPv4 address or prefix` };
      return {
        kind: "cidr",
        observable: "ipv4",
        version: 4,
        network: formatIpv4(v4.n),
        prefix: 32,
        display,
      };
    }
    case "ipv6": {
      const cidr = raw.includes("/") ? parseCidr(raw) : null;
      if (cidr !== null) {
        if (cidr.addr.version !== 6) return { reason: "VALUE_INVALID", detail: `${raw} is not an IPv6 prefix` };
        const net = cidrNetwork(cidr);
        return {
          kind: "cidr",
          observable: "ipv6",
          version: 6,
          network: formatIpv6(net.addr.version === 6 ? net.addr.w : new Uint32Array(4)),
          prefix: cidr.prefix,
          display,
        };
      }
      const v6 = parseIpv6(raw);
      if (v6 === null) return { reason: "VALUE_INVALID", detail: `${JSON.stringify(raw)} is not an IPv6 address or prefix` };
      return {
        kind: "cidr",
        observable: "ipv6",
        version: 6,
        network: formatIpv6(v6.w),
        prefix: 128,
        display,
      };
    }
    case "domain": {
      const key = normaliseDomain(raw);
      if (!isPlausibleDomain(key)) {
        return { reason: "VALUE_INVALID", detail: `${JSON.stringify(raw)} is not a valid domain name` };
      }
      return { kind: "domain", key, display };
    }
    case "url": {
      const key = normaliseUrl(raw);
      if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(key)) {
        return { reason: "VALUE_INVALID", detail: `${JSON.stringify(raw)} is not an absolute URL` };
      }
      return { kind: "url", key, display };
    }
    case "email": {
      const key = raw.trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+$/.test(key)) {
        return { reason: "VALUE_INVALID", detail: `${JSON.stringify(raw)} is not an email address` };
      }
      return { kind: "email", key, display };
    }
    case "hash": {
      const algo = algorithm as HashAlgorithm;
      const key = raw.trim().toLowerCase();
      if (!/^[0-9a-f]+$/.test(key) || key.length !== HASH_HEX_LENGTH[algo]) {
        return {
          reason: "VALUE_INVALID",
          detail: `${JSON.stringify(raw)} is not a ${algo} digest (${HASH_HEX_LENGTH[algo]} hex digits)`,
        };
      }
      return { kind: "hash", algorithm: algo, key, display };
    }
    default:
      return { reason: "OBSERVABLE_UNSUPPORTED", detail: `cannot match observable ${observable}` };
  }
}

function isPlausibleDomain(v: string): boolean {
  if (v.length === 0 || v.length > 253) return false;
  const labels = v.split(".");
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
    for (let i = 0; i < label.length; i++) {
      const c = label.charCodeAt(i);
      const ok = (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 45 || c === 95;
      if (!ok) return false;
    }
  }
  const tld = labels[labels.length - 1] as string;
  if (tld.length < 2) return false;
  if (!/[a-z]/.test(tld)) return false;
  return true;
}

function isUnsupported(v: unknown): v is UnsupportedCompile {
  return typeof v === "object" && v !== null && typeof (v as UnsupportedCompile).reason === "string";
}

function asUnsupported(v: unknown): UnsupportedCompile | null {
  return isUnsupported(v) ? v : null;
}

function compileNode(node: PatternNode, c: Compiler): Expr | UnsupportedCompile {
  switch (node.kind) {
    case "unsupported":
      return { reason: node.reason, detail: `pattern uses ${node.reason.split(":")[0]?.toLowerCase() ?? "an unsupported construct"}` };
    case "and":
    case "or": {
      const children: Expr[] = [];
      for (const child of node.children) {
        const r = compileNode(child, c);
        const bad = asUnsupported(r);
        if (bad !== null) return bad;
        children.push(r as Expr);
      }
      // Flatten same-operator nesting to keep evaluation shallow.
      const flat: Expr[] = [];
      for (const ch of children) {
        if (ch.kind === node.kind) flat.push(...ch.children);
        else flat.push(ch);
      }
      return { kind: node.kind, children: flat };
    }
    case "compare":
      return compileCompare(node, c);
    default:
      return { reason: "PATTERN_UNSUPPORTED", detail: "unrecognised pattern construct" };
  }
}

function compileCompare(node: CompareNode, c: Compiler): Expr | UnsupportedCompile {
  const resolved = resolveProperty(node.path);
  const bad = asUnsupported(resolved);
  if (bad !== null) return bad;
  const { observable, algorithm } = resolved as Resolved;
  const pathText = pathToString(node.path);

  if (node.op === "!=") {
    return { reason: "OPERATOR_UNSUPPORTED:NEQ", detail: `!= cannot be evaluated at line scope (${pathText})` };
  }
  if (node.op === "<" || node.op === ">" || node.op === "<=" || node.op === ">=") {
    return { reason: "OPERATOR_UNSUPPORTED:ORDERING", detail: `ordering comparison is not meaningful for ${pathText}` };
  }
  if (node.op === "ISSUPERSET") {
    return { reason: "OPERATOR_UNSUPPORTED:ISSUPERSET", detail: `ISSUPERSET is not supported (${pathText})` };
  }

  if (node.op === "IN") {
    if (node.value.kind !== "list") {
      return { reason: "PATTERN_SYNTAX", detail: `IN requires a list (${pathText})` };
    }
    if (node.value.items.length === 0) {
      return { reason: "PATTERN_SYNTAX", detail: `IN list is empty (${pathText})` };
    }
    const kids: Expr[] = [];
    for (const item of node.value.items) {
      const single: CompareNode = { kind: "compare", path: node.path, op: "=", value: item };
      const r = compileCompare(single, c);
      const b = asUnsupported(r);
      if (b !== null) return b;
      kids.push(r as Expr);
    }
    return kids.length === 1 ? (kids[0] as Expr) : { kind: "or", children: kids };
  }

  // ISSUBSET on an address is the containment test this engine already does
  // for a CIDR atom, so it lowers to identity with `=`.
  const effectiveOp: CompareOp = node.op === "ISSUBSET" ? "=" : node.op;

  if (effectiveOp === "MATCHES" || effectiveOp === "LIKE") {
    if (node.value.kind !== "string") {
      return { reason: "PATTERN_SYNTAX", detail: `${effectiveOp} requires a string (${pathText})` };
    }
    const source = node.value.value;
    if (source.length > 512) {
      return { reason: "REGEX_TOO_LONG", detail: `${pathText} ${effectiveOp} value exceeds 512 characters` };
    }
    let regex: RegExp;
    try {
      regex = effectiveOp === "LIKE" ? likeToRegExp(source) : new RegExp(source, "u");
    } catch (err) {
      return {
        reason: effectiveOp === "LIKE" ? "LIKE_INVALID" : "REGEX_INVALID",
        detail: `${pathText} ${effectiveOp} ${JSON.stringify(source)}: ${(err as Error).message}`,
      };
    }
    return {
      kind: "atom",
      atomId: c.atomFor(
        {
          kind: "regex",
          observable,
          source,
          flags: regex.flags,
          display: `${pathText} ${effectiveOp} '${source}'`,
        },
        `regex\u0000${observable}\u0000${effectiveOp}\u0000${source}`,
      ),
    };
  }

  // `=` (and `ISSUBSET`, normalised above) against a single literal.
  if (node.value.kind === "list") {
    return { reason: "PATTERN_SYNTAX", detail: `= requires a single literal (${pathText}); use IN` };
  }
  const raw = valueToString(node.value);
  if (raw === null) {
    return { reason: "PATTERN_SYNTAX", detail: `unsupported literal for ${pathText}` };
  }
  const spec = literalAtom(observable, algorithm, raw, `${pathText} = '${raw}'`);
  const badSpec = asUnsupported(spec);
  if (badSpec !== null) return badSpec;
  const atom = spec as AtomSpec;
  return {
    kind: "atom",
    atomId: c.atomFor(atom, `${atomKey(atom)}`),
  };
}

function atomKey(a: AtomSpec): string {
  switch (a.kind) {
    case "cidr":
      return `cidr\u0000${a.version}\u0000${a.network}/${a.prefix}`;
    case "domain":
      return `domain\u0000${a.key}`;
    case "url":
      return `url\u0000${a.key}`;
    case "email":
      return `email\u0000${a.key}`;
    case "hash":
      return `hash\u0000${a.algorithm}\u0000${a.key}`;
    case "regex":
      return `regex\u0000${a.observable}\u0000${a.flags}\u0000${a.source}`;
    case "exists":
      return `exists\u0000${a.observable}`;
  }
}

function renderExpr(e: Expr, atoms: readonly AtomSpec[]): string {
  switch (e.kind) {
    case "atom": {
      const a = atoms[e.atomId] as AtomSpec;
      switch (a.kind) {
        case "cidr":
          return `${a.observable === "ipv4" ? "ipv4-addr" : "ipv6-addr"}:value = '${a.prefix === (a.version === 4 ? 32 : 128) ? a.network : `${a.network}/${a.prefix}`}'`;
        case "domain":
          return `domain-name:value = '${a.key}'`;
        case "url":
          return `url:value = '${a.key}'`;
        case "email":
          return `email-addr:value = '${a.key}'`;
        case "hash":
          return `file:hashes.'${a.algorithm}' = '${a.key}'`;
        case "regex":
          return a.display;
        case "exists":
          return `${a.observable}:value EXISTS`;
      }
      return "?";
    }
    case "and":
      return `(${e.children.map((c) => renderExpr(c, atoms)).join(" AND ")})`;
    case "or":
      return `(${e.children.map((c) => renderExpr(c, atoms)).join(" OR ")})`;
  }
}

/**
 * Compile a parsed pattern. `patternText` is only used in diagnostics.
 */
export function compilePattern(node: PatternNode): CompileResult {
  if (node.kind === "unsupported") {
    return {
      ok: false,
      unsupported: {
        reason: node.reason,
        detail: unsupportedReasons(node).join(", ") || "unsupported pattern construct",
      },
    };
  }
  const c = new Compiler();
  const root = compileNode(node, c);
  const bad = asUnsupported(root);
  if (bad !== null) return { ok: false, unsupported: bad };
  const expr = root as Expr;
  return {
    ok: true,
    program: {
      atoms: c.atoms,
      root: expr,
      summary: renderExpr(expr, c.atoms),
      observables: [...c.observables].sort(),
    },
  };
}

// `ipv4Mask` is re-exported for tests that build prefixes by hand.
export { ipv4Mask };
