/**
 * Single-pass observable extraction from a log line.
 *
 * The scanner never hands a JS string to a matcher. This module walks the raw
 * bytes once and records the observables an indicator can reference, together
 * with their byte spans, in reusable typed arrays. Everything downstream
 * (prefix tries, byte maps, automata) consumes spans, so a line with no
 * candidates allocates nothing.
 *
 * Extraction rules (all byte-level, ASCII):
 *
 *  - Tokens end at whitespace, quotes, brackets, braces, `< > , ; \ ^ ` |`.
 *    Trailing `. , ; ! ? )` and a trailing `:` are trimmed when the token has
 *    no other meaning for them.
 *  - A token containing `scheme://` is a URL. Its authority host is also
 *    recorded as a domain (and as an IP when it is one). Bytes after the
 *    authority are scanned for IPs and hashes, because logs routinely carry
 *    indicators in query strings.
 *  - `a@b` inside a token is an email-addr; its domain half is also recorded
 *    as a domain.
 *  - IPv4: dotted quad, optionally followed by `:port` or `/prefix`, with
 *    leading-zero octets rejected (`010.1.1.1` is not an address).
 *  - IPv6: colon-bearing token, optionally bracketed and/or followed by
 *    `:port`, `/prefix` or `%zone`.
 *  - hash: a pure-hex token of exactly 32/40/64/128 chars maps to
 *    MD5 / SHA-1 / SHA-256 / SHA-512.
 *  - domain: a multi-label LDH-ish token whose TLD is alphabetic and at least
 *    two chars. Numeric-dotted tokens that are not valid IPv4 are rejected
 *    (no `999.1.1.1` or `1.2.3` hosts).
 *
 * Deliberate limits, documented in the README: ASCII only (IDNs must be
 * punycode), no defanged forms (`hxxp://`, `evil[.]com`), hashes must be
 * contiguous hex, and a domain appearing as a *path* component is treated as a
 * domain candidate (the domain index scans the whole line anyway, so this
 * matches how analysts expect a grep-replacement to behave).
 */

import { formatIpv6, parseIpv4N, parseIpv6Bytes } from "../util/ip.ts";
import { isAlnum, isAlpha, isDigit, isHexByte, hexNibble } from "../util/bytes.ts";

export type HashAlgorithm = "MD5" | "SHA-1" | "SHA-256" | "SHA-512";

const HASH_LENGTHS: ReadonlyMap<number, HashAlgorithm> = new Map<number, HashAlgorithm>([
  [32, "MD5"],
  [40, "SHA-1"],
  [64, "SHA-256"],
  [128, "SHA-512"],
]);

const CAP_INITIAL = 16;

function isTokenStop(c: number): boolean {
  return (
    c <= 32 ||
    c === 34 /* " */ ||
    c === 39 /* ' */ ||
    c === 60 /* < */ ||
    c === 62 /* > */ ||
    c === 91 /* [ */ ||
    c === 93 /* ] */ ||
    c === 123 /* { */ ||
    c === 125 /* } */ ||
    c === 44 /* , */ ||
    c === 59 /* ; */ ||
    c === 92 /* \ */ ||
    c === 94 /* ^ */ ||
    c === 96 /* ` */ ||
    c === 124 /* | */
  );
}

function isWordByte(c: number): boolean {
  return (
    isAlnum(c) ||
    c === 45 /* - */ ||
    c === 46 /* . */ ||
    c === 95 /* _ */ ||
    c === 58 /* : */ ||
    c === 64 /* @ */ ||
    c === 37 /* % */ ||
    c === 43 /* + */ ||
    c === 47 /* / */ ||
    c === 63 /* ? */ ||
    c === 35 /* # */ ||
    c === 38 /* & */
  );
}

export class Extractor {
  #text: Uint8Array<ArrayBufferLike>;

  #v4n = new Int32Array(CAP_INITIAL);
  #v4off = new Int32Array(CAP_INITIAL);
  #v4count = 0;

  #v6w = new Uint32Array(CAP_INITIAL * 4);
  #v6off = new Int32Array(CAP_INITIAL);
  #v6count = 0;

  #domStart = new Int32Array(CAP_INITIAL);
  #domEnd = new Int32Array(CAP_INITIAL);
  #domCount = 0;

  #urlStart = new Int32Array(CAP_INITIAL);
  #urlEnd = new Int32Array(CAP_INITIAL);
  #urlNormOff = new Int32Array(CAP_INITIAL);
  #urlNormLen = new Int32Array(CAP_INITIAL);
  #urlCount = 0;

  #mailStart = new Int32Array(CAP_INITIAL);
  #mailEnd = new Int32Array(CAP_INITIAL);
  #mailCount = 0;

  #hashStart = new Int32Array(CAP_INITIAL);
  #hashEnd = new Int32Array(CAP_INITIAL);
  #hashCount = 0;

  /** Canonical URL bytes, concatenated; spans are recorded per URL. */
  #norm = new Uint8Array(512);
  #normLen = 0;

  /** Scratch words reused by `v6Words`. */
  readonly #scratch6 = new Uint32Array(4);

  constructor(text: Uint8Array<ArrayBufferLike>) {
    this.#text = text;
  }

  /**
   * Re-point at a new line and clear all results. The typed arrays are kept,
   * so a long-running process performs no per-line allocation beyond what the
   * growth path needs. This is the only way the scanner uses the extractor;
   * the constructor form exists for tests and one-off use.
   */
  reset(text: Uint8Array<ArrayBufferLike>): void {
    this.#text = text;
    this.#v4count = 0;
    this.#v6count = 0;
    this.#domCount = 0;
    this.#urlCount = 0;
    this.#mailCount = 0;
    this.#hashCount = 0;
    this.#normLen = 0;
  }

  // -- accessors ---------------------------------------------------------

  get v4count(): number {
    return this.#v4count;
  }
  get v6count(): number {
    return this.#v6count;
  }
  get domainCount(): number {
    return this.#domCount;
  }
  get urlCount(): number {
    return this.#urlCount;
  }
  get emailCount(): number {
    return this.#mailCount;
  }
  get hashCount(): number {
    return this.#hashCount;
  }

  v4Value(i: number): number {
    return this.#v4n[i] as number;
  }
  v4Offset(i: number): number {
    return this.#v4off[i] as number;
  }
  v6Words(i: number, out: Uint32Array): void {
    out[0] = this.#v6w[i * 4] as number;
    out[1] = this.#v6w[i * 4 + 1] as number;
    out[2] = this.#v6w[i * 4 + 2] as number;
    out[3] = this.#v6w[i * 4 + 3] as number;
  }
  v6Offset(i: number): number {
    return this.#v6off[i] as number;
  }
  domainStart(i: number): number {
    return this.#domStart[i] as number;
  }
  domainEnd(i: number): number {
    return this.#domEnd[i] as number;
  }
  urlStart(i: number): number {
    return this.#urlStart[i] as number;
  }
  urlEnd(i: number): number {
    return this.#urlEnd[i] as number;
  }
  /** Canonical URL bytes (valid until the next line). */
  urlNormalised(i: number): Uint8Array {
    const off = this.#urlNormOff[i] as number;
    const len = this.#urlNormLen[i] as number;
    return this.#norm.subarray(off, off + len);
  }
  emailStart(i: number): number {
    return this.#mailStart[i] as number;
  }
  emailEnd(i: number): number {
    return this.#mailEnd[i] as number;
  }
  hashStart(i: number): number {
    return this.#hashStart[i] as number;
  }
  hashEnd(i: number): number {
    return this.#hashEnd[i] as number;
  }
  hashAlgorithm(i: number): HashAlgorithm | null {
    return HASH_LENGTHS.get((this.#hashEnd[i] as number) - (this.#hashStart[i] as number)) ?? null;
  }

  /** Copy a span out as lowercase text (cold paths only). */
  spanLower(start: number, end: number): string {
    let s = "";
    for (let i = start; i < end; i++) {
      const c = this.#text[i] as number;
      s += String.fromCharCode(c >= 65 && c <= 90 ? c + 32 : c);
    }
    return s;
  }
  span(start: number, end: number): string {
    return Buffer.from(this.#text.subarray(start, end)).toString("latin1");
  }
  /** Decode a hex span into `out` (must be big enough); returns byte count. */
  hexDecode(start: number, end: number, out: Uint8Array): number {
    const len = (end - start) >> 1;
    for (let i = 0; i < len; i++) {
      const hi = hexNibble(this.#text[start + i * 2] as number);
      const lo = hexNibble(this.#text[start + i * 2 + 1] as number);
      out[i] = ((hi << 4) | lo) & 0xff;
    }
    return len;
  }
  formatV6(i: number): string {
    this.v6Words(i, this.#scratch6);
    return formatIpv6(this.#scratch6);
  }

  // -- extraction --------------------------------------------------------

  run(): void {
    const t = this.#text;
    const n = t.length;
    let i = 0;
    while (i < n) {
      const c = t[i] as number;
      if (c === 91 /* [ */) {
        const close = this.#findByte(i + 1, 93);
        if (close > 0 && close - i > 3) {
          if (this.#tryIpv6(i + 1, close)) {
            i = close + 1;
            continue;
          }
        }
        i++;
        continue;
      }
      if (isWordByte(c)) {
        i = this.#readToken(i);
        continue;
      }
      i++;
    }
  }

  #findByte(from: number, byte: number): number {
    const t = this.#text;
    for (let i = from; i < t.length; i++) if (t[i] === byte) return i;
    return -1;
  }

  /**
   * Scan one token from `start`. Fills `#lastEnd` (end of the token body) and
   * `#lastSchemeAt` (index of an embedded `scheme://`, or -1) in a single
   * pass. Returns the index at which the caller should resume scanning.
   *
   * Two delimiter subtleties are handled here rather than in a second pass:
   *
   *   - `=` ends a `key=value` log field but not a URL query string, so it is
   *     only a terminator when no `://` has been seen in this token;
   *   - brackets are token stops (they delimit `[ipv6]`) except inside a URL
   *     authority, where `https://[::1]:443/` needs them.
   */
  #scanToken(start: number): number {
    const t = this.#text;
    const n = t.length;
    let i = start;
    let schemeAt = -1;
    while (i < n) {
      const c = t[i] as number;
      if (c === 58 /* : */ && schemeAt < 0 && i + 2 < n && t[i + 1] === 47 && t[i + 2] === 47) {
        // Walk back over the scheme name to its first byte.
        let s = i - 1;
        while (s >= start && isAlnum(t[s] as number)) s--;
        if (s + 1 < i && isAlpha(t[s + 1] as number)) schemeAt = s + 1;
      }
      if (c === 61 /* = */ && schemeAt < 0 && start !== i) break;
      if ((c === 91 || c === 93) && schemeAt >= 0) {
        i++;
        continue;
      }
      if (isTokenStop(c)) break;
      i++;
    }
    let end = i;
    while (end > start) {
      const c = t[end - 1] as number;
      if (c === 46 || c === 44 || c === 59 || c === 33 || c === 63 || c === 41) {
        end--;
        continue;
      }
      if (c === 58) {
        // A trailing single ':' is prose punctuation (`warning:`), but a
        // trailing '::' is the compressed-zero form of an IPv6 literal
        // (`::`, `2001:db8::`) and must be preserved.
        if (end - 1 > start && t[end - 2] === 58) break;
        if (this.#containsDoubleColon(start, end - 1)) break;
        end--;
        continue;
      }
      break;
    }
    this.#lastEnd = end;
    this.#lastSchemeAt = schemeAt;
    return i > start ? i : start + 1;
  }

  #lastEnd = 0;
  #lastSchemeAt = -1;

  #containsDoubleColon(start: number, end: number): boolean {
    const t = this.#text;
    for (let i = start; i + 1 < end; i++) if (t[i] === 58 && t[i + 1] === 58) return true;
    return false;
  }

  /** Index just past `scheme://` when the token starts with a URL scheme. */
  #schemeEnd(start: number, end: number): number {
    const t = this.#text;
    let i = start;
    if (i >= end || !isAlpha(t[i] as number)) return -1;
    i++;
    let len = 1;
    while (i < end && len < 20) {
      const c = t[i] as number;
      if (isAlnum(c) || c === 43 || c === 45 || c === 46) {
        i++;
        len++;
        continue;
      }
      break;
    }
    if (i + 2 < end && t[i] === 58 && t[i + 1] === 47 && t[i + 2] === 47) return i + 3;
    return -1;
  }

  #readToken(start: number): number {
    const resume = this.#scanToken(start);
    const end = this.#lastEnd;
    const urlAt = this.#lastSchemeAt;
    if (end <= start) return resume;

    if (urlAt >= 0) {
      // A URL may begin partway into the token (`url=http://x/y`). Everything
      // before it is classified normally; everything after the authority is
      // scanned for IPs and hashes, since query strings carry indicators.
      if (urlAt > start) this.#classifyHostLike(start, urlAt, true);
      this.#emitUrl(urlAt, end);
      const schemeEnd = this.#schemeEnd(urlAt, end);
      const authEnd = schemeEnd > 0 ? this.#authorityEnd(schemeEnd, end) : end;
      if (authEnd < end) this.#scanSubTokens(authEnd, end);
      return resume;
    }

    const at = this.#indexOfIn(start, end, 64 /* @ */);
    if (at > start) {
      const before = this.#mailCount;
      this.#emitEmail(start, end, at);
      // `user@10.0.0.1` is not an email-addr (the RHS is not a domain), but
      // the address is still an observable worth indexing.
      if (this.#mailCount === before) this.#classifyHostLike(at + 1, end, true);
      return resume;
    }

    this.#classifyHostLike(start, end, true);
    return resume;
  }

  /**
   * Classify a non-URL, non-email token: IP (with port/CIDR/zone), hash, or
   * domain. `allowDomain` is false inside URL tails.
   */
  #classifyHostLike(start: number, end: number, allowDomain: boolean): void {
    const withColon = this.#indexOfIn(start, end, 58 /* : */) >= 0;

    if (withColon) {
      // 1. Whole token as IPv6, tolerating a `%zone` suffix or a `/`-suffixed
      //    URI remainder (`2001:db8::1/path` in a proxy log). Tried first
      //    because `fe80::1` must win over a port-splitting interpretation.
      const pct = this.#indexOfIn(start, end, 37 /* % */);
      const slash = this.#indexOfIn(start, end, 47 /* / */);
      let v6End = end;
      if (pct > start) v6End = pct;
      if (slash > start && slash < v6End) v6End = slash;
      if (this.#tryIpv6(start, v6End)) return;

      const portColon = this.#lastIndexOfIn(start, end, 58);
      const hasPortTail = portColon > start && this.#isAllDigits(portColon + 1, end);

      if (hasPortTail) {
        // 2. IPv6 literal with a trailing `:port` (unbracketed in many logs).
        if (this.#tryIpv6(start, portColon)) return;
        // 3. `a.b.c.d:port`
        if (this.#tryIpv4(start, portColon)) return;
        // 4. `host.example:port`
        if (allowDomain && this.#tryDomain(start, portColon)) return;
      }
      return;
    }

    // Trailing `/prefix` (CIDR in logs).
    const slash = this.#indexOfIn(start, end, 47 /* / */);
    if (slash > start && end - slash <= 4 && this.#isAllDigits(slash + 1, end)) {
      if (this.#tryIpv4(start, slash) || this.#tryIpv6(start, slash)) return;
      return;
    }

    if (this.#looksNumericDotted(start, end)) {
      // Numeric dotted that is not a valid address is not a host either.
      this.#tryIpv4(start, end);
      return;
    }

    if (this.#isHexWord(start, end) && HASH_LENGTHS.has(end - start)) {
      this.#emitHash(start, end);
      return;
    }

    if (allowDomain) this.#tryDomain(start, end);
  }

  /** Walk `[from,to)` for IPs and hashes only (URL path/query). */
  #scanSubTokens(from: number, to: number): void {
    const t = this.#text;
    let i = from;
    while (i < to) {
      const c = t[i] as number;
      if (!isWordByte(c)) {
        i++;
        continue;
      }
      let j = i;
      // Stop at `=` as well: a query is `k=v&k=v`, and the value must be
      // classified on its own just like a `key=value` log field.
      while (j < to && !isTokenStop(t[j] as number) && t[j] !== 61) j++;
      if (j === i) {
        i++;
        continue;
      }
      let end = j;
      while (end > i) {
        const last = t[end - 1] as number;
        if (last === 46 || last === 44 || last === 59 || last === 33 || last === 63 || last === 41) end--;
        else break;
      }
      // A bare IPv4 is only seven bytes; requiring ten would skip the short
      // query values that are most common (`?ip=1.2.3.4`).
      if (end - i >= 4) {
        if (this.#indexOfIn(i, end, 58) >= 0) {
          if (!this.#tryIpv6(i, end)) {
            const portColon = this.#lastIndexOfIn(i, end, 58);
            if (portColon > i && this.#isAllDigits(portColon + 1, end)) this.#tryIpv4(i, portColon);
          }
        } else if (this.#looksNumericDotted(i, end)) {
          this.#tryIpv4(i, end);
        } else if (this.#isHexWord(i, end) && HASH_LENGTHS.has(end - i)) {
          this.#emitHash(i, end);
        }
      }
      i = j > i ? j : i + 1;
    }
  }

  #indexOfIn(start: number, end: number, byte: number): number {
    const t = this.#text;
    for (let i = start; i < end; i++) if (t[i] === byte) return i;
    return -1;
  }

  #lastIndexOfIn(start: number, end: number, byte: number): number {
    const t = this.#text;
    for (let i = end - 1; i >= start; i--) if (t[i] === byte) return i;
    return -1;
  }

  #isAllDigits(start: number, end: number): boolean {
    if (end <= start) return false;
    const t = this.#text;
    for (let i = start; i < end; i++) if (!isDigit(t[i] as number)) return false;
    return true;
  }

  #looksNumericDotted(start: number, end: number): boolean {
    const t = this.#text;
    let sawDot = false;
    let digits = 0;
    for (let i = start; i < end; i++) {
      const c = t[i] as number;
      if (c === 46) {
        sawDot = true;
        continue;
      }
      if (!isDigit(c)) return false;
      digits++;
    }
    return sawDot && digits >= 4;
  }

  #isHexWord(start: number, end: number): boolean {
    if (end <= start) return false;
    const t = this.#text;
    for (let i = start; i < end; i++) if (!isHexByte(t[i] as number)) return false;
    return true;
  }

  // -- growth ------------------------------------------------------------

  #grow2(a: Int32Array, b: Int32Array): [Int32Array<ArrayBuffer>, Int32Array<ArrayBuffer>] {
    const cap = a.length * 2;
    const na = new Int32Array(cap);
    const nb = new Int32Array(cap);
    na.set(a);
    nb.set(b);
    return [na, nb];
  }

  #emitV4(n: number, offset: number): void {
    if (this.#v4count === this.#v4n.length) {
      const [a2, b2] = this.#grow2(this.#v4n, this.#v4off);
      this.#v4n = a2;
      this.#v4off = b2;
    }
    this.#v4n[this.#v4count] = n;
    this.#v4off[this.#v4count] = offset;
    this.#v4count++;
  }

  #emitV6(w: Uint32Array, offset: number): void {
    if (this.#v6count === this.#v6off.length) {
      const cap = this.#v6off.length * 2;
      const nw = new Uint32Array(cap * 4);
      nw.set(this.#v6w);
      this.#v6w = nw;
      const no = new Int32Array(cap);
      no.set(this.#v6off);
      this.#v6off = no;
    }
    const base = this.#v6count * 4;
    this.#v6w[base] = w[0] as number;
    this.#v6w[base + 1] = w[1] as number;
    this.#v6w[base + 2] = w[2] as number;
    this.#v6w[base + 3] = w[3] as number;
    this.#v6off[this.#v6count] = offset;
    this.#v6count++;
  }

  #emitDomain(start: number, end: number): void {
    if (end <= start) return;
    if (this.#domCount === this.#domStart.length) {
      const [a2, b2] = this.#grow2(this.#domStart, this.#domEnd);
      this.#domStart = a2;
      this.#domEnd = b2;
    }
    this.#domStart[this.#domCount] = start;
    this.#domEnd[this.#domCount] = end;
    this.#domCount++;
  }

  #emitEmail(start: number, end: number, at: number): void {
    const domStart = at + 1;
    if (domStart >= end) return;
    if (!this.#isValidDomainShape(domStart, end)) return;
    // A URI scheme prefix (`mailto:a@b.com`) is not part of the address.
    let localStart = start;
    for (let i = at - 1; i >= start; i--) {
      if (this.#text[i] === 58 /* : */) {
        localStart = i + 1;
        break;
      }
    }
    if (localStart >= at) localStart = start;
    if (this.#mailCount === this.#mailStart.length) {
      const [a2, b2] = this.#grow2(this.#mailStart, this.#mailEnd);
      this.#mailStart = a2;
      this.#mailEnd = b2;
    }
    this.#mailStart[this.#mailCount] = localStart;
    this.#mailEnd[this.#mailCount] = end;
    this.#mailCount++;
    this.#emitDomain(domStart, end);
  }

  #emitHash(start: number, end: number): void {
    if (this.#hashCount === this.#hashStart.length) {
      const [a2, b2] = this.#grow2(this.#hashStart, this.#hashEnd);
      this.#hashStart = a2;
      this.#hashEnd = b2;
    }
    this.#hashStart[this.#hashCount] = start;
    this.#hashEnd[this.#hashCount] = end;
    this.#hashCount++;
  }

  #emitUrl(start: number, end: number): void {
    const schemeEnd = this.#schemeEnd(start, end);
    if (schemeEnd <= 0) return;
    const normOff = this.#normaliseUrlInto(start, end, schemeEnd);
    const authStart = schemeEnd;
    const authEnd = this.#authorityEnd(authStart, end);
    if (authEnd > authStart) {
      // Authority = [userinfo@]host[:port]
      let hostStart = authStart;
      for (let i = authStart; i < authEnd; i++) if (this.#text[i] === 64 /* @ */) hostStart = i + 1;
      if (hostStart < authEnd && this.#text[hostStart] === 91 /* [ */) {
        const close = this.#indexOfIn(hostStart, authEnd, 93);
        const litEnd = close >= 0 ? close : authEnd;
        this.#tryIpv6(hostStart + 1, litEnd);
      } else {
        const colon = this.#indexOfIn(hostStart, authEnd, 58 /* : */);
        const hostEnd = colon >= 0 ? colon : authEnd;
        if (this.#looksNumericDotted(hostStart, hostEnd)) this.#tryIpv4(hostStart, hostEnd);
        else this.#tryDomain(hostStart, hostEnd);
      }
    }
    if (normOff < 0) return;
    if (this.#urlCount === this.#urlStart.length) {
      const cap = this.#urlStart.length * 2;
      const a = new Int32Array(cap);
      const b = new Int32Array(cap);
      const c = new Int32Array(cap);
      const d = new Int32Array(cap);
      a.set(this.#urlStart);
      b.set(this.#urlEnd);
      c.set(this.#urlNormOff);
      d.set(this.#urlNormLen);
      this.#urlStart = a;
      this.#urlEnd = b;
      this.#urlNormOff = c;
      this.#urlNormLen = d;
    }
    this.#urlStart[this.#urlCount] = start;
    this.#urlEnd[this.#urlCount] = end;
    this.#urlNormOff[this.#urlCount] = normOff;
    this.#urlNormLen[this.#urlCount] = this.#normLen - normOff;
    this.#urlCount++;
  }

  #authorityEnd(from: number, end: number): number {
    const t = this.#text;
    for (let i = from; i < end; i++) {
      const c = t[i] as number;
      if (c === 47 /* / */ || c === 63 /* ? */ || c === 35 /* # */) return i;
    }
    return end;
  }

  // -- URL canonicalisation ----------------------------------------------

  #pushNorm(c: number): void {
    if (this.#normLen === this.#norm.length) {
      const bigger = new Uint8Array(this.#norm.length * 2);
      bigger.set(this.#norm);
      this.#norm = bigger;
    }
    this.#norm[this.#normLen++] = c;
  }

  #pushNormRange(start: number, end: number, lower: boolean): void {
    const t = this.#text;
    for (let i = start; i < end; i++) {
      const c = t[i] as number;
      this.#pushNorm(lower && c >= 65 && c <= 90 ? c + 32 : c);
    }
  }

  #pushNormLowerAscii(s: string): void {
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      this.#pushNorm(c >= 65 && c <= 90 ? c + 32 : c);
    }
  }

  /**
   * Canonicalise `[start,end)` into the scratch buffer, returning the offset.
   * Matches `normaliseUrl()` in `stix/compile.ts` exactly: lowercase scheme
   * and host, drop userinfo case-sensitivity, drop the default port for
   * http/https, drop a lone trailing slash, keep path case.
   */
  #normaliseUrlInto(start: number, end: number, schemeEnd: number): number {
    const t = this.#text;
    const off = this.#normLen;

    let isHttp = false;
    let isHttps = false;
    {
      let lowerScheme = "";
      for (let i = start; i < schemeEnd - 3; i++) lowerScheme += String.fromCharCode(t[i] as number).toLowerCase();
      isHttp = lowerScheme === "http";
      isHttps = lowerScheme === "https";
      this.#pushNormLowerAscii(lowerScheme);
    }
    this.#pushNorm(58);
    this.#pushNorm(47);
    this.#pushNorm(47);

    const authEnd = this.#authorityEnd(schemeEnd, end);
    let hostStart = schemeEnd;
    for (let i = schemeEnd; i < authEnd; i++) if (t[i] === 64 /* @ */) hostStart = i + 1;
    // Userinfo: preserved byte-exact (it is case-sensitive).
    this.#pushNormRange(schemeEnd, hostStart, false);

    let hostEnd: number;
    let portStart = -1;
    if (hostStart < authEnd && t[hostStart] === 91 /* [ */) {
      const close = this.#indexOfIn(hostStart, authEnd, 93);
      hostEnd = close >= 0 ? close + 1 : authEnd;
      if (hostEnd < authEnd && t[hostEnd] === 58) portStart = hostEnd;
    } else {
      const colon = this.#indexOfIn(hostStart, authEnd, 58);
      hostEnd = colon >= 0 ? colon : authEnd;
      if (colon >= 0) portStart = colon;
    }
    this.#pushNormRange(hostStart, hostEnd, true);

    if (portStart >= 0) {
      const portLen = authEnd - portStart - 1;
      const is80 = portLen === 2 && t[portStart + 1] === 56 && t[portStart + 2] === 48;
      const is443 = portLen === 3 && t[portStart + 1] === 52 && t[portStart + 2] === 52 && t[portStart + 3] === 51;
      if (!((isHttp && is80) || (isHttps && is443))) this.#pushNormRange(portStart, authEnd, false);
    }

    let tailStart = authEnd;
    let tailEnd = end;
    if (tailEnd - tailStart === 1 && t[tailStart] === 47) tailEnd = tailStart;
    this.#pushNormRange(tailStart, tailEnd, false);
    return off;
  }

  // -- validators --------------------------------------------------------

  #tryIpv4(start: number, end: number): boolean {
    const n = parseIpv4N(this.#text, start, end);
    if (n < 0) return false;
    // An IPv4-mapped-looking dotted quad adjacent to more octets is not an IP;
    // `parseIpv4N` already enforces exactly four octets within the span.
    this.#emitV4(n, start);
    return true;
  }

  #tryIpv6(start: number, end: number): boolean {
    const addr = parseIpv6Bytes(this.#text, start, end);
    if (addr === null) return false;
    this.#emitV6(addr.w, start);
    return true;
  }

  #tryDomain(start: number, end: number): boolean {
    if (!this.#isValidDomainShape(start, end)) return false;
    this.#emitDomain(start, end);
    return true;
  }

  #isValidDomainShape(start: number, end: number): boolean {
    const len = end - start;
    if (len < 4 || len > 253) return false;
    const t = this.#text;
    let labels = 0;
    let labelLen = 0;
    let tldStart = -1;
    for (let i = start; i < end; i++) {
      const c = t[i] as number;
      if (c === 46 /* . */) {
        if (labelLen === 0) return false;
        labels++;
        labelLen = 0;
        tldStart = i + 1;
      } else if (isAlnum(c) || c === 45 || c === 95) {
        labelLen++;
        if (labelLen > 63) return false;
      } else {
        return false;
      }
    }
    if (labelLen === 0) return false;
    labels++;
    if (labels < 2 || tldStart < 0) return false;
    if (end - tldStart < 2) return false;
    return isAlpha(t[tldStart] as number);
  }
}
