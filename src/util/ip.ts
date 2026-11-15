/**
 * IP parsing / formatting / prefix arithmetic.
 *
 * Everything on the scan hot path is byte-oriented: log lines are handled as
 * `Uint8Array` and an address is never turned into a JS string just to be
 * looked up. IPv4 is a uint32 and IPv6 is four uint32 words, so the prefix
 * tries never touch BigInt (far too slow per-IP) and `formatIp*` is only used
 * for output and diagnostics.
 */

export interface Ipv4Addr {
  readonly version: 4;
  readonly n: number;
}

export interface Ipv6Addr {
  readonly version: 6;
  readonly w: Uint32Array;
}

export type IpAddr = Ipv4Addr | Ipv6Addr;

export interface Cidr {
  readonly addr: IpAddr;
  readonly prefix: number;
}

const V4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const V4_MASK = 0xffffffff;

function hexVal(c: number): number {
  if (c >= 48 && c <= 57) return c - 48;
  if (c >= 97 && c <= 102) return c - 87;
  if (c >= 65 && c <= 70) return c - 55;
  return -1;
}

export function isDigitByte(c: number): boolean {
  return c >= 48 && c <= 57;
}

/**
 * Parse dotted-quad from bytes. Rejects leading zeros (`010.0.0.1`), octets
 * over 255, empty octets and anything that is not exactly four octets.
 */
export function parseIpv4Bytes(b: Uint8Array, start: number, end: number): Ipv4Addr | null {
  const n = parseIpv4N(b, start, end);
  return n < 0 ? null : { version: 4, n };
}

/** Allocation-free form of `parseIpv4Bytes`: -1 on failure, else uint32. */
export function parseIpv4N(b: Uint8Array, start: number, end: number): number {
  const len = end - start;
  if (len < 7 || len > 15) return -1;
  let n = 0;
  let octet = 0;
  let digits = 0;
  let dots = 0;
  for (let i = start; i < end; i++) {
    const c = b[i] as number;
    if (c === 46 /* . */) {
      if (digits === 0) return -1;
      if (digits > 1 && b[i - digits] === 48) return -1;
      n = ((n << 8) | octet) >>> 0;
      octet = 0;
      digits = 0;
      dots++;
      if (dots > 3) return -1;
    } else if (c >= 48 && c <= 57) {
      if (++digits > 3) return -1;
      octet = octet * 10 + (c - 48);
      if (octet > 255) return -1;
    } else {
      return -1;
    }
  }
  if (digits === 0 || dots !== 3) return -1;
  if (digits > 1 && b[end - digits] === 48) return -1;
  n = ((n << 8) | octet) >>> 0;
  return n >>> 0;
}

export function parseIpv4(s: string): Ipv4Addr | null {
  if (!V4_RE.test(s)) return null;
  return parseIpv4Bytes(Buffer.from(s, "latin1"), 0, s.length);
}

interface GroupResult {
  readonly groups: number[];
  readonly ok: boolean;
}

/** Parse colon-separated hex groups, with one optional embedded IPv4 tail. */
function parseHexGroups(b: Uint8Array, start: number, end: number, allowV4Tail: boolean): GroupResult | null {
  const groups: number[] = [];
  if (start === end) return { groups, ok: true };
  let i = start;
  let groupStart = start;
  let isLast = false;
  for (;;) {
    while (i < end && b[i] !== 58 /* : */) i++;
    isLast = i >= end;
    const gs = groupStart;
    const ge = i;
    if (ge === gs) return null; // empty group => ":::" or leading/trailing ':'
    let dot = -1;
    for (let k = gs; k < ge; k++) {
      if (b[k] === 46) {
        dot = k;
        break;
      }
    }
    if (dot >= 0) {
      if (!allowV4Tail) return null;
      const v4 = parseIpv4Bytes(b, gs, ge);
      if (v4 === null) return null;
      groups.push((v4.n >>> 16) & 0xffff, v4.n & 0xffff);
      if (!isLast) return null;
      return { groups, ok: true };
    }
    if (ge - gs > 4) return null;
    let v = 0;
    for (let k = gs; k < ge; k++) {
      const d = hexVal(b[k] as number);
      if (d < 0) return null;
      v = (v << 4) | d;
    }
    groups.push(v);
    if (isLast) return { groups, ok: true };
    i++; // skip ':'
    groupStart = i;
  }
}

function groupsToAddr(g: number[]): Ipv6Addr | null {
  if (g.length !== 8) return null;
  const w = new Uint32Array(4);
  for (let i = 0; i < 4; i++) {
    // Shifting a group above 0x7fff overflows a signed 32-bit intermediate,
    // so the high half must be shifted before the OR and the result forced
    // unsigned. Without the explicit `>>> 0` on the shift, `0x8000 << 16`
    // becomes a negative number and the OR corrupts the low group.
    const hi = ((g[i * 2] as number) << 16) >>> 0;
    w[i] = (hi | (g[i * 2 + 1] as number)) >>> 0;
  }
  return { version: 6, w };
}

/** Parse an IPv6 literal from bytes. Zone ids (`%eth0`) are not accepted. */
export function parseIpv6Bytes(b: Uint8Array, start: number, end: number): Ipv6Addr | null {
  const len = end - start;
  if (len < 2 || len > 45) return null;
  // Locate "::" (at most one).
  let dc = -1;
  for (let i = start; i < end - 1; i++) {
    if (b[i] === 58 && b[i + 1] === 58) {
      if (dc >= 0) return null;
      dc = i;
      i++;
    }
  }
  if (dc < 0) {
    const r = parseHexGroups(b, start, end, true);
    if (r === null || !r.ok) return null;
    return groupsToAddr(r.groups);
  }
  const head = parseHexGroups(b, start, dc, false);
  if (head === null || !head.ok) return null;
  const tailStart = dc + 2;
  const tail = parseHexGroups(b, tailStart, end, true);
  if (tail === null || !tail.ok) return null;
  const missing = 8 - head.groups.length - tail.groups.length;
  if (missing < 1) return null;
  const all = head.groups.concat(new Array<number>(missing).fill(0), tail.groups);
  return groupsToAddr(all);
}

/** Parse an IPv6 literal from a string (tests, config, diagnostics). */
export function parseIpv6(s: string): Ipv6Addr | null {
  if (s.indexOf(":") < 0 || s.length > 45) return null;
  return parseIpv6Bytes(Buffer.from(s, "latin1"), 0, s.length);
}

export function parseIp(s: string): IpAddr | null {
  return parseIpv4(s) ?? parseIpv6(s);
}

export function formatIpv4(n: number): string {
  return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}

/** RFC 5952 canonical text form (longest zero run compressed, lowercase). */
export function formatIpv6(w: Uint32Array): string {
  const g: number[] = new Array(8);
  for (let i = 0; i < 8; i++) {
    const word = w[i >> 1] as number;
    g[i] = i % 2 === 0 ? (word >>> 16) & 0xffff : word & 0xffff;
  }
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (g[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i >= 2 && j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = (v: number): string => v.toString(16);
  if (bestStart < 0) return g.map(hex).join(":");
  const left = g.slice(0, bestStart).map(hex).join(":");
  const right = g.slice(bestStart + bestLen).map(hex).join(":");
  return `${left}::${right}`;
}

export function formatIp(addr: IpAddr): string {
  return addr.version === 4 ? formatIpv4(addr.n) : formatIpv6(addr.w);
}

export function parseCidr(s: string): Cidr | null {
  const slash = s.indexOf("/");
  if (slash < 0) return null;
  const addr = parseIp(s.slice(0, slash));
  if (addr === null) return null;
  const p = s.slice(slash + 1);
  if (p.length === 0 || p.length > 3) return null;
  let prefix = 0;
  for (let i = 0; i < p.length; i++) {
    const c = p.charCodeAt(i);
    if (c < 48 || c > 57) return null;
    prefix = prefix * 10 + (c - 48);
  }
  const max = addr.version === 4 ? 32 : 128;
  if (prefix > max) return null;
  return { addr, prefix };
}

export function ipv4Mask(prefix: number): number {
  if (prefix <= 0) return 0;
  if (prefix >= 32) return V4_MASK;
  return (V4_MASK << (32 - prefix)) >>> 0;
}

export function ipv4InPrefix(ip: number, network: number, prefix: number): boolean {
  if (prefix === 0) return true;
  return (((ip >>> 0) & ipv4Mask(prefix)) >>> 0) === (((network >>> 0) & ipv4Mask(prefix)) >>> 0);
}

export function ipv6InPrefix(ip: Uint32Array, network: Uint32Array, prefix: number): boolean {
  let remaining = prefix;
  for (let i = 0; i < 4 && remaining > 0; i++) {
    const take = Math.min(32, remaining);
    const mask = take >= 32 ? V4_MASK : (V4_MASK << (32 - take)) >>> 0;
    if (((((ip[i] as number) ^ (network[i] as number)) >>> 0) & mask) >>> 0 !== 0) return false;
    remaining -= take;
  }
  return true;
}

/** Clear host bits so an address can be inserted into a prefix trie. */
export function cidrNetwork(c: Cidr): Cidr {
  if (c.addr.version === 4) {
    return { addr: { version: 4, n: (c.addr.n & ipv4Mask(c.prefix)) >>> 0 }, prefix: c.prefix };
  }
  const w = new Uint32Array(4);
  let remaining = c.prefix;
  for (let i = 0; i < 4; i++) {
    const take = Math.min(32, remaining);
    const mask = take <= 0 ? 0 : take >= 32 ? V4_MASK : (V4_MASK << (32 - take)) >>> 0;
    w[i] = (((c.addr.w[i] as number) & mask) >>> 0);
    remaining -= take;
  }
  return { addr: { version: 6, w }, prefix: c.prefix };
}
