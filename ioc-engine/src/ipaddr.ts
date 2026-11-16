/** IP/CIDR parsing helpers. Addresses are represented as bigint (32 or 128 bits). */

export function parseV4(s: string): bigint | null {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let v = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    // reject things like "01" ambiguity? keep permissive
    v = (v << 8n) | BigInt(n);
  }
  return v;
}

export function formatV4(v: bigint): string {
  const parts: string[] = [];
  for (let i = 3; i >= 0; i--) parts.push(String((v >> BigInt(i * 8)) & 0xffn));
  return parts.join('.');
}

export function parseV6(s: string): bigint | null {
  if (s.includes('.')) return null; // embedded IPv4 not supported
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parseGroups = (g: string): number[] | null => {
    if (g === '') return [];
    const out: number[] = [];
    for (const h of g.split(':')) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(h)) return null;
      out.push(parseInt(h, 16));
    }
    return out;
  };
  const left = parseGroups(halves[0]);
  if (left === null) return null;
  let groups: number[];
  if (halves.length === 2) {
    const right = parseGroups(halves[1]);
    if (right === null) return null;
    if (left.length + right.length > 7) return null;
    groups = [...left, ...new Array(8 - left.length - right.length).fill(0), ...right];
  } else {
    if (left.length !== 8) return null;
    groups = left;
  }
  let v = 0n;
  for (const g of groups) v = (v << 16n) | BigInt(g);
  return v;
}

export function isV6Address(s: string): boolean {
  return s.includes(':');
}

export interface ParsedCidr {
  key: bigint;
  bits: number; // address width: 32 or 128
  prefixLen: number;
  canonical: string;
}

export function parseCidr(s: string): ParsedCidr | null {
  const slash = s.lastIndexOf('/');
  if (slash === -1) return null;
  const addr = s.slice(0, slash).trim();
  const lenStr = s.slice(slash + 1).trim();
  if (!/^\d{1,3}$/.test(lenStr)) return null;
  const prefixLen = Number(lenStr);
  if (isV6Address(addr)) {
    const key = parseV6(addr);
    if (key === null || prefixLen > 128) return null;
    return { key, bits: 128, prefixLen, canonical: `${addr}/${prefixLen}` };
  }
  const key = parseV4(addr);
  if (key === null || prefixLen > 32) return null;
  return { key, bits: 32, prefixLen, canonical: `${formatV4(key)}/${prefixLen}` };
}

/** Random address inside a CIDR (used by the log generator). */
export function randomIpInCidr(cidr: ParsedCidr, rand: () => number): string {
  const hostBits = BigInt(cidr.bits - cidr.prefixLen);
  let r = 0n;
  for (let i = 0n; i < hostBits; i += 32n) {
    r = (r << 32n) | BigInt(Math.floor(rand() * 0x100000000));
  }
  const mask = hostBits === 0n ? 0n : (1n << hostBits) - 1n;
  const ip = cidr.key | (r & mask);
  if (cidr.bits === 32) return formatV4(ip);
  // format v6
  const groups: string[] = [];
  for (let i = 7; i >= 0; i--) groups.push(((ip >> BigInt(i * 16)) & 0xffffn).toString(16));
  return groups.join(':');
}
