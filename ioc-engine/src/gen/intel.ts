import { mulberry32, pick, randInt, randHex, randUuid } from '../random';
import { StixBundle, StixObject } from '../types';

const TLDS = ['com', 'net', 'org', 'io', 'cn', 'ru', 'top', 'xyz', 'info', 'biz'];
const WORDS = [
  'update', 'secure', 'cdn', 'api', 'mail', 'login', 'track', 'ads', 'stat',
  'cloud', 'sync', 'pay', 'auth', 'gate', 'node', 'edge', 'cache', 'img',
];
const URL_PATHS = ['download', 'gate', 'api/v1', 'static', 'img', 'js', 'beacon', 'collect'];

function domain(rand: () => number): string {
  return `${pick(rand, WORDS)}-${randHex(rand, 6)}.${pick(rand, TLDS)}`;
}
function ipv4(rand: () => number): string {
  return `${randInt(rand, 11, 223)}.${randInt(rand, 0, 255)}.${randInt(rand, 0, 255)}.${randInt(rand, 1, 254)}`;
}
function cidr(rand: () => number): string {
  const prefix = pick(rand, [16, 20, 24]);
  if (prefix === 24) return `${randInt(rand, 11, 223)}.${randInt(rand, 0, 255)}.${randInt(rand, 0, 255)}.0/24`;
  if (prefix === 20) return `${randInt(rand, 11, 223)}.${randInt(rand, 0, 240)}.0.0/20`;
  return `${randInt(rand, 11, 223)}.${randInt(rand, 0, 255)}.0.0/16`;
}
function url(rand: () => number): string {
  return `http://${domain(rand)}/${pick(rand, URL_PATHS)}/${randHex(rand, 8)}.php`;
}
function hashOf(rand: () => number): { algo: string; len: number } {
  return pick(rand, [
    { algo: 'MD5', len: 32 },
    { algo: 'SHA-1', len: 40 },
    { algo: 'SHA-256', len: 64 },
    { algo: 'SHA-256', len: 64 },
  ]);
}

/** Patterns the engine deliberately does not support (must be skipped + reported). */
function unsupportedPattern(rand: () => number): string {
  return pick(rand, [
    `[domain-name:value MATCHES '.*${randHex(rand, 4)}\\\\.com']`,
    `[file:name LIKE '%${randHex(rand, 4)}.exe']`,
    `[network-traffic:dst_port = ${randInt(rand, 1, 65535)}]`,
    `[ipv4-addr:value != '${ipv4(rand)}']`,
    `[file:hashes.'SHA-256' = '${randHex(rand, 64)}'] FOLLOWEDBY [ipv4-addr:value = '${ipv4(rand)}']`,
    `[process:command_line CONTAINS '${randHex(rand, 6)}']`,
    `[domain-name:value = '${domain(rand)}' AND domain-name:resolves_to_refs[*].value = '${ipv4(rand)}']`,
  ]);
}

function supportedPattern(rand: () => number): string {
  const kind = rand();
  if (kind < 0.34) return `[domain-name:value = '${domain(rand)}']`;
  if (kind < 0.52) return `[ipv4-addr:value = '${ipv4(rand)}']`;
  if (kind < 0.56) return `[ipv6-addr:value = '2001:db8:${randHex(rand, 4)}::${randHex(rand, 4)}']`;
  if (kind < 0.66) return `[ipv4-addr:value ISSUBSET '${cidr(rand)}']`;
  if (kind < 0.78) return `[url:value = '${url(rand)}']`;
  if (kind < 0.90) {
    const h = hashOf(rand);
    return `[file:hashes.'${h.algo}' = '${randHex(rand, h.len)}']`;
  }
  if (kind < 0.94) {
    return `[ipv4-addr:value = '${ipv4(rand)}' AND domain-name:value = '${domain(rand)}']`;
  }
  if (kind < 0.97) {
    return `[domain-name:value = '${domain(rand)}'] OR [url:value = '${url(rand)}']`;
  }
  return `[domain-name:value IN ('${domain(rand)}', '${domain(rand)}', '${domain(rand)}')]`;
}

/**
 * Generate a synthetic STIX 2.1 bundle. Mix: ~92% supported patterns,
 * ~5% unsupported syntax, ~5% expired, ~3% revoked (flags stack on top).
 */
export function generateIntel(count: number, seed: number): StixBundle {
  const rand = mulberry32(seed);
  const objects: StixObject[] = [];
  const now = Date.now();
  const day = 86400_000;

  for (let i = 0; i < count; i++) {
    const unsupported = rand() < 0.05;
    const pattern = unsupported ? unsupportedPattern(rand) : supportedPattern(rand);
    const ind: Record<string, unknown> = {
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${randUuid(rand)}`,
      created: new Date(now - randInt(rand, 1, 90) * day).toISOString(),
      modified: new Date(now - randInt(rand, 0, 10) * day).toISOString(),
      name: `synthetic-ioc-${i}`,
      pattern,
      pattern_type: 'stix',
      valid_from: new Date(now - randInt(rand, 1, 30) * day).toISOString(),
      confidence: randInt(rand, 10, 100),
    };
    if (rand() < 0.05) {
      ind.valid_until = new Date(now - randInt(rand, 1, 10) * day).toISOString(); // expired
    } else if (rand() < 0.5) {
      ind.valid_until = new Date(now + randInt(rand, 1, 180) * day).toISOString(); // still valid
    }
    if (rand() < 0.03) ind.revoked = true;
    objects.push(ind as unknown as StixObject);
  }

  return {
    type: 'bundle',
    id: `bundle--${randUuid(rand)}`,
    objects,
  };
}
