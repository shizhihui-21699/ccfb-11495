/** Deterministic PRNG (mulberry32) so generated intel/logs are reproducible. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function pick<T>(rand: () => number, arr: readonly T[]): T {
  return arr[Math.floor(rand() * arr.length)];
}

export function randInt(rand: () => number, lo: number, hi: number): number {
  return lo + Math.floor(rand() * (hi - lo + 1));
}

const HEX = '0123456789abcdef';
export function randHex(rand: () => number, len: number): string {
  let s = '';
  for (let i = 0; i < len; i++) s += HEX[Math.floor(rand() * 16)];
  return s;
}

export function randUuid(rand: () => number): string {
  return (
    randHex(rand, 8) + '-' + randHex(rand, 4) + '-4' + randHex(rand, 3) +
    '-' + pick(rand, ['8', '9', 'a', 'b']) + randHex(rand, 3) + '-' + randHex(rand, 12)
  );
}
