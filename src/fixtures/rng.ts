/**
 * Deterministic PRNG helpers for fixtures and benchmarks.
 *
 * `Math.random()` is deliberately not used: test data and the ground-truth
 * files derived from it must be byte-identical across runs and machines so a
 * regression can be reproduced from an issue.
 */

/** xoshiro128**-style 32-bit generator; small, fast, good enough for fixtures. */
export class Rng {
  #s0: number;
  #s1: number;
  #s2: number;
  #s3: number;

  constructor(seed: number) {
    // SplitMix32 seeding so small/adjacent seeds give unrelated streams.
    let x = seed >>> 0;
    const next = (): number => {
      x = (x + 0x9e3779b9) >>> 0;
      let z = x;
      z = Math.imul(z ^ (z >>> 16), 0x85ebca6b) >>> 0;
      z = Math.imul(z ^ (z >>> 13), 0xc2b2ae35) >>> 0;
      return (z ^ (z >>> 16)) >>> 0;
    };
    this.#s0 = next();
    this.#s1 = next();
    this.#s2 = next();
    this.#s3 = next();
  }

  /** Uniform uint32. */
  nextU32(): number {
    const s1 = Math.imul(this.#s1, 5) >>> 0;
    const result = (Math.imul(((s1 << 7) | (s1 >>> 25)) >>> 0, 9) >>> 0) >>> 0;
    const t = (this.#s1 << 9) >>> 0;
    this.#s2 = (this.#s2 ^ this.#s0) >>> 0;
    this.#s3 = (this.#s3 ^ this.#s1) >>> 0;
    this.#s1 = (this.#s1 ^ this.#s2) >>> 0;
    this.#s0 = (this.#s0 ^ this.#s3) >>> 0;
    this.#s2 = (this.#s2 ^ t) >>> 0;
    this.#s3 = ((this.#s3 << 11) | (this.#s3 >>> 21)) >>> 0;
    return result;
  }

  /** Uniform integer in [0, n). */
  int(n: number): number {
    return n <= 0 ? 0 : this.nextU32() % n;
  }

  /** Uniform integer in [lo, hi]. */
  range(lo: number, hi: number): number {
    return lo + this.int(hi - lo + 1);
  }

  /** Uniform float in [0, 1). */
  float(): number {
    return this.nextU32() / 0x100000000;
  }

  /** Pick one element. */
  pick<T>(items: readonly T[]): T {
    return items[this.int(items.length)] as T;
  }

  /** Fisher-Yates, in place. */
  shuffle<T>(items: T[]): T[] {
    for (let i = items.length - 1; i > 0; i--) {
      const j = this.int(i + 1);
      const tmp = items[i] as T;
      items[i] = items[j] as T;
      items[j] = tmp;
    }
    return items;
  }

  /** `true` with probability p. */
  chance(p: number): boolean {
    return this.float() < p;
  }

  /** Lowercase hex string of `n` characters. */
  hex(n: number): string {
    const digits = "0123456789abcdef";
    let s = "";
    for (let i = 0; i < n; i++) s += digits[this.int(16)];
    return s;
  }
}

/** Stable 64-bit-ish FNV of a string, for deterministic id derivation. */
export function stableHash(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h = Math.imul(h ^ s.charCodeAt(i), 0x01000193) >>> 0;
  }
  return h >>> 0;
}
