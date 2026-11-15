/**
 * Open-addressing hash map keyed by byte spans.
 *
 * Exact-value lookups (URL, email, file hash) run once per candidate token, so
 * allocating a JS string for every token just to use a `Map` would dominate GC
 * time on multi-GB input. Keys are stored as canonical bytes and compared
 * against the input span directly: text keys compare ASCII case-insensitively
 * (URLs/emails are case-insensitive where it matters), hash keys compare
 * byte-exact after hex decoding.
 *
 * The map is immutable after `build()`, so workers share it freely.
 */

const FNV_OFFSET = 0x811c9dc5;
const FNV_PRIME = 0x01000193;

function hashBytes(bytes: Uint8Array, start: number, end: number, caseInsensitive: boolean): number {
  let h = FNV_OFFSET;
  if (caseInsensitive) {
    for (let i = start; i < end; i++) {
      const c = bytes[i] as number;
      h = Math.imul(h ^ (c >= 65 && c <= 90 ? c + 32 : c), FNV_PRIME) >>> 0;
    }
  } else {
    for (let i = start; i < end; i++) {
      h = Math.imul(h ^ (bytes[i] as number), FNV_PRIME) >>> 0;
    }
  }
  return h >>> 0;
}

interface Slot {
  readonly hash: number;
  readonly key: Uint8Array;
  readonly payload: number;
}

export class ByteMap {
  readonly #caseInsensitive: boolean;
  #slots: Array<Slot | undefined>;
  #count = 0;
  #mask: number;

  constructor(caseInsensitive: boolean, expected = 16) {
    this.#caseInsensitive = caseInsensitive;
    let cap = 16;
    while (cap < expected * 2) cap <<= 1;
    this.#slots = new Array<Slot | undefined>(cap).fill(undefined);
    this.#mask = cap - 1;
  }

  get size(): number {
    return this.#count;
  }

  #canonical(key: Uint8Array): Uint8Array {
    if (!this.#caseInsensitive) return key;
    const out = new Uint8Array(key.length);
    for (let i = 0; i < key.length; i++) {
      const c = key[i] as number;
      out[i] = c >= 65 && c <= 90 ? c + 32 : c;
    }
    return out;
  }

  insert(key: Uint8Array, payload: number): void {
    const canonical = this.#canonical(key);
    const h = hashBytes(canonical, 0, canonical.length, this.#caseInsensitive);
    this.#put(h, canonical, payload);
  }

  #put(h: number, key: Uint8Array, payload: number): void {
    // Resize at 75% occupancy to keep probe chains short.
    if ((this.#count + 1) * 4 > this.#slots.length * 3) this.#resize();
    let idx = h & this.#mask;
    for (;;) {
      const slot = this.#slots[idx];
      if (slot === undefined) {
        this.#slots[idx] = { hash: h, key, payload };
        this.#count++;
        return;
      }
      if (slot.hash === h && slot.key.length === key.length) {
        // Last insert wins for duplicate keys; compiled programs dedupe atoms
        // before the map is built, so equal payloads are the norm.
        this.#slots[idx] = { hash: h, key, payload };
        return;
      }
      idx = (idx + 1) & this.#mask;
    }
  }

  #resize(): void {
    const old = this.#slots;
    const cap = old.length << 1;
    this.#slots = new Array<Slot | undefined>(cap).fill(undefined);
    this.#mask = cap - 1;
    this.#count = 0;
    for (const slot of old) {
      if (slot !== undefined) this.#put(slot.hash, slot.key, slot.payload);
    }
  }

  /** Look up a span. Returns the payload, or -1 when absent. */
  lookup(bytes: Uint8Array, start: number, end: number): number {
    if (this.#count === 0) return -1;
    const h = hashBytes(bytes, start, end, this.#caseInsensitive);
    let idx = h & this.#mask;
    for (;;) {
      const slot = this.#slots[idx];
      if (slot === undefined) return -1;
      if (slot.hash === h && slot.key.length === end - start) {
        const key = slot.key;
        if (this.#caseInsensitive) {
          let same = true;
          for (let i = 0; i < key.length; i++) {
            const a = key[i] as number;
            const b0 = bytes[start + i] as number;
            const b = b0 >= 65 && b0 <= 90 ? b0 + 32 : b0;
            if (a !== b) {
              same = false;
              break;
            }
          }
          if (same) return slot.payload;
        } else {
          let same = true;
          for (let i = 0; i < key.length; i++) {
            if ((key[i] as number) !== (bytes[start + i] as number)) {
              same = false;
              break;
            }
          }
          if (same) return slot.payload;
        }
      }
      idx = (idx + 1) & this.#mask;
    }
  }
}
