/**
 * Multi-pattern domain indicator matching.
 *
 * A domain indicator is a *suffix at a label boundary* of a hostname:
 * `evil.com` must fire for `mail.evil.com` and `evil.com` but not for
 * `notevil.com` or `evil.com.attacker.net`. Two facts shape the design:
 *
 *   1. The engine only treats extracted *hosts* as domain candidates (see
 *      `extract/extractor.ts`). A domain string buried in a URL path, a JSON
 *      blob value or prose is not a hostname occurrence, so matching hosts —
 *      not raw line text — removes an entire class of false positives that a
 *      plain substring search cannot.
 *   2. Reversing makes suffix matching a prefix match: `evil.com` is a suffix
 *      of host `mail.evil.com` exactly when `moc.live` is a prefix of the
 *      reversed host `moc.live.liam`.
 *
 * So all candidate hosts are written, reversed, into one scratch buffer with a
 * NUL separator, and a single Aho-Corasick pass finds every indicator that is
 * a prefix of some reversed host. A hit is accepted only when
 *
 *   - it starts exactly at a host's start offset (prefix, not infix), and
 *   - the byte after it is NUL or `.` (label boundary, not `evil.comX`).
 *
 * Cost is one automaton pass over the (short) concatenated hosts, independent
 * of how many domain indicators there are.
 */

import { AhoCorasick } from "./aho-corasick.ts";

export interface DomainEntry {
  /** Normalised indicator domain (lowercase, no trailing dot). */
  readonly key: string;
  readonly atomId: number;
}

export interface DomainHitSink {
  (atomId: number, hostIndex: number): void;
}

export class DomainMatcher {
  readonly #ac: AhoCorasick;
  /** Pattern id -> atom id. */
  readonly #atomIds: number[];
  /** Pattern id -> indicator key length in bytes. */
  readonly #lengths: number[];

  constructor(entries: readonly DomainEntry[]) {
    const patterns: Uint8Array[] = [];
    const atomIds: number[] = [];
    const lengths: number[] = [];
    for (const e of entries) {
      const bytes = new Uint8Array(e.key.length);
      for (let i = 0; i < e.key.length; i++) bytes[i] = e.key.charCodeAt(i) & 0xff;
      const rev = new Uint8Array(bytes.length);
      for (let i = 0; i < bytes.length; i++) rev[i] = bytes[bytes.length - 1 - i] as number;
      patterns.push(rev);
      atomIds.push(e.atomId);
      lengths.push(rev.length);
    }
    this.#ac = new AhoCorasick(patterns);
    this.#atomIds = atomIds;
    this.#lengths = lengths;
  }

  get numPatterns(): number {
    return this.#ac.numPatterns;
  }

  get numStates(): number {
    return this.#ac.numStates;
  }

  /**
   * Scan a reversed-host buffer produced by `HostBuffer`. `hostStarts[i]` is
   * the offset of host `i`; `hostStarts` must be ascending.
   */
  scanHosts(reversed: Uint8Array, hostStarts: Int32Array, sink: DomainHitSink): void {
    const atomIds = this.#atomIds;
    const lengths = this.#lengths;
    this.#ac.scan(reversed, (pid, end) => {
      const len = lengths[pid] as number;
      const start = end - len + 1;
      // Must be a prefix of a host: the hit start has to be a known host start.
      const hostIndex = binarySearch(hostStarts, start);
      if (hostIndex < 0) return;
      // Prefix match, so the whole host was consumed when it ends exactly here
      // or the next byte starts a new label.
      const next = end + 1;
      if (next < reversed.length) {
        const c = reversed[next] as number;
        if (c !== 0 && c !== 46 /* . */) return;
      }
      sink(atomIds[pid] as number, hostIndex);
    });
  }
}

function binarySearch(sorted: Int32Array, value: number): number {
  let lo = 0;
  let hi = sorted.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const v = sorted[mid] as number;
    if (v === value) return mid;
    if (v < value) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

/**
 * Accumulates reversed host names for one line.
 *
 * The separator is NUL, which cannot appear in a normalised hostname, so no
 * automaton pattern can straddle two hosts.
 */
export class HostBuffer {
  #buf = new Uint8Array(256);
  #len = 0;
  #starts = new Int32Array(16);
  #count = 0;

  reset(): void {
    this.#len = 0;
    this.#count = 0;
  }

  get count(): number {
    return this.#count;
  }

  get buffer(): Uint8Array {
    return this.#buf.subarray(0, this.#len);
  }

  get starts(): Int32Array {
    return this.#starts.subarray(0, this.#count);
  }

  /** Append one host from `[start,end)`, lowercased and reversed. */
  addHost(text: Uint8Array, start: number, end: number): void {
    // A fully-qualified name with a root dot is the same host; the extractor
    // already trims it, but accepting both here keeps the matcher independent
    // of that detail.
    while (end > start && text[end - 1] === 46) end--;
    if (end <= start) return;
    const need = this.#len + (end - start) + 1;
    if (need > this.#buf.length) {
      let cap = this.#buf.length;
      while (cap < need) cap *= 2;
      const bigger = new Uint8Array(cap);
      bigger.set(this.#buf.subarray(0, this.#len));
      this.#buf = bigger;
    }
    if (this.#count === this.#starts.length) {
      const bigger = new Int32Array(this.#starts.length * 2);
      bigger.set(this.#starts);
      this.#starts = bigger;
    }
    this.#starts[this.#count++] = this.#len;
    // Fill from the end so the bytes land reversed in one pass.
    let write = this.#len + (end - start) - 1;
    for (let i = start; i < end; i++) {
      let c = text[i] as number;
      if (c >= 65 && c <= 90) c += 32;
      this.#buf[write--] = c;
    }
    this.#len += end - start;
    this.#buf[this.#len++] = 0;
  }
}
