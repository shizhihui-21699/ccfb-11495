/**
 * Prefix trie for CIDR containment lookups.
 *
 * One structure serves both families: `bits` is 32 for IPv4 (keys are a
 * uint32) or 128 for IPv6 (keys are four uint32 words). Each node stores its
 * two children plus the payloads of any prefixes terminating there. A lookup
 * walks at most `bits` links and collects payloads from *every* prefix on the
 * path, which gives true longest-prefix semantics: a /32 indicator still fires
 * inside a /8 indicator's range, and a /8 indicator fires for any address
 * beneath it.
 *
 * Nodes are flat typed arrays. With hundreds of thousands of intelligence
 * prefixes, per-node objects would cost far too much memory and destroy cache
 * locality. The two insert/lookup paths are separate so the hot loop contains
 * no per-bit family branching.
 */

export class PrefixTrie {
  readonly bits: number;
  #c0: Int32Array;
  #c1: Int32Array;
  /** Head of the payload list per node, -1 = none. */
  #head: Int32Array;
  readonly #next: number[] = [];
  readonly #payloads: number[] = [];
  #numNodes = 1;

  constructor(bits: 32 | 128, capacityNodes = 1024) {
    this.bits = bits;
    this.#c0 = new Int32Array(capacityNodes).fill(-1);
    this.#c1 = new Int32Array(capacityNodes).fill(-1);
    this.#head = new Int32Array(capacityNodes).fill(-1);
  }

  #grow(): void {
    if (this.#numNodes < this.#c0.length) return;
    const cap = this.#c0.length * 2;
    const c0 = new Int32Array(cap).fill(-1);
    const c1 = new Int32Array(cap).fill(-1);
    const head = new Int32Array(cap).fill(-1);
    c0.set(this.#c0);
    c1.set(this.#c1);
    head.set(this.#head);
    this.#c0 = c0;
    this.#c1 = c1;
    this.#head = head;
  }

  #attach(node: number, payload: number): void {
    const ref = this.#payloads.length;
    this.#payloads.push(payload);
    this.#next.push(this.#head[node] as number);
    this.#head[node] = ref;
  }

  /** Insert at `network/prefix`; host bits must already be cleared. */
  insertV4(network: number, prefix: number, payload: number): void {
    let node = 0;
    for (let i = 0; i < prefix; i++) {
      const bit = (network >>> (31 - i)) & 1;
      let child = (bit === 0 ? this.#c0[node] : this.#c1[node]) as number;
      if (child < 0) {
        this.#grow();
        child = this.#numNodes++;
        if (bit === 0) this.#c0[node] = child;
        else this.#c1[node] = child;
      }
      node = child;
    }
    this.#attach(node, payload);
  }

  insertV6(words: Uint32Array, prefix: number, payload: number): void {
    let node = 0;
    for (let i = 0; i < prefix; i++) {
      const bit = ((words[i >>> 5] as number) >>> (31 - (i & 31))) & 1;
      let child = (bit === 0 ? this.#c0[node] : this.#c1[node]) as number;
      if (child < 0) {
        this.#grow();
        child = this.#numNodes++;
        if (bit === 0) this.#c0[node] = child;
        else this.#c1[node] = child;
      }
      node = child;
    }
    this.#attach(node, payload);
  }

  /** Invoke `emit` with every payload whose prefix contains `ip`. */
  lookupV4(ip: number, emit: (payload: number) => void): void {
    const c0 = this.#c0;
    const c1 = this.#c1;
    const head = this.#head;
    const payloads = this.#payloads;
    const next = this.#next;
    let node = 0;
    let v = head[0] as number;
    while (v >= 0) {
      emit(payloads[v] as number);
      v = next[v] as number;
    }
    for (let i = 0; i < 32; i++) {
      const child = ((ip >>> (31 - i)) & 1) === 0 ? (c0[node] as number) : (c1[node] as number);
      if (child < 0) break;
      node = child;
      let w = head[node] as number;
      while (w >= 0) {
        emit(payloads[w] as number);
        w = next[w] as number;
      }
    }
  }

  lookupV6(words: Uint32Array, emit: (payload: number) => void): void {
    const c0 = this.#c0;
    const c1 = this.#c1;
    const head = this.#head;
    const payloads = this.#payloads;
    const next = this.#next;
    let node = 0;
    let v = head[0] as number;
    while (v >= 0) {
      emit(payloads[v] as number);
      v = next[v] as number;
    }
    for (let i = 0; i < 128; i++) {
      const bit = ((words[i >>> 5] as number) >>> (31 - (i & 31))) & 1;
      const child = bit === 0 ? (c0[node] as number) : (c1[node] as number);
      if (child < 0) break;
      node = child;
      let w = head[node] as number;
      while (w >= 0) {
        emit(payloads[w] as number);
        w = next[w] as number;
      }
    }
  }

  get numNodes(): number {
    return this.#numNodes;
  }

  get size(): number {
    return this.#payloads.length;
  }
}
