/**
 * Binary prefix trie for CIDR matching. Works for both IPv4 (32 bits) and
 * IPv6 (128 bits); addresses are bigint keys. Nodes live in flat arrays to
 * keep memory low with tens of thousands of prefixes.
 */
export class CidrTrie {
  private c0: number[] = [-1];
  private c1: number[] = [-1];
  private out: number[][] = [[]];

  constructor(private readonly bits: number) {}

  private newNode(): number {
    this.c0.push(-1);
    this.c1.push(-1);
    this.out.push([]);
    return this.c0.length - 1;
  }

  insert(key: bigint, prefixLen: number, atomId: number): void {
    let node = 0;
    for (let i = 0; i < prefixLen; i++) {
      const bit = Number((key >> BigInt(this.bits - 1 - i)) & 1n);
      const child = bit === 1 ? this.c1[node] : this.c0[node];
      if (child === -1) {
        const n = this.newNode();
        if (bit === 1) this.c1[node] = n; else this.c0[node] = n;
        node = n;
      } else {
        node = child;
      }
    }
    this.out[node].push(atomId);
  }

  /** Add every atomId whose CIDR contains `key` to `acc`. */
  lookupInto(key: bigint, acc: Set<number>): void {
    let node = 0;
    for (const id of this.out[0]) acc.add(id); // a /0 prefix matches everything
    for (let i = 0; i < this.bits; i++) {
      const bit = Number((key >> BigInt(this.bits - 1 - i)) & 1n);
      node = bit === 1 ? this.c1[node] : this.c0[node];
      if (node === -1) return;
      const outs = this.out[node];
      for (let k = 0; k < outs.length; k++) acc.add(outs[k]);
    }
  }

  get nodeCount(): number {
    return this.c0.length;
  }
}
