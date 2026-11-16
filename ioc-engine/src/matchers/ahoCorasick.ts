/**
 * Aho-Corasick multi-pattern string matcher.
 * One automaton is shared by domain and URL patterns; each pattern carries
 * its kind so the caller can apply the right boundary rule per match.
 */

export interface ACPattern {
  text: string;
  atomId: number;
  kind: 'domain' | 'url';
}

export class AhoCorasick {
  private next: Array<Map<number, number>> = [new Map()];
  private fail: number[] = [0];
  private out: number[][] = [[]];
  readonly patterns: ACPattern[] = [];

  add(text: string, atomId: number, kind: 'domain' | 'url'): void {
    let node = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      let n = this.next[node].get(c);
      if (n === undefined) {
        n = this.next.length;
        this.next.push(new Map());
        this.fail.push(0);
        this.out.push([]);
        this.next[node].set(c, n);
      }
      node = n;
    }
    this.out[node].push(this.patterns.length);
    this.patterns.push({ text, atomId, kind });
  }

  build(): void {
    const queue: number[] = [];
    for (const child of this.next[0].values()) queue.push(child);
    let head = 0;
    while (head < queue.length) {
      const r = queue[head++];
      for (const [c, s] of this.next[r]) {
        queue.push(s);
        let f = this.fail[r];
        while (f !== 0 && !this.next[f].has(c)) f = this.fail[f];
        const g = this.next[f].get(c);
        this.fail[s] = g !== undefined && g !== s ? g : 0;
        const fo = this.out[this.fail[s]];
        if (fo.length) this.out[s].push(...fo);
      }
    }
  }

  /** Invoke cb(patternIndex, endIndex) for every occurrence; endIndex is exclusive. */
  scan(text: string, cb: (patIdx: number, end: number) => void): void {
    let node = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      while (node !== 0 && !this.next[node].has(c)) node = this.fail[node];
      node = this.next[node].get(c) ?? 0;
      const outs = this.out[node];
      for (let k = 0; k < outs.length; k++) cb(outs[k], i + 1);
    }
  }

  get size(): number {
    return this.next.length;
  }
}
