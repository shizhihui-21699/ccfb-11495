/**
 * Byte-level Aho-Corasick automaton with sparse (CSR) transitions.
 *
 * The automaton is built once per worker and is immutable afterwards, so a
 * worker shares it across every file it scans.
 *
 * Used for multi-pattern domain matching. Patterns are *reversed* domain
 * names, which turns "does this text end with indicator X at a label
 * boundary" into "does the reversed text start with reversed(X), followed by
 * `.` or end-of-text". Reporting match positions is therefore part of the API,
 * not an afterthought: `scan()` hands the visitor the end offset of every hit.
 *
 * Design notes:
 *   - Transitions are a sorted (byte, target) run per state. Most states have
 *     out-degree 1–2 where a linear scan beats a hash; the root keeps a dense
 *     256-entry table because every byte consults it.
 *   - `dictLink` jumps straight to the nearest output-bearing suffix state, so
 *     reporting never walks output-free failure chains.
 */

const LINEAR_LIMIT = 6;

export type MatchVisitor = (patternId: number, endPosition: number) => void;

export class AhoCorasick {
  readonly #rootNext: Int32Array;
  readonly #edgesStart: Int32Array;
  readonly #edgeByte: Uint8Array;
  readonly #edgeTarget: Int32Array;
  readonly #fail: Int32Array;
  readonly #dictLink: Int32Array;
  readonly #outStart: Int32Array;
  readonly #outIds: Int32Array;
  readonly #numStates: number;
  readonly #numPatterns: number;

  constructor(patterns: Uint8Array[]) {
    const n = patterns.length;
    this.#numPatterns = n;

    const children: Array<Map<number, number> | undefined> = [new Map()];
    const stateOut: Array<number[] | undefined> = [undefined];
    let numStates = 1;

    for (let pid = 0; pid < n; pid++) {
      const p = patterns[pid] as Uint8Array;
      let state = 0;
      for (let i = 0; i < p.length; i++) {
        const b = p[i] as number;
        const map = children[state] as Map<number, number>;
        let next = map.get(b);
        if (next === undefined) {
          next = numStates++;
          map.set(b, next);
          children[next] = new Map();
          stateOut[next] = undefined;
        }
        state = next;
      }
      (stateOut[state] ??= []).push(pid);
    }

    // ---- Flatten to CSR, edges sorted by byte for binary search. ---------
    const edgesStart = new Int32Array(numStates + 1);
    let totalEdges = 0;
    for (let s = 0; s < numStates; s++) {
      edgesStart[s] = totalEdges;
      totalEdges += children[s]?.size ?? 0;
    }
    edgesStart[numStates] = totalEdges;

    const edgeByte = new Uint8Array(totalEdges);
    const edgeTarget = new Int32Array(totalEdges);
    for (let s = 0; s < numStates; s++) {
      const map = children[s];
      if (map === undefined || map.size === 0) continue;
      const keys = Array.from(map.keys()).sort((a, b) => a - b);
      const base = edgesStart[s] as number;
      for (let i = 0; i < keys.length; i++) {
        const b = keys[i] as number;
        edgeByte[base + i] = b;
        edgeTarget[base + i] = map.get(b) as number;
      }
    }
    children.length = 0;

    // ---- Root dense table. ----------------------------------------------
    const rootNext = new Int32Array(256);
    for (let k = edgesStart[0] as number; k < (edgesStart[1] as number); k++) {
      rootNext[edgeByte[k] as number] = edgeTarget[k] as number;
    }

    const gotoFn = (state: number, b: number): number => {
      const base = edgesStart[state] as number;
      const end = edgesStart[state + 1] as number;
      if (end - base <= LINEAR_LIMIT) {
        for (let k = base; k < end; k++) if (edgeByte[k] === b) return edgeTarget[k] as number;
        return -1;
      }
      let lo = base;
      let hi = end - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >>> 1;
        const mb = edgeByte[mid] as number;
        if (mb === b) return edgeTarget[mid] as number;
        if (mb < b) lo = mid + 1;
        else hi = mid - 1;
      }
      return -1;
    };

    // ---- BFS: failure + dictionary links. -------------------------------
    const fail = new Int32Array(numStates);
    const dictLink = new Int32Array(numStates);
    const queue = new Int32Array(numStates);
    let qt = 0;
    for (let k = edgesStart[0] as number; k < (edgesStart[1] as number); k++) {
      const child = edgeTarget[k] as number;
      queue[qt++] = child;
    }
    let qh = 0;
    while (qh < qt) {
      const state = queue[qh++] as number;
      for (let k = edgesStart[state] as number; k < (edgesStart[state + 1] as number); k++) {
        const b = edgeByte[k] as number;
        const child = edgeTarget[k] as number;
        let f = fail[state] as number;
        let target = -1;
        while (f !== 0) {
          target = gotoFn(f, b);
          if (target >= 0) break;
          f = fail[f] as number;
        }
        if (target < 0) target = gotoFn(0, b);
        fail[child] = target < 0 ? 0 : target;
        const f2 = fail[child] as number;
        dictLink[child] = stateOut[f2] !== undefined ? f2 : (dictLink[f2] as number);
        queue[qt++] = child;
      }
    }

    // ---- Output CSR. -----------------------------------------------------
    const outStart = new Int32Array(numStates + 1);
    let totalOut = 0;
    for (let s = 0; s < numStates; s++) {
      outStart[s] = totalOut;
      totalOut += stateOut[s]?.length ?? 0;
    }
    outStart[numStates] = totalOut;
    const outIds = new Int32Array(totalOut);
    for (let s = 0; s < numStates; s++) {
      const list = stateOut[s];
      if (list === undefined) continue;
      const base = outStart[s] as number;
      for (let i = 0; i < list.length; i++) outIds[base + i] = list[i] as number;
    }

    this.#rootNext = rootNext;
    this.#edgesStart = edgesStart;
    this.#edgeByte = edgeByte;
    this.#edgeTarget = edgeTarget;
    this.#fail = fail;
    this.#dictLink = dictLink;
    this.#outStart = outStart;
    this.#outIds = outIds;
    this.#numStates = numStates;
  }

  get numPatterns(): number {
    return this.#numPatterns;
  }

  get numStates(): number {
    return this.#numStates;
  }

  #step(state: number, b: number): number {
    const fail = this.#fail;
    for (;;) {
      if (state === 0) return this.#rootNext[b] as number;
      const base = this.#edgesStart[state] as number;
      const end = this.#edgesStart[state + 1] as number;
      if (end - base <= LINEAR_LIMIT) {
        for (let k = base; k < end; k++) {
          if (this.#edgeByte[k] === b) return this.#edgeTarget[k] as number;
        }
      } else {
        let lo = base;
        let hi = end - 1;
        while (lo <= hi) {
          const mid = (lo + hi) >>> 1;
          const mb = this.#edgeByte[mid] as number;
          if (mb === b) return this.#edgeTarget[mid] as number;
          if (mb < b) lo = mid + 1;
          else hi = mid - 1;
        }
      }
      state = fail[state] as number;
    }
  }

  /**
   * Feed `data` and invoke `visit(patternId, endPosition)` for every match,
   * including matches of patterns that are suffixes of longer ones.
   */
  scan(data: Uint8Array, visit: MatchVisitor): void {
    const outStart = this.#outStart;
    const outIds = this.#outIds;
    const dictLink = this.#dictLink;
    let state = 0;
    for (let i = 0; i < data.length; i++) {
      state = this.#step(state, data[i] as number);
      let s = state;
      while (s !== 0) {
        for (let k = outStart[s] as number; k < (outStart[s + 1] as number); k++) {
          visit(outIds[k] as number, i);
        }
        s = dictLink[s] as number;
      }
    }
  }

  /** Distinct pattern ids present in `data`, written into `hits`. */
  matchInto(data: Uint8Array, hits: Int32Array): number {
    const outStart = this.#outStart;
    const outIds = this.#outIds;
    const dictLink = this.#dictLink;
    let state = 0;
    let count = 0;
    for (let i = 0; i < data.length; i++) {
      state = this.#step(state, data[i] as number);
      let s = state;
      while (s !== 0) {
        for (let k = outStart[s] as number; k < (outStart[s + 1] as number); k++) {
          const pid = outIds[k] as number;
          let dup = false;
          for (let j = 0; j < count; j++) {
            if (hits[j] === pid) {
              dup = true;
              break;
            }
          }
          if (!dup && count < hits.length) hits[count++] = pid;
        }
        s = dictLink[s] as number;
      }
    }
    return count;
  }

  /** Convenience wrapper returning a fresh array (tests, cold paths). */
  match(data: Uint8Array): number[] {
    const out: number[] = [];
    const seen = new Set<number>();
    this.scan(data, (pid) => {
      if (!seen.has(pid)) {
        seen.add(pid);
        out.push(pid);
      }
    });
    return out;
  }
}
