/**
 * Scan engine: line text in, indicator hits out.
 *
 * Evaluation uses the inverted postings from `compile-set.ts`: once a line's
 * satisfied atom ids are known, only programs that reference one of those
 * atoms are evaluated. A line matching nothing costs one extraction pass and
 * one bitset test; the per-program boolean evaluation is skipped entirely.
 *
 * The engine is deliberately synchronous and allocation-light per line so it
 * can run inside a worker thread at full speed. Concurrency lives one layer up
 * in `pool.ts`.
 */

import type { CompiledSet, ProgramRecord } from "../stix/compile-set.ts";
import type { Expr } from "../stix/compile.ts";
import { LineMatcher, type Bitset, type LineMatches } from "./line-matcher.ts";

export interface Hit {
  /** Program index within the compiled set. */
  readonly program: number;
  readonly indicatorId: string;
  readonly indicatorName?: string;
  readonly confidence: number;
  readonly labels: readonly string[];
  readonly pattern: string;
  readonly matchedSummary: string;
  /** 0-based line number within the input file. */
  readonly lineNumber: number;
  /** Byte offset of the line start within the (decompressed) input. */
  readonly byteOffset: number;
  /** The line text, truncated to `maxCaptureBytes`. */
  readonly line: string;
  readonly truncated: boolean;
}

export interface ScanOptions {
  /** Keep at most this many bytes of each matching line. Default 2048. */
  readonly maxCaptureBytes?: number;
  /** Stop after this many hits. 0 = unlimited. */
  readonly maxHits?: number;
  /** Include the offending line text in hits. Default true. */
  readonly captureLine?: boolean;
}

export interface ScanCounters {
  lines: number;
  bytes: number;
  hits: number;
  evalPrograms: number;
  overlongLines: number;
  overlongBytes: number;
}

function evalExpr(expr: Expr, bits: Bitset): boolean {
  switch (expr.kind) {
    case "atom":
      return bits.has(expr.atomId);
    case "and": {
      for (let i = 0; i < expr.children.length; i++) {
        if (!evalExpr(expr.children[i] as Expr, bits)) return false;
      }
      return true;
    }
    case "or": {
      for (let i = 0; i < expr.children.length; i++) {
        if (evalExpr(expr.children[i] as Expr, bits)) return true;
      }
      return false;
    }
  }
}

export class ScanEngine {
  readonly #set: CompiledSet;
  readonly #matcher: LineMatcher;
  readonly #options: Required<Pick<ScanOptions, "maxCaptureBytes" | "maxHits" | "captureLine">>;
  readonly #counters: ScanCounters = {
    lines: 0,
    bytes: 0,
    hits: 0,
    evalPrograms: 0,
    overlongLines: 0,
    overlongBytes: 0,
  };
  /**
   * Scratch bitmap of programs already evaluated for the current line. Avoids
   * re-evaluating a program when several of its atoms match at once.
   */
  readonly #visited: Uint8Array;
  #lineNumber = 0;
  #byteOffset = 0;
  #stop = false;

  constructor(set: CompiledSet, options: ScanOptions = {}) {
    this.#set = set;
    this.#matcher = new LineMatcher(set.index);
    this.#options = {
      maxCaptureBytes: options.maxCaptureBytes ?? 2048,
      maxHits: options.maxHits ?? 0,
      captureLine: options.captureLine ?? true,
    };
    this.#visited = new Uint8Array(set.programs.length);
  }

  get counters(): Readonly<ScanCounters> {
    return this.#counters;
  }

  /**
   * Reset per-file state. Line numbers and byte offsets are *file-relative*,
   * so a worker that scans several files reports `line: 0` for the first line
   * of each. Without resetting these, hits from the second file would carry
   * offsets from the first and could not be used to reopen the input.
   */
  resetCounters(): void {
    this.#lineNumber = 0;
    this.#byteOffset = 0;
    this.#stop = false;
    this.#counters.lines = 0;
    this.#counters.bytes = 0;
    this.#counters.hits = 0;
    this.#counters.evalPrograms = 0;
    this.#counters.overlongLines = 0;
    this.#counters.overlongBytes = 0;
  }

  /** Scan one line. Calls `onHit` for every matching program. */
  scanLine(line: Uint8Array, onHit: (hit: Hit) => void): void {
    this.#counters.lines++;
    this.#counters.bytes += line.length;
    if (this.#stop) return;

    const matches: LineMatches = this.#matcher.match(line);
    if (matches.atomCount === 0) {
      this.#lineNumber++;
      this.#byteOffset += line.length + 1;
      return;
    }

    const postings = this.#set.postings;
    const programs = this.#set.programs;
    const visited = this.#visited;
    // Clearing only the touched program slots is cheaper than filling the
    // whole bitmap; we track which were set and reset them afterwards.
    const touched: number[] = [];

    for (let i = 0; i < matches.atomCount; i++) {
      const atomId = matches.atomIds[i] as number;
      const list = postings[atomId];
      if (list === undefined) continue;
      for (let k = 0; k < list.length; k++) {
        const p = list[k] as number;
        if (visited[p] !== 0) continue;
        visited[p] = 1;
        touched.push(p);
        const program = programs[p] as ProgramRecord;
        this.#counters.evalPrograms++;
        if (!evalExpr(program.expr, matches.bits)) continue;
        this.#counters.hits++;
        onHit(this.#buildHit(p, program, line));
        if (this.#options.maxHits > 0 && this.#counters.hits >= this.#options.maxHits) {
          this.#stop = true;
          for (const t of touched) visited[t] = 0;
          return;
        }
      }
    }

    for (let i = 0; i < touched.length; i++) visited[touched[i] as number] = 0;
    this.#lineNumber++;
    this.#byteOffset += line.length + 1;
  }

  #buildHit(programIndex: number, program: ProgramRecord, line: Uint8Array): Hit {
    const ind = program.indicator;
    const cap = this.#options.maxCaptureBytes;
    const truncated = line.length > cap;
    const slice = truncated ? line.subarray(0, cap) : line;
    const text = this.#options.captureLine ? Buffer.from(slice).toString("utf8") : "";
    const base = {
      program: programIndex,
      indicatorId: ind.id,
      confidence: ind.confidence,
      labels: ind.labels,
      pattern: ind.pattern,
      matchedSummary: program.summary,
      lineNumber: this.#lineNumber,
      byteOffset: this.#byteOffset,
      line: text,
      truncated: this.#options.captureLine && truncated,
    };
    return ind.name === undefined ? base : { ...base, indicatorName: ind.name };
  }
}

/**
 * Standalone single-file scan over an iterable of lines. Used by workers and
 * by tests; the pool calls this with its own hit sink.
 */
export async function scanLines(
  engine: ScanEngine,
  lines: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
  onHit: (hit: Hit) => void,
): Promise<ScanCounters> {
  for await (const line of lines as AsyncIterable<Uint8Array>) {
    engine.scanLine(line, onHit);
  }
  return { ...engine.counters };
}
