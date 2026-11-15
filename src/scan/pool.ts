/**
 * Multi-process scan pool.
 *
 * Node has no `fork` in the POSIX sense, so "multi-process" here means
 * `worker_threads`: each worker is a separate V8 isolate with its own heap and
 * its own copy of the match index, and they run in parallel across cores. This
 * is the right model for a CPU-bound scanner: the workload is embarrassingly
 * parallel over files, the index is built once per worker rather than once per
 * file, and no shared mutable state crosses threads.
 *
 * Scheduling is dynamic, not static: workers pull the next file when they
 * finish, so one huge file cannot pin a single worker while the rest idle. Hit
 * arrival order therefore varies by design; a caller that needs a stable order
 * can collect hits and pass them through `sortHits`.
 *
 * Failure policy: a worker that throws on a file reports it and the pool marks
 * that file failed and moves on. If a worker dies (uncaught exception, OOM,
 * failed init), the pool replaces it and requeues the file it held, up to
 * `maxWorkerRestarts` total replacements. If restarts are exhausted, every
 * still-queued file is marked failed and `run()` rejects — it never hangs, and
 * nothing is silently dropped.
 *
 * Requeueing a file re-scans it from the start, so a worker death can emit
 * duplicate hits for that one file. That is deliberate at-least-once
 * behaviour: for an alerting pipeline a repeated hit is harmless, while a
 * missed one is not. A caller that cannot tolerate duplicates should dedupe on
 * `(file, lineNumber, indicatorId)`.
 */

import { availableParallelism } from "node:os";
import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import { stat } from "node:fs/promises";
import type { CompiledSet, CompiledSetSpec } from "../stix/compile-set.ts";
import { toSpec } from "../stix/compile-set.ts";
import type { Hit } from "./engine.ts";
import type { DoneMessage, OutboundMessage } from "./worker.ts";

export interface FileResult {
  readonly path: string;
  readonly ok: boolean;
  readonly error?: string;
  readonly counters: {
    lines: number;
    bytes: number;
    hits: number;
    evalPrograms: number;
    overlongLines: number;
    overlongBytes: number;
  };
  readonly lineStats: {
    bytesRead: number;
    linesRead: number;
    overlongLines: number;
    overlongBytes: number;
  };
}

export interface PoolOptions {
  readonly workers: number;
  readonly engineOptions: {
    readonly maxCaptureBytes: number;
    readonly maxHits: number;
    readonly captureLine: boolean;
    readonly maxLineBytes: number;
  };
  /** Per-file hit cap for a single worker (0 = unlimited). */
  readonly maxHitsPerFile?: number;
  /**
   * Keep every hit in memory so `pool.hits` can be read afterwards. Off by
   * default: on a multi-GB scan the streamed hit corpus can be hundreds of MB
   * and the CLI consumes hits as they arrive. Only enable it for callers that
   * genuinely need the full set in memory (tests, small scans).
   */
  readonly retainHits?: boolean;
  /**
   * Test seam: invoked with an opaque "kill" function once per worker, right
   * after it starts. Production callers never set it. It exists because a
   * worker dying from the outside (OOM killer, native crash) is otherwise
   * impossible to reproduce deterministically in a test.
   */
  readonly onWorkerStarted?: (kill: () => void) => void;
  readonly onHitBatch?: (path: string, hits: readonly Hit[]) => void;
  readonly onProgress?: (progress: { path: string; lines: number; bytes: number; hits: number }) => void;
  readonly maxWorkerRestarts?: number;
}

interface Job {
  readonly path: string;
  readonly size: number;
  /** True when this job is the stdin pipe and must be relayed by the pool. */
  readonly isStdin: boolean;
}

class WorkerSlot {
  readonly worker: Worker;
  #jobId = 0;
  current: Job | null = null;
  readonly pending = new Map<number, Job>();
  done = false;

  constructor(spec: CompiledSetSpec) {
    // The worker is TypeScript. Node 22.18+ strips types natively; older
    // runtimes need the explicit flag, so it is passed only when the running
    // binary does not already accept `.ts` entry points.
    const supportsNativeTs = Number(process.versions.node.split(".")[0] ?? "0") >= 23;
    this.worker = new Worker(fileURLToPath(new URL("./worker.ts", import.meta.url)), {
      execArgv: supportsNativeTs ? ["--no-warnings"] : ["--experimental-strip-types", "--no-warnings"],
      resourceLimits: { maxOldGenerationSizeMb: 2048 },
    });
    this.worker.postMessage({ kind: "init", spec });
  }

  nextJobId(): number {
    return this.#jobId++;
  }
}

function defaultWorkers(): number {
  // Leave one core for the coordinator (file I/O, hit sorting, output).
  return Math.max(1, availableParallelism() - 1);
}

export class ScanPool {
  readonly #spec: CompiledSetSpec;
  readonly #options: Required<Pick<PoolOptions, "maxWorkerRestarts" | "retainHits">> & PoolOptions;
  readonly #slots: WorkerSlot[] = [];
  readonly #hits: Array<{ path: string; hit: Hit }> = [];
  readonly #results = new Map<string, FileResult>();
  readonly #failures: string[] = [];
  #queue: Job[] = [];
  #restarts = 0;
  #finished = 0;
  #total = 0;
  #settled = false;
  /** Workers spawned and not yet retired; drives completion. */
  #active = 0;
  /** Resolver for the in-flight `run()`, if any. */
  #resolveRun: (() => void) | null = null;
  #rejectRun: ((err: Error) => void) | null = null;
  #fatal: Error | null = null;

  constructor(set: CompiledSet, options: PoolOptions) {
    this.#spec = toSpec(set);
    this.#options = { maxWorkerRestarts: 3, retainHits: false, ...options };
  }

  get hits(): readonly { path: string; hit: Hit }[] {
    return this.#hits;
  }

  get results(): ReadonlyMap<string, FileResult> {
    return this.#results;
  }

  get failures(): readonly string[] {
    return this.#failures;
  }

  get totalFiles(): number {
    return this.#total;
  }

  get finishedFiles(): number {
    return this.#finished;
  }

  /** Scan every path, resolving once all files have been processed. */
  async run(paths: readonly string[]): Promise<void> {
    const jobs: Job[] = [];
    for (const p of paths) {
      // `-` is stdin: it has no size and must be scheduled first, because only
      // one consumer can read a pipe.
      if (p === "-") {
        jobs.push({ path: p, size: Number.MAX_SAFE_INTEGER, isStdin: true });
        continue;
      }
      try {
        const st = await stat(p);
        jobs.push({ path: p, size: st.size, isStdin: false });
      } catch (err) {
        this.#results.set(p, {
          path: p,
          ok: false,
          error: `cannot stat: ${(err as Error).message}`,
          counters: emptyCounters(),
          lineStats: emptyLineStats(),
        });
        this.#failures.push(p);
      }
    }

    // Largest first: a long file starts immediately and can be overlapped by
    // many short ones, which is what keeps tail latency down.
    jobs.sort((a, b) => b.size - a.size);
    this.#queue = jobs;
    this.#total = jobs.length;
    this.#finished = this.#results.size;

    if (jobs.length === 0) return;

    // Spawning a worker per file is wasteful when there are only a few, and a
    // single stdin pipe can only ever occupy one worker anyway.
    const count = Math.max(1, Math.min(this.#options.workers, jobs.length, 64));
    await new Promise<void>((resolve, reject) => {
      this.#resolveRun = resolve;
      this.#rejectRun = reject;
      for (let i = 0; i < count; i++) this.#spawn();
    });

    this.#assertSettled();
    if (this.#fatal !== null) throw this.#fatal;
  }

  #spawn(): void {
    const slot = new WorkerSlot(this.#spec);
    this.#slots.push(slot);
    this.#active++;

    /**
     * Retire this worker. Idempotent: a dying worker can reach here through
     * several paths (`error`, `exit`, an explicit shutdown).
     */
    let retired = false;
    const retire = (): void => {
      if (retired) return;
      retired = true;
      slot.done = true;
      this.#active--;
      const at = this.#slots.indexOf(slot);
      if (at >= 0) this.#slots.splice(at, 1);
      void slot.worker.terminate();
      if (this.#active <= 0) this.#maybeSettle();
    };

    /**
     * A worker is unusable: requeue whatever it held, then replace it so the
     * remaining queue still gets processed, or give up with a fatal error once
     * restarts are exhausted. Requeueing precedes `retire` so the replacement
     * sees the work.
     */
    const lose = (reason: string): void => {
      if (retired) return;
      // `slot.current` is also the most recent entry in `slot.pending`, so
      // collecting both would requeue that job twice and scan it twice. The
      // pending map alone is the authoritative set of unfinished work.
      const lost: Job[] = [...slot.pending.values()];
      slot.pending.clear();
      slot.current = null;
      slot.done = true;
      for (let i = lost.length - 1; i >= 0; i--) this.#queue.unshift(lost[i] as Job);
      retire();
      // Nothing was in flight and nothing is queued: this worker simply ran out
      // of work, which `dispatch` handles as a clean shutdown.
      if (lost.length === 0 && this.#queue.length === 0) return;

      this.#restarts++;
      if (this.#restarts > this.#options.maxWorkerRestarts) {
        this.#fatal = new Error(`worker lost ${this.#restarts} times; last reason: ${reason}`);
        this.#maybeSettle();
        return;
      }
      if (!this.#settled) this.#spawn();
    };

    const dispatch = (): void => {
      if (slot.done) return;
      const job = this.#queue.shift();
      if (job === undefined) {
        slot.done = true;
        slot.worker.postMessage({ kind: "shutdown" });
        retire();
        return;
      }
      slot.current = job;
      const jobId = slot.nextJobId();
      slot.pending.set(jobId, job);
      slot.worker.postMessage({
        kind: "scan",
        jobId,
        path: job.isStdin ? null : job.path,
        engineOptions: {
          ...this.#options.engineOptions,
          maxHits: this.#options.maxHitsPerFile ?? this.#options.engineOptions.maxHits,
        },
      });
      // Stdin cannot be replayed: if the worker holding the pipe dies, the
      // bytes already consumed are gone. The file is still reported, but its
      // hit set will be partial — see the module note on at-least-once.
      if (job.isStdin) this.#relayStdin(slot, jobId);
    };

    slot.worker.on("message", (msg: OutboundMessage) => {
      switch (msg.kind) {
        case "ready": {
          dispatch();
          return;
        }
        case "progress": {
          const job = slot.pending.get(msg.jobId);
          if (job !== undefined) {
            this.#options.onProgress?.({ path: job.path, lines: msg.lines, bytes: msg.bytes, hits: msg.hits });
          }
          return;
        }
        case "hits": {
          const job = slot.pending.get(msg.jobId);
          if (job === undefined) return;
          if (this.#options.onHitBatch !== undefined) this.#options.onHitBatch(job.path, msg.hits);
          if (this.#options.retainHits) {
            for (const hit of msg.hits) this.#hits.push({ path: job.path, hit });
          }
          return;
        }
        case "done": {
          const job = slot.pending.get(msg.jobId);
          if (job === undefined) return;
          slot.pending.delete(msg.jobId);
          slot.current = null;
          this.#recordDone(job.path, msg);
          dispatch();
          return;
        }
        case "error": {
          const jobId: number | undefined = msg.jobId;
          const job = jobId === undefined ? undefined : slot.pending.get(jobId);
          if (job !== undefined) {
            slot.pending.delete(jobId as number);
            slot.current = null;
            this.#recordFailure(job.path, msg.message);
            dispatch();
          } else {
            // Init failure: this worker can never serve work. Requeue it so a
            // replacement is spawned rather than leaving the pool short.
            lose(`init failed: ${msg.message}`);
          }
          return;
        }
      }
    });

    // An uncaught worker error kills the isolate. `exit` follows, but acting
    // here lets us requeue while the slot bookkeeping is still fresh.
    slot.worker.on("error", (err) => {
      lose(`worker error: ${err.message}`);
    });

    slot.worker.on("exit", (code) => {
      // A worker that exits with anything but a clean 0 before finishing its
      // queue died unexpectedly; `lose` is idempotent, so a normal shutdown
      // that already retired the slot is a no-op here.
      if (!retired && (code !== 0 || this.#queue.length > 0 || slot.current !== null)) {
        lose(`worker exited with code ${code}`);
      } else {
        retire();
      }
    });

    this.#options.onWorkerStarted?.(() => {
      void slot.worker.terminate();
    });
  }

  /** Resolve or reject the in-flight `run()` once no worker is left. */
  #maybeSettle(): void {
    if (this.#settled || this.#active > 0) return;
    this.#settled = true;
    const resolve = this.#resolveRun;
    const reject = this.#rejectRun;
    this.#resolveRun = null;
    this.#rejectRun = null;
    if (this.#fatal !== null) {
      reject?.(this.#fatal);
    } else {
      resolve?.();
    }
  }

  /**
   * Forward `process.stdin` to the worker that owns the stdin job. Workers
   * cannot open the parent's pipe themselves, so the pool pumps it. Back
   * pressure is respected: the reader is paused while `write` returns false.
   */
  #relayStdin(slot: WorkerSlot, jobId: number): void {
    const input = process.stdin;
    const send = (chunk: Uint8Array): void => {
      if (slot.done) return;
      slot.worker.postMessage({ kind: "stdinChunk", jobId, chunk: new Uint8Array(chunk) });
    };
    input.on("data", (chunk: Buffer) => {
      send(chunk);
    });
    input.on("end", () => {
      slot.worker.postMessage({ kind: "stdinEnd", jobId });
    });
    input.on("error", (err: Error) => {
      this.#failures.push(`stdin: ${err.message}`);
      slot.worker.postMessage({ kind: "stdinEnd", jobId });
    });
  }

  #recordDone(path: string, msg: DoneMessage): void {
    this.#finished++;
    this.#results.set(path, {
      path,
      ok: true,
      counters: msg.counters,
      lineStats: msg.lineStats,
    });
  }

  #recordFailure(path: string, message: string): void {
    // A job can only be recorded once. When a worker dies mid-file its job is
    // requeued and finished by a replacement; if the dying worker had already
    // reported an error for it, counting it again would make `results` larger
    // than the input set and double-report the file.
    if (this.#results.has(path)) return;
    this.#finished++;
    this.#failures.push(path);
    this.#results.set(path, {
      path,
      ok: false,
      error: message,
      counters: emptyCounters(),
      lineStats: emptyLineStats(),
    });
  }

  #assertSettled(): void {
    const missing = [...this.#queue];
    if (missing.length > 0) {
      for (const job of missing) this.#recordFailure(job.path, "not processed: pool ended early");
    }
  }
}

export function defaultWorkerCount(): number {
  return defaultWorkers();
}

function emptyCounters(): FileResult["counters"] {
  return { lines: 0, bytes: 0, hits: 0, evalPrograms: 0, overlongLines: 0, overlongBytes: 0 };
}

function emptyLineStats(): FileResult["lineStats"] {
  return { bytesRead: 0, linesRead: 0, overlongLines: 0, overlongBytes: 0 };
}

/** Deterministic hit ordering: file, then line, then byte offset, then id. */
export function sortHits(hits: Array<{ path: string; hit: Hit }>): Array<{ path: string; hit: Hit }> {
  return hits.sort((a, b) => {
    if (a.path !== b.path) return a.path < b.path ? -1 : 1;
    if (a.hit.lineNumber !== b.hit.lineNumber) return a.hit.lineNumber - b.hit.lineNumber;
    if (a.hit.byteOffset !== b.hit.byteOffset) return a.hit.byteOffset - b.hit.byteOffset;
    if (a.hit.indicatorId !== b.hit.indicatorId) return a.hit.indicatorId < b.hit.indicatorId ? -1 : 1;
    return 0;
  });
}

