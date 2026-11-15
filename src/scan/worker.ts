/**
 * Scan worker.
 *
 * One worker owns one `ScanEngine` built from the posted spec and processes
 * whole input files handed to it by the pool. It streams hits back in batches
 * so the parent never receives a giant array, and reports progress counters
 * periodically so the CLI can show a live rate.
 *
 * Protocol (parent -> worker):
 *   { kind: "init", spec }
 *   { kind: "scan", jobId, path, engineOptions, hitBatch }
 *   { kind: "shutdown" }
 *
 * Protocol (worker -> parent):
 *   { kind: "ready" }
 *   { kind: "progress", jobId, counters }
 *   { kind: "hits", jobId, hits }
 *   { kind: "done", jobId, counters, lineStats }
 *   { kind: "error", jobId?, message }
 */

import { parentPort } from "node:worker_threads";
import { buildFromSpec, type CompiledSet, type CompiledSetSpec } from "../stix/compile-set.ts";
import { ScanEngine, type Hit } from "./engine.ts";
import { iterateLines, openByteStream } from "./line-reader.ts";
import { Readable } from "node:stream";

export interface InitMessage {
  readonly kind: "init";
  readonly spec: CompiledSetSpec;
}

export interface ScanMessage {
  readonly kind: "scan";
  readonly jobId: number;
  /**
   * A filesystem path to stream, or `null` for the stdin pipe. Stdin cannot be
   * opened by a worker (each thread has its own `process.stdin` facade that is
   * not connected to the parent's pipe), so the pool forwards its chunks as
   * `stdinChunk` messages instead.
   */
  readonly path: string | null;
  readonly engineOptions: {
    readonly maxCaptureBytes: number;
    readonly maxHits: number;
    readonly captureLine: boolean;
    readonly maxLineBytes: number;
  };
}

export interface StdinChunkMessage {
  readonly kind: "stdinChunk";
  readonly jobId: number;
  readonly chunk: Uint8Array;
}

export interface StdinEndMessage {
  readonly kind: "stdinEnd";
  readonly jobId: number;
}

export interface ShutdownMessage {
  readonly kind: "shutdown";
}

export type InboundMessage = InitMessage | ScanMessage | StdinChunkMessage | StdinEndMessage | ShutdownMessage;

export interface ProgressMessage {
  readonly kind: "progress";
  readonly jobId: number;
  readonly lines: number;
  readonly bytes: number;
  readonly hits: number;
}

export interface HitsMessage {
  readonly kind: "hits";
  readonly jobId: number;
  readonly hits: Hit[];
}

export interface DoneMessage {
  readonly kind: "done";
  readonly jobId: number;
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

export interface ErrorMessage {
  readonly kind: "error";
  readonly jobId?: number;
  readonly message: string;
}

export type OutboundMessage = ProgressMessage | HitsMessage | DoneMessage | ErrorMessage | { readonly kind: "ready" };

const port = parentPort;
if (port === null) {
  throw new Error("scan worker must be started as a Worker");
}

let compiledSet: CompiledSet | null = null;
let hitBuffer: Hit[] = [];

/** Stdin relay: the parent pushes chunks here, the running job consumes them. */
let stdinQueue: Array<Uint8Array | null> = [];
let stdinWaiter: (() => void) | null = null;
const HIT_BATCH = 512;
const PROGRESS_EVERY_LINES = 5000;

function flushHits(jobId: number): void {
  if (hitBuffer.length === 0) return;
  port!.postMessage({ kind: "hits", jobId, hits: hitBuffer } satisfies HitsMessage);
  hitBuffer = [];
}

port.on("message", (msg: InboundMessage) => {
  switch (msg.kind) {
    case "init": {
      try {
        compiledSet = buildFromSpec(msg.spec);
        port!.postMessage({ kind: "ready" });
      } catch (err) {
        port!.postMessage({ kind: "error", message: `init failed: ${(err as Error).message}` });
      }
      return;
    }
    case "stdinChunk": {
      stdinQueue.push(msg.chunk);
      stdinWaiter?.();
      stdinWaiter = null;
      return;
    }
    case "stdinEnd": {
      stdinQueue.push(null);
      stdinWaiter?.();
      stdinWaiter = null;
      return;
    }
    case "shutdown": {
      port!.close();
      return;
    }
    case "scan": {
      void runJob(msg);
      return;
    }
  }
});

/**
 * Drain the parent's relayed stdin chunks. An async generator plus
 * `Readable.from` is simpler and less error-prone than implementing `_read`,
 * and it preserves ordering: chunks arrive on the message queue in send order.
 */
function stdinReadable(): Readable {
  const chunks = (async function* (): AsyncGenerator<Uint8Array> {
    for (;;) {
      if (stdinQueue.length === 0) {
        await new Promise<void>((resolve) => {
          stdinWaiter = resolve;
        });
        continue;
      }
      const next = stdinQueue.shift() as Uint8Array | null;
      if (next === null) return;
      yield next;
    }
  })();
  return Readable.from(chunks);
}

async function runJob(msg: ScanMessage): Promise<void> {
  if (compiledSet === null) {
    port!.postMessage({ kind: "error", jobId: msg.jobId, message: "worker scanned before init" });
    return;
  }
  // A fresh engine per job: engine options (capture width, line capture) are
  // per-scan, and constructing one is cheap — it only allocates the matcher's
  // bitsets, not the index, which is shared through `compiledSet`.
  const eng = new ScanEngine(compiledSet, {
    maxCaptureBytes: msg.engineOptions.maxCaptureBytes,
    maxHits: msg.engineOptions.maxHits,
    captureLine: msg.engineOptions.captureLine,
  });
  hitBuffer = [];

  let lastProgressLines = 0;
  const stream = msg.path === null ? stdinReadable() : openByteStream(msg.path);
  const lines = iterateLines(stream, { maxLineBytes: msg.engineOptions.maxLineBytes });

  const onHit = (hit: Hit): void => {
    hitBuffer.push(hit);
    if (hitBuffer.length >= HIT_BATCH) flushHits(msg.jobId);
  };

  try {
    const lineStats = await (async () => {
      // `iterateLines` returns the stats as the generator's return value.
      const gen = lines;
      let stats = { bytesRead: 0, linesRead: 0, overlongLines: 0, overlongBytes: 0 };
      for (;;) {
        const next = await gen.next();
        if (next.done) {
          stats = next.value;
          break;
        }
        eng.scanLine(next.value, onHit);
        const c = eng.counters;
        if (c.lines - lastProgressLines >= PROGRESS_EVERY_LINES) {
          lastProgressLines = c.lines;
          port!.postMessage({
            kind: "progress",
            jobId: msg.jobId,
            lines: c.lines,
            bytes: c.bytes,
            hits: c.hits,
          } satisfies ProgressMessage);
        }
        if (msg.engineOptions.maxHits > 0 && c.hits >= msg.engineOptions.maxHits) break;
      }
      return stats;
    })();

    flushHits(msg.jobId);
    port!.postMessage({
      kind: "done",
      jobId: msg.jobId,
      counters: { ...eng.counters },
      lineStats,
    } satisfies DoneMessage);
  } catch (err) {
    flushHits(msg.jobId);
    port!.postMessage({
      kind: "error",
      jobId: msg.jobId,
      message: (err as Error).message,
    } satisfies ErrorMessage);
  }
}
