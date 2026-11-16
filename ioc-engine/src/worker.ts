/**
 * Worker thread: scans one byte range of one log file.
 * Each worker builds its own engine from the intel path — for tens of
 * thousands of indicators this takes well under a second and avoids
 * serializing the automaton across the thread boundary.
 */
import { parentPort, workerData } from 'node:worker_threads';
import { buildEngineFromFile } from './engineBuilder';
import { scanRange } from './scanner';
import { Hit } from './types';

interface WorkerInput {
  intelPath: string;
  logFile: string;
  start: number;
  end: number;
}

interface DoneMsg {
  type: 'done';
  lines: number;
  bytes: number;
  hits: number;
}

const { intelPath, logFile, start, end } = workerData as WorkerInput;
const out = parentPort!;

const SNIPPET_MAX = 300;
const BATCH = 500;

async function main(): Promise<void> {
  const { engine } = buildEngineFromFile(intelPath);
  let batch: Hit[] = [];
  let hitCount = 0;

  const stats = await scanRange(logFile, start, end, (line, offset) => {
    const matches = engine.matchLine(line);
    if (matches.length === 0) return;
    hitCount += matches.length;
    const snippet = line.length > SNIPPET_MAX ? line.slice(0, SNIPPET_MAX) + '…' : line;
    for (const m of matches) {
      batch.push({
        indicatorId: m.indicator.id,
        indicatorName: m.indicator.name,
        confidence: m.indicator.confidence,
        matched: m.matchedAtoms.map((a) => `${a.kind}:${a.value}`),
        file: logFile,
        offset,
        snippet,
      });
    }
    if (batch.length >= BATCH) {
      out.postMessage({ type: 'hits', hits: batch });
      batch = [];
    }
  });

  if (batch.length > 0) out.postMessage({ type: 'hits', hits: batch });
  const done: DoneMsg = { type: 'done', lines: stats.lines, bytes: stats.bytes, hits: hitCount };
  out.postMessage(done);
}

main().catch((e) => {
  out.postMessage({ type: 'error', message: String(e?.stack ?? e) });
});
