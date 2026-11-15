/**
 * Benchmark harness.
 *
 * Measures the three things that decide whether this engine can replace a
 * grep-over-logs pipeline:
 *
 *   1. throughput on realistic mixed lines (MiB/s and lines/s),
 *   2. index build cost for a realistic feed (tens of thousands of indicators),
 *   3. per-stage cost breakdown, so a regression can be attributed.
 *
 * Run with `npm run bench`. Numbers are machine-specific; the value is in the
 * ratios and in catching regressions across commits.
 */

import { readFileSync, existsSync } from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateIntel } from "../src/fixtures/intel.ts";
import { generateLogs } from "../src/fixtures/logs.ts";
import { loadIndicators } from "../src/stix/bundle.ts";
import { compileIndicators } from "../src/stix/compile-set.ts";
import { ScanEngine } from "../src/scan/engine.ts";
import { Extractor } from "../src/extract/extractor.ts";
import { writeFileSync } from "node:fs";

const NOW = Date.parse("2026-06-01T00:00:00Z");

function human(n: number): string {
  return n.toLocaleString("en-US");
}

function bench(name: string, iterations: number, fn: () => void): { name: string; perOpMs: number; opsPerSec: number } {
  // Warm up so JIT compilation does not land in the measured window.
  for (let i = 0; i < Math.min(iterations, 3); i++) fn();
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) fn();
  const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
  return { name, perOpMs: elapsedMs / iterations, opsPerSec: (iterations / elapsedMs) * 1000 };
}

function section(title: string): void {
  process.stdout.write(`\n=== ${title} ===\n`);
}

function table(rows: Array<{ name: string; perOpMs: number; opsPerSec: number }>): void {
  const width = Math.max(...rows.map((r) => r.name.length));
  for (const r of rows) {
    process.stdout.write(
      `  ${r.name.padEnd(width)}  ${r.perOpMs.toFixed(3).padStart(9)} ms/op  ${human(Math.round(r.opsPerSec)).padStart(12)} op/s\n`,
    );
  }
}

const dir = mkdtempSync(join(tmpdir(), "iocscan-bench-"));
try {
  // -------------------------------------------------------------------------
  // Index build at feed scale
  // -------------------------------------------------------------------------
  section("index build");
  const feedSizes = [1_000, 10_000, 50_000];
  const buildRows: Array<{ name: string; perOpMs: number; opsPerSec: number }> = [];
  for (const count of feedSizes) {
    const { bundle } = generateIntel({ seed: count, count, now: new Date(NOW).toISOString() });
    const text = JSON.stringify(bundle);
    let set = compileIndicators(loadIndicators(text, { now: NOW }).indicators);
    const t0 = process.hrtime.bigint();
    const loaded = loadIndicators(text, { now: NOW });
    const parsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
    const t1 = process.hrtime.bigint();
    set = compileIndicators(loaded.indicators);
    const compiledMs = Number(process.hrtime.bigint() - t1) / 1e6;
    process.stdout.write(
      `  ${human(count).padStart(7)} indicators: json ${parsedMs.toFixed(0)} ms, ` +
        `compile+index ${compiledMs.toFixed(0)} ms, programs ${set.programs.length}, ` +
        `atoms ${set.atoms.length}, AC states ${set.stats.acStates}\n`,
    );
  }
  void buildRows;

  // -------------------------------------------------------------------------
  // Throughput on realistic lines
  // -------------------------------------------------------------------------
  section("scan throughput");
  const { bundle, manifest } = generateIntel({ seed: 42, count: 5000, now: new Date(NOW).toISOString() });
  const compiled = compileIndicators(loadIndicators(JSON.stringify(bundle), { now: NOW }).indicators);
  const logs = generateLogs(manifest, { seed: 42, lines: 200_000, files: 4, hitRate: 0.005, decoyRate: 0.02 });

  // Write the corpus once so the streaming path can be measured end to end.
  const paths: string[] = [];
  let totalBytes = 0;
  for (const f of logs.files) {
    const p = join(dir, f.name);
    writeFileSync(p, f.content);
    totalBytes += Buffer.byteLength(f.content);
    paths.push(p);
  }

  const lineBufs = logs.files[0]!.content.split("\n").slice(0, -1).map((l) => Buffer.from(l, "latin1"));
  const engine = new ScanEngine(compiled);
  let hitCount = 0;

  const scanRow = bench(`scan ${human(lineBufs.length)} lines (${compiled.programs.length} programs)`, 3, () => {
    hitCount = 0;
    for (const line of lineBufs) engine.scanLine(line, () => hitCount++);
  });
  const mbPerSec = (lineBufs.reduce((n, b) => n + b.length, 0) / (1024 * 1024)) / (scanRow.perOpMs / 1000);
  process.stdout.write(
    `  ${human(Math.round((lineBufs.length / scanRow.perOpMs) * 1000))} lines/s, ` +
      `${mbPerSec.toFixed(0)} MiB/s, ${human(hitCount)} hits per pass\n`,
  );

  // -------------------------------------------------------------------------
  // Stage breakdown
  // -------------------------------------------------------------------------
  section("stage breakdown (per line)");
  const extractor = new Extractor(new Uint8Array(0));
  const stageRows = [
    bench("extract observables", 3, () => {
      for (const line of lineBufs) {
        extractor.reset(line);
        extractor.run();
      }
    }),
    bench("full match (extract + indexes)", 3, () => {
      for (const line of lineBufs) engine.scanLine(line, () => undefined);
    }),
  ];
  table(stageRows);
  const extractMs = stageRows[0]!.perOpMs;
  const fullMs = stageRows[1]!.perOpMs;
  process.stdout.write(
    `  extraction is ${((extractMs / fullMs) * 100).toFixed(0)}% of total line cost; ` +
      `index lookups are ${(((fullMs - extractMs) / fullMs) * 100).toFixed(0)}%\n`,
  );

  // -------------------------------------------------------------------------
  // Pathological inputs
  // -------------------------------------------------------------------------
  section("pathological lines");
  const longLine = Buffer.from("x".repeat(64 * 1024) + " 203.0.113.9 " + "y".repeat(64 * 1024));
  const manyIps = Buffer.from(Array.from({ length: 2000 }, (_, i) => `10.${i >> 8}.${i & 255}.1`).join(" "));
  const pathological = bench("128 KiB line with one indicator", 5, () => {
    engine.scanLine(longLine, () => undefined);
  });
  const manyIpsRow = bench("line with 2000 distinct IPs", 200, () => {
    engine.scanLine(manyIps, () => undefined);
  });
  table([pathological, manyIpsRow]);
  const lineMiB = longLine.length / (1024 * 1024);
  process.stdout.write(`  long line: ${(lineMiB / (pathological.perOpMs / 1000)).toFixed(1)} MiB/s single-threaded\n`);

  // -------------------------------------------------------------------------
  // Host file throughput (streaming, one worker)
  // -------------------------------------------------------------------------
  section("streaming file scan");
  const filePath = paths[0]!;
  const fileBytes = readFileSync(filePath).length;
  process.stdout.write(`  ${filePath.split("/").pop()}: ${(fileBytes / (1024 * 1024)).toFixed(1)} MiB, ${human(totalBytes)} B total\n`);
  process.stdout.write(`  (use \`iocscan scan\` for end-to-end pool throughput)\n`);
  void existsSync;
} finally {
  rmSync(dir, { recursive: true, force: true });
}
