#!/usr/bin/env node
/**
 * `iocscan` command line.
 *
 * Subcommands:
 *   scan      compile intel and scan log files with a worker pool
 *   validate  compile intel and report every rejection by reason (no scanning)
 *   gen-intel write a synthetic STIX bundle + manifest
 *   gen-logs  write synthetic logs + ground truth for a manifest
 *
 * Exit codes (chosen so CI can distinguish "found things" from "broke"):
 *   0  scan completed, no hits
 *   1  scan completed, hits found
 *   2  usage or configuration error
 *   3  one or more inputs failed (missing file, bad bundle, worker crash)
 *
 * Hits go to stdout as JSONL by default and diagnostics go to stderr, so
 * `iocscan scan ... | jq` works without contaminating the stream.
 */

import { createWriteStream } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve as resolvePath } from "node:path";
import { parseArgs } from "node:util";
import { loadIndicators, type SkipRecord } from "./stix/bundle.ts";
import { compileIndicators, type CompiledSet } from "./stix/compile-set.ts";
import { ScanPool, defaultWorkerCount, sortHits } from "./scan/pool.ts";
import { readTextFile } from "./scan/line-reader.ts";
import { generateIntel } from "./fixtures/intel.ts";
import { generateLogs } from "./fixtures/logs.ts";
import { loadConfig, ConfigError, type ScanConfig } from "./config.ts";

const USAGE = `Usage: iocscan <command> [options]

Commands:
  scan       Compile STIX intel and scan log files
  validate   Compile intel and report rejections without scanning
  gen-intel  Generate a synthetic STIX 2.1 bundle + manifest
  gen-logs   Generate synthetic logs + ground truth from a manifest

scan options:
  --intel <path>          STIX bundle (JSON, NDJSON, .gz, .zst)        [required]
  --logs <path...>        Log files or directories                     [required]
  --output <path>         Write hits here instead of stdout
  --workers <n>           Scanning processes (default: cores - 1)
  --format <jsonl|csv>    Hit output format (default: jsonl)
  --max-hits <n>          Global hit ceiling (0 = unlimited)
  --max-hits-per-file <n> Per-file hit ceiling
  --max-capture-bytes <n> Max bytes of line text in a hit (default 2048)
  --no-line               Omit line text from hits (smaller output)
  --max-line-bytes <n>    Lines longer than this are skipped (default 8 MiB)
  --now <iso8601>         Reference time for valid_from/valid_until
  --config <path>         JSON config file (CLI flags win)
  --quiet                 Suppress the summary line

validate options:
  --intel <path>          STIX bundle                                    [required]
  --reasons               Print a per-reason count table
  --show <n>              Show the first N rejected patterns (default 10)

gen-intel options:
  --out <path>            Bundle output path                            [required]
  --manifest <path>       Manifest output path (default: <out>.manifest.json)
  --seed <n>              PRNG seed (default 1)
  --count <n>             Ordinary indicators (default 60)

gen-logs options:
  --manifest <path>       Manifest from gen-intel                       [required]
  --out <dir>             Directory for .log files + truth.json         [required]
  --lines <n>             Total lines (default 100000)
  --files <n>             File count (default 4)
  --seed <n>              PRNG seed (default 1)
`;

function fail(message: string, code = 2): never {
  process.stderr.write(`iocscan: ${message}\n`);
  process.exit(code);
}

function info(msg: string): void {
  process.stderr.write(`${msg}\n`);
}

function flatten(arrays: ReadonlyArray<readonly string[] | string | undefined>): string[] {
  const out: string[] = [];
  for (const a of arrays) {
    if (a === undefined) continue;
    if (typeof a === "string") out.push(a);
    else for (const s of a) out.push(s);
  }
  return out;
}

/** Resolve directories into their `.log`-ish members, recursively. */
async function resolveLogInputs(inputs: readonly string[]): Promise<string[]> {
  const { stat, readdir } = await import("node:fs/promises");
  const out: string[] = [];
  const walk = async (p: string): Promise<void> => {
    // `-` means stdin; it has no filesystem presence, so hand it through and
    // let the reader stream from `process.stdin`.
    if (p === "-") {
      out.push(p);
      return;
    }
    const st = await stat(p);
    if (st.isDirectory()) {
      const entries = await readdir(p, { withFileTypes: true });
      entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      for (const e of entries) {
        if (e.name.startsWith(".")) continue;
        if (e.isDirectory()) await walk(resolvePath(p, e.name));
        else out.push(resolvePath(p, e.name));
      }
    } else {
      out.push(p);
    }
  };
  for (const input of inputs) await walk(input);
  return out;
}

function mergeConfig(cfg: ScanConfig | null, cli: Partial<ScanConfig>): ScanConfig {
  if (cfg === null) return cli;
  return { ...cfg, ...Object.fromEntries(Object.entries(cli).filter(([, v]) => v !== undefined)) } as ScanConfig;
}

function formatHit(
  hit: { path: string; hit: import("./scan/engine.ts").Hit },
  format: "jsonl" | "csv",
): string {
  const h = hit.hit;
  if (format === "csv") {
    const fields = [
      hit.path,
      String(h.lineNumber),
      String(h.byteOffset),
      h.indicatorId,
      h.indicatorName ?? "",
      String(h.confidence),
      h.labels.join("|"),
      escapeCsv(h.pattern),
      escapeCsv(h.line),
    ];
    return fields.join(",");
  }
  return JSON.stringify({
    file: hit.path,
    line: h.lineNumber,
    offset: h.byteOffset,
    indicator_id: h.indicatorId,
    ...(h.indicatorName === undefined ? {} : { indicator_name: h.indicatorName }),
    confidence: h.confidence,
    labels: h.labels,
    pattern: h.pattern,
    matched: h.matchedSummary,
    text: h.line,
    truncated: h.truncated,
  });
}

function escapeCsv(s: string): string {
  if (s.includes(",") || s.includes('"') || s.includes("\n")) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function reasonHistogram(items: ReadonlyArray<{ reason: string }>): Array<[string, number]> {
  const counts = new Map<string, number>();
  for (const it of items) counts.set(it.reason, (counts.get(it.reason) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
}

interface LoadedForScan {
  readonly set: CompiledSet;
  readonly skips: readonly SkipRecord[];
  readonly objectCount: number;
}

async function loadAndCompile(intelPath: string, nowMs: number): Promise<LoadedForScan> {
  const text = await readTextFile(intelPath);
  const loaded = loadIndicators(text, { now: nowMs });
  const set = compileIndicators(loaded.indicators);
  return { set, skips: loaded.skipped, objectCount: loaded.objectCount };
}

async function cmdValidate(argv: string[]): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    options: {
      intel: { type: "string" },
      reasons: { type: "boolean", default: false },
      show: { type: "string", default: "10" },
      now: { type: "string" },
    },
    allowPositionals: false,
  });
  const intel = values.intel;
  if (intel === undefined) fail("validate requires --intel <path>");
  const nowMs = values.now === undefined ? Date.now() : Date.parse(values.now);
  if (Number.isNaN(nowMs)) fail(`--now is not a timestamp: ${values.now}`);

  let loaded: LoadedForScan;
  try {
    loaded = await loadAndCompile(intel, nowMs);
  } catch (err) {
    fail(`failed to read intel: ${(err as Error).message}`, 3);
  }

  const skipHist = reasonHistogram(loaded.skips);
  const rejectHist = reasonHistogram(loaded.set.rejected);
  const show = Number(values.show);

  process.stdout.write(
    JSON.stringify(
      {
        objects_in_bundle: loaded.objectCount,
        indicators_live: loaded.set.stats.indicators,
        programs_compiled: loaded.set.stats.compiled,
        atoms: loaded.set.stats.atoms,
        automaton_states: loaded.set.stats.acStates,
        loader_skips: Object.fromEntries(skipHist),
        compile_rejections: Object.fromEntries(rejectHist),
      },
      null,
      2,
    ) + "\n",
  );

  if (values.reasons) {
    process.stdout.write("\nLoader skips by reason:\n");
    for (const [reason, n] of skipHist) process.stdout.write(`  ${reason.padEnd(28)} ${n}\n`);
    process.stdout.write("\nCompile rejections by reason:\n");
    for (const [reason, n] of rejectHist) process.stdout.write(`  ${reason.padEnd(28)} ${n}\n`);
  }

  if (show > 0 && loaded.set.rejected.length > 0) {
    process.stdout.write(`\nFirst ${Math.min(show, loaded.set.rejected.length)} rejected patterns:\n`);
    for (const r of loaded.set.rejected.slice(0, show)) {
      process.stdout.write(`  ${r.id}  [${r.reason}]\n    ${r.pattern}\n    -> ${r.detail}\n`);
    }
  }
  return 0;
}

async function cmdScan(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      intel: { type: "string" },
      logs: { type: "string", multiple: true },
      output: { type: "string" },
      workers: { type: "string" },
      format: { type: "string" },
      "max-hits": { type: "string" },
      "max-hits-per-file": { type: "string" },
      "max-capture-bytes": { type: "string" },
      "max-line-bytes": { type: "string" },
      "no-line": { type: "boolean", default: false },
      now: { type: "string" },
      config: { type: "string" },
      quiet: { type: "boolean", default: false },
    },
    allowPositionals: true,
  });

  let cfg: ScanConfig | null = null;
  if (values.config !== undefined) {
    try {
      cfg = await loadConfig(values.config);
    } catch (err) {
      fail(err instanceof ConfigError ? err.message : String(err));
    }
  }

  const intelArg = values.intel ?? cfg?.intel;
  const logsArgs = flatten([values.logs, values.logs === undefined ? cfg?.logs : undefined]);
  const logInputs = [...logsArgs, ...positionals];
  if (intelArg === undefined) fail("scan requires --intel <path>");
  if (logInputs.length === 0) fail("scan requires --logs <path...>");

  const num = (flag: string | undefined, base: number | undefined): number | undefined => {
    if (flag === undefined) return base;
    const n = Number(flag);
    if (!Number.isFinite(n) || n < 0) fail(`${flag} must be a non-negative number`);
    return n;
  };

  const merged: ScanConfig = mergeConfig(cfg, {
    intel: intelArg,
    ...(values.output === undefined ? {} : { output: values.output }),
    ...(values.workers === undefined ? {} : { workers: num(values.workers, undefined) as number }),
    ...(values.format === undefined ? {} : { format: values.format as "jsonl" | "csv" }),
    ...(values["max-hits"] === undefined ? {} : { maxHits: num(values["max-hits"], undefined) as number }),
    ...(values["max-hits-per-file"] === undefined ? {} : { maxHitsPerFile: num(values["max-hits-per-file"], undefined) as number }),
    ...(values["max-capture-bytes"] === undefined ? {} : { maxCaptureBytes: num(values["max-capture-bytes"], undefined) as number }),
    ...(values["max-line-bytes"] === undefined ? {} : { maxLineBytes: num(values["max-line-bytes"], undefined) as number }),
    ...(values["no-line"] ? { captureLine: false } : {}),
    ...(values.now === undefined ? {} : { now: values.now }),
  });

  const format = merged.format ?? "jsonl";
  const nowMs = merged.now === undefined ? Date.now() : Date.parse(merged.now);
  if (Number.isNaN(nowMs)) fail(`now is not a valid timestamp: ${merged.now}`);

  let logPaths: string[];
  try {
    logPaths = await resolveLogInputs(logInputs);
  } catch (err) {
    fail(`cannot read log inputs: ${(err as Error).message}`, 3);
  }
  if (logPaths.length === 0) fail("no log files found in the given paths", 3);

  let loaded: LoadedForScan;
  try {
    loaded = await loadAndCompile(merged.intel as string, nowMs);
  } catch (err) {
    fail(`failed to read intel: ${(err as Error).message}`, 3);
  }

  if (!values.quiet) {
    info(
      `intel: ${loaded.objectCount} objects, ${loaded.set.stats.compiled} programs compiled, ` +
        `${loaded.skips.length} skipped, ${loaded.set.rejected.length} rejected`,
    );
    for (const [reason, n] of reasonHistogram(loaded.set.rejected).slice(0, 5)) {
      info(`  rejected ${reason}: ${n}`);
    }
    info(`logs: ${logPaths.length} file(s)`);
  }

  const workers = merged.workers ?? defaultWorkerCount();
  if (workers > 256) fail("workers must be <= 256");

  // An unwritable output (disk full, bad directory) must fail loudly and stop
  // the scan rather than silently discarding hits. `write` returning false is
  // normal back-pressure; only an `error` event is fatal.
  let outputFailed: Error | null = null;
  const writeStream = merged.output === undefined ? null : createWriteStream(merged.output, { encoding: "utf8" });
  if (writeStream !== null) {
    writeStream.on("error", (err: Error) => {
      outputFailed = err;
    });
  }
  const write = (line: string): void => {
    if (outputFailed !== null) return;
    if (writeStream !== null) writeStream.write(line + "\n");
    else process.stdout.write(line + "\n");
  };

  const started = process.hrtime.bigint();
  const pool = new ScanPool(loaded.set, {
    workers,
    engineOptions: {
      maxCaptureBytes: merged.maxCaptureBytes ?? 2048,
      maxHits: merged.maxHits ?? 0,
      captureLine: merged.captureLine ?? true,
      maxLineBytes: merged.maxLineBytes ?? 8 * 1024 * 1024,
    },
    ...(merged.maxHitsPerFile === undefined ? {} : { maxHitsPerFile: merged.maxHitsPerFile }),
    onHitBatch: (_path, hits) => {
      for (const h of hits) {
        // Emitted in worker batch order; the final summary reports that hit
        // order across files is sorted. Streaming output prioritises latency
        // over global ordering, which is what an alerting pipeline wants.
        write(formatHit({ path: _path, hit: h }, format));
      }
    },
  });

  try {
    await pool.run(logPaths);
  } catch (err) {
    fail(`scan aborted: ${(err as Error).message}`, 3);
  }

  if (writeStream !== null && outputFailed === null) {
    await new Promise<void>((resolve) => writeStream.end(resolve));
  }
  if (outputFailed !== null) {
    fail(`cannot write hits: ${(outputFailed as Error).message}`, 3);
  }
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  const results = [...pool.results.values()];
  const failed = results.filter((r) => !r.ok);
  const totals = results.reduce(
    (acc, r) => {
      acc.lines += r.counters.lines;
      acc.bytes += r.counters.bytes;
      acc.hits += r.counters.hits;
      acc.overlong += r.lineStats.overlongLines;
      return acc;
    },
    { lines: 0, bytes: 0, hits: 0, overlong: 0 },
  );

  if (!values.quiet) {
    const mb = totals.bytes / (1024 * 1024);
    const rate = elapsedMs > 0 ? mb / (elapsedMs / 1000) : 0;
    info(
      `scanned ${totals.lines} lines, ${mb.toFixed(1)} MiB in ${(elapsedMs / 1000).toFixed(2)}s ` +
        `(${rate.toFixed(1)} MiB/s, ${workers} workers)`,
    );
    info(`hits: ${totals.hits}  overlong lines skipped: ${totals.overlong}`);
    if (failed.length > 0) {
      info(`failed files: ${failed.length}`);
      for (const f of failed.slice(0, 10)) info(`  ${f.path}: ${f.error}`);
    }
  }

  if (failed.length > 0) return 3;
  return totals.hits > 0 ? 1 : 0;
}

async function cmdGenIntel(argv: string[]): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    options: {
      out: { type: "string" },
      manifest: { type: "string" },
      seed: { type: "string", default: "1" },
      count: { type: "string", default: "60" },
      now: { type: "string" },
    },
    allowPositionals: false,
  });
  if (values.out === undefined) fail("gen-intel requires --out <path>");
  const seed = Number(values.seed);
  const count = Number(values.count);
  if (!Number.isFinite(seed)) fail("--seed must be a number");
  if (!Number.isFinite(count) || count < 0) fail("--count must be a non-negative number");
  const { bundle, manifest } = generateIntel({
    seed,
    count,
    ...(values.now === undefined ? {} : { now: values.now }),
  });
  await mkdir(dirname(resolvePath(values.out)), { recursive: true });
  await writeFile(values.out, JSON.stringify(bundle, null, 2) + "\n", "utf8");
  const manifestPath = values.manifest ?? `${values.out}.manifest.json`;
  await mkdir(dirname(resolvePath(manifestPath)), { recursive: true });
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");
  info(`wrote ${values.out} (${(bundle as { objects: unknown[] }).objects.length} objects) and ${manifestPath}`);
  return 0;
}

async function cmdGenLogs(argv: string[]): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    options: {
      manifest: { type: "string" },
      out: { type: "string" },
      lines: { type: "string", default: "100000" },
      files: { type: "string", default: "4" },
      seed: { type: "string", default: "1" },
      "hit-rate": { type: "string" },
      "decoy-rate": { type: "string" },
    },
    allowPositionals: false,
  });
  if (values.manifest === undefined) fail("gen-logs requires --manifest <path>");
  if (values.out === undefined) fail("gen-logs requires --out <dir>");
  const lines = Number(values.lines);
  const files = Number(values.files);
  const seed = Number(values.seed);
  if (!Number.isInteger(lines) || lines <= 0) fail("--lines must be a positive integer");
  if (!Number.isInteger(files) || files <= 0) fail("--files must be a positive integer");
  if (!Number.isFinite(seed)) fail("--seed must be a number");

  const manifestRaw = JSON.parse(await readTextFile(values.manifest)) as import("./fixtures/intel.ts").IntelManifest;
  const out = generateLogs(manifestRaw, {
    seed,
    lines,
    files,
    ...(values["hit-rate"] === undefined ? {} : { hitRate: Number(values["hit-rate"]) }),
    ...(values["decoy-rate"] === undefined ? {} : { decoyRate: Number(values["decoy-rate"]) }),
  });
  await mkdir(resolvePath(values.out), { recursive: true });
  for (const f of out.files) {
    await writeFile(resolvePath(values.out, f.name), f.content, "utf8");
  }
  await writeFile(
    resolvePath(values.out, "truth.json"),
    JSON.stringify({ truth: out.truth, decoys: out.decoys, totalLines: out.totalLines }, null, 0) + "\n",
    "utf8",
  );
  // A brand-newline-terminated, gzip copy to exercise decompression paths.
  const { gzipSync } = await import("node:zlib");
  const combined = out.files.map((f) => f.content).join("");
  await writeFile(resolvePath(values.out, "combined.log.gz"), gzipSync(Buffer.from(combined, "utf8")));
  info(`wrote ${out.files.length} log file(s) + truth.json to ${values.out} (${out.totalLines} lines)`);
  return 0;
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const command = argv[0];
  if (command === undefined || command === "--help" || command === "-h" || command === "help") {
    process.stdout.write(USAGE);
    return 0;
  }
  const rest = argv.slice(1);
  switch (command) {
    case "scan":
      return cmdScan(rest);
    case "validate":
      return cmdValidate(rest);
    case "gen-intel":
      return cmdGenIntel(rest);
    case "gen-logs":
      return cmdGenLogs(rest);
    default:
      process.stderr.write(`iocscan: unknown command "${command}"\n\n${USAGE}`);
      return 2;
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`iocscan: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    process.exitCode = 3;
  },
);

