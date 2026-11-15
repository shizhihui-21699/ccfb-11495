import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const NODE = process.execPath;

interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[], stdin?: string): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(NODE, [CLI, ...args], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => {
      stdout += d.toString();
    });
    child.stderr.on("data", (d: Buffer) => {
      stderr += d.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    if (stdin !== undefined) child.stdin.end(stdin);
    else child.stdin.end();
  });
}

function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "iocscan-cli-"));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

function writeIntel(dir: string): string {
  const path = join(dir, "intel.json");
  writeFileSync(
    path,
    JSON.stringify({
      type: "bundle",
      objects: [
        { type: "indicator", id: "indicator--ip", name: "C2", pattern: "[ipv4-addr:value = '203.0.113.9']", pattern_type: "stix", confidence: 80 },
        { type: "indicator", id: "indicator--dom", pattern: "[domain-name:value = 'evil.example.com']", pattern_type: "stix", confidence: 90 },
        { type: "indicator", id: "indicator--revoked", pattern: "[ipv4-addr:value = '203.0.113.10']", pattern_type: "stix", revoked: true },
        { type: "indicator", id: "indicator--bad", pattern: "[ipv4-addr:value = '1.1.1.1'] WITHIN 60 SECONDS", pattern_type: "stix" },
      ],
    }),
  );
  return path;
}

test("cli: scan finds hits and exits 1, writing JSONL with indicator metadata", async () => {
  await withTempDir(async (dir) => {
    const intel = writeIntel(dir);
    const log = join(dir, "a.log");
    writeFileSync(log, "connect 203.0.113.9\nnothing\nquery evil.example.com\n");
    const r = await runCli(["scan", "--intel", intel, "--logs", log, "--workers", "1", "--quiet", "--now", "2026-06-01T00:00:00Z"]);
    assert.equal(r.code, 1);
    const hits = r.stdout
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l));
    assert.equal(hits.length, 2);
    const ip = hits.find((h) => h.indicator_id === "indicator--ip");
    assert.notEqual(ip, undefined);
    assert.equal(ip.confidence, 80);
    assert.equal(ip.line, 0);
    assert.equal(ip.indicator_name, "C2");
    assert.equal(ip.text, "connect 203.0.113.9");
  });
});

test("cli: exits 0 when nothing matches", async () => {
  await withTempDir(async (dir) => {
    const intel = writeIntel(dir);
    const log = join(dir, "a.log");
    writeFileSync(log, "all clear\n");
    const r = await runCli(["scan", "--intel", intel, "--logs", log, "--workers", "1", "--quiet"]);
    assert.equal(r.code, 0);
    assert.equal(r.stdout.trim(), "");
  });
});

test("cli: revoked indicators are never reported", async () => {
  await withTempDir(async (dir) => {
    const intel = writeIntel(dir);
    const log = join(dir, "a.log");
    writeFileSync(log, "203.0.113.10\n");
    const r = await runCli(["scan", "--intel", intel, "--logs", log, "--workers", "1", "--quiet"]);
    assert.equal(r.code, 0);
  });
});

test("cli: --format csv emits a csv row", async () => {
  await withTempDir(async (dir) => {
    const intel = writeIntel(dir);
    const log = join(dir, "a.log");
    writeFileSync(log, "203.0.113.9\n");
    const r = await runCli(["scan", "--intel", intel, "--logs", log, "--workers", "1", "--quiet", "--format", "csv"]);
    const row = r.stdout.trim();
    assert.ok(row.startsWith(`${log},0,0,indicator--ip,`), row);
  });
});

test("cli: --output writes hits to a file and nothing to stdout", async () => {
  await withTempDir(async (dir) => {
    const intel = writeIntel(dir);
    const log = join(dir, "a.log");
    const out = join(dir, "hits.jsonl");
    writeFileSync(log, "203.0.113.9\n");
    const r = await runCli(["scan", "--intel", intel, "--logs", log, "--workers", "1", "--quiet", "--output", out]);
    assert.equal(r.code, 1);
    assert.equal(r.stdout.trim(), "");
    const lines = readFileSync(out, "utf8").trim().split("\n");
    assert.equal(lines.length, 1);
  });
});

test("cli: gzip input is decompressed", async () => {
  await withTempDir(async (dir) => {
    const intel = writeIntel(dir);
    const log = join(dir, "a.log.gz");
    const { gzipSync } = await import("node:zlib");
    writeFileSync(log, gzipSync(Buffer.from("203.0.113.9\n")));
    const r = await runCli(["scan", "--intel", intel, "--logs", log, "--workers", "1", "--quiet"]);
    assert.equal(r.code, 1);
  });
});

test("cli: stdin as the log input", async () => {
  await withTempDir(async (dir) => {
    const intel = writeIntel(dir);
    const r = await runCli(
      ["scan", "--intel", intel, "--logs", "-", "--workers", "1", "--quiet"],
      "203.0.113.9\nnothing\n",
    );
    assert.equal(r.code, 1);
    const hit = JSON.parse(r.stdout.trim());
    assert.equal(hit.indicator_id, "indicator--ip");
    assert.equal(hit.file, "-");
  });
});

test("cli: a directory argument is walked recursively and sorted", async () => {
  await withTempDir(async (dir) => {
    const intel = writeIntel(dir);
    const logs = join(dir, "logs");
    const { mkdirSync } = await import("node:fs");
    mkdirSync(join(logs, "sub"), { recursive: true });
    writeFileSync(join(logs, "b.log"), "203.0.113.9\n");
    writeFileSync(join(logs, "sub", "a.log"), "evil.example.com\n");
    const r = await runCli(["scan", "--intel", intel, "--logs", logs, "--workers", "2", "--quiet"]);
    assert.equal(r.code, 1);
    const files = r.stdout
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l).file.split("/").pop())
      .sort();
    assert.deepEqual(files, ["a.log", "b.log"]);
  });
});

test("cli: validate reports reasons and does not scan", async () => {
  await withTempDir(async (dir) => {
    const intel = writeIntel(dir);
    const r = await runCli(["validate", "--intel", intel, "--reasons"]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /indicators_live/);
    assert.match(r.stdout, /revoked/);
    assert.match(r.stdout, /QUALIFIER_UNSUPPORTED:WITHIN/);
  });
});

test("cli: missing --intel is a usage error with exit 2", async () => {
  const r = await runCli(["scan", "--logs", "x.log"]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /requires --intel/);
});

test("cli: unknown command exits 2", async () => {
  const r = await runCli(["frobnicate"]);
  assert.equal(r.code, 2);
});

test("cli: an unreadable intel file exits 3", async () => {
  await withTempDir(async (dir) => {
    const log = join(dir, "a.log");
    writeFileSync(log, "x\n");
    const r = await runCli(["scan", "--intel", join(dir, "nope.json"), "--logs", log, "--quiet"]);
    assert.equal(r.code, 3);
  });
});

test("cli: gen-intel and gen-logs produce usable fixtures", async () => {
  await withTempDir(async (dir) => {
    const intelOut = join(dir, "intel.json");
    const manifestOut = join(dir, "manifest.json");
    const gen = await runCli(["gen-intel", "--out", intelOut, "--manifest", manifestOut, "--seed", "3", "--count", "10"]);
    assert.equal(gen.code, 0);

    const logsOut = join(dir, "logs");
    const logs = await runCli(["gen-logs", "--manifest", manifestOut, "--out", logsOut, "--lines", "2000", "--files", "2", "--seed", "3"]);
    assert.equal(logs.code, 0);

    const truth = JSON.parse(readFileSync(join(logsOut, "truth.json"), "utf8")) as { truth: unknown[] };
    assert.ok(truth.truth.length > 0, "generated logs must contain planted hits");

    const scan = await runCli([
      "scan",
      "--intel",
      intelOut,
      "--logs",
      join(logsOut, "access-0000.log"),
      "--workers",
      "1",
      "--quiet",
      "--now",
      JSON.parse(readFileSync(manifestOut, "utf8")).generatedAt,
    ]);
    assert.equal(scan.code, 1);
  });
});

test("cli: --max-hits caps global output", async () => {
  await withTempDir(async (dir) => {
    const intel = writeIntel(dir);
    const log = join(dir, "a.log");
    writeFileSync(log, "203.0.113.9\n".repeat(50));
    const r = await runCli(["scan", "--intel", intel, "--logs", log, "--workers", "1", "--quiet", "--max-hits", "5"]);
    assert.equal(r.stdout.trim().split("\n").length, 5);
  });
});

test("cli: --no-line omits the log text from hits", async () => {
  await withTempDir(async (dir) => {
    const intel = writeIntel(dir);
    const log = join(dir, "a.log");
    writeFileSync(log, "203.0.113.9 very secret payload\n");
    const r = await runCli(["scan", "--intel", intel, "--logs", log, "--workers", "1", "--quiet", "--no-line"]);
    const hit = JSON.parse(r.stdout.trim());
    assert.equal(hit.text, "");
  });
});

test("cli: config file provides defaults and CLI overrides it", async () => {
  await withTempDir(async (dir) => {
    const intel = writeIntel(dir);
    const log = join(dir, "a.log");
    writeFileSync(log, "203.0.113.9\n");
    const cfg = join(dir, "cfg.json");
    writeFileSync(cfg, JSON.stringify({ intel, logs: [log], workers: 1, quiet: true }));
    const viaConfig = await runCli(["scan", "--config", cfg]);
    assert.equal(viaConfig.code, 1);
    // CLI flag wins over config: point at a non-matching file.
    const other = join(dir, "b.log");
    writeFileSync(other, "clean\n");
    const overridden = await runCli(["scan", "--config", cfg, "--logs", other]);
    assert.equal(overridden.code, 0);
  });
});

test("cli: an invalid config value exits 2 with a clear message", async () => {
  await withTempDir(async (dir) => {
    const cfg = join(dir, "cfg.json");
    writeFileSync(cfg, JSON.stringify({ workers: "many" }));
    const r = await runCli(["scan", "--config", cfg, "--intel", "x", "--logs", "y"]);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /workers must be a positive integer/);
  });
});

test("cli: overlong lines are skipped and reported, scan continues", async () => {
  await withTempDir(async (dir) => {
    const intel = writeIntel(dir);
    const log = join(dir, "a.log");
    writeFileSync(log, `${"x".repeat(300)}\n203.0.113.9\n`);
    const r = await runCli([
      "scan", "--intel", intel, "--logs", log, "--workers", "1", "--max-line-bytes", "100",
    ]);
    assert.equal(r.code, 1, "the short line must still be scanned");
    assert.match(r.stderr, /overlong lines skipped: 1/);
  });
});
