import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadIndicators } from "../src/stix/bundle.ts";
import { compileIndicators } from "../src/stix/compile-set.ts";
import { ScanPool, sortHits, defaultWorkerCount } from "../src/scan/pool.ts";

const NOW = Date.parse("2026-06-01T00:00:00Z");

function bundle(objects: unknown[]): string {
  return JSON.stringify({ type: "bundle", objects });
}

function makeSet() {
  return compileIndicators(
    loadIndicators(
      bundle([
        { type: "indicator", id: "indicator--ip", pattern: "[ipv4-addr:value = '203.0.113.9']", pattern_type: "stix", confidence: 80 },
        { type: "indicator", id: "indicator--cidr", pattern: "[ipv4-addr:value = '198.51.100.0/24']", pattern_type: "stix", confidence: 60 },
        { type: "indicator", id: "indicator--dom", pattern: "[domain-name:value = 'evil.example.com']", pattern_type: "stix", confidence: 90 },
        {
          type: "indicator",
          id: "indicator--and",
          pattern: "[ipv4-addr:value = '192.0.2.5'] AND [domain-name:value = 'evil.example.com']",
          pattern_type: "stix",
          confidence: 100,
        },
      ]),
      { now: NOW },
    ).indicators,
  );
}

function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "iocscan-pool-"));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

const ENGINE_OPTIONS = {
  maxCaptureBytes: 512,
  maxHits: 0,
  captureLine: true,
  maxLineBytes: 1 << 20,
} as const;

test("pool: scans multiple files across workers and returns every hit", async () => {
  await withTempDir(async (dir) => {
    const a = join(dir, "a.log");
    const b = join(dir, "b.log");
    writeFileSync(a, "connect 203.0.113.9\nnothing\nquery mail.evil.example.com\n");
    writeFileSync(b, "beacon 198.51.100.77\n192.0.2.5 then evil.example.com\n");

    const pool = new ScanPool(makeSet(), { workers: 2, engineOptions: { ...ENGINE_OPTIONS }, retainHits: true });
    await pool.run([a, b]);

    const hits = sortHits([...pool.hits]);
    const summary = hits.map((h) => `${h.path.split("/").pop()}:${h.hit.lineNumber}:${h.hit.indicatorId}`);
    assert.deepEqual(summary, [
      "a.log:0:indicator--ip",
      "a.log:2:indicator--dom",
      "b.log:0:indicator--cidr",
      "b.log:1:indicator--and",
      "b.log:1:indicator--dom",
    ]);
    assert.equal(pool.finishedFiles, 2);
    assert.equal(pool.failures.length, 0);
  });
});

test("pool: per-file counters and line counts are reported", async () => {
  await withTempDir(async (dir) => {
    const a = join(dir, "a.log");
    writeFileSync(a, "one\ntwo\n203.0.113.9\nfour\n");
    const pool = new ScanPool(makeSet(), { workers: 1, engineOptions: { ...ENGINE_OPTIONS }, retainHits: true });
    await pool.run([a]);
    const result = pool.results.get(a);
    assert.notEqual(result, undefined);
    assert.equal(result!.ok, true);
    assert.equal(result!.counters.lines, 4);
    assert.equal(result!.counters.hits, 1);
    assert.equal(result!.lineStats.linesRead, 4);
  });
});

test("pool: a missing file is reported as a failure, not a crash", async () => {
  await withTempDir(async (dir) => {
    const a = join(dir, "a.log");
    writeFileSync(a, "203.0.113.9\n");
    const pool = new ScanPool(makeSet(), { workers: 2, engineOptions: { ...ENGINE_OPTIONS } });
    await pool.run([a, join(dir, "does-not-exist.log")]);
    assert.equal(pool.failures.length, 1);
    assert.match(pool.failures[0]!, /does-not-exist/);
    const ok = [...pool.results.values()].filter((r) => r.ok);
    assert.equal(ok.length, 1);
  });
});

test("pool: single worker and many workers produce the same hit set", async () => {
  await withTempDir(async (dir) => {
    const paths: string[] = [];
    for (let i = 0; i < 6; i++) {
      const p = join(dir, `f${i}.log`);
      writeFileSync(p, `203.0.113.9 line ${i}\n198.51.100.${10 + i}\nevil.example.com\nplain\n`);
      paths.push(p);
    }
    const collect = async (workers: number): Promise<string[]> => {
      const pool = new ScanPool(makeSet(), { workers, engineOptions: { ...ENGINE_OPTIONS }, retainHits: true });
      await pool.run(paths);
      return sortHits([...pool.hits]).map((h) => `${h.path.split("/").pop()}:${h.hit.lineNumber}:${h.hit.indicatorId}`);
    };
    assert.deepEqual(await collect(1), await collect(8));
  });
});

test("pool: maxHitsPerFile caps each file independently", async () => {
  await withTempDir(async (dir) => {
    const a = join(dir, "a.log");
    const b = join(dir, "b.log");
    const line = "203.0.113.9\n".repeat(20);
    writeFileSync(a, line);
    writeFileSync(b, line);
    const pool = new ScanPool(makeSet(), {
      workers: 2,
      engineOptions: { ...ENGINE_OPTIONS },
      maxHitsPerFile: 3,
      retainHits: true,
    });
    await pool.run([a, b]);
    const perFile = new Map<string, number>();
    for (const h of pool.hits) perFile.set(h.path, (perFile.get(h.path) ?? 0) + 1);
    assert.equal(perFile.get(a), 3);
    assert.equal(perFile.get(b), 3);
  });
});

test("pool: onHitBatch receives hits as they arrive", async () => {
  await withTempDir(async (dir) => {
    const a = join(dir, "a.log");
    writeFileSync(a, "203.0.113.9\n203.0.113.9\n");
    const batches: number[] = [];
    const pool = new ScanPool(makeSet(), {
      workers: 1,
      engineOptions: { ...ENGINE_OPTIONS },
      onHitBatch: (_path, hits) => batches.push(hits.length),
    });
    await pool.run([a]);
    assert.equal(batches.reduce((a, b) => a + b, 0), 2);
    // Without retainHits the pool does not accumulate the corpus.
    assert.equal(pool.hits.length, 0);
  });
});

test("pool: progress callbacks report lines", async () => {
  await withTempDir(async (dir) => {
    const a = join(dir, "a.log");
    writeFileSync(a, "x\n".repeat(12000));
    const progress: number[] = [];
    const pool = new ScanPool(makeSet(), {
      workers: 1,
      engineOptions: { ...ENGINE_OPTIONS },
      onProgress: (p) => progress.push(p.lines),
    });
    await pool.run([a]);
    assert.ok(progress.length > 0, "expected at least one progress event");
    assert.ok(Math.max(...progress) >= 5000);
  });
});

test("pool: an empty file set resolves cleanly", async () => {
  const pool = new ScanPool(makeSet(), { workers: 2, engineOptions: { ...ENGINE_OPTIONS } });
  await pool.run([]);
  assert.equal(pool.totalFiles, 0);
});

test("pool: sortHits is deterministic regardless of arrival order", () => {
  const mk = (path: string, line: number, id: string) => ({
    path,
    hit: {
      program: 0,
      indicatorId: id,
      confidence: 0,
      labels: [] as string[],
      pattern: "",
      matchedSummary: "",
      lineNumber: line,
      byteOffset: line * 10,
      line: "",
      truncated: false,
    },
  });
  const a = [mk("b.log", 2, "x"), mk("a.log", 3, "y"), mk("a.log", 1, "z")];
  const b = [mk("a.log", 1, "z"), mk("b.log", 2, "x"), mk("a.log", 3, "y")];
  assert.deepEqual(
    sortHits(a).map((h) => `${h.path}:${h.hit.lineNumber}`),
    sortHits(b).map((h) => `${h.path}:${h.hit.lineNumber}`),
  );
});

test("pool: recovers when a worker dies mid-scan, with no lost files and no hang", async () => {
  await withTempDir(async (dir) => {
    const paths: string[] = [];
    for (let i = 0; i < 10; i++) {
      const p = join(dir, `f${i}.log`);
      writeFileSync(p, "203.0.113.9\n".repeat(20_000));
      paths.push(p);
    }
    const pool = new ScanPool(makeSet(), {
      workers: 2,
      engineOptions: { ...ENGINE_OPTIONS },
      retainHits: true,
      // Kill the first worker once it has started, after a short delay so it
      // is mid-file (the seam fires at spawn, before dispatch).
      onWorkerStarted: (kill) => {
        if (killed) return;
        killed = true;
        setTimeout(kill, 25);
      },
    });
    let killed = false;
    await pool.run(paths);
    // Every input must have a terminal result: processed or explicitly failed.
    assert.equal(pool.results.size, 10, "every input file must be accounted for");
    assert.equal(pool.finishedFiles, 10);
    const failed = [...pool.results.values()].filter((r) => !r.ok);
    assert.equal(failed.length, 0, `no file should be lost: ${failed.map((f) => f.error).join("; ")}`);
    // Exactly one hit per line: if a dying worker's in-flight file were
    // requeued *and* also still counted as pending, that file would be scanned
    // twice and report double hits.
    assert.equal(pool.hits.length, 10 * 20_000, "each line must be scanned exactly once");
  });
});

test("pool: gives up rather than hanging when workers keep dying", async () => {
  await withTempDir(async (dir) => {
    const paths: string[] = [];
    for (let i = 0; i < 10; i++) {
      const p = join(dir, `f${i}.log`);
      writeFileSync(p, "203.0.113.9\n".repeat(20_000));
      paths.push(p);
    }
    const pool = new ScanPool(makeSet(), {
      workers: 2,
      engineOptions: { ...ENGINE_OPTIONS },
      maxWorkerRestarts: 2,
      onWorkerStarted: (kill) => {
        setTimeout(kill, 5);
      },
    });
    await assert.rejects(pool.run(paths), /worker lost/);
  });
});

test("pool: default worker count is at least one", () => {
  assert.ok(defaultWorkerCount() >= 1);
});
