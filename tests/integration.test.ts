import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadIndicators, parseBundleText, selectLive } from "../src/stix/bundle.ts";
import { compileIndicators } from "../src/stix/compile-set.ts";
import { generateIntel } from "../src/fixtures/intel.ts";
import { ScanEngine } from "../src/scan/engine.ts";
import { iterateLines } from "../src/scan/line-reader.ts";
import { generateLogs } from "../src/fixtures/logs.ts";
import { Readable } from "node:stream";
import { gzipSync } from "node:zlib";

const NOW = Date.parse("2026-06-01T00:00:00Z");
const enc = (s: string): Uint8Array => Buffer.from(s, "latin1");

function bundleJson(objects: unknown[]): string {
  return JSON.stringify({ type: "bundle", id: "bundle--test", spec_version: "2.1", objects });
}

// ---------------------------------------------------------------------------
// Bundle loading / liveness
// ---------------------------------------------------------------------------

test("bundle: loads indicators from a bundle object", () => {
  const r = loadIndicators(
    bundleJson([
      { type: "indicator", id: "indicator--1", pattern: "[ipv4-addr:value = '1.2.3.4']", pattern_type: "stix" },
      { type: "malware", id: "malware--1", name: "x" },
    ]),
    { now: NOW },
  );
  assert.equal(r.indicators.length, 1);
  assert.equal(r.indicators[0]!.id, "indicator--1");
  assert.equal(r.objectCount, 2);
  assert.equal(r.skipped.filter((s) => s.reason === "not_an_indicator").length, 1);
});

test("bundle: accepts a bare array and NDJSON", () => {
  const arr = JSON.stringify([{ type: "indicator", id: "indicator--a", pattern: "[ipv4-addr:value = '1.1.1.1']", pattern_type: "stix" }]);
  assert.equal(loadIndicators(arr, { now: NOW }).indicators.length, 1);
  const ndjson = [
    JSON.stringify({ type: "indicator", id: "indicator--a", pattern: "[ipv4-addr:value = '1.1.1.1']", pattern_type: "stix" }),
    JSON.stringify({ type: "indicator", id: "indicator--b", pattern: "[ipv4-addr:value = '2.2.2.2']", pattern_type: "stix" }),
  ].join("\n");
  assert.equal(loadIndicators(ndjson, { now: NOW }).indicators.length, 2);
});

test("bundle: invalid JSON is reported, not thrown", () => {
  const r = loadIndicators("{ not json", { now: NOW });
  assert.equal(r.indicators.length, 0);
  assert.equal(r.skipped[0]!.reason, "invalid_json");
});

test("bundle: revoked indicators are dropped with reason known", () => {
  const r = loadIndicators(
    bundleJson([
      { type: "indicator", id: "indicator--r", pattern: "[ipv4-addr:value = '1.2.3.4']", pattern_type: "stix", revoked: true },
    ]),
    { now: NOW },
  );
  assert.equal(r.indicators.length, 0);
  assert.equal(r.skipped.find((s) => s.id === "indicator--r")!.reason, "revoked");
});

test("bundle: a newer live revision supersedes a revoked tombstone", () => {
  const r = loadIndicators(
    bundleJson([
      {
        type: "indicator",
        id: "indicator--x",
        pattern: "[ipv4-addr:value = '1.2.3.4']",
        pattern_type: "stix",
        revoked: true,
        modified: "2026-01-01T00:00:00Z",
      },
      {
        type: "indicator",
        id: "indicator--x",
        pattern: "[ipv4-addr:value = '5.6.7.8']",
        pattern_type: "stix",
        modified: "2026-02-01T00:00:00Z",
      },
    ]),
    { now: NOW },
  );
  assert.equal(r.indicators.length, 1);
  assert.match(r.indicators[0]!.pattern, /5\.6\.7\.8/);
});

test("bundle: an older live revision does not resurrect a newer tombstone", () => {
  const r = loadIndicators(
    bundleJson([
      { type: "indicator", id: "indicator--y", pattern: "[ipv4-addr:value = '1.2.3.4']", pattern_type: "stix", modified: "2026-01-01T00:00:00Z" },
      {
        type: "indicator",
        id: "indicator--y",
        pattern: "[ipv4-addr:value = '1.2.3.4']",
        pattern_type: "stix",
        revoked: true,
        modified: "2026-02-01T00:00:00Z",
      },
    ]),
    { now: NOW },
  );
  assert.equal(r.indicators.length, 0);
});

test("bundle: valid_until in the past is expired", () => {
  const r = loadIndicators(
    bundleJson([
      { type: "indicator", id: "indicator--e", pattern: "[ipv4-addr:value = '1.2.3.4']", pattern_type: "stix", valid_until: "2026-01-01T00:00:00Z" },
    ]),
    { now: NOW },
  );
  assert.equal(r.indicators.length, 0);
  assert.equal(r.skipped[0]!.reason, "expired");
});

test("bundle: valid_until exactly now counts as expired (half-open interval)", () => {
  const r = loadIndicators(
    bundleJson([
      { type: "indicator", id: "indicator--e", pattern: "[ipv4-addr:value = '1.2.3.4']", pattern_type: "stix", valid_until: new Date(NOW).toISOString() },
    ]),
    { now: NOW },
  );
  assert.equal(r.indicators.length, 0);
  assert.equal(r.skipped[0]!.reason, "expired");
});

test("bundle: valid_until in the future is live", () => {
  const r = loadIndicators(
    bundleJson([
      { type: "indicator", id: "indicator--f", pattern: "[ipv4-addr:value = '1.2.3.4']", pattern_type: "stix", valid_until: "2027-01-01T00:00:00Z" },
    ]),
    { now: NOW },
  );
  assert.equal(r.indicators.length, 1);
});

test("bundle: valid_from in the future is not yet valid", () => {
  const r = loadIndicators(
    bundleJson([
      { type: "indicator", id: "indicator--n", pattern: "[ipv4-addr:value = '1.2.3.4']", pattern_type: "stix", valid_from: "2027-01-01T00:00:00Z" },
    ]),
    { now: NOW },
  );
  assert.equal(r.indicators.length, 0);
  assert.equal(r.skipped[0]!.reason, "not_yet_valid");
});

test("bundle: malformed timestamps do not kill an indicator", () => {
  const r = loadIndicators(
    bundleJson([
      { type: "indicator", id: "indicator--m", pattern: "[ipv4-addr:value = '1.2.3.4']", pattern_type: "stix", valid_until: "not-a-date" },
    ]),
    { now: NOW },
  );
  // An unparseable bound is treated as absent rather than as "expired".
  assert.equal(r.indicators.length, 1);
});

test("bundle: unsupported pattern_type is skipped with a reason", () => {
  const r = loadIndicators(
    bundleJson([{ type: "indicator", id: "indicator--p", pattern: "snort rule here", pattern_type: "snort" }]),
    { now: NOW },
  );
  assert.equal(r.indicators.length, 0);
  assert.equal(r.skipped[0]!.reason, "unsupported_pattern_type");
});

test("bundle: confidence is clamped and defaults to 0", () => {
  const r = loadIndicators(
    bundleJson([
      { type: "indicator", id: "indicator--c1", pattern: "[ipv4-addr:value = '1.1.1.1']", pattern_type: "stix", confidence: 150 },
      { type: "indicator", id: "indicator--c2", pattern: "[ipv4-addr:value = '2.2.2.2']", pattern_type: "stix" },
      { type: "indicator", id: "indicator--c3", pattern: "[ipv4-addr:value = '3.3.3.3']", pattern_type: "stix", confidence: -5 },
    ]),
    { now: NOW },
  );
  const byId = new Map(r.indicators.map((i) => [i.id, i.confidence]));
  assert.equal(byId.get("indicator--c1"), 100);
  assert.equal(byId.get("indicator--c2"), 0);
  assert.equal(byId.get("indicator--c3"), 0);
});

test("bundle: selectLive treats missing ids as independent objects", () => {
  const objs = [
    { type: "indicator", pattern: "[ipv4-addr:value = '1.1.1.1']" },
    { type: "indicator", pattern: "[ipv4-addr:value = '2.2.2.2']" },
  ];
  const { live } = selectLive(objs as never, NOW);
  assert.equal(live.length, 2);
});

test("bundle: parseBundleText separates a single bare object", () => {
  const r = parseBundleText(JSON.stringify({ type: "indicator", id: "indicator--z", pattern: "[ipv4-addr:value = '1.1.1.1']" }));
  assert.equal(r.objects.length, 1);
  assert.equal(r.error, undefined);
});

// ---------------------------------------------------------------------------
// Compilation across many indicators
// ---------------------------------------------------------------------------

test("compile-set: identical atoms across indicators are merged", () => {
  const r = loadIndicators(
    bundleJson([
      { type: "indicator", id: "indicator--1", pattern: "[ipv4-addr:value = '1.2.3.4']", pattern_type: "stix" },
      { type: "indicator", id: "indicator--2", pattern: "[ipv4-addr:value = '1.2.3.4']", pattern_type: "stix" },
    ]),
    { now: NOW },
  );
  const set = compileIndicators(r.indicators);
  assert.equal(set.programs.length, 2);
  assert.equal(set.atoms.length, 1);
  assert.deepEqual([...set.postings[0]!], [0, 1]);
});

test("compile-set: a rejected indicator does not stop the rest", () => {
  const r = loadIndicators(
    bundleJson([
      { type: "indicator", id: "indicator--bad", pattern: "[ipv4-addr:value = '1.2.3.4'] WITHIN 60 SECONDS", pattern_type: "stix" },
      { type: "indicator", id: "indicator--good", pattern: "[ipv4-addr:value = '1.2.3.4']", pattern_type: "stix" },
    ]),
    { now: NOW },
  );
  const set = compileIndicators(r.indicators);
  assert.equal(set.programs.length, 1);
  assert.equal(set.rejected.length, 1);
  assert.match(set.rejected[0]!.reason, /QUALIFIER/);
});

// ---------------------------------------------------------------------------
// Engine behaviour
// ---------------------------------------------------------------------------

function engineFor(objects: unknown[]): ScanEngine {
  const loaded = loadIndicators(bundleJson(objects), { now: NOW });
  return new ScanEngine(compileIndicators(loaded.indicators));
}

test("engine: a supported indicator fires on a matching line with metadata", () => {
  const engine = engineFor([
    {
      type: "indicator",
      id: "indicator--hit",
      name: "Known C2",
      pattern: "[ipv4-addr:value = '203.0.113.9']",
      pattern_type: "stix",
      confidence: 87,
      labels: ["malicious-activity"],
    },
  ]);
  const hits: Array<{ id: string; confidence: number; labels: readonly string[]; line: string }> = [];
  engine.scanLine(enc("dst=203.0.113.9:443"), (h) =>
    hits.push({ id: h.indicatorId, confidence: h.confidence, labels: h.labels, line: h.line }),
  );
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.id, "indicator--hit");
  assert.equal(hits[0]!.confidence, 87);
  assert.deepEqual([...hits[0]!.labels], ["malicious-activity"]);
  assert.equal(hits[0]!.line, "dst=203.0.113.9:443");
});

test("engine: domain indicator matches subdomains but not look-alikes", () => {
  const engine = engineFor([
    { type: "indicator", id: "indicator--d", pattern: "[domain-name:value = 'evil.com']", pattern_type: "stix" },
  ]);
  const fires = (line: string): boolean => {
    let hit = false;
    engine.scanLine(enc(line), () => {
      hit = true;
    });
    return hit;
  };
  assert.equal(fires("query evil.com"), true);
  assert.equal(fires("query mail.evil.com"), true);
  assert.equal(fires("query notevil.com"), false);
  assert.equal(fires("query evil.com.attacker.net"), false);
});

test("engine: CIDR indicator catches every address in range", () => {
  const engine = engineFor([
    { type: "indicator", id: "indicator--c", pattern: "[ipv4-addr:value = '203.0.113.0/24']", pattern_type: "stix" },
  ]);
  const fires = (line: string): boolean => {
    let hit = false;
    engine.scanLine(enc(line), () => {
      hit = true;
    });
    return hit;
  };
  assert.equal(fires("10.0.0.1 203.0.113.1"), true);
  assert.equal(fires("10.0.0.1 203.0.113.255"), true);
  assert.equal(fires("10.0.0.1 203.0.114.1"), false);
});

test("engine: AND requires both observables on the same line", () => {
  const engine = engineFor([
    {
      type: "indicator",
      id: "indicator--and",
      pattern: "[ipv4-addr:value = '192.0.2.5'] AND [domain-name:value = 'evil.com']",
      pattern_type: "stix",
    },
  ]);
  const fires = (line: string): boolean => {
    let hit = false;
    engine.scanLine(enc(line), () => {
      hit = true;
    });
    return hit;
  };
  assert.equal(fires("192.0.2.5 contacted evil.com"), true);
  assert.equal(fires("192.0.2.5 only"), false);
  assert.equal(fires("evil.com only"), false);
});

test("engine: OR fires when either operand matches", () => {
  const engine = engineFor([
    {
      type: "indicator",
      id: "indicator--or",
      pattern: "[domain-name:value = 'a.example'] OR [domain-name:value = 'b.example']",
      pattern_type: "stix",
    },
  ]);
  const count = (line: string): number => {
    let n = 0;
    engine.scanLine(enc(line), () => n++);
    return n;
  };
  assert.equal(count("a.example"), 1);
  assert.equal(count("b.example"), 1);
  assert.equal(count("c.example"), 0);
});

test("engine: a line matching several indicators reports each once", () => {
  const engine = engineFor([
    { type: "indicator", id: "indicator--1", pattern: "[domain-name:value = 'evil.com']", pattern_type: "stix" },
    { type: "indicator", id: "indicator--2", pattern: "[ipv4-addr:value = '203.0.113.9']", pattern_type: "stix" },
    { type: "indicator", id: "indicator--3", pattern: "[ipv4-addr:value = '203.0.113.0/24']", pattern_type: "stix" },
  ]);
  const ids: string[] = [];
  engine.scanLine(enc("203.0.113.9 said evil.com twice: evil.com 203.0.113.9"), (h) => ids.push(h.indicatorId));
  assert.deepEqual(ids.sort(), ["indicator--1", "indicator--2", "indicator--3"]);
});

test("engine: URL indicator requires the full normalised URL", () => {
  const engine = engineFor([
    { type: "indicator", id: "indicator--u", pattern: "[url:value = 'http://evil.com/dropper.exe']", pattern_type: "stix" },
  ]);
  const fires = (line: string): boolean => {
    let hit = false;
    engine.scanLine(enc(line), () => {
      hit = true;
    });
    return hit;
  };
  assert.equal(fires("GET http://evil.com/dropper.exe HTTP/1.1"), true);
  assert.equal(fires("GET HTTP://EVIL.COM:80/dropper.exe HTTP/1.1"), true);
  assert.equal(fires("GET http://evil.com/other.exe HTTP/1.1"), false);
});

test("engine: maxHits stops the scan", () => {
  const engine = engineFor([
    { type: "indicator", id: "indicator--h", pattern: "[ipv4-addr:value = '203.0.113.9']", pattern_type: "stix" },
  ]);
  engine.resetCounters();
  let n = 0;
  const limited = new ScanEngine(compileIndicators(loadIndicators(
    bundleJson([{ type: "indicator", id: "indicator--h", pattern: "[ipv4-addr:value = '203.0.113.9']", pattern_type: "stix" }]),
    { now: NOW },
  ).indicators), { maxHits: 2 });
  for (let i = 0; i < 10; i++) limited.scanLine(enc("203.0.113.9"), () => n++);
  assert.equal(n, 2);
  void engine;
});

test("engine: counters and byte offsets are tracked", () => {
  const engine = engineFor([
    { type: "indicator", id: "indicator--o", pattern: "[ipv4-addr:value = '203.0.113.9']", pattern_type: "stix" },
  ]);
  const offsets: number[] = [];
  const lines = ["nothing", "still nothing", "203.0.113.9 here"];
  for (const line of lines) engine.scanLine(enc(line), (h) => offsets.push(h.byteOffset));
  assert.equal(engine.counters.lines, 3);
  // "nothing" + \n + "still nothing" + \n = 7 + 1 + 13 + 1 = 22
  assert.deepEqual(offsets, [22]);
});

test("engine: line capture honours maxCaptureBytes", () => {
  const loaded = loadIndicators(
    bundleJson([{ type: "indicator", id: "indicator--cap", pattern: "[ipv4-addr:value = '203.0.113.9']", pattern_type: "stix" }]),
    { now: NOW },
  );
  const engine = new ScanEngine(compileIndicators(loaded.indicators), { maxCaptureBytes: 8 });
  let captured = "";
  let truncated = false;
  engine.scanLine(enc("203.0.113.9 and a lot of trailing text"), (h) => {
    captured = h.line;
    truncated = h.truncated;
  });
  assert.equal(captured.length, 8);
  assert.equal(truncated, true);
});

test("engine: captureLine=false omits text", () => {
  const loaded = loadIndicators(
    bundleJson([{ type: "indicator", id: "indicator--noline", pattern: "[ipv4-addr:value = '203.0.113.9']", pattern_type: "stix" }]),
    { now: NOW },
  );
  const engine = new ScanEngine(compileIndicators(loaded.indicators), { captureLine: false });
  let text = "unset";
  engine.scanLine(enc("203.0.113.9"), (h) => {
    text = h.line;
  });
  assert.equal(text, "");
});

// ---------------------------------------------------------------------------
// Line reader
// ---------------------------------------------------------------------------

test("line reader: streams lines without a trailing newline", async () => {
  const lines: string[] = [];
  const stats = await (async () => {
    const gen = iterateLines(Readable.from([Buffer.from("a\nb\nc")]));
    for (;;) {
      const n = await gen.next();
      if (n.done) return n.value;
      lines.push(Buffer.from(n.value).toString());
    }
  })();
  assert.deepEqual(lines, ["a", "b", "c"]);
  assert.equal(stats.linesRead, 3);
});

test("line reader: trims CRLF", async () => {
  const lines: string[] = [];
  const gen = iterateLines(Readable.from([Buffer.from("a\r\nb\r\n")]));
  for (;;) {
    const n = await gen.next();
    if (n.done) break;
    lines.push(Buffer.from(n.value).toString());
  }
  assert.deepEqual(lines, ["a", "b"]);
});

test("line reader: handles line boundaries split across chunks", async () => {
  const chunks = [Buffer.from("hel"), Buffer.from("lo\nwor"), Buffer.from("ld\n")];
  const lines: string[] = [];
  const gen = iterateLines(Readable.from(chunks));
  for (;;) {
    const n = await gen.next();
    if (n.done) break;
    lines.push(Buffer.from(n.value).toString());
  }
  assert.deepEqual(lines, ["hello", "world"]);
});

test("line reader: skips overlong lines and reports them", async () => {
  const big = "x".repeat(100);
  const input = Buffer.from(`ok\n${big}\nfine\n`);
  const lines: string[] = [];
  const stats = await (async () => {
    const gen = iterateLines(Readable.from([input]), { maxLineBytes: 20 });
    for (;;) {
      const n = await gen.next();
      if (n.done) return n.value;
      lines.push(Buffer.from(n.value).toString());
    }
  })();
  assert.deepEqual(lines, ["ok", "fine"]);
  assert.equal(stats.overlongLines, 1);
});

test("line reader: decompresses gzip transparently through the CLI path", async () => {
  const dir = mkdtempSync(join(tmpdir(), "iocscan-"));
  try {
    const gz = join(dir, "x.log.gz");
    writeFileSync(gz, gzipSync(Buffer.from("one\ntwo\n")));
    const { openByteStream } = await import("../src/scan/line-reader.ts");
    const stream = openByteStream(gz);
    const lines: string[] = [];
    const gen = iterateLines(stream);
    for (;;) {
      const n = await gen.next();
      if (n.done) break;
      lines.push(Buffer.from(n.value).toString());
    }
    assert.deepEqual(lines, ["one", "two"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// End-to-end with generated fixtures
// ---------------------------------------------------------------------------

test("end-to-end: generated intel and logs achieve full recall with no false positives", () => {
  const { bundle, manifest } = generateIntel({ seed: 1234, count: 40, now: "2026-06-01T00:00:00Z" });
  const loaded = loadIndicators(JSON.stringify(bundle), { now: NOW });
  const set = compileIndicators(loaded.indicators);
  assert.ok(set.programs.length > 30, "expected a meaningful number of compiled programs");

  // Every manifest expectation must hold, so a fixture change cannot quietly
  // reduce coverage without failing here.
  const skipReasons = new Set(loaded.skipped.map((s) => `${s.id}:${s.reason}`));
  for (const exp of manifest.expectedSkips) {
    assert.ok(skipReasons.has(`${exp.id}:${exp.reason}`), `expected skip ${exp.id} as ${exp.reason}`);
  }
  const rejectReasons = new Set(set.rejected.map((r) => `${r.id}:${r.reason}`));
  for (const exp of manifest.expectedRejections) {
    assert.ok(rejectReasons.has(`${exp.id}:${exp.reason}`), `expected rejection ${exp.id} as ${exp.reason}`);
  }

  const engine = new ScanEngine(set);
  const logs = generateLogs(manifest, { seed: 1234, lines: 20000, files: 4, hitRate: 0.02, decoyRate: 0.02 });

  const observed = new Set<string>();
  for (const file of logs.files) {
    const lines = file.content.split("\n").slice(0, -1);
    for (let i = 0; i < lines.length; i++) {
      engine.scanLine(enc(lines[i] as string), (h) => observed.add(`${file.name}:${i}:${h.indicatorId}`));
    }
  }

  const truth = new Set(logs.truth.map((t) => `${t.file}:${t.line}:${t.indicatorId}`));
  const missed = [...truth].filter((t) => !observed.has(t));
  assert.deepEqual(missed, [], "every planted occurrence must be found");

  const decoyHits = logs.decoys.filter((d) => observed.has(`${d.file}:${d.line}:${d.mustNotMatch}`));
  assert.deepEqual(decoyHits, [], "no look-alike may fire its indicator");

  const expected = new Set([...truth, ...logs.decoys.map((d) => `${d.file}:${d.line}:${d.mustNotMatch}`)]);
  void expected;
  // Any hit that is neither a planted truth nor a decoy marker is a false
  // positive against background traffic.
  const truthByLine = new Set(logs.truth.map((t) => `${t.file}:${t.line}`));
  const decoyByLine = new Set(logs.decoys.map((d) => `${d.file}:${d.line}`));
  const unexpected = [...observed].filter((o) => {
    const [file, line] = o.split(":") as [string, string];
    return !truthByLine.has(`${file}:${line}`) && !decoyByLine.has(`${file}:${line}`);
  });
  assert.deepEqual(unexpected, [], "background traffic must not produce hits");
});
