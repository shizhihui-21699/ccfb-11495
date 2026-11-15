/**
 * Synthetic STIX 2.1 intelligence generator.
 *
 * Produces a bundle that exercises every supported construct *and* every
 * documented rejection path, so the log generator and the tests can rely on a
 * known distribution of live / revoked / expired / unsupported indicators.
 *
 * The generator also emits a **manifest** describing what it created. The
 * test suite uses the manifest to assert the loader's decisions exactly, which
 * keeps the fixtures honest: a fixture that silently stops producing a
 * revoked object would fail the manifest check rather than quietly weakening
 * coverage.
 */

import { Rng } from "./rng.ts";

export interface IntelOptions {
  readonly seed: number;
  /** Number of "ordinary" indicators (IP/CIDR/domain/URL/hash). Default 60. */
  readonly count?: number;
  /** How many indicators are revoked / expired / unsupported. */
  readonly revoked?: number;
  readonly expired?: number;
  readonly notYetValid?: number;
  readonly unsupported?: number;
  readonly malformed?: number;
  /** Reference time used for valid_from / valid_until. */
  readonly now?: string;
}

export interface GeneratedLiteral {
  readonly indicatorId: string;
  readonly type: "ipv4" | "cidr" | "domain" | "url" | "hash";
  /** Text that must appear verbatim in a matching line. */
  readonly text: string;
  readonly confidence: number;
}

export interface IntelManifest {
  readonly generatedAt: string;
  readonly seed: number;
  readonly bundleId: string;
  /** Indicators expected to be live and compiled. */
  readonly live: number;
  /** Per-observable literals the log generator should plant. */
  readonly literals: readonly GeneratedLiteral[];
  /** Indicators expected to be dropped by the loader, with reasons. */
  readonly expectedSkips: ReadonlyArray<{ readonly id: string; readonly reason: string }>;
  /** Indicators expected to be rejected at compile time, with reasons. */
  readonly expectedRejections: ReadonlyArray<{ readonly id: string; readonly reason: string }>;
  /** AND-joined pairs: both texts must appear on one line. */
  readonly andPairs: ReadonlyArray<{
    readonly indicatorId: string;
    readonly left: string;
    readonly right: string;
    readonly leftType: "ipv4" | "cidr";
    readonly rightType: "domain";
  }>;
}

export interface IntelOutput {
  readonly bundle: unknown;
  readonly manifest: IntelManifest;
}

const TLDS = ["com", "net", "org", "io", "ru", "cn", "top", "xyz", "info", "biz"];
const LABELS = [
  "cdn", "mail", "login", "update", "secure", "static", "api", "docs", "portal",
  "auth", "track", "pay", "sync", "media", "img", "assets", "verify", "account",
];
const BRANDS = [
  "evil", "malware", "phish", "c2", "botnet", "drop", "payload", "stealer",
  "ransom", "beacon", "exfil", "loader", "rat", "spy",
];
const HASH_ALGOS = [
  { stix: "MD5", len: 32 },
  { stix: "SHA-1", len: 40 },
  { stix: "SHA-256", len: 64 },
  { stix: "SHA-512", len: 128 },
] as const;

function stixId(rng: Rng, prefix: string): string {
  // STIX ids are `<type>--<uuid v4-shaped>`; the engine treats them opaquely.
  const h = rng.hex(8) + "-" + rng.hex(4) + "-4" + rng.hex(3) + "-" + "89ab"[rng.int(4)] + rng.hex(3) + "-" + rng.hex(12);
  return `${prefix}--${h}`;
}

function isoAt(base: number, offsetDays: number): string {
  return new Date(base + offsetDays * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function generateIntel(options: IntelOptions): IntelOutput {
  const rng = new Rng(options.seed);
  const count = options.count ?? 60;
  const revokedCount = options.revoked ?? 4;
  const expiredCount = options.expired ?? 4;
  const notYetValidCount = options.notYetValid ?? 2;
  const unsupportedCount = options.unsupported ?? 6;
  const malformedCount = options.malformed ?? 2;

  const nowMs = Date.parse(options.now ?? "2026-06-01T00:00:00Z");
  const bundleId = stixId(rng, "bundle");
  const objects: Record<string, unknown>[] = [];
  const literals: GeneratedLiteral[] = [];
  const expectedSkips: Array<{ id: string; reason: string }> = [];
  const expectedRejections: Array<{ id: string; reason: string }> = [];
  const andPairs: Array<IntelManifest["andPairs"][number]> = [];

  const addIndicator = (
    prefix: string,
    extra: Record<string, unknown>,
  ): { id: string; confidence: number } => {
    const id = stixId(rng, prefix);
    const confidence = rng.range(10, 99);
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id,
      created: isoAt(nowMs, -rng.range(1, 90)),
      modified: isoAt(nowMs, -rng.range(0, 5)),
      valid_from: isoAt(nowMs, -rng.range(1, 30)),
      confidence,
      pattern_type: "stix",
      pattern_version: "2.1",
      ...extra,
    });
    return { id, confidence };
  };

  // Address indicators are allocated from disjoint pools so a planted
  // occurrence maps to a known set of indicators (see `generateLogs`, which
  // expands a repeated literal to every indicator sharing it).
  //
  //   IPv4 /32s : 198.18.0.0/16 (RFC 2544 benchmarking range), 65 534 slots
  //   CIDRs     : 203.0.113.0/24 carved into 16 aligned /28 blocks
  //
  // RFC 2544 space is used rather than RFC 5737 because the fixture must be
  // able to describe feeds with tens of thousands of *distinct* address
  // indicators; a single /24 would run out and start producing addresses
  // like `198.51.100.4987`, which are not IPv4 at all.
  const IPV4_SLOT_LIMIT = 65_534;
  const ipSlotCursor = { value: 0 };
  const cidrBlocks: Array<{ text: string }> = [];
  for (let b = 0; b < 16; b++) cidrBlocks.push({ text: `203.0.113.${b * 16}/28` });
  const cidrCursor = { value: 0 };

  // --- ordinary indicators ------------------------------------------------
  for (let i = 0; i < count; i++) {
    const kind = i % 5;
    if (kind === 0) {
      // Non-routable documentation/benchmark ranges keep fixtures from
      // resembling real command-and-control infrastructure.
      const slot = ipSlotCursor.value++ % IPV4_SLOT_LIMIT;
      const ip = `198.18.${Math.floor((slot + 1) / 256)}.${(slot + 1) % 256}`;
      const { id, confidence } = addIndicator("indicator", {
        name: `C2 ${ip}`,
        pattern: `[ipv4-addr:value = '${ip}']`,
        labels: ["malicious-activity"],
      });
      literals.push({ indicatorId: id, type: "ipv4", text: ip, confidence });
    } else if (kind === 1) {
      const text = (cidrBlocks[cidrCursor.value++ % cidrBlocks.length] as { text: string }).text;
      const { id, confidence } = addIndicator("indicator", {
        name: `Scan range ${text}`,
        pattern: `[ipv4-addr:value = '${text}']`,
      });
      literals.push({ indicatorId: id, type: "cidr", text, confidence });
    } else if (kind === 2) {
      const domain = `${rng.pick(BRANDS)}-${rng.pick(LABELS)}.${rng.pick(TLDS)}`;
      const { id, confidence } = addIndicator("indicator", {
        name: `Domain ${domain}`,
        pattern: `[domain-name:value = '${domain}']`,
      });
      literals.push({ indicatorId: id, type: "domain", text: domain, confidence });
    } else if (kind === 3) {
      const domain = `${rng.pick(BRANDS)}.${rng.pick(TLDS)}`;
      const path = `/${rng.pick(LABELS)}/${rng.hex(8)}.exe`;
      const url = `http://${domain}${path}`;
      const { id, confidence } = addIndicator("indicator", {
        name: `URL ${url}`,
        pattern: `[url:value = '${url}']`,
      });
      literals.push({ indicatorId: id, type: "url", text: url, confidence });
    } else {
      const algo = rng.pick(HASH_ALGOS);
      const digest = rng.hex(algo.len);
      const { id, confidence } = addIndicator("indicator", {
        name: `${algo.stix} sample`,
        pattern: `[file:hashes.'${algo.stix}' = '${digest}']`,
      });
      literals.push({ indicatorId: id, type: "hash", text: digest, confidence });
    }
  }

  // --- AND combinations ---------------------------------------------------
  for (let i = 0; i < 3; i++) {
    const ip = `198.51.100.${200 + i}`;
    const domain = `${rng.pick(BRANDS)}-pair${i}.${rng.pick(TLDS)}`;
    const { id } = addIndicator("indicator", {
      name: `Correlated ${ip} + ${domain}`,
      pattern: `[ipv4-addr:value = '${ip}'] AND [domain-name:value = '${domain}']`,
      confidence: 100,
    });
    andPairs.push({ indicatorId: id, left: ip, right: domain, leftType: "ipv4", rightType: "domain" });
  }

  // --- OR combinations ----------------------------------------------------
  const orA = `${rng.pick(BRANDS)}-or1.${rng.pick(TLDS)}`;
  const orB = `${rng.pick(BRANDS)}-or2.${rng.pick(TLDS)}`;
  addIndicator("indicator", {
    name: "Either backend",
    pattern: `[domain-name:value = '${orA}'] OR [domain-name:value = '${orB}']`,
  });

  // --- revoked / expired / future-dated -----------------------------------
  for (let i = 0; i < revokedCount; i++) {
    const id = stixId(rng, "indicator");
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id,
      created: isoAt(nowMs, -40),
      modified: isoAt(nowMs, -1),
      valid_from: isoAt(nowMs, -30),
      revoked: true,
      pattern_type: "stix",
      confidence: rng.range(10, 99),
      pattern: `[ipv4-addr:value = '198.51.100.${100 + i}']`,
    });
    expectedSkips.push({ id, reason: "revoked" });
  }
  for (let i = 0; i < expiredCount; i++) {
    const id = stixId(rng, "indicator");
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id,
      created: isoAt(nowMs, -400),
      modified: isoAt(nowMs, -300),
      valid_from: isoAt(nowMs, -400),
      valid_until: isoAt(nowMs, -rng.range(10, 200)),
      pattern_type: "stix",
      pattern: `[domain-name:value = 'expired-${i}.${rng.pick(TLDS)}']`,
    });
    expectedSkips.push({ id, reason: "expired" });
  }
  for (let i = 0; i < notYetValidCount; i++) {
    const id = stixId(rng, "indicator");
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id,
      created: isoAt(nowMs, -1),
      modified: isoAt(nowMs, -1),
      valid_from: isoAt(nowMs, rng.range(30, 200)),
      pattern_type: "stix",
      pattern: `[domain-name:value = 'future-${i}.${rng.pick(TLDS)}']`,
    });
    expectedSkips.push({ id, reason: "not_yet_valid" });
  }

  // --- unsupported constructs (must be rejected, not approximated) --------
  const unsupportedTemplates: Array<{ pattern: string; reason: string }> = [
    { pattern: `[ipv4-addr:value = '10.1.1.1'] WITHIN 300 SECONDS`, reason: "QUALIFIER_UNSUPPORTED:WITHIN" },
    { pattern: `[domain-name:value = 'q.example.com'] REPEATS 3 TIMES`, reason: "QUALIFIER_UNSUPPORTED:REPEATS" },
    { pattern: `[file:name = 'x'] FOLLOWEDBY [domain-name:value = 'y.example.com']`, reason: "QUALIFIER_UNSUPPORTED:FOLLOWEDBY" },
    { pattern: `[ipv4-addr:value != '10.2.2.2']`, reason: "OPERATOR_UNSUPPORTED:NEQ" },
    { pattern: `[file:size > 1024]`, reason: "OBSERVABLE_UNSUPPORTED" },
    { pattern: `[x509-certificate:hashes.MD5 = 'aa']`, reason: "OBSERVABLE_UNSUPPORTED" },
  ];
  for (let i = 0; i < unsupportedCount; i++) {
    const t = unsupportedTemplates[i % unsupportedTemplates.length] as { pattern: string; reason: string };
    const id = stixId(rng, "indicator");
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id,
      created: isoAt(nowMs, -10),
      modified: isoAt(nowMs, -10),
      pattern_type: "stix",
      pattern: t.pattern,
      confidence: 50,
    });
    expectedRejections.push({ id, reason: t.reason });
  }

  // --- malformed patterns (loader keeps them, compiler rejects) -----------
  for (let i = 0; i < malformedCount; i++) {
    const id = stixId(rng, "indicator");
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id,
      created: isoAt(nowMs, -10),
      modified: isoAt(nowMs, -10),
      pattern_type: "stix",
      // Both really are malformed: an unclosed bracket and an unclosed
      // string literal. A trailing space after a complete pattern is *not*
      // malformed, so it would be a bad fixture for this slot.
      pattern: i % 2 === 0 ? `[ipv4-addr:value = '10.3.3.${i}'] AND` : `[ipv4-addr:value = 'unterminated]`,
    });
    expectedRejections.push({ id, reason: "PATTERN_SYNTAX" });
  }

  // --- non-indicator decoys ----------------------------------------------
  for (let i = 0; i < 4; i++) {
    objects.push({
      type: "malware",
      spec_version: "2.1",
      id: stixId(rng, "malware"),
      name: `Sample family ${i}`,
      is_family: true,
    });
  }
  for (let i = 0; i < 2; i++) {
    objects.push({
      type: "report",
      spec_version: "2.1",
      id: stixId(rng, "report"),
      name: `Daily report ${i}`,
      published: isoAt(nowMs, -1),
      object_refs: [],
    });
  }

  // Shuffle object order: bundles are unordered, and a loader that depends on
  // ordering would be wrong.
  rng.shuffle(objects);

  const bundle = {
    type: "bundle",
    id: bundleId,
    spec_version: "2.1",
    objects,
  };

  const manifest: IntelManifest = {
    generatedAt: new Date(nowMs).toISOString(),
    seed: options.seed,
    bundleId,
    live: count + 3 + 1,
    literals,
    expectedSkips,
    expectedRejections,
    andPairs,
  };

  return { bundle, manifest };
}
