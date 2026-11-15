/**
 * Synthetic log generator with injected ground truth.
 *
 * The generator writes ordinary-looking mixed traffic (web access, DNS, proxy,
 * EDR process lines, firewall) into files, and at controlled rates plants the
 * literals from an intel manifest. For every planted occurrence it records the
 * exact expected hit — indicator id, file, line number — into a ground-truth
 * file.
 *
 * This is what makes the end-to-end test meaningful: recall is measured
 * against injected occurrences, not against "whatever the engine returned".
 * A benign look-alike corpus is planted alongside (see `decoyLines`) so
 * precision can be measured too: domains that merely *contain* an indicator,
 * IPs one octet off, hashes one nibble off, and so on. Each decoy carries the
 * indicator it must NOT trigger.
 */

import { Rng } from "./rng.ts";
import type { IntelManifest } from "./intel.ts";

export interface LogOptions {
  readonly seed: number;
  /** Total lines to write across all files. */
  readonly lines: number;
  /** Number of files to split the lines into. */
  readonly files: number;
  /** Fraction of lines that plant one true positive. Default 0.01. */
  readonly hitRate?: number;
  /** Fraction of lines that plant a benign look-alike. Default 0.02. */
  readonly decoyRate?: number;
  /** First file index (for sharded generation into one directory). */
  readonly fileIndexBase?: number;
}

export interface GroundTruthHit {
  readonly file: string;
  readonly line: number;
  readonly indicatorId: string;
}

export interface DecoyCase {
  readonly file: string;
  readonly line: number;
  /** Indicator that must NOT fire on this line. */
  readonly mustNotMatch: string;
  /** Why the line is a decoy (for failure messages). */
  readonly note: string;
}

export interface GeneratedFile {
  readonly name: string;
  readonly content: string;
}

export interface LogOutput {
  readonly files: readonly GeneratedFile[];
  readonly truth: readonly GroundTruthHit[];
  readonly decoys: readonly DecoyCase[];
  readonly totalLines: number;
}

const METHODS = ["GET", "POST", "HEAD", "PUT", "DELETE"] as const;
const PATHS = ["/", "/index.html", "/api/v1/items", "/login", "/static/app.js", "/health", "/search?q=test", "/download/file.zip"];
const AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "curl/8.4.0",
  "python-requests/2.31.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1)",
];
const STATUSES = [200, 200, 200, 301, 304, 403, 404, 500];
const BENIGN_DOMAINS = [
  "www.example.com", "api.github.com", "cdn.jsdelivr.net", "mail.google.com",
  "registry.npmjs.org", "docs.microsoft.com", "pypi.org", "example.org",
];
const PROCESSES = ["svchost.exe", "chrome", "node", "python3", "curl", "bash", "powershell.exe"];

function ip(rng: Rng, base: readonly [number, number, number]): string {
  return `${base[0]}.${base[1]}.${base[2]}.${rng.range(1, 254)}`;
}

function privateIp(rng: Rng): string {
  return rng.chance(0.7) ? `10.${rng.range(0, 255)}.${rng.range(0, 255)}.${rng.range(1, 254)}` : `192.168.${rng.range(0, 255)}.${rng.range(1, 254)}`;
}

function timestamp(rng: Rng, dayOffset: number): string {
  const t = Date.UTC(2026, 5, 1) + dayOffset * 86_400_000 + rng.range(0, 86_399) * 1000;
  return new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** A random ordinary line, with `payload` optionally embedded. */
function ordinaryLine(rng: Rng, day: number, payload?: string): string {
  const kind = rng.int(10);
  const ts = timestamp(rng, day);
  if (kind < 4) {
    // Web access log.
    const method = rng.pick(METHODS);
    const status = rng.pick(STATUSES);
    const host = payload ?? rng.pick(BENIGN_DOMAINS);
    const path = rng.pick(PATHS);
    const src = privateIp(rng);
    return `${src} - - [${ts}] "${method} http://${host}${path} HTTP/1.1" ${status} ${rng.range(100, 90000)} "-" "${rng.pick(AGENTS)}"`;
  }
  if (kind < 6) {
    // DNS query log.
    const q = payload ?? rng.pick(BENIGN_DOMAINS);
    return `${ts} query[A] ${q} from ${privateIp(rng)}`;
  }
  if (kind < 8) {
    // Proxy log.
    const dst = rng.pick([ip(rng, [93, 184, 216]), ip(rng, [151, 101, 1]), ip(rng, [104, 16, 32])]);
    const host = payload ?? rng.pick(BENIGN_DOMAINS);
    return `${ts} ${privateIp(rng)} -> ${dst}:443 CONNECT ${host} bytes=${rng.range(200, 2_000_000)}`;
  }
  if (kind < 9) {
    // EDR process event.
    const proc = rng.pick(PROCESSES);
    return `${ts} process_start pid=${rng.range(100, 65000)} user=CORP\\${rng.pick(["alice", "bob", "svc_backup"])} proc=${proc} cmdline="${proc} --silent"`;
  }
  // Firewall. Background destinations deliberately avoid the documentation
  // ranges the intel generator uses (198.51.100.0/24, 203.0.113.0/24 and
  // 192.0.2.0/24), so an ordinary line can never hit an indicator by accident.
  const src = privateIp(rng);
  const dst = rng.pick([ip(rng, [93, 184, 216]), ip(rng, [151, 101, 1]), ip(rng, [104, 16, 32]), ip(rng, [172, 64, 9])]);
  return `${ts} FW ALLOW src=${src}:${rng.range(1024, 65000)} dst=${dst}:${rng.pick([80, 443, 53, 8443])} proto=tcp`;
}

/** Embed `payload` in a plausible field of a random line shape. */
function lineWith(rng: Rng, day: number, payload: string, kind: "ip" | "domain" | "url" | "hash"): string {
  const ts = timestamp(rng, day);
  const src = privateIp(rng);
  if (kind === "ip") {
    const dstPort = rng.pick([80, 443, 8080, 4444]);
    return `${ts} FW ALLOW src=${src}:${rng.range(1024, 65000)} dst=${payload}:${dstPort} proto=tcp action=allow`;
  }
  if (kind === "domain") {
    return `${ts} query[A] ${payload} from ${src}`;
  }
  if (kind === "url") {
    return `${src} - - [${ts}] "GET ${payload} HTTP/1.1" 200 ${rng.range(100, 90000)} "-" "${rng.pick(AGENTS)}"`;
  }
  return `${ts} file_scan path=/var/tmp/${rng.range(1000, 9999)}.bin sha256=${payload} verdict=quarantine src=${src}`;
}

/**
 * Every address/mask the intel manifest can match, so a decoy can be checked
 * against *all* indicators rather than only the one it was derived from. A
 * look-alike for indicator A that accidentally lands inside indicator B's
 * range is a fixture bug, not an engine bug, and it would show up as a false
 * positive in the precision metric.
 */
interface IntelSpace {
  readonly v4Exact: ReadonlySet<string>;
  readonly v4Ranges: ReadonlyArray<{ readonly base: number; readonly mask: number }>;
  readonly domains: ReadonlySet<string>;
  readonly urls: ReadonlySet<string>;
  readonly hashes: ReadonlySet<string>;
}

function buildIntelSpace(manifest: IntelManifest): IntelSpace {
  const v4Exact = new Set<string>();
  const v4Ranges: Array<{ base: number; mask: number }> = [];
  const domains = new Set<string>();
  const urls = new Set<string>();
  const hashes = new Set<string>();
  const toU32 = (s: string): number => {
    const p = s.split(".").map(Number);
    return (((p[0]! << 24) | (p[1]! << 16) | (p[2]! << 8) | p[3]!) >>> 0);
  };
  for (const lit of manifest.literals) {
    if (lit.type === "ipv4") {
      v4Exact.add(lit.text);
      v4Ranges.push({ base: toU32(lit.text), mask: 0xffffffff });
    } else if (lit.type === "cidr") {
      const [net, p] = lit.text.split("/") as [string, string];
      const prefix = Number(p);
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      v4Ranges.push({ base: (toU32(net) & mask) >>> 0, mask });
    } else if (lit.type === "domain") {
      domains.add(lit.text);
    } else if (lit.type === "url") {
      urls.add(lit.text);
    } else {
      hashes.add(lit.text);
    }
  }
  return { v4Exact, v4Ranges, domains, urls, hashes };
}

function ipInIntelSpace(space: IntelSpace, ipText: string): boolean {
  const parts = ipText.split(".");
  if (parts.length !== 4) return false;
  const value = (((Number(parts[0]) << 24) | (Number(parts[1]) << 16) | (Number(parts[2]) << 8) | Number(parts[3])) >>> 0);
  for (const r of space.v4Ranges) {
    if (((value & r.mask) >>> 0) === ((r.base & r.mask) >>> 0)) return true;
  }
  return false;
}

/** Domain indicator suffix check with label boundary semantics. */
function domainInIntelSpace(space: IntelSpace, host: string): boolean {
  const lower = host.toLowerCase();
  for (const d of space.domains) {
    if (lower === d || lower.endsWith(`.${d}`)) return true;
  }
  return false;
}

function decoyPayload(
  rng: Rng,
  space: IntelSpace,
  literal: string,
  kind: "ip" | "cidr" | "domain" | "url" | "hash",
): string | null {
  switch (kind) {
    case "ip":
    case "cidr": {
      // One octet off, retried until it leaves every indicator's range.
      const base = kind === "cidr" ? literal.split("/")[0] as string : literal;
      const parts = base.split(".").map(Number);
      for (let attempt = 0; attempt < 64; attempt++) {
        const octet = rng.int(3);
        const candidate = parts.slice();
        candidate[octet] = (candidate[octet]! + rng.range(1, 200)) % 256;
        const text = candidate.join(".");
        if (!ipInIntelSpace(space, text)) return text;
      }
      return null;
    }
    case "domain": {
      // A hostname that *contains* the indicator as a substring but not as a
      // label-boundary suffix: `evil.com` -> `evil.comlookalike.net`.
      for (let attempt = 0; attempt < 32; attempt++) {
        const [first, ...rest] = literal.split(".");
        const host = `${first}${rng.pick(["x", "not", "cdn", "mirror"])}.${rest.join(".")}`;
        if (!domainInIntelSpace(space, host)) return host;
      }
      return null;
    }
    case "url": {
      const candidate = `${literal}.bak`;
      return space.urls.has(candidate) ? null : candidate;
    }
    case "hash": {
      const last = literal[literal.length - 1];
      const candidate = literal.slice(0, -1) + (last === "0" ? "1" : "0");
      return space.hashes.has(candidate) ? null : candidate;
    }
  }
}

export function generateLogs(manifest: IntelManifest, options: LogOptions): LogOutput {
  const rng = new Rng(options.seed);
  const totalLines = options.lines;
  const fileCount = Math.max(1, options.files);
  const hitRate = options.hitRate ?? 0.01;
  const decoyRate = options.decoyRate ?? 0.02;
  const fileIndexBase = options.fileIndexBase ?? 0;
  const space = buildIntelSpace(manifest);

  const perFile = Math.ceil(totalLines / fileCount);
  const files: GeneratedFile[] = [];
  const truth: GroundTruthHit[] = [];
  const decoys: DecoyCase[] = [];

  /**
   * Literal text -> every indicator it belongs to. The intel generator reuses
   * a finite pool of addresses/domains, so several indicators can share one
   * literal; a planted occurrence then legitimately satisfies all of them and
   * the ground truth must say so.
   */
  const indicatorsByLiteral = new Map<string, string[]>();
  for (const lit of manifest.literals) {
    const key = `${lit.type}\u0000${lit.text}`;
    const list = indicatorsByLiteral.get(key);
    if (list === undefined) indicatorsByLiteral.set(key, [lit.indicatorId]);
    else list.push(lit.indicatorId);
  }
  /** Every /32 or CIDR indicator whose range contains `ip` (for CIDR plants). */
  const indicatorsForCidrSample = (sample: string): string[] => {
    const p = sample.split(".").map(Number);
    const value = ((p[0]! << 24) | (p[1]! << 16) | (p[2]! << 8) | p[3]!) >>> 0;
    const ids: string[] = [];
    for (const lit of manifest.literals) {
      if (lit.type !== "ipv4" && lit.type !== "cidr") continue;
      if (lit.type === "ipv4") {
        if (lit.text === sample) ids.push(lit.indicatorId);
        continue;
      }
      const [net, prefixStr] = lit.text.split("/") as [string, string];
      const prefix = Number(prefixStr);
      const n = net.split(".").map(Number);
      const base = ((n[0]! << 24) | (n[1]! << 16) | (n[2]! << 8) | n[3]!) >>> 0;
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      if (((value & mask) >>> 0) === ((base & mask) >>> 0)) ids.push(lit.indicatorId);
    }
    return ids;
  };

  // Only literals whose indicator survives loading are usable for planting:
  // manifest.literals already excludes revoked/expired by construction.
  const byType = {
    ipv4: manifest.literals.filter((l) => l.type === "ipv4"),
    cidr: manifest.literals.filter((l) => l.type === "cidr"),
    domain: manifest.literals.filter((l) => l.type === "domain"),
    url: manifest.literals.filter((l) => l.type === "url"),
    hash: manifest.literals.filter((l) => l.type === "hash"),
  };

  /** Turn a CIDR indicator into an address inside the range. */
  const cidrSample = (text: string): string => {
    const [net, prefixStr] = text.split("/") as [string, string];
    const prefix = Number(prefixStr);
    const octets = net.split(".").map(Number);
    const hostBits = 32 - prefix;
    const rnd = rng.nextU32() >>> 0;
    const mask = hostBits === 0 ? 0 : (0xffffffff >>> (32 - hostBits)) >>> 0;
    const baseNet = ((octets[0]! << 24) | (octets[1]! << 16) | (octets[2]! << 8) | octets[3]!) >>> 0;
    const value = (baseNet & ~mask | (rnd & mask)) >>> 0;
    return `${(value >>> 24) & 255}.${(value >>> 16) & 255}.${(value >>> 8) & 255}.${value & 255}`;
  };

  let lineCounter = 0;
  for (let f = 0; f < fileCount; f++) {
    const name = `access-${String(fileIndexBase + f).padStart(4, "0")}.log`;
    const chunks: string[] = [];
    const linesThisFile = Math.min(perFile, totalLines - f * perFile);
    if (linesThisFile <= 0) break;

    for (let i = 0; i < linesThisFile; i++) {
      const day = rng.int(28);
      const roll = rng.float();
      if (roll < hitRate && manifest.literals.length > 0) {
        // Plant one true positive, chosen across observable kinds.
        const typeRoll = rng.int(5);
        const literal = typeRoll === 0
          ? rng.pick(byType.ipv4)
          : typeRoll === 1
            ? rng.pick(byType.cidr)
            : typeRoll === 2
              ? rng.pick(byType.domain)
              : typeRoll === 3
                ? rng.pick(byType.url)
                : rng.pick(byType.hash);
        if (literal === undefined) {
          chunks.push(ordinaryLine(rng, day));
          lineCounter++;
          continue;
        }
        const payload = literal.type === "cidr" ? cidrSample(literal.text) : literal.text;
        const kind: "ip" | "domain" | "url" | "hash" =
          literal.type === "ipv4" || literal.type === "cidr" ? "ip" : literal.type;
        chunks.push(lineWith(rng, day, payload, kind));
        const ids =
          literal.type === "cidr"
            ? indicatorsForCidrSample(payload)
            : (indicatorsByLiteral.get(`${literal.type}\u0000${literal.text}`) ?? [literal.indicatorId]);
        for (const indicatorId of ids) truth.push({ file: name, line: i, indicatorId });
        lineCounter++;
        continue;
      }
      if (roll < hitRate + decoyRate && manifest.literals.length > 0) {
        // Plant a benign look-alike. The candidate source literal is retried
        // until the derived look-alike is provably outside *every* indicator,
        // including CIDR ranges other than the one it was derived from.
        let literal = rng.pick(manifest.literals);
        let kind: "ip" | "domain" | "url" | "hash" =
          literal.type === "ipv4" || literal.type === "cidr" ? "ip" : literal.type;
        let lookalike: string | null = null;
        for (let attempt = 0; attempt < 8 && lookalike === null; attempt++) {
          const decoyKind: "ip" | "cidr" | "domain" | "url" | "hash" =
            literal.type === "ipv4" ? "ip" : literal.type;
          lookalike = decoyPayload(rng, space, literal.type === "cidr" ? cidrSample(literal.text) : literal.text, decoyKind);
          if (lookalike === null) {
            literal = rng.pick(manifest.literals);
            kind = literal.type === "ipv4" || literal.type === "cidr" ? "ip" : literal.type;
          }
        }
        if (lookalike !== null) {
          chunks.push(lineWith(rng, day, lookalike, kind));
          // The decoy must not match *any* sharing indictor of the literal it
          // was derived from, so record all of them.
          const sharing =
            literal.type === "cidr"
              ? indicatorsForCidrSample(cidrSample(literal.text))
              : (indicatorsByLiteral.get(`${literal.type}\u0000${literal.text}`) ?? [literal.indicatorId]);
          for (const indicatorId of sharing) {
            decoys.push({
              file: name,
              line: i,
              mustNotMatch: indicatorId,
              note: `${literal.type} look-alike ${lookalike}`,
            });
          }
          lineCounter++;
          continue;
        }
      }
      if (roll < hitRate + decoyRate + 0.004 && manifest.andPairs.length > 0) {
        // Plant an AND pair *split across two lines*: neither line alone may
        // satisfy the pair. This catches an engine that treats AND as OR.
        const pair = rng.pick(manifest.andPairs);
        chunks.push(lineWith(rng, day, pair.left, "ip"));
        chunks.push(lineWith(rng, day, pair.right, "domain"));
        for (const [k, p] of [pair.left, pair.right].entries()) {
          const kind = k === 0 ? "ip" : "domain";
          decoys.push({
            file: name,
            line: i + k,
            mustNotMatch: pair.indicatorId,
            note: `AND half ${p} (${kind}) on its own line`,
          });
        }
        i++;
        lineCounter += 2;
        continue;
      }
      chunks.push(ordinaryLine(rng, day));
      lineCounter++;
    }

    // Terminate with a newline; the reader handles a missing one, but real
    // logs virtually always end with one and we want the fixture realistic.
    files.push({ name, content: chunks.join("\n") + "\n" });
  }

  return { files, truth, decoys, totalLines: lineCounter };
}

/**
 * Emit a single line that contains both halves of an AND pair, and the truth
 * record for it. Exposed so tests can assert positive AND behaviour without
 * depending on the random mix.
 */
export function andPairLine(manifest: IntelManifest, pairIndex: number, seed: number): { line: string; indicatorId: string } | null {
  const pair = manifest.andPairs[pairIndex];
  if (pair === undefined) return null;
  const rng = new Rng(seed);
  return {
    line: `${timestamp(rng, 0)} proxy src=${pair.left} dst=${pair.left}:443 host=${pair.right} action=allow`,
    indicatorId: pair.indicatorId,
  };
}
