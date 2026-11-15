/**
 * Config loading: guardrails for an operator-facing scanner.
 *
 * Defaults are deliberately conservative: a bundled intel path is required, a
 * worker count above the core count is allowed but warned about, and a
 * `maxHits` ceiling exists so a pathological feed cannot fill a disk with
 * output before anyone notices.
 */

import { readFile } from "node:fs/promises";

export interface ScanConfig {
  readonly intel?: string;
  readonly logs?: string[];
  readonly output?: string;
  readonly workers?: number;
  readonly maxCaptureBytes?: number;
  readonly maxHits?: number;
  readonly maxHitsPerFile?: number;
  readonly maxLineBytes?: number;
  readonly captureLine?: boolean;
  readonly format?: "jsonl" | "csv";
  readonly now?: string;
  readonly follow?: boolean;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

function asString(v: unknown, field: string): string | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== "string") throw new ConfigError(`${field} must be a string`);
  return v;
}

function asPositiveInt(v: unknown, field: string): number | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) {
    throw new ConfigError(`${field} must be a positive integer`);
  }
  return v;
}

function asBool(v: unknown, field: string): boolean | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== "boolean") throw new ConfigError(`${field} must be a boolean`);
  return v;
}

export function parseConfig(raw: unknown): ScanConfig {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ConfigError("config must be a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  const logs = obj["logs"];
  if (logs !== undefined && (!Array.isArray(logs) || logs.some((l) => typeof l !== "string"))) {
    throw new ConfigError("logs must be an array of paths");
  }
  const format = asString(obj["format"], "format");
  if (format !== undefined && format !== "jsonl" && format !== "csv") {
    throw new ConfigError('format must be "jsonl" or "csv"');
  }
  const now = asString(obj["now"], "now");
  if (now !== undefined && Number.isNaN(Date.parse(now))) {
    throw new ConfigError(`now is not a valid ISO-8601 timestamp: ${now}`);
  }
  return {
    ...(asString(obj["intel"], "intel") === undefined ? {} : { intel: asString(obj["intel"], "intel") }),
    ...(logs === undefined ? {} : { logs: logs as string[] }),
    ...(asString(obj["output"], "output") === undefined ? {} : { output: asString(obj["output"], "output") }),
    ...(asPositiveInt(obj["workers"], "workers") === undefined ? {} : { workers: asPositiveInt(obj["workers"], "workers") }),
    ...(asPositiveInt(obj["maxCaptureBytes"], "maxCaptureBytes") === undefined ? {} : { maxCaptureBytes: asPositiveInt(obj["maxCaptureBytes"], "maxCaptureBytes") }),
    ...(asPositiveInt(obj["maxHits"], "maxHits") === undefined ? {} : { maxHits: asPositiveInt(obj["maxHits"], "maxHits") }),
    ...(asPositiveInt(obj["maxHitsPerFile"], "maxHitsPerFile") === undefined ? {} : { maxHitsPerFile: asPositiveInt(obj["maxHitsPerFile"], "maxHitsPerFile") }),
    ...(asPositiveInt(obj["maxLineBytes"], "maxLineBytes") === undefined ? {} : { maxLineBytes: asPositiveInt(obj["maxLineBytes"], "maxLineBytes") }),
    ...(asBool(obj["captureLine"], "captureLine") === undefined ? {} : { captureLine: asBool(obj["captureLine"], "captureLine") }),
    // `--config` and CLI share one shape; accept the CLI's kebab spelling too.
    ...(asBool(obj["no-line"], "no-line") === undefined
      ? {}
      : { captureLine: asBool(obj["no-line"], "no-line") === false }),
    ...(format === undefined ? {} : { format }),
    ...(now === undefined ? {} : { now }),
    ...(asBool(obj["follow"], "follow") === undefined ? {} : { follow: asBool(obj["follow"], "follow") }),
  };
}

export async function loadConfig(path: string): Promise<ScanConfig> {
  const text = await readFile(path, "utf8");
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new ConfigError(`${path}: invalid JSON: ${(err as Error).message}`);
  }
  return parseConfig(raw);
}
