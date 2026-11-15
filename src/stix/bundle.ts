/**
 * STIX 2.1 bundle loading.
 *
 * Handles:
 *   - bundles (`{"type":"bundle","objects":[...]}`) and bare arrays of objects,
 *     plus NDJSON (one object per line), which is how many feeds ship;
 *   - `indicator` objects, compiling each `pattern`;
 *   - `*_pattern` objects (STIX Patterning in `pattern` + `valid_from`), which
 *     a few feeds use instead of indicators;
 *   - tombstones (`revoked: true`) and `valid_until` expiry.
 *
 * ### Liveness rules
 *
 * An object is *live* only when all of these hold, evaluated once at load
 * time against the scan's reference clock:
 *
 *   1. it is not revoked (`revoked: true`), and its `revoked_by_ref` is not
 *      itself a live object of the same type;
 *   2. `valid_from` is absent or <= now;
 *   3. `valid_until` is absent or > now.
 *
 * `created`/`modified` are ignored for liveness: feeds routinely backfill
 * `created` while leaving `valid_from` correct, so `created` is the wrong clock
 * to filter on. Expired-but-not-revoked indicators are dropped too — "valid
 * until last year" is not a signal to hunt for.
 *
 * A bundle revision (`revoked: false` with a higher `modified` on the same id)
 * supersedes an earlier revoked tombstone, so tombstones are collected first,
 * then cleared by any live sibling with the same id.
 */

export interface StixIndicator {
  readonly type: string;
  readonly id?: string;
  readonly name?: string;
  readonly description?: string;
  readonly pattern?: string;
  readonly pattern_type?: string;
  readonly pattern_version?: string;
  readonly valid_from?: string;
  readonly valid_until?: string;
  readonly created?: string;
  readonly modified?: string;
  readonly revoked?: boolean;
  readonly revoked_by_ref?: string;
  readonly confidence?: number;
  readonly labels?: string[];
  readonly external_references?: Array<{ source_name?: string; external_id?: string; url?: string }>;
  readonly [key: string]: unknown;
}

export interface StixBundle {
  readonly type?: string;
  readonly id?: string;
  readonly objects?: StixIndicator[];
  readonly [key: string]: unknown;
}

export type SkipReason =
  | "not_an_indicator"
  | "missing_pattern"
  | "unsupported_pattern_type"
  | "revoked"
  | "expired"
  | "not_yet_valid"
  | "invalid_json"
  | "invalid_bundle";

export interface SkipRecord {
  readonly id: string;
  readonly name?: string;
  readonly reason: SkipReason;
  readonly detail?: string;
}

export interface LiveIndicator {
  readonly id: string;
  readonly name?: string;
  readonly pattern: string;
  readonly patternType: string;
  readonly confidence: number;
  readonly labels: readonly string[];
  readonly validFrom?: string;
  readonly validUntil?: string;
  readonly sourceRef?: string;
  readonly description?: string;
}

export interface LoadResult {
  readonly indicators: LiveIndicator[];
  readonly skipped: SkipRecord[];
  readonly objectCount: number;
}

export interface LoadOptions {
  /** Reference clock in epoch ms. Defaults to `Date.now()`. */
  readonly now?: number;
  /** Accept objects whose `pattern_type` is absent (STIX 2.0 indicators). */
  readonly allowMissingPatternType?: boolean;
}

const SUPPORTED_PATTERN_TYPES = new Set(["stix", "stix2"]);

function parseTime(value: unknown): number | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

interface Candidate {
  readonly obj: StixIndicator;
  readonly modifiedMs: number;
}

/**
 * Decide liveness for a set of indicator objects.
 *
 * Two passes: gather the newest revision per id, then decide. A revoked
 * object whose id also has a newer non-revoked revision is live under that
 * revision; a revoked object with no live sibling is dead.
 */
export function selectLive(objects: readonly StixIndicator[], now: number): { live: StixIndicator[]; dead: Array<{ obj: StixIndicator; reason: SkipReason; detail: string }> } {
  const bestById = new Map<string, Candidate>();
  const noId: StixIndicator[] = [];
  for (const obj of objects) {
    if (typeof obj.id !== "string" || obj.id.length === 0) {
      noId.push(obj);
      continue;
    }
    const modifiedMs = parseTime(obj.modified) ?? parseTime(obj.created) ?? 0;
    const existing = bestById.get(obj.id);
    if (existing === undefined || modifiedMs > existing.modifiedMs) {
      bestById.set(obj.id, { obj, modifiedMs });
    }
  }

  const live: StixIndicator[] = [];
  const dead: Array<{ obj: StixIndicator; reason: SkipReason; detail: string }> = [];

  const decide = (obj: StixIndicator): void => {
    if (obj.revoked === true) {
      dead.push({ obj, reason: "revoked", detail: "revoked: true" });
      return;
    }
    const validFrom = parseTime(obj.valid_from);
    if (validFrom !== null && validFrom > now) {
      dead.push({ obj, reason: "not_yet_valid", detail: `valid_from ${obj.valid_from}` });
      return;
    }
    const validUntil = parseTime(obj.valid_until);
    if (validUntil !== null && validUntil <= now) {
      dead.push({ obj, reason: "expired", detail: `valid_until ${obj.valid_until}` });
      return;
    }
    live.push(obj);
  };

  for (const obj of noId) decide(obj);
  for (const { obj } of bestById.values()) decide(obj);
  return { live, dead };
}

/** Convert a live object into the engine's neutral indicator record. */
export function toLiveIndicator(obj: StixIndicator): LiveIndicator | SkipRecord {
  const id = typeof obj.id === "string" ? obj.id : "";
  const name = typeof obj.name === "string" ? obj.name : undefined;
  if (typeof obj.pattern !== "string" || obj.pattern.trim().length === 0) {
    return { id, name, reason: "missing_pattern" };
  }
  const patternType = typeof obj.pattern_type === "string" ? obj.pattern_type.toLowerCase() : "";
  const confidenceRaw = obj.confidence;
  const confidence =
    typeof confidenceRaw === "number" && Number.isFinite(confidenceRaw)
      ? Math.max(0, Math.min(100, Math.round(confidenceRaw)))
      : 0;
  const labels = Array.isArray(obj.labels) ? obj.labels.filter((l): l is string => typeof l === "string") : [];
  const refs = Array.isArray(obj.external_references) ? obj.external_references : [];
  const sourceRef = refs
    .map((r) => (typeof r?.external_id === "string" ? `${r.source_name ?? "ref"}:${r.external_id}` : undefined))
    .find((s): s is string => s !== undefined);
  const record: LiveIndicator = {
    id,
    pattern: obj.pattern,
    patternType,
    confidence,
    labels,
    ...(name === undefined ? {} : { name }),
    ...(typeof obj.valid_from === "string" ? { validFrom: obj.valid_from } : {}),
    ...(typeof obj.valid_until === "string" ? { validUntil: obj.valid_until } : {}),
    ...(sourceRef === undefined ? {} : { sourceRef }),
    ...(typeof obj.description === "string" ? { description: obj.description } : {}),
  };
  return record;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Load a JSON text that is a bundle, an array of objects or an NDJSON stream.
 * `invalid_json` is reported rather than thrown so one bad feed file cannot
 * abort a multi-feed run.
 */
export function parseBundleText(text: string): { objects: StixIndicator[]; error?: string } {
  const trimmed = text.trim();
  if (trimmed.length === 0) return { objects: [] };
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (Array.isArray(parsed)) {
      return { objects: parsed.filter(isRecord) as StixIndicator[] };
    }
    if (isRecord(parsed)) {
      const objects = parsed["objects"];
      if (Array.isArray(objects)) {
        return { objects: objects.filter(isRecord) as StixIndicator[] };
      }
      // A single bare object.
      return { objects: [parsed as StixIndicator] };
    }
    return { objects: [], error: "top-level JSON is not an object or array" };
  } catch (err) {
    // Fall back to NDJSON: every non-blank line is one object.
    const out: StixIndicator[] = [];
    let lineNo = 0;
    let sawAny = false;
    for (const line of trimmed.split(/\r?\n/)) {
      lineNo++;
      const l = line.trim();
      if (l.length === 0) continue;
      sawAny = true;
      try {
        const obj: unknown = JSON.parse(l);
        if (isRecord(obj)) out.push(obj as StixIndicator);
      } catch {
        return { objects: [], error: `line ${lineNo}: ${(err as Error).message}` };
      }
    }
    if (sawAny) return { objects: out };
    return { objects: [], error: (err as Error).message };
  }
}

/** Load and filter one bundle text at a fixed reference time. */
export function loadIndicators(text: string, options: LoadOptions = {}): LoadResult {
  const now = options.now ?? Date.now();
  const skipped: SkipRecord[] = [];
  const parsed = parseBundleText(text);
  if (parsed.error !== undefined) {
    return {
      indicators: [],
      skipped: [{ id: "", reason: "invalid_json", detail: parsed.error }],
      objectCount: 0,
    };
  }

  const candidates: StixIndicator[] = [];
  for (const obj of parsed.objects) {
    const type = typeof obj.type === "string" ? obj.type : "";
    if (type === "indicator" || type.endsWith("_pattern") || (options.allowMissingPatternType === true && typeof obj.pattern === "string")) {
      candidates.push(obj);
    } else {
      skipped.push({
        id: typeof obj.id === "string" ? obj.id : "",
        reason: "not_an_indicator",
        detail: type.length > 0 ? `type ${type}` : "missing type",
      });
    }
  }

  const { live, dead } = selectLive(candidates, now);
  for (const d of dead) {
    skipped.push({
      id: typeof d.obj.id === "string" ? d.obj.id : "",
      ...(typeof d.obj.name === "string" ? { name: d.obj.name } : {}),
      reason: d.reason,
      detail: d.detail,
    });
  }

  const indicators: LiveIndicator[] = [];
  for (const obj of live) {
    const rec = toLiveIndicator(obj);
    if ("reason" in rec) {
      skipped.push(rec);
      continue;
    }
    if (rec.patternType.length > 0 && !SUPPORTED_PATTERN_TYPES.has(rec.patternType)) {
      skipped.push({
        id: rec.id,
        ...(rec.name === undefined ? {} : { name: rec.name }),
        reason: "unsupported_pattern_type",
        detail: rec.patternType,
      });
      continue;
    }
    indicators.push(rec);
  }

  return { indicators, skipped, objectCount: parsed.objects.length };
}
