import * as fs from 'node:fs';
import { StixBundle, StixIndicator, StixObject, SkippedIndicator } from './types';

export function loadBundle(path: string): StixBundle {
  const raw = fs.readFileSync(path, 'utf8');
  const bundle = JSON.parse(raw) as StixBundle;
  if (bundle.type !== 'bundle' || !Array.isArray(bundle.objects)) {
    throw new Error(`${path}: not a STIX 2.1 bundle (expected {type:"bundle", objects:[...]})`);
  }
  return bundle;
}

export interface FilterResult {
  active: StixIndicator[];
  skipped: SkippedIndicator[];
  /** count of bundle objects that are not indicators at all */
  nonIndicators: number;
}

/**
 * Keep only usable indicators:
 *  - drop revoked === true
 *  - drop valid_until in the past (expired)
 *  - drop missing pattern or non-STIX pattern_type
 */
export function filterIndicators(objects: StixObject[], now: Date = new Date()): FilterResult {
  const active: StixIndicator[] = [];
  const skipped: SkippedIndicator[] = [];
  let nonIndicators = 0;
  for (const obj of objects) {
    if (obj.type !== 'indicator') { nonIndicators++; continue; }
    const ind = obj as StixIndicator;
    const id = ind.id ?? '(no id)';
    if (ind.revoked === true) {
      skipped.push({ id, reason: 'revoked', pattern: ind.pattern });
      continue;
    }
    if (typeof ind.valid_until === 'string') {
      const until = Date.parse(ind.valid_until);
      if (!Number.isNaN(until) && until < now.getTime()) {
        skipped.push({ id, reason: `expired (valid_until ${ind.valid_until})`, pattern: ind.pattern });
        continue;
      }
    }
    if (typeof ind.pattern !== 'string' || ind.pattern.trim() === '') {
      skipped.push({ id, reason: 'missing pattern' });
      continue;
    }
    if (typeof ind.pattern_type === 'string' && ind.pattern_type.toLowerCase() !== 'stix') {
      skipped.push({ id, reason: `pattern_type '${ind.pattern_type}' is not supported`, pattern: ind.pattern });
      continue;
    }
    active.push(ind);
  }
  return { active, skipped, nonIndicators };
}
