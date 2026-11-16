import { MatchEngine } from './engine';
import { loadBundle, filterIndicators } from './stix';
import { SkippedIndicator } from './types';

export interface BuiltEngine {
  engine: MatchEngine;
  skipped: SkippedIndicator[]; // filter-level + compile-level, in order
  nonIndicators: number;
}

/** Load a STIX bundle, drop revoked/expired indicators, compile the rest. */
export function buildEngineFromFile(intelPath: string, now?: Date): BuiltEngine {
  const bundle = loadBundle(intelPath);
  const { active, skipped, nonIndicators } = filterIndicators(bundle.objects ?? [], now);
  const engine = new MatchEngine();
  for (const ind of active) engine.addIndicator(ind);
  engine.finalize();
  return { engine, skipped: [...skipped, ...engine.skipped], nonIndicators };
}
