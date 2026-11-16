export interface StixObject {
  type?: string;
  id?: string;
  [k: string]: unknown;
}

export interface StixIndicator extends StixObject {
  type: 'indicator';
  id: string;
  pattern?: string;
  pattern_type?: string;
  valid_from?: string;
  valid_until?: string;
  revoked?: boolean;
  confidence?: number;
  name?: string;
}

export interface StixBundle {
  type: string;
  id?: string;
  objects?: StixObject[];
}

export type AtomKind = 'ip' | 'cidr' | 'domain' | 'url' | 'hash';

/** A single matchable unit extracted from a STIX pattern. */
export interface Atom {
  id: number;
  kind: AtomKind;
  /** normalized value: lowercase for domain/url/hash, canonical form for ip/cidr */
  value: string;
}

export type BoolExpr =
  | { op: 'and' | 'or'; args: BoolExpr[] }
  | { op: 'atom'; atomId: number };

export interface CompiledIndicator {
  id: string;
  name?: string;
  /** STIX confidence 0-100, null when absent */
  confidence: number | null;
  expr: BoolExpr;
  atomIds: number[];
}

export interface SkippedIndicator {
  id: string;
  reason: string;
  pattern?: string;
}

export interface Hit {
  indicatorId: string;
  indicatorName?: string;
  confidence: number | null;
  /** human-readable matched atoms, e.g. ["domain:evil.com"] */
  matched: string[];
  file: string;
  /** byte offset of the start of the matching line */
  offset: number;
  snippet: string;
}
