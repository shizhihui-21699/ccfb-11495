/**
 * Indicator compilation: STIX bundle -> matcher programs + one shared index.
 *
 * This is the bridge between the feed layer (`stix/bundle.ts`) and the scan
 * layer (`scan/line-matcher.ts`). Responsibilities:
 *
 *   - parse and compile every live indicator,
 *   - report each rejection with a machine-readable reason,
 *   - merge all programs' atoms into a single deduplicated atom table, so
 *     one trie/automaton/map serves every indicator,
 *   - build the inverted atom->program postings used to evaluate only the
 *     programs a given line can possibly satisfy.
 *
 * Atom ids in the merged table are *global*: each program's local atom ids are
 * remapped during the merge. Programs keep their own expression trees.
 *
 * ### Worker hand-off
 *
 * Worker threads cannot share JS object graphs, and structured-cloning the
 * compiled matchers would copy megabytes per worker. Instead the *spec*
 * (atom table + program expressions + indicator metadata, all plain JSON) is
 * sent once via `postMessage`, and each worker rebuilds its own index with
 * `buildFromSpec`. Index construction is fast and, more importantly, the
 * automaton and tries then live in the worker's own heap with no shared-memory
 * coordination.
 */

import { parsePattern, PatternParseError, type PatternNode } from "./pattern.ts";
import { compilePattern, type AtomSpec, type CompiledProgram, type Expr, type ObservableKind } from "./compile.ts";
import type { LiveIndicator } from "./bundle.ts";
import { buildAtomIndex, type AtomIndex } from "../index/atom-index.ts";

export interface ProgramRecord {
  readonly indicator: LiveIndicator;
  /** Expression over *global* atom ids. */
  readonly expr: Expr;
  readonly summary: string;
  readonly observables: readonly ObservableKind[];
}

export interface RejectRecord {
  readonly id: string;
  readonly name?: string;
  readonly reason: string;
  readonly detail: string;
  readonly pattern: string;
}

export interface CompiledSetStats {
  readonly indicators: number;
  readonly compiled: number;
  readonly rejected: number;
  readonly atoms: number;
  readonly acStates: number;
  readonly programs: number;
}

export interface CompiledSet {
  readonly programs: readonly ProgramRecord[];
  readonly atoms: readonly AtomSpec[];
  /** atom id -> ascending program indices. */
  readonly postings: readonly Int32Array[];
  readonly index: AtomIndex;
  readonly rejected: readonly RejectRecord[];
  readonly stats: CompiledSetStats;
}

/** Plain-JSON form of a compiled set, small enough to postMessage to workers. */
export interface CompiledSetSpec {
  readonly atoms: readonly AtomSpec[];
  readonly programs: ReadonlyArray<{
    readonly indicator: LiveIndicator;
    readonly expr: Expr;
    readonly summary: string;
    readonly observables: readonly ObservableKind[];
  }>;
  readonly rejected: readonly RejectRecord[];
  readonly stats: { readonly indicators: number; readonly rejected: number };
}

/** Key used to merge equal atoms across programs. */
function atomKey(a: AtomSpec): string {
  switch (a.kind) {
    case "cidr":
      return `c:${a.version}/${a.network}/${a.prefix}`;
    case "domain":
      return `d:${a.key}`;
    case "url":
      return `u:${a.key}`;
    case "email":
      return `e:${a.key}`;
    case "hash":
      return `h:${a.algorithm}:${a.key}`;
    case "regex":
      return `r:${a.observable}:${a.flags}:${a.source}`;
    case "exists":
      return `x:${a.observable}`;
  }
}

function remapExpr(expr: Expr, mapping: Int32Array): Expr {
  switch (expr.kind) {
    case "atom":
      return { kind: "atom", atomId: mapping[expr.atomId] as number };
    case "and":
      return { kind: "and", children: expr.children.map((c) => remapExpr(c, mapping)) };
    case "or":
      return { kind: "or", children: expr.children.map((c) => remapExpr(c, mapping)) };
  }
}

/** Recompute postings + index from a plain spec. Runs in the main thread and
 *  in every worker. */
export function buildFromSpec(spec: CompiledSetSpec): CompiledSet {
  const programs: ProgramRecord[] = spec.programs.map((p) => ({
    indicator: p.indicator,
    expr: p.expr,
    summary: p.summary,
    observables: p.observables,
  }));

  const buckets: number[][] = Array.from({ length: spec.atoms.length }, () => []);
  for (let p = 0; p < programs.length; p++) {
    const seen = new Set<number>();
    const collect = (e: Expr): void => {
      if (e.kind === "atom") {
        if (!seen.has(e.atomId)) {
          seen.add(e.atomId);
          (buckets[e.atomId] as number[]).push(p);
        }
        return;
      }
      for (const c of e.children) collect(c);
    };
    collect((programs[p] as ProgramRecord).expr);
  }
  const postings = buckets.map((b) => Int32Array.from(b));

  const { index, stats } = buildAtomIndex(spec.atoms);

  return {
    programs,
    atoms: spec.atoms,
    postings,
    index,
    rejected: spec.rejected,
    stats: {
      indicators: spec.stats.indicators,
      compiled: programs.length,
      rejected: spec.stats.rejected,
      atoms: spec.atoms.length,
      acStates: stats.acStates,
      programs: programs.length,
    },
  };
}

export function toSpec(set: CompiledSet): CompiledSetSpec {
  return {
    atoms: set.atoms,
    programs: set.programs.map((p) => ({
      indicator: p.indicator,
      expr: p.expr,
      summary: p.summary,
      observables: p.observables,
    })),
    rejected: set.rejected,
    stats: { indicators: set.stats.indicators, rejected: set.stats.rejected },
  };
}

/**
 * Compile a set of live indicators. Rejections (syntax, unsupported
 * constructs, bad values) are collected rather than thrown: a single bad
 * indicator in a 50k-object feed must not stop the run.
 */
export function compileIndicators(indicators: readonly LiveIndicator[]): CompiledSet {
  const programs: Array<CompiledSetSpec["programs"][number]> = [];
  const rejected: RejectRecord[] = [];
  const globalAtoms: AtomSpec[] = [];
  const globalKeys = new Map<string, number>();

  for (const ind of indicators) {
    let ast: PatternNode;
    try {
      ast = parsePattern(ind.pattern);
    } catch (err) {
      const detail = err instanceof PatternParseError ? err.message : String(err);
      rejected.push({
        id: ind.id,
        ...(ind.name === undefined ? {} : { name: ind.name }),
        reason: err instanceof PatternParseError ? "PATTERN_SYNTAX" : "PATTERN_PARSE_ERROR",
        detail,
        pattern: ind.pattern,
      });
      continue;
    }

    const compiled = compilePattern(ast);
    if (!compiled.ok) {
      rejected.push({
        id: ind.id,
        ...(ind.name === undefined ? {} : { name: ind.name }),
        reason: compiled.unsupported.reason,
        detail: compiled.unsupported.detail,
        pattern: ind.pattern,
      });
      continue;
    }

    const program: CompiledProgram = compiled.program;
    const mapping = new Int32Array(program.atoms.length);
    for (let local = 0; local < program.atoms.length; local++) {
      const atom = program.atoms[local] as AtomSpec;
      const key = atomKey(atom);
      let globalId = globalKeys.get(key);
      if (globalId === undefined) {
        globalId = globalAtoms.length;
        globalAtoms.push(atom);
        globalKeys.set(key, globalId);
      }
      mapping[local] = globalId;
    }

    programs.push({
      indicator: ind,
      expr: remapExpr(program.root, mapping),
      summary: program.summary,
      observables: program.observables,
    });
  }

  return buildFromSpec({
    atoms: globalAtoms,
    programs,
    rejected,
    stats: { indicators: indicators.length, rejected: rejected.length },
  });
}
