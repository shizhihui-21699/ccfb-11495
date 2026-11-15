/**
 * Aggregated match index across every loaded indicator.
 *
 * One index serves a batch of compiled programs. It holds only what the
 * matchers need, keyed by a flat atom id:
 *
 *   - CIDR prefixes       -> IPv4 / IPv6 prefix tries
 *   - domains             -> one reversed-label Aho-Corasick automaton
 *   - hashes              -> per-algorithm byte maps over hex-decoded digests
 *   - URLs / emails       -> canonical byte maps
 *   - `MATCHES` / `LIKE`  -> per-observable regex lists
 *   - existential atoms   -> a per-kind "does the line contain one" answer
 *
 * Building the index is the only phase that allocates per-indicator objects;
 * after `seal()` it is read-only and shared by every scanning process.
 */

import { DomainMatcher, type DomainEntry } from "../match/domain.ts";
import { PrefixTrie } from "../match/trie.ts";
import { ByteMap } from "../index-file/byte-map.ts";
import { parseCidr, cidrNetwork } from "../util/ip.ts";
import type { AtomSpec, HashAlgorithm, ObservableKind } from "../stix/compile.ts";

/** Contribution of one atom to a match set: atomId + the indicator atoms. */
export interface AtomIndex {
  readonly v4: PrefixTrie;
  readonly v6: PrefixTrie;
  readonly domains: DomainMatcher | null;
  readonly urlMap: ByteMap | null;
  readonly emailMap: ByteMap | null;
  readonly hashMaps: ReadonlyMap<HashAlgorithm, ByteMap>;
  readonly regexes: ReadonlyMap<ObservableKind, readonly RegexEntry[]>;
  /** Atom ids that assert "line contains an observable of this kind". */
  readonly existsAtoms: ReadonlyMap<ObservableKind, readonly number[]>;
  /** Atom id per CIDR insertion, so trie hits map back to atoms. */
  readonly atomSpecs: readonly AtomSpec[];
}

export interface RegexEntry {
  readonly atomId: number;
  readonly re: RegExp;
}

export interface BuildStats {
  readonly atoms: number;
  readonly v4Prefixes: number;
  readonly v6Prefixes: number;
  readonly domains: number;
  readonly urls: number;
  readonly emails: number;
  readonly hashes: number;
  readonly regexes: number;
  readonly acStates: number;
}

export function buildAtomIndex(atoms: readonly AtomSpec[]): { index: AtomIndex; stats: BuildStats } {
  const v4 = new PrefixTrie(32, 1024);
  const v6 = new PrefixTrie(128, 256);

  const domains: DomainEntry[] = [];
  const urls: Array<{ key: Uint8Array; atomId: number }> = [];
  const emails: Array<{ key: Uint8Array; atomId: number }> = [];
  const hashKeys = new Map<HashAlgorithm, Array<{ key: Uint8Array; atomId: number }>>();
  const regexByKind = new Map<ObservableKind, RegexEntry[]>();
  const existsByKind = new Map<ObservableKind, number[]>();
  let v4Prefixes = 0;
  let v6Prefixes = 0;

  for (let atomId = 0; atomId < atoms.length; atomId++) {
    const atom = atoms[atomId] as AtomSpec;
    switch (atom.kind) {
      case "cidr": {
        const cidr = parseCidr(`${atom.network}/${atom.prefix}`);
        if (cidr === null) break;
        const net = cidrNetwork(cidr);
        if (net.addr.version === 4) {
          v4.insertV4(net.addr.n, net.prefix, atomId);
          v4Prefixes++;
        } else if (net.addr.version === 6) {
          v6.insertV6(net.addr.w, net.prefix, atomId);
          v6Prefixes++;
        }
        break;
      }
      case "domain":
        domains.push({ key: atom.key, atomId });
        break;
      case "url":
        urls.push({ key: latin1(atom.key), atomId });
        break;
      case "email":
        emails.push({ key: latin1(atom.key), atomId });
        break;
      case "hash": {
        let list = hashKeys.get(atom.algorithm);
        if (list === undefined) {
          list = [];
          hashKeys.set(atom.algorithm, list);
        }
        list.push({ key: hexToBytes(atom.key), atomId });
        break;
      }
      case "regex": {
        let list = regexByKind.get(atom.observable);
        if (list === undefined) {
          list = [];
          regexByKind.set(atom.observable, list);
        }
        list.push({ atomId, re: new RegExp(atom.source, atom.flags) });
        break;
      }
      case "exists": {
        let list = existsByKind.get(atom.observable);
        if (list === undefined) {
          list = [];
          existsByKind.set(atom.observable, list);
        }
        list.push(atomId);
        break;
      }
    }
  }

  const urlMap = urls.length > 0 ? buildByteMap(urls) : null;
  const emailMap = emails.length > 0 ? buildByteMap(emails) : null;
  const hashMaps = new Map<HashAlgorithm, ByteMap>();
  for (const [algo, list] of hashKeys) hashMaps.set(algo, buildByteMap(list));

  const domainMatcher = domains.length > 0 ? new DomainMatcher(domains) : null;

  const stats: BuildStats = {
    atoms: atoms.length,
    v4Prefixes,
    v6Prefixes,
    domains: domains.length,
    urls: urls.length,
    emails: emails.length,
    hashes: [...hashKeys.values()].reduce((n, l) => n + l.length, 0),
    regexes: [...regexByKind.values()].reduce((n, l) => n + l.length, 0),
    acStates: domainMatcher?.numStates ?? 0,
  };

  return {
    index: {
      v4,
      v6,
      domains: domainMatcher,
      urlMap,
      emailMap,
      hashMaps,
      regexes: regexByKind,
      existsAtoms: existsByKind,
      atomSpecs: atoms,
    },
    stats,
  };
}

function buildByteMap(entries: Array<{ key: Uint8Array; atomId: number }>): ByteMap {
  const map = new ByteMap(true, entries.length);
  for (const e of entries) map.insert(e.key, e.atomId);
  return map;
}

function latin1(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
