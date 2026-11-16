import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePattern, UnsupportedPattern } from '../src/patternParser';
import { lowerExpr, collectAtomIds, evalExpr, AtomSpec } from '../src/compile';
import { MatchEngine } from '../src/engine';
import { filterIndicators } from '../src/stix';
import { CidrTrie } from '../src/matchers/cidrTrie';
import { AhoCorasick } from '../src/matchers/ahoCorasick';
import { parseV4, parseV6, parseCidr } from '../src/ipaddr';
import { StixIndicator, Atom } from '../src/types';

function interner() {
  const specs: AtomSpec[] = [];
  const map = new Map<string, number>();
  const intern = (s: AtomSpec) => {
    const k = `${s.kind}:${s.value}`;
    const e = map.get(k);
    if (e !== undefined) return e;
    map.set(k, specs.length);
    specs.push(s);
    return specs.length - 1;
  };
  return { specs, intern };
}

function ind(id: string, pattern: string, extra: Partial<StixIndicator> = {}): StixIndicator {
  return { type: 'indicator', id, pattern, ...extra };
}

test('parser: simple comparison', () => {
  const e = parsePattern("[ipv4-addr:value = '1.2.3.4']");
  assert.deepEqual(e, { type: 'cmp', path: 'ipv4-addr:value', op: '=', value: '1.2.3.4' });
});

test('parser: AND/OR precedence and observation brackets', () => {
  const e = parsePattern(
    "[ipv4-addr:value = '1.2.3.4' AND domain-name:value = 'a.com'] OR [url:value = 'http://x/']",
  );
  assert.equal(e.type, 'or');
  if (e.type === 'or') {
    assert.equal(e.args[0].type, 'and');
    assert.equal(e.args[1].type, 'cmp');
  }
});

test('parser: IN list lowers to OR of atoms', () => {
  const { specs, intern } = interner();
  const expr = lowerExpr(parsePattern("[domain-name:value IN ('a.com', 'b.com')]"), intern);
  assert.equal(expr.op, 'or');
  assert.deepEqual(specs.map((s) => s.value).sort(), ['a.com', 'b.com']);
});

test('parser: quoted hash key path', () => {
  const e = parsePattern(`[file:hashes.'SHA-256' = 'abc123']`);
  assert.deepEqual(e, { type: 'cmp', path: 'file:hashes:SHA-256'.replace('hashes:', 'hashes.'), op: '=', value: 'abc123' });
});

test('compile: rejects unsupported syntax with reasons', () => {
  const bad = [
    "[domain-name:value MATCHES '.*evil.*']",
    "[file:name LIKE '%.exe']",
    "[network-traffic:dst_port = 443]",
    "[ipv4-addr:value != '1.2.3.4']",
    "[file:hashes.'SHA-256' = 'zzzz']",
    "[file:hashes.'SHA-256' = 'abcd']", // wrong length
    "[domain-name:value = 'a.com'] FOLLOWEDBY [ipv4-addr:value = '1.2.3.4']",
    "[ipv4-addr:value = '999.1.1.1']",
    "[domain-name:value = 'a.com' AND domain-name:resolves_to_refs[*].value = '1.2.3.4']",
    "[process:command_line CONTAINS 'x']",
  ];
  for (const p of bad) {
    assert.throws(() => lowerExpr(parsePattern(p), () => 0), UnsupportedPattern, p);
  }
});

test('compile: NOT is rejected', () => {
  assert.throws(
    () => lowerExpr(parsePattern("[ipv4-addr:value = '1.2.3.4' AND NOT domain-name:value = 'a.com']"), () => 0),
    UnsupportedPattern,
  );
});

test('ipaddr: v4/v6/cidr parsing', () => {
  assert.equal(parseV4('1.2.3.4'), (1n << 24n) | (2n << 16n) | (3n << 8n) | 4n);
  assert.equal(parseV4('256.1.1.1'), null);
  assert.equal(parseV6('::1'), 1n);
  assert.equal(parseV6('2001:db8::1'), (0x20010db8n << 96n) | 1n);
  assert.equal(parseV6('aa:bb:cc:dd:ee:ff'), null); // MAC address is not IPv6
  const c = parseCidr('10.0.0.0/8')!;
  assert.equal(c.prefixLen, 8);
  assert.equal(c.bits, 32);
  assert.equal(parseCidr('10.0.0.0/33'), null);
});

test('cidr trie: longest-prefix containment', () => {
  const trie = new CidrTrie(32);
  trie.insert(parseV4('10.0.0.0')!, 8, 1);
  trie.insert(parseV4('10.1.0.0')!, 16, 2);
  const acc = new Set<number>();
  trie.lookupInto(parseV4('10.1.2.3')!, acc);
  assert.deepEqual([...acc].sort(), [1, 2]);
  acc.clear();
  trie.lookupInto(parseV4('11.0.0.1')!, acc);
  assert.equal(acc.size, 0);
});

test('aho-corasick: multi-pattern with overlapping matches', () => {
  const ac = new AhoCorasick();
  ac.add('evil.com', 1, 'domain');
  ac.add('evil', 2, 'domain');
  ac.build();
  const hits: [number, number][] = [];
  ac.scan('go to evil.com now', (p, end) => hits.push([ac.patterns[p].atomId, end]));
  assert.deepEqual(hits.map((h) => h[0]).sort(), [1, 2]);
});

test('engine: domain boundary rules (subdomain ok, lookalikes rejected)', () => {
  const eng = new MatchEngine();
  eng.addIndicator(ind('i1', "[domain-name:value = 'evil.com']"));
  eng.finalize();
  assert.equal(eng.matchLine('dns query sub.evil.com from 10.0.0.1').length, 1); // subdomain
  assert.equal(eng.matchLine('dns query evil.com from 10.0.0.1').length, 1); // exact
  assert.equal(eng.matchLine('dns query notevil.com from 10.0.0.1').length, 0); // suffix lookalike
  assert.equal(eng.matchLine('dns query evil.com.cn from 10.0.0.1').length, 0); // longer TLD
  assert.equal(eng.matchLine('GET http://evil.com/x HTTP/1.1').length, 1); // inside URL
});

test('engine: AND requires all atoms in one line, OR any', () => {
  const eng = new MatchEngine();
  eng.addIndicator(ind('and1', "[ipv4-addr:value = '1.2.3.4' AND domain-name:value = 'evil.com']"));
  eng.addIndicator(ind('or1', "[domain-name:value = 'a.example'] OR [ipv4-addr:value = '9.9.9.9']"));
  eng.finalize();
  assert.deepEqual(eng.matchLine('src=1.2.3.4 host=evil.com').map((h) => h.indicator.id), ['and1']);
  assert.equal(eng.matchLine('src=1.2.3.4 host=other.org').length, 0); // only one atom
  assert.deepEqual(eng.matchLine('dst=9.9.9.9').map((h) => h.indicator.id), ['or1']);
  assert.deepEqual(eng.matchLine('visit a.example today').map((h) => h.indicator.id), ['or1']);
});

test('engine: cidr, hash, url, ipv6', () => {
  const eng = new MatchEngine();
  eng.addIndicator(ind('c1', "[ipv4-addr:value ISSUBSET '203.0.113.0/24']"));
  eng.addIndicator(ind('h1', `[file:hashes.'SHA-256' = '${'a'.repeat(64)}']`));
  eng.addIndicator(ind('u1', "[url:value = 'http://bad.example/payload.exe']"));
  eng.addIndicator(ind('v6', "[ipv6-addr:value = '2001:db8::dead']"));
  eng.finalize();
  assert.deepEqual(eng.matchLine('deny dst=203.0.113.77 dpt=443').map((h) => h.indicator.id), ['c1']);
  assert.equal(eng.matchLine('deny dst=203.0.114.1 dpt=443').length, 0);
  assert.deepEqual(eng.matchLine(`av: quarantine sha256=${'A'.repeat(64)}`).map((h) => h.indicator.id), ['h1']);
  assert.deepEqual(eng.matchLine('proxy GET http://bad.example/payload.exe 200').map((h) => h.indicator.id), ['u1']);
  assert.equal(eng.matchLine('proxy GET http://bad.example/payload.exe2 200').length, 0); // prefix is not a match
  assert.deepEqual(eng.matchLine('flow src=2001:db8::dead dpt=53').map((h) => h.indicator.id), ['v6']);
});

test('engine: confidence and name carried into hits', () => {
  const eng = new MatchEngine();
  eng.addIndicator(ind('c', "[domain-name:value = 'evil.com']", { confidence: 87, name: 'apt-x c2' }));
  eng.finalize();
  const hits = eng.matchLine('query evil.com');
  assert.equal(hits[0].indicator.confidence, 87);
  assert.equal(hits[0].indicator.name, 'apt-x c2');
  assert.deepEqual(hits[0].matchedAtoms.map((a: Atom) => `${a.kind}:${a.value}`), ['domain:evil.com']);
});

test('stix filter: revoked and expired dropped', () => {
  const now = new Date('2026-11-17T00:00:00Z');
  const objs = [
    ind('ok', "[domain-name:value = 'a.com']"),
    ind('rev', "[domain-name:value = 'b.com']", { revoked: true }),
    ind('exp', "[domain-name:value = 'c.com']", { valid_until: '2020-01-01T00:00:00Z' }),
    ind('valid', "[domain-name:value = 'd.com']", { valid_until: '2027-01-01T00:00:00Z' }),
    ind('nopat', undefined as unknown as string),
    ind('yara', 'rule x { condition: true }', { pattern_type: 'yara' }),
    { type: 'identity', id: 'identity--1' } as unknown as StixIndicator,
  ];
  const r = filterIndicators(objs, now);
  assert.deepEqual(r.active.map((i) => i.id).sort(), ['ok', 'valid']);
  assert.deepEqual(r.skipped.map((s) => s.id).sort(), ['exp', 'nopat', 'rev', 'yara']);
  assert.equal(r.nonIndicators, 1);
});

test('engine: skipped indicators are reported, not fatal', () => {
  const eng = new MatchEngine();
  eng.addIndicator(ind('good', "[domain-name:value = 'evil.com']"));
  eng.addIndicator(ind('bad', "[domain-name:value MATCHES '.*']"));
  eng.finalize();
  assert.equal(eng.indicators.length, 1);
  assert.equal(eng.skipped.length, 1);
  assert.equal(eng.skipped[0].id, 'bad');
  assert.match(eng.skipped[0].reason, /MATCHES|not supported/);
});

test('evalExpr sanity', () => {
  const { intern } = interner();
  const a = intern({ kind: 'domain', value: 'a.com' });
  const b = intern({ kind: 'ip', value: '1.2.3.4' });
  const expr = lowerExpr(parsePattern("[domain-name:value = 'a.com' AND ipv4-addr:value = '1.2.3.4']"), intern);
  assert.equal(collectAtomIds(expr).length, 2);
  assert.equal(evalExpr(expr, new Set([a, b])), true);
  assert.equal(evalExpr(expr, new Set([a])), false);
});
