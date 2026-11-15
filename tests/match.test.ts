import { test } from "node:test";
import assert from "node:assert/strict";
import { AhoCorasick } from "../src/match/aho-corasick.ts";
import { DomainMatcher, HostBuffer, type DomainEntry } from "../src/match/domain.ts";
import { PrefixTrie } from "../src/match/trie.ts";
import { ByteMap } from "../src/index-file/byte-map.ts";
import { parseIpv4, parseIpv6 } from "../src/util/ip.ts";

const enc = (s: string): Uint8Array => Buffer.from(s, "latin1");

// ---------------------------------------------------------------------------
// Aho-Corasick
// ---------------------------------------------------------------------------

test("aho-corasick: classic overlap case", () => {
  const ac = new AhoCorasick(["he", "she", "his", "hers"].map(enc));
  assert.deepEqual(ac.match(enc("ushers")).sort(), [0, 1, 3]);
});

test("aho-corasick: reports every occurrence position", () => {
  const ac = new AhoCorasick([enc("ab")]);
  const seen: Array<[number, number]> = [];
  ac.scan(enc("abab"), (pid, end) => seen.push([pid, end]));
  assert.deepEqual(seen, [[0, 1], [0, 3]]);
});

test("aho-corasick: suffix patterns fire on longer matches", () => {
  const ac = new AhoCorasick([enc("bc"), enc("abc")]);
  assert.deepEqual(ac.match(enc("abc")).sort(), [0, 1]);
});

test("aho-corasick: no false match across unrelated text", () => {
  const ac = new AhoCorasick([enc("evil.com")]);
  assert.deepEqual(ac.match(enc("notevil.com")), [0]); // substring semantics
  assert.deepEqual(ac.match(enc("good.com")), []);
});

test("aho-corasick: empty input and empty pattern set", () => {
  const ac = new AhoCorasick([enc("x")]);
  assert.deepEqual(ac.match(new Uint8Array(0)), []);
  const empty = new AhoCorasick([]);
  assert.deepEqual(empty.match(enc("anything")), []);
});

test("aho-corasick: matchInto deduplicates and respects capacity", () => {
  const ac = new AhoCorasick([enc("a"), enc("aa")]);
  const hits = new Int32Array(1);
  const n = ac.matchInto(enc("aaaa"), hits);
  assert.equal(n, 1);
  assert.equal(hits.length, 1);
});

// ---------------------------------------------------------------------------
// Domain matcher
// ---------------------------------------------------------------------------

function domainHits(entries: DomainEntry[], hosts: string[]): number[] {
  const matcher = new DomainMatcher(entries);
  const buf = new HostBuffer();
  for (const h of hosts) {
    const b = enc(h);
    buf.addHost(b, 0, b.length);
  }
  const out: number[] = [];
  matcher.scanHosts(buf.buffer, buf.starts, (atomId) => out.push(atomId));
  return [...new Set(out)].sort();
}

test("domain: exact host matches", () => {
  assert.deepEqual(domainHits([{ key: "evil.com", atomId: 7 }], ["evil.com"]), [7]);
});

test("domain: subdomain matches", () => {
  assert.deepEqual(domainHits([{ key: "evil.com", atomId: 7 }], ["mail.evil.com"]), [7]);
  assert.deepEqual(domainHits([{ key: "evil.com", atomId: 7 }], ["a.b.c.evil.com"]), [7]);
});

test("domain: a look-alike host that only contains the indicator does not match", () => {
  assert.deepEqual(domainHits([{ key: "evil.com", atomId: 7 }], ["notevil.com"]), []);
  assert.deepEqual(domainHits([{ key: "evil.com", atomId: 7 }], ["evilevil.com"]), []);
});

test("domain: indicator as a leading label of a longer name does not match", () => {
  assert.deepEqual(domainHits([{ key: "evil.com", atomId: 7 }], ["evil.com.attacker.net"]), []);
});

test("domain: case-insensitive", () => {
  const buf = new HostBuffer();
  const b = enc("MAIL.Evil.COM");
  buf.addHost(b, 0, b.length);
  const matcher = new DomainMatcher([{ key: "evil.com", atomId: 3 }]);
  const out: number[] = [];
  matcher.scanHosts(buf.buffer, buf.starts, (id) => out.push(id));
  assert.deepEqual(out, [3]);
});

test("domain: one automaton pass handles many indicators and many hosts", () => {
  const entries: DomainEntry[] = [
    { key: "a.example", atomId: 1 },
    { key: "b.example", atomId: 2 },
    { key: "c.example", atomId: 3 },
  ];
  assert.deepEqual(domainHits(entries, ["x.a.example", "b.example", "notc.example", "c.example."]), [1, 2, 3]);
});

test("domain: hosts never match across a host boundary", () => {
  // `evil.com` split across two hosts must not be joined by the automaton.
  assert.deepEqual(domainHits([{ key: "vil.comx", atomId: 9 }], ["evil.com", "xvil.comx"]), []);
});

test("host buffer: separates hosts with NUL and reverses them", () => {
  const buf = new HostBuffer();
  const a = enc("ab.com");
  buf.addHost(a, 0, a.length);
  assert.equal(Buffer.from(buf.buffer.subarray(0, 6)).toString("latin1"), "moc.ba");
  assert.equal(buf.buffer[6], 0);
  assert.equal(buf.count, 1);
});

test("host buffer: grows past its initial capacity", () => {
  const buf = new HostBuffer();
  for (let i = 0; i < 200; i++) {
    const h = enc(`host${i}.example.com`);
    buf.addHost(h, 0, h.length);
  }
  assert.equal(buf.count, 200);
  const matcher = new DomainMatcher([{ key: "example.com", atomId: 1 }]);
  const out: number[] = [];
  matcher.scanHosts(buf.buffer, buf.starts, (id) => out.push(id));
  assert.equal(new Set(out).size, 1);
});

// ---------------------------------------------------------------------------
// Prefix trie
// ---------------------------------------------------------------------------

test("trie: longest-prefix semantics return both the /8 and the /32", () => {
  const trie = new PrefixTrie(32);
  trie.insertV4(parseIpv4("10.0.0.0")!.n, 8, 100);
  trie.insertV4(parseIpv4("10.1.2.3")!.n, 32, 200);
  const hit = (ip: string): number[] => {
    const out: number[] = [];
    trie.lookupV4(parseIpv4(ip)!.n, (p) => out.push(p));
    return out.sort((a, b) => a - b);
  };
  assert.deepEqual(hit("10.1.2.3"), [100, 200]);
  assert.deepEqual(hit("10.9.9.9"), [100]);
  assert.deepEqual(hit("11.0.0.1"), []);
});

test("trie: /0 matches everything", () => {
  const trie = new PrefixTrie(32);
  trie.insertV4(0, 0, 1);
  const out: number[] = [];
  trie.lookupV4(parseIpv4("8.8.8.8")!.n, (p) => out.push(p));
  assert.deepEqual(out, [1]);
});

test("trie: ipv6 containment across word boundaries", () => {
  const trie = new PrefixTrie(128);
  const net = parseIpv6("2001:db8::")!;
  trie.insertV6(net.w, 32, 5);
  const hit = (ip: string): number[] => {
    const out: number[] = [];
    trie.lookupV6(parseIpv6(ip)!.w, (p) => out.push(p));
    return out;
  };
  assert.deepEqual(hit("2001:db8::1"), [5]);
  assert.deepEqual(hit("2001:db8:ffff::1"), [5]);
  assert.deepEqual(hit("2001:db9::1"), []);
});

test("trie: identical prefixes inserted twice both report", () => {
  const trie = new PrefixTrie(32);
  const net = parseIpv4("192.0.2.0")!.n;
  trie.insertV4(net, 24, 1);
  trie.insertV4(net, 24, 2);
  const out: number[] = [];
  trie.lookupV4(parseIpv4("192.0.2.55")!.n, (p) => out.push(p));
  assert.deepEqual(out.sort(), [1, 2]);
});

test("trie: grows through many inserts without losing entries", () => {
  const trie = new PrefixTrie(32, 2);
  for (let i = 0; i < 2000; i++) {
    const ip = ((10 << 24) | (i & 0xffff)) >>> 0;
    trie.insertV4(ip, 32, i);
  }
  assert.equal(trie.size, 2000);
  assert.ok(trie.numNodes > 2000);
});

// ---------------------------------------------------------------------------
// Byte map
// ---------------------------------------------------------------------------

test("byte map: case-insensitive lookup through a span", () => {
  const map = new ByteMap(true);
  map.insert(enc("http://example.com/X"), 42);
  const line = enc("see HTTP://EXAMPLE.COM/X here");
  assert.equal(map.lookup(line, 4, 24), 42);
});

test("byte map: case-sensitive lookup", () => {
  const map = new ByteMap(false);
  map.insert(enc("abcdef"), 7);
  const line = enc("xxabcdefyy");
  assert.equal(map.lookup(line, 2, 8), 7);
  assert.equal(map.lookup(line, 2, 7), -1);
});

test("byte map: absent keys and prefix spans do not match", () => {
  const map = new ByteMap(true);
  map.insert(enc("evil.com"), 1);
  assert.equal(map.lookup(enc("evil.co"), 0, 7), -1);
  // "notevil.com": indices 3..11 are "evil.com".
  assert.equal(map.lookup(enc("notevil.com"), 3, 11), 1);
  assert.equal(map.lookup(enc("good.com"), 0, 8), -1);
});

test("byte map: survives rehashing with many entries", () => {
  const map = new ByteMap(true, 2);
  for (let i = 0; i < 500; i++) map.insert(enc(`key${i}.example`), i);
  assert.equal(map.size, 500);
  for (let i = 0; i < 500; i++) {
    const k = enc(`KEY${i}.EXAMPLE`);
    assert.equal(map.lookup(k, 0, k.length), i);
  }
});
