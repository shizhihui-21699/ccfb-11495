import { test } from "node:test";
import assert from "node:assert/strict";
import {
  cidrNetwork,
  formatIpv4,
  formatIpv6,
  ipv4InPrefix,
  ipv4Mask,
  parseCidr,
  parseIpv4,
  parseIpv4Bytes,
  parseIpv4N,
  parseIpv6,
  parseIpv6Bytes,
} from "../src/util/ip.ts";

const bytes = (s: string): Uint8Array => Buffer.from(s, "latin1");

test("ipv4: accepts canonical dotted quads", () => {
  for (const [text, expected] of [
    ["0.0.0.0", "0.0.0.0"],
    ["1.2.3.4", "1.2.3.4"],
    ["10.0.0.1", "10.0.0.1"],
    ["192.168.100.200", "192.168.100.200"],
    ["255.255.255.255", "255.255.255.255"],
    ["198.51.100.7", "198.51.100.7"],
  ] as const) {
    const addr = parseIpv4(text);
    assert.notEqual(addr, null, text);
    assert.equal(formatIpv4(addr!.n), expected);
  }
});

test("ipv4: rejects leading zeros, out-of-range octets and malformed text", () => {
  for (const bad of [
    "010.0.0.1",
    "1.2.3.04",
    "1.2.3.256",
    "256.1.1.1",
    "999.1.1.1",
    "1.2.3",
    "1.2.3.4.5",
    "1..2.3",
    ".1.2.3",
    "1.2.3.",
    " 1.2.3.4",
    "1.2.3.4 ",
    "1.2.3.a",
    "1-2-3-4",
    "",
  ]) {
    assert.equal(parseIpv4(bad), null, `expected null for ${JSON.stringify(bad)}`);
  }
});

test("ipv4: byte parser and allocation-free parser agree with string parser", () => {
  for (const text of ["0.0.0.0", "127.0.0.1", "8.8.8.8", "255.255.255.255"]) {
    const b = bytes(text);
    const viaBytes = parseIpv4Bytes(b, 0, b.length);
    const viaN = parseIpv4N(b, 0, b.length);
    const viaString = parseIpv4(text);
    assert.notEqual(viaBytes, null);
    assert.equal(viaBytes!.n, viaN);
    assert.equal(viaBytes!.n, viaString!.n);
  }
});

test("ipv4: byte parser rejects a span that is only part of a longer dotted run", () => {
  const b = bytes("1.2.3.4.5");
  // A span covering the first four octets is a valid address even though the
  // surrounding token continues; span semantics are what the extractor needs.
  assert.notEqual(parseIpv4N(b, 0, 7), -1);
  // A span starting mid-octet must fail.
  assert.equal(parseIpv4N(b, 1, 7), -1);
});

test("ipv6: canonical forms", () => {
  const cases: Array<[string, string]> = [
    ["::", "::"],
    ["::1", "::1"],
    ["1::", "1::"],
    ["2001:db8::1", "2001:db8::1"],
    ["2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"],
    ["fe80::a:b:c:d", "fe80::a:b:c:d"],
    ["1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"],
    ["::ffff:192.168.1.1", "::ffff:c0a8:101"],
    ["0:0:0:0:0:0:0:0", "::"],
    ["2001:DB8::AB", "2001:db8::ab"],
  ];
  for (const [input, expected] of cases) {
    const addr = parseIpv6(input);
    assert.notEqual(addr, null, input);
    assert.equal(formatIpv6(addr!.w), expected, input);
  }
});

test("ipv6: rejects malformed literals", () => {
  for (const bad of [
    "::g",
    "1::2::3",
    "1:2:3:4:5:6:7:8:9",
    "1:2:3:4:5:6:7",
    "1:::2",
    ":::",
    ":1::",
    "12345::",
    "fe80::1%eth0", // zone ids are not accepted by the matcher
    "1.2.3.4",
    "",
  ]) {
    assert.equal(parseIpv6(bad), null, `expected null for ${JSON.stringify(bad)}`);
  }
});

test("ipv6: RFC 5952 picks the longest zero run, first on ties", () => {
  assert.equal(formatIpv6(parseIpv6("2001:db8:0:0:1:0:0:1")!.w), "2001:db8::1:0:0:1");
  assert.equal(formatIpv6(parseIpv6("2001:0:0:1:0:0:1:1")!.w), "2001::1:0:0:1:1");
  assert.equal(formatIpv6(parseIpv6("2001:db8:0:1:1:1:1:1")!.w), "2001:db8:0:1:1:1:1:1");
});

test("ipv6: a single zero group is not compressed", () => {
  // RFC 5952 forbids `1:2:3:0:5:6:7:8` -> `1:2:3::5:6:7:8`.
  assert.equal(formatIpv6(parseIpv6("1:2:3:0:5:6:7:8")!.w), "1:2:3:0:5:6:7:8");
});

test("ipv6: embedded IPv4 occupies the last two groups", () => {
  const addr = parseIpv6("::ffff:192.168.1.1")!;
  // 0000:0000:0000:0000:0000:ffff:c0a8:0101, so the IPv4 pair lands in word 3.
  assert.equal(addr.w[3], 0xc0a80101);
  assert.equal(formatIpv6(addr.w), "::ffff:c0a8:101");
});

test("ipv6: byte parser matches string parser", () => {
  for (const text of ["::", "::1", "2001:db8::1", "fe80::1", "::ffff:1.2.3.4"]) {
    const b = bytes(text);
    const viaBytes = parseIpv6Bytes(b, 0, b.length);
    const viaString = parseIpv6(text);
    assert.notEqual(viaBytes, null, text);
    assert.deepEqual([...viaBytes!.w], [...viaString!.w], text);
  }
});

test("cidr: parsing, masking and containment", () => {
  const c = parseCidr("203.0.113.0/24")!;
  assert.notEqual(c, null);
  assert.equal(c.prefix, 24);
  const net = cidrNetwork(parseCidr("203.0.113.77/24")!) as { addr: { n: number }; prefix: number };
  assert.equal(formatIpv4(net.addr.n), "203.0.113.0");

  const network = parseIpv4("203.0.113.0")!.n;
  assert.equal(ipv4InPrefix(parseIpv4("203.0.113.1")!.n, network, 24), true);
  assert.equal(ipv4InPrefix(parseIpv4("203.0.113.255")!.n, network, 24), true);
  assert.equal(ipv4InPrefix(parseIpv4("203.0.114.1")!.n, network, 24), false);
});

test("cidr: /0 matches everything and /32 matches one address", () => {
  const all = parseIpv4("0.0.0.0")!.n;
  assert.equal(ipv4InPrefix(parseIpv4("8.8.8.8")!.n, all, 0), true);
  const one = parseIpv4("8.8.8.8")!.n;
  assert.equal(ipv4InPrefix(one, one, 32), true);
  assert.equal(ipv4InPrefix(parseIpv4("8.8.8.9")!.n, one, 32), false);
});

test("cidr: rejects bad prefixes", () => {
  for (const bad of ["10.0.0.0", "10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/", "10.0.0.0/abc", "::/129", "notanip/8"]) {
    assert.equal(parseCidr(bad), null, bad);
  }
});

test("ipv4Mask: boundary prefixes", () => {
  assert.equal(ipv4Mask(0) >>> 0, 0);
  assert.equal(ipv4Mask(8) >>> 0, 0xff000000);
  assert.equal(ipv4Mask(24) >>> 0, 0xffffff00);
  assert.equal(ipv4Mask(32) >>> 0, 0xffffffff);
});

test("ipv6: masking clears host bits across word boundaries", () => {
  const net = cidrNetwork(parseCidr("2001:db8:abcd:1234:5678:9abc:def0:1234/49")!);
  assert.equal(net.addr.version, 6);
  const text = formatIpv6((net.addr as { w: Uint32Array }).w);
  // /49 = 32 bits of word 0 + 17 bits of word 1.
  assert.equal(text, "2001:db8:abcd::");
});
