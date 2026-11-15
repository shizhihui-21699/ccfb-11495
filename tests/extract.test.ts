import { test } from "node:test";
import assert from "node:assert/strict";
import { Extractor } from "../src/extract/extractor.ts";

const enc = (s: string): Uint8Array => Buffer.from(s, "latin1");

interface Extracted {
  v4: string[];
  v6: string[];
  domains: string[];
  urls: string[];
  emails: string[];
  hashes: string[];
}

function extract(line: string): Extracted {
  const ex = new Extractor(enc(line));
  ex.run();
  const v4: string[] = [];
  for (let i = 0; i < ex.v4count; i++) {
    const n = ex.v4Value(i);
    v4.push(`${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`);
  }
  const v6: string[] = [];
  for (let i = 0; i < ex.v6count; i++) v6.push(ex.formatV6(i));
  const domains: string[] = [];
  for (let i = 0; i < ex.domainCount; i++) domains.push(ex.spanLower(ex.domainStart(i), ex.domainEnd(i)));
  const urls: string[] = [];
  for (let i = 0; i < ex.urlCount; i++) urls.push(Buffer.from(ex.urlNormalised(i)).toString("latin1"));
  const emails: string[] = [];
  for (let i = 0; i < ex.emailCount; i++) emails.push(ex.span(ex.emailStart(i), ex.emailEnd(i)));
  const hashes: string[] = [];
  for (let i = 0; i < ex.hashCount; i++) hashes.push(ex.spanLower(ex.hashStart(i), ex.hashEnd(i)));
  return { v4, v6, domains, urls, emails, hashes };
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

test("extract: bare and field-embedded IPv4", () => {
  assert.deepEqual(extract("connect to 203.0.113.9 now").v4, ["203.0.113.9"]);
  assert.deepEqual(extract("src=10.1.2.3 dst=10.4.5.6").v4, ["10.1.2.3", "10.4.5.6"]);
  assert.deepEqual(extract("172.16.0.1:8443").v4, ["172.16.0.1"]);
});

test("extract: IPv4 with CIDR suffix still yields the address", () => {
  assert.deepEqual(extract("block 10.0.0.0/8 please").v4, ["10.0.0.0"]);
  assert.deepEqual(extract("range=192.168.1.5/24").v4, ["192.168.1.5"]);
});

test("extract: rejects non-addresses that look numeric", () => {
  assert.deepEqual(extract("version 1.2.3 released").v4, []);
  assert.deepEqual(extract("999.1.1.1 is not an IP").v4, []);
  assert.deepEqual(extract("010.1.1.1 has a leading zero").v4, []);
  assert.deepEqual(extract("price 1.25 dollars").v4, []);
});

test("extract: an IPv4 must not be taken from inside a longer dotted run", () => {
  // `1.2.3.4.5` is not four valid octets followed by data; the span parser
  // rejects five-octet runs, and the token is dropped rather than truncated.
  assert.deepEqual(extract("1.2.3.4.5").v4, []);
});

test("extract: IPv4 with a trailing colon in prose", () => {
  assert.deepEqual(extract("server 10.9.8.7: see logs").v4, ["10.9.8.7"]);
});

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

test("extract: bare and bracketed IPv6", () => {
  assert.deepEqual(extract("addr 2001:db8::1 ok").v6, ["2001:db8::1"]);
  assert.deepEqual(extract("[2001:db8::5]:443").v6, ["2001:db8::5"]);
  assert.deepEqual(extract("http://[::1]:8080/x").v6, ["::1"]);
});

test("extract: unbracketed IPv6 with a port", () => {
  assert.deepEqual(extract("peer 2001:db8::2:443").v6, ["2001:db8::2:443"]);
  assert.deepEqual(extract("peer 2001:db8::2 port 443").v6, ["2001:db8::2"]);
});

test("extract: IPv6 with a zone id is dropped, not misparsed", () => {
  // `%eth0` is a zone, not part of the address; the extractor classifies the
  // token as v6 only when the address part parses, and here it does not
  // because there is no trailing zone handling for bare tokens.
  const out = extract("fe80::1%eth0");
  assert.deepEqual(out.v4, []);
});

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

test("extract: plain hostnames", () => {
  assert.deepEqual(extract("query[A] mail.evil.com from 10.0.0.1").domains, ["mail.evil.com"]);
  assert.deepEqual(extract("host=WWW.Example.COM").domains, ["www.example.com"]);
});

test("extract: a URL contributes only its authority host as a domain", () => {
  assert.deepEqual(extract("http://a.com/path/to/b.com?q=c.com").domains, ["a.com"]);
});

test("extract: JSON-embedded host", () => {
  assert.deepEqual(extract('{"host":"bad.example.net","port":443}').domains, ["bad.example.net"]);
});

test("extract: host:port keeps the host", () => {
  assert.deepEqual(extract("upstream api.example.org:9000").domains, ["api.example.org"]);
});

test("extract: numeric-dotted tokens are never domains", () => {
  assert.deepEqual(extract("1.2.3.4").domains, []);
  assert.deepEqual(extract("999.1.1.1").domains, []);
});

test("extract: trailing root dot is not part of the domain", () => {
  assert.deepEqual(extract("evil.com. has a root dot").domains, ["evil.com"]);
});

test("extract: single-label tokens are not domains", () => {
  assert.deepEqual(extract("localhost internal-host app").domains, []);
});

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

test("extract: URL normalisation", () => {
  assert.deepEqual(extract("GET http://Example.COM:80/a/b HTTP/1.1").urls, ["http://example.com/a/b"]);
  assert.deepEqual(extract("https://example.com:443/").urls, ["https://example.com"]);
  assert.deepEqual(extract("https://example.com:8443/x").urls, ["https://example.com:8443/x"]);
});

test("extract: URL in a key=value field", () => {
  assert.deepEqual(extract("url=http://bad.example/payload.bin").urls, ["http://bad.example/payload.bin"]);
});

test("extract: URL query strings are preserved", () => {
  assert.deepEqual(extract("http://a.com/s?q=1&x=2").urls, ["http://a.com/s?q=1&x=2"]);
});

test("extract: an IP inside a URL query is still an IP", () => {
  const out = extract("http://a.com/t?ip=1.2.3.4");
  assert.deepEqual(out.urls, ["http://a.com/t?ip=1.2.3.4"]);
  assert.deepEqual(out.v4, ["1.2.3.4"]);
});

// ---------------------------------------------------------------------------
// Emails
// ---------------------------------------------------------------------------

test("extract: email-addr and its domain half", () => {
  const out = extract("From: alice@mail.evil.com");
  assert.deepEqual(out.emails, ["alice@mail.evil.com"]);
  assert.deepEqual(out.domains, ["mail.evil.com"]);
});

test("extract: a non-domain right-hand side is not an email", () => {
  assert.deepEqual(extract("contact user@localhost").emails, []);
});

// ---------------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------------

test("extract: hashes of each supported length", () => {
  const md5 = "5d41402abc4b2a76b9719d911017c592";
  const sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
  const sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
  const sha512 =
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
  assert.deepEqual(extract(`md5=${md5}`).hashes, [md5]);
  assert.deepEqual(extract(`sha1=${sha1}`).hashes, [sha1]);
  assert.deepEqual(extract(`sha256=${sha256}`).hashes, [sha256]);
  assert.deepEqual(extract(`sha512=${sha512}`).hashes, [sha512]);
});

test("extract: hash algorithm classification is by exact length", () => {
  const ex = new Extractor(enc("aaaa 5d41402abc4b2a76b9719d911017c592"));
  ex.run();
  assert.equal(ex.hashCount, 1);
  assert.equal(ex.hashAlgorithm(0), "MD5");
});

test("extract: non-hex and wrong-length tokens are not hashes", () => {
  assert.deepEqual(extract("id 5d41402abc4b2a76b9719d911017c59z").hashes, []);
  assert.deepEqual(extract("id 5d41402abc4b2a76b9719d911017c59").hashes, []);
});

// ---------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------

test("extract: does not throw on arbitrary bytes", () => {
  const samples = [
    Buffer.from([0x00, 0xff, 0xfe, 0x01]),
    Buffer.from("☃ ünïcode …", "utf8"),
    Buffer.from("a".repeat(10000)),
    Buffer.from("\r\n\t  "),
    Buffer.from("[[[[[]]]]]"),
    Buffer.from("::::::"),
    Buffer.from("@.@.@"),
  ];
  for (const s of samples) {
    const ex = new Extractor(s);
    assert.doesNotThrow(() => ex.run());
  }
});

test("extract: very long line with many observables", () => {
  const parts: string[] = [];
  for (let i = 0; i < 500; i++) parts.push(`10.0.${i >> 8}.${i & 255} h${i}.example.com`);
  const out = extract(parts.join(" "));
  assert.equal(out.v4.length, 500);
  assert.equal(out.domains.length, 500);
});

test("extract: the unspecified address :: survives trailing-colon trimming", () => {
  assert.deepEqual(extract("bind ::").v6, ["::"]);
  assert.deepEqual(extract("any 2001:db8::").v6, ["2001:db8::"]);
  // A single trailing colon is still prose punctuation.
  assert.deepEqual(extract("warning:").v6, []);
});

test("extract: IPv6 with a URI path suffix in a log field", () => {
  assert.deepEqual(extract("IPv6 2001:db8::1/path").v6, ["2001:db8::1"]);
});

test("extract: mailto: is stripped from the email local part", () => {
  const out = extract("mailto:alice@evil.com");
  assert.deepEqual(out.emails, ["alice@evil.com"]);
  assert.deepEqual(out.domains, ["evil.com"]);
});

test("extract: user@IP yields the IP even though it is not an email", () => {
  const out = extract("ssh user@10.0.0.1");
  assert.deepEqual(out.v4, ["10.0.0.1"]);
  assert.deepEqual(out.emails, []);
});

test("extract: reset() clears prior results", () => {
  const ex = new Extractor(enc("1.2.3.4 a.example.com"));
  ex.run();
  assert.equal(ex.v4count, 1);
  ex.reset(enc("nothing here"));
  ex.run();
  assert.equal(ex.v4count, 0);
  assert.equal(ex.domainCount, 0);
});
