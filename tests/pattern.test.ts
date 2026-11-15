import { test } from "node:test";
import assert from "node:assert/strict";
import { parsePattern, PatternParseError, pathToString, observableTypes } from "../src/stix/pattern.ts";
import { compilePattern, likeToRegExp, normaliseDomain, normaliseUrl, urlHost } from "../src/stix/compile.ts";

test("pattern: parses a simple equality", () => {
  const ast = parsePattern("[ipv4-addr:value = '1.2.3.4']");
  assert.equal(ast.kind, "compare");
  if (ast.kind !== "compare") return;
  assert.equal(ast.path.type, "ipv4-addr");
  assert.deepEqual(ast.path.props, ["value"]);
  assert.equal(ast.op, "=");
  assert.deepEqual(ast.value, { kind: "string", value: "1.2.3.4" });
});

test("pattern: AND binds tighter than OR", () => {
  const ast = parsePattern("[ipv4-addr:value = '1.1.1.1'] AND [ipv4-addr:value = '2.2.2.2'] OR [ipv4-addr:value = '3.3.3.3']");
  assert.equal(ast.kind, "or");
  if (ast.kind !== "or") return;
  assert.equal(ast.children.length, 2);
  assert.equal(ast.children[0]!.kind, "and");
  assert.equal(ast.children[1]!.kind, "compare");
});

test("pattern: parentheses override precedence", () => {
  const ast = parsePattern("[ipv4-addr:value = '1.1.1.1'] AND ([ipv4-addr:value = '2.2.2.2'] OR [ipv4-addr:value = '3.3.3.3'])");
  assert.equal(ast.kind, "and");
  if (ast.kind !== "and") return;
  assert.equal(ast.children[1]!.kind, "or");
});

test("pattern: IN list and nested quoted hash property", () => {
  const ast = parsePattern("[file:hashes.'SHA-256' IN ('aa','bb')]");
  assert.equal(ast.kind, "compare");
  if (ast.kind !== "compare") return;
  assert.deepEqual(ast.path.props, ["hashes", "SHA-256"]);
  assert.equal(ast.op, "IN");
  assert.equal(ast.value.kind, "list");
});

test("pattern: escaped quotes inside strings", () => {
  const ast = parsePattern("[file:name = 'it\\'s']");
  assert.equal(ast.kind, "compare");
  if (ast.kind !== "compare") return;
  assert.deepEqual(ast.value, { kind: "string", value: "it's" });
});

test("pattern: MATCHES / LIKE / ISSUBSET operators", () => {
  for (const op of ["MATCHES", "LIKE", "ISSUBSET"] as const) {
    const ast = parsePattern(`[domain-name:value ${op} 'a.*']`);
    assert.equal(ast.kind, "compare");
    if (ast.kind === "compare") assert.equal(ast.op, op);
  }
});

test("pattern: qualifiers are reported, not silently dropped", () => {
  const ast = parsePattern("[ipv4-addr:value = '1.1.1.1'] WITHIN 300 SECONDS");
  assert.equal(ast.kind, "unsupported");
  if (ast.kind === "unsupported") assert.match(ast.reason, /QUALIFIER_UNSUPPORTED/);
});

test("pattern: NOT and EXISTS operands are rejected explicitly", () => {
  // The unsupported operand sits inside an AND, so the AND itself is what the
  // compiler sees; it must refuse the whole expression (verified in the
  // compile test) rather than drop the negated half.
  const notAst = parsePattern("[ipv4-addr:value = '1.1.1.1'] AND NOT [domain-name:value = 'x.com']");
  assert.equal(notAst.kind, "and");
  if (notAst.kind === "and") assert.equal(notAst.children[1]!.kind, "unsupported");
  const existsAst = parsePattern("EXISTS [url:value = 'x']");
  assert.equal(existsAst.kind, "unsupported");
  if (existsAst.kind === "unsupported") assert.match(existsAst.reason, /EXISTS/);
});

test("pattern: syntactically invalid input throws with a position", () => {
  const cases = [
    "",
    "[ipv4-addr:value = '1.2.3.4'", // unclosed bracket
    "[ipv4-addr:value = ]",
    "[ipv4-addr:value '1.2.3.4']", // missing operator
    "ipv4-addr:value = '1.2.3.4'", // missing brackets
    "[ipv4-addr:value = 'x]",
    "[]",
    "[unknown]",
  ];
  for (const c of cases) {
    assert.throws(() => parsePattern(c), PatternParseError, JSON.stringify(c));
  }
});

test("pattern: pathToString round-trips quoted properties", () => {
  assert.equal(pathToString({ type: "file", props: ["hashes", "SHA-256"] }), "file:hashes.'SHA-256'");
  assert.equal(pathToString({ type: "ipv4-addr", props: ["value"] }), "ipv4-addr:value");
});

test("pattern: observableTypes collects nested types", () => {
  const ast = parsePattern("([ipv4-addr:value = '1.1.1.1'] AND [url:value = 'http://a.com/x']) OR [domain-name:value = 'b.com']");
  assert.deepEqual(observableTypes(ast).sort(), ["domain-name", "ipv4-addr", "url"]);
});

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

test("compile: IP literals become CIDR atoms, with /32 for a bare address", () => {
  const r = compilePattern(parsePattern("[ipv4-addr:value = '1.2.3.4']"));
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.program.atoms.length, 1);
  const atom = r.program.atoms[0]!;
  assert.equal(atom.kind, "cidr");
  if (atom.kind === "cidr") {
    assert.equal(atom.network, "1.2.3.4");
    assert.equal(atom.prefix, 32);
  }
});

test("compile: host bits are cleared from a CIDR indicator", () => {
  const r = compilePattern(parsePattern("[ipv4-addr:value = '203.0.113.77/24']"));
  assert.equal(r.ok, true);
  if (!r.ok) return;
  const atom = r.program.atoms[0]!;
  assert.equal(atom.kind, "cidr");
  if (atom.kind === "cidr") {
    assert.equal(atom.network, "203.0.113.0");
    assert.equal(atom.prefix, 24);
  }
});

test("compile: IN becomes an OR of its members", () => {
  const r = compilePattern(parsePattern("[ipv4-addr:value IN ('1.1.1.1','2.2.2.2','3.3.3.3')]"));
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.program.root.kind, "or");
  assert.equal(r.program.atoms.length, 3);
});

test("compile: duplicate atoms within one program are deduplicated", () => {
  const r = compilePattern(parsePattern("[ipv4-addr:value = '1.1.1.1'] OR [ipv4-addr:value = '1.1.1.1']"));
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.program.atoms.length, 1);
});

test("compile: rejects != with an explicit reason", () => {
  const r = compilePattern(parsePattern("[ipv4-addr:value != '1.1.1.1']"));
  assert.equal(r.ok, false);
  if (r.ok) return;
  assert.equal(r.unsupported.reason, "OPERATOR_UNSUPPORTED:NEQ");
});

test("compile: rejects ordering comparisons", () => {
  const r = compilePattern(parsePattern("[file:size > 1024]"));
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.unsupported.reason, /OBSERVABLE_UNSUPPORTED|OPERATOR_UNSUPPORTED/);
});

test("compile: rejects a non-indexable observable path", () => {
  const r = compilePattern(parsePattern("[x509-certificate:hashes.MD5 = 'aa']"));
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.unsupported.reason, "OBSERVABLE_UNSUPPORTED");
});

test("compile: rejects unsupported hash algorithms", () => {
  const r = compilePattern(parsePattern("[file:hashes.'SHA3-256' = 'aa']"));
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.unsupported.reason, "HASH_ALGORITHM_UNSUPPORTED");
});

test("compile: rejects a hash of the wrong length for its algorithm", () => {
  const r = compilePattern(parsePattern("[file:hashes.MD5 = 'aabb']"));
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.unsupported.reason, "VALUE_INVALID");
});

test("compile: accepts all four supported hash algorithms", () => {
  for (const [algo, len] of [["MD5", 32], ["SHA-1", 40], ["SHA-256", 64], ["SHA-512", 128]] as const) {
    const digest = "a".repeat(len);
    const r = compilePattern(parsePattern(`[file:hashes.'${algo}' = '${digest}']`));
    assert.equal(r.ok, true, algo);
    if (r.ok) {
      const atom = r.program.atoms[0]!;
      assert.equal(atom.kind, "hash");
      if (atom.kind === "hash") assert.equal(atom.algorithm, algo);
    }
  }
});

test("compile: rejects an invalid domain and invalid URL", () => {
  const badDomain = compilePattern(parsePattern("[domain-name:value = 'not a domain']"));
  assert.equal(badDomain.ok, false);
  const badUrl = compilePattern(parsePattern("[url:value = 'notaurl']"));
  assert.equal(badUrl.ok, false);
});

test("compile: rejects an invalid regex rather than matching nothing", () => {
  const r = compilePattern(parsePattern("[domain-name:value MATCHES '([unclosed']"));
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.unsupported.reason, "REGEX_INVALID");
});

test("compile: rejects an over-long regex", () => {
  const r = compilePattern(parsePattern(`[domain-name:value MATCHES '${"a".repeat(513)}']`));
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.unsupported.reason, "REGEX_TOO_LONG");
});

test("compile: an AND containing one unsupported half is rejected whole", () => {
  // The critical policy: never drop the unsupported half and keep the rest.
  const r = compilePattern(parsePattern("[ipv4-addr:value = '1.1.1.1'] AND [ipv4-addr:value != '2.2.2.2']"));
  assert.equal(r.ok, false);
});

test("compile: summary is human readable", () => {
  const r = compilePattern(parsePattern("[ipv4-addr:value = '1.1.1.1'] AND [domain-name:value = 'evil.com']"));
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.match(r.program.summary, /ipv4-addr:value = '1\.1\.1\.1'/);
    assert.match(r.program.summary, /domain-name:value = 'evil\.com'/);
    assert.match(r.program.summary, /AND/);
  }
});

// ---------------------------------------------------------------------------
// Normalisation helpers
// ---------------------------------------------------------------------------

test("normaliseDomain: lowercases, strips root dot and wildcard prefixes", () => {
  assert.equal(normaliseDomain("Evil.Example.COM"), "evil.example.com");
  assert.equal(normaliseDomain("evil.example.com."), "evil.example.com");
  assert.equal(normaliseDomain("*.evil.example.com"), "evil.example.com");
  assert.equal(normaliseDomain(".evil.example.com"), "evil.example.com");
});

test("normaliseUrl: scheme/host case, default port, trailing slash", () => {
  assert.equal(normaliseUrl("HTTP://Example.COM/Path"), "http://example.com/Path");
  assert.equal(normaliseUrl("http://example.com:80/x"), "http://example.com/x");
  assert.equal(normaliseUrl("https://example.com:443/x"), "https://example.com/x");
  assert.equal(normaliseUrl("https://example.com:8443/x"), "https://example.com:8443/x");
  assert.equal(normaliseUrl("https://example.com/"), "https://example.com");
  // Path case must be preserved: it is significant on most origins.
  assert.equal(normaliseUrl("https://example.com/AbC?X=1"), "https://example.com/AbC?X=1");
});

test("normaliseUrl: userinfo is preserved but host is not confused by it", () => {
  assert.equal(normaliseUrl("http://user:pw@Example.com/x"), "http://user:pw@example.com/x");
  assert.equal(normaliseUrl("http://user@host.com:8080/x"), "http://user@host.com:8080/x");
});

test("normaliseUrl: bracketed IPv6 authority keeps its brackets", () => {
  assert.equal(normaliseUrl("https://[2001:DB8::1]:8443/x"), "https://[2001:db8::1]:8443/x");
});

test("urlHost: extracts the host from normalised URLs", () => {
  assert.equal(urlHost("http://example.com/x"), "example.com");
  assert.equal(urlHost("http://user:pw@example.com:8080/x"), "example.com");
  assert.equal(urlHost("http://[2001:db8::1]:443/x"), "2001:db8::1");
});

test("likeToRegExp: % and _ translate, regex metacharacters are escaped", () => {
  assert.equal(likeToRegExp("a%b").test("aXYZb"), true);
  assert.equal(likeToRegExp("a_b").test("axb"), true);
  assert.equal(likeToRegExp("a_b").test("aXXb"), false);
  assert.equal(likeToRegExp("a.b").test("aXb"), false);
  assert.equal(likeToRegExp("a.b").test("a.b"), true);
});
