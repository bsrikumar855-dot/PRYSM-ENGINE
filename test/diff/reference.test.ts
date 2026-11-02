// Unit tests for the independent reference implementation. Expectations are derived from
// docs/auto-builder/POLICY-SPEC.md (not from the production engine).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  refDecide,
  refGlob,
  refHostFromString,
  refLoadPolicy,
  refMatchPath,
  refNormalizePath,
  codePoints,
  type RefPolicy,
} from "../../eval/reference/index.ts";

const SAMPLE = readFileSync(new URL("../../eval/policies/support-agent.policy.json", import.meta.url), "utf8");
const sample = refLoadPolicy(SAMPLE);

const CTX = { agentId: "agent-1" };
function dec(p: RefPolicy, tool: string, args: unknown, ctx: unknown = CTX): string {
  const r = refDecide(p, { tool, args, ctx });
  return `${r.effect}/${r.reason_code}`;
}

// ---------- glob ----------
test("glob: spec §2 semantics", () => {
  const g = (p: string, t: string): boolean => refGlob(codePoints(p), t);
  assert.equal(g("a*c", "abc"), true);
  assert.equal(g("a*c", "ac"), true);
  assert.equal(g("a?c", "abc"), true);
  assert.equal(g("a?c", "ac"), false);
  assert.equal(g("*", ""), true);
  assert.equal(g("?", ""), false);
  assert.equal(g("?", "\u{1F600}"), true, "? is exactly one code point");
  assert.equal(g("a*", "a/b/c"), true, "* crosses /");
  assert.equal(g("A", "a"), false, "case-sensitive");
  assert.equal(g("abc", "abcd"), false, "whole-string");
  assert.equal(g("\u00e9", "e\u0301"), true, "NFC applied to text");
  assert.equal(g("", ""), true);
  assert.equal(g("*a*b*", "xxaxxbxx"), true);
  assert.equal(g("*a*b*", "xxbxxaxx"), false);
});

// ---------- host extraction ----------
test("host: accepted forms and normalisation (§3)", () => {
  const h = (s: string): string | null => refHostFromString(s).host;
  assert.equal(h("https://corp.com/x"), "corp.com");
  assert.equal(refHostFromString("https://corp.com/x").form, "url");
  assert.equal(refHostFromString("a@corp.com").form, "email");
  assert.equal(refHostFromString("corp.com").form, "host");
  assert.equal(h("a@corp.com"), "corp.com");
  assert.equal(h("corp.com."), "corp.com", "exactly one trailing dot stripped");
  assert.equal(h("corp.com.."), null);
  assert.equal(h("CORP.COM"), "corp.com");
  assert.equal(h("http://CORP.com:8080/p?q#f"), "corp.com");
  assert.equal(h("xn--nxasmq6b.com"), "xn--nxasmq6b.com");
});

test("host: rejections (§3)", () => {
  const h = (s: string): string | null => refHostFromString(s).host;
  for (const s of [
    "http://127.0.0.1/", "http://0x7f.1/", "http://2130706433/", "1.2.3.4", "mailto:bob@corp.com", "ftp://corp.com",
    "a@b@corp.com", "corp.com:80", "\uff43orp.com", "a b.com", " corp.com", "corp.com ", "a%41.com", "a\\b.com",
    "-a.com", "a-.com", "a..com", "a_b.com", "http://user@corp.com/", "http://user:pw@corp.com/", "[::1]", "http://[::1]/",
    "corp.com/x", "corp.com?x", "corp.com#x", "x@corp.com/y", "x@[::1]", "@corp.com", "a\u0000@corp.com", "corp.com\n",
    "", ".", "http://", "//corp.com",
  ]) {
    assert.equal(h(s), null, JSON.stringify(s));
  }
  assert.equal(h(`${"a".repeat(64)}.com`), null, "label > 63");
  assert.equal(h(`${"a".repeat(63)}.com`), `${"a".repeat(63)}.com`);
  assert.equal(h(`${"a.".repeat(127)}com`), null, "total > 253");
});

test("host: accept list decides which shape is allowed", async () => {
  const { refMatchHost } = await import("../../eval/reference/index.ts");
  const m = (v: string, accept: string[]): string => refMatchHost(v, "suffix", "corp.com", new Set(accept));
  assert.equal(m("a@corp.com", ["email"]), "match");
  assert.equal(m("a@corp.com", ["url", "host"]), "unparseable");
  assert.equal(m("https://corp.com", ["email"]), "unparseable");
  assert.equal(m("corp.com", ["email"]), "unparseable");
  assert.equal(m("corp.com", ["host"]), "match");
  assert.equal(m("x.corp.com", ["host"]), "match");
  assert.equal(m("xcorp.com", ["host"]), "no_match", "dot boundary");
  assert.equal(m("corp.com.evil.com", ["host"]), "no_match");
  const ex = (v: string): string => refMatchHost(v, "exact", "docs.corp.com", new Set(["url"]));
  assert.equal(ex("https://docs.corp.com/"), "match");
  assert.equal(ex("https://a.docs.corp.com/"), "no_match");
});

// ---------- path ----------
test("path: normalisation (§4)", () => {
  const n = (s: string): string | null => {
    const r = refNormalizePath(s);
    return r === null ? null : r.prefix + "/" + r.segs.join("/");
  };
  assert.equal(n("/workspace/./a//b"), "/workspace/a/b");
  assert.equal(n("/a/b/../c"), "/a/c");
  assert.equal(n("c:\\Work\\a"), "C:/Work/a");
  assert.equal(n("/"), "/");
  assert.equal(n("/a%zz"), "/a%zz", "% not followed by two hex digits is literal");
  assert.equal(n("C:/x"), "C:/x");
});

test("path: rejections (§4 steps 1-3, §10.3)", () => {
  for (const s of [
    "/a/../..", "/..", "/CON", "/con.txt", "/com1", "/a/lpt9.x", "/Aux", "/nul", "/conin$", "/CONOUT$.x", "/a.", "/a ", "/a/b./c",
    "/PROGRA~1", "/abc~12/x", "/abc~1.txt", "\\\\srv\\x", "\\\\?\\C:\\x", "//x", "/a:b", "C:foo", "1:/x", "/a%2e", "/a%2E%2e/b", "/a?b",
    "/a*b", '/a"b', "/a<b", "/a>b", "/a|b", "rel/path", "", "./x", "/\u00e9", "/a\u0000b", "/a\nb", "\\/x", "/\\x", "/a/.../b",
    "/con/../x",
  ]) {
    assert.equal(refNormalizePath(s), null, JSON.stringify(s));
  }
  assert.notEqual(refNormalizePath("/console"), null, "console is not CON");
  assert.notEqual(refNormalizePath("/abcdefghi~1"), null, "9-char stem is not 8.3 (^[^.]{1,8}~)");
  assert.notEqual(refNormalizePath("/.hidden"), null);
});

test("path: within-root matching, tri-state (§4.5, §11)", () => {
  const m = (v: string, root: string, ci = false): string => refMatchPath(v, root, ci);
  assert.equal(m("/workspace", "/workspace"), "match");
  assert.equal(m("/workspace/x", "/workspace"), "match");
  assert.equal(m("/workspace/./x/../y", "/workspace"), "match");
  assert.equal(m("/workspaceX", "/workspace"), "no_match");
  assert.equal(m("/Workspace/x", "/workspace"), "no_match");
  assert.equal(m("/Workspace/x", "/workspace", true), "match");
  assert.equal(m("/workspace/../etc", "/workspace"), "no_match");
  assert.equal(m("/x", "/"), "match");
  assert.equal(m("C:/x", "/"), "no_match", "root / does not match drive paths");
  assert.equal(m("C:/workspace/x", "/workspace"), "no_match");
  assert.equal(m("/", "/workspace"), "no_match");
  assert.equal(m("/workspace/%2e%2e/x", "/workspace"), "unparseable");
  assert.equal(m("relative", "/workspace"), "unparseable");
  assert.equal(m("/workspace/\u00e9", "/workspace"), "unparseable");
});

// ---------- decide: sample policy ----------
test("decide: unknown tool / args strictness", () => {
  assert.equal(dec(sample, "nope", {}), "deny/unknown_tool");
  assert.equal(dec(sample, "constructor", {}), "deny/unknown_tool");
  assert.equal(dec(sample, "search_docs", { query: "x" }), "permit/permitted");
  assert.equal(dec(sample, "search_docs", {}), "deny/invalid_args");
  assert.equal(dec(sample, "search_docs", { query: "x", extra: 1 }), "deny/invalid_args");
  assert.equal(dec(sample, "search_docs", { query: 5 }), "deny/invalid_args");
  assert.equal(dec(sample, "search_docs", { query: null }), "deny/invalid_args");
});

test("decide: path rules incl. deny-wins and unparseable-in-deny (§11)", () => {
  assert.equal(dec(sample, "read_file", { path: "/workspace/a.txt" }), "permit/permitted");
  assert.equal(dec(sample, "read_file", { path: "/workspace/../etc/passwd" }), "deny/default_deny");
  assert.equal(dec(sample, "read_file", { path: "/workspace/secrets/k" }), "deny/denied_by_rule");
  assert.equal(dec(sample, "read_file", { path: "/WORKSPACE/SECRETS/k" }), "deny/denied_by_rule");
  assert.equal(dec(sample, "read_file", { path: "/workspace/x/../secrets/k" }), "deny/denied_by_rule");
  assert.equal(dec(sample, "read_file", { path: "/workspace/%73ecrets/k" }), "deny/denied_by_rule", "unparseable counts as deny match");
  assert.equal(dec(sample, "read_file", { path: "/workspace/\u00e9" }), "deny/denied_by_rule");
  assert.equal(dec(sample, "read_file", { path: "relative" }), "deny/denied_by_rule");
  assert.equal(dec(sample, "read_file", { path: "/etc/passwd" }), "deny/default_deny");
});

test("decide: email with provenance and optional-arg idiom (§6.4, §10.9)", () => {
  const base = { to: "bob@corp.com", subject: "s", body: "b" };
  const trusted = { agentId: "a", provenance: { to: ["trusted-user"] } };
  assert.equal(dec(sample, "send_email", base, trusted), "permit/permitted");
  assert.equal(dec(sample, "send_email", base, { agentId: "a", provenance: { to: ["trusted-user", "policy-constant"] } }), "permit/permitted");
  assert.equal(dec(sample, "send_email", base, CTX), "deny/default_deny", "no labels => untrusted:unknown");
  assert.equal(dec(sample, "send_email", base, { agentId: "a", provenance: { to: [] } }), "deny/default_deny");
  assert.equal(dec(sample, "send_email", base, { agentId: "a", provenance: { to: ["trusted-user", "web"] } }), "deny/default_deny");
  assert.equal(dec(sample, "send_email", { ...base, to: "bob@evil.com" }, trusted), "deny/default_deny");
  assert.equal(dec(sample, "send_email", { ...base, to: "https://corp.com" }, trusted), "deny/default_deny");
  assert.equal(dec(sample, "send_email", { ...base, cc: "" }, trusted), "deny/denied_by_rule", "present optional arg trips max_length deny");
  assert.equal(dec(sample, "send_email", { ...base, cc: 5 }, trusted), "deny/invalid_args");
});

test("decide: url domain rules", () => {
  assert.equal(dec(sample, "http_get", { url: "https://docs.corp.com/x" }), "permit/permitted");
  assert.equal(dec(sample, "http_get", { url: "https://corp.com" }), "permit/permitted");
  assert.equal(dec(sample, "http_get", { url: "https://evilcorp.com" }), "deny/default_deny");
  assert.equal(dec(sample, "http_get", { url: "https://corp.com@evil.com/" }), "deny/default_deny");
  assert.equal(dec(sample, "http_get", { url: "https://evil.com\\@corp.com/" }), "deny/default_deny");
  assert.equal(dec(sample, "http_get", { url: "corp.com" }), "deny/default_deny");
  assert.equal(dec(sample, "delete_file", { path: "/workspace/a" }), "deny/denied_by_rule");
});

test("decide: range, -0, scopes, taint", () => {
  const sales = { agentId: "a", scopes: ["sales"] };
  assert.equal(dec(sample, "set_discount", { percent: 5 }, sales), "permit/permitted");
  assert.equal(dec(sample, "set_discount", { percent: 10 }, sales), "permit/permitted");
  assert.equal(dec(sample, "set_discount", { percent: 10.0000001 }, sales), "deny/default_deny");
  assert.equal(dec(sample, "set_discount", { percent: -0 }, sales), "permit/permitted");
  assert.equal(dec(sample, "set_discount", { percent: -1 }, sales), "deny/default_deny");
  assert.equal(dec(sample, "set_discount", { percent: 5 }, CTX), "deny/default_deny");
  assert.equal(dec(sample, "set_discount", { percent: "5" }, sales), "deny/invalid_args");
  assert.equal(dec(sample, "set_discount", { percent: NaN }, sales), "deny/invalid_request");
  assert.equal(dec(sample, "set_discount", { percent: Infinity }, sales), "deny/invalid_request");
  assert.equal(dec(sample, "set_discount", { percent: 5 }, { ...sales, sessionTainted: true }), "deny/tainted_session");
  assert.equal(dec(sample, "set_discount", { percent: 5 }, { ...sales, sessionTainted: false }), "permit/permitted");
  assert.equal(dec(sample, "search_docs", { query: "q" }, { agentId: "a", sessionTainted: true }), "permit/permitted", "no external effect");
  assert.equal(dec(sample, "http_get", { url: "https://corp.com" }, { agentId: "a", sessionTainted: true }), "deny/tainted_session");
});

test("decide: request shape (§5)", () => {
  const q = { query: "x" };
  assert.equal(refDecide(sample, null).reason_code, "invalid_request");
  assert.equal(refDecide(sample, []).reason_code, "invalid_request");
  assert.equal(refDecide(sample, "x").reason_code, "invalid_request");
  assert.equal(refDecide(sample, { tool: "search_docs", args: q }).reason_code, "invalid_request", "ctx missing");
  assert.equal(refDecide(sample, { tool: "search_docs", args: q, ctx: null }).reason_code, "invalid_request");
  assert.equal(refDecide(sample, { tool: "search_docs", args: q, ctx: [] }).reason_code, "invalid_request");
  assert.equal(refDecide(sample, { tool: "search_docs", ctx: CTX }).reason_code, "invalid_request", "args missing");
  assert.equal(refDecide(sample, { tool: "search_docs", args: [], ctx: CTX }).reason_code, "invalid_request");
  assert.equal(refDecide(sample, { tool: "search_docs", args: q, ctx: CTX, extra: 1 }).reason_code, "invalid_request");
  assert.equal(refDecide(sample, { tool: 5, args: q, ctx: CTX }).reason_code, "invalid_request");
  assert.equal(dec(sample, "search_docs", q, { agentId: "" }), "deny/invalid_request");
  assert.equal(dec(sample, "search_docs", q, {}), "deny/invalid_request");
  assert.equal(dec(sample, "search_docs", q, { agentId: "a", userId: 1 }), "deny/invalid_request");
  assert.equal(dec(sample, "search_docs", q, { agentId: "a", scopes: ["a", 1] }), "deny/invalid_request");
  assert.equal(dec(sample, "search_docs", q, { agentId: "a", scopes: "a" }), "deny/invalid_request");
  assert.equal(dec(sample, "search_docs", q, { agentId: "a", sessionTainted: "true" }), "deny/invalid_request");
  assert.equal(dec(sample, "search_docs", q, { agentId: "a", other: 1 }), "deny/invalid_request");
  assert.equal(dec(sample, "search_docs", q, { agentId: "a", provenance: { query: "x" } }), "deny/invalid_request");
});

test("decide: provenance key/label ordering (§6 3b, §9.4)", () => {
  assert.equal(dec(sample, "search_docs", { query: "x" }, { agentId: "a", provenance: { zzz: ["l"] } }), "deny/invalid_request");
  assert.equal(dec(sample, "nope", {}, { agentId: "a", provenance: { zzz: ["l"] } }), "deny/unknown_tool");
  assert.equal(dec(sample, "nope", {}, { agentId: "a", provenance: { zzz: ["bad label"] } }), "deny/invalid_request");
  assert.equal(dec(sample, "search_docs", { query: "x" }, { agentId: "a", provenance: { query: [""] } }), "deny/invalid_request");
  assert.equal(dec(sample, "search_docs", { query: "x" }, { agentId: "a", provenance: { query: ["a".repeat(65)] } }), "deny/invalid_request");
  assert.equal(dec(sample, "search_docs", { query: "x" }, { agentId: "a", provenance: { query: ["a".repeat(64)] } }), "permit/permitted");
  assert.equal(dec(sample, "search_docs", { query: "x" }, { agentId: "a", provenance: { query: ["\u202e"] } }), "deny/invalid_request");
});

test("snapshot: hostile JS values -> invalid_request", () => {
  const ok = { query: "x" };
  const code = (args: unknown): string => refDecide(sample, { tool: "search_docs", args, ctx: CTX }).reason_code;
  assert.equal(code(ok), "permitted");
  assert.equal(code({ query: "a\ud800" }), "invalid_request");
  assert.equal(code({ query: "\udc00a" }), "invalid_request");
  assert.equal(code({ query: "\ud83d\ude00" }), "permitted");
  assert.equal(code({ query: undefined }), "invalid_request");
  assert.equal(code({ query: 1n }), "invalid_request");
  assert.equal(code({ query: Symbol("s") }), "invalid_request");
  assert.equal(code({ query: () => 1 }), "invalid_request");
  assert.equal(code(JSON.parse('{"__proto__": 1, "query": "x"}')), "invalid_request");
  assert.equal(code(JSON.parse('{"constructor": 1, "query": "x"}')), "invalid_request");
  const g = { query: "x" };
  Object.defineProperty(g, "q2", { get: () => "y", enumerable: true });
  assert.equal(code(g), "invalid_request");
  assert.equal(code(new Proxy({ query: "x" }, {})), "invalid_request");
  const cyc: Record<string, unknown> = { query: "x" };
  cyc.self = cyc;
  assert.equal(code(cyc), "invalid_request");
  assert.equal(code({ query: "x", d: new Date(0) }), "invalid_request");
  assert.equal(code({ query: "x", m: new Map() }), "invalid_request");
  assert.equal(code({ query: "x", [Symbol("k")]: 1 }), "invalid_request");
  const hidden = { query: "x" };
  Object.defineProperty(hidden, "h", { value: 1, enumerable: false });
  assert.equal(code(hidden), "invalid_request");
  assert.equal(code(Object.assign(Object.create(null), { query: "x" })), "permitted", "null-prototype object is plain");
  assert.equal(code(Object.assign(Object.create({ inherited: 1 }), { query: "x" })), "invalid_request");
});

test("snapshot: limits -> limit_exceeded (§5, §10.2)", () => {
  const code = (req: unknown): string => refDecide(sample, req).reason_code;
  const nest = (d: number): unknown => (d === 0 ? 1 : { n: nest(d - 1) });
  // root object depth 1; args depth 2; nest inside args
  assert.equal(code({ tool: "search_docs", args: { query: "x", e: nest(6) }, ctx: CTX }), "invalid_args", "depth 8 allowed");
  assert.equal(code({ tool: "search_docs", args: { query: "x", e: nest(7) }, ctx: CTX }), "limit_exceeded", "depth 9");
  assert.equal(code({ tool: "search_docs", args: { query: "a".repeat(8192) }, ctx: CTX }), "permitted");
  assert.equal(code({ tool: "search_docs", args: { query: "a".repeat(8193) }, ctx: CTX }), "limit_exceeded");
  const many = (n: number): Record<string, number> => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, i]));
  assert.equal(code({ tool: "search_docs", args: many(64), ctx: CTX }), "invalid_args");
  assert.equal(code({ tool: "search_docs", args: many(65), ctx: CTX }), "limit_exceeded");
  assert.equal(code({ tool: "search_docs", args: { query: "x", e: new Array(256).fill(1) }, ctx: CTX }), "invalid_args");
  assert.equal(code({ tool: "search_docs", args: { query: "x", e: new Array(257).fill(1) }, ctx: CTX }), "limit_exceeded");
  const big = Array.from({ length: 9 }, () => "a".repeat(8000));
  assert.equal(code({ tool: "search_docs", args: { query: "x", e: big }, ctx: CTX }), "limit_exceeded", "> 64KiB");
  // shared references are visited each time: 16*16*16 = 4096 leaf containers + inner
  const leaf: unknown[] = [];
  const l2 = Array.from({ length: 16 }, () => leaf);
  const l3 = Array.from({ length: 16 }, () => l2);
  const l4 = Array.from({ length: 16 }, () => l3);
  assert.equal(code({ tool: "search_docs", args: { query: "x", e: l4 }, ctx: CTX }), "limit_exceeded", "container visit budget");
});

test("snapshot: NFC normalisation (§10.4)", () => {
  const p = refLoadPolicy(JSON.stringify({
    policy_schema_version: 1, name: "n", mode: "enforce",
    tools: { t: { risk: "low", external_effect: false, read_only: true, fail_mode: "closed", args: { s: { type: "string" } } } },
    rules: [{ id: "r", effect: "permit", reason_code: "ok", match: { args: { s: { equals: "\u00e9" } } } }],
  }));
  assert.equal(dec(p, "t", { s: "e\u0301" }), "permit/permitted");
  assert.equal(dec(p, "t", { s: "\u00e9" }), "permit/permitted");
  assert.equal(dec(p, "t", { s: "E\u0301" }), "deny/default_deny");
  // NFC key collision is rejected (deny-safe reading)
  assert.equal(refDecide(p, { tool: "t", args: { "\u00e9": 1, "e\u0301": 2 }, ctx: CTX }).reason_code, "invalid_request");
});

// ---------- decide: synthetic policy for string[], tri-state, precedence ----------
function synth(rules: unknown[]): RefPolicy {
  return refLoadPolicy(JSON.stringify({
    policy_schema_version: 1, name: "synth", mode: "enforce",
    tools: {
      lst: { risk: "high", external_effect: true, read_only: false, fail_mode: "closed",
        args: { names: { type: "string[]" }, tag: { type: "string", optional: true } } },
      num: { risk: "low", external_effect: false, read_only: true, fail_mode: "open_on_audit_failure",
        args: { n: { type: "number" }, b: { type: "boolean", optional: true } } },
    },
    rules,
  }));
}
const R = (id: string, effect: string, match: unknown): unknown => ({ id, effect, reason_code: "rc_" + id, match });

test("string[]: permit=all, deny=any, empty matches neither (§10.1)", () => {
  const p = synth([R("p", "permit", { tools: ["lst"], args: { names: { glob: "a*" } } })]);
  assert.equal(dec(p, "lst", { names: ["ab", "ac"] }), "permit/permitted");
  assert.equal(dec(p, "lst", { names: ["ab", "b"] }), "deny/default_deny");
  assert.equal(dec(p, "lst", { names: [] }), "deny/default_deny");
  const d = synth([R("d", "deny", { tools: ["lst"], args: { names: { glob: "b*" } } }), R("p", "permit", { tools: ["lst"] })]);
  assert.equal(dec(d, "lst", { names: ["ab", "b"] }), "deny/denied_by_rule");
  assert.equal(dec(d, "lst", { names: ["ab"] }), "permit/permitted");
  assert.equal(dec(d, "lst", { names: [] }), "permit/permitted", "deny rule cannot block empty array");
  assert.equal(dec(d, "lst", { names: [1] }), "deny/invalid_args");
});

test("string[] with tri-state matchers (§11)", () => {
  const d = synth([
    R("d", "deny", { tools: ["lst"], args: { names: { path_within: { root: "/secret", case_insensitive: false } } } }),
    R("p", "permit", { tools: ["lst"] }),
  ]);
  assert.equal(dec(d, "lst", { names: ["/ok", "/secret/x"] }), "deny/denied_by_rule");
  assert.equal(dec(d, "lst", { names: ["/ok", "%2fsecret"] }), "deny/denied_by_rule", "unparseable element in deny");
  assert.equal(dec(d, "lst", { names: ["/ok", "/fine"] }), "permit/permitted");
  const p = synth([R("p", "permit", { tools: ["lst"], args: { names: { path_within: { root: "/ok", case_insensitive: false } } } })]);
  assert.equal(dec(p, "lst", { names: ["/ok/a", "/ok/b"] }), "permit/permitted");
  assert.equal(dec(p, "lst", { names: ["/ok/a", "%2f"] }), "deny/default_deny", "unparseable in permit = no match");
  const h = synth([R("d", "deny", { tools: ["lst"], args: { names: { domain_exact: "bad.com", accept: ["host"] } } })]);
  assert.equal(dec(h, "lst", { names: ["good.com", "http://bad.com"] }), "deny/denied_by_rule", "wrong accept form is unparseable => deny matches");
  assert.equal(dec(h, "lst", { names: ["good.com"] }), "deny/default_deny");
});

test("deny wins; optional arg absent never matches; permit/deny same call", () => {
  const p = synth([
    R("d", "deny", { tools: ["num"], args: { n: { range: { min: 0, max: 5 } } } }),
    R("p", "permit", { tools: ["num"], args: { n: { range: { min: 0, max: 10 } } } }),
  ]);
  assert.equal(dec(p, "num", { n: 3 }), "deny/denied_by_rule");
  assert.equal(dec(p, "num", { n: 7 }), "permit/permitted");
  const o = synth([R("d", "deny", { tools: ["num"], args: { b: { equals: true } } }), R("p", "permit", { tools: ["num"] })]);
  assert.equal(dec(o, "num", { n: 1 }), "permit/permitted", "absent optional arg => deny rule does not match");
  assert.equal(dec(o, "num", { n: 1, b: true }), "deny/denied_by_rule");
  assert.equal(dec(o, "num", { n: 1, b: false }), "permit/permitted");
  assert.equal(dec(o, "num", { n: 1, b: 1 }), "deny/invalid_args");
});

test("tainted session: external effect needs a session_tainted:true permit (§6.7)", () => {
  const p = synth([
    R("p1", "permit", { tools: ["lst"] }),
    R("p2", "permit", { tools: ["lst"], session_tainted: true, agents: ["trusted"] }),
  ]);
  const t = (agentId: string): string => dec(p, "lst", { names: [] }, { agentId, sessionTainted: true });
  assert.equal(t("other"), "deny/tainted_session");
  assert.equal(t("trusted"), "permit/permitted");
  assert.equal(dec(p, "lst", { names: [] }, { agentId: "trusted", sessionTainted: false }), "permit/permitted");
  const none = synth([]);
  assert.equal(dec(none, "lst", { names: [] }, { agentId: "a", sessionTainted: true }), "deny/tainted_session", "no permits at all, still tainted_session");
  assert.equal(dec(none, "lst", { names: [] }, { agentId: "a" }), "deny/default_deny");
  assert.equal(dec(none, "num", { n: 1 }, { agentId: "a", sessionTainted: true }), "deny/default_deny", "non-external tool");
  const sd = synth([R("d", "deny", { tools: ["lst"], session_tainted: false }), R("p", "permit", { tools: ["lst"] })]);
  assert.equal(dec(sd, "lst", { names: [] }), "deny/denied_by_rule");
  assert.equal(dec(sd, "lst", { names: [] }, { agentId: "a", sessionTainted: true }), "deny/tainted_session");
});

test("agents / scopes_any / glob / equals / in / max_length", () => {
  const p = synth([
    R("a", "permit", { tools: ["num"], agents: ["bot"], args: { n: { in: [1, 2, 3] } } }),
    R("m", "permit", { tools: ["lst"], scopes_any: ["x", "y"], args: { names: { max_length: 2 } } }),
    R("e", "permit", { tools: ["lst"], args: { tag: { equals: "k" } } }),
  ]);
  assert.equal(dec(p, "num", { n: 2 }, { agentId: "bot" }), "permit/permitted");
  assert.equal(dec(p, "num", { n: 2 }, { agentId: "bot2" }), "deny/default_deny");
  assert.equal(dec(p, "num", { n: 4 }, { agentId: "bot" }), "deny/default_deny");
  assert.equal(dec(p, "lst", { names: ["ab", "c"] }, { agentId: "a", scopes: ["y"] }), "permit/permitted");
  assert.equal(dec(p, "lst", { names: ["abc"] }, { agentId: "a", scopes: ["y"] }), "deny/default_deny");
  assert.equal(dec(p, "lst", { names: ["\u{1F600}\u{1F600}"] }, { agentId: "a", scopes: ["y"] }), "permit/permitted", "max_length counts code points");
  assert.equal(dec(p, "lst", { names: ["ab"] }, { agentId: "a", scopes: [] }), "deny/default_deny");
  assert.equal(dec(p, "lst", { names: [], tag: "k" }), "permit/permitted");
  assert.equal(dec(p, "lst", { names: [], tag: "K" }), "deny/default_deny");
});

test("provenance any_in / all_in / optional arg absent (§6.4)", () => {
  const p = synth([
    R("a", "permit", { tools: ["lst"], provenance: { names: { any_in: ["good"] } } }),
    R("b", "permit", { tools: ["lst"], provenance: { tag: { all_in: ["unlabelled:x"] } } }),
  ]);
  assert.equal(dec(p, "lst", { names: [] }, { agentId: "a", provenance: { names: ["bad", "good"] } }), "permit/permitted");
  assert.equal(dec(p, "lst", { names: [] }, { agentId: "a", provenance: { names: ["bad"] } }), "deny/default_deny");
  assert.equal(dec(p, "lst", { names: [] }), "deny/default_deny", "default label untrusted:unknown not in list");
  assert.equal(dec(p, "lst", { names: [], tag: "t" }, { agentId: "a", provenance: { tag: ["unlabelled:x"] } }), "permit/permitted");
  assert.equal(dec(p, "lst", { names: [] }, { agentId: "a", provenance: { tag: ["unlabelled:x"] } }), "deny/default_deny", "absent arg => provenance no match");
});

test("matched ids are sorted and complete", () => {
  const p = synth([R("z", "permit", { tools: ["num"] }), R("a", "permit", { tools: ["num"] }), R("m", "deny", { tools: ["num"] })]);
  const r = refDecide(p, { tool: "num", args: { n: 1 }, ctx: CTX });
  assert.deepEqual(r.matched, { deny: ["m"], permit: ["a", "z"] });
});

test("order independence of rules", () => {
  const rules = [
    R("d", "deny", { tools: ["num"], args: { n: { range: { max: 0 } } } }),
    R("p1", "permit", { tools: ["num"] }),
    R("p2", "permit", { tools: ["num"], args: { n: { equals: 0 } } }),
  ];
  const a = synth(rules);
  const b = synth([...rules].reverse());
  for (const n of [-1, 0, 1]) {
    assert.equal(dec(a, "num", { n }), dec(b, "num", { n }));
  }
});

// ---------- loader ----------
function baseDoc(): Record<string, any> {
  return JSON.parse(JSON.stringify({
    policy_schema_version: 1, name: "t", mode: "monitor_only",
    tools: {
      files: { risk: "medium", external_effect: false, read_only: true, fail_mode: "closed", args: { path: { type: "string" }, n: { type: "number" } } },
      lst: { risk: "low", external_effect: false, read_only: true, fail_mode: "open_on_audit_failure", args: { names: { type: "string[]" }, flag: { type: "boolean", optional: true } } },
    },
    rules: [{ id: "r1", effect: "permit", reason_code: "ok", match: { tools: ["files"], args: { path: { glob: "/w/*" } } } }],
  }));
}
function loads(doc: unknown): boolean {
  try {
    refLoadPolicy(typeof doc === "string" || doc instanceof Uint8Array ? doc : JSON.stringify(doc));
    return true;
  } catch {
    return false;
  }
}
function withRule(match: unknown, extra: Record<string, unknown> = {}): Record<string, any> {
  const d = baseDoc();
  d.rules = [{ id: "r1", effect: "permit", reason_code: "ok", match, ...extra }];
  return d;
}
const pred = (tools: string[] | undefined, arg: string, p: unknown): Record<string, any> =>
  withRule({ ...(tools ? { tools } : {}), args: { [arg]: p } });

test("loader: valid documents", () => {
  assert.equal(loads(baseDoc()), true);
  assert.equal(loads(SAMPLE), true);
  const e = baseDoc(); e.rules = []; e.tools = {};
  assert.equal(loads(e), true, "empty rules/tools legal");
  const t = baseDoc(); t.tools.files.args = {};
  t.rules = [];
  assert.equal(loads(t), true, "empty args legal");
  assert.equal(loads(JSON.stringify(baseDoc()).replace('"policy_schema_version":1', '"policy_schema_version":1.0')), true);
  assert.equal(loads(JSON.stringify(baseDoc()).replace('"policy_schema_version":1', '"policy_schema_version":1e0')), true);
  assert.equal(loads(pred(["lst"], "names", { glob: "a*" })), true, "glob on string[]");
  assert.equal(loads(pred(["files"], "path", { domain_suffix: "corp.com", accept: ["url", "url", "email"] })), true, "duplicate accept legal");
  assert.equal(loads(pred(["files"], "path", { path_within: { root: "/", case_insensitive: true } })), true);
  assert.equal(loads(pred(["files", "lst"], "path", { equals: "x" })), false, "arg not declared for every tool");
  assert.equal(loads(withRule({ session_tainted: false, agents: ["a:b"], scopes_any: ["s"] })), true);
  assert.equal(loads(pred(["files"], "n", { equals: -0 })), true);
  assert.equal(loads(new TextEncoder().encode(JSON.stringify(baseDoc()))), true, "byte input");
});

test("loader: rejections", () => {
  const rejects: Array<[string, unknown]> = [];
  const add = (name: string, d: unknown): number => rejects.push([name, d]);
  let d: Record<string, any>;
  d = baseDoc(); d.policy_schema_version = "1"; add("version string", d);
  d = baseDoc(); d.policy_schema_version = 2; add("version 2", d);
  d = baseDoc(); delete d.policy_schema_version; add("version missing", d);
  d = baseDoc(); d.extra = 1; add("unknown top key", d);
  d = baseDoc(); d.mode = "audit"; add("bad mode", d);
  d = baseDoc(); d.name = "bad name"; add("bad name", d);
  d = baseDoc(); d.tools.files.extra = 1; add("unknown tool key", d);
  d = baseDoc(); d.tools.files.risk = "extreme"; add("bad risk", d);
  d = baseDoc(); d.tools.files.fail_mode = "open_on_audit_failure"; add("open fail_mode on medium risk", d);
  d = baseDoc(); d.tools.lst.read_only = false; add("open fail_mode on non-read-only", d);
  d = baseDoc(); d.tools["a:b"] = d.tools.files; add("tool name with colon", d);
  d = baseDoc(); d.tools.files.args.path.type = "int"; add("bad arg type", d);
  d = baseDoc(); d.tools.files.args.path.optional = "yes"; add("optional non-bool", d);
  d = baseDoc(); d.rules.push({ ...d.rules[0] }); add("duplicate rule id", d);
  d = baseDoc(); d.rules[0].effect = "audit"; add("bad effect", d);
  d = baseDoc(); d.rules[0].reason_code = "has space"; add("bad reason code", d);
  d = baseDoc(); d.rules[0].priority = 1; add("unknown rule key", d);
  d = withRule({}); add("empty match", d);
  d = withRule({ tools: [] }); add("empty tools list", d);
  d = withRule({ agents: [] }); add("empty agents list", d);
  d = withRule({ scopes_any: [] }); add("empty scopes list", d);
  d = withRule({ tools: ["ghost"] }); add("unknown tool in match", d);
  d = withRule({ unknown: 1 }); add("unknown match key", d);
  d = withRule({ session_tainted: "yes" }); add("session_tainted non-bool", d);
  d = withRule({ agents: ["bad agent"] }); add("agent id charset", d);
  d = withRule({ agents: Array.from({ length: 257 }, (_, i) => `a${i}`) }); add("list > 256", d);
  d = withRule({ args: {} }); add("empty args object", d);
  d = withRule({ provenance: {} }); add("empty provenance object", d);
  d = pred(["files"], "path", { range: { min: 0 } }); add("range on string", d);
  d = pred(["files"], "n", { glob: "x" }); add("glob on number", d);
  d = pred(["files"], "n", { max_length: 3 }); add("max_length on number", d);
  d = pred(["files"], "n", { equals: "x" }); add("equals string on number", d);
  d = pred(["files"], "path", { equals: 3 }); add("equals number on string", d);
  d = pred(["lst"], "flag", { equals: "x" }); add("equals string on boolean", d);
  d = pred(["files"], "path", { in: [] }); add("in empty", d);
  d = pred(["files"], "path", { in: ["a", 1] }); add("in mixed", d);
  d = pred(["files"], "n", { range: { min: 5, max: 1 } }); add("range min>max", d);
  d = pred(["files"], "n", { range: {} }); add("range empty", d);
  d = pred(["files"], "n", { range: { min: "1" } }); add("range non-number", d);
  d = pred(["files"], "n", { range: { min: 1, step: 2 } }); add("range unknown key", d);
  d = pred(["files"], "path", { max_length: -1 }); add("max_length negative", d);
  d = pred(["files"], "path", { max_length: 1.5 }); add("max_length fractional", d);
  d = pred(["files"], "path", { max_length: "3" }); add("max_length string", d);
  d = pred(["files"], "path", { glob: "a*b*c*d*e*" }); add("5 stars", d);
  d = pred(["files"], "path", { glob: "x".repeat(257) }); add("glob too long", d);
  d = pred(["files"], "path", { glob: "x", accept: ["url"] }); add("accept on glob", d);
  d = pred(["files"], "path", { glob: "x", equals: "y" }); add("two operators", d);
  d = pred(["files"], "path", {}); add("zero operators", d);
  d = pred(["files"], "path", { domain_suffix: "a.com" }); add("accept missing", d);
  d = pred(["files"], "path", { domain_suffix: "a.com", accept: [] }); add("accept empty", d);
  d = pred(["files"], "path", { domain_suffix: "a.com", accept: ["ftp"] }); add("accept bad entry", d);
  d = pred(["files"], "path", { domain_suffix: "A.com", accept: ["host"] }); add("domain uppercase", d);
  d = pred(["files"], "path", { domain_suffix: "a.com.", accept: ["host"] }); add("domain trailing dot", d);
  d = pred(["files"], "path", { domain_suffix: "*.a.com", accept: ["host"] }); add("domain wildcard", d);
  d = pred(["files"], "path", { domain_suffix: "1.2.3.4", accept: ["host"] }); add("domain IP", d);
  d = pred(["files"], "path", { domain_suffix: "a_b.com", accept: ["host"] }); add("domain underscore", d);
  d = pred(["files"], "path", { domain_exact: "a.com", domain_suffix: "a.com", accept: ["host"] }); add("two domain ops", d);
  d = pred(["files"], "n", { domain_suffix: "a.com", accept: ["host"] }); add("domain on number", d);
  d = pred(["files"], "path", { path_within: { root: "/w" } }); add("case_insensitive missing", d);
  d = pred(["files"], "path", { path_within: { root: "/w", case_insensitive: "no" } }); add("case_insensitive non-bool", d);
  d = pred(["files"], "path", { path_within: { root: "w", case_insensitive: false } }); add("relative root", d);
  d = pred(["files"], "path", { path_within: { root: "/w/", case_insensitive: false } }); add("trailing slash root", d);
  d = pred(["files"], "path", { path_within: { root: "/w/../x", case_insensitive: false } }); add("dotdot root", d);
  d = pred(["files"], "path", { path_within: { root: "/w//x", case_insensitive: false } }); add("double slash root", d);
  d = pred(["files"], "path", { path_within: { root: "/w/./x", case_insensitive: false } }); add("dot root", d);
  d = pred(["files"], "path", { path_within: { root: "/w\u00e9", case_insensitive: false } }); add("non-ASCII root", d);
  d = pred(["files"], "n", { path_within: { root: "/w", case_insensitive: false } }); add("path_within on number", d);
  d = pred(undefined, "ghost", { equals: "x" }); add("arg declared nowhere", d);
  d = withRule({ args: { path: { equals: "x" }, n: { equals: 1 } }, tools: ["files", "lst"] }); add("arg not on every tool", d);
  d = baseDoc(); d.tools.lst.args.path = { type: "number" };
  d.rules = [{ id: "r", effect: "deny", reason_code: "x", match: { args: { path: { equals: "x" } } } }]; add("arg type conflict, no tools clause", d);
  d = withRule({ tools: ["files"], provenance: { ghost: { all_in: ["x"] } } }); add("provenance undeclared", d);
  d = withRule({ tools: ["files"], provenance: { path: {} } }); add("provenance entry empty", d);
  d = withRule({ tools: ["files"], provenance: { path: { all_in: [] } } }); add("all_in empty", d);
  d = withRule({ tools: ["files"], provenance: { path: { any_in: ["bad label"] } } }); add("label charset", d);
  d = withRule({ tools: ["files"], provenance: { path: { all_in: ["x"], none_in: ["y"] } } }); add("provenance unknown key", d);
  d = baseDoc(); d.name = "zero\u200bwidth"; add("zero-width in name", d);
  d = baseDoc(); d.tools.files.schema_hash = "a\u0007b"; add("control char in schema_hash", d);
  d = baseDoc(); d.tools.files.schema_hash = "a\u202eb"; add("bidi in schema_hash", d);
  d = baseDoc(); d.tools.files.schema_hash = "a\u00a0b"; add("nbsp in schema_hash", d);
  d = baseDoc(); d.tools.files.schema_hash = "a\u2028b"; add("line separator", d);
  d = baseDoc(); d.tools.files.schema_hash = "a\ue000b"; add("private use", d);
  d = baseDoc(); d.tools.files.schema_hash = 5; add("schema_hash non-string", d);
  d = pred(["files"], "path", { equals: "a\u0085b" }); add("C1 control in literal", d);
  d = baseDoc(); d.rules = Array.from({ length: 1001 }, (_, i) => ({ id: `r${i}`, effect: "permit", reason_code: "ok", match: { tools: ["files"] } })); add("1001 rules", d);
  add("BOM string", "\ufeff" + JSON.stringify(baseDoc()));
  add("BOM bytes", new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode(JSON.stringify(baseDoc()))]));
  add("invalid utf8", new Uint8Array([0x7b, 0xff, 0x7d]));
  add("dup key", JSON.stringify(baseDoc()).replace('"name":"t"', '"name":"t","name":"u"'));
  add("__proto__ key", JSON.stringify(baseDoc()).replace('"name":"t"', '"name":"t","__proto__":{}'));
  add("constructor key", JSON.stringify(baseDoc()).replace('"name":"t"', '"name":"t","constructor":1'));
  add("prototype key", JSON.stringify(baseDoc()).replace('"tools":{', '"tools":{"prototype":{},'));
  add("trailing comma", JSON.stringify(baseDoc()).replace(/}$/, ",}"));
  add("not json", "policy");
  add("array root", "[]");
  add("null root", "null");
  add("file > 1MiB", JSON.stringify({ ...baseDoc(), name: "t", pad: "x".repeat(1024 * 1024) }));
  assert.ok(rejects.length >= 60);
  const wrong = rejects.filter(([, doc]) => loads(doc)).map(([n]) => n);
  assert.deepEqual(wrong, [], "loaded but should have been rejected");
});

test("loader: forbidden-character scan across all code points (§11.14)", () => {
  // every control / format / separator code point in the BMP must be rejected inside a policy string
  const bad: number[] = [];
  for (let cp = 0; cp <= 0xffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    const ch = String.fromCodePoint(cp);
    if (/[\p{Cf}\p{Zl}\p{Zp}\p{Cc}\p{Co}\p{Cn}]/u.test(ch) || (/\p{Zs}/u.test(ch) && ch !== " ")) {
      const d = baseDoc();
      d.tools.files.schema_hash = "a" + ch + "b";
      if (loads(JSON.stringify(d))) bad.push(cp);
    }
  }
  assert.deepEqual(bad, []);
  const ok = baseDoc();
  ok.tools.files.schema_hash = "a b \u00e9 \u4e2d";
  assert.equal(loads(ok), true, "ordinary text allowed");
  const lone = JSON.stringify(baseDoc()).replace('"name":"t"', '"name":"t\\ud800"');
  assert.equal(loads(lone), false, "lone surrogate escape rejected");
});

// ---------- v1.4 rulings (POLICY-SPEC §12) ----------
test("§12.1 limits take precedence over validity (the 18 previously disagreeing minimal shapes)", () => {
  const big = "a".repeat(8193);
  const code = (args: unknown, ctx: unknown = CTX): string => refDecide(sample, { tool: "search_docs", args, ctx }).reason_code;
  const arr = Array.from({ length: 257 }, () => "a");
  assert.equal(code({ query: "x", e: ["\ud800"], big }), "limit_exceeded", "invalid before limit");
  assert.equal(code({ query: "x", big, e: ["\ud800"] }), "limit_exceeded", "limit before invalid");
  assert.equal(code({ query: "x", e: undefined, big }), "limit_exceeded");
  assert.equal(code({ query: "x", e: 1n, big }), "limit_exceeded");
  assert.equal(code({ query: "x", e: new Date(0), big }), "limit_exceeded");
  assert.equal(code({ query: "x", e: arr, [Symbol("k")]: 1 }), "limit_exceeded", "symbol key + limit");
  assert.equal(code({ query: "x", e: arr, [Symbol("k")]: 1 } as never), "limit_exceeded");
  assert.equal(code(new Proxy({ query: "x", e: arr }, {})), "limit_exceeded", "proxy + limit");
  assert.equal(code({ query: "x", e: "a\ud800" + "a".repeat(8200) }), "limit_exceeded", "lone surrogate + long string");
  assert.equal(code({ query: "x", g: ["\ud800"] }, { agentId: "a", provenance: { query: arr } }), "limit_exceeded");
  assert.equal(refDecide(sample, { tool: undefined, args: { query: "x", e: arr }, ctx: CTX }).reason_code, "limit_exceeded");
  assert.equal(refDecide(sample, { args: { query: "x", e: big }, ctx: CTX }).reason_code, "limit_exceeded", "missing tool + limit");
  // each fault alone keeps its own code
  assert.equal(code({ query: "x", e: arr }), "limit_exceeded");
  assert.equal(code({ query: "x", e: ["\ud800"] }), "invalid_request");
  assert.equal(code({ query: "x", [Symbol("k")]: 1 }), "invalid_request");
  assert.equal(code(new Proxy({ query: "x" }, {})), "invalid_request");
  const cyc: Record<string, unknown> = { query: "x" };
  cyc.self = cyc;
  assert.equal(code(cyc), "invalid_request");
});

test("§12.2 size limit measured on the NFC snapshot", () => {
  const mk = (q: string, target: number): unknown => {
    const req = { tool: "search_docs", args: { query: q, pad: [] as string[] }, ctx: CTX };
    const bytes = (): number => Buffer.byteLength(JSON.stringify(req), "utf8");
    const pad = req.args.pad;
    while (bytes() < target) {
      const L = Math.min(8000, target - bytes() - 2 - (pad.length ? 1 : 0));
      if (L < 0) break;
      pad.push("a".repeat(L));
    }
    return req;
  };
  const code = (r: unknown): string => refDecide(sample, r).reason_code;
  // raw 65 537 bytes; NFC form is 1 byte shorter (e + U+0301 -> U+00E9) => 65 536 => within the limit
  assert.equal(code(mk("e\u0301", 65537)), "invalid_args");
  assert.equal(code(mk("e\u0301", 65538)), "limit_exceeded");
  assert.equal(code(mk("x", 65536)), "invalid_args");
  assert.equal(code(mk("x", 65537)), "limit_exceeded");
});

test("§12.3 drive-prefixed path_within roots", () => {
  const p = refLoadPolicy(JSON.stringify({
    policy_schema_version: 1, name: "n", mode: "enforce",
    tools: { t: { risk: "low", external_effect: false, read_only: true, fail_mode: "closed", args: { p: { type: "string" } } } },
    rules: [
      { id: "d", effect: "permit", reason_code: "ok", match: { args: { p: { path_within: { root: "C:/work", case_insensitive: false } } } } },
      { id: "u", effect: "permit", reason_code: "ok2", match: { args: { p: { path_within: { root: "/work", case_insensitive: false } } } } },
    ],
  }));
  const m = (v: string): { deny: string[]; permit: string[] } => refDecide(p, { tool: "t", args: { p: v }, ctx: CTX }).matched;
  assert.deepEqual(m("C:/work/x").permit, ["d"]);
  assert.deepEqual(m("c:\\work\\x").permit, ["d"], "drive letter upper-cased");
  assert.deepEqual(m("/work/x").permit, ["u"], "drive root never matches unix path and vice versa");
  assert.deepEqual(m("D:/work/x").permit, []);
  for (const root of ["c:/work", "C:", "C:/a/../b", "C:/a//b", "C:/a/", "CC:/a"]) {
    const d = JSON.parse(JSON.stringify({
      policy_schema_version: 1, name: "n", mode: "enforce", tools: {},
      rules: [],
    }));
    assert.equal(loads(d), true);
    const bad = baseDoc();
    bad.rules[0].match.args.path = { path_within: { root, case_insensitive: false } };
    assert.equal(loads(bad), false, root);
  }
});

test("§12.4 string / string[] arguments are compatible without a tools clause", () => {
  const d = baseDoc();
  d.tools.lst.args.path = { type: "string[]" }; // `path` is `string` in tool `files`
  d.rules = [{ id: "r", effect: "deny", reason_code: "x", match: { args: { path: { equals: "x" } } } }];
  assert.equal(loads(d), true);
  d.rules[0].match.args.path = { range: { min: 1 } };
  assert.equal(loads(d), false, "range on string argument still rejected");
  const e = baseDoc();
  e.tools.lst.args.n = { type: "boolean" }; // `n` is number in `files`
  e.rules = [{ id: "r", effect: "deny", reason_code: "x", match: { args: { n: { equals: 1 } } } }];
  assert.equal(loads(e), false, "incompatible required type");
});
