// Random VALID policy generator and invalid-policy mutator for the differential harness.
// Generated from POLICY-SPEC.md only.
import type { Rng } from "./prng.ts";

export type ArgType = "string" | "number" | "boolean" | "string[]";
export type Doc = Record<string, any>;

export type Hint =
  | { kind: "path"; root: string }
  | { kind: "host"; value: string }
  | { kind: "str"; value: string }
  | { kind: "num"; value: number }
  | { kind: "bool"; value: boolean }
  | { kind: "len"; n: number };

export interface GenTool {
  name: string;
  args: Array<{ name: string; type: ArgType; optional: boolean }>;
}
export interface GenPolicy {
  doc: Doc;
  text: string;
  tools: GenTool[];
  agents: string[];
  scopes: string[];
  labels: string[];
  hints: Map<string, Hint[]>;
}

const TOOL_NAMES = ["read_file", "send_email", "http_get", "t.x", "tool-2", "delete", "query", "a", "Tool_9"];
const ARG_POOL = ["path", "url", "to", "cc", "body", "q", "mode", "files", "flags", "n", "amount", "on", "x-y", "k.1"];
const DEFAULT_TYPE: Record<string, ArgType> = {
  path: "string", url: "string", to: "string", cc: "string", body: "string", q: "string", mode: "string",
  files: "string[]", flags: "string[]", n: "number", amount: "number", on: "boolean", "x-y": "string", "k.1": "string[]",
};
const AGENTS = ["agent-1", "agent-2", "bot", "admin:root", "A.b_c"];
const SCOPES = ["sales", "read", "write:x", "admin", "s-1"];
const LABELS = ["trusted-user", "policy-constant", "untrusted:unknown", "web:page", "user_1", "a.b-c:d"];
const LITS = ["admin", "a/b", "\u00e9", "x y", "", "Hello", "0", "true", "e\u0301", "\uff41", "ID-7"];
const NUMS = [0, 1, -1, 5, 10, 0.5, 100, 1e21, 1e-7, 255, -3.5, 9007199254740991];
const DOMAINS = ["corp.com", "docs.corp.com", "a.b.example.org", "xn--nxasmq6b.com", "x-y.io", "localhost", "a1.co", "example.com"];
const ROOTS = ["/", "/workspace", "/workspace/secrets", "/a/b/c", "/Users/Bob", "/tmp", "/Program Files", "/data.v2", "/etc"];
const DRIVE_ROOTS = ["C:/", "C:/work", "D:/Data/x", "C:/Program Files"];
const SAMPLES = ["/workspace/a.txt", "report-2024.pdf", "https://corp.com/x/y", "bob@corp.com", "hello world", "abc", "/a/b/c/d", "x.y.z"];
const REASONS = ["ok", "blocked", "rule_a", "R-1", "why:not", "policy.deny"];
const RULE_ID_PREFIX = ["rule", "r", "perm", "deny.x", "id:"];

function baseOf(t: ArgType): "string" | "number" | "boolean" {
  return t === "string[]" ? "string" : t;
}

export function genPolicy(rng: Rng): GenPolicy {
  // tool set
  const toolNames = rng.sample(TOOL_NAMES, rng.range(1, 6));
  const tools: GenTool[] = [];
  for (const name of toolNames) {
    const argNames = rng.sample(ARG_POOL, rng.range(0, 4));
    const args = argNames.map((an) => {
      let type = DEFAULT_TYPE[an] as ArgType;
      if (rng.chance(0.1)) type = rng.pick(["string", "number", "boolean", "string[]"] as const);
      return { name: an, type, optional: rng.chance(0.3) };
    });
    tools.push({ name, args });
  }
  const docTools: Record<string, any> = {};
  for (const t of tools) {
    const risk = rng.pick(["low", "medium", "high"] as const);
    const read_only = rng.chance(0.5);
    const canOpen = risk === "low" && read_only;
    const argsDoc: Record<string, any> = {};
    for (const a of t.args) argsDoc[a.name] = a.optional || rng.chance(0.1) ? (a.optional ? { type: a.type, optional: true } : { type: a.type, optional: false }) : { type: a.type };
    const td: Record<string, any> = {
      risk,
      external_effect: rng.chance(0.5),
      read_only,
      fail_mode: canOpen && rng.chance(0.5) ? "open_on_audit_failure" : "closed",
      args: argsDoc,
    };
    if (rng.chance(0.1)) td.schema_hash = "sha256:" + "ab".repeat(8);
    docTools[t.name] = td;
  }

  const hints = new Map<string, Hint[]>();
  const addHint = (arg: string, h: Hint): void => {
    const l = hints.get(arg) ?? [];
    l.push(h);
    hints.set(arg, l);
  };
  const agents = new Set<string>();
  const scopes = new Set<string>();
  const labels = new Set<string>();

  const typeOf = (tool: GenTool, arg: string): ArgType | undefined => tool.args.find((a) => a.name === arg)?.type;

  const rules: Doc[] = [];
  const nRules = rng.range(1, 12);
  for (let i = 0; i < nRules; i++) {
    const effect = rng.chance(0.45) ? "deny" : "permit";
    const match: Doc = {};
    let ruleTools: GenTool[] | undefined;
    if (rng.chance(0.75)) {
      ruleTools = rng.sample(tools, rng.range(1, Math.min(3, tools.length)));
      match.tools = ruleTools.map((t) => t.name);
    }
    if (rng.chance(0.2)) {
      const a = rng.sample(AGENTS, rng.range(1, 3));
      a.forEach((x) => agents.add(x));
      match.agents = a;
    }
    if (rng.chance(0.2)) {
      const s = rng.sample(SCOPES, rng.range(1, 3));
      s.forEach((x) => scopes.add(x));
      match.scopes_any = s;
    }
    if (rng.chance(0.12)) match.session_tainted = rng.chance(0.6);

    // candidate arg names usable for predicates
    const candidates = (): string[] => {
      const pool = new Set<string>();
      const holders = ruleTools ?? tools;
      for (const t of holders) for (const a of t.args) pool.add(a.name);
      const out: string[] = [];
      for (const an of pool) {
        if (ruleTools) {
          if (!ruleTools.every((t) => typeOf(t, an) !== undefined)) continue;
        } else {
          const types = new Set(tools.map((t) => typeOf(t, an)).filter((x) => x !== undefined));
          const bs = new Set([...types].map((t) => baseOf(t as ArgType)));
          if (bs.size !== 1) continue;
        }
        out.push(an);
      }
      return out;
    };
    const cands = candidates();
    if (cands.length > 0 && rng.chance(0.7)) {
      const an = rng.sample(cands, rng.range(1, Math.min(2, cands.length)));
      const argsM: Doc = {};
      for (const name of an) {
        const holders = (ruleTools ?? tools).filter((t) => typeOf(t, name) !== undefined);
        const bases = new Set(holders.map((t) => baseOf(typeOf(t, name) as ArgType)));
        if (bases.size !== 1) continue;
        argsM[name] = genPredicate(rng, [...bases][0] as "string" | "number" | "boolean", name, addHint);
      }
      if (Object.keys(argsM).length > 0) match.args = argsM;
    }
    if (cands.length > 0 && rng.chance(0.2)) {
      const name = rng.pick(cands);
      const entry: Doc = {};
      if (rng.chance(0.6)) entry.all_in = rng.sample(LABELS, rng.range(1, 3));
      if (!entry.all_in || rng.chance(0.2)) entry.any_in = rng.sample(LABELS, rng.range(1, 3));
      [...(entry.all_in ?? []), ...(entry.any_in ?? [])].forEach((l: string) => labels.add(l));
      match.provenance = { [name]: entry };
    }
    if (Object.keys(match).length === 0) match.tools = [rng.pick(tools).name];
    rules.push({
      id: `${rng.pick(RULE_ID_PREFIX)}${i}`,
      effect,
      reason_code: rng.pick(REASONS),
      match,
    });
  }
  // tool-less policies still need at least one tool for `match.tools`; if tools exist always
  const doc: Doc = {
    policy_schema_version: 1,
    name: rng.pick(["p", "support-agent", "test.policy_1", "x:y"]),
    mode: rng.pick(["enforce", "monitor_only"]),
    tools: docTools,
    rules,
  };
  LABELS.slice(0, 3).forEach((l) => labels.add(l));
  return { doc, text: JSON.stringify(doc), tools, agents: [...agents], scopes: [...scopes], labels: [...labels], hints };
}

function genPredicate(
  rng: Rng,
  base: "string" | "number" | "boolean",
  arg: string,
  addHint: (a: string, h: Hint) => void,
): Doc {
  if (base === "number") {
    const k = rng.int(4);
    if (k === 0) {
      const v = rng.pick(NUMS);
      addHint(arg, { kind: "num", value: v });
      return { equals: v };
    }
    if (k === 1) {
      const vs = rng.sample(NUMS, rng.range(1, 4));
      vs.forEach((v) => addHint(arg, { kind: "num", value: v }));
      return { in: vs };
    }
    let min: number | undefined = rng.chance(0.7) ? rng.pick([-10, -1, 0, 0.5, 1, 5]) : undefined;
    let max: number | undefined = rng.chance(0.7) || min === undefined ? rng.pick([0, 1, 5, 10, 100, 1e6]) : undefined;
    if (min !== undefined && max !== undefined && min > max) [min, max] = [max, min];
    const r: Doc = {};
    if (min !== undefined) {
      r.min = min;
      addHint(arg, { kind: "num", value: min });
    }
    if (max !== undefined) {
      r.max = max;
      addHint(arg, { kind: "num", value: max });
    }
    return { range: r };
  }
  if (base === "boolean") {
    if (rng.chance(0.6)) {
      const v = rng.chance(0.5);
      addHint(arg, { kind: "bool", value: v });
      return { equals: v };
    }
    const vs = rng.chance(0.5) ? [true] : [false, true];
    return { in: vs };
  }
  // string
  const k = rng.int(7);
  switch (k) {
    case 0: {
      const v = rng.pick(LITS);
      addHint(arg, { kind: "str", value: v });
      return { equals: v };
    }
    case 1: {
      const vs = rng.sample(LITS, rng.range(1, 4));
      vs.forEach((v) => addHint(arg, { kind: "str", value: v }));
      return { in: vs };
    }
    case 2: {
      const sample = rng.pick(SAMPLES);
      addHint(arg, { kind: "str", value: sample });
      return { glob: mutateGlob(rng, sample) };
    }
    case 3: {
      const n = rng.pick([0, 1, 3, 8, 16, 64, 256, 8192]);
      addHint(arg, { kind: "len", n });
      return { max_length: n };
    }
    case 4: {
      const d = rng.pick(DOMAINS);
      addHint(arg, { kind: "host", value: d });
      const acc = rng.sample(["url", "email", "host"], rng.range(1, 3));
      if (rng.chance(0.1)) acc.push(acc[0] as string);
      return { [rng.chance(0.6) ? "domain_suffix" : "domain_exact"]: d, accept: acc };
    }
    default: {
      const root = rng.chance(0.2) ? rng.pick(DRIVE_ROOTS) : rng.pick(ROOTS);
      addHint(arg, { kind: "path", root });
      return { path_within: { root, case_insensitive: rng.chance(0.5) } };
    }
  }
}

function mutateGlob(rng: Rng, sample: string): string {
  const cps = [...sample];
  let stars = 0;
  const out: string[] = [];
  for (let i = 0; i < cps.length; i++) {
    const r = rng.next();
    if (r < 0.12 && stars < 4) {
      stars++;
      out.push("*");
      while (i + 1 < cps.length && rng.chance(0.5)) i++;
    } else if (r < 0.2) out.push("?");
    else out.push(cps[i] as string);
  }
  if (rng.chance(0.3) && stars < 4) out.push("*");
  return out.join("").slice(0, 200);
}

// ---------------------------------------------------------------------------------------------
// Invalid-policy mutations. Each returns {name, input} where input is text or bytes that the
// SPEC says must be rejected. Expectation field "expect" is "reject" unless stated.
export interface PolicyCase {
  name: string;
  expect: "reject" | "accept";
  input: string | Uint8Array;
}

type Mut = (d: Doc, rng: Rng) => PolicyCase | void;

function clone(d: Doc): Doc {
  return JSON.parse(JSON.stringify(d));
}

function firstTool(d: Doc): string | undefined {
  return Object.keys(d.tools)[0];
}

function ruleWith(d: Doc, match: Doc, extra: Doc = {}): Doc {
  d.rules = [...d.rules, { id: "zz.mut", effect: "permit", reason_code: "ok", match, ...extra }];
  return d;
}

const T = (name: string, d: unknown, expect: "reject" | "accept" = "reject"): PolicyCase => ({ name, expect, input: JSON.stringify(d) });

const ADD_TOOL = (d: Doc): void => {
  d.tools["zz_tool"] = {
    risk: "medium", external_effect: false, read_only: true, fail_mode: "closed",
    args: { zs: { type: "string" }, zn: { type: "number" }, zb: { type: "boolean", optional: true }, zl: { type: "string[]" } },
  };
};

const MUTS: Mut[] = [
  (d) => { d.policy_schema_version = "1"; return T("version-string", d); },
  (d, r) => { d.policy_schema_version = r.pick([0, 2, true, null, 1.5]); return T("version-other", d); },
  (d) => { delete d.policy_schema_version; return T("version-missing", d); },
  (d) => { d.extra = 1; return T("unknown-top-key", d); },
  (d) => { d.mode = "audit"; return T("bad-mode", d); },
  (d) => { d.name = "bad name"; return T("bad-name", d); },
  (d) => { d.name = "x".repeat(65); return T("name-65", d); },
  (d) => { const t = firstTool(d); if (!t) return; d.tools[t].zzz = 1; return T("unknown-tool-key", d); },
  (d) => { const t = firstTool(d); if (!t) return; d.tools[t].risk = "critical"; return T("bad-risk", d); },
  (d) => { const t = firstTool(d); if (!t) return; d.tools[t].risk = "high"; d.tools[t].fail_mode = "open_on_audit_failure"; return T("open-on-high", d); },
  (d) => { const t = firstTool(d); if (!t) return; d.tools[t].risk = "low"; d.tools[t].read_only = false; d.tools[t].fail_mode = "open_on_audit_failure"; return T("open-not-readonly", d); },
  (d) => { d.tools["bad:name"] = { risk: "low", external_effect: false, read_only: true, fail_mode: "closed", args: {} }; return T("tool-name-colon", d); },
  (d) => { const t = firstTool(d); if (!t) return; d.tools[t].args["bad:arg"] = { type: "string" }; return T("arg-name-colon", d); },
  (d) => { const t = firstTool(d); if (!t) return; d.tools[t].args["zq"] = { type: "int" }; return T("bad-arg-type", d); },
  (d) => { const t = firstTool(d); if (!t) return; d.tools[t].args["zq"] = { type: "string", optional: 1 }; return T("optional-nonbool", d); },
  (d) => { const t = firstTool(d); if (!t) return; d.tools[t].args["zq"] = { type: "string", extra: 1 }; return T("unknown-arg-key", d); },
  (d) => { if (d.rules.length === 0) return; d.rules.push({ ...d.rules[0] }); return T("dup-rule-id", d); },
  (d) => { if (d.rules.length === 0) return; d.rules[0].priority = 1; return T("unknown-rule-key", d); },
  (d) => { if (d.rules.length === 0) return; d.rules[0].effect = "audit"; return T("bad-effect", d); },
  (d) => { if (d.rules.length === 0) return; d.rules[0].reason_code = "has space"; return T("bad-reason", d); },
  (d) => { if (d.rules.length === 0) return; d.rules[0].id = ""; return T("empty-id", d); },
  (d) => { if (d.rules.length === 0) return; d.rules[0].match = {}; return T("empty-match", d); },
  (d) => { const t = firstTool(d); if (!t) return; return T("empty-tools-list", ruleWith(d, { tools: [] })); },
  (d) => T("empty-agents", ruleWith(d, { agents: [] })),
  (d) => T("empty-scopes", ruleWith(d, { scopes_any: [] })),
  (d) => T("unknown-tool-in-match", ruleWith(d, { tools: ["no_such_tool"] })),
  (d) => T("unknown-match-key", ruleWith(d, { foo: 1 })),
  (d) => T("tainted-nonbool", ruleWith(d, { session_tainted: "yes" })),
  (d) => T("agent-charset", ruleWith(d, { agents: ["bad agent"] })),
  (d) => T("list-257", ruleWith(d, { scopes_any: Array.from({ length: 257 }, (_, i) => `s${i}`) })),
  (d) => T("list-256-ok", ruleWith(d, { scopes_any: Array.from({ length: 256 }, (_, i) => `s${i}`) }), "accept"),
  (d) => T("empty-args-obj", ruleWith(d, { args: {} })),
  (d) => T("empty-prov-obj", ruleWith(d, { provenance: {} })),
  (d) => { ADD_TOOL(d); return T("range-on-string", ruleWith(d, { tools: ["zz_tool"], args: { zs: { range: { min: 1 } } } })); },
  (d) => { ADD_TOOL(d); return T("glob-on-number", ruleWith(d, { tools: ["zz_tool"], args: { zn: { glob: "a" } } })); },
  (d) => { ADD_TOOL(d); return T("maxlen-on-bool", ruleWith(d, { tools: ["zz_tool"], args: { zb: { max_length: 3 } } })); },
  (d) => { ADD_TOOL(d); return T("equals-type", ruleWith(d, { tools: ["zz_tool"], args: { zn: { equals: "1" } } })); },
  (d) => { ADD_TOOL(d); return T("equals-null", ruleWith(d, { tools: ["zz_tool"], args: { zs: { equals: null } } })); },
  (d) => { ADD_TOOL(d); return T("equals-array", ruleWith(d, { tools: ["zz_tool"], args: { zl: { equals: ["a"] } } })); },
  (d) => { ADD_TOOL(d); return T("in-empty", ruleWith(d, { tools: ["zz_tool"], args: { zs: { in: [] } } })); },
  (d) => { ADD_TOOL(d); return T("in-mixed", ruleWith(d, { tools: ["zz_tool"], args: { zs: { in: ["a", 1] } } })); },
  (d) => { ADD_TOOL(d); return T("in-257", ruleWith(d, { tools: ["zz_tool"], args: { zs: { in: Array.from({ length: 257 }, (_, i) => `v${i}`) } } })); },
  (d) => { ADD_TOOL(d); return T("range-minmax", ruleWith(d, { tools: ["zz_tool"], args: { zn: { range: { min: 5, max: 1 } } } })); },
  (d) => { ADD_TOOL(d); return T("range-empty", ruleWith(d, { tools: ["zz_tool"], args: { zn: { range: {} } } })); },
  (d) => { ADD_TOOL(d); return T("range-string-bound", ruleWith(d, { tools: ["zz_tool"], args: { zn: { range: { min: "1" } } } })); },
  (d) => { ADD_TOOL(d); return T("range-unknown-key", ruleWith(d, { tools: ["zz_tool"], args: { zn: { range: { min: 1, step: 1 } } } })); },
  (d, r) => { ADD_TOOL(d); return T("maxlen-bad", ruleWith(d, { tools: ["zz_tool"], args: { zs: { max_length: r.pick([-1, 1.5, "3", null]) } } })); },
  (d) => { ADD_TOOL(d); return T("glob-5-stars", ruleWith(d, { tools: ["zz_tool"], args: { zs: { glob: "*a*b*c*d*" } } })); },
  (d) => { ADD_TOOL(d); return T("glob-4-stars-ok", ruleWith(d, { tools: ["zz_tool"], args: { zs: { glob: "*a*b*c*d" } } }), "accept"); },
  (d) => { ADD_TOOL(d); return T("glob-257", ruleWith(d, { tools: ["zz_tool"], args: { zs: { glob: "x".repeat(257) } } })); },
  (d) => { ADD_TOOL(d); return T("glob-256-ok", ruleWith(d, { tools: ["zz_tool"], args: { zs: { glob: "x".repeat(256) } } }), "accept"); },
  (d) => { ADD_TOOL(d); return T("glob-accept", ruleWith(d, { tools: ["zz_tool"], args: { zs: { glob: "x", accept: ["url"] } } })); },
  (d) => { ADD_TOOL(d); return T("two-ops", ruleWith(d, { tools: ["zz_tool"], args: { zs: { glob: "x", equals: "x" } } })); },
  (d) => { ADD_TOOL(d); return T("zero-ops", ruleWith(d, { tools: ["zz_tool"], args: { zs: {} } })); },
  (d) => { ADD_TOOL(d); return T("pred-nonobject", ruleWith(d, { tools: ["zz_tool"], args: { zs: "x" } })); },
  (d) => { ADD_TOOL(d); return T("domain-no-accept", ruleWith(d, { tools: ["zz_tool"], args: { zs: { domain_suffix: "a.com" } } })); },
  (d) => { ADD_TOOL(d); return T("domain-empty-accept", ruleWith(d, { tools: ["zz_tool"], args: { zs: { domain_exact: "a.com", accept: [] } } })); },
  (d) => { ADD_TOOL(d); return T("domain-bad-accept", ruleWith(d, { tools: ["zz_tool"], args: { zs: { domain_exact: "a.com", accept: ["mailto"] } } })); },
  (d, r) => { ADD_TOOL(d); return T("domain-bad-value", ruleWith(d, { tools: ["zz_tool"], args: { zs: { domain_suffix: r.pick(["A.com", "a.com.", "*.a.com", "1.2.3.4", "a_b.com", "-a.com", "a..com", "", "a.com/x", "[::1]", "caf\u00e9.com", "a b.com", "a.123", "x".repeat(64) + ".com"]), accept: ["host"] } } })); },
  (d) => { ADD_TOOL(d); return T("domain-two-ops", ruleWith(d, { tools: ["zz_tool"], args: { zs: { domain_exact: "a.com", domain_suffix: "a.com", accept: ["host"] } } })); },
  (d) => { ADD_TOOL(d); return T("domain-on-number", ruleWith(d, { tools: ["zz_tool"], args: { zn: { domain_suffix: "a.com", accept: ["host"] } } })); },
  (d) => { ADD_TOOL(d); return T("domain-dup-accept-ok", ruleWith(d, { tools: ["zz_tool"], args: { zs: { domain_suffix: "a.com", accept: ["host", "host", "url"] } } }), "accept"); },
  (d) => { ADD_TOOL(d); return T("domain-on-strarr-ok", ruleWith(d, { tools: ["zz_tool"], args: { zl: { domain_suffix: "a.com", accept: ["host"] } } }), "accept"); },
  (d) => { ADD_TOOL(d); return T("pw-no-ci", ruleWith(d, { tools: ["zz_tool"], args: { zs: { path_within: { root: "/w" } } } })); },
  (d) => { ADD_TOOL(d); return T("pw-ci-nonbool", ruleWith(d, { tools: ["zz_tool"], args: { zs: { path_within: { root: "/w", case_insensitive: 0 } } } })); },
  (d) => { ADD_TOOL(d); return T("pw-no-root", ruleWith(d, { tools: ["zz_tool"], args: { zs: { path_within: { case_insensitive: true } } } })); },
  (d) => { ADD_TOOL(d); return T("pw-extra-key", ruleWith(d, { tools: ["zz_tool"], args: { zs: { path_within: { root: "/w", case_insensitive: true, x: 1 } } } })); },
  (d, r) => { ADD_TOOL(d); return T("pw-bad-root", ruleWith(d, { tools: ["zz_tool"], args: { zs: { path_within: { root: r.pick(["w", "/w/", "/w/../x", "/w//x", "/w/./x", "/w/..", "", "./w", "/w\u00e9", "/\u00e9", "\\w", "/w\\x"]), case_insensitive: false } } } })); },
  (d) => { ADD_TOOL(d); return T("pw-on-number", ruleWith(d, { tools: ["zz_tool"], args: { zn: { path_within: { root: "/w", case_insensitive: false } } } })); },
  (d) => { ADD_TOOL(d); return T("pw-on-strarr-ok", ruleWith(d, { tools: ["zz_tool"], args: { zl: { path_within: { root: "/w", case_insensitive: false } } } }), "accept"); },
  (d) => T("arg-undeclared", ruleWith(d, { args: { nosucharg: { equals: "x" } } })),
  (d) => { ADD_TOOL(d); return T("arg-not-on-all-tools", ruleWith(d, { tools: ["zz_tool", firstTool(d) as string], args: { zs: { equals: "x" } } })); },
  (d) => {
    ADD_TOOL(d);
    d.tools["zz_tool2"] = { risk: "low", external_effect: false, read_only: true, fail_mode: "closed", args: { zs: { type: "number" } } };
    return T("arg-type-conflict-no-tools", ruleWith(d, { args: { zs: { equals: "x" } } }));
  },
  (d) => {
    ADD_TOOL(d);
    d.tools["zz_tool2"] = { risk: "low", external_effect: false, read_only: true, fail_mode: "closed", args: { zs: { type: "string[]" } } };
    return T("arg-string-vs-strarr-compatible-ok", ruleWith(d, { args: { zs: { equals: "x" } } }), "accept");
  },
  (d) => { ADD_TOOL(d); return T("prov-undeclared", ruleWith(d, { tools: ["zz_tool"], provenance: { nope: { all_in: ["x"] } } })); },
  (d) => { ADD_TOOL(d); return T("prov-entry-empty", ruleWith(d, { tools: ["zz_tool"], provenance: { zs: {} } })); },
  (d) => { ADD_TOOL(d); return T("prov-all-empty", ruleWith(d, { tools: ["zz_tool"], provenance: { zs: { all_in: [] } } })); },
  (d) => { ADD_TOOL(d); return T("prov-label-bad", ruleWith(d, { tools: ["zz_tool"], provenance: { zs: { any_in: ["bad label"] } } })); },
  (d) => { ADD_TOOL(d); return T("prov-unknown-key", ruleWith(d, { tools: ["zz_tool"], provenance: { zs: { all_in: ["a"], zzz: ["b"] } } })); },
  (d) => { ADD_TOOL(d); return T("prov-both-ok", ruleWith(d, { tools: ["zz_tool"], provenance: { zs: { all_in: ["a:b"], any_in: ["a:b"] } } }), "accept"); },
  (d, r) => { d.name = "n" + r.pick(["\u200b", "\u200d", "\u2060", "\ufeff", "\u202e", "\u2066", "\u00ad", "\u034f", "\u061c", "\u180e", "\u2028", "\u2029", "\ufe0f", "\u{e0001}", "\u0007", "\u007f", "\u0085", "\u00a0", "\u3000", "\u2003", "\ue000", "\ufdd0", "\u0378"]); return T("name-forbidden-char", d); },
  (d, r) => { const t = firstTool(d); if (!t) return; d.tools[t].schema_hash = "a" + r.pick(["\u200b", "\u202e", "\u0000", "\u2028", "\u00a0", "\u3000", "\ue000", "\u0085", "\u00ad"]) + "b"; return T("schema-hash-forbidden", d); },
  (d) => { ADD_TOOL(d); return T("literal-forbidden-char", ruleWith(d, { tools: ["zz_tool"], args: { zs: { equals: "a\u200bb" } } })); },
  (d) => { ADD_TOOL(d); return T("literal-ok-unicode", ruleWith(d, { tools: ["zz_tool"], args: { zs: { equals: "caf\u00e9 \u4e2d\u6587 \u{1f600}" } } }), "accept"); },
  (d) => { const t = firstTool(d); if (!t) return; d.tools[t].schema_hash = 5; return T("schema-hash-nonstring", d); },
  (d) => { d.rules = Array.from({ length: 1001 }, (_, i) => ({ id: `r${i}`, effect: "permit", reason_code: "ok", match: { session_tainted: true } })); return T("rules-1001", d); },
  (d) => { d.rules = Array.from({ length: 1000 }, (_, i) => ({ id: `r${i}`, effect: "permit", reason_code: "ok", match: { session_tainted: true } })); return T("rules-1000-ok", d, "accept"); },
  (d) => { d.rules = []; d.tools = {}; return T("empty-ok", d, "accept"); },
  (d) => ({ name: "version-1.0-ok", expect: "accept", input: JSON.stringify(d).replace('"policy_schema_version":1', '"policy_schema_version":1.0') }),
  (d) => ({ name: "version-1e0-ok", expect: "accept", input: JSON.stringify(d).replace('"policy_schema_version":1', '"policy_schema_version":1e0') }),
  (d) => ({ name: "bom-string", expect: "reject", input: "\ufeff" + JSON.stringify(d) }),
  (d) => ({ name: "bom-bytes", expect: "reject", input: new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode(JSON.stringify(d))]) }),
  (d) => ({ name: "bytes-ok", expect: "accept", input: new TextEncoder().encode(JSON.stringify(d)) }),
  (d) => ({ name: "invalid-utf8", expect: "reject", input: new Uint8Array([...new TextEncoder().encode('{"name":"'), 0xff, 0xfe, ...new TextEncoder().encode('"}')]) }),
  (d) => ({ name: "dup-key", expect: "reject", input: JSON.stringify(d).replace('"mode":', '"name":"dup","mode":') }),
  (d, r) => ({ name: "forbidden-key", expect: "reject", input: JSON.stringify(d).replace('"mode":', `"${r.pick(["__proto__", "constructor", "prototype"])}":{},"mode":`) }),
  (d) => ({ name: "forbidden-key-nested", expect: "reject", input: JSON.stringify(d).replace('"tools":{', '"tools":{"__proto__":{},') }),
  (d) => ({ name: "trailing-comma", expect: "reject", input: JSON.stringify(d).replace(/}$/, ",}") }),
  (d) => ({ name: "comment", expect: "reject", input: "/*x*/" + JSON.stringify(d) }),
  (d) => ({ name: "pretty-ok", expect: "accept", input: JSON.stringify(d, null, 2) + "\n" }),
  () => ({ name: "not-json", expect: "reject", input: "policy" }),
  () => ({ name: "array-root", expect: "reject", input: "[]" }),
  (d) => ({ name: "too-large", expect: "reject", input: JSON.stringify({ ...d, pad: "x".repeat(1024 * 1024) }) }),
  (d) => {
    // depth > 8 inside an unknown key is still an unknown key; use a legal-looking deep structure instead
    let deep: unknown = 1;
    for (let i = 0; i < 12; i++) deep = [deep];
    return T("deep-unknown", { ...d, zz: deep });
  },
  (d) => ({ name: "lone-surrogate-escape", expect: "reject", input: JSON.stringify(d).replace('"name":"', '"name":"\\ud800') }),
  (d) => T("nonascii-root-fullwidth", ruleWith(ADDED(d), { tools: ["zz_tool"], args: { zs: { path_within: { root: "/\uff57", case_insensitive: false } } } })),
  (d) => T("drive-root-ok", ruleWith(ADDED(d), { tools: ["zz_tool"], args: { zs: { path_within: { root: "C:/work", case_insensitive: false } } } }), "accept"),
  (d, r) => T("drive-root-bad", ruleWith(ADDED(d), { tools: ["zz_tool"], args: { zs: { path_within: { root: r.pick(["c:/work", "C:", "C:/a/../b", "C:/a//b", "C:/a/", "CC:/a", "C:\work"]), case_insensitive: false } } } })),
  (d) => T("missing-mode", (() => { const c = clone(d); delete c.mode; return c; })()),
  (d) => T("missing-name", (() => { const c = clone(d); delete c.name; return c; })()),
  (d) => T("missing-rules", (() => { const c = clone(d); delete c.rules; return c; })()),
  (d) => T("missing-tools", (() => { const c = clone(d); delete c.tools; return c; })()),
  (d) => T("rule-missing-reason", ((): Doc => { const c = clone(d); if (c.rules.length) delete c.rules[0].reason_code; else c.rules.push({ id: "q", effect: "permit", match: { session_tainted: true } }); return c; })()),
  (d) => { ADD_TOOL(d); return T("equals-number-ok", ruleWith(d, { tools: ["zz_tool"], args: { zn: { equals: 1 } } }), "accept"); },
  (d) => { ADD_TOOL(d); const s = JSON.stringify(ruleWith(d, { tools: ["zz_tool"], args: { zn: { equals: 12345 } } })).replace("12345", "1e999"); return { name: "number-1e999", expect: "reject", input: s } as PolicyCase; },
  (d) => { ADD_TOOL(d); return T("tools-clause-on-optional-ok", ruleWith(d, { tools: ["zz_tool"], args: { zb: { equals: true } } }), "accept"); },
  (d) => { ADD_TOOL(d); return T("range-min-only-ok", ruleWith(d, { tools: ["zz_tool"], args: { zn: { range: { min: 0 } } } }), "accept"); },
];

function ADDED(d: Doc): Doc {
  ADD_TOOL(d);
  return d;
}

export function genPolicyCase(rng: Rng, base: GenPolicy): PolicyCase {
  const d = clone(base.doc);
  for (let tries = 0; tries < 8; tries++) {
    const m = rng.pick(MUTS);
    const r = m(d, rng);
    if (r) return r;
  }
  return { name: "unmutated", expect: "accept", input: base.text };
}

export const MUTATION_COUNT = MUTS.length;
