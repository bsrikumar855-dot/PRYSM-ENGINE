// Independent policy loader + validator, written from POLICY-SPEC.md §1, §2, §9, §10, §11 only.

import { parseStrictJson, type JsonValue } from "./json.ts";
import { codePoints } from "./matchers.ts";

export type ArgType = "string" | "number" | "boolean" | "string[]";
export type Literal = string | number | boolean;

export interface RefArg {
  type: ArgType;
  optional: boolean;
}
export interface RefTool {
  name: string;
  risk: string;
  external_effect: boolean;
  read_only: boolean;
  fail_mode: string;
  args: Map<string, RefArg>;
}

export type Pred =
  | { kind: "equals"; value: Literal }
  | { kind: "in"; values: Literal[] }
  | { kind: "glob"; pattern: number[] }
  | { kind: "range"; min: number | undefined; max: number | undefined }
  | { kind: "max_length"; n: number }
  | { kind: "domain"; mode: "suffix" | "exact"; value: string; accept: Set<string> }
  | { kind: "path_within"; root: string; ci: boolean };

export interface RefRule {
  id: string;
  effect: "permit" | "deny";
  reason_code: string;
  agents?: string[];
  scopes_any?: string[];
  tools?: string[];
  args?: Array<[string, Pred]>;
  provenance?: Array<[string, { all_in?: string[]; any_in?: string[] }]>;
  session_tainted?: boolean;
}

export interface RefPolicy {
  readonly refPolicy: true;
  name: string;
  mode: "enforce" | "monitor_only";
  tools: Map<string, RefTool>;
  rules: RefRule[];
}

export class RefPolicyError extends Error {
  readonly path: string;
  constructor(path: string, message: string) {
    super(`${path}: ${message}`);
    this.name = "RefPolicyError";
    this.path = path;
  }
}

const fail = (path: string, msg: string): never => {
  throw new RefPolicyError(path, msg);
};

const ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/; // tool / arg names: no ':'
const MAX_LIST = 256;
const FORBIDDEN_RE = /[\p{Cf}\p{Zl}\p{Zp}\p{Cc}\p{Co}\p{Cn}\p{Cs}]/u;

function hasForbidden(s: string): boolean {
  if (FORBIDDEN_RE.test(s)) return true;
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number;
    if (ch !== " " && /\p{Zs}/u.test(ch)) return true;
    // §10.7 enumerated list members not covered by the categories above (union, deny-safe)
    if (cp === 0x34f || (cp >= 0xfe00 && cp <= 0xfe0f)) return true;
  }
  return false;
}

type Obj = { [k: string]: JsonValue };
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

function scanStrings(v: JsonValue, path: string): void {
  if (typeof v === "string") {
    if (hasForbidden(v)) fail(path, "forbidden character in string");
  } else if (Array.isArray(v)) {
    v.forEach((x, i) => scanStrings(x, `${path}[${i}]`));
  } else if (isObj(v)) {
    for (const k of Object.keys(v)) {
      if (hasForbidden(k)) fail(path, "forbidden character in key");
      scanStrings(v[k] as JsonValue, `${path}.${k.length <= 40 ? k : "…"}`);
    }
  }
}

function expectObj(v: unknown, path: string, allowed: string[], required: string[]): Obj {
  if (!isObj(v)) return fail(path, "expected object");
  for (const k of Object.keys(v)) if (!allowed.includes(k)) fail(path, "unknown key");
  for (const k of required) if (!(k in v)) fail(path, `missing key ${k}`);
  return v;
}

function expectBool(v: unknown, path: string): boolean {
  if (typeof v !== "boolean") return fail(path, "expected boolean");
  return v;
}

function expectStrList(v: unknown, path: string, re: RegExp | null, nonEmpty: boolean): string[] {
  if (!Array.isArray(v)) return fail(path, "expected array");
  if (v.length > MAX_LIST) fail(path, "list too long");
  if (nonEmpty && v.length === 0) fail(path, "empty list");
  for (const x of v) {
    if (typeof x !== "string") fail(path, "expected string element");
    if (re && !re.test(x as string)) fail(path, "bad identifier");
  }
  return v as string[];
}

function validHostValue(v: string): boolean {
  if (v.length === 0 || v.length > 253) return false;
  const labels = v.split(".");
  for (const l of labels) {
    if (l.length === 0 || l.length > 63) return false;
    if (!/^[a-z0-9-]+$/.test(l)) return false;
    if (l.startsWith("-") || l.endsWith("-")) return false;
  }
  if (/^[0-9]+$/.test(labels[labels.length - 1] as string)) return false; // IP-like
  return true;
}

function validRoot(r: string): boolean {
  if (!/^[\x20-\x7e]*$/.test(r)) return false; // ASCII only (printable; control chars rejected earlier)
  if (r.includes("\\")) return false;
  if (/^[A-Z]:\//.test(r)) {
    const rest = r.slice(3);
    if (rest === "") return false;
    return rest.split("/").every((seg) => seg !== "" && seg !== "." && seg !== "..");
  }
  if (!r.startsWith("/")) return false; // drive-prefixed roots rejected by default (deny-safe, see report)
  if (r === "/") return true;
  if (r.endsWith("/")) return false;
  for (const seg of r.slice(1).split("/")) {
    if (seg === "" || seg === "." || seg === "..") return false;
  }
  return true;
}

const OPS = ["equals", "in", "glob", "range", "max_length", "domain_suffix", "domain_exact", "path_within"];

function parsePredicate(raw: unknown, path: string): Pred {
  if (!isObj(raw)) return fail(path, "predicate must be an object");
  const keys = Object.keys(raw);
  const ops = keys.filter((k) => OPS.includes(k));
  for (const k of keys) if (!OPS.includes(k) && k !== "accept") fail(path, "unknown predicate key");
  if (ops.length !== 1) return fail(path, "predicate needs exactly one operator");
  const op = ops[0] as string;
  const isDomain = op === "domain_suffix" || op === "domain_exact";
  if (!isDomain && "accept" in raw) fail(path, "accept only valid on domain predicates");
  if (isDomain && !("accept" in raw)) fail(path, "accept required");
  switch (op) {
    case "equals": {
      const v = raw.equals;
      if (typeof v !== "string" && typeof v !== "number" && typeof v !== "boolean") return fail(path, "bad equals literal");
      if (typeof v === "number" && !Number.isFinite(v)) fail(path, "non-finite");
      return { kind: "equals", value: typeof v === "string" ? v.normalize("NFC") : Object.is(v, -0) ? 0 : v };
    }
    case "in": {
      const v = raw.in;
      if (!Array.isArray(v)) return fail(path, "in must be array");
      if (v.length === 0 || v.length > MAX_LIST) return fail(path, "bad in list size");
      const vals: Literal[] = v.map((x) => {
        if (typeof x !== "string" && typeof x !== "number" && typeof x !== "boolean") return fail(path, "bad in literal");
        if (typeof x === "number" && !Number.isFinite(x)) fail(path, "non-finite");
        return typeof x === "string" ? x.normalize("NFC") : Object.is(x, -0) ? 0 : x;
      });
      return { kind: "in", values: vals };
    }
    case "glob": {
      const p = raw.glob;
      if (typeof p !== "string") return fail(path, "glob must be string");
      if (p.length > 256) fail(path, "glob too long");
      const nfc = p.normalize("NFC");
      if (nfc.length > 256) fail(path, "glob too long");
      let stars = 0;
      for (const ch of nfc) if (ch === "*") stars++;
      if (stars > 4) fail(path, "too many stars");
      return { kind: "glob", pattern: codePoints(nfc) };
    }
    case "range": {
      const r = expectObj(raw.range, path, ["min", "max"], []);
      const min = r.min;
      const max = r.max;
      if (min === undefined && max === undefined) fail(path, "empty range");
      for (const b of [min, max]) {
        if (b !== undefined && (typeof b !== "number" || !Number.isFinite(b))) fail(path, "bad bound");
      }
      if (min !== undefined && max !== undefined && (min as number) > (max as number)) fail(path, "min > max");
      return {
        kind: "range",
        min: min === undefined ? undefined : (min as number),
        max: max === undefined ? undefined : (max as number),
      };
    }
    case "max_length": {
      const n = raw.max_length;
      if (typeof n !== "number" || !Number.isInteger(n) || n < 0) return fail(path, "bad max_length");
      return { kind: "max_length", n };
    }
    case "domain_suffix":
    case "domain_exact": {
      const val = raw[op];
      if (typeof val !== "string" || !validHostValue(val)) return fail(path, "bad domain value");
      const acc = raw.accept;
      if (!Array.isArray(acc)) return fail(path, "accept must be array");
      const set = new Set<string>();
      for (const a of acc) {
        if (a !== "url" && a !== "email" && a !== "host") return fail(path, "bad accept entry");
        set.add(a);
      }
      if (set.size === 0) fail(path, "accept empty");
      if (set.size > MAX_LIST) fail(path, "accept too long");
      return { kind: "domain", mode: op === "domain_suffix" ? "suffix" : "exact", value: val, accept: set };
    }
    default: {
      const pw = expectObj(raw.path_within, path, ["root", "case_insensitive"], ["root", "case_insensitive"]);
      if (typeof pw.root !== "string" || !validRoot(pw.root)) return fail(path, "bad root");
      const ci = expectBool(pw.case_insensitive, path);
      return { kind: "path_within", root: pw.root, ci };
    }
  }
}

function predCompat(p: Pred, t: ArgType, path: string): void {
  const base = t === "string[]" ? "string" : t;
  switch (p.kind) {
    case "equals":
      if (typeof p.value !== base) fail(path, "equals type mismatch");
      break;
    case "in":
      for (const v of p.values) if (typeof v !== base) fail(path, "in type mismatch");
      break;
    case "range":
      if (base !== "number") fail(path, "range needs number arg");
      break;
    default:
      if (base !== "string") fail(path, "predicate needs string arg");
  }
}

function toArgType(v: unknown, path: string): ArgType {
  if (v === "string" || v === "number" || v === "boolean" || v === "string[]") return v;
  return fail(path, "bad arg type");
}


export function refLoadPolicy(input: Uint8Array | string): RefPolicy {
  let text: string;
  if (typeof input === "string") {
    if (Buffer.byteLength(input, "utf8") > 1024 * 1024) fail("$", "file too large");
    text = input;
  } else {
    if (input.length > 1024 * 1024) fail("$", "file too large");
    if (input.length >= 3 && input[0] === 0xef && input[1] === 0xbb && input[2] === 0xbf) fail("$", "BOM");
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(input);
    } catch {
      return fail("$", "invalid UTF-8");
    }
  }
  if (text.charCodeAt(0) === 0xfeff) fail("$", "BOM");
  let doc: JsonValue;
  try {
    doc = parseStrictJson(text);
  } catch (e) {
    return fail("$", "json: " + (e instanceof Error ? e.message : "error"));
  }
  scanStrings(doc, "$");

  const top = expectObj(doc, "$", ["policy_schema_version", "name", "mode", "tools", "rules"],
    ["policy_schema_version", "name", "mode", "tools", "rules"]);
  if (top.policy_schema_version !== 1) fail("$.policy_schema_version", "must be 1");
  if (typeof top.name !== "string" || !ID_RE.test(top.name)) fail("$.name", "bad name");
  if (top.mode !== "enforce" && top.mode !== "monitor_only") fail("$.mode", "bad mode");

  // tools
  const toolsRaw = expectObj(top.tools, "$.tools", Object.keys(isObj(top.tools) ? top.tools : {}), []);
  const tools = new Map<string, RefTool>();
  for (const tname of Object.keys(toolsRaw)) {
    const p = `$.tools.${tname.length <= 40 ? tname : "…"}`;
    if (!NAME_RE.test(tname)) fail(p, "bad tool name");
    const t = expectObj(toolsRaw[tname], p, ["risk", "external_effect", "read_only", "fail_mode", "args", "schema_hash"],
      ["risk", "external_effect", "read_only", "fail_mode", "args"]);
    if (t.risk !== "low" && t.risk !== "medium" && t.risk !== "high") fail(p, "bad risk");
    const ee = expectBool(t.external_effect, p);
    const ro = expectBool(t.read_only, p);
    if (t.fail_mode !== "closed" && t.fail_mode !== "open_on_audit_failure") fail(p, "bad fail_mode");
    if (t.fail_mode === "open_on_audit_failure" && !(t.risk === "low" && ro === true)) fail(p, "fail_mode illegal");
    if ("schema_hash" in t && typeof t.schema_hash !== "string") fail(p, "bad schema_hash");
    const argsRaw = expectObj(t.args, p + ".args", Object.keys(isObj(t.args) ? t.args : {}), []);
    const args = new Map<string, RefArg>();
    for (const an of Object.keys(argsRaw)) {
      if (!NAME_RE.test(an)) fail(p + ".args", "bad arg name");
      const a = expectObj(argsRaw[an], p + ".args", ["type", "optional"], ["type"]);
      const type = toArgType(a.type, p + ".args");
      let optional = false;
      if ("optional" in a) optional = expectBool(a.optional, p + ".args");
      args.set(an, { type, optional });
    }
    tools.set(tname, {
      name: tname,
      risk: t.risk as string,
      external_effect: ee,
      read_only: ro,
      fail_mode: t.fail_mode as string,
      args,
    });
  }

  // rules
  if (!Array.isArray(top.rules)) fail("$.rules", "expected array");
  const rulesRaw = top.rules as JsonValue[];
  if (rulesRaw.length > 1000) fail("$.rules", "too many rules");
  const ids = new Set<string>();
  const rules: RefRule[] = [];
  rulesRaw.forEach((rr, idx) => {
    const p = `$.rules[${idx}]`;
    const r = expectObj(rr, p, ["id", "effect", "reason_code", "match"], ["id", "effect", "reason_code", "match"]);
    if (typeof r.id !== "string" || !ID_RE.test(r.id)) fail(p, "bad id");
    if (ids.has(r.id as string)) fail(p, "duplicate id");
    ids.add(r.id as string);
    if (r.effect !== "permit" && r.effect !== "deny") fail(p, "bad effect");
    if (typeof r.reason_code !== "string" || !ID_RE.test(r.reason_code)) fail(p, "bad reason_code");
    const m = expectObj(r.match, p + ".match",
      ["agents", "scopes_any", "tools", "args", "provenance", "session_tainted"], []);
    if (Object.keys(m).length === 0) fail(p + ".match", "empty match");
    const rule: RefRule = { id: r.id as string, effect: r.effect as "permit" | "deny", reason_code: r.reason_code as string };
    if ("agents" in m) rule.agents = expectStrList(m.agents, p + ".match.agents", ID_RE, true);
    if ("scopes_any" in m) rule.scopes_any = expectStrList(m.scopes_any, p + ".match.scopes_any", ID_RE, true);
    if ("tools" in m) {
      rule.tools = expectStrList(m.tools, p + ".match.tools", NAME_RE, true);
      for (const tn of rule.tools) if (!tools.has(tn)) fail(p + ".match.tools", "unknown tool");
    }
    if ("session_tainted" in m) rule.session_tainted = expectBool(m.session_tainted, p + ".match.session_tainted");

    // declared-ness (shared by args and provenance) and type resolution
    const declaringTools = (argName: string): RefTool[] => {
      if (rule.tools) {
        const ts = rule.tools.map((tn) => tools.get(tn) as RefTool);
        for (const t of ts) if (!t.args.has(argName)) fail(p + ".match", "arg not declared for every tool");
        return ts;
      }
      const ts = [...tools.values()].filter((t) => t.args.has(argName));
      if (ts.length === 0) fail(p + ".match", "arg not declared");
      return ts;
    };

    if ("args" in m) {
      const am = expectObj(m.args, p + ".match.args", Object.keys(isObj(m.args) ? m.args : {}), []);
      const names = Object.keys(am);
      if (names.length === 0) fail(p + ".match.args", "empty args");
      rule.args = [];
      for (const an of names) {
        const ts = declaringTools(an);
        const pred = parsePredicate(am[an], `${p}.match.args.${an.length <= 40 ? an : "…"}`);
        const types = new Set(ts.map((t) => (t.args.get(an) as RefArg).type));
        for (const ty of types) predCompat(pred, ty, p + ".match.args");
        rule.args.push([an, pred]);
      }
    }
    if ("provenance" in m) {
      const pm = expectObj(m.provenance, p + ".match.provenance", Object.keys(isObj(m.provenance) ? m.provenance : {}), []);
      const names = Object.keys(pm);
      if (names.length === 0) fail(p + ".match.provenance", "empty provenance");
      rule.provenance = [];
      for (const an of names) {
        declaringTools(an);
        const pe = expectObj(pm[an], p + ".match.provenance", ["all_in", "any_in"], []);
        if (!("all_in" in pe) && !("any_in" in pe)) fail(p + ".match.provenance", "needs all_in or any_in");
        const entry: { all_in?: string[]; any_in?: string[] } = {};
        if ("all_in" in pe) entry.all_in = expectStrList(pe.all_in, p + ".match.provenance", ID_RE, true);
        if ("any_in" in pe) entry.any_in = expectStrList(pe.any_in, p + ".match.provenance", ID_RE, true);
        rule.provenance.push([an, entry]);
      }
    }
    rules.push(rule);
  });

  return { refPolicy: true, name: top.name as string, mode: top.mode as "enforce" | "monitor_only", tools, rules };
}

