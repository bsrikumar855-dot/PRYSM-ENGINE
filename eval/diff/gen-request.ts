// Random request generator biased to interesting boundaries. Produces raw JS values (some hostile).
import type { GenPolicy, GenTool, Hint, ArgType } from "./gen-policy.ts";
import type { Rng } from "./prng.ts";

export interface GenCase {
  family: string;
  request: unknown;
}
type Rec = Record<string, unknown>;

const UNICODE_BITS = [
  "e\u0301", "\u00e9", "\uff41\uff42", "\u0430", "\u212a", "\u202e", "\u200b", "\ufeff", "\ud800", "\udc00", "\u{1f600}",
  "\u0000", "\t", "\n", "\u00a0", "\u00ad", "\u0301", "\u0130", "\u00df", "\u03c3\u03c2", "\u2066", "\u200d", "\u3002", "\uff0e",
  "\u0131", "\ufb01", "\u1e9e",
];
const WORDS = ["alpha", "Beta", "gamma-3", "x", "", "hello world", "a.b", "ID-7", "0", "true"];
const NUM_EDGES = [-0, 0, 1, -1, 1e308, -1e308, 5e-324, -5e-324, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0.1 + 0.2, 1e21, 1e-7, 0.5, 10, 5, 100, 255, 9007199254740993, 1.7976931348623157e308];
const WRONG_VALUES: unknown[] = [5, "5", true, false, null, [], {}, ["a"], [1], [null], "", 0, -1.5];

function pathTrick(rng: Rng, s: string): string {
  const base = s.startsWith("/") || /^[A-Za-z]:\//.test(s) ? s : "/" + s;
  const tricks: Array<() => string> = [
    () => base.replace(/\//g, "\\"),
    () => "\\\\srv\\share" + base,
    () => "\\\\?\\C:" + base,
    () => "//" + base.slice(1),
    () => base + "/..",
    () => base + "/../x",
    () => "/.." + base,
    () => base.replace("/", "/%2e%2e/"),
    () => base + "%2F",
    () => base + "%2f..%2f",
    () => base + "%zz",
    () => base + "%4",
    () => "C:" + base,
    () => "c:\\" + base.slice(1).replace(/\//g, "\\"),
    () => base + "/CON",
    () => base + "/aux.txt",
    () => base + "/NUL.",
    () => base + "/nul.txt.bak",
    () => base + "/CONIN$",
    () => base + "/com1",
    () => base + "/com10",
    () => base + "/console",
    () => base + "/PROGRA~1",
    () => base + "/abc~1.txt",
    () => base + "/abcdefghi~1",
    () => base + "/x.",
    () => base + "/x ",
    () => base + "/ x",
    () => base + "/...",
    () => base + "/x:y",
    () => base + "/x?y",
    () => base + "/*",
    () => base + '/"q"',
    () => base + "/a<b",
    () => base + "/a|b",
    () => base.toUpperCase(),
    () => base.toLowerCase(),
    () => base + "/",
    () => base + "//x",
    () => base + "/./x/./y",
    () => base + "\u0000",
    () => base + "\n",
    () => base.slice(1),
    () => "",
    () => "/",
    () => ".",
    () => "..",
    () => base + "/x/y/../../z",
    () => base + "/\u00e9",
    () => base + "/\uff41",
    () => base + "/e\u0301",
    () => base + "\u202e/x",
    () => base + "/.hidden",
    () => "/" + "a/".repeat(rng.range(50, 400)) + "b",
    () => "/\\" + base.slice(1),
    () => "\\/" + base.slice(1),
    () => base + "\\..\\x",
    () => base + "/x\\y",
    () => "/./" + base.slice(1),
    () => "/a/../" + base.slice(1),
    () => base + "/" + "x".repeat(300),
  ];
  return rng.pick(tricks)();
}

function hostTrick(rng: Rng, h: string): string {
  const tricks: Array<() => string> = [
    () => h,
    () => "www." + h,
    () => "x." + h,
    () => "a.b." + h,
    () => "evil-" + h,
    () => "evil" + h,
    () => h + ".evil.com",
    () => h + ".",
    () => h + "..",
    () => h.toUpperCase(),
    () => "user@" + h,
    () => "a.b+c@" + h,
    () => "a@b@" + h,
    () => "@" + h,
    () => h + "@evil.com",
    () => "u@" + h + ":8080",
    () => h + ":8080",
    () => h + ":",
    () => "https://" + h,
    () => "https://" + h + "/path?q=1#f",
    () => "http://" + h + ":80/",
    () => "http://user:pw@" + h + "/",
    () => "https://user@" + h + "/",
    () => "https://" + h + "@evil.com/",
    () => "https://evil.com\\@" + h + "/",
    () => "https://evil.com#@" + h + "/",
    () => "https://evil.com?@" + h + "/",
    () => "https://" + h + "\\.evil.com/",
    () => "ftp://" + h + "/",
    () => "file:///" + h,
    () => "//" + h,
    () => "https:///" + h,
    () => "https:/" + h,
    () => "HTTPS://" + h.toUpperCase() + "/",
    () => "mailto:bob@" + h,
    () => "javascript://" + h + "/%0aalert(1)",
    () => "127.0.0.1",
    () => "http://127.0.0.1/",
    () => "http://0x7f.1/",
    () => "http://0177.0.0.1/",
    () => "http://2130706433/",
    () => "http://127.1/",
    () => "http://[::1]/",
    () => "[::1]",
    () => "http://[::ffff:127.0.0.1]/",
    () => "1.2.3.4",
    () => h + ".1",
    () => h + ".0x1",
    () => "1.0x1",
    () => "xn--" + h.replace(/[^a-z0-9]/g, "") + "-abc.com",
    () => "xn--nxasmq6b." + h,
    () => "xn--zz.com",
    () => "xn--" + "a".repeat(80) + ".com",
    () => h.replace(/\./g, "\u3002"),
    () => h.replace(/\./g, "\uff0e"),
    () => h.replace(/a/g, "\u0430"),
    () => h.replace(/o/g, "\uff4f"),
    () => "\uff43\uff4f\uff52\uff50." + h,
    () => "caf\u00e9." + h,
    () => "e\u0301." + h,
    () => h + "%2f",
    () => h + "%00",
    () => "%63orp.com",
    () => " " + h,
    () => h + " ",
    () => h + "\n",
    () => h + "\t",
    () => h + "\u0000",
    () => "a b." + h,
    () => "-" + h,
    () => "a-." + h,
    () => "a_b." + h,
    () => "a".repeat(63) + "." + h,
    () => "a".repeat(64) + "." + h,
    () => ("a".repeat(60) + ".").repeat(4) + h,
    () => "a." .repeat(rng.range(120, 130)) + "com",
    () => h + "/",
    () => h + "?x",
    () => h + "#x",
    () => h + "\\x",
    () => h + "\u202e",
    () => h + "\u200b",
    () => "",
    () => ".",
    () => "..",
    () => "http://",
    () => "http://.",
    () => "://" + h,
    () => "https://" + h + "\u0000",
    () => "https://" + h + "/\u00e9",
    () => "https://" + h + ":99999/",
    () => "https://" + h + ":0/",
    () => "https://" + h + ":-1/",
    () => "https://" + h + ".:443/",
  ];
  return rng.pick(tricks)();
}

function unicodeTrick(rng: Rng, s: string): string {
  const bit = rng.pick(UNICODE_BITS);
  switch (rng.int(7)) {
    case 0: return s + bit;
    case 1: return bit + s;
    case 2: {
      const i = rng.int(s.length + 1);
      return s.slice(0, i) + bit + s.slice(i);
    }
    case 3: return s.toUpperCase();
    case 4: return s.toLowerCase();
    case 5: return s.normalize("NFD");
    default: return s.normalize("NFC") + bit;
  }
}

function stringFromHint(rng: Rng, h: Hint | undefined): { s: string; kind: string } {
  if (!h) return { s: rng.pick(WORDS), kind: "word" };
  switch (h.kind) {
    case "path": return { s: h.root + rng.pick(["", "/x", "/x/y.txt", "/sub/../x", "/Sub/X", "x"]), kind: "path" };
    case "host": return { s: rng.pick([h.value, "www." + h.value, "a@" + h.value, "https://" + h.value + "/p"]), kind: "host" };
    case "str": return { s: h.value, kind: "str" };
    case "len": {
      const n = Math.max(0, Math.min(9000, h.n + rng.pick([-1, 0, 0, 1])));
      return rng.chance(0.2) ? { s: "\u{1f600}".repeat(Math.floor(n / 2)) + (n % 2 ? "a" : ""), kind: "len" } : { s: "a".repeat(n), kind: "len" };
    }
    default: return { s: rng.pick(WORDS), kind: "word" };
  }
}

function makeString(rng: Rng, hints: Hint[] | undefined, p: number): { s: string; family: string } {
  const strHints = (hints ?? []).filter((h) => h.kind !== "num" && h.kind !== "bool");
  const h = strHints.length > 0 && rng.chance(0.8) ? rng.pick(strHints) : undefined;
  const { s, kind } = stringFromHint(rng, h);
  if (!rng.chance(p)) return { s, family: "plain" };
  const r = rng.next();
  if (kind === "path" || (r < 0.25 && kind !== "host")) return { s: pathTrick(rng, s), family: "path" };
  if (kind === "host" || r < 0.5) return { s: hostTrick(rng, kind === "host" && h && h.kind === "host" ? h.value : rng.pick(["corp.com", "docs.corp.com", "example.com", "a.b.example.org"])), family: "host" };
  return { s: unicodeTrick(rng, s), family: "unicode" };
}

function makeNumber(rng: Rng, hints: Hint[] | undefined, p: number): { n: number; family: string } {
  const nh = (hints ?? []).filter((h): h is Extract<Hint, { kind: "num" }> => h.kind === "num");
  if (nh.length > 0 && rng.chance(0.75)) {
    const v = rng.pick(nh).value;
    if (!rng.chance(p)) return { n: v, family: "plain" };
    const eps = rng.pick([0, 1e-9, -1e-9, 1, -1, Number.EPSILON * Math.max(1, Math.abs(v)), -Number.EPSILON * Math.max(1, Math.abs(v)), v]);
    return { n: v + eps, family: "numeric" };
  }
  return { n: rng.pick(NUM_EDGES), family: "numeric" };
}

function makeValue(rng: Rng, type: ArgType, hints: Hint[] | undefined, p: number): { v: unknown; family: string } {
  switch (type) {
    case "string": {
      const r = makeString(rng, hints, p);
      return { v: r.s, family: r.family };
    }
    case "number": {
      const r = makeNumber(rng, hints, p);
      return { v: r.n, family: r.family };
    }
    case "boolean":
      return { v: rng.chance(0.5), family: "plain" };
    default: {
      const n = rng.chance(0.08) ? rng.pick([0, 256, 257]) : rng.pick([0, 1, 1, 2, 3, 5]);
      const out: string[] = [];
      let fam = "plain";
      for (let i = 0; i < n; i++) {
        if (n >= 256) {
          out.push(rng.pick(WORDS));
          continue;
        }
        const r = makeString(rng, hints, p);
        out.push(r.s);
        if (r.family !== "plain") fam = r.family;
      }
      return { v: out, family: fam };
    }
  }
}

function baseCtx(rng: Rng, gp: GenPolicy, tool: GenTool): Rec {
  const ctx: Rec = {
    agentId: gp.agents.length > 0 && rng.chance(0.7) ? rng.pick(gp.agents) : rng.pick(["agent-1", "agent-9", "x"]),
  };
  if (rng.chance(0.3)) ctx.userId = rng.pick(["u1", "user@x.com", "\u00e9"]);
  if (rng.chance(0.55)) {
    const pool = gp.scopes.length > 0 ? gp.scopes : ["sales", "none"];
    ctx.scopes = rng.sample(pool, rng.range(0, Math.min(3, pool.length)));
  }
  if (rng.chance(0.4)) ctx.sessionTainted = rng.chance(0.5);
  else if (rng.chance(0.1)) ctx.sessionTainted = false;
  if (rng.chance(0.5)) {
    const prov: Rec = {};
    for (const a of tool.args) {
      if (!rng.chance(0.6)) continue;
      const k = rng.chance(0.15) ? 0 : rng.range(1, 3);
      prov[a.name] = rng.sample(gp.labels, k);
    }
    ctx.provenance = prov;
  }
  return ctx;
}

function validRequest(rng: Rng, gp: GenPolicy, tool: GenTool, p: number): { req: Rec; family: string } {
  const args: Rec = {};
  let fam = "valid";
  for (const a of tool.args) {
    if (a.optional && rng.chance(0.4)) continue;
    const r = makeValue(rng, a.type, gp.hints.get(a.name), p);
    args[a.name] = r.v;
    if (r.family !== "plain") fam = r.family;
  }
  return { req: { tool: tool.name, args, ctx: baseCtx(rng, gp, tool) }, family: fam };
}

function makeNest(depth: number, leaf: unknown): unknown {
  let v = leaf;
  for (let i = 0; i < depth; i++) v = { n: v };
  return v;
}

function jsonBytes(v: unknown): number {
  return Buffer.byteLength(JSON.stringify(v), "utf8");
}

function ctxHostile(rng: Rng, gp: GenPolicy, tool: GenTool, req: Rec): string {
  const ctx = req.ctx as Rec;
  const argName = tool.args.length > 0 ? rng.pick(tool.args).name : "zzz";
  const variants: Array<[string, () => void]> = [
    ["ctx-missing", () => { delete req.ctx; }],
    ["ctx-null", () => { req.ctx = null; }],
    ["ctx-array", () => { req.ctx = []; }],
    ["ctx-string", () => { req.ctx = "x"; }],
    ["ctx-empty", () => { req.ctx = {}; }],
    ["agent-empty", () => { ctx.agentId = ""; }],
    ["agent-number", () => { ctx.agentId = 5; }],
    ["agent-missing", () => { delete ctx.agentId; }],
    ["agent-nfd", () => { ctx.agentId = "e\u0301"; }],
    ["agent-unicode", () => { ctx.agentId = unicodeTrick(rng, String(ctx.agentId)); }],
    ["user-number", () => { ctx.userId = 5; }],
    ["scopes-string", () => { ctx.scopes = "sales"; }],
    ["scopes-mixed", () => { ctx.scopes = ["sales", 1]; }],
    ["scopes-null", () => { ctx.scopes = null; }],
    ["scopes-dups", () => { ctx.scopes = ["sales", "sales", "read"]; }],
    ["scopes-unicode", () => { ctx.scopes = [unicodeTrick(rng, "sales")]; }],
    ["tainted-string", () => { ctx.sessionTainted = rng.pick(["true", "false", ""]); }],
    ["tainted-number", () => { ctx.sessionTainted = rng.pick([1, 0]); }],
    ["tainted-null", () => { ctx.sessionTainted = null; }],
    ["tainted-undefined", () => { ctx.sessionTainted = undefined; }],
    ["tainted-true", () => { ctx.sessionTainted = true; }],
    ["ctx-unknown-key", () => { ctx.extra = 1; }],
    ["ctx-unknown-key-case", () => { ctx.AgentId = "x"; }],
    ["prov-undeclared-key", () => { ctx.provenance = { zzz_undeclared: ["trusted-user"] }; }],
    ["prov-value-string", () => { ctx.provenance = { [argName]: "trusted-user" }; }],
    ["prov-value-number", () => { ctx.provenance = { [argName]: [1] }; }],
    ["prov-label-space", () => { ctx.provenance = { [argName]: ["bad label"] }; }],
    ["prov-label-empty", () => { ctx.provenance = { [argName]: [""] }; }],
    ["prov-label-65", () => { ctx.provenance = { [argName]: ["a".repeat(65)] }; }],
    ["prov-label-64", () => { ctx.provenance = { [argName]: ["a".repeat(64)] }; }],
    ["prov-label-bidi", () => { ctx.provenance = { [argName]: ["trusted-user\u202e"] }; }],
    ["prov-label-unicode", () => { ctx.provenance = { [argName]: ["tr\u00fcsted"] }; }],
    ["prov-label-newline", () => { ctx.provenance = { [argName]: ["trusted-user\n"] }; }],
    ["prov-empty-array", () => { ctx.provenance = { [argName]: [] }; }],
    ["prov-array", () => { ctx.provenance = []; }],
    ["prov-null", () => { ctx.provenance = null; }],
    ["prov-proto-key", () => { ctx.provenance = JSON.parse('{"__proto__": ["x"]}'); }],
    ["prov-ctor-key", () => { ctx.provenance = { constructor: ["x"] }; }],
    ["prov-nested", () => { ctx.provenance = { [argName]: [["a"]] }; }],
    ["prov-labels-match", () => { ctx.provenance = { [argName]: gp.labels.length ? rng.sample(gp.labels, rng.range(1, 4)) : ["trusted-user"] }; }],
    ["prov-65-keys", () => { ctx.provenance = Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`k${i}`, ["a"]])); }],
    ["prov-257-labels", () => { ctx.provenance = { [argName]: Array.from({ length: 257 }, () => "a") }; }],
    ["prov-256-labels", () => { ctx.provenance = { [argName]: Array.from({ length: 256 }, () => "a") }; }],
  ];
  const [name, fn] = rng.pick(variants);
  fn();
  return name;
}

function topHostile(rng: Rng, tool: GenTool, req: Rec): { family: string; request: unknown } {
  const variants: Array<[string, () => unknown]> = [
    ["req-null", () => null],
    ["req-array", () => []],
    ["req-string", () => "x"],
    ["req-number", () => 5],
    ["req-undefined", () => undefined],
    ["req-empty", () => ({})],
    ["req-extra-key", () => ({ ...req, extra: 1 })],
    ["req-extra-ctxlike", () => ({ ...req, userId: "u" })],
    ["req-no-tool", () => { const r = { ...req }; delete r.tool; return r; }],
    ["req-no-args", () => { const r = { ...req }; delete r.args; return r; }],
    ["req-args-null", () => ({ ...req, args: null })],
    ["req-args-array", () => ({ ...req, args: [] })],
    ["req-args-array-vals", () => ({ ...req, args: ["a"] })],
    ["req-args-string", () => ({ ...req, args: "x" })],
    ["req-tool-number", () => ({ ...req, tool: 5 })],
    ["req-tool-null", () => ({ ...req, tool: null })],
    ["req-tool-array", () => ({ ...req, tool: [tool.name] })],
    ["req-tool-undefined", () => ({ ...req, tool: undefined })],
    ["req-key-order", () => ({ ctx: req.ctx, args: req.args, tool: req.tool })],
    ["req-frozen", () => Object.freeze({ ...req })],
    ["req-nullproto", () => Object.assign(Object.create(null), req)],
  ];
  const [family, fn] = rng.pick(variants);
  return { family, request: fn() };
}

function toolHostile(rng: Rng, gp: GenPolicy, req: Rec): string {
  const t = req.tool as string;
  const variants: Array<[string, () => unknown]> = [
    ["tool-unknown", () => "no_such_tool"],
    ["tool-upper", () => t.toUpperCase()],
    ["tool-space", () => t + " "],
    ["tool-leading-space", () => " " + t],
    ["tool-empty", () => ""],
    ["tool-ctor", () => "constructor"],
    ["tool-proto", () => "__proto__"],
    ["tool-toString", () => rng.pick(["toString", "hasOwnProperty", "valueOf", "prototype"])],
    ["tool-zwsp", () => t + "\u200b"],
    ["tool-fullwidth", () => t.replace(/a/g, "\uff41") + "\uff41"],
    ["tool-nfd", () => "e\u0301" + t],
    ["tool-long", () => "t".repeat(rng.pick([64, 65, 8192, 8193]))],
    ["tool-other", () => rng.pick(gp.tools).name],
  ];
  const [name, fn] = rng.pick(variants);
  req.tool = fn();
  return name;
}

function limitsCase(rng: Rng, gp: GenPolicy, tool: GenTool): { family: string; request: unknown } {
  const { req } = validRequest(rng, gp, tool, 0.1);
  const args = req.args as Rec;
  const strArgs = tool.args.filter((a) => a.type === "string");
  const arrArgs = tool.args.filter((a) => a.type === "string[]");
  const kind = rng.int(9);
  switch (kind) {
    case 0: {
      const n = rng.pick([8191, 8192, 8193, 8194]);
      const s = rng.chance(0.3) ? "\u{1f600}".repeat(n >> 1) + (n & 1 ? "a" : "") : "a".repeat(n);
      if (strArgs.length > 0) args[rng.pick(strArgs).name] = s;
      else args["big"] = s;
      return { family: "limit-string", request: req };
    }
    case 1: {
      const n = rng.pick([63, 64, 65]);
      for (let i = 0; i < n; i++) args[`extra${i}`] = i;
      return { family: "limit-keys", request: req };
    }
    case 2: {
      const n = rng.pick([255, 256, 257]);
      const arr = Array.from({ length: n }, () => "a");
      if (arrArgs.length > 0) args[rng.pick(arrArgs).name] = arr;
      else args["arr"] = arr;
      return { family: "limit-array", request: req };
    }
    case 3: {
      const d = rng.range(5, 9);
      args["deep"] = makeNest(d - 2, 1); // args at depth 2, deep object depth 3
      return { family: "limit-depth", request: req };
    }
    case 4: {
      // JSON size boundary: pad an extra / string[] arg until the exact size hits 65536 + delta
      const delta = rng.pick([-3, -2, -1, 0, 0, 1, 2, 3]);
      const target = 65536 + delta;
      const padName = arrArgs.length > 0 && rng.chance(0.6) ? rng.pick(arrArgs).name : "pad";
      const pad: string[] = [];
      args[padName] = pad;
      let cur = jsonBytes(req);
      while (cur < target) {
        const overhead = 2 + (pad.length > 0 ? 1 : 0);
        const L = Math.min(8000, target - cur - overhead);
        if (L < 0) break;
        pad.push("a".repeat(L));
        cur = jsonBytes(req);
      }
      return { family: "limit-size", request: req };
    }
    case 5: {
      const f1 = rng.range(10, 16), f2 = rng.range(10, 16), f3 = rng.range(10, 16);
      const leaf: unknown[] = [];
      const l2 = Array.from({ length: f3 }, () => leaf);
      const l3 = Array.from({ length: f2 }, () => l2);
      const l4 = Array.from({ length: f1 }, () => l3);
      args["dag"] = l4;
      return { family: "limit-containers", request: req };
    }
    case 6: {
      const inner = new Array(256).fill(1);
      const n = rng.range(60, 68);
      args["dag"] = Array.from({ length: n }, () => inner);
      return { family: "limit-nodes", request: req };
    }
    case 7: {
      // size + invalid mixed (precedence)
      const s = "a".repeat(8193);
      args["x"] = s;
      (req.ctx as Rec).extra = 1;
      return { family: "limit-and-invalid", request: req };
    }
    default: {
      // many labels / long provenance
      (req.ctx as Rec).provenance = Object.fromEntries(tool.args.map((a) => [a.name, Array.from({ length: rng.pick([1, 255, 256, 257]) }, () => "l")]));
      return { family: "limit-prov", request: req };
    }
  }
}

function jsHostile(rng: Rng, gp: GenPolicy, tool: GenTool): { family: string; request: unknown } {
  const { req } = validRequest(rng, gp, tool, 0.1);
  const args = req.args as Rec;
  const ctx = req.ctx as Rec;
  const argNames = tool.args.map((a) => a.name);
  const target = argNames.length > 0 ? rng.pick(argNames) : "zz";
  const kind = rng.int(26);
  switch (kind) {
    case 0: return { family: "js-proxy-args", request: { ...req, args: new Proxy(args, {}) } };
    case 1: return { family: "js-proxy-ctx", request: { ...req, ctx: new Proxy(ctx, {}) } };
    case 2: return { family: "js-proxy-root", request: new Proxy(req, {}) };
    case 3: return { family: "js-proxy-array", request: (() => { args[target] = new Proxy(["a"], {}); return req; })() };
    case 4: { Object.defineProperty(args, target, { get: () => "x", enumerable: true, configurable: true }); return { family: "js-getter-arg", request: req }; }
    case 5: { Object.defineProperty(ctx, "scopes", { get: () => [], enumerable: true, configurable: true }); return { family: "js-getter-ctx", request: req }; }
    case 6: { args[Symbol("s") as unknown as string] = 1; return { family: "js-symbol-key", request: req }; }
    case 7: { args["self"] = args; return { family: "js-cycle-args", request: req }; }
    case 8: { ctx["self"] = ctx; return { family: "js-cycle-ctx", request: req }; }
    case 9: { args[target] = new Date(0); return { family: "js-date", request: req }; }
    case 10: { args[target] = new Map(); return { family: "js-map", request: req }; }
    case 11: { class K { a = "x"; } args[target] = new K(); return { family: "js-class-instance", request: req }; }
    case 12: { const sparse = new Array(3); sparse[0] = "a"; args[target] = sparse; return { family: "js-sparse", request: req }; }
    case 13: { const a: unknown[] = ["a"]; (a as unknown as Rec).extra = 1; args[target] = a; return { family: "js-array-extra-prop", request: req }; }
    case 14: { Object.defineProperty(args, "hidden", { value: 1, enumerable: false }); return { family: "js-nonenumerable", request: req }; }
    case 15: { args[target] = 1n; return { family: "js-bigint", request: req }; }
    case 16: { args[target] = undefined; return { family: "js-undefined", request: req }; }
    case 17: { args[target] = () => 1; return { family: "js-function", request: req }; }
    case 18: { args[target] = rng.pick([NaN, Infinity, -Infinity]); return { family: "js-nonfinite", request: req }; }
    case 19: { args["np"] = Object.assign(Object.create(null), { a: 1 }); return { family: "js-nullproto-nested", request: req }; }
    case 20: { args["inh"] = Object.assign(Object.create({ z: 1 }), { a: 1 }); return { family: "js-inherited", request: req }; }
    case 21: { args[target] = new Uint8Array(2); return { family: "js-typedarray", request: req }; }
    case 22: { args[target] = Object("x"); return { family: "js-boxed", request: req }; }
    case 23: { class A2 extends Array {} const a = new A2(); a.push("a"); args[target] = a; return { family: "js-array-subclass", request: req }; }
    case 24: { args["a\ud800"] = 1; return { family: "js-lone-surrogate-key", request: req }; }
    default: { args[rng.pick(["__proto__", "constructor", "prototype"])] = 1; Object.defineProperty(args, "__proto__", { value: 1, enumerable: true, configurable: true, writable: true }); return { family: "js-forbidden-key", request: req }; }
  }
}

function argsHostile(rng: Rng, gp: GenPolicy, tool: GenTool): { family: string; request: unknown } {
  const { req } = validRequest(rng, gp, tool, 0.2);
  const args = req.args as Rec;
  const names = tool.args.map((a) => a.name);
  const target = names.length > 0 ? rng.pick(names) : undefined;
  const kind = rng.int(8);
  switch (kind) {
    case 0: args["unexpected"] = 1; return { family: "args-extra", request: req };
    case 1: if (target) delete args[target]; else args["unexpected"] = 1; return { family: "args-missing", request: req };
    case 2: if (target) args[target] = rng.pick(WRONG_VALUES); else args["unexpected"] = null; return { family: "args-wrongtype", request: req };
    case 3: args[unicodeTrick(rng, target ?? "k")] = "x"; return { family: "args-key-unicode", request: req };
    case 4: if (target) args[target.toUpperCase()] = args[target]; return { family: "args-key-case", request: req };
    case 5: if (target) args[target] = null; return { family: "args-null", request: req };
    case 6: if (target) args[target] = { v: args[target] }; return { family: "args-wrapped", request: req };
    default: { for (const n of names) delete args[n]; return { family: "args-empty", request: req }; }
  }
}

export function genCase(rng: Rng, gp: GenPolicy): GenCase {
  const tool = rng.pick(gp.tools);
  const roll = rng.int(100);
  if (roll < 45) {
    const { req, family } = validRequest(rng, gp, tool, 0.3);
    return { family, request: req };
  }
  if (roll < 60) {
    const { req, family } = validRequest(rng, gp, tool, 0.9);
    return { family: family === "valid" ? "valid" : family, request: req };
  }
  if (roll < 66) {
    const { req } = validRequest(rng, gp, tool, 0.3);
    return { family: toolHostile(rng, gp, req), request: req };
  }
  if (roll < 78) {
    const { req } = validRequest(rng, gp, tool, 0.3);
    return { family: ctxHostile(rng, gp, tool, req), request: req };
  }
  if (roll < 85) {
    const { req } = validRequest(rng, gp, tool, 0.3);
    return topHostile(rng, tool, req);
  }
  if (roll < 91) return argsHostile(rng, gp, tool);
  if (roll < 96) return limitsCase(rng, gp, tool);
  return jsHostile(rng, gp, tool);
}
