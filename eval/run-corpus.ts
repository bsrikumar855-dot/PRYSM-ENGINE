// Runs the independently labelled corpus (eval/corpus/*.jsonl) against src/core.
// Later files override earlier ones by case id (corrections to v1 labels).
// Usage: node eval/run-corpus.ts [--verbose]   Exit 1 on any mismatch.
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { decide, loadPolicy } from "../src/core/index.ts";

const here = dirname(fileURLToPath(import.meta.url));
const verbose = process.argv.includes("--verbose");

type Case = {
  id: string; class: string; request?: any; request_gen?: any;
  policy_text?: string; policy_gen?: any; bytes_prefix_hex?: string;
  expected: { effect?: string; reason_code?: string; loads?: boolean }; why?: string;
};

function applyGen(req: any, g: any): any {
  const parts = String(g.at).split(".");
  let holder = req;
  for (const p of parts.slice(0, -1)) holder = holder[p];
  const key: any = Array.isArray(holder) && /^\d+$/.test(parts[parts.length - 1]!) ? Number(parts[parts.length - 1]) : parts[parts.length - 1]!;
  const as = g.as ?? "string";
  let v: any;
  if (as === "string") v = (g.prefix ?? "") + String(g.repeat).repeat(g.times) + (g.suffix ?? "");
  else if (as === "array") v = Array.from({ length: g.times }, () => g.repeat);
  else if (as === "array_of_strings") v = Array.from({ length: g.count }, () => String(g.repeat).repeat(g.times));
  else if (as === "object_keys") { v = {}; for (let i = 0; i < g.times; i++) v["k" + i] = 1; }
  else if (as === "nested_object") { v = 1; for (let i = 0; i < g.times; i++) v = { k: v }; }
  else if (as === "nested_array") { v = 1; for (let i = 0; i < g.times; i++) v = [v]; }
  else throw new Error("unknown request_gen.as " + as);
  holder[key] = v;
  return req;
}

function genPolicyToken(g: any): string {
  switch (g.kind) {
    case "repeat": return String(g.repeat).repeat(g.times);
    case "list": return Array.from({ length: g.count }, () => g.item).join(",");
    case "rules": return Array.from({ length: g.count }, (_, i) =>
      `{"id":"r${i}","effect":"permit","reason_code":"ok","match":{"tools":["a"]}}`).join(",");
    case "nest": return "[".repeat(g.depth) + "]".repeat(g.depth);
    default: throw new Error("unknown policy_gen.kind " + g.kind);
  }
}

const corpusDir = join(here, "corpus");
const cases = new Map<string, Case>();
let overridden = 0;
const MIN_CASES: Record<string, number> = { unauthorized_tool: 36, unknown_tool_and_arg_smuggling: 64, path_traversal: 96, ssrf_and_domain: 123, taint_and_provenance: 43, limits_and_malformed: 73, policy_load_abuse: 128 };
for (const f of readdirSync(corpusDir).filter((x) => x.endsWith(".jsonl")).sort()) {
  for (const line of readFileSync(join(corpusDir, f), "utf8").split("\n")) {
    if (!line.trim()) continue;
    const c = JSON.parse(line) as Case;
    if (cases.has(c.id)) overridden++;
    cases.set(c.id, c);
  }
}

const fixture = loadPolicy(readFileSync(join(here, "policies", "support-agent.policy.json")));
const stats = new Map<string, { n: number; fail: number }>();
const failures: string[] = [];

for (const c of cases.values()) {
  const s = stats.get(c.class) ?? { n: 0, fail: 0 };
  s.n++;
  let ok = false; let got = "";
  try {
    if (c.policy_text !== undefined) {
      let text = c.policy_text;
      if (c.policy_gen) text = text.replace("@@GEN@@", genPolicyToken(c.policy_gen));
      let loaded = true;
      try {
        if (c.bytes_prefix_hex) {
          const pre = Buffer.from(c.bytes_prefix_hex, "hex");
          loadPolicy(new Uint8Array(Buffer.concat([pre, Buffer.from(text, "utf8")])));
        } else loadPolicy(text);
      } catch { loaded = false; }
      got = `loads=${loaded}`;
      ok = loaded === c.expected.loads;
    } else {
      let req = c.request;
      if (c.request_gen) { req = structuredCloneSafe(c.request); for (const g of ([] as any[]).concat(c.request_gen)) req = applyGen(req, g); }
      const d = decide(fixture, req);
      got = `${d.effect}/${d.reason_code}`;
      ok = d.effect === c.expected.effect && d.reason_code === c.expected.reason_code;
    }
  } catch (e) { got = "HARNESS_ERROR " + String((e as Error).message); }
  if (!ok) { s.fail++; failures.push(`${c.id}: expected ${JSON.stringify(c.expected)} got ${got}  [${c.why ?? ""}]`); }
  stats.set(c.class, s);
}

function structuredCloneSafe(x: any) { return JSON.parse(JSON.stringify(x)); }

let total = 0, bad = 0;
for (const [k, v] of [...stats].sort()) {
  console.log(`${v.fail === 0 ? "PASS" : "FAIL"}  ${k}: ${v.n - v.fail}/${v.n}`);
  total += v.n; bad += v.fail;
}
for (const [k, min] of Object.entries(MIN_CASES)) {
  const n = stats.get(k)?.n ?? 0;
  if (n < min) { console.log(`FAIL  corpus class ${k} has ${n} cases, expected at least ${min} (file deleted or truncated?)`); bad++; }
}
console.log(`(${overridden} cases were overridden by later corpus files)`);
const leadDerived = [...cases.values()].filter((c) => (c.why ?? "").startsWith("v1.2 LEAD-DERIVED")).length;
console.log(`TOTAL ${total - bad}/${total} agree with the labels (${total - leadDerived} blind-labeller, ${leadDerived} lead-derived and NOT independent); ${bad} mismatches`);
if (bad && (verbose || bad <= 60)) for (const f of failures) console.log("  MISMATCH " + f);
process.exit(bad ? 1 : 0);
