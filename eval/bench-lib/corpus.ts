// Loads eval/corpus/*.jsonl (later files override earlier ones by id) and evaluates it.
// Request generation helpers are copied from eval/run-corpus.ts (which must not be edited).
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { aggregate } from "./confusion.ts";
import type { Aggregate, Outcome } from "./confusion.ts";

export interface CorpusCase {
  id: string; class: string; request?: any; request_gen?: any;
  policy_text?: string; policy_gen?: any; bytes_prefix_hex?: string;
  expected: { effect?: string; reason_code?: string; loads?: boolean }; why?: string;
}
export interface DecisionLike { effect: string; reason_code: string; matched?: { deny: readonly string[]; permit: readonly string[] } }
export type DecideFn = (request: any) => DecisionLike;
export type LoadFn = (bytes: Uint8Array | string) => unknown;

export function applyGen(req: any, g: any): any {
  const parts = String(g.at).split(".");
  let holder = req;
  for (const p of parts.slice(0, -1)) holder = holder[p];
  const last = parts[parts.length - 1]!;
  const key: any = Array.isArray(holder) && /^\d+$/.test(last) ? Number(last) : last;
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

export function genPolicyToken(g: any): string {
  switch (g.kind) {
    case "repeat": return String(g.repeat).repeat(g.times);
    case "list": return Array.from({ length: g.count }, () => g.item).join(",");
    case "rules": return Array.from({ length: g.count }, (_, i) =>
      `{"id":"r${i}","effect":"permit","reason_code":"ok","match":{"tools":["a"]}}`).join(",");
    case "nest": return "[".repeat(g.depth) + "]".repeat(g.depth);
    default: throw new Error("unknown policy_gen.kind " + g.kind);
  }
}

export function materializeRequest(c: CorpusCase): any {
  let req = c.request;
  if (c.request_gen) {
    req = JSON.parse(JSON.stringify(c.request));
    for (const g of ([] as any[]).concat(c.request_gen)) req = applyGen(req, g);
  }
  return req;
}

export interface LoadedCorpus { cases: CorpusCase[]; overridden: number; files: string[] }

export function loadCorpus(dir: string): LoadedCorpus {
  const map = new Map<string, CorpusCase>();
  let overridden = 0;
  const files = readdirSync(dir).filter((x) => x.endsWith(".jsonl")).sort();
  for (const f of files) {
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) {
      if (!line.trim()) continue;
      const c = JSON.parse(line) as CorpusCase;
      if (map.has(c.id)) overridden++;
      map.set(c.id, c);
    }
  }
  return { cases: [...map.values()], overridden, files };
}

/** Provenance from the `why` text. Anything marked LEAD-DERIVED is not independent. */
export function provenanceOf(c: { why?: string }): "lead-derived" | "blind-labeller" {
  return /LEAD-DERIVED/.test(c.why ?? "") ? "lead-derived" : "blind-labeller";
}
/** Finer bucket: the leading version tag of `why` (e.g. "v1.3 relabel"), else "v1 original / unprefixed". */
export function provenanceBucket(c: { why?: string }): string {
  const m = /^(v\d+(?:\.\d+)*)[ :]+(LEAD-DERIVED|relabel)?/.exec(c.why ?? "");
  if (!m) return "unprefixed (v1 original)";
  return m[2] ? `${m[1]} ${m[2]}` : m[1]!;
}

export function runDecision(c: { id: string; class: string; why?: string; expected: { effect?: string; reason_code?: string } }, req: any, decideFn: DecideFn): Outcome {
  const expectedEffect = c.expected.effect === "permit" ? "permit" : "deny";
  let gotEffect: Outcome["gotEffect"]; let gotReason: string;
  try {
    const d = decideFn(req);
    gotEffect = d.effect === "permit" ? "permit" : d.effect === "deny" ? "deny" : "error";
    gotReason = d.reason_code;
  } catch (e) { gotEffect = "error"; gotReason = "HARNESS_ERROR " + String((e as Error).message); }
  return { id: c.id, class: c.class, expectedEffect, expectedReason: c.expected.reason_code, gotEffect, gotReason, why: c.why };
}

export interface LoadResult { id: string; expected: boolean; got: boolean | "error"; ok: boolean }

export function runLoadCase(c: CorpusCase, loadFn: LoadFn): LoadResult {
  let text = c.policy_text ?? "";
  try {
    if (c.policy_gen) text = text.replace("@@GEN@@", genPolicyToken(c.policy_gen));
    let loaded = true;
    try {
      if (c.bytes_prefix_hex) {
        const pre = Buffer.from(c.bytes_prefix_hex, "hex");
        loadFn(new Uint8Array(Buffer.concat([pre, Buffer.from(text, "utf8")])));
      } else loadFn(text);
    } catch { loaded = false; }
    return { id: c.id, expected: c.expected.loads === true, got: loaded, ok: loaded === c.expected.loads };
  } catch { return { id: c.id, expected: c.expected.loads === true, got: "error", ok: false }; }
}

export interface CorpusEval {
  outcomes: Outcome[]; aggregate: Aggregate;
  load: { n: number; agree: number; disagree: LoadResult[] };
  skipped_no_effect: string[];
}

export function evaluateCorpus(cases: readonly CorpusCase[], decideFn: DecideFn, loadFn: LoadFn): CorpusEval {
  const outcomes: Outcome[] = [];
  const loads: LoadResult[] = [];
  const skipped: string[] = [];
  for (const c of cases) {
    if (c.policy_text !== undefined) { loads.push(runLoadCase(c, loadFn)); continue; }
    if (c.expected.effect !== "permit" && c.expected.effect !== "deny") { skipped.push(c.id); continue; }
    let req: any;
    try { req = materializeRequest(c); } catch (e) {
      outcomes.push({ id: c.id, class: c.class, expectedEffect: c.expected.effect, expectedReason: c.expected.reason_code, gotEffect: "error", gotReason: "HARNESS_ERROR " + String((e as Error).message), why: c.why });
      continue;
    }
    outcomes.push(runDecision(c, req, decideFn));
  }
  return { outcomes, aggregate: aggregate(outcomes), load: { n: loads.length, agree: loads.filter((l) => l.ok).length, disagree: loads.filter((l) => !l.ok) }, skipped_no_effect: skipped };
}
