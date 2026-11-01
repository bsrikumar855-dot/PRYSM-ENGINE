// Policy-decision accuracy benchmark (BENCH-SPEC section 1/2). `npm run eval`.
// Usage: node eval/run-benchmark.ts [--json] [--out file] [--allow-mismatch]
//          [--corpus-dir d] [--benign-dir d] [--policy file]
// Exit 0 whenever the run completes, EXCEPT exit 1 if any pinned attack-corpus case disagrees on
// EFFECT (or on load behaviour), unless --allow-mismatch. Accuracy numbers are information, not pass/fail.
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { decide, loadPolicy } from "../src/core/index.ts";
import type { Decision } from "../src/core/index.ts";
import { aggregate } from "./bench-lib/confusion.ts";
import type { Aggregate, ClassSummary, Outcome } from "./bench-lib/confusion.ts";
import { describe } from "./bench-lib/stats.ts";
import { evaluateCorpus, loadCorpus, provenanceBucket, provenanceOf, runDecision } from "./bench-lib/corpus.ts";
import type { CorpusCase, DecideFn, LoadFn } from "./bench-lib/corpus.ts";
import { loadBenign } from "./benign/loader.ts";
import type { BenignLoad } from "./benign/loader.ts";

const here = dirname(fileURLToPath(import.meta.url));

export const SCHEMA_VERSION = 1;

export interface Mismatch { id: string; class: string; expected: string; got: string; why: string }
export interface Triage {
  id: string; got: string; matched_deny: string[]; matched_reasons: { id: string; effect: string; reason_code: string }[];
  trace_matched: { rule: string; why: string }[]; request: { tool: string; args: unknown; ctx: unknown }; why: string; source: string;
  classify_as: "policy too strict | labeller error | engine defect (human decision required)";
}

export interface Summary {
  schema_version: number;
  scope: string;
  attack_corpus: {
    cases_loaded: number; decision_cases: number; overridden_by_later_files: number; files: string[];
    provenance: { blind_labeller: number; lead_derived: number; non_independent: number; buckets: Record<string, number> };
    per_class: Aggregate["per_class"]; overall: ClassSummary;
    effect_mismatches: Mismatch[]; reason_mismatches: Mismatch[];
  };
  load_behaviour: { cases: number; agree: number; disagree: { id: string; expected: boolean; got: boolean | "error" }[] };
  benign_set: {
    present: boolean; cases: number; files: string[]; schema_errors: { file: string; line: number; message: string }[]; duplicates_overridden: number;
    overall: ClassSummary | null; false_positives: Mismatch[]; reason_mismatches: Mismatch[]; triage: Triage[];
  };
  baselines: { no_guard: { fn_rate: 1; measured: false; note: string }; prompt_only: { measured: false; note: string } };
  caveats: string[];
  regression_guard: { pinned_effect_mismatches: number; exit_code: number; allow_mismatch: boolean };
}

export interface RunOptions {
  corpusDir?: string; benignDir?: string; policyPath?: string; allowMismatch?: boolean;
  decideFn?: (req: any) => Decision; loadFn?: LoadFn;
}

const exp = (o: Outcome): string => `${o.expectedEffect}${o.expectedReason ? "/" + o.expectedReason : ""}`;
const mm = (o: Outcome): Mismatch => ({ id: o.id, class: o.class, expected: exp(o), got: `${o.gotEffect}/${o.gotReason}`, why: o.why ?? "" });

export function runBenchmark(opts: RunOptions = {}): Summary {
  const policy = loadPolicy(readFileSync(opts.policyPath ?? join(here, "policies", "support-agent.policy.json")));
  const engine = opts.decideFn ?? ((req: any) => decide(policy, req));
  const loadFn: LoadFn = opts.loadFn ?? ((b) => loadPolicy(b));

  const corpus = loadCorpus(opts.corpusDir ?? join(here, "corpus"));
  const ev = evaluateCorpus(corpus.cases, engine as DecideFn, loadFn);
  const decisionCases = corpus.cases.filter((c: CorpusCase) => c.policy_text === undefined);
  const buckets: Record<string, number> = {};
  let lead = 0;
  for (const c of corpus.cases) {
    buckets[provenanceBucket(c)] = (buckets[provenanceBucket(c)] ?? 0) + 1;
    if (provenanceOf(c) === "lead-derived") lead++;
  }
  const sortedBuckets: Record<string, number> = {};
  for (const k of Object.keys(buckets).sort()) sortedBuckets[k] = buckets[k]!;

  const effectMm = ev.outcomes.filter((o) => o.gotEffect !== o.expectedEffect).map(mm);
  const reasonMm = ev.outcomes.filter((o) => o.gotEffect === o.expectedEffect && o.expectedReason !== undefined && o.expectedReason !== o.gotReason).map(mm);

  // Benign set (optional)
  const benign: BenignLoad = loadBenign(opts.benignDir ?? join(here, "benign"));
  let benignOverall: ClassSummary | null = null;
  const fps: Mismatch[] = []; const bReason: Mismatch[] = []; const triage: Triage[] = [];
  if (benign.present) {
    const outs: Outcome[] = [];
    for (const c of benign.cases) {
      let last: Decision | null = null;
      const o = runDecision(c, c.request, (r) => { const d = engine(r); last = d; return d; });
      outs.push(o);
      if (o.gotEffect !== "permit") {
        fps.push(mm(o));
        const d = last as Decision | null;
        triage.push({
          id: c.id, got: `${o.gotEffect}/${o.gotReason}`,
          matched_deny: d ? [...d.matched.deny] : [],
          matched_reasons: d ? d.matched_reasons.map((r) => ({ id: r.id, effect: r.effect, reason_code: r.reason_code })) : [],
          trace_matched: d ? d.trace.filter((t) => t.matched).map((t) => ({ rule: t.rule, why: t.why })) : [],
          request: c.request, why: c.why ?? "", source: c.source ?? "",
          classify_as: "policy too strict | labeller error | engine defect (human decision required)",
        });
      } else if (o.expectedReason !== undefined && o.expectedReason !== o.gotReason) bReason.push(mm(o));
    }
    benignOverall = aggregate(outs).overall;
  }

  const pinned = effectMm.length + ev.load.disagree.length;
  const exit_code = pinned > 0 && !opts.allowMismatch ? 1 : 0;
  return {
    schema_version: SCHEMA_VERSION,
    scope: "Policy-decision accuracy of policy + engine on the labelled corpora below. Not a detection rate against real attackers or real models.",
    attack_corpus: {
      cases_loaded: corpus.cases.length, decision_cases: decisionCases.length, overridden_by_later_files: corpus.overridden, files: corpus.files,
      provenance: { blind_labeller: corpus.cases.length - lead, lead_derived: lead, non_independent: lead, buckets: sortedBuckets },
      per_class: ev.aggregate.per_class, overall: ev.aggregate.overall,
      effect_mismatches: effectMm, reason_mismatches: reasonMm,
    },
    load_behaviour: { cases: ev.load.n, agree: ev.load.agree, disagree: ev.load.disagree.map((d) => ({ id: d.id, expected: d.expected, got: d.got })) },
    benign_set: {
      present: benign.present, cases: benign.cases.length, files: benign.files, schema_errors: benign.errors, duplicates_overridden: benign.duplicates_overridden,
      overall: benignOverall, false_positives: fps, reason_mismatches: bReason, triage,
    },
    baselines: {
      no_guard: { fn_rate: 1, measured: false, note: "FN = 100% by construction: with no guard every attack call executes. Stated, not measured." },
      prompt_only: { measured: false, note: "Prompt-only guard is NOT measured: the owner chose a mock-only model (DEC-16) and a scripted mock cannot say anything about real-model prompt compliance." },
    },
    caveats: [
      "The 563-case attack/near-miss corpus is a regression pin: the engine agrees with all labels, which is not independent evidence of correctness (circularity, DEC-20).",
      "FN/FP are properties of policy plus engine on these corpora, not detection rates against real attackers.",
      "Mock-only: nothing here measures real-LLM behaviour or prompt-injection detection.",
    ],
    regression_guard: { pinned_effect_mismatches: pinned, exit_code, allow_mismatch: opts.allowMismatch === true },
  };
}

const pad = (s: string, n: number): string => (s.length >= n ? s : s + " ".repeat(n - s.length));
const padL = (s: string, n: number): string => (s.length >= n ? s : " ".repeat(n - s.length) + s);

export function renderText(s: Summary): string {
  const L: string[] = [];
  const a = s.attack_corpus;
  L.push("PRYSM policy-decision accuracy benchmark (deterministic; policy + engine on a labelled corpus)");
  L.push("");
  L.push(`Attack/near-miss corpus: ${a.cases_loaded} cases loaded (${a.decision_cases} decision cases, ${s.load_behaviour.cases} policy-load cases), ${a.overridden_by_later_files} overridden by later files`);
  L.push(`Label provenance: ${a.provenance.blind_labeller} blind-labeller, ${a.provenance.lead_derived} lead-derived; ${a.provenance.non_independent} non-independent`);
  L.push("  by why-prefix: " + Object.entries(a.provenance.buckets).map(([k, v]) => `${k}=${v}`).join(", "));
  L.push("");
  L.push(pad("class", 34) + padL("n", 5) + padL("exp-deny", 9) + padL("exp-perm", 9) + padL("FN", 4) + padL("FP", 4) + padL("reason", 7) + "  FN 95% / FP 95%");
  const row = (name: string, c: ClassSummary): string => {
    const fn = c.fn_rate, fp = c.fp_rate;
    const f = (iv: typeof fn): string => iv.n === 0 || iv.upper === null || iv.lower === null ? "n/a" : iv.k === 0 ? `0/${iv.n} ub ${(iv.upper * 100).toFixed(2)}%` : `${iv.k}/${iv.n} [${(iv.lower * 100).toFixed(2)},${(iv.upper * 100).toFixed(2)}]%`;
    return pad(name, 34) + padL(String(c.n), 5) + padL(String(c.expected_deny), 9) + padL(String(c.expected_permit), 9) + padL(String(c.fn), 4) + padL(String(c.fp), 4) + padL(String(c.reason_mismatch), 7) + `  ${f(fn)} / ${f(fp)}`;
  };
  for (const [k, v] of Object.entries(a.per_class)) L.push(row(k, v));
  L.push(row("OVERALL", a.overall));
  L.push("");
  L.push(describe("Attack corpus FN rate (expected deny, engine permit)", a.overall.fn_rate));
  L.push(describe("Attack corpus FP rate (expected permit, engine deny)", a.overall.fp_rate));
  L.push(`Reason-code agreement: ${a.overall.reason_mismatch} case(s) with the right effect but a different reason_code (reported separately, not FN/FP)`);
  L.push(`Load behaviour (policy_load_abuse, reported separately): ${s.load_behaviour.agree}/${s.load_behaviour.cases} agree`);
  L.push("");
  const b = s.benign_set;
  if (!b.present) {
    L.push("benign set: not present");
    if (b.schema_errors.length) L.push(`  (${b.schema_errors.length} schema error(s) in eval/benign; no valid cases)`);
  } else {
    L.push(`benign set: ${b.cases} cases from ${b.files.join(", ")} (${b.duplicates_overridden} duplicate ids overridden, ${b.schema_errors.length} schema errors)`);
    L.push(describe("Benign FP rate (expected permit, engine deny)", b.overall!.fp_rate));
    L.push(`  reason-code disagreements among correct permits: ${b.reason_mismatches.length}`);
  }
  for (const e of b.schema_errors.slice(0, 20)) L.push(`  SCHEMA ERROR ${e.file}:${e.line} ${e.message}`);
  L.push("");
  L.push("Baselines");
  L.push("  no guard: FN = 100% by construction (every attack call executes); stated, not measured");
  L.push("  prompt-only guard: NOT measured (mock-only decision, DEC-16)");
  L.push("");
  for (const c of s.caveats) L.push("Caveat: " + c);
  L.push("");
  if (a.effect_mismatches.length === 0 && s.load_behaviour.disagree.length === 0) L.push("Regression pin: 0 effect mismatches in the attack corpus");
  else {
    L.push(`Regression pin: ${s.regression_guard.pinned_effect_mismatches} mismatch(es)${s.regression_guard.allow_mismatch ? " (--allow-mismatch: not failing)" : ""}`);
    for (const m of a.effect_mismatches) L.push(`  MISMATCH ${m.id}: expected ${m.expected} got ${m.got}  [${m.why}]`);
    for (const m of s.load_behaviour.disagree) L.push(`  LOAD MISMATCH ${m.id}: expected loads=${m.expected} got ${String(m.got)}`);
  }
  if (b.triage.length) {
    L.push("");
    L.push(`Benign false positives needing triage (${b.triage.length}); classify each: policy too strict / labeller error / engine defect. None dropped.`);
    for (const t of b.triage) {
      L.push(`  FP ${t.id}: got ${t.got}`);
      L.push(`     tool=${t.request.tool} deny-rules=[${t.matched_deny.join(", ")}] matched=[${t.matched_reasons.map((r) => `${r.id}:${r.effect}:${r.reason_code}`).join(", ")}]`);
      if (t.why) L.push(`     label why: ${t.why}`);
    }
  }
  return L.join("\n");
}

function main(argv: string[]): number {
  const flag = (n: string): boolean => argv.includes(n);
  const val = (n: string): string | undefined => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  const opts: RunOptions = { allowMismatch: flag("--allow-mismatch") };
  const cd = val("--corpus-dir"); if (cd) opts.corpusDir = cd;
  const bd = val("--benign-dir"); if (bd) opts.benignDir = bd;
  const pp = val("--policy"); if (pp) opts.policyPath = pp;
  const s = runBenchmark(opts);
  const json = JSON.stringify(s, null, 2);
  const out = val("--out");
  if (out) writeFileSync(out, json + "\n");
  console.log(flag("--json") ? json : renderText(s));
  return s.regression_guard.exit_code;
}

if (import.meta.main) process.exit(main(process.argv.slice(2)));
