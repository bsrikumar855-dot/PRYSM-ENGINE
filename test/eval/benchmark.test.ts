import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { wilson, describe as describeIv, Z_95 } from "../../eval/bench-lib/stats.ts";
import { aggregate } from "../../eval/bench-lib/confusion.ts";
import type { Outcome } from "../../eval/bench-lib/confusion.ts";
import { evaluateCorpus, provenanceBucket, provenanceOf } from "../../eval/bench-lib/corpus.ts";
import type { CorpusCase } from "../../eval/bench-lib/corpus.ts";
import { loadBenign } from "../../eval/benign/loader.ts";
import { runBenchmark, renderText } from "../../eval/run-benchmark.ts";

const near = (a: number | null, b: number, eps = 1e-9): void => { assert.ok(a !== null && Math.abs(a - b) < eps, `${a} vs ${b}`); };

// Independent reference: written directly from the textbook formula, separate from the implementation.
function refWilson(k: number, n: number): [number, number] {
  const z = 1.959963984540054, p = k / n;
  const a = p + (z * z) / (2 * n);
  const b = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  const d = 1 + (z * z) / n;
  return [(a - b) / d, (a + b) / d];
}

test("wilson: closed forms at the endpoints", () => {
  const z2 = Z_95 * Z_95;
  const z0 = wilson(0, 100);
  assert.equal(z0.lower, 0);
  near(z0.upper, z2 / (100 + z2)); // ~0.036995
  near(z0.upper, 0.03699, 1e-5);
  const all = wilson(100, 100);
  assert.equal(all.upper, 1);
  near(all.lower, 100 / (100 + z2));
});

test("wilson: 5/100 and 50/100 against the reference formula and published values", () => {
  for (const [k, n] of [[5, 100], [50, 100], [1, 10], [348, 348 + 0], [0, 1], [1, 1], [7, 435]] as const) {
    const w = wilson(k, n);
    const [lo, hi] = refWilson(k, n);
    if (k !== 0) near(w.lower, lo);
    if (k !== n) near(w.upper, hi);
  }
  const w5 = wilson(5, 100);
  near(w5.lower, 0.0215, 5e-4); near(w5.upper, 0.1118, 5e-4);
  const w50 = wilson(50, 100);
  near(w50.lower, 0.4038, 5e-4); near(w50.upper, 0.5962, 5e-4);
  near(w50.lower! + w50.upper!, 1); // symmetric at p = 0.5
});

test("wilson: invalid input and n = 0", () => {
  assert.throws(() => wilson(-1, 5), RangeError);
  assert.throws(() => wilson(6, 5), RangeError);
  assert.throws(() => wilson(1.5, 5), RangeError);
  const e = wilson(0, 0);
  assert.equal(e.rate, null); assert.equal(e.upper, null);
  assert.match(describeIv("X", e), /n\/a/);
});

test("describe phrases zero as '0 of N, 95% upper bound x%'", () => {
  assert.equal(describeIv("FN", wilson(0, 100)), "FN: 0 of 100, 95% upper bound 3.70%");
  assert.match(describeIv("FN", wilson(5, 100)), /^FN: 5 of 100 \(5\.00%\), 95% Wilson CI \[2\.15%, 11\.18%\]$/);
});

// ---- confusion counting with a stub engine ----
const stubEngine = (req: any) => {
  switch (req.tool) {
    case "allow": return { effect: "permit", reason_code: "permitted" };
    case "deny": return { effect: "deny", reason_code: "denied_by_rule" };
    case "deny_other": return { effect: "deny", reason_code: "default_deny" };
    case "boom": throw new Error("stub failure");
    default: return { effect: "permit", reason_code: "permitted" };
  }
};
const mk = (id: string, cls: string, tool: string, effect: string, reason?: string): CorpusCase => ({ id, class: cls, request: { tool, args: {}, ctx: {} }, expected: reason ? { effect, reason_code: reason } : { effect } });

test("confusion: FN / FP / reason mismatch / harness error on a tiny synthetic corpus", () => {
  const cases: CorpusCase[] = [
    mk("a1", "A", "deny", "deny", "denied_by_rule"),      // TN
    mk("a2", "A", "allow", "deny", "denied_by_rule"),     // FN
    mk("a3", "A", "allow", "permit", "permitted"),        // TP
    mk("a4", "A", "deny", "permit", "permitted"),         // FP
    mk("b1", "B", "deny_other", "deny", "denied_by_rule"),// effect right, reason differs
    mk("b2", "B", "boom", "deny"),                        // harness error: counted as mismatch, not FN
    mk("b3", "B", "allow", "deny"),                       // FN with no reason label
  ];
  const ev = evaluateCorpus(cases, stubEngine, () => ({}));
  const { per_class, overall } = aggregate(ev.outcomes);
  assert.equal(per_class.A!.n, 4); assert.equal(per_class.A!.fn, 1); assert.equal(per_class.A!.fp, 1);
  assert.equal(per_class.A!.expected_deny, 2); assert.equal(per_class.A!.expected_permit, 2);
  assert.equal(per_class.A!.true_deny, 1); assert.equal(per_class.A!.true_permit, 1);
  assert.equal(per_class.B!.fn, 1); assert.equal(per_class.B!.fp, 0);
  assert.equal(per_class.B!.reason_mismatch, 1);
  assert.equal(per_class.B!.harness_error, 1);
  assert.equal(per_class.B!.effect_mismatch, 2);
  assert.equal(overall.n, 7); assert.equal(overall.fn, 2); assert.equal(overall.fp, 1);
  assert.equal(overall.fn_rate.n, 5); assert.equal(overall.fp_rate.n, 2);
  near(overall.fn_rate.rate, 2 / 5);
  assert.deepEqual(Object.keys(per_class), ["A", "B"]);
});

test("confusion: load cases are separated from decision cases and skipped when unlabelled", () => {
  const cases: CorpusCase[] = [
    mk("d1", "A", "allow", "permit"),
    { id: "l1", class: "policy_load_abuse", policy_text: "ok", expected: { loads: true } },
    { id: "l2", class: "policy_load_abuse", policy_text: "bad", expected: { loads: true } },
    { id: "x1", class: "A", request: { tool: "allow", args: {}, ctx: {} }, expected: {} },
  ];
  const ev = evaluateCorpus(cases, stubEngine, (b) => { if (b === "bad") throw new Error("nope"); });
  assert.equal(ev.outcomes.length, 1);
  assert.equal(ev.load.n, 2); assert.equal(ev.load.agree, 1);
  assert.deepEqual(ev.load.disagree.map((d) => d.id), ["l2"]);
  assert.deepEqual(ev.skipped_no_effect, ["x1"]);
});

test("provenance from why text", () => {
  assert.equal(provenanceOf({ why: "v1.2 LEAD-DERIVED: x" }), "lead-derived");
  assert.equal(provenanceOf({ why: "v1.3 relabel: blind labeller" }), "blind-labeller");
  assert.equal(provenanceOf({}), "blind-labeller");
  assert.equal(provenanceBucket({ why: "v1.2 LEAD-DERIVED: x" }), "v1.2 LEAD-DERIVED");
  assert.equal(provenanceBucket({ why: "v1.3 relabel: y" }), "v1.3 relabel");
  assert.equal(provenanceBucket({ why: "v1.1: z" }), "v1.1");
  assert.equal(provenanceBucket({ why: "plain" }), "unprefixed (v1 original)");
});

// ---- benign loader ----
function tmp(): string { return mkdtempSync(join(tmpdir(), "prysm-eval-")); }
const benignLine = (id: string, extra: any = {}) => JSON.stringify({ id, class: "benign", request: { tool: "search_docs", args: { query: "x" }, ctx: { agentId: "support-bot" } }, expected: { effect: "permit" }, why: "w", source: "s", ...extra });

test("benign loader tolerates missing and empty directories", () => {
  const d = tmp();
  try {
    const missing = loadBenign(join(d, "nope"));
    assert.equal(missing.present, false); assert.equal(missing.cases.length, 0);
    const empty = join(d, "empty"); mkdirSync(empty);
    assert.equal(loadBenign(empty).present, false);
    const s = runBenchmark({ benignDir: empty });
    assert.equal(s.benign_set.present, false);
    assert.match(renderText(s), /benign set: not present/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("benign loader reports schema errors, keeps good lines, later duplicates override", () => {
  const d = tmp();
  try {
    writeFileSync(join(d, "a.jsonl"), [benignLine("b1"), "{not json", benignLine("b2", { expected: { effect: "deny" } }), benignLine("b1", { why: "second" }), ""].join("\n"));
    const r = loadBenign(d);
    assert.equal(r.present, true);
    assert.equal(r.cases.length, 1);
    assert.equal(r.cases[0]!.why, "second");
    assert.equal(r.duplicates_overridden, 1);
    assert.equal(r.errors.length, 2);
    assert.deepEqual(r.errors.map((e) => e.line), [2, 3]);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("benign FP triage lists matching rule ids and is never auto-dropped", () => {
  const d = tmp();
  try {
    writeFileSync(join(d, "b.jsonl"), [
      benignLine("ok1"),
      JSON.stringify({ id: "fp1", class: "benign", request: { tool: "delete_file", args: { path: "/workspace/a" }, ctx: { agentId: "support-bot" } }, expected: { effect: "permit" }, why: "labeller thought deletes are fine", source: "t" }),
    ].join("\n"));
    const s = runBenchmark({ benignDir: d });
    assert.equal(s.benign_set.cases, 2);
    assert.equal(s.benign_set.overall!.fp, 1);
    assert.equal(s.benign_set.overall!.fp_rate.n, 2);
    assert.equal(s.benign_set.false_positives[0]!.id, "fp1");
    const t = s.benign_set.triage[0]!;
    assert.equal(t.id, "fp1");
    assert.ok(t.matched_deny.includes("file.delete-forbidden"));
    assert.equal(s.regression_guard.exit_code, 0); // benign FPs are information, not pass/fail
    assert.match(renderText(s), /FP fp1: got deny\/denied_by_rule/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

// ---- JSON schema stability + end to end ----
test("end to end over the real corpus: 0 effect mismatches, stable JSON shape", () => {
  const s = runBenchmark();
  assert.equal(s.attack_corpus.effect_mismatches.length, 0);
  assert.equal(s.attack_corpus.overall.fn, 0); assert.equal(s.attack_corpus.overall.fp, 0);
  assert.equal(s.load_behaviour.disagree.length, 0);
  assert.equal(s.regression_guard.exit_code, 0);
  assert.equal(s.attack_corpus.cases_loaded, 563);
  assert.equal(s.attack_corpus.decision_cases + s.load_behaviour.cases, 563);
  assert.equal(s.attack_corpus.provenance.blind_labeller + s.attack_corpus.provenance.lead_derived, 563);
  assert.equal(s.baselines.no_guard.fn_rate, 1);
  assert.equal(s.baselines.prompt_only.measured, false);

  assert.deepEqual(Object.keys(s), ["schema_version", "scope", "attack_corpus", "load_behaviour", "benign_set", "baselines", "caveats", "regression_guard"]);
  assert.equal(s.schema_version, 1);
  assert.deepEqual(Object.keys(s.attack_corpus), ["cases_loaded", "decision_cases", "overridden_by_later_files", "files", "provenance", "per_class", "overall", "effect_mismatches", "reason_mismatches"]);
  assert.deepEqual(Object.keys(s.attack_corpus.overall), ["n", "expected_deny", "expected_permit", "true_deny", "true_permit", "fn", "fp", "effect_mismatch", "reason_mismatch", "harness_error", "fn_rate", "fp_rate"]);
  assert.deepEqual(Object.keys(s.attack_corpus.overall.fn_rate), ["k", "n", "rate", "lower", "upper"]);
  assert.deepEqual(Object.keys(s.benign_set), ["present", "cases", "files", "schema_errors", "duplicates_overridden", "overall", "false_positives", "reason_mismatches", "triage"]);
  assert.deepEqual(JSON.parse(JSON.stringify(s)), JSON.parse(JSON.stringify(runBenchmark()))); // deterministic
});

test("a deliberately wrong engine produces mismatches and exit code 1 unless --allow-mismatch", () => {
  const permitAll = (_req: any): any => ({ effect: "permit", reason_code: "permitted", matched: { deny: [], permit: [] }, matched_reasons: [], trace: [] });
  const bad = runBenchmark({ decideFn: permitAll });
  assert.ok(bad.attack_corpus.overall.fn > 300);
  assert.equal(bad.regression_guard.exit_code, 1);
  assert.ok(bad.attack_corpus.effect_mismatches.every((m) => m.id.length > 0 && m.expected.startsWith("deny")));
  assert.match(renderText(bad), /MISMATCH /);
  const allowed = runBenchmark({ decideFn: permitAll, allowMismatch: true });
  assert.equal(allowed.regression_guard.exit_code, 0);
});

test("CLI: --json parses and --out writes the same summary; exit 0", async () => {
  const { spawnSync } = await import("node:child_process");
  const d = tmp();
  try {
    const out = join(d, "sum.json");
    const r = spawnSync(process.execPath, ["--no-warnings=ExperimentalWarning", "eval/run-benchmark.ts", "--json", "--out", out], { encoding: "utf8", cwd: join(import.meta.dirname, "..", "..") });
    assert.equal(r.status, 0, r.stderr);
    const printed = JSON.parse(r.stdout);
    const { readFileSync } = await import("node:fs");
    assert.deepEqual(JSON.parse(readFileSync(out, "utf8")), printed);
    assert.equal(printed.schema_version, 1);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
