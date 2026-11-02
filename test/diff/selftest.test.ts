// Harness self-tests: inject KNOWN faults into the REFERENCE side only and assert the harness reports them.
// These guard against a broken harness (always-equivalent rule, classify ignoring effect, ref == prod, ...).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import {
  refDecide as baseDecide,
  refFaultKinds,
  refLoadPolicy as baseLoad,
  type RefDecision,
  type RefPolicy,
} from "../../eval/reference/index.ts";
import { decide as prodDecide } from "../../src/core/index.ts";
import { HARNESS_VERSION, referenceHashes, runDiff, type RefHooks } from "../../eval/diff/run-diff.ts";

const SEED = "selftest-seed";
const N = 3000;
const run = (hooks?: RefHooks, cases = N): ReturnType<typeof runDiff> =>
  runDiff({ cases, seed: SEED, minimise: false, ...(hooks ? { refHooks: hooks } : {}) });

const honest = run();

function rawOf(x: unknown): { tool?: unknown; args?: unknown; ctx?: unknown } {
  return (typeof x === "object" && x !== null ? x : {}) as never;
}

test("baseline for self-tests: honest reference gives no real disagreements at this scale", () => {
  assert.equal(honest.decide.effect_mismatch, 0);
  assert.equal(honest.decide.matched_mismatch_same_decision, 0);
  assert.equal(honest.decide.reason_mismatch_same_effect, 0);
  assert.equal(honest.load.valid_disagree, 0);
});

test("(a) injected effect flip for one request shape is reported as effect disagreements", () => {
  const r = run({
    decide: (p: RefPolicy, raw: unknown): RefDecision => {
      const d = baseDecide(p, raw);
      const tool = rawOf(raw).tool;
      if (d.reason_code === "permitted" && typeof tool === "string" && tool.length % 2 === 0) {
        return { ...d, effect: "deny", reason_code: "default_deny" };
      }
      return d;
    },
  });
  assert.ok(r.decide.effect_mismatch > 0, `effect_mismatch=${r.decide.effect_mismatch}`);
  assert.ok(r.decide.disagree >= r.decide.effect_mismatch);
});

test("(b) changed reason_code on SINGLE-fault requests is a reason disagreement, not swallowed by the equivalence rule", () => {
  const r = run({
    decide: (p: RefPolicy, raw: unknown): RefDecision => {
      const d = baseDecide(p, raw);
      if (d.reason_code === "limit_exceeded") {
        const fk = refFaultKinds(raw);
        if (fk.limit && !fk.invalid) return { ...d, reason_code: "invalid_request" };
      }
      return d;
    },
  });
  assert.ok(r.decide.reason_mismatch_same_effect > 0, `reason_mismatch=${r.decide.reason_mismatch_same_effect}`);
  assert.equal(r.decide.equivalent_multifault_code_difference, honest.decide.equivalent_multifault_code_difference, "equivalence counter must not absorb single-fault differences");
  assert.ok(r.decide.disagree >= r.decide.reason_mismatch_same_effect);
});

test("(2) both fault kinds + invalid/limit pair is counted as equivalent, never as a disagreement", () => {
  const r = run({
    decide: (p: RefPolicy, raw: unknown): RefDecision => {
      const d = baseDecide(p, raw);
      if (d.reason_code === "limit_exceeded" || d.reason_code === "invalid_request") {
        const fk = refFaultKinds(raw);
        if (fk.limit && fk.invalid) return { ...d, reason_code: d.reason_code === "limit_exceeded" ? "invalid_request" : "limit_exceeded" };
      }
      return d;
    },
  });
  assert.ok(r.decide.equivalent_multifault_code_difference >= honest.decide.equivalent_multifault_code_difference);
  assert.equal(r.decide.disagree, honest.decide.disagree);
  assert.equal(r.decide.effect_mismatch, 0);
});

test("(c) dropped matched rule id is reported as a matched-id disagreement", () => {
  const r = run({
    decide: (p: RefPolicy, raw: unknown): RefDecision => {
      const d = baseDecide(p, raw);
      if (d.matched.permit.length > 0) return { ...d, matched: { deny: d.matched.deny, permit: d.matched.permit.slice(1) } };
      return d;
    },
  });
  assert.ok(r.decide.matched_mismatch_same_decision > 0, `matched=${r.decide.matched_mismatch_same_decision}`);
  assert.equal(r.decide.effect_mismatch, 0);
});

test("(d) a reference that accepts a policy the spec rejects is reported as a load disagreement", () => {
  const stub = baseLoad(JSON.stringify({ policy_schema_version: 1, name: "stub", mode: "enforce", tools: {}, rules: [] }));
  const r = run({
    load: (input: string | Uint8Array): RefPolicy => {
      try {
        return baseLoad(input);
      } catch {
        return stub;
      }
    },
  });
  assert.ok(r.load.mutated_disagree > 0, `load disagree=${r.load.mutated_disagree}`);
  assert.ok(r.load_disagreements.some((e) => e.ref === "accept" && e.prod.startsWith("reject")));
});

test("(4) sensitivity: max_length off-by-one in the reference is detected at quick scale", () => {
  const bump = (v: unknown): void => {
    if (Array.isArray(v)) v.forEach(bump);
    else if (typeof v === "object" && v !== null) {
      const o = v as Record<string, unknown>;
      for (const k of Object.keys(o)) {
        if (k === "max_length" && typeof o[k] === "number" && (o[k] as number) > 0) o[k] = (o[k] as number) - 1;
        else bump(o[k]);
      }
    }
  };
  const r = run({
    load: (input: string | Uint8Array): RefPolicy => {
      if (typeof input !== "string") return baseLoad(input);
      const doc = JSON.parse(input) as unknown;
      bump(doc);
      return baseLoad(JSON.stringify(doc));
    },
  }, 5000);
  assert.ok(r.decide.disagree > 0, `max_length off-by-one produced ${r.decide.disagree} disagreements`);
});

test("(4) sensitivity: 'deny does not override permit' in the reference is detected at quick scale", () => {
  const r = run({
    decide: (p: RefPolicy, raw: unknown): RefDecision => {
      const d = baseDecide(p, raw);
      if (d.reason_code === "denied_by_rule" && d.matched.permit.length > 0) return { ...d, effect: "permit", reason_code: "permitted" };
      return d;
    },
  }, 5000);
  assert.ok(r.decide.effect_mismatch > 0, `deny-override fault produced ${r.decide.effect_mismatch} effect disagreements`);
});

test("(3) reference and production are different functions in different module files; reference imports nothing from src/", () => {
  assert.notEqual(baseDecide as unknown, prodDecide as unknown);
  assert.notEqual(String(baseDecide), String(prodDecide));
  const refUrl = import.meta.resolve("../../eval/reference/decide.ts");
  const prodUrl = import.meta.resolve("../../src/core/index.ts");
  assert.notEqual(refUrl, prodUrl);
  assert.ok(!refUrl.includes("/src/"));
  const dir = new URL("../../eval/reference/", import.meta.url);
  const files = readdirSync(dir).filter((n) => n.endsWith(".ts"));
  assert.ok(files.length >= 6);
  const specRe = /(?:from\s+|import\s*\(\s*|import\s+)["']([^"']+)["']/g;
  for (const f of files) {
    const text = readFileSync(new URL(f, dir), "utf8");
    for (const m of text.matchAll(specRe)) {
      const spec = m[1] as string;
      if (spec.startsWith("node:")) continue;
      assert.ok(spec.startsWith("./"), `${f}: non-local import ${spec}`);
      assert.ok(!/src[\\/]/.test(spec) && !spec.includes(".."), `${f}: imports from src/ or parent: ${spec}`);
    }
  }
  // the harness wires the reference from ../reference and production from src/core only through its public index
  const harness = readFileSync(new URL("../../eval/diff/run-diff.ts", import.meta.url), "utf8");
  assert.match(harness, /from "\.\.\/\.\.\/src\/core\/index\.ts"/);
  assert.match(harness, /from "\.\.\/reference\/index\.ts"/);
});

test("(5) reports carry the harness version and reference file hashes", () => {
  assert.equal(honest.harness_version, HARNESS_VERSION);
  const h = referenceHashes();
  assert.deepEqual(honest.reference_files_sha256, h);
  for (const [name, hash] of Object.entries(h)) {
    assert.match(hash, /^[0-9a-f]{64}$/);
    assert.ok(name.endsWith(".ts"));
  }
  assert.ok("decide.ts" in h && "policy.ts" in h && "request.ts" in h && "matchers.ts" in h);
});
