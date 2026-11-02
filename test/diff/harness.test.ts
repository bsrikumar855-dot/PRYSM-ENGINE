import { test } from "node:test";
import assert from "node:assert/strict";
import { runDiff } from "../../eval/diff/run-diff.ts";
import { derive } from "../../eval/diff/prng.ts";
import { genPolicy } from "../../eval/diff/gen-policy.ts";
import { genCase } from "../../eval/diff/gen-request.ts";
import { describe } from "../../eval/diff/describe.ts";
import { refLoadPolicy } from "../../eval/reference/index.ts";

function strip(r: ReturnType<typeof runDiff>): unknown {
  return { ...r, elapsed_ms: undefined };
}

test("harness is deterministic for the same seed", () => {
  const a = runDiff({ cases: 400, seed: 7, minimise: false });
  const b = runDiff({ cases: 400, seed: 7, minimise: false });
  assert.equal(a.case_digest, b.case_digest);
  assert.equal(a.result_digest, b.result_digest);
  assert.deepEqual(strip(a), strip(b));
  const c = runDiff({ cases: 400, seed: 8, minimise: false });
  assert.notEqual(a.case_digest, c.case_digest);
});

test("generators: same stream gives same policy/request; policies load in reference", () => {
  for (let i = 0; i < 30; i++) {
    const p1 = genPolicy(derive(5, i, 0));
    const p2 = genPolicy(derive(5, i, 0));
    assert.equal(p1.text, p2.text);
    refLoadPolicy(p1.text);
    const c1 = genCase(derive(5, i, 1), p1);
    const c2 = genCase(derive(5, i, 1), p2);
    assert.equal(describe(c1.request, true), describe(c2.request, true));
  }
});

test("quick differential smoke: completes and reports (disagreements are reported, not asserted)", () => {
  const r = runDiff({ cases: 1500, seed: "smoke", minimise: true });
  assert.equal(r.cases, 1500);
  assert.equal(r.decide.compared, 1500);
  assert.equal(r.decide.agree + r.decide.disagree, 1500);
  assert.equal(r.decide.ref_engine_error, 0, "reference must not hit internal errors");
  assert.ok(r.decide_disagreements.length <= 30);
  assert.ok(Object.keys(r.decide.outcome_histogram).length >= 5);
  assert.equal(r.load.valid_policies, r.policies);
  assert.match(r.case_digest, /^sha256:[0-9a-f]{64}$/);
  JSON.stringify(r);
  if (r.decide.disagree > 0 || r.load.mutated_disagree > 0) {
    console.log(`# diff smoke reported ${r.decide.disagree} decide and ${r.load.mutated_disagree} load disagreements`);
  }
});
