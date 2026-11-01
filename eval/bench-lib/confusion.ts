// Confusion counting for decision cases. FN = expected deny, got permit. FP = expected permit, got deny.
import { wilson } from "./stats.ts";
import type { Interval } from "./stats.ts";

export type Effect = "permit" | "deny";
export interface Outcome {
  id: string; class: string;
  expectedEffect: Effect; expectedReason?: string | undefined;
  gotEffect: Effect | "error"; gotReason: string;
  why?: string | undefined;
}

export interface Tally {
  n: number;
  expected_deny: number; expected_permit: number;
  true_deny: number; true_permit: number;
  fn: number; fp: number;
  effect_mismatch: number;
  reason_mismatch: number; // effect right, reason_code differs (only counted where a reason was labelled)
  harness_error: number;
}
export interface ClassSummary extends Tally { fn_rate: Interval; fp_rate: Interval }

export const emptyTally = (): Tally => ({ n: 0, expected_deny: 0, expected_permit: 0, true_deny: 0, true_permit: 0, fn: 0, fp: 0, effect_mismatch: 0, reason_mismatch: 0, harness_error: 0 });

export function addOutcome(t: Tally, o: Outcome): void {
  t.n++;
  if (o.expectedEffect === "deny") t.expected_deny++; else t.expected_permit++;
  if (o.gotEffect === "error") { t.harness_error++; t.effect_mismatch++; return; }
  if (o.gotEffect !== o.expectedEffect) {
    t.effect_mismatch++;
    if (o.expectedEffect === "deny") t.fn++; else t.fp++;
    return;
  }
  if (o.expectedEffect === "deny") t.true_deny++; else t.true_permit++;
  if (o.expectedReason !== undefined && o.expectedReason !== o.gotReason) t.reason_mismatch++;
}

export function summarize(t: Tally): ClassSummary {
  return { ...t, fn_rate: wilson(t.fn, t.expected_deny), fp_rate: wilson(t.fp, t.expected_permit) };
}

export interface Aggregate { per_class: Record<string, ClassSummary>; overall: ClassSummary }

/** Per-class and overall aggregation. Keys are sorted so JSON output is stable. */
export function aggregate(outcomes: readonly Outcome[]): Aggregate {
  const by = new Map<string, Tally>();
  const all = emptyTally();
  for (const o of outcomes) {
    let t = by.get(o.class);
    if (!t) { t = emptyTally(); by.set(o.class, t); }
    addOutcome(t, o); addOutcome(all, o);
  }
  const per_class: Record<string, ClassSummary> = {};
  for (const k of [...by.keys()].sort()) per_class[k] = summarize(by.get(k)!);
  return { per_class, overall: summarize(all) };
}
