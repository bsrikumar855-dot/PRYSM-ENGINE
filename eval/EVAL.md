# Policy-decision accuracy benchmark (`npm run eval`)

Implements BENCH-SPEC sections 1 and 2. Deterministic: `decide()` is a pure function, so the question measured is "does policy plus engine give the intended outcome on this labelled corpus", not "does a detector catch attacks".

## Commands
- `npm run eval` prints the human table.
- `npm run eval -- --json` prints the machine summary (schema_version 1; deterministic, no timestamps).
- `npm run eval -- --out file.json` also writes the JSON summary.
- `npm run eval -- --allow-mismatch` exploration mode (see exit codes).
- Optional: `--corpus-dir`, `--benign-dir`, `--policy` to point at other inputs.
- Tests: `node --test test/eval/benchmark.test.ts` (also run by `npm test`).

## Exit codes
0 whenever the run completes: accuracy numbers (FN, FP, intervals, benign false positives) are information, not pass/fail. 1 if any case in the pinned attack corpus disagrees with its label on EFFECT, or any `policy_load_abuse` case disagrees on load behaviour (same semantics as `npm run corpus`). `--allow-mismatch` keeps the mismatches listed but exits 0. Every mismatching case id is printed with expected and got.

## Definitions
- **FN**: expected `deny`, engine `permit` (an attack or unauthorised call the policy lets through).
- **FP**: expected `permit`, engine `deny` (a legitimate call blocked).
- FN rate = FN / expected-deny cases. FP rate = FP / expected-permit cases. Each has a Wilson 95% score interval (z = 1.959964). Zero is phrased "0 of N, 95% upper bound x%".
- **Reason-code agreement** is separate: the effect is right but `reason_code` differs from the label. It is counted per class (`reason` column) and never contributes to FN/FP.
- **Harness error** (the request could not be built or the engine function threw): counted as an effect mismatch, but is neither FN nor FP.
- **Load behaviour**: `policy_load_abuse` cases test `loadPolicy()` accepting or rejecting policy text. They are not decisions, are excluded from FN/FP and the per-class table, and are reported as "k/N agree".
- Rates are per class and overall, over this corpus only. No extrapolation.

## Corpora and provenance
- Attack/near-miss: `eval/corpus/*.jsonl`, later files override earlier by id. Provenance is read from the `why` text: a `LEAD-DERIVED` marker means lead-written and not independent; everything else is counted blind-labeller. The summary also gives counts by `why` prefix (`v1.1`, `v1.2 relabel`, `v1.3 relabel`, unprefixed v1 original). The current corpus has 0 lead-derived cases. The prefix-based split is only as accurate as the `why` text.
- Benign set: `eval/benign/*.jsonl` (optional; independent labeller, blind to the engine). Schema `{"id","class":"benign","request":{tool,args,ctx},"expected":{"effect":"permit"},"why","source"}`. A missing or empty directory prints `benign set: not present`. Malformed lines are listed as schema errors, never silently dropped; later duplicate ids override earlier.
- **Triage**: every benign FP is printed with the matching deny rule ids, matched reasons and the label's `why`. A human classifies each as (a) policy too strict, (b) labeller error, (c) engine defect. The runner never removes or edits cases.

## Baselines
- No guard: FN = 100% by construction (every attack call executes). Stated, not measured.
- Prompt-only guard: not measured. The owner chose a mock-only model (DEC-16); a scripted mock cannot say anything about real-model prompt compliance.

## How to read results
- The 563-case attack corpus is a regression pin. The engine agrees with the labels, which is not independent evidence the labels or engine are right (circularity, DEC-20). Zero mismatches means "no regression", not "proven secure".
- Upper bounds shrink only with more cases: with 0 of 348 the 95% upper bound is about 1.1%, so a true FN rate of up to that is still consistent with the data.
- Near-miss classes with few expected-permit cases have wide FP intervals (for example 0 of 5 gives an upper bound of 43%).
- FN/FP are properties of policy plus engine on these corpora. They are not detection rates against real attackers, and nothing here measures real-LLM behaviour or prompt-injection detection. Windows, single machine.
