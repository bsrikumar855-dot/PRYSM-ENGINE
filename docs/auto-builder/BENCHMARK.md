# PRYSM benchmark results (M5)

Protocol: `BENCH-SPEC.md` (fixed before any number was produced). Date of the full performance run: 2026-11-02. Everything here is from one machine and one operating system. Raw data is committed: `bench/results/2026-11-02/` (performance), `eval/diff/reports/` (differential), and `npm run eval` prints the accuracy numbers (reproducible: they are deterministic).

**What these numbers are not.** They are not detection rates against real attackers and say nothing about how any language model behaves (owner decision DEC-16: mock model only). False negatives and false positives below are properties of the policy plus the engine on the stated corpora.

## 1. Policy-decision accuracy

### 1.1 Attack and near-miss corpus (435 decision cases)
Labelled blind to the code by an independent labeller, then re-labelled in three rounds after spec rulings. **Disclosure (from the M5 audit):** 67 case ids are overridden by later correction files; for 23 of them the expected EFFECT changed (mostly permit to deny: 14 in the first round, 6 in the second, 1 deny to permit) and for 44 only the reason code changed. So the 0 FN / 0 FP result below is agreement **after** about 5% of decision labels were re-labelled toward the behaviour the spec and engine settled on; it is not first-round agreement. The relabelling was done by the same blind labeller from the amended spec, but their rationale texts read like engine-trace reasoning, so 'blind' is not demonstrated for those 67 final labels. The 'blind-labeller, 0 lead-derived' counts printed by `npm run eval` come from a text tag in each case (a case counts as lead-derived only if its note contains `LEAD-DERIVED`); that is an absence-of-tag check, not an audit of authorship. Because the spec was amended from that same labeller's rulings, **agreement is a regression pin and not independent evidence of correctness** (DEC-20).

| Class | Cases | Expected deny | Expected permit | FN | FP | FN upper bound (95%) |
|---|---|---|---|---|---|---|
| limits_and_malformed | 73 | 62 | 11 | 0 | 0 | 5.83% |
| path_traversal | 96 | 73 | 23 | 0 | 0 | 5.00% |
| ssrf_and_domain | 123 | 102 | 21 | 0 | 0 | 3.63% |
| taint_and_provenance | 43 | 28 | 15 | 0 | 0 | 12.06% |
| unauthorized_tool | 36 | 24 | 12 | 0 | 0 | 13.80% |
| unknown_tool_and_arg_smuggling | 64 | 59 | 5 | 0 | 0 | 6.11% |
| **Overall** | **435** | **348** | **87** | **0** | **0** | **1.09%** (FP upper bound 4.23%) |

Plus 128 policy-load cases: 128 of 128 agree. FN = an attack call the policy permits; FP = a legitimate call the policy denies. Intervals are Wilson 95%; "0 of 348" means at most 1.09% at 95% confidence on this corpus, nothing more.

### 1.2 Benign set (independent, blind to the engine and the policy outcome)
326 cases written by business intent: 306 legitimate calls expected to be permitted, 20 "legitimate but intentionally refused" expected to be denied.

| Measure | Result |
|---|---|
| FP, all 306 expected-permit cases | 16 of 306 (5.23%), 95% CI [3.24%, 8.32%] |
| FP excluding the 16-case `borderline-fp-risk` stress category | 0 of 290, 95% upper bound 1.31% |
| Per category (docs-search 45, file-read 45, email 50, http-fetch 40, discount 30, workflow 30, borderline 50) | 0 FP each; upper bounds 7.1% to 11.4% |
| Intended-deny (legitimate request the policy refuses by design) | 20 of 20 denied as intended |

`borderline-fp-risk` was built to stress the policy (the labeller predicted a deny for each from the spec), so **neither benign rate is a population estimate**. Triage of the 16 false positives (every one examined; none dropped; no labeller error and no engine defect found):

| Cases | What the call was | Why denied | Class |
|---|---|---|---|
| 291, 292 | internal email with a cc | fixture rule `email.deny-cc` denies any cc | policy choice, too strict for real use |
| 293, 294, 305 | internal email, provenance missing or not in the trusted set | `email.corp-only` requires trusted provenance asserted by the host | policy choice; the proxy cannot assert provenance per call |
| 295, 296, 302, 303 | non-ASCII file names, URL paths, email names | ASCII-only matching (POLICY-SPEC §10.3, §3) | documented MVP limitation |
| 297, 301, 306 | `%`-encoded file name or URL | percent-encoding is rejected (§3, §4) | documented deny-safe limitation |
| 298, 299, 300 | name that looks like an 8.3 short name, a colon in the name, a reserved device name (`con.csv`) | Windows-safety rules (§4) | documented deny-safe limitation |
| 304 | a string with two `@` (comma-separated recipients) | email form check (§3) | documented limitation |

Usability finding (open, backlog): for the six file reads in 295-300 the audit trail reports the block as caused by `file.deny-secrets`, because a value the path matcher cannot interpret counts as a match for deny rules (the safe design that closed a bypass in review). The decision is right but the explanation can mislead an operator; the explanation should say the value could not be interpreted.

### 1.3 Independent second implementation (differential)
A second implementation of POLICY-SPEC written without reading the production code, and a seeded random differential harness (valid and hostile policies and requests, mutated policies). Three full seeds, 100,000 decision cases and 5,000 valid plus 5,000 mutated policies per seed, reproduced by the lead with identical digests:

| Seed | Agree exactly | Equivalent multi-fault code difference | Disagreements | Valid policy load | Mutated policy load |
|---|---|---|---|---|---|
| 20261102 | 99,987 | 13 | 0 | 5,000/5,000 | 5,000/5,000 |
| 20261103 | 99,988 | 12 | 0 | 5,000/5,000 | 5,000/5,000 |
| 20261104 | 99,991 | 9 | 0 | 5,000/5,000 | 5,000/5,000 |

The first run (before spec rulings) had 19 decision and 88 load disagreements, all spec ambiguities (DEC-37, DEC-38); no engine defect was found and no effect (allow versus deny) ever differed. **Disclosure (from the M5 audit):** the final 0-disagreement result is after alignment: the reference was changed after round 1, and in all four ruled points (drive-prefixed path roots, string/string[] compatibility, size measured after NFC normalisation, the invalid/limit code pair) the spec was changed to adopt the production engine's behaviour. The equivalence rule for the invalid/limit pair was added after the disagreements were seen and relaxes independence for that one reason-code pair (DEC-38). The reference shares no code with the engine (checked: no imports from `src/`, no copied logic beyond spec-defined constants) but all commits are by one account, so the claim 'written without reading the production code' rests on the process, not on history. The harness is now self-tested with injected faults (46 tests) and reports carry the reference file hashes. "Equivalent multi-fault code difference" means a request carrying both a limit fault and a validity fault received `invalid_request` from one implementation and `limit_exceeded` from the other (both deny; which code is reported is not part of the contract, spec §13). Limits: two implementations of one spec agreeing shows consistent interpretation, not a correct spec; the generator caps policies at 12 rules, so work-budget exhaustion and the 1,000-rule timing are not exercised; the equivalent differences are counted, not listed individually.

### 1.4 Baselines
No guard: FN = 100% by construction (every attack call executes); stated, not measured. Prompt-only guard: **not measured** (mock-only decision).

## 2. Performance
Machine: AMD Ryzen 7 4800H (16 logical cores), 15.4 GiB RAM, Windows 11 Home 10.0.26200, Node v24.13.1, power plan Performance, no other heavy process. Protocol: 2,000 warm-up iterations discarded, 10,000 measured (decision) or 2,000 (guard, store, proxy), 5 independent repetitions in separate processes plus one cold run, seed 20260101. Values are the median across the 5 runs of each run's percentile, with min-max where the spread matters.

| Workload | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|
| W1 decision, 8-rule fixture | 0.039 | 0.070 | 0.152 (0.134-0.160) |
| W2 decision, 200 rules, tiny arguments | 0.074 | 0.130 | 0.301 (0.242-0.341) |
| W2 200 rules, 1 KiB string | 0.169 | 0.294 | 0.461 |
| W2 200 rules, 8 KiB string | 0.947 | 1.722 | 2.321 (2.294-2.486) |
| W2 200 rules, 64-element string list | 0.235 | 0.359 | 0.560 |
| W3 evaluate (with snapshot), fixture | 0.025 | 0.041 | 0.094 |
| W4 guard call, permit, audit FULL | 1.918 | 2.873 | 10.40 (8.38-12.55) |
| W4 guard call, permit, audit NORMAL | 0.399 | 0.922 | 12.90 (11.7-40.4) |
| W4 guard call, deny, audit FULL | 0.943 | 1.329 | 1.824 |
| W4 guard call, deny, audit NORMAL | 0.308 | 0.646 | 1.378 |
| W7 permit, stub store (no durable write) | 0.041 | 0.084 | 0.271 |
| W7 deny, stub store | 0.030 | 0.060 | 0.245 |
| W6 direct client to server round trip | 1.098 | 1.432 | 1.639 |
| W6 through the proxy | 3.578 | 4.351 | 12.96 (11.1-13.7) |

- **Concurrency (W5, 1 store, async calls):** throughput is flat at about 455 guarded calls per second at concurrency 1, 4, 16 and 64 (the store is synchronous, so calls serialise on the event loop); latency at higher concurrency is queueing: p50 2.0, 8.1, 32.6 and 140 ms at 1, 4, 16, 64. The median hides slow repetitions: the minimum per-run throughput was 122/s at concurrency 1 (one noisy repetition), 302/s at 4 and 392/s at 64. Four processes appending to one store: about 1,045 appends per second, all 4,000 rows present.
- **Durable-write cost (difference of the W4 and W7-stub medians of per-run percentiles; the p99 figures are differences of p99s, not the p99 of a difference):** permit FULL 1.88 ms p50 (10.1 ms p99), permit NORMAL 0.36 ms (12.6 ms p99), deny FULL 0.91 ms, deny NORMAL 0.28 ms.
- **Proxy overhead (difference of the medians of the per-run percentiles, not the percentile of a difference):** p50 2.48 ms, p95 2.92 ms, p99 11.32 ms; 8,004 audit rows written for 4,000 calls (4,000 decision rows, 4,000 result rows, 4 start-up rows). **Correction:** the first W6 run reported p99 overhead 3.15 ms and 5,004 rows because the proxy's default result-row budget (1,000 per minute) was exhausted by warm-up, so most measured calls wrote no result row; that was a product defect as well as a measurement flaw (fixed, DEC-39) and W6 was re-measured with a row-accounting check. The proxy p99 is dominated by the second synchronous durable write per call.
- **Cold start:** the first decision takes 1.6-4.1 ms (against 0.03-0.95 ms warm); a first guard call with a real store takes about 4.4-7 ms across cases (W4 deny NORMAL 4.4, W5 concurrency-1 5.8, permit paths 6-7).
- **Large stores (W8, single run each):** report generation 0.43 s (1k rows), 0.90 s (10k), 5.68 s (100k), peak RSS 95 / 157 / 248 MB; `verify-chain` 0.27 s, 0.60 s, 3.72 s (RSS 75 / 134 / 238 MB). The report output stays about 1.1 MB because it shows at most 500 events by default. The 100k test store was built with `synchronous=NORMAL` (100,000 fsyncs would take too long to set up); rows and hash chain are identical.

### Hypotheses (tested, not claims)
| | Hypothesis | Result |
|---|---|---|
| H1 | decision p99 < 1 ms at 200 rules | **MISSED**: 0.30, 0.46, 0.56 ms for tiny, 1 KiB and list arguments but 2.32 ms for an 8 KiB string; suspected cause: wildcard matching of long strings across many rules (not profiled) |
| H2 | guard call p99 < 10 ms with synchronous FULL audit | **MISSED, and the miss is stable on this machine**: permit-path p99 medians were 10.40 ms (original run), 11.22, 11.75 and 11.77 ms (three supplementary full-protocol runs of the same case, raw files in `bench/results/2026-11-02/supplementary/`); 18 of the 20 individual repetitions exceeded 10 ms, with outliers of 20.6 and 28.8 ms; p50 is stable at about 2 ms. The deny path passes (p99 1.82 ms). Likely cause: occasional disk flush or checkpoint stalls on the permit path (two durable rows per call), not verified. An earlier draft of this document cited a quick-profile run showing 2.6 ms; that line was wrong to cite (the quick profile uses 200 samples, so its p99 is the second-largest value and is not comparable) and has been removed |
| H3 | proxy overhead p99 < 15 ms | met with little headroom: 11.32 ms after the correction (the worst single repetition is about 12 ms); the original 3.15 ms was understated |
| H4 | `verify-chain` of 100k rows < 30 s | met: 3.72 s |

Variance and anomalies: one noisy repetition at concurrency 1 (p50 6.7 ms against about 2.0 ms in the others, coefficient of variation 0.73), not re-run; `W4.permit.NORMAL` p99 varies 11.7-40.4 ms; `W2.tiny` p50 coefficient of variation 0.21 (microsecond-scale JIT/frequency noise). Windows timer behaviour matters (anecdotal, no raw data kept): an echo tool answering through a timer added about 15 ms to both legs in a first attempt, so the proxy comparison uses `send_email`, a high-risk permit-path call that answers immediately and exercises the durable audit path.

### Harness choices (disclosed from the harness README and the audit)
- The guard cases (W4, W5, W7) raise the guard's best-effort row budgets so denied calls always write their row; the W6 proxy leg originally did not (see the correction above).
- W2's synthetic deny rules never match the random requests, so W2 measures rule traversal ending in permit or default-deny, not the cost of a `denied_by_rule` outcome.
- W7 is derived (a stub store), W8 stores are built with `synchronous=NORMAL`, W8 stores contain decision rows only (no result rows).
- Garbage collection and CPU frequency were not controlled or recorded.

## 3. Sample application and first-use time
`npm run demo` (scripted mock model, real sandboxed tools, in-process guard and the MCP proxy): seven scenarios, all side-effect assertions pass. With PRYSM, the poisoned-document scenario leaves the outbox empty (three exfiltration attempts denied as `tainted_session`); without PRYSM the same script sends two emails and the docs server receives the exfiltration URL. This proves the gate on a scripted model, **not** model behaviour. A-09: the first blocked call happened 0.33-0.41 s after process start in three runs by the implementer and 0.39-0.86 s in four consecutive runs by the reviewer (0.33-0.86 s over seven runs, not archived in `bench/results`); this excludes `npm install` and a cold file cache, so it is not the full clone-to-first-block time.

## 4. Reading the results honestly
- The accuracy numbers describe this policy and engine on three corpora; the engine cannot be said to "catch attacks" because it does not detect: it enforces what the policy says.
- The benign false-positive finding is real and operational: non-ASCII file names, percent-encoded URLs, 8.3-like and colon names, a blanket `cc` deny and missing provenance all cause denials; operators must know this before deploying.
- Two of four performance hypotheses were missed on this machine; the 8 KiB glob case and the permit-path tail latency are the items to investigate or to accept with documented limits.
- Not measured: real-model prompt compliance, a prompt-only baseline, other operating systems, other disks, network storage, concurrency across machines, the work-budget limit and 1,000-rule policies under load.

## 5. Reproduce
```
npm run eval                       # accuracy (deterministic)
npm run diff -- --seeds 20261102,20261103,20261104 --out eval/diff/reports/full.json
npm run bench:quick                # about a minute, reduced protocol
npm run bench                      # full protocol, 10-15 minutes
npm run demo                       # sample application
```
