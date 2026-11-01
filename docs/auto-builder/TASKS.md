# Execution backlog

## Status (update after every task — this is the resume point after compaction)

| Field | Value |
|---|---|
| Current phase | Phase 5 implementation (Checkpoint A approved: "Approve, mock only", DEC-15/16) |
| Current milestone | M3 gate passed (3 of 5 passes) → M4 CLI + static report next |
| Pass for this milestone (budget: 5 by default; edit here) | M3 closed after 3 / 5 passes (0 / 5 for M4) |
| Total passes, all milestones | 10 |
| Failing checks → attempts (one line per distinct check; max 3 each) | F-01..F-09: closed except F-05(glob only)/F-07 partial; N-01 deny/unparseable: 1 attempt; N-02 metering: 1; N-03 mutable toolInfo: 1; N-04 hidden chars: 2 (F-07 then N-04) |
| Last verified commit | 2e6848e (M0) |
| Independent review done for current milestone? | M3: yes (security-engineer x2 passes, critical-reviewer x2, qa-engineer blind plan + black-box ~95 scenarios); M3 pass-3 residual fixes (exit code, stall shutdown, caps) verified by lead via CLI probes + tests, not re-reviewed |

## Milestone gates

Budget: 5 implement→verify passes per milestone, 3 attempts per failing check. Independent review (critical-reviewer + qa-engineer, plus security-engineer where security gate applies) at end of M2, M3, M5 and final M6.

| Milestone | Expected outcome | Verification command(s) | Tests run | Regression run | Review (independent?) | Criteria verified | Docs updated | Open blocker/major | Gate passed |
|---|---|---|---|---|---|---|---|---|---|
| M0 Scaffold + toolchain | TS project, test runner, lint/typecheck, `npm ci`; `node:sqlite` smoke test passes on this Windows machine (open, WAL, BEGIN IMMEDIATE, concurrent reader, crash-recovery) or fallback chosen behind store interface | `npm test`, `npm run typecheck`, `npm run smoke:sqlite` | – | – | not required (mechanical) | – | – | – | no |
| M1 Core: canonicalise + `decide()` | JSON policy loader (strict), JCS hash, plain-JSON snapshot, deny-overrides `decide()`, matchers (domain, path-within, glob, in/equals/range), explanations, limits; property tests (order independence, deny monotonicity, determinism, idempotence), start adversarial corpus (P-01,06,11,12,13,14,15). **Cedar differential: deferred to M5 (DEC-21)** | `npm test -- core`, `npm run corpus` | `npm test` 107/107; `npm run corpus` 563/563 | typecheck clean; core import test | security-engineer x2 + critical-reviewer x2 (independent); N-01..N-04 pending re-check in M2 gate | A-02/07/16/17 partial, A-19 verified (see checklist) | POLICY-SPEC v1.3, DECISIONS DEC-19..22, SECURITY-REVIEW | none open Critical/High; Medium/Low N-01..N-04 fixed, unverified | yes (with caveats) |
| M2 Store + guard | SQLite hash-chained store behind narrow interface, sync decision-before-execute, fault-injection tests, concurrency test, verify-chain, anchor, retention checkpoint, redaction choke point, HMAC digests, session taint, fail-mode matrix | `npm test -- store guard` (verify-chain CLI script moved to M4, DEC-24) | `npm test` 233/233; `npm run corpus` 563/563; QA black-box 119/123 (2 deviations fixed) | typecheck clean; M1 suite green | independent: security-engineer x3, critical-reviewer, qa-engineer | A-01, A-05, A-06, A-13 (see checklist) | AUDIT-SPEC v1.3, DEC-23..26, SECURITY-REVIEW | none Critical/High; M2-21 Medium/Low and M2-22 Low tracked | yes |
| M3 MCP stdio proxy | Proxy over same core; e2e against a real local MCP server; unauthorized/unknown/tainted calls never reach server; control channel for taint (or documented in-process-only) | `npm test -- proxy`, `npm run demo:e2e` | `npm test` 308 pass / 1 skipped (SIGTERM not testable on Windows); corpus 563/563; QA black-box ~95 scenarios no enforcement defect | typecheck clean; M1/M2 suites green | independent: security-engineer x2, critical-reviewer x2, qa-engineer | A-18 (see checklist) | PROXY-SPEC v1.3, DEC-27..30, SECURITY-REVIEW, README | none Critical/High; M3-11 Low (documented), SIGINT/SIGTERM untested | yes (with caveats) |
| M4 CLI + static report | `validate, explain, events, verify-chain, anchor, simulate`; self-contained HTML report incl. events, explanations, policy versions, chain status, real-event metrics; empty state | `npm test -- cli report` | – | – | qa-engineer | – | – | – | no |
| M5 Benchmark + real-model scenario | Labelled corpus (≥30/class) + benign ≥200 traces, second-party labels, FN/FP with Wilson intervals, baselines; latency bench (p50/p95/p99, cold/warm, concurrency, FULL vs NORMAL); Cedar differential test on shared tool/scope subset (deferred from M1, DEC-21); second blind-labeller pass for the extended fixture (any_in, string[], agents, equals/in/max_length, domain_exact, host accept, session_tainted opt-in, monitor_only); real-LLM injection scenario (A-15, owner-approved model) | `npm run bench`, `npm run eval` | – | – | **independent review gate** | – | – | – | no |
| M6 Docs, optional live viewer, final review | Docs reflect actual behaviour and limits; optional hardened live viewer; final whole-project review + security review; delivery report | full suite | – | – | final independent review | – | – | – | no |

## Acceptance checklist

| ID | Criterion (measurable) | State | Evidence |
|---|---|---|---|
| A-01 | Denied tool function invoked 0 times (call counter); result carries decision_id and reason_code; `explain` shows rule id | Verified (M2, in-process guard) | guard tests: denied tool invoked 0 times for default-deny, rule-deny, unknown-tool, tainted, invalid args; QA black-box G-deny-* all PASS; decision row visible to the tool during execution; snapshot identity/mutation tests |
| A-02 (replaced) | Same DecisionRequest ⇒ byte-identical decision over 1000 runs, shuffled rule order, on Windows (+Linux if available) | Partially verified (M1) | Property tests (shuffle incl. policy_version equality, 1000-repeat determinism) pass via `npm test`; Windows only, deepEqual rather than byte-compare; Linux not run |
| A-03 | `prysm explain <id>` prints rule/version/reason/redacted args; exit 0 known, non-zero unknown | Untested | – |
| A-04 | `npm run bench` reports p50/p95/p99 over ≥10,000 evals vs hypotheses (decide p99 <1 ms @200 rules; guard overhead with sync audit <10 ms; both recorded even if missed) | Untested | – |
| A-05 | Canary secret absent from args/results/model_meta/errors/stack/engine_error/CLI/export/report/digest | Verified (M2) | canary scan of .db/-wal/-shm/.key, sink, exports, errors in 12+ encodings: 0 hits (repo test + independent QA CAN-matrix with positive control) |
| A-06 | Forced engine exception ⇒ all calls deny, `engine_error` event; no fail-open on engine error | Verified (M2) | forced engine error / non-loaded policy / hmac throw => blocked unavailable, no execution, engine_error row; never fail-open |
| A-07 | ≥15 precedence cases + property tests pass; any rule change changes version hash; semantically-equal files same hash | Partially verified (M1) | 27 numbered behaviour cases + property tests pass; rule reorder keeps version, mode change changes it (pending final M1 gate re-verification) |
| A-08 | Report/viewer empty on empty store; after demo count equals `prysm events --count`; no seeded fixtures in runtime path (grep) | Untested | – |
| A-09 | Fresh clone → first blocked call time recorded (target ≤30 min) | Untested | – |
| A-10 | Swapping example model adapter leaves policy unchanged | Untested | – |
| A-11 | Docs state limits: only routed calls enforced; proxy must be sole path; provenance asserted; advisory heuristics; tamper-evident not tamper-proof | Untested | – |
| A-12 | Benchmark per DEC-08 executed; FN/FP + intervals + corpus sizes reported; thresholds met or misses reported | Untested | – |
| A-13 | `verify-chain` detects modified, deleted-middle, reordered rows; tail deletion detected via anchor; concurrent writers yield linear chain | Verified (M2) | tamper tests (mutate, delete-middle, reorder, tail delete via anchor, rewrite via anchor, forged checkpoint), 5-6 process concurrent writers linear chain; limits documented: unkeyed chain needs external anchor |
| A-14 | (if live viewer built) wrong Host/Origin ⇒ 403, missing token ⇒ 401, XSS payload rendered as text, traversal ⇒ 404 | Untested | – |
| A-15 | Real-LLM injection scenario — NOT PERFORMED (owner chose mock only, DEC-16); mock-scripted scenario only, labelled unit-level | Out of scope by owner decision | n/a |
| A-16 | Unknown tool ⇒ deny; unregistered/changed tool schema hash ⇒ deny; extra args rejected | Partially verified (M1) | unknown tool/extra args denied (tests + corpus); `schema_hash` is stored but NOT enforced until M3 — untested |
| A-17 | Sink differential: for each matcher vector table, decision matches what the real sink would touch | Partially verified (M1: decide side only) | Matcher vector tables + 563-case corpus pass; no real sink exists until M2/M5 helpers |
| A-18 | Proxy e2e: forbidden call never reaches real MCP server (server-side counter 0); allowed call does | Verified (M3, fixture MCP server, mock-scripted) | e2e tests through the real CLI: forbidden/unknown/hidden/pinned/tainted calls leave the server-side counter at 0, allowed call once with the guard snapshot args; independent QA ran ~95 scenarios black-box with the same result; limits: only fixture server (running third-party servers was blocked), Windows only, SIGINT/SIGTERM untested |
| A-19 | Core import-graph test: no net/http/child_process/fetch/store imports in `src/core` | Verified (M1, regex heuristic) | `test/core-imports.test.ts` passes; static pattern check, not a full module-graph analysis |

## Tasks (milestone-level; sub-tasks expanded at milestone start)

| ID | Task | Milestone | Dependencies | Acceptance criteria | Verification | Status | Owner | Files owned |
|---|---|---|---|---|---|---|---|---|
| T-0.1 | Scaffold package, tsconfig, test runner (node:test), lint, scripts | M0 | approval | `npm test` runs | `npm test` | pending | lead | root config |
| T-0.2 | node:sqlite Windows smoke test | M0 | T-0.1 | all smoke assertions pass or fallback recorded | `npm run smoke:sqlite` | pending | backend-engineer | `smoke/`, |
| T-1.1 | Policy schema + strict loader + JCS hash | M1 | T-0.1 | A-07 | tests | pending | backend-engineer | `src/core/policy*` |
| T-1.2 | Snapshot/canonicaliser + matchers | M1 | T-1.1 | A-17 (part) | tests | pending | backend-engineer | `src/core/canon*, matchers*` |
| T-1.3 | `decide()` + explanations + limits | M1 | T-1.1 | A-02, A-07 | tests | pending | backend-engineer | `src/core/decide*` |
| T-1.4 | Adversarial corpus v1 (labels by qa-engineer) | M1 | T-1.1 spec | corpus ≥ start | `npm run corpus` | pending | qa-engineer proposes, lead writes | `eval/` |
| T-2.x | Store, chain, guard, redaction, taint, fault-injection | M2 | M1 | A-01,05,06,13,16,19 | tests | done (gate passed) | backend-engineer | `src/store, src/guard` |
| T-3.x | MCP proxy + e2e | M3 | M2 | A-18 | e2e | pending | backend-engineer | `src/proxy` |
| T-4.5 | Coalesce repeated deny rows / per-session budgets (M2-21) | M4 | M2 | after deny flood a distinct rule-denied call is still recorded | tests | pending | backend-engineer | `src/guard` |
| T-6.5 | ACL principal full-name/SID compare (M2-22a); tools_replaced identity (M2-22b) | M6 | M2 | tests | tests | pending | backend-engineer | `src/store` |
| T-4.6 | M4 consumers filter policy_activate rows on outcome.event (proxy_config/proxy_client/tools_replaced); report shows proxy posture | M4 | M3 | report lists posture rows | tests | pending | frontend-engineer | `src/report` |
| T-6.6 | Split proxy.ts (~1000 lines) into registry/client/server/lifecycle modules; backpressure+provenance CLI mutation checks; SIGINT/SIGTERM test on a real console; third-party MCP server compatibility test (needs owner permission) | M6 | M3 | – | review | pending | backend-engineer | `src/proxy` |
| T-4.x | CLI + static report | M4 | M2 | A-03,08 | tests | pending | backend-engineer + frontend-engineer | `src/cli, src/report` |
| T-5.x | Benchmark, benign set, real-LLM scenario | M5 | M3 | A-04,12,15 | bench/eval | pending | ai-engineer + qa-engineer | `bench/, eval/, examples/` |
| T-6.x | Docs, live viewer (optional), final reviews | M6 | M5 | A-09,10,11,14 | review | pending | lead | `docs/, README` |

## Blockers
Awaiting owner approval at Checkpoint A (decisions DEC-09, DEC-12, DEC-13, licence).

## Deferred / out of scope (needs user approval)
Layer 2 enforcement, approvals/quarantine/escalation, governance reports/inventory UI, learned risk scoring, hosted multi-tenant, YAML policies, AgentDojo subset, Cedar/OPA runtime.

## Recently completed
Discovery: research, product scope, architecture draft, three independent challenges, v2 resolutions (DECISIONS.md).
