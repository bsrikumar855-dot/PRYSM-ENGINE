# Execution backlog

## Status (update after every task — this is the resume point after compaction)

| Field | Value |
|---|---|
| Current phase | Phase 4 complete → **waiting at Checkpoint A (owner approval)**; no implementation started |
| Current milestone | none (M0 next) |
| Pass for this milestone (budget: 5 by default; edit here) | 0 / 5 |
| Total passes, all milestones | 0 |
| Failing checks → attempts (one line per distinct check; max 3 each) | none |
| Last verified commit | none (no commits) |
| Independent review done for current milestone? | Discovery challenge: yes (architect, security-engineer, critical-reviewer; document review only) |

## Milestone gates

Budget: 5 implement→verify passes per milestone, 3 attempts per failing check. Independent review (critical-reviewer + qa-engineer, plus security-engineer where security gate applies) at end of M2, M3, M5 and final M6.

| Milestone | Expected outcome | Verification command(s) | Tests run | Regression run | Review (independent?) | Criteria verified | Docs updated | Open blocker/major | Gate passed |
|---|---|---|---|---|---|---|---|---|---|
| M0 Scaffold + toolchain | TS project, test runner, lint/typecheck, `npm ci`; `node:sqlite` smoke test passes on this Windows machine (open, WAL, BEGIN IMMEDIATE, concurrent reader, crash-recovery) or fallback chosen behind store interface | `npm test`, `npm run typecheck`, `npm run smoke:sqlite` | – | – | not required (mechanical) | – | – | – | no |
| M1 Core: canonicalise + `decide()` | JSON policy loader (strict), JCS hash, plain-JSON snapshot, deny-overrides `decide()`, matchers (domain, path-within, glob, in/equals/range), explanations, limits; property tests (order independence, deny monotonicity, determinism, idempotence), Cedar differential on shared subset; start adversarial corpus (P-01,06,11,12,13,14,15) | `npm test -- core`, `npm run corpus` | – | – | security-engineer re-check of P-01/06/11/13/14 | – | – | – | no |
| M2 Store + guard | SQLite hash-chained store behind narrow interface, sync decision-before-execute, fault-injection tests, concurrency test, verify-chain, anchor, retention checkpoint, redaction choke point, HMAC digests, session taint, fail-mode matrix | `npm test -- store guard`, `npm run verify-chain` | – | – | **independent review gate** (critical-reviewer, qa-engineer, security-engineer) | – | – | – | no |
| M3 MCP stdio proxy | Proxy over same core; e2e against a real local MCP server; unauthorized/unknown/tainted calls never reach server; control channel for taint (or documented in-process-only) | `npm test -- proxy`, `npm run demo:e2e` | – | – | **independent review gate** | – | – | – | no |
| M4 CLI + static report | `validate, explain, events, verify-chain, anchor, simulate`; self-contained HTML report incl. events, explanations, policy versions, chain status, real-event metrics; empty state | `npm test -- cli report` | – | – | qa-engineer | – | – | – | no |
| M5 Benchmark + real-model scenario | Labelled corpus (≥30/class) + benign ≥200 traces, second-party labels, FN/FP with Wilson intervals, baselines; latency bench (p50/p95/p99, cold/warm, concurrency, FULL vs NORMAL); real-LLM injection scenario (A-15, owner-approved model) | `npm run bench`, `npm run eval` | – | – | **independent review gate** | – | – | – | no |
| M6 Docs, optional live viewer, final review | Docs reflect actual behaviour and limits; optional hardened live viewer; final whole-project review + security review; delivery report | full suite | – | – | final independent review | – | – | – | no |

## Acceptance checklist

| ID | Criterion (measurable) | State | Evidence |
|---|---|---|---|
| A-01 | Denied tool function invoked 0 times (call counter); result carries decision_id and reason_code; `explain` shows rule id | Untested | – |
| A-02 (replaced) | Same DecisionRequest ⇒ byte-identical decision over 1000 runs, shuffled rule order, on Windows (+Linux if available) | Untested | – |
| A-03 | `prysm explain <id>` prints rule/version/reason/redacted args; exit 0 known, non-zero unknown | Untested | – |
| A-04 | `npm run bench` reports p50/p95/p99 over ≥10,000 evals vs hypotheses (decide p99 <1 ms @200 rules; guard overhead with sync audit <10 ms; both recorded even if missed) | Untested | – |
| A-05 | Canary secret absent from args/results/model_meta/errors/stack/engine_error/CLI/export/report/digest | Untested | – |
| A-06 | Forced engine exception ⇒ all calls deny, `engine_error` event; no fail-open on engine error | Untested | – |
| A-07 | ≥15 precedence cases + property tests pass; any rule change changes version hash; semantically-equal files same hash | Untested | – |
| A-08 | Report/viewer empty on empty store; after demo count equals `prysm events --count`; no seeded fixtures in runtime path (grep) | Untested | – |
| A-09 | Fresh clone → first blocked call time recorded (target ≤30 min) | Untested | – |
| A-10 | Swapping example model adapter leaves policy unchanged | Untested | – |
| A-11 | Docs state limits: only routed calls enforced; proxy must be sole path; provenance asserted; advisory heuristics; tamper-evident not tamper-proof | Untested | – |
| A-12 | Benchmark per DEC-08 executed; FN/FP + intervals + corpus sizes reported; thresholds met or misses reported | Untested | – |
| A-13 | `verify-chain` detects modified, deleted-middle, reordered rows; tail deletion detected via anchor; concurrent writers yield linear chain | Untested | – |
| A-14 | (if live viewer built) wrong Host/Origin ⇒ 403, missing token ⇒ 401, XSS payload rendered as text, traversal ⇒ 404 | Untested | – |
| A-15 | Real-LLM injection scenario — NOT PERFORMED (owner chose mock only, DEC-16); mock-scripted scenario only, labelled unit-level | Out of scope by owner decision | n/a |
| A-16 | Unknown tool ⇒ deny; unregistered/changed tool schema hash ⇒ deny; extra args rejected | Untested | – |
| A-17 | Sink differential: for each matcher vector table, decision matches what the real sink would touch | Untested | – |
| A-18 | Proxy e2e: forbidden call never reaches real MCP server (server-side counter 0); allowed call does | Untested | – |
| A-19 | Core import-graph test: no net/http/child_process/fetch/store imports in `src/core` | Untested | – |

## Tasks (milestone-level; sub-tasks expanded at milestone start)

| ID | Task | Milestone | Dependencies | Acceptance criteria | Verification | Status | Owner | Files owned |
|---|---|---|---|---|---|---|---|---|
| T-0.1 | Scaffold package, tsconfig, test runner (node:test), lint, scripts | M0 | approval | `npm test` runs | `npm test` | pending | lead | root config |
| T-0.2 | node:sqlite Windows smoke test | M0 | T-0.1 | all smoke assertions pass or fallback recorded | `npm run smoke:sqlite` | pending | backend-engineer | `smoke/`, |
| T-1.1 | Policy schema + strict loader + JCS hash | M1 | T-0.1 | A-07 | tests | pending | backend-engineer | `src/core/policy*` |
| T-1.2 | Snapshot/canonicaliser + matchers | M1 | T-1.1 | A-17 (part) | tests | pending | backend-engineer | `src/core/canon*, matchers*` |
| T-1.3 | `decide()` + explanations + limits | M1 | T-1.1 | A-02, A-07 | tests | pending | backend-engineer | `src/core/decide*` |
| T-1.4 | Adversarial corpus v1 (labels by qa-engineer) | M1 | T-1.1 spec | corpus ≥ start | `npm run corpus` | pending | qa-engineer proposes, lead writes | `eval/` |
| T-2.x | Store, chain, guard, redaction, taint, fault-injection | M2 | M1 | A-01,05,06,13,16,19 | tests | pending | backend-engineer | `src/store, src/guard` |
| T-3.x | MCP proxy + e2e | M3 | M2 | A-18 | e2e | pending | backend-engineer | `src/proxy` |
| T-4.x | CLI + static report | M4 | M2 | A-03,08 | tests | pending | backend-engineer + frontend-engineer | `src/cli, src/report` |
| T-5.x | Benchmark, benign set, real-LLM scenario | M5 | M3 | A-04,12,15 | bench/eval | pending | ai-engineer + qa-engineer | `bench/, eval/, examples/` |
| T-6.x | Docs, live viewer (optional), final reviews | M6 | M5 | A-09,10,11,14 | review | pending | lead | `docs/, README` |

## Blockers
Awaiting owner approval at Checkpoint A (decisions DEC-09, DEC-12, DEC-13, licence).

## Deferred / out of scope (needs user approval)
Layer 2 enforcement, approvals/quarantine/escalation, governance reports/inventory UI, learned risk scoring, hosted multi-tenant, YAML policies, AgentDojo subset, Cedar/OPA runtime.

## Recently completed
Discovery: research, product scope, architecture draft, three independent challenges, v2 resolutions (DECISIONS.md).
