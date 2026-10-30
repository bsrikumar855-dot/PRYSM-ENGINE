# PRYSM — Requirements (v1 + v2 changes)

**v2 notes:** the authoritative acceptance checklist is in `TASKS.md` (A-01..A-19; A-02 replaced because the original was true by construction; A-15 real-model scenario, A-16..A-19 added). F-07 (model wrapper) moves out of core to `examples/`; F-12 deferred; F-13 becomes session taint + asserted tags (DEC-04); F-17 MCP proxy is promoted to **Must** (DEC-01); policy format JSON (DEC-02). See `DECISIONS.md`.

Source: product-manager report (2026-10-30), adopted with lead edits. All numeric targets are hypotheses validated by benchmark, never claims.

## Personas
P1 agent developer (primary) · P2 security/platform engineer · P3 red-teamer · P4 governance lead (later) · P5 approver (later).

## Journeys
J1 wrap tools, see why a call was blocked · J2 injection text cannot change a decision · J3 simulate a policy change (Should) · J4 engine failure → configured fail mode.

## Functional (M=Must for MVP, S=Should, C=Could, L=Later)
| ID | Pri | Requirement |
|---|---|---|
| F-01 | M | Tool-call interception: agent reaches tools only via guarded handles; allow/block decided before execution with arguments evaluated |
| F-02 | M | Versioned declarative policy, default deny, explicit precedence, version = content hash |
| F-03 | M | Decision explanation: rule id, policy version, reason code, evaluated (redacted) fields, losing rules |
| F-04 | M | Effects in MVP: allow, block, redact; other actions exist as schema values only and are rejected if used in a rule |
| F-05 | M | Fail mode per tool and risk level |
| F-06 | M | Local append-only hash-chained audit store, redacted/hashed by default |
| F-07 | M | Model-invocation wrapper with provider adapter interface (mock + optional real); records model metadata and proposed tool calls |
| F-08 | M | CLI: validate, explain, events, verify-chain, demo |
| F-09 | M | Local read-only viewer over real events only; empty state when none |
| F-10 | M | Host-supplied identity/context per call (agentId, userId, scopes) |
| F-11 | S | Policy simulation/replay with decision diff |
| F-12 | S | Input/output rule hooks with regex/allowlist detectors (secrets, PII, injection patterns), labelled advisory |
| F-13 | S | Provenance labels as policy input (caller-supplied; see DECISIONS) |
| F-14 | S | Heuristic risk score as policy *input* (never override) |
| F-15 | S | Measured latency / FP-FN metrics surfaced in CLI/viewer from real runs |
| F-16 | C | Tool/agent inventory derived from observed calls |
| F-17 | C | MCP stdio proxy mode (first "later" item; revisit after architect review) |
| F-18 | L | RAG provenance enforcement, approvals, quarantine, escalation, governance reports, hosted multi-tenant |

## Non-functional hypotheses
N-01 p95 `decide()` < 5 ms, p99 < 20 ms, ≤200 rules, in-process (report, don't hide misses) · N-02 10,000 repeated evaluations identical · N-03 clone→first blocked call ≤ 30 min · N-04 canary secret in args appears in 0 stored events/viewer output by default · N-05 forced engine error → 100% of high-risk calls denied · N-06 runs offline, no Docker/paid service · N-07 swapping model adapter changes 0 policy files · N-08 no path to a guarded tool except through the guard (in-process limits documented).

## Acceptance criteria
A-01 denied tool function invoked 0 times (counter test), result shows rule_id · A-02 20+ injection/override strings → identical decision (rule+version) · A-03 `prysm explain <id>` prints rule/version/reason/redacted args; exit 0 known, non-zero unknown · A-04 `npm run bench` reports p50/p95/p99 over ≥10,000 evals and records vs N-01 · A-05 canary secret absent from audit store + viewer · A-06 forced engine exception → high-risk deny + `engine_error` event · A-07 ≥15 precedence cases pass; rule change changes version hash · A-08 viewer empty on empty store; after demo count equals `prysm events --count`; no seeded fixtures in runtime path · A-09 fresh-clone timing recorded · A-10 adapter swap leaves policy files unchanged · A-11 docs state limits plainly (in-process only; advisory heuristics; no completeness claim).
Added by lead: A-12 benchmark defined: labelled adversarial tool-call corpus + benign tool-call trace set, FP and FN rates reported with corpus size and construction method, no extrapolation · A-13 `verify-chain` detects a modified/deleted event · A-14 viewer rejects requests without token / wrong Host header.
