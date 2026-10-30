# PRYSM — Phase 1 Discovery & Architecture Proposal (v1 draft + v2 amendments)

**READ FIRST — v2 supersedes v1 where they conflict.** After independent challenge (architect, security-engineer, critical-reviewer) the binding resolutions are in `DECISIONS.md` (DEC-01..DEC-14), `SECURITY-REVIEW.md` and `TASKS.md`. Superseded v1 items: in-process-only guard (now proxy + in-process, DEC-01); YAML/priority/specificity/redact effect (DEC-02); audit/fail-open semantics (DEC-03); per-argument provenance as headline (DEC-04); five workspaces and `@prysm/models` (DEC-06); milestone order (TASKS.md); viewer-first (DEC-10); "full table in PROGRESS.md appendix" was a dangling reference — competitor detail lives in the researcher report summarised in §2 with [V]/[S]/[U] labels.

## v2 layer-by-layer scope (answers the brief's five layers + control plane)

| Layer / component | Design (deliverable now) | MVP status |
|---|---|---|
| L1 Prompt/input | Input hook calls the same policy engine with advisory detectors (secrets/PII/injection patterns); decisions never rely on LLM judges; allow/block/quarantine mapped to `deny`+flag | **Deferred** (design only); detectors are a crowded market |
| L2 Context/RAG | Trust labels on retrieved chunks → session taint + provenance tags; retrieval access validation as a tool-call policy on the retriever tool; document provenance records | **Designed; partially covered** by session taint (DEC-04); no retrieval enforcement |
| L3 Model invocation | Provider adapter interface, request/response metadata in audit, model routing as policy on a `model.invoke` pseudo-tool | **Deferred**; example adapters only in `examples/` |
| L4 Tool/agent | Proxy + in-process guard, deny-overrides policy, strict args, unknown-tool deny, taint restriction, pre-execution durable audit | **Built (MVP core)** |
| L5 Output | Output hook: redact/block via policy + advisory detectors; audit-path redaction | **Deferred** (audit-path redaction only) |
| Policy engine | DEC-02 | Built |
| Risk engine | Static tool risk tier + session taint as policy inputs; scoring deferred | Reduced |
| Enforcement engine | permit/deny now; require-approval/quarantine/escalate as schema values rejected if used | Reduced |
| Audit/event engine | DEC-03 | Built |
| Governance engine | Inventory derived from observed calls; evidence = chain + anchors; no compliance claims | **Deferred** |
| Observability | Metrics computed from real events in CLI/static report (deny rate, latency, FP labels) | Built (report), live viewer optional |

This is a deliberate reduction of the brief (DEC-13) and is an explicit owner decision at Checkpoint A.

## Original v1 text follows

Status: draft for independent challenge, then Checkpoint A. Date: 2026-10-30.
Evidence labels: **[V]** verified on a primary page by the researcher, **[S]** secondary/vendor source, **[U]** unverified. Nothing here is a measured result; every number is a hypothesis.

## 1. Problem and opportunity

Agents get tool access gated by system prompts and ad-hoc code. A prompt is not a security boundary: a prompt injection or confused agent can still emit a call to a tool it should not have. PRYSM's thesis: a **deterministic policy decision point in the tool-call path, independent of prompt, model and provider**, with explainable decisions and a privacy-aware audit trail.

What this can and cannot do (honest framing, principle 14): it bounds blast radius (which tools, arguments, destinations). It does **not** detect or stop injection itself, and cannot judge whether an *authorised* action is semantically right.

## 2. Competitive landscape (summary; full table in researcher report, kept in PROGRESS.md appendix)

| Area | State of market | PRYSM stance |
|---|---|---|
| Injection/jailbreak/PII classifiers | Crowded and consolidating (Lakera→Check Point, Protect AI→Palo Alto, Prompt Security→SentinelOne, Invariant→Snyk) [S]; cloud options cheap (Bedrock regex/word filters free [V]) | Do **not** compete. Detectors are optional advisory inputs. |
| Generic AI gateways with guardrail hooks | LiteLLM, Cloudflare, Kong, Portkey [V/U] | Complement; PRYSM can sit behind them. |
| Cedar/OPA for MCP tool authz | Already productised: AWS AgentCore Policy (Cedar, GA Mar 2026) [S], TrueFoundry [S], ToolHive [S] | Closest competitor. Cloud/gateway-bound. PRYSM differs only by neutrality + provenance context + local-first. |
| Agent guardrail policy over traces | Invariant Guardrails (now Snyk) [S] — closest conceptual match | Do not claim uniqueness. |
| Governance platforms | Credo AI, watsonx.governance — workflow, not inline [U] | Later; evidence from real decision logs. |

**Defensible opportunity (hypotheses, unvalidated):** (1) provenance-aware tool authorisation as an external policy layer (arguments derived from untrusted content), (2) vendor/framework neutrality and local-first/open-core, (3) tamper-evident decision logs usable as audit evidence (no compliance claims), (4) honest reproducible benchmark (attack success, utility loss, latency). Risk: incumbents bundle/undercut; taint tracking across black-box frameworks is hard unless the integrator tags provenance.

Standards used for mapping (researcher could only confirm secondary sources — verify against official docs before any external mapping): OWASP LLM Top 10 2025 (LLM06 Excessive Agency is the core target; LLM01 containment only; LLM02/LLM05 via output rules), OWASP Agentic Top 10 2026 (ASI01 Agent Goal Hijack confirmed [S]; ASI02–10 titles unverified), NIST AI RMF + AI 600-1, ISO/IEC 42001/27001 (PRYSM provides evidence, cannot make anyone "compliant"), MITRE ATLAS tagging.

## 3. Technical research conclusions

- Patterns research (arXiv 2506.08837; CaMeL 2503.18813, 77% vs 84% undefended on AgentDojo [V abstract]) → restrict actions after untrusted data is seen rather than detect injection. Informs the provenance feature.
- Cedar: static-analysable, no external data at eval; OPA/Rego: external data, harder to analyse [S]. Decision: custom small evaluator for MVP (see D3) with property tests; adopt Cedar/OPA-WASM if property tests find precedence bugs.
- Benchmarks: AgentDojo (MIT) for end-to-end later; deepset/prompt-injections (Apache-2.0, 662 rows) smoke test only; JailbreakBench (code MIT; dataset licence to check); PINT archived, method only. PRYSM must build its own benign tool-call trace set to measure policy false positives.

## 4. Users and use cases

Personas P1 agent developer (primary), P2 security/platform engineer, P3 red-teamer, P4 governance lead, P5 approver (later). Journeys J1 wrap-and-see-why-blocked, J2 injection can't change decision, J3 simulate policy change (Should), J4 fail-closed. Details in REQUIREMENTS.md.

## 5. Requirements and MVP scope

See REQUIREMENTS.md (F-01..F-18, N-01..N-08, A-01..A-11 from product-manager, adopted with changes noted in DECISIONS.md).
**MVP = Layer 4 tool gate + deterministic versioned policy + explanations + redacting hash-chained audit + CLI + local read-only viewer over real events + thin model-invocation wrapper (mock + one real adapter optional) + fail-closed config.**
Excluded: hosted SaaS/accounts, learned detection, RAG enforcement, approvals, quarantine, compliance mapping/claims, proxy/sidecar, seeded dashboards.
Layers 1, 3, 5 appear in MVP only as: input/output rule hooks using the same policy engine with regex/allowlist detectors flagged **advisory** (Should, M3); Layer 2 deferred.

## 6. Threat model (summary; full register in SECURITY-REVIEW.md after review)

Assets: tool side effects, secrets/PII in args and outputs, policy files, audit log integrity, decision correctness.
Adversaries: A1 prompt injector (direct/indirect) steering agent; A2 malicious/compromised agent code in same process; A3 malicious tool arguments (path traversal, SSRF, command injection, domain lookalikes, unicode); A4 policy author mistake; A5 local attacker reading/tampering audit store or viewer; A6 supply chain (dependencies, adapters).
Key abuse cases and required controls:
| ID | Abuse | Control |
|---|---|---|
| T1 | Injection makes model emit forbidden tool call | Decision keyed on identity/tool/args/provenance only; prompt text never an input; tested with 20+ override strings (A-02) |
| T2 | Agent reaches tool without guard | Tools exposed only as guarded handles; raw functions not exported to agent; documented in-process limit (N-08/A-11) |
| T3 | Argument manipulation (allowlist bypass: `a@corp.com.evil.com`, case/unicode, `../`, URL userinfo tricks) | Typed schema validation, canonicalisation before match, anchored matchers, negative tests |
| T4 | TOCTOU: args mutated between check and execute | Decide on deep-frozen canonical copy; execute exactly that copy; test |
| T5 | Policy engine error/timeout | Per-tool/risk fail mode, default closed for high-risk; audit `engine_error` |
| T6 | Policy tamper / rollback | Version = content hash; activation event logged; load fails closed on parse error |
| T7 | Audit leak of secrets | Hash/redact by default, field allowlist for raw capture, canary test (A-05) |
| T8 | Audit tamper | Hash-chained events (tamper-*evident*, not tamper-proof; local attacker with write access can rewrite whole chain — disclosed) |
| T9 | Viewer/API abuse (local web) | Bind 127.0.0.1, random per-run bearer token, no CORS, CSP, read-only, no HTML injection of event data (escape), DNS-rebinding Host check |
| T10 | ReDoS / policy DoS | No user-regex by default; linear-time matchers or RE2-style limits; eval budget |
| T11 | Dependency/supply chain | Minimal deps, lockfile, `npm audit` as automated scanning evidence (not proof) |
| T12 | Confused deputy via approved identity (agent ID spoofing) | Identity supplied by host app, not by model output; documented trust boundary |

## 7. Trust boundaries

```
 [User / external content]  --untrusted-->  [Agent app code + LLM (UNTRUSTED decision-maker)]
                                                   |  proposed tool call (name,args,provenance tags)
                                       ==== TRUST BOUNDARY (PRYSM guard) ====
                                                   v
   [policy files (trusted, versioned)] --> [Policy Engine: pure, deterministic] --> decision
                                                   |                                   |
                                            [Audit writer: redact, hash-chain] <-------+
                                                   |  allow only
                                                   v
                                       [Real tool function (privileged side effects)]
   [CLI / local viewer 127.0.0.1] -- read-only --> [Audit store (SQLite)]
```
Trusted: policy files, host-app-supplied identity, PRYSM core. Untrusted: model output, user input, retrieved content, tool results, argument values.

## 8–10. Architecture, components, runtime sequence

Single TypeScript monorepo (npm workspaces), no microservices:
- `@prysm/core`: policy schema+loader, evaluator (pure function `decide(request, policy) → Decision`), canonicaliser, decision explanation, redactor, audit writer interface, `guard()` wrapper. Zero network, zero LLM calls.
- `@prysm/store`: SQLite (`node:sqlite`, verify stability on Node 24) append-only event table with hash chain; JSONL export.
- `@prysm/models`: provider adapter interface; mock scripted adapter; optional real adapter (owner-gated, D7).
- `@prysm/cli`: `validate`, `explain`, `events`, `verify-chain`, `simulate` (Should), `demo`.
- `@prysm/viewer`: tiny Node HTTP server + static vanilla/Preact page reading the store.
- `examples/support-agent`: sample app with real sandboxed tools.
- `bench/`, `eval/`: latency benchmark, adversarial corpus + benign trace set.

Runtime sequence: app → `session.runModel()` (input hook; model adapter) → model proposes tool call → `guard.call(tool,args,ctx{agentId,userId,scopes,provenance})` → canonicalise+freeze → `decide()` → write audit (before execution; execute only on allow; result summary appended) → return result or structured denial `{blocked, rule_id, policy_version, reason_code}` → output hook (redact/block) → final audit.
Audit write failure on a tool-call decision: configurable, default closed for high-risk.

## 11. Policy engine design

Declarative YAML/JSON, schema-validated (own checks; evaluate zod vs hand-rolled in M1). Elements: `defaults` (deny), `tools` registry (risk level, arg schema, fail_mode), `rules` (id, effect allow|deny|redact, priority, match on agent/user/scope/tool/arg predicates/provenance). Precedence: explicit deny > allow; then specificity; then lower `priority` number; default deny. Predicates: equals, in, anchored glob, domain-suffix (canonicalised), numeric range, path-within (after normalisation), provenance-in. No arbitrary code, no user regex in MVP. Version = SHA-256 of canonical policy bytes. Each decision returns trace: matched rules, losing rules, why precedence resolved so. Deterministic: no clock/random/network in `decide()`.

## 12. SDK / API design (sketch)

```ts
const prysm = createPrysm({ policy: "policy.yaml", store: ".prysm/audit.db" });
const tools = prysm.guard({ search_docs, send_email }, { agentId: "support-bot" });
const r = await tools.send_email({ to, body }, { userId, provenance: { to: "untrusted:model" } });
// r: { ok:true, value } | { ok:false, blocked:true, rule_id, policy_version, reason_code, decision_id }
```
Viewer API (local): `GET /api/events`, `/api/decisions/:id` with bearer token. No write endpoints.

## 13. Event schema (SQLite)

`events(seq INTEGER PK, id TEXT, ts INTEGER, execution_id, kind {decision|tool_result|model_call|policy_activate|engine_error}, agent_id, tool, enforcement {enforced|monitor_only}, effect, rule_id, policy_version, reason_code, risk, latency_us, model_meta JSON, args_digest, args_redacted JSON, prev_hash, hash)`. Raw args absent by default; per-field opt-in. Retention default 30 days (D5).

## 14. MVP scope and exclusions — see §5.

## 15. Technology choices

| Decision | Choice | Alternatives | Rationale |
|---|---|---|---|
| Language | TypeScript/Node 24 | Python/FastAPI | MCP/agent JS ecosystem, installed, one language for core+viewer; owner may flip (D1) |
| Storage | `node:sqlite` | JSONL; Postgres+Docker | No Docker available; queryable; single file. Risk: experimental flag status → verify in M0, fallback better-sqlite3 or JSONL |
| Policy | Custom evaluator + property tests | Cedar WASM, OPA WASM | Need provenance predicates and explanations; escape hatch noted |
| Viewer | Node http + static page | Next.js/shadcn | No build chain, tiny attack surface; Next.js deferred until governance UI |
| Redis, Postgres, FastAPI | Not used | — | No requirement in MVP |

## 16. Performance and security strategy

Bench: 10k+ evals, 200-rule policy, report p50/p95/p99 and end-to-end guard overhead incl. audit write (sync vs batched measured separately); fixed seed, documented hardware. Security: gate rules per SKILL; static inspection by security-engineer; `npm audit` + typecheck + lint as automated scanning; no pen testing. Adversarial corpus tested against `decide()`.

## 17. Milestone roadmap

M0 scaffold+toolchain check (node:sqlite, test runner) · M1 policy engine + precedence + explanations + property tests · M2 guard wrapper + canonicalisation + audit store (hash chain, redaction) + fail-closed · M3 CLI + mock model + demo scenarios (benign/unauthorized/injection) · M4 local viewer (real events only) · M5 sample app + optional real adapter + advisory input/output detectors · M6 benchmarks + adversarial/benign eval · M7 docs, security final review, delivery. Budget 5 passes each.

## 18. Acceptance criteria — A-01..A-11 in REQUIREMENTS.md.

## Assumptions needing owner approval

D1 TypeScript-only first; D2 local-first library (no SaaS); D7 mock model by default, no paid API usage; D8 Apache-2.0 open core; D3 custom policy evaluator; D5 30-day local retention; D6 fail-closed high-risk/fail-open low-risk per tool; MVP defers RAG layer, approvals, governance UI; first audience = JS/MCP agent developers (unvalidated; plan says run 5–10 developer interviews before building beyond MVP).
