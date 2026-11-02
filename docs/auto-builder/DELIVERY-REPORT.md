# PRYSM delivery report

Date: 2026-11-02. Repository: PRYSM-ENGINE (`main`). Platform tested: Windows 11, Node 24.13.1, AMD Ryzen 7 4800H, one machine. Mock model only (owner decision DEC-15/16: no real-LLM test, no downloads, no API spend).

PRYSM is an MVP of a deterministic runtime policy gate for AI agent tool calls. It limits what an agent can do through routed tool calls and records a tamper-evident audit trail. **It does not claim complete protection against AI attacks, does not detect prompt injection, and makes no regulatory-compliance claim.** No security claim is made beyond the evidence below.

## 1. What was built
- `src/core`: strict-JSON policy loader, versioned (JCS hash), default deny, deny-overrides decision engine, frozen request snapshot, matchers, work budgets.
- `src/store`: SQLite hash-chained audit store (tamper-evident, not tamper-proof), keyed digests, anchors, checkpoint/prune.
- `src/guard`: decision-before-execute guard, sessions with sticky taint, fail modes, rate-limited best-effort rows.
- `src/proxy`: MCP stdio proxy (only `tools/call` enforced).
- `src/cli`, `src/report`, `src/explain`: `prysm` CLI and a static, script-free HTML report.
- `eval/`, `bench/`, `examples/`: accuracy runner, 563-case corpus, 326-case benign set, independent reference implementation and differential harness, performance harness, sample support agent.

## 2. Acceptance criteria
| ID | Criterion (short) | Status | Evidence / limit |
|---|---|---|---|
| A-01 | Tool-call gate: unauthorized/unknown blocked with decision id and reason | Verified | guard + proxy tests; QA re-ran CLI and proxy blocks |
| A-02 | Deterministic decisions | Partially verified | repo tests (deepEqual, not byte compare), Windows only |
| A-03 | `explain` / CLI | Verified | repo tests; QA ran validate, events, explain, verify-chain, anchor, simulate, report, ~60 cases |
| A-04 | Latency p50/p95/p99 vs hypotheses | Partially verified | H1 missed, H2 missed (stable), H3 met (little headroom), H4 met; guard/proxy workloads 2,000 samples, not 10,000; one machine |
| A-05 | Canary secret never in outputs | Verified (M2) | repo test + independent canary matrix; not re-run by M6 QA |
| A-06 | Engine failure never fails open | Verified (M2) | repo tests; M6 security re-read |
| A-07 | Precedence/version hash | Partially verified | 27 cases + property tests |
| A-08 | Report/real data only | Verified (M4) | tests; no seeded fixtures in runtime path |
| A-09 | Fresh clone to first block | Partially verified | 0.33-0.86 s process-to-first-block over 7 runs; excludes `npm install`; clone-to-first-block not measured |
| A-10 | Swap model adapter, policy unchanged | Untested | no swap test written |
| A-11 | Docs state limits | Verified | README (M6 pass) |
| A-12 | FN/FP with intervals | Partially verified | see section 3; labels revised after spec; no baseline comparison |
| A-13 | Tamper detection | Verified | modified/deleted/reordered detected; tail deletion only with an external anchor (documented) |
| A-14 | Live viewer | Not built | static report only (DEC-10) |
| A-15 | Real-LLM injection scenario | Out of scope (owner) | mock-scripted scenarios only |
| A-16 | Unknown tool / schema pin | Partially verified | `--require-pins` tested against a fixture server only |
| A-17 | Sink differential | Partially verified | no automated sink-vs-matcher differential; sample sandbox probed by a reviewer |
| A-18 | Proxy e2e: forbidden never reaches server | Verified | fixture MCP server, Windows, mock-scripted; no third-party server |
| A-19 | Core has no I/O imports | Verified (regex heuristic) | `test/core-imports.test.ts` |

## 3. Measured results (full detail and caveats: BENCHMARK.md)
- Attack corpus: FN 0 of 348 (95% upper bound 1.09%), FP 0 of 87. **These are regression pins**: 23 of 67 overridden labels flipped the expected effect after the spec settled.
- Benign set: 16 of 306 false positives (5.23%, CI 3.24-8.32%); 0 of 290 outside the `borderline-fp-risk` stress category. Known causes: non-ASCII names, `%`, 8.3 and colon names, the fixture's blanket `cc` deny.
- Differential vs an independent second implementation: 3 x 100,000 cases, 0 disagreements. Independence is process-based; the spec was changed to adopt engine behaviour in four ruled points.
- Latency (p99): decision 0.15 ms (8 rules), 0.30 ms (200 rules), 2.32 ms (200 rules, 8 KiB string); guard permit path 10.4-11.8 ms; proxy overhead 11.32 ms; verify-chain on 100,000 rows 3.7 s. Throughput about 455 guarded calls/s.
- Sample app: all 7 scenarios pass in-process and through the proxy. With PRYSM the outbox stays empty after a poisoned document; without it the exfiltration succeeds (mock model).

## 4. Security status (method: static inspection, project tests, reviewers' local probe scripts; no penetration testing, no `npm audit`)
- Independent security reviews at M1, M2, M3, M4, M5 and final M6. **No Critical or High finding open.**
- Fixed in M6: S-01 (verify crash on large stores), QA F1 (30 s hang when client EOF raced a dying server).
- **Open Medium: S-02** `guard.call` trusts caller-supplied scopes/userId/provenance; hosts must not give untrusted code the raw guard (README). API fix is backlog.
- Open Low/Medium-Low: S-03 (backslash treated as separator on every OS; matters for POSIX), S-04 (`--allow-methods` forwards without audit/taint), S-05 (ephemeral calls do not taint), S-06 (key file ACL window on Windows), S-07 (case-sensitive path rules on Windows), S-08 (server instructions forwarded; pins optional), S-09 hygiene, M2-21 (single-class flood hides later same-class rows), M2-22a/b, M3-11/12, M4-02, M5-05 (temp litter).
- Usability: for values the path matcher cannot interpret, `explain`/report blame `file.deny-secrets` instead of saying the value was uninterpretable.
- Privacy: an earlier commit pushed a Windows username in benchmark output; history was not rewritten (owner decision). Commit author email is public.

## 5. Not tested / untested
Fresh-clone install, Linux/macOS, SIGINT/SIGTERM on a real console, symlink `--out` refusal, third-party MCP servers, real LLMs and a prompt-only baseline, proxy exit 70, individual proxy flags (`--list-mode`, `--max-server-line-bytes`, etc.) by QA, opening the HTML report in a browser (checked by grep), `npm audit`, concurrent multi-process writers beyond the suite, `anchor --no-verify` on a tampered store (exit 1 observed, reason not examined).

## 6. Run it
```bash
npm install --ignore-scripts
npm test            # 539 tests, 2 skipped (SIGTERM, symlink refusal)
npm run typecheck
npm run corpus
npm run eval
npm run demo
npm run prysm -- help
```
Proxy usage, deployment duties and Windows notes are in README.md.

## 7. Process notes
Cedar differential was replaced by an independent second implementation (DEC-36). Reviewer findings drove every spec amendment; the register and decisions are in SECURITY-REVIEW.md and DECISIONS.md (DEC-01..41). AUTO-BUILDER itself was not modified.
