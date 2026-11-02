# Security review

**Current status (M6, final):** no Critical or High finding is open in the reviewed scope. The register below shows the current state of each design-phase item (the original open/closed history is in DECISIONS.md and the milestone sections). Methods across the project: static inspection, the project's own tests, reviewers' local probe scripts. Penetration testing: not performed. Dependency scanning: not performed (no runtime dependencies). **No claim of security is made.**

Open items at delivery (all Medium or lower): S-02 (Medium, design: `guard.call` accepts caller-supplied scopes/userId/provenance; hosts must not hand the raw guard to untrusted agent code, see README), S-03, S-04, S-05, S-06, S-07, S-08 (M6 review, below), M2-21, M2-22a/b, M2-05, M3-11, M3-12, M4-02, M5-05, and the explain wording for uninterpretable values.

## Register (source: security-engineer report 2026-10-30; resolution in DECISIONS.md)

| ID | Title | Sev | Milestone gate | Resolution reference | State |
|---|---|---|---|---|---|
| P-01 | Canonicalisation differential / TOCTOU (paths, URLs, getters/Proxy, dup keys) | High (Pot.) | M1, M3 | DEC-07 plain-JSON snapshot, sink-level differential tests | Closed (re-read in code by the M6 security review) |
| P-02 | Provenance spoofing/omission | High (Pot.) | M2 | DEC-04 default-untrusted, session taint, asserted label | Closed (re-read in code by the M6 security review) |
| P-03 | Fail-open on audit/store/engine failure | High (Pot.) | M2 | DEC-03 no fail-open on engine error, unknown tool deny | Closed (re-read in code by the M6 security review) |
| P-04 | SSRF via allowed URL tools | High (Pot.) | M5 | DEC-07 guarded fetch, dot-boundary suffix | Closed for the sample app (loopback fixture); PRYSM matchers re-verified M6 |
| P-05 | Viewer rebinding/token leakage/XSS | High (Pot.) | M6 | DEC-10 static report first; hardened live viewer last | N/A (no live viewer built; static report only) |
| P-06 | Policy parsing/injection (YAML, proto pollution, dup keys) | High (Pot.) | M1 | DEC-02 strict JSON, JCS hash | Closed (re-read in code by the M6 security review) |
| P-07 | Audit chain weakness (truncation, preimage, retention, concurrency) | High→Medium if documented (Pot.) | M2 | DEC-03 | Mitigated as documented (tamper-evident only; needs external anchor) |
| P-08 | Secrets/PII in audit, errors, denial oracle | High (Pot.) | M2 | DEC-03/DEC-05 single redaction choke point, HMAC digests | Closed (re-read in code by the M6 security review) |
| P-09 | Tool-result injection / result laundering | High (Pot.) | M3 | DEC-04 session taint scenario test | Closed (re-read in code by the M6 security review) |
| P-10 | Audit log injection (newlines/ANSI/oversize) | Medium | M2/M4 | JSON-encode, escape, size caps | Closed (re-read in code by the M6 security review) |
| P-11 | Unicode confusables / bidi | Medium (High if IDN allowed) | M1 | DEC-02/DEC-07 | Closed (re-read in code by the M6 security review) |
| P-12 | Symlink/junction/path tricks | Medium (High for write tools) | M1/M5 | DEC-07 realpath | Closed (re-read in code by the M6 security review) |
| P-13 | ReDoS / eval DoS (sync, no wall-clock timeout) | Medium | M1 | linear matcher, size limits, `limit_exceeded` | Closed (re-read in code by the M6 security review) |
| P-14 | Precedence bugs, `monitor_only` kill switch | Medium | M1 | DEC-02/DEC-03 | Closed (re-read in code by the M6 security review) |
| P-15 | Policy tamper/rollback | Medium | M1/M2 | read-once, optional pin, no hot reload | Closed (re-read in code by the M6 security review) |
| P-16 | Identity spoofing / ctx race | Medium | M2 | immutable per-call ctx, concurrency test | Closed (re-read in code by the M6 security review) |
| P-17 | Supply chain, `node:sqlite` stability | Medium | M0 | lockfile, `npm ci`, ignore-scripts, import-graph test | Closed for M5 scope (no runtime deps; no npm audit run) |
| P-18 | Adapter secrets / spend abuse | Medium | M5 | redaction, per-session cap | N/A (no real model adapter; mock only) |
| P-19 | Decision-id/result replay | Low | M2 | bind result to decision digest | Closed (re-read in code by the M6 security review) |
| P-20 | Timestamp trust | Low | docs | documented | Documented limit |
| P-21 | Retention vs evidence | Low | M2 | DEC-03 checkpoint | Mitigated (checkpoint/prune with strict expectPruned) |

## Claims downgraded from draft v1
T2 (guarded handles) is a convention in-process, a control only in proxy deployment; T4 freeze is not sufficient (plain-JSON snapshot required); T9/T10 not verified controls yet; "tamper-evident" requires anchoring and does not cover a same-user attacker who rewrites everything; provenance is an assertion; "fail-closed" headline contradicted by D6 in v1 (fixed by DEC-03); acceptance IDs were cited before REQUIREMENTS.md was populated (now populated; security-engineer read it while empty).

## Required security regression tests (from register; to be placed in TESTING.md)
Table-driven sink differential per matcher (paths, URLs, unicode), getter/Proxy/mutation rejection, store-throws fail-mode matrix, concurrent writers linear chain, row mutate/delete/reorder/tail-truncate detection, canary across args/results/errors/stack/CLI/export/report, YAML-free policy abuse set (alias n/a, `__proto__`, duplicate keys), pathological glob timing, tainted-session exfiltration scenario, ctx interleaving, viewer header/Host/Origin/token tests (M6), `innerHTML` grep.

## Not done
Dynamic testing, dependency scanning, Windows junction behaviour tests, legal/privacy review of audit retention.

## M1 review findings (security-engineer, 2026-10-30; static inspection + own local probe scripts; no pen testing)
| ID | Finding | Sev | State |
|---|---|---|---|
| F-01 | Deny rule bypass via mixed `string[]` (spec hole; any-vs-all quantification) | **High, Confirmed** | Fix specified (SPEC §10.1); Open until re-verified |
| F-02 | Snapshot walk lacks work bound for shared-reference graphs (13.6 s measured; deeper = OOM) — decide() not total | Medium, Confirmed | Fix specified (§10.2); Open |
| F-03 | Decision not bound to the snapshot the tool receives (TOCTOU at integration boundary) | Medium, Confirmed (API) | Fix specified (§10.5); closes in M2 guard design; Open |
| F-04 | Case-insensitive path match uses toLowerCase not folding (ſ, ı) | Medium, Potential | Fix: ASCII-only paths (§10.3); Open |
| F-05 | 1000 rules x 8 KiB arg glob = 7.9 s decide() | Medium/Low, Confirmed | Fix: precompile, star cap, work budget (§10.2); Open |
| F-06 | Windows aliases COM¹, CONIN$, fullwidth dots not rejected | Low, Potential | Fix: ASCII-only + reserved names (§10.3); Open |
| F-07 | Hidden characters allowed in policy values (U+00AD, U+061C, …) | Low, Confirmed | Fix (§10.7); Open |
| F-08 | Fixture cc deny is a blocklist | Low, Confirmed (fixture) | Fix: deny-if-present (§10.9); Open |
| F-09 | NFC compared but raw string given to the tool | Low, Potential | Fix: NFC snapshot (§10.4); Open |
Register state after M1 review: P-04 (domain part), P-06, P-14, P-15 Closed for M1; P-01, P-11, P-12, P-13 Open pending fixes above. No finding accepted by the owner.

### M1 re-verification (security-engineer pass 2; static + own scripts; no pen testing; 2026-10-30)
Closed with evidence: F-01, F-02, F-03 (M1 API; M2 guard must pass `evaluate().snapshot`), F-04, F-06, F-08, F-09. F-05 closed for glob only; F-07 partial.
New: N-01 Medium Confirmed (deny rule unmatched by unparseable value → broader permit of another predicate kind wins), N-02 Medium/Low Confirmed (path/domain predicates unmetered; 1000 rules x 256x250-char string = 2.6 s), N-03 Low (toolInfo returns live mutable object), N-04 Low (invisible char classes). All have fixes specified in POLICY-SPEC §11 (pass 3). No confirmed Critical or High in M1 scope. Register: P-01 Closed for M1 core; P-04/P-06/P-14/P-15 Closed; P-12 lexical part Closed with N-01 residual; P-11 and P-13 Open (Low/Medium) pending pass 3.

### M2 design review (qa-engineer blind test plan, 2026-10-30; spec-only, no code)
31 spec findings A1-A31 resolved in AUDIT-SPEC section 4 (DEC-23). Security-relevant: A21 taint shedding via sessionId (High, spec fixed), A16 monitor_only executes on engine error (High, spec fixed), A11 key file creation/regeneration/ACL (High to Medium, spec fixed; key beside DB remains a documented residual because DB access implies key access), A5 hash round-trip (High, spec fixed), A15/A18 pre-evaluate ordering and prototype lookup (Medium, spec fixed), A27 fail-open drift (Medium, budget added), A26 best-effort stall (Medium, breaker added), A10 sink hygiene (Medium, allowlist added), A9 reason oracle and A14 lost deny evidence (accepted, documented). All remain Open until implemented and independently verified at the M2 gate.

### M2 gate pass 1 (security-engineer M2-01..M2-09; critical-reviewer MAJOR-1..4; 2026-10-31)
N-01..N-04 Closed (independent probes). No confirmed Critical or High. Medium: M2-01 malformed anchor accepted, M2-02 prefix deletion with forged checkpoint verifies ok, M2-03 key beside DB and Windows 0o600 no-op, M2-04 unbounded audit growth and fail-open under dead store; Low: M2-05 taint shedding edges (documented), M2-06 proto key accident, M2-07 guard best-effort ignores 250 ms cap (critical-reviewer MAJOR-1), M2-08 no prune retention floor, M2-09 residual invisible code points. Fixes specified in AUDIT-SPEC section 5; all Open until re-verified. Register: P-02, P-03, P-10, P-16, P-19, F-03 Closed for M2; P-07 Open (M2-01, M2-02); P-08 content leakage Closed, key location Open (M2-03).

### M2 gate re-verification (security-engineer, 2026-10-31)
Closed: M2-01, M2-03 (ACL verified; residual M2-11), M2-06, M2-07, M2-08, M2-09; N-01..N-04. New: M2-10 Medium Confirmed (pruned-history check bypassable via expectPruned/allowPruned with forged second checkpoint), M2-11 Low (ACL principal from env var; Everyone accepted; meta trusted), M2-12 Medium Confirmed (rate limiter lets 1000 junk calls suppress later deny and tool_result rows), M2-13 Medium/Low (taint shed via stale handle after eviction), M2-14 Low/Medium design (setTools reachable and unaudited). Fixes specified in AUDIT-SPEC section 6. No Critical/High. P-07 and P-21 Open until M2-10/M2-12 fixed; P-02 residual M2-13.

### M2 gate final (security-engineer pass 3, 2026-10-31): CLOSED for M2
M2-10, M2-11, M2-12 (cross-class), M2-13, M2-14 Closed with evidence. Open (not blocking): M2-21 Medium/Low (single-class best-effort flood still hides later evidence of the same class; fix: coalesce repeated deny rows, per-session budgets; task T-4.5), M2-22a Low (evaluateAcl accepts any DOMAIN-qualified account with the same user name; compare full name or SID; task T-6.5), M2-22b Low (tools_replaced row hashes names only), M2-05 Low (taint in-memory only, documented). Documented limits: chain unkeyed so tail truncation and full recompute are undetected without an external anchor; allowPruned accepts any pruning; key file beside DB by default (key_colocated warning); POSIX key mode and non-English icacls output untested. No confirmed Critical or High. This is not a claim that the system is secure.

### M3 gate pass 1 (security-engineer M3-01..M3-06; critical-reviewer; QA black-box; 2026-10-31)
No Critical/High. Medium M3-01 (client notifications/progress and initialize params forwarded unvalidated to the server: unpoliced data channel up to 1 MiB, no audit) Open. Low: M3-02 (U+2028/2029/0085 unescaped on output, desync of readline-based servers), M3-03 (proxy-written deny rows not accounted when rate-limited), M3-04 (server stderr unsanitised), M3-05 (pins optional and list-time only), M3-06 (process-tree cleanup, spawn exit code). Critical-reviewer majors: oversize result kills proxy, Windows launch/orphan processes, untested guarantees. Fixes specified in PROXY-SPEC section 9. Held: method confusion, duplicate-key smuggling (top-level rejected, nested last-wins = snapshot), id collisions, snapshot forwarding (NFC, __proto__ blocked), deep nesting (400k levels), 50 MiB no-newline, cancel races (200 rounds), canary leaks, no execution without prior decision row. Register: P-01, P-03, F-03 Closed through the proxy; P-09 Closed with documented residuals; P-17 Closed for M3 scope (no new runtime deps).

### M3 gate pass 2 re-verification (security-engineer, 2026-11-01)
M3-01..M3-06 Closed with evidence. P-01, P-03, F-03 Closed through the proxy; P-09 Closed with documented residuals (parallel already-decided calls, restart resets taint, unpinned tools warned only); P-17 Closed for M3 scope (no new runtime dependency; no dependency scan). New Low (open until fixed in section 10): M3-11 (one oversize server result fails all concurrent calls; fails closed, documented), M3-12 (client that never drains blocks shutdown), M3-13 (PRYSM_PROXY_TEST_FATAL hook in production CLI). Not checked: SIGINT/SIGTERM on a real Windows console, memory at the 64 MiB line cap, CLI path of the synchronous spawn throw (lead found it exits 2 not 3), real third-party servers. No claim that the system is secure.

### M4 gate (CLI + static report) closed, 2026-11-02
security-engineer (2 passes): no Critical/High. M4-01 (--out names ending in dot/space) Closed, M4-03 (forged DB recursive view hang; schema allow-list on every open) Closed, M4-11 (anchor could not verify pruned stores and steered operators to --no-verify) Closed, M4-12 (ANALYZE statistics tables rejected) Closed, M4-02 (read-only opens leave -wal/-shm files) Open by design, documented. critical-reviewer (2 passes): MAJOR report named permit rules as the cause of a block Closed (outcome.deny_n plus shared src/explain), CLI non-rule-denial divergence Closed, test gaps added. Register: P-08 and P-10 Closed for M4 (no values, keys or absolute paths in CLI/report; HTML, terminal and JSON injection held under hostile rows built via raw store.append). Limits: symlink refusal not exercised on this OS; no real-browser testing of print or screen readers; forged-index/attached-schema tricks against checkSchema only partly probed; very large stores untested beyond 6000 rows. No claim that the system is secure.

## M5 security gate (security-engineer, independent; static inspection + one `npm run demo` run; no penetration testing)
Result: **no Critical, High or Medium finding.** Sample-app sandbox held in both the guarded and the unguarded executor (traversal, backslash, drive/UNC/`\?\`, ADS, device and 8.3 names, look-alikes, 5000-segment path); docs fixture binds 127.0.0.1 and reads nothing from disk; no shell spawns; no runtime dependencies or install scripts; 188 tracked files and 32 commits contain no key/env/db files or real credential patterns.
| Id | Sev | Finding | Status |
|---|---|---|---|
| M5-01 | Low | Committed bench results contained a personal Windows path (username) and machine fingerprint | Fixed: paths scrubbed from results, harness records `<path>/basename`, regression test `test/eval/privacy.test.ts`. CPU/RAM/OS description is kept deliberately (needed to interpret numbers). Username was already pushed in earlier commits: history is not rewritten (owner decision) |
| M5-02 | Low | Real username used as a test fixture; author email in commit metadata | Fixture renamed. Author email left as is (owner's account) |
| M5-03 | Low | `.gitignore` lacked `*.key` | Fixed (`*.key`, `*.pem`, `prysm-*.html`) |
| M5-04 | Low | Sample MCP server/direct executor returned raw error messages with absolute paths | Fixed: fixed text `tool error` |
| M5-05 | Low (potential) | Test/demo runs leave temp directories | Open: documented; not measured how many the suite itself leaves |
Not checked: planted symlink/junction in the workspace, non-Windows, orphan processes on failed runs, `npm audit`, whether the GitHub repo is public. Register: P-12 closed for the sample app, P-04 loopback-only, P-17 closed for M5 scope, P-08 Low items above.


## M6 final security review (security-engineer, independent; static inspection + project tests + local probes; no penetration testing, no npm audit)
Every register item marked fixed was re-read in current code and held (core, loader, guard, store, proxy, CLI, report). Findings:
| Id | Sev | Finding | Status |
|---|---|---|---|
| S-01 | Medium (confirmed) | `Math.min(...decisions.map(...))` in `store.verify()` threw RangeError above ~125,000 decision rows, so `verify-chain`, `anchor` and the report integrity check failed (exit 2, fail-closed) on large stores | Fixed (reduce instead of spread). Verified manually against the reviewer's 130,000-row store (`verify-chain` OK, count 130000); no regression test in the suite because building such a store takes about 50 s |
| S-02 | Medium (confirmed, design) | `guard.call(tool, args, ctx)` takes scopes, userId and provenance from the caller; untrusted code holding the guard can self-grant them (proxy path is safe: host flags) | **Open, documented.** Host duty: expose only a wrapper that fixes ctx. API change (host-only facet) is backlog |
| S-03 | Low-Medium | Backslash is treated as a separator on every OS; on POSIX `/work/secret/a\..\..	mp` normalises outside the deny root. Only matters for POSIX hosts with tools that can create backslash-named entries | Open. Project verified on Windows only; not fixed because platform-specific behaviour would break determinism |
| S-04 | Low-Medium (potential) | `--allow-methods` / `--allow-server-requests` forward content without audit rows or taint | Open, opt-in; documented here |
| S-05 | Low | `guard.call` without a session uses an ephemeral state, so `taintsSession` tools do not taint later calls | Open; use sessions |
| S-06 | Low | Windows key file created with the inherited ACL before `icacls` tightens it; failure leaves `unprotected` key with a verify-time warning only | Open |
| S-07 | Low | `path_within` with `case_insensitive:false` on Windows is bypassable by case variants (policy author choice) | Open (hardening) |
| S-08 | Low | Server `initialize.instructions`, tool descriptions and progress params are forwarded verbatim (prompt-injection channel to the client model); pins optional | Open; use `--require-pins` |
| S-09 | Low | Stray empty `node_modules/@modelcontextprotocol`; `writeAtomic` temp file left after a crash; unthrottled proxy stderr lines for hostile server | Open (hygiene) |
Not checked: dynamic/penetration testing, `npm audit`, real MCP servers, SIGINT/SIGTERM on a real console, POSIX behaviour, junction/symlink behaviour of `--out`, `src/report/build.ts` aggregation (skimmed), git history for secrets (the M5 review covered it), repository visibility.
