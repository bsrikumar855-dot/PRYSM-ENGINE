# Security review

Method this round: **static inspection of design documents only** (security-engineer, independent, read-only). Automated scanning: none (no code). Penetration testing: not performed. All findings are *Potential* design-level; nothing is implemented. Overall status: **design not approved until the controls below are specified in code and tests (Phase M0–M3 gates)**. No claim of security is made.

Gate status: no Critical. Potential High P-01..P-09 block their milestones until closed with `security-engineer` re-verification. No High accepted by the owner.

## Register (source: security-engineer report 2026-10-30; resolution in DECISIONS.md)

| ID | Title | Sev | Milestone gate | Resolution reference | State |
|---|---|---|---|---|---|
| P-01 | Canonicalisation differential / TOCTOU (paths, URLs, getters/Proxy, dup keys) | High (Pot.) | M1, M3 | DEC-07 plain-JSON snapshot, sink-level differential tests | Open |
| P-02 | Provenance spoofing/omission | High (Pot.) | M2 | DEC-04 default-untrusted, session taint, asserted label | Open |
| P-03 | Fail-open on audit/store/engine failure | High (Pot.) | M2 | DEC-03 no fail-open on engine error, unknown tool deny | Open |
| P-04 | SSRF via allowed URL tools | High (Pot.) | M5 | DEC-07 guarded fetch, dot-boundary suffix | Open |
| P-05 | Viewer rebinding/token leakage/XSS | High (Pot.) | M6 | DEC-10 static report first; hardened live viewer last | Open |
| P-06 | Policy parsing/injection (YAML, proto pollution, dup keys) | High (Pot.) | M1 | DEC-02 strict JSON, JCS hash | Open |
| P-07 | Audit chain weakness (truncation, preimage, retention, concurrency) | High→Medium if documented (Pot.) | M2 | DEC-03 | Open |
| P-08 | Secrets/PII in audit, errors, denial oracle | High (Pot.) | M2 | DEC-03/DEC-05 single redaction choke point, HMAC digests | Open |
| P-09 | Tool-result injection / result laundering | High (Pot.) | M3 | DEC-04 session taint scenario test | Open |
| P-10 | Audit log injection (newlines/ANSI/oversize) | Medium | M2/M4 | JSON-encode, escape, size caps | Open |
| P-11 | Unicode confusables / bidi | Medium (High if IDN allowed) | M1 | DEC-02/DEC-07 | Open |
| P-12 | Symlink/junction/path tricks | Medium (High for write tools) | M1/M5 | DEC-07 realpath | Open |
| P-13 | ReDoS / eval DoS (sync, no wall-clock timeout) | Medium | M1 | linear matcher, size limits, `limit_exceeded` | Open |
| P-14 | Precedence bugs, `monitor_only` kill switch | Medium | M1 | DEC-02/DEC-03 | Open |
| P-15 | Policy tamper/rollback | Medium | M1/M2 | read-once, optional pin, no hot reload | Open |
| P-16 | Identity spoofing / ctx race | Medium | M2 | immutable per-call ctx, concurrency test | Open |
| P-17 | Supply chain, `node:sqlite` stability | Medium | M0 | lockfile, `npm ci`, ignore-scripts, import-graph test | Open |
| P-18 | Adapter secrets / spend abuse | Medium | M5 | redaction, per-session cap | Open |
| P-19 | Decision-id/result replay | Low | M2 | bind result to decision digest | Open |
| P-20 | Timestamp trust | Low | docs | documented | Open |
| P-21 | Retention vs evidence | Low | M2 | DEC-03 checkpoint | Open |

## Claims downgraded from draft v1
T2 (guarded handles) is a convention in-process, a control only in proxy deployment; T4 freeze is not sufficient (plain-JSON snapshot required); T9/T10 not verified controls yet; "tamper-evident" requires anchoring and does not cover a same-user attacker who rewrites everything; provenance is an assertion; "fail-closed" headline contradicted by D6 in v1 (fixed by DEC-03); acceptance IDs were cited before REQUIREMENTS.md was populated (now populated; security-engineer read it while empty).

## Required security regression tests (from register; to be placed in TESTING.md)
Table-driven sink differential per matcher (paths, URLs, unicode), getter/Proxy/mutation rejection, store-throws fail-mode matrix, concurrent writers linear chain, row mutate/delete/reorder/tail-truncate detection, canary across args/results/errors/stack/CLI/export/report, YAML-free policy abuse set (alias n/a, `__proto__`, duplicate keys), pathological glob timing, tainted-session exfiltration scenario, ctx interleaving, viewer header/Host/Origin/token tests (M6), `innerHTML` grep.

## Not done
Dynamic testing, dependency scanning, Windows junction behaviour tests, legal/privacy review of audit retention.
