# Changelog

All notable changes. Dates are UTC. Decisions (DEC-nn) are in `docs/auto-builder/DECISIONS.md`; findings (S-nn, F-nn, M-nn) in `docs/auto-builder/SECURITY-REVIEW.md`.

## 0.1.1 (2026-11-20): fixes from the second independent re-review (DEC-55)

Not published to npm. These fixes have not been re-reviewed independently.

### Behaviour changes

- **Explanations:** a denial is explained as uncertain when any argument check of the rule held only through a value that could not be interpreted, even if another check genuinely matched. The 0.1.0 rule could present such a block as certain. The wording now says the condition is uncertain, not that nothing matched.
- **Audit under flooding:** best-effort signature tracking is per class, and only rows actually written count. In 0.1.0, about 5000 server-chosen notification names could make a later policy denial leave no row.
- **Key file on Windows:**
  - the principal comes from the process token (`whoami`), never from `USERDOMAIN` or `USERNAME`;
  - the key is granted to the token SID;
  - if the token cannot be read, the key is judged unprotected and the proxy refuses to start unless `--allow-unprotected-key`;
  - `whoami` and `icacls` run from System32 by absolute path.
- **Key file on every platform:**
  - a newly created key is judged on the linked file;
  - temp leftovers are swept on every writable open.
- **Proxy:**
  - only `description` and `title` strings in tool schemas and annotations are shortened; any other over-long string, an over-long key or deep nesting hides the tool instead of being cut;
  - an invalid `protocolVersion` from the server is refused instead of replaced;
  - long server names are truncated instead of replaced;
  - forwarded client notifications are audited.

### API additions

- `currentAclUser()` and `parseWhoami()` exported from the store module.

### Migration notes

- On Windows, a proxy run where `whoami.exe` cannot be started (for example a stripped container) now refuses an existing key as unprotected. Use `--allow-unprotected-key` only if you accept that.
- MCP servers with schema `pattern` or `enum` strings over 4096 characters are no longer listed.

## 0.1.0 (2026-11-20): production hardening (P1)

First tagged version. Not published to npm (`package.json` stays `private`). This is not a claim that PRYSM is secure or complete: see the residual risks at the end of SECURITY-REVIEW.md.

### Behaviour changes (may change decisions or what reaches the client)

- **Deny rules match more paths** (POLICY-SPEC 14):
  - a backslash outside a drive-letter path makes the value unparseable (S-03, DEC-45);
  - deny-rule `path_within` always compares case-insensitively (S-07, DEC-45);
  - a drive letter on only one side is ignored, so `C:/Windows` also covers `/Windows/...` and `/workspace/secrets` covers `C:/workspace/secrets/...` (F2, DEC-50).

  Permit rules are unchanged, so these can only turn permits into denials. Four corpus labels changed as a result; they are marked LEAD-DERIVED (BENCHMARK 4a).
- **Proxy, forwarded traffic** (S-04, F3; DEC-44, DEC-51):
  - every request forwarded with `--allow-methods` writes a `method_forwarded` audit row, and its result taints the session;
  - allowed server requests and notifications are audited (`direction: "to_client"`) and taint the session;
  - a forwarded method's server error reaches the client as `{code, message: "Server error"}` only.

  `--no-taint-forwarded` turns the taint off, and that choice is recorded in the posture row.
- **Proxy, server text** (S-08, F10; DEC-48, DEC-51):
  - `initialize.instructions` is dropped unless `--forward-instructions`;
  - `initialize` passes only `protocolVersion`, the tools capability and capped `serverInfo`;
  - tool `title` and `description`, and every string nested in schemas and annotations, are capped at 4096 characters;
  - a tool whose schema is still over 64 KiB is not listed;
  - progress for a call in flight carries numbers only.
- **Proxy, key file** (S-06; DEC-47, DEC-53): the proxy refuses to start on an unprotected key file (exit 2, `key_unprotected`) unless `--allow-unprotected-key`.
- **Key creation** (DEC-47, DEC-53, DEC-49):
  - the key is written only into an already-protected file, through the descriptor that created it, and is then hard-linked into place;
  - this needs a filesystem with hard links;
  - on Windows the user must match as `DOMAIN\user`, and explicit SYSTEM and Administrators entries are removed by SID.
- **Best-effort audit rows** (M2-21, F8; DEC-46, DEC-52): a flood of one kind of denial can no longer hide a different one:
  - each class has a 64-row novelty reserve;
  - the first row of each new (class, tool, reason) in a window is always written, up to 512 per window;
  - forwarded-method rows have their own budget.
- **Explanations** (DEC-46, DEC-54): a denial caused only by a value that could not be interpreted says so; a rule that genuinely matched is never explained that way.
- **Proxy sink lines** (S-09, F9): noisy lines are throttled per kind and side, and suppressed counts are written by a timer and at shutdown.

### API additions

- `Guard.forAgent(binding)` returns an `AgentGuard` (`sessionId`, `tainted`, `call(tool, args, opts?)`) with host-fixed identity:
  - the only call option is `sessionTainted: true`;
  - the optional `provenance(tool, args)` callback receives the frozen, normalised snapshot;
  - a callback that throws makes the call `invalid_request`.

  New exported types: `AgentGuard`, `AgentBinding`, `AgentCallOptions` (S-02, DEC-43, DEC-54).
- `GuardAdmin.recordForwarded(method, sessionId, direction?)` and the type `ForwardDirection` (`'to_server' | 'to_client'`).
- `Decision.matched_unparseable: readonly string[]`, and decision rows carry `outcome.unparseable` when it is non-empty.
- `openStore({ requireProtectedKey: true })` and `StoreError` code `key_unprotected`.
- Proxy options `taintForwarded`, `forwardInstructions` and `allowUnprotectedKey`, the matching CLI flags, and proxy config error code `key_unprotected`.
- The `proxy_config` posture row gains `taint_forwarded`, `forward_instructions`, `allow_unprotected_key` and `key_protection`.

### Migration notes

- Hosts that hand `Guard` to agent code should hand `guard.forAgent({...})` instead; the raw `guard.call` still trusts its caller.
- Policies that relied on a deny root with a drive letter **not** covering drive-less paths (or the reverse) now deny those paths.
- Clients that read server error messages for forwarded methods now see `"Server error"`.
- An existing key file created on localised Windows by an earlier version may be judged unprotected; recreate it (move the old key aside, keep it for verifying old stores).
- A proxy whose key lives on FAT/exFAT or a network share without hard links cannot create a key; create it on a supporting filesystem.

### Project

- CI on GitHub Actions: Ubuntu, Windows and macOS, Node 24. It runs the typecheck, tests, corpus, accuracy evaluation, one differential seed and the demo.
- Independent re-review on 2026-11-20, by the security engineer and the critical reviewer; its findings and the fixes are in SECURITY-REVIEW.md. The fixes made after it have not been re-reviewed.
- Benchmark disclosures corrected:
  - against the blind labels, 2 of 87 expected-permit corpus cases are now denied;
  - the differential is not independent for POLICY-SPEC 14.

## 0.0.0: MVP (M0-M6)

Delivered milestones M0 to M6; see `docs/auto-builder/DELIVERY-REPORT.md`.
