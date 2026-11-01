# PRYSM-ENGINE

**PRYSM** is a deterministic, runtime policy gate for AI agent tool calls. It sits between an agent and its tools, decides allow/deny from a versioned policy (never from prompt text), and records a privacy-aware, hash-chained audit trail.

> **Status: work in progress (MVP, not released).** Milestones M0–M4 are complete and independently reviewed; M5 (benchmarks, false-positive/negative and latency measurement) and M6 (final review and docs) are not done. No performance or detection-rate claims are made yet because they have not been measured. See `docs/auto-builder/TASKS.md` for the live roadmap and evidence table.

## What it does (and does not)

- **Enforces** policy on tool calls that are routed through it: unknown tools, unauthorized tools, bad arguments and tainted-session external actions are blocked **before** the tool runs. The decision row is written durably before execution.
- **Does not** detect or stop prompt injection itself, judge whether an *authorized* action is semantically right, or stop code that bypasses it. It limits what an injected agent can do.
- Provenance and session taint are **asserted by the host**; they are not verified by PRYSM.
- The audit chain is **tamper-evident, not tamper-proof**: without an externally stored anchor, tail truncation or a full rewrite by someone with write access to the database is not detectable.
- Only the tool layer is built. Input, retrieval (RAG), model-invocation and output layers, a risk-scoring engine and governance reporting are designed but deferred.
- All bypass-resistance evidence so far uses **scripted mock models** (owner decision: no real-model test).

## Requirements

Node.js 24 or newer. No runtime dependencies. Development dependencies: TypeScript and `@types/node`. Storage uses Node's built-in `node:sqlite` (still marked experimental by Node; a warning is printed unless suppressed).

```bash
npm install --ignore-scripts
npm test            # full suite (~20 s)
npm run typecheck
npm run corpus      # independently labelled adversarial policy corpus (563 cases)
npm run prysm -- help   # CLI: validate, events, explain, verify-chain, anchor, simulate, report
```

## Library use (in-process)

```ts
import { loadPolicy } from './src/core/index.ts';
import { openStore } from './src/store/index.ts';
import { createGuard } from './src/guard/index.ts';
import { readFileSync } from 'node:fs';

const policy = loadPolicy(readFileSync('policy.json'));
const store = openStore({ path: '.prysm/audit.db', keyPath: '/secure/place/audit.key' });
const guard = createGuard({
  policy, store, agentId: 'support-bot',
  tools: { search_docs: async (args) => /* your tool */ ({ ok: true }) },
});

const r = await guard.call('search_docs', { query: 'hello' });
// r = { ok: true, value, decision_id }
//   | { ok: false, blocked: true, decision_id, reason_code: 'denied'|'unknown_tool'|'invalid_request'|'unavailable' }
//   | { ok: false, blocked: false, decision_id, error: 'tool_error'|'tool_timeout' }
```

The tool function receives the guard's frozen, normalized snapshot of the arguments, never the caller's object. The agent-facing denial contains no rule ids, policy version or argument values; those are in the audit store only.

A policy is strict JSON: default deny, `deny` beats `permit`, no priorities. See `docs/auto-builder/POLICY-SPEC.md` and the example `eval/policies/support-agent.policy.json`.

## MCP stdio proxy (the enforcing mode)

The proxy sits between an MCP client (the agent host) and a real MCP server, in a separate process. Only `tools/call` is policy-enforced; other methods are on a short allowlist or refused.

```bash
node src/proxy/bin.ts --policy policy.json --db /secure/audit.db --key-path /secure/audit.key \
  --taint-tools search_docs --scopes sales -- node path/to/mcp-server.js
```

Key flags: `--taint-tools` (retrieval tools whose use taints the session), `--list-mode hide|show`, `--require-pins`, `--tool-timeout-ms`, `--max-server-line-bytes`, `--allow-methods`, `--policy-sha256`. Full specification: `docs/auto-builder/PROXY-SPEC.md` (§9 is current). Exit codes: `0` clean shutdown, `1` server exit/crash, `2` bad flags/policy/store configuration, `3` server could not be started, `70` fatal error.

### Deployment duties (the proxy is only enforcing if you do these)

- Make the proxy the **only** path from the agent host to the tool server. An agent host that can launch the tool server itself bypasses PRYSM.
- Keep the policy file, audit database and key file **where the agent host and the tool server cannot read or write them** (different OS account or sandbox). The server child runs as the same OS user as the proxy and is outside the protection scope for those files.
- Put `--key-path` outside the database directory. With the key beside the database, anyone who can read the database can brute-force low-entropy keyed digests; `verify()` warns `key_colocated`.
- Store an **anchor** (`store.anchor()`; the proxy also prints one on shutdown) somewhere an attacker with database access cannot rewrite, and verify with it.
- Pass `--policy-sha256` so a swapped policy file is refused at startup.

### Windows notes

- Launch the real executable or `node <script>`. `.cmd`/`.bat` shims such as `npx.cmd` are not supported (the proxy never uses a shell); they fail to start.
- Ctrl+C is handled (clean shutdown with an anchor line). A `SIGTERM` sent by another process is a forced terminate on Windows and cannot be intercepted.
- The server's environment is limited to a small allowlist (`PATH`, `SystemRoot`, `ComSpec`, `PATHEXT`, `windir`, `SystemDrive`, `HOME`, `USERPROFILE`, `TEMP`, `TMP`); pass anything else with `--env NAME`.
- Very large tool results are capped by `--max-server-line-bytes` (default 16 MiB). An oversize line fails **all** pending calls (including healthy concurrent ones, which fail closed after the server already ran them) but does not stop the proxy; raise the cap or avoid huge outputs.

## Security status

Independent reviews (security, critical review, blind-labelled test corpora and black-box QA) have been run on each milestone; findings and their state are in `docs/auto-builder/SECURITY-REVIEW.md`. There are no confirmed Critical or High findings open in the reviewed scope, and several Medium/Low items are tracked. This is **not** a claim that the system is secure: methods were static inspection, the project's own tests, and reviewers' local probe scripts. Penetration testing was not performed and dependency scanning is trivial (no runtime dependencies).

## Repository layout

```
src/core     policy loader, request snapshot, deterministic decision engine (no I/O)
src/store    hash-chained SQLite audit store, keyed digests, redaction
src/guard    decision-before-execute guard, sessions, taint, fail modes
src/proxy    MCP stdio proxy (CLI and library)
eval/        policy fixture and 563-case independently labelled corpus + runner
test/        node:test suites (unit, property, fault-injection, end-to-end)
docs/auto-builder/  specs, decisions, threat/finding register, roadmap
```

## License

Apache-2.0 (see `LICENSE`).
