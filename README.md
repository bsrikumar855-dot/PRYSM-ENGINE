# PRYSM-ENGINE

**PRYSM** is a deterministic, runtime policy gate for AI agent tool calls. It sits between an agent and its tools, decides allow/deny from a versioned policy (never from prompt text), and records a privacy-aware, hash-chained audit trail.

> **Status: MVP, not released.** Milestones M0–M5 are complete (M6, final review and delivery report, is in progress). Measured results, with their limits, are in `docs/auto-builder/BENCHMARK.md`; the headline numbers are *regression pins on a corpus whose labels were revised after the spec settled* and a benign set with 16 of 306 known false positives, not detection rates against real attackers. Two of four latency hypotheses were missed (decision p99 with 8 KiB strings; guard permit-path p99 above 10 ms with synchronous durable audit). See `docs/auto-builder/TASKS.md` for the roadmap and evidence table.

## What it does (and does not)

- **Enforces** policy on tool calls that are routed through it: unknown tools, unauthorized tools, bad arguments and tainted-session external actions are blocked **before** the tool runs. In the default fail-closed mode the decision row is written durably before execution; an opt-in `open_on_audit_failure` mode for low-risk read-only tools executes without a durable row on busy/IO errors (bounded streak, see AUDIT-SPEC), and `monitor_only` mode executes calls that would be denied. On `tool_timeout` the caller gets an error but the tool may still finish its side effect.
- **Does not** detect or stop prompt injection itself, judge whether an *authorized* action is semantically right, or stop code that bypasses it. It limits what an injected agent can do.
- Provenance and session taint are **asserted by the host**; they are not verified by PRYSM.
- The audit chain is **tamper-evident, not tamper-proof**: without an externally stored anchor, tail truncation or a full rewrite by someone with write access to the database is not detectable.
- Only the tool layer is built. Input, retrieval (RAG), model-invocation and output layers, a risk-scoring engine and governance reporting (inventory, approvals) are designed but deferred. A static audit report ships (`prysm report`).
- All bypass-resistance evidence so far uses **scripted mock models** (owner decision: no real-model test).

## Requirements

Node.js 24 or newer. No runtime dependencies. Development dependencies: TypeScript and `@types/node`. Storage uses Node's built-in `node:sqlite` (still marked experimental by Node; a warning is printed unless suppressed).

```bash
npm install --ignore-scripts
npm test            # full suite (539 tests, 2 skipped; about 40-60 s on the benchmark machine)
npm run typecheck
npm run corpus      # labelled adversarial policy corpus (563 cases: 435 decision, 128 policy-load)
npm run eval        # accuracy runner incl. 326-case benign set (prints known false positives)
npm run demo        # sample support agent, with and without PRYSM (mock model)
npm run diff        # differential test against the independent reference implementation
npm run bench       # performance harness (full protocol takes a long time; `bench:quick` is a rough profile and writes `bench/results/<date>-quick/`, git-ignored)
npm run prysm -- help   # CLI: validate, events, explain, verify-chain, anchor, simulate, report
```

`prysm simulate` takes JSONL requests of the form `{"tool": "...", "args": {...}, "ctx": {"agentId": "..."}}`; `ctx.agentId` is required, otherwise every request is `invalid_request`.

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

**Trust boundary:** `guard.call(tool, args, ctx)` accepts `scopes`, `userId` and `provenance` in `ctx` and trusts them (they are host-asserted). Untrusted agent code must not hold the raw guard; give it a wrapper that fixes `ctx`, or use the proxy, where these come from host flags. Calls without a session use an ephemeral state, so use sessions if you rely on taint. The tool function receives the guard's frozen, normalized snapshot of the arguments, never the caller's object. The agent-facing denial contains no rule ids, policy version or argument values; those are in the audit store only.

A policy is strict JSON: default deny, `deny` beats `permit`, no priorities. See `docs/auto-builder/POLICY-SPEC.md` and the example `eval/policies/support-agent.policy.json`.

## MCP stdio proxy (the enforcing mode)

The proxy sits between an MCP client (the agent host) and a real MCP server, in a separate process. Only `tools/call` is policy-enforced; other methods are on a short allowlist or refused.

```bash
node src/proxy/bin.ts --policy policy.json --db /secure/audit.db --key-path /secure/audit.key \
  --taint-tools search_docs --scopes sales -- node path/to/mcp-server.js
```

Key flags: `--taint-tools` (retrieval tools whose use taints the session), `--list-mode hide|show`, `--require-pins`, `--tool-timeout-ms`, `--max-server-line-bytes`, `--allow-methods`, `--policy-sha256`. Full specification: `docs/auto-builder/PROXY-SPEC.md` (§9 is current). Exit codes: `0` clean shutdown (including a client that closes stdin first, even if the server dies at the same moment), `1` server exit/crash while the client is still connected, `2` bad flags/policy/store configuration, `3` server could not be started, `70` fatal error.

### Deployment duties (the proxy is only enforcing if you do these)

- Make the proxy the **only** path from the agent host to the tool server. An agent host that can launch the tool server itself bypasses PRYSM.
- Keep the policy file, audit database and key file **where the agent host and the tool server cannot read or write them** (different OS account or sandbox). The server child runs as the same OS user as the proxy and is outside the protection scope for those files.
- Put `--key-path` outside the database directory. With the key beside the database, anyone who can read the database can brute-force low-entropy keyed digests; `verify()` warns `key_colocated`.
- Store an **anchor** (`store.anchor()`; the proxy also prints one on shutdown) somewhere an attacker with database access cannot rewrite, and verify with it.
- Pass `--policy-sha256` so a swapped policy file is refused at startup.

### Windows notes

- Launch the real executable or `node <script>`. `.cmd`/`.bat` shims such as `npx.cmd` are not supported (the proxy never uses a shell); they fail to start.
- Ctrl+C is handled (clean shutdown with an anchor line; verified by tests that simulate it, not on a real interactive console). A `SIGTERM` sent by another process is a forced terminate on Windows and cannot be intercepted.
- The server's environment is limited to a small allowlist (`PATH`, `SystemRoot`, `ComSpec`, `PATHEXT`, `windir`, `SystemDrive`, `HOME`, `USERPROFILE`, `TEMP`, `TMP`); pass anything else with `--env NAME`.
- Very large tool results are capped by `--max-server-line-bytes` (default 16 MiB). An oversize line fails **all** pending calls (including healthy concurrent ones, which fail closed after the server already ran them) but does not stop the proxy; raise the cap or avoid huge outputs.

## Security status

Independent reviews (security, critical review, blind-labelled test corpora and black-box QA) were run at each milestone gate, with exceptions recorded in TASKS.md and DECISIONS.md (some late fixes were verified by the lead only; QA did not run the report and `--out` scenarios in M4). Findings and their state are in `docs/auto-builder/SECURITY-REVIEW.md`. There are no confirmed Critical or High findings open in the reviewed scope, and several Medium/Low items are tracked. This is **not** a claim that the system is secure: methods were static inspection, the project's own tests, and reviewers' local probe scripts. Penetration testing was not performed and dependency scanning is trivial (no runtime dependencies).

## Repository layout

```
src/core     policy loader, request snapshot, deterministic decision engine (no I/O)
src/store    hash-chained SQLite audit store, keyed digests, redaction
src/guard    decision-before-execute guard, sessions, taint, fail modes
src/proxy    MCP stdio proxy (CLI and library)
src/cli      `prysm` CLI (validate, events, explain, verify-chain, anchor, simulate, report)
src/report   static HTML report (no JS, no external URLs)
src/explain  shared decision-cause explanation used by CLI and report
eval/        policy fixture, 563-case labelled corpus, benign set, independent reference implementation and differential harness
bench/       performance harness and committed results
examples/    sample support agent (mock model, sandboxed tools, MCP server)
smoke/       node:sqlite smoke test
test/        node:test suites (unit, property, fault-injection, end-to-end)
docs/auto-builder/  specs, decisions, threat/finding register, roadmap
```

## License

Apache-2.0 (see `LICENSE`).
