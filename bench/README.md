# PRYSM benchmark harness

Implements the performance protocol in `docs/auto-builder/BENCH-SPEC.md` section 3. Zero dependencies; Node 24 runs the TypeScript directly.

```
npm run bench          # full protocol: 2000 warm-up, 10 000 (decide) / 2 000 (guard, store, proxy) measured, 5 reps + 1 cold per case
npm run bench:quick    # reduced iterations for smoke/CI; NOT protocol results
npm run bench -- --only W2,W4.permit   # subset by workload, case id or id prefix
npm run bench -- --out some/dir        # alternative output directory
```

Do not run other heavy processes while the full run is going. It takes several minutes (the `W8` 100k store and the FULL-sync guard cases dominate).

## How a run works

The parent (`bench/run.ts`, `bench/lib/orchestrate.ts`) never measures anything itself. For each case it starts **separate child
processes**: `reps` independent measured runs (5 in the full profile) and one **cold** run (no warm-up, first 100 iterations in
a fresh process). A child opens its own policy/store in a fresh temp directory, runs warm-up (discarded) and the measured loop
with `process.hrtime.bigint()` timers, and returns per-run percentiles plus a log2 histogram (never raw sample arrays). The
parent aggregates: **median of the per-run p50/p95/p99**, min/max across runs, **coefficient of variation** (sample sd / mean)
across runs. Percentiles are nearest-rank. Inputs are seeded (mulberry32, base seed `20260101`, derived per case); the seed is
stored in every result.

## Workloads

| Id | What |
|---|---|
| W1 | `decide()` on the 8-rule fixture policy (`eval/policies/support-agent.policy.json`), seeded mix: about 40% allow, 25% deny, 15% tainted session, 20% invalid args |
| W2 | `decide()` on a deterministic 200-rule synthetic policy (`bench/lib/policygen.ts`, 10 tools, eight predicate shapes), args: tiny, 1 KiB, 8 KiB string, 64-element `string[]` |
| W3 | `evaluate()` including the request snapshot (fixture mix; 200-rule policy with a 1 KiB string) |
| W4 | `guard.call()` end to end, no-op tool, store `synchronous=FULL` vs `NORMAL`, permit path (durable decision row before execution) and deny path (best-effort row) |
| W5 | 1/4/16/64 concurrent async guard calls on one store (throughput and latency); plus 4 processes appending to one store (barrier-synchronised start) |
| W6 | `tools/call` round trip direct to the fixture MCP server vs through the proxy CLI process (same fixture); overhead = difference; audit rows counted |
| W7 | audit overhead: guard with an in-memory no-op store stub (`bench/lib/guardkit.ts`) vs the real store (W4); durable-write cost is derived as W4 minus W7 and written to the summary |
| W8 | `prysm report` and `prysm verify-chain` on stores of 1k / 10k / 100k decision rows built through `store.append`; single run each, time and peak RSS |

Hypotheses (decided before measuring, evaluated automatically in `bench/lib/hypotheses.ts`):
H1 decide p99 < 1 ms at 200 rules (worst of the four W2 variants); H2 guard `call()` p99 < 10 ms with `synchronous=FULL`
(both permit and deny paths); H3 proxy overhead p99 < 15 ms (proxy p99 minus direct p99); H4 `verify-chain` of 100k rows < 30 s
(process wall time including Node start-up). A miss is recorded as `MISSED`, never tuned away.

## Design decisions to know about

- **Best-effort row budgets are raised in the guard** (`maxDenyRowsPerWindow`, `maxResultRowsPerWindow`, `maxPreEvaluateRowsPerWindow` set to 1e9). The defaults (1000 rows per minute) would turn later deny calls into cheaper no-write calls and understate the deny-path cost. Each result records `audit_rows` and `unexpected_results` (calls that did not take the intended path).
- **W6 uses `send_email`** on the fixture server, because the fixture's `echo` tool answers through `setTimeout`, which on Windows adds a timer-resolution quantum (about 15 ms) to both legs. `send_email` is answered synchronously. The policy permits it, so the proxy leg is the permit path.
- **W6 uses real OS pipes and a real proxy CLI process** (`src/proxy/bin.ts`), so the proxy leg includes its process, JSON-RPC framing, policy, audit store (`synchronous=FULL` default) and the second pipe to the server.
- **W5 concurrency** is async calls inside one process; the store is synchronous (node:sqlite), so the calls serialise on the event loop and latency at higher concurrency is mostly queueing. Throughput is the useful number there.
- **W8 stores are built with `synchronous=NORMAL`** (100k fsyncs would take far too long); row content and the hash chain are identical. RSS is the peak working set of a probe process (`bench/probe.ts`) that runs the CLI command in-process, so it excludes the store builder.
- The synthetic 200-rule policy has deny rules whose tokens requests never match (requests are random), so W2 exercises evaluation of every rule (deny-overrides needs them all) mostly ending in permit or default-deny, not `denied_by_rule`.
- The timer itself costs on the order of 100 ns per sample; it matters only for the sub-microsecond end of W1/W3.

## Output

`bench/results/<YYYY-MM-DD>/` (quick runs go to `<date>-quick`, smoke to `<date>-smoke`):

- `<case>.json` one per case: machine info, seed, every run (per-run n/min/max/mean/p50/p95/p99, histogram, wall time, extras such as throughput and audit-row counts), the cold run, the aggregate, failed runs if any. W8 files hold the single run's measurements.
- `summary.json`: compact machine-readable summary in milliseconds, derived values (proxy overhead, durable-write cost, W5 throughput), the four hypothesis verdicts, failures.

`docs/auto-builder/BENCHMARK.md` is written by the lead from these files; the harness does not generate it.

## Caveats (state them with any number)

Single machine, Windows only, one OS power plan, other processes were not controlled beyond not starting any. A cold run is a fresh
process but the OS file cache and CPU frequency state are not reset. Latencies are for no-op tools, not real tool work. Results of
`--quick` and `--smoke` are never protocol results.

## Tests

`npm test` includes `test/bench/bench.test.ts`: statistics on known data (nearest-rank percentiles, median-of-runs, CV, histogram), PRNG determinism, the policy generator, hypothesis boundaries, each workload in-process with tiny counts, and an end-to-end parent run with child processes that checks the written JSON is valid and small.
