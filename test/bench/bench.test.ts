// Smoke tests for the benchmark harness (tiny iteration counts). They prove the harness runs, the statistics are right
// and the outputs are valid, small JSON. They do not measure anything.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide } from '../../src/core/index.ts';
import { PROFILES } from '../../bench/lib/config.ts';
import { evaluateHypotheses } from '../../bench/lib/hypotheses.ts';
import { machineInfo, localDate } from '../../bench/lib/machine.ts';
import { executeRun, parentMain, parseOptions } from '../../bench/lib/orchestrate.ts';
import { loadSyntheticPolicy, syntheticPolicyDoc, syntheticRequests, fixtureRequests, loadFixturePolicy } from '../../bench/lib/policygen.ts';
import { mulberry32, caseRng } from '../../bench/lib/prng.ts';
import { aggregateExtras, aggregateRuns, cv, log2Histogram, median, percentileNearestRank, summarize } from '../../bench/lib/stats.ts';
import type { RunStats } from '../../bench/lib/stats.ts';
import { stubStore, benchGuard } from '../../bench/lib/guardkit.ts';
import { allCases } from '../../bench/workloads/index.ts';
import { cleanup } from '../support/tmp.ts';

const made: string[] = [];
const scratch = (): string => { const d = mkdtempSync(join(tmpdir(), 'prysm-benchtest-')); made.push(d); return d; };
after(() => {
  cleanup();
  for (const d of made) for (let i = 0; i < 5; i++) { try { rmSync(d, { recursive: true, force: true }); break; } catch { /* retry */ } }
});

const smoke = PROFILES.smoke;
const caseById = (id: string) => {
  const c = allCases(smoke).find((x) => x.id === id);
  assert.ok(c, `case ${id} exists`);
  return c;
};

// ---------------------------------------------------------------- statistics
test('percentile nearest-rank on known data', () => {
  const hundred = Array.from({ length: 100 }, (_, i) => i + 1);
  assert.equal(percentileNearestRank(hundred, 50), 50);
  assert.equal(percentileNearestRank(hundred, 95), 95);
  assert.equal(percentileNearestRank(hundred, 99), 99);
  assert.equal(percentileNearestRank(hundred, 100), 100);
  const ten = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
  assert.equal(percentileNearestRank(ten, 50), 50); // ceil(5) = rank 5
  assert.equal(percentileNearestRank(ten, 95), 100); // ceil(9.5) = rank 10
  assert.equal(percentileNearestRank(ten, 99), 100);
  assert.equal(percentileNearestRank(ten, 10), 10); // ceil(1) = rank 1
  assert.equal(percentileNearestRank([7], 50), 7);
  assert.equal(percentileNearestRank([7], 99), 7);
  const twenty = Array.from({ length: 20 }, (_, i) => i + 1);
  assert.equal(percentileNearestRank(twenty, 95), 19);
});

test('percentile rejects empty input and bad p', () => {
  assert.throws(() => percentileNearestRank([], 50));
  assert.throws(() => percentileNearestRank([1], 0));
  assert.throws(() => percentileNearestRank([1], 101));
});

test('median: odd, even, unsorted input is not mutated', () => {
  assert.equal(median([3, 1, 2]), 2);
  assert.equal(median([4, 1, 3, 2]), 2.5);
  assert.equal(median([9]), 9);
  const xs = [3, 1, 2];
  median(xs);
  assert.deepEqual(xs, [3, 1, 2]);
  assert.throws(() => median([]));
});

test('cv: sample standard deviation over mean', () => {
  // mean 5, sum of squares 32, sample sd = sqrt(32/7)
  assert.ok(Math.abs(cv([2, 4, 4, 4, 5, 5, 7, 9]) - Math.sqrt(32 / 7) / 5) < 1e-12);
  assert.equal(cv([5, 5, 5]), 0);
  assert.equal(cv([5]), 0);
  assert.equal(cv([0, 0]), 0);
});

test('log2 histogram buckets', () => {
  assert.deepEqual(log2Histogram([1, 2, 3, 4, 1000, 1023, 1024]), { 0: 1, 1: 2, 2: 1, 9: 2, 10: 1 });
});

test('summarize: percentiles, min/max/mean and unsorted input', () => {
  const samples = Array.from({ length: 100 }, (_, i) => 100 - i); // 100..1 descending
  const s = summarize(samples);
  assert.equal(s.n, 100);
  assert.equal(s.min, 1);
  assert.equal(s.max, 100);
  assert.equal(s.p50, 50);
  assert.equal(s.p95, 95);
  assert.equal(s.p99, 99);
  assert.equal(s.mean, 50.5);
  assert.deepEqual(samples.slice(0, 3), [100, 99, 98], 'input untouched');
  assert.throws(() => summarize([]));
});

test('aggregateRuns: median-of-runs of per-run percentiles, min/max and CV across runs', () => {
  const mk = (p50: number, p95: number, p99: number): RunStats => ({ n: 1000, min: p50 / 2, max: p99 * 2, mean: p50, p50, p95, p99, hist_log2_ns: {} });
  const runs = [mk(10, 20, 30), mk(12, 22, 90), mk(11, 21, 40), mk(50, 60, 70), mk(13, 23, 50)];
  const a = aggregateRuns(runs);
  assert.equal(a.runs, 5);
  assert.equal(a.n_per_run, 1000);
  assert.equal(a.p50.median, 12);
  assert.equal(a.p50.min, 10);
  assert.equal(a.p50.max, 50);
  assert.equal(a.p95.median, 22);
  assert.equal(a.p99.median, 50);
  assert.equal(a.p99.max, 90);
  assert.equal(a.min_ns, 5);
  assert.equal(a.max_ns, 180);
  assert.ok(Math.abs(a.p50.cv - cv([10, 12, 11, 50, 13])) < 1e-12);
  assert.throws(() => aggregateRuns([]));
});

test('aggregateExtras only keeps numeric fields present in every run', () => {
  const e = aggregateExtras([{ t: 1, x: 'a', only: 1 }, { t: 3, x: 'b' }, { t: 2, x: 'c' }]);
  assert.deepEqual(Object.keys(e), ['t']);
  assert.equal(e['t']?.median, 2);
});

// ---------------------------------------------------------------- prng and inputs
test('PRNG is deterministic per seed, differs across seeds and stays in range', () => {
  const a = mulberry32(42);
  const b = mulberry32(42);
  const c = mulberry32(43);
  const sa = Array.from({ length: 50 }, () => a.next());
  const sb = Array.from({ length: 50 }, () => b.next());
  const sc = Array.from({ length: 50 }, () => c.next());
  assert.deepEqual(sa, sb);
  assert.notDeepEqual(sa, sc);
  assert.ok(sa.every((x) => x >= 0 && x < 1));
  assert.equal(mulberry32(1).hex(37).length, 37);
  assert.notEqual(caseRng(1, 'a').next(), caseRng(1, 'b').next());
});

test('synthetic policy: 200 rules, deterministic, loads, decides; request pools are deterministic and shaped', () => {
  const doc = syntheticPolicyDoc(200);
  assert.equal((doc['rules'] as unknown[]).length, 200);
  assert.equal(JSON.stringify(doc), JSON.stringify(syntheticPolicyDoc(200)));
  assert.notEqual(JSON.stringify(doc), JSON.stringify(syntheticPolicyDoc(201)));
  const p = loadSyntheticPolicy(200);
  assert.equal(p.document.rules.length, 200);
  for (const shape of ['tiny', 'kib1', 'kib8', 'list64'] as const) {
    const pool = syntheticRequests(mulberry32(5), shape, 20);
    assert.deepEqual(pool, syntheticRequests(mulberry32(5), shape, 20));
    const args = (pool[0] as { args: Record<string, unknown> }).args;
    const aLen = (args['a'] as string).length;
    assert.equal(aLen, shape === 'kib1' ? 1024 : shape === 'kib8' ? 8192 : 16);
    assert.equal(Array.isArray(args['list']) ? (args['list'] as unknown[]).length : 0, shape === 'list64' ? 64 : 0);
    for (const r of pool) assert.ok(['permit', 'deny'].includes(decide(p, r).effect));
  }
});

test('fixture request pool covers allow, deny, taint and invalid-args outcomes', () => {
  const p = loadFixturePolicy();
  assert.equal(p.document.rules.length, 8);
  const seen = new Set<string>();
  for (const r of fixtureRequests(mulberry32(9), 400)) seen.add(decide(p, r).reason_code);
  for (const code of ['permitted', 'denied_by_rule', 'tainted_session', 'invalid_args']) assert.ok(seen.has(code), `reason ${code} present`);
});

// ---------------------------------------------------------------- options, machine, hypotheses
test('parseOptions: profiles, filters, child mode and unknown flags', () => {
  assert.equal(parseOptions([]).profile, 'full');
  assert.equal(parseOptions(['--quick']).profile, 'quick');
  assert.equal(parseOptions(['--smoke']).profile, 'smoke');
  assert.deepEqual(parseOptions(['--only', 'W1,W4.permit']).only, ['W1', 'W4.permit']);
  assert.deepEqual(parseOptions(['--child', 'W1.fixture-mix', '--cold', '--rep', '3']).child, { id: 'W1.fixture-mix', cold: true, rep: 3 });
  assert.throws(() => parseOptions(['--nope']));
  assert.throws(() => parseOptions(['--profile', 'x']));
  assert.throws(() => parseOptions(['--only']));
});

test('profiles: full profile meets the protocol minimums', () => {
  const f = PROFILES.full;
  assert.ok(f.warmup >= 2000 && f.decideIters >= 10_000 && f.guardIters >= 2000 && f.reps === 5 && f.coldIters === 100);
  assert.deepEqual(f.w8Rows, [1000, 10_000, 100_000]);
  assert.deepEqual(f.concurrency, [1, 4, 16, 64]);
});

test('machine info has the protocol fields', () => {
  const m = machineInfo();
  assert.ok(m.cpu_model.length > 0 && m.logical_cores >= 1 && m.ram_bytes > 0 && m.os.length > 0 && m.node.startsWith('v'));
  assert.match(m.date, /^\d{4}-\d\d-\d\dT/);
  assert.match(localDate(new Date(2026, 0, 5)), /^2026-01-05$/);
});

test('hypotheses: thresholds, boundaries and not-evaluated', () => {
  const agg = (p50: number, p99: number) => ({ runs: 5, n_per_run: 1, p50: { median: p50, min: p50, max: p50, cv: 0 }, p95: { median: p99, min: p99, max: p99, cv: 0 }, p99: { median: p99, min: p99, max: p99, cv: 0 }, min_ns: 0, max_ns: 0, mean: { median: p50, min: p50, max: p50, cv: 0 } });
  const ok = {
    'W2.tiny': agg(1e4, 5e5), 'W2.kib1': agg(1e4, 5e5), 'W2.kib8': agg(1e4, 9.99e5), 'W2.list64': agg(1e4, 5e5),
    'W4.permit.FULL': agg(3e6, 9.9e6), 'W4.deny.FULL': agg(3e6, 5e6), 'W6.direct': agg(1e6, 2e6), 'W6.proxy': agg(2e6, 16.9e6),
  };
  const h = evaluateHypotheses({ aggregates: ok, verifyWallMs: { 100_000: 29_999 } });
  assert.deepEqual(h.map((x) => x.status), ['met', 'met', 'met', 'met']);
  const bad = evaluateHypotheses({
    aggregates: { ...ok, 'W2.kib8': agg(1e4, 1e6), 'W4.deny.FULL': agg(3e6, 10e6), 'W6.proxy': agg(2e6, 17e6) },
    verifyWallMs: { 100_000: 30_000 },
  });
  assert.deepEqual(bad.map((x) => x.status), ['MISSED', 'MISSED', 'MISSED', 'MISSED']);
  assert.ok(bad[3]?.numbers.includes('30.00'));
  const none = evaluateHypotheses({ aggregates: { 'W2.tiny': agg(1, 1) }, verifyWallMs: {} });
  assert.deepEqual(none.map((x) => x.status), ['not evaluated', 'not evaluated', 'not evaluated', 'not evaluated']);
});

// ---------------------------------------------------------------- the workloads run
test('guard over the no-op stub store permits and denies without writing', async () => {
  const guard = benchGuard(stubStore(), true);
  assert.equal((await guard.call('read_file', { path: '/workspace/docs/readme.md' }, { scopes: ['sales'] })).ok, true);
  const d = await guard.call('delete_file', { path: '/workspace/x' }, { scopes: ['sales'] });
  assert.equal(d.ok, false);
  guard.close();
});

test('every case is registered once with a unique id and covers W1-W8', () => {
  const all = allCases(PROFILES.full);
  assert.equal(new Set(all.map((c) => c.id)).size, all.length);
  for (const w of ['W1', 'W2', 'W3', 'W4', 'W5', 'W6', 'W7', 'W8']) assert.ok(all.some((c) => c.workload === w), w);
  assert.deepEqual(all.filter((c) => c.workload === 'W5').map((c) => c.id), ['W5.c1', 'W5.c4', 'W5.c16', 'W5.c64', 'W5.procs4']);
  assert.deepEqual(all.filter((c) => c.workload === 'W8').map((c) => c.id), ['W8.rows1000', 'W8.rows10000', 'W8.rows100000']);
});

for (const id of ['W1.fixture-mix', 'W2.tiny', 'W2.kib8', 'W2.list64', 'W3.fixture-mix', 'W3.synth-kib1', 'W7.permit.stub', 'W7.deny.stub']) {
  test(`case ${id} runs in-process with tiny counts`, async () => {
    const rec = await executeRun(caseById(id), smoke, false, 1);
    assert.equal(rec.output.kind, 'latency');
    if (rec.output.kind !== 'latency') return;
    assert.equal(rec.output.stats.n, rec.iters);
    assert.equal(rec.iters, id.startsWith('W7') ? smoke.guardIters : smoke.decideIters);
    assert.ok(rec.output.stats.p50 > 0 && rec.output.stats.p50 <= rec.output.stats.p95 && rec.output.stats.p95 <= rec.output.stats.p99);
    if (id.startsWith('W7')) assert.equal(rec.output.extra['unexpected_results'], 0);
  });
}

for (const id of ['W4.permit.FULL', 'W4.permit.NORMAL', 'W4.deny.FULL', 'W4.deny.NORMAL', 'W5.c4']) {
  test(`case ${id} runs with a real store and writes audit rows`, async () => {
    const rec = await executeRun(caseById(id), smoke, false, 1);
    assert.equal(rec.output.kind, 'latency');
    if (rec.output.kind !== 'latency') return;
    assert.equal(rec.output.extra['unexpected_results'], 0, 'every call took the intended path');
    const calls = smoke.warmup + smoke.guardIters;
    assert.ok((rec.output.extra['audit_rows'] as number) >= calls, 'at least one durable row per call');
    if (id.startsWith('W5')) assert.ok((rec.output.extra['throughput_per_s'] as number) > 0);
  });
}

test('cold run: no warm-up, coldIters measured iterations', async () => {
  const rec = await executeRun(caseById('W1.fixture-mix'), smoke, true, 0);
  assert.equal(rec.cold, true);
  assert.equal(rec.warmup, 0);
  assert.equal(rec.iters, smoke.coldIters);
  assert.equal(rec.output.kind === 'latency' ? rec.output.stats.n : -1, smoke.coldIters);
});

test('W5.procs4: four processes append to one store, every row lands', { timeout: 120_000 }, async () => {
  const rec = await executeRun(caseById('W5.procs4'), smoke, false, 1);
  if (rec.output.kind !== 'latency') throw new Error('expected latency');
  const x = rec.output.extra;
  assert.equal(x['processes'], 4);
  assert.equal(x['worker_nonzero_exits'], 0);
  assert.equal(x['audit_rows'], x['rows_expected']);
});

test('W6: proxy and direct round trips both work and the proxy writes audit rows', { timeout: 120_000 }, async () => {
  const direct = await executeRun(caseById('W6.direct'), smoke, false, 1);
  const proxy = await executeRun(caseById('W6.proxy'), smoke, false, 1);
  if (direct.output.kind !== 'latency' || proxy.output.kind !== 'latency') throw new Error('expected latency');
  assert.equal(direct.output.extra['error_replies'], 0);
  assert.equal(proxy.output.extra['error_replies'], 0);
  const calls = smoke.warmup + smoke.guardIters;
  assert.equal(proxy.output.extra['tool_decision_rows'], calls);
  assert.ok((proxy.output.extra['audit_rows'] as number) >= calls);
});

test('W8: store of N rows, report and verify-chain succeed with RSS recorded', { timeout: 120_000 }, async () => {
  const rec = await executeRun(caseById('W8.rows50'), smoke, false, 1);
  if (rec.output.kind !== 'custom') throw new Error('expected custom');
  const d = rec.output.data as { rows: number; head_seq: number; db_bytes: number; report: Record<string, number>; verify_chain: Record<string, number | string> };
  assert.equal(d.rows, 50);
  assert.equal(d.head_seq, 50);
  assert.ok(d.db_bytes > 0);
  assert.equal(d.report['exit_code'], 0);
  assert.ok((d.report['html_bytes'] as number) > 1000);
  assert.ok((d.report['peak_rss_mb'] as number) > 10);
  assert.equal(d.verify_chain['exit_code'], 0);
  assert.equal(d.verify_chain['stdout_first_line'], 'OK');
});

// ---------------------------------------------------------------- end to end: parent, child processes, files
test('parent runs cases in separate child processes and writes valid, small JSON', { timeout: 240_000 }, async () => {
  const out = join(scratch(), 'results');
  const lines: string[] = [];
  const r = await parentMain({ profile: 'smoke', only: ['W1', 'W4.permit.NORMAL', 'W8.rows50'], out, child: null }, (l) => { lines.push(l); });
  assert.equal(r.summary.failures.length, 0, JSON.stringify(r.summary.failures));
  const files = readdirSync(out).sort();
  assert.deepEqual(files, ['W1.fixture-mix.json', 'W4.permit.NORMAL.json', 'W8.rows50.json', 'summary.json']);
  for (const f of files) {
    const p = join(out, f);
    assert.ok(statSync(p).size < 60_000, `${f} is small`);
    JSON.parse(readFileSync(p, 'utf8')); // valid JSON
  }
  const w1 = JSON.parse(readFileSync(join(out, 'W1.fixture-mix.json'), 'utf8'));
  assert.equal(w1.seed, 20_260_101);
  assert.equal(w1.runs.length, smoke.reps);
  assert.equal(w1.runs.length, 2);
  assert.ok(w1.cold && w1.cold.cold === true && w1.cold.output.stats.n === smoke.coldIters);
  assert.equal(w1.aggregate.runs, smoke.reps);
  for (const run of w1.runs) {
    assert.equal(Array.isArray(run.output.samples), false, 'no raw sample arrays');
    assert.equal(run.output.stats.n, smoke.decideIters);
  }
  assert.ok(w1.machine.cpu_model && w1.machine.logical_cores > 0);
  const summary = JSON.parse(readFileSync(join(out, 'summary.json'), 'utf8'));
  assert.equal(summary.schema, 'prysm-bench-summary/1');
  assert.equal(summary.profile, 'smoke');
  assert.equal(summary.hypotheses.length, 4);
  assert.ok(summary.latency_ms['W1.fixture-mix'].p99.median >= summary.latency_ms['W1.fixture-mix'].p50.median);
  assert.ok(summary.w8['W8.rows50'].verify_chain.wall_ms > 0);
  assert.ok(lines.some((l) => l.startsWith('H1 ')));
  assert.ok(existsSync(join(out, 'summary.json')));
});

test('an unknown --only filter is an error, not an empty run', async () => {
  await assert.rejects(parentMain({ profile: 'smoke', only: ['W99'], out: join(scratch(), 'x'), child: null }, () => undefined), /no case matches/);
});
