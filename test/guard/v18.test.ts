// AUDIT-SPEC §8 (v1.4): result rows of executed permits are not rate-limited by default.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { openStore } from '../../src/store/index.ts';
import { KEY, kit, faulty } from '../support/guard-kit.ts';
import { cleanup, tmpDir, dbPath } from '../support/tmp.ts';

after(cleanup);
type Out = { dropped_before?: Record<string, number> };

test('3000 sequential permitted calls produce 3000 tool_result rows and no outcome_unknown', async () => {
  const store = openStore({ path: dbPath(tmpDir()), hmacKey: KEY, synchronous: 'NORMAL' });
  const k = kit({ store });
  for (let i = 0; i < 3000; i++) {
    const r = await k.guard.call('read_file', { path: '/ok/' + String(i) });
    assert.equal((r as { ok: boolean }).ok, true);
  }
  const rows = k.rows();
  assert.equal(rows.filter((r) => r.kind === 'tool_result').length, 3000);
  assert.equal(rows.filter((r) => r.kind === 'decision' && (r.outcome as { will_execute?: boolean }).will_execute === true).length, 3000);
  const v = store.verify();
  assert.deepEqual(v.warnings.filter((w) => w.code === 'outcome_unknown' || w.code === 'orphan_result'), []);
  assert.equal(rows.some((r) => (r.outcome as Out | null)?.dropped_before !== undefined), false, 'nothing was dropped');
  store.close();
});

test('a finite maxResultRowsPerWindow is still a hard ceiling: excess result rows are dropped and counted', async () => {
  const k = kit({ guardOpts: { maxResultRowsPerWindow: 2, bestEffortWindowMs: 60_000 } });
  for (let i = 0; i < 5; i++) await k.guard.call('read_file', { path: '/ok/' + String(i) });
  assert.equal(k.rows().filter((r) => r.kind === 'tool_result').length, 2);
  assert.ok(k.lines.some((l) => l.includes('"audit_skipped"') && l.includes('"tool_result"')), 'one rate_limit sink line');
  // the drop count rides on the next row that is written (here a rule-deny row)
  const k2 = kit({ guardOpts: { maxResultRowsPerWindow: 1, bestEffortWindowMs: 60_000 } });
  for (let i = 0; i < 3; i++) await k2.guard.call('read_file', { path: '/ok/' + String(i) });
  const d = await k2.guard.call('read_file', { path: '/secret/z' });
  const row = k2.rows().find((r) => r.id === (d as { decision_id: string }).decision_id);
  assert.deepEqual((row?.outcome as Out).dropped_before, { tool_result: 2 });
  k.store.close();
  k2.store.close();
});

test('an invalid finite/negative ceiling is still rejected; Infinity is accepted', () => {
  assert.throws(() => kit({ guardOpts: { maxResultRowsPerWindow: -1 } }));
  assert.throws(() => kit({ guardOpts: { maxResultRowsPerWindow: 1.5 } }));
  kit({ guardOpts: { maxResultRowsPerWindow: Infinity } }).store.close();
});

test('a failing store never blocks a permitted call once its decision row is durable (result row is best-effort)', async () => {
  const k = kit({ wrap: (s) => faulty(s, (ev) => ev.kind === 'tool_result') });
  const r = await k.guard.call('read_file', { path: '/ok/x' });
  assert.equal((r as { ok: boolean }).ok, true);
  assert.equal(k.count('read_file'), 1);
  assert.ok(k.lines.some((l) => l.includes('"audit_write_failed"')), 'sink line on failure');
  const rows = k.rows();
  assert.equal(rows.filter((x) => x.kind === 'tool_result').length, 0);
  assert.equal(rows.filter((x) => x.kind === 'decision').length, 1);
  k.store.close();
});

test('at most one result row per decision, outside the budget, even with the other classes exhausted', async () => {
  const k = kit({ guardOpts: { maxPreEvaluateRowsPerWindow: 1, maxDenyRowsPerWindow: 1 } });
  for (let i = 0; i < 5; i++) {
    await k.guard.call('nope_' + String(i), {});
    await k.guard.call('read_file', { path: '/secret/' + String(i) });
  }
  for (let i = 0; i < 4; i++) await k.guard.call('read_file', { path: '/ok/' + String(i) });
  const rows = k.rows();
  const results = rows.filter((x) => x.kind === 'tool_result');
  assert.equal(results.length, 4);
  assert.equal(new Set(results.map((x) => x.decision_id)).size, 4);
  k.store.close();
});
