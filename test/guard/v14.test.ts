// PROXY-SPEC §9.5: GuardAdmin.denyUnexposed and setTools meta.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createGuardWithAdmin } from '../../src/guard/index.ts';
import { loadPolicy } from '../../src/core/index.ts';
import { openStore } from '../../src/store/index.ts';
import { POLICY_DOC } from '../support/policy.ts';
import { KEY } from '../support/guard-kit.ts';
import { cleanup, tmpDir, dbPath } from '../support/tmp.ts';

after(cleanup);
type Json = Record<string, unknown>;
const mk = (mode: 'enforce' | 'monitor_only' = 'enforce', opts: Json = {}) => {
  const store = openStore({ path: dbPath(tmpDir()), hmacKey: KEY });
  const lines: string[] = [];
  const policy = loadPolicy(JSON.stringify(POLICY_DOC(mode)));
  const g = createGuardWithAdmin({ policy, store, agentId: 'a', tools: {}, secondarySink: (l: string) => { lines.push(l); }, ...opts } as never);
  return { store, g, lines };
};

test('denyUnexposed writes an enforced deny row (even in monitor_only) with reason, policy name only if own key, else ? + tool_hmac', () => {
  for (const mode of ['enforce', 'monitor_only'] as const) {
    const { store, g } = mk(mode);
    const a = g.admin.denyUnexposed('read_file', 'schema_changed');
    const b = g.admin.denyUnexposed('not_a_policy_tool', 'tool_not_offered');
    const c = g.admin.denyUnexposed(42, 'not_ready');
    const rows = store.iterate({ limit: 100 }).filter((r) => r.kind === 'decision');
    const ra = rows.find((r) => r.id === a.decision_id) as { tool: string; effect: string; enforcement: string; reason_code: string; outcome: Json };
    assert.equal(ra.tool, 'read_file');
    assert.equal(ra.effect, 'deny');
    assert.equal(ra.enforcement, 'enforced');
    assert.equal(ra.reason_code, 'unknown_tool');
    assert.equal(ra.outcome['reason'], 'schema_changed');
    const rb = rows.find((r) => r.id === b.decision_id) as { tool: string; outcome: Json };
    assert.equal(rb.tool, '?');
    assert.equal(rb.outcome['tool_hmac'], store.hmac('tool', 'not_a_policy_tool'));
    assert.ok(!JSON.stringify(rb).includes('not_a_policy_tool'));
    const rc = rows.find((r) => r.id === c.decision_id) as { tool: string; outcome: Json };
    assert.equal(rc.tool, '?');
    assert.equal(rc.outcome['reason'], 'not_ready');
    assert.equal(store.verify().ok, true);
    store.close();
  }
});

test('denyUnexposed shares the pre_evaluate budget and carries dropped_before onto the next written row', () => {
  const { store, g, lines } = mk('enforce', { maxPreEvaluateRowsPerWindow: 3 });
  for (let i = 0; i < 10; i++) g.admin.denyUnexposed('x' + String(i), 'tool_not_offered');
  assert.equal(store.iterate({ limit: 100 }).filter((r) => r.kind === 'decision').length, 3);
  assert.equal(lines.filter((l) => l.includes('rate_limit')).length, 1);
  store.close();
  const { store: s2, g: g2 } = mk('enforce', { maxPreEvaluateRowsPerWindow: 1, bestEffortWindowMs: 60 });
  g2.admin.denyUnexposed('a', 'no_pin');
  g2.admin.denyUnexposed('b', 'no_pin');
  g2.admin.denyUnexposed('c', 'no_pin');
  const t0 = Date.now();
  while (Date.now() - t0 < 120) { /* let the window roll */ }
  const next = g2.admin.denyUnexposed('d', 'no_pin');
  const row = s2.iterate({ limit: 100 }).find((r) => r.id === next.decision_id) as { outcome: Json };
  assert.deepEqual(row.outcome['dropped_before'], { pre_evaluate: 2 });
  s2.close();
});

test('setTools meta is merged into the tools_replaced row; core fields win; invalid meta throws and leaves the registry', async () => {
  const { store, g } = mk();
  g.admin.setTools({ note: () => 'x' }, { exposed_n: 1, hidden: { schema_changed: 2 }, label: 'ok', event: 'evil', policy_version: 'evil' });
  const row = store.latest('policy_activate') as { outcome: Json };
  assert.equal(row.outcome['exposed_n'], 1);
  assert.deepEqual(row.outcome['hidden'], { schema_changed: 2 });
  assert.equal(row.outcome['event'], 'tools_replaced');
  assert.notEqual(row.outcome['policy_version'], 'evil');
  const n = store.count();
  for (const bad of [{ a: 'x'.repeat(65) }, { a: [1] }, { hidden: { x: 'str' } }, Object.fromEntries(Array.from({ length: 9 }, (_, i) => ['k' + String(i), 1])), { 'bad key': 1 }, { a: 1.5 }]) {
    assert.throws(() => g.admin.setTools({ search_docs: () => 'y' }, bad as never), TypeError);
  }
  assert.equal(store.count(), n);
  assert.equal((await g.guard.call('note', { text: 't' })).ok, true, 'registry unchanged after rejected meta');
  store.close();
});
