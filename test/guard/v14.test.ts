// PROXY-SPEC §9.5: GuardAdmin.denyUnexposed and setTools meta.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createGuardWithAdmin } from '../../src/guard/index.ts';
import { loadPolicy } from '../../src/core/index.ts';
import { openStore } from '../../src/store/index.ts';
import { POLICY_DOC } from '../support/policy.ts';
import { KEY } from '../support/guard-kit.ts';
import { cleanup, tmpDir, dbPath } from '../support/tmp.ts';
import { existsSync, readFileSync } from 'node:fs';

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

test('denyUnexposed: tool_hmac is the keyed HMAC of the raw name, and the raw name never reaches the DB files', () => {
  const dir = tmpDir();
  const store = openStore({ path: dbPath(dir), hmacKey: KEY });
  const policy = loadPolicy(JSON.stringify(POLICY_DOC('enforce')));
  const g = createGuardWithAdmin({ policy, store, agentId: 'a', tools: {}, secondarySink: () => undefined });
  const raw = 'RAW-NAME-not-in-policy-7f3a';
  const r = g.admin.denyUnexposed(raw, 'tool_not_offered');
  const row = store.iterate({ limit: 100 }).find((x) => x.id === r.decision_id) as { tool: string; outcome: Json };
  assert.equal(row.tool, '?');
  assert.equal(row.outcome['tool_hmac'], store.hmac('tool', raw));
  assert.match(String(row.outcome['tool_hmac']), /^[0-9a-f]{32}$/);
  store.close();
  const p = dbPath(dir);
  const dump = [p, p + '-wal'].filter((f) => existsSync(f)).map((f) => readFileSync(f).toString('latin1')).join('');
  assert.ok(!dump.includes(raw));
});

test('denyUnexposed after guard.close() writes no row and returns an id only', () => {
  const { store, g } = mk();
  g.guard.close();
  const n = store.count();
  const r = g.admin.denyUnexposed('read_file', 'schema_changed');
  assert.match(r.decision_id, /^[0-9a-f-]{36}$/);
  assert.equal(store.count(), n);
  store.close();
});

test('activation lookup scans back over policy_activate rows and skips ones without outcome.policy_version', () => {
  const dir = tmpDir();
  const p = dbPath(dir);
  const policy = loadPolicy(JSON.stringify(POLICY_DOC('enforce')));
  const mkGuard = (store: ReturnType<typeof openStore>) => createGuardWithAdmin({ policy, store, agentId: 'a', tools: {}, secondarySink: () => undefined });
  const store = openStore({ path: p, hmacKey: KEY });
  mkGuard(store);
  const activations = (): number => store.iterate({ limit: 100000 }).filter((r) => r.kind === 'policy_activate' && typeof (r.outcome as Json | null)?.['policy_version'] === 'string' && (r.outcome as Json)['event'] === undefined).length;
  assert.equal(activations(), 1);
  for (let i = 0; i < 10; i++) {
    store.append({ id: 'cfg-' + String(i), kind: 'policy_activate', agent_id: 'a', effect: null, tool: null, enforcement: 'enforced', policy_version: policy.policy_version, engine_version: 'prysm-engine/1', outcome: { event: i % 2 ? 'proxy_client' : 'proxy_config' } });
  }
  mkGuard(store); // restart: the proxy_config/proxy_client rows are skipped, the earlier activation row matches
  assert.equal(activations(), 1, 'no redundant activation row');
  // beyond 50 policy_activate rows without a version the lookup gives up and writes a fresh activation
  for (let i = 0; i < 60; i++) {
    store.append({ id: 'cfg2-' + String(i), kind: 'policy_activate', agent_id: 'a', effect: null, tool: null, enforcement: 'enforced', policy_version: policy.policy_version, engine_version: 'prysm-engine/1', outcome: { event: 'proxy_config' } });
  }
  mkGuard(store);
  assert.equal(activations(), 2);
  store.close();
});
