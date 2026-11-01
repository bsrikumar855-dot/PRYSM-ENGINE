// AUDIT-SPEC §6 (v1.3) guard amendments: per-class budgets, single session state, admin facet.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { StoreError, openStore } from '../../src/store/index.ts';
import type { Store } from '../../src/store/index.ts';
import { loadPolicy } from '../../src/core/index.ts';
import { createGuard, createGuardWithAdmin } from '../../src/guard/index.ts';
import type { GuardResult } from '../../src/guard/index.ts';
import { POLICY_DOC } from '../support/policy.ts';
import { kit, faulty, defaultTools, KEY } from '../support/guard-kit.ts';
import { cleanup, tmpDir, dbPath } from '../support/tmp.ts';

after(cleanup);

const reason = (r: GuardResult): string => {
  assert.equal(r.ok, false);
  assert.ok('blocked' in r && r.blocked === true, 'expected blocked');
  return (r as { reason_code: string }).reason_code;
};
const rowFor = (k: ReturnType<typeof kit>, id: string) => k.rows().find((r) => r.id === id);
const email = { to: 'a@b.c', subject: 's', body: 'b' };

// ---------------------------------------------------------------- item 3
test('budgets are independent: 1000+ unknown_tool calls never suppress a rule-denied row or a tool_result row', async () => {
  const k = kit(); // default budgets: pre_evaluate 200, policy_deny 1000, tool_result 1000
  k.lines.length = 0;
  for (let i = 0; i < 1100; i++) await k.guard.call('no_such_tool_' + (i % 7), {});
  const pre = k.decisionRows().filter((r) => r.reason_code === 'unknown_tool');
  assert.equal(pre.length, 200);
  const limitLines = k.lines.map((l) => JSON.parse(l) as Record<string, unknown>).filter((o) => o['kind'] === 'rate_limit');
  assert.equal(limitLines.length, 1, 'at most one sink line per class per window');
  assert.equal(limitLines[0]?.['class'], 'pre_evaluate');
  // other classes are untouched by the flood
  const denied = await k.guard.call('read_file', { path: '/secret/x' });
  assert.equal(reason(denied), 'denied');
  const drow = rowFor(k, (denied as { decision_id: string }).decision_id);
  assert.ok(drow, 'rule-denied row recorded despite the pre-evaluate flood');
  assert.equal(drow.reason_code, 'denied_by_rule');
  assert.deepEqual((drow.outcome as { dropped_before: unknown }).dropped_before, { pre_evaluate: 900 }, 'drop count carried per class');
  const ok = await k.guard.call('read_file', { path: '/a' });
  assert.equal(ok.ok, true);
  const res = k.rows().find((r) => r.kind === 'tool_result' && r.decision_id === (ok as { decision_id: string }).decision_id);
  assert.ok(res, 'tool_result row recorded despite the flood');
  assert.equal((res.outcome as Record<string, unknown>)['dropped_before'], undefined, 'counts are recorded once');
  k.store.close();
});

test('each class floods independently (deny and tool_result floods do not suppress other classes)', async () => {
  const k = kit({ guardOpts: { maxPreEvaluateRowsPerWindow: 2, maxDenyRowsPerWindow: 2, maxResultRowsPerWindow: 2, bestEffortWindowMs: 60_000 } });
  for (let i = 0; i < 5; i++) await k.guard.call('read_file', { path: '/secret/' + i });
  for (let i = 0; i < 5; i++) await k.guard.call('read_file', { path: '/ok/' + i }); // results: 2 recorded, 3 dropped
  const rows = () => k.rows();
  assert.equal(rows().filter((r) => r.kind === 'decision' && r.reason_code === 'denied_by_rule').length, 2);
  assert.equal(rows().filter((r) => r.kind === 'tool_result').length, 2);
  // pre-evaluate budget is still full
  const u = await k.guard.call('unknown_one', {});
  assert.ok(rowFor(k, (u as { decision_id: string }).decision_id), 'pre-evaluate row recorded');
  assert.deepEqual((rowFor(k, (u as { decision_id: string }).decision_id)?.outcome as { dropped_before: unknown }).dropped_before, { tool_result: 3 });
  const lines = k.lines.map((l) => JSON.parse(l) as Record<string, unknown>).filter((o) => o['kind'] === 'rate_limit').map((o) => o['class']).sort();
  assert.deepEqual(lines, ['policy_deny', 'tool_result']);
  // permit decision rows are never capped
  const before = k.decisionRows().length;
  for (let i = 0; i < 4; i++) await k.guard.call('search_docs', { query: 'q' + i });
  assert.equal(k.decisionRows().length, before + 4);
  k.store.close();
});

test('the single maxBestEffortRowsPerWindow option no longer exists', () => {
  const k = kit();
  const opts = { maxBestEffortRowsPerWindow: 1 } as Record<string, unknown>;
  // not part of the options type: it is simply ignored (the three class budgets apply)
  const g = createGuard({ policy: k.policy, store: k.store, agentId: 'a', tools: defaultTools({}), secondarySink: () => {}, ...(opts as object) });
  assert.deepEqual(Object.keys(g).sort(), ['call', 'close', 'session']);
  k.store.close();
});

// ---------------------------------------------------------------- item 4
test('stale handle cannot shed taint: A=session(a), evict, B=session(a), B.taint(), A.call(external-effect) is blocked', async () => {
  const k = kit({ guardOpts: { maxSessions: 2 } });
  const A = k.guard.session('a');
  k.guard.session('x');
  k.guard.session('y'); // cap 2: evicts the least-recently-used untainted session (a)
  const B = k.guard.session('a'); // re-registered under the same id (evicts x)
  assert.notEqual(A, B);
  B.taint();
  assert.equal(A.tainted, true, 'taint merges both ways through the registered state');
  const r = await A.call('send_email', email);
  assert.equal(reason(r), 'denied');
  assert.equal(k.count('send_email'), 0);
  const row = rowFor(k, (r as { decision_id: string }).decision_id);
  assert.equal(row?.reason_code, 'tainted_session');
  assert.equal(row?.session_id, 'a');
  k.store.close();
});

test('stale handle taint flows to the registered state; a stale handle re-registers when the id is free', async () => {
  const k = kit({ guardOpts: { maxSessions: 2 } });
  const A = k.guard.session('a');
  k.guard.session('x');
  k.guard.session('y'); // a evicted
  const B = k.guard.session('a'); // new registered state
  A.taint(); // taint set through the stale handle
  assert.equal(B.tainted, true);
  assert.equal(reason(await B.call('send_email', email)), 'denied');
  // a lone evicted handle (id free) re-registers its own state when used
  const k2 = kit({ guardOpts: { maxSessions: 1 } });
  const S = k2.guard.session('s');
  k2.guard.session('t'); // evicts s
  assert.equal((await S.call('read_file', { path: '/a' })).ok, true);
  S.taint();
  assert.equal(k2.guard.session('s'), S, 'the re-registered state is the one the guard hands out');
  assert.equal(k2.guard.session('s').tainted, true);
  k.store.close();
  k2.store.close();
});

test('taintsSession taint on an evicted handle is not lost', async () => {
  const k = kit({
    guardOpts: { maxSessions: 2 },
    tools: (calls) => ({ ...defaultTools(calls), search_docs: { fn: () => 'r', taintsSession: true } }),
  });
  const A = k.guard.session('a');
  k.guard.session('x');
  k.guard.session('y');
  const B = k.guard.session('a');
  assert.equal((await A.call('search_docs', { query: 'q' })).ok, true);
  assert.equal(B.tainted, true);
  assert.equal(reason(await B.call('send_email', email)), 'denied');
  k.store.close();
});

// ---------------------------------------------------------------- item 5
test('Guard has no setTools; createGuard returns only the guard; createGuardWithAdmin returns {guard, admin}', () => {
  const k = kit();
  const g = createGuard({ policy: k.policy, store: k.store, agentId: 'a', tools: defaultTools({}), secondarySink: () => {} });
  assert.deepEqual(Object.keys(g).sort(), ['call', 'close', 'session']);
  assert.equal((g as unknown as Record<string, unknown>)['setTools'], undefined);
  assert.equal((g as unknown as Record<string, unknown>)['admin'], undefined);
  const both = createGuardWithAdmin({ policy: k.policy, store: k.store, agentId: 'a', tools: defaultTools({}), secondarySink: () => {} });
  assert.deepEqual(Object.keys(both).sort(), ['admin', 'guard']);
  assert.deepEqual(Object.keys(both.guard).sort(), ['call', 'close', 'session']);
  assert.deepEqual(Object.keys(both.admin), ['setTools', 'denyUnexposed']);
  assert.ok(Object.isFrozen(both.admin) && Object.isFrozen(both.guard));
  k.store.close();
});

test('admin.setTools appends a durable tools_replaced row before swapping; failure leaves the registry unchanged', async () => {
  let failing = false;
  const k = kit({ wrap: (s) => faulty(s, (ev) => failing && ev.kind === 'policy_activate') });
  const calls: string[] = [];
  const next = { read_file: () => { calls.push('new'); return 'new'; }, note: () => 'n' };
  const activationRows = () => k.rows().filter((r) => r.kind === 'policy_activate');
  const before = activationRows().length;
  // failure: the row cannot be written => throws, nothing changes
  failing = true;
  assert.throws(() => k.admin.setTools(next as never), (e: unknown) => e instanceof StoreError);
  assert.equal(activationRows().length, before);
  assert.equal((await k.guard.call('read_file', { path: '/a' })).ok && k.count('read_file'), 1, 'old registry still in force');
  assert.equal(calls.length, 0);
  failing = false;
  // success: audited row, then the swap
  k.admin.setTools(next as never);
  const rows = activationRows();
  assert.equal(rows.length, before + 1);
  const last = rows.at(-1);
  const o = last?.outcome as Record<string, unknown>;
  assert.equal(o['event'], 'tools_replaced');
  assert.equal(o['tool_names_hash'], createHash('sha256').update(JSON.stringify(['note', 'read_file'])).digest('hex'));
  assert.equal(last?.agent_id, 'agent-1');
  assert.equal(last?.effect, null);
  assert.equal(last?.tool, null);
  assert.equal(last?.enforcement, 'enforced');
  assert.equal((await k.guard.call('read_file', { path: '/a' })).ok, true);
  assert.deepEqual(calls, ['new']);
  assert.equal(reason(await k.guard.call('search_docs', { query: 'q' })), 'unknown_tool');
  // invalid registry: TypeError, no row, registry unchanged
  const n = activationRows().length;
  for (const bad of [null, 5, { x: 5 }]) assert.throws(() => k.admin.setTools(bad as never), TypeError);
  assert.equal(activationRows().length, n);
  assert.equal((await k.guard.call('read_file', { path: '/a' })).ok, true);
  assert.equal(k.store.verify().ok, true);
  k.store.close();
});

test('admin.setTools with an invalid guard clock throws and leaves the registry unchanged', async () => {
  let bad = false;
  const k = kit({ clock: () => (bad ? NaN : 1000) });
  bad = true;
  assert.throws(() => k.admin.setTools({ read_file: () => 'x' } as never));
  bad = false;
  assert.equal((await k.guard.call('search_docs', { query: 'q' })).ok, true, 'original tools still registered');
  k.store.close();
});

test('restarting a guard after setTools does not append a spurious activation row for the same policy', () => {
  const path = dbPath(tmpDir());
  const store: Store = openStore({ path, hmacKey: KEY });
  const policy = loadPolicy(JSON.stringify(POLICY_DOC()));
  const { admin } = createGuardWithAdmin({ policy, store, agentId: 'a', tools: defaultTools({}), secondarySink: () => {} });
  admin.setTools({ read_file: () => 'x' } as never);
  const n = store.iterate().filter((r) => r.kind === 'policy_activate').length;
  createGuard({ policy, store, agentId: 'a', tools: defaultTools({}), secondarySink: () => {} });
  assert.equal(store.iterate().filter((r) => r.kind === 'policy_activate').length, n);
  store.close();
});
