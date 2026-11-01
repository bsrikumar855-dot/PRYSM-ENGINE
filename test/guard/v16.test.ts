// REPORT-SPEC §5.1 / AUDIT-SPEC DEC-34: every decision row carries outcome.deny_n (deny ids first in rule_ids).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createGuardWithAdmin } from '../../src/guard/index.ts';
import { loadPolicy } from '../../src/core/index.ts';
import { openStore } from '../../src/store/index.ts';
import { POLICY_DOC, rule } from '../support/policy.ts';
import { KEY, kit } from '../support/guard-kit.ts';
import { cleanup, tmpDir, dbPath } from '../support/tmp.ts';

after(cleanup);
type Out = { deny_n?: unknown; will_execute?: unknown };

test('deny_n counts the deny ids at the start of rule_ids (rule deny, permit, default deny)', async () => {
  const k = kit();
  const denied = await k.guard.call('read_file', { path: '/secret/x' }); // d.secret + p.read
  const ok = await k.guard.call('read_file', { path: '/ok' }); // p.read
  const dd = await k.guard.call('denied_by_default', { x: 'a' }); // none
  const rows = k.decisionRows();
  const by = (id: string) => rows.find((r) => r.id === id) as { rule_ids: string[]; outcome: Out };
  const a = by((denied as { decision_id: string }).decision_id);
  assert.deepEqual(a.rule_ids, ['d.secret', 'p.read']);
  assert.equal(a.outcome.deny_n, 1);
  const b = by((ok as { decision_id: string }).decision_id);
  assert.equal(b.outcome.deny_n, 0);
  assert.equal(b.outcome.will_execute, true, 'will_execute is kept next to deny_n');
  assert.equal(by((dd as { decision_id: string }).decision_id).outcome.deny_n, 0);
  for (const r of rows) assert.equal(Number.isInteger((r.outcome as Out).deny_n), true);
  k.store.close();
});

test('deny_n with two deny rules and a permit rule', async () => {
  const k = kit({ extraRules: [rule('deny', 'd.second', { tools: ['read_file'], args: { path: { glob: '/secret*' } } })] });
  const r = await k.guard.call('read_file', { path: '/secret/y' });
  const row = k.decisionRows().find((x) => x.id === (r as { decision_id: string }).decision_id) as { rule_ids: string[]; outcome: Out };
  assert.equal(row.outcome.deny_n, 2);
  assert.equal(row.rule_ids.length, 3);
  k.store.close();
});

test('pre-evaluate rows (unknown tool, invalid ctx, non-string tool) and denyUnexposed rows carry deny_n 0', async () => {
  const k = kit();
  await k.guard.call('does_not_exist', {});
  await k.guard.call('read_file', {}, { agentId: 'x' } as never);
  await k.guard.call(42 as never, {});
  await k.guard.call('read_file', { path: 5 }); // invalid_args
  const rows = k.decisionRows();
  assert.ok(rows.length >= 4);
  for (const r of rows) assert.equal((r.outcome as Out | null)?.deny_n, 0);
  k.store.close();

  const store = openStore({ path: dbPath(tmpDir()), hmacKey: KEY });
  const { admin } = createGuardWithAdmin({
    policy: loadPolicy(JSON.stringify(POLICY_DOC())), store, agentId: 'a', tools: {}, secondarySink: () => {},
  } as never);
  const d = admin.denyUnexposed('read_file', 'not_ready');
  const row = store.getEvent(d.decision_id);
  assert.equal((row?.outcome as Out).deny_n, 0);
  store.close();
});

test('monitor_only would-be deny keeps its deny_n', async () => {
  const k = kit({ mode: 'monitor_only' });
  const r = await k.guard.call('read_file', { path: '/secret/z' });
  const row = k.decisionRows().find((x) => x.id === (r as { decision_id: string }).decision_id);
  assert.equal((row?.outcome as Out).deny_n, 1);
  assert.equal((row?.outcome as Out).will_execute, true);
  k.store.close();
});
