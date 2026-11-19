// M2-21 (AUDIT-SPEC section 10): a flood of identical denials cannot hide a later, different denial.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { loadPolicy } from '../../src/core/index.ts';
import { kit } from '../support/guard-kit.ts';
import { cleanup } from '../support/tmp.ts';

after(cleanup);

test('M2-21: after the deny budget is spent by a flood, a denial with a new signature is still recorded', async () => {
  const k = kit({ guardOpts: { maxDenyRowsPerWindow: 3, bestEffortWindowMs: 60_000 } });
  for (let i = 0; i < 50; i++) await k.guard.call('read_file', { path: '/secret/' + i });
  const before = k.decisionRows().filter((r) => r.reason_code === 'denied_by_rule').length;
  assert.equal(before, 3, 'the flood itself is capped by the budget');
  const r = await k.guard.call('denied_by_default', { x: 'a' });
  const row = k.decisionRows().find((x) => x.id === r.decision_id);
  assert.ok(row, 'the different denial has a row');
  assert.equal(row.reason_code, 'default_deny');
  const dropped = (row.outcome as { dropped_before?: Record<string, number> } | null)?.dropped_before;
  assert.ok(dropped !== undefined && (dropped['policy_deny'] ?? 0) >= 47, 'the drop count rides on the next written row');
  // a repeat of the same new signature is not novel any more and is dropped
  const r2 = await k.guard.call('denied_by_default', { x: 'b' });
  assert.equal(k.decisionRows().some((x) => x.id === r2.decision_id), false);
  k.store.close();
});

test('M2-21: the novelty reserve is bounded (64 per window), so varied denials cannot write without limit', async () => {
  // 80 policy tools with no permit rule: each call is a default deny with its own signature (the tool differs)
  const tools: Record<string, unknown> = {};
  const reg: Record<string, () => string> = {};
  for (let i = 0; i < 80; i++) {
    tools['t' + i] = { risk: 'low', external_effect: false, read_only: true, fail_mode: 'closed', args: {} };
    reg['t' + i] = () => 'x';
  }
  const policy = loadPolicy(JSON.stringify({ policy_schema_version: 1, name: 'm221', mode: 'enforce', tools, rules: [] }));
  const k = kit({ policy, tools: () => reg as never, guardOpts: { maxDenyRowsPerWindow: 1, bestEffortWindowMs: 60_000 } });
  for (let i = 0; i < 80; i++) await k.guard.call('t' + i, {});
  const written = k.decisionRows().filter((r) => r.reason_code === 'default_deny').length;
  assert.equal(written, 1 + 64, 'budget (1) plus the novelty reserve (64); the other 15 are dropped');
  k.store.close();
});

test('M2-21: repeats of a novel signature do not reuse the reserve', async () => {
  const k = kit({ guardOpts: { maxDenyRowsPerWindow: 1, bestEffortWindowMs: 60_000 }, extraRules: [] });
  // the same tool with different denying rules: d.secret (rule) and default deny on a policy-unknown arg path
  await k.guard.call('read_file', { path: '/secret/a' }); // uses the budget
  const ids: string[] = [];
  for (let i = 0; i < 3; i++) ids.push((await k.guard.call('denied_by_default', { x: String(i) })).decision_id);
  const written = ids.filter((id) => k.decisionRows().some((r) => r.id === id)).length;
  assert.equal(written, 1, 'one novel signature is written, its repeats are not');
  k.store.close();
});
