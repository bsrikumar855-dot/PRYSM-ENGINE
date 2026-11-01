// CLI explain (REPORT-SPEC §1.3, §4.3, §4.10, §4.11, A-03).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { openStore } from '../../src/store/index.ts';
import { cleanup, tmpDir, dbPath } from '../support/tmp.ts';
import { POLICY_DOC, rule } from '../support/policy.ts';
import { KEY, kit } from '../support/guard-kit.ts';
import { guardFixture, runCli } from '../support/cli-kit.ts';

after(cleanup);
const fixture = guardFixture();
const ESC = String.fromCharCode(27);
const CR = String.fromCharCode(13);

test('explain: blocked decision without --policy', async () => {
  const f = await fixture;
  const r = await runCli(['explain', f.deniedId, '--db', f.db]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /^verdict +BLOCKED by rule\(s\) d\.secret/m);
  assert.match(r.stdout, /reason_code +denied_by_rule/);
  assert.match(r.stdout, /enforcement +enforced/);
  assert.match(r.stdout, /policy_version +sha256:/);
  assert.match(r.stdout, /args_redacted +\{/);
  assert.match(r.stdout, /will_execute +no/);
  assert.match(r.stdout, /result +none recorded/);
  assert.ok(!r.stdout.includes('glob'), 'no rule detail without --policy');
  assert.ok(!r.stdout.includes('/secret'), 'no argument value');
});

test('explain: allowed decision shows the linked tool_result', async () => {
  const f = await fixture;
  const r = await runCli(['explain', f.allowedId, '--db', f.db]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /^verdict +ALLOWED by rule\(s\) p\.read$/m);
  assert.match(r.stdout, /result +seq=\d+ status=ok .*result_type=string/);
  assert.match(r.stdout, /will_execute +yes/);
});

test('explain: --policy with the same version shows rule detail; a different version shows only the warning', async () => {
  const f = await fixture;
  const same = await runCli(['explain', f.deniedId, '--db', f.db, '--policy', f.policyPath]);
  assert.equal(same.code, 0);
  assert.match(same.stdout, /^rule +d\.secret +effect=deny +reason_code=r_d_secret/m);
  assert.match(same.stdout, /arg path: glob "\/secret\*"/);
  assert.match(same.stdout, /tool is one of \["read_file"\]/);
  // verdict names only the deny rule when the effect of each rule is known
  assert.match(same.stdout, /^verdict +BLOCKED by rule\(s\) d\.secret because/m);
  assert.ok(!same.stdout.includes('policy version differs'));

  const dir = tmpDir();
  const other = join(dir, 'other.json');
  writeFileSync(other, JSON.stringify(POLICY_DOC('enforce', [rule('deny', 'x.only.in.other', { tools: ['note'] })])));
  const diff = await runCli(['explain', f.deniedId, '--db', f.db, '--policy', other]);
  assert.equal(diff.code, 0);
  assert.match(diff.stdout, /policy version differs; rule detail not shown/);
  for (const leak of ['r_d_secret', 'glob', 'x.only.in.other', 'effect=deny']) assert.ok(!diff.stdout.includes(leak), leak);
  const dj = JSON.parse((await runCli(['explain', f.deniedId, '--db', f.db, '--policy', other, '--json'])).stdout);
  assert.deepEqual(dj.warnings, ['policy version differs; rule detail not shown']);
  assert.equal(dj.rules, null);
  const bad = join(dir, 'bad.json');
  writeFileSync(bad, '{}');
  assert.equal((await runCli(['explain', f.deniedId, '--db', f.db, '--policy', bad])).code, 2);
});

test('explain: unknown id and non-decision rows exit 1', async () => {
  const f = await fixture;
  const u = await runCli(['explain', 'no-such-id', '--db', f.db]);
  assert.equal(u.code, 1);
  assert.match(u.stderr, /no such decision/);
  assert.ok(!u.stderr.includes('no-such-id'));
  const t = await runCli(['explain', f.resultId, '--db', f.db]);
  assert.equal(t.code, 1);
  assert.match(t.stderr, /not a decision/);
});

test('explain: unique id prefix (>= 8 chars) works, short or ambiguous prefixes exit 1', async () => {
  const dir = tmpDir();
  const db = dbPath(dir);
  const s = openStore({ path: db, hmacKey: KEY });
  for (const id of ['abcdef12-0001', 'abcdef12-0002', 'zzzzzzzz-0001']) {
    s.append({ id, kind: 'decision', ts_ms: 1, effect: 'permit', enforcement: 'enforced', reason_code: 'permitted' });
  }
  s.close();
  assert.equal((await runCli(['explain', 'zzzzzzzz', '--db', db])).code, 0);
  assert.equal((await runCli(['explain', 'abcdef12-0001', '--db', db])).code, 0);
  const amb = await runCli(['explain', 'abcdef12', '--db', db]);
  assert.equal(amb.code, 1);
  assert.match(amb.stderr, /ambiguous id \(2 matches\)/);
  assert.equal((await runCli(['explain', 'zzzzzz', '--db', db])).code, 1);
});

test('explain --json shape, exactly one document, nothing on stderr', async () => {
  const f = await fixture;
  const r = await runCli(['explain', f.allowedId, '--db', f.db, '--policy', f.policyPath, '--json']);
  assert.equal(r.code, 0);
  assert.equal(r.stderr, '');
  assert.equal(r.stdout.trim().split('\n').length, 1);
  const o = JSON.parse(r.stdout);
  assert.deepEqual(Object.keys(o).sort(), ['decision', 'results', 'rules', 'verdict', 'warnings']);
  assert.equal(o.decision.id, f.allowedId);
  assert.equal(o.results.length, 1);
  assert.equal(o.results[0].kind, 'tool_result');
  assert.deepEqual(o.warnings, []);
  assert.ok(Array.isArray(o.rules));
  assert.match(o.verdict, /^ALLOWED by rule\(s\)/);
  const n = JSON.parse((await runCli(['explain', f.allowedId, '--db', f.db, '--json'])).stdout);
  assert.equal(n.rules, null);
});

test('A-03: every decision in a real guard run is explainable and consistent with its stored row', async () => {
  const f = await fixture;
  const decisions = f.rows.filter((r) => r.kind === 'decision');
  assert.ok(decisions.length >= 6);
  for (const d of decisions) {
    const r = await runCli(['explain', d.id, '--db', f.db, '--policy', f.policyPath, '--json']);
    assert.equal(r.code, 0);
    const o = JSON.parse(r.stdout);
    assert.deepEqual(o.decision, JSON.parse(JSON.stringify(d)));
    assert.match(o.verdict, d.effect === 'deny' ? /^BLOCKED by/ : /^ALLOWED by/);
    assert.equal(o.results.length, f.rows.filter((x) => x.kind === 'tool_result' && x.decision_id === d.id).length);
    if (d.reason_code === 'denied_by_rule') {
      assert.ok(o.rules.some((x: { effect: string }) => x.effect === 'deny'));
    }
  }
});

test('explain: monitor_only wording (WOULD BE BLOCKED ... / ALLOWED (monitor_only))', async () => {
  const k = kit({ mode: 'monitor_only' });
  const denied = await k.guard.call('read_file', { path: '/secret/a' });
  const ok = await k.guard.call('read_file', { path: '/ok/a' });
  const bad = await k.guard.call('read_file', { path: 5 });
  k.guard.close();
  k.store.close();
  const a = await runCli(['explain', (denied as { decision_id: string }).decision_id, '--db', k.path]);
  assert.match(a.stdout, /^verdict +WOULD BE BLOCKED \(monitor_only: the tool ran\) by rule\(s\) /m);
  const b = await runCli(['explain', (ok as { decision_id: string }).decision_id, '--db', k.path]);
  assert.match(b.stdout, /^verdict +ALLOWED \(monitor_only\) by rule\(s\) p\.read$/m);
  const c = await runCli(['explain', (bad as { decision_id: string }).decision_id, '--db', k.path]);
  assert.match(c.stdout, /WOULD BE BLOCKED \(monitor_only: the tool did not run\)/);
});

test('explain: hostile stored strings are escaped; dropped_before is shown', async () => {
  const dir = tmpDir();
  const db = dbPath(dir);
  const s = openStore({ path: db, hmacKey: KEY });
  s.append({
    id: 'hostile-decision-1', kind: 'decision', ts_ms: 1, effect: 'deny', enforcement: 'enforced', tool: 'a' + CR + 'b',
    reason_code: ESC + '[2Jevil', rule_ids: ['r' + ESC + '1'], outcome: { dropped_before: { policy_deny: 3 } },
  });
  s.close();
  const r = await runCli(['explain', 'hostile-decision-1', '--db', db]);
  assert.equal(r.code, 0);
  assert.ok(!r.stdout.includes(ESC) && !r.stdout.includes(CR));
  assert.match(r.stdout, /dropped_before +\{"policy_deny":3\}/);
  assert.match(r.stdout, /\?\[2Jevil/);
});
