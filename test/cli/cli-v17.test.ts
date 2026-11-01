// Final M4 re-check: one shared cause/verdict implementation (src/explain) for the CLI and the report.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { openStore } from '../../src/store/index.ts';
import { buildReportData } from '../../src/report/index.ts';
import { rowVerdict } from '../../src/explain/index.ts';
import { cleanup, tmpDir, dbPath } from '../support/tmp.ts';
import { KEY, kit } from '../support/guard-kit.ts';
import { rule } from '../support/policy.ts';
import { runCli } from '../support/cli-kit.ts';

after(cleanup);
const ELLIPSIS = String.fromCharCode(0x2026);
const MARK = ELLIPSIS + '+';
type Row = Parameters<ReturnType<typeof openStore>['append']>[0];
const dec = (id: string, over: Partial<Row>): Row => ({
  id, kind: 'decision', ts_ms: 1000, tool: 'send_email', effect: 'deny', enforcement: 'enforced', reason_code: 'denied_by_rule', session_id: 's1', ...over,
});

function forged(rows: Row[]): string {
  const db = dbPath(tmpDir());
  const s = openStore({ path: db, hmacKey: KEY });
  for (const r of rows) s.append(r);
  s.close();
  return db;
}
const explainJson = async (db: string, id: string): Promise<{ verdict: string }> => JSON.parse((await runCli(['explain', id, '--db', db, '--json'])).stdout);

test('explain over a tainted_session deny: no permit id is named, the reason is', async () => {
  const db = forged([
    dec('taint-with-n', { reason_code: 'tainted_session', rule_ids: ['p.email'], outcome: { deny_n: 0 } }),
    dec('taint-legacy', { reason_code: 'tainted_session', rule_ids: ['p.email'], outcome: null }),
    dec('default-legacy', { reason_code: 'default_deny', rule_ids: [], outcome: null }),
    dec('mon-taint', { reason_code: 'tainted_session', enforcement: 'monitor_only', rule_ids: ['p.email'], outcome: { deny_n: 0, will_execute: true } }),
  ]);
  for (const id of ['taint-with-n', 'taint-legacy']) {
    const v = (await explainJson(db, id)).verdict;
    assert.equal(v, 'BLOCKED because the session is tainted.');
    assert.ok(!v.includes('p.email'));
  }
  assert.equal((await explainJson(db, 'default-legacy')).verdict, 'BLOCKED because no permit rule matched.');
  assert.equal((await explainJson(db, 'mon-taint')).verdict, 'WOULD BE BLOCKED (monitor_only: the tool ran) because the session is tainted.');
  const t = await runCli(['explain', 'taint-with-n', '--db', db]);
  assert.match(t.stdout, /^verdict +BLOCKED because the session is tainted\.$/m);
  assert.match(t.stdout, /^why +The session was tainted by untrusted content\.$/m);
});

test('20 matched deny rules: guard stores 16 ids + marker with deny_n 16; CLI and report name 16 ids, never the marker, never legacy', async () => {
  const extra = Array.from({ length: 20 }, (_, i) => rule('deny', 'd.x' + String(i + 1).padStart(2, '0'), { tools: ['read_file'], args: { path: { glob: '/secret*' } } }));
  const k = kit({ extraRules: extra });
  const r = await k.guard.call('read_file', { path: '/secret/q' });
  k.guard.close();
  const id = (r as { decision_id: string }).decision_id;
  const row = k.store.getEvent(id) as unknown as { rule_ids: string[]; outcome: { deny_n: number } };
  assert.equal(row.rule_ids.length, 17);
  assert.ok((row.rule_ids[16] as string).startsWith(MARK));
  assert.equal(row.outcome.deny_n, 16, 'deny_n never exceeds the stored deny ids');
  const data = buildReportData(k.store, { generatedMs: 1, dbName: 'x.db' });
  const view = data.decisions.find((d) => d.id === id);
  assert.equal(view?.cause_source, 'deny_n');
  assert.equal(view?.cause_ids.length, 16);
  assert.ok(!(view?.verdict ?? '').includes(ELLIPSIS));
  assert.equal(data.metrics.top_rules_excluded, 0);
  assert.ok(!data.metrics.top_rules.some((x) => x.name.startsWith(ELLIPSIS)));
  k.store.close();
  const j = await explainJson(k.path, id);
  assert.match(j.verdict, /^BLOCKED by rules d\.secret, d\.x01,/);
  assert.ok(!j.verdict.includes(ELLIPSIS));
  assert.equal(j.verdict, view?.verdict, 'CLI and report agree');
});

test('a deny_n larger than the stored ids is clamped (not legacy) in the CLI and the report', async () => {
  const db = forged([dec('big-n', { rule_ids: ['d.a', 'd.b', MARK + '4'], outcome: { deny_n: 20 } })]);
  const v = (await explainJson(db, 'big-n')).verdict;
  assert.equal(v, 'BLOCKED by rules d.a, d.b.');
  const s = openStore({ path: db, hmacKey: KEY, readOnly: true });
  const view = buildReportData(s, { generatedMs: 1, dbName: 'x.db' }).decisions[0];
  assert.equal(view?.cause_source, 'deny_n');
  assert.equal(view?.verdict, v);
  s.close();
});

test('parity: for a fixture set of decision rows the CLI verdict, the report verdict and the shared function are identical', async () => {
  const rows: Row[] = [
    dec('par-1', { rule_ids: ['d.a', 'p.b'], outcome: { deny_n: 1 } }),
    dec('par-2', { rule_ids: ['d.a', 'p.b'], outcome: null }),
    dec('par-3', { reason_code: 'unknown_tool', tool: '?', rule_ids: [], outcome: { deny_n: 0 } }),
    dec('par-4', { reason_code: 'invalid_args', rule_ids: [], outcome: { deny_n: 0 } }),
    dec('par-5', { enforcement: 'monitor_only', rule_ids: ['d.a'], outcome: { deny_n: 1, will_execute: true } }),
    dec('par-6', { enforcement: 'monitor_only', rule_ids: ['d.a'], outcome: { deny_n: 1 } }),
    dec('par-7', { effect: 'permit', reason_code: 'permitted', rule_ids: ['p.a', 'p.b'], outcome: { deny_n: 0, will_execute: true } }),
    dec('par-8', { effect: 'permit', reason_code: 'permitted', enforcement: 'monitor_only', rule_ids: ['p.a'], outcome: { deny_n: 0 } }),
    dec('par-9', { reason_code: 'engine_error', rule_ids: [], outcome: { deny_n: 0 } }),
  ];
  const db = forged(rows);
  const s = openStore({ path: db, hmacKey: KEY, readOnly: true });
  const data = buildReportData(s, { generatedMs: 1, dbName: 'x.db' });
  for (const r of rows) {
    const stored = s.getEvent(r.id) as NonNullable<ReturnType<typeof s.getEvent>>;
    const shared = rowVerdict(stored).verdict;
    assert.equal(data.decisions.find((d) => d.id === r.id)?.verdict, shared, r.id);
    assert.equal((await explainJson(db, r.id)).verdict, shared, r.id);
  }
  s.close();
});

test('--scan-limit below the row count makes the report show the newest N of M cover note', async () => {
  const dir = tmpDir();
  const db = dbPath(dir);
  const s = openStore({ path: db, hmacKey: KEY, synchronous: 'NORMAL' });
  for (let i = 1; i <= 1200; i++) s.append({ id: 'bulk-' + i, kind: 'decision', ts_ms: 1000 + i, effect: 'permit', enforcement: 'enforced', reason_code: 'permitted', tool: 't' });
  s.close();
  const out = join(dir, 'r.html');
  const r = await runCli(['report', '--db', db, '--out', out, '--scan-limit', '1000']);
  assert.equal(r.code, 0, r.stderr);
  const text = readFileSync(out, 'utf8').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
  assert.match(text, /Metrics cover the newest 1,?000 of 1,?200 rows/);
});

test('BOM anchor file is rejected by the dedicated BOM check (specific message)', async () => {
  const k = forged([dec('b1', { outcome: { deny_n: 0 } })]);
  const dir = tmpDir();
  const a = (await runCli(['anchor', '--db', k])).stdout;
  const f = join(dir, 'a.json');
  writeFileSync(f, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(a)]));
  const r = await runCli(['verify-chain', '--db', k, '--anchor', f]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /--anchor: byte order mark is not allowed/);
  const r2 = await runCli(['anchor', '--db', k, '--anchor', f]);
  assert.equal(r2.code, 2);
  assert.match(r2.stderr, /byte order mark is not allowed/);
});
