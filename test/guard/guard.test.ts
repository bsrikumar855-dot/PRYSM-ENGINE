import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { loadPolicy } from '../../src/core/index.ts';
import { openStore, StoreError } from '../../src/store/index.ts';
import type { Store } from '../../src/store/index.ts';
import { createGuard, GuardError } from '../../src/guard/index.ts';
import type { GuardResult } from '../../src/guard/index.ts';
import { POLICY_DOC, rule } from '../support/policy.ts';
import { kit, faulty, defaultTools, KEY } from '../support/guard-kit.ts';
import type { Kit } from '../support/guard-kit.ts';
import { cleanup, tmpDir, dbPath } from '../support/tmp.ts';

after(cleanup);

const blockedReason = (r: GuardResult): string => {
  assert.equal(r.ok, false);
  assert.ok('blocked' in r && r.blocked === true, 'expected a blocked result');
  return (r as { reason_code: string }).reason_code;
};
const sinkKinds = (k: Kit): string[] => k.lines.map((l) => (JSON.parse(l) as { prysm: string }).prysm);
const rowFor = (k: Kit, id: string) => k.rows().find((r) => r.id === id);

// ---------------------------------------------------------------- A-01
test('A-01: denied calls invoke the tool 0 times (default-deny, rule-deny, unknown-tool, tainted, invalid args)', async () => {
  const k = kit();
  const s = k.guard.session('s-taint');
  s.taint();
  const cases: [string, Promise<GuardResult>, string, string | null][] = [
    ['default-deny', k.guard.call('denied_by_default', { x: 'a' }), 'denied', 'default_deny'],
    ['rule-deny', k.guard.call('read_file', { path: '/secret/x' }), 'denied', 'denied_by_rule'],
    ['unknown-tool (not registered)', k.guard.call('does_not_exist', { x: 1 }), 'unknown_tool', 'unknown_tool'],
    ['policy tool not registered in guard', k.guard.call('nope_tool', {}), 'unknown_tool', 'unknown_tool'],
    ['registered but missing from policy', k.guard.call('ghost', {}), 'unknown_tool', 'unknown_tool'],
    ['tainted session', s.call('send_email', { to: 'a@b.c', subject: 's', body: 'b' }), 'denied', 'tainted_session'],
    ['invalid arg type', k.guard.call('read_file', { path: 5 }), 'invalid_request', 'invalid_args'],
    ['extra arg', k.guard.call('read_file', { path: '/a', extra: 1 }), 'invalid_request', 'invalid_args'],
    ['missing arg', k.guard.call('read_file', {}), 'invalid_request', 'invalid_args'],
    ['args not an object', k.guard.call('read_file', 'str' as never), 'invalid_request', 'invalid_request'],
    ['non-string tool', k.guard.call(42 as never, {}), 'invalid_request', null],
  ];
  for (const [name, p, pub, core] of cases) {
    const r = await p;
    assert.equal(blockedReason(r), pub, name);
    assert.ok('decision_id' in r && r.decision_id.length > 0);
    const row = rowFor(k, r.decision_id);
    assert.ok(row, `${name}: audit row exists`);
    assert.equal(row.effect, 'deny', name);
    assert.equal(row.outcome === null || (row.outcome as { will_execute?: boolean }).will_execute !== true, true, name);
    if (core !== null) assert.equal(row.reason_code, core, name);
  }
  for (const t of ['denied_by_default', 'read_file', 'send_email', 'ghost', 'does_not_exist', 'nope_tool']) assert.equal(k.count(t), 0, t);
  // the agent-facing result carries no rule ids, values or policy version
  const r = await k.guard.call('read_file', { path: '/secret/x' });
  assert.deepEqual(Object.keys(r).sort(), ['blocked', 'decision_id', 'ok', 'reason_code']);
  k.store.close();
});

test('A-01: permit invokes exactly once with the frozen snapshot, immune to caller mutation', async () => {
  const k = kit({
    tools: (calls) => ({
      ...defaultTools(calls),
      note: async (args: unknown) => {
        (calls['note'] ??= []).push([args]);
        await new Promise((r) => setTimeout(r, 15));
        (calls['note'] as unknown[][])[0]?.push(JSON.stringify(args)); // what the tool sees after its own await
        return 'ok';
      },
    }),
  });
  const args = { text: 'hello', tags: ['a', 'b'] };
  const p = k.guard.call('note', args);
  args.text = 'MUTATED-BEFORE';
  args.tags.push('MUTATED-BEFORE');
  const mid = new Promise<void>((r) => setTimeout(() => { args.text = 'MUTATED-DURING'; args.tags[0] = 'X'; r(); }, 5));
  const res = await p;
  await mid;
  args.text = 'MUTATED-AFTER';
  assert.equal(res.ok, true);
  assert.equal(k.count('note'), 1);
  const [seen, seenLater] = k.calls['note']?.[0] as [{ text: string; tags: string[] }, string];
  assert.notEqual(seen, args, 'tool does not receive the caller object');
  assert.notEqual(seen.tags, args.tags);
  assert.deepEqual(seen, { text: 'hello', tags: ['a', 'b'] });
  assert.equal(seenLater, JSON.stringify({ text: 'hello', tags: ['a', 'b'] }));
  assert.ok(Object.isFrozen(seen) && Object.isFrozen(seen.tags));
  assert.throws(() => { (seen as { text: string }).text = 'x'; }, TypeError);
  k.store.close();
});

test('A-01: decision row is committed BEFORE the tool runs (tool sees its own decision row)', async () => {
  let observed: { effect: unknown; willExecute: unknown; hasResult: boolean; tool: unknown } | null = null;
  const holder: { store?: Store } = {};
  const k = kit({
    tools: (calls) => ({
      ...defaultTools(calls),
      read_file: () => {
        const rows = holder.store?.iterate() ?? [];
        const d = rows.filter((r) => r.kind === 'decision' && r.tool === 'read_file').at(-1);
        observed = {
          effect: d?.effect,
          willExecute: (d?.outcome as { will_execute?: boolean } | null)?.will_execute,
          hasResult: rows.some((r) => r.kind === 'tool_result'),
          tool: d?.tool,
        };
        return 'x';
      },
    }),
  });
  holder.store = k.store;
  const r = await k.guard.call('read_file', { path: '/a' });
  assert.equal(r.ok, true);
  assert.deepEqual(observed, { effect: 'permit', willExecute: true, hasResult: false, tool: 'read_file' });
  const rows = k.rows();
  assert.ok(rows.findIndex((x) => x.kind === 'decision') < rows.findIndex((x) => x.kind === 'tool_result'));
  k.store.close();
});

// ---------------------------------------------------------------- fault matrix
type Fault = 'decision_append_throws' | 'result_append_throws' | 'tool_throws' | 'tool_rejects';
const RAW = 'RAW-SECRET-' + randomBytes(6).toString('hex');
for (const fault of ['decision_append_throws', 'result_append_throws', 'tool_throws', 'tool_rejects'] as Fault[]) {
  for (const [tool, args, open] of [
    ['send_email', { to: 'a@b.c', subject: RAW, body: RAW }, false],
    ['search_docs', { query: RAW }, true],
  ] as const) {
    test(`fault matrix: ${fault} x ${open ? 'low-risk open_on_audit_failure' : 'high-risk closed'}`, async () => {
      let failKind: string | null = fault === 'decision_append_throws' ? 'decision' : fault === 'result_append_throws' ? 'tool_result' : null;
      const k = kit({
        wrap: (s) => faulty(s, (ev) => ev.kind === failKind),
        tools: (calls) => ({
          ...defaultTools(calls),
          [tool]: (a: unknown) => {
            (calls[tool] ??= []).push([a]);
            if (fault === 'tool_throws') throw new Error(RAW);
            if (fault === 'tool_rejects') return Promise.reject(new TypeError(RAW));
            return { v: 'fine' };
          },
        }),
      });
      k.lines.length = 0;
      const r = await k.guard.call(tool, args);
      const kinds = sinkKinds(k);
      const rows = k.rows();
      switch (fault) {
        case 'decision_append_throws':
          if (open) {
            assert.equal(r.ok, true);
            assert.equal(k.count(tool), 1);
            assert.deepEqual(kinds, ['audit_write_failed', 'fail_open']);
            assert.equal(rows.filter((x) => x.kind === 'decision').length, 0);
            const fo = JSON.parse(k.lines[1] as string);
            assert.deepEqual(Object.keys(fo).sort(), ['code', 'decision_id', 'prysm', 'tool']);
          } else {
            assert.equal(blockedReason(r), 'unavailable');
            assert.equal(k.count(tool), 0, 'closed tool must not run without a durable decision');
            assert.deepEqual(kinds, ['audit_write_failed']);
          }
          break;
        case 'result_append_throws':
          assert.equal(r.ok, true);
          assert.equal(k.count(tool), 1);
          assert.deepEqual(kinds, ['audit_write_failed']);
          assert.equal((JSON.parse(k.lines[0] as string) as { kind: string }).kind, 'tool_result');
          assert.equal(rows.filter((x) => x.kind === 'decision').length, 1);
          assert.equal(rows.filter((x) => x.kind === 'tool_result').length, 0);
          break;
        case 'tool_throws':
        case 'tool_rejects': {
          assert.deepEqual(r, { ok: false, blocked: false, decision_id: (r as { decision_id: string }).decision_id, error: 'tool_error' });
          assert.equal(k.count(tool), 1);
          assert.deepEqual(kinds, []);
          const res = rows.find((x) => x.kind === 'tool_result');
          assert.equal((res?.outcome as { status: string }).status, 'error');
          assert.equal((res?.outcome as { error_class: string }).error_class, fault === 'tool_throws' ? 'Error' : 'TypeError');
          break;
        }
      }
      failKind = null;
      // never a raw value anywhere observable
      assert.ok(!k.lines.join('\n').includes(RAW));
      assert.ok(!JSON.stringify(rows).includes(RAW));
      assert.ok(!JSON.stringify(r).includes(RAW));
      k.store.close();
    });
  }
}

test('fault: deny-path audit failure is best-effort (still blocked, sink line written)', async () => {
  const k = kit({ wrap: (s) => faulty(s, (ev) => ev.kind === 'decision') });
  k.lines.length = 0;
  const r = await k.guard.call('read_file', { path: '/secret/x' });
  assert.equal(blockedReason(r), 'denied');
  assert.deepEqual(sinkKinds(k), ['audit_write_failed']);
  assert.equal(k.count('read_file'), 0);
  k.store.close();
});

test('fail-open budget: after 5 consecutive fail-open executions the tool fails closed until a durable append succeeds', async () => {
  let failing = true;
  const k = kit({ wrap: (s) => faulty(s, (ev) => failing && ev.kind === 'decision') });
  k.lines.length = 0;
  for (let i = 0; i < 5; i++) assert.equal((await k.guard.call('search_docs', { query: 'q' + i })).ok, true);
  assert.equal(k.count('search_docs'), 5);
  assert.equal(sinkKinds(k).filter((x) => x === 'fail_open').length, 5);
  assert.equal(blockedReason(await k.guard.call('search_docs', { query: 'q6' })), 'unavailable');
  assert.equal(k.count('search_docs'), 5);
  failing = false;
  assert.equal((await k.guard.call('search_docs', { query: 'ok' })).ok, true); // durable append succeeds, budget resets
  failing = true;
  assert.equal((await k.guard.call('search_docs', { query: 'again' })).ok, true); // fail-open allowed again
  assert.equal(k.count('search_docs'), 7);
  k.store.close();
});

test('best-effort circuit breaker is used by the guard: repeated deny-row failures end in audit_skipped lines', async () => {
  const k = kit({ wrap: (s) => faulty(s, (ev) => ev.kind === 'decision') });
  k.lines.length = 0;
  for (let i = 0; i < 5; i++) await k.guard.call('read_file', { path: '/secret/' + i });
  const kinds = sinkKinds(k);
  assert.equal(kinds.filter((x) => x === 'audit_write_failed').length, 3);
  assert.equal(kinds.filter((x) => x === 'audit_skipped').length, 2);
  k.store.close();
});

test('a throwing secondary sink never changes the outcome', async () => {
  const k = kit({ wrap: (s) => faulty(s, (ev) => ev.kind === 'decision'), sink: () => { throw new Error('sink down'); } });
  assert.equal(blockedReason(await k.guard.call('send_email', { to: 'a', subject: 'b', body: 'c' })), 'unavailable');
  assert.equal(blockedReason(await k.guard.call('read_file', { path: '/secret' })), 'denied');
  assert.equal((await k.guard.call('search_docs', { query: 'q' })).ok, true);
  k.guard.close();
  k.store.close();
});

test('sink hygiene: only allowlisted single-line shapes, strings <= 64 chars', async () => {
  const k = kit({ mode: 'monitor_only', wrap: (s) => faulty(s, (ev) => ev.kind === 'tool_result') });
  await k.guard.call('search_docs', { query: 'q' });
  k.guard.close();
  const shapes: Record<string, string[]> = {
    fail_open: ['code', 'decision_id', 'prysm', 'tool'],
    audit_write_failed: ['code', 'id', 'kind', 'prysm'],
    monitor_only: ['policy_version', 'prysm'],
    anchor: ['genesis_hash', 'head_hash', 'head_seq', 'prysm'],
    audit_skipped: ['id', 'kind', 'prysm'],
  };
  assert.ok(k.lines.length >= 3);
  for (const l of k.lines) {
    assert.ok(!l.includes('\n'));
    const o = JSON.parse(l) as Record<string, unknown>;
    assert.deepEqual(Object.keys(o).sort(), shapes[o['prysm'] as string]);
    for (const [key, v] of Object.entries(o)) {
      if (typeof v === 'string') assert.ok(Array.from(v).length <= (key === 'policy_version' ? 80 : 64), key);
    }
  }
  k.store.close();
});

// ---------------------------------------------------------------- crash / unknown outcome
test('crash between decision and result => verify() warns outcome_unknown (real process kill)', async () => {
  const dir = tmpDir();
  const path = dbPath(dir);
  openStore({ path }).close(); // creates DB + key
  const worker = decodeURIComponent(new URL('../support/crash-worker.ts', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
  const code = await new Promise<{ code: number | null; signal: string | null }>((resolve) => {
    const p = spawn(process.execPath, ['--no-warnings', worker, path], { stdio: 'ignore' });
    p.on('exit', (c, s) => resolve({ code: c, signal: s }));
  });
  assert.ok(code.signal === 'SIGKILL' || code.code !== 0, 'child was killed');
  const s = openStore({ path });
  const rows = s.iterate();
  const d = rows.find((r) => r.kind === 'decision');
  assert.ok(d, 'decision row was durable before the crash');
  assert.equal((d.outcome as { will_execute: boolean }).will_execute, true);
  assert.ok(!rows.some((r) => r.kind === 'tool_result'));
  // a later row (restart) makes the missing outcome observable; default grace is 10 s
  s.append({ id: 'later', kind: 'policy_activate', ts_ms: d.ts_ms + 60_000 });
  const v = s.verify();
  assert.deepEqual(v.warnings.filter((w) => w.code === 'outcome_unknown'), [{ seq: d.seq, code: 'outcome_unknown' }]);
  assert.equal(v.ok, true);
  s.close();
});

test('lost tool_result row surfaces as outcome_unknown (in-process)', async () => {
  const k = kit({ wrap: (s) => faulty(s, (ev) => ev.kind === 'tool_result') });
  const r = await k.guard.call('read_file', { path: '/a' });
  assert.equal(r.ok, true);
  assert.equal(k.store.verify().warnings.length, 0, 'tail row in flight is never flagged');
  await k.guard.call('read_file', { path: '/b' });
  const w = k.store.verify({ graceMs: 0 }).warnings.filter((x) => x.code === 'outcome_unknown');
  assert.equal(w.length, 1, 'first decision flagged, the tail one is not');
  k.store.close();
});

// ---------------------------------------------------------------- engine errors (A-06)
test('A-06: forced engine error => blocked unavailable, no execution, event recorded (enforce and monitor_only)', async () => {
  for (const mode of ['enforce', 'monitor_only'] as const) {
    const real = loadPolicy(JSON.stringify(POLICY_DOC(mode)));
    const fake = { ...real }; // not produced by loadPolicy => core evaluate() fails closed with engine_error
    const k = kit({ policy: fake as typeof real });
    const r = await k.guard.call('read_file', { path: '/a' });
    assert.equal(blockedReason(r), 'unavailable');
    assert.equal(k.count('read_file'), 0);
    const row = rowFor(k, (r as { decision_id: string }).decision_id);
    assert.equal(row?.reason_code, 'engine_error');
    assert.equal(row?.effect, 'deny');
    k.store.close();
  }
});

test('A-06: unexpected exception inside the guard => blocked unavailable, never executed, event recorded', async () => {
  const k = kit({
    wrap: (s) => ({ ...s, hmac: (l, d) => { if (l === 'args') throw new Error('hmac exploded'); return s.hmac(l, d); } }),
  });
  const r = await k.guard.call('read_file', { path: '/a' });
  assert.equal(blockedReason(r), 'unavailable');
  assert.equal(k.count('read_file'), 0);
  assert.equal(rowFor(k, (r as { decision_id: string }).decision_id)?.reason_code, 'engine_error');
  k.store.close();
});

// ---------------------------------------------------------------- ctx handling
test('ctx interleaving: 50 concurrent calls with distinct ctx are each decided on their own ctx', async () => {
  const k = kit({
    tools: (calls) => ({
      ...defaultTools(calls),
      send_email: async (a: unknown) => {
        (calls['send_email'] ??= []).push([a]);
        await new Promise((r) => setTimeout(r, Math.floor(Math.random() * 20)));
        return { to: (a as { to: string }).to };
      },
    }),
  });
  const N = 50;
  const results = await Promise.all(Array.from({ length: N }, (_, i) => {
    const ctx = { userId: `user-${i}`, scopes: [`scope-${i}`], sessionTainted: i % 2 === 0 };
    return k.guard.call('send_email', { to: `u${i}@x.io`, subject: 's', body: 'b' }, ctx);
  }));
  results.forEach((r, i) => {
    if (i % 2 === 0) assert.equal(blockedReason(r), 'denied', `call ${i} tainted`);
    else {
      assert.equal(r.ok, true, `call ${i}`);
      assert.deepEqual((r as { value: unknown }).value, { to: `u${i}@x.io` });
    }
    const row = rowFor(k, (r as { decision_id: string }).decision_id);
    assert.equal(row?.user_hmac, k.store.hmac('user', `user-${i}`), `row ${i} user`);
    assert.equal(row?.session_tainted, i % 2 === 0 ? 1 : 0);
  });
  assert.equal(k.count('send_email'), N / 2);
  k.store.close();
});

test('per-call ctx validation: unknown keys, agentId, sessionId, bad types, Proxy => blocked invalid_request', async () => {
  const k = kit();
  const bad: unknown[] = [
    { agentId: 'evil' },
    { sessionId: 'x' },
    { foo: 1 },
    { userId: 5 },
    { scopes: 'a' },
    { scopes: [1] },
    { sessionTainted: 'yes' },
    { provenance: [] },
    { provenance: { path: 'x' } },
    [],
    'string',
    42,
    null,
    new Proxy({}, { ownKeys() { throw new Error('trap'); } }),
    { get userId() { return 'u'; } },
  ];
  for (const c of bad) {
    const r = await k.guard.call('read_file', { path: '/a' }, c as never);
    if (typeof c === 'object' && c !== null && !Array.isArray(c) && 'userId' in c && Object.getOwnPropertyDescriptor(c, 'userId')?.get) {
      assert.equal(r.ok, true, 'accessor on a plain object is read once into a copy (documented)');
      continue;
    }
    assert.equal(blockedReason(r), 'invalid_request', `ctx case ${bad.indexOf(c)}`);
    const row = rowFor(k, (r as { decision_id: string }).decision_id);
    assert.equal(row?.reason_code, 'invalid_request');
    assert.equal(row?.request_digest, null);
    assert.equal(row?.args_hmac, null);
  }
  assert.equal(k.count('read_file'), 1);
  // session.call also rejects sessionId
  const s = k.guard.session('abc');
  assert.equal(blockedReason(await s.call('read_file', { path: '/a' }, { sessionId: 'abc' } as never)), 'invalid_request');
  k.store.close();
});

test('pre-evaluate rejections: own-property registry, tool name only if known, hmac otherwise', async () => {
  const canary = 'CANARY-' + randomBytes(8).toString('hex');
  const k = kit();
  for (const name of ['constructor', '__proto__', 'toString', 'hasOwnProperty', canary]) {
    const r = await k.guard.call(name, {});
    assert.equal(blockedReason(r), 'unknown_tool', name);
    const row = rowFor(k, (r as { decision_id: string }).decision_id);
    assert.equal(row?.tool, '?');
    assert.deepEqual(row?.outcome, { tool_hmac: k.store.hmac('tool', name) });
    assert.equal(row?.effect, 'deny');
    assert.equal(row?.request_digest, null);
  }
  assert.ok(!JSON.stringify(k.rows()).includes(canary));
  // a policy-declared tool that is not registered keeps its (known) name
  const k2 = kit({ tools: (calls) => { const t = defaultTools(calls) as Record<string, unknown>; delete t['note']; return t as never; } });
  const r = await k2.guard.call('note', { text: 'x' });
  assert.equal(blockedReason(r), 'unknown_tool');
  assert.equal(rowFor(k2, (r as { decision_id: string }).decision_id)?.tool, 'note');
  k.store.close();
  k2.store.close();
});

test('registry is copied and frozen at creation', async () => {
  const calls: Kit['calls'] = {};
  const tools = defaultTools(calls) as Record<string, unknown>;
  const k = kit({ tools: () => tools as never });
  tools['read_file'] = () => { throw new Error('swapped'); };
  delete tools['search_docs'];
  tools['denied_by_default'] = () => 'added';
  const r = await k.guard.call('read_file', { path: '/a' });
  assert.equal(r.ok, true);
  assert.equal(((await k.guard.call('search_docs', { query: 'q' })) as { ok: boolean }).ok, true);
  k.store.close();
});

// ---------------------------------------------------------------- sessions and taint
test('sessions: same id => same object; sticky taint; ids validated; taint reason not stored', async () => {
  const k = kit();
  const s = k.guard.session('sess-1');
  assert.equal(k.guard.session('sess-1'), s);
  assert.notEqual(k.guard.session('sess-2'), s);
  assert.equal(s.tainted, false);
  const email = { to: 'a@b.c', subject: 's', body: 'b' };
  assert.equal((await s.call('send_email', email)).ok, true);
  s.taint('SECRET-REASON-TEXT');
  assert.equal(s.tainted, true);
  assert.equal(blockedReason(await s.call('send_email', email)), 'denied');
  assert.equal(k.guard.session('sess-1').tainted, true, 're-opening cannot shed taint');
  assert.equal((await k.guard.session('sess-2').call('send_email', email)).ok, true, 'other sessions unaffected');
  // taint is sticky: nothing resets it
  s.taint();
  assert.equal(s.tainted, true);
  // non-external tools still run in a tainted session
  assert.equal((await s.call('read_file', { path: '/a' })).ok, true);
  const taintedRow = k.decisionRows().filter((r) => r.session_id === 'sess-1').at(-1);
  assert.equal(taintedRow?.session_tainted, 1);
  for (const id of ['', 'a b', 'x'.repeat(65), 'é', '../x', 5 as never]) assert.throws(() => k.guard.session(id), GuardError);
  assert.ok(!JSON.stringify(k.rows()).includes('SECRET-REASON-TEXT'));
  assert.ok(typeof k.guard.session().id === 'string');
  assert.deepEqual(Object.keys(s).sort(), ['call', 'close', 'id', 'taint', 'tainted']);
  k.store.close();
});

test('taintsSession tool taints after a successful call only; tainted + external_effect is denied; ephemeral calls do not leak', async () => {
  const email = { to: 'a@b.c', subject: 's', body: 'b' };
  let fail = false;
  const mkk = (flag: unknown) => kit({
    tools: (calls) => ({
      ...defaultTools(calls),
      search_docs: { fn: () => { if (fail) throw new Error('x'); return 'retrieved'; }, taintsSession: flag as boolean },
    }),
  });
  const k = mkk(true);
  const s = k.guard.session('t1');
  fail = true;
  assert.equal((await s.call('search_docs', { query: 'q' })).ok, false);
  assert.equal(s.tainted, false, 'failed retrieval does not taint');
  fail = false;
  assert.equal((await s.call('search_docs', { query: 'q' })).ok, true);
  assert.equal(s.tainted, true);
  assert.equal(blockedReason(await s.call('send_email', email)), 'denied');
  // ephemeral session: taint from a retrieval via guard.call does not leak to the next call
  assert.equal((await k.guard.call('search_docs', { query: 'q' })).ok, true);
  assert.equal((await k.guard.call('send_email', email)).ok, true);
  // per-call ctx taint
  assert.equal(blockedReason(await k.guard.call('send_email', email, { sessionTainted: true })), 'denied');
  k.store.close();
  // taintsSession must be exactly true
  const k2 = mkk('yes');
  const s2 = k2.guard.session('t2');
  await s2.call('search_docs', { query: 'q' });
  assert.equal(s2.tainted, false);
  k2.store.close();
});

test('taint is applied synchronously when the tool resolves, before the result row is appended', async () => {
  let taintAtResultAppend: boolean | null = null;
  const holder: { s?: { tainted: boolean } } = {};
  const k = kit({
    wrap: (st) => ({
      ...st,
      append: (ev) => st.append(ev),
      appendShort: (ev) => {
        if (ev.kind === 'tool_result') taintAtResultAppend = holder.s?.tainted ?? null;
        return st.appendShort(ev);
      },
    }),
    tools: (calls) => ({ ...defaultTools(calls), search_docs: { fn: () => 'r', taintsSession: true } }),
  });
  const s = k.guard.session('sync');
  holder.s = s;
  await s.call('search_docs', { query: 'q' });
  assert.equal(taintAtResultAppend, true);
  k.store.close();
});

// ---------------------------------------------------------------- monitor_only
test('monitor_only: executes would-be-denied calls, records would-be effect, activation line, invalid still blocked', async () => {
  const k = kit({ mode: 'monitor_only' });
  assert.deepEqual(k.lines.map((l) => JSON.parse(l)), [{ prysm: 'monitor_only', policy_version: k.policy.policy_version }]);
  // would be default_deny
  const r1 = await k.guard.call('denied_by_default', { x: 'a' });
  assert.equal(r1.ok, true);
  assert.equal(k.count('denied_by_default'), 1);
  const d1 = rowFor(k, (r1 as { decision_id: string }).decision_id);
  assert.equal(d1?.effect, 'deny');
  assert.equal(d1?.reason_code, 'default_deny');
  assert.equal(d1?.enforcement, 'monitor_only');
  assert.deepEqual(d1?.outcome, { will_execute: true });
  // would be denied_by_rule
  assert.equal((await k.guard.call('read_file', { path: '/secret/x' })).ok, true);
  // would be tainted_session
  const s = k.guard.session('m');
  s.taint();
  assert.equal((await s.call('send_email', { to: 'a', subject: 'b', body: 'c' })).ok, true);
  assert.equal(k.count('send_email'), 1);
  // permit
  assert.equal((await k.guard.call('search_docs', { query: 'q' })).ok, true);
  // never executes: invalid_args, invalid_request, unknown_tool (policy or registry), engine_error, limit_exceeded
  const before = Object.values(k.calls).flat().length;
  assert.equal(blockedReason(await k.guard.call('read_file', { path: 5 })), 'invalid_request');
  assert.equal(blockedReason(await k.guard.call('read_file', 'x' as never)), 'invalid_request');
  assert.equal(blockedReason(await k.guard.call('ghost', {})), 'unknown_tool');
  assert.equal(blockedReason(await k.guard.call('nonexistent', {})), 'unknown_tool');
  assert.equal(blockedReason(await k.guard.call('read_file', { path: 'x'.repeat(9000) })), 'invalid_request');
  assert.equal(blockedReason(await k.guard.call('read_file', { path: '/a' }, { foo: 1 } as never)), 'invalid_request');
  assert.equal(Object.values(k.calls).flat().length, before);
  // line written on EVERY createGuard
  const k2 = kit({ mode: 'monitor_only', store: k.store, sink: (l) => k.lines.push(l) });
  assert.equal(k.lines.filter((l) => l.includes('"monitor_only"')).length, 2);
  void k2;
  k.store.close();
});

// ---------------------------------------------------------------- provenance
test('provenance: untagged => untrusted:unknown; given labels recorded; undeclared keys collapse', async () => {
  const k = kit({
    extraRules: [rule('permit', 'p.email.trusted', { tools: ['send_email'], provenance: { to: { all_in: ['trusted-user'] } } })],
  });
  const email = { to: 'a@b.c', subject: 's', body: 'b' };
  const r1 = await k.guard.call('read_file', { path: '/a' });
  assert.deepEqual(rowFor(k, (r1 as { decision_id: string }).decision_id)?.provenance_asserted, { _: 'untrusted:unknown' });
  const r2 = await k.guard.call('send_email', email, { provenance: { to: ['trusted-user'] } });
  assert.deepEqual(rowFor(k, (r2 as { decision_id: string }).decision_id)?.provenance_asserted, { to: ['trusted-user'] });
  // provenance and taint are never read from args
  const r3 = await k.guard.call('send_email', { ...email, provenance: { to: ['trusted-user'] }, sessionTainted: false } as never);
  assert.equal(blockedReason(r3), 'invalid_request');
  const r4 = await k.guard.call('read_file', { path: '/a' }, { provenance: { 'secret-key-name': ['x'] } });
  assert.equal(blockedReason(r4), 'invalid_request');
  const row4 = rowFor(k, (r4 as { decision_id: string }).decision_id);
  assert.deepEqual(row4?.provenance_asserted, { _undeclared: 1 });
  assert.ok(!JSON.stringify(k.rows()).includes('secret-key-name'));
  k.store.close();
});

// ---------------------------------------------------------------- A-05 canary
test('A-05 canary: secrets appear in zero bytes of the DB/WAL/SHM, exports, sink and returned errors', async () => {
  const hex = () => randomBytes(12).toString('hex');
  const cArg = 'CANARYARG' + hex();
  const cResult = 'CANARYRES' + hex();
  const cUser = 'CANARYUSER' + hex();
  const cErr = 'CANARYERR' + hex();
  const cKey = 'CANARYKEY' + hex();
  const cTool = 'CANARYTOOL' + hex();
  const cScope = 'CANARYSCOPE' + hex();
  const cMasked = hex() + hex();
  const cRawPlain = 'CANARYRAWPLAIN' + hex();
  const secretKey = 'sk-' + cMasked; // matches the sk- mask pattern
  const k = kit({
    rawFields: { read_file: ['path'] },
    tools: (calls) => ({
      ...defaultTools(calls),
      send_email: () => ({ leaked: cResult, arr: [cResult] }),
      set_discount: () => { throw new Error(cErr); },
      note: () => cResult,
    }),
  });
  const returned: unknown[] = [];
  const sessionish = k.guard.session('canary-sess');
  returned.push(await sessionish.call('send_email', { to: cArg, subject: cArg, body: cArg }, { userId: cUser, scopes: [cScope] }));
  returned.push(await k.guard.call('set_discount', { percent: 5 }, { userId: cUser }));
  returned.push(await k.guard.call('set_discount', { percent: cArg } as never, { userId: cUser })); // invalid: wrong type
  returned.push(await k.guard.call('send_email', { to: 'a', subject: 'b', body: 'c', [cKey]: cArg } as never, { userId: cUser }));
  returned.push(await k.guard.call(cTool, { x: cArg }, { userId: cUser }));
  returned.push(await k.guard.call('note', { text: cArg, tags: [cArg] }, { userId: cUser }));
  returned.push(await k.guard.call('read_file', { path: secretKey + ' ' + cRawPlain }, { userId: cUser }));
  returned.push(await k.guard.call('denied_by_default', { x: cArg }, { userId: cUser }));
  returned.push(await k.guard.call('send_email', { to: cArg }, { userId: cUser, agentId: cArg } as never));

  // positive controls: the plain raw field IS stored, the sk- one is masked
  const rawRow = k.decisionRows().find((r) => r.tool === 'read_file' && r.effect === 'permit');
  const path = (rawRow?.args_redacted as { path: { value: string } }).path.value;
  assert.ok(path.includes(cRawPlain), 'rawFields value is stored (positive control for the scanner)');
  assert.ok(!path.includes(cMasked) && path.includes('«masked»'));
  const errRow = k.rows().find((r) => r.kind === 'tool_result' && (r.outcome as { status?: string }).status === 'error');
  assert.equal((errRow?.outcome as { error_class: string }).error_class, 'Error');

  const exportsText = JSON.stringify(k.rows()) + JSON.stringify(k.store.verify()) + JSON.stringify(k.store.anchor());
  const resultsText = JSON.stringify(returned.filter((r) => (r as { ok: boolean }).ok !== true));
  const sinkText = k.lines.join('\n');
  k.guard.close();
  const scanFiles = (): Buffer[] => [k.path, k.path + '-wal', k.path + '-shm', k.path + '.key']
    .filter((p) => existsSync(p)).map((p) => readFileSync(p));
  const must = [cArg, cResult, cUser, cErr, cKey, cTool, cScope, cMasked];
  for (const needle of must) {
    for (const [i, b] of scanFiles().entries()) assert.ok(!b.includes(Buffer.from(needle)), `${needle} found in file ${i} (open)`);
    for (const [name, text] of [['exports', exportsText], ['returned', resultsText], ['sink', sinkText]] as const) {
      assert.ok(!text.includes(needle), `${needle} found in ${name}`);
    }
  }
  assert.ok(scanFiles().some((b) => b.includes(Buffer.from(cRawPlain))), 'scanner sees raw bytes of the DB/WAL');
  k.store.close();
  for (const needle of must) {
    for (const [i, b] of [k.path, k.path + '-wal', k.path + '-shm'].filter((p) => existsSync(p)).map((p) => readFileSync(p)).entries()) {
      assert.ok(!b.includes(Buffer.from(needle)), `${needle} found in file ${i} (closed)`);
    }
  }
  // UTF-16 form too
  for (const needle of must) assert.ok(!readFileSync(k.path).includes(Buffer.from(needle, 'utf16le')));
});

// ---------------------------------------------------------------- results / outcome shape
test('tool_result outcome: types, lengths, keyed digest only; big/odd results never throw', async () => {
  const big = 'z'.repeat(5 * 1024 * 1024);
  class MyErr extends Error {}
  let mode = 'string';
  const k = kit({
    tools: (calls) => ({
      ...defaultTools(calls),
      note: () => {
        switch (mode) {
          case 'string': return 'abc';
          case 'object': return { a: [1, 2] };
          case 'big': return big;
          case 'undefined': return undefined;
          case 'bigint': return 10n;
          case 'fn': return () => 1;
          case 'cyclic': { const o: Record<string, unknown> = {}; o['self'] = o; return o; }
          case 'class': return new Date(0);
          case 'myerr': throw new MyErr('m');
          case 'nonerror': throw 'plain string';
          case 'weird': { const e = new Error('x'); (e.constructor as { name: string }); Object.defineProperty(e, 'constructor', { value: { name: 'bad name!' } }); throw e; }
          default: return null;
        }
      },
    }),
  });
  const run = async (m: string) => {
    mode = m;
    const r = await k.guard.call('note', { text: 'q' });
    return { r, row: k.rows().filter((x) => x.kind === 'tool_result').at(-1)?.outcome as Record<string, unknown> };
  };
  let x = await run('string');
  assert.deepEqual(x.row, { status: 'ok', result_type: 'string', result_len: 5, result_hmac: k.store.hmac('result', '"abc"') });
  x = await run('object');
  assert.equal(x.row['result_type'], 'object');
  assert.equal(x.row['result_hmac'], k.store.hmac('result', '{"a":[1,2]}'));
  x = await run('big');
  assert.equal(x.r.ok, true);
  assert.deepEqual(x.row, { status: 'ok', result_type: 'string', result_len: null, result_hmac: null });
  assert.equal(((x.r as { value: string }).value).length, big.length, 'caller gets exactly what the tool returned');
  for (const [m, t] of [['undefined', 'undefined'], ['bigint', 'bigint'], ['fn', 'other'], ['cyclic', 'object'], ['class', 'object']] as const) {
    x = await run(m);
    assert.equal(x.r.ok, true, m);
    assert.equal(x.row['result_type'], t, m);
    assert.equal(x.row['result_hmac'], null, m);
  }
  x = await run('null');
  assert.deepEqual(x.row, { status: 'ok', result_type: 'null', result_len: 4, result_hmac: k.store.hmac('result', 'null') });
  x = await run('myerr');
  assert.equal(x.row['error_class'], 'MyErr');
  x = await run('nonerror');
  assert.equal(x.row['error_class'], 'NonError');
  x = await run('weird');
  assert.equal(x.row['error_class'], 'Unknown');
  assert.equal(x.r.ok, false);
  k.store.close();
});

test('decision row content (§2.3): keyed digests, redacted args, execution/session ids, risk, latency', async () => {
  const k = kit();
  const s = k.guard.session('row-sess');
  const args = { to: 'someone@corp.com', subject: 'topsecret-subject', body: 'b' };
  const r = await s.call('send_email', args, { userId: 'alice' });
  const row = rowFor(k, (r as { decision_id: string }).decision_id);
  assert.ok(row);
  assert.equal(row.kind, 'decision');
  assert.equal(row.agent_id, 'agent-1');
  assert.equal(row.session_id, 'row-sess');
  assert.match(row.execution_id as string, /^row-sess#\d+$/);
  assert.equal(row.tool, 'send_email');
  assert.equal(row.effect, 'permit');
  assert.equal(row.enforcement, 'enforced');
  assert.deepEqual(row.rule_ids, ['p.email']);
  assert.equal(row.reason_code, 'permitted');
  assert.equal(row.policy_version, k.policy.policy_version);
  assert.equal(row.risk, 'high');
  assert.equal(row.user_hmac, k.store.hmac('user', 'alice'));
  assert.equal(row.args_hmac?.length, 32);
  assert.ok(typeof row.latency_us === 'number' && row.latency_us >= 0);
  assert.equal(row.session_tainted, 0);
  assert.ok(row.request_digest && !row.request_digest.startsWith('sha256:'), 'request digest is keyed, not the plain core digest');
  assert.deepEqual(row.args_redacted, {
    to: { type: 'string', len: 16 }, subject: { type: 'string', len: 17 }, body: { type: 'string', len: 1 },
  });
  assert.ok(!JSON.stringify(row).includes('topsecret-subject'));
  const res = k.rows().find((x) => x.kind === 'tool_result');
  assert.equal(res?.decision_id, row.id);
  assert.equal(res?.execution_id, row.execution_id);
  // undeclared arg names collapse
  const r2 = await k.guard.call('read_file', { path: '/a', 'weird-name': 1 });
  assert.equal(blockedReason(r2), 'invalid_request');
  assert.deepEqual(rowFor(k, (r2 as { decision_id: string }).decision_id)?.args_redacted, { path: { type: 'string', len: 2 }, _undeclared: 1 });
  k.store.close();
});

// ---------------------------------------------------------------- activation / API surface / lifecycle
test('policy_activate: durable, once per version+mode, fields per spec, creation fails if the append fails', async () => {
  const k = kit();
  const act = k.rows().filter((r) => r.kind === 'policy_activate');
  assert.equal(act.length, 1);
  const a = act[0];
  assert.equal(a?.agent_id, 'agent-1');
  assert.equal(a?.effect, null);
  assert.equal(a?.tool, null);
  assert.equal(a?.enforcement, 'enforced');
  const o = a?.outcome as Record<string, unknown>;
  assert.deepEqual(Object.keys(o).sort(), ['mode', 'policy_version', 'rule_count', 'tool_names_hash']);
  assert.equal(o['policy_version'], k.policy.policy_version);
  assert.equal(o['rule_count'], 6);
  assert.match(o['tool_names_hash'] as string, /^[0-9a-f]{64}$/);
  // same policy again: no new row; new mode: new row
  const mk2 = (policy: typeof k.policy) => createGuard({ policy, store: k.store, agentId: 'agent-1', tools: defaultTools({}), secondarySink: () => {} });
  mk2(k.policy);
  assert.equal(k.rows().filter((r) => r.kind === 'policy_activate').length, 1);
  mk2(loadPolicy(JSON.stringify(POLICY_DOC('monitor_only'))));
  const acts = k.rows().filter((r) => r.kind === 'policy_activate');
  assert.equal(acts.length, 2);
  assert.equal(acts[1]?.enforcement, 'monitor_only');
  // failure to record activation is fatal
  assert.throws(() => createGuard({
    policy: loadPolicy(JSON.stringify(POLICY_DOC('enforce', [rule('permit', 'zz', { tools: ['note'] })]))),
    store: faulty(k.store, (ev) => ev.kind === 'policy_activate'), agentId: 'agent-1', tools: defaultTools({}),
  }), (e: unknown) => e instanceof StoreError);
  k.store.close();
});

test('public API surface: only call/session/close; tool functions are not exposed; creation validation', () => {
  const k = kit();
  assert.deepEqual(Object.keys(k.guard).sort(), ['call', 'close', 'session']);
  assert.ok(Object.isFrozen(k.guard));
  const dump = JSON.stringify(k.guard, (_, v) => (typeof v === 'function' ? 'fn' : v));
  assert.ok(!dump.includes('read_file'));
  const base = { policy: k.policy, store: k.store, agentId: 'a', tools: {} };
  assert.throws(() => createGuard({ ...base, agentId: '' }), TypeError);
  assert.throws(() => createGuard({ ...base, policy: {} as never }), TypeError);
  assert.throws(() => createGuard({ ...base, tools: { x: 5 as never } }), TypeError);
  assert.throws(() => createGuard({ ...base, tools: { x: { fn: 'no' } as never } }), TypeError);
  k.store.close();
});

test('close(): later calls blocked unavailable, anchor line written once, double close fine, store left open', async () => {
  const k = kit();
  await k.guard.call('read_file', { path: '/a' });
  k.lines.length = 0;
  k.guard.close();
  k.guard.close();
  assert.equal(k.lines.length, 1);
  const a = JSON.parse(k.lines[0] as string) as { prysm: string; head_seq: number; head_hash: string; genesis_hash: string };
  assert.equal(a.prysm, 'anchor');
  const anchor = k.store.anchor();
  assert.equal(a.head_seq, anchor.head_seq);
  assert.equal(a.head_hash, anchor.head_hash);
  assert.equal(a.genesis_hash, anchor.genesis_hash);
  assert.equal(k.store.verify({ anchor: { ...anchor, ...a, ts_ms: 0 } }).ok, true);
  assert.equal(blockedReason(await k.guard.call('read_file', { path: '/a' })), 'unavailable');
  assert.equal(k.count('read_file'), 1);
  assert.equal(k.store.count() > 0, true, 'store not closed by guard.close()');
  k.store.close();
});

test('guard clock returning an invalid timestamp blocks closed tools (store rejects it)', async () => {
  let bad = false;
  const k = kit({ clock: () => (bad ? -5 : 1000) });
  bad = true;
  assert.equal(blockedReason(await k.guard.call('send_email', { to: 'a', subject: 'b', body: 'c' })), 'unavailable');
  assert.equal(k.count('send_email'), 0);
  k.store.close();
});

test('real SQLite end to end: chain verifies after a mixed workload', async () => {
  const k = kit();
  const s = k.guard.session('e2e');
  await s.call('read_file', { path: '/a' });
  await s.call('read_file', { path: '/secret/x' });
  await s.call('nope', {});
  await Promise.all(Array.from({ length: 20 }, (_, i) => k.guard.call('search_docs', { query: 'q' + i })));
  const v = k.store.verify();
  assert.equal(v.ok, true, JSON.stringify(v.errors));
  assert.deepEqual(v.warnings, []);
  assert.ok(existsSync(k.path));
  k.store.close();
});
