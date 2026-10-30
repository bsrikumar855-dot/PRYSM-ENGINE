// AUDIT-SPEC §5 (v1.2) guard amendments + QA follow-ups.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { GuardError, MAX_CALL_DEPTH } from '../../src/guard/index.ts';
import type { Guard, GuardResult } from '../../src/guard/index.ts';
import { kit, faulty, defaultTools } from '../support/guard-kit.ts';
import type { Kit } from '../support/guard-kit.ts';
import { cleanup } from '../support/tmp.ts';

after(cleanup);

const reason = (r: GuardResult): string => {
  assert.equal(r.ok, false);
  assert.ok('blocked' in r && r.blocked === true, 'expected blocked');
  return (r as { reason_code: string }).reason_code;
};
const rowFor = (k: Kit, id: string) => k.rows().find((r) => r.id === id);
const email = { to: 'a@b.c', subject: 's', body: 'b' };

// ---------------------------------------------------------------- items 5, 6, 7
test('held write lock: a deny call and a result row return within 600 ms (appendShort cap)', async () => {
  let other: DatabaseSync | null = null;
  let toolReturnedAt = 0;
  const k = kit({
    tools: (calls) => ({
      ...defaultTools(calls),
      read_file: () => {
        other = new DatabaseSync(k.path, { timeout: 50 });
        other.exec('BEGIN IMMEDIATE'); // hold the write lock while the result row is written
        toolReturnedAt = Date.now();
        return 'x';
      },
    }),
  });
  // deny path: lock held by a second connection
  const lock = new DatabaseSync(k.path, { timeout: 50 });
  lock.exec('BEGIN IMMEDIATE');
  const t0 = Date.now();
  const denied = await k.guard.call('denied_by_default', { x: 'a' });
  const dt = Date.now() - t0;
  assert.equal(reason(denied), 'denied');
  assert.ok(dt < 600, `deny call took ${dt}ms`);
  lock.exec('ROLLBACK');
  lock.close();
  // result row path
  const r = await k.guard.call('read_file', { path: '/a' });
  const dt2 = Date.now() - toolReturnedAt;
  assert.equal(r.ok, true);
  assert.ok(dt2 < 600, `result row took ${dt2}ms`);
  (other as DatabaseSync | null)?.exec('ROLLBACK');
  (other as DatabaseSync | null)?.close();
  k.store.close();
});

test('best-effort budgets are per class: drops counted per class, one sink line per class per window, dropped_before per class, permit rows exempt', async () => {
  const k = kit({ guardOpts: { maxDenyRowsPerWindow: 3, maxResultRowsPerWindow: 0, bestEffortWindowMs: 250 } });
  k.lines.length = 0;
  for (let i = 0; i < 6; i++) await k.guard.call('denied_by_default', { x: 'a' + i });
  assert.equal(k.decisionRows().filter((r) => r.tool === 'denied_by_default').length, 3);
  const limitLines = () => k.lines.map((l) => JSON.parse(l) as Record<string, unknown>).filter((o) => o['kind'] === 'rate_limit');
  assert.equal(limitLines().filter((o) => o['class'] === 'policy_deny').length, 1, 'one line per class per window');
  assert.equal(limitLines()[0]?.['prysm'], 'audit_skipped');
  // permit decision rows are never capped (their result row is capped at 0 here)
  const before = k.decisionRows().length;
  assert.equal((await k.guard.call('search_docs', { query: 'q' })).ok, true);
  assert.equal(k.decisionRows().length, before + 1);
  assert.equal(k.rows().filter((r) => r.kind === 'tool_result').length, 0);
  assert.equal(limitLines().filter((o) => o['class'] === 'tool_result').length, 1);
  await new Promise((r) => setTimeout(r, 300));
  const r = await k.guard.call('denied_by_default', { x: 'after-window' });
  const row = rowFor(k, (r as { decision_id: string }).decision_id);
  assert.deepEqual((row?.outcome as { dropped_before: unknown }).dropped_before, { policy_deny: 3, tool_result: 1 });
  const next = await k.guard.call('denied_by_default', { x: 'later' });
  assert.equal(rowFor(k, (next as { decision_id: string }).decision_id)?.outcome, null, 'dropped counts are recorded once');
  k.store.close();
});

test('fail-open only on busy/io; failOpenBudget 0 disables it', async () => {
  for (const [codeName, expectOpen] of [['busy', true], ['io', true], ['corrupt', false], ['invalid_event', false], ['duplicate_id', false], ['key_mismatch', false], ['key_invalid', false]] as const) {
    const k = kit({ wrap: (s) => faulty(s, (ev) => ev.kind === 'decision', codeName) });
    k.lines.length = 0;
    const r = await k.guard.call('search_docs', { query: 'q' });
    if (expectOpen) {
      assert.equal(r.ok, true, codeName);
      assert.equal(k.count('search_docs'), 1);
    } else {
      assert.equal(reason(r), 'unavailable', codeName);
      assert.equal(k.count('search_docs'), 0, codeName);
      assert.ok(!k.lines.some((l) => l.includes('fail_open')));
    }
    k.store.close();
  }
  const off = kit({ wrap: (s) => faulty(s, (ev) => ev.kind === 'decision', 'busy'), guardOpts: { failOpenBudget: 0 } });
  assert.equal(reason(await off.guard.call('search_docs', { query: 'q' })), 'unavailable');
  assert.equal(off.count('search_docs'), 0);
  off.store.close();
  const two = kit({ wrap: (s) => faulty(s, (ev) => ev.kind === 'decision', 'busy'), guardOpts: { failOpenBudget: 2 } });
  assert.equal((await two.guard.call('search_docs', { query: '1' })).ok, true);
  assert.equal((await two.guard.call('search_docs', { query: '2' })).ok, true);
  assert.equal(reason(await two.guard.call('search_docs', { query: '3' })), 'unavailable');
  two.store.close();
});

// ---------------------------------------------------------------- QA (a)(b)(c)
test('bad guard clock => blocked unavailable for ALL tools incl. low-risk open_on_audit_failure; creation still works', async () => {
  for (const bad of [NaN, -5, 1.5, 'x', Infinity, undefined] as unknown[]) {
    const k = kit({ clock: () => bad as number });
    assert.equal(reason(await k.guard.call('search_docs', { query: 'q' })), 'unavailable', String(bad));
    assert.equal(reason(await k.guard.call('send_email', email)), 'unavailable', String(bad));
    assert.equal(reason(await k.guard.call('read_file', { path: '/a' })), 'unavailable', String(bad));
    assert.equal(k.count('search_docs') + k.count('send_email') + k.count('read_file'), 0, String(bad));
    k.store.close();
  }
});

test('guard.session(badId) throws a typed GuardError invalid_session_id', () => {
  const k = kit();
  for (const id of ['', 'a b', 'x'.repeat(65), 'é', '../x', 5, null, {}]) {
    assert.throws(() => k.guard.session(id as never), (e: unknown) => e instanceof GuardError && e.code === 'invalid_session_id' && !(e instanceof TypeError));
  }
  k.store.close();
});

// ---------------------------------------------------------------- item 8 sessions
test('sessions: LRU eviction of untainted sessions at the cap; tainted never evicted; session_limit only if all tainted', async () => {
  const k = kit({ guardOpts: { maxSessions: 3 } });
  const a = k.guard.session('a');
  const b = k.guard.session('b');
  const c = k.guard.session('c');
  b.taint();
  await a.call('read_file', { path: '/x' }); // touch a: LRU order is now b, c, a
  const d = k.guard.session('d'); // evicts the oldest UNtainted session: c
  assert.equal(k.guard.session('b'), b, 'tainted session kept');
  assert.equal(k.guard.session('a'), a, 'recently used session kept');
  assert.notEqual(k.guard.session('c'), c, 'c was evicted and recreated untainted');
  // taint everything that is live: cap reached with all tainted
  const live = ['a', 'b', 'c', 'd'].map((id) => k.guard.session(id));
  void d;
  for (const s of live) s.taint();
  assert.throws(() => k.guard.session('fresh'), (e: unknown) => e instanceof GuardError && e.code === 'session_limit');
  k.store.close();
});

test('evicted session handle that is tainted later: taint follows the id (no shedding via eviction)', () => {
  const k = kit({ guardOpts: { maxSessions: 1 } });
  const old = k.guard.session('x');
  k.guard.session('y'); // evicts x (untainted)
  const fresh = k.guard.session('x'); // evicts y; new object for x
  assert.notEqual(fresh, old);
  old.taint(); // the host still held the old handle
  assert.equal(fresh.tainted, true);
  k.store.close();
});

test('session.close(): untainted is released; tainted is marked closed and stays tainted; calls blocked unavailable', async () => {
  const k = kit();
  const s = k.guard.session('u1');
  assert.equal((await s.call('read_file', { path: '/a' })).ok, true);
  s.close();
  assert.equal(reason(await s.call('read_file', { path: '/a' })), 'unavailable');
  assert.notEqual(k.guard.session('u1'), s, 'released id starts fresh');
  const t = k.guard.session('t1');
  t.taint();
  t.close();
  assert.equal(reason(await t.call('read_file', { path: '/a' })), 'unavailable');
  assert.equal(k.guard.session('t1'), t, 'tainted session is not released');
  assert.equal(t.tainted, true);
  assert.equal(k.count('read_file'), 1);
  k.store.close();
});

// ---------------------------------------------------------------- item 9
test('provenance __proto__ key is an ordinary key rejected by core (no prototype pollution)', async () => {
  const k = kit();
  const prov = JSON.parse('{"__proto__":["trusted-user"]}');
  const r = await k.guard.call('read_file', { path: '/a' }, { provenance: prov });
  assert.equal(reason(r), 'invalid_request');
  assert.equal(k.count('read_file'), 0);
  assert.equal(({} as Record<string, unknown>)['trusted-user'], undefined);
  assert.equal(Object.getPrototypeOf({}), Object.prototype);
  assert.equal(rowFor(k, (r as { decision_id: string }).decision_id)?.reason_code, 'invalid_request');
  k.store.close();
});

// ---------------------------------------------------------------- item 10
test('setTools: atomic replacement, frozen copy, sessions and taint preserved, invalid registry changes nothing', async () => {
  const k = kit();
  const s = k.guard.session('keep');
  s.taint();
  assert.equal(k.guard.session('keep').tainted, true);
  const calls: string[] = [];
  const reg: Record<string, unknown> = { read_file: () => { calls.push('new'); return 'new'; } };
  k.admin.setTools(reg as never);
  reg['send_email'] = () => 'added later';
  delete reg['read_file'];
  const r = await s.call('read_file', { path: '/a' });
  assert.equal(r.ok && r.value, 'new');
  assert.equal(k.count('read_file'), 0, 'old function no longer reachable');
  assert.equal(reason(await s.call('send_email', email)), 'unknown_tool', 'tool absent from the replacement registry');
  assert.equal(k.guard.session('keep'), s);
  assert.equal(s.tainted, true);
  assert.equal(reason(await k.guard.call('search_docs', { query: 'q' })), 'unknown_tool');
  for (const bad of [null, 5, { x: 5 }, { x: { fn: 'no' } }]) assert.throws(() => k.admin.setTools(bad as never), TypeError);
  assert.equal((await s.call('read_file', { path: '/a' })).ok, true, 'previous registry kept after a rejected replacement');
  assert.deepEqual(calls, ['new', 'new']);
  // call in flight keeps the registry it started with
  let release: () => void = () => {};
  const gate = new Promise<void>((res) => { release = res; });
  k.admin.setTools({ read_file: async () => { await gate; return 'slow-old'; } } as never);
  const inflight = k.guard.call('read_file', { path: '/a' });
  k.admin.setTools({ read_file: () => 'swapped' } as never);
  release();
  assert.equal((await inflight as { value: unknown }).value, 'slow-old');
  k.store.close();
});

test('tool receives (args, { signal, decisionId }); guard.close() aborts in-flight signals', async () => {
  let seen: { signal: AbortSignal; decisionId: string } | null = null;
  let abortedDuringCall = false;
  const k = kit({
    tools: (calls) => ({
      ...defaultTools(calls),
      read_file: (async (_args: unknown, o: { signal: AbortSignal; decisionId: string }) => {
        seen = o;
        await new Promise<void>((res) => o.signal.addEventListener('abort', () => { abortedDuringCall = true; res(); }));
        return 'aborted-result';
      }) as never,
    }),
  });
  const p = k.guard.call('read_file', { path: '/a' });
  await new Promise((r) => setTimeout(r, 20));
  const s = seen as { signal: AbortSignal; decisionId: string } | null;
  assert.ok(s && s.signal instanceof AbortSignal);
  assert.equal(s.signal.aborted, false);
  k.guard.close();
  const r = await p;
  assert.equal(abortedDuringCall, true);
  assert.equal(s.signal.aborted, true);
  assert.equal((r as { decision_id: string }).decision_id, s.decisionId);
  k.store.close();
});

test('toolTimeoutMs: never-resolving tool => tool_timeout, signal aborted, result row status timeout, no unhandled rejection', async () => {
  const unhandled: unknown[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(e);
  process.on('unhandledRejection', onUnhandled);
  let signalAborted = false;
  const k = kit({
    guardOpts: { toolTimeoutMs: 60 },
    tools: (calls) => ({
      ...defaultTools(calls),
      read_file: ((_a: unknown, o: { signal: AbortSignal }) => new Promise((_res, rej) => {
        o.signal.addEventListener('abort', () => { signalAborted = true; setTimeout(() => rej(new Error('late rejection')), 10); });
      })) as never,
    }),
  });
  const t0 = Date.now();
  const r = await k.guard.call('read_file', { path: '/a' });
  assert.ok(Date.now() - t0 < 2000);
  assert.deepEqual(r, { ok: false, blocked: false, decision_id: (r as { decision_id: string }).decision_id, error: 'tool_timeout' });
  assert.equal(signalAborted, true);
  const res = k.rows().find((x) => x.kind === 'tool_result');
  assert.equal((res?.outcome as { status: string }).status, 'timeout');
  assert.equal(res?.decision_id, (r as { decision_id: string }).decision_id);
  await new Promise((res2) => setTimeout(res2, 50));
  assert.deepEqual(unhandled, []);
  process.off('unhandledRejection', onUnhandled);
  // fast tools are unaffected
  k.admin.setTools(defaultTools({}) as never);
  assert.equal((await k.guard.call('read_file', { path: '/a' })).ok, true);
  k.store.close();
});

test('ctx.timeoutMs is not accepted (agents control ctx)', async () => {
  const k = kit();
  assert.equal(reason(await k.guard.call('read_file', { path: '/a' }, { timeoutMs: 1 } as never)), 'invalid_request');
  assert.equal(k.count('read_file'), 0);
  k.store.close();
});

test('tool re-entrancy: nested guard.call is audited, no deadlock, depth limited', async () => {
  const holder: { g?: Guard } = {};
  let executions = 0;
  const k = kit({
    tools: (calls) => ({
      ...defaultTools(calls),
      note: async () => {
        executions++;
        const inner = await (holder.g as Guard).call('note', { text: 'again' });
        return inner.ok ? 'ok' : (inner as { reason_code?: string }).reason_code;
      },
    }),
  });
  holder.g = k.guard;
  const r = await k.guard.call('note', { text: 'start' });
  assert.equal(r.ok, true);
  assert.equal(executions, MAX_CALL_DEPTH, 'the call at depth 8 is blocked');
  assert.equal(MAX_CALL_DEPTH, 8);
  const decisions = k.decisionRows().filter((d) => d.tool === 'note');
  assert.equal(decisions.length, MAX_CALL_DEPTH + 1);
  assert.equal(decisions.filter((d) => d.effect === 'permit').length, MAX_CALL_DEPTH);
  const blockedRow = decisions.find((d) => d.reason_code === 'engine_error');
  assert.equal(blockedRow?.effect, 'deny');
  // the innermost permitted tool saw `unavailable`; every level returned
  assert.equal(k.rows().filter((x) => x.kind === 'tool_result').length, MAX_CALL_DEPTH);
  assert.equal(k.store.verify().ok, true);
  // depth does not leak to later top-level calls
  executions = 0;
  assert.equal((await k.guard.call('note', { text: 'second' })).ok, true);
  assert.equal(executions, MAX_CALL_DEPTH);
  k.store.close();
});

// ---------------------------------------------------------------- items 11, 12
test('non-string tool names: tool "?" and outcome.tool_hmac', async () => {
  const k = kit();
  for (const bad of [42, null, undefined, {}, [], Symbol('x'), true]) {
    const r = await k.guard.call(bad as never, {});
    assert.equal(reason(r), 'invalid_request');
    const row = rowFor(k, (r as { decision_id: string }).decision_id);
    assert.equal(row?.tool, '?');
    const oc = row?.outcome as { tool_hmac: string };
    assert.match(oc.tool_hmac, /^[0-9a-f]{32}$/);
  }
  assert.equal(Object.values(k.calls).flat().length, 0);
  k.store.close();
});

test('result digest: total string bytes inside a value are capped at 1 MiB (result_hmac null above)', async () => {
  let mode = 'small';
  const k = kit({
    tools: (calls) => ({
      ...defaultTools(calls),
      note: () => {
        if (mode === 'small') return { a: 'x'.repeat(100_000), b: 'y'.repeat(100_000) };
        if (mode === 'many') return Array.from({ length: 30 }, () => 'z'.repeat(60_000)); // 1.8 MB total, each part small
        if (mode === 'keys') return Object.fromEntries(Array.from({ length: 30 }, (_, i) => ['k'.repeat(50_000) + i, 1]));
        return 'ok';
      },
    }),
  });
  const last = () => k.rows().filter((x) => x.kind === 'tool_result').at(-1)?.outcome as Record<string, unknown>;
  await k.guard.call('note', { text: 'q' });
  assert.equal(typeof last()['result_hmac'], 'string');
  for (const m of ['many', 'keys']) {
    mode = m;
    const r = await k.guard.call('note', { text: 'q' });
    assert.equal(r.ok, true);
    assert.equal(last()['result_hmac'], null, m);
    assert.equal(last()['result_len'], null, m);
  }
  k.store.close();
});

test('A-05 canary extension: secrets in nested results/timeouts/session ids never reach the store or sink', async () => {
  const canary = 'CANARYV12' + randomBytes(10).toString('hex');
  const k = kit({
    guardOpts: { toolTimeoutMs: 40 },
    tools: (calls) => ({
      ...defaultTools(calls),
      read_file: () => new Promise(() => {}),
      note: () => ({ nested: [canary] }),
    }),
  });
  await k.guard.call('read_file', { path: canary });
  await k.guard.call('note', { text: canary }, { userId: canary });
  await k.guard.call(canary as never, { x: canary });
  const text = JSON.stringify(k.rows()) + k.lines.join('\n');
  assert.ok(!text.includes(canary));
  k.store.close();
});
