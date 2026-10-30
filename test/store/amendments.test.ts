// AUDIT-SPEC §4 (v1.1) store amendments.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { openStore, StoreError, makeBestEffort } from '../../src/store/index.ts';
import type { Store, NewEvent } from '../../src/store/index.ts';
import { tmpDir, cleanup, dbPath } from '../support/tmp.ts';

after(cleanup);
const KEY = new Uint8Array(32).fill(3);

function mk(extra: Record<string, unknown> = {}): { s: Store; path: string; dir: string } {
  const dir = tmpDir();
  const path = dbPath(dir);
  return { s: openStore({ path, hmacKey: KEY, ...extra }), path, dir };
}
const ev = (i: number, extra: Partial<NewEvent> = {}): NewEvent => ({ id: `e-${i}`, kind: 'decision', ts_ms: 1000 + i, ...extra });
function raw<T>(path: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(path);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}
const code = (c: string) => (e: unknown) => e instanceof StoreError && e.code === c;

test('per-store genesis nonce: stores differ; anchor shape; empty store anchor/verify', () => {
  const a = mk();
  const b = mk();
  const aa = a.s.anchor();
  assert.deepEqual(Object.keys(aa).sort(), ['genesis_hash', 'head_hash', 'head_seq', 'ts_ms']);
  assert.equal(aa.head_seq, 0);
  assert.equal(aa.head_hash, aa.genesis_hash);
  assert.notEqual(aa.genesis_hash, b.s.anchor().genesis_hash);
  assert.equal(a.s.head(), null);
  assert.equal(a.s.count(), 0);
  const v = a.s.verify({ anchor: aa });
  assert.equal(v.ok, true);
  assert.equal(v.count, 0);
  // anchor from another store
  a.s.append(ev(1));
  const r = a.s.verify({ anchor: b.s.anchor() });
  assert.deepEqual(r.errors, [{ seq: 0, code: 'anchor_mismatch' }]);
  // reopen keeps the same genesis
  a.s.close();
  const again = openStore({ path: a.path, hmacKey: KEY });
  assert.equal(again.anchor().genesis_hash, aa.genesis_hash);
  again.close();
  b.s.close();
});

test('anchor beyond head is a mismatch; anchor with wrong hash at a retained seq is a mismatch', () => {
  const { s } = mk();
  for (let i = 1; i <= 3; i++) s.append(ev(i));
  const a = s.anchor();
  assert.equal(s.verify({ anchor: { ...a, head_seq: 9 } }).errors[0]?.code, 'anchor_mismatch');
  assert.equal(s.verify({ anchor: { ...a, head_seq: 2 } }).errors[0]?.code, 'anchor_mismatch');
  assert.equal(s.verify({ anchor: { ...a, head_hash: 'f'.repeat(64) } }).errors[0]?.code, 'anchor_mismatch');
  s.close();
});

test('prune takes only the longest seq prefix (non-monotonic clock never prunes a non-prefix)', () => {
  const { s } = mk();
  const ts = [1, 2, 50, 3, 4];
  ts.forEach((t, i) => s.append(ev(i + 1, { ts_ms: t })));
  const r = s.checkpointAndPrune(10);
  assert.equal(r.pruned, 2);
  const seqs = s.iterate().map((e) => e.seq);
  assert.deepEqual(seqs, [3, 4, 5, 6]);
  const v = s.verify({ allowPruned: true });
  assert.equal(v.ok, true, JSON.stringify(v.errors));
  assert.equal(v.pruned_through, 2);
  // nothing prunable: a no-op that appends nothing
  const headBefore = s.head();
  const r2 = s.checkpointAndPrune(0);
  assert.equal(r2.pruned, 0);
  assert.deepEqual(s.head(), headBefore);
  assert.equal(s.verify({ allowPruned: true }).ok, true);
  // invalid arguments change nothing
  const before = s.count();
  for (const bad of [NaN, -1, Infinity, '5' as unknown as number]) assert.throws(() => s.checkpointAndPrune(bad), code('invalid_event'));
  assert.equal(s.count(), before);
  s.close();
});

test('anchor_pruned warning when the anchored seq fell into a pruned range', () => {
  const { s } = mk();
  for (let i = 1; i <= 6; i++) s.append(ev(i));
  const old = { ...s.anchor(), head_seq: 2, head_hash: s.iterate().find((e) => e.seq === 2)?.hash as string };
  s.checkpointAndPrune(1004); // prunes seq 1..3? ts 1001..1006 => before 1004 => 1,2,3
  const v = s.verify({ anchor: old, allowPruned: true });
  assert.equal(v.ok, true);
  assert.ok(v.warnings.some((w) => w.code === 'anchor_pruned' && w.seq === 2));
  s.close();
});

test('unexpected_first_row when the checkpoint that justifies a pruned start is missing', () => {
  const { s, path } = mk();
  for (let i = 1; i <= 4; i++) s.append(ev(i));
  s.checkpointAndPrune(1003); // prunes 1,2 ; checkpoint seq 5
  raw(path, (db) => {
    db.exec('DROP TRIGGER events_no_delete');
    db.exec("DELETE FROM events WHERE kind='checkpoint'");
  });
  const v = s.verify();
  assert.ok(v.errors.some((e) => e.code === 'unexpected_first_row'));
  s.close();
});

test('prune_open is reset on open and verify warns prune_flag_reset', () => {
  const { s, path } = mk();
  s.append(ev(1));
  raw(path, (db) => db.exec("UPDATE meta SET value='1' WHERE key='prune_open'"));
  s.close();
  const s2 = openStore({ path, hmacKey: KEY });
  assert.equal(raw(path, (db) => (db.prepare("SELECT value FROM meta WHERE key='prune_open'").get() as { value: string }).value), '0');
  assert.ok(s2.verify().warnings.some((w) => w.code === 'prune_flag_reset'));
  s2.close();
});

test('seq is never reused after tail deletion', () => {
  const { s, path } = mk();
  for (let i = 1; i <= 5; i++) s.append(ev(i));
  raw(path, (db) => {
    db.exec('DROP TRIGGER events_no_delete');
    db.exec('DELETE FROM events WHERE seq IN (4,5)');
  });
  const r = s.append(ev(6));
  assert.equal(r.seq, 6);
  s.close();
});

test('will_execute / outcome_unknown (grace), orphan_result, duplicate_result', () => {
  const { s } = mk();
  s.append(ev(1, { id: 'd-exec', outcome: { will_execute: true }, ts_ms: 1000 })); // no result
  s.append(ev(2, { id: 'd-noexec', effect: 'deny', ts_ms: 1001 })); // no will_execute => never flagged
  s.append(ev(3, { id: 'd-done', outcome: { will_execute: true }, ts_ms: 1002 }));
  s.append({ id: 'r1', kind: 'tool_result', decision_id: 'd-done', ts_ms: 1003 });
  s.append({ id: 'r-orphan', kind: 'tool_result', decision_id: 'nope', ts_ms: 1004 });
  s.append({ id: 'r2', kind: 'tool_result', decision_id: 'd-done', ts_ms: 1005 });
  // within grace (newest - row < 10000): no outcome_unknown
  assert.ok(!s.verify().warnings.some((w) => w.code === 'outcome_unknown'));
  const v = s.verify({ graceMs: 3 });
  const codes = v.warnings.map((w) => `${w.code}@${w.seq}`).sort();
  assert.deepEqual(codes, ['duplicate_result@3', 'orphan_result@5', 'outcome_unknown@1']);
  // the tail row in flight is never flagged
  const t = mk();
  t.s.append(ev(1, { outcome: { will_execute: true }, ts_ms: 1 }));
  assert.equal(t.s.verify({ graceMs: 0 }).warnings.length, 0);
  t.s.append(ev(2, { ts_ms: 20000 }));
  assert.equal(t.s.verify().warnings.filter((w) => w.code === 'outcome_unknown').length, 1);
  s.close();
  t.s.close();
});

test('round-trip property: random strings never cause a false hash_mismatch', () => {
  const { s } = mk();
  let seed = 12345;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const pieces = ['a', 'Z', ' ', '\n', '\t', '\u0000', '\ud800', '\udc00', '\u{1F600}', '\u{1F468}‍\u{1F469}', 'é', 'é', '�', '￿', '"', '\\', ' ', '‮', '\u0085', '\u{10FFFF}'];
  const rs = (n: number) => {
    let out = '';
    for (let i = 0; i < n; i++) out += pieces[Math.floor(rnd() * pieces.length)] as string;
    return out;
  };
  for (let i = 0; i < 300; i++) {
    const len = i % 50 === 0 ? 400 + Math.floor(rnd() * 200) : Math.floor(rnd() * 40);
    s.append({
      id: 'p-' + i,
      kind: 'decision',
      tool: rs(len),
      reason_code: rs(len),
      session_id: rs(3),
      outcome: { s: rs(len), arr: [rs(5), rs(5)] },
      args_redacted: { [rs(4)]: rs(6) },
    });
  }
  const v = s.verify();
  assert.equal(v.ok, true, JSON.stringify(v.errors.slice(0, 3)));
  assert.equal(v.count, 300);
  // stored text is exactly the sanitised input: no lone surrogates / NUL remain
  for (const e of s.iterate({ limit: 1000 })) {
    const t = e.tool as string;
    assert.ok(!t.includes('\u0000'));
    assert.ok(!new RegExp('[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]').test(t), 'no lone surrogates');
    assert.ok(Array.from(t).length <= 256);
  }
  s.close();
});

test('integer fields must be safe integers; text truncation counts code points incl. marker', () => {
  const { s } = mk();
  assert.throws(() => s.append(ev(1, { latency_us: 2 ** 60 })), code('invalid_event'));
  assert.throws(() => s.append(ev(1, { latency_us: 1.5 })), code('invalid_event'));
  const r = s.append(ev(2, { tool: '\u{1F600}'.repeat(400) }));
  assert.equal(Array.from(r.tool as string).length, 256);
  assert.ok((r.tool as string).endsWith('…[trunc]'));
  s.close();
});

test('rule_ids keeps at most 16 ids then an overflow marker', () => {
  const { s } = mk();
  const r = s.append(ev(1, { rule_ids: Array.from({ length: 40 }, (_, i) => 'r' + i) }));
  const ids = r.rule_ids as string[];
  assert.equal(ids.length, 17);
  assert.equal(ids[16], '…+24');
  s.close();
});

test('row cap: oversize rows shrink args_redacted first; impossible rows are invalid_event', () => {
  const { s } = mk();
  const fat = { v: 'y'.repeat(4000) };
  const r = s.append(ev(1, {
    args_redacted: fat, provenance_asserted: fat, model_meta: fat, outcome: fat, rule_ids: ['x'.repeat(250), 'y'.repeat(250), 'z'.repeat(250), 'w'.repeat(250), 'q'.repeat(250), 'r'.repeat(250), 't'.repeat(250)],
    tool: '\u{1F600}'.repeat(256), reason_code: '\u{1F600}'.repeat(256), session_id: '\u{1F600}'.repeat(256), execution_id: '\u{1F600}'.repeat(256),
  }));
  assert.equal((r.args_redacted as { truncated?: boolean }).truncated, true);
  assert.equal(s.verify().ok, true);
  const huge: Partial<NewEvent> = {};
  for (const k of ['id', 'tool', 'reason_code', 'session_id', 'execution_id', 'agent_id', 'user_hmac', 'policy_version', 'request_digest', 'args_hmac', 'decision_id', 'engine_version']) {
    (huge as Record<string, string>)[k] = '\u{1F600}'.repeat(256);
  }
  huge.rule_ids = Array.from({ length: 16 }, () => 'x'.repeat(250));
  assert.throws(() => s.append(ev(2, huge)), code('invalid_event'));
  assert.equal(s.count(), 1);
  s.close();
});

test('clock option: finite non-negative integers only', () => {
  let t = 5;
  const { s } = mk({ clock: () => t });
  assert.equal(s.append({ id: 'a', kind: 'decision' }).ts_ms, 5);
  for (const badClock of [-1, 1.5, NaN, Infinity]) {
    t = badClock;
    assert.throws(() => s.append({ id: 'b' + String(badClock), kind: 'decision' }), code('invalid_event'));
  }
  t = 7;
  assert.equal(s.append({ id: 'c', kind: 'decision' }).ts_ms, 7);
  const thrower = mk({ clock: () => { throw new Error('boom'); } });
  assert.throws(() => thrower.s.append({ id: 'a', kind: 'decision' }), code('invalid_event'));
  assert.equal(thrower.s.append({ id: 'a', kind: 'decision', ts_ms: 3 }).ts_ms, 3);
  s.close();
  thrower.s.close();
});

test('keys: keyPath, wx creation, 32-byte file, key_mismatch when missing/corrupt (never regenerated)', () => {
  const dir = tmpDir();
  const keyDir = tmpDir();
  const path = dbPath(dir);
  const keyPath = join(keyDir, 'k.key');
  const s = openStore({ path, keyPath });
  assert.ok(existsSync(keyPath));
  assert.ok(!existsSync(path + '.key'));
  const key = readFileSync(keyPath);
  assert.equal(key.length, 32);
  const h = s.hmac('args', 'v');
  s.close();
  assert.equal(openStore({ path, keyPath }).hmac('args', 'v'), h);
  // corrupt key file
  writeFileSync(keyPath, Buffer.alloc(5));
  assert.throws(() => openStore({ path, keyPath }), code('key_mismatch'));
  assert.equal(readFileSync(keyPath).length, 5, 'key file untouched');
  // missing key file for an existing store
  const dir2 = tmpDir();
  const p2 = dbPath(dir2);
  openStore({ path: p2 }).close();
  rmKey(p2 + '.key');
  assert.throws(() => openStore({ path: p2 }), code('key_mismatch'));
  assert.ok(!existsSync(p2 + '.key'), 'not regenerated');
  // new store with a wrong-sized stale key file
  const dir3 = tmpDir();
  writeFileSync(dbPath(dir3) + '.key', Buffer.alloc(10));
  assert.throws(() => openStore({ path: dbPath(dir3) }), code('key_invalid'));
  // key id check also applies with provided keys
  assert.throws(() => openStore({ path, hmacKey: new Uint8Array(32).fill(1) }), code('key_mismatch'));
});
function rmKey(p: string): void {
  rmSync(p);
}

test('paths: :memory: needs a key; missing parent dir is io; relative misuse', () => {
  assert.throws(() => openStore({ path: ':memory:' }), code('invalid_event'));
  const m = openStore({ path: ':memory:', hmacKey: KEY });
  m.append({ id: 'a', kind: 'decision' });
  assert.equal(m.verify().ok, true);
  m.close();
  const dir = tmpDir();
  assert.throws(() => openStore({ path: join(dir, 'nope', 'x.db'), hmacKey: KEY }), code('io'));
  mkdirSync(join(dir, 'ok'));
  openStore({ path: join(dir, 'ok', 'x.db'), hmacKey: KEY }).close();
});

test('best-effort circuit breaker: 3 failures then skip with audit_skipped lines; recovers after the window', async () => {
  const lines: string[] = [];
  const { s, path } = mk({ busyTimeoutMs: 100, secondarySink: (l: string) => lines.push(l) });
  s.append(ev(0));
  const other = new DatabaseSync(path, { timeout: 50 });
  other.exec('BEGIN IMMEDIATE');
  for (let i = 1; i <= 3; i++) assert.equal(s.appendBestEffort(ev(i)), null);
  assert.deepEqual(lines.map((l) => (JSON.parse(l) as { prysm: string }).prysm), ['audit_write_failed', 'audit_write_failed', 'audit_write_failed']);
  other.exec('ROLLBACK');
  other.close();
  // lock is gone but the breaker is open: skipped without touching the store
  assert.equal(s.appendBestEffort(ev(4)), null);
  assert.equal(JSON.parse(lines[3] as string).prysm, 'audit_skipped');
  assert.equal(s.count(), 1);
  await new Promise((r) => setTimeout(r, 5200));
  assert.ok(s.appendBestEffort(ev(5)));
  assert.equal(s.count(), 2);
  s.close();
});

test('makeBestEffort: malformed events do not trip the breaker; a throwing sink is harmless', () => {
  let calls = 0;
  const be = makeBestEffort(() => { calls++; throw new StoreError('invalid_event'); }, () => { throw new Error('sink down'); });
  for (let i = 0; i < 10; i++) assert.equal(be({ id: 'x', kind: 'decision' }), null);
  assert.equal(calls, 10);
});

test('best-effort busy timeout is capped at 250ms', () => {
  const { s, path } = mk({ busyTimeoutMs: 5000, secondarySink: () => {} });
  s.append(ev(0));
  const other = new DatabaseSync(path, { timeout: 50 });
  other.exec('BEGIN IMMEDIATE');
  const t0 = Date.now();
  assert.equal(s.appendBestEffort(ev(1)), null);
  assert.ok(Date.now() - t0 < 2000);
  other.exec('ROLLBACK');
  other.close();
  s.close();
});
