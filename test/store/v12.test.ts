// AUDIT-SPEC §5 (v1.2) store amendments.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { openStore, StoreError } from '../../src/store/index.ts';
import type { Store, NewEvent, Anchor } from '../../src/store/index.ts';
import { tmpDir, cleanup, dbPath } from '../support/tmp.ts';

after(cleanup);
const KEY = new Uint8Array(32).fill(9);
const DAY = 24 * 3600 * 1000;

function mk(extra: Record<string, unknown> = {}): { s: Store; path: string; lines: string[] } {
  const lines: string[] = [];
  const path = dbPath(tmpDir());
  return { s: openStore({ path, hmacKey: KEY, secondarySink: (l: string) => lines.push(l), ...extra }), path, lines };
}
const ev = (i: number, extra: Partial<NewEvent> = {}): NewEvent => ({ id: `e-${i}`, kind: 'decision', ts_ms: 1000 + i, ...extra });
const code = (c: string) => (e: unknown) => e instanceof StoreError && e.code === c;
const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
function canon(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return '{' + Object.keys(o).sort().map((k) => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}
const JSON_COLS = ['rule_ids', 'args_redacted', 'provenance_asserted', 'model_meta', 'outcome'];

// ---------------------------------------------------------------- anchors (item 1)
test('malformed anchors never verify (table-driven)', () => {
  const { s } = mk();
  for (let i = 1; i <= 3; i++) s.append(ev(i));
  const good = s.anchor();
  assert.equal(s.verify({ anchor: good }).ok, true);
  const H = 'a'.repeat(64);
  const cases: [string, unknown][] = [
    ['NaN head_seq', { ...good, head_seq: NaN }],
    ['negative head_seq', { ...good, head_seq: -1 }],
    ['fractional head_seq', { ...good, head_seq: 1.5 }],
    ['string head_seq', { ...good, head_seq: '3' }],
    ['unsafe head_seq', { ...good, head_seq: 2 ** 60 }],
    ['missing head_seq', { genesis_hash: good.genesis_hash, head_hash: good.head_hash, ts_ms: 1 }],
    ['missing genesis_hash', { head_seq: 3, head_hash: good.head_hash, ts_ms: 1 }],
    ['missing head_hash', { genesis_hash: good.genesis_hash, head_seq: 3, ts_ms: 1 }],
    ['63-char head_hash', { ...good, head_hash: good.head_hash.slice(1) }],
    ['65-char head_hash', { ...good, head_hash: good.head_hash + '0' }],
    ['uppercase head_hash', { ...good, head_hash: good.head_hash.toUpperCase() }],
    ['non-hex genesis', { ...good, genesis_hash: 'z'.repeat(64) }],
    ['short genesis', { ...good, genesis_hash: good.genesis_hash.slice(2) }],
    ['head_seq 0 with wrong hash', { ...good, head_seq: 0, head_hash: H }],
    ['head_seq 0 with store genesis but anchor genesis foreign', { genesis_hash: H, head_seq: 0, head_hash: good.genesis_hash, ts_ms: 1 }],
    ['null', null],
    ['string', 'anchor'],
    ['array', []],
    ['empty object', {}],
  ];
  for (const [name, a] of cases) {
    const v = s.verify({ anchor: a as Anchor });
    assert.equal(v.ok, false, name);
    assert.ok(v.errors.some((e) => e.code === 'anchor_mismatch' && e.seq === 0), name);
  }
  s.close();
});

test('anchor genesis_hash check is load-bearing (foreign genesis, otherwise-correct anchor)', () => {
  const a = mk();
  const b = mk();
  for (let i = 1; i <= 3; i++) a.s.append(ev(i));
  const anchor = a.s.anchor();
  // only the genesis differs: head_seq and head_hash are right for store A
  const foreign = { ...anchor, genesis_hash: b.s.anchor().genesis_hash };
  const v = a.s.verify({ anchor: foreign });
  assert.equal(v.ok, false);
  assert.deepEqual(v.errors, [{ seq: 0, code: 'anchor_mismatch' }]);
  // empty store, foreign genesis (internally consistent anchor from another store)
  const emptyA = mk();
  const v2 = emptyA.s.verify({ anchor: b.s.anchor() });
  assert.equal(v2.ok, false);
  assert.deepEqual(v2.errors, [{ seq: 0, code: 'anchor_mismatch' }]);
  assert.equal(emptyA.s.verify({ anchor: emptyA.s.anchor() }).ok, true);
  for (const x of [a, b, emptyA]) x.s.close();
});

test('anchor below the first retained seq without a covering checkpoint is anchor_mismatch (not anchor_pruned)', () => {
  const { s, path } = mk();
  for (let i = 1; i <= 5; i++) s.append(ev(i));
  const old = { ...s.anchor(), head_seq: 2, head_hash: s.iterate().find((e) => e.seq === 2)?.hash as string };
  const db = new DatabaseSync(path);
  db.exec('DROP TRIGGER events_no_delete; DELETE FROM events WHERE seq <= 3;');
  db.close();
  const v = s.verify({ anchor: old });
  assert.ok(v.errors.some((e) => e.code === 'anchor_mismatch' && e.seq === 2));
  assert.ok(!v.warnings.some((w) => w.code === 'anchor_pruned'));
  s.close();
});

// ---------------------------------------------------------------- pruned history (item 2, 3)
test('pruned history: verify fails unless allowPruned or a matching expectPruned; sink checkpoint line', () => {
  const { s, lines } = mk();
  for (let i = 1; i <= 6; i++) s.append(ev(i));
  const r = s.checkpointAndPrune(1004);
  assert.deepEqual(Object.keys(r).sort(), ['checkpointSeq', 'last_hash', 'pruned', 'through_seq']);
  assert.equal(r.through_seq, 3);
  assert.equal(r.pruned, 3);
  assert.equal(r.last_hash.length, 64);
  const line = JSON.parse(lines.at(-1) as string);
  assert.deepEqual(line, { prysm: 'checkpoint', genesis_hash: s.anchor().genesis_hash, through_seq: 3, last_hash: r.last_hash });
  const plain = s.verify();
  assert.equal(plain.ok, false);
  assert.deepEqual(plain.errors, [{ seq: r.checkpointSeq, code: 'history_pruned' }]);
  assert.equal(s.verify({ allowPruned: true }).ok, true);
  assert.equal(s.verify({ expectPruned: { through_seq: 3, last_hash: r.last_hash } }).ok, true);
  assert.equal(s.verify({ expectPruned: { through_seq: 3, last_hash: 'f'.repeat(64) } }).ok, false);
  assert.equal(s.verify({ expectPruned: { through_seq: 4, last_hash: r.last_hash } }).ok, false);
  s.close();
});

test('forged checkpoint (rows 1..5 deleted, checkpoint built with the public hash scheme) fails verify', () => {
  const { s, path } = mk();
  for (let i = 1; i <= 8; i++) s.append(ev(i));
  const rows = s.iterate();
  const db = new DatabaseSync(path);
  db.exec('DROP TRIGGER events_no_delete; DROP TRIGGER events_no_update;');
  db.exec('DELETE FROM events WHERE seq <= 5');
  const tail = rows[7] as (typeof rows)[number];
  const row: Record<string, unknown> = {
    seq: 9, id: 'forged', ts_ms: 5, kind: 'checkpoint', execution_id: null, session_id: null, agent_id: null, user_hmac: null,
    tool: null, effect: null, enforcement: null, rule_ids: null, reason_code: null, policy_version: null, request_digest: null,
    args_hmac: null, args_redacted: null, risk: null, latency_us: null, session_tainted: null, provenance_asserted: null,
    model_meta: null, outcome: { pruned_through_seq: 5, pruned_last_hash: (rows[4] as { hash: string }).hash, pruned_count: 5 },
    decision_id: null, engine_version: null, prev_hash: tail.hash,
  };
  const hash = sha(String(row['prev_hash']) + '\n' + canon(row));
  const cols = Object.keys(row);
  db.prepare(`INSERT INTO events(${cols.join(',')}, hash) VALUES (${cols.map(() => '?').join(',')}, ?)`).run(
    ...cols.map((c) => (JSON_COLS.includes(c) && row[c] !== null ? JSON.stringify(row[c]) : (row[c] as string | number | null))), hash);
  db.close();
  const v = s.verify();
  assert.equal(v.ok, false, 'a forged checkpoint must not make pruned history look clean');
  assert.deepEqual(v.errors, [{ seq: 9, code: 'history_pruned' }]);
  assert.equal(s.verify({ allowPruned: true }).ok, true, 'only the explicit opt-in accepts it');
  // the genuine expectation (none recorded / different values) does not match the forged checkpoint
  assert.equal(s.verify({ expectPruned: { through_seq: 5, last_hash: '0'.repeat(64) } }).ok, false);
  s.close();
});

test('retention floor, force, minRetainMs, and the no-op when nothing is eligible', () => {
  const { s, lines } = mk();
  const now = Date.now();
  s.append({ id: 'recent', kind: 'decision', ts_ms: now - 1000 });
  s.append({ id: 'old', kind: 'decision', ts_ms: now - 2 * DAY });
  assert.throws(() => s.checkpointAndPrune(now), code('invalid_event'));
  assert.throws(() => s.checkpointAndPrune(now - 1000), code('invalid_event'));
  assert.equal(s.count(), 2);
  // nothing eligible: seq 1 ('recent') is not < before, so the prefix is empty
  const headBefore = s.head();
  const lineCount = lines.length;
  const noop = s.checkpointAndPrune(now - 3 * DAY);
  assert.equal(noop.pruned, 0);
  assert.deepEqual(s.head(), headBefore);
  assert.equal(lines.length, lineCount, 'no checkpoint line for a no-op');
  // force overrides the floor
  const f = s.checkpointAndPrune(now, { force: true });
  assert.equal(f.pruned, 2);
  assert.equal(lines.length, lineCount + 1);
  s.close();
  const zero = mk({ minRetainMs: 0 });
  zero.s.append({ id: 'a', kind: 'decision', ts_ms: 5 });
  assert.equal(zero.s.checkpointAndPrune(Date.now()).pruned, 1);
  zero.s.close();
  assert.throws(() => openStore({ path: dbPath(tmpDir()), hmacKey: KEY, minRetainMs: -1 }), code('invalid_event'));
});

test('orphan_result is suppressed for results whose decision was pruned, but real orphans still warn', () => {
  const { s } = mk();
  s.append({ id: 'd1', kind: 'decision', ts_ms: 1, outcome: { will_execute: true } }); // seq 1 pruned
  s.append({ id: 'r1', kind: 'tool_result', decision_id: 'd1', ts_ms: 9_000_000 }); // seq 2 retained, decision pruned
  s.checkpointAndPrune(100);
  s.append({ id: 'd2', kind: 'decision', ts_ms: 9_000_001 });
  const v = s.verify({ allowPruned: true });
  assert.ok(!v.warnings.some((w) => w.code === 'orphan_result'));
  s.append({ id: 'r-bad', kind: 'tool_result', decision_id: 'never-existed', ts_ms: 9_000_002 });
  const v2 = s.verify({ allowPruned: true });
  assert.equal(v2.warnings.filter((w) => w.code === 'orphan_result').length, 1);
  s.close();
});

// ---------------------------------------------------------------- key protection (item 4)
test('key protection reporting and warnings (injectable behaviour)', () => {
  const mkKey = (protect: ((p: string) => 'acl' | 'mode_0600' | 'unprotected') | undefined, keyElsewhere: boolean) => {
    const dir = tmpDir();
    const keyDir = keyElsewhere ? tmpDir() : dir;
    return openStore({
      path: dbPath(dir), keyPath: dbPath(keyDir, 'k.key'), ...(protect ? { keyProtect: protect } : {}),
    });
  };
  const codes = (s: Store) => s.verify().warnings.map((w) => w.code);
  const unp = mkKey(() => 'unprotected', true);
  assert.equal(unp.keyProtection(), 'unprotected');
  assert.deepEqual(codes(unp), ['key_unprotected']);
  const acl = mkKey(() => 'acl', true);
  assert.equal(acl.keyProtection(), 'acl');
  assert.deepEqual(codes(acl), []);
  const co = mkKey(() => 'mode_0600', false);
  assert.equal(co.keyProtection(), 'mode_0600');
  assert.deepEqual(codes(co), ['key_colocated']);
  const both = mkKey(() => 'unprotected', false);
  assert.deepEqual(codes(both).sort(), ['key_colocated', 'key_unprotected']);
  const external = openStore({ path: dbPath(tmpDir()), hmacKey: KEY });
  assert.equal(external.keyProtection(), 'external');
  assert.deepEqual(codes(external), []);
  for (const x of [unp, acl, co, both, external]) x.close();
});

test('default key protection: reported honestly, warning iff unprotected, stable across reopen', () => {
  const dir = tmpDir();
  const keyPath = dbPath(tmpDir(), 'k.key');
  const path = dbPath(dir);
  const s = openStore({ path, keyPath });
  const p = s.keyProtection();
  assert.ok(['acl', 'mode_0600', 'unprotected'].includes(p));
  if (process.platform !== 'win32') assert.equal(p, 'mode_0600');
  assert.equal(s.verify().warnings.some((w) => w.code === 'key_unprotected'), p === 'unprotected');
  s.close();
  const s2 = openStore({ path, keyPath });
  assert.equal(s2.keyProtection(), p);
  s2.close();
});

// ---------------------------------------------------------------- read API (item 13)
test('getEvent, eventsByDecision, query', () => {
  const { s } = mk();
  s.append(ev(1, { id: 'dec-1', tool: 'read_file', effect: 'permit', session_id: 's1' }));
  s.append({ id: 'res-1', kind: 'tool_result', decision_id: 'dec-1', tool: 'read_file', session_id: 's1', ts_ms: 2 });
  s.append(ev(3, { id: 'dec-2', tool: 'send_email', effect: 'deny', session_id: 's2' }));
  assert.equal(s.getEvent('dec-2')?.seq, 3);
  assert.equal(s.getEvent('nope'), null);
  assert.deepEqual(s.eventsByDecision('dec-1').map((e) => e.id), ['dec-1', 'res-1']);
  assert.deepEqual(s.eventsByDecision('missing'), []);
  assert.deepEqual(s.query({ tool: 'read_file' }).map((e) => e.seq), [1, 2]);
  assert.deepEqual(s.query({ kind: 'tool_result' }).map((e) => e.id), ['res-1']);
  assert.deepEqual(s.query({ sessionId: 's2' }).map((e) => e.id), ['dec-2']);
  assert.deepEqual(s.query({ effect: 'deny' }).map((e) => e.id), ['dec-2']);
  assert.deepEqual(s.query({ afterSeq: 1, limit: 1 }).map((e) => e.seq), [2]);
  assert.equal(s.query().length, 3);
  // parameterised: hostile strings are data
  assert.deepEqual(s.query({ tool: "x' OR '1'='1" }), []);
  assert.equal(s.getEvent("dec-1' OR '1'='1"), null);
  s.close();
});

test('query/iterate validation: invalid limit/afterSeq/filters => invalid_event', () => {
  const { s } = mk();
  s.append(ev(1));
  const bad: unknown[] = [
    { limit: NaN }, { limit: 0 }, { limit: -1 }, { limit: 10001 }, { limit: 1.5 }, { limit: '5' }, { limit: Infinity },
    { afterSeq: -1 }, { afterSeq: NaN }, { afterSeq: 1.5 }, { afterSeq: '1' },
    { kind: 'bogus' }, { kind: 5 }, { effect: 'maybe' }, { tool: 5 }, { sessionId: {} }, { extra: 1 },
  ];
  for (const q of bad) assert.throws(() => s.query(q as never), code('invalid_event'), JSON.stringify(q));
  assert.throws(() => s.query(null as never), code('invalid_event'));
  assert.equal(s.query({ limit: 10000 }).length, 1);
  assert.throws(() => s.iterate({ limit: NaN }), code('invalid_event'));
  assert.throws(() => s.iterate({ afterSeq: -3 }), code('invalid_event'));
  assert.throws(() => s.getEvent(5 as never), code('invalid_event'));
  assert.throws(() => s.eventsByDecision(null as never), code('invalid_event'));
  assert.equal(s.iterate({ limit: 100000 }).length, 1);
  s.close();
});

test('reads use a separate connection: another handle sees committed writes; chunked verify spans >1000 rows', () => {
  const dir = tmpDir();
  const path = dbPath(dir);
  const w = openStore({ path, hmacKey: KEY, synchronous: 'NORMAL' });
  const r = openStore({ path, hmacKey: KEY, synchronous: 'NORMAL' });
  for (let i = 1; i <= 2500; i++) w.append(ev(i));
  assert.equal(r.count(), 2500);
  assert.equal(r.head()?.seq, 2500);
  const v = r.verify();
  assert.equal(v.ok, true);
  assert.equal(v.count, 2500);
  w.append(ev(2501));
  assert.equal(r.verify().count, 2501, 'a verify reader sees the concurrent writer commit');
  // tamper in the second chunk
  const db = new DatabaseSync(path);
  db.exec('DROP TRIGGER events_no_update');
  db.exec("UPDATE events SET tool='evil' WHERE seq=1500");
  db.close();
  const bad = w.verify();
  assert.deepEqual(bad.errors, [{ seq: 1500, code: 'hash_mismatch' }]);
  w.close();
  r.close();
});

test('appendShort is capped at 250 ms even with a long busy timeout', () => {
  const { s, path } = mk({ busyTimeoutMs: 5000 });
  s.append(ev(0));
  const other = new DatabaseSync(path, { timeout: 50 });
  other.exec('BEGIN IMMEDIATE');
  const t0 = Date.now();
  assert.throws(() => s.appendShort(ev(1)), code('busy'));
  const dt = Date.now() - t0;
  assert.ok(dt < 1500, `appendShort took ${dt}ms`);
  other.exec('ROLLBACK');
  other.close();
  assert.ok(s.appendShort(ev(2)));
  s.close();
});
