import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createHash, createHmac } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { openStore, StoreError, redactArgs } from '../../src/store/index.ts';
import type { Store, NewEvent } from '../../src/store/index.ts';
import { tmpDir, cleanup, dbPath } from '../support/tmp.ts';

after(cleanup);

const KEY = new Uint8Array(32).fill(7);
const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
const genesisOf = (path: string): string => {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    const r = db.prepare("SELECT value FROM meta WHERE key='nonce'").get() as { value: string };
    return sha('prysm-genesis-v1:' + r.value);
  } finally {
    db.close();
  }
};

function mkStore(extra: Record<string, unknown> = {}): { s: Store; path: string; dir: string } {
  const dir = tmpDir();
  const path = dbPath(dir);
  const s = openStore({ path, hmacKey: KEY, ...extra });
  return { s, path, dir };
}

function ev(i: number, extra: Partial<NewEvent> = {}): NewEvent {
  return { id: `e-${i}`, kind: 'decision', ts_ms: 1000 + i, effect: 'permit', tool: 'read_file', agent_id: 'a', ...extra };
}

// ---- independent canonicalisation + hashing (does NOT use store code) ----
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
function rawRows(path: string): Record<string, unknown>[] {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return db.prepare('SELECT * FROM events ORDER BY seq').all() as Record<string, unknown>[];
  } finally {
    db.close();
  }
}
function independentHash(row: Record<string, unknown>): string {
  const o: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) {
    if (k === 'hash') continue;
    o[k] = JSON_COLS.includes(k) && typeof v === 'string' ? JSON.parse(v) : v === undefined ? null : v;
  }
  return sha(String(row['prev_hash']) + '\n' + canon(o));
}
function attackerRewrite(path: string, mutate?: (rows: Record<string, unknown>[]) => void): void {
  const gen = genesisOf(path);
  const db = new DatabaseSync(path);
  db.exec('DROP TRIGGER events_no_update; DROP TRIGGER events_no_delete;');
  if (mutate) {
    let prev = gen;
    const rows = db.prepare('SELECT * FROM events ORDER BY seq').all() as Record<string, unknown>[];
    mutate(rows);
    for (const r of rows) {
      r['prev_hash'] = prev;
      r['hash'] = independentHash(r);
      prev = r['hash'] as string;
      db.prepare('UPDATE events SET prev_hash=?, hash=?, outcome=?, tool=? WHERE seq=?').run(
        r['prev_hash'] as string, r['hash'] as string, (r['outcome'] as string | null) ?? null, (r['tool'] as string | null) ?? null, r['seq'] as number);
    }
  }
  db.close();
}
function raw<T>(path: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(path);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

test('append/iterate/head/count', () => {
  const { s } = mkStore();
  assert.equal(s.count(), 0);
  assert.equal(s.head(), null);
  const a = s.append(ev(1));
  const b = s.append(ev(2, { outcome: { x: [1, 2] }, rule_ids: ['r1', 'r2'], session_tainted: true, latency_us: 12 }));
  assert.equal(a.seq, 1);
  assert.equal(b.seq, 2);
  assert.equal(b.prev_hash, a.hash);
  assert.equal(a.prev_hash, s.anchor().genesis_hash);
  assert.match(a.prev_hash, /^[0-9a-f]{64}$/);
  assert.equal(s.count(), 2);
  assert.deepEqual(s.head(), { seq: 2, hash: b.hash });
  const all = s.iterate();
  assert.equal(all.length, 2);
  assert.deepEqual(all[1]?.outcome, { x: [1, 2] });
  assert.deepEqual(all[1]?.rule_ids, ['r1', 'r2']);
  assert.equal(all[1]?.session_tainted, 1);
  assert.equal(all[0]?.outcome, null);
  assert.deepEqual(s.iterate({ afterSeq: 1 }).map((e) => e.seq), [2]);
  assert.deepEqual(s.iterate({ limit: 1 }).map((e) => e.seq), [1]);
  assert.equal(s.latest('decision')?.seq, 2);
  assert.equal(s.latest('checkpoint'), null);
  assert.equal(s.verify().ok, true);
  s.close();
});

test('invalid events are rejected with a value-free StoreError', () => {
  const { s } = mkStore();
  const SECRET = 'SUPER-SECRET-VALUE-123';
  const bads: unknown[] = [
    { id: '', kind: 'decision' },
    { id: 'x', kind: 'nope' },
    { id: 'x', kind: 'decision', effect: SECRET },
    { id: 'x', kind: 'decision', tool: 5 },
    { id: 'x', kind: 'decision', seq: 5 },
    { id: 'x', kind: 'decision', hash: SECRET },
    { id: 'x', kind: 'decision', ts_ms: 1.5 },
    { id: 'x', kind: 'decision', ts_ms: -1 },
    { id: 'x', kind: 'decision', enforcement: SECRET },
    { id: 'x', kind: 'decision', outcome: { a: undefined } },
    null,
  ];
  for (const b of bads) {
    assert.throws(() => s.append(b as NewEvent), (e: unknown) => {
      assert.ok(e instanceof StoreError);
      assert.equal(e.code, 'invalid_event');
      assert.ok(!e.message.includes(SECRET));
      return true;
    });
  }
  s.append(ev(1));
  assert.throws(() => s.append(ev(1)), (e: unknown) => e instanceof StoreError && e.code === 'duplicate_id'); // duplicate id
  assert.equal(s.count(), 1);
  assert.equal(s.verify().ok, true);
  s.close();
});

test('appendBestEffort never throws and writes one value-free sink line', () => {
  const lines: string[] = [];
  const { s } = mkStore({ secondarySink: (l: string) => lines.push(l) });
  assert.ok(s.appendBestEffort(ev(1)));
  assert.equal(lines.length, 0);
  const r = s.appendBestEffort({ id: 'e-1', kind: 'decision', tool: 'SECRET-TOOL' });
  assert.equal(r, null);
  assert.equal(lines.length, 1);
  assert.deepEqual(JSON.parse(lines[0] as string), { prysm: 'audit_write_failed', code: 'duplicate_id', kind: 'decision', id: 'e-1' });
  assert.equal(s.appendBestEffort(null as unknown as NewEvent), null);
  assert.ok(!lines.join('').includes('SECRET'));
  s.close();
  assert.equal(s.appendBestEffort(ev(9)), null); // closed store: still no throw
});

test('chain recomputation by independent code matches stored hashes', () => {
  const { s, path } = mkStore();
  for (let i = 1; i <= 20; i++) {
    s.append(ev(i, { outcome: { n: i, s: 'é\n"q"' }, rule_ids: ['b', 'a'], args_redacted: { z: { type: 'string', len: 3 } } }));
  }
  s.close();
  const rows = rawRows(path);
  assert.equal(rows.length, 20);
  let prev = genesisOf(path);
  for (const r of rows) {
    assert.equal(r['prev_hash'], prev);
    assert.equal(independentHash(r), r['hash']);
    prev = r['hash'] as string;
  }
});

test('tamper: mutate a row => hash_mismatch', () => {
  const { s, path } = mkStore();
  for (let i = 1; i <= 5; i++) s.append(ev(i, { outcome: { i } }));
  attackerRewrite(path);
  raw(path, (db) => db.exec("UPDATE events SET tool='evil' WHERE seq=3"));
  const v = s.verify();
  assert.equal(v.ok, false);
  assert.deepEqual(v.errors, [{ seq: 3, code: 'hash_mismatch' }]);
  s.close();
});

test('tamper: delete a middle row => seq_gap and prev_mismatch', () => {
  const { s, path } = mkStore();
  for (let i = 1; i <= 5; i++) s.append(ev(i));
  attackerRewrite(path);
  raw(path, (db) => db.exec('DELETE FROM events WHERE seq=3'));
  const v = s.verify();
  assert.equal(v.ok, false);
  const codes = v.errors.map((e) => e.code);
  assert.ok(codes.includes('seq_gap'));
  assert.ok(codes.includes('prev_mismatch'));
  s.close();
});

test('tamper: reorder rows is detected', () => {
  const { s, path } = mkStore();
  for (let i = 1; i <= 5; i++) s.append(ev(i));
  attackerRewrite(path);
  raw(path, (db) => {
    db.exec('UPDATE events SET seq = 99 WHERE seq = 2');
    db.exec('UPDATE events SET seq = 2 WHERE seq = 3');
    db.exec('UPDATE events SET seq = 3 WHERE seq = 99');
  });
  const v = s.verify();
  assert.equal(v.ok, false);
  assert.ok(v.errors.length > 0);
  s.close();
});

test('tamper: tail delete detected only with an anchor', () => {
  const { s, path } = mkStore();
  for (let i = 1; i <= 5; i++) s.append(ev(i));
  const anchor = s.anchor();
  assert.equal(anchor.head_seq, 5);
  attackerRewrite(path);
  raw(path, (db) => db.exec('DELETE FROM events WHERE seq IN (4,5)'));
  const plain = s.verify();
  assert.equal(plain.ok, true, 'a truncated chain is internally consistent');
  assert.equal(plain.count, 3);
  const anchored = s.verify({ anchor });
  assert.equal(anchored.ok, false);
  assert.ok(anchored.errors.some((e) => e.code === 'anchor_mismatch'));
  s.close();
});

test('tamper: full-chain rewrite detected only with an external anchor', () => {
  const { s, path } = mkStore();
  for (let i = 1; i <= 5; i++) s.append(ev(i, { outcome: { i } }));
  const anchor = s.anchor();
  attackerRewrite(path, (rows) => {
    for (const r of rows) r['tool'] = 'rewritten';
  });
  const plain = s.verify();
  assert.equal(plain.ok, true, 'attacker with the DB can recompute the whole chain');
  assert.equal(plain.count, 5);
  const anchored = s.verify({ anchor });
  assert.equal(anchored.ok, false);
  assert.ok(anchored.errors.some((e) => e.code === 'anchor_mismatch'));
  s.close();
});

test('a valid anchor verifies, and an anchor for an empty store verifies', () => {
  const { s } = mkStore();
  const empty = s.anchor();
  assert.equal(s.verify({ anchor: empty }).ok, true);
  for (let i = 1; i <= 3; i++) s.append(ev(i));
  const a = s.anchor();
  s.append(ev(4));
  assert.equal(s.verify({ anchor: a }).ok, true);
  s.close();
});

test('schema_version mismatch is reported by verify and blocks append', () => {
  const { s, path } = mkStore();
  s.append(ev(1));
  raw(path, (db) => db.exec("UPDATE meta SET value='2' WHERE key='schema_version'"));
  const v = s.verify();
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => e.code === 'schema_version'));
  assert.throws(() => s.append(ev(2)), (e: unknown) => e instanceof StoreError && e.code === 'corrupt');
  s.close();
  assert.throws(() => openStore({ path, hmacKey: KEY }), (e: unknown) => e instanceof StoreError && e.code === 'corrupt');
});

test('bad genesis and unexpected first row are reported', () => {
  const { s, path } = mkStore();
  for (let i = 1; i <= 3; i++) s.append(ev(i));
  attackerRewrite(path);
  raw(path, (db) => db.exec('DELETE FROM events WHERE seq=1'));
  const v = s.verify();
  assert.ok(v.errors.some((e) => e.code === 'unexpected_first_row'));
  s.close();
  const g = mkStore();
  g.s.append(ev(1));
  raw(g.path, (db) => db.exec("UPDATE meta SET value='00' WHERE key='genesis_hash'"));
  assert.ok(g.s.verify().errors.some((e) => e.code === 'bad_genesis'));
  g.s.close();
});

test('triggers block UPDATE and DELETE on the normal path', () => {
  const { s, path } = mkStore();
  s.append(ev(1));
  raw(path, (db) => {
    assert.throws(() => db.exec("UPDATE events SET tool='x'"), /append-only/);
    assert.throws(() => db.exec('DELETE FROM events'), /append-only/);
  });
  s.close();
});

test('concurrent writers: 4 processes x 100 appends => linear chain, exact count, no fork', async () => {
  const dir = tmpDir();
  const path = dbPath(dir);
  const s = openStore({ path }); // creates DB + key file
  s.append(ev(0));
  const worker = new URL('../support/append-worker.ts', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
  const run = (tag: string) =>
    new Promise<void>((resolve, reject) => {
      const p = spawn(process.execPath, ['--no-warnings', decodeURIComponent(worker), path, tag, '100'], { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      let err = '';
      p.stdout.on('data', (d) => (out += String(d)));
      p.stderr.on('data', (d) => (err += String(d)));
      p.on('exit', (code) => (code === 0 && out.includes('DONE') ? resolve() : reject(new Error(`worker ${tag} failed: ${code} ${err.slice(0, 300)}`))));
    });
  await Promise.all(['w1', 'w2', 'w3', 'w4', 'w5'].map(run));
  assert.equal(s.count(), 501);
  const v = s.verify();
  assert.equal(v.ok, true, JSON.stringify(v.errors.slice(0, 3)));
  assert.equal(v.count, 501);
  assert.equal(v.head_seq, 501);
  const rows = rawRows(path);
  let prev = genesisOf(path);
  rows.forEach((r, i) => {
    assert.equal(r['seq'], i + 1);
    assert.equal(r['prev_hash'], prev);
    assert.equal(independentHash(r), r['hash']);
    prev = r['hash'] as string;
  });
  const perAgent = new Map<string, number>();
  for (const r of rows) perAgent.set(String(r['agent_id']), (perAgent.get(String(r['agent_id'])) ?? 0) + 1);
  for (const t of ['w1', 'w2', 'w3', 'w4', 'w5']) assert.equal(perAgent.get(t), 100);
  s.close();
});

test('busy timeout is bounded and surfaces StoreError busy', () => {
  const { s, path } = mkStore({ busyTimeoutMs: 150 });
  s.append(ev(1));
  const other = new DatabaseSync(path, { timeout: 100 });
  other.exec('BEGIN IMMEDIATE');
  const t0 = Date.now();
  assert.throws(() => s.append(ev(2)), (e: unknown) => e instanceof StoreError && e.code === 'busy' && !/e-2/.test(e.message));
  const dt = Date.now() - t0;
  assert.ok(dt < 3000, `waited ${dt}ms`);
  assert.equal(s.appendBestEffort(ev(3)), null);
  other.exec('ROLLBACK');
  other.close();
  assert.ok(s.append(ev(4)));
  assert.equal(s.count(), 2);
  assert.equal(s.verify().ok, true);
  s.close();
});

test('prune + checkpoint: chain verifies from the checkpoint; rows after remain', () => {
  const { s } = mkStore();
  for (let i = 1; i <= 10; i++) s.append(ev(i)); // ts 1001..1010
  const r = s.checkpointAndPrune(1006); // prune seq 1..5
  assert.equal(r.pruned, 5);
  assert.equal(r.checkpointSeq, 11);
  assert.equal(s.count(), 6); // 6..10 + checkpoint
  const v = s.verify({ allowPruned: true });
  assert.equal(v.ok, true, JSON.stringify(v.errors));
  assert.equal(v.pruned_through, 5);
  assert.deepEqual(v.warnings.filter((w) => w.code === 'history_pruned'), [{ seq: 11, code: 'history_pruned' }]);
  const cp = s.latest('checkpoint');
  assert.equal((cp?.outcome as { pruned_through_seq: number }).pruned_through_seq, 5);
  assert.equal((cp?.outcome as { pruned_count: number }).pruned_count, 5);
  s.append(ev(11));
  assert.equal(s.verify({ allowPruned: true }).ok, true);
  // trigger re-armed after prune
  assert.equal(s.count(), 7);
  // second prune: first retained row is the previous checkpoint
  const r2 = s.checkpointAndPrune(10_000_000);
  assert.equal(r2.pruned, 5, 'the old checkpoint row carries a real-clock ts, so the prefix stops there');
  assert.equal(s.count(), 3);
  assert.equal(s.verify({ allowPruned: true }).ok, true);
  s.close();
});

test('prune: an old anchor still verifies when its head row was pruned; delete trigger re-armed', () => {
  const { s, path } = mkStore();
  for (let i = 1; i <= 4; i++) s.append(ev(i));
  const a = s.anchor();
  s.checkpointAndPrune(1_000_000);
  assert.equal(s.verify({ anchor: a, allowPruned: true }).ok, true);
  raw(path, (db) => assert.throws(() => db.exec('DELETE FROM events'), /append-only/));
  assert.equal(raw(path, (db) => (db.prepare("SELECT value FROM meta WHERE key='prune_open'").get() as { value: string }).value), '0');
  s.close();
});

test('prune rolls back wholly on error', () => {
  const { s, path } = mkStore();
  for (let i = 1; i <= 6; i++) s.append(ev(i));
  const before = s.verify();
  const headBefore = s.head();
  raw(path, (db) => db.exec("CREATE TRIGGER evil BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'nope'); END;"));
  assert.throws(() => s.checkpointAndPrune(1_000_000), (e: unknown) => e instanceof StoreError);
  assert.equal(s.count(), 6, 'nothing deleted');
  assert.deepEqual(s.head(), headBefore, 'no checkpoint event survived');
  assert.equal(s.latest('checkpoint'), null);
  assert.equal(raw(path, (db) => (db.prepare("SELECT value FROM meta WHERE key='prune_open'").get() as { value: string }).value), '0');
  assert.deepEqual(s.verify(), before);
  assert.throws(() => s.checkpointAndPrune(NaN), (e: unknown) => e instanceof StoreError && e.code === 'invalid_event');
  s.close();
});

test('size caps: long text truncated, big JSON replaced, whole row capped', () => {
  const { s, path } = mkStore();
  const big = 'x'.repeat(10_000);
  const r = s.append(ev(1, {
    tool: big,
    reason_code: 'é'.repeat(300),
    outcome: { v: big },
    model_meta: { arr: Array.from({ length: 3000 }, (_, i) => i) },
    args_redacted: { ok: 1 },
  }));
  assert.ok((r.tool as string).length <= 256);
  assert.ok((r.tool as string).endsWith('…[trunc]'));
  assert.ok(Array.from(r.reason_code as string).length <= 256);
  assert.equal((r.outcome as { truncated: boolean }).truncated, true);
  assert.equal((r.outcome as { bytes: number }).bytes > 4096, true);
  assert.equal((r.model_meta as { truncated: boolean }).truncated, true);
  assert.deepEqual(r.args_redacted, { ok: 1 });
  // worst case row: every field maxed
  const maxed: NewEvent = { id: 'm', kind: 'decision' };
  for (const k of ['execution_id', 'session_id', 'agent_id', 'user_hmac', 'tool', 'reason_code', 'policy_version', 'request_digest', 'args_hmac', 'decision_id', 'engine_version'] as const) {
    (maxed as unknown as Record<string, string>)[k] = '€'.repeat(400);
  }
  for (const k of ['rule_ids', 'args_redacted', 'provenance_asserted', 'model_meta', 'outcome'] as const) {
    (maxed as unknown as Record<string, unknown>)[k] = { v: 'y'.repeat(4000) };
  }
  s.append(maxed);
  const rows = rawRows(path);
  for (const row of rows) {
    let bytes = 0;
    for (const v of Object.values(row)) bytes += typeof v === 'string' ? Buffer.byteLength(v) : 8;
    assert.ok(bytes <= 16 * 1024 + 256, `row ${String(row['seq'])} is ${bytes} bytes`);
  }
  assert.equal(s.verify().ok, true);
  s.close();
});

test('log-injection strings are stored as data and cannot forge records', () => {
  const { s, path } = mkStore();
  const inj = '\n{"kind":"decision"}\r\n\u001b[31mRED\u001b[0m\u0000\u2028x';
  const r = s.append(ev(1, {
    tool: inj,
    reason_code: inj,
    outcome: { note: inj },
    args_redacted: { f: { type: 'string', len: 1, value: inj } },
  }));
  assert.equal((r.outcome as { note: string }).note, inj, 'JSON column round-trips exactly');
  assert.equal(r.tool, inj.replace('\u0000', '\uFFFD'), 'text columns keep the string as data (only NUL replaced)');
  const rows = s.iterate();
  assert.equal(rows.length, 1);
  assert.equal((rows[0]?.outcome as { note: string }).note, inj);
  const exported = JSON.stringify(rows[0]);
  assert.equal(exported.split('\n').length, 1, 'JSON export is a single line');
  assert.ok(!exported.includes('\u001b'), 'JSON export escapes control characters');
  assert.equal(s.verify().ok, true);
  const rawOutcome = raw(path, (db) => (db.prepare('SELECT outcome FROM events').get() as { outcome: string }).outcome);
  assert.ok(!rawOutcome.includes('\n') && !rawOutcome.includes('\r') && !rawOutcome.includes('\u001b'));
  s.append(ev(2, { tool: 'a\ud800b', outcome: { lone: '\udc00' } }));
  assert.equal(s.verify().ok, true);
  s.close();
});

test('HMAC key file: created, reused across reopen, different keys differ, plain sha256 does not match', () => {
  const dir = tmpDir();
  const path = dbPath(dir);
  const s1 = openStore({ path });
  assert.ok(existsSync(path + '.key'));
  const key = readFileSync(path + '.key');
  assert.equal(key.length, 32);
  const h1 = s1.hmac('args', 'hunter2');
  assert.match(h1, /^[0-9a-f]{32}$/);
  assert.equal(h1, createHmac('sha256', key).update('args:hunter2').digest('hex').slice(0, 32));
  assert.notEqual(s1.hmac('user', 'hunter2'), h1, 'label separates domains');
  s1.close();
  const s2 = openStore({ path });
  assert.equal(s2.hmac('args', 'hunter2'), h1, 'key reused');
  assert.deepEqual(readFileSync(path + '.key'), key);
  // plain unsalted hashes of a low-entropy value must not appear as the digest
  assert.notEqual(h1, sha('hunter2').slice(0, 32));
  assert.notEqual(h1, sha('args:hunter2').slice(0, 32));
  s2.close();
  // different key => different digest
  const other = openStore({ path: dbPath(tmpDir()), hmacKey: new Uint8Array(32).fill(9) });
  const same = openStore({ path: dbPath(tmpDir()), hmacKey: KEY });
  assert.notEqual(other.hmac('args', 'x'), same.hmac('args', 'x'));
  other.close();
  same.close();
  assert.throws(() => same.hmac('args', 'x'.repeat(1)) && s2.append(ev(1)), (e: unknown) => e instanceof StoreError);
});

test('opening an existing DB with a different key is refused (fail closed)', () => {
  const dir = tmpDir();
  const path = dbPath(dir);
  openStore({ path, hmacKey: KEY }).close();
  assert.throws(() => openStore({ path, hmacKey: new Uint8Array(32).fill(1) }), (e: unknown) => e instanceof StoreError && e.code === 'key_mismatch');
  assert.throws(() => openStore({ path, hmacKey: new Uint8Array(16) }), (e: unknown) => e instanceof StoreError && e.code === 'key_invalid');
  assert.throws(() => openStore({ path: '' }), (e: unknown) => e instanceof StoreError);
  openStore({ path, hmacKey: KEY }).close();
});

test('stored digests are keyed: request/args digests are not plain hashes', () => {
  const { s } = mkStore();
  const low = 'yes';
  const r = s.append(ev(1, { args_hmac: s.hmac('args', low), request_digest: s.hmac('request', 'sha256:' + sha(low)) }));
  assert.notEqual(r.args_hmac, sha(low).slice(0, 32));
  s.close();
});

test('redactArgs: default is type+len only, rawFields are masked and truncated', () => {
  const secret = 'sk-ABCDEFGHIJKLMNOP1234';
  const out = redactArgs({ a: 'héllo', n: 5, arr: [1, 2, 3], o: { k: 1 }, t: true, z: null, path: `x ${secret} ${'y'.repeat(300)}` }, { rawFields: ['path'] });
  assert.deepEqual(out['a'], { type: 'string', len: 5 });
  assert.deepEqual(out['arr'], { type: 'array', len: 3 });
  assert.deepEqual(out['n'], { type: 'number', len: null });
  assert.ok(!JSON.stringify(out).includes('héllo'));
  const p = out['path'] as { value: string; len: number };
  assert.ok(!p.value.includes(secret));
  assert.ok(p.value.includes('«masked»'));
  assert.ok(Array.from(p.value).length <= 200);
  for (const bad of ['AKIAABCDEFGHIJKLMNOP', 'ghp_' + 'a'.repeat(24), '-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----',
    'Bearer ' + 'a'.repeat(20), 'eyJhbGciOi.eyJzdWIiOi.sig', 'password=hunter2xyz', 'api_key: abc123']) {
    const m = (redactArgs({ f: bad }, { rawFields: ['f'] })['f'] as { value: string }).value;
    assert.equal(m, '«masked»', bad);
  }
  assert.deepEqual(redactArgs('str' as unknown), { _: { type: 'string', len: 3 } });
  // arg names are data too
  const k = redactArgs({ [secret]: 1, ok_name: 2 });
  assert.ok(!JSON.stringify(k).includes(secret));
  assert.ok('ok_name' in k);
  const allowed = redactArgs({ keep: 1, other: 2 }, { allowedKeys: ['keep'] });
  assert.deepEqual(Object.keys(allowed).sort(), ['_undeclared', 'keep']);
  assert.equal(allowed['_undeclared'], 1);
  // hostile input never throws
  const hostile = new Proxy({}, { ownKeys() { throw new Error('x'); } });
  assert.doesNotThrow(() => redactArgs(hostile));
});

test('crash recovery: killed writer mid-transaction leaves a verifiable chain', async () => {
  const dir = tmpDir();
  const path = dbPath(dir);
  const s = openStore({ path });
  s.append(ev(1));
  s.close();
  const child = `
    import { DatabaseSync } from "node:sqlite";
    const db = new DatabaseSync(${JSON.stringify(path)}, { timeout: 500 });
    db.exec("BEGIN IMMEDIATE");
    db.exec("INSERT INTO meta(key,value) VALUES ('junk','1')");
    console.log("READY");
    setInterval(() => {}, 1000);`;
  const p = spawn(process.execPath, ['--no-warnings', '--input-type=module', '-e', child]);
  await new Promise<void>((res, rej) => {
    p.stdout.on('data', (d) => String(d).includes('READY') && res());
    setTimeout(() => rej(new Error('child timeout')), 8000);
  });
  p.kill('SIGKILL');
  await new Promise((r) => p.on('exit', r));
  const s2 = openStore({ path });
  s2.append(ev(2));
  assert.equal(s2.verify().ok, true);
  assert.equal(s2.count(), 2);
  s2.close();
});
