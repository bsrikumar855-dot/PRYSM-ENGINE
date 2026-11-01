// M4 amendment: openStore({ readOnly: true }) for the CLI read commands.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { existsSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { openStore, StoreError } from '../../src/store/index.ts';
import type { NewEvent } from '../../src/store/index.ts';
import { tmpDir, cleanup, dbPath } from '../support/tmp.ts';

after(cleanup);
const ev = (i: number, extra: Partial<NewEvent> = {}): NewEvent => ({ id: `e-${i}`, kind: 'decision', ts_ms: 1000 + i, ...extra });

function build(n = 3): { path: string; keyPath: string } {
  const dir = tmpDir();
  const path = dbPath(dir);
  const keyPath = path + '.key';
  const s = openStore({ path });
  for (let i = 1; i <= n; i++) s.append(ev(i, { tool: 't' + i, effect: 'permit' }));
  s.close();
  return { path, keyPath };
}

function code(fn: () => unknown): string | undefined {
  try { fn(); } catch (e) { return e instanceof StoreError ? e.code : 'other'; }
  return undefined;
}

test('readOnly: reads, verify, anchor work; keyProtection is unknown; hmac unavailable; row count and head unchanged', () => {
  const { path } = build(4);
  const s = openStore({ path, readOnly: true });
  assert.equal(s.count(), 4);
  assert.equal(s.head()?.seq, 4);
  assert.equal(s.query({ tool: 't2' }).length, 1);
  assert.equal(s.getEvent('e-3')?.seq, 3);
  const v = s.verify();
  assert.equal(v.ok, true);
  assert.equal(v.count, 4);
  assert.equal(s.anchor().head_seq, 4);
  assert.equal(s.keyProtection(), 'unknown');
  assert.equal(code(() => s.hmac('tool', 'x')), 'key_mismatch');
  s.close();
  const w = openStore({ path });
  assert.equal(w.count(), 4);
  assert.equal(w.head()?.seq, 4);
  w.close();
});

test('readOnly: every write method fails with io and nothing changes', () => {
  const { path } = build(2);
  const s = openStore({ path, readOnly: true, secondarySink: () => {} });
  assert.equal(code(() => s.append(ev(9))), 'io');
  assert.equal(code(() => s.appendShort(ev(9))), 'io');
  assert.equal(s.appendBestEffort(ev(9, { id: 'be' })), null);
  assert.equal(code(() => s.checkpointAndPrune(0, { force: true })), 'io');
  assert.equal(s.count(), 2);
  s.close();
  const w = openStore({ path });
  assert.equal(w.count(), 2);
  w.close();
});

test('readOnly: a present key file is never loaded, changed or replaced; a missing one is never created', () => {
  const { path, keyPath } = build(2);
  const keyBytes = readFileSync(keyPath);
  const s1 = openStore({ path, readOnly: true });
  assert.equal(s1.keyProtection(), 'unknown');
  assert.equal(s1.verify().ok, true);
  s1.close();
  assert.deepEqual(readFileSync(keyPath), keyBytes);
  rmSync(keyPath);
  const s = openStore({ path, readOnly: true, secondarySink: () => {} });
  assert.equal(existsSync(keyPath), false);
  assert.equal(s.count(), 2);
  assert.equal(s.verify().ok, true);
  assert.equal(code(() => s.hmac('tool', 'x')), 'key_mismatch');
  s.close();
  assert.equal(existsSync(keyPath), false);
  // a writable open still refuses to regenerate (existing behaviour)
  assert.equal(code(() => openStore({ path })), 'key_mismatch');
});

test('readOnly: query_only - the connection cannot write even through raw SQL paths of the store', () => {
  const { path } = build(2);
  const s = openStore({ path, readOnly: true });
  assert.equal(code(() => s.append(ev(50))), 'io');
  assert.equal(s.count(), 2);
  s.close();
});

test('readOnly: a missing DB file is an io error and is not created', () => {
  const dir = tmpDir();
  const path = dbPath(dir, 'nope.db');
  assert.equal(code(() => openStore({ path, readOnly: true })), 'io');
  assert.equal(existsSync(path), false);
  assert.equal(existsSync(path + '.key'), false);
});

test('readOnly: an SQLite file that is not a store is corrupt and no table is created', () => {
  const dir = tmpDir();
  const path = dbPath(dir, 'other.db');
  const d = new DatabaseSync(path);
  d.exec('CREATE TABLE x(a)');
  d.close();
  assert.equal(code(() => openStore({ path, readOnly: true })), 'corrupt');
  const d2 = new DatabaseSync(path, { readOnly: true });
  const tables = d2.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as { name: string }[];
  d2.close();
  assert.deepEqual(tables.map((t) => t.name), ['x']);
  assert.equal(existsSync(path + '.key'), false);
});

test('readOnly: a plain non-SQLite file is rejected and left untouched', () => {
  const dir = tmpDir();
  const path = dbPath(dir, 'junk.db');
  writeFileSync(path, 'this is not a database, definitely not');
  assert.notEqual(code(() => openStore({ path, readOnly: true })), undefined);
  assert.equal(readFileSync(path, 'utf8'), 'this is not a database, definitely not');
});

test('readOnly: does not reset the prune_open flag or add prune_flag_reset', () => {
  const { path } = build(2);
  const d = new DatabaseSync(path);
  d.exec("UPDATE meta SET value='1' WHERE key='prune_open'");
  d.close();
  const s = openStore({ path, readOnly: true });
  s.close();
  const r = new DatabaseSync(path, { readOnly: true });
  const po = r.prepare("SELECT value FROM meta WHERE key='prune_open'").get() as { value: string };
  const pf = r.prepare("SELECT value FROM meta WHERE key='prune_flag_reset'").get();
  r.close();
  assert.equal(po.value, '1');
  assert.equal(pf, undefined);
});

test('readOnly: validation of the option and :memory:', () => {
  assert.equal(code(() => openStore({ path: ':memory:', hmacKey: new Uint8Array(32), readOnly: true })), 'invalid_event');
  const { path } = build(1);
  assert.equal(code(() => openStore({ path, readOnly: 'yes' as unknown as boolean })), 'invalid_event');
});

test('readOnly: a supplied hmacKey is used and protection is external', () => {
  const dir = tmpDir();
  const path = dbPath(dir);
  const key = new Uint8Array(32).fill(9);
  const w = openStore({ path, hmacKey: key });
  w.append(ev(1));
  const mac = w.hmac('tool', 'x');
  w.close();
  const s = openStore({ path, hmacKey: key, readOnly: true });
  assert.equal(s.keyProtection(), 'external');
  assert.equal(s.hmac('tool', 'x'), mac);
  s.close();
});
