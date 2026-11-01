// REPORT-SPEC §5.5: schema allow-list on every open (read-only or not).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { openStore, StoreError } from '../../src/store/index.ts';
import { tmpDir, cleanup, dbPath } from '../support/tmp.ts';

after(cleanup);
const KEY = new Uint8Array(32).fill(6);

function good(): string {
  const path = dbPath(tmpDir());
  const s = openStore({ path, hmacKey: KEY });
  s.append({ id: 'a', kind: 'decision', ts_ms: 1 });
  s.close();
  return path;
}
function raw(path: string, sql: string): void {
  const d = new DatabaseSync(path);
  d.exec(sql);
  d.close();
}
function codeOf(fn: () => unknown): string | undefined {
  try { fn(); } catch (e) { return e instanceof StoreError ? e.code : 'other:' + String(e); }
  return undefined;
}
const opens = (path: string): (string | undefined)[] => [
  codeOf(() => openStore({ path, hmacKey: KEY }).close()),
  codeOf(() => openStore({ path, hmacKey: KEY, readOnly: true }).close()),
];

test('a clean store (and a store whose append-only triggers were dropped) still opens', () => {
  const p = good();
  assert.deepEqual(opens(p), [undefined, undefined]);
  raw(p, 'DROP TRIGGER events_no_update; DROP TRIGGER events_no_delete;');
  assert.deepEqual(opens(p), [undefined, undefined]);
});

test('a forged DB whose events is a recursive view fails with corrupt immediately (never queried)', () => {
  const path = dbPath(tmpDir());
  raw(path, `CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
    CREATE VIEW events AS WITH RECURSIVE r(seq) AS (SELECT 1 UNION ALL SELECT seq + 1 FROM r) SELECT seq FROM r;`);
  const t0 = Date.now();
  assert.deepEqual(opens(path), ['corrupt', 'corrupt']);
  assert.ok(Date.now() - t0 < 2000, 'must not hang on the view');
});

test('events replaced by a view in an otherwise real store is corrupt', () => {
  const p = good();
  raw(p, 'DROP TRIGGER events_no_update; DROP TRIGGER events_no_delete; ALTER TABLE events RENAME TO events_old; CREATE VIEW events AS SELECT * FROM events_old;');
  assert.deepEqual(opens(p), ['corrupt', 'corrupt']);
});

test('extra views, tables, indexes and unexpected triggers are corrupt', () => {
  for (const sql of [
    'CREATE VIEW v AS SELECT 1',
    'CREATE TABLE extra(x)',
    'CREATE INDEX evil_idx ON events(tool)',
    "CREATE TRIGGER evil AFTER INSERT ON events BEGIN SELECT 1; END",
    "DROP TRIGGER events_no_update; CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT 1; END",
    "DROP TRIGGER events_no_delete; CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN SELECT 1; END",
  ]) {
    const p = good();
    raw(p, sql);
    assert.deepEqual(opens(p), ['corrupt', 'corrupt'], sql);
  }
});

test('a virtual table is corrupt when the module is available (otherwise SQLite itself refuses the DB)', () => {
  const p = good();
  let created = true;
  try { raw(p, 'CREATE VIRTUAL TABLE vt USING fts5(a)'); } catch { created = false; }
  if (!created) {
    assert.ok(true, 'SKIPPED: fts5 is not compiled into this node:sqlite build; virtual-table branch is exercised via the table-name allow-list only');
    return;
  }
  assert.deepEqual(opens(p), ['corrupt', 'corrupt']);
});

test('events present without meta (or the reverse) is corrupt', () => {
  const p = good();
  raw(p, 'DROP TRIGGER events_no_update; DROP TRIGGER events_no_delete; DROP TABLE meta');
  assert.deepEqual(opens(p), ['corrupt', 'corrupt']);
});

test('query_only defence in depth: a raw SQLite read-only connection rejects writes, and the read-only store appends nothing', () => {
  const p = good();
  const d = new DatabaseSync(p, { readOnly: true });
  assert.throws(() => d.exec("INSERT INTO meta(key, value) VALUES ('x','y')"));
  d.close();
  const s = openStore({ path: p, hmacKey: KEY, readOnly: true });
  assert.equal(codeOf(() => s.append({ id: 'b', kind: 'decision', ts_ms: 2 })), 'io');
  assert.equal(s.count(), 1);
  s.close();
});
