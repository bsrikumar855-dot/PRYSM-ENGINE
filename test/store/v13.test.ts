// AUDIT-SPEC §6 (v1.3) store amendments: strict expectPruned, ACL honesty.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { userInfo } from 'node:os';
import { openStore, evaluateAcl, isWellKnownGroup } from '../../src/store/index.ts';
import type { Store, NewEvent } from '../../src/store/index.ts';
import { tmpDir, cleanup, dbPath } from '../support/tmp.ts';

after(cleanup);
const KEY = new Uint8Array(32).fill(4);
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
const ev = (i: number, extra: Partial<NewEvent> = {}): NewEvent => ({ id: `e-${i}`, kind: 'decision', ts_ms: 1000 + i, ...extra });
const codes = (r: { errors: { code: string }[] }) => [...new Set(r.errors.map((e) => e.code))].sort();

function forgeCheckpoint(path: string, seq: number, prevHash: string, through: number, lastHash: string): void {
  const row: Record<string, unknown> = {
    seq, id: 'forged-' + seq, ts_ms: 5, kind: 'checkpoint', execution_id: null, session_id: null, agent_id: null, user_hmac: null,
    tool: null, effect: null, enforcement: null, rule_ids: null, reason_code: null, policy_version: null, request_digest: null,
    args_hmac: null, args_redacted: null, risk: null, latency_us: null, session_tainted: null, provenance_asserted: null,
    model_meta: null, outcome: { pruned_through_seq: through, pruned_last_hash: lastHash, pruned_count: through },
    decision_id: null, engine_version: null, prev_hash: prevHash,
  };
  const hash = sha(prevHash + '\n' + canon(row));
  const cols = Object.keys(row);
  const db = new DatabaseSync(path);
  db.prepare(`INSERT INTO events(${cols.join(',')}, hash) VALUES (${cols.map(() => '?').join(',')}, ?)`).run(
    ...cols.map((c) => (JSON_COLS.includes(c) && row[c] !== null ? JSON.stringify(row[c]) : (row[c] as string | number | null))), hash);
  db.close();
}

function legitPruned(): { s: Store; path: string; legit: { through_seq: number; last_hash: string }; hash12: string; cpSeq: number } {
  const path = dbPath(tmpDir());
  const s = openStore({ path, hmacKey: KEY });
  for (let i = 1; i <= 12; i++) s.append(ev(i));
  const hash12 = s.iterate().find((e) => e.seq === 12)?.hash as string;
  const r = s.checkpointAndPrune(1006); // prunes 1..5, checkpoint at seq 13
  return { s, path, legit: { through_seq: r.through_seq, last_hash: r.last_hash }, hash12, cpSeq: r.checkpointSeq };
}

test('expectPruned: legit prune through 5 then forged checkpoint through 12 fails by default and under expectPruned=[legit]', () => {
  const { s, path, legit, hash12, cpSeq } = legitPruned();
  assert.equal(legit.through_seq, 5);
  const good = s.verify({ expectPruned: [legit] });
  assert.equal(good.ok, true, JSON.stringify(good.errors));
  assert.deepEqual(good.checkpoints, [{ seq: cpSeq, through_seq: 5, last_hash: legit.last_hash }]);
  assert.equal(s.verify({ expectPruned: legit }).ok, true, 'a single object is a one-element array');
  // attacker: drop triggers, delete rows 6..12, append a forged checkpoint through 12 using the public scheme
  const db = new DatabaseSync(path);
  db.exec('DROP TRIGGER events_no_delete; DROP TRIGGER events_no_update;');
  db.exec('DELETE FROM events WHERE seq BETWEEN 6 AND 12');
  db.close();
  forgeCheckpoint(path, cpSeq + 1, s.head()?.hash as string, 12, hash12);
  const byDefault = s.verify();
  assert.equal(byDefault.ok, false);
  assert.ok(byDefault.errors.some((e) => e.code === 'history_pruned' && e.seq === cpSeq + 1));
  const strict = s.verify({ expectPruned: [legit] });
  assert.equal(strict.ok, false);
  assert.ok(strict.errors.some((e) => e.code === 'history_pruned' && e.seq === cpSeq + 1), 'forged checkpoint is not in the expected list');
  assert.ok(strict.errors.some((e) => e.code === 'unexpected_first_row'), 'the expected checkpoint does not justify the start boundary');
  assert.equal(strict.checkpoints.length, 2, 'both retained checkpoints are listed for the operator');
  s.close();
});

test('expectPruned: every retained checkpoint must be expected; every expected entry must exist; malformed entries fail', () => {
  const { s, legit } = legitPruned();
  const other = { through_seq: 99, last_hash: 'a'.repeat(64) };
  const missing = s.verify({ expectPruned: [legit, other] });
  assert.equal(missing.ok, false);
  assert.deepEqual(codes(missing), ['checkpoint_missing']);
  const wrong = s.verify({ expectPruned: [other] });
  assert.deepEqual(codes(wrong), ['checkpoint_missing', 'history_pruned', 'unexpected_first_row']);
  assert.equal(s.verify({ expectPruned: [] }).ok, false, 'an empty expectation rejects any retained checkpoint');
  for (const bad of [[{}], [null], [{ through_seq: 5 }], [{ through_seq: '5', last_hash: legit.last_hash }], [{ through_seq: 5, last_hash: 'short' }]]) {
    const v = s.verify({ expectPruned: [legit, ...bad] as never });
    assert.equal(v.ok, false, JSON.stringify(bad));
    assert.ok(v.errors.some((e) => e.code === 'checkpoint_missing'));
  }
  // allowPruned is the dev-only downgrade; it does not weaken an explicit expectation
  assert.equal(s.verify({ allowPruned: true }).ok, true);
  assert.equal(s.verify({ allowPruned: true, expectPruned: [other] }).ok, false);
  s.close();
  const fresh = openStore({ path: dbPath(tmpDir()), hmacKey: KEY });
  fresh.append(ev(1));
  const v = fresh.verify({ expectPruned: [] });
  assert.equal(v.ok, true);
  assert.deepEqual(v.checkpoints, []);
  assert.equal(fresh.verify({ expectPruned: [legit] }).ok, false);
  fresh.close();
});

// ---------------------------------------------------------------- key ACL honesty
const ME = userInfo().username;
const aclOut = (kp: string, lines: string[]) =>
  [kp + ' ' + lines[0], ...lines.slice(1).map((l) => '                 ' + l), '', 'Successfully processed 1 files; Failed processing 0 files', ''].join('\r\n');

test('evaluateAcl: exactly one principal, the current user, inheritance removed', () => {
  const kp = 'C:\\keys\\prysm.key';
  assert.equal(evaluateAcl(aclOut(kp, ['HOST\\babus:(R,W)']), kp, 'babus'), true);
  assert.equal(evaluateAcl(aclOut(kp, ['babus:(R,W)']), kp, 'BABUS'), true, 'case-insensitive');
  assert.equal(evaluateAcl(aclOut(kp, ['HOST\\babus:(R,W)', 'NT AUTHORITY\\SYSTEM:(F)']), kp, 'babus'), false, 'two principals');
  assert.equal(evaluateAcl(aclOut(kp, ['HOST\\babus:(I)(F)']), kp, 'babus'), false, 'inherited entry');
  assert.equal(evaluateAcl(aclOut(kp, ['HOST\\someone:(R,W)']), kp, 'babus'), false, 'another user');
  assert.equal(evaluateAcl(aclOut(kp, ['Everyone:(R,W)']), kp, 'Everyone'), false, 'a group can never be the grantee');
  assert.equal(evaluateAcl(aclOut(kp, ['BUILTIN\\Users:(R,W)']), kp, 'BUILTIN\\Users'), false);
  assert.equal(evaluateAcl(aclOut(kp, ['NT AUTHORITY\\SYSTEM:(R,W)']), kp, 'SYSTEM'), false);
  assert.equal(evaluateAcl('', kp, 'babus'), false);
  assert.equal(evaluateAcl('garbage without entries', kp, 'babus'), false);
  assert.equal(evaluateAcl(aclOut(kp, ['HOST\\babus:(R,W)']), kp, ''), false);
  for (const g of ['Everyone', 'Users', 'Authenticated Users', 'SYSTEM', 'BUILTIN\\Administrators', 'NT AUTHORITY\\Authenticated Users', 'everyone']) {
    assert.equal(isWellKnownGroup(g), true, g);
  }
  assert.equal(isWellKnownGroup('babus'), false);
});

test('store ACL status comes from re-reading the ACL on every open; meta and env vars are not trusted', () => {
  const path = dbPath(tmpDir());
  const keyPath = dbPath(tmpDir(), 'k.key');
  const good = (kp: string) => aclOut(kp, [`HOST\\${ME}:(R,W)`]);
  const s1 = openStore({ path, keyPath, aclReader: good });
  assert.equal(s1.keyProtection(), 'acl');
  assert.equal(s1.verify().warnings.some((w) => w.code === 'key_unprotected'), false);
  s1.close();
  // reopen with a reader that now reports a broad grant: meta still says 'acl' but it is only a hint
  const s2 = openStore({ path, keyPath, aclReader: (kp) => aclOut(kp, ['Everyone:(R,W)', `HOST\\${ME}:(F)`]) });
  assert.equal(s2.keyProtection(), 'unprotected');
  assert.ok(s2.verify().warnings.some((w) => w.code === 'key_unprotected'));
  s2.close();
  for (const reader of [() => null, () => { throw new Error('icacls missing'); }, () => 'junk']) {
    const s = openStore({ path, keyPath, aclReader: reader });
    assert.equal(s.keyProtection(), 'unprotected');
    s.close();
  }
  // principal comes from os.userInfo(), not USERNAME: USERNAME=Everyone cannot produce or block 'acl'
  const saved = process.env['USERNAME'];
  process.env['USERNAME'] = 'Everyone';
  try {
    const ok = openStore({ path, keyPath, aclReader: good });
    assert.equal(ok.keyProtection(), 'acl');
    ok.close();
    const bad = openStore({ path, keyPath, aclReader: (kp) => aclOut(kp, ['Everyone:(R,W)']) });
    assert.equal(bad.keyProtection(), 'unprotected');
    bad.close();
  } finally {
    if (saved === undefined) delete process.env['USERNAME'];
    else process.env['USERNAME'] = saved;
  }
  // an injected principal that is a well-known group never yields acl
  const g = openStore({ path, keyPath, aclUser: 'Everyone', aclReader: (kp) => aclOut(kp, ['Everyone:(R,W)']) });
  assert.equal(g.keyProtection(), 'unprotected');
  g.close();
});

test('default (real) key protection is re-evaluated on reopen and consistent with the warning', () => {
  const path = dbPath(tmpDir());
  const keyPath = dbPath(tmpDir(), 'k.key');
  const a = openStore({ path, keyPath });
  const p = a.keyProtection();
  a.close();
  const b = openStore({ path, keyPath });
  assert.equal(b.keyProtection(), p);
  assert.equal(b.verify().warnings.some((w) => w.code === 'key_unprotected'), p === 'unprotected');
  b.close();
});
