// CLI verify-chain + anchor (REPORT-SPEC §1.4-1.5, §4.4, §4.5, §4.11, §4.13; A-13 CLI part).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { openStore } from '../../src/store/index.ts';
import { cleanup, tmpDir, dbPath } from '../support/tmp.ts';
import { KEY } from '../support/guard-kit.ts';
import { forgeCheckpoint, guardFixture, rawTamper, runCli } from '../support/cli-kit.ts';

after(cleanup);

function fresh(n = 8): { dir: string; db: string } {
  const dir = tmpDir();
  const db = dbPath(dir);
  const s = openStore({ path: db, hmacKey: KEY });
  for (let i = 1; i <= n; i++) s.append({ id: 'e' + i, kind: 'decision', ts_ms: 1000 + i, effect: 'permit', enforcement: 'enforced', reason_code: 'permitted', tool: 'search_docs' });
  s.close();
  return { dir, db };
}
const wr = (dir: string, name: string, text: string): string => {
  const p = join(dir, name);
  writeFileSync(p, text);
  return p;
};

test('verify-chain: ok on a real guard store, text and --json schema', async () => {
  const f = await guardFixture();
  const r = await runCli(['verify-chain', '--db', f.db]);
  assert.equal(r.code, 0);
  assert.equal(r.stdout.split('\n')[0], 'OK');
  assert.match(r.stdout, /head seq=11 hash=[0-9a-f]{64}/);
  assert.match(r.stdout, /no anchor supplied/);
  const j = await runCli(['verify-chain', '--db', f.db, '--json']);
  assert.equal(j.stderr, '');
  const o = JSON.parse(j.stdout);
  assert.deepEqual(Object.keys(o).sort(), ['checkpoints', 'errors', 'head_hash', 'head_seq', 'ok', 'warnings']);
  assert.equal(o.ok, true);
  assert.equal(o.head_seq, 11);
  // the guard's own anchor sink line is accepted as --anchor and via --anchor-log
  const dir = tmpDir();
  const one = wr(dir, 'a.json', f.anchorLine);
  const ok1 = await runCli(['verify-chain', '--db', f.db, '--anchor', one]);
  assert.equal(ok1.code, 0);
  assert.ok(!ok1.stdout.includes('no anchor supplied'));
  const log = wr(dir, 'mixed.log', ['[server] {"prysm":"anchor","genesis_hash":"bad"}', 'noise', '{"prysm":"audit_skipped"}', f.anchorLine, ''].join('\n'));
  assert.equal((await runCli(['verify-chain', '--db', f.db, '--anchor-log', log])).code, 0);
});

test('verify-chain: tampered row => exit 1 with hash_mismatch; notes never change the exit code', async () => {
  const { db } = fresh();
  rawTamper(db, (d) => { d.exec("UPDATE events SET tool='evil' WHERE seq=3"); });
  const r = await runCli(['verify-chain', '--db', db]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /^FAILED/);
  assert.match(r.stdout, /error seq=3 code=hash_mismatch/);
  const j = JSON.parse((await runCli(['verify-chain', '--db', db, '--json'])).stdout);
  assert.equal(j.ok, false);
  assert.ok(j.errors.some((e: { seq: number; code: string }) => e.seq === 3 && e.code === 'hash_mismatch'));
});

test('verify-chain: tail truncation is detected only with an anchor (exit 1 vs 0)', async () => {
  const { dir, db } = fresh();
  const anchor = join(dir, 'anchor.json');
  assert.equal((await runCli(['anchor', '--db', db, '--out', anchor])).code, 0);
  rawTamper(db, (d) => { d.exec('DELETE FROM events WHERE seq > 5'); });
  const without = await runCli(['verify-chain', '--db', db]);
  assert.equal(without.code, 0, 'undetectable without an anchor');
  assert.match(without.stdout, /no anchor supplied/);
  const withA = await runCli(['verify-chain', '--db', db, '--anchor', anchor]);
  assert.equal(withA.code, 1);
  assert.match(withA.stdout, /error seq=8 code=anchor_mismatch/);
});

test('verify-chain: forged checkpoint is rejected under --expect-pruned; the legit one is accepted', async () => {
  const dir = tmpDir();
  const db = dbPath(dir);
  const sink: string[] = [];
  const s = openStore({ path: db, hmacKey: KEY, secondarySink: (l) => sink.push(l) });
  for (let i = 1; i <= 8; i++) s.append({ id: 'e' + i, kind: 'decision', ts_ms: 1000 + i });
  const pr = s.checkpointAndPrune(1005, { force: true });
  assert.equal(pr.pruned, 4);
  s.close();
  const cpLine = sink.find((l) => l.includes('"prysm":"checkpoint"')) as string;
  const legit = wr(dir, 'cp.jsonl', cpLine + '\n');
  // pruned history is never silently OK
  const bare = await runCli(['verify-chain', '--db', db]);
  assert.equal(bare.code, 1);
  assert.match(bare.stdout, /code=history_pruned/);
  // expected checkpoint accepted; informational note, exit 0
  const ok = await runCli(['verify-chain', '--db', db, '--expect-pruned', legit]);
  assert.equal(ok.code, 0, ok.stdout);
  assert.match(ok.stdout, /notes:\n(.*\n)*? {2}seq=\d+ code=history_pruned/);
  const okLog = await runCli(['verify-chain', '--db', db, '--expect-pruned-log', wr(dir, 'mixed.log', ['[server] ' + cpLine, 'x', cpLine].join('\n'))]);
  assert.equal(okLog.code, 0);
  // --allow-pruned is development only and says so on stderr (plain mode)
  const ap = await runCli(['verify-chain', '--db', db, '--allow-pruned']);
  assert.equal(ap.code, 0);
  assert.match(ap.stderr, /development only/);
  const apj = await runCli(['verify-chain', '--db', db, '--allow-pruned', '--json']);
  assert.equal(apj.stderr, '');
  // a wrong expected hash => checkpoint_missing + history_pruned, exit 1
  const wrong = wr(dir, 'wrong.json', JSON.stringify([{ through_seq: pr.through_seq, last_hash: 'ab'.repeat(32) }]));
  const w = await runCli(['verify-chain', '--db', db, '--expect-pruned', wrong]);
  assert.equal(w.code, 1);
  assert.match(w.stdout, /checkpoint_missing/);
  // forged second checkpoint
  forgeCheckpoint(db, 12, 'cd'.repeat(32));
  const forged = await runCli(['verify-chain', '--db', db, '--expect-pruned', legit]);
  assert.equal(forged.code, 1);
  assert.match(forged.stdout, /error seq=\d+ code=history_pruned/);
});

test('verify-chain: malformed / unreadable anchor or expected files => exit 2, nothing verified', async () => {
  const { dir, db } = fresh(3);
  const g = '0'.repeat(64);
  const bads: [string, string][] = [
    ['--anchor', 'not json'], ['--anchor', ''], ['--anchor', '[]'], ['--anchor', '{}'],
    ['--anchor', JSON.stringify({ genesis_hash: g, head_seq: -1, head_hash: g })],
    ['--anchor', JSON.stringify({ genesis_hash: 'zz', head_seq: 1, head_hash: g })],
    ['--anchor', JSON.stringify({ genesis_hash: g, head_seq: 1.5, head_hash: g })],
    ['--anchor', JSON.stringify({ genesis_hash: g, head_seq: 0, head_hash: 'a'.repeat(64) })],
    ['--anchor', JSON.stringify({ prysm: 'checkpoint', genesis_hash: g, head_seq: 0, head_hash: g })],
    ['--anchor', '{"genesis_hash":"' + g + '","head_seq":0,"head_hash":"' + g + '"}\n{"x":1}'],
    ['--anchor', '{"a":1,"a":2}'],
    ['--anchor-log', 'only noise\n[server] {}'],
    ['--expect-pruned', ''], ['--expect-pruned', '{"through_seq":1}'], ['--expect-pruned', '[{"through_seq":"1","last_hash":"' + g + '"}]'],
    ['--expect-pruned', '[1,2]'], ['--expect-pruned', '{"prysm":"anchor","through_seq":1,"last_hash":"' + g + '"}'],
    ['--expect-pruned', 'garbage'],
  ];
  for (const [flag, text] of bads) {
    const r = await runCli(['verify-chain', '--db', db, flag, wr(dir, 'in.txt', text)]);
    assert.equal(r.code, 2, flag + ' ' + text.slice(0, 40));
    assert.ok(!r.stdout.includes('OK'));
  }
  assert.equal((await runCli(['verify-chain', '--db', db, '--anchor', join(dir, 'missing.json')])).code, 2);
  const big = wr(dir, 'big.json', ' '.repeat(1024 * 1024 + 1) + '{}');
  assert.equal((await runCli(['verify-chain', '--db', db, '--anchor', big])).code, 2);
  // a well-formed but wrong anchor is a verification failure (1), not a usage error
  const wrong = wr(dir, 'wrong.json', JSON.stringify({ genesis_hash: g, head_seq: 2, head_hash: 'b'.repeat(64) }));
  assert.equal((await runCli(['verify-chain', '--db', db, '--anchor', wrong])).code, 1);
});

test('anchor: output equals store.anchor() (genesis, head_seq, head_hash); --out safety', async () => {
  const f = await guardFixture();
  const ro = openStore({ path: f.db, hmacKey: KEY, readOnly: true });
  const exp = ro.anchor();
  ro.close();
  const r = await runCli(['anchor', '--db', f.db]);
  assert.equal(r.code, 0);
  const o = JSON.parse(r.stdout);
  assert.equal(o.genesis_hash, exp.genesis_hash);
  assert.equal(o.head_seq, exp.head_seq);
  assert.equal(o.head_hash, exp.head_hash);
  assert.equal(typeof o.ts_ms, 'number');
  const dir = tmpDir();
  const out = join(dir, 'anchor.json');
  assert.equal((await runCli(['anchor', '--db', f.db, '--out', out])).code, 0);
  assert.equal(JSON.parse(readFileSync(out, 'utf8')).head_hash, exp.head_hash);
  assert.equal((await runCli(['verify-chain', '--db', f.db, '--anchor', out])).code, 0);
  // existing file: refused without --force, content untouched; overwritten with --force
  writeFileSync(out, 'precious');
  const refuse = await runCli(['anchor', '--db', f.db, '--out', out]);
  assert.equal(refuse.code, 2);
  assert.equal(readFileSync(out, 'utf8'), 'precious');
  assert.equal((await runCli(['anchor', '--db', f.db, '--out', out, '--force'])).code, 0);
  assert.equal(JSON.parse(readFileSync(out, 'utf8')).head_seq, exp.head_seq);
  // empty store anchor
  const e = dbPath(tmpDir());
  openStore({ path: e, hmacKey: KEY }).close();
  const ea = JSON.parse((await runCli(['anchor', '--db', e])).stdout);
  assert.equal(ea.head_seq, 0);
  assert.equal(ea.head_hash, ea.genesis_hash);
});

test('--out path safety (anchor): protected inputs, links, devices, streams, non-files; --force never overrides', async () => {
  const f = await guardFixture();
  const dir = tmpDir();
  const keyFile = join(dir, 'k.key');
  writeFileSync(keyFile, Buffer.alloc(32, 1));
  const targets = [f.db, f.db + '-wal', f.db + '-shm', 'NUL', 'CON', 'com1', 'aux.txt', join(dir, 'a.json:stream'), dir];
  for (const t of targets) {
    const r = await runCli(['anchor', '--db', f.db, '--out', t, '--force']);
    assert.equal(r.code, 2, t);
  }
  // the key file given via --key-path is protected; verify-chain inputs for report are protected too (see report tests)
  assert.equal((await runCli(['anchor', '--db', f.db, '--key-path', keyFile, '--out', keyFile, '--force'])).code, 2);
  assert.deepEqual(readFileSync(keyFile), Buffer.alloc(32, 1));
  // symlink target (skipped silently where symlinks need privileges)
  const real = join(dir, 'real.json');
  writeFileSync(real, 'x');
  const link = join(dir, 'link.json');
  let linked = true;
  try { symlinkSync(real, link); } catch { linked = false; }
  if (linked) {
    assert.equal((await runCli(['anchor', '--db', f.db, '--out', link, '--force'])).code, 2);
    assert.equal(readFileSync(real, 'utf8'), 'x');
  }
  // the DB is intact
  assert.equal((await runCli(['verify-chain', '--db', f.db])).code, 0);
});
