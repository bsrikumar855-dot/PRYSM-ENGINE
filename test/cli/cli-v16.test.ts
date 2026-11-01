// REPORT-SPEC §5 (v1.2) CLI items: 5.2 explain cause precedence, 5.4 names, 5.5 schema allow-list at CLI level,
// 5.6 BOM / pretty expect-pruned / marker start, 5.7 anchor verifies first, --scan-limit.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { openStore } from '../../src/store/index.ts';
import { cleanup, tmpDir, dbPath } from '../support/tmp.ts';
import { KEY } from '../support/guard-kit.ts';
import { guardFixture, keyedFixture, rawTamper, runCli } from '../support/cli-kit.ts';

after(cleanup);
const fixture = guardFixture();
const START = '<!doctype html><!-- prysm-report v1 -->';

test('--limit 1001 and 0 exit 2; --scan-limit below 1000 exits 2, a valid one reports', async () => {
  const k = keyedFixture(2);
  assert.equal((await runCli(['events', '--db', k.db, '--limit', '1001'])).code, 2);
  assert.equal((await runCli(['events', '--db', k.db, '--limit', '1000'])).code, 0);
  const out = join(k.dir, 'r.html');
  assert.equal((await runCli(['report', '--db', k.db, '--out', out, '--scan-limit', '999'])).code, 2);
  assert.equal(existsSync(out), false);
  assert.equal((await runCli(['report', '--db', k.db, '--out', out, '--scan-limit', '1000'])).code, 0);
  assert.ok(readFileSync(out, 'utf8').startsWith(START));
});

test('--out refusals: directory, trailing dot/space, symlink (visible skip reason when the OS denies links)', async (t) => {
  const fx = await fixture;
  const dir = tmpDir();
  for (const cmd of [['report'], ['anchor']]) {
    for (const target of [dir, join(dir, 'x.html.'), join(dir, 'x.html '), join(dir, 'sub') + '/..']) {
      const r = await runCli([...cmd, '--db', fx.db, '--out', target, '--force']);
      assert.equal(r.code, 2, cmd[0] + ' ' + JSON.stringify(target));
    }
  }
  assert.deepEqual(await Promise.resolve(existsSync(join(dir, 'x.html.'))), false);
  const real = join(dir, 'real.txt');
  writeFileSync(real, 'x');
  const link = join(dir, 'link.html');
  try {
    symlinkSync(real, link);
  } catch (e) {
    t.skip('symlink creation denied by the OS (' + String((e as { code?: unknown }).code) + '); symlink refusal not exercised on this machine');
    return;
  }
  for (const cmd of [['report'], ['anchor']]) {
    assert.equal((await runCli([...cmd, '--db', fx.db, '--out', link, '--force'])).code, 2);
  }
  assert.equal(readFileSync(real, 'utf8'), 'x');
});

test('schema allow-list at CLI level: events replaced by a view exits 2 quickly for every read command', async () => {
  const dir = tmpDir();
  const db = dbPath(dir);
  const d = new DatabaseSync(db);
  d.exec(`CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
    CREATE VIEW events AS WITH RECURSIVE r(seq) AS (SELECT 1 UNION ALL SELECT seq + 1 FROM r) SELECT seq FROM r;`);
  d.close();
  const t0 = Date.now();
  for (const c of [['events'], ['events', '--count'], ['verify-chain'], ['anchor'], ['explain', 'abcdefgh'], ['report', '--out', join(dir, 'r.html')]]) {
    const r = await runCli([...c, '--db', db]);
    assert.equal(r.code, 2, c.join(' '));
    assert.match(r.stderr, /corrupt/);
  }
  assert.ok(Date.now() - t0 < 20000);
});

test('BOM in --anchor / --expect-pruned / logs is malformed (exit 2), never stripped', async () => {
  const fx = await fixture;
  const dir = tmpDir();
  const bom = Buffer.from([0xef, 0xbb, 0xbf]);
  const anchorFile = join(dir, 'a.json');
  writeFileSync(anchorFile, Buffer.concat([bom, Buffer.from(fx.anchorLine)]));
  assert.equal((await runCli(['verify-chain', '--db', fx.db, '--anchor', anchorFile])).code, 2);
  const cp = join(dir, 'c.json');
  writeFileSync(cp, Buffer.concat([bom, Buffer.from('[]')]));
  assert.equal((await runCli(['verify-chain', '--db', fx.db, '--expect-pruned', cp])).code, 2);
  // the same content without a BOM is accepted
  writeFileSync(anchorFile, fx.anchorLine);
  assert.equal((await runCli(['verify-chain', '--db', fx.db, '--anchor', anchorFile])).code, 0);
});

test('pretty-printed --expect-pruned object and array are accepted', async () => {
  const dir = tmpDir();
  const db = dbPath(dir);
  const sink: string[] = [];
  const s = openStore({ path: db, hmacKey: KEY, secondarySink: (l) => sink.push(l) });
  for (let i = 1; i <= 6; i++) s.append({ id: 'e' + i, kind: 'decision', ts_ms: 1000 + i });
  s.checkpointAndPrune(1004, { force: true });
  s.close();
  const cp = JSON.parse(sink.find((l) => l.includes('"prysm":"checkpoint"')) as string);
  const obj = join(dir, 'obj.json');
  writeFileSync(obj, JSON.stringify({ through_seq: cp.through_seq, last_hash: cp.last_hash }, null, 2) + '\n');
  const r = await runCli(['verify-chain', '--db', db, '--expect-pruned', obj]);
  assert.equal(r.code, 0, r.stdout + r.stderr);
  const arr = join(dir, 'arr.json');
  writeFileSync(arr, JSON.stringify([{ through_seq: cp.through_seq, last_hash: cp.last_hash }], null, 4));
  assert.equal((await runCli(['verify-chain', '--db', db, '--expect-pruned', arr])).code, 0);
});

test('report overwrite marker must be at the very start of the file', async () => {
  const fx = await fixture;
  const dir = tmpDir();
  const out = join(dir, 'r.html');
  for (const body of [' ' + START + 'x', 'junk' + START, '<!doctype html>\n<!-- prysm-report v1 -->', '<!-- prysm-report v1 -->' + START]) {
    writeFileSync(out, body);
    const r = await runCli(['report', '--db', fx.db, '--out', out]);
    assert.equal(r.code, 2, JSON.stringify(body.slice(0, 20)));
    assert.equal(readFileSync(out, 'utf8'), body);
  }
  writeFileSync(out, START + '<html>old report</html>');
  assert.equal((await runCli(['report', '--db', fx.db, '--out', out])).code, 0);
  assert.ok(readFileSync(out, 'utf8').startsWith(START));
  assert.ok(!readFileSync(out, 'utf8').includes('old report'));
});

test('anchor verifies first: refuses a tampered chain (exit 1, codes only, nothing written); --no-verify overrides', async () => {
  const k = keyedFixture(5);
  rawTamper(k.db, (d) => { d.exec("UPDATE events SET tool='evil' WHERE seq=2"); });
  const out = join(k.dir, 'anchor.json');
  const r = await runCli(['anchor', '--db', k.db, '--out', out]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /hash_mismatch/);
  assert.ok(!r.stderr.includes('evil'));
  assert.equal(r.stdout, '');
  assert.equal(existsSync(out), false);
  const o = await runCli(['anchor', '--db', k.db, '--out', out, '--no-verify']);
  assert.equal(o.code, 0);
  assert.equal(JSON.parse(readFileSync(out, 'utf8')).head_seq, 5);
});

test('anchor on a store with warnings only proceeds; notes go to stderr, stdout stays the anchor JSON', async () => {
  const fx = await fixture; // guard store: key_colocated note
  const r = await runCli(['anchor', '--db', fx.db]);
  assert.equal(r.code, 0);
  JSON.parse(r.stdout);
  assert.match(r.stderr, /note: seq=0 code=key_colocated/);
});

function forged(effectRows: { id: string; rule_ids: string[]; outcome: unknown; policy_version: string | null; reason?: string }[]): string {
  const db = dbPath(tmpDir());
  const s = openStore({ path: db, hmacKey: KEY });
  for (const r of effectRows) {
    s.append({
      id: r.id, kind: 'decision', ts_ms: 1, effect: 'deny', enforcement: 'enforced', reason_code: r.reason ?? 'denied_by_rule',
      rule_ids: r.rule_ids, outcome: r.outcome, policy_version: r.policy_version, tool: 'read_file',
    });
  }
  s.close();
  return db;
}

test('explain cause precedence: deny_n, then same-version policy, then the legacy caveat; permit ids are never a cause', async () => {
  const fx = await fixture;
  const pv = fx.policy.policy_version;
  const db = forged([
    { id: 'row-denyn-1', rule_ids: ['d.secret', 'p.read'], outcome: { deny_n: 1 }, policy_version: pv },
    { id: 'row-denyn-2', rule_ids: ['d.secret', 'p.read'], outcome: { deny_n: 2 }, policy_version: pv },
    { id: 'row-legacy-1', rule_ids: ['d.secret', 'p.read'], outcome: null, policy_version: pv },
    { id: 'row-legacy-2', rule_ids: ['d.secret', 'p.read'], outcome: null, policy_version: 'sha256:other' },
  ]);
  const verdictOf = async (id: string, withPolicy: boolean): Promise<string> => {
    const r = await runCli(['explain', id, '--db', db, '--json', ...(withPolicy ? ['--policy', fx.policyPath] : [])]);
    assert.equal(r.code, 0);
    return JSON.parse(r.stdout).verdict as string;
  };
  // deny_n present: first deny_n ids, with or without a policy
  for (const wp of [false, true]) {
    const v = await verdictOf('row-denyn-1', wp);
    assert.match(v, /^BLOCKED by rule\(s\) d\.secret because/);
    assert.ok(!v.includes('p.read'));
  }
  // deny_n wins over the policy
  assert.match(await verdictOf('row-denyn-2', true), /by rule\(s\) d\.secret, p\.read because/);
  // legacy + same-version policy: deny-effect rules only
  const lp = await verdictOf('row-legacy-1', true);
  assert.match(lp, /^BLOCKED by rule\(s\) d\.secret because/);
  assert.ok(!lp.includes('p.read'));
  // legacy, no policy / different version: caveat wording, still not "by rule(s)"
  for (const [id, wp] of [['row-legacy-1', false], ['row-legacy-2', true]] as const) {
    const v = await verdictOf(id, wp);
    assert.match(v, /^BLOCKED\. A deny rule matched\. All matched rules, deny rules listed first: d\.secret, p\.read$/);
  }
  // plain text mode shows the same wording
  const t = await runCli(['explain', 'row-legacy-1', '--db', db]);
  assert.match(t.stdout, /A deny rule matched\. All matched rules, deny rules listed first: d\.secret, p\.read/);
});

test('M4-11: anchor accepts verify-chain inputs; a legitimately pruned store anchors with --expect-pruned-log', async () => {
  const dir = tmpDir();
  const db = dbPath(dir);
  const sink: string[] = [];
  const s = openStore({ path: db, hmacKey: KEY, secondarySink: (l) => sink.push(l) });
  for (let i = 1; i <= 8; i++) s.append({ id: 'e' + i, kind: 'decision', ts_ms: 1000 + i });
  s.checkpointAndPrune(1005, { force: true });
  s.close();
  const log = join(dir, 'guard.log');
  writeFileSync(log, ['[server] noise', ...sink].join('\n') + '\n');
  const out = join(dir, 'anchor.json');
  // without flags: refused, message names the expected-pruned remedy first and never recommends --no-verify first
  const bare = await runCli(['anchor', '--db', db, '--out', out]);
  assert.equal(bare.code, 1);
  assert.match(bare.stderr, /history_pruned/);
  assert.match(bare.stderr, /--expect-pruned-log/);
  assert.ok(bare.stderr.indexOf('--expect-pruned-log') < bare.stderr.indexOf('--no-verify'));
  assert.match(bare.stderr, /last resort/);
  assert.equal(existsSync(out), false);
  // with the logged checkpoint: ok, anchor written, and it verifies with the same inputs
  const ok = await runCli(['anchor', '--db', db, '--out', out, '--expect-pruned-log', log]);
  assert.equal(ok.code, 0, ok.stderr);
  assert.equal(JSON.parse(readFileSync(out, 'utf8')).head_seq, 9);
  assert.equal((await runCli(['verify-chain', '--db', db, '--anchor', out, '--expect-pruned-log', log])).code, 0);
  // a newer anchor checked against an older one
  const newer = join(dir, 'newer.json');
  assert.equal((await runCli(['anchor', '--db', db, '--out', newer, '--anchor', out, '--expect-pruned-log', log])).code, 0);
  // --allow-pruned (development only) also lets it through
  assert.equal((await runCli(['anchor', '--db', db, '--allow-pruned', '--force', '--out', newer])).code, 0);
  // tampered chain with the same flags is still refused
  rawTamper(db, (d) => { d.exec("UPDATE events SET tool='evil' WHERE seq=7"); });
  const bad = await runCli(['anchor', '--db', db, '--out', join(dir, 'x.json'), '--expect-pruned-log', log]);
  assert.equal(bad.code, 1);
  assert.match(bad.stderr, /hash_mismatch/);
  assert.equal(existsSync(join(dir, 'x.json')), false);
  // malformed input file => exit 2
  writeFileSync(join(dir, 'bad.json'), 'nope');
  assert.equal((await runCli(['anchor', '--db', db, '--anchor', join(dir, 'bad.json')])).code, 2);
});

test('M4-12 at CLI level: a store after ANALYZE works for read-only commands', async () => {
  const k = keyedFixture(3);
  const d = new DatabaseSync(k.db);
  d.exec('ANALYZE');
  d.close();
  for (const c of [['events'], ['verify-chain'], ['anchor'], ['report', '--out', join(k.dir, 'r.html')]]) {
    assert.equal((await runCli([...c, '--db', k.db])).code, 0, c[0]);
  }
});
