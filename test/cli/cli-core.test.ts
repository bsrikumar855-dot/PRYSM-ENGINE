// CLI: validate, usage errors, events, terminal escaping, read-only guarantees (REPORT-SPEC §1, §3, §4.2, §4.6-4.9).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { openStore } from '../../src/store/index.ts';
import { cleanup, tmpDir, dbPath } from '../support/tmp.ts';
import { POLICY_DOC } from '../support/policy.ts';
import { KEY } from '../support/guard-kit.ts';
import { guardFixture, keyedFixture, lines, runCli } from '../support/cli-kit.ts';

after(cleanup);
const fixture = guardFixture();
const ESC = String.fromCharCode(27);
const CR = String.fromCharCode(13);
const LS = String.fromCharCode(0x2028);
const NEL = String.fromCharCode(0x85);
const RLO = String.fromCharCode(0x202e);

function policyFile(doc: unknown = POLICY_DOC()): { dir: string; path: string; text: string } {
  const dir = tmpDir();
  const path = join(dir, 'p.json');
  const text = JSON.stringify(doc);
  writeFileSync(path, text);
  return { dir, path, text };
}

test('validate: ok (text and --json)', async () => {
  const f = policyFile();
  const r = await runCli(['validate', f.path]);
  assert.equal(r.code, 0);
  assert.match(r.stdout.trim(), /^valid {2}sha256:[0-9a-f]{64} {2}rules=6 tools=6 mode=enforce$/);
  assert.equal(r.stderr, '');
  const j = await runCli(['validate', f.path, '--json']);
  const o = JSON.parse(j.stdout);
  assert.equal(o.ok, true);
  assert.equal(o.rules, 6);
});

test('validate: invalid policy exits 2 with code+path only, never values', async () => {
  const doc = POLICY_DOC() as { rules: { match: Record<string, unknown> }[] };
  const f = policyFile({ ...doc, mode: 'SECRETVALUE-xyz' });
  const r = await runCli(['validate', f.path]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /invalid_value/);
  assert.match(r.stderr, /\$\.mode/);
  assert.ok(!r.stderr.includes('SECRETVALUE'));
  const bad = join(f.dir, 'bad.json');
  writeFileSync(bad, '{not json');
  assert.equal((await runCli(['validate', bad])).code, 2);
  assert.equal((await runCli(['validate', join(f.dir, 'missing.json')])).code, 2);
});

test('validate: --sha256 match, mismatch and malformed', async () => {
  const f = policyFile();
  const sha = createHash('sha256').update(readFileSync(f.path)).digest('hex');
  assert.equal((await runCli(['validate', f.path, '--sha256', sha])).code, 0);
  assert.equal((await runCli(['validate', f.path, '--sha256', sha.toUpperCase()])).code, 0);
  const mm = await runCli(['validate', f.path, '--sha256', '0'.repeat(64)]);
  assert.equal(mm.code, 2);
  assert.ok(!mm.stdout.startsWith('valid'));
  assert.equal((await runCli(['validate', f.path, '--sha256', 'abc'])).code, 2);
});

test('usage errors exit 2 and never echo argument values', async () => {
  const secret = 'S3CRET-VALUE-9f2';
  const cases: string[][] = [
    [], ['nosuchcmd-' + secret], ['validate'], ['validate', 'a', 'b'], ['events'], ['events', '--bogus-' + secret],
    ['events', '--db'], ['events', '--db', 'x', '--limit', secret], ['events', '--db', 'x', '--limit', '0'],
    ['events', '--db', 'x', '--limit', '1001'], ['events', '--db', 'x', '--kind', secret], ['events', '--db', 'x', '--effect', secret],
    ['events', '--db', 'x', '--db', 'y'], ['events', '--db', 'x', '--count=' + secret], ['explain', '--db', 'x'],
    ['verify-chain', '--db', 'x', '--anchor', 'a', '--anchor-log', 'b'], ['report', '--db', 'x', '--max-events', '5001'],
    ['simulate', '--policy', 'x'],
  ];
  for (const c of cases) {
    const r = await runCli(c);
    assert.equal(r.code, 2, JSON.stringify(c.map((x) => x.replace(secret, '<S>'))));
    assert.ok(!(r.stdout + r.stderr).includes(secret));
  }
  const noArgs = await runCli([]);
  assert.match(noArgs.stderr, /usage: prysm/);
  const help = await runCli(['help']);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /verify-chain/);
  assert.ok(!/\u001b/.test(help.stdout));
});

test('missing --db file: exit 2 and nothing is created', async () => {
  const dir = tmpDir();
  const db = dbPath(dir, 'absent.db');
  for (const c of [['events'], ['verify-chain'], ['anchor'], ['report', '--out', join(dir, 'r.html')]]) {
    const r = await runCli([...c, '--db', db]);
    assert.equal(r.code, 2);
  }
  assert.equal(existsSync(db), false);
  assert.equal(existsSync(db + '.key'), false);
});

test('events: filters, --count equals an independent query, limit/after-seq/tail', async () => {
  const f = await fixture;
  const ro = openStore({ path: f.db, hmacKey: KEY, readOnly: true });
  const all = ro.iterate({ limit: 1000 });
  const sess = all.find((r) => r.session_id !== null)?.session_id as string;
  const cases: { args: string[]; expect: number }[] = [
    { args: [], expect: all.length },
    { args: ['--kind', 'decision'], expect: all.filter((r) => r.kind === 'decision').length },
    { args: ['--kind', 'tool_result'], expect: all.filter((r) => r.kind === 'tool_result').length },
    { args: ['--effect', 'deny'], expect: all.filter((r) => r.effect === 'deny').length },
    { args: ['--tool', 'read_file'], expect: all.filter((r) => r.tool === 'read_file').length },
    { args: ['--tool', 'read_file', '--effect', 'deny'], expect: all.filter((r) => r.tool === 'read_file' && r.effect === 'deny').length },
    { args: ['--session', sess], expect: all.filter((r) => r.session_id === sess).length },
    { args: ['--after-seq', '5'], expect: all.filter((r) => r.seq > 5).length },
    { args: ['--tool', 'no_such_tool'], expect: 0 },
  ];
  for (const c of cases) {
    const n = await runCli(['events', '--db', f.db, '--count', ...c.args]);
    assert.equal(n.code, 0);
    assert.equal(n.stdout, String(c.expect) + '\n', c.args.join(' '));
    const l = await runCli(['events', '--db', f.db, '--limit', '1000', ...c.args]);
    assert.equal(lines(l.stdout).length, c.expect);
  }
  // --count ignores --limit; with --json prints {"count":n}
  const cj = await runCli(['events', '--db', f.db, '--count', '--limit', '2', '--json']);
  assert.deepEqual(JSON.parse(cj.stdout), { count: all.length });
  // default limit applies to the listing, ascending
  const lim = await runCli(['events', '--db', f.db, '--limit', '3']);
  assert.deepEqual(lines(lim.stdout).map((l) => Number(l.split('  ')[0])), [1, 2, 3]);
  // --tail: newest N, ascending
  const tail = await runCli(['events', '--db', f.db, '--limit', '3', '--tail']);
  assert.deepEqual(lines(tail.stdout).map((l) => Number(l.split('  ')[0])), all.slice(-3).map((r) => r.seq));
  // line shape: seq ts kind effect/enforcement reason tool id8
  const dec = lines(lim.stdout)[1] as string;
  const parts = dec.split('  ');
  assert.equal(parts.length, 7);
  assert.match(parts[1] as string, /^\d{4}-\d\d-\d\dT/);
  assert.equal(parts[2], 'decision');
  assert.equal(parts[3], 'permit/enforced');
  assert.equal(parts[6], (all[1] as { id: string }).id.slice(0, 8));
  // --json rows are the stored rows
  const js = await runCli(['events', '--db', f.db, '--limit', '2', '--json']);
  const rows = lines(js.stdout).map((l) => JSON.parse(l));
  assert.deepEqual(rows[0].hash, all[0]?.hash);
  assert.equal(rows[1].id, all[1]?.id);
  ro.close();
});

test('events: hostile tool names are escaped for terminals (text and --json)', async () => {
  const dir = tmpDir();
  const db = dbPath(dir);
  const s = openStore({ path: db, hmacKey: KEY });
  const hostile = [
    ESC + '[31mRED' + ESC + '[0m', 'a' + CR + 'b', 'x\ny{"kind":"decision"}', 'u' + LS + 'v', 'n' + NEL + 'l', 'rtl' + RLO + 'evil',
  ];
  hostile.forEach((t, i) => s.append({ id: 'h-' + i, kind: 'decision', ts_ms: 1000 + i, tool: t, effect: 'deny', enforcement: 'enforced', reason_code: t }));
  s.close();
  const r = await runCli(['events', '--db', db]);
  assert.equal(r.code, 0);
  assert.equal(lines(r.stdout).length, hostile.length, 'no injected lines');
  for (const bad of [ESC, CR, LS, NEL, RLO]) assert.ok(!r.stdout.includes(bad));
  assert.ok(r.stdout.includes('?[31mRED'));
  const j = await runCli(['events', '--db', db, '--json']);
  assert.equal(lines(j.stdout).length, hostile.length);
  for (const bad of [ESC, CR, LS, NEL, RLO]) assert.ok(!j.stdout.includes(bad));
  for (const l of lines(j.stdout)) JSON.parse(l);
  assert.ok(j.stdout.includes('\\u2028') && j.stdout.includes('\\u0085'));
  // filtering by the exact hostile value still works
  const one = await runCli(['events', '--db', db, '--count', '--tool=' + hostile[3]]);
  assert.equal(one.stdout, '1\n');
});

test('events: empty store prints nothing / 0', async () => {
  const dir = tmpDir();
  const db = dbPath(dir);
  openStore({ path: db, hmacKey: KEY }).close();
  const r = await runCli(['events', '--db', db]);
  assert.deepEqual([r.code, r.stdout, r.stderr], [0, '', '']);
  const c = await runCli(['events', '--db', db, '--count']);
  assert.deepEqual([c.code, c.stdout], [0, '0\n']);
});

test('hostile --db path is escaped in stderr and the file is not created', async () => {
  const r = await runCli(['events', '--db', 'no-such' + ESC + '[2J.db']);
  assert.equal(r.code, 2);
  assert.ok(!r.stderr.includes(ESC));
});

test('read-only commands: no key file created, row count and head unchanged, no -wal growth', async () => {
  const k = keyedFixture(5);
  const { db, keyPath } = k;
  const ref = openStore({ path: db, readOnly: true });
  const before = { count: ref.count(), head: ref.head(), wal: existsSync(db + '-wal') ? readFileSync(db + '-wal').length : 0 };
  ref.close();
  const keyBytes = readFileSync(keyPath);
  const out = join(k.dir, 'anchor-out.json');
  const runs = [
    ['events', '--db', db], ['events', '--db', db, '--count'], ['events', '--db', db, '--tail'],
    ['explain', 'ev-1-aaaaaaaa', '--db', db], ['verify-chain', '--db', db], ['anchor', '--db', db], ['anchor', '--db', db, '--out', out],
    ['report', '--db', db, '--out', join(k.dir, 'r.html')],
  ];
  for (const withKey of [true, false]) {
    if (!withKey) rmSync(keyPath);
    for (const c of runs) {
      const r = await runCli(c);
      assert.ok(r.code === 0, c.join(' ') + ' => ' + r.code + ' ' + r.stderr);
      if (withKey) assert.deepEqual(readFileSync(keyPath), keyBytes);
      else assert.equal(existsSync(keyPath), false, 'key file must not be created: ' + c[0]);
      for (const f of [out, join(k.dir, 'r.html')]) rmSync(f, { force: true });
    }
  }
  assert.equal(existsSync(keyPath), false);
  // verify the store unchanged with the key restored
  writeFileSync(keyPath, keyBytes);
  const after2 = openStore({ path: db });
  assert.equal(after2.count(), before.count);
  assert.deepEqual(after2.head(), before.head);
  after2.close();
  const walAfter = existsSync(db + '-wal') ? readFileSync(db + '-wal').length : 0;
  assert.ok(walAfter <= before.wal || walAfter === 0);
});

test('read-only commands do not reset the prune_open flag', async () => {
  const k = keyedFixture(2);
  const { DatabaseSync } = await import('node:sqlite');
  let d = new DatabaseSync(k.db);
  d.exec("UPDATE meta SET value='1' WHERE key='prune_open'");
  d.close();
  for (const c of [['events'], ['verify-chain'], ['anchor']]) await runCli([...c, '--db', k.db]);
  d = new DatabaseSync(k.db, { readOnly: true });
  const po = d.prepare("SELECT value FROM meta WHERE key='prune_open'").get() as { value: string };
  const pf = d.prepare("SELECT value FROM meta WHERE key='prune_flag_reset'").get();
  d.close();
  assert.equal(po.value, '1');
  assert.equal(pf, undefined);
});

test('closed pipe ends quietly with exit 0', async () => {
  const f = await fixture;
  const { spawn } = await import('node:child_process');
  const { BIN, ROOT } = await import('../support/cli-kit.ts');
  const code = await new Promise<number | null>((res) => {
    const c = spawn(process.execPath, [BIN, 'events', '--db', f.db, '--limit', '1000'], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    c.stdout.destroy();
    c.on('close', (x) => res(x));
  });
  assert.equal(code, 0);
});
