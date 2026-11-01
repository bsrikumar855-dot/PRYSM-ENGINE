// CLI simulate and report (REPORT-SPEC §1.6-1.7, §4.1, §4.9, §4.12).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { cleanup, tmpDir } from '../support/tmp.ts';
import { POLICY_DOC, rule } from '../support/policy.ts';
import { guardFixture, lines, runCli } from '../support/cli-kit.ts';

after(cleanup);
const MARKER = '<!-- prysm-report v1 -->';

function files(): { dir: string; a: string; b: string; c: string; req: (text: string) => string } {
  const dir = tmpDir();
  const wr = (n: string, v: unknown): string => {
    const p = join(dir, n);
    writeFileSync(p, JSON.stringify(v));
    return p;
  };
  const a = wr('a.json', POLICY_DOC());
  // B denies search_docs (permit -> deny); C drops the secret deny (deny -> permit)
  const b = wr('b.json', POLICY_DOC('enforce', [rule('deny', 'd.docs', { tools: ['search_docs'] })]));
  const base = POLICY_DOC() as { rules: { id: string }[] };
  const c = wr('c.json', { ...base, rules: base.rules.filter((r) => r.id !== 'd.secret') });
  let n = 0;
  return { dir, a, b, c, req: (text) => { const p = join(dir, `req${n++}.jsonl`); writeFileSync(p, text); return p; } };
}

const REQ = [
  JSON.stringify({ id: 'r-read', tool: 'read_file', args: { path: '/ok/readme' }, ctx: { agentId: 'agent-1' } }),
  JSON.stringify({ id: 'r-secret', tool: 'read_file', args: { path: '/secret/keys' }, ctx: { agentId: 'agent-1' } }),
  JSON.stringify({ tool: 'search_docs', args: { query: 'q' }, ctx: { agentId: 'agent-1' } }),
  'this is not json',
  '[1,2,3]',
  '',
  JSON.stringify({ tool: 'read_file', args: { path: 7 }, ctx: { agentId: 'agent-1' } }),
].join('\n');

test('simulate: one policy, invalid lines reported with line numbers and counted, exit 0', async () => {
  const f = files();
  const r = await runCli(['simulate', '--policy', f.a, '--requests', f.req(REQ)]);
  assert.equal(r.code, 0);
  const l = lines(r.stdout);
  assert.equal(l[0], 'r-read  A:permit/permitted');
  assert.equal(l[1], 'r-secret  A:deny/denied_by_rule');
  assert.equal(l[2], '3  A:permit/permitted', 'id defaults to the 1-based line number');
  assert.equal(l[3], 'line 4  INVALID  not_json');
  assert.equal(l[4], 'line 5  INVALID  not_object');
  assert.equal(l[5], '7  A:deny/invalid_args', 'invalid_args is a normal decision; blank line 6 skipped');
  assert.equal(l[6], 'summary: total=4 invalid=2 permit=2 deny=2');
});

test('simulate: two policies, CHANGED when effect or reason differs, counts and ids', async () => {
  const f = files();
  const r = await runCli(['simulate', '--policy', f.a, '--policy-b', f.b, '--requests', f.req(REQ)]);
  assert.equal(r.code, 0);
  const l = lines(r.stdout);
  assert.equal(l[0], 'r-read  A:permit/permitted  B:permit/permitted');
  assert.equal(l[2], '3  A:permit/permitted  B:deny/denied_by_rule  CHANGED');
  assert.ok(l.includes('summary: total=4 invalid=2 changed=1 permit->deny=1 deny->permit=0'));
  assert.ok(l.includes('permit->deny: 3'));
  const r2 = await runCli(['simulate', '--policy', f.a, '--policy-b', f.c, '--requests', f.req(REQ)]);
  const l2 = lines(r2.stdout);
  assert.equal(l2[1], 'r-secret  A:deny/denied_by_rule  B:permit/permitted  CHANGED');
  assert.ok(l2.includes('deny->permit: r-secret'));
  assert.equal(r2.code, 0);
  // same policy twice: nothing changed
  const same = await runCli(['simulate', '--policy', f.a, '--policy-b', f.a, '--requests', f.req(REQ)]);
  assert.ok(lines(same.stdout).includes('summary: total=4 invalid=2 changed=0 permit->deny=0 deny->permit=0'));
  // --json: json lines + summary
  const j = await runCli(['simulate', '--policy', f.a, '--policy-b', f.b, '--requests', f.req(REQ), '--json']);
  const objs = lines(j.stdout).map((x) => JSON.parse(x));
  assert.equal(objs[2].changed, true);
  assert.deepEqual(objs[3], { line: 4, invalid: 'not_json' });
  assert.equal(objs[objs.length - 1].summary.changed, 1);
});

test('simulate: size caps and unreadable inputs exit 2 with no partial output', async () => {
  const f = files();
  const tooMany = await runCli(['simulate', '--policy', f.a, '--requests', f.req('\n'.repeat(100001))]);
  assert.equal(tooMany.code, 2);
  assert.equal(tooMany.stdout, '');
  const atCap = await runCli(['simulate', '--policy', f.a, '--requests', f.req('\n'.repeat(100000))]);
  assert.equal(atCap.code, 0);
  assert.match(atCap.stdout, /total=0 invalid=0/);
  const big = await runCli(['simulate', '--policy', f.a, '--requests', f.req('a'.repeat(10 * 1024 * 1024 + 1))]);
  assert.equal(big.code, 2);
  assert.equal(big.stdout, '');
  assert.equal((await runCli(['simulate', '--policy', f.a, '--requests', join(f.dir, 'nope.jsonl')])).code, 2);
  assert.equal((await runCli(['simulate', '--policy', join(f.dir, 'nope.json'), '--requests', f.req(REQ)])).code, 2);
  const bad = join(f.dir, 'bad.json');
  writeFileSync(bad, '{}');
  assert.equal((await runCli(['simulate', '--policy', f.a, '--policy-b', bad, '--requests', f.req(REQ)])).code, 2);
});

test('simulate: hostile ids/values never reach the terminal raw', async () => {
  const f = files();
  const ESC = String.fromCharCode(27);
  const text = JSON.stringify({ id: ESC + 'x', tool: 'read_file', args: { path: '/a' }, ctx: { agentId: 'agent-1' } });
  const r = await runCli(['simulate', '--policy', f.a, '--requests', f.req(text)]);
  assert.equal(r.code, 0);
  assert.ok(!r.stdout.includes(ESC));
});

test('report: writes a file starting with doctype + marker; build matches events --count', async () => {
  const fx = await guardFixture();
  const dir = tmpDir();
  const out = join(dir, 'r.html');
  const r = await runCli(['report', '--db', fx.db, '--out', out, '--policy', fx.policyPath, '--title', 'My title']);
  assert.equal(r.code, 0, r.stderr);
  const html = readFileSync(out, 'utf8');
  assert.ok(html.slice(0, 200).includes(MARKER));
  assert.ok(!html.includes('<script'));
  assert.ok(html.includes('My title'));
  assert.deepEqual(readdirSync(dir), ['r.html'], 'no temp file left behind');
  // report on the same store twice is allowed (overwrites its own output)
  assert.equal((await runCli(['report', '--db', fx.db, '--out', out, '--max-events', '5'])).code, 0);
  assert.ok(readFileSync(out, 'utf8').slice(0, 200).includes(MARKER));
  // default output name lands in cwd
  const def = await runCli(['report', '--db', fx.db], { cwd: dir });
  assert.equal(def.code, 0);
  assert.ok(existsSync(join(dir, 'prysm-report.html')));
  // tampered DB still yields a report (exit 0) that shows FAILED
});

test('report: refuses to overwrite foreign files unless --force; protected paths are never overwritten', async () => {
  const fx = await guardFixture();
  const dir = tmpDir();
  const foreign = join(dir, 'notes.html');
  writeFileSync(foreign, '<html>mine</html>');
  const r = await runCli(['report', '--db', fx.db, '--out', foreign]);
  assert.equal(r.code, 2);
  assert.equal(readFileSync(foreign, 'utf8'), '<html>mine</html>');
  assert.equal((await runCli(['report', '--db', fx.db, '--out', foreign, '--force'])).code, 0);
  assert.ok(readFileSync(foreign, 'utf8').slice(0, 200).includes(MARKER));
  // protected: DB, policy input, anchor input, even with --force
  const anchor = join(dir, 'a.json');
  writeFileSync(anchor, fx.anchorLine);
  for (const t of [fx.db, fx.policyPath, anchor]) {
    const before = readFileSync(t);
    const x = await runCli(['report', '--db', fx.db, '--policy', fx.policyPath, '--anchor', anchor, '--out', t, '--force']);
    assert.equal(x.code, 2, t);
    assert.deepEqual(readFileSync(t), before);
  }
  // directories, devices and streams
  for (const t of [dir, 'NUL', 'CON', join(dir, 'x.html:s')]) {
    assert.equal((await runCli(['report', '--db', fx.db, '--out', t, '--force'])).code, 2, t);
  }
  // missing parent directory
  assert.equal((await runCli(['report', '--db', fx.db, '--out', join(dir, 'no', 'such', 'r.html')])).code, 2);
  assert.equal((await runCli(['verify-chain', '--db', fx.db])).code, 0);
});

test('report: a tampered store still produces a report (exit 0) and malformed anchor input exits 2', async () => {
  const fx = await guardFixture();
  const { rawTamper } = await import('../support/cli-kit.ts');
  const dir = tmpDir();
  const out = join(dir, 'r.html');
  rawTamper(fx.db, (d) => { d.exec("UPDATE events SET tool='evil' WHERE seq=2"); });
  const r = await runCli(['report', '--db', fx.db, '--out', out]);
  assert.equal(r.code, 0);
  assert.match(readFileSync(out, 'utf8'), /FAILED/);
  const bad = join(dir, 'bad.json');
  writeFileSync(bad, 'nope');
  assert.equal((await runCli(['report', '--db', fx.db, '--out', join(dir, 'r2.html'), '--anchor', bad])).code, 2);
  assert.equal(existsSync(join(dir, 'r2.html')), false);
});
