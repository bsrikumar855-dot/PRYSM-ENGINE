// End-to-end through the real CLI process (stdio pipes): A-18, injection scenario, lifecycle, audit, flags.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { cleanup } from '../support/tmp.ts';
import { startCli, makeEnv, callCount, toolText, isErr, openAudit, rowsOf, serverCalls, serverMethods } from '../support/proxy-kit.ts';
import type { Env } from '../support/proxy-kit.ts';

after(cleanup);
const baseFlags = (env: Env): string[] => ['--policy', env.policyPath, '--db', env.dbPath, '--key-path', env.keyPath];

test('CLI A-18: forbidden calls leave the server counter at 0; allowed call runs once', async () => {
  const cli = startCli();
  const env = cli.env;
  await cli.client.handshake();
  assert.equal(toolText(await cli.client.call('echo', { text: 'hi' })), 'echo:hi');
  for (const [tool, args] of [['echo', { text: 'deny-x' }], ['secret_tool', { x: 'a' }], ['nope', {}], ['echo', { text: 'a', extra: 1 }]] as const) {
    const r = await cli.client.call(tool, args);
    assert.ok(isErr(r));
    assert.match(toolText(r), /^Blocked by PRYSM policy: (denied|unknown_tool|invalid_request) \(decision [0-9a-f-]{36}\)$/);
  }
  assert.equal(callCount(env), 1);
  assert.equal(callCount(env, 'echo'), 1);
  cli.client.end();
  assert.equal(await cli.exited, 0);
});

test('CLI prompt injection: taint tool result, then attacker send is denied; before taint it is permitted', async () => {
  const env = makeEnv();
  const cli = startCli({ env, flags: [...baseFlags(env), '--taint-tools', 'search_docs'] });
  await cli.client.handshake();
  assert.equal(isErr(await cli.client.call('send_email', { to: 'ok@example.com' })), false);
  const doc = await cli.client.call('search_docs', { query: 'q' });
  assert.match(toolText(doc), /IGNORE ALL PREVIOUS INSTRUCTIONS/);
  assert.ok(isErr(await cli.client.call('send_email', { to: 'attacker@evil.example' })));
  assert.equal(callCount(env, 'send_email'), 1);
  cli.client.end();
  assert.equal(await cli.exited, 0);
});

test('CLI lifecycle: EOF => exit 0 with anchor line on stderr; server crash => exit 1 with proxy_server_exit', async () => {
  const cli = startCli();
  await cli.client.handshake();
  cli.client.end();
  assert.equal(await cli.exited, 0);
  assert.match(cli.stderrText(), /"prysm":"anchor"/);
  assert.equal(cli.stderrText().split('\n').filter((l) => l.startsWith('{') && !l.startsWith('{"prysm"')).length, 0);

  const c2 = startCli();
  await c2.client.handshake();
  assert.match(toolText(await c2.client.call('crash', {})), /^Tool error/);
  assert.equal(await c2.exited, 1);
  assert.match(c2.stderrText(), /\{"prysm":"proxy_server_exit","code":3\}/);
});

test('CLI audit: canary absent from DB/WAL/stderr/stdout leaks; verify ok; decision durable before execution', async () => {
  const env = makeEnv();
  const cli = startCli({ env, serverExtra: ['--db', env.dbPath], flags: [...baseFlags(env)] });
  await cli.client.handshake();
  const canary = 'CANARY-b81c44e0-cli-secret';
  await cli.client.call('echo', { text: canary });
  const d = await cli.client.call('echo', { text: 'deny-' + canary });
  cli.client.end();
  assert.equal(await cli.exited, 0);
  assert.ok(!cli.stderrText().includes(canary));
  assert.ok(!toolText(d).includes(canary));
  const s = openAudit(env, true);
  const rows = rowsOf(s);
  assert.equal(s.verify().ok, true);
  const dec = rows.find((r) => r.kind === 'decision' && r.effect === 'permit');
  assert.ok(dec);
  const call = serverCalls(env)[0] as { audit: number };
  assert.ok(call.audit >= dec.seq, JSON.stringify([call.audit, dec.seq]));
  s.close();
  const dump = [env.dbPath, env.dbPath + '-wal'].filter((p) => existsSync(p)).map((p) => readFileSync(p).toString('latin1')).join('');
  assert.ok(!dump.includes(canary));
});

test('CLI flags: bad flags exit 2; policy sha256 mismatch exits 2 without spawning the server', async () => {
  const env = makeEnv();
  const run = async (flags: string[], noServer = false) => {
    const c = startCli({ env, flags, noServer });
    return { code: await c.exited, err: c.stderrText() };
  };
  assert.equal((await run([], true)).code, 2);
  assert.equal((await run(['--bogus', 'x', '--policy', env.policyPath, '--db', env.dbPath])).code, 2);
  assert.equal((await run(['--policy', env.policyPath, '--db', env.dbPath], true)).code, 2); // no server command
  assert.equal((await run([...baseFlags(env), '--tool-timeout-ms', '0'])).code, 2);
  assert.equal((await run([...baseFlags(env), '--list-mode', 'x'])).code, 2);
  assert.equal((await run([...baseFlags(env), '--allow-methods', 'tools/call'])).code, 2);
  assert.equal((await run([...baseFlags(env), '--taint-tools', 'not_in_policy'])).code, 2);
  assert.equal((await run(['--policy', join(env.dir, 'missing.json'), '--db', env.dbPath])).code, 2);
  const r = await run([...baseFlags(env), '--policy-sha256', 'a'.repeat(64)]);
  assert.equal(r.code, 2);
  assert.ok(!r.err.includes('a'.repeat(64)));
  assert.ok(!existsSync(join(env.dir, 'env.json')), 'server was never spawned');
  assert.ok(!existsSync(join(env.dir, 'methods.jsonl')));

  const sha = createHash('sha256').update(readFileSync(env.policyPath)).digest('hex');
  const ok = startCli({ env, flags: [...baseFlags(env), '--policy-sha256', sha] });
  await ok.client.handshake();
  ok.client.end();
  assert.equal(await ok.exited, 0);

});

test('CLI: unspawnable server => exit 3', async () => {
  const env = makeEnv();
  const { spawn } = await import('node:child_process');
  const { BIN } = await import('../support/proxy-kit.ts');
  const p = spawn(process.execPath, ['--no-warnings=ExperimentalWarning', BIN, ...baseFlags(env), '--', 'definitely-not-a-command-xyz'], { stdio: ['pipe', 'pipe', 'pipe'] });
  let err = '';
  p.stderr.on('data', (c: Buffer) => { err += c.toString(); });
  const code = await new Promise<number | null>((r) => { p.on('close', r); });
  assert.equal(code, 3);
  assert.ok(!err.includes('definitely-not'));
});

test('CLI env allowlist: a canary env var in the proxy process is not visible to the server unless --env lists it', async () => {
  const env = makeEnv();
  const cli = startCli({ env, childEnv: { PRYSM_CANARY_SECRET: 'zzz', PRYSM_ALLOWED: 'yes' }, flags: [...baseFlags(env), '--env', 'PRYSM_ALLOWED'] });
  await cli.client.handshake();
  cli.client.end();
  assert.equal(await cli.exited, 0);
  const keys = JSON.parse(readFileSync(join(env.dir, 'env.json'), 'utf8')) as string[];
  assert.ok(!keys.includes('PRYSM_CANARY_SECRET'));
  assert.ok(keys.includes('PRYSM_ALLOWED'));
  assert.ok(keys.some((k) => k.toUpperCase() === 'PATH'));
  assert.ok(serverMethods(env).length > 0);
});
