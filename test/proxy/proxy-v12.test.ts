// PROXY-SPEC §9 (v1.2) amendment tests.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PassThrough, Writable } from 'node:stream';
import { cleanup } from '../support/tmp.ts';
import { rule } from '../support/policy.ts';
import { faulty } from '../support/guard-kit.ts';
import {
  startLib, startCli, makeEnv, policyDoc, callCount, serverMethods, toolText, isErr, openAudit, rowsOf, waitFor, sleep, KEY,
} from '../support/proxy-kit.ts';
import type { Lib, Client } from '../support/proxy-kit.ts';
import { parseArgs } from '../../src/proxy/index.ts';

after(cleanup);
type Json = Record<string, unknown>;
const finish = async (l: Lib): Promise<number> => { l.client.end(); return l.done; };
const sample = (n: number, f: (i: number) => unknown) => Array.from({ length: n }, (_, i) => f(i));

// ---------------------------------------------------------------- §9.1 data channels
test('9.1 client progress notifications and initialize extras never reach the server', async () => {
  const env = makeEnv();
  const l = startLib({ env });
  const r = await l.client.request('initialize', {
    protocolVersion: '2025-03-26', capabilities: { roots: { listChanged: true }, sampling: {} }, _meta: { secret: 'S' },
    clientInfo: { name: 'my-client', version: '1.2', extra: 'E' }, covert: 'channel',
  });
  assert.ok(r['result']);
  l.client.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  l.client.send({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 'tok', progress: 1, covert: 'x' } });
  await l.client.request('tools/list');
  await sleep(150);
  const init = serverMethods(env).find((m) => m['method'] === 'initialize') as { params: Json };
  assert.deepEqual(init.params, { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'my-client', version: '1.2' } });
  assert.ok(!serverMethods(env).some((m) => m['method'] === 'notifications/progress'));
  assert.ok(!JSON.stringify(serverMethods(env)).includes('covert'));
  await finish(l);

  // with server requests opted in, progress is forwarded but rebuilt to numbers/token only
  const env2 = makeEnv();
  const l2 = startLib({ env: env2, proxy: { allowServerRequests: ['sampling/createMessage'] } });
  await l2.client.handshake();
  l2.client.send({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 'tok', progress: 2, total: 5, covert: 'x' } });
  l2.client.send({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 'bad token!', progress: 2 } });
  await waitFor(() => serverMethods(env2).some((m) => m['method'] === 'notifications/progress'));
  await sleep(100);
  const prog = serverMethods(env2).filter((m) => m['method'] === 'notifications/progress');
  assert.equal(prog.length, 1);
  assert.deepEqual((prog[0] as { params: Json }).params, { progressToken: 'tok', progress: 2, total: 5 });
  await finish(l2);
});

test('9.1 progressToken must match the token grammar or be a non-negative safe integer, else _meta is omitted', async () => {
  const env = makeEnv();
  const l = startLib({ env });
  await l.client.handshake();
  for (const [tok, i] of ([['ok.tok:1', 1], ['bad token', 2], [-1, 3], [1.5, 4], [7, 5], ['x'.repeat(65), 6]] as const)) {
    await l.client.request('tools/call', { name: 'echo', arguments: { text: 't' + String(i) }, _meta: { progressToken: tok } }, 700 + i);
  }
  const calls = serverMethods(env).filter((m) => m['method'] === 'tools/call').map((m) => (m['params'] as Json)['_meta']);
  assert.deepEqual(calls, [{ progressToken: 'ok.tok:1' }, undefined, undefined, undefined, { progressToken: 7 }, undefined]);
  await finish(l);
});

// ---------------------------------------------------------------- §9.2 escaping
test('9.2 U+2028/U+2029/U+0085 round trip through a readline-based fixture without desynchronising the stream', async () => {
  const env = makeEnv();
  const l = startLib({ env });
  await l.client.handshake();
  const text = 'a\u2028b\u2029c\u0085d';
  const r = await l.client.call('echo', { text });
  assert.equal(toolText(r), 'echo:' + text);
  const raw = l.client.rawLines.find((x) => x.includes('echo:a'));
  assert.ok(raw && !raw.includes('\u2028') && !raw.includes('\u2029') && !raw.includes('\u0085') && raw.includes('\\u2028'));
  const recv = serverMethods(env).filter((m) => m['method'] === 'tools/call').pop() as { params: { arguments: { text: string } } };
  assert.equal(recv.params.arguments.text, text.normalize('NFC'));
  assert.deepEqual((await l.client.request('ping'))['result'], {});
  await finish(l);
});

// ---------------------------------------------------------------- §9.3 oversize keeps the proxy alive
test('9.3 oversize server line: pending calls fail closed, proxy keeps running and serving; late replies would be dropped', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { maxServerLineBytes: 100_000 } });
  await l.client.handshake();
  l.client.send({ jsonrpc: '2.0', id: 61, method: 'tools/call', params: { name: 'slow', arguments: {} } });
  await waitFor(() => callCount(env, 'slow') === 1);
  const r = await l.client.call('big', { bytes: 200_000 });
  assert.match(toolText(r), /^Tool error \(decision [0-9a-f-]{36}\)$/);
  // the call that hung when the oversize line arrived is failed closed as well
  assert.match(toolText(await l.client.reply(61)), /^Tool error \(decision /);
  assert.match(l.stderrText(), /\{"prysm":"proxy_server_oversize"\}/);
  assert.ok(!/proxy_server_exit/.test(l.stderrText()), 'the proxy does not exit or kill the server');
  assert.equal(toolText(await l.client.call('echo', { text: 'still alive' })), 'echo:still alive');
  assert.equal(await Promise.race([l.done, sleep(100).then(() => 'pending')]), 'pending');
  await finish(l);
});

// ---------------------------------------------------------------- §9.4 launch & cleanup
test('9.4 a synchronous spawn throw maps to spawn_failed (exit 3), without command text', () => {
  const env = makeEnv();
  let msg = '';
  try {
    startLib({ env, proxy: { spawn: () => { throw new Error('boom /secret/path'); } } });
    assert.fail('expected throw');
  } catch (e) { msg = (e as { code?: string; message: string }).code ?? ''; assert.ok(!(e as Error).message.includes('secret')); }
  assert.equal(msg, 'spawn_failed');
});

test('9.4 shutdown kills the server process tree (grandchild does not survive)', { skip: process.platform !== 'win32' ? 'taskkill /T is Windows-only' : false }, async () => {
  const env = makeEnv();
  const pidFile = join(env.dir, 'grandchild.pid');
  const l = startLib({ env, serverExtra: ['--grandchild', pidFile, '--ignore-eof'], proxy: { killGraceMs: 300 } });
  await l.client.handshake();
  await waitFor(() => existsSync(pidFile));
  const pid = Number(readFileSync(pidFile, 'utf8'));
  const alive = (): boolean => { try { process.kill(pid, 0); return true; } catch { return false; } };
  assert.ok(alive(), 'grandchild is running before shutdown');
  try {
    assert.equal(await finish(l), 0); // the fixture ignores EOF, so only the grace-period tree kill ends it
    await waitFor(() => !alive(), 5000);
    assert.equal(alive(), false);
  } finally {
    try { process.kill(pid); } catch { /* already gone */ }
  }
});

test('9.4 SIGTERM runs the orderly shutdown (anchor line, exit 0)', { skip: process.platform === 'win32' ? 'POSIX signals are not catchable on Windows child processes' : false }, async () => {
  const cli = startCli();
  await cli.client.handshake();
  cli.child.kill('SIGTERM');
  assert.equal(await cli.exited, 0);
  assert.match(cli.stderrText(), /"prysm":"anchor"/);
});

test('9.4 exit 70 on an uncaught exception (test seam) with a proxy_fatal line and no message content', async () => {
  const cli = startCli({ childEnv: { PRYSM_PROXY_TEST_FATAL: '1' } });
  assert.equal(await cli.exited, 70);
  assert.match(cli.stderrText(), /\{"prysm":"proxy_fatal"\}/);
  assert.ok(!cli.stderrText().includes('test fatal'));
});

// ---------------------------------------------------------------- §9.5 guard-routed rows
test('9.5 unexposed-tool denials are written by the guard; a flood shows dropped_before on the next written row; rows are enforced in monitor_only', async () => {
  const pinned = { crash: { risk: 'low', external_effect: false, read_only: true, fail_mode: 'closed', args: { x: { type: 'string', optional: true } }, schema_hash: '0'.repeat(64) } };
  const env = makeEnv(policyDoc(pinned));
  const l = startLib({ env });
  await l.client.handshake();
  for (let i = 0; i < 230; i++) await l.client.call('crash', {});
  assert.equal(callCount(env, 'crash'), 0);
  const d = await l.client.call('echo', { text: 'deny-me' }); // policy_deny class has its own budget
  assert.match(toolText(d), /denied/);
  await finish(l);
  const s = openAudit(env);
  const rows = rowsOf(s).filter((r) => r.kind === 'decision');
  const crash = rows.filter((r) => r.tool === 'crash');
  assert.equal(crash.length, 200, 'pre_evaluate budget');
  assert.ok(crash.every((r) => r.enforcement === 'enforced' && r.reason_code === 'unknown_tool' && (r.outcome as Json)['reason'] === 'schema_changed'));
  const denyRow = rows.find((r) => r.tool === 'echo' && r.effect === 'deny');
  assert.deepEqual((denyRow?.outcome as Json)['dropped_before'], { pre_evaluate: 30 });
  assert.equal(s.verify().ok, true);
  s.close();

  const doc = policyDoc(pinned) as Json;
  doc['mode'] = 'monitor_only';
  const env2 = makeEnv(doc);
  const l2 = startLib({ env: env2 });
  await l2.client.handshake();
  assert.match(toolText(await l2.client.call('crash', {})), /unknown_tool/);
  assert.equal(callCount(env2, 'crash'), 0);
  await finish(l2);
  const s2 = openAudit(env2);
  const row = rowsOf(s2).find((r) => r.kind === 'decision' && r.tool === 'crash');
  assert.equal(row?.enforcement, 'enforced');
  const cfg = rowsOf(s2).find((r) => r.kind === 'policy_activate' && (r.outcome as Json | null)?.['event'] === 'proxy_config');
  assert.equal((cfg?.outcome as Json)['policy_mode'], 'monitor_only');
  s2.close();
});

// ---------------------------------------------------------------- §9.13 posture rows
test('9.13 proxy_config / proxy_client / tools_replaced rows carry posture and counts, never names', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { allowMethods: ['resources/list'], scopes: ['a', 'b'], userId: 'u1', taintTools: ['search_docs'] } });
  await l.client.request('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'my-client', version: '9.9' } });
  l.client.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  await l.client.request('tools/list');
  await finish(l);
  const s = openAudit(env);
  const rows = rowsOf(s).filter((r) => r.kind === 'policy_activate').map((r) => r.outcome as Json);
  const cfg = rows.find((o) => o['event'] === 'proxy_config') as Json;
  assert.deepEqual(
    { ...cfg, policy_version: undefined },
    { event: 'proxy_config', policy_mode: 'enforce', list_mode: 'hide', require_pins: false, tool_timeout_ms: 60000, taint_tools_n: 1,
      allow_methods: ['resources/list'], allow_server_requests: [], allow_server_notifications: false, provenance_args: [],
      scopes_n: 2, user_set: true, policy_version: undefined });
  const cl = rows.find((o) => o['event'] === 'proxy_client') as Json;
  assert.equal(cl['name'], 'my-client'); assert.equal(cl['version'], '9.9');
  const tr = rows.find((o) => o['event'] === 'tools_replaced') as Json;
  assert.equal(tr['exposed_n'], 7);
  assert.deepEqual(tr['hidden'], { bad_name: 1, not_in_policy: 1 });
  assert.ok(!JSON.stringify(rows).includes('secret_tool'));
  s.close();
});

// ---------------------------------------------------------------- §9.6 / 9.9 sink lines
test('9.6/9.9 truncated tool list and unpinned tools are reported with counts only', async () => {
  const env = makeEnv();
  const control = join(env.dir, 'control.json');
  writeFileSync(control, JSON.stringify({ add: sample(2100, (i) => ({ name: 'extra_' + String(i), description: 'd', inputSchema: { type: 'object' } })) }));
  const l = startLib({ env, serverExtra: ['--control', control] });
  await l.client.handshake();
  assert.match(l.stderrText(), /\{"prysm":"proxy_tool_ignored","reason":"truncated","n":\d+\}/);
  const m = /"reason":"truncated","n":(\d+)/.exec(l.stderrText());
  assert.ok(Number(m?.[1]) > 0);
  assert.match(l.stderrText(), /\{"prysm":"proxy_unpinned_tools","n":7\}/);
  assert.ok(!l.stderrText().includes('extra_'));
  await finish(l);
});

// ---------------------------------------------------------------- §9.7 forward timeout
test('9.7 an allow-listed forwarded request times out with -32603 and is released; late reply is an orphan', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { allowMethods: ['resources/hang'], forwardTimeoutMs: 300 } });
  await l.client.handshake();
  const t0 = Date.now();
  const r = await l.client.request('resources/hang', {}, 41);
  assert.equal((r['error'] as Json)['code'], -32603);
  assert.ok(Date.now() - t0 >= 250);
  assert.equal(l.client.messages.filter((m) => m['id'] === 41).length, 1);
  // the id is released: it can be reused
  l.client.send({ jsonrpc: '2.0', id: 41, method: 'ping' });
  await waitFor(() => l.client.messages.filter((m) => m['id'] === 41).length === 2);
  assert.deepEqual((l.client.messages.filter((m) => m['id'] === 41)[1] as Json)['result'], {});
  await finish(l);
});

// ---------------------------------------------------------------- §9.8 stderr
test('9.8 server stderr is sanitised: controls replaced, U+2028/2029/0085 escaped, capped at 1000 chars, prefixed', async () => {
  const env = makeEnv();
  const l = startLib({ env, serverExtra: ['--stderr-noise'] });
  await l.client.handshake();
  await waitFor(() => l.stderrText().includes('LLLL'));
  await finish(l);
  const err = l.stderrText();
  assert.ok(!/[\u001b\u0007\u2028\u2029\u0085]/.test(err.replace(/\n/g, '')) && !err.includes('\r'));
  const noisy = err.split('\n').find((x) => x.includes('ansi')) as string;
  assert.ok(noisy.startsWith('[server] '));
  assert.ok(noisy.includes('\\u2028') && noisy.includes('\\u2029') && noisy.includes('\\u0085'));
  assert.ok(noisy.includes('tab\tok'));
  const long = err.split('\n').find((x) => x.includes('LLLL')) as string;
  assert.ok(long.startsWith('[server] ') && long.length <= 9 + 1000);
});

// ---------------------------------------------------------------- §9.10 flags
test('9.10 flag validation: identifiers, empty CSV entries and undeclared provenance args are rejected', () => {
  const bad: Json[] = [
    { agentId: 'bad id' }, { scopes: ['ok', 'bad scope'] }, { scopes: [''] }, { userId: 'has space' }, { userId: 'x'.repeat(129) },
    { taintTools: ['search_docs', ''] }, { env: [''] }, { env: ['GOOD', ''] }, { provenance: { not_declared_anywhere: ['user_input'] } },
    { provenance: { to: ['bad label!'] } }, { maxServerLineBytes: 65 * 1024 * 1024 }, { forwardTimeoutMs: 0 },
  ];
  for (const b of bad) assert.throws(() => startLib({ env: makeEnv(), proxy: b as never }), /bad_option|taint_tool_unknown/, JSON.stringify(b));
  assert.deepEqual(parseArgs(['--policy', 'p', '--db', 'd', '--taint-tools', 'a,,b', '--', 'x']).taintTools, ['a', '', 'b']);
  assert.equal(parseArgs(['--policy', 'p', '--db', 'd', '--max-server-line-bytes', '1048576', '--forward-timeout-ms', '500', '--', 'x']).maxServerLineBytes, 1048576);
});

// ---------------------------------------------------------------- §9.11 envelope
test('9.11 whitespace-only lines are ignored; an id-only message gets -32600 echoing the id; late replies to cancelled calls are orphans once', async () => {
  const env = makeEnv();
  const l = startLib({ env });
  await l.client.handshake();
  const n = l.client.messages.length;
  l.client.sendRaw('   ');
  l.client.sendRaw('\t \r');
  l.client.sendRaw('');
  l.client.sendRaw('{"jsonrpc":"2.0","id":88}');
  const r = await l.client.reply(88);
  assert.equal((r['error'] as Json)['code'], -32600);
  assert.equal(l.client.messages.length, n + 1, 'whitespace-only lines produced no output');
  await finish(l);
});

// ---------------------------------------------------------------- §9.12 backpressure
async function floodScenario(): Promise<{ inPaused: boolean; queued: number; echoSeenWhilePaused: number; l: Lib; env: ReturnType<typeof makeEnv>; release: () => void; flood: Promise<Json> }> {
  const env = makeEnv();
  const gate = { open: false };
  const held: [Buffer, () => void][] = [];
  let client: Client | undefined;
  const clientIn = new PassThrough();
  const out = new Writable({
    highWaterMark: 1024,
    write(c: Buffer, _e, cb) {
      if (gate.open) { client?.feed(c); cb(); } else held.push([c, cb]);
    },
  });
  const l = startLib({ env, clientIn, proxy: { clientOut: out } });
  client = l.client;
  gate.open = true;
  await l.client.handshake();
  gate.open = false;
  l.client.send({ jsonrpc: '2.0', id: 500, method: 'tools/call', params: { name: 'weird', arguments: { mode: 'flood' }, _meta: { progressToken: 'mine' } } });
  await sleep(1200);
  // the client never reads: a second request sent now must not even be read by the proxy
  l.client.send({ jsonrpc: '2.0', id: 501, method: 'tools/call', params: { name: 'echo', arguments: { text: 'queued' } } });
  await sleep(400);
  const queued = out.writableLength + held.reduce((a, [c]) => a + c.length, 0);
  const echoSeenWhilePaused = callCount(env, 'echo');
  const inPaused = clientIn.isPaused();
  const release = (): void => {
    gate.open = true;
    for (const [c, cb] of held.splice(0)) { client?.feed(c); cb(); }
  };
  return { inPaused, queued, echoSeenWhilePaused, l, env, release, flood: l.client.reply(500, 30000) };
}

test('9.12 backpressure: with a non-reading client the proxy pauses the server stdout AND the client stdin; flow resumes on drain', async () => {
  const f = await floodScenario();
  // unbounded growth would approach ~4 MB (20000 progress messages); a paused proxy only holds what was already read
  assert.ok(f.queued < 700_000, 'client output buffer stayed bounded: ' + String(f.queued));
  assert.equal(f.inPaused, true, 'client stdin is paused while the output is backed up');
  f.release();
  assert.equal(toolText(await f.flood), 'flood-done');
  assert.equal(toolText(await f.l.client.reply(501, 30000)), 'echo:queued');
  assert.equal(callCount(f.env, 'echo'), 1);
  await finish(f.l);
});

// ---------------------------------------------------------------- registry failure with a fault-injected store
test('9.14 a failing setTools audit append keeps the last good registry and writes proxy_registry_refresh_failed', async () => {
  const env = makeEnv();
  const control = join(env.dir, 'control.json');
  let failing = false;
  const l = startLib({
    env, serverExtra: ['--control', control],
    proxy: {
      storeWrap: (s) => faulty(s, (ev) => failing && ev.kind === 'policy_activate' && (ev.outcome as Json | null)?.['event'] === 'tools_replaced'),
    },
  });
  await l.client.handshake();
  failing = true;
  writeFileSync(control, JSON.stringify({ remove: ['big'] }));
  await waitFor(() => /set_tools_failed/.test(l.stderrText()));
  assert.match(l.stderrText(), /\{"prysm":"proxy_registry_refresh_failed","reason":"set_tools_failed"\}/);
  const tools = ((await l.client.request('tools/list'))['result'] as Json)['tools'] as Json[];
  assert.ok(tools.some((t) => t['name'] === 'big'), 'last good listing kept');
  assert.equal(toolText(await l.client.call('echo', { text: 'ok' })), 'echo:ok');
  assert.equal(l.client.messages.filter((m) => m['method'] === 'notifications/tools/list_changed').length, 0);
  await finish(l);
});

// ---------------------------------------------------------------- waiters cap + coalescing
test('9.14 readiness waiters are capped at 64 (65th waiter is refused at once)', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { readyTimeoutMs: 1500 } });
  await l.client.request('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  for (let i = 0; i < 64; i++) l.client.send({ jsonrpc: '2.0', id: 3000 + i, method: 'tools/call', params: { name: 'echo', arguments: { text: 'w' } } });
  await sleep(100);
  const t0 = Date.now();
  const r = await l.client.request('tools/list', undefined, 9999);
  assert.equal((r['error'] as Json)['code'], -32603);
  assert.ok(Date.now() - t0 < 700, 'refused immediately, not after the readiness timeout');
  await finish(l);
});

test('9.14 list_changed bursts are coalesced into at most one running plus one queued refresh', async () => {
  const env = makeEnv();
  const control = join(env.dir, 'control.json');
  const l = startLib({ env, serverExtra: ['--control', control] });
  await l.client.handshake();
  const before = serverMethods(env).filter((m) => m['method'] === 'tools/list').length;
  writeFileSync(control, JSON.stringify({ burst: 30, remove: ['big'] }));
  await l.client.next((m) => m['method'] === 'notifications/tools/list_changed');
  await sleep(500);
  const after = serverMethods(env).filter((m) => m['method'] === 'tools/list').length;
  assert.ok(after - before >= 1 && after - before <= 2, 'refreshes: ' + String(after - before));
  await finish(l);
});

// ---------------------------------------------------------------- CLI: provenance
test('9.14 --provenance through the real CLI asserts the label (sink line) and satisfies a provenance rule', async () => {
  const doc = policyDoc() as { rules: { id: string }[] };
  doc.rules = doc.rules.filter((r) => r.id !== 'p.email').concat([rule('permit', 'p.email.prov', { tools: ['send_email'], provenance: { to: { any_in: ['user_input'] } } })] as never);
  const env = makeEnv(doc as never);
  const base = ['--policy', env.policyPath, '--db', env.dbPath, '--key-path', env.keyPath];
  const cli = startCli({ env, flags: [...base, '--provenance', 'to=user_input'] });
  await cli.client.handshake();
  assert.equal(isErr(await cli.client.call('send_email', { to: 'a@example.com' })), false);
  assert.equal(callCount(env, 'send_email'), 1);
  cli.client.end();
  assert.equal(await cli.exited, 0);
  assert.match(cli.stderrText(), /\{"prysm":"proxy_provenance_asserted","arg":"to"\}/);

  const env2 = makeEnv(doc as never);
  const cli2 = startCli({ env: env2 });
  await cli2.client.handshake();
  assert.ok(isErr(await cli2.client.call('send_email', { to: 'a@example.com' })));
  assert.equal(callCount(env2, 'send_email'), 0);
  cli2.client.end();
  await cli2.exited;
  void KEY;
});

test('9.5 the decision id in a not-ready block refers to a guard-written row (reason not_ready, enforced)', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { readyTimeoutMs: 300 } });
  await l.client.request('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  const r = await l.client.call('echo', { text: 'early' });
  const id = /decision ([0-9a-f-]{36})/.exec(toolText(r))?.[1] as string;
  assert.ok(id);
  await finish(l);
  const s = openAudit(env);
  const row = rowsOf(s).find((x) => x.id === id);
  assert.ok(row, 'row exists');
  assert.equal(row.enforcement, 'enforced');
  assert.equal(row.reason_code, 'unknown_tool');
  assert.equal((row.outcome as Json)['reason'], 'not_ready');
  s.close();
});
