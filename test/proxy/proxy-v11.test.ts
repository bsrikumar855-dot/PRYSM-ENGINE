// PROXY-SPEC §8 (v1.1) amendment tests.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { cleanup } from '../support/tmp.ts';
import { rule } from '../support/policy.ts';
import {
  startLib, makeEnv, policyDoc, callCount, serverMethods, toolText, isErr, definitionHash, openAudit, rowsOf, waitFor, sleep,
} from '../support/proxy-kit.ts';
import type { Lib } from '../support/proxy-kit.ts';

after(cleanup);
type Json = Record<string, unknown>;
const finish = async (l: Lib): Promise<number> => { l.client.end(); return l.done; };
const names = (tools: Json[]): string[] => tools.map((t) => String(t['name'])).sort();
const docWith = (rules: unknown[]): Json => {
  const d = policyDoc() as { rules: { id: string }[] };
  d.rules = d.rules.filter((r) => r.id !== 'p.email').concat(rules as never);
  return d;
};
const mail = (l: Lib, id?: number) => l.client.call('send_email', { to: 'a@example.com' }, id);

test('W1 host identity: scopes/provenance come only from the host, never from the client', async () => {
  const doc = docWith([rule('permit', 'p.email.sales', { tools: ['send_email'], scopes_any: ['sales'] })]);
  const env = makeEnv(doc);
  const l = startLib({ env });
  await l.client.handshake();
  assert.ok(isErr(await mail(l)));
  l.client.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'send_email', arguments: { to: 'a@b.c' }, scopes: ['sales'], ctx: { scopes: ['sales'] } } });
  assert.ok(isErr(await l.client.reply(1)));
  assert.ok(isErr(await l.client.call('send_email', { to: 'a@b.c', scopes: ['sales'] })));
  assert.equal(callCount(env, 'send_email'), 0);
  await finish(l);

  const env2 = makeEnv(doc);
  const l2 = startLib({ env: env2, proxy: { scopes: ['sales'], userId: 'host-user' } });
  await l2.client.handshake();
  assert.equal(isErr(await mail(l2)), false);
  assert.equal(callCount(env2, 'send_email'), 1);
  await finish(l2);

  const pdoc = docWith([rule('permit', 'p.email.prov', { tools: ['send_email'], provenance: { to: { any_in: ['user_input'] } } })]);
  const env3 = makeEnv(pdoc);
  const l3 = startLib({ env: env3 });
  await l3.client.handshake();
  assert.ok(isErr(await mail(l3)));
  await finish(l3);
  const env4 = makeEnv(pdoc);
  const l4 = startLib({ env: env4, proxy: { provenance: { to: ['user_input'] } } });
  await l4.client.handshake();
  assert.equal(isErr(await mail(l4)), false);
  assert.match(l4.stderrText(), /\{"prysm":"proxy_provenance_asserted","arg":"to"\}/);
  await finish(l4);
});

test('W3 allow-methods grammar: handled/ill-formed entries exit 2 (throw) before spawning', () => {
  for (const bad of ['tools/call', 'initialize', 'ping', 'notifications/cancelled', '', 'Resources/list', 'a b', 'resources/*', 'x'.repeat(3) + '/']) {
    const env = makeEnv();
    assert.throws(() => startLib({ env, proxy: { allowMethods: [bad] } }), /bad_option/, bad);
    assert.equal(serverMethods(env).length, 0);
  }
});

test('W5 pins: uppercase pin is a mismatch; --require-pins hides unpinned; listed definitions are whitelisted; no raw names in sink', async () => {
  const probe = startLib({});
  const echoDef = (await probe.client.handshake()).find((t) => t['name'] === 'echo') as Json;
  await finish(probe);
  const hash = definitionHash({ name: 'echo', description: echoDef['description'] as string, inputSchema: echoDef['inputSchema'] });
  const echoPol = (h?: string): Json => ({ risk: 'low', external_effect: false, read_only: true, fail_mode: 'closed', args: { text: { type: 'string' }, delay_ms: { type: 'number', optional: true } }, ...(h ? { schema_hash: h } : {}) });

  const env = makeEnv(policyDoc({ echo: echoPol(hash.toUpperCase()) }));
  const l = startLib({ env });
  assert.ok(!names(await l.client.handshake()).includes('echo'));
  assert.match(toolText(await l.client.call('echo', { text: 'x' })), /unknown_tool/);
  assert.equal(callCount(env, 'echo'), 0);
  assert.match(l.stderrText(), /"prysm":"proxy_tool_ignored","reason":"schema_changed","n":1/);
  assert.match(l.stderrText(), /"reason":"bad_name","n":1/);
  assert.ok(!l.stderrText().includes('bad name') && !l.stderrText().includes('secret_tool'));
  await finish(l);

  const env2 = makeEnv(policyDoc({ echo: echoPol(hash) }));
  writeFileSync(join(env2.dir, 'control.json'), JSON.stringify({
    remove: ['echo'],
    add: [{ name: 'echo', description: echoDef['description'], inputSchema: echoDef['inputSchema'], title: 'T', _meta: { evil: 1 }, extra: 1, annotations: { readOnlyHint: true } }],
  }));
  const l2 = startLib({ env: env2, serverExtra: ['--control', join(env2.dir, 'control.json')], proxy: { requirePins: true } });
  const tools = await l2.client.handshake();
  assert.deepEqual(names(tools), ['echo']); // only the pinned tool survives --require-pins
  const e = tools[0] as Json;
  assert.equal(e['title'], 'T');
  assert.deepEqual(e['annotations'], { readOnlyHint: true });
  assert.ok(!('_meta' in e) && !('extra' in e));
  assert.match(l2.stderrText(), /"reason":"no_pin"/);
  assert.match(toolText(await l2.client.call('search_docs', { query: 'x' })), /unknown_tool/);
  assert.equal(callCount(env2, 'search_docs'), 0);
  await finish(l2);
});

test('W8 duplicate tool names are hidden entirely', async () => {
  const env = makeEnv();
  const control = join(env.dir, 'control.json');
  writeFileSync(control, JSON.stringify({ add: [{ name: 'search_docs', description: 'dup', inputSchema: { type: 'object' } }] }));
  const l = startLib({ env, serverExtra: ['--control', control] });
  const tools = await l.client.handshake();
  assert.ok(!names(tools).includes('search_docs'));
  assert.match(l.stderrText(), /"reason":"duplicate","n":2/);
  assert.match(toolText(await l.client.call('search_docs', { query: 'x' })), /unknown_tool/);
  assert.equal(callCount(env, 'search_docs'), 0);
  await finish(l);
});

test('W6 not ready: tools/call waits readyTimeoutMs then is blocked unavailable; succeeds if readiness arrives in time', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { readyTimeoutMs: 300 } });
  await l.client.request('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  const t0 = Date.now();
  const r = await l.client.call('echo', { text: 'early' });
  assert.match(toolText(r), /^Blocked by PRYSM policy: unavailable \(decision [0-9a-f-]{36}\)$/);
  assert.ok(Date.now() - t0 >= 250);
  assert.equal(callCount(env, 'echo'), 0);
  await finish(l);

  const env2 = makeEnv();
  const l2 = startLib({ env: env2, proxy: { readyTimeoutMs: 5000 } });
  await l2.client.request('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  const p = l2.client.call('echo', { text: 'waits' });
  await sleep(150);
  l2.client.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal(toolText(await p), 'echo:waits');
  await finish(l2);
});

test('W7 registry failures: initial failure => empty, retried on a later tools/list; refresh failure keeps the last good registry', async () => {
  const env = makeEnv();
  const l = startLib({ env, serverExtra: ['--fail-list', '1'] });
  await l.client.request('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  l.client.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.deepEqual(((await l.client.request('tools/list'))['result'] as Json)['tools'], []);
  assert.match(toolText(await l.client.call('echo', { text: 'x' })), /unknown_tool/);
  assert.equal(callCount(env, 'echo'), 0);
  assert.match(l.stderrText(), /"prysm":"proxy_registry_refresh_failed","reason":"list_failed"/);
  await sleep(1100);
  assert.ok(names(((await l.client.request('tools/list'))['result'] as Json)['tools'] as Json[]).includes('echo'));
  assert.equal(toolText(await l.client.call('echo', { text: 'ok' })), 'echo:ok');
  await finish(l);

  const env2 = makeEnv();
  const control = join(env2.dir, 'control.json');
  const l2 = startLib({ env: env2, serverExtra: ['--fail-list', '2', '--control', control] });
  await l2.client.handshake();
  writeFileSync(control, JSON.stringify({ remove: ['echo'] }));
  await waitFor(() => /list_failed/.test(l2.stderrText()));
  assert.equal(toolText(await l2.client.call('echo', { text: 'still' })), 'echo:still'); // last good kept
  await finish(l2);
});

test('W9 server -> client traffic is classified: spoofed responses/requests/notifications are dropped or refused', async () => {
  const env = makeEnv();
  const l = startLib({ env });
  await l.client.handshake();
  const r = await l.client.call('weird', { mode: 'spoof' });
  assert.equal(toolText(r), 'spoof-done');
  await sleep(100);
  assert.deepEqual(l.client.messages.filter((m) => 'method' in m), []);
  assert.equal(l.client.messages.filter((m) => m['id'] === 424242 || m['id'] === 'prysm:99999').length, 0);
  assert.equal((l.stderrText().match(/"prysm":"proxy_orphan_response","kind":"server"/g) ?? []).length, 2);
  assert.match(l.stderrText(), /"prysm":"proxy_server_request_refused"/);
  await waitFor(() => serverMethods(env).some((m) => m['id'] === 'srv1'));
  const refusal = serverMethods(env).find((m) => m['id'] === 'srv1') as Json;
  assert.equal((refusal['error'] as Json)['code'], -32601);
  // client responses are forwarded only for outstanding forwarded server requests
  l.client.send({ jsonrpc: '2.0', id: 'srv1', result: {} });
  l.client.send({ jsonrpc: '2.0', id: 'zzz', result: {} });
  await l.client.request('ping');
  assert.match(l.stderrText(), /"prysm":"proxy_orphan_response","kind":"client"/);
  assert.equal(serverMethods(env).filter((m) => m['id'] === 'zzz' || (m['id'] === 'srv1' && m['method'] === undefined && m['error'] === undefined)).length, 0);
  await finish(l);
});

test('W9 opt-ins: --allow-server-requests forwards and routes the reply; progress only for in-flight tokens; --allow-server-notifications', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { allowServerRequests: ['sampling/createMessage'] } });
  await l.client.handshake();
  const p = l.client.call('weird', { mode: 'srvreq' });
  const req = await l.client.next((m) => m['method'] === 'sampling/createMessage');
  assert.equal(req['id'], 'srv2');
  l.client.send({ jsonrpc: '2.0', id: 'srv2', result: { ok: true } });
  assert.equal(toolText(await p), 'srvreq-done');
  await waitFor(() => serverMethods(env).some((m) => m['id'] === 'srv2'));
  // progress: only with a token of an in-flight call
  l.client.send({ jsonrpc: '2.0', id: 90, method: 'tools/call', params: { name: 'weird', arguments: { mode: 'progress' }, _meta: { progressToken: 'mine' } } });
  await l.client.reply(90);
  assert.equal(l.client.messages.filter((m) => m['method'] === 'notifications/progress').length, 1);
  await l.client.call('weird', { mode: 'progress' });
  assert.equal(l.client.messages.filter((m) => m['method'] === 'notifications/progress').length, 1);
  await finish(l);

  const l2 = startLib({ proxy: { allowServerNotifications: true } });
  await l2.client.handshake();
  await l2.client.call('weird', { mode: 'spoof' });
  assert.ok(l2.client.messages.some((m) => m['method'] === 'notifications/message'));
  await finish(l2);
});

test('W17 invalid server result shapes => tool_error; garbage and duplicate responses are dropped', async () => {
  const env = makeEnv();
  const l = startLib({ env });
  await l.client.handshake();
  for (const mode of ['both', 'noresult', 'strresult']) {
    assert.match(toolText(await l.client.call('weird', { mode })), /^Tool error \(decision /, mode);
  }
  assert.equal(toolText(await l.client.call('weird', { mode: 'garbage' })), 'after-garbage');
  assert.equal(toolText(await l.client.call('weird', { mode: 'dup' })), 'first');
  await sleep(100);
  assert.ok((l.stderrText().match(/proxy_orphan_response","kind":"server"/g) ?? []).length >= 2);
  await finish(l);
});

test('W10 caps: 65th+ concurrent call gets -32000 and proxy_busy with no server execution', async () => {
  const env = makeEnv();
  const l = startLib({ env });
  await l.client.handshake();
  const ps = Array.from({ length: 70 }, (_, i) => l.client.call('echo', { text: 'c' + String(i), delay_ms: 600 }, 2000 + i));
  const rs = await Promise.all(ps);
  const busy = rs.filter((r) => (r['error'] as Json | undefined)?.['code'] === -32000);
  assert.equal(busy.length, 6);
  assert.equal(rs.filter((r) => r['result'] !== undefined && !isErr(r)).length, 64);
  assert.equal(callCount(env, 'echo'), 64);
  assert.equal((l.stderrText().match(/"prysm":"proxy_busy"/g) ?? []).length, 6);
  await finish(l);
});

test('W11/W12/W13: ids 1 and "1" are distinct; tools/call notification dropped; only tracked calls are cancelled; extra params dropped', async () => {
  const env = makeEnv();
  const l = startLib({ env });
  await l.client.handshake();
  const [a, b] = await Promise.all([l.client.call('echo', { text: 'num', delay_ms: 200 }, 1), l.client.call('echo', { text: 'str', delay_ms: 200 }, '1')]);
  assert.equal(a['id'], 1); assert.equal(b['id'], '1');
  assert.equal(toolText(a), 'echo:num'); assert.equal(toolText(b), 'echo:str');
  l.client.send({ jsonrpc: '2.0', method: 'tools/call', params: { name: 'echo', arguments: { text: 'notif' } } });
  for (const requestId of ['prysm:1', 12345, 'nope', 1]) l.client.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId } });
  l.client.send({ jsonrpc: '2.0', id: 55, method: 'tools/call', params: { name: 'echo', arguments: { text: 'x' }, task: { evil: true }, extra: 1 } });
  await l.client.reply(55);
  assert.equal(callCount(env, 'echo'), 3);
  assert.ok(!serverMethods(env).some((m) => m['method'] === 'notifications/cancelled'));
  const last = serverMethods(env).filter((m) => m['method'] === 'tools/call').pop() as { params: Json };
  assert.deepEqual(Object.keys(last.params).sort(), ['arguments', 'name']);
  await finish(l);
});

test('W14 taint on dispatch: a timed-out or erroring taint tool still taints the session', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { taintTools: ['slow'], toolTimeoutMs: 300 } });
  await l.client.handshake();
  assert.match(toolText(await l.client.call('slow', {})), /^Tool timed out/);
  assert.ok(isErr(await mail(l)));
  assert.equal(callCount(env, 'send_email'), 0);
  await finish(l);
});

test('W15 initialize: capabilities rewritten to tools only, second initialize rejected, ping local', async () => {
  const env = makeEnv();
  const l = startLib({ env });
  const r = await l.client.request('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  const res = r['result'] as Json;
  assert.deepEqual(res['capabilities'], { tools: { listChanged: true } });
  assert.equal(res['instructions'], 'fixture instructions');
  assert.equal(res['protocolVersion'], '2025-03-26');
  assert.equal(((await l.client.request('initialize', {}))['error'] as Json)['code'], -32600);
  assert.deepEqual((await l.client.request('ping'))['result'], {});
  assert.ok(!serverMethods(env).some((m) => m['method'] === 'ping'));
  await finish(l);
});

test('W18/W19: unspawnable server => exit 3 without command text; server stderr is prefixed; stdout closed => exit 1', async () => {
  const l = startLib({ proxy: { server: { command: 'definitely-not-a-command-xyz-123' } } });
  assert.equal(await l.done, 3);
  assert.ok(!l.stderrText().includes('definitely-not'));

  const env = makeEnv();
  const l2 = startLib({ env, serverExtra: ['--stderr-forge'] });
  await l2.client.handshake();
  await waitFor(() => l2.stderrText().includes('head_seq'));
  await finish(l2);
  const forged = l2.stderrText().split('\n').filter((x) => x.includes('"head_seq":999'));
  assert.ok(forged.length === 1 && forged[0]?.startsWith('[server] '));

  const bad = new Writable({ write(_c, _e, cb) { cb(new Error('closed')); } });
  const l3 = startLib({ proxy: { clientOut: bad } });
  l3.client.send({ jsonrpc: '2.0', id: 1, method: 'ping' });
  assert.equal(await l3.done, 1);
});

test('audit store rows exist for hidden-tool denials and verify stays ok across v1.1 paths', async () => {
  const env = makeEnv();
  const l = startLib({ env });
  await l.client.handshake();
  await l.client.call('echo', { text: 'a' });
  await finish(l);
  const s = openAudit(env);
  assert.equal(s.verify().ok, true);
  assert.ok(rowsOf(s).length >= 3);
  s.close();
});
