// S-04: requests the operator allow-lists are audited, and their results taint the session by default.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { makeEnv, startLib, openAudit, rowsOf, callCount } from '../support/proxy-kit.ts';
import type { Lib } from '../support/proxy-kit.ts';
import { cleanup } from '../support/tmp.ts';

after(cleanup);

type Json = Record<string, unknown>;
const finish = async (l: Lib): Promise<number> => {
  l.client.end();
  return l.done;
};

const isErr = (r: Json): boolean => (r['result'] as Json | undefined)?.['isError'] === true || r['error'] !== undefined;

test('S-04: a forwarded allow-listed request writes a method_forwarded row and taints the session', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { allowMethods: ['resources/list'] } });
  await l.client.handshake();
  assert.equal(isErr(await l.client.call('send_email', { to: 'a@example.com' })), false, 'permitted before any forwarded content');
  const r = await l.client.request('resources/list', {});
  assert.deepEqual(r['result'], { resources: [] });
  assert.equal(isErr(await l.client.call('send_email', { to: 'b@example.com' })), true, 'outbound call denied after forwarded content');
  assert.equal(callCount(env, 'send_email'), 1);
  await finish(l);
  const s = openAudit(env);
  const rows = rowsOf(s);
  const fwd = rows.filter((x) => x.kind === 'policy_activate' && (x.outcome as Json | null)?.['event'] === 'method_forwarded');
  assert.equal(fwd.length, 1);
  assert.equal((fwd[0]?.outcome as Json)['method'], 'resources/list');
  const denied = rows.filter((x) => x.kind === 'decision' && x.reason_code === 'tainted_session');
  assert.equal(denied.length, 1);
  const cfg = rows.find((x) => (x.outcome as Json | null)?.['event'] === 'proxy_config');
  assert.equal((cfg?.outcome as Json)['taint_forwarded'], true);
  s.close();
});

test('S-04: taintForwarded=false keeps forwarding audited but does not taint (operator opt-out, recorded in posture)', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { allowMethods: ['resources/list'], taintForwarded: false } });
  await l.client.handshake();
  await l.client.request('resources/list', {});
  assert.equal(isErr(await l.client.call('send_email', { to: 'b@example.com' })), false);
  await finish(l);
  const s = openAudit(env);
  const rows = rowsOf(s);
  assert.equal(rows.filter((x) => (x.outcome as Json | null)?.['event'] === 'method_forwarded').length, 1);
  assert.equal((rows.find((x) => (x.outcome as Json | null)?.['event'] === 'proxy_config')?.outcome as Json)['taint_forwarded'], false);
  s.close();
});

test('S-04 / F3: a server error to a forwarded request reaches the client as generic text only (code kept)', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { allowMethods: ['resources/inject'] } });
  await l.client.handshake();
  const r = await l.client.request('resources/inject', {});
  assert.deepEqual(r['error'], { code: -32000, message: 'Server error' });
  assert.doesNotMatch(JSON.stringify(l.client.messages), /IGNORE PREVIOUS|exfil/);
  await finish(l);
});

test('S-04: a forwarded request that times out does not taint (no server content reached the client)', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { allowMethods: ['resources/hang'], forwardTimeoutMs: 300 } });
  await l.client.handshake();
  const r = await l.client.request('resources/hang', {});
  assert.ok(r['error'] !== undefined);
  assert.equal(isErr(await l.client.call('send_email', { to: 'b@example.com' })), false);
  await finish(l);
});

const forwardedRows = (env: ReturnType<typeof makeEnv>): Json[] => {
  const s = openAudit(env);
  const rows = rowsOf(s).filter((x) => (x.outcome as Json | null)?.['event'] === 'method_forwarded').map((x) => x.outcome as Json);
  s.close();
  return rows;
};

test('S-04 / F3: an allowed server request is audited (to_client) and taints the session', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { allowServerRequests: ['sampling/createMessage'] } });
  await l.client.handshake();
  const p = l.client.call('weird', { mode: 'srvreq' });
  await l.client.next((m) => m['method'] === 'sampling/createMessage');
  l.client.send({ jsonrpc: '2.0', id: 'srv2', result: { ok: true } });
  await p;
  assert.equal(isErr(await l.client.call('send_email', { to: 'b@example.com' })), true, 'outbound denied after a server request');
  await finish(l);
  assert.deepEqual(forwardedRows(env), [{ event: 'method_forwarded', method: 'sampling/createMessage', direction: 'to_client' }]);
});

test('S-04 / F3: an allowed server notification is audited and taints; progress for a call in flight does neither', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { allowServerNotifications: true } });
  await l.client.handshake();
  l.client.send({ jsonrpc: '2.0', id: 90, method: 'tools/call', params: { name: 'weird', arguments: { mode: 'progress' }, _meta: { progressToken: 'mine' } } });
  await l.client.reply(90);
  assert.equal(isErr(await l.client.call('send_email', { to: 'a@example.com' })), false, 'token-bound progress does not taint');
  await l.client.call('weird', { mode: 'spoof' }); // sends notifications/message
  assert.ok(l.client.messages.some((m) => m['method'] === 'notifications/message'));
  assert.equal(isErr(await l.client.call('send_email', { to: 'b@example.com' })), true, 'outbound denied after a server notification');
  await finish(l);
  const rows = forwardedRows(env);
  assert.ok(rows.some((o) => o['method'] === 'notifications/message' && o['direction'] === 'to_client'));
  assert.ok(rows.every((o) => o['direction'] === 'to_client'));
});

test('S-08 / F10: progress for a call in flight is passed on as numbers only (free-text message dropped)', async () => {
  const env = makeEnv();
  const l = startLib({ env });
  await l.client.handshake();
  l.client.send({ jsonrpc: '2.0', id: 91, method: 'tools/call', params: { name: 'weird', arguments: { mode: 'progressmsg' }, _meta: { progressToken: 'mine' } } });
  await l.client.reply(91);
  const pr = l.client.messages.filter((m) => m['method'] === 'notifications/progress');
  assert.equal(pr.length, 1);
  assert.deepEqual(pr[0]?.['params'], { progressToken: 'mine', progress: 1, total: 2 });
  await finish(l);
});

test('S-09 / F9: throttled lines are counted per side and the count is written at shutdown', async () => {
  const l = startLib({});
  await l.client.handshake();
  for (let i = 0; i < 25; i++) l.client.send({ jsonrpc: '2.0', id: 'orphan-' + i, result: {} });
  await l.client.call('weird', { mode: 'spoof' }); // the server sends orphan responses of its own
  await finish(l);
  const lines = l.stderrText().split('\n').filter((x) => x.startsWith('{"prysm"')).map((x) => JSON.parse(x) as Json);
  const orphans = (k: string): number => lines.filter((x) => x['prysm'] === 'proxy_orphan_response' && x['kind'] === k).length;
  assert.equal(orphans('client'), 20, 'client lines capped at 20 per window');
  assert.ok(orphans('server') >= 1, 'a client flood does not silence the server side');
  const sup = lines.filter((x) => x['prysm'] === 'proxy_lines_suppressed');
  assert.deepEqual(sup, [{ prysm: 'proxy_lines_suppressed', kind: 'proxy_orphan_response', sub: 'client', n: 5 }]);
});

test('second review N6.4: an allow-listed client notification forwarded to the server is audited (to_server), without taint', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { allowMethods: ['notifications/roots/list_changed'] } });
  await l.client.handshake();
  l.client.send({ jsonrpc: '2.0', method: 'notifications/roots/list_changed' });
  assert.equal(isErr(await l.client.call('send_email', { to: 'a@example.com' })), false, 'no taint from a client notification');
  await finish(l);
  assert.deepEqual(forwardedRows(env), [{ event: 'method_forwarded', method: 'notifications/roots/list_changed', direction: 'to_server' }]);
});
