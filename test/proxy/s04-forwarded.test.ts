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

test('S-04: an error result from the server does not taint', async () => {
  const env = makeEnv();
  const l = startLib({ env, proxy: { allowMethods: ['resources/hang'], forwardTimeoutMs: 300 } });
  await l.client.handshake();
  const r = await l.client.request('resources/hang', {});
  assert.ok(r['error'] !== undefined);
  assert.equal(isErr(await l.client.call('send_email', { to: 'b@example.com' })), false);
  await finish(l);
});
