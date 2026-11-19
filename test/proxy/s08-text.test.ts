// S-08: model-visible text from the server: initialize instructions dropped by default, tool text capped.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { makeEnv, startLib } from '../support/proxy-kit.ts';
import type { Lib } from '../support/proxy-kit.ts';
import { cleanup } from '../support/tmp.ts';

after(cleanup);
type Json = Record<string, unknown>;
const finish = async (l: Lib): Promise<number> => { l.client.end(); return l.done; };

test('S-08: initialize instructions are dropped by default and reported on the sink', async () => {
  const l = startLib({ env: makeEnv() });
  const r = await l.client.request('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'c', version: '1' } });
  assert.equal((r['result'] as Json)['instructions'], undefined);
  await finish(l);
  assert.match(l.stderrText(), /"prysm":"proxy_instructions_dropped"/);
});

test('S-08: --forward-instructions passes them through (operator opt-in)', async () => {
  const l = startLib({ env: makeEnv(), proxy: { forwardInstructions: true } });
  const r = await l.client.request('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'c', version: '1' } });
  assert.equal((r['result'] as Json)['instructions'], 'fixture instructions');
  await finish(l);
});
