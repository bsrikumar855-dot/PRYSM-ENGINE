// S-08: model-visible text from the server: initialize instructions dropped by default, tool text capped.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { makeEnv, startLib } from '../support/proxy-kit.ts';
import type { Lib } from '../support/proxy-kit.ts';
import { cleanup } from '../support/tmp.ts';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

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

test('S-08 / F10: initialize passes only protocolVersion, tools capability and capped serverInfo', async () => {
  const l = startLib({ env: makeEnv() });
  const r = await l.client.request('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'c', version: '1' } });
  assert.deepEqual(Object.keys(r['result'] as Json).sort(), ['capabilities', 'protocolVersion', 'serverInfo']);
  assert.deepEqual((r['result'] as Json)['serverInfo'], { name: 'fixture', version: '0' });
  await finish(l);
});

test('S-08 / F10: nested schema text is capped, the cut never splits a surrogate pair, oversize schemas are not listed', async () => {
  const env = makeEnv();
  const control = join(env.dir, 'control.json');
  const emoji = String.fromCodePoint(0x1f600); // two UTF-16 units
  writeFileSync(control, JSON.stringify({
    descriptions: { echo: 'a'.repeat(4095) + emoji + 'tail' },
    add: [
      { name: 'deep_tool', description: 'd', inputSchema: { type: 'object', properties: { x: { type: 'string', description: 'x'.repeat(5000) } } } },
      { name: 'huge_tool', description: 'h', inputSchema: { type: 'object', properties: Object.fromEntries(Array.from({ length: 40 }, (_, i) => ['p' + i, { type: 'string', description: 'y'.repeat(2000) }])) } },
    ],
  }));
  const l = startLib({ env, serverExtra: ['--control', control], proxy: { listMode: 'show' } });
  const tools = (await l.client.handshake()) as unknown as Json[];
  const byName = (n: string): Json | undefined => tools.find((t) => t['name'] === n);
  const echo = byName('echo');
  assert.equal((echo?.['description'] as string).length, 4095, 'the cut lands before the surrogate pair, not inside it');
  const deep = byName('deep_tool');
  const xd = (((deep?.['inputSchema'] as Json)['properties'] as Json)['x'] as Json)['description'] as string;
  assert.equal(xd.length, 4096);
  assert.equal(byName('huge_tool'), undefined, 'a schema larger than 64 KiB after capping is not listed');
  await finish(l);
  assert.match(l.stderrText(), /"prysm":"proxy_tool_ignored","reason":"oversize","n":1/);
  assert.match(l.stderrText(), /"prysm":"proxy_tool_text_capped"/);
});
