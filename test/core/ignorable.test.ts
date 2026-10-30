import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadCode } from './helpers.ts';

const mkName = (s: string) => `{"policy_schema_version":1,"name":"${s}","mode":"enforce","tools":{},"rules":[]}`;
const esc = (cp: number) => String.fromCharCode(92) + 'u' + cp.toString(16).padStart(4, '0');

test('Default_Ignorable_Code_Point and Hangul/braille fillers are rejected in policy strings', () => {
  for (const cp of [0x115f, 0x1160, 0x3164, 0xffa0, 0x2800, 0x180b, 0x180e, 0x2062, 0x2064, 0x00ad, 0x034f, 0xfe0f, 0x17b4, 0x17b5]) {
    assert.equal(loadCode(mkName('a' + esc(cp) + 'b')), 'forbidden_char', cp.toString(16));
  }
  // the same code points inside a rule id / tool name are rejected too
  const doc = (id: string) => `{"policy_schema_version":1,"name":"n","mode":"enforce","tools":{},"rules":[{"id":"${id}","effect":"deny","reason_code":"x","match":{}}]}`;
  assert.notEqual(loadCode(doc('a' + esc(0x3164))), 'OK');
  assert.notEqual(loadCode(doc('a' + esc(0x2800))), 'OK');
  // ordinary text still loads
  assert.equal(loadCode(mkName('plain-name')), 'OK');
});
