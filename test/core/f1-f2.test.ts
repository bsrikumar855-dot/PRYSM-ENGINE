// Security re-review F1 (unparseable explanation) and F2 (drive letter on one side only), POLICY-SPEC 14.4.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide } from '../../src/core/index.ts';
import { mk, permit, deny, req } from './helpers.ts';
import { refDecide, refLoadPolicy } from '../../eval/reference/index.ts';
import { policyDoc } from './helpers.ts';

const pw = (root: string) => ({ path_within: { root, case_insensitive: false } });

test('F1: a rule that genuinely matched is never explained as "could not be interpreted"', () => {
  const p = mk([
    deny('d.tags', { tools: ['tag_item'], args: { tags: pw('/workspace/secrets') } }),
    deny('d.mail', { tools: ['send_email'], args: { subject: pw('/workspace/secrets'), to: { domain_suffix: 'example.com', accept: ['email'] } } }),
  ]);
  // a real secrets value plus a junk element, in either order
  for (const tags of [['/workspace/secrets/api_key.txt', 'notes\\x.txt'], ['relative.txt', '/workspace/secrets/api_key.txt']]) {
    const d = decide(p, req('tag_item', { tags }));
    assert.equal(d.reason_code, 'denied_by_rule', JSON.stringify(tags));
    assert.deepEqual(d.matched_unparseable, [], JSON.stringify(tags));
  }
  // a real path match plus an uninterpretable value in another predicate of the same rule
  const m = decide(p, req('send_email', { to: 'bob@exämple.com', subject: '/workspace/secrets/k', body: 'b' }));
  assert.equal(m.reason_code, 'denied_by_rule');
  assert.deepEqual(m.matched_unparseable, []);
  // only uninterpretable values: still explained that way
  const u = decide(p, req('tag_item', { tags: ['relative.txt', 'notes\\x.txt'] }));
  assert.equal(u.reason_code, 'denied_by_rule');
  assert.deepEqual(u.matched_unparseable, ['d.tags']);
});

test('F2: a deny root with a drive letter also covers the same path without one (and the reverse)', () => {
  const win = mk([permit('p.all', { tools: ['read_file'] }), deny('d.win', { tools: ['read_file'], args: { path: pw('C:/Windows') } })]);
  const eff = (path: string): string => decide(win, req('read_file', { path })).effect;
  for (const v of ['/Windows/System32/config/SAM', '/windows/x', '/Windows']) assert.equal(eff(v), 'deny', v);
  for (const v of ['/WindowsOld/x', '/work/x', 'D:/Windows/x']) assert.equal(eff(v), 'permit', v);
  const d = decide(win, req('read_file', { path: '/Windows/System32/config/SAM' }));
  assert.deepEqual(d.matched_unparseable, ['d.win'], 'explained as an uncertain match, not a certain one');

  const posix = mk([permit('p.all', { tools: ['read_file'] }), deny('d.posix', { tools: ['read_file'], args: { path: pw('/workspace/secrets') } })]);
  assert.equal(decide(posix, req('read_file', { path: 'C:/workspace/secrets/k' })).effect, 'deny');
  assert.equal(decide(posix, req('read_file', { path: 'C:/workspace/public/k' })).effect, 'permit');

  const driveRoot = mk([permit('p.all', { tools: ['read_file'] }), deny('d.c', { tools: ['read_file'], args: { path: pw('C:/') } })]);
  assert.equal(decide(driveRoot, req('read_file', { path: '/anything' })).effect, 'deny');
  assert.equal(decide(driveRoot, req('read_file', { path: 'D:/anything' })).effect, 'permit');
});

test('F2: permit rules are unchanged: a drive letter on one side only never matches', () => {
  const p = mk([permit('p.w', { tools: ['read_file'], args: { path: pw('C:/work') } })]);
  assert.equal(decide(p, req('read_file', { path: '/work/a' })).effect, 'deny');
  assert.equal(decide(p, req('read_file', { path: 'C:/work/a' })).effect, 'permit');
});

test('F2: the reference implementation agrees on these cases', () => {
  const docs = [
    { rules: [permit('p.all', { tools: ['read_file'] }), deny('d.win', { tools: ['read_file'], args: { path: pw('C:/Windows') } })] },
    { rules: [permit('p.all', { tools: ['read_file'] }), deny('d.posix', { tools: ['read_file'], args: { path: pw('/workspace/secrets') } })] },
    { rules: [permit('p.all', { tools: ['read_file'] }), deny('d.c', { tools: ['read_file'], args: { path: pw('C:/') } })] },
  ];
  const values = ['/Windows/System32/x', '/WindowsOld/x', 'C:/workspace/secrets/k', 'c:/WORKSPACE/Secrets', 'C:/workspace/public', '/anything', 'D:/anything', '/'];
  for (const d of docs) {
    const p = mk(d.rules);
    for (const v of values) {
      const prod = decide(p, req('read_file', { path: v }));
      const ref = refDecide(refLoadPolicy(JSON.stringify(policyDoc(d.rules))), req('read_file', { path: v }));
      assert.equal(prod.effect, ref.effect, `${d.rules[1]?.id} ${v}`);
    }
  }
});
