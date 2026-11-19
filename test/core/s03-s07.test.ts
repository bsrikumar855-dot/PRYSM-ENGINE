// POLICY-SPEC section 14 (DEC-45): S-03 backslash paths and S-07 case variants against deny rules.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide } from '../../src/core/index.ts';
import { mk, permit, deny, req } from './helpers.ts';

const pw = (root: string, ci: boolean) => ({ tools: ['read_file'], args: { path: { path_within: { root, case_insensitive: ci } } } });
const policy = mk([permit('p.work', pw('/work', false)), deny('d.secret', pw('/work/secret', false))]);
const effect = (path: string): string => decide(policy, req('read_file', { path })).effect;
const reason = (path: string): string => decide(policy, req('read_file', { path })).reason_code;

test('S-03: the review bypass is closed: a backslash outside a drive-letter path is unparseable, so the deny rule matches', () => {
  // POSIX reads this as one file name inside /work/secret; it must not normalise to /work/tmp and be permitted
  assert.equal(effect('/work/secret/a\\..\\..\\tmp'), 'deny');
  assert.equal(reason('/work/secret/a\\..\\..\\tmp'), 'denied_by_rule');
  for (const v of ['/work\\a.txt', '\\work\\a.txt', '/work/x\\y']) assert.equal(effect(v), 'deny', v);
});

test('S-03: drive-letter paths keep the backslash as a separator', () => {
  const win = mk([permit('p.w', pw('C:/work', false)), deny('d.s', pw('C:/work/secret', false))]);
  assert.equal(decide(win, req('read_file', { path: 'C:\\work\\a.txt' })).effect, 'permit');
  assert.equal(decide(win, req('read_file', { path: 'c:\\work\\secret\\k' })).effect, 'deny');
  assert.equal(decide(win, req('read_file', { path: 'C:\\work\\..\\secret\\k' })).effect, 'deny');
});

test('S-07: a deny rule folds case even when case_insensitive is false; a permit rule keeps the author\'s choice', () => {
  for (const v of ['/work/SECRET/k', '/work/Secret/k', '/WORK/SECRET/k']) assert.equal(reason(v), 'denied_by_rule', v);
  assert.equal(effect('/work/secret/k'), 'deny');
  assert.equal(effect('/work/public/k'), 'permit');
  assert.equal(effect('/WORK/public/k'), 'deny'); // permit rule is case-sensitive: no match, default deny
});

test('S-07: an uppercase deny root still matches lowercase and mixed-case values', () => {
  const p = mk([permit('p.work', pw('/work', false)), deny('d.up', pw('/work/SECRET', false))]);
  for (const v of ['/work/secret/k', '/work/SECRET/k', '/work/SeCrEt/k']) assert.equal(decide(p, req('read_file', { path: v })).effect, 'deny', v);
});
