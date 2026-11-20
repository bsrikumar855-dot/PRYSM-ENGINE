// DEC-53 as revised after the second review (N2 / C): the key-file principal comes from the process token, not the
// environment; M2-22a: OTHERDOM\<same name> is never taken for the current user on Windows.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { userInfo } from 'node:os';
import { spawnSync } from 'node:child_process';
import { openStore, currentAclUser, parseWhoami } from '../../src/store/index.ts';
import { tmpDir, cleanup, dbPath } from '../support/tmp.ts';

after(cleanup);

const aclOut = (kp: string, lines: string[]) =>
  [kp + ' ' + lines[0], ...lines.slice(1).map((l) => '                 ' + l), '', 'Successfully processed 1 files; Failed processing 0 files', ''].join('\r\n');

test('parseWhoami accepts exactly one "domain\\user","SID" line', () => {
  assert.deepEqual(parseWhoami('"host\\alice","S-1-5-21-1-2-3-1001"\r\n'), { name: 'host\\alice', sid: 'S-1-5-21-1-2-3-1001' });
  assert.deepEqual(parseWhoami('"azuread\\alice smith","S-1-12-1-11-22-33-44"'), { name: 'azuread\\alice smith', sid: 'S-1-12-1-11-22-33-44' });
  for (const bad of ['', 'alice', '"alice","S-1-5-21-1"', '"host\\alice","not-a-sid"', '"host\\alice","S-1-5-21-1"\n"x\\y","S-1-5-1"', '"a\\b\\c","S-1-5-1"']) {
    assert.equal(parseWhoami(bad), null, JSON.stringify(bad));
  }
});

test('Windows: the principal is the token user and does not follow USERDOMAIN or USERNAME', { skip: process.platform !== 'win32' }, () => {
  const fromToken = parseWhoami(spawnSync((process.env['SystemRoot'] ?? 'C:\\Windows') + '\\System32\\whoami.exe', ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8' }).stdout);
  assert.ok(fromToken !== null);
  const saved = { d: process.env['USERDOMAIN'], n: process.env['USERNAME'] };
  try {
    process.env['USERDOMAIN'] = 'OTHERDOM';
    process.env['USERNAME'] = 'mallory';
    assert.equal(currentAclUser(), fromToken.name);
    delete process.env['USERDOMAIN'];
    assert.equal(currentAclUser(), fromToken.name, 'no silent fallback to a bare name');
  } finally {
    if (saved.d === undefined) delete process.env['USERDOMAIN']; else process.env['USERDOMAIN'] = saved.d;
    if (saved.n === undefined) delete process.env['USERNAME']; else process.env['USERNAME'] = saved.n;
  }
});

test('Windows / M2-22a: a key whose only entry is OTHERDOM\\<same user name> is unprotected', { skip: process.platform !== 'win32' }, () => {
  const me = currentAclUser() as string;
  const bare = me.slice(me.indexOf('\\') + 1);
  assert.equal(bare.toLowerCase(), userInfo().username.toLowerCase());
  const keyPath = dbPath(tmpDir(), 'k.key');
  const other = openStore({ path: dbPath(tmpDir()), keyPath, aclReader: (kp) => aclOut(kp, ['OTHERDOM\\' + bare + ':(R,W)']) });
  assert.equal(other.keyProtection(), 'unprotected');
  other.close();
  const mine = openStore({ path: dbPath(tmpDir()), keyPath, aclReader: (kp) => aclOut(kp, [me.toUpperCase() + ':(R,W)']) });
  assert.equal(mine.keyProtection(), 'acl');
  mine.close();
});
