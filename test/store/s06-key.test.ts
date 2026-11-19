// S-06: the key is written only after its file is protected; an unprotected key can be refused (the proxy does so).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, writeFileSync, chmodSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { openStore, StoreError, evaluateAcl } from '../../src/store/index.ts';
import { cleanup, tmpDir, dbPath } from '../support/tmp.ts';
import { makeEnv, startLib } from '../support/proxy-kit.ts';

after(cleanup);

test('S-06: key creation leaves no temporary file and produces a 32-byte key', () => {
  const dir = tmpDir();
  const path = dbPath(dir);
  const keyDir = tmpDir();
  const keyPath = dbPath(keyDir, 'k.key');
  const s = openStore({ path, keyPath });
  s.close();
  assert.equal(readFileSync(keyPath).length, 32);
  assert.deepEqual(readdirSync(keyDir).filter((f) => f.includes('.tmp-')), []);
  // reopening reuses the same key (no regeneration)
  const s2 = openStore({ path, keyPath });
  assert.ok(s2.keyProtection() !== 'external');
  s2.close();
});

test('S-06: requireProtectedKey refuses to create a key it cannot protect, and leaves nothing behind', () => {
  const keyDir = tmpDir();
  const keyPath = dbPath(keyDir, 'k.key');
  assert.throws(() => openStore({ path: dbPath(tmpDir()), keyPath, keyProtect: () => 'unprotected', requireProtectedKey: true }),
    (e: unknown) => e instanceof StoreError && e.code === 'key_unprotected');
  assert.equal(existsSync(keyPath), false);
  assert.deepEqual(readdirSync(keyDir), []);
});

test('S-06: requireProtectedKey refuses an existing unprotected key; without it the library only warns', () => {
  const path = dbPath(tmpDir());
  const keyPath = dbPath(tmpDir(), 'k.key');
  openStore({ path, keyPath, keyProtect: () => 'acl' }).close();
  assert.throws(() => openStore({ path, keyPath, keyProtect: () => 'unprotected', requireProtectedKey: true }),
    (e: unknown) => e instanceof StoreError && e.code === 'key_unprotected');
  const s = openStore({ path, keyPath, keyProtect: () => 'unprotected' });
  assert.ok(s.verify().warnings.some((w) => w.code === 'key_unprotected'));
  s.close();
});

/** Makes a real key file readable by everyone (the condition S-06 is about), on this platform. */
function makeWorldReadable(keyPath: string): boolean {
  writeFileSync(keyPath, randomBytes(32));
  if (process.platform !== 'win32') {
    chmodSync(keyPath, 0o644);
    return true;
  }
  const r = spawnSync('icacls', [keyPath, '/grant', '*S-1-1-0:(R)'], { windowsHide: true }); // S-1-1-0 = Everyone
  return r.status === 0;
}

test('S-06: the proxy refuses to start on an unprotected key file unless --allow-unprotected-key', (t) => {
  const env = makeEnv();
  if (!makeWorldReadable(env.keyPath)) {
    t.skip('could not widen the key file ACL on this account');
    return;
  }
  const viaKeyFile = { hmacKey: undefined, keyPath: env.keyPath };
  assert.throws(() => startLib({ env, proxy: viaKeyFile }), /key_unprotected/);
  const l = startLib({ env, proxy: { ...viaKeyFile, allowUnprotectedKey: true } });
  l.client.end();
  return l.done.then((code) => assert.equal(code, 0));
});

test('S-06 / DEC-49: the icacls output captured on a GitHub Windows runner is judged protected', () => {
  // verbatim from CI run 44552941737 (temporary diagnostic step): SYSTEM and Administrators are explicit entries there
  const keyPath = 'C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\prysm-diag-jZ6Ufm\\k.key';
  const output = 'C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\prysm-diag-jZ6Ufm\\k.key NT AUTHORITY\\SYSTEM:(F)\n                                                             BUILTIN\\Administrators:(F)\n                                                             runnervmm7ud1\\runneradmin:(R,W)\n\nSuccessfully processed 1 files; Failed processing 0 files\r\n';
  assert.equal(evaluateAcl(output, keyPath, 'runneradmin'), true);
  assert.equal(evaluateAcl(output.replace('runneradmin:(R,W)', 'runneradmin:(R,W)' + '\\n   BUILTIN\\\\Users:(R)'), keyPath, 'runneradmin'), false);
});
