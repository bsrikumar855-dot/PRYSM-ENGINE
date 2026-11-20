// S-06: the key is written only after its file is protected; an unprotected key can be refused (the proxy does so).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, writeFileSync, chmodSync, existsSync, unlinkSync, utimesSync } from 'node:fs';
import { dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { openStore, StoreError, evaluateAcl } from '../../src/store/index.ts';
import { cleanup, tmpDir, dbPath } from '../support/tmp.ts';
import { makeEnv, startLib, openAudit, rowsOf } from '../support/proxy-kit.ts';

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
  return l.done.then((code) => {
    assert.equal(code, 0);
    // the opt-out is visible: a sink line, and the audited posture row records the flag and the real protection
    assert.match(l.stderrText(), /"prysm":"proxy_key_unprotected"/);
    const s = openAudit(env, true);
    const rows = rowsOf(s);
    const cfg = rows.map((r) => r.outcome as Record<string, unknown> | null).find((o) => o?.['event'] === 'proxy_config');
    assert.equal(cfg?.['allow_unprotected_key'], true);
    assert.equal(cfg?.['key_protection'], 'unprotected');
    s.close();
  });
});

test('S-06 / DEC-49: the icacls output captured on a GitHub Windows runner is judged protected', () => {
  // verbatim from CI run 44552941737 (temporary diagnostic step): SYSTEM and Administrators are explicit entries there
  const keyPath = 'C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\prysm-diag-jZ6Ufm\\k.key';
  const output = 'C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\prysm-diag-jZ6Ufm\\k.key NT AUTHORITY\\SYSTEM:(F)\n                                                             BUILTIN\\Administrators:(F)\n                                                             runnervmm7ud1\\runneradmin:(R,W)\n\nSuccessfully processed 1 files; Failed processing 0 files\r\n';
  assert.equal(evaluateAcl(output, keyPath, 'runneradmin'), true);
  // a real extra line (not the two characters backslash-n) granting BUILTIN\Users must make it unprotected
  const widened = output.replace('runneradmin:(R,W)', 'runneradmin:(R,W)\n                                                             BUILTIN\\Users:(R)');
  assert.notEqual(widened, output);
  assert.equal(evaluateAcl(widened, keyPath, 'runneradmin'), false);
});

test('S-06 / F4: a protected key file that already exists opens a NEW database under requireProtectedKey', () => {
  const keyPath = dbPath(tmpDir(), 'k.key');
  openStore({ path: dbPath(tmpDir()), keyPath }).close(); // creates and protects the key with the real OS mechanism
  const s = openStore({ path: dbPath(tmpDir()), keyPath, requireProtectedKey: true }); // fresh DB, existing key
  assert.notEqual(s.keyProtection(), 'unprotected');
  assert.equal(s.verify().warnings.some((w) => w.code === 'key_unprotected'), false);
  s.close();
});

test('S-06 / F4: an unprotected key file that already exists is refused for a NEW database too', () => {
  const keyPath = dbPath(tmpDir(), 'k.key');
  writeFileSync(keyPath, randomBytes(32));
  assert.throws(() => openStore({ path: dbPath(tmpDir()), keyPath, keyProtect: () => 'unprotected', requireProtectedKey: true }),
    (e: unknown) => e instanceof StoreError && e.code === 'key_unprotected');
  const s = openStore({ path: dbPath(tmpDir()), keyPath, keyProtect: (kp) => (kp === keyPath ? 'acl' : 'unprotected') });
  assert.equal(s.keyProtection(), 'acl', 'judged on the key file itself');
  s.close();
});

test('S-06 / F4: when another process links its key first, that key file (not our temp file) is judged', () => {
  const keyPath = dbPath(tmpDir(), 'k.key');
  const theirs = randomBytes(32);
  const judged: string[] = [];
  const keyProtect = (kp: string) => {
    judged.push(kp);
    if (kp !== keyPath) {
      writeFileSync(keyPath, theirs, { flag: 'wx' }); // the other creator wins the race while we protect our temp file
      return 'acl' as const;
    }
    return 'unprotected' as const;
  };
  assert.throws(() => openStore({ path: dbPath(tmpDir()), keyPath, keyProtect, requireProtectedKey: true }),
    (e: unknown) => e instanceof StoreError && e.code === 'key_unprotected');
  assert.ok(judged.includes(keyPath), 'the winning key file was checked');
  assert.deepEqual(readFileSync(keyPath), theirs, 'their key was not replaced');
  assert.deepEqual(readdirSync(dirname(keyPath)).filter((f) => f.includes('.tmp-')), []);
});

test('S-06 / F5: a temp file swapped after it was protected is never linked into place', () => {
  const keyPath = dbPath(tmpDir(), 'k.key');
  const keyProtect = (kp: string) => {
    if (kp !== keyPath) { unlinkSync(kp); writeFileSync(kp, 'planted', { flag: 'wx' }); }
    return 'acl' as const;
  };
  assert.throws(() => openStore({ path: dbPath(tmpDir()), keyPath, keyProtect }),
    (e: unknown) => e instanceof StoreError && e.code === 'io');
  assert.equal(existsSync(keyPath), false);
  assert.deepEqual(readdirSync(dirname(keyPath)), []);
});

test('S-06 / F6: a key temp file left by a crash is removed when a new key is created; recent and unrelated files stay', () => {
  const dir = tmpDir();
  const keyPath = dbPath(dir, 'k.key');
  const old = keyPath + '.tmp-0123456789ab';
  const recent = keyPath + '.tmp-ba9876543210';
  const other = keyPath + '.tmp-notahexname';
  for (const f of [old, recent, other]) writeFileSync(f, randomBytes(32));
  const past = new Date(Date.now() - 3600_000);
  utimesSync(old, past, past);
  openStore({ path: dbPath(tmpDir()), keyPath }).close();
  assert.equal(existsSync(old), false);
  assert.equal(existsSync(recent), true);
  assert.equal(existsSync(other), true);
});

test('S-06 / F4: the proxy starts on a NEW database with a protected key file that already exists', () => {
  const env = makeEnv();
  openStore({ path: dbPath(tmpDir()), keyPath: env.keyPath }).close(); // protected key, different database
  const l = startLib({ env, proxy: { hmacKey: undefined, keyPath: env.keyPath } });
  l.client.end();
  return l.done.then((code) => assert.equal(code, 0));
});
