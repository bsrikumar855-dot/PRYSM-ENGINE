import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// QA M6 F1: client EOF racing a crashing server must not wait out the 30 s forward timeout.
test('client EOF while a pending forward targets a dying server shuts down promptly', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'prysm-proxy-eof-'));
  try {
    const args = [
      resolve('src/proxy/bin.ts'), '--policy', resolve('eval/policies/support-agent.policy.json'),
      '--db', join(dir, 'a.db'), '--key-path', join(dir, 'a.key'),
      '--', process.execPath, '-e', 'setTimeout(() => process.exit(5), 300)',
    ];
    const child = spawn(process.execPath, args, { stdio: ['pipe', 'ignore', 'ignore'] });
    const t0 = Date.now();
    const code = await new Promise<number | null>((res) => {
      child.on('close', res);
      child.stdin.end('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}\n');
    });
    assert.ok(Date.now() - t0 < 10_000, 'shutdown took ' + String(Date.now() - t0) + ' ms');
    assert.ok(code === 0 || code === 1, 'exit ' + String(code));
  } finally {
    try { rmSync(dir, { recursive: true, force: true, maxRetries: 5 }); } catch { /* best effort */ }
  }
});
