// Temp-dir helper; tolerates Windows WAL handle lingering on cleanup.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dirs: string[] = [];

export function tmpDir(prefix = 'prysm-test-'): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}

export function cleanup(): void {
  for (const d of dirs.splice(0)) {
    for (let i = 0; i < 5; i++) {
      try {
        rmSync(d, { recursive: true, force: true });
        break;
      } catch {
        /* handle still held; retry once more then give up */
      }
    }
  }
}

export function dbPath(dir: string, name = 'audit.db'): string {
  return join(dir, name);
}
