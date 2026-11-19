// Temp-dir helper; tolerates Windows WAL handle lingering on cleanup.
import { mkdtempSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dirs: string[] = [];

// M5-05: a directory whose SQLite file is still open cannot be removed on Windows, so a run can leave a few behind.
// Each test process sweeps this project's own test directories that are more than an hour old (exact prefixes only;
// the age check keeps a concurrent run's directories safe). The sample app's `prysm-support-agent-*` directory is
// kept on purpose for inspection and is not swept.
const SWEPT_PREFIXES = ['prysm-test-', 'prysm-report-', 'prysm-proxy-', 'prysm-proxy-eof-', 'prysm-sec-'];
let swept = false;
function sweepStale(): void {
  if (swept) return;
  swept = true;
  try {
    const root = tmpdir();
    const cutoff = Date.now() - 60 * 60_000;
    for (const name of readdirSync(root)) {
      if (!SWEPT_PREFIXES.some((p) => name.startsWith(p) && /^[A-Za-z0-9]{6}$/.test(name.slice(p.length)))) continue;
      const p = join(root, name);
      try {
        const st = statSync(p);
        if (st.isDirectory() && st.mtimeMs < cutoff) rmSync(p, { recursive: true, force: true, maxRetries: 2, retryDelay: 20 });
      } catch { /* in use or gone: next run */ }
    }
  } catch { /* best effort */ }
}

export function tmpDir(prefix = 'prysm-test-'): string {
  sweepStale();
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}

export function cleanup(): void {
  for (const d of dirs.splice(0)) {
    try {
      rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    } catch {
      /* handle still held by an unclosed store: the next run's sweep removes it */
    }
  }
}

export function dbPath(dir: string, name = 'audit.db'): string {
  return join(dir, name);
}
