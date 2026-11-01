// `npm run demo`: runs scenarios 1-7 of the sample support agent, then writes audit reports with `prysm report`.
// SCRIPTED MOCK MODEL: this proves the gate, not model behaviour. No network beyond 127.0.0.1, no API keys.
import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { firstBlocked } from './agent.ts';
import {
  POLICY_PATH, PROXY_POLICY_PATH, closeLab, createLab,
  scenario1, scenario2, scenario3, scenario4, scenario4Unguarded, scenario5, scenario6, scenario7,
} from './scenarios.ts';

const out = (l: string): void => { process.stdout.write(l + '\n'); };
const dir = mkdtempSync(join(tmpdir(), 'prysm-support-agent-'));
out('PRYSM sample support agent. Scripted mock model: proves the gate, not model behaviour.');
out(`working directory (kept): ${dir}`);

const lab = await createLab(dir, out);
let failed = false;
try {
  await scenario1(lab);
  await scenario2(lab);
  await scenario3(lab);
  await scenario4(lab);
  await scenario4Unguarded(lab);
  await scenario5(lab);
  await scenario6(lab);
  await scenario7(lab);
  out('');
  out('All scenario assertions passed.');
} catch (e) {
  failed = true;
  out('');
  out('SCENARIO ASSERTION FAILED: ' + (e instanceof Error ? e.stack ?? e.message : String(e)));
} finally {
  await closeLab(lab);
}

const reports: string[] = [];
const report = (db: string, key: string, policy: string, name: string, title: string): void => {
  const target = join(dir, name);
  const r = spawnSync(process.execPath, [
    '--no-warnings=ExperimentalWarning', resolve(import.meta.dirname, '../../src/cli/bin.ts'),
    'report', '--db', db, '--key-path', key, '--policy', policy, '--out', target, '--title', title,
  ], { encoding: 'utf8' });
  if (r.status === 0) reports.push(target);
  else { failed = true; out(`report failed (exit ${String(r.status)}): ${r.stderr.trim()}`); }
};
report(lab.dbPath, lab.keyPath, POLICY_PATH, 'report-inprocess.html', 'Support agent demo (in-process guard)');
report(lab.proxyDbPath, lab.proxyKeyPath, PROXY_POLICY_PATH, 'report-proxy.html', 'Support agent demo (MCP proxy)');
for (const r of reports) out(`report written: ${r}`);

out('');
if (firstBlocked.atS !== null) {
  out(`A-09: first blocked call (${String(firstBlocked.tool)}) happened ${firstBlocked.atS.toFixed(2)} s after process start (process.uptime(); includes Node startup, module load, store open and the earlier scripted steps; excludes npm install).`);
} else {
  out('A-09: no call was blocked');
}
out(`total wall time of this process: ${process.uptime().toFixed(2)} s`);
process.exitCode = failed ? 1 : 0;
