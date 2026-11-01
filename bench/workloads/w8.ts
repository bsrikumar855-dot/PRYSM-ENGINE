// W8: report generation and verify-chain for stores of N decision rows (single run each, with peak RSS).
// Stores are built directly through store.append (synchronous=NORMAL, so building 100k rows is fast; the chain content
// is identical to a FULL store). Each command runs in its own process (probe.ts) so peak RSS belongs to it alone.
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { statSync } from 'node:fs';
import { FIXTURE_POLICY_PATH } from '../lib/policygen.ts';
import { openBenchStore } from '../lib/guardkit.ts';
import { caseRng } from '../lib/prng.ts';
import { decisionRow } from '../lib/rows.ts';
import type { CaseCtx, CaseDef, CaseOutput } from '../lib/types.ts';

const PROBE = join(import.meta.dirname, '..', 'probe.ts');

interface ProbeResult { wall_ms: number; exit_code: number | null; inproc_ms: number; peak_rss_mb: number; stdout_first_line: string; stderr_lines: number }

function probe(args: string[]): Promise<ProbeResult> {
  return new Promise((res, rej) => {
    const t0 = process.hrtime.bigint();
    const child = spawn(process.execPath, ['--no-warnings=ExperimentalWarning', PROBE, ...args], { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
    let out = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (d: string) => { out += d; });
    child.on('error', rej);
    child.on('close', () => {
      const wall_ms = Number(process.hrtime.bigint() - t0) / 1e6;
      const line = out.split('\n').find((l) => l.startsWith('PROBE '));
      if (line === undefined) { rej(new Error('probe produced no result')); return; }
      res({ wall_ms, ...(JSON.parse(line.slice(6)) as Omit<ProbeResult, 'wall_ms'>) });
    });
  });
}

const w8 = (rows: number): CaseDef => ({
  id: `W8.rows${rows}`, workload: 'W8', title: `report + verify-chain on a store of ${rows} decision rows (single run)`, size: 'single', repeat: false,
  run: async (c: CaseCtx): Promise<CaseOutput> => {
    const store = openBenchStore(c.workDir, 'NORMAL');
    const rng = caseRng(c.baseSeed, 'W8');
    const b0 = process.hrtime.bigint();
    for (let i = 0; i < rows; i++) store.append(decisionRow(rng, 'w8', i));
    const buildMs = Number(process.hrtime.bigint() - b0) / 1e6;
    const head = store.head();
    store.close();
    const db = join(c.workDir, 'audit.db');
    const out = join(c.workDir, 'report.html');
    const report = await probe(['report', '--db', db, '--policy', FIXTURE_POLICY_PATH, '--out', out]);
    const reportBytes = statSync(out).size;
    const verify = await probe(['verify-chain', '--db', db]);
    return {
      kind: 'custom',
      data: {
        rows,
        head_seq: head?.seq ?? null,
        build_ms: buildMs,
        db_bytes: statSync(db).size,
        report: { ...report, html_bytes: reportBytes },
        verify_chain: verify,
      },
    };
  },
});

export const cases = (sizes: readonly number[]): CaseDef[] => sizes.map(w8);
