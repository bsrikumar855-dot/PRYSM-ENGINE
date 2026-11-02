// W4 guard call() end to end (FULL vs NORMAL, permit/deny); W5 concurrency + multi-process appends; W7 audit overhead (stub store).
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { join } from 'node:path';
import type { Guard } from '../../src/guard/index.ts';
import type { Store } from '../../src/store/index.ts';
import { benchGuard, CALLS, openBenchStore, stubStore } from '../lib/guardkit.ts';
import type { Path } from '../lib/guardkit.ts';
import { PROCS } from '../lib/config.ts';
import { checkRows } from '../lib/accounting.ts';
import { timeAsync, timeConcurrent } from '../lib/timer.ts';
import type { CaseCtx, CaseDef, CaseOutput } from '../lib/types.ts';

const WORKER = join(import.meta.dirname, '..', 'workers', 'append-worker.ts');

interface Tally { ok: number; blocked: number; other: number }

/** One guard.call on the given path; tallies the outcome so a broken setup shows up as `unexpected_results`. */
function callOp(guard: Guard, path: Path, tally: Tally): () => Promise<unknown> {
  const { tool, args } = CALLS[path];
  return async () => {
    const r = await guard.call(tool, args, { scopes: ['sales'] });
    if (r.ok) tally.ok++;
    else if (r.blocked) tally.blocked++;
    else tally.other++;
  };
}

const unexpected = (path: Path, t: Tally): number => (path === 'permit' ? t.blocked + t.other : t.ok + t.other);

async function guardCase(c: CaseCtx, path: Path, store: Store, extra: Record<string, unknown>): Promise<CaseOutput> {
  const guard = benchGuard(store);
  const tally: Tally = { ok: 0, blocked: 0, other: 0 };
  const samplesNs = await timeAsync(callOp(guard, path, tally), c.warmup, c.iters);
  const rows = store.count();
  guard.close();
  store.close();
  const acc = checkRows(`W4/W7 ${path}`, c.warmup + c.iters, path === 'permit' ? 2 : 1, rows);
  return { kind: 'latency', samplesNs, extra: { ...extra, ...acc, unexpected_results: unexpected(path, tally) } };
}

const w4 = (path: Path, sync: 'FULL' | 'NORMAL'): CaseDef => ({
  id: `W4.${path}.${sync}`, workload: 'W4', title: `guard.call() no-op tool, ${path} path, store synchronous=${sync}`, size: 'guard', repeat: true,
  run: (c) => guardCase(c, path, openBenchStore(c.workDir, sync), {}),
});

const w7 = (path: Path): CaseDef => ({
  id: `W7.${path}.stub`, workload: 'W7', title: `guard.call() no-op tool, ${path} path, in-memory no-op store stub (durable-write cost = W4 FULL minus this)`, size: 'guard', repeat: true,
  run: (c) => guardCase(c, path, stubStore(), {}),
});

const w5 = (lanes: number): CaseDef => ({
  id: `W5.c${lanes}`, workload: 'W5', title: `${lanes} concurrent async guard calls on one store (permit path, synchronous=FULL)`, size: 'guard', repeat: true,
  run: async (c): Promise<CaseOutput> => {
    const store = openBenchStore(c.workDir, 'FULL');
    const guard = benchGuard(store, true);
    const tally: Tally = { ok: 0, blocked: 0, other: 0 };
    const { samples, wallNs } = await timeConcurrent(callOp(guard, 'permit', tally), lanes, c.warmup, c.iters);
    const rows = store.count();
    guard.close();
    store.close();
    const acc = checkRows(`W5 c${lanes}`, c.warmup + c.iters, 2, rows);
    return { kind: 'latency', samplesNs: samples, extra: { lanes, throughput_per_s: c.iters / (wallNs / 1e9), ...acc, unexpected_results: unexpected('permit', tally) } };
  },
});

class Lines {
  #buf = '';
  #waiters: { pred: (l: string) => boolean; res: (l: string) => void }[] = [];
  readonly lines: string[] = [];
  constructor(child: ChildProcess) {
    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (d: string) => {
      this.#buf += d;
      for (;;) {
        const i = this.#buf.indexOf('\n');
        if (i < 0) return;
        const line = this.#buf.slice(0, i);
        this.#buf = this.#buf.slice(i + 1);
        this.lines.push(line);
        for (const w of [...this.#waiters]) {
          if (w.pred(line)) { this.#waiters.splice(this.#waiters.indexOf(w), 1); w.res(line); }
        }
      }
    });
  }
  next(pred: (l: string) => boolean, ms = 300_000): Promise<string> {
    const have = this.lines.find(pred);
    if (have !== undefined) return Promise.resolve(have);
    return new Promise((res, rej) => {
      const t = setTimeout(() => { rej(new Error('worker line timeout')); }, ms);
      this.#waiters.push({ pred, res: (l) => { clearTimeout(t); res(l); } });
    });
  }
}

const procs4: CaseDef = {
  id: `W5.procs${PROCS}`, workload: 'W5', title: `${PROCS} processes appending decision rows to one store (synchronous=FULL, one append per commit)`, size: 'guard', repeat: true,
  run: async (c): Promise<CaseOutput> => {
    // create schema first so workers only append
    const init = openBenchStore(c.workDir, 'FULL');
    init.close();
    const db = join(c.workDir, 'audit.db');
    const perProc = Math.ceil(c.iters / PROCS);
    const warmPer = Math.ceil(c.warmup / PROCS);
    const kids = Array.from({ length: PROCS }, (_, k) => {
      const child = spawn(process.execPath, ['--no-warnings=ExperimentalWarning', WORKER, db, `p${k}`, String(warmPer), String(perProc), String(c.baseSeed + k)], { stdio: ['pipe', 'pipe', 'inherit'], windowsHide: true });
      return { child, lines: new Lines(child), exited: new Promise<number | null>((res) => { child.on('close', (code) => { res(code); }); }) };
    });
    try {
      await Promise.all(kids.map((k) => k.lines.next((l) => l === 'READY')));
      for (const k of kids) k.child.stdin?.write('warm\n');
      await Promise.all(kids.map((k) => k.lines.next((l) => l === 'WARM')));
      const w0 = process.hrtime.bigint();
      for (const k of kids) k.child.stdin?.write('go\n');
      const results = await Promise.all(kids.map((k) => k.lines.next((l) => l.startsWith('{'))));
      const wallNs = Number(process.hrtime.bigint() - w0);
      const codes = await Promise.all(kids.map((k) => k.exited));
      const samplesNs: number[] = [];
      for (const r of results) samplesNs.push(...(JSON.parse(r) as { samplesNs: number[] }).samplesNs);
      const check = openBenchStore(c.workDir, 'FULL');
      const rows = check.count();
      check.close();
      const expected = PROCS * (warmPer + perProc);
      if (rows !== expected) throw new Error(`W5 procs: audit row accounting failed: ${rows} rows, expected exactly ${expected}`);
      return {
        kind: 'latency', samplesNs,
        extra: { processes: PROCS, throughput_per_s: samplesNs.length / (wallNs / 1e9), audit_rows: rows, rows_expected: PROCS * (warmPer + perProc), worker_nonzero_exits: codes.filter((x) => x !== 0).length },
      };
    } finally {
      for (const k of kids) if (k.child.exitCode === null) k.child.kill();
    }
  },
};

export function cases(levels: readonly number[]): CaseDef[] {
  return [
    w4('permit', 'FULL'), w4('permit', 'NORMAL'), w4('deny', 'FULL'), w4('deny', 'NORMAL'),
    ...levels.map(w5), procs4,
    w7('permit'), w7('deny'),
  ];
}
