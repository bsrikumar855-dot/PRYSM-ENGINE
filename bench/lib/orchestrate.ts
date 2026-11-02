// Parent/child orchestration. The parent runs every case in separate child processes (reps + one cold run) and aggregates;
// a child runs exactly one case once (this same entry, `--child`).
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { BASE_SEED, PROFILES } from './config.ts';
import type { Profile } from './config.ts';
import { localDate, machineInfo } from './machine.ts';
import { buildCaseResult, buildSummary, writeResults } from './results.ts';
import type { CaseResult, Summary } from './results.ts';
import { summarize } from './stats.ts';
import type { CaseCtx, CaseDef, RunRecord } from './types.ts';
import { allCases, selectCases } from '../workloads/index.ts';

const ENTRY = resolve(import.meta.dirname, '..', 'run.ts');
const RESULT_PREFIX = 'BENCH_RESULT ';

export interface Options {
  profile: Profile['name'];
  only: string[];
  out: string | null;
  /** Reason recorded in the summary when a subset is re-run into an existing results directory. */
  note: string | null;
  child: { id: string; cold: boolean; rep: number } | null;
}

export function parseOptions(argv: readonly string[]): Options {
  const o: Options = { profile: 'full', only: [], out: null, note: null, child: null };
  let childId: string | null = null;
  let cold = false;
  let rep = 0;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    const val = (): string => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} needs a value`);
      return v;
    };
    if (a === '--quick') o.profile = 'quick';
    else if (a === '--smoke') o.profile = 'smoke';
    else if (a === '--profile') {
      const v = val();
      if (v !== 'full' && v !== 'quick' && v !== 'smoke') throw new Error('unknown profile');
      o.profile = v;
    } else if (a === '--only') o.only = val().split(',').filter((x) => x !== '');
    else if (a === '--out') o.out = resolve(val());
    else if (a === '--note') o.note = val();
    else if (a === '--child') childId = val();
    else if (a === '--cold') cold = true;
    else if (a === '--rep') rep = Number(val());
    else throw new Error(`unknown argument ${a}`);
  }
  if (childId !== null) o.child = { id: childId, cold, rep };
  return o;
}

function removeDir(dir: string): void {
  for (let i = 0; i < 5; i++) {
    try { rmSync(dir, { recursive: true, force: true }); return; } catch { /* Windows may still hold the WAL handle; retry */ }
  }
}

/** Runs one case once in THIS process and returns its record (used by the child and by the tests). */
export async function executeRun(def: CaseDef, profile: Profile, cold: boolean, rep: number): Promise<RunRecord> {
  const workDir = mkdtempSync(join(tmpdir(), 'prysm-bench-'));
  const iters = def.size === 'single' ? 1 : cold ? profile.coldIters : def.size === 'decide' ? profile.decideIters : profile.guardIters;
  const warmup = cold || def.size === 'single' ? 0 : profile.warmup;
  const ctx: CaseCtx = { profile, baseSeed: BASE_SEED, cold, warmup, iters, workDir };
  const t0 = process.hrtime.bigint();
  try {
    const out = await def.run(ctx);
    const wall_ms = Number(process.hrtime.bigint() - t0) / 1e6;
    const base = { rep, cold, seed_base: BASE_SEED, warmup, iters, wall_ms };
    if (out.kind === 'latency') {
      return { ...base, output: { kind: 'latency', stats: summarize(out.samplesNs), first_iteration_ns: out.samplesNs[0] ?? 0, extra: out.extra ?? {} } };
    }
    return { ...base, output: { kind: 'custom', data: out.data } };
  } finally {
    removeDir(workDir);
  }
}

export async function childMain(o: Options): Promise<void> {
  const profile = PROFILES[o.profile];
  const def = allCases(profile).find((c) => c.id === o.child?.id);
  if (def === undefined || o.child === null) throw new Error('unknown case');
  const rec = await executeRun(def, profile, o.child.cold, o.child.rep);
  process.stdout.write(RESULT_PREFIX + JSON.stringify(rec) + '\n');
}

function spawnChild(id: string, profile: Profile, cold: boolean, rep: number): Promise<RunRecord> {
  return new Promise((res, rej) => {
    const args = ['--no-warnings=ExperimentalWarning', ENTRY, '--profile', profile.name, '--child', id, '--rep', String(rep), ...(cold ? ['--cold'] : [])];
    const child = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let out = '';
    let err = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d: string) => { out += d; });
    child.stderr.on('data', (d: string) => { err += d; });
    child.on('error', rej);
    child.on('close', (code) => {
      const line = out.split('\n').find((l) => l.startsWith(RESULT_PREFIX));
      if (line === undefined) { rej(new Error(`child exited ${String(code)} without a result: ${err.trim().split('\n').slice(-3).join(' | ').slice(0, 400)}`)); return; }
      res(JSON.parse(line.slice(RESULT_PREFIX.length)) as RunRecord);
    });
  });
}

export async function parentMain(o: Options, log: (s: string) => void = (s) => { console.log(s); }): Promise<{ dir: string; files: string[]; results: CaseResult[]; summary: ReturnType<typeof buildSummary> }> {
  const profile = PROFILES[o.profile];
  const machine = machineInfo();
  const cases = selectCases(allCases(profile), o.only);
  if (cases.length === 0) throw new Error('no case matches --only');
  const dir = o.out ?? resolve(import.meta.dirname, '..', 'results', localDate() + (profile.name === 'full' ? '' : '-' + profile.name));
  log(`PRYSM bench profile=${profile.name} seed=${BASE_SEED} cases=${cases.length} reps=${profile.reps}`);
  log(`machine: ${machine.cpu_model}, ${machine.logical_cores} logical cores, ${(machine.ram_bytes / 2 ** 30).toFixed(1)} GiB RAM, ${machine.os}, node ${machine.node}, power plan: ${machine.power_plan ?? 'unknown'}`);
  const results: CaseResult[] = [];
  for (const def of cases) {
    const runs: RunRecord[] = [];
    const failed: CaseResult['failed_runs'] = [];
    const reps = def.repeat ? profile.reps : 1;
    for (let k = 1; k <= reps; k++) {
      try { runs.push(await spawnChild(def.id, profile, false, k)); } catch (e) { failed.push({ rep: k, cold: false, error: String((e as Error).message) }); }
    }
    let cold: RunRecord | null = null;
    if (def.repeat) {
      try { cold = await spawnChild(def.id, profile, true, 0); } catch (e) { failed.push({ rep: 0, cold: true, error: String((e as Error).message) }); }
    }
    const r = buildCaseResult(def, profile, BASE_SEED, machine, runs, cold, failed);
    results.push(r);
    const a = r.aggregate;
    log(a
      ? `${def.id.padEnd(18)} p50=${(a.p50.median / 1e6).toFixed(3)}ms p95=${(a.p95.median / 1e6).toFixed(3)}ms p99=${(a.p99.median / 1e6).toFixed(3)}ms cv50=${a.p50.cv.toFixed(3)} runs=${a.runs}${failed.length ? ` FAILED=${failed.length}` : ''}`
      : `${def.id.padEnd(18)} ${runs.length ? 'done' : 'FAILED'}${failed.length ? ' ' + failed[0]?.error : ''}`);
  }
  // Re-running a subset into an existing directory: keep the other cases' files untouched and regenerate the summary from all of them.
  let all = results;
  let reruns: Summary['reruns'] = [];
  let summaryMachine = machine;
  const prevPath = join(dir, 'summary.json');
  if (o.only.length > 0 && existsSync(prevPath)) {
    const prev = JSON.parse(readFileSync(prevPath, 'utf8')) as Summary;
    if (prev.profile !== profile.name) throw new Error('existing summary has a different profile; refusing to merge');
    reruns = [...(prev.reruns ?? []), { date: machine.date, cases: results.map((r) => r.case), note: o.note ?? 'subset re-run' }];
    summaryMachine = prev.machine;
    const fresh = new Set(results.map((r) => r.case));
    const kept: CaseResult[] = [];
    for (const f of readdirSync(dir)) {
      if (!f.endsWith('.json') || f === 'summary.json') continue;
      const cr = JSON.parse(readFileSync(join(dir, f), 'utf8')) as CaseResult;
      if (!fresh.has(cr.case)) kept.push(cr);
    }
    const order = allCases(profile).map((c) => c.id);
    all = [...kept, ...results].sort((a, b) => order.indexOf(a.case) - order.indexOf(b.case));
  }
  const summary = buildSummary(all, profile, BASE_SEED, summaryMachine, reruns);
  const files = writeResults(dir, results, summary);
  for (const h of summary.hypotheses) log(`${h.id} ${h.status === 'met' ? 'met' : h.status === 'MISSED' ? 'MISSED' : 'not evaluated'}: ${h.statement} [${h.numbers}]`);
  for (const f of summary.failures) log(`FAILED ${f.case} rep=${f.rep}${f.cold ? ' (cold)' : ''}: ${f.error}`);
  log(`results written to ${dir} (${files.length} files)`);
  return { dir, files, results, summary };
}
