// Result files: one JSON per case (all runs: per-run percentiles + histogram, never raw sample arrays), one summary.json.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Profile } from './config.ts';
import { evaluateHypotheses } from './hypotheses.ts';
import type { HypothesisResult } from './hypotheses.ts';
import type { MachineInfo } from './machine.ts';
import { aggregateExtras, aggregateRuns } from './stats.ts';
import type { Aggregate, Spread } from './stats.ts';
import type { CaseDef, RunRecord } from './types.ts';

export interface CaseResult {
  case: string;
  workload: string;
  title: string;
  profile: Profile['name'];
  seed: number;
  machine: MachineInfo;
  failed_runs: { rep: number; cold: boolean; error: string }[];
  runs: RunRecord[];
  cold: RunRecord | null;
  aggregate: Aggregate | null;
  extra_aggregate: Record<string, Spread> | null;
}

export function buildCaseResult(def: CaseDef, profile: Profile, seed: number, machine: MachineInfo, runs: RunRecord[], cold: RunRecord | null, failed: CaseResult['failed_runs']): CaseResult {
  const lat = runs.flatMap((r) => (r.output.kind === 'latency' ? [r.output] : []));
  return {
    case: def.id, workload: def.workload, title: def.title, profile: profile.name, seed, machine, failed_runs: failed, runs, cold,
    aggregate: lat.length > 0 ? aggregateRuns(lat.map((o) => o.stats)) : null,
    extra_aggregate: lat.length > 0 ? aggregateExtras(lat.map((o) => o.extra)) : null,
  };
}

const ms = (ns: number): number => Math.round(ns / 1e3) / 1e3;
const ns2ms = (s: Spread): { median: number; min: number; max: number; cv: number } => ({ median: ms(s.median), min: ms(s.min), max: ms(s.max), cv: Math.round(s.cv * 1e4) / 1e4 });

export interface Summary {
  schema: 'prysm-bench-summary/1';
  profile: Profile['name'];
  seed: number;
  machine: MachineInfo;
  note: string;
  /** Latency cases, milliseconds; median of the per-run percentiles with min/max across runs and CV. */
  latency_ms: Record<string, {
    n_per_run: number; runs: number;
    p50: ReturnType<typeof ns2ms>; p95: ReturnType<typeof ns2ms>; p99: ReturnType<typeof ns2ms>;
    cold: { p50: number; p99: number; first_iteration: number; n: number } | null;
    extra: Record<string, Spread>;
  }>;
  w8: Record<string, unknown>;
  derived: {
    w6_proxy_overhead_ms: { p50: number; p95: number; p99: number; audit_rows_proxy: number | null } | null;
    w7_durable_write_cost_ms: Record<string, { p50: number; p99: number }>;
    w5_throughput_per_s: Record<string, { median: number; min: number; max: number }>;
  };
  hypotheses: HypothesisResult[];
  failures: { case: string; rep: number; cold: boolean; error: string }[];
}

export function buildSummary(results: readonly CaseResult[], profile: Profile, seed: number, machine: MachineInfo): Summary {
  const latency: Summary['latency_ms'] = {};
  const w8: Record<string, unknown> = {};
  const aggregates: Record<string, Aggregate | undefined> = {};
  const verifyWallMs: Record<number, number | undefined> = {};
  const failures: Summary['failures'] = [];
  for (const r of results) {
    for (const f of r.failed_runs) failures.push({ case: r.case, ...f });
    if (r.aggregate !== null) {
      aggregates[r.case] = r.aggregate;
      const c = r.cold?.output.kind === 'latency' ? r.cold.output : null;
      latency[r.case] = {
        n_per_run: r.aggregate.n_per_run, runs: r.aggregate.runs,
        p50: ns2ms(r.aggregate.p50), p95: ns2ms(r.aggregate.p95), p99: ns2ms(r.aggregate.p99),
        cold: c ? { p50: ms(c.stats.p50), p99: ms(c.stats.p99), first_iteration: ms(c.first_iteration_ns), n: c.stats.n } : null,
        extra: r.extra_aggregate ?? {},
      };
    } else {
      const run = r.runs[0];
      if (run?.output.kind === 'custom') {
        w8[r.case] = run.output.data;
        const rows = run.output.data['rows'];
        const v = run.output.data['verify_chain'] as { wall_ms?: number } | undefined;
        if (typeof rows === 'number' && typeof v?.wall_ms === 'number') verifyWallMs[rows] = v.wall_ms;
      }
    }
  }
  const px = aggregates['W6.proxy'];
  const dr = aggregates['W6.direct'];
  const proxyExtra = results.find((r) => r.case === 'W6.proxy')?.extra_aggregate?.['audit_rows']?.median ?? null;
  const w7: Summary['derived']['w7_durable_write_cost_ms'] = {};
  for (const path of ['permit', 'deny']) {
    const stub = aggregates[`W7.${path}.stub`];
    for (const sync of ['FULL', 'NORMAL']) {
      const real = aggregates[`W4.${path}.${sync}`];
      if (stub && real) w7[`${path}.${sync}`] = { p50: ms(real.p50.median - stub.p50.median), p99: ms(real.p99.median - stub.p99.median) };
    }
  }
  const w5: Summary['derived']['w5_throughput_per_s'] = {};
  for (const r of results) {
    const t = r.extra_aggregate?.['throughput_per_s'];
    if (r.workload === 'W5' && t) w5[r.case] = { median: Math.round(t.median), min: Math.round(t.min), max: Math.round(t.max) };
  }
  return {
    schema: 'prysm-bench-summary/1', profile: profile.name, seed, machine,
    note: profile.name === 'full' ? 'Protocol run (BENCH-SPEC section 3).' : `Profile "${profile.name}" uses reduced iteration counts: smoke/CI only, not protocol results.`,
    latency_ms: latency, w8,
    derived: {
      w6_proxy_overhead_ms: px && dr ? { p50: ms(px.p50.median - dr.p50.median), p95: ms(px.p95.median - dr.p95.median), p99: ms(px.p99.median - dr.p99.median), audit_rows_proxy: proxyExtra } : null,
      w7_durable_write_cost_ms: w7,
      w5_throughput_per_s: w5,
    },
    hypotheses: evaluateHypotheses({ aggregates, verifyWallMs }),
    failures,
  };
}

export function writeResults(dir: string, results: readonly CaseResult[], summary: Summary): string[] {
  mkdirSync(dir, { recursive: true });
  const files: string[] = [];
  for (const r of results) {
    const p = join(dir, `${r.case}.json`);
    writeFileSync(p, JSON.stringify(r, null, 1) + '\n');
    files.push(p);
  }
  const sp = join(dir, 'summary.json');
  writeFileSync(sp, JSON.stringify(summary, null, 1) + '\n');
  files.push(sp);
  return files;
}
