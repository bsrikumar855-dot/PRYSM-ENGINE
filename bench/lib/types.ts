// Shared types for benchmark cases.
import type { Profile } from './config.ts';
import type { RunStats } from './stats.ts';

export interface CaseCtx {
  profile: Profile;
  baseSeed: number;
  /** Cold run: no warm-up, `coldIters` measured iterations in a fresh process. */
  cold: boolean;
  /** Discarded warm-up iterations for this run (0 when cold). */
  warmup: number;
  /** Measured iterations for this run. */
  iters: number;
  /** A fresh empty directory owned by this run (removed by the caller). */
  workDir: string;
}

export interface LatencyOutput {
  kind: 'latency';
  /** One sample per measured iteration, nanoseconds. */
  samplesNs: number[];
  /** Numeric/other facts about the run (throughput, rows written, ...). Numeric fields are aggregated across runs. */
  extra?: Record<string, unknown>;
}

export interface CustomOutput {
  kind: 'custom';
  data: Record<string, unknown>;
}

export type CaseOutput = LatencyOutput | CustomOutput;

export interface CaseDef {
  id: string;
  workload: 'W1' | 'W2' | 'W3' | 'W4' | 'W5' | 'W6' | 'W7' | 'W8';
  title: string;
  /** Which iteration count of the profile applies. */
  size: 'decide' | 'guard' | 'single';
  /** False: a single run, no repetitions and no cold run (W8). */
  repeat: boolean;
  run(ctx: CaseCtx): Promise<CaseOutput>;
}

/** The per-run record written to raw JSON (no raw samples; percentiles and a histogram only). */
export interface RunRecord {
  rep: number;
  cold: boolean;
  seed_base: number;
  warmup: number;
  iters: number;
  wall_ms: number;
  output:
    | { kind: 'latency'; stats: RunStats; first_iteration_ns: number; extra: Record<string, unknown> }
    | { kind: 'custom'; data: Record<string, unknown> };
}
