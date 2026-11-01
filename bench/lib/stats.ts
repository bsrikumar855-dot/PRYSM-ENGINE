// Statistics: nearest-rank percentiles, median-of-runs, coefficient of variation, log2 histogram.

/** Nearest-rank percentile (p in (0,100]) of an ASCENDING-sorted array. Throws on empty input. */
export function percentileNearestRank(sorted: ArrayLike<number>, p: number): number {
  const n = sorted.length;
  if (n === 0) throw new Error('percentile of empty sample');
  if (!(p > 0 && p <= 100)) throw new Error('p must be in (0, 100]');
  const rank = Math.max(1, Math.ceil((p * n) / 100));
  return sorted[rank - 1] as number;
}

export function median(xs: readonly number[]): number {
  if (xs.length === 0) throw new Error('median of empty sample');
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 === 1 ? (s[m] as number) : ((s[m - 1] as number) + (s[m] as number)) / 2;
}

export function mean(xs: readonly number[]): number {
  if (xs.length === 0) throw new Error('mean of empty sample');
  let t = 0;
  for (const x of xs) t += x;
  return t / xs.length;
}

/** Coefficient of variation = sample standard deviation (n-1) / mean. 0 for fewer than 2 values or a zero mean. */
export function cv(xs: readonly number[]): number {
  if (xs.length < 2) return 0;
  const m = mean(xs);
  if (m === 0) return 0;
  let ss = 0;
  for (const x of xs) ss += (x - m) * (x - m);
  return Math.sqrt(ss / (xs.length - 1)) / m;
}

/** Histogram by power of two: key k counts samples in [2^k, 2^(k+1)) (same unit as the samples, nanoseconds). */
export function log2Histogram(samples: ArrayLike<number>): Record<string, number> {
  const h: Record<string, number> = {};
  for (let i = 0; i < samples.length; i++) {
    const v = samples[i] as number;
    const k = v < 1 ? 0 : Math.floor(Math.log2(v));
    h[String(k)] = (h[String(k)] ?? 0) + 1;
  }
  return h;
}

export interface RunStats {
  n: number;
  min: number;
  max: number;
  mean: number;
  p50: number;
  p95: number;
  p99: number;
  hist_log2_ns: Record<string, number>;
}

/** Summarise one run's samples (nanoseconds). */
export function summarize(samplesNs: ArrayLike<number>): RunStats {
  const sorted = Float64Array.from(samplesNs).sort();
  const n = sorted.length;
  if (n === 0) throw new Error('no samples');
  let sum = 0;
  for (let i = 0; i < n; i++) sum += sorted[i] as number;
  return {
    n,
    min: sorted[0] as number,
    max: sorted[n - 1] as number,
    mean: sum / n,
    p50: percentileNearestRank(sorted, 50),
    p95: percentileNearestRank(sorted, 95),
    p99: percentileNearestRank(sorted, 99),
    hist_log2_ns: log2Histogram(sorted),
  };
}

export interface Spread {
  median: number;
  min: number;
  max: number;
  cv: number;
}

export function spread(xs: readonly number[]): Spread {
  return { median: median(xs), min: Math.min(...xs), max: Math.max(...xs), cv: cv(xs) };
}

export interface Aggregate {
  runs: number;
  n_per_run: number;
  p50: Spread;
  p95: Spread;
  p99: Spread;
  /** Extremes across runs of the per-run min and max sample. */
  min_ns: number;
  max_ns: number;
  mean: Spread;
}

/** Median-of-runs of the per-run p50/p95/p99 with min/max across runs and CV. */
export function aggregateRuns(runs: readonly RunStats[]): Aggregate {
  if (runs.length === 0) throw new Error('no runs');
  return {
    runs: runs.length,
    n_per_run: runs[0]?.n ?? 0,
    p50: spread(runs.map((r) => r.p50)),
    p95: spread(runs.map((r) => r.p95)),
    p99: spread(runs.map((r) => r.p99)),
    min_ns: Math.min(...runs.map((r) => r.min)),
    max_ns: Math.max(...runs.map((r) => r.max)),
    mean: spread(runs.map((r) => r.mean)),
  };
}

/** Aggregate numeric fields present in every per-run `extra` object (median/min/max/cv); others are ignored. */
export function aggregateExtras(extras: readonly Record<string, unknown>[]): Record<string, Spread> {
  const out: Record<string, Spread> = {};
  const keys = new Set<string>();
  for (const e of extras) for (const k of Object.keys(e)) keys.add(k);
  for (const k of keys) {
    const vals = extras.map((e) => e[k]).filter((v): v is number => typeof v === 'number' && Number.isFinite(v));
    if (vals.length === extras.length && vals.length > 0) out[k] = spread(vals);
  }
  return out;
}

export const nsToMs = (ns: number): number => ns / 1e6;
