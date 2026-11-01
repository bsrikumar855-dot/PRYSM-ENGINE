// Hypotheses H1-H4 (BENCH-SPEC section 3), fixed before any measurement. Thresholds are never changed after results.
import type { Aggregate } from './stats.ts';

export interface HypothesisResult {
  id: 'H1' | 'H2' | 'H3' | 'H4';
  statement: string;
  threshold: string;
  status: 'met' | 'MISSED' | 'not evaluated';
  /** Human-readable numbers behind the verdict. */
  numbers: string;
  value: number | null;
  unit: 'ms' | 's';
}

export interface Inputs {
  /** Aggregates by case id (latency cases only). */
  aggregates: Readonly<Record<string, Aggregate | undefined>>;
  /** verify-chain process wall time in ms by row count (W8). */
  verifyWallMs: Readonly<Record<number, number | undefined>>;
}

const ms = (ns: number): number => ns / 1e6;
const f = (x: number): string => x.toFixed(x < 1 ? 3 : 2);

export function evaluateHypotheses(inp: Inputs): HypothesisResult[] {
  const out: HypothesisResult[] = [];
  const agg = (id: string): Aggregate | undefined => inp.aggregates[id];

  // H1: decide p99 < 1 ms at 200 rules, for every argument-size variant (worst variant decides).
  const w2 = ['W2.tiny', 'W2.kib1', 'W2.kib8', 'W2.list64'].map((id) => ({ id, a: agg(id) }));
  const h1 = w2.filter((x): x is { id: string; a: Aggregate } => x.a !== undefined);
  if (h1.length === 0) {
    out.push({ id: 'H1', statement: 'decide() p99 < 1 ms at 200 rules', threshold: '< 1 ms', status: 'not evaluated', numbers: 'W2 not run', value: null, unit: 'ms' });
  } else {
    const worst = Math.max(...h1.map((x) => ms(x.a.p99.median)));
    out.push({
      id: 'H1', statement: 'decide() p99 < 1 ms at 200 rules (worst of the W2 variants; median of per-run p99)', threshold: '< 1 ms',
      status: h1.length === 4 && worst < 1 ? 'met' : h1.length < 4 ? 'not evaluated' : 'MISSED',
      numbers: h1.map((x) => `${x.id} p99=${f(ms(x.a.p99.median))} ms`).join(', '), value: worst, unit: 'ms',
    });
  }

  // H2: guard call overhead with synchronous (FULL) audit p99 < 10 ms, both the permit and the deny path.
  const p = agg('W4.permit.FULL');
  const d = agg('W4.deny.FULL');
  if (p === undefined || d === undefined) {
    out.push({ id: 'H2', statement: 'guard overhead with sync audit p99 < 10 ms', threshold: '< 10 ms', status: 'not evaluated', numbers: 'W4 FULL not run', value: null, unit: 'ms' });
  } else {
    const worst = Math.max(ms(p.p99.median), ms(d.p99.median));
    out.push({
      id: 'H2', statement: 'guard call() with no-op tool and synchronous=FULL audit: p99 < 10 ms (both permit and deny paths; median of per-run p99)', threshold: '< 10 ms',
      status: worst < 10 ? 'met' : 'MISSED',
      numbers: `permit p99=${f(ms(p.p99.median))} ms (p50 ${f(ms(p.p50.median))}), deny p99=${f(ms(d.p99.median))} ms (p50 ${f(ms(d.p50.median))})`, value: worst, unit: 'ms',
    });
  }

  // H3: proxy overhead p99 < 15 ms = proxy p99 minus direct p99 (medians of per-run p99).
  const px = agg('W6.proxy');
  const dr = agg('W6.direct');
  if (px === undefined || dr === undefined) {
    out.push({ id: 'H3', statement: 'proxy overhead p99 < 15 ms', threshold: '< 15 ms', status: 'not evaluated', numbers: 'W6 not run', value: null, unit: 'ms' });
  } else {
    const o99 = ms(px.p99.median - dr.p99.median);
    const o50 = ms(px.p50.median - dr.p50.median);
    out.push({
      id: 'H3', statement: 'proxy overhead p99 < 15 ms (proxy p99 minus direct p99, medians of per-run p99)', threshold: '< 15 ms',
      status: o99 < 15 ? 'met' : 'MISSED',
      numbers: `overhead p99=${f(o99)} ms, p50=${f(o50)} ms (proxy p50 ${f(ms(px.p50.median))}/p99 ${f(ms(px.p99.median))}; direct p50 ${f(ms(dr.p50.median))}/p99 ${f(ms(dr.p99.median))})`, value: o99, unit: 'ms',
    });
  }

  // H4: verify-chain of 100k rows < 30 s (process wall time including node start-up).
  const v = inp.verifyWallMs[100_000];
  if (v === undefined) {
    out.push({ id: 'H4', statement: 'verify-chain of 100k rows < 30 s', threshold: '< 30 s', status: 'not evaluated', numbers: '100k store not run in this profile', value: null, unit: 's' });
  } else {
    out.push({
      id: 'H4', statement: 'verify-chain of 100k rows < 30 s (process wall time)', threshold: '< 30 s',
      status: v / 1000 < 30 ? 'met' : 'MISSED', numbers: `verify-chain wall=${(v / 1000).toFixed(2)} s`, value: v / 1000, unit: 's',
    });
  }
  return out;
}
