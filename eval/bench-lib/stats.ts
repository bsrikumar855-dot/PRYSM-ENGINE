// Wilson score interval for a binomial proportion (two-sided). Zero dependencies.
export const Z_95 = 1.959963984540054;

export interface Interval { k: number; n: number; rate: number | null; lower: number | null; upper: number | null }

/** Wilson score interval for k successes of n trials. n = 0 yields nulls (undefined rate). */
export function wilson(k: number, n: number, z: number = Z_95): Interval {
  if (!Number.isInteger(k) || !Number.isInteger(n) || k < 0 || n < 0 || k > n) throw new RangeError(`invalid counts k=${k} n=${n}`);
  if (n === 0) return { k, n, rate: null, lower: null, upper: null };
  const p = k / n;
  const z2 = z * z;
  const denom = 1 + z2 / n;
  const centre = (p + z2 / (2 * n)) / denom;
  const half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;
  // Exact endpoints: lower is 0 when k=0 and upper is 1 when k=n; floating error must not leak past them.
  const lower = k === 0 ? 0 : Math.max(0, centre - half);
  const upper = k === n ? 1 : Math.min(1, centre + half);
  return { k, n, rate: p, lower, upper };
}

const pct = (x: number): string => (x * 100).toFixed(2) + "%";

/** Human phrasing required by BENCH-SPEC section 1: "0 of N, 95% upper bound x%" when zero. */
export function describe(label: string, iv: Interval): string {
  if (iv.n === 0 || iv.rate === null || iv.lower === null || iv.upper === null) return `${label}: n/a (0 applicable cases)`;
  if (iv.k === 0) return `${label}: 0 of ${iv.n}, 95% upper bound ${pct(iv.upper)}`;
  return `${label}: ${iv.k} of ${iv.n} (${pct(iv.rate)}), 95% Wilson CI [${pct(iv.lower)}, ${pct(iv.upper)}]`;
}
