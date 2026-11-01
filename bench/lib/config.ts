// Iteration profiles. The protocol minimums (BENCH-SPEC section 3) are the `full` profile; `quick` and `smoke` are reduced
// and must never be reported as protocol results.

export interface Profile {
  name: 'full' | 'quick' | 'smoke';
  /** Warm-up iterations, discarded. */
  warmup: number;
  /** Measured iterations for decide/evaluate workloads. */
  decideIters: number;
  /** Measured iterations for guard/store/proxy workloads. */
  guardIters: number;
  /** Independent repetitions (separate processes) per case. */
  reps: number;
  /** Iterations of the cold run (no warm-up). */
  coldIters: number;
  /** Decision rows for the W8 stores. */
  w8Rows: readonly number[];
  /** Appends per process in the 4-process W5 test. */
  procAppends: number;
  /** Concurrency levels for W5. */
  concurrency: readonly number[];
}

export const PROFILES: Record<Profile['name'], Profile> = {
  full: { name: 'full', warmup: 2000, decideIters: 10_000, guardIters: 2000, reps: 5, coldIters: 100, w8Rows: [1000, 10_000, 100_000], procAppends: 500, concurrency: [1, 4, 16, 64] },
  quick: { name: 'quick', warmup: 200, decideIters: 1000, guardIters: 200, reps: 2, coldIters: 100, w8Rows: [1000, 5000, 10_000], procAppends: 50, concurrency: [1, 4, 16, 64] },
  smoke: { name: 'smoke', warmup: 5, decideIters: 40, guardIters: 12, reps: 2, coldIters: 10, w8Rows: [50, 100, 200], procAppends: 5, concurrency: [1, 4] },
};

/** Fixed base PRNG seed; recorded in every result. */
export const BASE_SEED = 20_260_101;
export const PROCS = 4;
