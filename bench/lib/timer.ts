// Timing loops built on process.hrtime.bigint(). Warm-up iterations run first and are discarded.
const hr = process.hrtime.bigint;

/** Synchronous operation: `op(i)` is called warmup + iters times; only the last `iters` are timed (ns). */
export function timeSync(op: (i: number) => unknown, warmup: number, iters: number): number[] {
  for (let i = 0; i < warmup; i++) op(i);
  const out = new Array<number>(iters);
  for (let i = 0; i < iters; i++) {
    const t0 = hr();
    op(warmup + i);
    out[i] = Number(hr() - t0);
  }
  return out;
}

/** Async operation, one at a time. */
export async function timeAsync(op: (i: number) => Promise<unknown>, warmup: number, iters: number): Promise<number[]> {
  for (let i = 0; i < warmup; i++) await op(i);
  const out = new Array<number>(iters);
  for (let i = 0; i < iters; i++) {
    const t0 = hr();
    await op(warmup + i);
    out[i] = Number(hr() - t0);
  }
  return out;
}

/**
 * `lanes` concurrent lanes pull indices from a shared counter. Each sample is call start to resolution.
 * Returns the samples (in index order) and the wall time of the measured phase in ns.
 */
export async function timeConcurrent(op: (i: number) => Promise<unknown>, lanes: number, warmup: number, iters: number): Promise<{ samples: number[]; wallNs: number }> {
  const pool = async (total: number, base: number, record: ((i: number, ns: number) => void) | null): Promise<void> => {
    let next = 0;
    const lane = async (): Promise<void> => {
      for (;;) {
        const i = next++;
        if (i >= total) return;
        const t0 = hr();
        await op(base + i);
        if (record) record(i, Number(hr() - t0));
      }
    };
    await Promise.all(Array.from({ length: lanes }, () => lane()));
  };
  await pool(warmup, 0, null);
  const samples = new Array<number>(iters);
  const w0 = hr();
  await pool(iters, warmup, (i, ns) => { samples[i] = ns; });
  return { samples, wallNs: Number(hr() - w0) };
}
