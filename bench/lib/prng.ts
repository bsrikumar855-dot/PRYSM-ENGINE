// Deterministic seeded PRNG (mulberry32) and small helpers. Never use Math.random in the harness.
export interface Rng {
  /** Float in [0, 1). */
  next(): number;
  /** Integer in [0, n). */
  int(n: number): number;
  pick<T>(xs: readonly T[]): T;
  /** Lowercase hex string of exactly `len` characters. */
  hex(len: number): string;
}

export function mulberry32(seed: number): Rng {
  let a = seed >>> 0;
  const next = (): number => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number): number => Math.floor(next() * n);
  return {
    next,
    int,
    pick: <T>(xs: readonly T[]): T => xs[int(xs.length)] as T,
    hex: (len: number): string => {
      let s = '';
      while (s.length < len) s += int(0x100000000).toString(16).padStart(8, '0');
      return s.slice(0, len);
    },
  };
}

/** FNV-1a 32-bit hash of a string, used to derive a per-case seed from the base seed. */
export function hashString(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

export function caseRng(baseSeed: number, caseId: string): Rng {
  return mulberry32((baseSeed ^ hashString(caseId)) >>> 0);
}
