// Seeded PRNG utilities for the differential harness (deterministic, no Math.random).
import { createHash } from "node:crypto";

export class Rng {
  private s: number;
  constructor(seed: number) {
    this.s = seed >>> 0;
  }
  /** mulberry32, uniform in [0,1). */
  next(): number {
    this.s = (this.s + 0x6d2b79f5) >>> 0;
    let t = this.s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  int(n: number): number {
    return Math.floor(this.next() * n);
  }
  range(lo: number, hi: number): number {
    return lo + this.int(hi - lo + 1);
  }
  chance(p: number): boolean {
    return this.next() < p;
  }
  pick<T>(a: readonly T[]): T {
    return a[this.int(a.length)] as T;
  }
  sample<T>(a: readonly T[], k: number): T[] {
    const c = [...a];
    const out: T[] = [];
    while (out.length < k && c.length > 0) out.push(c.splice(this.int(c.length), 1)[0] as T);
    return out;
  }
}

export function seedFrom(s: string | number): number {
  if (typeof s === "number") return s >>> 0;
  if (/^\d+$/.test(s)) return Number(s) >>> 0;
  return createHash("sha256").update(s).digest().readUInt32BE(0);
}

/** Independent stream for (seed, a, b). */
export function derive(seed: number, a: number, b = 0): Rng {
  const h = createHash("sha256").update(`${seed}:${a}:${b}`).digest();
  return new Rng(h.readUInt32BE(0));
}
