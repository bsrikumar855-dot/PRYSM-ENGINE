// Case registry. Order is execution order.
import type { Profile } from '../lib/config.ts';
import type { CaseDef } from '../lib/types.ts';
import { cases as w13 } from './w1-w3.ts';
import { cases as w457 } from './w4-w5-w7.ts';
import { cases as w6 } from './w6.ts';
import { cases as w8 } from './w8.ts';

export function allCases(profile: Profile): CaseDef[] {
  return [...w13, ...w457(profile.concurrency), ...w6, ...w8(profile.w8Rows)];
}

/** Select by exact id, workload ("W4") or id prefix ("W4.permit"). Empty filter selects everything. */
export function selectCases(all: readonly CaseDef[], only: readonly string[]): CaseDef[] {
  if (only.length === 0) return [...all];
  return all.filter((c) => only.some((o) => c.id === o || c.workload === o || c.id.startsWith(o + '.') || c.id.startsWith(o)));
}
