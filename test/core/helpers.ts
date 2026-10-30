// Shared test helpers for core tests (not itself a test file).
import { loadPolicy, PolicyError } from '../../src/core/index.ts';
import type { LoadedPolicy, PolicyErrorCode } from '../../src/core/index.ts';

export const TOOLS = {
  search_docs: { risk: 'low', external_effect: false, read_only: true, fail_mode: 'open_on_audit_failure', args: { query: { type: 'string' } } },
  read_file: { risk: 'medium', external_effect: false, read_only: true, fail_mode: 'closed', args: { path: { type: 'string' } } },
  send_email: {
    risk: 'high', external_effect: true, read_only: false, fail_mode: 'closed',
    args: { to: { type: 'string' }, subject: { type: 'string' }, body: { type: 'string' }, cc: { type: 'string', optional: true } },
  },
  http_get: { risk: 'medium', external_effect: true, read_only: true, fail_mode: 'closed', args: { url: { type: 'string' } } },
  set_discount: { risk: 'high', external_effect: true, read_only: false, fail_mode: 'closed', args: { percent: { type: 'number' } } },
  tag_item: { risk: 'low', external_effect: false, read_only: false, fail_mode: 'closed', args: { tags: { type: 'string[]' }, flag: { type: 'boolean', optional: true } } },
} as const;

export interface RuleLike {
  id: string;
  effect: 'permit' | 'deny';
  reason_code: string;
  match: Record<string, unknown>;
}

export function permit(id: string, match: Record<string, unknown>): RuleLike {
  return { id, effect: 'permit', reason_code: 'r_' + id.replace(/[^A-Za-z0-9]/g, '_'), match };
}
export function deny(id: string, match: Record<string, unknown>): RuleLike {
  return { id, effect: 'deny', reason_code: 'r_' + id.replace(/[^A-Za-z0-9]/g, '_'), match };
}

export function policyDoc(rules: RuleLike[], mode: 'enforce' | 'monitor_only' = 'enforce'): Record<string, unknown> {
  return { policy_schema_version: 1, name: 'test-policy', mode, tools: TOOLS, rules };
}

export function mk(rules: RuleLike[], mode: 'enforce' | 'monitor_only' = 'enforce'): LoadedPolicy {
  return loadPolicy(JSON.stringify(policyDoc(rules, mode)));
}

/** Returns the PolicyError code produced by loading, or 'OK'. Rethrows non-PolicyErrors. */
export function loadCode(input: unknown): PolicyErrorCode | 'OK' {
  try {
    loadPolicy(typeof input === 'string' || input instanceof Uint8Array ? input : JSON.stringify(input));
    return 'OK';
  } catch (e) {
    if (e instanceof PolicyError) return e.code;
    throw e;
  }
}

export function req(tool: string, args: Record<string, unknown>, ctx: Record<string, unknown> = {}): Record<string, unknown> {
  return { tool, args, ctx: { agentId: 'agent-1', ...ctx } };
}

/** mulberry32 seeded PRNG */
export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
