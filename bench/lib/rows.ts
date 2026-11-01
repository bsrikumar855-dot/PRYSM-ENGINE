// Realistic decision rows (shaped like the ones the guard writes) for the store-heavy workloads (W5 processes, W8).
import type { NewEvent } from '../../src/store/index.ts';
import type { Rng } from './prng.ts';

const TOOLS = [
  { tool: 'search_docs', risk: 'low' },
  { tool: 'read_file', risk: 'medium' },
  { tool: 'send_email', risk: 'high' },
  { tool: 'http_get', risk: 'medium' },
  { tool: 'delete_file', risk: 'high' },
  { tool: 'set_discount', risk: 'high' },
] as const;

const POLICY_VERSION = 'sha256:' + 'ab'.repeat(32);

/** Row `i` of a stream: about 70 percent permit, 30 percent deny, with digests, redacted args and outcome JSON. */
export function decisionRow(rng: Rng, tag: string, i: number, baseTs = 1_760_000_000_000): NewEvent {
  const t = TOOLS[rng.int(TOOLS.length)] as (typeof TOOLS)[number];
  const permit = rng.next() < 0.7;
  return {
    id: `${tag}-${i}`,
    kind: 'decision',
    ts_ms: baseTs + i * 7,
    execution_id: `exec-${tag}-${Math.floor(i / 4)}`,
    session_id: `sess-${tag}-${Math.floor(i / 20)}`,
    agent_id: 'bench-agent',
    tool: t.tool,
    effect: permit ? 'permit' : 'deny',
    enforcement: 'enforced',
    rule_ids: [permit ? `${t.tool}.allow` : 'file.deny-secrets'],
    reason_code: permit ? 'permitted' : 'denied_by_rule',
    policy_version: POLICY_VERSION,
    request_digest: 'sha256:' + rng.hex(64),
    args_hmac: rng.hex(64),
    args_redacted: { path: { len: 10 + rng.int(60), kind: 'string' }, n: rng.int(100) },
    risk: t.risk,
    latency_us: 20 + rng.int(400),
    session_tainted: rng.next() < 0.05 ? 1 : 0,
    provenance_asserted: { _: 'untrusted:unknown' },
    outcome: { deny_n: permit ? 0 : 1, note: 'bench row ' + i },
    engine_version: 'prysm-engine/1',
  };
}
