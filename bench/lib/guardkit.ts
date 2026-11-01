// Guard fixtures for W4/W5/W7: the 8-rule fixture policy, no-op tools, a real store or an in-memory no-op stub.
import { join } from 'node:path';
import { createGuard } from '../../src/guard/index.ts';
import type { Guard } from '../../src/guard/index.ts';
import { openStore } from '../../src/store/index.ts';
import type { NewEvent, Store, StoredEvent } from '../../src/store/index.ts';
import { loadFixturePolicy } from './policygen.ts';

export const BENCH_KEY = new Uint8Array(32).fill(0x42);
const NOOP = (): void => undefined;
const BIG = 1_000_000_000;

export type Path = 'permit' | 'deny';

export const CALLS: Record<Path, { tool: string; args: Record<string, unknown> }> = {
  permit: { tool: 'read_file', args: { path: '/workspace/docs/readme.md' } },
  deny: { tool: 'delete_file', args: { path: '/workspace/docs/readme.md' } },
};

export function openBenchStore(dir: string, sync: 'FULL' | 'NORMAL', name = 'audit.db'): Store {
  return openStore({ path: join(dir, name), hmacKey: BENCH_KEY, synchronous: sync, secondarySink: NOOP, busyTimeoutMs: 20_000 });
}

/**
 * In-memory no-op store: every write returns a fake row immediately. Benchmark-only stub (W7); it implements exactly
 * what the guard calls (append, appendShort, appendBestEffort, head, hmac, query, anchor) and nothing else.
 */
export function stubStore(): Store {
  let seq = 0;
  const row = (ev: NewEvent): StoredEvent => ({ seq: ++seq, id: ev.id, ts_ms: 0, kind: ev.kind } as unknown as StoredEvent);
  const unused = (): never => { throw new Error('stub store: method not used by the guard'); };
  const store: Store = {
    append: row,
    appendShort: row,
    appendBestEffort: row,
    iterate: () => [],
    head: () => null,
    count: () => seq,
    latest: () => null,
    verify: unused,
    getEvent: () => null,
    eventsByDecision: () => [],
    query: () => [],
    keyProtection: unused,
    anchor: () => ({ genesis_hash: '0'.repeat(64), head_seq: seq, head_hash: '0'.repeat(64), ts_ms: 0 }),
    checkpointAndPrune: unused,
    close: NOOP,
    hmac: () => '0'.repeat(64),
  };
  return store;
}

/**
 * Guard over the fixture policy with no-op tools. The best-effort row budgets are raised so that every deny/result
 * row is really written (the defaults, 1000 per minute, would silently turn later calls into cheaper no-write calls).
 */
export function benchGuard(store: Store, asyncTool = false): Guard {
  const tool = asyncTool ? (): Promise<string> => Promise.resolve('ok') : (): string => 'ok';
  return createGuard({
    policy: loadFixturePolicy(),
    store,
    agentId: 'bench-agent',
    tools: { read_file: tool, delete_file: tool },
    secondarySink: NOOP,
    maxDenyRowsPerWindow: BIG,
    maxResultRowsPerWindow: BIG,
    maxPreEvaluateRowsPerWindow: BIG,
  });
}
