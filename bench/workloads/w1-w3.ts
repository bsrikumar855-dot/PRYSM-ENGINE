// W1 decide() on the 8-rule fixture; W2 decide() on the 200-rule synthetic policy; W3 evaluate() incl. snapshot.
import { decide, evaluate } from '../../src/core/index.ts';
import type { LoadedPolicy } from '../../src/core/index.ts';
import { caseRng } from '../lib/prng.ts';
import { fixtureRequests, loadFixturePolicy, loadSyntheticPolicy, syntheticRequests } from '../lib/policygen.ts';
import type { ArgShape } from '../lib/policygen.ts';
import { timeSync } from '../lib/timer.ts';
import type { CaseCtx, CaseDef, CaseOutput } from '../lib/types.ts';

const POOL = 512;
/** The synthetic policy is generated from a fixed sub-seed so every case and run sees the same 200 rules. */
const SYNTH_SEED = 200;

function decideCase(id: string, workload: 'W1' | 'W2', title: string, policy: () => LoadedPolicy, requests: (c: CaseCtx) => Record<string, unknown>[]): CaseDef {
  return {
    id, workload, title, size: 'decide', repeat: true,
    run: (c: CaseCtx): Promise<CaseOutput> => {
      const p = policy();
      const pool = requests(c);
      const effects = { permit: 0, deny: 0 };
      const samplesNs = timeSync((i) => { effects[decide(p, pool[i % pool.length]).effect]++; }, c.warmup, c.iters);
      return Promise.resolve({ kind: 'latency', samplesNs, extra: { permit_calls: effects.permit, deny_calls: effects.deny, rules: p.document.rules.length } });
    },
  };
}

const shapes: { shape: ArgShape; label: string }[] = [
  { shape: 'tiny', label: 'tiny string' },
  { shape: 'kib1', label: '1 KiB string' },
  { shape: 'kib8', label: '8 KiB string' },
  { shape: 'list64', label: '64-element string[]' },
];

export const cases: CaseDef[] = [
  decideCase('W1.fixture-mix', 'W1', 'decide() on the 8-rule fixture, allow/deny/tainted/invalid mix', loadFixturePolicy, (c) => fixtureRequests(caseRng(c.baseSeed, 'W1'), POOL)),
  ...shapes.map(({ shape, label }) =>
    decideCase(`W2.${shape}`, 'W2', `decide() on the 200-rule synthetic policy, ${label}`, () => loadSyntheticPolicy(SYNTH_SEED), (c) => syntheticRequests(caseRng(c.baseSeed, 'W2.' + shape), shape, POOL))),
  {
    id: 'W3.fixture-mix', workload: 'W3', title: 'evaluate() incl. snapshot, 8-rule fixture mix', size: 'decide', repeat: true,
    run: (c): Promise<CaseOutput> => {
      const p = loadFixturePolicy();
      const pool = fixtureRequests(caseRng(c.baseSeed, 'W3'), POOL);
      let snaps = 0;
      const samplesNs = timeSync((i) => { if (evaluate(p, pool[i % pool.length]).snapshot !== null) snaps++; }, c.warmup, c.iters);
      return Promise.resolve({ kind: 'latency', samplesNs, extra: { snapshots_taken: snaps } });
    },
  },
  {
    id: 'W3.synth-kib1', workload: 'W3', title: 'evaluate() incl. snapshot, 200-rule policy, 1 KiB string', size: 'decide', repeat: true,
    run: (c): Promise<CaseOutput> => {
      const p = loadSyntheticPolicy(SYNTH_SEED);
      const pool = syntheticRequests(caseRng(c.baseSeed, 'W3.kib1'), 'kib1', POOL);
      let snaps = 0;
      const samplesNs = timeSync((i) => { if (evaluate(p, pool[i % pool.length]).snapshot !== null) snaps++; }, c.warmup, c.iters);
      return Promise.resolve({ kind: 'latency', samplesNs, extra: { snapshots_taken: snaps } });
    },
  },
];
