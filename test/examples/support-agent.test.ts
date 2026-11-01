// Sample support agent: scenarios 1-7 with a scripted mock model. Proves the gate, not model behaviour.
// Scenario functions assert side effects themselves; these tests add audit-store checks and run each in a temp dir.
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { directExecutor, firstBlocked, runAgent, scriptedModel } from '../../examples/support-agent/agent.ts';
import type { Step } from '../../examples/support-agent/agent.ts';
import {
  closeLab, createLab, scenario1, scenario2, scenario3, scenario4, scenario4Unguarded, scenario5, scenario6, scenario7,
} from '../../examples/support-agent/scenarios.ts';
import type { Lab, ScenarioResult } from '../../examples/support-agent/scenarios.ts';
import { cleanup, tmpDir } from '../support/tmp.ts';

async function withLab<T>(fn: (lab: Lab) => Promise<T>): Promise<T> {
  const lab = await createLab(tmpDir('prysm-sa-'));
  try {
    return await fn(lab);
  } finally {
    await closeLab(lab);
  }
}

/** In-process results: every agent-visible decision id is a row in the store with the matching verdict. */
function checkRowsMatchTurns(lab: Lab, r: ScenarioResult): void {
  for (const t of r.turns) {
    if (t.outcome.decisionId === null) continue;
    const row = lab.store.getEvent(t.outcome.decisionId);
    assert.ok(row !== null, 'decision row exists');
    assert.equal(row.effect, t.outcome.status === 'blocked' ? 'deny' : 'permit');
  }
  assert.equal(lab.store.verify().ok, true, 'hash chain verifies');
}

describe('support agent (scripted mock model)', () => {
  after(() => { cleanup(); });

  it('agent loop is deterministic and budget-limited', async () => {
    const steps: Step[] = [{ kind: 'call', tool: 'a', args: {} }, (h) => ({ kind: 'call', tool: 'b', args: { n: h.length } })];
    const seen: string[][] = [];
    for (let i = 0; i < 2; i++) {
      const run = await runAgent(scriptedModel(steps), directExecutor({ a: () => Promise.resolve(1), b: () => Promise.resolve(2) }));
      seen.push(run.turns.map((t) => JSON.stringify(t.action)));
      assert.equal(run.stoppedBy, 'final');
    }
    assert.deepEqual(seen[0], seen[1]);
    const forever = { next: () => ({ kind: 'call' as const, tool: 'a', args: {} }) };
    const capped = await runAgent(forever, directExecutor({ a: () => Promise.resolve(1) }), { maxSteps: 3 });
    assert.equal(capped.stoppedBy, 'step_budget');
    assert.equal(capped.turns.length, 3);
  });

  it('scenario 1: benign flow is permitted end to end', async () => {
    await withLab(async (lab) => {
      const r = await scenario1(lab);
      assert.equal(r.outbox.length, 1);
      assert.deepEqual(r.ledger, [{ percent: 5 }]);
      checkRowsMatchTurns(lab, r);
    });
  });

  it('scenario 2: unauthorized tool is blocked, file stays, tool never entered', async () => {
    await withLab(async (lab) => {
      const r = await scenario2(lab);
      assert.ok(firstBlocked.atS !== null && firstBlocked.atS > 0, 'A-09 timestamp recorded');
      checkRowsMatchTurns(lab, r);
    });
  });

  it('scenario 3: traversal and secrets reads are blocked', async () => {
    await withLab(async (lab) => {
      const r = await scenario3(lab);
      assert.equal(r.rows.filter((x) => x.effect === 'deny').length, 6);
      checkRowsMatchTurns(lab, r);
    });
  });

  it('scenario 4: poisoned document taints the session and exfiltration is denied; without PRYSM it succeeds', async () => {
    await withLab(async (lab) => {
      const guarded = await scenario4(lab);
      assert.deepEqual(guarded.outbox, []);
      assert.equal(guarded.extra['taintedAfter'], true);
      assert.deepEqual(guarded.rows.slice(2).map((x) => x.reason), ['tainted_session', 'tainted_session', 'tainted_session']);
      checkRowsMatchTurns(lab, guarded);
      const open = await scenario4Unguarded(lab);
      assert.equal(open.outbox.length, 2);
      assert.equal(open.outbox[0]?.['to'], 'attacker@evil.example');
      assert.equal(open.rows.length, 0, 'no audit rows without PRYSM');
    });
  });

  it('scenario 5: policy swap changes the verdict and the denial is explained', async () => {
    await withLab(async (lab) => {
      const r = await scenario5(lab);
      assert.deepEqual(r.rows.map((x) => x.effect), ['permit', 'deny']);
      assert.match(String(r.extra['explained']), /discount\.freeze/);
      checkRowsMatchTurns(lab, r);
    });
  });

  it('scenario 6: store down fails closed for high risk and uses the fail-open budget for low risk', async () => {
    await withLab(async (lab) => {
      const r = await scenario6(lab);
      assert.equal(r.outbox.length, 0);
      assert.equal(r.ledger.length, 0);
      assert.equal(lab.store.verify().ok, true);
    });
  });

  it('scenario 7: scenarios 1-4 through the MCP proxy', { timeout: 120000 }, async () => {
    await withLab(async (lab) => {
      const rs = await scenario7(lab);
      assert.equal(rs.length, 4);
      assert.deepEqual(rs[3]?.outbox, []);
      assert.deepEqual(rs[1]?.rows.map((x) => x.effect), ['deny', 'deny']);
      assert.ok(rs.every((x) => x.backend === 'proxy'));
    });
  });
});
