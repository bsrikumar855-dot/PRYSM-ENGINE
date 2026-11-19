// Usability finding from the M5 benign-set triage: a value the path matcher cannot interpret must be explained as
// such, not blamed on the deny rule's subject (outcome.unparseable + src/explain).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadPolicy } from '../../src/core/index.ts';
import { rowVerdict, UNPARSEABLE_WHY } from '../../src/explain/index.ts';
import { kit } from '../support/guard-kit.ts';
import { cleanup } from '../support/tmp.ts';

after(cleanup);

const policy = loadPolicy(readFileSync(new URL('../../eval/policies/support-agent.policy.json', import.meta.url)));

test('an uninterpretable path is explained as uninterpretable; a real secrets path still names the rule plainly', async () => {
  const k = kit({ policy });
  const odd = await k.guard.call('read_file', { path: '/workspace/café.txt' }); // non-ASCII: unparseable
  const real = await k.guard.call('read_file', { path: '/workspace/secrets/api_key.txt' });
  const rows = k.decisionRows();
  const oddRow = rows.find((r) => r.id === odd.decision_id);
  const realRow = rows.find((r) => r.id === real.decision_id);
  assert.ok(oddRow && realRow);
  assert.deepEqual((oddRow.outcome as { unparseable?: string[] }).unparseable, ['file.deny-secrets']);
  assert.equal((realRow.outcome as { unparseable?: string[] }).unparseable, undefined);

  const v1 = rowVerdict(oddRow, { policy });
  assert.match(v1.verdict, /could not be interpreted/);
  assert.equal(v1.why, UNPARSEABLE_WHY);
  const v2 = rowVerdict(realRow, { policy });
  assert.equal(v2.verdict, 'BLOCKED by rule file.deny-secrets.');
  k.store.close();
});
