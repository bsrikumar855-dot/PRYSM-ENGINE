// DEC-43 / S-02: the agent-facing facet cannot grant itself identity, scopes or provenance.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { loadPolicy } from '../../src/core/index.ts';
import type { GuardResult } from '../../src/guard/index.ts';
import { POLICY_DOC } from '../support/policy.ts';
import { kit, defaultTools } from '../support/guard-kit.ts';
import type { Kit } from '../support/guard-kit.ts';
import { cleanup } from '../support/tmp.ts';

after(cleanup);

// discount needs the "sales" scope; e-mail needs a trusted provenance label on "to"
function strictPolicy() {
  const doc = POLICY_DOC('enforce', []) as { rules: { id: string; match: Record<string, unknown> }[] };
  doc.rules = doc.rules.map((r) => {
    if (r.id === 'p.discount') return { ...r, match: { ...r.match, scopes_any: ['sales'] } };
    if (r.id === 'p.email') return { ...r, match: { ...r.match, provenance: { to: { all_in: ['trusted-user'] } } } };
    return r;
  });
  return loadPolicy(JSON.stringify(doc));
}

const mk = (): Kit => kit({
  policy: strictPolicy(),
  tools: (calls) => ({ ...defaultTools(calls), search_docs: { fn: defaultTools(calls)['search_docs'] as never, taintsSession: true } }),
});
const reason = (r: GuardResult): string => (r.ok ? 'ok' : 'blocked' in r && r.blocked ? r.reason_code : 'error');
const row = (k: Kit, id: string) => k.rows().find((x) => x.id === id);

test('S-02: the agent facet rejects caller-supplied scopes, user and provenance (denied and audited, tool never runs)', async () => {
  const k = mk();
  const agent = k.guard.forAgent({ userId: 'u-1' });
  for (const opts of [{ scopes: ['sales'] }, { userId: 'admin' }, { provenance: { to: ['trusted-user'] } }, { sessionTainted: false }, { other: 1 }, null, 'x', []]) {
    const r = await agent.call('set_discount', { percent: 5 }, opts as never);
    assert.equal(reason(r), 'invalid_request', JSON.stringify(opts));
    assert.equal(row(k, r.decision_id)?.reason_code, 'invalid_request');
  }
  assert.equal(k.count('set_discount'), 0);
  k.store.close();
});

test('S-02: scopes come only from the host binding', async () => {
  const k = mk();
  const plain = k.guard.forAgent({ userId: 'u-1' });
  assert.equal(reason(await plain.call('set_discount', { percent: 5 })), 'denied');
  const sales = k.guard.forAgent({ userId: 'u-2', scopes: ['sales'] });
  assert.equal(reason(await sales.call('set_discount', { percent: 5 })), 'ok');
  assert.equal(k.count('set_discount'), 1);
  k.store.close();
});

test('S-02: a binding array mutated after forAgent() does not change the facet', async () => {
  const k = mk();
  const scopes: string[] = [];
  const agent = k.guard.forAgent({ scopes });
  scopes.push('sales');
  assert.equal(reason(await agent.call('set_discount', { percent: 5 })), 'denied');
  k.store.close();
});

test('S-02 / F7: provenance comes only from the host callback, which sees the frozen, normalised snapshot', async () => {
  const k = mk();
  const seen: unknown[] = [];
  const agent = k.guard.forAgent({
    provenance: (tool, args) => {
      seen.push(args);
      return tool === 'send_email' ? { to: ['trusted-user'] } : undefined;
    },
  });
  const decomposed = 'café@b.c'; // NFD; the policy decides on the NFC form, and so must the callback
  const r = await agent.call('send_email', { to: 'a@b.c', subject: 's', body: 'b' });
  assert.equal(reason(r), 'ok');
  await agent.call('send_email', { to: decomposed, subject: 's', body: 'b' });
  assert.equal(seen.length, 2);
  assert.ok(Object.isFrozen(seen[0]), 'the callback gets the frozen snapshot');
  assert.equal((seen[1] as { to: string }).to, decomposed.normalize('NFC'));
  // a callback that tries to mutate the arguments throws on the frozen snapshot: the call fails closed
  const mutating = k.guard.forAgent({
    provenance: (_tool, args) => { (args as Record<string, unknown>)['to'] = 'mutated@evil.example'; return undefined; },
  });
  assert.equal(reason(await mutating.call('send_email', { to: 'a@b.c', subject: 's', body: 'b' })), 'invalid_request');
  assert.equal(k.calls['send_email']?.every((c) => (c[0] as { to: string }).to !== 'mutated@evil.example'), true);
  const untrusted = k.guard.forAgent({ provenance: () => ({ to: ['model-generated'] }) });
  assert.equal(reason(await untrusted.call('send_email', { to: 'a@b.c', subject: 's', body: 'b' })), 'denied');
  k.store.close();
});

test('S-02: a throwing or malformed provenance callback fails closed', async () => {
  const k = mk();
  const throwing = k.guard.forAgent({ provenance: () => { throw new Error('boom'); } });
  assert.equal(reason(await throwing.call('send_email', { to: 'a@b.c', subject: 's', body: 'b' })), 'invalid_request');
  const bad = k.guard.forAgent({ provenance: () => ({ to: 'trusted-user' }) as never });
  assert.equal(reason(await bad.call('send_email', { to: 'a@b.c', subject: 's', body: 'b' })), 'invalid_request');
  const asyncFn = k.guard.forAgent({ provenance: (async () => ({ to: ['trusted-user'] })) as never });
  assert.equal(reason(await asyncFn.call('send_email', { to: 'a@b.c', subject: 's', body: 'b' })), 'invalid_request');
  assert.equal(k.count('send_email'), 0);
  k.store.close();
});

test('S-02/S-05: the facet is session-bound, so taint is sticky across its calls; the agent may only add taint', async () => {
  const k = mk();
  const trusted = (tool: string) => (tool === 'send_email' ? { to: ['trusted-user'] } : undefined);
  const agent = k.guard.forAgent({ sessionId: 'agent-s1', provenance: trusted });
  assert.equal(agent.sessionId, 'agent-s1');
  assert.equal(agent.tainted, false);
  assert.equal(reason(await agent.call('search_docs', { query: 'q' })), 'ok');
  assert.equal(agent.tainted, true);
  assert.equal(reason(await agent.call('send_email', { to: 'a@b.c', subject: 's', body: 'b' })), 'denied');
  // a fresh facet on a fresh session can taint itself for one call, never un-taint
  const other = k.guard.forAgent({ provenance: trusted });
  assert.equal(reason(await other.call('send_email', { to: 'a@b.c', subject: 's', body: 'b' }, { sessionTainted: true })), 'denied');
  assert.equal(reason(await other.call('send_email', { to: 'a@b.c', subject: 's', body: 'b' })), 'ok');
  k.store.close();
});

test('S-02: the facet exposes no host capability and rejects bad bindings', () => {
  const k = mk();
  const agent = k.guard.forAgent();
  assert.deepEqual(Object.keys(agent).sort(), ['call', 'sessionId', 'tainted']);
  assert.ok(Object.isFrozen(agent));
  for (const b of [{ scopes: 'sales' }, { userId: 7 }, { provenance: {} }, { admin: true }, { sessionId: 'bad id!' }]) {
    assert.throws(() => k.guard.forAgent(b as never), b.sessionId ? /invalid_session_id/ : TypeError);
  }
  k.store.close();
});

test('S-05: a taint on an ephemeral host call is reported once on the sink', async () => {
  const k = mk();
  await k.guard.call('search_docs', { query: 'q' });
  await k.guard.call('search_docs', { query: 'q2' });
  const warns = k.lines.filter((l) => (JSON.parse(l) as { prysm: string }).prysm === 'ephemeral_taint_dropped');
  assert.equal(warns.length, 1);
  k.store.close();
});
