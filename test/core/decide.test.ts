import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decide, evaluate, isSnapshot, toolInfo, loadPolicy } from '../../src/core/index.ts';
import type { Decision, LoadedPolicy } from '../../src/core/index.ts';
import { mk, permit, deny, policyDoc, req, prng, TOOLS } from './helpers.ts';
import type { RuleLike } from './helpers.ts';

const mail = (to: string, extra: Record<string, unknown> = {}) => ({ to, subject: 's', body: 'b', ...extra });

function eff(p: LoadedPolicy, r: unknown): string {
  const d = decide(p, r);
  return `${d.effect}:${d.reason_code}`;
}

// ---------------------------------------------------------------- precedence

test('01 deny beats permit when both match (order independent)', () => {
  const rules = [permit('a.permit', { tools: ['read_file'] }), deny('b.deny', { tools: ['read_file'] })];
  for (const rs of [rules, [...rules].reverse()]) {
    const d = decide(mk(rs), req('read_file', { path: '/x' }));
    assert.equal(d.effect, 'deny');
    assert.equal(d.reason_code, 'denied_by_rule');
    assert.deepEqual(d.matched, { deny: ['b.deny'], permit: ['a.permit'] });
  }
});

test('02 default deny with no matching rule, and with no rules at all', () => {
  assert.equal(eff(mk([]), req('read_file', { path: '/x' })), 'deny:default_deny');
  const p = mk([permit('a', { tools: ['http_get'] })]);
  assert.equal(eff(p, req('read_file', { path: '/x' })), 'deny:default_deny');
});

test('03 unknown tool is denied, even if a rule has no tools clause', () => {
  const p = mk([permit('any', { agents: ['agent-1'] })]);
  assert.equal(eff(p, req('rm_rf', {})), 'deny:unknown_tool');
  assert.equal(eff(p, req('', {})), 'deny:unknown_tool');
  assert.equal(eff(p, req('constructor', {})), 'deny:unknown_tool');
  assert.equal(eff(p, req('__proto__', {})), 'deny:unknown_tool');
  assert.equal(eff(p, req('toString', {})), 'deny:unknown_tool');
  assert.equal(eff(p, req('READ_FILE', { path: '/x' })), 'deny:unknown_tool');
  assert.equal(eff(p, req('read_file ', { path: '/x' })), 'deny:unknown_tool');
});

test('04 strict args: undeclared argument is invalid_args', () => {
  const p = mk([permit('a', { tools: ['read_file'] })]);
  assert.equal(eff(p, req('read_file', { path: '/x' })), 'permit:permitted');
  assert.equal(eff(p, req('read_file', { path: '/x', mode: 'rw' })), 'deny:invalid_args');
  assert.equal(eff(p, req('read_file', { path: '/x', toString: 'x' })), 'deny:invalid_args');
});

test('05 strict args: missing required argument is invalid_args, optional may be absent', () => {
  const p = mk([permit('a', { tools: ['send_email'] })]);
  assert.equal(eff(p, req('send_email', { to: 'a', subject: 's' })), 'deny:invalid_args');
  assert.equal(eff(p, req('send_email', {})), 'deny:invalid_args');
  assert.equal(eff(p, req('send_email', mail('a'))), 'permit:permitted');
  assert.equal(eff(p, req('send_email', mail('a', { cc: 'c' }))), 'permit:permitted');
});

test('06 strict args: wrong types are invalid_args', () => {
  const p = mk([permit('a', { tools: ['set_discount', 'tag_item', 'read_file'] })]);
  assert.equal(eff(p, req('set_discount', { percent: '5' })), 'deny:invalid_args');
  assert.equal(eff(p, req('set_discount', { percent: null })), 'deny:invalid_args');
  assert.equal(eff(p, req('set_discount', { percent: [5] })), 'deny:invalid_args');
  assert.equal(eff(p, req('read_file', { path: 5 })), 'deny:invalid_args');
  assert.equal(eff(p, req('read_file', { path: ['/x'] })), 'deny:invalid_args');
  assert.equal(eff(p, req('read_file', { path: { a: 1 } })), 'deny:invalid_args');
  assert.equal(eff(p, req('tag_item', { tags: 'a' })), 'deny:invalid_args');
  assert.equal(eff(p, req('tag_item', { tags: ['a', 1] })), 'deny:invalid_args');
  assert.equal(eff(p, req('tag_item', { tags: ['a'], flag: 'yes' })), 'deny:invalid_args');
  assert.equal(eff(p, req('tag_item', { tags: [] })), 'permit:permitted');
  assert.equal(eff(p, req('tag_item', { tags: ['a'], flag: false })), 'permit:permitted');
});

test('07 invalid_args is decided before rules: deny rules cannot be bypassed or confused by bad args', () => {
  const p = mk([deny('d', { tools: ['read_file'] })]);
  const d = decide(p, req('read_file', { path: 5 }));
  assert.equal(d.reason_code, 'invalid_args');
  assert.deepEqual(d.matched, { deny: [], permit: [] });
});

test('08 absent optional arg never matches an args predicate, for permit or deny', () => {
  const p = mk([permit('p', { tools: ['send_email'] }), deny('d.cc', { tools: ['send_email'], args: { cc: { glob: '*@*' } } })]);
  assert.equal(eff(p, req('send_email', mail('a'))), 'permit:permitted'); // deny rule did not match (absent)
  assert.equal(eff(p, req('send_email', mail('a', { cc: 'x@evil.com' }))), 'deny:denied_by_rule');
  const q = mk([permit('p.cc', { tools: ['send_email'], args: { cc: { glob: '*' } } })]);
  assert.equal(eff(q, req('send_email', mail('a'))), 'deny:default_deny');
  const tr = decide(q, req('send_email', mail('a'))).trace;
  assert.equal(tr[0]?.matched, false);
});

test('09 provenance on an absent optional arg does not match', () => {
  const p = mk([permit('p', { tools: ['send_email'], provenance: { cc: { all_in: ['trusted-user'] } } })]);
  assert.equal(eff(p, req('send_email', mail('a'))), 'deny:default_deny');
  assert.equal(eff(p, req('send_email', mail('a', { cc: 'c' }), { provenance: { cc: ['trusted-user'] } })), 'permit:permitted');
});

test('10 tainted session + external effect: permit rules are not enough', () => {
  const p = mk([permit('p', { tools: ['send_email'] })]);
  assert.equal(eff(p, req('send_email', mail('a'), { sessionTainted: false })), 'permit:permitted');
  assert.equal(eff(p, req('send_email', mail('a'), { sessionTainted: true })), 'deny:tainted_session');
  assert.equal(eff(p, req('http_get', { url: 'http://corp.com' }, { sessionTainted: true })), 'deny:tainted_session'); // external effect, no matching permit
});

test('11 tainted session + non-external tool is decided normally', () => {
  const p = mk([permit('p', { tools: ['read_file'] })]);
  assert.equal(eff(p, req('read_file', { path: '/x' }, { sessionTainted: true })), 'permit:permitted');
});

test('12 session_tainted opt-in permit allows an external tool in a tainted session', () => {
  const p = mk([
    permit('p.normal', { tools: ['send_email'] }),
    permit('p.tainted-ok', { tools: ['send_email'], session_tainted: true, args: { to: { domain_exact: 'corp.com', accept: ['email'] } } }),
  ]);
  assert.equal(eff(p, req('send_email', mail('x@corp.com'), { sessionTainted: true })), 'permit:permitted');
  // opt-in rule does not match for another recipient => still tainted_session
  assert.equal(eff(p, req('send_email', mail('x@other.com'), { sessionTainted: true })), 'deny:tainted_session');
  // string 'true' (not boolean true) is invalid, and `undefined` means untainted
  assert.equal(eff(p, req('send_email', mail('x@other.com'), { sessionTainted: 'true' })), 'deny:invalid_request');
  assert.equal(eff(p, req('send_email', mail('x@other.com'))), 'permit:permitted');
});

test('13 tainted session: a matching deny rule still wins over the opt-in permit', () => {
  const p = mk([
    permit('p.t', { tools: ['send_email'], session_tainted: true }),
    deny('d', { tools: ['send_email'], args: { subject: { equals: 's' } } }),
  ]);
  assert.equal(eff(p, req('send_email', mail('a'), { sessionTainted: true })), 'deny:denied_by_rule');
});

test('14 session_tainted:true rules only match tainted sessions; false rules only untainted', () => {
  const p = mk([deny('d.t', { tools: ['read_file'], session_tainted: true }), permit('p.u', { tools: ['read_file'], session_tainted: false })]);
  assert.equal(eff(p, req('read_file', { path: '/x' })), 'permit:permitted');
  assert.equal(eff(p, req('read_file', { path: '/x' }, { sessionTainted: false })), 'permit:permitted');
  assert.equal(eff(p, req('read_file', { path: '/x' }, { sessionTainted: true })), 'deny:denied_by_rule');
});

test('15 provenance: missing tags default to untrusted:unknown and fail trusted-only rules', () => {
  const p = mk([permit('p', { tools: ['send_email'], args: { to: { domain_suffix: 'corp.com', accept: ['email'] } }, provenance: { to: { all_in: ['trusted-user', 'policy-constant'] } } })]);
  const m = mail('a@corp.com');
  assert.equal(eff(p, req('send_email', m)), 'deny:default_deny');
  assert.equal(eff(p, req('send_email', m, { provenance: { to: [] } })), 'deny:default_deny');
  assert.equal(eff(p, req('send_email', m, { provenance: { to: ['trusted-user'] } })), 'permit:permitted');
  assert.equal(eff(p, req('send_email', m, { provenance: { to: ['trusted-user', 'policy-constant'] } })), 'permit:permitted');
  assert.equal(eff(p, req('send_email', m, { provenance: { to: ['trusted-user', 'tool:web'] } })), 'deny:default_deny');
  assert.equal(eff(p, req('send_email', m, { provenance: { to: ['untrusted:unknown'] } })), 'deny:default_deny');
  // tags never come from args
  assert.equal(eff(p, req('send_email', mail('a@corp.com', { cc: 'x' }), { provenance: {} })), 'deny:default_deny'); // provenance for `to` missing => untrusted:unknown
});

test('16 provenance any_in and combined all_in+any_in', () => {
  const any = mk([permit('p', { tools: ['read_file'], provenance: { path: { any_in: ['trusted-user', 'x:y'] } } })]);
  assert.equal(eff(any, req('read_file', { path: '/a' }, { provenance: { path: ['tool:web', 'x:y'] } })), 'permit:permitted');
  assert.equal(eff(any, req('read_file', { path: '/a' }, { provenance: { path: ['tool:web'] } })), 'deny:default_deny');
  assert.equal(eff(any, req('read_file', { path: '/a' })), 'deny:default_deny');
  const both = mk([permit('p', { tools: ['read_file'], provenance: { path: { all_in: ['a', 'b'], any_in: ['b'] } } })]);
  assert.equal(eff(both, req('read_file', { path: '/a' }, { provenance: { path: ['a', 'b'] } })), 'permit:permitted');
  assert.equal(eff(both, req('read_file', { path: '/a' }, { provenance: { path: ['a'] } })), 'deny:default_deny');
  // a deny rule keyed on untrusted provenance fires by default
  const d = mk([permit('p', { tools: ['read_file'] }), deny('d', { tools: ['read_file'], provenance: { path: { any_in: ['untrusted:unknown'] } } })]);
  assert.equal(eff(d, req('read_file', { path: '/a' })), 'deny:denied_by_rule');
  assert.equal(eff(d, req('read_file', { path: '/a' }, { provenance: { path: ['trusted-user'] } })), 'permit:permitted');
});

test('17 provenance keys must be declared args of the tool, else invalid_request', () => {
  const p = mk([permit('p', { tools: ['read_file'] })]);
  assert.equal(eff(p, req('read_file', { path: '/a' }, { provenance: { nope: ['trusted-user'] } })), 'deny:invalid_request');
  assert.equal(eff(p, req('read_file', { path: '/a' }, { provenance: { to: ['trusted-user'] } })), 'deny:invalid_request');
  assert.equal(eff(p, req('read_file', { path: '/a' }, { provenance: { path: ['bad label'] } })), 'deny:invalid_request');
  // step 3b comes after the tool lookup and args check: unknown tool wins
  assert.equal(eff(p, req('nope', {}, { provenance: { zzz: ['trusted-user'] } })), 'deny:unknown_tool');
  assert.equal(eff(p, req('read_file', {}, { provenance: { zzz: ['trusted-user'] } })), 'deny:invalid_args');
});

test('18 agents and scopes_any clauses (AND semantics)', () => {
  const p = mk([permit('p', { tools: ['set_discount'], agents: ['agent-1', 'agent-2'], scopes_any: ['sales', 'admin'] })]);
  const a = { percent: 5 };
  assert.equal(eff(p, req('set_discount', a, { scopes: ['sales'] })), 'permit:permitted');
  assert.equal(eff(p, req('set_discount', a, { scopes: ['x', 'admin'] })), 'permit:permitted');
  assert.equal(eff(p, req('set_discount', a, { scopes: ['x'] })), 'deny:default_deny');
  assert.equal(eff(p, req('set_discount', a)), 'deny:default_deny');
  assert.equal(eff(p, req('set_discount', a, { scopes: [] })), 'deny:default_deny');
  assert.equal(eff(p, req('set_discount', a, { agentId: 'agent-3', scopes: ['sales'] })), 'deny:default_deny');
  assert.equal(eff(p, req('set_discount', a, { agentId: 'AGENT-1', scopes: ['sales'] })), 'deny:default_deny');
});

test('19 range predicate boundaries (inclusive, -0, wrong type)', () => {
  const p = mk([permit('p', { tools: ['set_discount'], args: { percent: { range: { min: 0, max: 10 } } } })]);
  for (const [v, e] of [[0, 'permit'], [-0, 'permit'], [10, 'permit'], [5.5, 'permit'], [10.0000001, 'deny'], [-0.0000001, 'deny'], [1e308, 'deny'], [-1, 'deny']] as const) {
    assert.equal(decide(p, req('set_discount', { percent: v })).effect, e, String(v));
  }
  assert.equal(eff(p, req('set_discount', { percent: NaN })), 'deny:invalid_request');
  assert.equal(eff(p, req('set_discount', { percent: Infinity })), 'deny:invalid_request');
  const onlyMin = mk([permit('p', { tools: ['set_discount'], args: { percent: { range: { min: 5 } } } })]);
  assert.equal(decide(onlyMin, req('set_discount', { percent: 5 })).effect, 'permit');
  assert.equal(decide(onlyMin, req('set_discount', { percent: 4.99 })).effect, 'deny');
  const neg = mk([permit('p', { tools: ['set_discount'], args: { percent: { range: { min: -0, max: 0 } } } })]);
  assert.equal(decide(neg, req('set_discount', { percent: -0 })).effect, 'permit');
});

test('20 equals / in / max_length / glob; no coercion; NFC', () => {
  const p = mk([
    permit('eq', { tools: ['read_file'], args: { path: { equals: '/a' } } }),
    permit('in', { tools: ['http_get'], args: { url: { in: ['http://a', 'http://b'] } } }),
    permit('ml', { tools: ['search_docs'], args: { query: { max_length: 3 } } }),
    permit('nfc', { tools: ['tag_item'], args: { tags: { equals: 'é' } } }),
    permit('num', { tools: ['set_discount'], args: { percent: { in: [1, 2, 3] } } }),
  ]);
  assert.equal(eff(p, req('read_file', { path: '/a' })), 'permit:permitted');
  assert.equal(eff(p, req('read_file', { path: '/A' })), 'deny:default_deny');
  assert.equal(eff(p, req('http_get', { url: 'http://b' })), 'permit:permitted');
  assert.equal(eff(p, req('http_get', { url: 'http://c' })), 'deny:default_deny');
  assert.equal(eff(p, req('search_docs', { query: 'abc' })), 'permit:permitted');
  assert.equal(eff(p, req('search_docs', { query: 'abcd' })), 'deny:default_deny');
  assert.equal(eff(p, req('search_docs', { query: '😀😀😀' })), 'permit:permitted'); // 3 code points
  assert.equal(eff(p, req('search_docs', { query: '😀'.repeat(4) })), 'deny:default_deny');
  assert.equal(eff(p, req('tag_item', { tags: ['é'] })), 'permit:permitted'); // NFC equal
  assert.equal(eff(p, req('set_discount', { percent: 2 })), 'permit:permitted');
  assert.equal(eff(p, req('set_discount', { percent: 4 })), 'deny:default_deny');
});

test('21 string[] args: every element must satisfy the predicate; empty array never matches', () => {
  const p = mk([permit('p', { tools: ['tag_item'], args: { tags: { glob: 'ok-*' } } })]);
  assert.equal(eff(p, req('tag_item', { tags: ['ok-1', 'ok-2'] })), 'permit:permitted');
  assert.equal(eff(p, req('tag_item', { tags: ['ok-1', 'bad'] })), 'deny:default_deny');
  assert.equal(eff(p, req('tag_item', { tags: [] })), 'deny:default_deny');
  // deny over arrays matches if ANY element matches (spec 10.1)
  const d = mk([permit('p', { tools: ['tag_item'] }), deny('d', { tools: ['tag_item'], args: { tags: { glob: 'bad-*' } } })]);
  assert.equal(eff(d, req('tag_item', { tags: ['bad-1', 'bad-2'] })), 'deny:denied_by_rule');
  assert.equal(eff(d, req('tag_item', { tags: ['bad-1', 'fine'] })), 'deny:denied_by_rule');
  assert.equal(eff(d, req('tag_item', { tags: ['fine', 'bad-1'] })), 'deny:denied_by_rule');
  assert.equal(eff(d, req('tag_item', { tags: ['fine', 'fine2'] })), 'permit:permitted');
});

test('22 invalid and oversized requests deny with the right reason', () => {
  const p = mk([permit('p', { tools: ['read_file'] })]);
  assert.equal(eff(p, undefined), 'deny:invalid_request');
  assert.equal(eff(p, null), 'deny:invalid_request');
  assert.equal(eff(p, req('read_file', { path: undefined })), 'deny:invalid_request');
  assert.equal(eff(p, req('read_file', { path: '\ud800' })), 'deny:invalid_request');
  assert.equal(eff(p, req('read_file', { path: '/a' }, { agentId: '' })), 'deny:invalid_request');
  assert.equal(eff(p, req('read_file', { path: 'x'.repeat(9000) })), 'deny:limit_exceeded');
  assert.equal(eff(p, req('read_file', { path: '/a' }, { scopes: Array.from({ length: 300 }, () => 's') })), 'deny:limit_exceeded');
  assert.equal(eff(p, JSON.parse('{"tool":"read_file","args":{"__proto__":{"path":"/x"}},"ctx":{"agentId":"a"}}')), 'deny:invalid_request');
});

test('23 monitor_only computes the same decision as enforce (mode is reported, version differs)', () => {
  const rules = [permit('p', { tools: ['read_file'] }), deny('d', { tools: ['read_file'], args: { path: { glob: '/secret*' } } })];
  const e = mk(rules, 'enforce');
  const m = mk(rules, 'monitor_only');
  for (const path of ['/a', '/secret', '/secrets/x']) {
    const de = decide(e, req('read_file', { path }));
    const dm = decide(m, req('read_file', { path }));
    assert.equal(de.mode, 'enforce');
    assert.equal(dm.mode, 'monitor_only');
    assert.notEqual(de.policy_version, dm.policy_version);
    assert.deepEqual({ ...dm, mode: 'enforce', policy_version: de.policy_version }, de);
  }
});

test('24 result shape: sorted matched ids, sorted trace with reasons, frozen, policy_version', () => {
  const p = mk([
    permit('z.p', { tools: ['read_file'] }), permit('a.p', { tools: ['read_file'] }),
    deny('m.d', { tools: ['http_get'] }), deny('b.d', { tools: ['read_file'], args: { path: { glob: '*' } } }), deny('a.d', { tools: ['read_file'] }),
  ]);
  const d = decide(p, req('read_file', { path: '/x' }));
  assert.deepEqual(d.matched, { deny: ['a.d', 'b.d'], permit: ['a.p', 'z.p'] });
  assert.deepEqual(d.trace.map((t) => t.rule), ['a.d', 'a.p', 'b.d', 'm.d', 'z.p']);
  assert.deepEqual(d.trace.map((t) => t.matched), [true, true, true, false, true]);
  assert.equal(d.trace.find((t) => t.rule === 'm.d')?.why, 'no_match:tools');
  assert.equal(d.policy_version, p.policy_version);
  assert.ok(Object.isFrozen(d) && Object.isFrozen(d.matched) && Object.isFrozen(d.trace));
  assert.equal(typeof d.trace[0]?.why, 'string');
});

test('25 decide() with a policy that was not produced by loadPolicy denies with engine_error', () => {
  for (const bad of [null, undefined, {}, 5, 'x', [], new Proxy({}, {}), { document: {}, policy_version: 'x' }, JSON.parse(JSON.stringify(mk([])))]) {
    const d = decide(bad as never, req('read_file', { path: '/a' }));
    assert.equal(d.effect, 'deny');
    assert.equal(d.reason_code, 'engine_error');
  }
  const thrower = new Proxy({}, { get() { throw new Error('boom'); }, getPrototypeOf() { throw new Error('boom'); } });
  assert.equal(decide(thrower as never, {}).reason_code, 'engine_error');
});

test('26 tool names that collide with Object.prototype members are not tools', () => {
  const p = mk([permit('p', { tools: ['read_file'] })]);
  for (const t of ['hasOwnProperty', 'valueOf', '__defineGetter__', 'isPrototypeOf']) assert.equal(eff(p, req(t, {})), 'deny:unknown_tool', t);
  const q = mk([permit('p', { tools: ['read_file'] })]);
  assert.equal(eff(q, req('read_file', { path: '/a', hasOwnProperty: 1 })), 'deny:invalid_args');
});

test('27 fixture policy behaves as written', () => {
  const p = loadPolicy(readFileSync(new URL('../../eval/policies/support-agent.policy.json', import.meta.url)));
  assert.equal(eff(p, req('search_docs', { query: 'refund' })), 'permit:permitted');
  assert.equal(eff(p, req('read_file', { path: '/workspace/notes.txt' })), 'permit:permitted');
  assert.equal(eff(p, req('read_file', { path: '/workspace/../etc/passwd' })), 'deny:default_deny');
  assert.equal(eff(p, req('read_file', { path: '/workspace/secrets/key' })), 'deny:denied_by_rule');
  assert.equal(eff(p, req('read_file', { path: '/WORKSPACE/Secrets/key' })), 'deny:denied_by_rule'); // case-insensitive deny matches
  assert.equal(eff(p, req('read_file', { path: '/workspace/SECRETS/../secrets/k' })), 'deny:denied_by_rule');
  assert.equal(eff(p, req('read_file', { path: '/workspace/SECRETS/key' })), 'deny:denied_by_rule');
  assert.equal(eff(p, req('read_file', { path: '/workspace/secrets/key' }, { provenance: { path: ['trusted-user'] } })), 'deny:denied_by_rule');
  assert.equal(eff(p, req('delete_file', { path: '/workspace/a' })), 'deny:denied_by_rule');
  assert.equal(eff(p, req('send_email', mail('bob@corp.com'), { provenance: { to: ['trusted-user'] } })), 'permit:permitted');
  assert.equal(eff(p, req('send_email', mail('bob@corp.com'))), 'deny:default_deny');
  assert.equal(eff(p, req('send_email', mail('bob@corp.com.evil.com'), { provenance: { to: ['trusted-user'] } })), 'deny:default_deny');
  assert.equal(eff(p, req('send_email', mail('bob@corp.com', { cc: 'x@evil.com' }), { provenance: { to: ['trusted-user'] } })), 'deny:denied_by_rule');
  assert.equal(eff(p, req('send_email', mail('bob@corp.com'), { provenance: { to: ['trusted-user'] }, sessionTainted: true })), 'deny:tainted_session');
  assert.equal(eff(p, req('http_get', { url: 'https://docs.corp.com/a' })), 'permit:permitted');
  assert.equal(eff(p, req('http_get', { url: 'https://docs.corp.com@evil.com/a' })), 'deny:default_deny');
  assert.equal(eff(p, req('set_discount', { percent: 5 }, { scopes: ['sales'] })), 'permit:permitted');
  assert.equal(eff(p, req('set_discount', { percent: 50 }, { scopes: ['sales'] })), 'deny:default_deny');
  assert.equal(eff(p, req('set_discount', { percent: 5 })), 'deny:default_deny');
});

// ---------------------------------------------------------------- property tests

const PATHS = ['/w/a', '/w/../etc', '/w', '/x/y', 'rel', '/w/CON', ''];
const STRS = ['a', 'ab', 'abc', 'x@corp.com', 'corp.com', 'http://corp.com/x', 'http://evil.com', '/w/a', '/w/../etc', 'é', ''];
const LABELS = ['trusted-user', 'policy-constant', 'tool:web', 'untrusted:unknown'];

function pick<T>(r: () => number, a: readonly T[]): T {
  return a[Math.floor(r() * a.length)] as T;
}

const TOOL_ARGS: Record<string, { name: string; type: string }[]> = {};
for (const [t, def] of Object.entries(TOOLS)) {
  TOOL_ARGS[t] = Object.entries(def.args).map(([name, a]) => ({ name, type: a.type }));
}

function genPredicate(r: () => number, type: string): unknown {
  if (type === 'number') return pick(r, [{ range: { min: 0, max: 10 } }, { equals: 5 }, { in: [1, 2, 3] }, { range: { max: 3 } }]);
  if (type === 'boolean') return { equals: true };
  return pick(r, [
    { equals: 'a' }, { in: ['a', 'ab'] }, { glob: 'a*' }, { glob: '*c' }, { max_length: 2 }, { domain_suffix: 'corp.com', accept: ['email', 'host'] },
    { domain_exact: 'corp.com', accept: ['url'] }, { path_within: { root: '/w', case_insensitive: false } }, { glob: '?' },
  ]);
}

function genRule(r: () => number, id: string, effect?: 'permit' | 'deny'): RuleLike {
  const tool = pick(r, Object.keys(TOOLS));
  const args = TOOL_ARGS[tool] as { name: string; type: string }[];
  const match: Record<string, unknown> = {};
  if (r() < 0.9) match['tools'] = [tool];
  if (match['tools'] === undefined) {
    // without a tools clause every arg must be declared by some tool; keep it simple and add a safe clause
    match['agents'] = pick(r, [['agent-1'], ['agent-2'], ['agent-1', 'agent-2']]);
  }
  if (r() < 0.6) {
    const a = pick(r, args);
    match['args'] = { [a.name]: genPredicate(r, a.type) };
  }
  if (r() < 0.25) match['session_tainted'] = r() < 0.5;
  if (r() < 0.2) match['scopes_any'] = [pick(r, ['sales', 'admin'])];
  if (r() < 0.25) {
    const a = pick(r, args);
    match['provenance'] = { [a.name]: r() < 0.5 ? { all_in: ['trusted-user', 'policy-constant'] } : { any_in: ['tool:web', 'untrusted:unknown'] } };
  }
  return { id, effect: effect ?? (r() < 0.45 ? 'deny' : 'permit'), reason_code: 'rc', match };
}

function genValue(r: () => number, type: string): unknown {
  if (type === 'number') return pick(r, [0, -0, 1, 5, 10, 11, -1, 2.5]);
  if (type === 'boolean') return r() < 0.5;
  if (type === 'string[]') return Array.from({ length: Math.floor(r() * 3) }, () => pick(r, STRS));
  return pick(r, [...STRS, ...PATHS]);
}

function genRequest(r: () => number): Record<string, unknown> {
  const tool = r() < 0.05 ? 'no_such_tool' : pick(r, Object.keys(TOOLS));
  const defs = TOOL_ARGS[tool] ?? [];
  const args: Record<string, unknown> = {};
  for (const a of defs) {
    const optional = (TOOLS as Record<string, { args: Record<string, { optional?: boolean }> }>)[tool]?.args[a.name]?.optional === true;
    if (optional && r() < 0.5) continue;
    if (r() < 0.03) continue; // occasionally invalid
    args[a.name] = genValue(r, a.type);
  }
  const ctx: Record<string, unknown> = { agentId: pick(r, ['agent-1', 'agent-2', 'agent-3']) };
  if (r() < 0.5) ctx['scopes'] = r() < 0.5 ? ['sales'] : ['admin', 'x'];
  if (r() < 0.5) ctx['sessionTainted'] = r() < 0.5;
  if (r() < 0.5 && defs.length > 0) {
    const a = pick(r, defs);
    ctx['provenance'] = { [a.name]: Array.from({ length: Math.floor(r() * 3) }, () => pick(r, LABELS)) };
  }
  return { tool, args, ctx };
}

function genRules(r: () => number, n: number): RuleLike[] {
  return Array.from({ length: n }, (_, i) => genRule(r, `rule${String(i).padStart(2, '0')}`));
}

function shuffle<T>(r: () => number, a: readonly T[]): T[] {
  const out = [...a];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(r() * (i + 1));
    [out[i], out[j]] = [out[j] as T, out[i] as T];
  }
  return out;
}


test('property (a): shuffling rule order never changes the Decision (including trace)', () => {
  const r = prng(0xc0ffee);
  let permits = 0;
  let denies = 0;
  for (let i = 0; i < 300; i++) {
    const rules = genRules(r, 3 + Math.floor(r() * 10));
    const p1 = mk(rules);
    const p2 = mk(shuffle(r, rules));
    const p3 = mk([...rules].reverse());
    for (let j = 0; j < 8; j++) {
      const rq = genRequest(r);
      const d1 = decide(p1, rq);
      assert.deepEqual(decide(p2, rq), d1);
      assert.deepEqual(decide(p3, rq), d1);
      assert.equal(p2.policy_version, p1.policy_version);
      assert.equal(p3.policy_version, p1.policy_version);
      if (d1.effect === 'permit') permits++;
      else denies++;
    }
  }
  assert.ok(permits > 50 && denies > 50, `generator is degenerate: ${permits} permits, ${denies} denies`);
});

test('property (b): adding a deny rule never turns a deny into a permit', () => {
  const r = prng(0xbadf00d);
  let checked = 0;
  for (let i = 0; i < 300; i++) {
    const rules = genRules(r, 3 + Math.floor(r() * 8));
    const base = mk(rules);
    const extended = mk([...rules, genRule(r, 'zz.extra', 'deny')]);
    for (let j = 0; j < 8; j++) {
      const rq = genRequest(r);
      const before = decide(base, rq);
      const after = decide(extended, rq);
      if (before.effect === 'deny') {
        assert.equal(after.effect, 'deny', JSON.stringify({ rules, rq }));
        checked++;
      }
      if (before.effect === 'permit' && after.effect === 'permit') {
        assert.ok(!after.matched.deny.includes('zz.extra'));
      }
    }
  }
  assert.ok(checked > 100);
});

test('property (b2): adding a permit rule never turns a deny-by-rule/invalid decision into a permit', () => {
  const r = prng(0x5eed);
  for (let i = 0; i < 200; i++) {
    const rules = genRules(r, 3 + Math.floor(r() * 8));
    const base = mk(rules);
    const extended = mk([...rules, genRule(r, 'zz.extra', 'permit')]);
    for (let j = 0; j < 8; j++) {
      const rq = genRequest(r);
      const before = decide(base, rq);
      if (['denied_by_rule', 'invalid_args', 'unknown_tool', 'invalid_request', 'limit_exceeded'].includes(before.reason_code)) {
        assert.equal(decide(extended, rq).effect, 'deny');
      }
    }
  }
});

test('property (c): decide() is deterministic and idempotent over 1000 repeats', () => {
  const r = prng(42);
  const rules = genRules(r, 12);
  const p = mk(rules);
  const rq = req('send_email', mail('a@corp.com'), { provenance: { to: ['trusted-user'] } });
  const first = decide(p, rq);
  for (let i = 0; i < 1000; i++) assert.deepEqual(decide(p, rq), first);
  for (let i = 0; i < 1000; i++) {
    const q = genRequest(r);
    const a = decide(p, q);
    assert.deepEqual(decide(p, q), a);
  }
  // deciding on a frozen snapshot of the same request equals deciding on the raw request
  const raw = genRequest(r);
  assert.deepEqual(decide(p, JSON.parse(JSON.stringify(raw))), decide(p, raw));
});

test('property (c2): decide() does not mutate its input or the policy', () => {
  const p = mk([permit('p', { tools: ['read_file'] })]);
  const rq = req('read_file', { path: '/a' }, { scopes: ['s'] });
  const before = JSON.stringify(rq);
  const docBefore = JSON.stringify(p.document);
  decide(p, rq);
  assert.equal(JSON.stringify(rq), before);
  assert.equal(JSON.stringify(p.document), docBefore);
});

// ---------------------------------------------------------------- fuzz

class Weird { x = 1; }

function garbage(r: () => number, depth = 0): unknown {
  const k = Math.floor(r() * 24);
  switch (k) {
    case 0: return undefined;
    case 1: return null;
    case 2: return NaN;
    case 3: return -Infinity;
    case 4: return 10n ** 30n;
    case 5: return Symbol('s');
    case 6: return () => 1;
    case 7: return 'x'.repeat(10_000 + Math.floor(r() * 1_000_000));
    case 8: return '\ud800';
    case 9: return new Weird();
    case 10: return new Map([[1, 2]]);
    case 11: return new Date(NaN);
    case 12: return new Proxy({}, { get() { throw new Error('trap'); }, ownKeys() { throw new Error('trap'); }, getPrototypeOf() { throw new Error('trap'); } });
    case 13: return new Proxy([], {});
    case 14: return { get a() { throw new Error('getter'); } };
    case 15: { const c: Record<string, unknown> = {}; c['c'] = c; return c; }
    case 16: return Object.create({ inherited: 1 });
    case 17: return JSON.parse('{"__proto__":{"polluted":true}}');
    case 18: return Array.from({ length: 1 + Math.floor(r() * 400) }, () => (depth < 3 ? garbage(r, depth + 1) : 1));
    case 19: return depth < 4 ? Object.fromEntries(Array.from({ length: Math.floor(r() * 5) }, (_, i) => [`k${i}`, garbage(r, depth + 1)])) : 0;
    case 20: return [, 1];
    case 21: return Object.freeze({ tool: 'read_file', args: { path: '/w/a' }, ctx: { agentId: 'agent-1' } });
    case 22: return new Uint8Array(3);
    default: return Math.floor(r() * 1000) - 500;
  }
}

test('property (d): decide() never throws on garbage; hostile inputs are denied', () => {
  const p = mk([permit('p', { tools: ['read_file'] }), permit('q', { agents: ['agent-1'] })]);
  const r = prng(1234567);
  for (let i = 0; i < 1500; i++) {
    const shape = Math.floor(r() * 4);
    const g = garbage(r);
    const rq = shape === 0 ? g : shape === 1 ? { tool: 'read_file', args: g, ctx: { agentId: 'agent-1' } }
      : shape === 2 ? { tool: g, args: { path: '/w/a' }, ctx: { agentId: 'agent-1' } }
        : { tool: 'read_file', args: { path: '/w/a' }, ctx: g };
    let d: Decision | undefined;
    assert.doesNotThrow(() => { d = decide(p, rq); });
    assert.ok(d !== undefined);
    assert.ok(d.effect === 'permit' || d.effect === 'deny');
    assert.equal(typeof d.reason_code, 'string');
    if (d.effect === 'permit') {
      // only the genuinely valid request can be permitted
      assert.equal(shape, 0, 'permit for a hostile request');
      assert.equal((g as { tool?: string }).tool, 'read_file');
    }
  }
  assert.equal(({} as Record<string, unknown>)['polluted'], undefined);
});

test('fuzz: named hostile inputs are denied, never thrown', () => {
  const p = mk([permit('p', { tools: ['read_file'] })]);
  const ok = req('read_file', { path: '/w/a' });
  const hostile: [string, unknown][] = [
    ['proxy request', new Proxy(ok, {})],
    ['throwing proxy', new Proxy({}, { get() { throw new Error('x'); }, has() { throw new Error('x'); }, ownKeys() { throw new Error('x'); } })],
    ['getter args', { tool: 'read_file', args: { get path() { throw new Error('x'); } }, ctx: { agentId: 'a' } }],
    ['getter tool', { get tool() { throw new Error('x'); }, args: {}, ctx: { agentId: 'a' } }],
    ['cycle', (() => { const o: Record<string, unknown> = { tool: 'read_file', args: {}, ctx: { agentId: 'a' } }; o['self'] = o; return o; })()],
    ['huge string', req('read_file', { path: 'x'.repeat(50_000_000) })],
    ['huge key', req('read_file', { ['k'.repeat(1_000_000)]: 1 })],
    ['bigint', req('read_file', { path: 1n })],
    ['symbol', req('read_file', { path: Symbol('x') })],
    ['symbol key', req('read_file', { path: '/a', [Symbol('x')]: 1 })],
    ['class instance args', { tool: 'read_file', args: new (class { path = '/a'; })(), ctx: { agentId: 'a' } }],
    ['class instance request', new (class { tool = 'read_file'; args = { path: '/a' }; ctx = { agentId: 'a' }; })()],
    ['toString trap', { tool: 'read_file', args: { path: { toString() { throw new Error('x'); } } }, ctx: { agentId: 'a' } }],
    ['valueOf object tool', { tool: { valueOf() { return 'read_file'; }, toString() { return 'read_file'; } }, args: {}, ctx: { agentId: 'a' } }],
    ['array tool', { tool: ['read_file'], args: {}, ctx: { agentId: 'a' } }],
    ['deep', (() => { let d: unknown = 1; for (let i = 0; i < 1_000_000; i++) d = { d }; return req('read_file', { path: d }); })()],
    ['revoked proxy', (() => { const { proxy, revoke } = Proxy.revocable({}, {}); revoke(); return proxy; })()],
    ['frozen with extra', Object.freeze({ ...ok, extra: 1 })],
  ];
  for (const [name, input] of hostile) {
    let d: Decision | undefined;
    assert.doesNotThrow(() => { d = decide(p, input); }, name);
    assert.equal(d?.effect, 'deny', name);
  }
});

test('fuzz: a request whose accessor mutates state mid-read cannot desynchronise snapshot and decision', () => {
  const p = mk([permit('p', { tools: ['read_file'], args: { path: { glob: '/w/*' } } })]);
  let n = 0;
  const args = Object.defineProperty({}, 'path', { enumerable: true, get() { return n++ === 0 ? '/w/ok' : '/etc/passwd'; } });
  assert.equal(decide(p, { tool: 'read_file', args, ctx: { agentId: 'a' } }).effect, 'deny');
  assert.ok(n <= 1);
});

test('policy documents cannot be tampered with after load', () => {
  const p = mk([deny('d', { tools: ['read_file'] })]);
  assert.throws(() => { (p.document.rules as unknown as unknown[]).pop(); }, TypeError);
  assert.throws(() => { (p.document.rules[0] as { effect: string }).effect = 'permit'; }, TypeError);
  assert.throws(() => { (p as { policy_version: string }).policy_version = 'x'; }, TypeError);
  assert.equal(eff(p, req('read_file', { path: '/a' })), 'deny:denied_by_rule');
  // and rebuilding a lookalike object does not make decide() trust it
  const fake = { ...p, document: policyDoc([permit('p', { tools: ['read_file'] })]) };
  assert.equal(decide(fake as never, req('read_file', { path: '/a' })).reason_code, 'engine_error');
});

// ---------------------------------------------------------------- v1.2 additions

function pathsPolicy(order: 'denyFirst' | 'denyLast'): LoadedPolicy {
  const permitR = permit('p.ws', { tools: ['read_paths'], args: { paths: { path_within: { root: '/workspace', case_insensitive: false } } } });
  const denyR = deny('d.secrets', { tools: ['read_paths'], args: { paths: { path_within: { root: '/workspace/secrets', case_insensitive: true } } } });
  const rules = order === 'denyFirst' ? [denyR, permitR] : [permitR, denyR];
  const d = policyDoc(rules) as { tools: Record<string, unknown> };
  return loadPolicy(JSON.stringify({
    ...d,
    tools: { ...d.tools, read_paths: { risk: 'low', external_effect: false, read_only: true, fail_mode: 'closed', args: { paths: { type: 'string[]' } } } },
  }));
}

test('F-01: string[] quantification is effect dependent (deny=any, permit=all, empty=no match)', () => {
  const ok = '/workspace/ok.txt';
  const secret = '/workspace/Secrets/key';
  for (const order of ['denyFirst', 'denyLast'] as const) {
    const p = pathsPolicy(order);
    const run = (paths: string[]) => eff(p, req('read_paths', { paths }));
    assert.equal(run([ok]), 'permit:permitted', order);
    assert.equal(run([ok, secret]), 'deny:denied_by_rule', order);
    assert.equal(run([secret, ok]), 'deny:denied_by_rule', order);
    assert.equal(run([secret]), 'deny:denied_by_rule', order);
    assert.equal(run([]), 'deny:default_deny', order);
    assert.equal(run([ok, '/etc/passwd']), 'deny:default_deny', order); // permit needs ALL
  }
});

test('F-01: equals / max_length variants on string[]', () => {
  const p = mk([
    permit('p.len', { tools: ['tag_item'], args: { tags: { max_length: 3 } } }),
    deny('d.bad', { tools: ['tag_item'], args: { tags: { equals: 'bad' } } }),
  ]);
  const run = (tags: string[]) => eff(p, req('tag_item', { tags }));
  assert.equal(run(['a', 'bb']), 'permit:permitted');
  assert.equal(run(['a', 'toolong']), 'deny:default_deny'); // permit needs all
  assert.equal(run(['bad', 'zzzzzzzz']), 'deny:denied_by_rule'); // deny any
  assert.equal(run(['zzzzzzzz', 'bad']), 'deny:denied_by_rule');
  assert.equal(run([]), 'deny:default_deny');
  const q = mk([deny('d.long', { tools: ['tag_item'], args: { tags: { max_length: 2 } } }), permit('p', { tools: ['tag_item'] })]);
  assert.equal(eff(q, req('tag_item', { tags: ['abcdef', 'a'] })), 'deny:denied_by_rule');
  assert.equal(eff(q, req('tag_item', { tags: ['abcdef', 'abc'] })), 'permit:permitted');
});

test('evaluate returns the frozen snapshot; raw mutation afterwards changes nothing; digest is stable', () => {
  const p = mk([permit('p', { tools: ['read_file'] })]);
  const raw = req('read_file', { path: '/a' }, { scopes: ['s'] }) as { args: { path: string }; ctx: { scopes: string[] } };
  const ev = evaluate(p, raw);
  assert.equal(ev.decision.effect, 'permit');
  assert.ok(ev.snapshot !== null && isSnapshot(ev.snapshot));
  assert.ok(Object.isFrozen(ev.snapshot) && Object.isFrozen(ev.snapshot.args));
  const digest = ev.decision.request_digest;
  assert.match(String(digest), /^sha256:[0-9a-f]{64}$/);
  const before = JSON.stringify(ev.snapshot);
  raw.args.path = '/etc/passwd';
  raw.ctx.scopes.push('admin');
  assert.equal(JSON.stringify(ev.snapshot), before);
  assert.equal(ev.snapshot?.args['path'], '/a');
  assert.equal(evaluate(p, req('read_file', { path: '/a' }, { scopes: ['s'] })).decision.request_digest, digest);
  assert.notEqual(evaluate(p, req('read_file', { path: '/b' }, { scopes: ['s'] })).decision.request_digest, digest);
  assert.deepEqual(decide(p, ev.snapshot), ev.decision);
  const bad = evaluate(p, { tool: 5 });
  assert.equal(bad.snapshot, null);
  assert.equal(bad.decision.request_digest, null);
  assert.equal(bad.decision.reason_code, 'invalid_request');
  assert.equal(evaluate(p, req('read_file', { path: 'x'.repeat(9000) })).decision.reason_code, 'limit_exceeded');
  assert.equal(isSnapshot(raw), false);
});

test('evaluate: non-loaded policy => engine_error, policy_version unknown, no snapshot', () => {
  for (const bad of [null, {}, JSON.parse(JSON.stringify(mk([])))]) {
    const ev = evaluate(bad as never, req('read_file', { path: '/a' }));
    assert.equal(ev.decision.reason_code, 'engine_error');
    assert.equal(ev.decision.policy_version, 'unknown');
    assert.equal(ev.snapshot, null);
  }
});

test('toolInfo and matched_reasons', () => {
  const p = mk([permit('b.p', { tools: ['send_email'] }), deny('a.d', { tools: ['read_file'] })]);
  assert.deepEqual(toolInfo(p, 'send_email'), { risk: 'high', external_effect: true, read_only: false, fail_mode: 'closed' });
  assert.deepEqual(toolInfo(p, 'search_docs'), { risk: 'low', external_effect: false, read_only: true, fail_mode: 'open_on_audit_failure' });
  assert.equal(toolInfo(p, 'nope'), undefined);
  assert.equal(toolInfo(p, 'constructor'), undefined);
  assert.equal(toolInfo({} as never, 'send_email'), undefined);
  const d = decide(mk([permit('z.p', { tools: ['read_file'] }), deny('a.d', { tools: ['read_file'] })]), req('read_file', { path: '/x' }));
  assert.deepEqual(d.matched_reasons, [
    { id: 'a.d', effect: 'deny', reason_code: 'r_a_d' },
    { id: 'z.p', effect: 'permit', reason_code: 'r_z_p' },
  ]);
});

test('domain_exact with host accept, decided end to end', () => {
  const p = mk([permit('p', { tools: ['http_get'], args: { url: { domain_exact: 'docs.corp.com', accept: ['host'] } } })]);
  assert.equal(eff(p, req('http_get', { url: 'docs.corp.com' })), 'permit:permitted');
  assert.equal(eff(p, req('http_get', { url: 'https://docs.corp.com/' })), 'deny:default_deny');
  assert.equal(eff(p, req('http_get', { url: 'a.docs.corp.com' })), 'deny:default_deny');
});

test('request NFC normalisation reaches the decision: compared string is the used string', () => {
  const p = mk([permit('p', { tools: ['search_docs'], args: { query: { equals: 'é' } } })]);
  const ev = evaluate(p, req('search_docs', { query: 'é' }));
  assert.equal(ev.decision.effect, 'permit');
  assert.equal(ev.snapshot?.args['query'], 'é');
});
