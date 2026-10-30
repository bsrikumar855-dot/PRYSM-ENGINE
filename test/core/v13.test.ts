import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide, loadPolicy, toolInfo, PolicyError } from '../../src/core/index.ts';
import type { Decision, LoadedPolicy } from '../../src/core/index.ts';
import { compiledPolicyOf } from '../../src/core/policy.ts';
import { TOOLS, permit, deny, policyDoc, mk, req } from './helpers.ts';
import type { RuleLike } from './helpers.ts';

const EXTRA_TOOLS = {
  read_paths: { risk: 'low', external_effect: false, read_only: true, fail_mode: 'closed', args: { paths: { type: 'string[]' } } },
  fetch_all: { risk: 'low', external_effect: false, read_only: true, fail_mode: 'closed', args: { urls: { type: 'string[]' } } },
};

function mkx(rules: RuleLike[]): LoadedPolicy {
  const d = policyDoc(rules) as { tools: Record<string, unknown> };
  return loadPolicy(JSON.stringify({ ...d, tools: { ...d.tools, ...EXTRA_TOOLS } }));
}
const eff = (p: LoadedPolicy, r: unknown): string => {
  const d = decide(p, r);
  return `${d.effect}:${d.reason_code}`;
};

// ---------------------------------------------------------------- N-01

test('N-01: deny path_within is not bypassed by values the path matcher cannot parse', () => {
  const p = mkx([
    permit('p.len', { tools: ['read_paths'], args: { paths: { max_length: 100 } } }),
    deny('d.secrets', { tools: ['read_paths'], args: { paths: { path_within: { root: '/workspace/secrets', case_insensitive: true } } } }),
  ]);
  const run = (paths: string[]) => eff(p, req('read_paths', { paths }));
  assert.equal(run(['/workspace/secrets/é']), 'deny:denied_by_rule'); // non-ASCII
  assert.equal(run(['/workspace/secrets/CON']), 'deny:denied_by_rule'); // reserved name
  assert.equal(run(['/workspace/secrets/x*']), 'deny:denied_by_rule'); // illegal char
  assert.equal(run(['/workspace/secrets/a%2e%2e']), 'deny:denied_by_rule');
  assert.equal(run(['/workspace/ok', '/workspace/secrets/é']), 'deny:denied_by_rule');
  assert.equal(run(['relative/path']), 'deny:denied_by_rule'); // unparseable => deny matches
  assert.equal(run(['/workspace/ok']), 'permit:permitted'); // parseable, outside the deny root
  assert.equal(run([]), 'deny:default_deny');
  // scalar arg, same shape
  const q = mk([
    permit('p.len', { tools: ['read_file'], args: { path: { max_length: 100 } } }),
    deny('d.secrets', { tools: ['read_file'], args: { path: { path_within: { root: '/workspace/secrets', case_insensitive: true } } } }),
  ]);
  assert.equal(eff(q, req('read_file', { path: '/workspace/secrets/é' })), 'deny:denied_by_rule');
  assert.equal(eff(q, req('read_file', { path: '/workspace/ok' })), 'permit:permitted');
});

test('N-01: permit path_within / domain treat unparseable as no match', () => {
  const p = mkx([permit('p', { tools: ['read_paths'], args: { paths: { path_within: { root: '/workspace', case_insensitive: false } } } })]);
  assert.equal(eff(p, req('read_paths', { paths: ['/workspace/é'] })), 'deny:default_deny');
  assert.equal(eff(p, req('read_paths', { paths: ['/workspace/a', '/workspace/CON'] })), 'deny:default_deny');
  assert.equal(eff(p, req('read_paths', { paths: ['/workspace/a', '/workspace/b'] })), 'permit:permitted');
  const d = mkx([permit('p', { tools: ['http_get'], args: { url: { domain_suffix: 'corp.com', accept: ['url'] } } })]);
  assert.equal(eff(d, req('http_get', { url: 'https://x.é.corp.com/' })), 'deny:default_deny');
});

test('N-01: deny domain predicates are not bypassed by hosts hostFromString rejects', () => {
  const bad = [
    'https://évil.com/', // non-ASCII
    'https://evil.com/%41', // percent
    'https://evil.com\\@corp.com/', // backslash
    'bob@corp.com', // wrong accept form for a url-only predicate
    'evil.com', // bare host with url-only accept
    'https://user:pw@evil.com/',
    'ftp://evil.com/',
    'https://127.0.0.1/',
    '  https://evil.com/',
  ];
  for (const kind of ['domain_suffix', 'domain_exact'] as const) {
    const p = mkx([
      permit('p.len1', { tools: ['fetch_all'], args: { urls: { max_length: 200 } } }),
      permit('p.len2', { tools: ['http_get'], args: { url: { max_length: 200 } } }),
      deny('d.dom1', { tools: ['fetch_all'], args: { urls: { [kind]: 'corp.com', accept: ['url'] } } }),
      deny('d.dom2', { tools: ['http_get'], args: { url: { [kind]: 'corp.com', accept: ['url'] } } }),
    ]);
    for (const b of bad) {
      assert.equal(eff(p, req('fetch_all', { urls: [b] })), 'deny:denied_by_rule', `${kind} ${b}`);
      assert.equal(eff(p, req('http_get', { url: b })), 'deny:denied_by_rule', `${kind} ${b}`);
    }
    assert.equal(eff(p, req('fetch_all', { urls: ['https://other.com/'] })), 'permit:permitted');
    assert.equal(eff(p, req('fetch_all', { urls: ['https://other.com/', 'é'] })), 'deny:denied_by_rule');
    assert.equal(eff(p, req('fetch_all', { urls: [] })), 'deny:default_deny');
  }
  // a parseable host that simply does not match stays no_match for the deny rule
  const q = mkx([permit('p', { tools: ['http_get'], args: { url: { max_length: 200 } } }), deny('d', { tools: ['http_get'], args: { url: { domain_exact: 'corp.com', accept: ['url'] } } })]);
  assert.equal(eff(q, req('http_get', { url: 'https://corp.com/' })), 'deny:denied_by_rule');
  assert.equal(eff(q, req('http_get', { url: 'https://docs.corp.com/' })), 'permit:permitted');
});

// ---------------------------------------------------------------- N-02

function timed(p: LoadedPolicy, r: unknown): { d: Decision; ms: number } {
  let d: Decision | undefined;
  const t0 = performance.now();
  assert.doesNotThrow(() => { d = decide(p, r); });
  return { d: d as Decision, ms: performance.now() - t0 };
}

test('N-02: 1000 path_within rules x string[256 x ~240 chars] stay fast and never throw', () => {
  const rules = Array.from({ length: 1000 }, (_, i) =>
    i % 2 === 0
      ? deny('d' + String(i).padStart(4, '0'), { tools: ['read_paths'], args: { paths: { path_within: { root: '/zone' + i, case_insensitive: i % 4 === 0 } } } })
      : permit('p' + String(i).padStart(4, '0'), { tools: ['read_paths'], args: { paths: { path_within: { root: '/w', case_insensitive: true } } } }));
  const p = mkx(rules);
  const paths = Array.from({ length: 256 }, (_, i) => '/w/' + String(i).padStart(3, '0') + 'a'.repeat(230));
  const { d, ms } = timed(p, req('read_paths', { paths }));
  assert.ok(ms < 1500, `took ${ms.toFixed(0)} ms`);
  assert.ok(['permit', 'deny'].includes(d.effect));
});

test('N-02: 1000 domain_suffix rules x string[256 x ~240-char urls] stay fast and never throw', () => {
  const rules = Array.from({ length: 1000 }, (_, i) =>
    deny('d' + String(i).padStart(4, '0'), { tools: ['fetch_all'], args: { urls: { [i % 2 ? 'domain_suffix' : 'domain_exact']: 'h' + i + '.test', accept: i % 3 ? ['url'] : ['url', 'email', 'host'] } } }));
  const p = mkx(rules);
  const urls = Array.from({ length: 256 }, (_, i) => 'https://x' + i + '.evil.com/' + 'p'.repeat(220));
  const { d, ms } = timed(p, req('fetch_all', { urls }));
  assert.ok(ms < 1500, `took ${ms.toFixed(0)} ms`);
  assert.equal(d.reason_code, 'default_deny');
});

test('N-02: 1000 rules x one 8192-char "/a/.." string stay fast and never throw', () => {
  const rules = Array.from({ length: 1000 }, (_, i) => deny('d' + String(i).padStart(4, '0'), { tools: ['read_file'], args: { path: { path_within: { root: '/z' + i, case_insensitive: i % 2 === 0 } } } }));
  const p = mk(rules);
  const value = '/a/..'.repeat(1638) + '/a'; // 8192 chars
  assert.equal(value.length, 8192);
  const { d, ms } = timed(p, req('read_file', { path: value }));
  assert.ok(ms < 1500, `took ${ms.toFixed(0)} ms`);
  assert.equal(d.effect, 'deny');
});

// ---------------------------------------------------------------- N-03

test('N-03: toolInfo returns a frozen copy; compiled structures are immutable', () => {
  const p = mk([permit('p', { tools: ['send_email'], agents: ['a1'], args: { to: { domain_suffix: 'corp.com', accept: ['email'] } }, provenance: { to: { all_in: ['trusted-user'] } } })]);
  const info = toolInfo(p, 'send_email');
  assert.ok(info !== undefined && Object.isFrozen(info));
  assert.throws(() => { (info as { risk: string }).risk = 'low'; }, TypeError);
  assert.deepEqual(toolInfo(p, 'send_email'), { risk: 'high', external_effect: true, read_only: false, fail_mode: 'closed' });
  assert.notEqual(toolInfo(p, 'send_email'), info); // a copy each call

  const c = compiledPolicyOf(p);
  assert.ok(c !== undefined);
  assert.ok(Object.isFrozen(c) && Object.isFrozen(c.rules) && Object.isFrozen(c.rules[0]));
  assert.throws(() => (c.tools as Map<string, unknown>).set('x', {}), TypeError);
  assert.throws(() => (c.tools as Map<string, unknown>).delete('send_email'), TypeError);
  assert.throws(() => (c.tools as Map<string, unknown>).clear(), TypeError);
  const rule = c.rules[0];
  assert.ok(rule !== undefined);
  assert.throws(() => (rule.agents as Set<string>).add('evil'), TypeError);
  assert.throws(() => (rule.agents as Set<string>).clear(), TypeError);
  assert.throws(() => (rule.tools as Set<string>).delete('send_email'), TypeError);
  assert.throws(() => (c.rules as unknown[]).push({}), TypeError);
  const tool = c.tools.get('send_email');
  assert.throws(() => (tool?.args as Map<string, unknown>).set('zzz', {}), TypeError);
  assert.throws(() => { (rule.args as unknown[]).length = 0; }, TypeError);
  // later decisions are unchanged
  const r = req('send_email', { to: 'a@corp.com', subject: 's', body: 'b' }, { agentId: 'a1', provenance: { to: ['trusted-user'] } });
  assert.equal(eff(p, r), 'permit:permitted');
  assert.equal(eff(p, req('send_email', { to: 'a@evil.com', subject: 's', body: 'b' }, { agentId: 'a1', provenance: { to: ['trusted-user'] } })), 'deny:default_deny');
});

// ---------------------------------------------------------------- N-04

test('N-04: every code point in Cf/Zl/Zp/Cc/Co/Cn/Zs(non-space) is rejected by loadPolicy; ASCII printable accepted', () => {
  const base = { ...policyDoc([permit('p', { tools: ['read_file'], args: { path: { glob: '@@' } } })]), tools: { read_file: TOOLS.read_file } };
  const text = JSON.stringify(base);
  const [pre, post] = text.split('"@@"') as [string, string];
  const forbidden = /[\p{Cf}\p{Zl}\p{Zp}\p{Cc}\p{Co}\p{Cn}]|(?! )\p{Zs}/u;
  const load = (cp: number): 'OK' | string => {
    try {
      loadPolicy(pre + JSON.stringify('a' + String.fromCodePoint(cp) + 'b') + post);
      return 'OK';
    } catch (e) {
      if (e instanceof PolicyError) return e.code;
      throw e;
    }
  };
  let rejected = 0;
  const missed: string[] = [];
  const savedLimit = Error.stackTraceLimit;
  Error.stackTraceLimit = 0; // keep the 1.1M-iteration scan fast
  try {
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    const ch = String.fromCodePoint(cp);
    if (forbidden.test(ch)) {
      rejected++;
      const r = load(cp);
      if (r !== 'forbidden_char') missed.push(cp.toString(16) + ':' + r);
    } else if (cp >= 0x21 && cp <= 0x7e) {
      assert.equal(load(cp), 'OK', 'U+' + cp.toString(16));
    }
  }
  } finally {
    Error.stackTraceLimit = savedLimit;
  }
  assert.deepEqual(missed.slice(0, 10), []);
  assert.ok(rejected > 100000, 'scanned ' + rejected);
  assert.equal(load(0x20), 'OK'); // plain space stays legal
  assert.equal(load(0x0a), 'forbidden_char');
});

test('N-04: extra explicit forbidden characters from spec 10.7 stay rejected', () => {
  const mkName = (s: string) => `{"policy_schema_version":1,"name":"${s}","mode":"enforce","tools":{},"rules":[]}`;
  for (const esc of ['\\u034f', '\\ufe00', '\\ufe0f', '\\u00ad', '\\u180e', '\\udb40\\udc01']) {
    assert.throws(() => loadPolicy(mkName('a' + esc + 'b')), (e: unknown) => e instanceof PolicyError && e.code === 'forbidden_char', esc);
  }
});

test('key-count cap: a huge object is rejected as limit_exceeded without throwing', () => {
  const o: Record<string, number> = {};
  for (let i = 0; i < 200_000; i++) o['k' + i] = 1;
  const p = mk([permit('p', { tools: ['read_file'] })]);
  assert.equal(eff(p, { tool: 'read_file', args: o, ctx: { agentId: 'a' } }), 'deny:limit_exceeded');
});

void TOOLS;
