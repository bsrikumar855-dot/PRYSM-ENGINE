import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadPolicy, jcs, PolicyError } from '../../src/core/index.ts';
import { TOOLS, permit, deny, policyDoc, loadCode, mk } from './helpers.ts';

const FIXTURE = new URL('../../eval/policies/support-agent.policy.json', import.meta.url);

function withRule(match: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return policyDoc([{ id: 'r1', effect: 'permit', reason_code: 'ok', match, ...extra } as never]);
}

test('fixture policy loads from bytes and is frozen', () => {
  const p = loadPolicy(readFileSync(FIXTURE));
  assert.match(p.policy_version, /^sha256:[0-9a-f]{64}$/);
  assert.equal(p.name, 'support-agent');
  assert.equal(p.mode, 'enforce');
  assert.ok(Object.isFrozen(p));
  assert.ok(Object.isFrozen(p.document));
  assert.ok(Object.isFrozen(p.document.rules));
  assert.ok(Object.isFrozen(p.document.rules[0]));
  assert.throws(() => {
    (p.document as { name: string }).name = 'x';
  }, TypeError);
});

test('minimal valid policies load', () => {
  assert.equal(loadCode(policyDoc([])), 'OK');
  assert.equal(loadCode({ policy_schema_version: 1, name: 'n', mode: 'monitor_only', tools: {}, rules: [] }), 'OK');
});

test('BOM is rejected (string and bytes)', () => {
  const text = JSON.stringify(policyDoc([]));
  assert.equal(loadCode('\ufeff' + text), 'bom');
  assert.equal(loadCode(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text)])), 'bom');
});

test('invalid UTF-8 and malformed JSON are rejected', () => {
  assert.equal(loadCode(new Uint8Array([0x7b, 0xff, 0x7d])), 'invalid_encoding');
  assert.equal(loadCode(''), 'invalid_json');
  assert.equal(loadCode('[]'), 'invalid_type');
  assert.equal(loadCode('{"a":1,}'), 'invalid_json');
  assert.equal(loadCode(JSON.stringify(policyDoc([])) + ' x'), 'invalid_json');
  assert.equal(loadCode("{'a':1}"), 'invalid_json');
  assert.equal(loadCode('{"a":01}'), 'invalid_json');
  assert.equal(loadCode('{"a":1e999}'), 'invalid_json');
  assert.equal(loadCode('{"a":"\\x"}'), 'invalid_json');
  assert.equal(loadCode('{"a":NaN}'), 'invalid_json');
  assert.equal(loadCode('\ud800'), 'invalid_encoding');
});

test('duplicate keys are rejected, including via escapes and nested objects', () => {
  assert.equal(loadCode('{"a":1,"a":2}'), 'duplicate_key');
  assert.equal(loadCode('{"a":1,"\\u0061":2}'), 'duplicate_key');
  const base = JSON.stringify(policyDoc([]));
  assert.equal(loadCode(base.replace('"name":"test-policy"', '"name":"a","name":"b"')), 'duplicate_key');
  const tools = '"tools":{"x":{"risk":"low","risk":"low"}}';
  assert.equal(loadCode(`{"policy_schema_version":1,"name":"n","mode":"enforce",${tools},"rules":[]}`), 'duplicate_key');
});

test('__proto__, constructor and prototype keys are rejected anywhere', () => {
  for (const k of ['__proto__', 'constructor', 'prototype']) {
    assert.equal(loadCode(`{"${k}":1}`), 'forbidden_key', k);
    assert.equal(loadCode(`{"policy_schema_version":1,"name":"n","mode":"enforce","tools":{"${k}":{}},"rules":[]}`), 'forbidden_key', k);
    assert.equal(loadCode(`{"policy_schema_version":1,"name":"n","mode":"enforce","tools":{},"rules":[{"id":"a","effect":"deny","reason_code":"x","match":{"args":{"${k}":{}}}}]}`), 'forbidden_key', k);
  }
  assert.equal(loadCode('{"\\u005f_proto__":1}'), 'forbidden_key');
});

test('forbidden characters in strings are rejected', () => {
  const mkName = (s: string) => `{"policy_schema_version":1,"name":"${s}","mode":"enforce","tools":{},"rules":[]}`;
  assert.equal(loadCode(mkName('a\\u0000b')), 'forbidden_char');
  assert.equal(loadCode(mkName('a\\u0001b')), 'forbidden_char');
  assert.equal(loadCode(mkName('a\\u007fb')), 'forbidden_char');
  assert.equal(loadCode(mkName('a\\u0085b')), 'forbidden_char');
  assert.equal(loadCode(mkName('a\\u009fb')), 'forbidden_char');
  assert.equal(loadCode(mkName('a\\u200bb')), 'forbidden_char');
  assert.equal(loadCode(mkName('a\\u200fb')), 'forbidden_char');
  assert.equal(loadCode(mkName('a\\u2060b')), 'forbidden_char');
  assert.equal(loadCode(mkName('a\\ufeffb')), 'forbidden_char');
  assert.equal(loadCode(mkName('a\\u202eb')), 'forbidden_char');
  assert.equal(loadCode(mkName('a\\u2066b')), 'forbidden_char');
  assert.equal(loadCode(mkName('a\\u2069b')), 'forbidden_char');
  assert.equal(loadCode(mkName('a\tb')), 'forbidden_char'); // raw control char
  assert.equal(loadCode(mkName('a\\nb')), 'forbidden_char'); // escaped newline
  assert.equal(loadCode(mkName('a\\ud800b')), 'invalid_encoding'); // lone surrogate
  // a forbidden char inside a predicate value (not just identifiers)
  const d = withRule({ tools: ['read_file'], args: { path: { glob: '/a\u200b*' } } });
  assert.equal(loadCode(d), 'forbidden_char');
});

test('unknown keys anywhere are rejected', () => {
  assert.equal(loadCode({ ...policyDoc([]), extra: 1 }), 'unknown_key');
  const d = policyDoc([]);
  assert.equal(loadCode({ ...d, tools: { x: { ...TOOLS.read_file, bonus: 1 } } }), 'unknown_key');
  assert.equal(loadCode({ ...d, tools: { x: { ...TOOLS.read_file, args: { a: { type: 'string', nope: 1 } } } } }), 'unknown_key');
  assert.equal(loadCode(policyDoc([{ id: 'a', effect: 'deny', reason_code: 'x', match: { tools: ['read_file'] }, priority: 1 } as never])), 'unknown_key');
  assert.equal(loadCode(withRule({ tools: ['read_file'], negate: true })), 'unknown_key');
  assert.equal(loadCode(withRule({ tools: ['read_file'], args: { path: { glob: 'a', extra: 1 } } })), 'invalid_predicate');
  assert.equal(loadCode(withRule({ tools: ['read_file'], args: { path: { regex: '.*' } } })), 'invalid_predicate');
  assert.equal(loadCode(withRule({ tools: ['read_file'], provenance: { path: { all_in: ['a'], none_in: ['b'] } } })), 'unknown_key');
});

test('missing required keys and wrong types are rejected', () => {
  const { name: _n, ...noName } = policyDoc([]);
  assert.equal(loadCode(noName), 'missing_key');
  assert.equal(loadCode({ ...policyDoc([]), policy_schema_version: 2 }), 'invalid_value');
  assert.equal(loadCode({ ...policyDoc([]), policy_schema_version: '1' }), 'invalid_value');
  assert.equal(loadCode({ ...policyDoc([]), mode: 'audit' }), 'invalid_value');
  assert.equal(loadCode({ ...policyDoc([]), mode: 1 }), 'invalid_type');
  assert.equal(loadCode({ ...policyDoc([]), rules: {} }), 'invalid_type');
  assert.equal(loadCode({ ...policyDoc([]), tools: [] }), 'invalid_type');
  assert.equal(loadCode({ ...policyDoc([]), tools: { x: { ...TOOLS.read_file, risk: 'extreme' } } }), 'invalid_value');
  assert.equal(loadCode({ ...policyDoc([]), tools: { x: { ...TOOLS.read_file, external_effect: 'no' } } }), 'invalid_type');
  assert.equal(loadCode({ ...policyDoc([]), tools: { x: { ...TOOLS.read_file, args: { a: { type: 'object' } } } } }), 'invalid_value');
  assert.equal(loadCode(policyDoc([{ id: 'a', effect: 'allow', reason_code: 'x', match: { tools: ['read_file'] } } as never])), 'invalid_value');
  assert.equal(loadCode({ ...policyDoc([]), tools: { x: { ...TOOLS.read_file, schema_hash: 5 } } }), 'invalid_type');
  assert.equal(loadCode({ ...policyDoc([]), tools: { x: { ...TOOLS.read_file, schema_hash: 'abc' } } }), 'OK');
});

test('identifiers are validated', () => {
  const bad = ['', 'has space', 'a/b', 'a'.repeat(65), 'é', 'a\\b'];
  for (const n of bad) assert.equal(loadCode({ ...policyDoc([]), name: n }), 'invalid_identifier', JSON.stringify(n));
  assert.equal(loadCode({ ...policyDoc([]), name: 'a'.repeat(64) }), 'OK');
  assert.equal(loadCode({ ...policyDoc([]), name: 'a:b.c_d-e' }), 'OK');
  // tool and arg names may not contain ':'
  assert.equal(loadCode({ ...policyDoc([]), tools: { 'a:b': TOOLS.read_file } }), 'invalid_identifier');
  assert.equal(loadCode({ ...policyDoc([]), tools: { x: { ...TOOLS.read_file, args: { 'a:b': { type: 'string' } } } } }), 'invalid_identifier');
  // rule ids / reason codes / agents / scopes / labels may
  assert.equal(loadCode(policyDoc([permit('a:b', { agents: ['ag:1'], scopes_any: ['s:1'], tools: ['read_file'] })])), 'OK');
  assert.equal(loadCode(policyDoc([{ id: 'a b', effect: 'deny', reason_code: 'x', match: { tools: ['read_file'] } }])), 'invalid_identifier');
  assert.equal(loadCode(policyDoc([{ id: 'a', effect: 'deny', reason_code: 'bad code', match: { tools: ['read_file'] } }])), 'invalid_identifier');
  assert.equal(loadCode(policyDoc([permit('a', { agents: ['bad agent'] })])), 'invalid_identifier');
  assert.equal(loadCode(policyDoc([permit('a', { tools: ['read_file'], provenance: { path: { all_in: ['x:y', 'z'] } } })])), 'OK');
  assert.equal(loadCode(policyDoc([permit('a', { tools: ['read_file'], provenance: { path: { all_in: ['x y'] } } })])), 'invalid_identifier');
  assert.equal(loadCode(policyDoc([permit('a', { tools: ['read_file'], provenance: { nope: { all_in: ['x'] } } })])), 'unknown_arg');
});

test('fail_mode open_on_audit_failure is only legal for low risk read-only tools', () => {
  const t = (over: Record<string, unknown>) => ({ ...policyDoc([]), tools: { x: { ...TOOLS.search_docs, ...over } } });
  assert.equal(loadCode(t({})), 'OK');
  assert.equal(loadCode(t({ risk: 'medium' })), 'invalid_fail_mode');
  assert.equal(loadCode(t({ risk: 'high' })), 'invalid_fail_mode');
  assert.equal(loadCode(t({ read_only: false })), 'invalid_fail_mode');
  assert.equal(loadCode(t({ fail_mode: 'closed', risk: 'high', read_only: false })), 'OK');
});

test('rule structure: empty match, duplicate ids, unknown tools/args', () => {
  assert.equal(loadCode(withRule({})), 'empty_match');
  assert.equal(loadCode(withRule({ args: {} , tools: ['read_file'] })), 'empty_match');
  assert.equal(loadCode(withRule({ tools: ['read_file'], provenance: {} })), 'empty_match');
  assert.equal(loadCode(withRule({ tools: ['read_file'], provenance: { path: {} } })), 'empty_match');
  assert.equal(loadCode(policyDoc([permit('a', { tools: ['read_file'] }), deny('a', { tools: ['read_file'] })])), 'duplicate_id');
  assert.equal(loadCode(withRule({ tools: ['nope'] })), 'unknown_tool');
  // args must be declared for EVERY listed tool
  assert.equal(loadCode(withRule({ tools: ['read_file', 'http_get'], args: { path: { glob: '*' } } })), 'unknown_arg');
  assert.equal(loadCode(withRule({ tools: ['read_file'], args: { path: { glob: '*' } } })), 'OK');
  // without tools: declared for at least one tool
  assert.equal(loadCode(withRule({ args: { path: { glob: '*' } } })), 'OK');
  assert.equal(loadCode(withRule({ args: { nonexistent: { glob: '*' } } })), 'unknown_arg');
  assert.equal(loadCode(withRule({ tools: ['read_file'], provenance: { url: { all_in: ['a'] } } })), 'unknown_arg');
  assert.equal(loadCode(withRule({ tools: ['read_file'], session_tainted: 'yes' })), 'invalid_type');
  assert.equal(loadCode(withRule({ agents: [] })), 'invalid_value');
});

test('limits: file size, rule count, list size, nesting depth', () => {
  const big = JSON.stringify(policyDoc([])).replace('"rules":[]', `"rules":[],"pad":"${'a'.repeat(1024 * 1024)}"`);
  assert.equal(loadCode(big), 'limit_exceeded');
  assert.equal(loadCode(new Uint8Array(1024 * 1024 + 1).fill(32)), 'limit_exceeded');

  const rules = (n: number) => Array.from({ length: n }, (_, i) => permit('r' + i, { tools: ['read_file'] }));
  assert.equal(loadCode(policyDoc(rules(1000))), 'OK');
  assert.equal(loadCode(policyDoc(rules(1001))), 'limit_exceeded');

  const agents = (n: number) => Array.from({ length: n }, (_, i) => 'a' + i);
  assert.equal(loadCode(policyDoc([permit('a', { agents: agents(256) })])), 'OK');
  assert.equal(loadCode(policyDoc([permit('a', { agents: agents(257) })])), 'limit_exceeded');
  const vals = (n: number) => Array.from({ length: n }, (_, i) => 'v' + i);
  assert.equal(loadCode(withRule({ tools: ['read_file'], args: { path: { in: vals(256) } } })), 'OK');
  assert.equal(loadCode(withRule({ tools: ['read_file'], args: { path: { in: vals(257) } } })), 'limit_exceeded');
  assert.equal(loadCode(withRule({ tools: ['read_file'], args: { path: { glob: 'a'.repeat(256) } } })), 'OK');
  assert.equal(loadCode(withRule({ tools: ['read_file'], args: { path: { glob: 'a'.repeat(257) } } })), 'limit_exceeded');

  // depth: the fixture's path_within sits at depth 8 and loads; one more level is rejected
  assert.equal(loadCode(readFileSync(FIXTURE)), 'OK');
  const deep = JSON.stringify({ ...policyDoc([]), extra: { a: { b: { c: { d: { e: { f: { g: {} } } } } } } } });
  assert.equal(loadCode(deep), 'limit_exceeded');
  assert.equal(loadCode('{"a":' + '['.repeat(100) + ']'.repeat(100) + '}'), 'limit_exceeded');
});

test('predicate values are validated', () => {
  const pred = (p: unknown) => withRule({ tools: ['read_file'], args: { path: p } });
  // domain predicate values: lowercase ASCII LDH hostnames only
  const dom = (v: string) => loadCode(withRule({ tools: ['http_get'], args: { url: { domain_suffix: v, accept: ['url'] } } }));
  assert.equal(dom('corp.com'), 'OK');
  assert.equal(dom('localhost'), 'OK');
  for (const v of ['Corp.com', 'corp.com.', '*.corp.com', '.corp.com', '127.0.0.1', '1.2.3.4', '[::1]', 'cörp.com', 'a_b.com', '-a.com', 'a-.com', 'a..com', '', 'a'.repeat(64) + '.com', 'corp.com/x']) {
    assert.equal(dom(v), 'invalid_value', JSON.stringify(v));
  }
  assert.equal(loadCode(withRule({ tools: ['http_get'], args: { url: { domain_exact: 'Docs.corp.com', accept: ['url'] } } })), 'invalid_value');
  assert.equal(loadCode(withRule({ tools: ['http_get'], args: { url: { domain_exact: 5, accept: ['url'] } } })), 'invalid_type');
  // accept is required, non-empty, a subset of url|email|host, and only for domain predicates
  const acc = (a: unknown) => loadCode(withRule({ tools: ['http_get'], args: { url: a === undefined ? { domain_suffix: 'corp.com' } : { domain_suffix: 'corp.com', accept: a } } }));
  assert.equal(acc(undefined), 'missing_key');
  assert.equal(acc([]), 'invalid_value');
  assert.equal(acc(['ftp']), 'invalid_value');
  assert.equal(acc('url'), 'invalid_type');
  assert.equal(acc(['url', 'email', 'host']), 'OK');
  assert.equal(acc(['email']), 'OK');
  assert.equal(loadCode(withRule({ tools: ['read_file'], args: { path: { glob: '*', accept: ['url'] } } })), 'unknown_key');

  // path_within
  const pw = (root: unknown, ci?: unknown) => loadCode(pred({ path_within: ci === undefined ? { root } : { root, case_insensitive: ci } }));
  assert.equal(pw('/workspace', false), 'OK');
  assert.equal(pw('/', true), 'OK');
  assert.equal(pw('C:/work', true), 'OK');
  assert.equal(pw('/workspace'), 'missing_key'); // case_insensitive is required
  assert.equal(pw('/workspace', 'no'), 'invalid_type');
  for (const r of ['workspace', '/workspace/', '/a/../b', '/a/./b', '//a', '/a//b', '\\a', 'c:/work', '/a/CON', '', '/a%2e', '/a:b']) {
    assert.equal(pw(r, false), 'invalid_value', JSON.stringify(r));
  }
  assert.equal(loadCode(pred({ path_within: { case_insensitive: false } })), 'missing_key');
  assert.equal(loadCode(pred({ path_within: { root: '/a', case_insensitive: false, x: 1 } })), 'unknown_key');

  // others
  assert.equal(loadCode(pred({ range: { min: 5, max: 1 } })), 'invalid_value');
  assert.equal(loadCode(pred({ range: {} })), 'invalid_predicate');
  assert.equal(loadCode(pred({ range: { min: '1' } })), 'invalid_type');
  assert.equal(loadCode(pred({ range: { lo: 1 } })), 'unknown_key');
  assert.equal(loadCode(pred({ max_length: -1 })), 'invalid_value');
  assert.equal(loadCode(pred({ max_length: 1.5 })), 'invalid_value');
  assert.equal(loadCode(pred({ max_length: '3' })), 'invalid_value');
  assert.equal(loadCode(pred({ equals: null })), 'invalid_type');
  assert.equal(loadCode(pred({ equals: ['a'] })), 'invalid_type');
  assert.equal(loadCode(pred({ in: [] })), 'invalid_value');
  assert.equal(loadCode(pred({ in: [{}] })), 'invalid_type');
  assert.equal(loadCode(pred({})), 'invalid_predicate');
  assert.equal(loadCode(pred({ equals: 'a', glob: 'a' })), 'invalid_predicate');
  assert.equal(loadCode(pred('x')), 'invalid_type');
  assert.equal(loadCode(pred({ glob: 5 })), 'invalid_type');
});

test('predicate / argument type mismatches are load errors', () => {
  const on = (tool: string, arg: string, p: unknown) => loadCode(withRule({ tools: [tool], args: { [arg]: p } }));
  assert.equal(on('read_file', 'path', { range: { min: 0 } }), 'invalid_predicate');
  assert.equal(on('set_discount', 'percent', { range: { min: 0 } }), 'OK');
  assert.equal(on('set_discount', 'percent', { glob: '*' }), 'invalid_predicate');
  assert.equal(on('set_discount', 'percent', { max_length: 3 }), 'invalid_predicate');
  assert.equal(on('set_discount', 'percent', { path_within: { root: '/a', case_insensitive: false } }), 'invalid_predicate');
  assert.equal(on('set_discount', 'percent', { equals: '5' }), 'invalid_predicate');
  assert.equal(on('set_discount', 'percent', { in: [1, '2'] }), 'invalid_predicate');
  assert.equal(on('set_discount', 'percent', { in: [1, 2] }), 'OK');
  assert.equal(on('read_file', 'path', { equals: 5 }), 'invalid_predicate');
  assert.equal(on('read_file', 'path', { in: [true] }), 'invalid_predicate');
  assert.equal(on('tag_item', 'tags', { glob: 'a*' }), 'OK'); // string[] counts as string
  assert.equal(on('tag_item', 'tags', { range: { min: 1 } }), 'invalid_predicate');
  assert.equal(on('tag_item', 'tags', { equals: 'a' }), 'OK');
  assert.equal(on('tag_item', 'flag', { equals: true }), 'OK');
  assert.equal(on('tag_item', 'flag', { equals: 'true' }), 'invalid_predicate');
  assert.equal(on('tag_item', 'flag', { glob: '*' }), 'invalid_predicate');
});

test('error messages never echo values longer than 40 chars', () => {
  const longName = 'x'.repeat(100);
  for (const d of [
    { ...policyDoc([]), name: longName },
    withRule({ tools: ['read_file'], args: { path: { glob: 'a'.repeat(300) } } }),
    { ...policyDoc([]), tools: { [longName]: TOOLS.read_file } },
    withRule({ tools: [longName] }),
    { ...policyDoc([]), mode: longName },
    withRule({ tools: ['http_get'], args: { url: { domain_suffix: longName.toUpperCase(), accept: ['url'] } } }),
  ]) {
    try {
      loadPolicy(JSON.stringify(d));
      assert.fail('expected a PolicyError');
    } catch (e) {
      assert.ok(e instanceof PolicyError);
      assert.ok(!e.message.includes('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'), e.message);
      assert.ok(!e.message.includes('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'), e.message);
      assert.ok(!e.path.includes('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'), e.path);
      assert.equal(typeof e.code, 'string');
      assert.equal(typeof e.path, 'string');
    }
  }
});

test('policy version: stable under key reorder and whitespace, changes with semantics', () => {
  const a = '{"policy_schema_version":1,"name":"n","mode":"enforce","tools":{},"rules":[]}';
  const b = '{\n  "rules": [],\n  "tools": {},\n\t"mode": "enforce",\n  "name": "n",\n  "policy_schema_version": 1\r\n}\n';
  assert.equal(loadPolicy(a).policy_version, loadPolicy(b).policy_version);
  assert.equal(loadPolicy(a).policy_version, loadPolicy(Buffer.from(b)).policy_version);

  const reordered = JSON.stringify({ rules: [], tools: {}, mode: 'enforce', name: 'n', policy_schema_version: 1 });
  assert.equal(loadPolicy(reordered).policy_version, loadPolicy(a).policy_version);

  // the fixture with reordered keys at every level hashes identically
  const fx = JSON.parse(readFileSync(FIXTURE, 'utf8')) as Record<string, unknown>;
  const rev = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(rev);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).reverse().map(([k, x]) => [k, rev(x)]));
    return v;
  };
  assert.equal(loadPolicy(JSON.stringify(rev(fx), null, 4)).policy_version, loadPolicy(readFileSync(FIXTURE)).policy_version);

  // semantic changes change the version, including mode
  const mon = a.replace('"enforce"', '"monitor_only"');
  assert.notEqual(loadPolicy(mon).policy_version, loadPolicy(a).policy_version);
  assert.notEqual(loadPolicy(a.replace('"n"', '"m"')).policy_version, loadPolicy(a).policy_version);
  const r1 = mk([permit('a', { tools: ['read_file'] })]);
  const r2 = mk([deny('a', { tools: ['read_file'] })]);
  assert.notEqual(r1.policy_version, r2.policy_version);
  assert.notEqual(mk([permit('a', { tools: ['read_file'] })], 'monitor_only').policy_version, r1.policy_version);
  assert.equal(loadPolicy(a).mode, 'enforce');
  assert.equal(loadPolicy(mon).mode, 'monitor_only');
});

test('policy version is independent of the caller mutating the input buffer afterwards', () => {
  const buf = Buffer.from(JSON.stringify(policyDoc([permit('a', { tools: ['read_file'] })])));
  const v = loadPolicy(buf).policy_version;
  buf.fill(0x20);
  assert.equal(loadPolicy(Buffer.from(JSON.stringify(policyDoc([permit('a', { tools: ['read_file'] })])))).policy_version, v);
});

test('jcs follows RFC 8785', () => {
  assert.equal(jcs({ b: 1, a: [1, 'x', null, true], c: {} }), '{"a":[1,"x",null,true],"b":1,"c":{}}');
  assert.equal(jcs([]), '[]');
  assert.equal(jcs('a"\\\n\u0001\u007f'), '"a\\"\\\\\\n\\u0001\u007f"');
  // numbers: ECMAScript serialisation
  assert.equal(jcs([1e21, 1e-7, 0.000001, 123456789012345680000, -0, 4.5, 0.1, 1e30, 333333333.33333329]),
    '[1e+21,1e-7,0.000001,123456789012345680000,0,4.5,0.1,1e+30,333333333.3333333]');
  // key order by UTF-16 code units (RFC 8785 section 3.2.3 example)
  const o: Record<string, number> = {
    '\u20ac': 1, '\r': 2, '\ufb33': 3, '1': 4, '\ud83d\ude00': 5, '\u0080': 6, '\u00f6': 7,
  };
  assert.equal(jcs(o), '{"\\r":2,"1":4,"\u0080":6,"\u00f6":7,"\u20ac":1,"\ud83d\ude00":5,"\ufb33":3}');
  assert.throws(() => jcs(undefined), TypeError);
  assert.throws(() => jcs(NaN), TypeError);
  assert.throws(() => jcs(Infinity), TypeError);
  assert.throws(() => jcs(1n), TypeError);
  assert.throws(() => jcs({ a: () => 1 }), TypeError);
});

test('v1.2: forbidden policy characters (written as escapes)', () => {
  const mkName = (s: string) => `{"policy_schema_version":1,"name":"${s}","mode":"enforce","tools":{},"rules":[]}`;
  for (const esc of ['\\u00ad', '\\u034f', '\\u061c', '\\u180e', '\\u2028', '\\u2029', '\\ufff9', '\\ufffb', '\\ufe00', '\\ufe0f', '\\udb40\\udc01', '\\udb40\\udc7f']) {
    assert.equal(loadCode(mkName('a' + esc + 'b')), 'forbidden_char', esc);
  }
  assert.equal(loadCode(mkName('a\\ufffcb')), 'invalid_identifier'); // not a forbidden char, but not an identifier
});

test('v1.2: accept duplicates are deduplicated before any cap', () => {
  const acc = (a: unknown) => loadCode(withRule({ tools: ['http_get'], args: { url: { domain_suffix: 'corp.com', accept: a } } }));
  assert.equal(acc(['url', 'url', 'url', 'url', 'url']), 'OK');
  assert.equal(acc(['url', 'host', 'url', 'host', 'email', 'email']), 'OK');
});

test('v1.2: reordering rules keeps policy_version', () => {
  const a = permit('a', { tools: ['read_file'] });
  const b = deny('b', { tools: ['http_get'] });
  const c = permit('c', { tools: ['search_docs'] });
  assert.equal(mk([a, b, c]).policy_version, mk([c, a, b]).policy_version);
  assert.equal(mk([a, b, c]).policy_version, mk([b, c, a]).policy_version);
  assert.notEqual(mk([a, b, c]).policy_version, mk([a, b]).policy_version);
});
