import { test } from 'node:test';
import assert from 'node:assert/strict';
import { snapshotRequest, RequestError } from '../../src/core/index.ts';
import type { RequestErrorCode } from '../../src/core/index.ts';

function code(x: unknown): RequestErrorCode | 'OK' {
  try {
    snapshotRequest(x);
    return 'OK';
  } catch (e) {
    if (e instanceof RequestError) return e.code;
    throw e;
  }
}
const base = (args: unknown = {}, ctx: unknown = { agentId: 'a' }) => ({ tool: 't', args, ctx });

test('snapshot is a deep, frozen copy isolated from later mutation', () => {
  const original = {
    tool: 'send_email',
    args: { to: 'a@corp.com', list: ['x', 'y'], nested: { n: 1 } },
    ctx: { agentId: 'a', scopes: ['s1'], provenance: { to: ['trusted-user'] } },
  };
  const snap = snapshotRequest(original);
  assert.deepEqual(snap, original);
  assert.notEqual(snap, original);
  assert.notEqual(snap.args, original.args);
  original.args.to = 'evil@evil.com';
  original.args.list.push('z');
  original.args.nested.n = 99;
  original.ctx.scopes.push('admin');
  original.ctx.provenance.to.push('untrusted');
  assert.equal(snap.args['to'], 'a@corp.com');
  assert.deepEqual(snap.args['list'], ['x', 'y']);
  assert.deepEqual(snap.args['nested'], { n: 1 });
  assert.deepEqual(snap.ctx.scopes, ['s1']);
  assert.deepEqual(snap.ctx.provenance, { to: ['trusted-user'] });

  const frozen = (v: unknown): boolean => {
    if (typeof v !== 'object' || v === null) return true;
    return Object.isFrozen(v) && Object.values(v).every(frozen);
  };
  assert.ok(frozen(snap));
  assert.throws(() => {
    (snap.args as Record<string, unknown>)['to'] = 'x';
  }, TypeError);
  assert.throws(() => {
    (snap.args['list'] as string[]).push('q');
  }, TypeError);
  assert.throws(() => {
    (snap as unknown as Record<string, unknown>)['tool'] = 'x';
  }, TypeError);
});

test('snapshot of a snapshot is the same frozen object; a copy is not trusted as a snapshot', () => {
  const s = snapshotRequest(base({ a: 1 }));
  assert.equal(snapshotRequest(s), s);
  const clone = JSON.parse(JSON.stringify(s));
  assert.notEqual(snapshotRequest(clone), clone);
});

test('plain JSON values are accepted; -0 is normalised; null-prototype objects accepted', () => {
  assert.equal(code(base({ a: null, b: true, c: 1.5, d: 'x', e: [], f: {}, g: [[1], [2]] })), 'OK');
  const s = snapshotRequest(base({ z: -0, arr: [-0] }));
  assert.ok(Object.is(s.args['z'], 0));
  assert.ok(Object.is((s.args['arr'] as number[])[0], 0));
  assert.equal(code(base(Object.assign(Object.create(null), { a: 1 }))), 'OK');
  const shared = { v: 1 };
  assert.equal(code(base({ a: shared, b: shared })), 'OK'); // DAG, not a cycle
});

test('non-JSON values are invalid_request', () => {
  const cases: [string, unknown][] = [
    ['undefined value', base({ a: undefined })],
    ['NaN', base({ a: NaN })],
    ['Infinity', base({ a: Infinity })],
    ['-Infinity', base({ a: -Infinity })],
    ['BigInt', base({ a: 1n })],
    ['symbol value', base({ a: Symbol('x') })],
    ['function', base({ a: () => 1 })],
    ['Date', base({ a: new Date(0) })],
    ['Map', base({ a: new Map() })],
    ['Set', base({ a: new Set() })],
    ['RegExp', base({ a: /x/ })],
    ['typed array', base({ a: new Uint8Array(2) })],
    ['Buffer', base({ a: Buffer.from('x') })],
    ['class instance', base({ a: new (class Foo { x = 1; })() })],
    ['error object', base({ a: new Error('x') })],
    ['boxed string', base({ a: new String('x') })],
    ['array subclass', base({ a: new (class A extends Array {})() })],
    ['lone high surrogate', base({ a: '\ud800' })],
    ['lone low surrogate', base({ a: 'x\udc00' })],
    ['lone surrogate in key', base({ ['\ud800']: 1 })],
    ['sparse array', base({ a: [1, , 3] })],
    ['array extra prop', base({ a: Object.assign([1], { extra: 1 }) })],
    ['non-enumerable prop', base(Object.defineProperty({}, 'a', { value: 1, enumerable: false }))],
    ['top-level not object', 5],
    ['null request', null],
    ['undefined request', undefined],
    ['array request', []],
    ['string request', 'x'],
    ['missing ctx', { tool: 't', args: {} }],
    ['missing args', { tool: 't', ctx: { agentId: 'a' } }],
    ['missing tool', { args: {}, ctx: { agentId: 'a' } }],
    ['tool not string', base({}, { agentId: 'a' }) && { tool: 5, args: {}, ctx: { agentId: 'a' } }],
    ['args array', base([])],
    ['args null', base(null)],
    ['unknown request key', { ...base(), extra: 1 }],
    ['unknown ctx key', base({}, { agentId: 'a', role: 'admin' })],
    ['missing agentId', base({}, {})],
    ['agentId number', base({}, { agentId: 1 })],
    ['agentId empty', base({}, { agentId: '' })],
    ['ctx null', { tool: 't', args: {}, ctx: null }],
    ['ctx array', { tool: 't', args: {}, ctx: [] }],
    ['userId number', base({}, { agentId: 'a', userId: 1 })],
    ['scopes not strings', base({}, { agentId: 'a', scopes: [1] })],
    ['scopes not array', base({}, { agentId: 'a', scopes: 'x' })],
    ['sessionTainted string', base({}, { agentId: 'a', sessionTainted: 'true' })],
    ['provenance label invalid', base({}, { agentId: 'a', provenance: { to: ['bad label'] } })],
    ['provenance label empty', base({}, { agentId: 'a', provenance: { to: [''] } })],
    ['provenance label too long', base({}, { agentId: 'a', provenance: { to: ['x'.repeat(65)] } })],
    ['provenance not array', base({}, { agentId: 'a', provenance: { to: 'x' } })],
    ['provenance not object', base({}, { agentId: 'a', provenance: [] })],
  ];
  for (const [name, input] of cases) assert.equal(code(input), 'invalid_request', name);
});

test('forbidden keys are invalid_request at any depth', () => {
  for (const k of ['__proto__', 'constructor', 'prototype']) {
    const o = JSON.parse(`{"${k}":1}`) as unknown;
    assert.equal(code(base(o)), 'invalid_request', k);
    assert.equal(code(base({ ok: { deeper: o } })), 'invalid_request', k);
    assert.equal(code({ ...base(), [k]: 1 }), 'invalid_request', k);
  }
});

test('accessors, symbol keys, Proxies and cycles are rejected without running attacker code twice', () => {
  let reads = 0;
  const getter = { get a() { reads++; return 1; } };
  assert.equal(code(base(getter)), 'invalid_request');
  assert.equal(reads, 0);
  assert.equal(code(base({ set a(_v: number) {} })), 'invalid_request');
  assert.equal(code(base({ [Symbol('k')]: 1 })), 'invalid_request');
  assert.equal(code(base({ arr: Object.defineProperty([1], '0', { get: () => 1, enumerable: true }) })), 'invalid_request');

  assert.equal(code(base(new Proxy({ a: 1 }, {}))), 'invalid_request');
  assert.equal(code(base({ a: new Proxy([1], {}) })), 'invalid_request');
  assert.equal(code(new Proxy(base(), {})), 'invalid_request');
  assert.equal(code(base({ a: new Proxy({}, { ownKeys() { throw new Error('boom'); } }) })), 'invalid_request');
  assert.equal(code(new Proxy({}, { getPrototypeOf() { throw new Error('boom'); } })), 'invalid_request');
  assert.equal(code(base(new Proxy({}, { get() { return 1; }, has() { return true; } }))), 'invalid_request');
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  assert.equal(code(base({ a: proxy })), 'invalid_request');

  const cyc: Record<string, unknown> = {};
  cyc['self'] = cyc;
  assert.equal(code(base(cyc)), 'invalid_request');
  const a: unknown[] = [];
  a.push(a);
  assert.equal(code(base({ a })), 'invalid_request');
  const x: Record<string, unknown> = { y: {} };
  (x['y'] as Record<string, unknown>)['x'] = x;
  assert.equal(code(base({ x })), 'invalid_request');
});

test('limits: string length boundaries', () => {
  assert.equal(code(base({ a: 'x'.repeat(8192) })), 'OK');
  assert.equal(code(base({ a: 'x'.repeat(8193) })), 'limit_exceeded');
  assert.equal(code(base({ a: 'x'.repeat(5_000_000) })), 'limit_exceeded');
  assert.equal(code(base({ ['k'.repeat(8193)]: 1 })), 'limit_exceeded');
});

test('limits: key and item counts', () => {
  const keys = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => ['k' + i, 1]));
  assert.equal(code(base(keys(64))), 'OK');
  assert.equal(code(base(keys(65))), 'limit_exceeded');
  assert.equal(code(base({ a: Array.from({ length: 256 }, () => 1) })), 'OK');
  assert.equal(code(base({ a: Array.from({ length: 257 }, () => 1) })), 'limit_exceeded');
  assert.equal(code(base({ a: new Array(1e9) })), 'limit_exceeded'); // huge sparse array: size checked before shape
});

test('limits: depth boundary (request root is depth 1)', () => {
  // root(1) args(2) a(3) b(4) c(5) d(6) e(7) f(8)
  assert.equal(code(base({ a: { b: { c: { d: { e: { f: {} } } } } } })), 'OK');
  assert.equal(code(base({ a: { b: { c: { d: { e: { f: { g: {} } } } } } } })), 'limit_exceeded');
  let deep: unknown = 1;
  for (let i = 0; i < 100000; i++) deep = [deep];
  assert.equal(code(base({ a: deep })), 'limit_exceeded'); // no stack overflow
});

test('limits: total JSON size is 64 KiB', () => {
  const chunk = 'x'.repeat(8000);
  const mkArgs = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => ['k' + i, chunk]));
  assert.equal(code(base(mkArgs(8))), 'OK'); // ~64,000 bytes + overhead < 65,536
  assert.equal(code(base(mkArgs(9))), 'limit_exceeded');
  // multi-byte characters count as bytes, not code units
  const wide = '€'.repeat(8000); // 24,000 bytes each
  assert.equal(code(base({ a: wide, b: wide })), 'OK');
  assert.equal(code(base({ a: wide, b: wide, c: wide })), 'limit_exceeded');
});

test('RequestError carries a code and path and does not echo values', () => {
  try {
    snapshotRequest(base({ secret: 'x'.repeat(9000) }));
    assert.fail('expected throw');
  } catch (e) {
    assert.ok(e instanceof RequestError);
    assert.equal(e.code, 'limit_exceeded');
    assert.ok(!e.message.includes('xxxxxxxx'));
    assert.match(e.path, /secret/);
  }
});

test('F-02: work bounds count every visit of shared references', () => {
  const fan = (f: number, l: number, leaf: () => unknown): unknown => {
    let cur: unknown = leaf();
    for (let i = 0; i < l; i++) {
      const c = cur;
      cur = Array.from({ length: f }, () => c);
    }
    return cur;
  };
  const cases: [string, unknown][] = [
    ['256x4 shared empty array', fan(256, 4, () => [])],
    ['256x4 shared empty object', fan(256, 4, () => ({}))],
    ['256x4 shared number', fan(256, 4, () => 1)],
    ['64x6 shared empty array', fan(64, 6, () => [])],
    ['64x6 shared empty object', fan(64, 6, () => ({}))],
    ['64x6 shared string', fan(64, 6, () => 'x')],
  ];
  for (const [name, v] of cases) {
    const t0 = performance.now();
    assert.equal(code(base({ a: v })), 'limit_exceeded', name);
    assert.ok(performance.now() - t0 < 1000, name + ' was slow');
  }
  // shared object fan-out through keys
  let o: unknown = { x: 1 };
  for (let i = 0; i < 6; i++) {
    const n: Record<string, unknown> = {};
    for (let k = 0; k < 40; k++) n['k' + k] = o;
    o = n;
  }
  const t1 = performance.now();
  assert.equal(code(base({ a: o })), 'limit_exceeded');
  assert.ok(performance.now() - t1 < 1000);
  // modest sharing is fine
  assert.equal(code(base({ a: Array.from({ length: 200 }, () => []) })), 'OK');
  const wide = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => ['k' + i, Array.from({ length: 256 }, () => Array.from({ length: 3 }, () => []))]));
  assert.equal(code(base(wide(5))), 'limit_exceeded'); // > 4096 containers
});

test('F-09: snapshot normalises values and keys to NFC; colliding keys are rejected', () => {
  const s = snapshotRequest(base({ ['é']: 'é', list: ['å'] }));
  assert.deepEqual(Object.keys(s.args), ['é', 'list']);
  assert.equal(s.args['é'], 'é');
  assert.deepEqual(s.args['list'], ['å']);
  assert.equal(code(base({ ['é']: 1, ['é']: 2 })), 'invalid_request');
  assert.equal(code({ tool: 't', args: {}, ctx: { agentId: 'á' } }), 'OK');
});
