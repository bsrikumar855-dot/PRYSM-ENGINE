import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hostFromString, matchPathWithin, globMatch, decide, PolicyError } from '../../src/core/index.ts';
import { mk, permit, req } from './helpers.ts';

// ---------------------------------------------------------------- hosts

test('hostFromString: extraction table', () => {
  const table: [string, string | null][] = [
    ['corp.com', 'corp.com'],
    ['CORP.COM', 'corp.com'],
    ['docs.Corp.com', 'docs.corp.com'],
    ['corp.com.', 'corp.com'], // exactly one trailing dot stripped
    ['corp.com..', null],
    ['.corp.com', null],
    ['notcorp.com', 'notcorp.com'],
    ['corp.com.evil.com', 'corp.com.evil.com'],
    ['alice@corp.com', 'corp.com'],
    ['corp.com@evil.com', 'evil.com'],
    ['a@b@corp.com', null],
    ['@corp.com', null],
    ['alice@', null],
    ['alice@corp.com/x', null],
    ['corp.com\\@evil.com', null],
    ['http://corp.com\\@evil.com', null],
    ['http://corp.com@evil.com/', null],
    ['http://user:pw@corp.com/', null],
    ['http://:pw@corp.com/', null],
    ['https://corp.com/path?x=1', 'corp.com'],
    ['https://corp.com:8443/x', 'corp.com'],
    ['https://corp.com#@evil.com', 'corp.com'], // WHATWG semantics (sink duty)
    ['http://CORP.com./x', 'corp.com'],
    ['ftp://corp.com/', null],
    ['file://corp.com/x', null],
    ['javascript://corp.com/%0aalert(1)', null],
    ['http://corp.com .evil.com/', null],
    ['http://corp.com\t.evil.com/', null],
    ['http:///corp.com', 'corp.com'],
    ['http://', null],
    ['', null],
    // IP literals never satisfy domain predicates
    ['http://2130706433/', null],
    ['http://0x7f.1/', null],
    ['http://127.1/', null],
    ['http://127.0.0.1/', null],
    ['http://0177.0.0.1/', null],
    ['2130706433', null],
    ['0x7f.1', null],
    ['0x7f', null],
    ['127.1', null],
    ['127.0.0.1', null],
    ['017700000001', null],
    ['1.2.3.4.', null],
    ['http://[::1]/', null],
    ['http://[::ffff:127.0.0.1]/', null],
    ['[::1]', null],
    ['::1', null],
    ['fe80::1', null],
    // whitespace and separators
    [' corp.com', null],
    ['corp.com ', null],
    ['corp .com', null],
    ['corp.com\n', null],
    ['corp.com\u00a0', null],
    ['corp.com/x', null],
    ['corp.com?x', null],
    ['corp.com#x', null],
    ['corp.com:80', null],
    ['corp%2ecom', null],
    // lexical validity
    ['a_b.com', null],
    ['-a.com', null],
    ['a-.com', null],
    ['a'.repeat(63) + '.com', 'a'.repeat(63) + '.com'],
    ['a'.repeat(64) + '.com', null],
    // unicode: IDNA, homoglyphs, fullwidth dots, zero-width
    ['m\u00fcnchen.corp.com', null], // v1.1: any non-ASCII => no match
    ['xn--mnchen-3ya.corp.com', 'xn--mnchen-3ya.corp.com'],
    ['\u0441orp.com', null], // Cyrillic es: non-ASCII => no match
    ['corp\uff0ecom', null], // fullwidth full stop
    ['corp\u3002com', null], // ideographic full stop
    ['corp\uff61com', null], // halfwidth ideographic full stop
    ['cor\u200bp.com', null],
    ['corp.com\u202e', null],
    ['\ud800.corp.com', null],
  ];
  for (const [input, expected] of table) {
    assert.equal(hostFromString(input), expected, JSON.stringify(input));
  }
  assert.equal(hostFromString('corp.c\u043em'), null);
});

test('hostFromString: bad input types and sizes', () => {
  assert.equal(hostFromString(undefined as never), null);
  assert.equal(hostFromString(5 as never), null);
  assert.equal(hostFromString('a'.repeat(9000)), null);
  assert.equal(hostFromString(('a'.repeat(60) + '.').repeat(5) + 'com'), null); // > 253 total
});

function domainPermit(kind: 'domain_suffix' | 'domain_exact', policyHost: string, accept: string[] = ['url', 'email', 'host']) {
  const p = mk([permit('d', { tools: ['http_get'], args: { url: { [kind]: policyHost, accept } } })]);
  return (value: string) => decide(p, req('http_get', { url: value })).effect === 'permit';
}

test('domain_suffix: dot-boundary semantics and lookalikes', () => {
  const ok = domainPermit('domain_suffix', 'corp.com');
  for (const v of ['corp.com', 'docs.corp.com', 'a.b.corp.com', 'CORP.com', 'corp.com.', 'https://docs.corp.com/x', 'bob@corp.com', 'https://corp.com#@evil.com', 'xn--mnchen-3ya.corp.com']) {
    assert.equal(ok(v), true, v);
  }
  for (const v of [
    'notcorp.com', 'corp.com.evil.com', 'corp.com@evil.com', 'http://corp.com\\@evil.com', 'http://corp.com@evil.com',
    'evil.com/corp.com', 'http://evil.com/?corp.com', 'http://evil.com#corp.com', 'corp.co', 'corp.comm', 'xcorp.com', 'com',
    '', ' corp.com', 'corp.com ', 'http://127.0.0.1/corp.com', '2130706433', '0x7f.1', '127.1', '[::1]', 'http://[::1]/',
    '\u0441orp.com', 'corp.c\u043em', 'corp\uff0ecom', 'm\u00fcnchen.corp.com', 'corp.com%2f', 'corp.com\\x', 'mailto:bob@corp.com', 'a b@corp.com', 'bob@corp.com/x', '@corp.com', 'bob@[::1]', 'a@b@corp.com', 'ftp://corp.com', 'corp.com:80', 'corp.com\t',
  ]) {
    assert.equal(ok(v), false, JSON.stringify(v));
  }
});

test('domain_exact: only the exact host matches', () => {
  const ok = domainPermit('domain_exact', 'docs.corp.com');
  assert.equal(ok('docs.corp.com'), true);
  assert.equal(ok('DOCS.corp.com.'), true);
  assert.equal(ok('https://docs.corp.com/a'), true);
  assert.equal(ok('x@docs.corp.com'), true);
  assert.equal(ok('corp.com'), false);
  assert.equal(ok('a.docs.corp.com'), false);
  assert.equal(ok('docs.corp.com.evil.com'), false);
  assert.equal(ok('xdocs.corp.com'), false);
});

test('accept selects which string shapes a domain predicate considers', () => {
  const email = domainPermit('domain_suffix', 'corp.com', ['email']);
  assert.equal(email('bob@corp.com'), true);
  assert.equal(email('b.o+b_1-x@docs.corp.com'), true);
  assert.equal(email('corp.com'), false);
  assert.equal(email('https://corp.com/'), false);
  assert.equal(email('bob@https://corp.com'), false);
  const url = domainPermit('domain_suffix', 'corp.com', ['url']);
  assert.equal(url('https://corp.com/'), true);
  assert.equal(url('http://docs.corp.com/x?y=1#z'), true);
  assert.equal(url('bob@corp.com'), false);
  assert.equal(url('corp.com'), false);
  assert.equal(url('ftp://corp.com'), false);
  const host = domainPermit('domain_suffix', 'corp.com', ['host']);
  assert.equal(host('docs.corp.com'), true);
  assert.equal(host('bob@corp.com'), false);
  assert.equal(host('https://corp.com'), false);
  assert.equal(host('corp.com/x'), false);
  const two = domainPermit('domain_suffix', 'corp.com', ['url', 'host']);
  assert.equal(two('corp.com'), true);
  assert.equal(two('https://corp.com'), true);
  assert.equal(two('bob@corp.com'), false);
  // local-part charset and length
  const e = domainPermit('domain_suffix', 'corp.com', ['email']);
  assert.equal(e('a'.repeat(64) + '@corp.com'), true);
  assert.equal(e('a'.repeat(65) + '@corp.com'), false);
  assert.equal(e('a!b@corp.com'), false);
  assert.equal(e('a:b@corp.com'), false);
  assert.equal(e('a@b@corp.com'), false);
  assert.equal(hostFromString('bob@corp.com', ['url']), null);
  assert.equal(hostFromString('bob@corp.com', ['email']), 'corp.com');
});

test('domain predicates on non-string arguments are a load error', () => {
  assert.throws(() => mk([permit('d', { tools: ['set_discount'], args: { percent: { domain_suffix: 'corp.com', accept: ['host'] } } })]), PolicyError);
});

// ---------------------------------------------------------------- paths

const WS = { root: '/workspace', case_insensitive: false };

test('path_within: accepted paths', () => {
  for (const v of [
    '/workspace', '/workspace/a.txt', '/workspace/a/b/c', '/workspace/a/../b', '/workspace//a', '/workspace/./a',
    '/workspace/a/..', '\\workspace\\a', '/workspace/CONSOLE', '/workspace/com10', '/workspace/a~b',
    '/workspace/.hidden', '/workspace/a.b.c', '/workspace/x/../../workspace/y', '/workspace/100%', '/workspace/a%2',
  ]) {
    assert.equal(matchPathWithin(v, WS), true, JSON.stringify(v));
  }
});

test('path_within: rejected paths', () => {
  const cases: string[] = [
    // traversal and encodings
    '/workspace/../etc/passwd', '/../workspace', '/workspace/a/../../etc', '/workspace/%2e%2e/etc', '/workspace/%2E%2E/x',
    '/workspace/a%2fb', '/workspace/a%20b', '/workspace/%00',
    // prefix tricks
    '/workspaceX', '/workspace-evil/a', '/work', '/', '', 'workspace/a', './workspace/a', '../workspace',
    // UNC / device paths
    '\\\\server\\share\\workspace', '\\\\?\\C:\\workspace', '\\\\.\\C:\\workspace', '//workspace/a', '//server/share', '/\\workspace/a', '\\/workspace/a',
    // alternate data streams and colons
    '/workspace/a.txt:stream', '/workspace/a.txt::$DATA', '/workspace/a:b', '/workspace:x',
    // drive letters (root has none)
    'C:/workspace/a', 'c:\\workspace\\a', 'C:workspace', 'C:', 'CC:/workspace', '1:/workspace',
    // reserved device names
    '/workspace/CON', '/workspace/con', '/workspace/Con.txt', '/workspace/nul', '/workspace/NUL.tar.gz', '/workspace/PRN',
    '/workspace/aux.log', '/workspace/COM1', '/workspace/com9.txt', '/workspace/LPT1', '/workspace/lpt9.x', '/workspace/a/CON/b',
    // trailing dot / space
    '/workspace/a.', '/workspace/a ', '/workspace/...', '/workspace/a./b', '/workspace/a /b',
    // 8.3 short names
    '/workspace/PROGRA~1', '/workspace/progra~1/x', '/workspace/a~1.txt', '/workspace/ab~12',
    // illegal characters
    '/workspace/a\u0000b', '/workspace/a?b', '/workspace/a*', '/workspace/a"b', '/workspace/<a>', '/workspace/a|b', '/workspace/a\tb', '/workspace/a\nb', '/workspace/a\u0085b',
  ];
  for (const v of cases) assert.equal(matchPathWithin(v, WS), false, JSON.stringify(v));
});

test('path_within: case sensitivity', () => {
  assert.equal(matchPathWithin('/WORKSPACE/a', WS), false);
  assert.equal(matchPathWithin('/Workspace', WS), false);
  const ci = { root: '/workspace', case_insensitive: true };
  assert.equal(matchPathWithin('/WORKSPACE/a', ci), true);
  assert.equal(matchPathWithin('/WorkSpace', ci), true);
  assert.equal(matchPathWithin('/WORKSPACEX', ci), false);
  assert.equal(matchPathWithin('/work', ci), false);
  // a root with capitals compares lowercase on both sides when case-insensitive (loader lowercases it)
  assert.equal(matchPathWithin('/workspace/a', { root: '/workspace', case_insensitive: true }), true);
  // Unicode lowercasing
  assert.equal(matchPathWithin('/\u00c9COLE/x', { root: '/ecole', case_insensitive: true }), false); // non-ASCII never matches
});

test('path_within: drive roots and root "/"', () => {
  const c = { root: 'C:/Work', case_insensitive: false };
  assert.equal(matchPathWithin('C:/Work/x', c), true);
  assert.equal(matchPathWithin('c:\\Work\\x', c), true); // drive upper-cased
  assert.equal(matchPathWithin('C:\\Work', c), true);
  assert.equal(matchPathWithin('D:/Work/x', c), false);
  assert.equal(matchPathWithin('/Work/x', c), false);
  assert.equal(matchPathWithin('C:/work/x', c), false);
  assert.equal(matchPathWithin('C:/work/x', { root: 'C:/work', case_insensitive: true }), true);
  assert.equal(matchPathWithin('C:/Work/../Windows', c), false);
  assert.equal(matchPathWithin('C:/Work/CON', c), false);
  assert.equal(matchPathWithin('C:/Work/a.txt:ads', c), false);

  const root = { root: '/', case_insensitive: false };
  assert.equal(matchPathWithin('/', root), true);
  assert.equal(matchPathWithin('/anything/at/all', root), true);
  assert.equal(matchPathWithin('/a/../b', root), true);
  assert.equal(matchPathWithin('/..', root), false);
  assert.equal(matchPathWithin('C:/x', root), false); // no drive prefix
  assert.equal(matchPathWithin('relative', root), false);
  assert.equal(matchPathWithin('\\\\server\\x', root), false);
  assert.equal(matchPathWithin('/a%2e', root), false);
  const croot = { root: 'C:/', case_insensitive: true };
  assert.equal(matchPathWithin('c:/x', croot), true);
  assert.equal(matchPathWithin('D:/x', croot), false);
});

// ---------------------------------------------------------------- glob

test('globMatch: semantics', () => {
  const t: [string, string, boolean][] = [
    ['*', '', true], ['*', 'abc', true], ['', '', true], ['', 'a', false], ['a', 'a', true], ['a', 'A', false],
    ['a*', 'abc', true], ['*c', 'abc', true], ['*b*', 'abc', true], ['a*c', 'abc', true], ['a*c', 'ab', false],
    ['?', 'a', true], ['?', '', false], ['?', 'ab', false], ['a?c', 'abc', true], ['a?c', 'ac', false],
    ['*/*', 'a/b/c', true], ['/workspace/secrets/*', '/workspace/secrets/x/y', true], ['/workspace/secrets/*', '/workspace/secrets', false],
    ['*@*', 'a@b', true], ['*@*', 'ab', false], ['a**b', 'ab', true], ['a**b', 'a-b', true],
    ['*a*b*c', 'xxaxxbxxc', true], ['*a*b*c', 'xxaxxcxxb', false],
    ['[ab]', 'a', false], ['[ab]', '[ab]', true], ['a.c', 'abc', false], ['a.c', 'a.c', true], ['\\*', '\\x', true], // no escape syntax: backslash is a literal
    // code points: one ? is exactly one code point (astral), NFC-normalised
    ['?', '\ud83d\ude00', true], ['??', '\ud83d\ude00', false], ['a?b', 'a\ud83d\ude00b', true],
    ['\u00e9', 'e\u0301', true], ['e\u0301', '\u00e9', true],
    ['*', '\n', true], ['a?b', 'a\nb', true],
  ];
  for (const [p, v, e] of t) assert.equal(globMatch(p, v), e, `${JSON.stringify(p)} vs ${JSON.stringify(v)}`);
});

test('globMatch: pathological patterns finish quickly (no catastrophic backtracking)', () => {
  const v = 'a'.repeat(8000);
  globMatch('*a*a*a*a*a*b', v); // warm up
  const t0 = performance.now();
  assert.equal(globMatch('*a*a*a*a*a*b', v), false);
  const dt = performance.now() - t0;
  assert.ok(dt < 50, `took ${dt.toFixed(1)} ms`);

  const t1 = performance.now();
  assert.equal(globMatch('*a'.repeat(100) + 'b', v), false);
  assert.equal(globMatch('?*'.repeat(120) + 'b', v), false);
  assert.equal(globMatch('*' + 'a?'.repeat(125) + '*b', v), false);
  assert.equal(globMatch('*a*a*a*a*a*', v), true);
  const dt1 = performance.now() - t1;
  assert.ok(dt1 < 250, `took ${dt1.toFixed(1)} ms`);
});

test('glob predicate on a number argument is a load error', () => {
  assert.throws(() => mk([permit('g', { tools: ['set_discount'], args: { percent: { glob: '*' } } })]), PolicyError);
});

test('path_within is ASCII-only; confusables and reserved names never match (spec 10.3)', () => {
  const ci = { root: '/workspace/secrets', case_insensitive: true };
  const cs = { root: '/workspace', case_insensitive: false };
  const bad = [
    '/workspace/secret\u017f/x', // long s
    '/work\u017fpace/x',
    '/workspace/\u0131', // dotless i
    '/workspace/\u0130', // dotted capital I
    '/workspace/stra\u00dfe', // sharp s
    '/workspace/\u212a', // Kelvin sign
    '/workspace/COM\u00b9', // superscript one
    '/workspace/COM\u00b2.txt',
    '/workspace\uff0e/x', // fullwidth full stop
    '/workspace/\uff0e\uff0e/x',
    '/workspace/\u3002',
    '/workspace/e\u0301.txt', // NFD
    '/workspace/\u00e9.txt', // NFC
    '/\uff57orkspace/x',
  ];
  for (const v of bad) assert.equal(matchPathWithin(v, cs), false, JSON.stringify(v));
  assert.equal(matchPathWithin('/workspace/SECRET\u017f/x', ci), false);
  assert.equal(matchPathWithin('/WORKSPACE/SECRETS/x', ci), true);
  // reserved device names incl. CONIN$ / CONOUT$
  for (const v of ['/workspace/CONIN$', '/workspace/conout$', '/workspace/CONIN$.txt', '/workspace/CONOUT$.a.b']) {
    assert.equal(matchPathWithin(v, cs), false, v);
  }
  assert.equal(matchPathWithin('/workspace/CONIN', cs), true);
});

test('policy path roots must be ASCII', async () => {
  const { loadCode, policyDoc } = await import('./helpers.ts');
  for (const root of ['/caf\u00e9', '/\u00e9cole', '/\uff57']) {
    assert.equal(loadCode(policyDoc([permit('a', { tools: ['read_file'], args: { path: { path_within: { root, case_insensitive: false } } } })])), 'invalid_value', root);
  }
});

test('glob work budget: 1000 expensive rules against an 8192-char arg stay bounded and deterministic', () => {
  const rules = Array.from({ length: 1000 }, (_, i) => permit('g' + String(i).padStart(4, '0'), { tools: ['read_file'], args: { path: { glob: '*' + 'a'.repeat(250) + 'c' } } }));
  const p = mk(rules);
  const r = req('read_file', { path: 'a'.repeat(8192) });
  const t0 = performance.now();
  const d = decide(p, r);
  const dt = performance.now() - t0;
  assert.ok(dt < 1000, 'took ' + dt.toFixed(0) + ' ms');
  assert.equal(d.effect, 'deny');
  assert.ok(d.reason_code === 'limit_exceeded' || d.reason_code === 'default_deny', d.reason_code);
  assert.deepEqual(decide(p, r), d); // deterministic
});

test('glob with more than 4 wildcards is a load error', async () => {
  const { loadCode, policyDoc } = await import('./helpers.ts');
  const g = (pat: string) => loadCode(policyDoc([permit('a', { tools: ['read_file'], args: { path: { glob: pat } } })]));
  assert.equal(g('*a*a*a*a'), 'OK');
  assert.equal(g('*a*a*a*a*'), 'limit_exceeded');
  assert.equal(g('?????????*'), 'OK');
});
