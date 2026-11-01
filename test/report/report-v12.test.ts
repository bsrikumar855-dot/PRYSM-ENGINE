// REPORT-SPEC section 5 (v1.2) tests: block cause precedence, banner honesty, layout fixes, pre-flight over all render paths.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { cleanup } from '../support/tmp.ts';
import { freshStore, build, html, guardRun, monitorRun, appendHostile, policyOf, styleOf } from '../support/report-kit.ts';
import { renderReportHtml, CODE_HELP } from '../../src/report/render.ts';
import type { ReportData } from '../../src/report/index.ts';

after(cleanup);
const textOf = (h: string): string => h.replace(/<style>[\s\S]*?<\/style>/, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
const DASH = /[–—]/;
const BANNED_CLASS = /class="[^"]*\b(?:card|tile|pill|badge|eyebrow)\b/i;

type Ev = Parameters<ReturnType<typeof freshStore>['store']['append']>[0];
const dec = (id: string, over: Partial<Ev>): Ev => ({
  id, kind: 'decision', ts_ms: 1000, tool: 'read_file', effect: 'deny', enforcement: 'enforced', reason_code: 'denied_by_rule', session_id: 's1', ...over,
});

test('5.2 cause precedence 1: outcome.deny_n names only the first deny_n ids; permit ids never follow BLOCKED by', () => {
  const { store } = freshStore();
  store.append(dec('a1', { rule_ids: ['d.one', 'd.two', 'p.allow'], outcome: { deny_n: 2 } }));
  store.append(dec('a2', { rule_ids: ['p.allow', 'p.other'], outcome: { deny_n: 0 } }));
  const d = build(store);
  const a1 = d.decisions.find((x) => x.id === 'a1');
  assert.equal(a1?.verdict, 'BLOCKED by rules d.one, d.two.');
  assert.equal(a1?.cause_source, 'deny_n');
  assert.deepEqual(a1?.cause_ids, ['d.one', 'd.two']);
  const a2 = d.decisions.find((x) => x.id === 'a2');
  assert.equal(a2?.verdict, 'BLOCKED.');
  for (const x of d.decisions) assert.ok(!/BLOCKED[^.]* by rules? .*p\./.test(x.verdict), 'permit id after BLOCKED by: ' + x.verdict);
  assert.deepEqual(d.metrics.top_rules.map((r) => r.name), ['d.one', 'd.two']);
  assert.equal(d.metrics.top_rules_excluded, 0);
  assert.ok(!textOf(html(store)).includes('lack the deny/permit split'));
  store.close();
});

test('5.2 cause precedence 2: same-version policy effects decide when deny_n is absent', () => {
  const policy = policyOf('enforce');
  const { store } = freshStore();
  store.append(dec('l1', { rule_ids: ['p.read', 'd.secret'], policy_version: policy.policy_version }));
  store.append(dec('l2', { rule_ids: ['p.read', 'd.secret'], policy_version: 'other-version' }));
  const withPolicy = build(store, { policy });
  const l1 = withPolicy.decisions.find((x) => x.id === 'l1');
  assert.equal(l1?.cause_source, 'policy');
  assert.equal(l1?.verdict, 'BLOCKED by rule d.secret.');
  assert.deepEqual(withPolicy.metrics.top_rules.map((r) => r.name), ['d.secret']);
  const l2 = withPolicy.decisions.find((x) => x.id === 'l2');
  assert.equal(l2?.cause_source, 'legacy', 'a different policy version is never used');
  assert.equal(withPolicy.metrics.top_rules_excluded, 1);
  store.close();
});

test('5.2 cause precedence 3: legacy rows use caveat wording and are excluded from top rules with a count', () => {
  const { store } = freshStore();
  store.append(dec('g1', { rule_ids: ['d.secret', 'p.read'] }));
  store.append(dec('g2', { rule_ids: ['d.secret', 'p.read'], outcome: { deny_n: 1 } }));
  const d = build(store);
  const g1 = d.decisions.find((x) => x.id === 'g1');
  assert.equal(g1?.cause_source, 'legacy');
  assert.equal(g1?.verdict, 'BLOCKED.');
  assert.equal(g1?.why, 'A deny rule matched. All matched rules, deny rules listed first: d.secret, p.read');
  assert.deepEqual(d.metrics.top_rules, [{ name: 'd.secret', count: 1 }], 'only the deny_n row is counted');
  assert.equal(d.metrics.top_rules_excluded, 1);
  const t = textOf(html(store));
  assert.match(t, /1 row lacks the deny\/permit split and is left out of the top rules table/);
  assert.match(t, /A deny rule matched\. All matched rules, deny rules listed first: d\.secret, p\.read/);
  store.close();
});

test('5.2 truncation marker is never a cause or a top rule', () => {
  const { store } = freshStore();
  const ids = Array.from({ length: 20 }, (_, i) => 'r' + String(i));
  store.append(dec('t1', { rule_ids: ids, outcome: { deny_n: 17 } }));
  const d = build(store);
  assert.ok(!d.metrics.top_rules.some((r) => r.name.startsWith('…+')));
  assert.ok(!d.decisions[0]?.cause_ids.some((x) => x.startsWith('…+')));
  assert.ok(!(d.decisions[0]?.verdict ?? '').includes('…+'));
  store.close();
});

test('5.2 real guard rows never name a permit rule as the cause (with or without deny_n)', async () => {
  const k = await guardRun();
  await monitorRun(k);
  const d = build(k.store, { policy: k.policy });
  const blocked = d.decisions.filter((x) => x.reason_code === 'denied_by_rule');
  assert.ok(blocked.length > 0);
  for (const x of d.decisions) {
    const m = /\bby rules? (.*)\.$/.exec(x.verdict);
    if (x.effect === 'deny' && m) for (const id of (m[1] as string).split(', ')) assert.ok(id.startsWith('d.'), `${x.verdict}`);
  }
  assert.ok(!/BLOCKED by rules? p\./.test(textOf(html(k.store, { policy: k.policy }))));
  const hasSplit = blocked.some((x) => x.cause_source === 'deny_n');
  if (hasSplit) assert.equal(d.metrics.top_rules_excluded, 0, 'guard writes deny_n on every decision row');
});

test('5.9 banner shows the warning count and the development flag; header states scan truncation', () => {
  const { store } = freshStore();
  for (let i = 0; i < 12; i++) store.append({ id: 'b' + String(i), kind: 'decision', ts_ms: 1000 + i, effect: 'permit', enforcement: 'enforced' });
  store.checkpointAndPrune(1006, { force: true });
  const h = html(store, { allowPruned: true, scanLimit: 3 });
  const d = build(store, { allowPruned: true });
  assert.equal(d.verify.warnings.length, 1);
  const banner = /<div class="verdict[\s\S]*?<\/div>/.exec(h)?.[0] ?? '';
  assert.match(textOf(banner), /1 warning \(listed under Integrity and posture\)\./);
  assert.match(textOf(banner), /Development flag: pruned history accepted without an expected checkpoint/);
  const header = /<header[\s\S]*?<\/header>/.exec(h)?.[0] ?? '';
  assert.match(textOf(header), /Metrics cover the newest 3 of \d+ rows/);
  assert.ok(header.indexOf('</dl>') < header.indexOf('Metrics cover the newest'), 'directly under the summary strip');
  assert.match(textOf(/<div class="verdict[\s\S]*?<\/div>/.exec(html(store, { scanLimit: 3 }))?.[0] ?? ''), /FAILED[\s\S]*0 warnings/);
  const clean = freshStore();
  assert.match(textOf(html(clean.store)), /0 warnings\./);
  assert.ok(!textOf(html(clean.store)).includes('Development flag'));
  store.close();
  clean.store.close();
});

test('5.10 FAILED banner has a uniform 2 px border and the word FAILED (no side stripe)', () => {
  const css = styleOf(html(freshStore().store));
  assert.ok(!/border-left-width/.test(css));
  assert.ok(/\.verdict\{[^}]*border:2px solid/.test(css));
  assert.ok(!/14px/.test(css));
  const { store, path } = freshStore();
  store.append({ id: 'x', kind: 'decision', ts_ms: 1, effect: 'permit', enforcement: 'enforced' });
  const raw = new DatabaseSync(path);
  raw.exec('DROP TRIGGER events_no_update');
  raw.exec("UPDATE events SET tool='y' WHERE seq=1");
  raw.close();
  assert.match(textOf(html(store)), /FAILED: chain verification found 1 error/);
  store.close();
});

test('5.11 nav link size, no stray period after the head hash, no raw generated_ms, named vs ephemeral sessions', async () => {
  const k = await guardRun();
  const h = html(k.store);
  const css = styleOf(h);
  assert.match(css, /nav\.toc a\{[^}]*min-height:32px/);
  assert.match(css, /@media \(max-width:480px\)\{[^@]*nav\.toc a\{[^}]*min-height:44px/);
  const head = k.store.head();
  assert.ok(h.includes(`Head hash <code class="hash" title="${head?.hash as string}">${head?.hash as string}</code></p>`));
  assert.ok(!/<\/code>\.\s*<\/p>/.test(/<header[\s\S]*?<\/header>/.exec(h)?.[0].replace(/<div class="verdict[\s\S]*?<\/div>/, '') ?? ''));
  assert.ok(!/generated_ms/.test(textOf(h)));
  assert.match(h, /<time datetime="[^"]+" data-ms="\d+">/);
  const d = build(k.store);
  const rows = k.store.iterate({ limit: 1000 }).filter((e) => e.kind === 'decision');
  const named = new Set(rows.map((e) => e.session_id).filter((s): s is string => s !== null && !s.startsWith('eph-')));
  const eph = new Set(rows.map((e) => e.session_id).filter((s): s is string => s !== null && s.startsWith('eph-')));
  assert.ok(eph.size > 0 && named.size > 0, 'fixture has both kinds');
  assert.equal(d.metrics.sessions, named.size);
  assert.equal(d.metrics.ephemeral_sessions, eph.size);
  const t = textOf(h);
  assert.match(t, new RegExp(`Named sessions with decisions ${String(named.size)}`));
  assert.match(t, new RegExp(`Ephemeral per-call sessions ${String(eph.size)}`));
});

// ------------------------------------------------------------ 5.12 pre-flight over all render paths
function paths(): Promise<Record<string, string>> {
  return (async () => {
    const out: Record<string, string> = {};
    const k = await guardRun();
    await monitorRun(k);
    appendHostile(k.store);
    out['normal'] = html(k.store, { policy: k.policy, anchor: k.store.anchor() });
    out['truncated scan'] = html(k.store, { scanLimit: 4 });
    const e = freshStore();
    out['empty'] = html(e.store);
    const f = freshStore();
    f.store.append({ id: 'q', kind: 'decision', ts_ms: 1, effect: 'permit', enforcement: 'enforced' });
    f.store.append({ id: 'q2', kind: 'decision', ts_ms: 2, effect: 'permit', enforcement: 'enforced' });
    const raw = new DatabaseSync(f.path);
    raw.exec('DROP TRIGGER events_no_update');
    raw.exec("UPDATE events SET tool='z' WHERE seq=1");
    raw.close();
    out['failed verification'] = html(f.store);
    const base: ReportData = build(k.store);
    const codes = Object.keys(CODE_HELP);
    out['every CODE_HELP entry'] = renderReportHtml({
      ...base,
      verify: { ...base.verify, ok: false, errors: codes.map((c, i) => ({ seq: i, code: c })), warnings: codes.map((c, i) => ({ seq: i, code: c })) },
    });
    out['too large'] = renderReportHtml({ ...base, too_large: true, decisions: [], events: [], activations: [] });
    return out;
  })();
}

test('5.12 bans hold over the rendered output of every code path', async () => {
  const all = await paths();
  assert.deepEqual(Object.keys(all).sort(), ['empty', 'every CODE_HELP entry', 'failed verification', 'normal', 'too large', 'truncated scan']);
  for (const [name, h] of Object.entries(all)) {
    assert.ok(!DASH.test(h), `${name}: no en or em dash`);
    assert.ok(!BANNED_CLASS.test(h), `${name}: banned class name`);
    assert.ok(!/#(?:000|fff)(?:000|fff)?(?![0-9a-f])/i.test(h), `${name}: pure black/white`);
    assert.ok(!/<script/i.test(h), `${name}: script`);
    assert.equal((h.match(/<h1[ >]/g) ?? []).length, 1, `${name}: one h1`);
    assert.ok(h.startsWith('<!doctype html><!-- prysm-report v1 -->'), name);
    const tables = h.match(/<table>/g)?.length ?? 0;
    assert.equal((h.match(/<caption id="cap-\d+">/g) ?? []).length, tables, `${name}: captions`);
    let prev = 0;
    for (const m of h.matchAll(/<h([1-4])[ >]/g)) {
      assert.ok(Number(m[1]) <= prev + 1, `${name}: heading jump`);
      prev = Number(m[1]);
    }
    const css = styleOf(h);
    assert.ok(!/letter-spacing|uppercase|transition|animation|gradient|outline:\s*none|border-left-width/i.test(css), name);
  }
  assert.match(textOf(all['too large'] as string), /Report too large/);
  for (const c of Object.keys(CODE_HELP)) assert.ok((all['every CODE_HELP entry'] as string).includes(`<code>${c}</code>`), c);
});

test('5.12 render.ts and build.ts sources contain no en/em dash and no banned class names', () => {
  for (const f of ['render.ts', 'build.ts', 'types.ts']) {
    const src = readFileSync(new URL('../../src/report/' + f, import.meta.url), 'utf8');
    assert.ok(!DASH.test(src), f + ' has an en or em dash');
    assert.ok(!/class=["'][^"']*\b(?:card|tile|pill|badge|eyebrow)\b/i.test(src), f + ' banned class attribute');
    assert.ok(!/\.(?:card|tile|pill|badge|eyebrow)\b/i.test(src.replace(/\/\/.*$/gm, '')), f + ' banned selector');
  }
  for (const [k, v] of Object.entries(CODE_HELP)) assert.ok(!DASH.test(v) && v.length > 10, k);
});
