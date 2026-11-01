// Static report tests (REPORT-SPEC section 3 and v1.1 amendments). Real stores via the real guard/proxy;
// hostile rows only through the real store.append.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { openStore } from '../../src/store/index.ts';
import { cleanup } from '../support/tmp.ts';
import { KEY } from '../support/guard-kit.ts';
import {
  GEN_MS, freshStore, build, html, guardRun, monitorRun, proxyRun, policyOf, appendHostile, recount, markupOf, checkBalanced, HOSTILE,
} from '../support/report-kit.ts';
import type { Kit } from '../support/guard-kit.ts';

after(cleanup);

let fixture: Promise<Kit> | null = null;
function mixed(): Promise<Kit> {
  fixture ??= (async () => {
    const k = await guardRun();
    await monitorRun(k);
    return k;
  })();
  return fixture;
}
const textOf = (h: string): string => h.replace(/<style>[\s\S]*?<\/style>/, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');

test('A-08 empty store: empty states, zero values, verdict OK, no placeholders', () => {
  const { store } = freshStore();
  const h = html(store);
  const t = textOf(h);
  assert.match(t, /No events recorded yet\. Run your agent through the guard or proxy, then regenerate this report\./);
  assert.match(t, /No decisions recorded yet/);
  assert.match(t, /No policy activations recorded yet/);
  assert.match(t, /OK: chain verification passed/);
  assert.match(t, /the chain is empty/);
  assert.ok(!/NaN|undefined|null|Infinity|\[object/.test(t), 'no placeholder values');
  const d = build(store);
  assert.equal(d.metrics.events_total, 0);
  assert.equal(d.metrics.deny_rate, null);
  assert.equal(d.latency.n, 0);
  assert.match(t, /Deny rate no data/);
  assert.equal(checkBalanced(h), null);
  store.close();
});

test('A-08 after a real guard run the displayed totals equal an independent store query', async () => {
  const k = await mixed();
  const d = build(k.store);
  const r = recount(k.store);
  assert.equal(d.metrics.events_total, k.store.count());
  assert.equal(d.window.events_total, k.store.query({ limit: 10000 }).length);
  assert.equal(d.metrics.decisions_total, r.dec.length);
  assert.equal(d.metrics.denied, r.denied.length);
  assert.equal(d.metrics.would_be_denied, r.wouldBe.length);
  assert.equal(d.metrics.enforced_decisions, r.enforced.length);
  assert.equal(d.metrics.sessions, r.sessions);
  assert.equal(d.metrics.ephemeral_sessions, r.ephemeral);
  assert.equal(d.metrics.top_rules_excluded, r.ruleExcluded);
  assert.equal(d.metrics.tainted_decisions, r.tainted);
  assert.deepEqual(d.metrics.top_denied_tools.map((x) => [x.name, x.count]), r.topTools);
  assert.deepEqual(d.metrics.top_rules.map((x) => [x.name, x.count]), r.topRules);
  assert.equal(d.metrics.by_kind.reduce((a, x) => a + x.count, 0), k.store.count());
  const h = html(k.store);
  assert.ok(h.includes(`Events, newest first (${String(Math.min(200, k.store.count()))} of ${String(k.store.count())})`));
  const pctTxt = ((r.denied.length / r.enforced.length) * 100).toFixed(1);
  assert.ok(textOf(h).includes(`${String(r.denied.length)} of ${String(r.enforced.length)}, ${pctTxt}%`));
  assert.ok(r.denied.length > 0 && r.wouldBe.length > 0 && r.tainted > 0, 'fixture exercises denies, would-be denies and taint');
});

test('fixture proxy run: posture rows, counts and tool-result outcomes come from real rows', async () => {
  const { store } = await proxyRun();
  const d = build(store);
  const r = recount(store);
  assert.ok(d.posture_config !== null, 'proxy_config row');
  assert.ok(d.posture_config.fields.some((f) => f.key === 'policy_mode'));
  assert.ok(d.posture_client !== null, 'proxy_client row');
  assert.equal(d.metrics.decisions_total, r.dec.length);
  assert.ok(d.metrics.tool_results.ok >= 1);
  assert.ok(d.activations.some((a) => a.event === 'proxy_config'));
  assert.match(textOf(html(store)), /Proxy configuration/);
  store.close();
});

test('metrics: latency percentiles equal an independent nearest-rank on a fixture', () => {
  for (const n of [1, 7, 10, 100, 101]) {
    const { store } = freshStore();
    const vals: number[] = [];
    for (let i = 0; i < n; i++) {
      const v = ((i * 37) % 97) + 1;
      vals.push(v);
      store.append({ id: 'd' + String(i), kind: 'decision', ts_ms: 1000 + i, effect: 'permit', enforcement: 'enforced', reason_code: 'permitted', latency_us: v });
    }
    store.append({ id: 'nl', kind: 'decision', ts_ms: 5000, effect: 'permit', enforcement: 'enforced', reason_code: 'permitted', latency_us: null });
    const sorted = [...vals].sort((a, b) => a - b);
    const nr = (p: number): number => sorted[Math.ceil((p * n) / 100) - 1] as number;
    const l = build(store).latency;
    assert.equal(l.n, n);
    assert.deepEqual([l.p50, l.p95, l.p99, l.max], [nr(50), nr(95), nr(99), sorted[n - 1]]);
    store.close();
  }
  const { store } = freshStore();
  store.append({ id: 'neg', kind: 'decision', ts_ms: 1, effect: 'permit', enforcement: 'enforced', latency_us: -5 });
  assert.equal(build(store).latency.n, 0, 'negative latencies are not counted');
  assert.match(textOf(html(store)), /No data\. Latency is recorded/);
  assert.match(textOf(html(store)), /not end-to-end latency/);
  store.close();
});

test('4.16 deny rate is over enforced decisions; would-be denies are separate; no data at 0', () => {
  const { store } = freshStore();
  const ev = (id: string, effect: 'permit' | 'deny', enf: 'enforced' | 'monitor_only', tool: string, rules: string[], denyN = rules.length) =>
    store.append({ id, kind: 'decision', ts_ms: 10, effect, enforcement: enf, tool, rule_ids: rules, reason_code: effect === 'deny' ? 'denied_by_rule' : 'permitted', session_id: 's1', outcome: { deny_n: denyN } });
  ev('a', 'deny', 'enforced', 'zeta', ['r.b', 'r.a']);
  ev('b', 'deny', 'enforced', 'alpha', ['r.a', 'r.permit'], 1);
  ev('c', 'deny', 'enforced', '?', []);
  ev('d', 'permit', 'enforced', 'alpha', ['r.p']);
  ev('e', 'deny', 'monitor_only', 'alpha', ['r.m']);
  ev('f', 'permit', 'monitor_only', 'alpha', ['r.p']);
  store.append({ id: 'g', kind: 'decision', ts_ms: 10, effect: 'deny', enforcement: 'enforced', tool: 'beta', rule_ids: Array.from({ length: 20 }, (_, i) => 'x' + String(i)), outcome: { deny_n: 16 } });
  const m = build(store).metrics;
  assert.equal(m.enforced_decisions, 5);
  assert.equal(m.denied, 4);
  assert.equal(m.would_be_denied, 1);
  assert.equal(m.unknown_tool_names, 1);
  assert.deepEqual(m.top_denied_tools.map((x) => x.name), ['alpha', 'beta', 'zeta'], 'ties by name ascending');
  assert.ok(!m.top_rules.some((x) => x.name.startsWith('…+')), 'truncation marker excluded');
  assert.deepEqual(m.top_rules.slice(0, 2).map((x) => [x.name, x.count]), [['r.a', 2], ['r.b', 1]]);
  assert.ok(!m.top_rules.some((x) => x.name === 'r.m'), 'monitor_only rules are not in enforced-deny top rules');
  assert.ok(!m.top_rules.some((x) => x.name === 'r.permit'), 'permit ids are never counted');
  assert.equal(m.top_rules_excluded, 0);
  assert.equal(m.sessions, 1);
  assert.match(textOf(html(store)), /Deny rate \(enforced decisions\) 4 of 5, 80\.0%/);
  assert.match(textOf(html(store)), /unknown tool names \(hashed\)/);
  store.close();
  const e2 = freshStore();
  e2.store.append({ id: 'm', kind: 'decision', ts_ms: 1, effect: 'deny', enforcement: 'monitor_only', reason_code: 'default_deny' });
  assert.match(textOf(html(e2.store)), /Deny rate \(enforced decisions\) no data/);
  e2.store.close();
});

test('4.16 reason codes are shown raw, grouped; most-used version tie-breaks by version ascending', () => {
  const { store } = freshStore();
  const codes = ['permitted', 'denied_by_rule', 'default_deny', 'tainted_session', 'unknown_tool', 'invalid_args', 'limit_exceeded', 'engine_error', 'audit_unavailable'];
  codes.forEach((c, i) => store.append({ id: 'c' + String(i), kind: 'decision', ts_ms: 1, effect: i === 0 ? 'permit' : 'deny', enforcement: 'enforced', reason_code: c, policy_version: i % 2 === 0 ? 'vB' : 'vA' }));
  const d = build(store);
  const g = Object.fromEntries(d.metrics.reason_classes.map((r) => [r.code, r.group]));
  assert.deepEqual(g, {
    permitted: 'allowed', denied_by_rule: 'denied', default_deny: 'denied', tainted_session: 'denied', unknown_tool: 'unknown tool',
    invalid_args: 'invalid request', limit_exceeded: 'invalid request', engine_error: 'unavailable', audit_unavailable: 'unavailable',
  });
  assert.equal(d.top_policy_version, 'vB', 'vB has 5, vA has 4');
  const e = freshStore();
  e.store.append({ id: 'x1', kind: 'decision', ts_ms: 1, effect: 'permit', enforcement: 'enforced', policy_version: 'vB' });
  e.store.append({ id: 'x2', kind: 'decision', ts_ms: 1, effect: 'permit', enforcement: 'enforced', policy_version: 'vA' });
  assert.equal(build(e.store).top_policy_version, 'vA');
  store.close();
  e.store.close();
});

test('4.3 verdict wording derives from effect and enforcement; 4.22 anchors are d-<seq>', async () => {
  const k = await mixed();
  const d = build(k.store);
  const kinds = new Set(d.decisions.map((x) => `${String(x.effect)}/${String(x.enforcement)}`));
  assert.deepEqual([...kinds].sort(), ['deny/enforced', 'deny/monitor_only', 'permit/enforced', 'permit/monitor_only']);
  for (const x of d.decisions) {
    if (x.effect === 'deny' && x.enforcement === 'enforced') assert.match(x.verdict, /^BLOCKED/);
    if (x.effect === 'permit' && x.enforcement === 'enforced') assert.match(x.verdict, /^ALLOWED/);
    if (x.effect === 'deny' && x.enforcement === 'monitor_only') assert.match(x.verdict, /^WOULD BE BLOCKED \(monitor_only: the tool ran\)/);
    if (x.effect === 'permit' && x.enforcement === 'monitor_only') assert.match(x.verdict, /^ALLOWED \(monitor_only\)/);
    assert.equal(x.anchor, String(x.seq));
  }
  const h = html(k.store);
  const ids = new Set([...h.matchAll(/ id="(d-\d+)"/g)].map((m) => m[1]));
  const links = [...h.matchAll(/href="#(d-\d+)"/g)].map((m) => m[1] as string);
  assert.ok(ids.size === d.decisions.length && links.length > 0);
  for (const l of links) assert.ok(ids.has(l), 'every link has a target: ' + l);
  assert.ok(d.decisions.some((x) => x.results.length > 0), 'linked results shown');
  assert.ok(d.decisions.some((x) => x.session_tainted === true));
  assert.ok(d.metrics.tool_results.error >= 1, 'tool error counted');
});

test('rule detail only when versions match (no detail from another version)', async () => {
  const k = await mixed();
  const enforce = build(k.store, { policy: k.policy });
  const matched = enforce.decisions.filter((x) => x.rule_detail === 'shown');
  const mismatched = enforce.decisions.filter((x) => x.rule_detail === 'version_mismatch');
  assert.ok(matched.length > 0 && mismatched.length > 0, 'two policy versions in one store');
  const withRules = matched.find((x) => x.rules.some((r) => r.summary.length > 0));
  assert.ok(withRules !== undefined);
  assert.ok(withRules.rules.some((r) => r.summary.some((s) => s.startsWith('tool is one of'))));
  const secret = matched.find((x) => x.rule_ids.includes('d.secret'));
  assert.ok(secret && secret.rules[0]?.summary.some((s) => s.includes('matches the glob')));
  for (const x of mismatched) assert.deepEqual(x.rules, []);
  const h = html(k.store, { policy: k.policy });
  assert.match(textOf(h), /Policy version differs; rule detail not shown/);
  assert.match(textOf(html(k.store)), /No policy supplied, so rule detail is not shown/);
});

test('XSS and hostile strings appear only as escaped text (markup checked, not text)', () => {
  const { store } = freshStore();
  appendHostile(store, 3);
  const h = html(store, { title: '<script>alert(2)</script>', dbName: 'C:\\x\\<img onerror=1>.db' });
  const mk = markupOf(h);
  assert.ok(!/<script/i.test(h), 'no raw <script anywhere');
  assert.ok(!/onerror\s*=/i.test(mk), 'no onerror attribute in markup');
  assert.ok(!/javascript:/i.test(mk));
  assert.ok(!/<img/i.test(h));
  assert.ok(!/https?:\/\//i.test(mk));
  assert.equal(checkBalanced(h), null);
  for (const raw of [HOSTILE.ls, HOSTILE.ansi, HOSTILE.rtl, HOSTILE.nul]) assert.ok(!h.includes(raw), 'raw control string absent');
  assert.ok(!/\p{Cc}/u.test(h.replace(/[\n\r\t]/g, '')), 'no control characters in output');
  assert.ok(!/[\u2028\u2029\u0085\u202e]/.test(h));
  assert.ok(h.includes('\\u2028') && h.includes('\\u001b') && h.includes('\\u202e') && h.includes('\\u0085'));
  assert.ok(h.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(h.includes('&quot;&gt;&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(h.includes('&lt;script&gt;alert(2)&lt;/script&gt;'), 'title escaped');
  assert.ok(!h.includes('C:\\x'), 'db name reduced to the basename');
  assert.ok(h.includes('&lt;img onerror=1&gt;.db'));
  assert.ok(h.includes('&lt;script&gt;x&lt;/script&gt;'), 'clientInfo name escaped in posture');
  assert.equal((h.match(/<h1[ >]/g) ?? []).length, 1);
  store.close();
});

test('document skeleton, CSP, landmarks, captions, scroll regions (4.14, 4.21, 3)', async () => {
  const k = await mixed();
  const h = html(k.store, { policy: k.policy });
  assert.ok(h.startsWith('<!doctype html><!-- prysm-report v1 --><html lang="en"><head><meta charset="utf-8">'));
  assert.ok(Buffer.from(h).subarray(0, 200).toString().includes('<!-- prysm-report v1 -->'));
  assert.notEqual(h.charCodeAt(0), 0xfeff);
  assert.ok(h.includes('<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; img-src data:; base-uri &#39;none&#39;; form-action &#39;none&#39;">'));
  assert.ok(h.includes('<meta name="viewport" content="width=device-width, initial-scale=1">'));
  assert.match(h, /<title>[^<]+<\/title>/);
  assert.equal((h.match(/<h1[ >]/g) ?? []).length, 1);
  for (const tag of ['header', 'main', 'footer', 'nav']) assert.ok(h.includes('<' + tag), tag);
  assert.ok(!/<script|<iframe|<link|<img|<form|\son[a-z]+\s*=|innerHTML/i.test(markupOf(h)));
  assert.ok(!/https?:\/\//i.test(markupOf(h)));
  const tables = h.match(/<table>/g)?.length ?? 0;
  assert.ok(tables > 8);
  assert.equal((h.match(/<caption id="cap-\d+">/g) ?? []).length, tables, 'every table has a caption');
  const regions = [...h.matchAll(/<div class="scroll[^"]*" tabindex="0" role="region" aria-labelledby="(cap-\d+)">/g)].map((m) => m[1]);
  assert.equal(regions.length, tables);
  for (const id of regions) assert.ok(h.includes(` id="${id as string}">`));
  assert.equal(new Set(regions).size, regions.length, 'caption ids are unique');
  assert.ok(!/<th>/.test(h) && /<th scope="col"/.test(h) && /<th scope="row"/.test(h));
  assert.equal(checkBalanced(h), null);
  // heading levels never skip downwards
  let prev = 0;
  for (const m of h.matchAll(/<h([1-4])[ >]/g)) {
    const lvl = Number(m[1]);
    assert.ok(lvl <= prev + 1, `heading jump to h${String(lvl)} after h${String(prev)}`);
    prev = lvl;
  }
});

test('determinism: identical data and generatedMs give byte-identical output; generated time and head stated (4.24)', async () => {
  const k = await mixed();
  const a = html(k.store, { policy: k.policy });
  const b = html(k.store, { policy: k.policy });
  assert.equal(a, b);
  const d = build(k.store);
  assert.ok(a.includes(new Date(GEN_MS).toISOString()));
  assert.ok(a.includes(`<time datetime="${new Date(GEN_MS).toISOString()}" data-ms="${String(GEN_MS)}">`));
  assert.ok(!textOf(a).includes('generated_ms'), 'no raw generated_ms in visible text');
  assert.ok(a.includes(`up to seq ${String(d.head?.seq)}`));
  assert.ok(a.includes(`<code class="hash" title="${d.head?.hash as string}">${d.head?.hash as string}</code>`));
  assert.notEqual(html(k.store, { generatedMs: GEN_MS + 1000 }), a);
});

test('4.20 head, genesis, anchor and checkpoint hashes are printed in full', async () => {
  const k = await mixed();
  const anchor = k.store.anchor();
  const h = html(k.store, { anchor });
  for (const x of [anchor.head_hash, anchor.genesis_hash]) {
    assert.ok(h.includes(`<code class="hash" title="${x}">${x}</code>`), x);
  }
  assert.ok(!/<code class="hash"[^>]*>[0-9a-f]{12}…/.test(h));
  const e = freshStore();
  for (let i = 0; i < 3; i++) e.store.append({ id: 'o' + String(i), kind: 'decision', ts_ms: 1000 + i, effect: 'permit', enforcement: 'enforced' });
  const pr = e.store.checkpointAndPrune(1002, { force: true });
  const hh = html(e.store, { expectPruned: { through_seq: pr.through_seq, last_hash: pr.last_hash } });
  assert.ok(hh.includes(`<code class="hash" title="${pr.last_hash}">${pr.last_hash}</code>`));
  assert.match(textOf(hh), /OK: chain verification passed/);
  assert.match(textOf(html(e.store)), /FAILED: chain verification found/, 'pruning without an expected checkpoint fails');
  assert.match(textOf(html(e.store, { allowPruned: true })), /development only/);
  e.store.close();
});

test('tampered DB: the report shows FAILED with the error codes', async () => {
  const { store, path } = freshStore();
  for (let i = 0; i < 4; i++) store.append({ id: 't' + String(i), kind: 'decision', ts_ms: 1000 + i, effect: 'permit', enforcement: 'enforced', tool: 'echo' });
  assert.match(textOf(html(store)), /OK: chain verification passed/);
  const raw = new DatabaseSync(path);
  raw.exec('DROP TRIGGER events_no_update');
  raw.exec("UPDATE events SET tool='evil' WHERE seq=2");
  raw.close();
  const h = html(store);
  assert.match(textOf(h), /FAILED: chain verification found \d+ errors?/);
  assert.ok(h.includes('<code>hash_mismatch</code> at seq 2'));
  assert.ok(h.includes('role="alert"'));
  assert.match(textOf(h), /prysm verify-chain/);
  assert.equal(build(store).verify.ok, false);
  store.close();
});

test('anchor supplied vs not: notice text; a truncated tail is detected only with the anchor', () => {
  const { store, path } = freshStore();
  for (let i = 0; i < 5; i++) store.append({ id: 'n' + String(i), kind: 'decision', ts_ms: 1000 + i, effect: 'permit', enforcement: 'enforced' });
  const anchor = store.anchor();
  const notice = 'tail truncation and full rewrites are not detectable without an external anchor';
  assert.ok(textOf(html(store)).includes(notice));
  const withAnchor = textOf(html(store, { anchor }));
  assert.ok(!withAnchor.includes(notice));
  assert.match(withAnchor, /An external anchor was supplied and checked/);
  const raw = new DatabaseSync(path);
  raw.exec('DROP TRIGGER events_no_delete');
  raw.exec('DELETE FROM events WHERE seq > 3');
  raw.close();
  assert.match(textOf(html(store)), /OK: chain verification passed/, 'truncation invisible without an anchor');
  const failed = html(store, { anchor });
  assert.match(textOf(failed), /FAILED/);
  assert.ok(failed.includes('<code>anchor_mismatch</code>'));
  store.close();
});

test('4.17 scan limit: metrics cover the newest N of M rows and say so', () => {
  const { store } = freshStore();
  for (let i = 0; i < 12; i++) store.append({ id: 's' + String(i), kind: 'decision', ts_ms: 1000 + i, effect: 'permit', enforcement: 'enforced' });
  const d = build(store, { scanLimit: 5 });
  assert.deepEqual(d.scan, { scanned: 5, total: 12, truncated: true });
  assert.equal(d.metrics.decisions_total, 5);
  assert.match(textOf(html(store, { scanLimit: 5 })), /Metrics cover the newest 5 of 12 rows/);
  assert.ok(!/Metrics cover the newest/.test(textOf(html(store))));
  assert.equal(build(store).metrics.decisions_total, 12);
  store.close();
});

test('4.18 activations section shows the newest 200 and "showing N of M"', () => {
  const { store } = freshStore();
  for (let i = 0; i < 250; i++) {
    store.append({ id: 'p' + String(i), kind: 'policy_activate', ts_ms: 1000 + i, policy_version: 'v' + String(i), outcome: { policy_version: 'v' + String(i), mode: 'enforce', rule_count: i } });
  }
  const d = build(store);
  assert.equal(d.activations.length, 200);
  assert.equal(d.activations_total, 250);
  assert.equal(d.activations[0]?.rule_count, 50);
  assert.match(textOf(html(store)), /showing 200 of 250/);
  store.close();
});

test('4.18 oversized output halves the windows deterministically and stays under 8 MiB', () => {
  const dir = freshStore();
  dir.store.close();
  const store = openStore({ path: dir.path.replace('audit.db', 'big.db'), hmacKey: KEY, synchronous: 'NORMAL' });
  const rules = Array.from({ length: 16 }, (_, i) => 'r' + String(i) + '.' + 'x'.repeat(240));
  for (let i = 0; i < 5000; i++) {
    store.append({ id: 'b' + String(i), kind: 'decision', ts_ms: 1000 + i, tool: 'echo', effect: 'deny', enforcement: 'enforced', reason_code: 'denied_by_rule', rule_ids: rules, policy_version: 'v' + 'y'.repeat(200), session_id: 's' + String(i) });
  }
  const d = build(store, { maxEvents: 5000 });
  const h1 = html(store, { maxEvents: 5000 });
  assert.ok(Buffer.byteLength(h1) <= 8 * 1024 * 1024);
  assert.ok(d.window.shrunk && d.window.effective < 5000 && d.window.effective > 0, 'window ' + String(d.window.effective));
  assert.equal(d.window.requested, 5000);
  assert.equal(d.window.effective, [2500, 1250, 625, 312, 156, 78, 39, 19, 9, 4, 2, 1, 0].find((x) => x === d.window.effective));
  assert.match(textOf(h1), /The window was reduced automatically from 5000 to \d+ rows/);
  assert.equal(h1, html(store, { maxEvents: 5000 }), 'deterministic');
  assert.equal(d.metrics.decisions_total, 5000, 'metrics still cover everything');
  store.close();
});

test('5000-row window on ordinary rows stays within the size cap', () => {
  const store = openStore({ path: freshStore().path.replace('audit.db', 'w.db'), hmacKey: KEY, synchronous: 'NORMAL' });
  for (let i = 0; i < 5200; i++) {
    store.append({ id: 'w' + String(i), kind: i % 3 === 0 ? 'tool_result' : 'decision', ts_ms: 1000 + i, tool: 'read_file', effect: i % 3 === 0 ? null : 'permit', enforcement: i % 3 === 0 ? null : 'enforced', decision_id: i % 3 === 0 ? 'w' + String(i - 1) : null, outcome: i % 3 === 0 ? { status: 'ok', result_type: 'string', result_len: 4 } : null, latency_us: 10 });
  }
  const h = html(store, { maxEvents: 5000 });
  assert.ok(Buffer.byteLength(h) <= 8 * 1024 * 1024);
  const d = build(store, { maxEvents: 5000 });
  assert.equal(d.events.length, d.window.effective);
  assert.ok(d.decisions.length > 0 && d.decisions.length <= 5000);
  assert.equal(d.window.events_total, 5200);
  store.close();
});

test('4.23 read-only store: key protection reads "unknown (read-only report)"; nothing is written', async () => {
  const k = await mixed();
  const before = { n: k.store.count(), head: k.store.head() };
  const ro = openStore({ path: k.path, readOnly: true });
  const h = html(ro);
  assert.ok(textOf(h).includes('unknown (read-only report)'));
  assert.equal(ro.count(), before.n);
  assert.deepEqual(ro.head(), before.head);
  assert.ok(!existsSync(k.path + '.key'), 'no key file created');
  ro.close();
  assert.match(textOf(html(k.store)), /Key protection external/);
});

test('empty and error states are actionable (policy absent, no proxy rows, read error free)', () => {
  const { store } = freshStore();
  store.append({ id: 'only', kind: 'decision', ts_ms: 1, effect: 'permit', enforcement: 'enforced', tool: 'x', reason_code: 'permitted', latency_us: 3 });
  const t = textOf(html(store));
  assert.match(t, /No proxy_config row\. This store was not written by the proxy/);
  assert.match(t, /No linked tool_result row/);
  assert.match(t, /Fail-open fail-open events are not stored: see stderr/);
  assert.match(t, /Argument values are never stored/);
  assert.match(t, /False-positive and false-negative rates are not available from the store/);
  store.close();
});

test('policy_activate summary: events, versions and the most-used version are textual', async () => {
  const k = await mixed();
  const d = build(k.store);
  assert.ok(d.activations.length >= 2);
  assert.ok(d.activations.every((a) => a.event === 'activation'));
  assert.ok(d.top_policy_version !== null);
  assert.ok(textOf(html(k.store)).includes('Most-used policy version, by decisions'));
});

test('policy used for rule detail is exercised with real policy objects', () => {
  assert.equal(policyOf('enforce').mode, 'enforce');
  assert.notEqual(policyOf('enforce').policy_version, policyOf('monitor_only').policy_version);
});
