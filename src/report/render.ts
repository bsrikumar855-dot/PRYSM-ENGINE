// Static report renderer (REPORT-SPEC section 2). Pure: same data in, same bytes out. No clock, no I/O, no script.
// SECURITY RULE: every value that comes from the store goes through esc() before it reaches HTML. Template
// interpolations may only be esc(...), opt(...), num(...), pct(...), or an identifier ending in "Html" (an
// already escaped fragment). test/report/report-source.test.ts enforces this on this file.
//
// Design read: audit report for AI-agent developers and security engineers, calm technical-document language.
// Dials: variance 2 (symmetric), motion 1 (none), density 7 (dense tables, plain layout, no cards).
import type {
  ActivationView, CountRow, DecisionView, EventView, PostureView, ReasonRow, ReportData, RuleDetail,
} from './types.ts';

const ESC_RE = /[&<>"'\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/gu;

const BS = String.fromCharCode(92);

/** The single escaper: HTML metacharacters become entities; control, bidi, line-separator and lone-surrogate
 *  characters become visible \uXXXX text. */
export function esc(v: unknown): string {
  const s = typeof v === 'string' ? v : v === null || v === undefined ? '' : String(v);
  return s.replace(ESC_RE, (c) => {
    switch (c) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      case "'": return '&#39;';
      default: {
        const cp = c.codePointAt(0) as number;
        return cp > 0xffff ? BS + 'u{' + cp.toString(16) + '}' : BS + 'u' + cp.toString(16).padStart(4, '0');
      }
    }
  });
}

/** Escaped optional text; an absent or empty value is written as the word none (never a blank cell or a dash). */
export function opt(v: string | null | undefined): string {
  return esc(v === null || v === undefined || v === '' ? 'none' : v);
}

/** Integer formatting for counts (never NaN/Infinity). */
export function num(n: number | null | undefined): string {
  return typeof n === 'number' && Number.isFinite(n) ? String(Math.trunc(n)) : '0';
}

function pct(x: number | null): string {
  return x === null || !Number.isFinite(x) ? 'no data' : (x * 100).toFixed(1) + '%';
}

function iso(ms: number): string {
  try { return new Date(ms).toISOString(); } catch { return 'invalid time'; }
}

function abbrev(s: string | null, n = 8): string {
  if (s === null) return '';
  const pts = Array.from(s);
  return pts.length <= n ? s : pts.slice(0, n).join('') + '…';
}

const nbHtml = String.fromCharCode(160);

// Tokens: bg, surface, ink, muted, rule, accent (one accent for links, focus ring and anchors, cool neutrals only),
// plus an ok and a bad pair used only by the integrity verdict banner. One radius (4px). No motion exists on this
// page, so prefers-reduced-motion needs no handling: there are no animations or transitions at all.
const CSS = `
/* Contrast pairing: --fg-text, --fg-muted and --fg-accent appear on --bg-page and --bg-surface. --fg-ok appears only on --bg-ok. --fg-bad appears only on --bg-bad. */
:root{color-scheme:light dark;--gutter:16px;--r:4px;
--font:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
--bg-page:#f1f3f6;--bg-surface:#f8f9fb;--fg-text:#1c2128;--fg-muted:#4b5563;--rule:#c8cfd8;--fg-accent:#1d5bb8;
--fg-ok:#0e5a2b;--bg-ok:#e3f1e7;--fg-bad:#8b1a1a;--bg-bad:#f8e6e6}
@media (prefers-color-scheme:dark){:root{--bg-page:#12161c;--bg-surface:#181d24;--fg-text:#e3e7ec;--fg-muted:#a3adb9;--rule:#323c48;--fg-accent:#8db4f2;
--fg-ok:#93d9a8;--bg-ok:#14301f;--fg-bad:#ffb3b3;--bg-bad:#3b1818}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
[id]{scroll-margin-top:16px}
body{margin:0;background:var(--bg-page);color:var(--fg-text);font:16px/1.6 var(--font);overflow-wrap:anywhere}
.wrap{max-width:72rem;margin:0 auto;padding:0 var(--gutter)}
a{color:var(--fg-accent);text-underline-offset:3px}
a:focus-visible,.scroll:focus-visible{outline:3px solid var(--fg-accent);outline-offset:2px;border-radius:var(--r)}
.skip{position:absolute;left:var(--gutter);top:-100px;background:var(--bg-surface);color:var(--fg-text);padding:8px 12px;border:2px solid var(--fg-accent);border-radius:var(--r)}
.skip:focus{top:8px}
header.top{padding-top:20px}
h1{font-size:1.6rem;line-height:1.25;margin:0 0 4px;text-wrap:balance}
h2{font-size:1.25rem;line-height:1.3;margin:0 0 8px;text-wrap:balance}
h3{font-size:1.05rem;line-height:1.3;margin:0 0 6px;text-wrap:balance}
h4{font-size:1rem;margin:12px 0 4px}
section{margin:36px 0}
p,ul.plain,dl.legend{max-width:70ch}
p{margin:6px 0}
.meta,.muted{color:var(--fg-muted)}
code,.mono{font-family:var(--mono);font-size:.9em;overflow-wrap:anywhere}
.h-full{display:none}
code.hash{display:inline-block;max-width:100%;overflow-wrap:anywhere;word-break:break-all}
.verdict{margin:16px 0 8px;padding:12px 16px;border:2px solid var(--fg-text);border-radius:var(--r)}
.verdict p{max-width:75ch}
.verdict .head{font-size:1.4rem;line-height:1.3;font-weight:700;margin:0 0 4px}
.verdict.ok{color:var(--fg-ok);background:var(--bg-ok);border-color:var(--fg-ok)}
.verdict.bad{color:var(--fg-bad);background:var(--bg-bad);border-color:var(--fg-bad);border-left-width:14px}
nav.toc ul{list-style:none;margin:12px 0 0;padding:0;display:flex;flex-wrap:wrap;gap:0 20px}
nav.toc a{display:inline-block;padding:2px 0;min-height:28px;line-height:24px}
dl.summary{display:flex;flex-wrap:wrap;gap:8px 32px;margin:16px 0 0}
dl.summary div{min-width:0}
dl.summary dt{color:var(--fg-muted);font-size:.9rem}
dl.summary dd{margin:0;font-family:var(--mono);font-size:1.3rem;font-variant-numeric:tabular-nums}
.empty{color:var(--fg-muted);margin:6px 0}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr));gap:20px;align-items:start;margin-top:12px}
.scroll{overflow:auto;max-width:100%;border:1px solid var(--rule);border-radius:var(--r);background:var(--bg-surface);margin:8px 0}
.scroll.tall{max-height:70vh}
table{border-collapse:separate;border-spacing:0;width:100%;font-size:.9375rem;line-height:1.45;font-variant-numeric:tabular-nums}
caption{text-align:left;font-weight:600;padding:8px 10px}
th,td{padding:6px 10px;text-align:left;vertical-align:top;border-bottom:1px solid var(--rule)}
tbody tr:last-child>*{border-bottom:0}
thead th{position:sticky;top:0;background:var(--bg-surface);border-bottom:2px solid var(--rule);white-space:nowrap}
tbody th{font-weight:500}
td.n,th.n{text-align:right;font-family:var(--mono);white-space:nowrap}
td.nw{white-space:nowrap}
td a{display:inline-block;padding:3px 0;min-height:24px;line-height:18px}
dl.facts{display:grid;grid-template-columns:minmax(140px,max-content) 1fr;gap:4px 16px;margin:10px 0;max-width:72rem}
dl.facts dt{color:var(--fg-muted)}
dl.facts dd{margin:0;min-width:0}
article.detail{padding:12px 0 16px;border-bottom:1px solid var(--rule)}
article.detail:target{outline:3px solid var(--fg-accent);outline-offset:4px;border-radius:var(--r)}
article.detail ul{margin:4px 0;padding-left:20px}
.verdict-line{font-weight:600;margin:4px 0 8px}
dl.legend{margin:10px 0}
dl.legend dt{font-weight:600;margin-top:6px}
dl.legend dd{margin:0}
ul.plain{margin:6px 0;padding-left:20px}
footer{padding:8px 0 32px;color:var(--fg-muted)}
@media (max-width:480px){dl.facts{grid-template-columns:1fr;gap:0}dl.facts dd{margin-bottom:8px}h1{font-size:1.35rem}td a{padding:11px 0}nav.toc a{padding:10px 0}}
@media print{:root{--bg-page:#f8f9fb;--bg-surface:#f8f9fb;--fg-text:#1c2128;--fg-muted:#4b5563;--rule:#c8cfd8;--fg-accent:#1d5bb8;--fg-ok:#0e5a2b;--bg-ok:#e3f1e7;--fg-bad:#8b1a1a;--bg-bad:#f8e6e6}
.scroll,.scroll.tall{overflow:visible;max-height:none}thead th{position:static}.skip,nav.toc{display:none}
.h-short{display:none}.h-full{display:inline}article.detail{break-inside:avoid}table{font-size:.8rem}}
`;

const CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'";

const CODE_HELP: Record<string, string> = {
  hash_mismatch: 'row content does not match its stored hash (the row was modified)',
  prev_mismatch: 'row does not link to the previous row (rows removed, reordered or replaced)',
  seq_gap: 'a sequence number is missing (rows were removed)',
  bad_genesis: 'the chain does not start from this store’s genesis',
  unexpected_first_row: 'the first retained row is not explained by a valid checkpoint',
  history_pruned: 'history was pruned (a checkpoint row is present)',
  checkpoint_missing: 'an expected checkpoint is absent or malformed',
  anchor_mismatch: 'the store does not match the supplied external anchor',
  anchor_pruned: 'the anchored row was pruned; only a later checkpoint covers it',
  schema_version: 'the stored schema version is not the one this build expects',
  outcome_unknown: 'a permitted call has no recorded result (crash, timeout or dropped row)',
  orphan_result: 'a result row refers to a decision that is not in the store',
  duplicate_result: 'a decision has more than one result row',
  key_unprotected: 'the HMAC key file is not restricted to the current user',
  key_colocated: 'the key file sits in the same directory as the database',
  prune_flag_reset: 'a previous prune did not finish cleanly',
  verify_unavailable: 'verification could not run because the store was unreadable',
};

const KEY_HELP: Record<string, string> = {
  acl: 'key file restricted to the current user (Windows ACL)',
  mode_0600: 'key file restricted to the current user (file mode)',
  external: 'key supplied externally, no key file',
  unprotected: 'key file is readable by other users',
};

function emptyP(text: string): string {
  return `<p class="empty">${esc(text)}</p>`;
}

let tableSeq = 0;

function scrollTable(caption: string, headers: { label: string; cls?: string }[], rowsHtml: string, tall = false): string {
  const headHtml = headers.map((h) => `<th scope="col"${h.cls ? ` class="${esc(h.cls)}"` : ''}>${esc(h.label)}</th>`).join('');
  const cid = 'cap-' + String(++tableSeq);
  return `<div class="scroll${tall ? ' tall' : ''}" tabindex="0" role="region" aria-labelledby="${esc(cid)}">` +
    `<table><caption id="${esc(cid)}">${esc(caption)}</caption><thead><tr>${headHtml}</tr></thead><tbody>${rowsHtml}</tbody></table></div>`;
}

function countTable(caption: string, nameHeader: string, rows: CountRow[], total: number | null): string {
  if (rows.length === 0) return `<div><h3>${esc(caption)}</h3>${emptyP('None recorded.')}</div>`;
  const heads = [{ label: nameHeader }, { label: 'Count', cls: 'n' }];
  if (total !== null) heads.push({ label: 'Share', cls: 'n' });
  const rowsHtml = rows.map((r) => {
    const shareHtml = total !== null ? `<td class="n">${esc(pct(total > 0 ? r.count / total : null))}</td>` : '';
    return `<tr><th scope="row">${opt(r.name)}</th><td class="n">${num(r.count)}</td>${shareHtml}</tr>`;
  }).join('');
  return scrollTable(caption, heads, rowsHtml);
}

function dlItem(label: string, valueHtml: string): string {
  return `<dt>${esc(label)}</dt><dd>${valueHtml}</dd>`;
}

/** Full hash, always visible, wrapping; the title attribute is supplementary. */
function fullHtml(h: string | null): string {
  if (h === null || h === '') return 'none';
  return `<code class="hash" title="${esc(h)}">${esc(h)}</code>`;
}

/** Short form on screen, full value in print (the full form is hidden by CSS on screen). */
function hashHtml(h: string | null, n = 12): string {
  if (h === null || h === '') return 'none';
  return `<code class="h-short" title="${esc(h)}">${esc(abbrev(h, n))}</code><code class="h-full">${esc(h)}</code>`;
}

function postureHtml(title: string, p: PostureView | null, absent: string): string {
  if (p === null) return `<div><h3>${esc(title)}</h3>${emptyP(absent)}</div>`;
  const itemsHtml = p.fields.map((f) => dlItem(f.key, `<code>${opt(f.value)}</code>`)).join('');
  return `<div><h3>${esc(title)}</h3><p class="muted">Row ${num(p.seq)}, written ${esc(iso(p.ts_ms))}.</p><dl class="facts">${itemsHtml}</dl></div>`;
}

function banner(d: ReportData): string {
  const v = d.verify;
  if (v.ok) {
    const anchorHtml = d.anchor_supplied ? '' : '<p>No external anchor was supplied. See “Integrity and posture” for what that means.</p>';
    const rowWordHtml = v.count === 1 ? 'row' : 'rows';
    const emptyHtml = v.count === 0 ? ' (the chain is empty)' : '';
    return `<div class="verdict ok" role="status"><p class="head">OK: chain verification passed</p>` +
      `<p>${num(v.count)} ${rowWordHtml} checked${emptyHtml}, no errors.</p>${anchorHtml}</div>`;
  }
  const seen = new Set<string>();
  const codesHtml = v.errors.filter((e) => (seen.has(e.code) ? false : (seen.add(e.code), true))).slice(0, 8)
    .map((e) => `<code>${esc(e.code)}</code> at seq ${num(e.seq)}`).join(', ');
  const n = v.errors.length;
  const errWordHtml = n === 1 ? 'error' : 'errors';
  return `<div class="verdict bad" role="alert"><p class="head">FAILED: chain verification found ${num(n)} ${errWordHtml}</p>` +
    '<p>The audit log was modified after it was written, or the chain is incomplete. Compare against a stored anchor with <code>prysm verify-chain</code>.</p>' +
    `<p>Error codes: ${codesHtml}.</p></div>`;
}

function hashTable(caption: string, headers: { label: string; cls?: string }[], list: { a: number; b: number | null; hash: string }[]): string {
  const rowsHtml = list.map((x) => `<tr><td class="n">${num(x.a)}</td>${x.b === null ? '' : `<td class="n">${num(x.b)}</td>`}<td>${fullHtml(x.hash)}</td></tr>`).join('');
  return scrollTable(caption, headers, rowsHtml);
}

function renderIntegrity(d: ReportData): string {
  const v = d.verify;
  const issueRows = (list: { seq: number; code: string }[], label: string): string =>
    list.map((i) => `<tr><td class="nw">${esc(label)}</td><td class="n">${num(i.seq)}</td><td><code>${esc(i.code)}</code></td><td>${opt(CODE_HELP[i.code] ?? 'no description available')}</td></tr>`).join('');
  let issuesHtml: string;
  if (v.errors.length > 0 || v.warnings.length > 0) {
    issuesHtml = scrollTable('Verification errors and warnings', [{ label: 'Level' }, { label: 'Seq', cls: 'n' }, { label: 'Code' }, { label: 'Meaning' }],
      issueRows(v.errors, 'error') + issueRows(v.warnings, 'warning'));
  } else {
    issuesHtml = emptyP('No errors and no warnings.');
  }
  const anchorHtml = d.anchor_supplied
    ? '<p>An external anchor was supplied and checked as part of this verification.</p>'
    : '<p><strong>Notice:</strong> no anchor was supplied, so tail truncation and full rewrites are not detectable without an external anchor. Without one, the hash chain only detects edits and removals in the middle of the log. Create an anchor with <code>prysm anchor</code> and store it where an attacker with database access cannot rewrite it.</p>';
  const expectHtml = d.expected_pruned_supplied ? '<p>Expected pruning checkpoints were supplied and checked.</p>' : '';
  const allowHtml = d.allow_pruned
    ? '<p><strong>Warning:</strong> pruned history was accepted without an external record. This option is for development only.</p>'
    : '';
  const unavailHtml = v.unavailable
    ? '<p><strong>Verification could not run</strong> because the store could not be read. Check the database path and permissions, then regenerate this report.</p>'
    : '';
  const readErrHtml = d.read_error !== null
    ? `<p><strong>Some rows could not be decoded</strong> (code ${esc(d.read_error)}). Metrics and tables below are incomplete. Run <code>prysm verify-chain</code> to locate damaged rows.</p>`
    : '';
  const kp = d.key_protection === null || d.key_protection === 'unknown' ? null : d.key_protection;
  const keyHelp = kp === null ? undefined : KEY_HELP[kp];
  const warnHtml = kp === 'unprotected' ? '<strong>Warning:</strong> ' : '';
  const keyHtml = kp === null
    ? 'unknown (read-only report)'
    : `${warnHtml}${esc(kp)}${keyHelp ? ', ' + esc(keyHelp) : ''}`;
  const policyHtml = d.policy === null
    ? 'none supplied, so rule detail is not shown'
    : `${esc(d.policy.name)}, version ${hashHtml(d.policy.policy_version)}, mode ${esc(d.policy.mode)}, ${num(d.policy.rule_count)} rules`;
  const anchorInfoHtml = d.anchor_info === null ? 'none supplied' : `head seq ${num(d.anchor_info.head_seq)}, head hash ${fullHtml(d.anchor_info.head_hash)}, genesis ${fullHtml(d.anchor_info.genesis_hash)}`;
  const factsHtml = [
    dlItem('Verdict', v.ok ? '<strong>OK</strong>' : '<strong>FAILED</strong>'),
    dlItem('Rows in store', num(d.scan.total)),
    dlItem('Rows verified', num(v.count)),
    dlItem('Head', d.head === null ? 'empty chain' : `seq ${num(d.head.seq)}, ${fullHtml(d.head.hash)}`),
    dlItem('Genesis hash', fullHtml(d.genesis_hash)),
    dlItem('Anchor supplied', anchorInfoHtml),
    dlItem('Pruned through', v.pruned_through === null ? 'nothing pruned' : `seq ${num(v.pruned_through)}`),
    dlItem('Schema version', esc(d.schema_version)),
    dlItem('Key protection', keyHtml),
    dlItem('Policy for rule detail', policyHtml),
  ].join('');
  const cpHtml = d.checkpoints.length === 0 ? '' : hashTable('Retained checkpoint rows',
    [{ label: 'Row seq', cls: 'n' }, { label: 'Pruned through seq', cls: 'n' }, { label: 'Last pruned hash' }],
    d.checkpoints.map((c) => ({ a: c.seq, b: c.through_seq, hash: c.last_hash })));
  const expHtml = d.expected_pruned.length === 0 ? '' : hashTable('Expected checkpoints supplied',
    [{ label: 'Pruned through seq', cls: 'n' }, { label: 'Last pruned hash' }],
    d.expected_pruned.map((c) => ({ a: c.through_seq, b: null, hash: c.last_hash })));
  return `<section id="integrity" aria-labelledby="h-integrity"><h2 id="h-integrity">Integrity and posture</h2>${anchorHtml}${expectHtml}${allowHtml}${unavailHtml}${readErrHtml}` +
    `<dl class="facts">${factsHtml}</dl>${issuesHtml}${cpHtml}${expHtml}` +
    `<div class="grid2">${postureHtml('Proxy configuration (newest proxy_config row)', d.posture_config, 'No proxy_config row. This store was not written by the proxy, or no proxy has started against it yet.')}` +
    `${postureHtml('Proxy client (newest proxy_client row)', d.posture_client, 'No proxy_client row recorded. No client has connected through the proxy yet.')}</div></section>`;
}

function reasonTable(rows: ReasonRow[], total: number): string {
  if (rows.length === 0) return `<div><h3>Decisions by reason</h3>${emptyP('None recorded.')}</div>`;
  const rowsHtml = rows.map((r) =>
    `<tr><th scope="row">${esc(r.group)}</th><td><code>${opt(r.code)}</code></td><td class="n">${num(r.count)}</td><td class="n">${esc(pct(total > 0 ? r.count / total : null))}</td></tr>`).join('');
  return scrollTable('Decisions by reason (stored code, grouped)', [{ label: 'Group' }, { label: 'Reason code' }, { label: 'Count', cls: 'n' }, { label: 'Share', cls: 'n' }], rowsHtml);
}

function rate(num_: number, den: number): string {
  return den === 0 ? 'no data' : `${String(Math.trunc(num_))} of ${String(Math.trunc(den))}, ${((num_ / den) * 100).toFixed(1)}%`;
}

function renderOverview(d: ReportData): string {
  const m = d.metrics;
  const coverHtml = d.scan.truncated
    ? `<p><strong>Metrics cover the newest ${num(d.scan.scanned)} of ${num(d.scan.total)} rows.</strong> Older rows were not scanned.</p>` : '';
  if (m.events_total === 0) {
    return `<section id="overview" aria-labelledby="h-overview"><h2 id="h-overview">Overview</h2>` +
      `${emptyP('No events recorded yet. Run your agent through the guard or proxy, then regenerate this report.')}${coverHtml}` +
      '<p>All counts are 0. Fail-open events are written to the secondary sink, not to the store: see stderr.</p></section>';
  }
  const resultsRows: CountRow[] = [
    { name: 'ok', count: m.tool_results.ok }, { name: 'error', count: m.tool_results.error },
    { name: 'timeout', count: m.tool_results.timeout }, { name: 'other', count: m.tool_results.other },
  ];
  const dropHtml = m.dropped_before_total === 0
    ? '<p>Dropped events: 0. No best-effort audit rows were dropped.</p>'
    : `<p><strong>Dropped events: ${num(m.dropped_before_total)}.</strong> Best-effort audit rows were dropped before later rows were written (sum of <code>dropped_before</code>).</p>`;
  const toolRows: CountRow[] = m.unknown_tool_names > 0
    ? [...m.top_denied_tools, { name: 'unknown tool names (hashed)', count: m.unknown_tool_names }]
    : m.top_denied_tools;
  const tablesHtml = [
    countTable('Events by kind', 'Kind', m.by_kind, m.events_total),
    countTable('Decisions by effect', 'Effect', m.by_effect, m.decisions_total),
    countTable('Decisions by enforcement', 'Enforcement', m.by_enforcement, m.decisions_total),
    reasonTable(m.reason_classes, m.decisions_total),
    countTable('Top tools among enforced denies (up to 10)', 'Tool', toolRows, null),
    countTable('Top rules among enforced denies (up to 10)', 'Rule id', m.top_rules, null),
    countTable('Tool-result outcomes', 'Outcome', resultsRows.filter((r) => r.count > 0 || r.name !== 'other'), m.tool_results.total),
    m.dropped_before_by_class.length > 0 ? countTable('Dropped events by row class', 'Class', m.dropped_before_by_class, null) : '',
  ].join('');
  const factsHtml = [
    dlItem('Events scanned', num(m.events_total)),
    dlItem('Decisions', num(m.decisions_total)),
    dlItem('Denied (enforced)', num(m.denied)),
    dlItem('Would-be denied (monitor_only)', num(m.would_be_denied)),
    dlItem('Deny rate (enforced decisions)', esc(rate(m.denied, m.enforced_decisions))),
    dlItem('Sessions with decisions', num(m.sessions)),
    dlItem('Decisions in tainted sessions', esc(rate(m.tainted_decisions, m.decisions_total))),
    dlItem('Fail-open', 'fail-open events are not stored: see stderr'),
  ].join('');
  return `<section id="overview" aria-labelledby="h-overview"><h2 id="h-overview">Overview</h2>${coverHtml}` +
    '<p class="muted">Counts cover the scanned rows, not only the windows shown further down. A deny in monitor_only mode was recorded but not enforced, so it is counted separately.</p>' +
    `<dl class="facts">${factsHtml}</dl>${dropHtml}<div class="grid2">${tablesHtml}</div></section>`;
}

function renderLatency(d: ReportData): string {
  const l = d.latency;
  let bodyHtml: string;
  if (l.n === 0) bodyHtml = emptyP('No data. Latency is recorded on decision rows, and none exist yet.');
  else {
    const cell = (v: number | null): string => {
      const textHtml = v === null ? 'no data' : num(v) + nbHtml + 'µs';
      return `<td class="n">${textHtml}</td>`;
    };
    const rowsHtml = `<tr><th scope="row" class="n">${num(l.n)}</th>${cell(l.p50)}${cell(l.p95)}${cell(l.p99)}${cell(l.max)}</tr>`;
    bodyHtml = scrollTable('Decision latency in microseconds (nearest-rank percentiles)',
      [{ label: 'Decisions measured (n)', cls: 'n' }, { label: 'p50', cls: 'n' }, { label: 'p95', cls: 'n' }, { label: 'p99', cls: 'n' }, { label: 'max', cls: 'n' }], rowsHtml);
  }
  return `<section id="latency" aria-labelledby="h-latency"><h2 id="h-latency">Latency (enforcement overhead)</h2>${bodyHtml}` +
    '<p class="muted">Decision time only (policy evaluation in-process), measured by the guard; not end-to-end latency.</p></section>';
}

function renderActivations(d: ReportData): string {
  let bodyHtml: string;
  if (d.activations.length === 0) bodyHtml = emptyP('No policy activations recorded yet. The guard writes one row when it starts with a policy.');
  else {
    const rowsHtml = d.activations.map((a: ActivationView) => {
      const verHtml = a.policy_version === null ? 'none' : hashHtml(a.policy_version);
      const ruleHtml = a.rule_count === null ? 'n/a' : num(a.rule_count);
      return `<tr><td class="n">${num(a.seq)}</td><td class="nw">${esc(iso(a.ts_ms))}</td><td>${esc(a.event)}</td>` +
        `<td>${verHtml}</td><td>${opt(a.mode)}</td><td class="n">${ruleHtml}</td><td>${opt(a.details)}</td></tr>`;
    }).join('');
    bodyHtml = scrollTable(`Policy activations, oldest first (showing ${String(d.activations.length)} of ${String(d.activations_total)})`,
      [{ label: 'Seq', cls: 'n' }, { label: 'Time (UTC)' }, { label: 'Event' }, { label: 'Policy version' }, { label: 'Mode' }, { label: 'Rules', cls: 'n' }, { label: 'Details' }], rowsHtml, true);
  }
  const topHtml = d.top_policy_version === null
    ? '<p>Most-used policy version: no decisions yet.</p>'
    : `<p>Most-used policy version, by decisions: <strong>${hashHtml(d.top_policy_version)}</strong>.</p>`;
  const moreHtml = d.activations_total > d.activations.length
    ? `<p class="muted">Showing the newest ${num(d.activations.length)} of ${num(d.activations_total)} activation rows.</p>` : '';
  return `<section id="policies" aria-labelledby="h-policies"><h2 id="h-policies">Policy versions and activations</h2>${topHtml}${bodyHtml}${moreHtml}</section>`;
}

function effectLabel(e: string | null, enf: string | null): string {
  if (e === null && enf === null) return 'n/a';
  return `${e ?? 'n/a'}/${enf ?? 'n/a'}`;
}

function ruleDetailHtml(r: RuleDetail): string {
  if (!r.found) return `<li><code>${esc(r.id)}</code>: not found in the supplied policy.</li>`;
  const sumHtml = r.summary.map((s) => `<li>${esc(s)}</li>`).join('');
  return `<li><code>${esc(r.id)}</code>, effect <strong>${opt(r.effect)}</strong>, reason <code>${opt(r.reason_code)}</code>` +
    (sumHtml === '' ? '' : `<ul>${sumHtml}</ul>`) + '</li>';
}

function detailBlock(x: DecisionView): string {
  const resultsHtml = x.results.length === 0
    ? '<p class="muted">No linked tool_result row. The call did not run, or its result was not recorded.</p>'
    : scrollTable('Linked results', [{ label: 'Seq', cls: 'n' }, { label: 'Status' }, { label: 'Error class' }, { label: 'Result type' }, { label: 'Length', cls: 'n' }],
      x.results.map((r) => `<tr><td class="n">${num(r.seq)}</td><td>${opt(r.status)}</td><td>${opt(r.error_class)}</td><td>${opt(r.result_type)}</td><td class="n">${r.result_len === null ? 'n/a' : num(r.result_len)}</td></tr>`).join(''));
  let rulesHtml: string;
  if (x.rule_detail === 'shown') rulesHtml = x.rules.length === 0 ? '<p>No rules matched.</p>' : `<ul>${x.rules.map(ruleDetailHtml).join('')}</ul>`;
  else if (x.rule_detail === 'version_mismatch') rulesHtml = '<p class="muted">Policy version differs; rule detail not shown. Supply the policy file that was active for this row.</p>';
  else rulesHtml = '<p class="muted">No policy supplied, so rule detail is not shown. Pass the policy file to see what each matched rule requires.</p>';
  const taint = x.session_tainted === null ? 'unknown' : x.session_tainted ? 'yes' : 'no';
  const factsHtml = [
    dlItem('Decision id', `<code>${esc(x.id)}</code>`),
    dlItem('Seq and time', `${num(x.seq)}, ${esc(iso(x.ts_ms))}`),
    dlItem('Tool', `<code>${opt(x.tool)}</code>`),
    dlItem('Effect and enforcement', esc(effectLabel(x.effect, x.enforcement))),
    dlItem('Reason', `<code>${opt(x.reason_code)}</code> (class ${esc(x.reason_class)})`),
    dlItem('Matched rule ids', x.rule_ids.length === 0 ? 'none' : x.rule_ids.map((r) => `<code>${esc(r)}</code>`).join(', ')),
    dlItem('Policy version', x.policy_version === null ? 'none' : hashHtml(x.policy_version)),
    dlItem('Risk', opt(x.risk)),
    dlItem('Session', `<code>${opt(x.session_id)}</code>, tainted: ${esc(taint)}`),
    dlItem('Agent', `<code>${opt(x.agent_id)}</code>`),
    dlItem('Provenance asserted', `<code>${opt(x.provenance)}</code>`),
    dlItem('Arguments (redacted)', `<code>${opt(x.args_redacted)}</code>`),
    dlItem('Decision latency', x.latency_us === null ? 'no data' : `${num(x.latency_us)}${nbHtml}µs`),
    dlItem('Tool executed', x.will_execute ? 'yes, the call was allowed to run' : 'no, the call did not run'),
    x.dropped_before === null ? '' : dlItem('Dropped before this row', `<code>${esc(x.dropped_before)}</code>`),
  ].join('');
  return `<article class="detail" id="d-${esc(x.anchor)}" aria-labelledby="t-${esc(x.anchor)}">` +
    `<h3 id="t-${esc(x.anchor)}">Decision ${esc(abbrev(x.id, 8))}</h3>` +
    `<p class="verdict-line">${esc(x.verdict)}</p><p>${esc(x.why)}</p>` +
    `<dl class="facts">${factsHtml}</dl><h4>Matched rules</h4>${rulesHtml}${resultsHtml}` +
    '<p><a href="#decisions">Back to the decisions table</a></p></article>';
}

function renderDecisions(d: ReportData): string {
  const w = d.window;
  const legendHtml = '<dl class="legend"><dt>Effect</dt><dd>permit means policy allowed the call. deny means policy refused it.</dd>' +
    '<dt>Enforcement</dt><dd>enforced means the decision was applied. monitor_only means it was recorded but the call ran anyway.</dd>' +
    '<dt>Risk</dt><dd>The tool’s declared risk class: low, medium or high.</dd>' +
    '<dt>Tainted</dt><dd>The session had read untrusted content when the decision was made.</dd></dl>';
  if (d.decisions.length === 0) {
    return `<section id="decisions" aria-labelledby="h-decisions"><h2 id="h-decisions">Decisions explorer</h2>` +
      `${emptyP('No decisions recorded yet. Decisions appear after the first tool call passes through the guard or proxy.')}${legendHtml}</section>`;
  }
  const rowsHtml = d.decisions.map((x) =>
    `<tr><td class="n">${num(x.seq)}</td><td class="nw">${esc(iso(x.ts_ms))}</td>` +
    `<td class="nw">${esc(x.effect === 'deny' ? 'DENY' : x.effect === 'permit' ? 'PERMIT' : x.effect ?? 'n/a')}</td><td>${opt(x.enforcement)}</td>` +
    `<td>${opt(x.tool)}</td><td>${opt(x.reason_code)}</td><td>${opt(x.risk)}</td>` +
    `<td class="nw">${x.session_tainted ? 'tainted' : 'no'}</td>` +
    `<td class="nw mono"><a href="#d-${esc(x.anchor)}" title="${esc(x.id)}">${esc(abbrev(x.id, 8))}</a></td></tr>`).join('');
  const tableHtml = scrollTable(`Decisions, newest first (${num(w.decisions_shown)} of ${num(w.decisions_total)})`,
    [{ label: 'Seq', cls: 'n' }, { label: 'Time (UTC)' }, { label: 'Effect' }, { label: 'Enforcement' }, { label: 'Tool' }, { label: 'Reason' }, { label: 'Risk' }, { label: 'Tainted' }, { label: 'Detail' }], rowsHtml, true);
  const detailsHtml = d.decisions.map(detailBlock).join('');
  return `<section id="decisions" aria-labelledby="h-decisions"><h2 id="h-decisions">Decisions explorer</h2>` +
    `<p>Each row links to a plain-language explanation of that decision, listed below the table.</p>${legendHtml}${tableHtml}${detailsHtml}</section>`;
}

function renderEvents(d: ReportData): string {
  const w = d.window;
  if (d.events.length === 0) {
    return `<section id="events" aria-labelledby="h-events"><h2 id="h-events">Event log</h2>` +
      `${emptyP('No events recorded yet. Run your agent through the guard or proxy, then regenerate this report.')}</section>`;
  }
  const rowsHtml = d.events.map((e: EventView) => {
    const linkHtml = e.decision_id === null
      ? 'none'
      : e.decision_anchor === null
        ? `<span class="mono" title="${esc(e.decision_id)}">${esc(abbrev(e.decision_id, 8))}</span>`
        : `<a class="mono" href="#d-${esc(e.decision_anchor)}" title="${esc(e.decision_id)}">${esc(abbrev(e.decision_id, 8))}</a>`;
    return `<tr><td class="n">${num(e.seq)}</td><td class="nw">${esc(iso(e.ts_ms))}</td><td>${esc(e.kind)}</td>` +
      `<td class="nw">${esc(effectLabel(e.effect, e.enforcement))}</td><td>${opt(e.reason_code)}</td><td>${opt(e.tool)}</td>` +
      `<td class="nw">${linkHtml}</td></tr>`;
  }).join('');
  const tableHtml = scrollTable(`Events, newest first (${num(w.events_shown)} of ${num(w.events_total)})`,
    [{ label: 'Seq', cls: 'n' }, { label: 'Time (UTC)' }, { label: 'Kind' }, { label: 'Effect/enforcement' }, { label: 'Reason' }, { label: 'Tool' }, { label: 'Decision' }], rowsHtml, true);
  return `<section id="events" aria-labelledby="h-events"><h2 id="h-events">Event log</h2>${tableHtml}</section>`;
}

function renderLimits(d: ReportData): string {
  const w = d.window;
  const truncHtml = w.decisions_shown < w.decisions_total || w.events_shown < w.events_total
    ? `<li><strong>The windows are truncated.</strong> Showing ${num(w.decisions_shown)} of ${num(w.decisions_total)} decisions and ${num(w.events_shown)} of ${num(w.events_total)} events. Overview counts are not truncated.</li>`
    : '';
  const shrunkHtml = w.shrunk
    ? `<li><strong>The window was reduced automatically</strong> from ${num(w.requested)} to ${num(w.effective)} rows to keep this file under 8${nbHtml}MiB.</li>`
    : '';
  return `<section id="limits" aria-labelledby="h-limits"><h2 id="h-limits">Limits and notes</h2><ul class="plain">${truncHtml}${shrunkHtml}` +
    '<li>Argument values are never stored, only keyed digests and redacted type and length descriptors. Recorded traffic therefore cannot be replayed against a new policy.</li>' +
    '<li>Provenance labels are asserted by the host application. PRYSM does not verify them.</li>' +
    '<li>Latency is measured in-process around policy evaluation only.</li>' +
    '<li>False-positive and false-negative rates are not available from the store. They come from the labelled benchmark in <code>eval/</code>.</li>' +
    '<li>This report is a snapshot taken at generation time. Later events are not included.</li>' +
    '<li>The hash chain is tamper-evident, not tamper-proof. An OK verdict without an external anchor does not rule out truncation or a full rewrite.</li></ul></section>';
}

function renderSummary(d: ReportData): string {
  const m = d.metrics;
  const stat = (label: string, valueHtml: string): string => `<div><dt>${esc(label)}</dt><dd>${valueHtml}</dd></div>`;
  return '<dl class="summary">' + [
    stat('Events scanned', num(m.events_total)),
    stat('Decisions', num(m.decisions_total)),
    stat('Denied (enforced)', num(m.denied)),
    stat('Would-be denied (monitor_only)', num(m.would_be_denied)),
    stat('Deny rate', esc(rate(m.denied, m.enforced_decisions))),
    stat('Sessions', num(m.sessions)),
  ].join('') + '</dl>';
}

/** Renders the self-contained report. Deterministic: depends only on `d`. */
export function renderReportHtml(d: ReportData): string {
  const gen = iso(d.generated_ms);
  const navItems: [string, string][] = [
    ['integrity', 'Integrity'], ['overview', 'Overview'], ['latency', 'Latency'], ['policies', 'Policies'],
    ['decisions', 'Decisions'], ['events', 'Event log'], ['limits', 'Limits'],
  ];
  const navHtml = navItems.map(([id, label]) => `<li><a href="#${esc(id)}">${esc(label)}</a></li>`).join('');
  tableSeq = 0;
  const bannerHtml = banner(d);
  const summaryHtml = renderSummary(d);
  const coversHtml = d.head === null
    ? 'Covers an empty chain.'
    : `Covers the chain up to seq ${num(d.head.seq)}, head hash ${fullHtml(d.head.hash)}.`;
  let bodyHtml: string;
  let navBlockHtml = `<nav class="toc" aria-label="Report sections"><ul>${navHtml}</ul></nav>`;
  if (d.too_large) {
    bodyHtml = '<section id="too-large" aria-labelledby="h-too-large"><h2 id="h-too-large">Report too large</h2>' +
      `<p>The full report would exceed 8${nbHtml}MiB, so the tables were left out. The integrity verdict and totals above are complete. Use <code>prysm events</code> with filters to read individual rows.</p></section>` +
      renderIntegrity(d);
    navBlockHtml = '';
  } else {
    bodyHtml = [renderIntegrity(d), renderOverview(d), renderLatency(d), renderActivations(d), renderDecisions(d), renderEvents(d), renderLimits(d)].join('\n');
  }
  return '<!doctype html><!-- prysm-report v1 --><html lang="en"><head><meta charset="utf-8">' +
    `<meta http-equiv="Content-Security-Policy" content="${esc(CSP)}">` +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<meta name="color-scheme" content="light dark">' +
    '<meta name="theme-color" content="#f1f3f6" media="(prefers-color-scheme: light)">' +
    '<meta name="theme-color" content="#12161c" media="(prefers-color-scheme: dark)">' +
    `<title>${esc(d.title)} for ${esc(d.db_name)}</title>` + '<style>' + CSS + '</style></head><body>' +
    '<a class="skip" href="#main">Skip to the report</a>' +
    `<header class="top wrap"><h1>${esc(d.title)}</h1>` +
    `<p class="meta">Generated <time datetime="${esc(gen)}">${esc(gen)}</time> (generated_ms ${num(d.generated_ms)}) from database <code>${esc(d.db_name)}</code>. ${coversHtml}</p>` +
    `${bannerHtml}${summaryHtml}${navBlockHtml}</header>` +
    `<main id="main" class="wrap">${bodyHtml}</main>` +
    '<footer class="wrap"><p>This file is self-contained: it has no scripts and makes no network requests.</p></footer>' +
    '</body></html>\n';
}
