// Source scan for escaping discipline, pre-flight greps over generated output, and the contrast test from tokens.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { cleanup } from '../support/tmp.ts';
import { html, guardRun, monitorRun, appendHostile, freshStore, styleOf, markupOf } from '../support/report-kit.ts';

after(cleanup);

const SRC = readFileSync(new URL('../../src/report/render.ts', import.meta.url), 'utf8');

function interpolations(src: string): string[] {
  const out: string[] = [];
  for (let i = src.indexOf('${'); i >= 0; i = src.indexOf('${', i + 2)) {
    let depth = 1;
    let j = i + 2;
    while (j < src.length && depth > 0) {
      const c = src[j];
      if (c === '{') depth++;
      else if (c === '}') depth--;
      j++;
    }
    out.push(src.slice(i + 2, j - 1).trim());
  }
  return out;
}

test('renderer source: every template interpolation is esc/opt/num/pct/String or a pre-escaped *Html value', () => {
  const code = SRC.split('\n').filter((l) => !l.trim().startsWith('//') && !l.trim().startsWith('*') && !l.trim().startsWith('/*')).join('\n');
  const exprs = interpolations(code);
  assert.ok(exprs.length > 100, 'scan found the interpolations');
  // helpers that return already escaped HTML, or escape their text arguments internally
  const ok = /^(?:(?:esc|opt|num|pct|String|emptyP|fullHtml|hashHtml|postureHtml|cell)\([^`]*\)|[a-z][A-Za-z0-9]*Html)$/;
  // reviewed: conditionals over fixed literals, escaped values and numeric formatting only
  const reviewed = new Set([
    'h.cls ? ` class="${esc(h.cls)}"` : \'\'',
    "tall ? ' tall' : ''",
    "keyHelp ? ', ' + esc(keyHelp) : ''",
    "r.result_len === null ? 'n/a' : num(r.result_len)",
    "x.rules.map(ruleDetailHtml).join('')",
    "x.session_tainted ? 'tainted' : 'no'",
    "e ?? 'n/a'",
    "enf ?? 'n/a'",
    '((num_ / den) * 100).toFixed(1)',
    'x.b === null ? \'\' : `<td class="n">${num(x.b)}</td>`',
  ]);
  const bad = exprs.filter((e) => !ok.test(e) && !reviewed.has(e));
  assert.deepEqual(bad, [], 'unescaped interpolations');
});

let sample: string | null = null;
async function sampleHtml(): Promise<string> {
  if (sample !== null) return sample;
  const k = await guardRun();
  await monitorRun(k);
  appendHostile(k.store);
  sample = html(k.store, { policy: k.policy, anchor: k.store.anchor() });
  return sample;
}

test('pre-flight: banned characters, declarations and patterns are absent from generated output', async () => {
  const h = await sampleHtml();
  const css = styleOf(h);
  const mk = markupOf(h) + '\n' + css;
  assert.ok(!/—|–/.test(h.replace(/<[^>]*>/g, (m) => m)), 'no em or en dash');
  assert.ok(!/#(?:000|fff)(?:000|fff)?(?![0-9a-f])/i.test(h), 'no pure black or white');
  assert.ok(!/outline:\s*none/i.test(css));
  assert.ok(!/transition|animation|@keyframes/i.test(css), 'no motion at all');
  assert.ok(!/gradient|box-shadow|text-shadow|filter:|cursor:/i.test(css));
  assert.ok(!/letter-spacing/i.test(css), 'no tracked labels');
  assert.ok(!/text-transform:\s*uppercase/i.test(css));
  assert.ok(!/<script/i.test(markupOf(h)) && !/https?:\/\//i.test(mk));
  assert.ok(!/\p{Extended_Pictographic}/u.test(h.replace(/./gsu, (c) => (c === 'µ' ? '' : c))), 'no emoji');
  assert.ok(!/(tr|tbody tr)\s*\{[^}]*border-top/.test(css), 'no border-top on rows');
  assert.ok(!/\bz-index/.test(css));
  assert.ok(/@media print/.test(css));
  assert.ok(h.includes('<meta name="color-scheme" content="light dark">'));
  assert.ok(/color-scheme:light dark/.test(css));
  assert.equal((h.match(/<meta name="theme-color"/g) ?? []).length, 2);
  assert.ok(/prefers-color-scheme:light/.test(h) && /prefers-color-scheme:dark/.test(h) || (h.includes('prefers-color-scheme: light') && h.includes('prefers-color-scheme: dark')));
  assert.ok(/font:16px\/1\.6/.test(css));
  assert.ok(/text-wrap:balance/.test(css));
  assert.ok(/font-variant-numeric:tabular-nums/.test(css));
  assert.ok(/scroll-margin-top/.test(css));
  assert.ok(/:focus-visible/.test(css));
  assert.ok(/class="skip" href="#main"/.test(h));
  assert.ok(/--gutter:16px/.test(css));
  assert.ok(!/<(?:img|svg|canvas|video|iframe)/i.test(h));
  assert.ok(!/<div[^>]*class="(?:card|tile)/.test(h));
  assert.ok(!/(?:^|[>\s])(?:\.\.\.)(?:[<\s]|$)/.test(markupOf(h)));
});

// ---------------------------------------------------------------- contrast from the declared tokens
function parseVars(block: string): Record<string, string> {
  const o: Record<string, string> = {};
  for (const m of block.matchAll(/(--[a-z-]+):(#[0-9a-f]{6})/gi)) o[m[1] as string] = (m[2] as string).toLowerCase();
  return o;
}
function lum(hex: string): number {
  const ch = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * (ch[0] as number) + 0.7152 * (ch[1] as number) + 0.0722 * (ch[2] as number);
}
export function ratio(a: string, b: string): number {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

test('contrast: every --fg-* against the --bg-* it appears on is at least 4.5:1 in light and dark; non-text marks 3:1', async () => {
  const h = await sampleHtml();
  const css = styleOf(h);
  const light = parseVars(/:root\{color-scheme[^}]*\}/.exec(css)?.[0] ?? '');
  const dark = parseVars(/@media \(prefers-color-scheme:dark\)\{:root\{([^}]*)\}/.exec(css)?.[1] ?? '');
  assert.ok(Object.keys(light).length >= 9 && Object.keys(dark).length >= 9, 'both themes declare tokens');
  assert.deepEqual(Object.keys(light).sort(), Object.keys(dark).sort());
  const narrow: Record<string, string[]> = { '--fg-ok': ['--bg-ok'], '--fg-bad': ['--bg-bad'] };
  assert.ok(/--fg-ok appears only on --bg-ok/.test(css) && /--fg-bad appears only on --bg-bad/.test(css), 'narrow pairings are documented in CSS');
  const report: string[] = [];
  for (const [name, theme] of [['light', light], ['dark', dark]] as const) {
    const fgs = Object.keys(theme).filter((k) => k.startsWith('--fg-'));
    const bgs = Object.keys(theme).filter((k) => k.startsWith('--bg-'));
    for (const fg of fgs) {
      for (const bg of narrow[fg] ?? bgs.filter((b) => b === '--bg-page' || b === '--bg-surface')) {
        const r = ratio(theme[fg] as string, theme[bg] as string);
        report.push(`${name} ${fg} on ${bg} ${r.toFixed(2)}`);
        assert.ok(r >= 4.5, `${name} ${fg} on ${bg} is ${r.toFixed(2)}`);
      }
    }
    // meaningful non-text marks: focus ring/accent, verdict borders
    for (const fg of ['--fg-accent']) for (const bg of ['--bg-page', '--bg-surface']) assert.ok(ratio(theme[fg] as string, theme[bg] as string) >= 3);
    assert.ok(ratio(theme['--fg-ok'] as string, theme['--bg-page'] as string) >= 3, name + ' ok border vs page');
    assert.ok(ratio(theme['--fg-bad'] as string, theme['--bg-page'] as string) >= 3, name + ' bad border vs page');
    // no pure black/white and one cool neutral temperature (blue channel >= red channel for neutrals)
    for (const k of ['--bg-page', '--bg-surface', '--fg-text', '--fg-muted']) {
      const v = theme[k] as string;
      assert.ok(parseInt(v.slice(5, 7), 16) >= parseInt(v.slice(1, 3), 16), `${name} ${k} is cool`);
    }
  }
  assert.ok(report.length >= 12);
  assert.ok(!/opacity|rgba\(|hsla\(|color-mix/i.test(css), 'text colours never use alpha, opacity or color-mix');
  console.log(report.join('\n'));
});

test('hostile store data does not change the static structure (one h1, balanced)', () => {
  const { store } = freshStore();
  appendHostile(store, 2);
  const h = html(store);
  assert.equal((h.match(/<h1[ >]/g) ?? []).length, 1);
  store.close();
});
