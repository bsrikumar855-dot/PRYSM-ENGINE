// Report test kit: real stores built through the real guard (and an in-process proxy run), plus an
// independent recount helper and a minimal HTML checker. Hostile rows go through the real store.append.
import { loadPolicy } from '../../src/core/index.ts';
import type { LoadedPolicy } from '../../src/core/index.ts';
import { openStore } from '../../src/store/index.ts';
import type { Store, StoredEvent, NewEvent } from '../../src/store/index.ts';
import { buildReportData, renderReportHtml } from '../../src/report/index.ts';
import type { ReportData } from '../../src/report/index.ts';
import { kit, KEY } from './guard-kit.ts';
import type { Kit } from './guard-kit.ts';
import { POLICY_DOC, rule } from './policy.ts';
import { startLib, makeEnv, openAudit, rowsOf } from './proxy-kit.ts';
import { tmpDir, dbPath } from './tmp.ts';

export const GEN_MS = Date.UTC(2026, 0, 2, 3, 4, 5);

export function freshStore(): { store: Store; path: string; dir: string } {
  const dir = tmpDir('prysm-report-');
  const path = dbPath(dir);
  return { store: openStore({ path, hmacKey: KEY }), path, dir };
}

export function build(store: Store, extra: Record<string, unknown> = {}): ReportData {
  return buildReportData(store, { generatedMs: GEN_MS, dbName: 'audit.db', ...extra } as never);
}

export function html(store: Store, extra: Record<string, unknown> = {}): string {
  return renderReportHtml(build(store, extra));
}

/** A real guard run: permits, enforced denies, unknown tool, invalid args, a tainted session, a tool error. */
export async function guardRun(opts: { policy?: LoadedPolicy } = {}): Promise<Kit> {
  const k = kit({
    ...(opts.policy ? { policy: opts.policy } : {}),
    tools: (calls) => ({
      search_docs: (a: unknown) => { (calls['search_docs'] ??= []).push([a]); return 'r'; },
      read_file: (a: unknown) => { (calls['read_file'] ??= []).push([a]); return 'file'; },
      send_email: (a: unknown) => { (calls['send_email'] ??= []).push([a]); return { sent: true }; },
      set_discount: () => { throw new Error('boom'); },
      note: () => 'noted',
      denied_by_default: () => 'x',
    }) as never,
  });
  const g = k.guard;
  await g.call('search_docs', { query: 'one' });
  await g.call('search_docs', { query: 'two' });
  await g.call('read_file', { path: '/ok.txt' });
  await g.call('read_file', { path: '/secret/a' });
  await g.call('read_file', { path: '/secret/b' });
  await g.call('send_email', { to: 'a@example.com', subject: 's', body: 'b' });
  await g.call('set_discount', { percent: 5 });
  await g.call('no_such_tool', { x: 1 });
  await g.call('note', { text: 7 });
  await g.call('denied_by_default', { x: 'y' });
  const s = g.session();
  s.taint('test');
  await s.call('note', { text: 'tainted' });
  return k;
}

/** Second guard on the same store in monitor_only mode (would-be denies, a second policy version). */
export async function monitorRun(k: Kit): Promise<void> {
  const k2 = kit({
    mode: 'monitor_only', store: k.store,
    extraRules: [rule('deny', 'd.note.long', { tools: ['note'], args: { text: { glob: 'long*' } } })],
  });
  await k2.guard.call('note', { text: 'long text' });
  await k2.guard.call('note', { text: 'short' });
  await k2.guard.call('read_file', { path: '/secret/c' });
}

export async function proxyRun(): Promise<{ store: Store; policyPath: string }> {
  const env = makeEnv();
  const l = startLib({ env });
  await l.client.handshake();
  await l.client.call('echo', { text: 'hello' });
  await l.client.call('echo', { text: 'deny this' });
  await l.client.call('send_email', { to: 'a@example.com' });
  l.client.end();
  await l.done;
  return { store: openAudit(env), policyPath: env.policyPath };
}

export const policyOf = (mode: 'enforce' | 'monitor_only' = 'enforce', extra: unknown[] = []): LoadedPolicy =>
  loadPolicy(JSON.stringify(POLICY_DOC(mode, extra)));

/** Raw hostile rows through the real store.append (the guard and proxy cannot store such names). */
export const HOSTILE = {
  tool: '<script>alert(1)</script>',
  session: '"><img src=x onerror=alert(1)>',
  reason: 'javascript:alert(1)',
  ls: 'a' + String.fromCharCode(8232) + 'b',
  ansi: String.fromCharCode(27) + '[31mred' + String.fromCharCode(27) + '[0m',
  rtl: 'abc' + String.fromCharCode(8238) + 'def',
  nul: 'x' + String.fromCharCode(133) + 'y',
};

export function appendHostile(store: Store, n = 1): void {
  for (let i = 0; i < n; i++) {
    const base: NewEvent = {
      id: 'hostile-' + String(i),
      kind: 'decision',
      ts_ms: GEN_MS - 1000 + i,
      session_id: HOSTILE.session,
      agent_id: HOSTILE.rtl,
      tool: HOSTILE.tool,
      effect: 'deny',
      enforcement: 'enforced',
      rule_ids: ['<b>rule</b>', HOSTILE.ls],
      reason_code: HOSTILE.reason,
      policy_version: HOSTILE.ansi,
      risk: 'high',
      latency_us: 7,
      session_tainted: 1,
      args_redacted: { [HOSTILE.tool]: { type: HOSTILE.nul, len: 3 } },
      provenance_asserted: { '"><script>': HOSTILE.ansi },
      outcome: { will_execute: false },
    };
    store.append(base);
  }
  store.append({
    id: 'hostile-cfg', kind: 'policy_activate', ts_ms: GEN_MS - 500, policy_version: 'v',
    outcome: { event: 'proxy_client', name: '<script>x</script>', version: HOSTILE.rtl },
  });
}

/** Independent recount straight from store.iterate (no report code involved). */
export function recount(store: Store) {
  const all: StoredEvent[] = [];
  for (let after = 0; ;) {
    const c = store.iterate({ afterSeq: after, limit: 1000 });
    all.push(...c);
    if (c.length < 1000) break;
    after = (c[c.length - 1] as StoredEvent).seq;
  }
  const dec = all.filter((e) => e.kind === 'decision');
  const enforced = dec.filter((e) => e.enforcement === 'enforced');
  const denied = enforced.filter((e) => e.effect === 'deny');
  const tally = (xs: string[]): [string, number][] => {
    const m = new Map<string, number>();
    for (const x of xs) m.set(x, (m.get(x) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  };
  const lat = dec.map((e) => e.latency_us).filter((x): x is number => typeof x === 'number' && Number.isInteger(x) && x >= 0).sort((a, b) => a - b);
  return {
    all, dec, enforced, denied,
    wouldBe: dec.filter((e) => e.effect === 'deny' && e.enforcement === 'monitor_only'),
    topTools: tally(denied.map((e) => e.tool).filter((x): x is string => x !== null && x !== '?')).slice(0, 10),
    topRules: tally(denied.flatMap((e) => (Array.isArray(e.rule_ids) ? e.rule_ids as string[] : [])).filter((r) => !r.startsWith('…+'))).slice(0, 10),
    sessions: new Set(dec.map((e) => e.session_id).filter((s) => s !== null)).size,
    tainted: dec.filter((e) => e.session_tainted === 1).length,
    lat,
    nearest: (p: number): number | null => (lat.length === 0 ? null : (lat[Math.ceil((p * lat.length) / 100) - 1] as number)),
  };
}

export { rowsOf };

// ------------------------------------------------------------------ minimal HTML checker
/** Strips text content: returns only markup (tags with attributes), for "markup only" assertions. */
export function markupOf(h: string): string {
  const out: string[] = [];
  const re = /<(\/?)([a-zA-Z][a-zA-Z0-9-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(h)) !== null) out.push(m[0]);
  return out.join('\n');
}

export function styleOf(h: string): string {
  const m = /<style>([\s\S]*?)<\/style>/.exec(h);
  return m ? (m[1] as string) : '';
}

/** Tag-balance check for a small HTML subset; returns an error string or null. */
export function checkBalanced(h: string): string | null {
  const voids = new Set(['meta', 'br', 'hr', 'img', 'input', 'link']);
  const stack: string[] = [];
  const re = /<(!--[\s\S]*?--|!doctype[^>]*|\/?[a-zA-Z][a-zA-Z0-9-]*(?:[^>"']|"[^"]*"|'[^']*')*)>/gi;
  const body = h.replace(/<style>[\s\S]*?<\/style>/, '<style></style>');
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    const tag = m[1] as string;
    if (tag.startsWith('!')) continue;
    const close = tag.startsWith('/');
    const name = (/^\/?([a-zA-Z][a-zA-Z0-9-]*)/.exec(tag) as RegExpExecArray)[1]!.toLowerCase();
    if (voids.has(name)) continue;
    if (!close) { stack.push(name); continue; }
    const top = stack.pop();
    if (top !== name) return `mismatched </${name}> after <${String(top)}>`;
  }
  return stack.length === 0 ? null : 'unclosed ' + stack.join(',');
}
