// Report data builder (REPORT-SPEC section 2). All metrics are computed from the store only, in one pass over the
// whole chain (counts are never limited to the displayed window). Nothing here reads the clock or the file system.
import { SCHEMA_VERSION } from '../store/index.ts';
import type { Store, StoredEvent, VerifyResult } from '../store/index.ts';
import type {
  ActivationView, BuildReportOptions, CountRow, DecisionView, EventView, LatencyView, Metrics, PostureView,
  ReasonRow, ReportData, ResultView, RuleDetail, VerifyView,
} from './types.ts';
import { renderReportHtml } from './render.ts';

const MAX_BYTES = 8 * 1024 * 1024;
const DEFAULT_WINDOW = 500;
const MAX_WINDOW = 5000;
const CHUNK = 1000;
const DEFAULT_SCAN = 2_000_000;
const UNKNOWN_TOOL_MARKER = "?";
const ACTIVATIONS_SHOWN = 200;
const JSON_SHOWN = 600;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Maps a core reason code to the public reason class (AUDIT-SPEC 2.2); unknown codes are class "other". */
export function reasonClass(code: string | null): string {
  switch (code) {
    case 'permitted': return 'allowed';
    case 'denied_by_rule': case 'default_deny': case 'tainted_session': return 'denied';
    case 'unknown_tool': return 'unknown tool';
    case 'invalid_args': case 'invalid_request': case 'limit_exceeded': return 'invalid request';
    case 'engine_error': case 'audit_unavailable': return 'unavailable';
    default: return 'other';
  }
}
const CLASS_ORDER = ['allowed', 'denied', 'unknown tool', 'invalid request', 'unavailable', 'other'];

const WHY: Record<string, string> = {
  permitted: 'A permit rule matched and no deny rule matched.',
  denied_by_rule: 'A deny rule matched.',
  default_deny: 'No permit rule matched, so the default is to deny.',
  unknown_tool: 'The tool is not known to the policy or is not registered with the guard.',
  invalid_args: 'The arguments do not match the tool’s declared schema.',
  invalid_request: 'The request was malformed.',
  limit_exceeded: 'A request size or complexity limit was exceeded.',
  tainted_session: 'The session was tainted by untrusted content.',
  engine_error: 'The engine failed, and failures are denied.',
  audit_unavailable: 'The audit log could not be written, so the call was refused.',
};

function bump(m: Map<string, number>, k: string, by = 1): void {
  m.set(k, (m.get(k) ?? 0) + by);
}

function rows(m: Map<string, number>, limit?: number): CountRow[] {
  const out = [...m.entries()].map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return limit === undefined ? out : out.slice(0, limit);
}

function clip(s: string): string {
  const pts = Array.from(s);
  return pts.length <= JSON_SHOWN ? s : pts.slice(0, JSON_SHOWN).join('') + '… (shortened)';
}

function jsonText(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  try { return clip(JSON.stringify(v)); } catch { return null; }
}

function str(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}
function int(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function posture(e: StoredEvent): PostureView {
  const o = isObj(e.outcome) ? e.outcome : {};
  const fields: { key: string; value: string }[] = [];
  for (const k of Object.keys(o).sort()) {
    if (k === 'event') continue;
    const v = o[k];
    let t: string;
    if (Array.isArray(v)) t = v.length === 0 ? 'none' : v.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(', ');
    else if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') t = String(v);
    else t = JSON.stringify(v) ?? 'none';
    fields.push({ key: k, value: clip(t) });
  }
  return { seq: e.seq, ts_ms: e.ts_ms, fields };
}

function activation(e: StoredEvent): ActivationView {
  const o = isObj(e.outcome) ? e.outcome : {};
  const ev = str(o['event']) ?? 'activation';
  const skip = new Set(['event', 'policy_version', 'mode', 'policy_mode', 'rule_count', 'tool_names_hash']);
  const bits: string[] = [];
  for (const k of Object.keys(o).sort()) {
    if (skip.has(k)) continue;
    const v = o[k];
    if (typeof v === 'number' || typeof v === 'boolean') bits.push(k + '=' + String(v));
    else if (typeof v === 'string') bits.push(k + '=' + clip(v));
    else if (Array.isArray(v)) bits.push(k + '=' + String(v.length) + ' items');
    else if (isObj(v)) bits.push(k + '=' + clip(JSON.stringify(v)));
  }
  return {
    seq: e.seq, ts_ms: e.ts_ms, event: ev, policy_version: e.policy_version,
    mode: str(o['mode']) ?? str(o['policy_mode']), rule_count: int(o['rule_count']),
    details: bits.join(', '),
  };
}

/** Plain-language summary of one predicate object from a rule's match.args. */
function predicate(name: string, p: unknown): string {
  if (!isObj(p)) return `argument ${name} matches a condition`;
  const op = Object.keys(p).find((k) => k !== 'accept');
  const v = op === undefined ? undefined : p[op];
  const j = (x: unknown): string => JSON.stringify(x) ?? 'none';
  switch (op) {
    case 'equals': return `argument ${name} equals ${j(v)}`;
    case 'in': return `argument ${name} is one of ${j(v)}`;
    case 'glob': return `argument ${name} matches the glob ${j(v)}`;
    case 'range': {
      const r = isObj(v) ? v : {};
      const lo = r['min'] !== undefined ? `at least ${j(r['min'])}` : '';
      const hi = r['max'] !== undefined ? `at most ${j(r['max'])}` : '';
      return `argument ${name} is ${[lo, hi].filter((x) => x !== '').join(' and ')}`;
    }
    case 'max_length': return `argument ${name} is at most ${j(v)} characters long`;
    case 'domain_suffix': return `argument ${name} has a host ending in ${j(v)} (forms ${j(p['accept'])})`;
    case 'domain_exact': return `argument ${name} has the host ${j(v)} (forms ${j(p['accept'])})`;
    case 'path_within': return `argument ${name} is a path inside ${j(isObj(v) ? v['root'] : v)}`;
    default: return `argument ${name} matches a condition`;
  }
}

function summarizeMatch(match: unknown): string[] {
  if (!isObj(match)) return [];
  const out: string[] = [];
  const list = (v: unknown): string => (Array.isArray(v) ? v.map((x) => String(x)).join(', ') : String(v));
  if (match['tools'] !== undefined) out.push('tool is one of: ' + list(match['tools']));
  if (match['agents'] !== undefined) out.push('agent is one of: ' + list(match['agents']));
  if (match['scopes_any'] !== undefined) out.push('caller has at least one scope of: ' + list(match['scopes_any']));
  if (isObj(match['args'])) for (const k of Object.keys(match['args']).sort()) out.push(predicate(k, match['args'][k]));
  if (isObj(match['provenance'])) {
    for (const k of Object.keys(match['provenance']).sort()) {
      const s = match['provenance'][k];
      if (!isObj(s)) continue;
      if (s['all_in'] !== undefined) out.push(`every provenance label of ${k} is in: ${list(s['all_in'])}`);
      if (s['any_in'] !== undefined) out.push(`some provenance label of ${k} is in: ${list(s['any_in'])}`);
    }
  }
  if (match['session_tainted'] !== undefined) out.push('session tainted is ' + String(match['session_tainted']));
  return out;
}

/** Nearest-rank percentile over an ascending array: sorted[ceil(p*n/100) - 1], in integer math. */
export function nearestRank(sorted: number[], p: number): number | null {
  const n = sorted.length;
  if (n === 0) return null;
  const rank = Math.min(n, Math.max(1, Math.floor((p * n + 99) / 100)));
  return sorted[rank - 1] as number;
}

function clampWindow(v: number | undefined): number {
  if (v === undefined || !Number.isFinite(v)) return DEFAULT_WINDOW;
  return Math.min(MAX_WINDOW, Math.max(1, Math.trunc(v)));
}

function basename(p: string): string {
  const parts = p.split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

export function buildReportData(store: Store, opts: BuildReportOptions): ReportData {
  const requested = clampWindow(opts.maxEvents);
  const policy = opts.policy;

  // ---- verification (never throws: a failure to verify is itself a FAILED verdict)
  let vr: VerifyResult | null = null;
  try {
    vr = store.verify({
      ...(opts.anchor !== undefined ? { anchor: opts.anchor } : {}),
      ...(opts.expectPruned !== undefined ? { expectPruned: opts.expectPruned } : {}),
      ...(opts.allowPruned === true ? { allowPruned: true } : {}),
    });
  } catch {
    vr = null;
  }
  const head = store.head();
  const storeTotal = (() => { try { return store.count(); } catch { return 0; } })();
  const scanLimit = opts.scanLimit !== undefined && Number.isFinite(opts.scanLimit) && opts.scanLimit >= 1 ? Math.trunc(opts.scanLimit) : DEFAULT_SCAN;
  const genesis = (() => { try { return store.anchor().genesis_hash; } catch { return null; } })();
  const verify: VerifyView = vr === null
    ? { ok: false, count: 0, head_seq: 0, head_hash: '', pruned_through: null, errors: [{ seq: 0, code: 'verify_unavailable' }], warnings: [], checkpoints: 0, unavailable: true }
    : {
      ok: vr.ok, count: vr.count, head_seq: vr.head_seq, head_hash: vr.head_hash, pruned_through: vr.pruned_through,
      errors: vr.errors.map((e) => ({ seq: e.seq, code: e.code })), warnings: vr.warnings.map((e) => ({ seq: e.seq, code: e.code })),
      checkpoints: vr.checkpoints.length, unavailable: false,
    };

  // ---- single pass over every row
  const byKind = new Map<string, number>();
  const byEffect = new Map<string, number>();
  const byEnf = new Map<string, number>();
  const codes = new Map<string, number>();
  const deniedTools = new Map<string, number>();
  const ruleCounts = new Map<string, number>();
  const versions = new Map<string, number>();
  const dropClass = new Map<string, number>();
  const sessions = new Set<string>();
  const latencies: number[] = [];
  const results = { ok: 0, error: 0, timeout: 0, other: 0, total: 0 };
  let total = 0;
  let decisions = 0;
  let denied = 0;
  let wouldBe = 0;
  let enforced = 0;
  let unknownNames = 0;
  let tainted = 0;
  let dropped = 0;
  let activationsTotal = 0;
  const activationRing: StoredEvent[] = [];
  let cfg: StoredEvent | null = null;
  let client: StoredEvent | null = null;
  let evRing: StoredEvent[] = [];
  let decRing: StoredEvent[] = [];
  let readError: string | null = null;

  try {
    let after = head === null ? 0 : Math.max(0, head.seq - scanLimit);
    const last = head === null ? 0 : head.seq;
    for (;;) {
      const chunk = store.query({ afterSeq: after, limit: CHUNK });
      let done = false;
      for (const e of chunk) {
        if (e.seq > last) { done = true; break; }
        total++;
        bump(byKind, e.kind);
        after = e.seq;
        const oc = isObj(e.outcome) ? e.outcome : null;
        const db = oc !== null && isObj(oc['dropped_before']) ? oc['dropped_before'] : null;
        if (db !== null) {
          for (const k of Object.keys(db)) {
            const n = db[k];
            if (typeof n === 'number' && Number.isFinite(n) && n > 0) { dropped += n; bump(dropClass, k, n); }
          }
        }
        evRing.push(e);
        if (evRing.length > requested * 2) evRing = evRing.slice(-requested);
        if (e.kind === 'decision') {
          decisions++;
          bump(byEffect, e.effect ?? 'none');
          bump(byEnf, e.enforcement ?? 'none');
          bump(codes, e.reason_code ?? 'none');
          if (e.enforcement === 'enforced') enforced++;
          if (e.effect === 'deny' && e.enforcement === 'monitor_only') wouldBe++;
          if (e.effect === 'deny' && e.enforcement === 'enforced') {
            denied++;
            if (e.tool === UNKNOWN_TOOL_MARKER) unknownNames++;
            else if (e.tool !== null) bump(deniedTools, e.tool);
            if (Array.isArray(e.rule_ids)) {
              for (const r of e.rule_ids) if (typeof r === 'string' && !r.startsWith('…+')) bump(ruleCounts, r);
            }
          }
          if (e.session_id !== null) sessions.add(e.session_id);
          if (e.session_tainted === 1) tainted++;
          if (e.policy_version !== null) bump(versions, e.policy_version);
          if (typeof e.latency_us === 'number' && Number.isInteger(e.latency_us) && e.latency_us >= 0) latencies.push(e.latency_us);
          decRing.push(e);
          if (decRing.length > requested * 2) decRing = decRing.slice(-requested);
        } else if (e.kind === 'tool_result') {
          results.total++;
          const st = oc === null ? null : oc['status'];
          if (st === 'ok') results.ok++;
          else if (st === 'timeout' || (oc !== null && oc['error_class'] === 'timeout')) results.timeout++;
          else if (st === 'error') results.error++;
          else results.other++;
        } else if (e.kind === 'policy_activate') {
          activationsTotal++;
          activationRing.push(e);
          if (activationRing.length > ACTIVATIONS_SHOWN * 2) activationRing.splice(0, activationRing.length - ACTIVATIONS_SHOWN);
          const ev = oc === null ? null : oc['event'];
          if (ev === 'proxy_config') cfg = e;
          else if (ev === 'proxy_client') client = e;
        }
      }
      if (done || chunk.length < CHUNK) break;
    }
  } catch (e) {
    const c = (e as { code?: unknown } | null)?.code;
    readError = typeof c === 'string' ? c : 'unknown';
  }

  latencies.sort((a, b) => a - b);
  const latency: LatencyView = {
    n: latencies.length, p50: nearestRank(latencies, 50), p95: nearestRank(latencies, 95), p99: nearestRank(latencies, 99),
    max: latencies.length === 0 ? null : (latencies[latencies.length - 1] as number),
  };
  const classRows: ReasonRow[] = [...codes.entries()].map(([code, count]) => ({ group: reasonClass(code), code, count }))
    .sort((a, b) => CLASS_ORDER.indexOf(a.group) - CLASS_ORDER.indexOf(b.group) || (a.code < b.code ? -1 : a.code > b.code ? 1 : 0));
  const metrics: Metrics = {
    events_total: total,
    by_kind: rows(byKind),
    decisions_total: decisions,
    by_effect: rows(byEffect),
    by_enforcement: rows(byEnf),
    denied,
    would_be_denied: wouldBe,
    enforced_decisions: enforced,
    deny_rate: enforced === 0 ? null : denied / enforced,
    reason_classes: classRows,
    unknown_tool_names: unknownNames,
    top_denied_tools: rows(deniedTools, 10),
    top_rules: rows(ruleCounts, 10),
    sessions: sessions.size,
    tainted_decisions: tainted,
    tainted_share: decisions === 0 ? null : tainted / decisions,
    dropped_before_total: dropped,
    dropped_before_by_class: rows(dropClass),
    tool_results: results,
  };
  const topVersion = rows(versions)[0]?.name ?? null;

  // ---- decision views (memoised: shrinking the window must not re-query)
  const views = new Map<string, DecisionView>();
  const decisionView = (e: StoredEvent): DecisionView => {
    const known = views.get(e.id);
    if (known !== undefined) return known;
    let linked: StoredEvent[] = [];
    try { linked = store.eventsByDecision(e.id); } catch { linked = []; }
    const res: ResultView[] = linked.filter((r) => r.kind === 'tool_result').map((r) => {
      const o = isObj(r.outcome) ? r.outcome : {};
      return { seq: r.seq, id: r.id, status: str(o['status']), error_class: str(o['error_class']), result_type: str(o['result_type']), result_len: int(o['result_len']) };
    });
    const oc = isObj(e.outcome) ? e.outcome : {};
    const rids = Array.isArray(e.rule_ids) ? e.rule_ids.filter((x): x is string => typeof x === 'string') : [];
    const rc = e.reason_code;
    const why = (rc !== null ? WHY[rc] : undefined) ?? 'The reason code is not one this report knows how to explain.';
    const willExecute = oc['will_execute'] === true;
    let verdict: string;
    const by = rids.length === 0 ? '' : (rids.length === 1 ? ' by rule ' : ' by rules ') + rids.join(', ');
    if (e.effect === 'deny') {
      verdict = e.enforcement === 'monitor_only' ? 'WOULD BE BLOCKED (monitor_only: the tool ran)' + by : 'BLOCKED' + by;
    } else if (e.effect === 'permit') {
      verdict = e.enforcement === 'monitor_only' ? 'ALLOWED (monitor_only)' + by : 'ALLOWED' + by;
    } else {
      verdict = 'No effect recorded for this row';
    }
    let ruleDetail: DecisionView['rule_detail'] = 'no_policy';
    let rules: RuleDetail[] = [];
    if (policy !== undefined) {
      if (policy.policy_version === e.policy_version) {
        ruleDetail = 'shown';
        rules = rids.map((id): RuleDetail => {
          const r = policy.document.rules.find((x) => x.id === id);
          return r === undefined
            ? { id, found: false, effect: null, reason_code: null, summary: [] }
            : { id, found: true, effect: r.effect, reason_code: r.reason_code, summary: summarizeMatch(r.match) };
        });
      } else ruleDetail = 'version_mismatch';
    }
    const dropObj = isObj(oc['dropped_before']) ? oc['dropped_before'] : null;
    const v: DecisionView = {
      anchor: String(e.seq), seq: e.seq, id: e.id, ts_ms: e.ts_ms, session_id: e.session_id, agent_id: e.agent_id,
      tool: e.tool, effect: e.effect, enforcement: e.enforcement, reason_code: rc, reason_class: reasonClass(rc), rule_ids: rids,
      policy_version: e.policy_version, risk: e.risk, session_tainted: e.session_tainted === null ? null : e.session_tainted === 1,
      provenance: jsonText(e.provenance_asserted), args_redacted: jsonText(e.args_redacted), latency_us: e.latency_us,
      will_execute: willExecute, dropped_before: dropObj === null ? null : jsonText(dropObj), verdict: verdict + '.', why,
      results: res, rule_detail: ruleDetail, rules,
    };
    views.set(e.id, v);
    return v;
  };

  const assemble = (n: number, a: number, tooLarge: boolean): ReportData => {
    const decWin = n === 0 ? [] : decRing.slice(-n).reverse();
    const evWin = n === 0 ? [] : evRing.slice(-n).reverse();
    const dViews = decWin.map(decisionView);
    const anchors = new Map(dViews.map((x) => [x.id, x.anchor]));
    const eViews: EventView[] = evWin.map((e) => {
      const did = e.kind === 'decision' ? e.id : e.decision_id;
      return {
        seq: e.seq, id: e.id, ts_ms: e.ts_ms, kind: e.kind, effect: e.effect, enforcement: e.enforcement, reason_code: e.reason_code,
        tool: e.tool, decision_id: did, decision_anchor: did === null ? null : (anchors.get(did) ?? null),
      };
    });
    return {
      title: opts.title !== undefined && opts.title !== '' ? opts.title : 'PRYSM audit report',
      generated_ms: opts.generatedMs,
      db_name: basename(opts.dbName),
      schema_version: SCHEMA_VERSION,
      head: head === null ? null : { seq: head.seq, hash: head.hash },
      verify,
      anchor_supplied: opts.anchor !== undefined,
      expected_pruned_supplied: opts.expectPruned !== undefined,
      allow_pruned: opts.allowPruned === true,
      key_protection: (() => { try { return store.keyProtection(); } catch { return null; } })(),
      genesis_hash: genesis,
      anchor_info: opts.anchor === undefined ? null : { genesis_hash: opts.anchor.genesis_hash, head_seq: opts.anchor.head_seq, head_hash: opts.anchor.head_hash },
      expected_pruned: opts.expectPruned === undefined ? [] : (Array.isArray(opts.expectPruned) ? opts.expectPruned : [opts.expectPruned]).map((x) => ({ through_seq: x.through_seq, last_hash: x.last_hash })),
      checkpoints: vr === null ? [] : vr.checkpoints.map((c) => ({ seq: c.seq, through_seq: c.through_seq, last_hash: c.last_hash })),
      scan: { scanned: total, total: storeTotal, truncated: total < storeTotal },
      too_large: tooLarge,
      policy: policy === undefined ? null : {
        name: policy.name, policy_version: policy.policy_version, mode: policy.mode, rule_count: policy.document.rules.length,
      },
      posture_config: cfg === null ? null : posture(cfg),
      posture_client: client === null ? null : posture(client),
      metrics,
      latency,
      activations: a === 0 ? [] : activationRing.slice(-a).map(activation),
      activations_total: activationsTotal,
      top_policy_version: topVersion,
      decisions: dViews,
      events: eViews,
      window: {
        requested, effective: n, activations_shown: a === 0 ? 0 : Math.min(a, activationRing.length), decisions_shown: dViews.length, decisions_total: decisions,
        events_shown: eViews.length, events_total: storeTotal, shrunk: n < requested || a < ACTIVATIONS_SHOWN,
      },
      read_error: readError,
    };
  };

  // ---- size cap: halve the explorer/log windows to 0, then the activation window to 0, then a minimal page
  let n = requested;
  let a = ACTIVATIONS_SHOWN;
  let data = assemble(n, a, false);
  const tooBig = (x: ReportData): boolean => Buffer.byteLength(renderReportHtml(x), 'utf8') > MAX_BYTES;
  while (tooBig(data)) {
    if (n > 0) n = Math.floor(n / 2);
    else if (a > 0) a = Math.floor(a / 2);
    else { data = assemble(0, 0, true); break; }
    data = assemble(n, a, false);
  }
  return data;
}
