// `explain <decision_id>`: facts about one decision row, its tool_result rows and (same-version only) rule detail.
import type { StoredEvent, Store } from '../store/index.ts';
import type { LoadedPolicy } from '../core/index.ts';
import { cell, esc, iso, jsonLine } from './text.ts';
import { CliExit } from './files.ts';
import type { Io } from './files.ts';

export const VERSION_DIFFERS = 'policy version differs; rule detail not shown';

const PLAIN_REASON: Readonly<Record<string, string>> = {
  permitted: 'a permit rule matched and no deny rule matched',
  denied_by_rule: 'a deny rule matched',
  default_deny: 'no permit rule matched (default deny)',
  unknown_tool: 'the tool is not known to the policy or the guard',
  invalid_args: 'the arguments did not match the tool schema declared in the policy',
  invalid_request: 'the request or its context was malformed',
  limit_exceeded: 'a size or work limit was exceeded',
  tainted_session: 'the session is tainted and no tainted-session permit rule matched an external-effect tool',
  engine_error: 'the policy engine failed (fail-closed)',
  audit_unavailable: 'the audit store was unavailable (fail-closed)',
};

export function plainReason(code: string | null): string {
  if (code === null) return 'no reason recorded';
  return Object.hasOwn(PLAIN_REASON, code) ? (PLAIN_REASON[code] as string) : `reason code ${esc(code)}`;
}

function asObj(v: unknown): Record<string, unknown> | null {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

export function ruleIds(row: StoredEvent): string[] {
  return Array.isArray(row.rule_ids) ? row.rule_ids.filter((x): x is string => typeof x === 'string') : [];
}

export function willExecute(row: StoredEvent): boolean {
  return asObj(row.outcome)?.['will_execute'] === true;
}

export function droppedBefore(rows: readonly StoredEvent[]): unknown[] {
  const out: unknown[] = [];
  for (const r of rows) {
    const d = asObj(r.outcome)?.['dropped_before'];
    if (d !== undefined && d !== null) out.push(d);
  }
  return out;
}

/** One plain-language line. monitor_only is stated honestly: a would-be deny that executed is not "BLOCKED". */
export function verdict(row: StoredEvent, rules?: readonly { id: string; effect: string }[]): { verdict: string; why: string } {
  let ids = ruleIds(row);
  let by: string;
  if (row.reason_code === 'denied_by_rule' && row.effect === 'deny' && rules !== undefined) {
    // same-version policy: name only the deny rules that blocked the call
    ids = ids.filter((id) => rules.some((r) => r.id === id && r.effect === 'deny'));
    by = ids.length > 0 ? ids.map(esc).join(', ') : 'none (no matched deny rule found in the policy)';
  } else {
    by = ids.length > 0 ? ids.map(esc).join(', ') : 'none (no rule matched)';
    // the store keeps matched deny ids then permit ids without their effect
    if (row.reason_code === 'denied_by_rule' && ids.length > 0) by += ' [all matched rules, deny first; use --policy to see each effect]';
  }
  const why = plainReason(row.reason_code);
  const mon = row.enforcement === 'monitor_only';
  if (row.effect === 'deny') {
    if (mon) {
      return { verdict: `WOULD BE BLOCKED (monitor_only: the tool ${willExecute(row) ? 'ran' : 'did not run'}) by rule(s) ${by} because ${why}`, why };
    }
    return { verdict: `BLOCKED by rule(s) ${by} because ${why}`, why };
  }
  if (row.effect === 'permit') {
    return { verdict: mon ? `ALLOWED (monitor_only) by rule(s) ${by}` : `ALLOWED by rule(s) ${by}`, why };
  }
  return { verdict: 'UNKNOWN (no effect recorded)', why };
}

function list(v: unknown): string {
  return Array.isArray(v) ? '[' + v.map((x) => jsonLine(x)).join(', ') + ']' : jsonLine(v);
}

/** Human summary of a rule's match clauses. Content comes from the policy file (never from stored traffic). */
export function summarizeMatch(match: unknown): string[] {
  const m = asObj(match);
  if (m === null) return [];
  const out: string[] = [];
  if (m['tools'] !== undefined) out.push(`tool is one of ${list(m['tools'])}`);
  if (m['agents'] !== undefined) out.push(`agent is one of ${list(m['agents'])}`);
  if (m['scopes_any'] !== undefined) out.push(`any scope in ${list(m['scopes_any'])}`);
  if (m['session_tainted'] !== undefined) out.push(`session_tainted is ${jsonLine(m['session_tainted'])}`);
  const args = asObj(m['args']);
  if (args !== null) {
    for (const name of Object.keys(args).sort()) {
      const p = asObj(args[name]);
      if (p === null) continue;
      const parts = Object.keys(p).sort().map((op) => `${op} ${jsonLine(p[op])}`);
      out.push(`arg ${name}: ${parts.join(', ')}`);
    }
  }
  const prov = asObj(m['provenance']);
  if (prov !== null) {
    for (const name of Object.keys(prov).sort()) {
      const p = asObj(prov[name]);
      if (p === null) continue;
      const parts = Object.keys(p).sort().map((k) => `${k} ${list(p[k])}`);
      out.push(`provenance of ${name}: ${parts.join(', ')}`);
    }
  }
  return out;
}

export interface RuleView {
  id: string;
  effect: string;
  reason_code: string;
  match: string[];
}

function ruleDetail(policy: LoadedPolicy, ids: readonly string[]): RuleView[] {
  const out: RuleView[] = [];
  for (const id of ids) {
    const r = policy.document.rules.find((x) => x.id === id);
    if (r === undefined) continue;
    out.push({ id: r.id, effect: r.effect, reason_code: r.reason_code, match: summarizeMatch(r.match) });
  }
  return out;
}

/** Exact id, else a unique prefix (>= 8 characters) of a decision id. */
function resolveRow(store: Store, id: string): StoredEvent {
  const exact = store.getEvent(id);
  if (exact !== null) return exact;
  if (Array.from(id).length < 8) throw new CliExit(1, 'no such decision');
  const hits: StoredEvent[] = [];
  let after = 0;
  for (;;) {
    const rows = store.query({ kind: 'decision', afterSeq: after, limit: 10000 });
    for (const r of rows) if (r.id.startsWith(id)) hits.push(r);
    if (rows.length < 10000) break;
    after = (rows[rows.length - 1] as StoredEvent).seq;
  }
  if (hits.length === 0) throw new CliExit(1, 'no such decision');
  if (hits.length > 1) throw new CliExit(1, `ambiguous id (${hits.length} matches)`);
  return hits[0] as StoredEvent;
}

export function explain(store: Store, id: string, policy: LoadedPolicy | undefined, json: boolean, io: Io): number {
  const row = resolveRow(store, id);
  if (row.kind !== 'decision') throw new CliExit(1, 'not a decision');
  const linked = store.eventsByDecision(row.id);
  const results = linked.filter((r) => r.kind === 'tool_result' && r.decision_id === row.id);
  const dropped = droppedBefore([row, ...results]);
  let rules: RuleView[] | undefined;
  let warning: string | undefined;
  if (policy !== undefined) {
    if (row.policy_version !== null && row.policy_version === policy.policy_version) rules = ruleDetail(policy, ruleIds(row));
    else warning = VERSION_DIFFERS;
  }
  const v = verdict(row, rules);

  if (json) {
    io.out(jsonLine({
      decision: row,
      results,
      verdict: v.verdict,
      warnings: warning !== undefined ? [warning] : [],
      rules: rules ?? null,
    }));
    return 0;
  }

  const L = (k: string, val: string): void => io.out(k.padEnd(16) + val);
  L('decision', cell(row.id));
  L('time', iso(row.ts_ms));
  L('verdict', v.verdict);
  L('effect', cell(row.effect));
  L('enforcement', cell(row.enforcement));
  L('reason_code', cell(row.reason_code));
  const ids = ruleIds(row);
  L('rule_ids', ids.length > 0 ? ids.map(esc).join(', ') : '-');
  L('policy_version', cell(row.policy_version));
  L('tool', cell(row.tool));
  L('risk', cell(row.risk));
  L('session_tainted', row.session_tainted === null ? 'unknown' : row.session_tainted === 1 ? 'yes' : 'no');
  const prov = asObj(row.provenance_asserted);
  L('provenance', prov === null ? '-' : Object.keys(prov).map((k) => {
    const x = prov[k];
    return `${esc(k)}=${Array.isArray(x) ? x.map(esc).join('|') : esc(x)}`;
  }).join(' ') || '-');
  L('latency_us', cell(row.latency_us));
  L('args_redacted', row.args_redacted === null ? '-' : jsonLine(row.args_redacted));
  L('will_execute', willExecute(row) ? 'yes' : 'no');
  for (const d of dropped) L('dropped_before', jsonLine(d));
  if (results.length === 0) L('result', 'none recorded');
  for (const r of results) {
    const o = asObj(r.outcome) ?? {};
    L('result', `seq=${r.seq} status=${cell(o['status'])} error_class=${cell(o['error_class'])} result_type=${cell(o['result_type'])} result_len=${cell(o['result_len'])}`);
  }
  if (warning !== undefined) io.out('warning: ' + warning);
  if (rules !== undefined) {
    if (rules.length === 0) L('rule detail', 'no matched rule ids recorded for this decision');
    for (const r of rules) {
      L('rule', `${esc(r.id)}  effect=${esc(r.effect)}  reason_code=${esc(r.reason_code)}`);
      for (const m of r.match) L('', '  match: ' + m);
    }
  }
  return 0;
}
