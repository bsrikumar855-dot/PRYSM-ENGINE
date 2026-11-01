// Shared, pure explanation logic for one decision row (REPORT-SPEC 5.2; used by the CLI `explain` and the static
// report so they can never disagree). No I/O; no imports from src/cli or src/report.
import type { LoadedPolicy } from '../core/index.ts';

/** The fields of a stored decision row this module reads. */
export interface RowLike {
  effect: string | null;
  enforcement: string | null;
  reason_code: string | null;
  rule_ids: unknown;
  outcome: unknown;
  policy_version: string | null;
}

export type CauseKind = 'deny_n' | 'policy' | 'legacy' | 'none';
export interface Cause {
  kind: CauseKind;
  /** Deny-rule ids named as the cause (never permit ids, never the truncation marker). Empty for legacy/none. */
  ids: string[];
}

export const LEGACY_CAUSE = 'A deny rule matched. All matched rules, deny rules listed first:';

const MARKER = '…+';

const WHY: Readonly<Record<string, string>> = {
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

/** Short lower-case reason phrase used when no rule is the cause ("BLOCKED because ..."). */
const BECAUSE: Readonly<Record<string, string>> = {
  denied_by_rule: 'a deny rule matched',
  default_deny: 'no permit rule matched',
  unknown_tool: 'the tool is not known',
  invalid_args: 'the arguments do not match the tool schema',
  invalid_request: 'the request was malformed',
  limit_exceeded: 'a size or complexity limit was exceeded',
  tainted_session: 'the session is tainted',
  engine_error: 'the engine failed (failures are denied)',
  audit_unavailable: 'the audit log could not be written',
};

/** Plain-language reason sentence for a stored reason code (never echoes an unknown code). */
export function plainReason(code: string | null): string {
  return (code !== null && Object.hasOwn(WHY, code) ? WHY[code] : undefined) ?? 'The reason code is not one this tool knows how to explain.';
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Stored rule ids that are real ids (the "…+N" truncation marker is excluded). */
export function realRuleIds(row: RowLike): string[] {
  return Array.isArray(row.rule_ids) ? row.rule_ids.filter((x): x is string => typeof x === 'string' && !x.startsWith(MARKER)) : [];
}

/**
 * Who is named as the cause of a deny. Precedence: outcome.deny_n (first deny_n real ids, clamped to the stored
 * list), else a same-version policy (ids whose rule effect is deny), else legacy (not a cause). A deny that no
 * deny rule caused (tainted_session, default_deny, invalid_*, ...) has kind 'none'. Only meaningful for effect=deny.
 */
export function rowCause(row: RowLike, opts: { policy?: LoadedPolicy } = {}): Cause {
  const all = realRuleIds(row);
  const dn = isObj(row.outcome) ? row.outcome['deny_n'] : undefined;
  if (typeof dn === 'number' && Number.isSafeInteger(dn) && dn >= 0) {
    const ids = all.slice(0, Math.min(dn, all.length));
    return ids.length === 0 ? { kind: 'none', ids: [] } : { kind: 'deny_n', ids };
  }
  // no deny_n: only a denied_by_rule reason can have a deny-rule cause at all
  if (row.reason_code !== 'denied_by_rule') return { kind: 'none', ids: [] };
  const p = opts.policy;
  if (p !== undefined && row.policy_version !== null && p.policy_version === row.policy_version) {
    const denyIds = new Set(p.document.rules.filter((r) => r.effect === 'deny').map((r) => r.id));
    return { kind: 'policy', ids: all.filter((x) => denyIds.has(x)) };
  }
  return { kind: 'legacy', ids: [] };
}

export interface RowVerdict {
  /** One plain-language sentence; the same string in the CLI and the report. */
  verdict: string;
  /** Reason sentence (for legacy rows: the caveat is part of `verdict`, `why` stays the plain reason). */
  why: string;
  cause: Cause;
}

const byRules = (ids: readonly string[]): string => (ids.length === 1 ? ' by rule ' : ' by rules ') + ids.join(', ');

/** Verdict wording from effect AND enforcement (REPORT-SPEC 4.3). Rule ids are NOT escaped here: callers escape. */
export function rowVerdict(row: RowLike, opts: { policy?: LoadedPolicy } = {}): RowVerdict {
  const why = plainReason(row.reason_code);
  const mon = row.enforcement === 'monitor_only';
  const willExecute = isObj(row.outcome) && row.outcome['will_execute'] === true;
  if (row.effect === 'permit') {
    const ids = realRuleIds(row);
    const by = ids.length === 0 ? '' : byRules(ids);
    return { verdict: (mon ? 'ALLOWED (monitor_only)' : 'ALLOWED') + by + '.', why, cause: { kind: 'none', ids: [] } };
  }
  if (row.effect !== 'deny') return { verdict: 'No effect recorded for this row.', why, cause: { kind: 'none', ids: [] } };
  const head = mon ? `WOULD BE BLOCKED (monitor_only: the tool ${willExecute ? 'ran' : 'did not run'})` : 'BLOCKED';
  const cause = rowCause(row, opts);
  if (cause.kind === 'legacy') {
    const ids = realRuleIds(row);
    return { verdict: `${head}. ${LEGACY_CAUSE} ${ids.length > 0 ? ids.join(', ') : 'none'}`, why, cause };
  }
  if (cause.ids.length > 0) return { verdict: head + byRules(cause.ids) + '.', why, cause };
  const rc = row.reason_code;
  const because = rc !== null && Object.hasOwn(BECAUSE, rc) ? BECAUSE[rc] : undefined;
  return { verdict: because === undefined ? head + '.' : `${head} because ${because}.`, why, cause };
}
