// decide()/evaluate(): total, deterministic, order-independent (spec §6, §10). Never throw.
import { createHash } from 'node:crypto';
import { RequestError } from './errors.ts';
import { jcs } from './jcs.ts';
import { compiledPolicyOf } from './policy.ts';
import type { CompiledPolicy, CompiledRule, CompiledTool, LoadedPolicy, PolicyMode, ToolInfo } from './policy.ts';
import { evalPredicate, newEvalCtx, WorkBudgetExceeded } from './matchers.ts';
import type { ArgValue, EvalCtx } from './matchers.ts';
import { snapshotRequest } from './snapshot.ts';
import type { Request } from './snapshot.ts';

export type ReasonCode =
  | 'permitted'
  | 'denied_by_rule'
  | 'default_deny'
  | 'unknown_tool'
  | 'invalid_args'
  | 'invalid_request'
  | 'limit_exceeded'
  | 'tainted_session'
  | 'engine_error'
  | 'audit_unavailable';

export interface TraceEntry {
  readonly rule: string;
  readonly matched: boolean;
  readonly why: string;
}

export interface MatchedReason {
  readonly id: string;
  readonly effect: 'permit' | 'deny';
  readonly reason_code: string;
}

export interface Decision {
  readonly effect: 'permit' | 'deny';
  readonly reason_code: ReasonCode;
  readonly matched: { readonly deny: readonly string[]; readonly permit: readonly string[] };
  readonly matched_reasons: readonly MatchedReason[];
  readonly policy_version: string;
  readonly mode: PolicyMode;
  readonly request_digest: string | null;
  readonly trace: readonly TraceEntry[];
}

export interface Evaluation {
  readonly decision: Decision;
  /** The frozen snapshot the decision was made on; null if the snapshot step failed. Tools must receive this. */
  readonly snapshot: Request | null;
}

interface Extra {
  deny?: string[];
  permit?: string[];
  reasons?: MatchedReason[];
  trace?: TraceEntry[];
}

function result(
  effect: 'permit' | 'deny',
  reason: ReasonCode,
  version: string,
  mode: PolicyMode,
  digest: string | null,
  x: Extra = {},
): Decision {
  return Object.freeze({
    effect,
    reason_code: reason,
    matched: Object.freeze({ deny: Object.freeze(x.deny ?? []), permit: Object.freeze(x.permit ?? []) }),
    matched_reasons: Object.freeze((x.reasons ?? []).map((r) => Object.freeze(r))),
    policy_version: version,
    mode,
    request_digest: digest,
    trace: Object.freeze((x.trace ?? []).map((t) => Object.freeze(t))),
  });
}

function argTypeOk(type: string, v: unknown): boolean {
  switch (type) {
    case 'string': return typeof v === 'string';
    case 'number': return typeof v === 'number';
    case 'boolean': return typeof v === 'boolean';
    case 'string[]': return Array.isArray(v) && v.every((x) => typeof x === 'string');
    default: return false;
  }
}

/** Returns null if the rule matches, else a stable label for the first failing clause. */
function failingClause(rule: CompiledRule, req: Request, ec: EvalCtx): string | null {
  const { ctx, args } = req;
  if (rule.agents && !rule.agents.has(ctx.agentId)) return 'agents';
  if (rule.scopesAny) {
    const scopes = ctx.scopes ?? [];
    if (!scopes.some((s) => rule.scopesAny?.has(s) === true)) return 'scopes_any';
  }
  if (rule.tools && !rule.tools.has(req.tool)) return 'tools';
  if (rule.sessionTainted !== undefined && rule.sessionTainted !== (ctx.sessionTainted === true)) return 'session_tainted';
  for (const [name, pred] of rule.args) {
    if (!Object.hasOwn(args, name)) return `args.${name}:absent`;
    if (!evalPredicate(pred, args[name] as ArgValue, rule.effect, ec)) return `args.${name}`;
  }
  for (const [name, spec] of rule.provenance) {
    if (!Object.hasOwn(args, name)) return `provenance.${name}:absent`;
    const given = ctx.provenance !== undefined && Object.hasOwn(ctx.provenance, name) ? ctx.provenance[name] : undefined;
    const labels: readonly string[] = given !== undefined && given.length > 0 ? given : ['untrusted:unknown'];
    if (spec.allIn && !labels.every((l) => spec.allIn?.has(l) === true)) return `provenance.${name}`;
    if (spec.anyIn && !labels.some((l) => spec.anyIn?.has(l) === true)) return `provenance.${name}`;
  }
  return null;
}

function decideOnSnapshot(policy: CompiledPolicy, req: Request, digest: string): Decision {
  const { version, mode } = policy;
  const tool: CompiledTool | undefined = policy.tools.get(req.tool);
  if (tool === undefined) return result('deny', 'unknown_tool', version, mode, digest);

  for (const k of Object.keys(req.args)) {
    if (!tool.args.has(k)) return result('deny', 'invalid_args', version, mode, digest);
  }
  for (const [name, def] of tool.args) {
    if (!Object.hasOwn(req.args, name)) {
      if (!def.optional) return result('deny', 'invalid_args', version, mode, digest);
    } else if (!argTypeOk(def.type, req.args[name])) {
      return result('deny', 'invalid_args', version, mode, digest);
    }
  }
  if (req.ctx.provenance !== undefined) {
    for (const k of Object.keys(req.ctx.provenance)) {
      if (!tool.args.has(k)) return result('deny', 'invalid_request', version, mode, digest);
    }
  }

  const ec = newEvalCtx();
  const deny: string[] = [];
  const permit: string[] = [];
  const reasons: MatchedReason[] = [];
  const trace: TraceEntry[] = [];
  let taintedPermit = false;
  try {
    for (const rule of policy.rules) {
      const failed = failingClause(rule, req, ec);
      trace.push({ rule: rule.id, matched: failed === null, why: failed === null ? 'all_conditions_met' : `no_match:${failed}` });
      if (failed !== null) continue;
      reasons.push({ id: rule.id, effect: rule.effect, reason_code: rule.reasonCode });
      if (rule.effect === 'deny') deny.push(rule.id);
      else {
        permit.push(rule.id);
        if (rule.sessionTainted === true) taintedPermit = true;
      }
    }
  } catch (e) {
    if (e instanceof WorkBudgetExceeded) return result('deny', 'limit_exceeded', version, mode, digest);
    throw e;
  }
  const x: Extra = { deny, permit, reasons, trace };
  if (deny.length > 0) return result('deny', 'denied_by_rule', version, mode, digest, x);
  if (req.ctx.sessionTainted === true && tool.externalEffect) {
    if (taintedPermit) return result('permit', 'permitted', version, mode, digest, x);
    return result('deny', 'tainted_session', version, mode, digest, x);
  }
  if (permit.length > 0) return result('permit', 'permitted', version, mode, digest, x);
  return result('deny', 'default_deny', version, mode, digest, x);
}

/**
 * Snapshot once, decide on that snapshot. Never throws. Guards must pass `snapshot` (not the raw
 * object) to the tool.
 */
export function evaluate(policy: LoadedPolicy, raw: unknown): Evaluation {
  try {
    const compiled = compiledPolicyOf(policy);
    if (compiled === undefined) return { decision: result('deny', 'engine_error', 'unknown', 'enforce', null), snapshot: null };
    const { version, mode } = compiled;
    let snap: Request;
    try {
      snap = snapshotRequest(raw);
    } catch (e) {
      const code = e instanceof RequestError && e.code === 'limit_exceeded' ? 'limit_exceeded' : 'invalid_request';
      return { decision: result('deny', code, version, mode, null), snapshot: null };
    }
    try {
      const digest = 'sha256:' + createHash('sha256').update(jcs(snap), 'utf8').digest('hex');
      return { decision: decideOnSnapshot(compiled, snap, digest), snapshot: snap };
    } catch {
      return { decision: result('deny', 'engine_error', version, mode, null), snapshot: snap };
    }
  } catch {
    return { decision: result('deny', 'engine_error', 'unknown', 'enforce', null), snapshot: null };
  }
}

/** Never throws; any internal failure yields deny/engine_error. */
export function decide(policy: LoadedPolicy, request: unknown): Decision {
  return evaluate(policy, request).decision;
}

/** Tool metadata from the loaded policy, or undefined for non-loaded policies / unknown tools. */
export function toolInfo(policy: LoadedPolicy, name: string): ToolInfo | undefined {
  try {
    const c = compiledPolicyOf(policy);
    if (c === undefined || typeof name !== 'string') return undefined;
    const info = c.tools.get(name)?.info;
    return info === undefined ? undefined : Object.freeze({ ...info });
  } catch {
    return undefined;
  }
}
