// In-process guard (AUDIT-SPEC §2 + §4 + §5 amendments): the decision is audited durably BEFORE the tool runs;
// denied calls never reach the tool; the tool receives the frozen snapshot, never the caller's object.
// Tool results are UNTRUSTED data: only tools registered with taintsSession change session state.
//
// Documented properties:
// - `ctx: null` (and any non-plain-object, array, Proxy, or object with unknown keys incl. agentId/sessionId/timeoutMs)
//   is rejected as blocked `invalid_request`. ctx.provenance is host-asserted (trust boundary).
// - The permit path uses the full store busyTimeoutMs (a held write lock can stall a permitted call up to that long);
//   all best-effort rows (deny, pre-evaluate, tool_result) use the store's 250 ms-capped appendShort.
// - Session taint is in-memory only: it is not audited and is lost on restart.
// - The public split between denied / invalid_request / unavailable is an accepted small information oracle.
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomUUID } from 'node:crypto';
import { evaluate, jcs, toolInfo } from '../core/index.ts';
import type { LoadedPolicy, ToolInfo } from '../core/index.ts';
import { auditFailureLine, makeBestEffort, redactArgs } from '../store/index.ts';
import type { NewEvent, Store } from '../store/index.ts';

export interface ToolCallOptions {
  /** Aborted on tool timeout or guard.close(). */
  signal: AbortSignal;
  decisionId: string;
}
export type ToolFn = (args: never, opts: ToolCallOptions) => unknown;
export interface ToolEntry {
  fn: ToolFn;
  taintsSession?: boolean;
}
export type ToolRegistryInput = Record<string, ToolFn | ToolEntry>;

export interface CallContext {
  userId?: string;
  scopes?: string[];
  provenance?: Record<string, string[]>;
  sessionTainted?: boolean;
}

export type GuardResult =
  | { ok: true; value: unknown; decision_id: string }
  | {
      ok: false;
      blocked: true;
      decision_id: string;
      reason_code: 'denied' | 'unknown_tool' | 'invalid_request' | 'unavailable';
    }
  | { ok: false; blocked: false; decision_id: string; error: 'tool_error' | 'tool_timeout' };

export interface GuardSession {
  readonly id: string;
  /** Sticky: taint never reverts. In-memory only (not audited, lost on restart). The reason text is not stored. */
  taint(reason?: string): void;
  readonly tainted: boolean;
  call(tool: string, args: unknown, ctx?: CallContext): Promise<GuardResult>;
  /** Releases an untainted session; a tainted one is marked closed (later calls blocked `unavailable`). */
  close(): void;
}

export interface Guard {
  call(tool: string, args: unknown, ctx?: CallContext): Promise<GuardResult>;
  /** The same id returns the same session object (taint cannot be shed by re-opening). */
  session(sessionId?: string): GuardSession;
  /** Stops the guard (later calls blocked `unavailable`), aborts in-flight tool signals, writes the anchor line. */
  close(): void;
}

/**
 * Host-only facet. Whoever holds this object is trusted: give agent code only `guard.call` / `guard.session`.
 */
export interface GuardAdmin {
  /**
   * Atomically replaces the frozen tool registry (sessions and taint preserved). A durable policy_activate row
   * (`outcome.event = "tools_replaced"`) is appended BEFORE the swap; if that append fails, setTools throws and the
   * registry is unchanged.
   */
  setTools(tools: ToolRegistryInput, meta?: ToolsMeta): void;
  /**
   * Writes a best-effort deny decision row for a call to a tool the host chose not to expose (pre_evaluate budget,
   * dropped_before accounting). `enforcement` is "enforced" regardless of policy mode. Never executes anything.
   */
  denyUnexposed(toolName: unknown, reason: UnexposedReason): { decision_id: string };
}

export type UnexposedReason = 'schema_changed' | 'no_pin' | 'tool_not_offered' | 'not_ready';
/** Small descriptive fields merged into the tools_replaced row: <= 8 keys, integers / short strings, one nested level. */
export type ToolsMeta = Record<string, number | string | Record<string, number>>;
const UNEXPOSED = new Set<string>(['schema_changed', 'no_pin', 'tool_not_offered', 'not_ready']);
const META_KEY = /^[A-Za-z0-9_]{1,32}$/;

function checkMeta(meta: unknown): Record<string, unknown> {
  if (meta === undefined) return {};
  if (typeof meta !== 'object' || meta === null || Array.isArray(meta)) throw new TypeError('invalid meta');
  const keys = Object.keys(meta);
  if (keys.length > 8) throw new TypeError('invalid meta');
  const out: Record<string, unknown> = {};
  const scalar = (v: unknown): boolean => (typeof v === 'number' && Number.isSafeInteger(v)) || (typeof v === 'string' && v.length <= 64);
  for (const k of keys) {
    if (!META_KEY.test(k) || k === '__proto__') throw new TypeError('invalid meta');
    const v = (meta as Record<string, unknown>)[k];
    if (scalar(v)) { out[k] = v; continue; }
    if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
      const nk = Object.keys(v);
      if (nk.length > 8) throw new TypeError('invalid meta');
      const nested: Record<string, unknown> = {};
      for (const k2 of nk) {
        const v2 = (v as Record<string, unknown>)[k2];
        if (!META_KEY.test(k2) || k2 === '__proto__' || !(typeof v2 === 'number' && Number.isSafeInteger(v2))) throw new TypeError('invalid meta');
        nested[k2] = v2;
      }
      out[k] = nested;
      continue;
    }
    throw new TypeError('invalid meta');
  }
  return out;
}

export type GuardErrorCode = 'session_limit' | 'invalid_session_id';

export class GuardError extends Error {
  readonly code: GuardErrorCode;
  constructor(code: GuardErrorCode) {
    super('guard error: ' + code);
    this.name = 'GuardError';
    this.code = code;
  }
}

export interface CreateGuardOptions {
  policy: LoadedPolicy;
  store: Store;
  agentId: string;
  tools: ToolRegistryInput;
  secondarySink?: (line: string) => void;
  rawFields?: Record<string, string[]>;
  clock?: () => number;
  /** Per-call tool timeout (default none). */
  toolTimeoutMs?: number;
  /** Consecutive fail-open executions allowed (default 5; 0 disables fail-open). */
  failOpenBudget?: number;
  /** Per-window budgets for best-effort rows, one independent budget per class. */
  maxPreEvaluateRowsPerWindow?: number; // unknown tool, invalid request/ctx (default 200)
  maxDenyRowsPerWindow?: number; // policy denials (default 1000)
  maxResultRowsPerWindow?: number; // tool_result rows (default 1000)
  /** Window length for the rate limit (default 60000, hrtime-based). */
  bestEffortWindowMs?: number;
  /** Live-session cap (default 10000). */
  maxSessions?: number;
}

export const ENGINE_VERSION = 'prysm-engine/1';
export const FAIL_OPEN_BUDGET = 5;
export const MAX_CALL_DEPTH = 8;
const MAX_SESSIONS = 10_000;

type PublicReason = 'denied' | 'unknown_tool' | 'invalid_request' | 'unavailable';

const depthStore = new AsyncLocalStorage<number>();

const DEFAULT_INFO: ToolInfo = Object.freeze({ risk: 'high', external_effect: true, read_only: false, fail_mode: 'closed' });
const CTX_KEYS = new Set(['userId', 'scopes', 'provenance', 'sessionTainted']);
const UNTRUSTED = { _: 'untrusted:unknown' } as const;
const SAFE_CLASS = /^[A-Za-z0-9_]{1,64}$/;
const SESSION_ID = /^[A-Za-z0-9_.:-]{1,64}$/;
const SINK_BAD = new RegExp('[\\u0000-\\u001f\\u007f-\\u009f]|[\\uD800-\\uDBFF](?![\\uDC00-\\uDFFF])|(?<![\\uD800-\\uDBFF])[\\uDC00-\\uDFFF]', 'g');
const RESULT_MAX = 1024 * 1024;
const NOT_EXECUTED = new Set(['engine_error', 'invalid_args', 'invalid_request', 'limit_exceeded', 'unknown_tool', 'audit_unavailable']);

function publicReason(code: string): PublicReason {
  switch (code) {
    case 'denied_by_rule':
    case 'default_deny':
    case 'tainted_session':
      return 'denied';
    case 'unknown_tool':
      return 'unknown_tool';
    case 'invalid_args':
    case 'invalid_request':
    case 'limit_exceeded':
      return 'invalid_request';
    default:
      return 'unavailable';
  }
}

interface ParsedCtx {
  userId?: string;
  scopes?: string[];
  provenance?: Record<string, string[]>;
  sessionTainted: boolean;
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.length <= 256 && v.every((s) => typeof s === 'string');
}

/** Copies and strictly validates a per-call context. Returns null if invalid (incl. `null`). Synchronous. */
function parseCtx(input: unknown): ParsedCtx | null {
  if (input === undefined) return { sessionTainted: false };
  let c: unknown;
  try {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) return null;
    // structuredClone rejects Proxies/functions/symbols and yields a detached plain copy.
    c = structuredClone(input);
  } catch {
    return null;
  }
  if (typeof c !== 'object' || c === null) return null;
  const o = c as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!CTX_KEYS.has(k)) return null; // includes agentId, sessionId, timeoutMs
  const out: ParsedCtx = { sessionTainted: false };
  if (o['userId'] !== undefined) {
    if (typeof o['userId'] !== 'string') return null;
    out.userId = o['userId'];
  }
  if (o['scopes'] !== undefined) {
    if (!isStringArray(o['scopes'])) return null;
    out.scopes = o['scopes'];
  }
  if (o['sessionTainted'] !== undefined) {
    if (typeof o['sessionTainted'] !== 'boolean') return null;
    out.sessionTainted = o['sessionTainted'];
  }
  if (o['provenance'] !== undefined) {
    const p = o['provenance'];
    if (typeof p !== 'object' || p === null || Array.isArray(p)) return null;
    // null-prototype copy via defineProperty: a `__proto__` key stays an ordinary own key (core rejects it).
    const prov = Object.create(null) as Record<string, string[]>;
    for (const k of Object.keys(p)) {
      const v = (p as Record<string, unknown>)[k];
      if (!isStringArray(v)) return null;
      Object.defineProperty(prov, k, { value: v, enumerable: true, writable: true, configurable: true });
    }
    out.provenance = prov;
  }
  return out;
}

/** Cheap plain-JSON check with a node budget and a total string-byte cap (no classes, cycles, accessors). */
function isPlainJson(v: unknown): boolean {
  let budget = 100_000;
  let bytes = 0;
  const str = (s: string): boolean => {
    if (s.length > RESULT_MAX) return false;
    bytes += Buffer.byteLength(s, 'utf8');
    return bytes <= RESULT_MAX;
  };
  const walk = (x: unknown, depth: number): boolean => {
    if (--budget < 0 || depth > 32) return false;
    if (x === null || typeof x === 'boolean') return true;
    if (typeof x === 'string') return str(x);
    if (typeof x === 'number') return Number.isFinite(x);
    if (typeof x !== 'object') return false;
    if (Array.isArray(x)) {
      if (Object.getPrototypeOf(x) !== Array.prototype) return false;
      for (let i = 0; i < x.length; i++) if (!walk(x[i], depth + 1)) return false;
      return true;
    }
    const proto = Object.getPrototypeOf(x);
    if (proto !== Object.prototype && proto !== null) return false;
    for (const k of Object.keys(x)) {
      if (!str(k)) return false;
      const d = Object.getOwnPropertyDescriptor(x, k);
      if (d === undefined || !('value' in d)) return false;
      if (!walk(d.value, depth + 1)) return false;
    }
    return true;
  };
  return walk(v, 0);
}

interface SessionState {
  id: string;
  tainted: boolean;
  closed: boolean;
  ephemeral: boolean;
  inMap: boolean;
  handle?: GuardSession;
}

function cleanStr(s: string, max: number): string {
  return Array.from(s.replace(SINK_BAD, '�')).slice(0, max).join('');
}

/** Sink lines: single-line JSON, every string field sanitised and <= 64 chars (limits override per field). */
function sinkLine(o: Record<string, string | number | null>, limits: Record<string, number> = {}): string {
  const out: Record<string, string | number | null> = {};
  for (const [k, v] of Object.entries(o)) out[k] = typeof v === 'string' ? cleanStr(v, limits[k] ?? 64) : v;
  return JSON.stringify(out);
}

function validClock(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

type Registry = Readonly<Record<string, Readonly<{ fn: ToolFn; taintsSession: boolean }>>>;

function buildRegistry(input: ToolRegistryInput): Registry {
  if (typeof input !== 'object' || input === null) throw new TypeError('tools must be an object');
  const build = Object.create(null) as Record<string, Readonly<{ fn: ToolFn; taintsSession: boolean }>>;
  for (const [name, t] of Object.entries(input)) {
    const entry = typeof t === 'function' ? { fn: t, taintsSession: false } : t;
    if (typeof entry?.fn !== 'function') throw new TypeError('tool must be a function');
    build[name] = Object.freeze({ fn: entry.fn, taintsSession: entry.taintsSession === true });
  }
  return Object.freeze(build);
}

export function createGuardWithAdmin(opts: CreateGuardOptions): { guard: Guard; admin: GuardAdmin } {
  const { policy, store } = opts;
  if (typeof opts.agentId !== 'string' || opts.agentId === '') throw new TypeError('agentId required');
  const agentId = opts.agentId;
  if (typeof policy !== 'object' || policy === null || typeof policy.policy_version !== 'string') {
    throw new TypeError('policy must be a loaded policy');
  }
  const policyDoc = policy.document;
  if (typeof policyDoc !== 'object' || policyDoc === null || typeof policyDoc.tools !== 'object') {
    throw new TypeError('policy must be a loaded policy');
  }
  const sink = opts.secondarySink ?? ((line: string) => { process.stderr.write(line + '\n'); });
  const clock = opts.clock ?? Date.now;
  const rawFieldsByTool = new Map<string, readonly string[]>(Object.entries(opts.rawFields ?? {}));
  const toolTimeoutMs = opts.toolTimeoutMs;
  if (toolTimeoutMs !== undefined && (typeof toolTimeoutMs !== 'number' || !Number.isFinite(toolTimeoutMs) || toolTimeoutMs <= 0)) {
    throw new TypeError('toolTimeoutMs must be a positive number');
  }
  const failOpenBudget = opts.failOpenBudget ?? FAIL_OPEN_BUDGET;
  const caps = {
    pre_evaluate: opts.maxPreEvaluateRowsPerWindow ?? 200,
    policy_deny: opts.maxDenyRowsPerWindow ?? 1000,
    tool_result: opts.maxResultRowsPerWindow ?? 1000,
  } as const;
  const windowMs = opts.bestEffortWindowMs ?? 60_000;
  const maxSessions = opts.maxSessions ?? MAX_SESSIONS;
  if (!Number.isInteger(failOpenBudget) || failOpenBudget < 0 || !Object.values(caps).every((c) => Number.isInteger(c) && c >= 0) ||
    !(windowMs > 0) || !Number.isInteger(maxSessions) || maxSessions < 1) {
    throw new TypeError('invalid guard option');
  }

  const writeSink = (line: string): void => {
    try { sink(line); } catch { /* the sink must never change the outcome */ }
  };

  // Registry: copied and frozen; own-property lookups only. setTools replaces it atomically.
  let registry: Registry = buildRegistry(opts.tools);
  const inPolicy = (name: string): boolean => Object.hasOwn(policyDoc.tools, name);
  const policyArgNames = (tool: string): string[] => {
    const t = inPolicy(tool) ? policyDoc.tools[tool] : undefined;
    return t === undefined ? [] : Object.keys(t.args);
  };

  // --- policy activation (durable; failure is fatal) ---
  {
    // newest policy_activate row that carries outcome.policy_version (proxy_config / proxy_client / tools_replaced
    // rows are skipped); scan back over at most 50 policy_activate rows
    const prev = ((): ReturnType<Store['latest']> => {
      let hi = store.head()?.seq ?? 0;
      let seen = 0;
      for (let w = 0; w < 40 && hi > 0 && seen < 50; w++) {
        const lo = Math.max(0, hi - 500);
        const rows = store.query({ kind: 'policy_activate', afterSeq: lo, limit: 500 }).filter((r) => r.seq <= hi).sort((x, y) => y.seq - x.seq);
        for (const r of rows) {
          if (++seen > 50) return null;
          const o = r.outcome as { policy_version?: unknown } | null;
          if (o !== null && typeof o === 'object' && typeof o.policy_version === 'string') return r;
        }
        hi = lo;
      }
      return null;
    })();
    const po = prev?.outcome as { policy_version?: unknown; mode?: unknown } | null | undefined;
    if (po?.policy_version !== policy.policy_version || po?.mode !== policy.mode) {
      const names = Object.keys(policyDoc.tools).sort();
      let ts: unknown;
      try { ts = clock(); } catch { ts = undefined; }
      store.append({
        id: randomUUID(),
        kind: 'policy_activate',
        // an invalid guard clock must not stop creation: the store's own clock stamps the row
        ...(validClock(ts) ? { ts_ms: ts } : {}),
        agent_id: agentId,
        effect: null,
        tool: null,
        enforcement: policy.mode === 'monitor_only' ? 'monitor_only' : 'enforced',
        policy_version: policy.policy_version,
        engine_version: ENGINE_VERSION,
        outcome: {
          policy_version: policy.policy_version,
          mode: policy.mode,
          rule_count: Array.isArray(policyDoc.rules) ? policyDoc.rules.length : 0,
          tool_names_hash: createHash('sha256').update(jcs(names), 'utf8').digest('hex'),
        },
      });
    }
    if (policy.mode === 'monitor_only') {
      // policy_version is the one sink field allowed more than 64 chars (80)
      writeSink(sinkLine({ prysm: 'monitor_only', policy_version: policy.policy_version }, { policy_version: 80 }));
    }
  }

  const nowTs = (): number => {
    const t: unknown = clock();
    if (!validClock(t)) throw new Error('invalid clock');
    return t;
  };

  let closed = false;
  let counter = 0;
  let failOpenStreak = 0;
  const inflight = new Set<AbortController>();

  // Best-effort rows: store.appendShort (250 ms cap) through the circuit breaker, then a rate limit.
  const shortAppend = (ev: NewEvent) => (typeof store.appendShort === 'function' ? store.appendShort(ev) : store.append(ev));
  const breaker = makeBestEffort(shortAppend, writeSink);
  const hr = (): number => Number(process.hrtime.bigint() / 1_000_000n);
  type RowClass = 'pre_evaluate' | 'policy_deny' | 'tool_result';
  const classes: Record<RowClass, { used: number; dropped: number; lineWritten: boolean }> = {
    pre_evaluate: { used: 0, dropped: 0, lineWritten: false },
    policy_deny: { used: 0, dropped: 0, lineWritten: false },
    tool_result: { used: 0, dropped: 0, lineWritten: false },
  };
  let winStart = hr();
  const bestEffort = (ev: NewEvent, cls: RowClass): void => {
    try {
      const t = hr();
      if (t - winStart >= windowMs) {
        winStart = t;
        for (const c of Object.values(classes)) {
          c.used = 0;
          c.lineWritten = false;
        }
      }
      const c = classes[cls];
      if (c.used >= caps[cls]) {
        c.dropped++;
        if (!c.lineWritten) {
          c.lineWritten = true;
          writeSink(sinkLine({ prysm: 'audit_skipped', kind: 'rate_limit', class: cls, dropped: c.dropped }));
        }
        return;
      }
      c.used++;
      // the drop counts (per class, when non-zero) ride on the next row that is actually written
      const pending: Partial<Record<RowClass, number>> = {};
      for (const k of Object.keys(classes) as RowClass[]) if (classes[k].dropped > 0) pending[k] = classes[k].dropped;
      const hasPending = Object.keys(pending).length > 0;
      const out: NewEvent = hasPending
        ? { ...ev, outcome: { ...(typeof ev.outcome === 'object' && ev.outcome !== null ? ev.outcome : {}), dropped_before: pending } }
        : ev;
      if (breaker(out) !== null) {
        for (const k of Object.keys(pending) as RowClass[]) classes[k].dropped -= pending[k] as number;
      }
    } catch { /* best effort */ }
  };

  const blocked = (decision_id: string, reason_code: PublicReason): GuardResult => ({
    ok: false,
    blocked: true,
    decision_id,
    reason_code,
  });

  async function callImpl(sessState: SessionState | null, tool: unknown, args: unknown, ctxIn: unknown): Promise<GuardResult> {
    // Everything up to the first `await` is synchronous: caller-owned objects are copied here.
    const decision_id = randomUUID();
    const n = ++counter;
    const reg = registry;
    const depth = depthStore.getStore() ?? 0;
    const sess: SessionState = sessState ?? { id: 'eph-' + decision_id.slice(0, 8), tainted: false, closed: false, ephemeral: true, inMap: false };
    const execution_id = sess.id + '#' + String(n);
    const nameOk = typeof tool === 'string';
    let ev: NewEvent | null = null;
    let run: { fn: ToolFn; taintsSession: boolean; args: unknown } | null = null;
    let safeTool: string | null = null;
    try {
      if (closed || sess.closed) return blocked(decision_id, 'unavailable');
      const known = nameOk && (Object.hasOwn(reg, tool) || inPolicy(tool));
      safeTool = known ? tool : '?';
      const modeEnf = policy.mode === 'monitor_only' ? 'monitor_only' : 'enforced';
      const base = (): NewEvent => ({
        id: decision_id,
        kind: 'decision',
        ts_ms: nowTs(),
        execution_id,
        session_id: sess.id,
        agent_id: agentId,
        tool: safeTool,
        policy_version: policy.policy_version,
        engine_version: ENGINE_VERSION,
        enforcement: modeEnf,
        session_tainted: sess.tainted ? 1 : 0,
        provenance_asserted: UNTRUSTED,
      });
      const preReject = (reason: 'invalid_request' | 'unknown_tool' | 'engine_error'): GuardResult => {
        let outcome: unknown = { deny_n: 0 };
        if (!known) {
          try { outcome = { deny_n: 0, tool_hmac: store.hmac('tool', nameOk ? tool : 'non-string:' + typeof tool) }; } catch { outcome = { deny_n: 0 }; }
        }
        bestEffort({
          ...base(), effect: 'deny', reason_code: reason, rule_ids: [], request_digest: null, args_hmac: null,
          args_redacted: null, outcome,
        }, 'pre_evaluate');
        return blocked(decision_id, reason === 'engine_error' ? 'unavailable' : reason);
      };

      // Re-entrancy guard (a tool calling guard.call recursively).
      if (depth >= MAX_CALL_DEPTH) return preReject('engine_error');

      // (a) CallContext, (b) own-property tool lookup, (c) evaluate.
      const ctx = parseCtx(ctxIn);
      if (ctx === null || !nameOk) return preReject('invalid_request');
      if (!Object.hasOwn(reg, tool)) return preReject('unknown_tool');
      const entry = reg[tool];
      if (entry === undefined) return preReject('unknown_tool');

      const tainted = sess.tainted || ctx.sessionTainted;
      const reqCtx: Record<string, unknown> = { agentId, sessionTainted: tainted };
      if (ctx.userId !== undefined) reqCtx['userId'] = ctx.userId;
      if (ctx.scopes !== undefined) reqCtx['scopes'] = ctx.scopes;
      if (ctx.provenance !== undefined) reqCtx['provenance'] = ctx.provenance;

      const t0 = process.hrtime.bigint();
      const { decision, snapshot } = evaluate(policy, { tool, args, ctx: reqCtx });
      const latency_us = Number((process.hrtime.bigint() - t0) / 1000n);

      const info: ToolInfo = toolInfo(policy, tool) ?? DEFAULT_INFO;
      const effect = decision.effect;
      const reason: string = decision.reason_code;
      const monitor = decision.mode === 'monitor_only';
      const allowedKeys = policyArgNames(tool);
      let prov: unknown = UNTRUSTED;
      const sp = snapshot?.ctx.provenance;
      if (sp !== undefined && Object.keys(sp).length > 0) {
        const declared = new Set(allowedKeys);
        let u = 0;
        const o: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(sp)) {
          if (declared.has(k)) o[k] = v;
          else u++;
        }
        if (u > 0) o['_undeclared'] = u;
        prov = o;
      }
      const willExecute = snapshot !== null &&
        !NOT_EXECUTED.has(reason) &&
        (monitor || effect === 'permit');
      const decisionEvent: NewEvent = {
        ...base(),
        enforcement: monitor ? 'monitor_only' : 'enforced',
        user_hmac: ctx.userId === undefined ? null : store.hmac('user', ctx.userId),
        effect,
        rule_ids: [...decision.matched.deny, ...decision.matched.permit],
        reason_code: reason,
        policy_version: decision.policy_version,
        request_digest: decision.request_digest === null ? null : store.hmac('request', decision.request_digest),
        args_hmac: snapshot === null ? null : store.hmac('args', jcs(snapshot.args)),
        args_redacted: snapshot === null
          ? null
          : redactArgs(snapshot.args, { rawFields: rawFieldsByTool.get(tool) ?? [], allowedKeys }),
        risk: info.risk,
        latency_us,
        session_tainted: tainted ? 1 : 0,
        provenance_asserted: prov,
        outcome: willExecute ? { deny_n: decision.matched.deny.length, will_execute: true } : { deny_n: decision.matched.deny.length },
      };
      ev = decisionEvent;

      if (!willExecute || snapshot === null) {
        bestEffort(decisionEvent, 'policy_deny');
        return blocked(decision_id, publicReason(reason));
      }

      // Durable decision row BEFORE the tool runs (full store busy timeout; never rate-limited).
      try {
        store.append(decisionEvent);
        failOpenStreak = 0;
      } catch (e) {
        const code = (e as { code?: unknown } | null)?.code;
        const okCode = code === 'busy' || code === 'io' || code === 'invalid_event' || code === 'corrupt' ||
          code === 'duplicate_id' || code === 'key_invalid' || code === 'key_mismatch' ? code : 'unknown';
        writeSink(auditFailureLine(okCode, decisionEvent));
        // fail-open only for busy/io, only low-risk read-only open_on_audit_failure tools, within the budget
        const openOk = info.fail_mode === 'open_on_audit_failure' && info.risk === 'low' && info.read_only &&
          (okCode === 'busy' || okCode === 'io');
        if (!openOk || failOpenStreak >= failOpenBudget) return blocked(decision_id, 'unavailable');
        failOpenStreak++;
        writeSink(sinkLine({ prysm: 'fail_open', tool, decision_id, code: okCode }));
      }
      run = { fn: entry.fn, taintsSession: entry.taintsSession, args: snapshot.args };
    } catch {
      // Unexpected guard failure: treated as engine_error. Never execute.
      try {
        bestEffort({
          ...(ev ?? {
            id: decision_id, kind: 'decision' as const, execution_id, session_id: sess.id, agent_id: agentId,
            tool: safeTool, policy_version: policy.policy_version, engine_version: ENGINE_VERSION,
          }),
          effect: 'deny', reason_code: 'engine_error', rule_ids: [], outcome: { deny_n: 0 },
        }, 'policy_deny');
      } catch { /* nothing more can be done */ }
      return blocked(decision_id, 'unavailable');
    }

    // --- execute (frozen snapshot args) ---
    let status: 'ok' | 'error' | 'timeout' = 'ok';
    let value: unknown;
    let errorClass: string | undefined;
    const ac = new AbortController();
    inflight.add(ac);
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const f = run.fn;
      const p: Promise<unknown> = depthStore.run(depth + 1, () => {
        try {
          return Promise.resolve(f(run.args as never, { signal: ac.signal, decisionId: decision_id }));
        } catch (e) {
          return Promise.reject(e);
        }
      });
      p.catch(() => { /* a late rejection after a timeout must not become unhandled */ });
      if (toolTimeoutMs !== undefined) {
        const timeout = new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            status = 'timeout';
            ac.abort();
            reject(new Error('timeout'));
          }, toolTimeoutMs);
        });
        value = await Promise.race([p, timeout]);
      } else {
        value = await p;
      }
    } catch (e) {
      if ((status as string) !== 'timeout') {
        status = 'error';
        let cls = 'NonError';
        try {
          if (e instanceof Error) {
            const name = (e as { constructor?: { name?: unknown } }).constructor?.name;
            cls = typeof name === 'string' && SAFE_CLASS.test(name) ? name : 'Unknown';
          }
        } catch { cls = 'Unknown'; }
        errorClass = cls;
      }
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      inflight.delete(ac);
    }
    // Taint synchronously as soon as the tool resolves (before the result row and before returning).
    if (status === 'ok' && run.taintsSession) markTainted(sess);

    // Result digest: types, lengths and keyed digest only; never the value.
    const outcome: Record<string, unknown> = { status };
    if (errorClass !== undefined) outcome['error_class'] = errorClass;
    if (status === 'ok') {
      let rtype = 'other';
      const v = value;
      if (v === null) rtype = 'null';
      else if (Array.isArray(v)) rtype = 'array';
      else if (['string', 'number', 'boolean', 'object', 'undefined', 'bigint'].includes(typeof v)) rtype = typeof v;
      outcome['result_type'] = rtype;
      let len: number | null = null;
      let digest: string | null = null;
      try {
        if (isPlainJson(v)) {
          const s = jcs(v);
          if (s.length <= RESULT_MAX) {
            len = s.length;
            digest = store.hmac('result', s);
          }
        }
      } catch {
        len = null;
        digest = null;
      }
      outcome['result_len'] = len;
      outcome['result_hmac'] = digest;
    }
    try {
      bestEffort({
        id: randomUUID(),
        kind: 'tool_result',
        ts_ms: nowTs(),
        execution_id,
        session_id: sess.id,
        agent_id: agentId,
        tool: safeTool,
        decision_id,
        policy_version: policy.policy_version,
        engine_version: ENGINE_VERSION,
        outcome,
      }, 'tool_result');
    } catch { /* best effort (e.g. invalid clock) */ }
    if ((status as string) === 'timeout') return { ok: false, blocked: false, decision_id, error: 'tool_timeout' };
    if (status === 'error') return { ok: false, blocked: false, decision_id, error: 'tool_error' };
    return { ok: true, value, decision_id };
  }

  // --- sessions: LRU of untainted sessions at the cap; tainted sessions are never evicted ---
  const sessions = new Map<string, SessionState>();

  /** One registered state per id; a handle resolves through the map on every use (taint merged both ways). */
  function resolveState(own: SessionState): SessionState {
    const cur = sessions.get(own.id);
    if (cur === undefined) {
      sessions.set(own.id, own); // evicted: the handle re-registers its own state
      own.inMap = true;
      return own;
    }
    if (cur !== own) {
      if (own.tainted) cur.tainted = true;
      if (cur.tainted) own.tainted = true;
      return cur;
    }
    sessions.delete(own.id); // LRU touch
    sessions.set(own.id, own);
    return cur;
  }

  function peekTainted(own: SessionState): boolean {
    const cur = sessions.get(own.id);
    if (cur !== undefined && cur !== own) {
      if (own.tainted) cur.tainted = true;
      if (cur.tainted) own.tainted = true;
    }
    return own.tainted;
  }

  function markTainted(s: SessionState): void {
    s.tainted = true;
    if (s.ephemeral) return;
    if (!s.inMap) {
      const cur = sessions.get(s.id);
      if (cur !== undefined) cur.tainted = true; // same id re-created after eviction: taint follows the id
      else {
        sessions.set(s.id, s);
        s.inMap = true;
      }
    }
  }

  function evictOne(): boolean {
    for (const [id, s] of sessions) {
      if (!s.tainted) {
        sessions.delete(id);
        s.inMap = false;
        return true;
      }
    }
    return false;
  }

  const guard: Guard = {
    call: (tool, args, ctx) => callImpl(null, tool, args, ctx),
    session: (sessionId?: string): GuardSession => {
      const id = sessionId === undefined ? randomUUID() : sessionId;
      if (typeof id !== 'string' || !SESSION_ID.test(id)) throw new GuardError('invalid_session_id');
      const existing = sessions.get(id);
      if (existing?.handle !== undefined) {
        resolveState(existing);
        return existing.handle;
      }
      if (sessions.size >= maxSessions && !evictOne()) throw new GuardError('session_limit');
      const state: SessionState = { id, tainted: false, closed: false, ephemeral: false, inMap: true };
      const handle: GuardSession = Object.freeze({
        id,
        taint: (_reason?: string): void => {
          markTainted(state);
        },
        get tainted(): boolean {
          return peekTainted(state);
        },
        call: (tool: string, args: unknown, ctx?: CallContext) =>
          callImpl(state.closed ? state : resolveState(state), tool, args, ctx),
        close: (): void => {
          state.closed = true;
          if (!peekTainted(state) && state.inMap && sessions.get(state.id) === state) {
            sessions.delete(state.id);
            state.inMap = false;
          }
        },
      });
      state.handle = handle;
      sessions.set(id, state);
      return handle;
    },
    close: (): void => {
      if (closed) return;
      closed = true;
      for (const ac of inflight) {
        try { ac.abort(); } catch { /* ignore */ }
      }
      try {
        const a = store.anchor();
        writeSink(sinkLine({ prysm: 'anchor', genesis_hash: a.genesis_hash, head_seq: a.head_seq, head_hash: a.head_hash }));
      } catch { /* store may already be closed */ }
    },
  };
  const admin: GuardAdmin = Object.freeze({
    setTools: (tools: ToolRegistryInput, meta?: ToolsMeta): void => {
      const next = buildRegistry(tools); // throws before anything else happens
      const extra = checkMeta(meta);
      const names = Object.keys(next).sort();
      // durable, audited row BEFORE the swap; a failure leaves the registry unchanged
      store.append({
        id: randomUUID(),
        kind: 'policy_activate',
        ts_ms: nowTs(),
        agent_id: agentId,
        effect: null,
        tool: null,
        enforcement: policy.mode === 'monitor_only' ? 'monitor_only' : 'enforced',
        policy_version: policy.policy_version,
        engine_version: ENGINE_VERSION,
        outcome: {
          ...extra,
          event: 'tools_replaced',
          tool_names_hash: createHash('sha256').update(jcs(names), 'utf8').digest('hex'),
          policy_version: policy.policy_version,
          mode: policy.mode,
        },
      });
      registry = next;
    },
    denyUnexposed: (toolName: unknown, reason: UnexposedReason): { decision_id: string } => {
      const decision_id = randomUUID();
      if (closed) return { decision_id }; // after close(): no row, id only
      try {
        const n = ++counter;
        const nameOk = typeof toolName === 'string';
        const known = nameOk && inPolicy(toolName);
        const outcome: Record<string, unknown> = { deny_n: 0, reason: UNEXPOSED.has(reason) ? reason : 'tool_not_offered' };
        if (!known) {
          try { outcome['tool_hmac'] = store.hmac('tool', nameOk ? toolName : 'non-string:' + typeof toolName); } catch { /* none */ }
        }
        bestEffort({
          id: decision_id, kind: 'decision', ts_ms: nowTs(), execution_id: 'admin#' + String(n), session_id: null, agent_id: agentId,
          tool: known ? toolName : '?', policy_version: policy.policy_version, engine_version: ENGINE_VERSION,
          enforcement: 'enforced', effect: 'deny', reason_code: 'unknown_tool', rule_ids: [], request_digest: null,
          args_hmac: null, args_redacted: null, session_tainted: 0, provenance_asserted: UNTRUSTED, outcome,
        }, 'pre_evaluate');
      } catch { /* best effort */ }
      return { decision_id };
    },
  });
  return Object.freeze({ guard: Object.freeze(guard), admin });
}

/** Returns only the agent-facing guard (no admin facet). */
export function createGuard(opts: CreateGuardOptions): Guard {
  return createGuardWithAdmin(opts).guard;
}
