// PRYSM MCP stdio proxy (PROXY-SPEC.md v1.1). Only `tools/call` is policy-enforced, through the in-process guard.
// The arguments forwarded to the server are exactly the snapshot the guard hands the tool function.
// Server output is untrusted data. stdout of the proxy carries protocol messages only.
import { spawn as nodeSpawn, spawnSync } from 'node:child_process';
import type { ChildProcess, SpawnOptions } from 'node:child_process';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { Readable, Writable } from 'node:stream';
import { jcs, loadPolicy } from '../core/index.ts';
import type { LoadedPolicy } from '../core/index.ts';
import { openStore } from '../store/index.ts';
import type { Store } from '../store/index.ts';
import { createGuardWithAdmin, ENGINE_VERSION } from '../guard/index.ts';
import type { CallContext, GuardResult, ToolCallOptions, ToolEntry } from '../guard/index.ts';
import { LineSplitter } from './lines.ts';

export const MAX_CLIENT_LINE = 1024 * 1024;
export const MAX_SERVER_LINE = 16 * 1024 * 1024; // default; configurable up to MAX_SERVER_LINE_LIMIT
export const MAX_SERVER_LINE_LIMIT = 64 * 1024 * 1024;
const MAX_LIST_BYTES = 8 * 1024 * 1024;
const TOKEN_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const IDENT_RE = /^[A-Za-z0-9_.:-]{1,64}$/;

/** Serialises one protocol line; U+2028/2029/0085 are escaped so line-splitting readers cannot desynchronise. */
export function serializeLine(m: unknown): string {
  return JSON.stringify(m).replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029').replace(/\u0085/g, '\\u0085');
}
const validToken = (t: unknown): t is string | number =>
  (typeof t === 'string' && TOKEN_RE.test(t)) || (typeof t === 'number' && Number.isSafeInteger(t) && t >= 0);
const shortStr = (v: unknown, max: number, dflt: string): string =>
  typeof v === 'string' && v.length > 0 && v.length <= max ? v.replace(/[^\x20-\x7e]/g, '?') : dflt;
const MAX_PAGES = 20;
const MAX_TOOLS = 2000;
const MAX_CALLS = 64;
const MAX_WAITERS = 64;
const MAX_INFLIGHT = 1024;
const MAX_SERVER_REQS = 256;
const TOOL_NAME = /^[A-Za-z0-9_.:-]{1,64}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const METHOD_NAME = /^[a-z][a-z0-9_]*(\/[A-Za-z0-9_/-]+)?$/;
const LABEL = /^[A-Za-z0-9_.:-]{1,64}$/;
const ARG_NAME = /^[A-Za-z0-9_.-]{1,64}$/;
const BASE_ENV = ['PATH', 'SYSTEMROOT', 'HOME', 'USERPROFILE', 'TEMP', 'TMP', ...(process.platform === 'win32' ? ['ComSpec', 'PATHEXT', 'windir', 'SystemDrive'] : [])];
const HANDLED_METHODS = new Set([
  'initialize', 'ping', 'tools/list', 'tools/call', 'notifications/initialized', 'notifications/cancelled',
  'notifications/progress', 'notifications/tools/list_changed',
]);
const HEX64 = /^[0-9a-fA-F]{64}$/;
const LIST_FIELDS = ['name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations'];

export type ProxyConfigErrorCode =
  | 'bad_option' | 'policy_unreadable' | 'policy_invalid' | 'policy_sha256_mismatch' | 'taint_tool_unknown'
  | 'store_unavailable' | 'spawn_failed';

export class ProxyConfigError extends Error {
  readonly code: ProxyConfigErrorCode;
  constructor(code: ProxyConfigErrorCode) {
    super('proxy config error: ' + code);
    this.name = 'ProxyConfigError';
    this.code = code;
  }
}

export type SpawnFn = (command: string, args: string[], options: SpawnOptions) => ChildProcess;

export interface ProxyOptions {
  policyPath: string;
  dbPath: string;
  keyPath?: string;
  agentId?: string;
  policySha256?: string;
  taintTools?: string[];
  toolTimeoutMs?: number;
  listMode?: 'hide' | 'show';
  allowMethods?: string[];
  env?: string[];
  /** Host-supplied identity (never read from the client). */
  userId?: string;
  scopes?: string[];
  /** DANGEROUS host assertion: argName -> labels. The client controls argument values. */
  provenance?: Record<string, string[]>;
  requirePins?: boolean;
  readyTimeoutMs?: number;
  allowServerRequests?: string[];
  allowServerNotifications?: boolean;
  maxServerLineBytes?: number;
  forwardTimeoutMs?: number;
  server: { command: string; args?: string[] };
  clientIn: Readable;
  clientOut: Writable;
  /** PRYSM sink lines and the (prefixed) server stderr go here (default process.stderr). */
  stderr?: Writable;
  /** Test seams. */
  spawn?: SpawnFn;
  hmacKey?: Uint8Array;
  processEnv?: Record<string, string | undefined>;
  listTimeoutMs?: number;
  killGraceMs?: number;
  /** Output buffer full (no drain) for longer than this => shutdown, exit 1 (default 30000). */
  clientStallMs?: number;
  storeWrap?: (s: Store) => Store;
}

export interface ProxyHandle {
  /** Exit code: 0 clean, 1 server exit/crash/oversize/stdout closed, 3 server cannot be spawned. Never rejects. */
  readonly done: Promise<number>;
  readonly sessionId: string;
  /** Orderly shutdown (same path as client EOF; used for SIGINT/SIGTERM). Resolves when `done` is settled. */
  stop(): Promise<void>;
  /** Emergency stop (uncaught exception): proxy_fatal sink line, kills the server, touches nothing else. */
  fatal(): void;
}

type Msg = Record<string, unknown>;

class ServerExitError extends Error {}
class OversizeError extends Error {}
class CancelledError extends Error {}
class ServerToolError extends Error {}
class ServerShapeError extends Error {}

interface Entry {
  kind: 'call' | 'other';
  ctl: AbortController;
  serverId?: string;
  progressToken?: string | number;
}

function isPlain(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
const idOrNull = (v: unknown): string | number | null =>
  typeof v === 'string' || (typeof v === 'number' && Number.isFinite(v)) ? v : null;

/** definition_hash = sha256(JCS({name, description, inputSchema})); absent keys are omitted. */
export function definitionHash(tool: { name: string; description?: unknown; inputSchema?: unknown }): string {
  const o: Record<string, unknown> = { name: tool.name };
  if (tool.description !== undefined) o['description'] = tool.description;
  if (tool.inputSchema !== undefined) o['inputSchema'] = tool.inputSchema;
  return createHash('sha256').update(jcs(o), 'utf8').digest('hex');
}

/** Iterative scan (no recursion): true when a top-level key of an already-valid JSON object text repeats. */
export function hasDuplicateTopKeys(s: string): boolean {
  let depth = 0;
  let expectKey = false;
  const seen = new Set<string>();
  const n = s.length;
  let i = 0;
  while (i < n) {
    const c = s[i];
    if (c === '"') {
      let j = i + 1;
      while (j < n && s[j] !== '"') {
        if (s[j] === '\\') j++;
        j++;
      }
      if (depth === 1 && expectKey) {
        const key = JSON.parse(s.slice(i, j + 1)) as string;
        if (seen.has(key)) return true;
        seen.add(key);
        expectKey = false;
      }
      i = j + 1;
      continue;
    }
    if (c === '{' || c === '[') {
      depth++;
      if (depth === 1 && c === '{') expectKey = true;
    } else if (c === '}' || c === ']') depth--;
    else if (c === ',' && depth === 1) expectKey = true;
    i++;
  }
  return false;
}

function cfg(code: ProxyConfigErrorCode): never {
  throw new ProxyConfigError(code);
}

function buildServerEnv(extra: readonly string[], src: Record<string, string | undefined>): Record<string, string> {
  const ci = process.platform === 'win32';
  const norm = (s: string): string => (ci ? s.toUpperCase() : s);
  const allow = new Set([...BASE_ENV, ...extra].map(norm));
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(src)) if (v !== undefined && allow.has(norm(k))) env[k] = v;
  return env;
}

function methodList(list: readonly string[] | undefined): Set<string> {
  const out = new Set<string>();
  for (const m of list ?? []) {
    if (typeof m !== 'string' || !METHOD_NAME.test(m) || m.length > 128 || HANDLED_METHODS.has(m)) cfg('bad_option');
    out.add(m);
  }
  return out;
}

export function createProxy(opts: ProxyOptions): ProxyHandle {
  // ---------------------------------------------------------------- options
  const stderr = opts.stderr ?? process.stderr;
  const agentId = opts.agentId ?? 'prysm-proxy';
  if (typeof agentId !== 'string' || agentId === '' || agentId.length > 64) cfg('bad_option');
  const toolTimeoutMs = opts.toolTimeoutMs ?? 60_000;
  if (!Number.isInteger(toolTimeoutMs) || toolTimeoutMs <= 0) cfg('bad_option');
  const readyTimeoutMs = opts.readyTimeoutMs ?? 10_000;
  if (!Number.isInteger(readyTimeoutMs) || readyTimeoutMs <= 0) cfg('bad_option');
  const listMode = opts.listMode ?? 'hide';
  if (listMode !== 'hide' && listMode !== 'show') cfg('bad_option');
  const allowMethods = methodList(opts.allowMethods);
  const allowServerRequests = methodList(opts.allowServerRequests);
  if (allowMethods.size > 32 || allowServerRequests.size > 32) cfg('bad_option');
  const allowServerNotifications = opts.allowServerNotifications === true;
  const requirePins = opts.requirePins === true;
  for (const n of opts.env ?? []) if (typeof n !== 'string' || !ENV_NAME.test(n)) cfg('bad_option');
  if (typeof opts.server?.command !== 'string' || opts.server.command === '') cfg('bad_option');
  const serverArgs = opts.server.args ?? [];
  if (!Array.isArray(serverArgs) || !serverArgs.every((a) => typeof a === 'string')) cfg('bad_option');
  const listTimeoutMs = opts.listTimeoutMs ?? 10_000;
  const killGraceMs = opts.killGraceMs ?? 2000;
  const maxServerLine = opts.maxServerLineBytes ?? MAX_SERVER_LINE;
  if (!Number.isInteger(maxServerLine) || maxServerLine < 1024 || maxServerLine > MAX_SERVER_LINE_LIMIT) cfg('bad_option');
  const clientStallMs = opts.clientStallMs ?? 30_000;
  if (!Number.isInteger(clientStallMs) || clientStallMs <= 0) cfg('bad_option');
  const forwardTimeoutMs = opts.forwardTimeoutMs ?? 30_000;
  if (!Number.isInteger(forwardTimeoutMs) || forwardTimeoutMs <= 0) cfg('bad_option');
  if (opts.agentId !== undefined && !IDENT_RE.test(agentId)) cfg('bad_option');
  if (opts.policySha256 !== undefined && !HEX64.test(opts.policySha256)) cfg('bad_option');
  // host identity: the only source of ctx.userId / scopes / provenance
  const hostCtx: CallContext = {};
  if (opts.userId !== undefined) {
    if (typeof opts.userId !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(opts.userId)) cfg('bad_option');
    hostCtx.userId = opts.userId;
  }
  if (opts.scopes !== undefined) {
    if (!Array.isArray(opts.scopes) || opts.scopes.length > 64 || !opts.scopes.every((s) => typeof s === 'string' && IDENT_RE.test(s))) cfg('bad_option');
    hostCtx.scopes = [...opts.scopes];
  }
  const provNames = Object.keys(opts.provenance ?? {});
  if (provNames.length > 32) cfg('bad_option');
  if (opts.provenance !== undefined && provNames.length > 0) {
    const prov: Record<string, string[]> = {};
    for (const k of provNames) {
      const labels = opts.provenance[k];
      if (!ARG_NAME.test(k) || !Array.isArray(labels) || labels.length === 0 || !labels.every((l) => typeof l === 'string' && LABEL.test(l))) cfg('bad_option');
      Object.defineProperty(prov, k, { value: [...labels], enumerable: true, writable: true, configurable: true });
    }
    hostCtx.provenance = prov;
  }

  // ---------------------------------------------------------------- policy (bytes read once)
  let bytes: Buffer;
  try { bytes = readFileSync(opts.policyPath); } catch { return cfg('policy_unreadable'); }
  if (opts.policySha256 !== undefined) {
    if (createHash('sha256').update(bytes).digest('hex') !== opts.policySha256.toLowerCase()) cfg('policy_sha256_mismatch');
  }
  let policy: LoadedPolicy;
  try { policy = loadPolicy(bytes); } catch { return cfg('policy_invalid'); }
  const policyTools = policy.document.tools;
  const inPolicy = (n: string): boolean => Object.hasOwn(policyTools, n);
  for (const k of provNames) {
    if (!Object.values(policyTools).some((t) => Object.hasOwn(t.args, k))) cfg('bad_option');
  }
  const taintSet = new Set<string>(opts.taintTools ?? []);
  for (const t of taintSet) if (typeof t !== 'string' || !inPolicy(t)) cfg('taint_tool_unknown');

  const sink = (line: string): void => {
    try { stderr.write(line + '\n'); } catch { /* the sink must never change the outcome */ }
  };
  const proxyLine = (kind: string, fields: Record<string, string | number | null> = {}): void => {
    sink(JSON.stringify({ prysm: kind, ...fields }));
  };

  let store: Store;
  try {
    const raw = openStore({
      path: opts.dbPath,
      ...(opts.keyPath !== undefined ? { keyPath: opts.keyPath } : {}),
      ...(opts.hmacKey !== undefined ? { hmacKey: opts.hmacKey } : {}),
      secondarySink: sink,
    });
    store = opts.storeWrap ? opts.storeWrap(raw) : raw;
  } catch { return cfg('store_unavailable'); }

  // ---------------------------------------------------------------- guard + session
  const als = new AsyncLocalStorage<Entry>();
  const { guard, admin } = createGuardWithAdmin({
    policy, store, agentId, tools: {}, secondarySink: sink, toolTimeoutMs,
  });
  const session = guard.session();
  const sessionId = session.id;
  for (const a of provNames) proxyLine('proxy_provenance_asserted', { arg: a });
  {
    const unpinned = Object.values(policyTools).filter((t) => t.schema_hash === undefined).length;
    if (unpinned > 0) proxyLine('proxy_unpinned_tools', { n: unpinned });
    // durable posture row (audited start configuration); failure to write it is fatal at startup
    try {
      store.append({
        id: randomUUID(), kind: 'policy_activate', ts_ms: Date.now(), agent_id: agentId, effect: null, tool: null,
        enforcement: policy.mode === 'monitor_only' ? 'monitor_only' : 'enforced', policy_version: policy.policy_version,
        engine_version: ENGINE_VERSION,
        outcome: {
          event: 'proxy_config', policy_mode: policy.mode, list_mode: listMode, require_pins: requirePins,
          tool_timeout_ms: toolTimeoutMs, taint_tools_n: taintSet.size, allow_methods: [...allowMethods],
          allow_server_requests: [...allowServerRequests], allow_server_notifications: allowServerNotifications,
          provenance_args: [...provNames], scopes_n: hostCtx.scopes?.length ?? 0, user_set: hostCtx.userId !== undefined,
        },
      });
    } catch {
      try { guard.close(); store.close(); } catch { /* ignore */ }
      return cfg('store_unavailable');
    }
  }

  // ---------------------------------------------------------------- server
  const spawnFn: SpawnFn = opts.spawn ?? nodeSpawn;
  let child: ChildProcess;
  try {
    child = spawnFn(opts.server.command, [...serverArgs], {
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      env: buildServerEnv(opts.env ?? [], opts.processEnv ?? process.env),
    });
  } catch {
    try { guard.close(); store.close(); } catch { /* ignore */ }
    return cfg('spawn_failed');
  }
  child.stdin?.on('error', () => { /* a dead server must not throw */ });
  child.stdout?.on('error', () => { /* ignore */ });
  child.stderr?.on('error', () => { /* ignore */ });

  let serverDead = false;
  let shuttingDown = false; // set by whichever shutdown path starts first
  let muteOutput = false; // client EOF: nothing more is written
  let resolveDone!: (n: number) => void;
  const done = new Promise<number>((r) => { resolveDone = r; });
  let resolveGone!: () => void;
  const serverGone = new Promise<void>((r) => { resolveGone = r; });
  const tasks = new Set<Promise<unknown>>();
  const track = (p: Promise<unknown>): void => {
    const q = p.catch(() => undefined).finally(() => { tasks.delete(q); });
    tasks.add(q);
  };

  // ---------------------------------------------------------------- output to the client (with backpressure)
  let paused = false;
  let stallTimer: ReturnType<typeof setTimeout> | undefined;
  const resumeAll = (): void => {
    if (!paused) return;
    paused = false;
    if (stallTimer !== undefined) { clearTimeout(stallTimer); stallTimer = undefined; }
    opts.clientOut.removeListener('drain', resumeAll);
    opts.clientOut.removeListener('close', resumeAll);
    child.stdout?.resume();
    opts.clientIn.resume();
  };
  const writeClient = (m: Msg): void => {
    if (muteOutput) return;
    try {
      if (!opts.clientOut.write(serializeLine(m) + '\n') && !paused) {
        // stop reading BOTH the server's stdout and the client's stdin until the client output drains
        paused = true;
        child.stdout?.pause();
        opts.clientIn.pause();
        opts.clientOut.once('drain', resumeAll);
        opts.clientOut.once('close', resumeAll);
        // a client that never drains must not keep the proxy alive
        stallTimer = setTimeout(() => {
          stallTimer = undefined;
          if (shuttingDown) return;
          proxyLine('proxy_client_stalled');
          void onClientEnd(1);
        }, clientStallMs);
      }
    } catch { /* ignore */ }
  };
  const respond = (id: unknown, result: unknown): void => writeClient({ jsonrpc: '2.0', id, result });
  const respondError = (id: unknown, code: number, message: string): void =>
    writeClient({ jsonrpc: '2.0', id, error: { code, message } });
  const blockedResult = (reason: string, decision: string): unknown => ({
    isError: true,
    content: [{ type: 'text', text: `Blocked by PRYSM policy: ${reason} (decision ${decision})` }],
  });
  const errorResult = (text: string): unknown => ({ isError: true, content: [{ type: 'text', text }] });

  // ---------------------------------------------------------------- output to the server
  const writeServer = (m: Msg): boolean => {
    const s = child.stdin;
    if (serverDead || s === null || s === undefined || s.destroyed || s.writableEnded) return false;
    try { s.write(serializeLine(m) + '\n'); return true; } catch { return false; }
  };

  interface PendingReq { resolve: (m: Msg) => void; reject: (e: Error) => void }
  const pending = new Map<string, PendingReq>();
  const abandoned = new Set<string>();
  const serverReqs = new Set<string>(); // server-initiated requests forwarded to the client, awaiting its response
  let seq = 0;
  const abandon = (id: string): void => { if (abandoned.size < 10_000) abandoned.add(id); };
  const keyOf = (id: string | number): string => (typeof id === 'number' ? 'n:' : 's:') + String(id);

  function sendReq(method: string, params?: unknown): { id: string; promise: Promise<Msg> } {
    const id = 'prysm:' + String(++seq);
    const promise = new Promise<Msg>((resolve, reject) => {
      if (serverDead) { reject(new ServerExitError('server_exit')); return; }
      pending.set(id, { resolve, reject });
      const msg: Msg = { jsonrpc: '2.0', id, method };
      if (params !== undefined) msg['params'] = params;
      if (!writeServer(msg)) {
        pending.delete(id);
        reject(new ServerExitError('server_exit'));
      }
    });
    return { id, promise };
  }
  const sendCancel = (id: string): void => {
    writeServer({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: id, reason: 'cancelled' } });
  };
  const failAllPending = (e: Error): void => {
    for (const [id, p] of [...pending]) {
      pending.delete(id);
      abandon(id); // a late reply is dropped (proxy_orphan_response once per id)
      p.reject(e);
    }
  };

  // ---------------------------------------------------------------- tool registry
  let listed: Msg[] = [];
  let exposedPolicy = new Set<string>();
  let schemaChanged = new Set<string>();
  let lastListKey: string | null = null;
  let lastRegKey: string | null = null;
  let goodOnce = false;
  let lastTry = 0;
  let readyDone = false;
  let refreshing: Promise<void> | null = null;
  let refreshAgain = false;
  const readyWaiters = new Set<() => void>();
  const markReady = (): void => {
    readyDone = true;
    for (const w of [...readyWaiters]) w();
    readyWaiters.clear();
  };
  const waitReady = (): Promise<boolean> => {
    if (readyDone) return Promise.resolve(true);
    if (readyWaiters.size >= MAX_WAITERS) return Promise.resolve(false);
    return new Promise<boolean>((resolve) => {
      const w = (): void => { clearTimeout(t); resolve(true); };
      const t = setTimeout(() => { readyWaiters.delete(w); resolve(false); }, readyTimeoutMs);
      readyWaiters.add(w);
    });
  };

  const makeFn = (name: string) => (args: never, o: ToolCallOptions): Promise<unknown> => {
    const st = als.getStore();
    if (st === undefined) return Promise.reject(new Error('no_call_context'));
    return forwardCall(name, args as unknown, o.signal, st);
  };

  function forwardCall(name: string, args: unknown, signal: AbortSignal, st: Entry): Promise<unknown> {
    if (st.ctl.signal.aborted) return Promise.reject(new CancelledError('cancelled'));
    // taint on dispatch (the permit decision is already durable): errors, timeouts and isError results taint too
    if (taintSet.has(name)) session.taint();
    const params: Msg = { name, arguments: args };
    if (st.progressToken !== undefined) params['_meta'] = { progressToken: st.progressToken };
    const { id, promise } = sendReq('tools/call', params);
    st.serverId = id;
    return new Promise<unknown>((resolve, reject) => {
      const cleanup = (): void => {
        signal.removeEventListener('abort', onAbort);
        st.ctl.signal.removeEventListener('abort', onAbort);
      };
      function onAbort(): void {
        if (!pending.has(id)) return;
        pending.delete(id);
        abandon(id);
        cleanup();
        sendCancel(id);
        reject(new CancelledError('cancelled'));
      }
      signal.addEventListener('abort', onAbort, { once: true });
      st.ctl.signal.addEventListener('abort', onAbort, { once: true });
      promise.then((m) => {
        cleanup();
        if (m['error'] !== undefined) reject(new ServerToolError('server_error'));
        else resolve(m['result']);
      }, (e: unknown) => {
        cleanup();
        reject(e instanceof Error ? e : new Error('unknown'));
      });
      if (signal.aborted || st.ctl.signal.aborted) onAbort();
    });
  }

  let truncatedN = -1; // -1: not truncated in the last fetch
  async function fetchTools(): Promise<Msg[] | null> {
    const out: Msg[] = [];
    let totalBytes = 0;
    truncatedN = -1;
    let cursor: string | undefined;
    for (let page = 0; page < MAX_PAGES; page++) {
      const { id, promise } = sendReq('tools/list', cursor === undefined ? undefined : { cursor });
      let timer: ReturnType<typeof setTimeout> | undefined;
      let m: Msg;
      try {
        m = await Promise.race([
          promise,
          new Promise<never>((_, rej) => { timer = setTimeout(() => { rej(new Error('timeout')); }, listTimeoutMs); }),
        ]);
      } catch {
        if (pending.delete(id)) abandon(id);
        return null;
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
      const r = m['result'];
      if (!isPlain(r) || !Array.isArray(r['tools'])) return null;
      const arr = r['tools'] as unknown[];
      for (let i = 0; i < arr.length; i++) {
        const t = arr[i];
        let sz = 0;
        try { sz = JSON.stringify(t)?.length ?? 0; } catch { sz = MAX_LIST_BYTES; }
        totalBytes += sz;
        if (out.length >= MAX_TOOLS || totalBytes > MAX_LIST_BYTES) { truncatedN = arr.length - i; return out; }
        out.push(isPlain(t) ? t : {});
      }
      const next = r['nextCursor'];
      if (typeof next !== 'string' || next === '') return out;
      cursor = next;
    }
    truncatedN = 0;
    return out;
  }

  /** Returns true when the listed (exposed) set changed compared to the previous successful refresh. */
  async function doRefresh(): Promise<boolean> {
    lastTry = Date.now();
    const tools = await fetchTools();
    if (tools === null) {
      proxyLine('proxy_registry_refresh_failed', { reason: 'list_failed' });
      return false; // keep the last good registry (never widen); initial failure leaves it empty
    }
    const nextListed: Msg[] = [];
    const nextExposed = new Set<string>();
    const nextChanged = new Set<string>();
    const reg = Object.create(null) as Record<string, ToolEntry>;
    const keyParts: string[] = [];
    const counts = new Map<string, number>();
    for (const t of tools) {
      const nm = t['name'];
      if (typeof nm === 'string' && TOOL_NAME.test(nm)) counts.set(nm, (counts.get(nm) ?? 0) + 1);
    }
    if (truncatedN >= 0) proxyLine('proxy_tool_ignored', { reason: 'truncated', n: truncatedN });
    const ign = { bad_name: 0, duplicate: 0, schema_changed: 0, not_in_policy: 0, no_pin: 0 };
    for (const t of tools) {
      const nm = t['name'];
      if (typeof nm !== 'string' || !TOOL_NAME.test(nm)) { ign.bad_name++; continue; }
      if ((counts.get(nm) ?? 0) !== 1) { ign.duplicate++; continue; }
      let hash: string;
      try {
        hash = definitionHash({ name: nm, description: t['description'], inputSchema: t['inputSchema'] });
      } catch { ign.bad_name++; continue; }
      const def: Msg = {};
      for (const f of LIST_FIELDS) if (Object.hasOwn(t, f)) def[f] = t[f];
      if (inPolicy(nm)) {
        const pin = policyTools[nm]?.schema_hash;
        if (pin === undefined && requirePins) { ign.no_pin++; continue; }
        if (pin !== undefined && pin !== hash) { nextChanged.add(nm); ign.schema_changed++; continue; }
        nextExposed.add(nm);
        Object.defineProperty(reg, nm, {
          value: { fn: makeFn(nm), taintsSession: false }, enumerable: true, writable: true, configurable: true,
        });
        nextListed.push(def);
        keyParts.push(nm + ':' + hash);
      } else if (listMode === 'show') {
        nextListed.push(def);
        keyParts.push(nm + ':' + hash);
      } else {
        ign.not_in_policy++;
      }
    }
    // the audited guard swap comes first: if it fails the whole refresh fails and the last good state stays
    const regKey = JSON.stringify([...nextExposed].sort());
    if (regKey !== lastRegKey) {
      try {
        const hidden: Record<string, number> = {};
        for (const [k, v] of Object.entries(ign)) if (v > 0) hidden[k] = v;
        admin.setTools(reg, { exposed_n: nextExposed.size, hidden });
        lastRegKey = regKey;
      } catch {
        proxyLine('proxy_registry_refresh_failed', { reason: 'set_tools_failed' });
        return false;
      }
    }
    for (const [reason, n] of Object.entries(ign)) if (n > 0) proxyLine('proxy_tool_ignored', { reason, n });
    listed = nextListed;
    exposedPolicy = nextExposed;
    schemaChanged = nextChanged;
    goodOnce = true;
    keyParts.sort();
    const key = JSON.stringify(keyParts);
    const changed = lastListKey !== null && key !== lastListKey;
    lastListKey = key;
    return changed;
  }

  function refreshTools(): Promise<boolean> {
    if (refreshing !== null) {
      refreshAgain = true; // coalesced: at most one running + one queued
      return refreshing.then(() => false);
    }
    const run = (async (): Promise<boolean> => {
      let changed = false;
      do {
        refreshAgain = false;
        try { changed = (await doRefresh()) || changed; } catch { proxyLine('proxy_registry_refresh_failed', { reason: 'internal' }); }
      } while (refreshAgain && !shuttingDown);
      markReady();
      return changed;
    })();
    refreshing = run.then(() => undefined).finally(() => { refreshing = null; });
    return run;
  }

  // ---------------------------------------------------------------- client side
  const inflight = new Map<string, Entry>();
  let callsInflight = 0;
  let initializeSeen = false;

  async function handleCall(id: string | number, params: unknown, entry: Entry): Promise<void> {
    try {
      const shapeOk = isPlain(params) && typeof params['name'] === 'string' &&
        (params['arguments'] === undefined || isPlain(params['arguments']));
      if (!shapeOk) {
        let did = 'none';
        try { did = (await session.call(null as never, {})).decision_id; } catch { /* keep none */ }
        respond(id, blockedResult('invalid_request', did));
        return;
      }
      const ready = await waitReady();
      if (!ready) {
        respond(id, blockedResult('unavailable', admin.denyUnexposed(params['name'], 'not_ready').decision_id));
        return;
      }
      const p = params;
      const name = p['name'] as string;
      const meta = p['_meta'];
      if (isPlain(meta)) {
        const tok = meta['progressToken'];
        if (validToken(tok)) entry.progressToken = tok;
      }
      if (inPolicy(name) && !exposedPolicy.has(name)) {
        const reason = schemaChanged.has(name) ? 'schema_changed' : requirePins && policyTools[name]?.schema_hash === undefined ? 'no_pin' : 'tool_not_offered';
        respond(id, blockedResult('unknown_tool', admin.denyUnexposed(name, reason as 'schema_changed' | 'no_pin' | 'tool_not_offered').decision_id));
        return;
      }
      let r: GuardResult | null = null;
      try {
        r = await als.run(entry, () => session.call(name, p['arguments'] ?? {}, hostCtx));
      } catch { r = null; }
      if (r === null) respond(id, blockedResult('unavailable', 'none'));
      else if (r.ok) respond(id, r.value);
      else if (r.blocked) respond(id, blockedResult(r.reason_code, r.decision_id));
      else if (r.error === 'tool_timeout') respond(id, errorResult(`Tool timed out (decision ${r.decision_id})`));
      else respond(id, errorResult(`Tool error (decision ${r.decision_id})`));
    } catch {
      respondError(id, -32603, 'Internal error');
    } finally {
      inflight.delete(keyOf(id));
      callsInflight--;
    }
  }

  async function forwardRequest(id: string | number, msg: Msg, entry: Entry): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      let params = msg['params'];
      if (msg['method'] === 'initialize') {
        // whitelist rebuild: nothing else the client sent travels to the server
        const p = isPlain(params) ? params : {};
        const ci = isPlain(p['clientInfo']) ? p['clientInfo'] : {};
        const clientInfo = { name: shortStr(ci['name'], 64, 'client'), version: shortStr(ci['version'], 64, '0') };
        params = { protocolVersion: shortStr(p['protocolVersion'], 32, '2025-03-26'), capabilities: {}, clientInfo };
        try {
          store.appendShort({
            id: randomUUID(), kind: 'policy_activate', ts_ms: Date.now(), agent_id: agentId, effect: null, tool: null,
            enforcement: policy.mode === 'monitor_only' ? 'monitor_only' : 'enforced', policy_version: policy.policy_version,
            engine_version: ENGINE_VERSION, outcome: { event: 'proxy_client', name: clientInfo.name, version: clientInfo.version },
          });
        } catch { /* best effort */ }
      }
      const { id: sid, promise } = sendReq(msg['method'] as string, params);
      entry.serverId = sid;
      const m = await Promise.race([
        promise,
        new Promise<never>((_, rej) => {
          timer = setTimeout(() => {
            if (pending.delete(sid)) abandon(sid);
            rej(new Error('forward_timeout'));
          }, forwardTimeoutMs);
        }),
      ]);
      if (isPlain(m['error'])) {
        writeClient({ jsonrpc: '2.0', id, error: m['error'] });
      } else if (msg['method'] === 'initialize') {
        const r = m['result'] as Msg;
        const caps = r['capabilities'];
        const tools = isPlain(caps) ? caps['tools'] : undefined;
        const listChanged = isPlain(tools) && tools['listChanged'] === true;
        respond(id, { ...r, capabilities: { tools: { listChanged } } });
      } else {
        respond(id, m['result']);
      }
    } catch {
      respondError(id, -32603, 'Internal error');
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      inflight.delete(keyOf(id));
    }
  }

  async function handleToolsList(id: string | number): Promise<void> {
    try {
      if (!goodOnce && Date.now() - lastTry >= 1000 && readyDone && !shuttingDown) await refreshTools();
      const ok = await waitReady();
      if (!ok) respondError(id, -32603, 'tools not ready');
      else respond(id, { tools: listed });
    } finally {
      inflight.delete(keyOf(id));
    }
  }

  function dispatchClient(m: Msg): void {
    const hasId = Object.hasOwn(m, 'id');
    const rawId = m['id'];
    if (m['jsonrpc'] !== '2.0') {
      respondError(idOrNull(rawId), -32600, 'Invalid Request');
      return;
    }
    if (hasId && idOrNull(rawId) === null) {
      respondError(null, -32600, 'Invalid Request');
      return;
    }
    if (typeof rawId === 'string' && rawId.startsWith('prysm:')) {
      respondError(rawId, -32600, 'Invalid Request');
      return;
    }
    const method = m['method'];
    if (method === undefined) {
      // a client response: forwarded only for an outstanding forwarded server request
      const rid = idOrNull(rawId);
      if (rid !== null && hasId && (Object.hasOwn(m, 'result') !== Object.hasOwn(m, 'error')) && serverReqs.delete(keyOf(rid))) {
        const out: Msg = { jsonrpc: '2.0', id: rid };
        if (Object.hasOwn(m, 'result')) out['result'] = m['result'];
        else out['error'] = m['error'];
        writeServer(out);
      } else if (!Object.hasOwn(m, 'result') && !Object.hasOwn(m, 'error')) {
        respondError(rid, -32600, 'Invalid Request'); // an envelope with neither method nor result/error
      } else {
        proxyLine('proxy_orphan_response', { kind: 'client' });
      }
      return;
    }
    if (typeof method !== 'string') {
      respondError(idOrNull(rawId), -32600, 'Invalid Request');
      return;
    }
    if (!hasId) { dispatchNotification(method, m); return; }
    const id = rawId as string | number;
    const key = keyOf(id);
    if (inflight.has(key) || inflight.size >= MAX_INFLIGHT) {
      respondError(null, -32600, 'Invalid Request');
      return;
    }
    if (method === 'ping') { respond(id, {}); return; }
    if (method === 'initialize') {
      if (initializeSeen) { respondError(id, -32600, 'Invalid Request'); return; }
      initializeSeen = true;
    }
    const entry: Entry = { kind: method === 'tools/call' ? 'call' : 'other', ctl: new AbortController() };
    if (method === 'tools/list') {
      inflight.set(key, entry);
      track(handleToolsList(id));
    } else if (method === 'tools/call') {
      if (callsInflight >= MAX_CALLS) {
        proxyLine('proxy_busy');
        respondError(id, -32000, 'Server busy');
        return;
      }
      callsInflight++;
      inflight.set(key, entry);
      track(handleCall(id, m['params'], entry));
    } else if (method === 'initialize' || allowMethods.has(method)) {
      inflight.set(key, entry);
      track(forwardRequest(id, m, entry));
    } else {
      respondError(id, -32601, 'Method not found');
    }
  }

  function dispatchNotification(method: string, m: Msg): void {
    if (method === 'notifications/initialized') {
      writeServer({ jsonrpc: '2.0', method });
      track(refreshTools());
    } else if (method === 'notifications/progress') {
      const p = m['params'];
      if (allowServerRequests.size > 0 && isPlain(p) && validToken(p['progressToken']) && typeof p['progress'] === 'number' && Number.isFinite(p['progress'])) {
        const out: Msg = { progressToken: p['progressToken'], progress: p['progress'] };
        if (typeof p['total'] === 'number' && Number.isFinite(p['total'])) out['total'] = p['total'];
        writeServer({ jsonrpc: '2.0', method, params: out });
      }
    } else if (method === 'notifications/cancelled') {
      // only a tracked in-flight tools/call is cancelled; the proxy translates the id on its own
      const p = m['params'];
      const rid = isPlain(p) ? idOrNull(p['requestId']) : null;
      if (rid === null) return;
      const e = inflight.get(keyOf(rid));
      if (e !== undefined && e.kind === 'call') e.ctl.abort();
    } else if (allowMethods.has(method)) {
      writeServer({ jsonrpc: '2.0', method, ...(m['params'] !== undefined ? { params: m['params'] } : {}) });
    } // everything else (including tools/call as a notification) is dropped
  }

  function onClientLine(buf: Buffer): void {
    if (shuttingDown) return;
    let v: unknown;
    let text: string;
    try {
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buf);
      v = JSON.parse(text);
    } catch {
      respondError(null, -32700, 'Parse error');
      return;
    }
    if (!isPlain(v)) { respondError(null, -32600, 'Invalid Request'); return; }
    try {
      if (hasDuplicateTopKeys(text)) { respondError(idOrNull(v['id']), -32600, 'Invalid Request'); return; }
      dispatchClient(v);
    } catch { respondError(null, -32603, 'Internal error'); }
  }

  const clientSplit = new LineSplitter(MAX_CLIENT_LINE, onClientLine, () => {
    if (!shuttingDown) respondError(null, -32600, 'Invalid Request');
  });

  // ---------------------------------------------------------------- server side
  const validResp = (v: Msg): boolean => {
    const hasR = Object.hasOwn(v, 'result');
    const hasE = Object.hasOwn(v, 'error');
    if (hasR === hasE) return false;
    return hasR ? isPlain(v['result']) : isPlain(v['error']);
  };
  const hasToken = (tok: unknown): boolean => {
    if (typeof tok !== 'string' && typeof tok !== 'number') return false;
    for (const e of inflight.values()) if (e.progressToken === tok) return true;
    return false;
  };

  function onServerLine(buf: Buffer): void {
    let v: unknown;
    try { v = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buf)); } catch {
      proxyLine('proxy_orphan_response', { kind: 'server' });
      return;
    }
    if (!isPlain(v)) { proxyLine('proxy_orphan_response', { kind: 'server' }); return; }
    const method = v['method'];
    const hasId = Object.hasOwn(v, 'id');
    if (typeof method === 'string') {
      const p = v['params'];
      if (hasId) {
        const sid = idOrNull(v['id']);
        if (sid !== null && allowServerRequests.has(method) && serverReqs.size < MAX_SERVER_REQS && !serverReqs.has(keyOf(sid))) {
          serverReqs.add(keyOf(sid));
          writeClient({ jsonrpc: '2.0', id: sid, method, ...(p !== undefined ? { params: p } : {}) });
          return;
        }
        proxyLine('proxy_server_request_refused');
        if (sid !== null) writeServer({ jsonrpc: '2.0', id: sid, error: { code: -32601, message: 'Method not found' } });
        return;
      }
      if (method === 'notifications/tools/list_changed') {
        track(refreshTools().then((changed) => {
          if (changed) writeClient({ jsonrpc: '2.0', method });
        }));
      } else if (method === 'notifications/progress') {
        if (hasToken(isPlain(p) ? p['progressToken'] : undefined) || allowServerNotifications) {
          writeClient({ jsonrpc: '2.0', method, ...(p !== undefined ? { params: p } : {}) });
        }
      } else if (allowServerNotifications) {
        writeClient({ jsonrpc: '2.0', method, ...(p !== undefined ? { params: p } : {}) });
      }
      return;
    }
    const id = v['id'];
    if (hasId && typeof id === 'string') {
      const pr = pending.get(id);
      if (pr !== undefined) {
        pending.delete(id);
        if (validResp(v)) pr.resolve(v);
        else pr.reject(new ServerShapeError('bad_response'));
        return;
      }
      if (abandoned.delete(id)) { proxyLine('proxy_orphan_response', { kind: 'server' }); return; } // late reply, once per id
    }
    proxyLine('proxy_orphan_response', { kind: 'server' });
  }

  /** An oversize server line was discarded: fail closed for everything pending, keep running. */
  function onServerOversize(): void {
    if (shuttingDown) return;
    proxyLine('proxy_server_oversize');
    failAllPending(new OversizeError('oversize'));
  }
  const serverSplit = new LineSplitter(maxServerLine, onServerLine, onServerOversize);

  child.stdout?.on('data', (c: Buffer) => { serverSplit.push(Buffer.isBuffer(c) ? c : Buffer.from(c)); });
  // server stderr: every line is prefixed so it cannot be mistaken for a PRYSM sink line
  const stderrLine = (raw: string): string => '[server] ' + raw
    .replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029').replace(/\u0085/g, '\\u0085')
    .replace(/[\u0000-\u0008\u000a-\u001f\u007f-\u009f]/g, '?').slice(0, 1000);
  let errBuf = '';
  const flushErr = (final: boolean): void => {
    for (;;) {
      const i = errBuf.indexOf('\n');
      if (i < 0) break;
      sink(stderrLine(errBuf.slice(0, i)));
      errBuf = errBuf.slice(i + 1);
    }
    if (errBuf.length > 8192 || (final && errBuf.length > 0)) {
      sink(stderrLine(errBuf));
      errBuf = '';
    }
  };
  child.stderr?.on('data', (c: Buffer | string) => { errBuf += c.toString(); flushErr(false); });

  // ---------------------------------------------------------------- lifecycle
  function closeAll(): void {
    flushErr(true);
    try { guard.close(); } catch { /* ignore */ }
    try { store.close(); } catch { /* ignore */ }
  }
  /** Kills the server; on Windows the whole process tree (fixed binary, args array). Never touches a dead pid. */
  function killChild(): void {
    try {
      if (child.exitCode !== null || child.signalCode !== null) return;
      if (process.platform === 'win32' && typeof child.pid === 'number') {
        spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true, shell: false });
      } else {
        child.kill();
      }
    } catch { /* ignore */ }
  }
  async function settle(): Promise<void> {
    for (let i = 0; i < 50 && tasks.size > 0; i++) await Promise.allSettled([...tasks]);
  }

  let goneFired = false;
  let spawned = false;
  function onServerGone(code: number | null, signal: string | null): void {
    if (goneFired) return;
    goneFired = true;
    serverDead = true;
    resolveGone();
    if (shuttingDown) return; // expected (client EOF path)
    shuttingDown = true;
    proxyLine('proxy_server_exit', { code, ...(signal !== null ? { signal } : {}) });
    failAllPending(new ServerExitError('server_exit'));
    markReady();
    void (async () => {
      await settle();
      closeAll();
      resolveDone(1);
    })();
  }
  child.on('spawn', () => { spawned = true; });
  child.on('error', () => {
    if (!spawned) {
      // the server could not be started (no command or path text is printed)
      if (goneFired) return;
      goneFired = true;
      serverDead = true;
      resolveGone();
      if (shuttingDown) return;
      shuttingDown = true;
      proxyLine('proxy_server_exit', { code: null, reason: 'spawn_failed' });
      failAllPending(new ServerExitError('server_exit'));
      markReady();
      void (async () => {
        await settle();
        closeAll();
        resolveDone(3);
      })();
      return;
    }
    onServerGone(null, null);
  });
  child.on('exit', (code, signal) => { setTimeout(() => { onServerGone(code, signal); }, 200); });
  child.on('close', (code, signal) => { onServerGone(code, signal); });

  async function onClientEnd(code: number): Promise<void> {
    if (shuttingDown) return;
    shuttingDown = true;
    muteOutput = true;
    for (const e of inflight.values()) e.ctl.abort();
    markReady();
    await settle();
    try { child.stdin?.end(); } catch { /* ignore */ }
    if (!serverDead) {
      const t = setTimeout(killChild, killGraceMs);
      await serverGone;
      clearTimeout(t);
    }
    killChild();
    closeAll();
    resolveDone(code);
  }

  opts.clientIn.on('data', (c: Buffer | string) => {
    if (shuttingDown) return;
    clientSplit.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  });
  let ended = false;
  const onEnd = (): void => {
    if (ended) return;
    ended = true; // a partial final line (no newline) is discarded
    void onClientEnd(0);
  };
  opts.clientIn.on('end', onEnd);
  opts.clientIn.on('close', onEnd);
  opts.clientIn.on('error', onEnd);
  opts.clientOut.on('error', () => { void onClientEnd(1); }); // stdout closed

  return {
    done,
    sessionId,
    stop: () => onClientEnd(0),
    fatal: (): void => {
      proxyLine('proxy_fatal');
      shuttingDown = true;
      muteOutput = true;
      killChild();
    },
  };
}
