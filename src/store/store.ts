// Append-only, hash-chained audit store on node:sqlite (AUDIT-SPEC §1 + §4 amendments).
// The chain is tamper-EVIDENT, not tamper-proof: someone who can write the DB file can recompute it.
// Truncation and full rewrite are detected only against an external anchor (see anchor()).
// The SQL triggers are a speed bump, not a security control.
import { DatabaseSync } from 'node:sqlite';
import type { StatementSync } from 'node:sqlite';
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { userInfo } from 'node:os';
import { jcs } from '../core/index.ts';

export type StoreErrorCode = 'busy' | 'io' | 'invalid_event' | 'corrupt' | 'duplicate_id' | 'key_invalid' | 'key_mismatch';

/** Error with a fixed code. The message never contains values. */
export class StoreError extends Error {
  readonly code: StoreErrorCode;
  constructor(code: StoreErrorCode) {
    super('store error: ' + code);
    this.name = 'StoreError';
    this.code = code;
  }
}

export type EventKind = 'decision' | 'tool_result' | 'policy_activate' | 'checkpoint';
export type KeyProtection = 'acl' | 'mode_0600' | 'unprotected' | 'external' | 'unknown';
export type HmacLabel = 'args' | 'user' | 'result' | 'request' | 'tool';

export interface NewEvent {
  id: string;
  kind: EventKind;
  ts_ms?: number;
  execution_id?: string | null;
  session_id?: string | null;
  agent_id?: string | null;
  user_hmac?: string | null;
  tool?: string | null;
  effect?: 'permit' | 'deny' | null;
  enforcement?: 'enforced' | 'monitor_only' | null;
  rule_ids?: readonly string[] | null;
  reason_code?: string | null;
  policy_version?: string | null;
  request_digest?: string | null;
  args_hmac?: string | null;
  args_redacted?: unknown;
  risk?: 'low' | 'medium' | 'high' | null;
  latency_us?: number | null;
  session_tainted?: 0 | 1 | boolean | null;
  provenance_asserted?: unknown;
  model_meta?: unknown;
  outcome?: unknown;
  decision_id?: string | null;
  engine_version?: string | null;
}

export interface StoredEvent {
  seq: number;
  id: string;
  ts_ms: number;
  kind: EventKind;
  execution_id: string | null;
  session_id: string | null;
  agent_id: string | null;
  user_hmac: string | null;
  tool: string | null;
  effect: string | null;
  enforcement: string | null;
  rule_ids: unknown;
  reason_code: string | null;
  policy_version: string | null;
  request_digest: string | null;
  args_hmac: string | null;
  args_redacted: unknown;
  risk: string | null;
  latency_us: number | null;
  session_tainted: number | null;
  provenance_asserted: unknown;
  model_meta: unknown;
  outcome: unknown;
  decision_id: string | null;
  engine_version: string | null;
  prev_hash: string;
  hash: string;
}

export interface Anchor {
  genesis_hash: string;
  head_seq: number;
  head_hash: string;
  ts_ms: number;
}

export interface VerifyIssue {
  seq: number;
  code: string;
}

export interface CheckpointInfo {
  seq: number;
  through_seq: number;
  last_hash: string;
}

export interface VerifyResult {
  /** Retained, hash-valid checkpoint rows: log and compare these against the sink's checkpoint lines. */
  checkpoints: CheckpointInfo[];
  ok: boolean;
  count: number;
  head_seq: number;
  head_hash: string;
  pruned_through: number | null;
  errors: VerifyIssue[];
  warnings: VerifyIssue[];
}

export interface VerifyOptions {
  anchor?: Anchor;
  graceMs?: number;
  /** Accept ANY pruning without an external record: development only; downgrades history_pruned to a warning. */
  allowPruned?: boolean;
  /** The externally recorded checkpoint (from the sink line); pruned history is accepted only if it matches. */
  expectPruned?: { through_seq: number; last_hash: string } | { through_seq: number; last_hash: string }[];
}

export interface QueryOptions {
  kind?: EventKind;
  tool?: string;
  sessionId?: string;
  effect?: 'permit' | 'deny';
  afterSeq?: number;
  limit?: number;
}

export interface PruneResult {
  pruned: number;
  checkpointSeq: number;
  through_seq: number;
  last_hash: string;
}

export interface Store {
  append(ev: NewEvent): StoredEvent;
  appendBestEffort(ev: NewEvent): StoredEvent | null;
  /** append() with busy timeout min(busyTimeoutMs, 250): for best-effort rows that must not stall the event loop. */
  appendShort(ev: NewEvent): StoredEvent;
  iterate(opts?: { afterSeq?: number; limit?: number }): StoredEvent[];
  head(): { seq: number; hash: string } | null;
  count(): number;
  /** Most recent event of a kind (addition to the spec'd interface, used by the guard for policy_activate). */
  latest(kind: EventKind): StoredEvent | null;
  verify(opts?: VerifyOptions): VerifyResult;
  getEvent(id: string): StoredEvent | null;
  /** The decision row (id = decisionId) followed by every row whose decision_id = decisionId, in seq order. */
  eventsByDecision(decisionId: string): StoredEvent[];
  query(q?: QueryOptions): StoredEvent[];
  keyProtection(): KeyProtection;
  anchor(): Anchor;
  checkpointAndPrune(beforeTsMs: number, opts?: { force?: boolean }): PruneResult;
  close(): void;
  hmac(label: HmacLabel, data: string): string;
}

export interface OpenStoreOptions {
  path: string;
  /** Install key (>= 32 bytes). If absent, a 32-byte key file is used/created at keyPath. */
  hmacKey?: Uint8Array;
  /** Key file location (default: <path>.key; protection is the OS user's file ACL; keep it outside the DB directory). */
  keyPath?: string;
  busyTimeoutMs?: number;
  synchronous?: 'FULL' | 'NORMAL';
  /** Injectable clock for ts_ms (never used for ordering, not evidence of time). */
  clock?: () => number;
  /** Secondary sink for appendBestEffort lines (default: process.stderr). */
  secondarySink?: (line: string) => void;
  /** Retention floor for checkpointAndPrune (default 24 h). */
  minRetainMs?: number;
  /** Test seam: replaces the default key-file protection check/attempt. */
  keyProtect?: (keyPath: string) => KeyProtection;
  /** Test seam: returns raw `icacls <file>` output (null = unreadable). Enables the ACL evaluation on any platform. */
  aclReader?: (keyPath: string) => string | null;
  /** Test seam: the principal expected in the ACL (default: os.userInfo().username). */
  aclUser?: string;
  /**
   * Open an EXISTING store strictly read-only (CLI reads; query_only). Never creates the DB, tables, meta rows or a
   * key file, never loads a key file, never resets meta flags, never writes. Without `hmacKey`, `hmac` throws
   * key_mismatch and keyProtection() reports 'unknown'. All write methods throw StoreError io.
   */
  readOnly?: boolean;
}

export const SCHEMA_VERSION = '1';

const TEXT_COLS = [
  'id', 'kind', 'execution_id', 'session_id', 'agent_id', 'user_hmac', 'tool', 'effect', 'enforcement',
  'reason_code', 'policy_version', 'request_digest', 'args_hmac', 'risk', 'decision_id', 'engine_version',
] as const;
const JSON_COLS = ['rule_ids', 'args_redacted', 'provenance_asserted', 'model_meta', 'outcome'] as const;
const SHRINK_ORDER = ['args_redacted', 'provenance_asserted', 'model_meta', 'outcome'] as const;
const ALL_KEYS = new Set<string>([...TEXT_COLS, ...JSON_COLS, 'ts_ms', 'latency_us', 'session_tainted']);
const COLS = [
  'seq', 'id', 'ts_ms', 'kind', 'execution_id', 'session_id', 'agent_id', 'user_hmac', 'tool', 'effect',
  'enforcement', 'rule_ids', 'reason_code', 'policy_version', 'request_digest', 'args_hmac', 'args_redacted',
  'risk', 'latency_us', 'session_tainted', 'provenance_asserted', 'model_meta', 'outcome', 'decision_id',
  'engine_version', 'prev_hash', 'hash',
] as const;

const KINDS = new Set<string>(['decision', 'tool_result', 'policy_activate', 'checkpoint']);
const EFFECTS = new Set<string>(['permit', 'deny']);
const ENFORCEMENTS = new Set<string>(['enforced', 'monitor_only']);
const RISKS = new Set<string>(['low', 'medium', 'high']);
const HMAC_LABELS = new Set<string>(['args', 'user', 'result', 'request', 'tool']);
const CODES = new Set<string>(['busy', 'io', 'invalid_event', 'corrupt', 'duplicate_id', 'key_invalid', 'key_mismatch']);

const TEXT_MAX = 256; // code points, including the marker
const TRUNC = '…[trunc]';
const JSON_MAX = 4096;
const ROW_MAX = 16 * 1024;
const RULE_IDS_MAX = 16;

const SAFE_ID = /^[A-Za-z0-9_.:-]{1,64}$/;
const BAD_CHARS = new RegExp('\\u0000|[\\uD800-\\uDBFF](?![\\uDC00-\\uDFFF])|(?<![\\uD800-\\uDBFF])[\\uDC00-\\uDFFF]', 'g');

/** The single text sanitiser: NUL and lone surrogates become U+FFFD; truncation by code point; nothing else changes. */
export function sanitizeText(s: string): string {
  const t = s.replace(BAD_CHARS, '�');
  const pts = Array.from(t);
  if (pts.length <= TEXT_MAX) return t;
  return pts.slice(0, TEXT_MAX - Array.from(TRUNC).length).join('') + TRUNC;
}

type Row = Record<string, unknown>;

function bad(): never {
  throw new StoreError('invalid_event');
}

interface Normalized {
  text: Row;
  json: Record<string, unknown>;
  jsonText: Record<string, string | null>;
}

function checkClock(v: unknown): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) bad();
  return v;
}

function normalize(ev: NewEvent, now: () => number): Normalized {
  if (typeof ev !== 'object' || ev === null) bad();
  const e = ev as unknown as Record<string, unknown>;
  for (const k of Object.keys(e)) if (!ALL_KEYS.has(k)) bad();
  const text: Row = {};
  for (const c of TEXT_COLS) {
    const v = e[c];
    if (v === undefined || v === null) text[c] = null;
    else if (typeof v === 'string') text[c] = sanitizeText(v);
    else bad();
  }
  if (typeof text['id'] !== 'string' || text['id'] === '') bad();
  if (!KINDS.has(text['kind'] as string)) bad();
  if (text['effect'] !== null && !EFFECTS.has(text['effect'] as string)) bad();
  if (text['enforcement'] !== null && !ENFORCEMENTS.has(text['enforcement'] as string)) bad();
  if (text['risk'] !== null && !RISKS.has(text['risk'] as string)) bad();
  let tsRaw: unknown = e['ts_ms'];
  if (tsRaw === undefined || tsRaw === null) {
    try {
      tsRaw = now();
    } catch {
      bad();
    }
  }
  text['ts_ms'] = checkClock(tsRaw);
  const lat = e['latency_us'];
  if (lat === undefined || lat === null) text['latency_us'] = null;
  else if (typeof lat === 'number' && Number.isSafeInteger(lat)) text['latency_us'] = lat;
  else bad();
  const st = e['session_tainted'];
  if (st === undefined || st === null) text['session_tainted'] = null;
  else if (st === true || st === 1) text['session_tainted'] = 1;
  else if (st === false || st === 0) text['session_tainted'] = 0;
  else bad();

  const json: Record<string, unknown> = {};
  const jsonText: Record<string, string | null> = {};
  const setJson = (c: string, v: unknown): void => {
    if (v === undefined || v === null) {
      json[c] = null;
      jsonText[c] = null;
      return;
    }
    let s: string;
    try {
      s = jcs(v);
    } catch {
      return bad();
    }
    const bytes = Buffer.byteLength(s, 'utf8');
    if (bytes > JSON_MAX) s = jcs({ truncated: true, bytes });
    jsonText[c] = s;
    json[c] = JSON.parse(s) as unknown;
  };
  for (const c of JSON_COLS) {
    let v = e[c];
    if (c === 'rule_ids' && Array.isArray(v) && v.length > RULE_IDS_MAX) {
      v = [...v.slice(0, RULE_IDS_MAX), '…+' + String(v.length - RULE_IDS_MAX)];
    }
    setJson(c, v);
  }
  const size = (): number => {
    let n = 0;
    for (const c of TEXT_COLS) n += Buffer.byteLength((text[c] as string | null) ?? '', 'utf8');
    for (const c of JSON_COLS) n += Buffer.byteLength(jsonText[c] ?? '', 'utf8');
    return n + 64;
  };
  for (const c of SHRINK_ORDER) {
    if (size() <= ROW_MAX) break;
    if (jsonText[c] === null || jsonText[c] === undefined) continue;
    const bytes = Buffer.byteLength(jsonText[c] as string, 'utf8');
    jsonText[c] = jcs({ truncated: true, bytes });
    json[c] = JSON.parse(jsonText[c] as string) as unknown;
  }
  if (size() > ROW_MAX) bad();
  return { text, json, jsonText };
}

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

/** hash = sha256_hex(prev_hash + "\n" + JCS(row without hash)); JSON columns parsed; null for absent. */
function chainHash(rowWithoutHash: Record<string, unknown>): string {
  return sha256Hex(String(rowWithoutHash['prev_hash']) + '\n' + jcs(rowWithoutHash));
}

function toStored(r: Row): StoredEvent {
  const out: Row = { ...r };
  for (const c of JSON_COLS) {
    const v = r[c];
    if (v === null || v === undefined) out[c] = null;
    else if (typeof v === 'string') {
      try {
        out[c] = JSON.parse(v) as unknown;
      } catch {
        throw new StoreError('corrupt');
      }
    } else throw new StoreError('corrupt');
  }
  return out as unknown as StoredEvent;
}

function mapErr(e: unknown): StoreError {
  if (e instanceof StoreError) return e;
  const x = e as { errcode?: unknown; message?: unknown } | null;
  const msg = typeof x?.message === 'string' ? x.message : '';
  const code = typeof x?.errcode === 'number' ? x.errcode & 0xff : 0;
  if (/append-only/.test(msg)) return new StoreError('io');
  if (code === 5 || code === 6 || /database is locked|busy/i.test(msg)) return new StoreError('busy');
  if (/UNIQUE constraint failed: events\.id/.test(msg)) return new StoreError('duplicate_id');
  if (code === 19) return new StoreError(/UNIQUE constraint failed: events\.seq/.test(msg) ? 'corrupt' : 'invalid_event');
  if (code === 11 || code === 26) return new StoreError('corrupt');
  return new StoreError('io');
}

function safeSink(sink: (line: string) => void, line: string): void {
  try {
    sink(line);
  } catch {
    /* a sink must never break callers */
  }
}

function codeOf(e: unknown): string {
  const c = (e as { code?: unknown } | null)?.code;
  return typeof c === 'string' && CODES.has(c) ? c : 'unknown';
}

/** The secondary-sink JSON line for a failed audit write. Contains only code, kind and id. */
export function auditFailureLine(code: unknown, ev: unknown): string {
  const o = (typeof ev === 'object' && ev !== null ? ev : {}) as { kind?: unknown; id?: unknown };
  const okCode = typeof code === 'string' && CODES.has(code) ? code : 'unknown';
  const kind = typeof o.kind === 'string' && KINDS.has(o.kind) ? o.kind : null;
  const id = typeof o.id === 'string' && SAFE_ID.test(o.id) ? o.id : null;
  return JSON.stringify({ prysm: 'audit_write_failed', code: okCode, kind, id });
}

function auditSkippedLine(ev: unknown): string {
  const o = (typeof ev === 'object' && ev !== null ? ev : {}) as { kind?: unknown; id?: unknown };
  const kind = typeof o.kind === 'string' && KINDS.has(o.kind) ? o.kind : null;
  const id = typeof o.id === 'string' && SAFE_ID.test(o.id) ? o.id : null;
  return JSON.stringify({ prysm: 'audit_skipped', kind, id });
}

/**
 * Best-effort appender with a circuit breaker (§4.9): after 3 consecutive store failures (busy/io/corrupt/key)
 * attempts are skipped for 5000 ms (hrtime), one sink line per dropped event. Never throws.
 * Malformed events (invalid_event/duplicate_id) are caller bugs, not outages, and do not trip the breaker.
 */
export function makeBestEffort(
  append: (ev: NewEvent) => StoredEvent,
  sink: (line: string) => void,
  wrap?: <T>(fn: () => T) => T,
): (ev: NewEvent) => StoredEvent | null {
  let fails = 0;
  let skipUntil = 0n;
  const nowMs = (): bigint => process.hrtime.bigint() / 1000000n;
  return (ev) => {
    try {
      if (fails >= 3 && nowMs() < skipUntil) {
        safeSink(sink, auditSkippedLine(ev));
        return null;
      }
      try {
        const r = wrap === undefined ? append(ev) : wrap(() => append(ev));
        fails = 0;
        return r;
      } catch (e) {
        const c = codeOf(e);
        if (c !== 'invalid_event' && c !== 'duplicate_id') {
          fails++;
          if (fails >= 3) skipUntil = nowMs() + 5000n;
        }
        safeSink(sink, auditFailureLine(c, ev));
        return null;
      }
    } catch {
      return null;
    }
  };
}

const HEX64 = /^[0-9a-f]{64}$/;
const WELL_KNOWN_GROUP = /^(everyone|users|authenticated users|system|administrators|creator owner|builtin\\.*|nt authority\\.*|nt service\\.*)$/i;

/** True for well-known group/service principals that must never be the key file's grantee. */
export function isWellKnownGroup(name: string): boolean {
  const n = name.trim();
  const last = n.includes('\\') ? n.slice(n.lastIndexOf('\\') + 1) : n;
  return WELL_KNOWN_GROUP.test(n) || WELL_KNOWN_GROUP.test(last);
}

/**
 * Evaluate raw `icacls <file>` output: true only if exactly one principal entry is present, it is the
 * current user (not a well-known group), and inheritance is removed (no inherited `(I)` entry).
 */
export function evaluateAcl(output: string, keyPath: string, user: string): boolean {
  if (typeof output !== 'string' || typeof user !== 'string' || user === '' || isWellKnownGroup(user)) return false;
  const entries: { principal: string; rights: string }[] = [];
  let first = true;
  for (let line of output.split(/\r?\n/)) {
    if (/^\s*Successfully processed/i.test(line)) break;
    if (line.trim() === '') continue;
    if (first) {
      first = false;
      if (line.toLowerCase().startsWith(keyPath.toLowerCase())) line = line.slice(keyPath.length);
      else if (line.toLowerCase().startsWith('"' + keyPath.toLowerCase() + '"')) line = line.slice(keyPath.length + 2);
    }
    const m = /^\s*(.+?):((?:\([^)]*\))+)\s*$/.exec(line);
    if (m === null) return false; // anything unparseable is not trusted
    entries.push({ principal: (m[1] as string).trim(), rights: m[2] as string });
  }
  if (entries.length !== 1) return false;
  const e = entries[0] as { principal: string; rights: string };
  if (isWellKnownGroup(e.principal)) return false;
  if (/\(I\)/.test(e.rights)) return false; // inherited entry => inheritance not removed
  const u = user.toLowerCase();
  const p = e.principal.toLowerCase();
  return p === u || p.endsWith('\\' + u);
}

function currentUser(): string | null {
  try {
    const n = userInfo().username;
    return typeof n === 'string' && n !== '' ? n : null;
  } catch {
    return null;
  }
}

function defaultAclReader(keyPath: string): string | null {
  try {
    const r = spawnSync('icacls', [keyPath], { shell: false, timeout: 5000, windowsHide: true, encoding: 'utf8' });
    return r.error === undefined && r.status === 0 && typeof r.stdout === 'string' ? r.stdout : null;
  } catch {
    return null;
  }
}

/** win32: restrict the key file to the current user (args array, no shell). Success is judged by re-reading, not by exit status alone. */
function applyAcl(keyPath: string, user: string): void {
  if (isWellKnownGroup(user)) return;
  try {
    spawnSync('icacls', [keyPath, '/inheritance:r', '/grant:r', user + ':(R,W)'], {
      shell: false, timeout: 5000, windowsHide: true, stdio: 'ignore',
    });
  } catch {
    /* judged by the re-read */
  }
}

function readKeyFile(keyPath: string): Buffer | null {
  try {
    const b = readFileSync(keyPath);
    return b.length === 32 ? b : null;
  } catch {
    return null;
  }
}

const collapse = (x: string): string => x.replace(/\s+/g, ' ').trim().toLowerCase();
const EXPECTED_TRIGGERS: Readonly<Record<string, string>> = {
  events_no_update: collapse("CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'append-only'); END"),
  events_no_delete: collapse("CREATE TRIGGER events_no_delete BEFORE DELETE ON events WHEN COALESCE((SELECT value FROM meta WHERE key='prune_open'),'0') <> '1' BEGIN SELECT RAISE(ABORT, 'append-only'); END"),
};
const EXPECTED_INDEXES = new Set(['events_decision_id', 'events_kind']);

/**
 * Schema allow-list (REPORT-SPEC 5.5), applied on every open before any events/meta query: events and meta are
 * plain tables; no views, virtual tables or foreign objects; only the two append-only triggers (exact text; a
 * missing trigger is tolerated, a writable open recreates it); trusted_schema is switched off. A violation is
 * StoreError corrupt, so a forged recursive view is never queried.
 */
function checkSchema(db: DatabaseSync): void {
  db.exec('PRAGMA trusted_schema=OFF');
  const rows = db.prepare('SELECT type, name, sql FROM sqlite_master').all() as { type: string; name: string; sql: string | null }[];
  const tables = new Set<string>();
  for (const r of rows) {
    const sql = r.sql ?? '';
    if (r.type === 'table') {
      if (/^\s*create\s+virtual\s/i.test(sql)) throw new StoreError('corrupt');
      if (r.name !== 'events' && r.name !== 'meta' && r.name !== 'sqlite_sequence' && !/^sqlite_stat[1-4]$/.test(r.name)) throw new StoreError('corrupt');
      tables.add(r.name);
    } else if (r.type === 'index') {
      if (!r.name.startsWith('sqlite_autoindex_') && !EXPECTED_INDEXES.has(r.name)) throw new StoreError('corrupt');
    } else if (r.type === 'trigger') {
      const want = Object.hasOwn(EXPECTED_TRIGGERS, r.name) ? EXPECTED_TRIGGERS[r.name] : undefined;
      if (want === undefined || collapse(sql) !== want) throw new StoreError('corrupt');
    } else throw new StoreError('corrupt'); // views and anything else
  }
  const n = tables.has('events') || tables.has('meta');
  if (n && !(tables.has('events') && tables.has('meta'))) throw new StoreError('corrupt');
}

export function openStore(opts: OpenStoreOptions): Store {
  if (typeof opts !== 'object' || opts === null || typeof opts.path !== 'string' || opts.path === '') {
    throw new StoreError('invalid_event');
  }
  const path = opts.path;
  const busy = opts.busyTimeoutMs ?? 2000;
  if (!Number.isInteger(busy) || busy < 0) throw new StoreError('invalid_event');
  const sync = opts.synchronous ?? 'FULL';
  if (sync !== 'FULL' && sync !== 'NORMAL') throw new StoreError('invalid_event');
  const clock = opts.clock ?? Date.now;
  const sink = opts.secondarySink ?? ((line: string) => { process.stderr.write(line + '\n'); });
  if (opts.hmacKey !== undefined && (!(opts.hmacKey instanceof Uint8Array) || opts.hmacKey.length < 32)) {
    throw new StoreError('key_invalid');
  }
  if (path === ':memory:' && opts.hmacKey === undefined) throw new StoreError('invalid_event');
  const keyPath = opts.keyPath ?? path + '.key';
  const minRetain = opts.minRetainMs ?? 24 * 3600 * 1000;
  if (typeof minRetain !== 'number' || !Number.isFinite(minRetain) || minRetain < 0) throw new StoreError('invalid_event');
  let protection: KeyProtection = opts.hmacKey !== undefined ? 'external' : 'unprotected';
  const computeProtection = (kp: string, creating: boolean): KeyProtection => {
    if (opts.keyProtect !== undefined) return opts.keyProtect(kp);
    if (process.platform === 'win32' || opts.aclReader !== undefined) {
      const user = opts.aclUser ?? currentUser();
      if (user === null) return 'unprotected';
      const reader = opts.aclReader ?? defaultAclReader;
      if (creating && opts.aclReader === undefined) applyAcl(kp, user);
      try {
        const out = reader(kp);
        return out !== null && evaluateAcl(out, kp, user) ? 'acl' : 'unprotected';
      } catch {
        return 'unprotected';
      }
    }
    try {
      return (statSync(kp).mode & 0o077) === 0 ? 'mode_0600' : 'unprotected';
    } catch {
      return 'unprotected';
    }
  };

  const readOnly = opts.readOnly === true;
  if (opts.readOnly !== undefined && typeof opts.readOnly !== 'boolean') throw new StoreError('invalid_event');
  if (readOnly && path === ':memory:') throw new StoreError('invalid_event');
  let db: DatabaseSync;
  try {
    // readOnly: the file must already exist (SQLite never creates it) and nothing below issues a write.
    db = readOnly ? new DatabaseSync(path, { readOnly: true, timeout: busy }) : new DatabaseSync(path, { timeout: busy });
  } catch (e) {
    throw mapErr(e);
  }
  let key: Buffer = Buffer.alloc(0);
  let genesis = '';
  if (readOnly) {
    try {
      db.exec('PRAGMA busy_timeout=' + String(busy));
      checkSchema(db);
      db.exec('PRAGMA query_only=1');
      const get = (k: string): string | null => {
        const r = db.prepare('SELECT value FROM meta WHERE key=?').get(k) as { value: string | null } | undefined;
        return r?.value ?? null;
      };
      const nonce = get('nonce');
      if (nonce === null || get('schema_version') !== SCHEMA_VERSION) throw new StoreError('corrupt');
      genesis = sha256Hex('prysm-genesis-v1:' + nonce);
      // no key file is read or created in read-only mode; only an explicitly supplied key is usable
      if (opts.hmacKey !== undefined) key = Buffer.from(opts.hmacKey);
      else protection = 'unknown';
    } catch (e) {
      try { db.close(); } catch { /* ignore */ }
      if (e instanceof StoreError) throw e;
      const m = mapErr(e);
      const msg = (e as { message?: unknown } | null)?.message;
      throw typeof msg === 'string' && /no such table/i.test(msg) ? new StoreError('corrupt') : m;
    }
  } else try {
    db.exec('PRAGMA busy_timeout=' + String(busy));
    checkSchema(db);
    db.exec('PRAGMA journal_mode=WAL');
    db.exec('PRAGMA synchronous=' + sync);
    db.exec('BEGIN IMMEDIATE');
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS events(
          seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, ts_ms INTEGER NOT NULL, kind TEXT NOT NULL,
          execution_id TEXT, session_id TEXT, agent_id TEXT, user_hmac TEXT, tool TEXT, effect TEXT, enforcement TEXT,
          rule_ids TEXT, reason_code TEXT, policy_version TEXT, request_digest TEXT, args_hmac TEXT, args_redacted TEXT,
          risk TEXT, latency_us INTEGER, session_tainted INTEGER, provenance_asserted TEXT, model_meta TEXT, outcome TEXT,
          decision_id TEXT, engine_version TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS events_decision_id ON events(decision_id);
        CREATE INDEX IF NOT EXISTS events_kind ON events(kind, seq);
        CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
          BEGIN SELECT RAISE(ABORT, 'append-only'); END;
        CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
          WHEN COALESCE((SELECT value FROM meta WHERE key='prune_open'),'0') <> '1'
          BEGIN SELECT RAISE(ABORT, 'append-only'); END;
      `);
      const get = (k: string): string | null => {
        const r = db.prepare('SELECT value FROM meta WHERE key=?').get(k) as { value: string | null } | undefined;
        return r?.value ?? null;
      };
      const ins = db.prepare('INSERT OR IGNORE INTO meta(key, value) VALUES (?, ?)');
      ins.run('nonce', randomBytes(16).toString('hex'));
      genesis = sha256Hex('prysm-genesis-v1:' + (get('nonce') ?? ''));
      ins.run('schema_version', SCHEMA_VERSION);
      ins.run('genesis_hash', genesis);
      let created: unknown;
      try { created = clock(); } catch { created = 0; }
      ins.run('created_ms', String(typeof created === 'number' && Number.isSafeInteger(created) ? created : 0));
      ins.run('prune_open', '0');
      if (get('schema_version') !== SCHEMA_VERSION) throw new StoreError('corrupt');
      const existingKid = get('key_id');
      if (opts.hmacKey !== undefined) key = Buffer.from(opts.hmacKey);
      else if (existingKid !== null) {
        const k = readKeyFile(keyPath);
        if (k === null) throw new StoreError('key_mismatch'); // never regenerate for an existing store
        key = k;
      } else {
        let present = true;
        try { readFileSync(keyPath); } catch (e) { present = (e as { code?: string }).code !== 'ENOENT'; }
        if (present) {
          const existing = readKeyFile(keyPath);
          if (existing === null) throw new StoreError('key_invalid');
          key = existing;
        } else {
          const nk = randomBytes(32);
          try {
            writeFileSync(keyPath, nk, { flag: 'wx', mode: 0o600 });
            key = nk;
            protection = computeProtection(keyPath, true);
            db.prepare("INSERT OR REPLACE INTO meta(key, value) VALUES ('key_protection', ?)").run(protection);
          } catch (e) {
            if ((e as { code?: string }).code !== 'EEXIST') throw new StoreError('io');
            const k = readKeyFile(keyPath);
            if (k === null) throw new StoreError('key_invalid');
            key = k;
          }
        }
      }
      if (opts.hmacKey === undefined && existingKid !== null) {
        // existing key file: always re-checked on open; meta is only a hint and is never trusted
        protection = computeProtection(keyPath, false);
      }
      const keyIdHex = createHash('sha256').update(key).digest('hex').slice(0, 8);
      ins.run('key_id', keyIdHex);
      if (get('key_id') !== keyIdHex) throw new StoreError('key_mismatch');
      if (get('prune_open') === '1') {
        db.prepare("UPDATE meta SET value='0' WHERE key='prune_open'").run();
        db.prepare("INSERT OR REPLACE INTO meta(key, value) VALUES ('prune_flag_reset', '1')").run();
      }
      db.exec('COMMIT');
    } catch (e) {
      try { db.exec('ROLLBACK'); } catch { /* not in a transaction */ }
      throw e;
    }
  } catch (e) {
    try { db.close(); } catch { /* ignore */ }
    throw mapErr(e);
  }

  // Reads use a separate read-only connection (WAL: sees every committed write, never blocks the writer).
  // ':memory:' databases cannot be shared, so reads fall back to the write connection there.
  let rdb: DatabaseSync = db;
  if (path !== ':memory:') {
    try {
      rdb = new DatabaseSync(path, { readOnly: true, timeout: busy });
      rdb.exec('PRAGMA trusted_schema=OFF');
    } catch (e) {
      try { db.close(); } catch { /* ignore */ }
      throw mapErr(e);
    }
  }

  let closed = false;
  const mkPrep = (conn: DatabaseSync): ((sql: string) => StatementSync) => {
    const cache = new Map<string, StatementSync>();
    return (sql) => {
      let s = cache.get(sql);
      if (s === undefined) {
        s = conn.prepare(sql);
        cache.set(sql, s);
      }
      return s;
    };
  };
  const prep = mkPrep(db);
  const prepR = rdb === db ? prep : mkPrep(rdb);
  const assertOpen = (): void => {
    if (closed) throw new StoreError('io');
  };
  const metaGet = (k: string): string | null => {
    const r = prep('SELECT value FROM meta WHERE key=?').get(k) as { value: string | null } | undefined;
    return r?.value ?? null;
  };
  const metaGetR = (k: string): string | null => {
    const r = prepR('SELECT value FROM meta WHERE key=?').get(k) as { value: string | null } | undefined;
    return r?.value ?? null;
  };

  /** Must be called inside BEGIN IMMEDIATE. */
  const appendRow = (n: Normalized): StoredEvent => {
    if (metaGet('schema_version') !== SCHEMA_VERSION) throw new StoreError('corrupt');
    const tail = prep('SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1').get() as
      | { seq: number; hash: string }
      | undefined;
    if (tail !== undefined && (typeof tail.hash !== 'string' || !Number.isSafeInteger(tail.seq))) throw new StoreError('corrupt');
    const sq = prep("SELECT seq FROM sqlite_sequence WHERE name='events'").get() as { seq: number } | undefined;
    const seq = Math.max(tail?.seq ?? 0, sq?.seq ?? 0) + 1;
    const prev = tail === undefined ? genesis : tail.hash;
    const row: Record<string, unknown> = { seq, prev_hash: prev };
    for (const c of ['id', 'ts_ms', 'kind', 'execution_id', 'session_id', 'agent_id', 'user_hmac', 'tool', 'effect',
      'enforcement', 'reason_code', 'policy_version', 'request_digest', 'args_hmac', 'risk', 'latency_us',
      'session_tainted', 'decision_id', 'engine_version']) row[c] = n.text[c];
    for (const c of JSON_COLS) row[c] = n.json[c];
    const hash = chainHash(row);
    const values = COLS.map((c) => {
      if (c === 'hash') return hash;
      if ((JSON_COLS as readonly string[]).includes(c)) return n.jsonText[c] ?? null;
      return row[c] as string | number | null;
    });
    prep('INSERT INTO events(' + COLS.join(',') + ') VALUES (' + COLS.map(() => '?').join(',') + ')').run(...values);
    return { ...row, hash } as unknown as StoredEvent;
  };

  const inTxn = <T>(fn: () => T): T => {
    assertOpen();
    if (readOnly) throw new StoreError('io');
    try {
      db.exec('BEGIN IMMEDIATE');
    } catch (e) {
      throw mapErr(e);
    }
    try {
      const r = fn();
      db.exec('COMMIT');
      return r;
    } catch (e) {
      try { db.exec('ROLLBACK'); } catch { /* ignore */ }
      throw mapErr(e);
    }
  };

  const append = (ev: NewEvent): StoredEvent => {
    assertOpen();
    if (readOnly) throw new StoreError('io');
    const n = normalize(ev, clock);
    return inTxn(() => appendRow(n));
  };

  const appendShort = (ev: NewEvent): StoredEvent => {
    assertOpen();
    if (readOnly) throw new StoreError('io');
    const n = normalize(ev, clock);
    const t = Math.min(busy, 250);
    try { db.exec('PRAGMA busy_timeout=' + String(t)); } catch { /* ignore */ }
    try {
      return inTxn(() => appendRow(n));
    } finally {
      try { db.exec('PRAGMA busy_timeout=' + String(busy)); } catch { /* ignore */ }
    }
  };
  const appendBestEffort = makeBestEffort(appendShort, sink);

  const checkSeq = (v: unknown): number => {
    if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) throw new StoreError('invalid_event');
    return v;
  };
  const checkLimit = (v: unknown, max: number): number => {
    if (v === undefined) return 1000;
    if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 1 || v > max) throw new StoreError('invalid_event');
    return v;
  };
  const readAll = (sql: string, ...params: (string | number)[]): StoredEvent[] => {
    assertOpen();
    try {
      return (prepR(sql).all(...params) as Row[]).map(toStored);
    } catch (e) {
      throw mapErr(e);
    }
  };

  const iterate = (o: { afterSeq?: number; limit?: number } = {}): StoredEvent[] => {
    if (typeof o !== 'object' || o === null) throw new StoreError('invalid_event');
    const after = o.afterSeq === undefined ? 0 : checkSeq(o.afterSeq);
    const limit = checkLimit(o.limit, 100000);
    return readAll('SELECT * FROM events WHERE seq > ? ORDER BY seq LIMIT ?', after, limit);
  };

  const query = (q: QueryOptions = {}): StoredEvent[] => {
    if (typeof q !== 'object' || q === null) throw new StoreError('invalid_event');
    for (const k of Object.keys(q)) if (!['kind', 'tool', 'sessionId', 'effect', 'afterSeq', 'limit'].includes(k)) bad();
    const where: string[] = ['seq > ?'];
    const params: (string | number)[] = [q.afterSeq === undefined ? 0 : checkSeq(q.afterSeq)];
    if (q.kind !== undefined) {
      if (typeof q.kind !== 'string' || !KINDS.has(q.kind)) bad();
      where.push('kind = ?');
      params.push(q.kind);
    }
    if (q.tool !== undefined) {
      if (typeof q.tool !== 'string') bad();
      where.push('tool = ?');
      params.push(sanitizeText(q.tool));
    }
    if (q.sessionId !== undefined) {
      if (typeof q.sessionId !== 'string') bad();
      where.push('session_id = ?');
      params.push(sanitizeText(q.sessionId));
    }
    if (q.effect !== undefined) {
      if (typeof q.effect !== 'string' || !EFFECTS.has(q.effect)) bad();
      where.push('effect = ?');
      params.push(q.effect);
    }
    const limit = checkLimit(q.limit, 10000);
    return readAll('SELECT * FROM events WHERE ' + where.join(' AND ') + ' ORDER BY seq LIMIT ?', ...params, limit);
  };

  const getEvent = (id: string): StoredEvent | null => {
    if (typeof id !== 'string') throw new StoreError('invalid_event');
    return readAll('SELECT * FROM events WHERE id = ?', sanitizeText(id))[0] ?? null;
  };

  const eventsByDecision = (decisionId: string): StoredEvent[] => {
    if (typeof decisionId !== 'string') throw new StoreError('invalid_event');
    const d = sanitizeText(decisionId);
    return readAll('SELECT * FROM events WHERE id = ? OR decision_id = ? ORDER BY seq LIMIT 1000', d, d);
  };

  const head = (): { seq: number; hash: string } | null => {
    assertOpen();
    try {
      const r = prepR('SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1').get() as { seq: number; hash: string } | undefined;
      return r === undefined ? null : { seq: r.seq, hash: r.hash };
    } catch (e) {
      throw mapErr(e);
    }
  };

  const count = (): number => {
    assertOpen();
    try {
      return (prepR('SELECT COUNT(*) AS c FROM events').get() as { c: number }).c;
    } catch (e) {
      throw mapErr(e);
    }
  };

  const latest = (kind: EventKind): StoredEvent | null => {
    if (!KINDS.has(kind)) throw new StoreError('invalid_event');
    return readAll('SELECT * FROM events WHERE kind=? ORDER BY seq DESC LIMIT 1', kind)[0] ?? null;
  };

  const hmac = (label: HmacLabel, data: string): string => {
    if (!HMAC_LABELS.has(label) || typeof data !== 'string') throw new StoreError('invalid_event');
    if (key.length === 0) throw new StoreError('key_mismatch'); // readOnly open without a usable key
    // First 32 hex chars (128 bits) are kept: ample for correlation, shorter rows.
    return createHmac('sha256', key).update(label + ':' + data, 'utf8').digest('hex').slice(0, 32);
  };

  const anchor = (): Anchor => {
    const h = head();
    let ts: unknown;
    try { ts = clock(); } catch { throw new StoreError('invalid_event'); }
    return { genesis_hash: genesis, head_seq: h?.seq ?? 0, head_hash: h?.hash ?? genesis, ts_ms: checkClock(ts) };
  };

  const anchorValid = (a: unknown): a is Anchor => {
    if (typeof a !== 'object' || a === null) return false;
    const o = a as Record<string, unknown>;
    if (typeof o['genesis_hash'] !== 'string' || !HEX64.test(o['genesis_hash'])) return false;
    if (typeof o['head_hash'] !== 'string' || !HEX64.test(o['head_hash'])) return false;
    const hs = o['head_seq'];
    if (typeof hs !== 'number' || !Number.isSafeInteger(hs) || hs < 0) return false;
    if (hs === 0 && o['head_hash'] !== o['genesis_hash']) return false;
    return true;
  };

  const CHUNK = 1000;

  const verify = (vo: VerifyOptions = {}): VerifyResult => {
    assertOpen();
    const grace = vo.graceMs ?? 10000;
    const errors: VerifyIssue[] = [];
    const warnings: VerifyIssue[] = [];
    let n = 0;
    let headSeq = 0;
    let headHash = genesis;
    let headTs = 0;
    let prunedThrough: number | null = null;
    let cpList: CheckpointInfo[] = [];
    let inRead = false;
    try {
      // One consistent read snapshot for the whole (chunked) pass.
      if (rdb !== db) {
        rdb.exec('BEGIN');
        inRead = true;
      }
      const a = vo.anchor;
      const anchorOk = vo.anchor === undefined ? true : anchorValid(a);
      let expected: { through_seq: number; last_hash: string }[] | null = null;
      let expectedMalformed = false;
      if (vo.expectPruned !== undefined) {
        const list = Array.isArray(vo.expectPruned) ? vo.expectPruned : [vo.expectPruned];
        expected = [];
        for (const e of list) {
          if (typeof e === 'object' && e !== null && typeof e.through_seq === 'number' && Number.isSafeInteger(e.through_seq) &&
            typeof e.last_hash === 'string' && HEX64.test(e.last_hash)) expected.push({ through_seq: e.through_seq, last_hash: e.last_hash });
          else expectedMalformed = true;
        }
        if (expectedMalformed) errors.push({ seq: 0, code: 'checkpoint_missing' });
      }
      const isExpected = (c: { through: unknown; last: unknown }): boolean =>
        expected !== null && expected.some((e) => e.through_seq === c.through && e.last_hash === c.last);
      if (metaGetR('schema_version') !== SCHEMA_VERSION) errors.push({ seq: 0, code: 'schema_version' });
      const metaGenesisOk = metaGetR('genesis_hash') === genesis;
      if (metaGetR('prune_flag_reset') === '1') warnings.push({ seq: 0, code: 'prune_flag_reset' });
      if (protection === 'unprotected') warnings.push({ seq: 0, code: 'key_unprotected' });
      if (protection !== 'external' && path !== ':memory:' &&
        resolve(dirname(keyPath)).toLowerCase() === resolve(dirname(path)).toLowerCase()) {
        warnings.push({ seq: 0, code: 'key_colocated' });
      }

      let prevSeq: number | null = null;
      let prevHash: string | null = null;
      let first: { seq: number; prev: string } | null = null;
      const checkpoints: { seq: number; through: unknown; last: unknown }[] = [];
      const decisions: { seq: number; id: string; ts: number; willExecute: boolean }[] = [];
      const resultCount = new Map<string, number>();
      const resultRows: { seq: number; decision_id: string }[] = [];
      const decisionIds = new Set<string>();
      let anchorHashAtSeq: string | null = null;
      const anchorSeq = anchorOk && a !== undefined ? a.head_seq : -1;

      let after = 0;
      for (;;) {
        const chunk = prepR('SELECT * FROM events WHERE seq > ? ORDER BY seq LIMIT ' + String(CHUNK)).all(after) as Row[];
        if (chunk.length === 0) break;
        for (const raw of chunk) {
          n++;
          let stored: StoredEvent | null = null;
          try {
            stored = toStored(raw);
          } catch {
            stored = null;
          }
          const seqNum = typeof raw['seq'] === 'number' ? raw['seq'] : -1;
          let hashOk = false;
          if (stored !== null) {
            try {
              const { hash: _h, ...rest } = stored;
              void _h;
              hashOk = chainHash(rest as unknown as Record<string, unknown>) === stored.hash;
            } catch {
              hashOk = false;
            }
          }
          if (!hashOk) errors.push({ seq: seqNum, code: 'hash_mismatch' });
          const storedPrev = typeof raw['prev_hash'] === 'string' ? raw['prev_hash'] : '';
          const storedHash = typeof raw['hash'] === 'string' ? raw['hash'] : '';
          if (prevSeq === null) {
            first = { seq: seqNum, prev: storedPrev };
            if (seqNum === 1 && storedPrev !== genesis) errors.push({ seq: seqNum, code: 'bad_genesis' });
          } else {
            if (seqNum !== prevSeq + 1) errors.push({ seq: seqNum, code: 'seq_gap' });
            if (storedPrev !== prevHash) errors.push({ seq: seqNum, code: 'prev_mismatch' });
          }
          if (hashOk && stored !== null) {
            if (stored.kind === 'checkpoint') {
              const oc = stored.outcome as { pruned_through_seq?: unknown; pruned_last_hash?: unknown } | null;
              checkpoints.push({ seq: stored.seq, through: oc?.pruned_through_seq, last: oc?.pruned_last_hash });
            }
            if (stored.kind === 'decision') {
              const oc = stored.outcome as { will_execute?: unknown } | null;
              decisions.push({ seq: stored.seq, id: stored.id, ts: stored.ts_ms, willExecute: oc?.will_execute === true });
              decisionIds.add(stored.id);
            }
            if (stored.kind === 'tool_result' && typeof stored.decision_id === 'string') {
              resultCount.set(stored.decision_id, (resultCount.get(stored.decision_id) ?? 0) + 1);
              resultRows.push({ seq: stored.seq, decision_id: stored.decision_id });
            }
          }
          if (seqNum === anchorSeq && hashOk) anchorHashAtSeq = storedHash;
          prevSeq = seqNum;
          prevHash = storedHash;
          headSeq = seqNum;
          headHash = storedHash;
          headTs = typeof raw['ts_ms'] === 'number' ? raw['ts_ms'] : 0;
          after = seqNum;
        }
        if (chunk.length < CHUNK) break;
      }

      cpList = checkpoints
        .filter((c) => typeof c.through === 'number' && typeof c.last === 'string')
        .map((c) => ({ seq: c.seq, through_seq: c.through as number, last_hash: c.last as string }));
      if (!metaGenesisOk) errors.push({ seq: first?.seq ?? 0, code: 'bad_genesis' });
      if (first !== null && first.seq !== 1) {
        const f = first;
        const ok = checkpoints.some((c) => c.through === f.seq - 1 && c.last === f.prev && (expected === null || isExpected(c)));
        if (!ok) errors.push({ seq: f.seq, code: 'unexpected_first_row' });
        prunedThrough = f.seq - 1;
      }
      // Pruned history is never silently OK: with expectPruned every retained checkpoint must be an expected one.
      for (const c of checkpoints) {
        if (expected !== null) {
          if (!isExpected(c)) errors.push({ seq: c.seq, code: 'history_pruned' });
          else warnings.push({ seq: c.seq, code: 'history_pruned' });
        } else if (vo.allowPruned === true) warnings.push({ seq: c.seq, code: 'history_pruned' });
        else errors.push({ seq: c.seq, code: 'history_pruned' });
      }
      if (expected !== null) {
        for (const e of expected) {
          if (!checkpoints.some((c) => c.through === e.through_seq && c.last === e.last_hash)) errors.push({ seq: 0, code: 'checkpoint_missing' });
        }
      }
      for (const d of decisions) {
        if (d.willExecute && !resultCount.has(d.id) && d.seq < headSeq && headTs - d.ts >= grace) {
          warnings.push({ seq: d.seq, code: 'outcome_unknown' });
        }
      }
      // Results whose decision was pruned (they sit before the first retained decision) are not orphans.
      const firstDecisionSeq = decisions.length > 0 ? decisions.reduce((m, d) => (d.seq < m ? d.seq : m), Infinity) : Infinity;
      for (const r of resultRows) {
        if (decisionIds.has(r.decision_id)) continue;
        if (prunedThrough !== null && checkpoints.length > 0 && r.seq < firstDecisionSeq) continue;
        warnings.push({ seq: r.seq, code: 'orphan_result' });
      }
      for (const d of decisions) if ((resultCount.get(d.id) ?? 0) > 1) warnings.push({ seq: d.seq, code: 'duplicate_result' });

      if (vo.anchor !== undefined) {
        if (!anchorOk || a === undefined) errors.push({ seq: 0, code: 'anchor_mismatch' });
        else {
          const firstSeq = first?.seq ?? 0;
          if (a.genesis_hash !== genesis) errors.push({ seq: 0, code: 'anchor_mismatch' });
          else if (a.head_seq > headSeq) errors.push({ seq: a.head_seq, code: 'anchor_mismatch' });
          else if (a.head_seq === 0) {
            // validated: head_hash === genesis_hash === store genesis
          } else if (n > 0 && a.head_seq >= firstSeq) {
            if (anchorHashAtSeq !== a.head_hash) errors.push({ seq: a.head_seq, code: 'anchor_mismatch' });
          } else {
            const exact = checkpoints.find((c) => c.through === a.head_seq);
            if (exact !== undefined) {
              if (exact.last !== a.head_hash) errors.push({ seq: a.head_seq, code: 'anchor_mismatch' });
            } else if (checkpoints.some((c) => typeof c.through === 'number' && c.through > a.head_seq)) {
              warnings.push({ seq: a.head_seq, code: 'anchor_pruned' });
            } else errors.push({ seq: a.head_seq, code: 'anchor_mismatch' });
          }
        }
      }
    } catch (e) {
      throw mapErr(e);
    } finally {
      if (inRead) {
        try { rdb.exec('COMMIT'); } catch { /* ignore */ }
      }
    }
    return {
      ok: errors.length === 0,
      checkpoints: cpList,
      count: n,
      head_seq: headSeq,
      head_hash: headHash,
      pruned_through: prunedThrough,
      errors,
      warnings,
    };
  };

  const checkpointAndPrune = (before: number, po: { force?: boolean } = {}): PruneResult => {
    if (typeof before !== 'number' || !Number.isFinite(before) || before < 0) throw new StoreError('invalid_event');
    if (typeof po !== 'object' || po === null) throw new StoreError('invalid_event');
    if (po.force !== true) {
      let now: unknown;
      try { now = clock(); } catch { throw new StoreError('invalid_event'); }
      if (before > checkClock(now) - minRetain) throw new StoreError('invalid_event'); // retention floor
    }
    const res = inTxn(() => {
      prep("UPDATE meta SET value='1' WHERE key='prune_open'").run();
      // Longest seq prefix whose rows all have ts_ms < before.
      const firstKeep = prep('SELECT MIN(seq) AS s FROM events WHERE ts_ms >= ?').get(before) as { s: number | null };
      const lastPruned = (firstKeep.s === null
        ? prep('SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1').get()
        : prep('SELECT seq, hash FROM events WHERE seq < ? ORDER BY seq DESC LIMIT 1').get(firstKeep.s)) as
        | { seq: number; hash: string }
        | undefined;
      if (lastPruned === undefined) {
        // nothing eligible: no-op, nothing appended
        prep("UPDATE meta SET value='0' WHERE key='prune_open'").run();
        const f = prep('SELECT seq, prev_hash FROM events ORDER BY seq LIMIT 1').get() as { seq: number; prev_hash: string } | undefined;
        return { pruned: 0, checkpointSeq: 0, through_seq: f === undefined ? 0 : f.seq - 1, last_hash: f === undefined ? genesis : f.prev_hash };
      }
      const through = lastPruned.seq;
      const lastHash = lastPruned.hash;
      const expected = (prep('SELECT COUNT(*) AS c FROM events WHERE seq <= ?').get(through) as { c: number }).c;
      const cp = appendRow(normalize({
        id: randomUUID(),
        kind: 'checkpoint',
        outcome: { pruned_through_seq: through, pruned_last_hash: lastHash, pruned_count: expected },
      }, clock));
      const r = prep('DELETE FROM events WHERE seq <= ? AND seq < ?').run(through, cp.seq);
      const pruned = Number(r.changes);
      if (pruned !== expected) throw new StoreError('corrupt');
      prep("UPDATE meta SET value='0' WHERE key='prune_open'").run();
      return { pruned, checkpointSeq: cp.seq, through_seq: through, last_hash: lastHash };
    });
    if (res.pruned > 0) {
      safeSink(sink, JSON.stringify({ prysm: 'checkpoint', genesis_hash: genesis, through_seq: res.through_seq, last_hash: res.last_hash }));
    }
    return res;
  };

  const close = (): void => {
    if (closed) return;
    closed = true;
    try { if (rdb !== db) rdb.close(); } catch { /* ignore */ }
    try { db.close(); } catch { /* ignore */ }
  };

  return Object.freeze({
    append, appendBestEffort, appendShort, iterate, query, getEvent, eventsByDecision, head, count, latest, verify, anchor,
    checkpointAndPrune, close, hmac, keyProtection: (): KeyProtection => protection,
  });
}
