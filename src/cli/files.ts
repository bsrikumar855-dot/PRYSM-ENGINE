// Shared CLI plumbing: exit-carrying error, bounded file reads, anchor / checkpoint file parsing, policy loading,
// read-only store opening. Messages are fixed strings (+ fixed codes); operator input is never echoed.
import { readFileSync, statSync } from 'node:fs';
import { loadPolicy, parseStrictJson, PolicyError } from '../core/index.ts';
import type { LoadedPolicy, JsonValue } from '../core/index.ts';
import { openStore, StoreError } from '../store/index.ts';
import type { Anchor, Store } from '../store/index.ts';
import { esc } from './text.ts';

export interface Io {
  out(line: string): void;
  err(line: string): void;
}

/** A deliberate early exit with an exit code (1 = verification/lookup failure, 2 = usage/config). */
export class CliExit extends Error {
  exitCode: 1 | 2;
  detail: Record<string, unknown> | null;
  constructor(exitCode: 1 | 2, message: string, detail: Record<string, unknown> | null = null) {
    super(message);
    this.name = 'CliExit';
    this.exitCode = exitCode;
    this.detail = detail;
  }
}

export const MAX_POLICY_BYTES = 1024 * 1024;
export const MAX_SMALL_FILE_BYTES = 1024 * 1024;
export const MAX_LOG_BYTES = 16 * 1024 * 1024;

/** Read a regular file of at most `max` bytes. `label` is an option name from our own spec. */
export function readBounded(path: string, max: number, label: string): Buffer {
  let size: number;
  try {
    const st = statSync(path);
    if (!st.isFile()) throw new CliExit(2, `${label}: not a regular file`);
    size = st.size;
  } catch (e) {
    if (e instanceof CliExit) throw e;
    throw new CliExit(2, `${label}: cannot read file`);
  }
  if (size > max) throw new CliExit(2, `${label}: file too large`);
  try {
    const b = readFileSync(path);
    if (b.length > max) throw new CliExit(2, `${label}: file too large`);
    return b;
  } catch (e) {
    if (e instanceof CliExit) throw e;
    throw new CliExit(2, `${label}: cannot read file`);
  }
}

/** Load a policy file; PolicyError becomes exit 2 with code + path only (never the message, which may carry values). */
export function loadPolicyFile(path: string, label: string): { policy: LoadedPolicy; bytes: Buffer } {
  const bytes = readBounded(path, MAX_POLICY_BYTES, label);
  return { policy: loadPolicyBytes(bytes, label), bytes };
}

export function loadPolicyBytes(bytes: Buffer, label: string): LoadedPolicy {
  try {
    return loadPolicy(bytes);
  } catch (e) {
    if (e instanceof PolicyError) {
      throw new CliExit(2, `${label}: invalid policy ${e.code} ${esc(e.path)}`, { code: e.code, path: esc(e.path) });
    }
    throw new CliExit(2, `${label}: invalid policy`);
  }
}

const NL = new RegExp(String.fromCharCode(92) + 'r?' + String.fromCharCode(92) + 'n');
const HEX64 = /^[0-9a-f]{64}$/;

function parseJsonText(text: string, label: string): JsonValue {
  try {
    return parseStrictJson(text, { maxDepth: 6, maxItems: 10000 });
  } catch {
    throw new CliExit(2, `${label}: malformed JSON`);
  }
}

function toAnchor(v: JsonValue, label: string): Anchor {
  const bad = (): never => {
    throw new CliExit(2, `${label}: malformed anchor`);
  };
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return bad();
  const o = v as { [k: string]: JsonValue };
  if (Object.hasOwn(o, 'prysm') && o['prysm'] !== 'anchor') return bad();
  const g = o['genesis_hash'];
  const h = o['head_hash'];
  const s = o['head_seq'];
  if (typeof g !== 'string' || !HEX64.test(g) || typeof h !== 'string' || !HEX64.test(h)) return bad();
  if (typeof s !== 'number' || !Number.isSafeInteger(s) || s < 0) return bad();
  if (s === 0 && h !== g) return bad();
  const ts = o['ts_ms'];
  if (ts !== undefined && (typeof ts !== 'number' || !Number.isSafeInteger(ts) || ts < 0)) return bad();
  return { genesis_hash: g, head_seq: s, head_hash: h, ts_ms: ts ?? 0 };
}

const WS = /^[ \t\r\n]+|[ \t\r\n]+$/g;

/** UTF-8 text of an input file; a leading BOM is malformed (never stripped) and only JSON whitespace is trimmed. */
function inputText(path: string, label: string): string {
  const b = readBounded(path, MAX_SMALL_FILE_BYTES, label);
  if (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) throw new CliExit(2, `${label}: byte order mark is not allowed`);
  return b.toString('utf8').replace(WS, '');
}

/** The output of `anchor`, or exactly one `{"prysm":"anchor",...}` sink line. Anything else is exit 2. */
export function readAnchorFile(path: string, label: string): Anchor {
  const text = inputText(path, label);
  if (text === '') throw new CliExit(2, `${label}: malformed anchor`);
  return toAnchor(parseJsonText(text, label), label);
}

export interface ExpectedCheckpoint {
  through_seq: number;
  last_hash: string;
}

function toCheckpoint(v: JsonValue, label: string): ExpectedCheckpoint {
  const bad = (): never => {
    throw new CliExit(2, `${label}: malformed checkpoint`);
  };
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return bad();
  const o = v as { [k: string]: JsonValue };
  if (Object.hasOwn(o, 'prysm') && o['prysm'] !== 'checkpoint') return bad();
  const t = o['through_seq'];
  const h = o['last_hash'];
  if (typeof t !== 'number' || !Number.isSafeInteger(t) || t < 0 || typeof h !== 'string' || !HEX64.test(h)) return bad();
  return { through_seq: t, last_hash: h };
}

/** A JSON array, or JSON lines, of `{through_seq,last_hash}` / `{"prysm":"checkpoint",...}` objects. */
export function readExpectedFile(path: string, label: string): ExpectedCheckpoint[] {
  const text = inputText(path, label);
  if (text === '') throw new CliExit(2, `${label}: malformed checkpoint`);
  let items: JsonValue[];
  let whole: JsonValue | undefined;
  try {
    whole = parseStrictJson(text, { maxDepth: 6, maxItems: 10000 });
  } catch {
    whole = undefined;
  }
  if (whole !== undefined) items = Array.isArray(whole) ? whole : [whole];
  else {
    items = [];
    for (const line of text.split(NL)) {
      if (line.trim() === '') continue;
      items.push(parseJsonText(line, label));
    }
  }
  if (items.length > 1000) throw new CliExit(2, `${label}: too many checkpoints`);
  return items.map((i) => toCheckpoint(i, label));
}

/** The newest line of a mixed log that is a JSON object with prysm == "anchor" (lines prefixed `[server] ` are ignored). */
export function readAnchorLog(path: string, label: string): Anchor {
  const text = readBounded(path, MAX_LOG_BYTES, label).toString('utf8');
  let found: JsonValue | undefined;
  for (const line of text.split(NL)) {
    if (line.trim() === '' || line.startsWith('[server] ')) continue;
    let v: JsonValue;
    try {
      v = parseStrictJson(line, { maxDepth: 6, maxItems: 10000 });
    } catch {
      continue;
    }
    if (typeof v === 'object' && v !== null && !Array.isArray(v) && v['prysm'] === 'anchor') found = v;
  }
  if (found === undefined) throw new CliExit(2, `${label}: no anchor line found`);
  return toAnchor(found, label);
}

/** All non-`[server]` lines of a mixed log with prysm == "checkpoint". */
export function readExpectedLog(path: string, label: string): ExpectedCheckpoint[] {
  const text = readBounded(path, MAX_LOG_BYTES, label).toString('utf8');
  const out: ExpectedCheckpoint[] = [];
  for (const line of text.split(NL)) {
    if (line.trim() === '' || line.startsWith('[server] ')) continue;
    let v: JsonValue;
    try {
      v = parseStrictJson(line, { maxDepth: 6, maxItems: 10000 });
    } catch {
      continue;
    }
    if (typeof v === 'object' && v !== null && !Array.isArray(v) && v['prysm'] === 'checkpoint') out.push(toCheckpoint(v, label));
    if (out.length > 1000) throw new CliExit(2, `${label}: too many checkpoints`);
  }
  return out;
}

/** Open an existing store read-only. Never creates a DB or key file and never loads a key. Any failure => exit 2. */
export function openReadOnly(dbPath: string, keyPath: string | undefined): Store {
  try {
    return openStore({
      path: dbPath,
      readOnly: true,
      ...(keyPath !== undefined ? { keyPath } : {}),
      secondarySink: () => {},
    });
  } catch (e) {
    const code = e instanceof StoreError ? e.code : 'unknown';
    throw new CliExit(2, `--db: cannot open store (${code})`, { code });
  }
}
