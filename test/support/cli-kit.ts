// CLI test kit: real child processes (`node src/cli/bin.ts ...`) against stores built by the real guard/store.
import { spawn } from 'node:child_process';
import { copyFileSync, existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPolicy } from '../../src/core/index.ts';
import type { LoadedPolicy } from '../../src/core/index.ts';
import { openStore } from '../../src/store/index.ts';
import type { StoredEvent } from '../../src/store/index.ts';
import { kit } from './guard-kit.ts';
import { POLICY_DOC } from './policy.ts';
import { tmpDir, dbPath } from './tmp.ts';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const BIN = join(ROOT, 'src', 'cli', 'bin.ts');

export interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

export function runCli(args: string[], opts: { cwd?: string } = {}): Promise<CliResult> {
  return new Promise((res, rej) => {
    const child = spawn(process.execPath, [BIN, ...args], { cwd: opts.cwd ?? ROOT, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on('data', (d: Buffer) => out.push(d));
    child.stderr.on('data', (d: Buffer) => err.push(d));
    child.on('error', rej);
    child.on('close', (code) => res({ code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }));
  });
}

export const lines = (s: string): string[] => s.split('\n').filter((l) => l !== '');

export interface GuardFixture {
  dir: string;
  db: string;
  policyPath: string;
  policy: LoadedPolicy;
  rows: StoredEvent[];
  /** id of a decision that was denied by a rule (read_file /secret...). */
  deniedId: string;
  /** id of a permitted decision that executed and has a tool_result row. */
  allowedId: string;
  /** id of a tool_result row. */
  resultId: string;
  /** The `{"prysm":"anchor",...}` line the guard wrote to its secondary sink on close. */
  anchorLine: string;
}

/** A store written by the real guard (permit, rule deny, default deny, unknown tool, invalid args), then closed. */
export async function guardFixture(): Promise<GuardFixture> {
  const k = kit();
  const ok = await k.guard.call('read_file', { path: '/docs/readme.txt' });
  const denied = await k.guard.call('read_file', { path: '/secret/keys.txt' });
  await k.guard.call('denied_by_default', { x: 'a' });
  await k.guard.call('does_not_exist', { x: 1 });
  await k.guard.call('read_file', { path: 5 });
  await k.guard.call('send_email', { to: 'a@example.com', subject: 's', body: 'b' });
  await k.guard.call('search_docs', { query: 'q' });
  k.guard.close();
  const rows = k.rows();
  const policyPath = join(k.dir, 'policy.json');
  writeFileSync(policyPath, JSON.stringify(POLICY_DOC('enforce', [])));
  const allowedId = (ok as { decision_id: string }).decision_id;
  const resultId = (rows.find((r) => r.kind === 'tool_result' && r.decision_id === allowedId) as StoredEvent).id;
  k.store.close();
  return {
    dir: k.dir, db: k.path, policyPath, policy: loadPolicy(JSON.stringify(POLICY_DOC('enforce', []))), rows,
    anchorLine: k.lines.find((l) => l.includes('"prysm":"anchor"')) as string,
    deniedId: (denied as { decision_id: string }).decision_id, allowedId, resultId,
  };
}

/** A store with a real key FILE (no external key), filled by direct appends; closed. */
export function keyedFixture(n = 3, extra: (i: number) => Record<string, unknown> = () => ({})): { dir: string; db: string; keyPath: string } {
  const dir = tmpDir();
  const db = dbPath(dir);
  const s = openStore({ path: db, secondarySink: () => {} });
  for (let i = 1; i <= n; i++) s.append({ id: `ev-${i}-aaaaaaaa`, kind: 'decision', ts_ms: 1_700_000_000_000 + i, effect: 'permit', enforcement: 'enforced', reason_code: 'permitted', tool: 'search_docs', ...extra(i) });
  s.close();
  return { dir, db, keyPath: db + '.key' };
}

export interface Snapshot {
  bytes: Buffer;
  mtimeMs: number;
  wal: number | null;
  keyExists: boolean;
}

export function snapshot(db: string, keyPath: string): Snapshot {
  return {
    bytes: readFileSync(db),
    mtimeMs: statSync(db).mtimeMs,
    wal: existsSync(db + '-wal') ? statSync(db + '-wal').size : null,
    keyExists: existsSync(keyPath),
  };
}

export function copyDb(from: string, to: string): void {
  copyFileSync(from, to);
}

/** Open the DB raw (as an attacker with file access would), drop the append-only triggers, run `fn`. */
export function rawTamper(db: string, fn: (d: DatabaseSync) => void): void {
  const d = new DatabaseSync(db);
  try {
    d.exec('DROP TRIGGER IF EXISTS events_no_update; DROP TRIGGER IF EXISTS events_no_delete;');
    fn(d);
  } finally {
    d.close();
  }
}

const sha = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');
function canon(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return '{' + Object.keys(o).sort().map((k) => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

/** Append a hash-valid but forged checkpoint row at the tail (an attacker who can write the DB can do this). */
export function forgeCheckpoint(db: string, through: number, lastHash: string): void {
  const d = new DatabaseSync(db);
  try {
    const tail = d.prepare('SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1').get() as { seq: number; hash: string };
    const row: Record<string, unknown> = {
      seq: tail.seq + 1, id: 'forged-' + String(tail.seq + 1), ts_ms: 5, kind: 'checkpoint', execution_id: null, session_id: null,
      agent_id: null, user_hmac: null, tool: null, effect: null, enforcement: null, rule_ids: null, reason_code: null,
      policy_version: null, request_digest: null, args_hmac: null, args_redacted: null, risk: null, latency_us: null,
      session_tainted: null, provenance_asserted: null, model_meta: null,
      outcome: { pruned_through_seq: through, pruned_last_hash: lastHash, pruned_count: through }, decision_id: null,
      engine_version: null, prev_hash: tail.hash,
    };
    const hash = sha(tail.hash + String.fromCharCode(10) + canon(row));
    const cols = Object.keys(row);
    const jsonCols = ['rule_ids', 'args_redacted', 'provenance_asserted', 'model_meta', 'outcome'];
    d.prepare(`INSERT INTO events(${cols.join(',')}, hash) VALUES (${cols.map(() => '?').join(',')}, ?)`).run(
      ...cols.map((c) => (jsonCols.includes(c) && row[c] !== null ? JSON.stringify(row[c]) : (row[c] as string | number | null))), hash);
  } finally {
    d.close();
  }
}
