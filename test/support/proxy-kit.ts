// Proxy test kit: policy, fixture-server command, an MCP client over in-memory streams or the real CLI process.
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { PassThrough, Writable } from 'node:stream';
import { openStore } from '../../src/store/index.ts';
import type { Store, StoredEvent } from '../../src/store/index.ts';
import { createProxy, definitionHash } from '../../src/proxy/index.ts';
import type { ProxyHandle, ProxyOptions } from '../../src/proxy/index.ts';
import { rule } from './policy.ts';
import { tmpDir } from './tmp.ts';

export { definitionHash };
export const KEY = new Uint8Array(32).fill(9);
export const FIXTURE = resolve(import.meta.dirname, 'mcp-server.ts');
export const BIN = resolve(import.meta.dirname, '../../src/proxy/bin.ts');

type Json = Record<string, unknown>;

export function policyDoc(extraTools: Json = {}, extraRules: unknown[] = []): Json {
  return {
    policy_schema_version: 1,
    name: 'proxy-test',
    mode: 'enforce',
    tools: {
      echo: { risk: 'low', external_effect: false, read_only: true, fail_mode: 'closed', args: { text: { type: 'string' }, delay_ms: { type: 'number', optional: true } } },
      send_email: {
        risk: 'high', external_effect: true, read_only: false, fail_mode: 'closed',
        args: { to: { type: 'string' }, subject: { type: 'string', optional: true }, body: { type: 'string', optional: true } },
      },
      search_docs: { risk: 'low', external_effect: false, read_only: true, fail_mode: 'closed', args: { query: { type: 'string' } } },
      slow: { risk: 'low', external_effect: false, read_only: true, fail_mode: 'closed', args: { x: { type: 'string', optional: true } } },
      crash: { risk: 'low', external_effect: false, read_only: true, fail_mode: 'closed', args: { x: { type: 'string', optional: true } } },
      big: { risk: 'low', external_effect: false, read_only: true, fail_mode: 'closed', args: { bytes: { type: 'number' } } },
      weird: { risk: 'low', external_effect: false, read_only: true, fail_mode: 'closed', args: { mode: { type: 'string' } } },
      ...extraTools,
    },
    rules: [
      rule('permit', 'p.echo', { tools: ['echo'] }),
      rule('permit', 'p.email', { tools: ['send_email'] }),
      rule('permit', 'p.search', { tools: ['search_docs'] }),
      rule('permit', 'p.slow', { tools: ['slow'] }),
      rule('permit', 'p.crash', { tools: ['crash'] }),
      rule('permit', 'p.big', { tools: ['big'] }),
      rule('permit', 'p.weird', { tools: ['weird'] }),
      rule('deny', 'd.echo.secret', { tools: ['echo'], args: { text: { glob: 'deny*' } } }),
      ...extraRules,
    ],
  };
}

export interface Env {
  dir: string;
  policyPath: string;
  dbPath: string;
  keyPath: string;
  stderrText(): string;
}

export function makeEnv(doc: Json = policyDoc()): Env {
  const dir = tmpDir('prysm-proxy-');
  const policyPath = join(dir, 'policy.json');
  writeFileSync(policyPath, JSON.stringify(doc));
  return { dir, policyPath, dbPath: join(dir, 'audit.db'), keyPath: join(dir, 'audit.key'), stderrText: () => '' };
}

export function serverArgs(env: Env, extra: string[] = []): string[] {
  return ['--no-warnings=ExperimentalWarning', FIXTURE, '--dir', env.dir, ...extra];
}
export const serverCalls = (env: Env): Json[] => readJsonl(join(env.dir, 'calls.jsonl'));
export const serverMethods = (env: Env): Json[] => readJsonl(join(env.dir, 'methods.jsonl'));
export const callCount = (env: Env, tool?: string): number =>
  serverCalls(env).filter((c) => tool === undefined || c['tool'] === tool).length;

export function readJsonl(path: string): Json[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l) as Json);
}

/** Opens the audit store after the proxy is closed (read-only use). */
export function openAudit(env: Env, byKeyFile = false): Store {
  return byKeyFile ? openStore({ path: env.dbPath, keyPath: env.keyPath }) : openStore({ path: env.dbPath, hmacKey: KEY });
}
export const rowsOf = (s: Store): StoredEvent[] => s.iterate({ limit: 100000 });

// ------------------------------------------------------------------ client
export class Client {
  readonly messages: Json[] = [];
  readonly rawLines: string[] = [];
  readonly #write: (s: string | Buffer) => void;
  readonly #end: () => void;
  #buf = '';
  #waiters: { pred: (m: Json) => boolean; resolve: (m: Json) => void }[] = [];
  #id = 0;

  constructor(write: (s: string | Buffer) => void, end: () => void) {
    this.#write = write;
    this.#end = end;
  }

  feed(chunk: Buffer | string): void {
    this.#buf += chunk.toString();
    for (;;) {
      const i = this.#buf.indexOf('\n');
      if (i < 0) return;
      const line = this.#buf.slice(0, i);
      this.#buf = this.#buf.slice(i + 1);
      if (line === '') continue;
      this.rawLines.push(line);
      let m: Json;
      try { m = JSON.parse(line) as Json; } catch { throw new Error('non-JSON line on client channel'); }
      this.messages.push(m);
      for (const w of [...this.#waiters]) {
        if (w.pred(m)) {
          this.#waiters.splice(this.#waiters.indexOf(w), 1);
          w.resolve(m);
        }
      }
    }
  }

  sendRaw(line: string): void { this.#write(line + '\n'); }
  sendBytes(b: Buffer): void { this.#write(b); }
  send(m: Json): void { this.#write(JSON.stringify(m) + '\n'); }
  end(): void { this.#end(); }

  next(pred: (m: Json) => boolean, timeoutMs = 15000): Promise<Json> {
    const have = this.messages.find(pred);
    if (have) return Promise.resolve(have);
    return new Promise((res, rej) => {
      const t = setTimeout(() => { rej(new Error('client wait timeout')); }, timeoutMs);
      this.#waiters.push({ pred, resolve: (m) => { clearTimeout(t); res(m); } });
    });
  }

  reply(id: unknown, timeoutMs?: number): Promise<Json> {
    return this.next((m) => m['id'] === id && ('result' in m || 'error' in m), timeoutMs);
  }

  request(method: string, params?: unknown, id?: number | string): Promise<Json> {
    const rid = id ?? ++this.#id + 1000;
    this.send({ jsonrpc: '2.0', id: rid, method, ...(params !== undefined ? { params } : {}) });
    return this.reply(rid);
  }

  call(name: string, args: unknown, id?: number | string): Promise<Json> {
    return this.request('tools/call', { name, arguments: args }, id);
  }

  async handshake(): Promise<Json[]> {
    await this.request('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } });
    this.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const l = await this.request('tools/list');
    return ((l['result'] as Json)['tools'] as Json[]) ?? [];
  }
}

export const toolText = (r: Json): string => {
  const res = r['result'] as Json | undefined;
  const c = (res?.['content'] as Json[] | undefined)?.[0];
  return String(c?.['text'] ?? '');
};
export const isErr = (r: Json): boolean => (r['result'] as Json | undefined)?.['isError'] === true;

// ------------------------------------------------------------------ in-process proxy
export interface Lib {
  client: Client;
  handle: ProxyHandle;
  stderr: string[];
  stderrText(): string;
  done: Promise<number>;
  env: Env;
}

export interface LibOpts {
  serverExtra?: string[];
  proxy?: Partial<ProxyOptions>;
  env?: Env;
  processEnv?: Record<string, string | undefined>;
  clientIn?: PassThrough;
}

export function startLib(o: LibOpts = {}): Lib {
  const env = o.env ?? makeEnv();
  const clientIn = o.clientIn ?? new PassThrough();
  const stderr: string[] = [];
  const err = new Writable({ write(c: Buffer, _e, cb) { stderr.push(c.toString()); cb(); } });
  const client = new Client((s) => { clientIn.write(s); }, () => { clientIn.end(); });
  const clientOut = new Writable({ write(c: Buffer, _e, cb) { client.feed(c); cb(); } });
  const handle = createProxy({
    policyPath: env.policyPath,
    dbPath: env.dbPath,
    hmacKey: KEY,
    server: { command: process.execPath, args: serverArgs(env, o.serverExtra ?? []) },
    clientIn,
    clientOut,
    stderr: err,
    killGraceMs: 3000,
    ...(o.processEnv ? { processEnv: o.processEnv } : {}),
    ...(o.proxy ?? {}),
  });
  return { client, handle, stderr, stderrText: () => stderr.join(''), done: handle.done, env };
}

// ------------------------------------------------------------------ real CLI process
export interface Cli {
  client: Client;
  child: ChildProcess;
  stderrText(): string;
  exited: Promise<number | null>;
  env: Env;
}

export function startCli(o: { env?: Env; flags?: string[]; serverExtra?: string[]; childEnv?: Record<string, string>; noServer?: boolean } = {}): Cli {
  const env = o.env ?? makeEnv();
  const flags = o.flags ?? ['--policy', env.policyPath, '--db', env.dbPath, '--key-path', env.keyPath, '--tool-timeout-ms', '20000'];
  const args = ['--no-warnings=ExperimentalWarning', BIN, ...flags, ...(o.noServer ? [] : ['--', process.execPath, ...serverArgs(env, o.serverExtra ?? [])])];
  const child = spawn(process.execPath, args, {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, ...(o.childEnv ?? {}) },
    windowsHide: true,
  });
  const err: string[] = [];
  child.stderr?.on('data', (c: Buffer) => { err.push(c.toString()); });
  const client = new Client((s) => { child.stdin?.write(s); }, () => { child.stdin?.end(); });
  child.stdout?.on('data', (c: Buffer) => { client.feed(c); });
  child.stdin?.on('error', () => undefined);
  const exited = new Promise<number | null>((res) => { child.on('close', (c) => { res(c); }); });
  return { client, child, stderrText: () => err.join(''), exited, env };
}

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
export async function waitFor(pred: () => boolean, timeoutMs = 10000): Promise<void> {
  const t0 = Date.now();
  while (!pred()) {
    if (Date.now() - t0 > timeoutMs) throw new Error('waitFor timeout');
    await sleep(20);
  }
}
