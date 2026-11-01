// Minimal MCP client over a child process's stdio (newline-delimited JSON-RPC). Used by the proxy variant.
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import type { Executor, Outcome } from './agent.ts';
import type { Args } from './tools.ts';

type Json = Record<string, unknown>;

export interface McpClient {
  child: ChildProcess;
  stderr(): string;
  request(method: string, params?: unknown): Promise<Json>;
  executor(): Executor;
  /** Closes stdin (clean shutdown) and waits for the process to exit. */
  close(): Promise<number | null>;
}

const BLOCK_RE = /^Blocked by PRYSM policy: (\w+) \(decision ([0-9a-f-]{36})\)$/;

export function startMcpClient(command: string, args: string[]): McpClient {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  const err: string[] = [];
  child.stderr?.on('data', (c: Buffer) => { err.push(c.toString()); });
  child.stdin?.on('error', () => undefined);
  const pending = new Map<number, (m: Json) => void>();
  const rl = createInterface({ input: child.stdout as NodeJS.ReadableStream, crlfDelay: Infinity });
  rl.on('line', (line) => {
    let m: Json;
    try { m = JSON.parse(line) as Json; } catch { return; }
    const id = m['id'];
    if (typeof id === 'number') { pending.get(id)?.(m); pending.delete(id); }
  });
  const exited = new Promise<number | null>((res) => { child.on('close', (c) => { res(c); }); });
  let nextId = 1;
  const request = (method: string, params?: unknown): Promise<Json> => {
    const id = nextId++;
    return new Promise((res, rej) => {
      const t = setTimeout(() => { pending.delete(id); rej(new Error('mcp timeout: ' + method)); }, 20000);
      pending.set(id, (m) => { clearTimeout(t); res(m); });
      child.stdin?.write(JSON.stringify({ jsonrpc: '2.0', id, method, ...(params !== undefined ? { params } : {}) }) + '\n');
    });
  };
  const executor = (): Executor => ({
    async run(tool: string, a: Args): Promise<Outcome> {
      const r = await request('tools/call', { name: tool, arguments: a });
      const res = r['result'] as Json | undefined;
      const text = String(((res?.['content'] as Json[] | undefined)?.[0])?.['text'] ?? (r['error'] !== undefined ? 'error' : ''));
      if (res?.['isError'] === true) {
        const b = BLOCK_RE.exec(text);
        if (b !== null) return { tool, args: a, status: 'blocked', reason: b[1] as string, decisionId: b[2] as string, text };
        return { tool, args: a, status: 'error', reason: 'tool_error', decisionId: null, text };
      }
      if (r['error'] !== undefined) return { tool, args: a, status: 'error', reason: 'rpc_error', decisionId: null, text };
      return { tool, args: a, status: 'ok', reason: null, decisionId: null, text };
    },
  });
  return {
    child,
    stderr: () => err.join(''),
    request,
    executor,
    close: async () => {
      child.stdin?.end();
      const t = setTimeout(() => { child.kill(); }, 10000);
      const code = await exited;
      clearTimeout(t);
      return code;
    },
  };
}

export async function handshake(c: McpClient): Promise<string[]> {
  await c.request('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'support-agent-demo', version: '0' } });
  c.child.stdin?.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  const l = await c.request('tools/list');
  return (((l['result'] as Json | undefined)?.['tools'] as Json[] | undefined) ?? []).map((t) => String(t['name']));
}
