// MCP stdio server exposing the support-agent tools (used behind the PRYSM proxy).
// Run: node mcp-server.ts --root <dir> --docs-port <port>   (the proxy passes a minimal environment, so no env vars are used)
import { createInterface } from 'node:readline';
import { TOOL_SCHEMAS, makeTools } from './tools.ts';
import type { Workspace } from './tools.ts';
import { join } from 'node:path';

const argv = process.argv.slice(2);
const opt = (n: string): string | undefined => {
  const i = argv.indexOf(n);
  return i >= 0 ? argv[i + 1] : undefined;
};
const root = opt('--root');
const port = Number(opt('--docs-port'));
if (root === undefined || !Number.isInteger(port)) throw new Error('--root and --docs-port required');
// The workspace is created by the host before the proxy starts; only the paths are rebuilt here.
const w: Workspace = {
  root, docsDir: join(root, 'docs'), wsDir: join(root, 'workspace'), stateDir: join(root, 'state'),
  outboxPath: join(root, 'state', 'outbox.jsonl'), ledgerPath: join(root, 'state', 'ledger.jsonl'),
  invocationsPath: join(root, 'state', 'invocations.jsonl'),
};
const tools = makeTools(w, port);

type Json = Record<string, unknown>;
const send = (m: Json): void => { process.stdout.write(JSON.stringify(m) + '\n'); };

const toolDefs = Object.entries(TOOL_SCHEMAS).map(([name, s]) => ({
  name, description: s.description, inputSchema: { type: 'object', properties: s.properties, required: s.required },
}));

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', (line) => {
  if (line.trim() === '') return;
  const m = JSON.parse(line) as Json;
  const id = m['id'];
  if (typeof m['method'] !== 'string' || id === undefined) return;
  switch (m['method']) {
    case 'initialize':
      send({ jsonrpc: '2.0', id, result: { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'support-agent-tools', version: '0' } } });
      return;
    case 'ping':
      send({ jsonrpc: '2.0', id, result: {} });
      return;
    case 'tools/list':
      send({ jsonrpc: '2.0', id, result: { tools: toolDefs } });
      return;
    case 'tools/call': {
      const p = (m['params'] ?? {}) as Json;
      const impl = Object.hasOwn(tools, String(p['name'])) ? tools[String(p['name'])] : undefined;
      if (impl === undefined) { send({ jsonrpc: '2.0', id, error: { code: -32602, message: 'unknown tool' } }); return; }
      impl((p['arguments'] ?? {}) as Json).then(
        (v) => { send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(v) }] } }); },
        (e: unknown) => { send({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: e instanceof Error ? e.message : 'error' }] } }); },
      );
      return;
    }
    default:
      send({ jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found' } });
  }
});
rl.on('close', () => { process.exit(0); });
