// W6: MCP tools/call round trip, client -> fixture server directly vs client -> PRYSM proxy (real CLI process) -> same fixture server.
// Reuses the test fixture server and client helpers (test/support). Both legs use real OS pipes and a real server process.
import { spawn } from 'node:child_process';
import { Client, isErr, makeEnv, openAudit, serverArgs, startCli } from '../../test/support/proxy-kit.ts';
import { cleanup } from '../../test/support/tmp.ts';
import { checkRows } from '../lib/accounting.ts';
import { timeAsync } from '../lib/timer.ts';
import type { CaseCtx, CaseDef, CaseOutput } from '../lib/types.ts';

async function loop(client: Client, c: CaseCtx): Promise<{ samplesNs: number[]; errors: number }> {
  await client.handshake();
  let errors = 0;
  const samplesNs = await timeAsync(async (i) => {
    const r = await client.call('send_email', { to: 'user' + String(i % 10) + '@corp.com', subject: 'ping' });
    if (isErr(r) || 'error' in r) errors++;
  }, c.warmup, c.iters);
  return { samplesNs, errors };
}

const direct: CaseDef = {
  id: 'W6.direct', workload: 'W6', title: 'tools/call send_email round trip (the fixture answers it synchronously, no server-side timer), client -> fixture MCP server (no proxy)', size: 'guard', repeat: true,
  run: async (c): Promise<CaseOutput> => {
    const env = makeEnv();
    const child = spawn(process.execPath, serverArgs(env), { stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true });
    const client = new Client((s) => { child.stdin.write(s); }, () => { child.stdin.end(); });
    child.stdout.on('data', (d: Buffer) => { client.feed(d); });
    child.stdin.on('error', () => undefined);
    const exited = new Promise<void>((res) => { child.on('close', () => { res(); }); });
    try {
      const { samplesNs, errors } = await loop(client, c);
      client.end();
      await exited;
      return { kind: 'latency', samplesNs, extra: { calls_total: c.warmup + c.iters, error_replies: errors, audit_rows: 0 } };
    } finally {
      if (child.exitCode === null) child.kill();
      cleanup();
    }
  },
};

const proxy: CaseDef = {
  id: 'W6.proxy', workload: 'W6', title: 'tools/call send_email round trip (the fixture answers it synchronously, no server-side timer), client -> PRYSM proxy (CLI process, permit path) -> fixture MCP server', size: 'guard', repeat: true,
  run: async (c): Promise<CaseOutput> => {
    const cli = startCli();
    try {
      const { samplesNs, errors } = await loop(cli.client, c);
      cli.client.end();
      await cli.exited;
      const store = openAudit(cli.env, true);
      const rows = store.iterate({ limit: 100_000 });
      const decisions = rows.filter((r) => r.kind === 'decision' && r.tool === 'send_email').length;
      const total = store.count();
      store.close();
      const calls = c.warmup + c.iters;
      const results = rows.filter((r) => r.kind === 'tool_result').length;
      if (decisions !== calls) throw new Error(`W6 proxy: ${decisions} decision rows for ${calls} calls`);
      if (results < Math.floor(calls * 0.999)) throw new Error(`W6 proxy: only ${results} tool_result rows for ${calls} calls`);
      const acc = checkRows('W6 proxy', calls, 2, total);
      return { kind: 'latency', samplesNs, extra: { ...acc, error_replies: errors, tool_decision_rows: decisions, tool_result_rows: results } };
    } finally {
      if (cli.child.exitCode === null) cli.child.kill();
      cleanup();
    }
  },
};

export const cases: CaseDef[] = [direct, proxy];
