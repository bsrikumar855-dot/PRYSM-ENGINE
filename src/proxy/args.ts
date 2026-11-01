// CLI argument parsing for the proxy. Errors carry a short code only (never a flag value).
import type { ProxyOptions } from './proxy.ts';

export class ArgsError extends Error {
  readonly code: string;
  constructor(code: string) {
    super('invalid arguments: ' + code);
    this.name = 'ArgsError';
    this.code = code;
  }
}

export type CliConfig = Omit<ProxyOptions, 'clientIn' | 'clientOut' | 'stderr' | 'spawn' | 'hmacKey' | 'processEnv' | 'listTimeoutMs' | 'killGraceMs'>;

const VALUE_FLAGS = new Set([
  '--policy', '--db', '--key-path', '--agent-id', '--policy-sha256', '--taint-tools', '--tool-timeout-ms',
  '--list-mode', '--allow-methods', '--env', '--user-id', '--scopes', '--provenance', '--ready-timeout-ms',
  '--allow-server-requests', '--max-server-line-bytes', '--forward-timeout-ms',
]);
const BOOL_FLAGS = new Set(['--require-pins', '--allow-server-notifications']);

// empty entries are kept so createProxy rejects them (exit 2)
const csv = (v: string): string[] => v.split(',');

export function parseArgs(argv: readonly string[]): CliConfig {
  const sep = argv.indexOf('--');
  if (sep < 0) throw new ArgsError('missing_server_command');
  const rest = argv.slice(sep + 1);
  const flags = argv.slice(0, sep);
  const cmd = rest[0];
  if (cmd === undefined || cmd === '') throw new ArgsError('missing_server_command');
  const seen = new Map<string, string>();
  const envNames: string[] = [];
  const provPairs: string[] = [];
  const bools = new Set<string>();
  for (let i = 0; i < flags.length; i++) {
    const f = flags[i] as string;
    if (BOOL_FLAGS.has(f)) { bools.add(f); continue; }
    if (!VALUE_FLAGS.has(f)) throw new ArgsError('unknown_flag');
    const v = flags[++i];
    if (v === undefined) throw new ArgsError('missing_value');
    if (f === '--env') { envNames.push(...csv(v)); continue; }
    if (f === '--provenance') { provPairs.push(v); continue; }
    if (seen.has(f)) throw new ArgsError('duplicate_flag');
    seen.set(f, v);
  }
  const policyPath = seen.get('--policy');
  const dbPath = seen.get('--db');
  if (policyPath === undefined || policyPath === '' || dbPath === undefined || dbPath === '') throw new ArgsError('missing_required');
  const out: CliConfig = { policyPath, dbPath, server: { command: cmd, args: rest.slice(1) } };
  const kp = seen.get('--key-path');
  if (kp !== undefined) out.keyPath = kp;
  const ag = seen.get('--agent-id');
  if (ag !== undefined) out.agentId = ag;
  const sha = seen.get('--policy-sha256');
  if (sha !== undefined) {
    if (!/^[0-9a-fA-F]{64}$/.test(sha)) throw new ArgsError('bad_value');
    out.policySha256 = sha;
  }
  const tt = seen.get('--taint-tools');
  if (tt !== undefined) out.taintTools = csv(tt);
  for (const [flag, key] of [['--tool-timeout-ms', 'toolTimeoutMs'], ['--ready-timeout-ms', 'readyTimeoutMs'], ['--forward-timeout-ms', 'forwardTimeoutMs'], ['--max-server-line-bytes', 'maxServerLineBytes']] as const) {
    const v = seen.get(flag);
    if (v !== undefined) {
      if (!/^[1-9][0-9]{0,9}$/.test(v)) throw new ArgsError('bad_value');
      out[key] = Number(v);
    }
  }
  const lm = seen.get('--list-mode');
  if (lm !== undefined) {
    if (lm !== 'hide' && lm !== 'show') throw new ArgsError('bad_value');
    out.listMode = lm;
  }
  // list values are validated strictly by createProxy (no empty entries are silently accepted here)
  const am = seen.get('--allow-methods');
  if (am !== undefined) out.allowMethods = am.split(',');
  const asr = seen.get('--allow-server-requests');
  if (asr !== undefined) out.allowServerRequests = asr.split(',');
  if (envNames.length > 0) out.env = envNames;
  const uid = seen.get('--user-id');
  if (uid !== undefined) out.userId = uid;
  const sc = seen.get('--scopes');
  if (sc !== undefined) out.scopes = sc.split(',');
  if (provPairs.length > 0) {
    const prov: Record<string, string[]> = {};
    for (const p of provPairs) {
      const i = p.indexOf('=');
      if (i <= 0) throw new ArgsError('bad_value');
      const k = p.slice(0, i);
      const label = p.slice(i + 1);
      if (k === '__proto__') throw new ArgsError('bad_value');
      (Object.hasOwn(prov, k) ? (prov[k] as string[]) : (prov[k] = [])).push(label);
    }
    out.provenance = prov;
  }
  if (bools.has('--require-pins')) out.requirePins = true;
  if (bools.has('--allow-server-notifications')) out.allowServerNotifications = true;
  return out;
}
