// Deterministic 200-rule synthetic policy and request pools (W1-W3). Same seed => byte-identical output.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadPolicy } from '../../src/core/index.ts';
import type { LoadedPolicy } from '../../src/core/index.ts';
import { mulberry32 } from './prng.ts';
import type { Rng } from './prng.ts';

export const FIXTURE_POLICY_PATH = resolve(import.meta.dirname, '..', '..', 'eval', 'policies', 'support-agent.policy.json');
export const SYNTH_RULES = 200;
const TOOLS = 10;

type Json = Record<string, unknown>;

export function loadFixturePolicy(): LoadedPolicy {
  return loadPolicy(readFileSync(FIXTURE_POLICY_PATH, 'utf8'));
}

/** The synthetic policy document: 10 tools sharing one schema {a, b, n, list?}, 200 rules over eight predicate shapes. */
export function syntheticPolicyDoc(seed: number): Json {
  const rng = mulberry32(seed);
  const tools: Json = {};
  for (let t = 0; t < TOOLS; t++) {
    tools[`tool_${t}`] = {
      risk: ['low', 'medium', 'high'][t % 3],
      external_effect: t % 2 === 0,
      read_only: t % 2 === 1,
      fail_mode: 'closed',
      args: { a: { type: 'string' }, b: { type: 'string' }, n: { type: 'number' }, list: { type: 'string[]', optional: true } },
    };
  }
  const rules: Json[] = [];
  for (let i = 0; i < SYNTH_RULES; i++) {
    const id = `syn.r${String(i).padStart(3, '0')}`;
    const ti = rng.int(TOOLS);
    const tj = (ti + 1 + rng.int(TOOLS - 1)) % TOOLS;
    const tok = rng.hex(6);
    let effect: 'permit' | 'deny';
    let match: Json;
    switch (i % 8) {
      case 0:
        effect = 'permit';
        match = { tools: [`tool_${ti}`], args: { a: { glob: 'ok*' } } };
        break;
      case 1:
        effect = 'deny';
        match = { tools: [`tool_${ti}`], args: { a: { glob: `*bad${tok}*` } } };
        break;
      case 2:
        effect = 'permit';
        match = { tools: [`tool_${ti}`], args: { n: { range: { min: 0, max: 50 + rng.int(100) } } } };
        break;
      case 3:
        effect = 'deny';
        match = { args: { a: { equals: `blocked-${tok}` } } };
        break;
      case 4:
        effect = 'permit';
        match = { tools: [`tool_${ti}`], args: { b: { path_within: { root: `/work/${tok}`, case_insensitive: false } } } };
        break;
      case 5:
        effect = 'deny';
        match = { tools: [`tool_${ti}`, `tool_${tj}`], args: { a: { glob: `*x*y${tok}*z` } } };
        break;
      case 6:
        effect = 'permit';
        match = { tools: [`tool_${ti}`], args: { b: { domain_suffix: `d${tok}.corp.example`, accept: ['email'] } } };
        break;
      default:
        effect = 'deny';
        match = { tools: [`tool_${ti}`], args: { list: { glob: `*forbidden${tok}*` } } };
        break;
    }
    rules.push({ id, effect, reason_code: `syn_r${String(i).padStart(3, '0')}`, match });
  }
  return { policy_schema_version: 1, name: 'bench-synthetic-200', mode: 'enforce', tools, rules };
}

export function loadSyntheticPolicy(seed: number): LoadedPolicy {
  return loadPolicy(JSON.stringify(syntheticPolicyDoc(seed)));
}

export type ArgShape = 'tiny' | 'kib1' | 'kib8' | 'list64';

/** Pool of requests for the synthetic policy: argument `a` is tiny/1 KiB/8 KiB, or `list` has 64 strings. */
export function syntheticRequests(rng: Rng, shape: ArgShape, count: number): Json[] {
  const out: Json[] = [];
  for (let i = 0; i < count; i++) {
    const tool = `tool_${rng.int(TOOLS)}`;
    const prefix = rng.next() < 0.5 ? 'ok' : 'zz';
    const size = shape === 'kib1' ? 1024 : shape === 'kib8' ? 8192 : 16;
    const a = (prefix + rng.hex(size)).slice(0, size);
    const b = rng.next() < 0.5 ? `/work/${rng.hex(6)}/file-${rng.int(1000)}.txt` : `user${rng.int(1000)}@d${rng.hex(6)}.corp.example`;
    const args: Json = { a, b, n: rng.int(160) };
    if (shape === 'list64') {
      const list: string[] = [];
      for (let k = 0; k < 64; k++) list.push(rng.hex(32));
      args['list'] = list;
    }
    out.push({ tool, args, ctx: { agentId: 'agent-1', scopes: ['sales'] } });
  }
  return out;
}

/** Mixed pool for the 8-rule fixture: allow, deny, tainted and invalid-args requests (about 40/25/15/20 percent). */
export function fixtureRequests(rng: Rng, count: number): Json[] {
  const out: Json[] = [];
  const ctx = (extra: Json = {}): Json => ({ agentId: 'agent-1', userId: 'u1', scopes: ['sales'], ...extra });
  for (let i = 0; i < count; i++) {
    const r = rng.next();
    const w = rng.hex(8);
    if (r < 0.4) {
      const k = rng.int(5);
      if (k === 0) out.push({ tool: 'search_docs', args: { query: `refund policy ${w}` }, ctx: ctx() });
      else if (k === 1) out.push({ tool: 'read_file', args: { path: `/workspace/docs/${w}.md` }, ctx: ctx() });
      else if (k === 2) out.push({ tool: 'send_email', args: { to: `agent${rng.int(100)}@corp.com`, subject: `Hi ${w}`, body: 'Your ticket is resolved.' }, ctx: ctx({ provenance: { to: ['trusted-user'] } }) });
      else if (k === 3) out.push({ tool: 'set_discount', args: { percent: rng.int(11) }, ctx: ctx() });
      else out.push({ tool: 'http_get', args: { url: `https://docs.corp.com/kb/${w}` }, ctx: ctx() });
    } else if (r < 0.65) {
      const k = rng.int(4);
      if (k === 0) out.push({ tool: 'read_file', args: { path: `/workspace/secrets/${w}` }, ctx: ctx() });
      else if (k === 1) out.push({ tool: 'delete_file', args: { path: `/workspace/${w}` }, ctx: ctx() });
      else if (k === 2) out.push({ tool: 'set_discount', args: { percent: 11 + rng.int(80) }, ctx: ctx() });
      else out.push({ tool: 'send_email', args: { to: `x${rng.int(100)}@evil.example`, subject: 's', body: w }, ctx: ctx({ provenance: { to: ['model'] } }) });
    } else if (r < 0.8) {
      const k = rng.int(2);
      if (k === 0) out.push({ tool: 'send_email', args: { to: `agent${rng.int(100)}@corp.com`, subject: 'fwd', body: w }, ctx: ctx({ sessionTainted: true, provenance: { to: ['trusted-user'] } }) });
      else out.push({ tool: 'read_file', args: { path: `/workspace/docs/${w}.md` }, ctx: ctx({ sessionTainted: true }) });
    } else {
      const k = rng.int(5);
      if (k === 0) out.push({ tool: 'read_file', args: {}, ctx: ctx() });
      else if (k === 1) out.push({ tool: 'set_discount', args: { percent: 'ten' }, ctx: ctx() });
      else if (k === 2) out.push({ tool: 'no_such_tool', args: { x: w }, ctx: ctx() });
      else if (k === 3) out.push({ tool: 'search_docs', args: { query: w, extra: 1 }, ctx: ctx() });
      else out.push({ tool: 'read_file', args: { path: 42 }, ctx: ctx() });
    }
  }
  return out;
}
