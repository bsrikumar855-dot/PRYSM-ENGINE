// Request snapshot (spec §5): validate + deep copy + deep freeze plain JSON data.
import { RequestError } from './errors.ts';
import type { RequestErrorCode } from './errors.ts';
import { FORBIDDEN_KEYS, wellFormed } from './json.ts';

export type ArgJson = null | boolean | number | string | readonly ArgJson[] | { readonly [k: string]: ArgJson };

export interface RequestCtx {
  readonly agentId: string;
  readonly userId?: string;
  readonly scopes?: readonly string[];
  readonly sessionTainted?: boolean;
  readonly provenance?: { readonly [argName: string]: readonly string[] };
}

export interface Request {
  readonly tool: string;
  readonly args: { readonly [name: string]: ArgJson };
  readonly ctx: RequestCtx;
}

export const LIMITS = {
  maxBytes: 64 * 1024,
  maxDepth: 8,
  maxKeys: 64,
  maxItems: 256,
  maxStringLength: 8192,
  maxContainers: 4096,
  maxNodes: 16384,
} as const;

const LABEL = /^[A-Za-z0-9_.:-]{1,64}$/;

// Errors we throw ourselves; anything else (hostile traps etc.) is mapped to invalid_request.
const ours = new WeakSet<object>();
// Snapshots produced by this module (frozen, validated); decide() does not re-copy them.
const snapshots = new WeakSet<object>();

function bad(code: RequestErrorCode, path: string, message: string): never {
  const e = new RequestError(code, path, message);
  ours.add(e);
  throw e;
}

type Plain = { [k: string]: unknown };

function walk(
  input: unknown,
  path: string,
  depth: number,
  stack: unknown[],
  budget: { bytes: number; nodes: number; containers: number },
): ArgJson {
  if (++budget.nodes > LIMITS.maxNodes) return bad('limit_exceeded', path, 'too many nodes');
  if (budget.bytes > LIMITS.maxBytes) return bad('limit_exceeded', path, 'request too large');
  switch (typeof input) {
    case 'boolean':
      budget.bytes += input ? 4 : 5;
      break;
    case 'number': {
      if (!Number.isFinite(input)) return bad('invalid_request', path, 'non-finite number');
      budget.bytes += String(input).length;
      if (budget.bytes > LIMITS.maxBytes) return bad('limit_exceeded', path, 'request too large');
      return input === 0 ? 0 : input; // -0 -> 0
    }
    case 'string': {
      if (input.length > LIMITS.maxStringLength) return bad('limit_exceeded', path, 'string too long');
      if (!wellFormed(input)) return bad('invalid_request', path, 'lone surrogate');
      const n = input.normalize('NFC');
      if (n.length > LIMITS.maxStringLength) return bad('limit_exceeded', path, 'string too long');
      budget.bytes += n.length + 2;
      if (budget.bytes > LIMITS.maxBytes) return bad('limit_exceeded', path, 'request too large');
      return n;
    }
    case 'object':
      break;
    default:
      return bad('invalid_request', path, `unsupported type ${typeof input}`);
  }
  if (typeof input === 'boolean') return input;
  if (input === null) {
    budget.bytes += 4;
    return null;
  }
  if (stack.includes(input)) return bad('invalid_request', path, 'cycle');
  if (depth + 1 > LIMITS.maxDepth) return bad('limit_exceeded', path, 'nesting too deep');
  if (++budget.containers > LIMITS.maxContainers) return bad('limit_exceeded', path, 'too many containers');
  budget.bytes += 2;
  stack.push(input);
  try {
    if (Array.isArray(input)) {
      if (Object.getPrototypeOf(input) !== Array.prototype) return bad('invalid_request', path, 'array subclass');
      const lenDesc = Object.getOwnPropertyDescriptor(input, 'length');
      const len = lenDesc?.value as unknown;
      if (typeof len !== 'number') return bad('invalid_request', path, 'bad array');
      if (len > LIMITS.maxItems) return bad('limit_exceeded', path, 'too many array items');
      const keys = Reflect.ownKeys(input);
      if (keys.length !== len + 1) return bad('invalid_request', path, 'sparse array or extra properties');
      const out: ArgJson[] = [];
      for (let i = 0; i < len; i++) {
        const d = Object.getOwnPropertyDescriptor(input, String(i));
        if (d === undefined || !('value' in d) || d.enumerable !== true) {
          return bad('invalid_request', `${path}[${i}]`, 'sparse array or accessor');
        }
        budget.bytes += 1;
        if (budget.bytes > LIMITS.maxBytes) return bad('limit_exceeded', path, 'request too large');
        out.push(walk(d.value, `${path}[${i}]`, depth + 1, stack, budget));
      }
      return Object.freeze(out);
    }
    const proto = Object.getPrototypeOf(input);
    if (proto !== Object.prototype && proto !== null) return bad('invalid_request', path, 'not a plain object');
    // cheap early cap: for-in stops at the limit instead of materialising every key
    let seen = 0;
    for (const _k in input as object) {
      void _k;
      if (++seen > LIMITS.maxKeys) return bad('limit_exceeded', path, 'too many keys');
    }
    const keys = Reflect.ownKeys(input);
    if (keys.length > LIMITS.maxKeys) return bad('limit_exceeded', path, 'too many keys');
    const out: Plain = {};
    for (const k of keys) {
      if (typeof k === 'symbol') return bad('invalid_request', path, 'symbol key');
      if (k.length > LIMITS.maxStringLength) return bad('limit_exceeded', `${path}.<long key>`, 'key too long');
      if (!wellFormed(k)) return bad('invalid_request', path, 'lone surrogate in key');
      const nk = k.normalize('NFC');
      const kp = `${path}.${nk.length <= 40 ? nk : '<long key>'}`;
      if (nk.length > LIMITS.maxStringLength) return bad('limit_exceeded', kp, 'key too long');
      if (FORBIDDEN_KEYS.has(nk)) return bad('invalid_request', kp, 'forbidden key');
      if (Object.hasOwn(out, nk)) return bad('invalid_request', kp, 'keys collide after NFC');
      const d = Object.getOwnPropertyDescriptor(input, k);
      if (d === undefined || !('value' in d) || d.enumerable !== true) {
        return bad('invalid_request', kp, 'accessor or non-enumerable property');
      }
      budget.bytes += nk.length + 3;
      if (budget.bytes > LIMITS.maxBytes) return bad('limit_exceeded', kp, 'request too large');
      out[nk] = walk(d.value, kp, depth + 1, stack, budget);
    }
    return Object.freeze(out) as { readonly [k: string]: ArgJson };
  } finally {
    stack.pop();
  }
}

function isPlainRecord(v: unknown): v is { readonly [k: string]: ArgJson } {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function stringArray(v: unknown, path: string, label: boolean): readonly string[] {
  if (!Array.isArray(v)) return bad('invalid_request', path, 'expected an array of strings');
  for (const s of v) {
    if (typeof s !== 'string') return bad('invalid_request', path, 'expected an array of strings');
    if (label && !LABEL.test(s)) return bad('invalid_request', path, 'invalid provenance label');
  }
  return v as readonly string[];
}

/** True if the value was produced by snapshotRequest. */
export function isSnapshot(v: unknown): v is Request {
  return typeof v === 'object' && v !== null && snapshots.has(v);
}

/**
 * Validate and copy a request into a deep-frozen plain-JSON snapshot. Throws RequestError
 * (invalid_request | limit_exceeded). This copy is what the tool must receive.
 */
export function snapshotRequest(x: unknown): Request {
  if (isSnapshot(x)) return x;
  try {
    const copy = walk(x, '$', 0, [], { bytes: 0, nodes: 0, containers: 0 });
    // Final exact size check (the running budget is a lower bound).
    if (Buffer.byteLength(JSON.stringify(copy), 'utf8') > LIMITS.maxBytes) {
      return bad('limit_exceeded', '$', 'request too large');
    }
    // A Proxy cannot be recognised by pure JS reflection, but structuredClone rejects every
    // Proxy at any depth. The input is bounded by now, and only the boolean outcome is used.
    try {
      structuredClone(x);
    } catch {
      return bad('invalid_request', '$', 'proxy or non-cloneable value');
    }
    if (!isPlainRecord(copy)) return bad('invalid_request', '$', 'request must be an object');
    const top = copy as { readonly [k: string]: ArgJson };
    for (const k of Object.keys(top)) {
      if (k !== 'tool' && k !== 'args' && k !== 'ctx') return bad('invalid_request', `$.${k}`, 'unknown request key');
    }
    const tool = top['tool'];
    if (typeof tool !== 'string') return bad('invalid_request', '$.tool', 'tool must be a string');
    const args = top['args'];
    if (!isPlainRecord(args)) return bad('invalid_request', '$.args', 'args must be an object');
    const ctx = top['ctx'];
    if (!isPlainRecord(ctx)) return bad('invalid_request', '$.ctx', 'ctx must be an object');
    for (const k of Object.keys(ctx)) {
      if (k !== 'agentId' && k !== 'userId' && k !== 'scopes' && k !== 'sessionTainted' && k !== 'provenance') {
        return bad('invalid_request', `$.ctx.${k.length <= 40 ? k : '<long key>'}`, 'unknown ctx key');
      }
    }
    if (typeof ctx['agentId'] !== 'string' || ctx['agentId'] === '') return bad('invalid_request', '$.ctx.agentId', 'agentId must be a string');
    if (Object.hasOwn(ctx, 'userId') && typeof ctx['userId'] !== 'string') {
      return bad('invalid_request', '$.ctx.userId', 'userId must be a string');
    }
    if (Object.hasOwn(ctx, 'scopes')) stringArray(ctx['scopes'], '$.ctx.scopes', false);
    if (Object.hasOwn(ctx, 'sessionTainted') && typeof ctx['sessionTainted'] !== 'boolean') {
      return bad('invalid_request', '$.ctx.sessionTainted', 'sessionTainted must be a boolean');
    }
    if (Object.hasOwn(ctx, 'provenance')) {
      const prov = ctx['provenance'];
      if (!isPlainRecord(prov)) return bad('invalid_request', '$.ctx.provenance', 'provenance must be an object');
      for (const k of Object.keys(prov)) stringArray(prov[k], `$.ctx.provenance.${k.length <= 40 ? k : '<long key>'}`, true);
    }
    snapshots.add(copy);
    return copy as unknown as Request;
  } catch (e) {
    if (typeof e === 'object' && e !== null && ours.has(e)) throw e;
    throw new RequestError('invalid_request', '$', 'request could not be read as plain JSON');
  }
}
