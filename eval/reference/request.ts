// Independent request snapshot + shape validation, from POLICY-SPEC.md §5, §9, §10.2, §10.4.

import { types } from "node:util";

export type ReqCode = "invalid_request" | "limit_exceeded";

export class RefRequestError extends Error {
  readonly code: ReqCode;
  constructor(code: ReqCode, message: string) {
    super(message);
    this.name = "RefRequestError";
    this.code = code;
  }
}

const bad = (m: string): never => {
  throw new RefRequestError("invalid_request", m);
};
const over = (m: string): never => {
  throw new RefRequestError("limit_exceeded", m);
};

export const LIMITS = {
  bytes: 64 * 1024,
  depth: 8,
  keys: 64,
  items: 256,
  strUnits: 8192,
  containers: 4096,
  nodes: 16384,
};

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i++;
      else return true;
    } else if (c >= 0xdc00 && c <= 0xdfff) return true;
  }
  return false;
}

interface State {
  nodes: number;
  containers: number;
  bytes: number;
  stack: Set<object>;
}

function addBytes(st: State, n: number): void {
  st.bytes += n;
  if (st.bytes > LIMITS.bytes) over("size");
}

function strBytes(s: string): number {
  return Buffer.byteLength(JSON.stringify(s), "utf8");
}

function checkStr(s: string): void {
  if (hasLoneSurrogate(s)) bad("lone surrogate");
  if (s.length > LIMITS.strUnits) over("string too long");
}

function walk(v: unknown, depth: number, st: State): unknown {
  st.nodes++;
  if (st.nodes > LIMITS.nodes) over("nodes");
  if (v === null) {
    addBytes(st, 4);
    return null;
  }
  switch (typeof v) {
    case "boolean":
      addBytes(st, v ? 4 : 5);
      return v;
    case "number": {
      if (!Number.isFinite(v)) bad("non-finite");
      const n = Object.is(v, -0) ? 0 : v;
      addBytes(st, String(n).length);
      return n;
    }
    case "string": {
      checkStr(v);
      addBytes(st, strBytes(v));
      return v.normalize("NFC");
    }
    case "object":
      break;
    default:
      return bad("non-JSON type");
  }
  const o = v as object;
  if (types.isProxy(o)) bad("proxy");
  if (st.stack.has(o)) bad("cycle");
  st.containers++;
  if (st.containers > LIMITS.containers) over("containers");
  if (depth > LIMITS.depth) over("depth");
  st.stack.add(o);
  try {
    if (Array.isArray(o)) {
      if (Object.getPrototypeOf(o) !== Array.prototype) bad("array prototype");
      if (o.length > LIMITS.items) over("array too long");
      const keys = Reflect.ownKeys(o);
      if (keys.length !== o.length + 1) bad("sparse or extra array props");
      addBytes(st, 2);
      const out: unknown[] = [];
      for (let i = 0; i < o.length; i++) {
        const d = Object.getOwnPropertyDescriptor(o, String(i));
        if (!d || !("value" in d)) bad("accessor/sparse element");
        if (i > 0) addBytes(st, 1);
        out.push(walk((d as PropertyDescriptor).value, depth + 1, st));
      }
      return Object.freeze(out);
    }
    const proto = Object.getPrototypeOf(o);
    if (proto !== Object.prototype && proto !== null) bad("non-plain object");
    const keys = Reflect.ownKeys(o);
    for (const k of keys) if (typeof k === "symbol") bad("symbol key");
    if (keys.length > LIMITS.keys) over("too many keys");
    addBytes(st, 2);
    const out: { [k: string]: unknown } = {};
    const seen = new Set<string>();
    let first = true;
    for (const k of keys as string[]) {
      if (FORBIDDEN_KEYS.has(k)) bad("forbidden key");
      checkStr(k);
      const d = Object.getOwnPropertyDescriptor(o, k) as PropertyDescriptor;
      if (!("value" in d)) bad("accessor");
      if (!d.enumerable) bad("non-enumerable");
      addBytes(st, strBytes(k) + 1 + (first ? 0 : 1));
      first = false;
      const nk = k.normalize("NFC");
      if (FORBIDDEN_KEYS.has(nk)) bad("forbidden key");
      if (seen.has(nk)) bad("duplicate key after NFC");
      seen.add(nk);
      out[nk] = walk(d.value, depth + 1, st);
    }
    return Object.freeze(out);
  } finally {
    st.stack.delete(o);
  }
}

export function refSnapshot(raw: unknown): unknown {
  return walk(raw, 1, { nodes: 0, containers: 0, bytes: 0, stack: new Set() });
}

export const LABEL_RE = /^[A-Za-z0-9_.:-]{1,64}$/;

export interface RefCtx {
  agentId: string;
  userId?: string;
  scopes: string[];
  sessionTainted: boolean;
  provenance: { [arg: string]: string[] };
}
export interface RefRequest {
  tool: string;
  args: { [k: string]: unknown };
  ctx: RefCtx;
}

const isPlain = (v: unknown): v is { [k: string]: unknown } =>
  typeof v === "object" && v !== null && !Array.isArray(v);

// Shape validation on an already-snapshotted request (all failures are invalid_request).
export function refValidateShape(s: unknown): RefRequest {
  if (!isPlain(s)) return bad("request not an object");
  const keys = Object.keys(s);
  if (keys.length !== 3 || !keys.includes("tool") || !keys.includes("args") || !keys.includes("ctx")) bad("top-level keys");
  if (typeof s.tool !== "string") bad("tool not string");
  if (!isPlain(s.args)) bad("args not object");
  const c = s.ctx;
  if (!isPlain(c)) return bad("ctx not object");
  for (const k of Object.keys(c)) {
    if (!["agentId", "userId", "scopes", "sessionTainted", "provenance"].includes(k)) bad("unknown ctx key");
  }
  if (typeof c.agentId !== "string" || c.agentId.length === 0) bad("agentId");
  if ("userId" in c && typeof c.userId !== "string") bad("userId");
  let scopes: string[] = [];
  if ("scopes" in c) {
    if (!Array.isArray(c.scopes) || !c.scopes.every((x) => typeof x === "string")) bad("scopes");
    scopes = c.scopes as string[];
  }
  let tainted = false;
  if ("sessionTainted" in c) {
    if (typeof c.sessionTainted !== "boolean") bad("sessionTainted");
    tainted = c.sessionTainted as boolean;
  }
  const prov: { [arg: string]: string[] } = {};
  if ("provenance" in c) {
    if (!isPlain(c.provenance)) bad("provenance");
    for (const k of Object.keys(c.provenance as object)) {
      const arr = (c.provenance as { [k: string]: unknown })[k];
      if (!Array.isArray(arr) || !arr.every((x) => typeof x === "string")) bad("provenance value");
      for (const lab of arr as string[]) if (!LABEL_RE.test(lab)) bad("provenance label");
      prov[k] = arr as string[];
    }
  }
  const out: RefCtx = { agentId: c.agentId as string, scopes, sessionTainted: tainted, provenance: prov };
  if ("userId" in c) out.userId = c.userId as string;
  return { tool: s.tool as string, args: s.args as { [k: string]: unknown }, ctx: out };
}
