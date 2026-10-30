// Predicate matchers: glob, host/domain extraction, lexical path matching.
// Pure functions; only node:url is used (domainToASCII).
import { domainToASCII } from 'node:url';

export type Scalar = string | number | boolean;
export type ArgValue = Scalar | readonly string[];

export type CompiledPredicate =
  | { kind: 'equals'; value: Scalar }
  | { kind: 'in'; values: readonly Scalar[] }
  | { kind: 'glob'; pattern: readonly string[] }
  | { kind: 'range'; min?: number; max?: number }
  | { kind: 'max_length'; max: number }
  | { kind: 'domain_suffix'; host: string; accept: readonly HostForm[] }
  | { kind: 'domain_exact'; host: string; accept: readonly HostForm[] }
  | { kind: 'path_within'; root: string; caseInsensitive: boolean };

// ---------------------------------------------------------------- glob

/**
 * Whole-string glob: `*` = zero or more code points, `?` = exactly one code point.
 * Iterative, no regex, no recursion. Worst case O(len(pattern) * len(value)), which is bounded
 * (pattern <= 256, value <= 8192) by the policy loader and the request snapshot.
 */
export const GLOB_STEP_BUDGET = 5_000_000;

/** Thrown when the deterministic per-decision glob work budget is exhausted. */
export class WorkBudgetExceeded extends Error {
  constructor() {
    super('glob work budget exceeded');
    this.name = 'WorkBudgetExceeded';
  }
}

interface CacheEntry {
  nfc: string;
  cps?: readonly string[];
  /** normalizePath result: undefined = not computed, null = unparseable */
  path?: string | null;
  pathLower?: string | null;
  hosts?: Map<string, string | null>;
}

export interface EvalCtx {
  steps: number;
  readonly cache: Map<string, CacheEntry>;
}
export function newEvalCtx(): EvalCtx {
  return { steps: 0, cache: new Map() };
}

function charge(ctx: EvalCtx, n: number): void {
  ctx.steps += n;
  if (ctx.steps > GLOB_STEP_BUDGET) throw new WorkBudgetExceeded();
}

function normOf(ctx: EvalCtx, v: string): CacheEntry {
  let e = ctx.cache.get(v);
  if (e === undefined) {
    e = { nfc: v.normalize('NFC') };
    ctx.cache.set(v, e);
  }
  return e;
}

export function globMatch(pattern: string, value: string): boolean {
  return globRun(Array.from(pattern.normalize('NFC')), Array.from(value.normalize('NFC')));
}

export function globRun(p: readonly string[], s: readonly string[], ctx?: EvalCtx): boolean {
  let pi = 0;
  let si = 0;
  let star = -1;
  let mark = 0;
  while (si < s.length) {
    if (ctx !== undefined && ++ctx.steps > GLOB_STEP_BUDGET) throw new WorkBudgetExceeded();
    const pc = pi < p.length ? p[pi] : undefined;
    if (pc === '*') {
      star = pi++;
      mark = si;
    } else if (pc !== undefined && (pc === '?' || pc === s[si])) {
      pi++;
      si++;
    } else if (star !== -1) {
      pi = star + 1;
      si = ++mark;
    } else {
      return false;
    }
  }
  while (pi < p.length && p[pi] === '*') pi++;
  return pi === p.length;
}

// ---------------------------------------------------------------- hosts

/** True for lowercase ASCII LDH hostname text that is not IP-like (used for policy values and results). */
export function isCanonicalHostname(h: string): boolean {
  if (h.length === 0 || h.length > 253) return false;
  const labels = h.split('.');
  for (const l of labels) {
    if (l.length === 0 || l.length > 63) return false;
    if (!/^[a-z0-9-]+$/.test(l)) return false;
    if (l.startsWith('-') || l.endsWith('-')) return false;
  }
  const last = labels[labels.length - 1] as string;
  if (/^[0-9]+$/.test(last)) return false;
  return true;
}

export type HostForm = 'url' | 'email' | 'host';
export const ALL_FORMS: readonly HostForm[] = ['url', 'email', 'host'];
const EMAIL_LOCAL = /^[A-Za-z0-9._+-]{1,64}$/;

/**
 * Spec §3 (v1.1). Returns the normalised ASCII lowercase host, or null (no match).
 * The form is chosen by the shape of the string and must be in `accept`.
 * IP literals (v4 in any WHATWG form, v6) always return null.
 */
export function hostFromString(input: string, accept: readonly HostForm[] = ALL_FORMS): string | null {
  if (typeof input !== 'string' || input.length === 0 || input.length > 8192) return null;
  // printable ASCII only: no non-ASCII, whitespace or control characters; no backslash; no %
  if (/[^\x21-\x7e]/.test(input) || input.includes('\\') || input.includes('%')) return null;
  let hostText: string;
  if (input.includes('://')) {
    if (!accept.includes('url')) return null;
    let url: URL;
    try {
      url = new URL(input);
    } catch {
      return null;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    if (url.username !== '' || url.password !== '') return null;
    hostText = url.hostname;
  } else if (input.includes('@')) {
    if (!accept.includes('email')) return null;
    const parts = input.split('@');
    if (parts.length !== 2) return null;
    if (!EMAIL_LOCAL.test(parts[0] as string)) return null;
    hostText = parts[1] as string;
    if (/[/?#:[\]]/.test(hostText)) return null;
  } else {
    if (!accept.includes('host')) return null;
    if (/[/?#:[\]@]/.test(input)) return null;
    hostText = input;
  }
  if (hostText.length === 0 || hostText.includes('[') || hostText.includes(':')) return null;
  const rawLast = (hostText.endsWith('.') ? hostText.slice(0, -1) : hostText).split('.').pop() as string;
  if (/^(?:0x[0-9a-f]*|[0-9]+)$/i.test(rawLast)) return null;
  let ascii = domainToASCII(hostText);
  if (ascii === '') return null;
  ascii = ascii.toLowerCase();
  if (ascii.endsWith('.')) ascii = ascii.slice(0, -1);
  return isCanonicalHostname(ascii) ? ascii : null;
}

export function matchDomain(
  kind: 'domain_suffix' | 'domain_exact',
  policyHost: string,
  value: string,
  accept: readonly HostForm[],
): boolean {
  const host = hostFromString(value, accept);
  if (host === null) return false;
  if (kind === 'domain_exact') return host === policyHost;
  return host === policyHost || host.endsWith('.' + policyHost);
}

// ---------------------------------------------------------------- paths

const RESERVED_NAMES: ReadonlySet<string> = new Set([
  'con', 'prn', 'aux', 'nul', 'conin$', 'conout$',
  'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
  'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
]);

/**
 * Spec §4 steps 1-4: lexical normalisation. Returns "/a/b" or "C:/a/b" ("/" and "C:/" for roots),
 * or null when the value must not match.
 */
export function normalizePath(input: string): string | null {
  if (typeof input !== 'string') return null;
  if (/[^\u0000-\u007f]/.test(input)) return null; // ASCII only (spec 10.3)
  let s = input;
  if (/[\u0000-\u001f\u007f-\u009f]/.test(s)) return null;
  if (/%[0-9a-fA-F]{2}/.test(s)) return null;
  if (/[?*"<>|]/.test(s)) return null;
  const colon = s.indexOf(':');
  let drive = '';
  if (colon !== -1) {
    if (colon !== 1 || !/^[A-Za-z]$/.test(s.charAt(0)) || s.indexOf(':', 2) !== -1) return null;
  }
  s = s.replaceAll('\\', '/');
  if (s.startsWith('//')) return null;
  if (colon === 1) {
    drive = s.charAt(0).toUpperCase() + ':';
    s = s.slice(2);
  }
  if (!s.startsWith('/')) return null;
  const segs: string[] = [];
  for (const seg of s.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (segs.length === 0) return null;
      segs.pop();
      continue;
    }
    if (seg.endsWith('.') || seg.endsWith(' ')) return null;
    const base = (seg.split('.')[0] as string).toLowerCase();
    if (RESERVED_NAMES.has(base)) return null;
    if (/^[^.]{1,8}~\d+/.test(seg)) return null;
    segs.push(seg);
  }
  return drive + '/' + segs.join('/');
}

export function matchPathWithin(value: string, spec: { root: string; case_insensitive: boolean }): boolean {
  const n0 = normalizePath(value);
  if (n0 === null) return false;
  let n = n0;
  let r = spec.root;
  if (spec.case_insensitive) {
    n = n.toLowerCase();
    r = r.toLowerCase();
  }
  if (r.endsWith('/')) return n.startsWith(r);
  return n === r || n.startsWith(r + '/');
}

// ---------------------------------------------------------------- predicate evaluation

type Tri = 'match' | 'no_match' | 'unparseable';
const tri = (b: boolean): Tri => (b ? 'match' : 'no_match');

function pathTri(ctx: EvalCtx, v: string, root: string, ci: boolean): Tri {
  const e = normOf(ctx, v);
  if (e.path === undefined) {
    charge(ctx, v.length);
    e.path = normalizePath(v);
    e.pathLower = e.path === null ? null : e.path.toLowerCase();
  }
  if (e.path === null || e.path === undefined) return 'unparseable';
  const n = ci ? (e.pathLower as string) : e.path;
  if (root.endsWith('/')) return tri(n.startsWith(root));
  return tri(n === root || n.startsWith(root + '/'));
}

function domainTri(ctx: EvalCtx, v: string, p: { kind: 'domain_suffix' | 'domain_exact'; host: string; accept: readonly HostForm[] }): Tri {
  const e = normOf(ctx, v);
  const key = p.accept.join(',');
  e.hosts ??= new Map();
  let h = e.hosts.get(key);
  if (h === undefined && !e.hosts.has(key)) {
    charge(ctx, v.length);
    h = hostFromString(v, p.accept);
    e.hosts.set(key, h);
  }
  if (h === null || h === undefined) return 'unparseable';
  if (p.kind === 'domain_exact') return tri(h === p.host);
  return tri(h === p.host || h.endsWith('.' + p.host));
}

function evalScalar(p: CompiledPredicate, v: Scalar, ctx: EvalCtx): Tri {
  switch (p.kind) {
    case 'equals':
      return tri(typeof v === typeof p.value && (typeof v === 'string' ? normOf(ctx, v).nfc === p.value : v === p.value));
    case 'in': {
      const nv = typeof v === 'string' ? normOf(ctx, v).nfc : v;
      for (const x of p.values) if (typeof x === typeof nv && x === nv) return 'match';
      return 'no_match';
    }
    case 'glob': {
      if (typeof v !== 'string') return 'no_match';
      const e = normOf(ctx, v);
      if (e.cps === undefined) e.cps = Array.from(e.nfc);
      return tri(globRun(p.pattern, e.cps, ctx));
    }
    case 'range':
      if (typeof v !== 'number' || !Number.isFinite(v)) return 'no_match';
      if (p.min !== undefined && v < p.min) return 'no_match';
      if (p.max !== undefined && v > p.max) return 'no_match';
      return 'match';
    case 'max_length': {
      if (typeof v !== 'string') return 'no_match';
      const e = normOf(ctx, v);
      e.cps ??= Array.from(e.nfc);
      return tri(e.cps.length <= p.max);
    }
    case 'domain_suffix':
    case 'domain_exact':
      return typeof v === 'string' ? domainTri(ctx, v, p) : 'no_match';
    case 'path_within':
      return typeof v === 'string' ? pathTri(ctx, v, p.root, p.caseInsensitive) : 'no_match';
  }
}

/**
 * Effect-dependent evaluation (spec 10.1, 11.11). Each value yields match / no_match / unparseable.
 * Deny rule: match or unparseable counts as a match; permit rule: only match does.
 * string[]: deny = ANY element, permit = ALL elements; an empty array never matches.
 */
export function evalPredicate(p: CompiledPredicate, value: ArgValue, effect: 'permit' | 'deny', ctx: EvalCtx): boolean {
  const hit = (t: Tri): boolean => (effect === 'deny' ? t !== 'no_match' : t === 'match');
  if (Array.isArray(value)) {
    if (value.length === 0) return false;
    let any = false;
    for (const el of value as readonly unknown[]) {
      const ok = typeof el === 'string' && hit(evalScalar(p, el, ctx));
      if (effect === 'permit' && !ok) return false;
      if (ok) any = true;
    }
    return effect === 'permit' ? true : any;
  }
  return hit(evalScalar(p, value as Scalar, ctx));
}
