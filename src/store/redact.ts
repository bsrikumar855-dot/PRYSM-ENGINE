// Redaction choke point (AUDIT-SPEC §1.6). redactArgs is the ONLY producer of `args_redacted`.
// Default output per argument is { type, len } and never contains a value. Only fields named in
// rawFields keep (a masked, truncated) string value.

const MASKED = '«masked»';

const MASK_PATTERNS: readonly RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  /sk-[A-Za-z0-9_-]{16,}/g,
  /AKIA[0-9A-Z]{16}/g,
  /ghp_[A-Za-z0-9]{20,}/g,
  /Bearer [A-Za-z0-9._-]{16,}/g,
  /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g,
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*[^\s&"']+/gi,
];

/** Replace secret-shaped substrings with «masked». */
export function maskSecrets(s: string): string {
  let out = s;
  for (const re of MASK_PATTERNS) out = out.replace(re, MASKED);
  return out;
}

const RAW_MAX_CHARS = 200;
const MAX_ENTRIES = 64;
const SAFE_KEY = /^[A-Za-z0-9_.-]{1,64}$/;

function codePoints(s: string): number {
  let n = 0;
  for (const _c of s) {
    void _c;
    n++;
  }
  return n;
}

export interface ArgDescriptor {
  readonly type: 'string' | 'number' | 'boolean' | 'null' | 'array' | 'object' | 'other';
  readonly len: number | null;
  readonly value?: string;
}

function describe(v: unknown): ArgDescriptor {
  if (v === null) return { type: 'null', len: null };
  switch (typeof v) {
    case 'string':
      return { type: 'string', len: codePoints(v) };
    case 'number':
      return { type: 'number', len: null };
    case 'boolean':
      return { type: 'boolean', len: null };
    case 'object': {
      if (Array.isArray(v)) return { type: 'array', len: v.length };
      let n = 0;
      try {
        n = Object.keys(v).length;
      } catch {
        n = 0;
      }
      return { type: 'object', len: n };
    }
    default:
      return { type: 'other', len: null };
  }
}

export interface RedactOptions {
  /** Fields whose (masked, truncated) string value may be stored. */
  readonly rawFields?: readonly string[];
  /** If given (guard: names declared in the policy for the tool), other argument names collapse into `_undeclared: <count>`. */
  readonly allowedKeys?: readonly string[];
}

/** Produce the redacted description of a call's arguments. Never throws, never returns values (except rawFields). */
export function redactArgs(args: unknown, opts: RedactOptions = {}): Record<string, ArgDescriptor | number> {
  try {
    if (typeof args !== 'object' || args === null || Array.isArray(args)) return { _: describe(args) };
    const raw = new Set(opts.rawFields ?? []);
    const allowed = opts.allowedKeys === undefined ? undefined : new Set(opts.allowedKeys);
    const entries: [string, ArgDescriptor | number][] = [];
    let undeclared = 0;
    let i = 0;
    for (const k of Object.keys(args)) {
      if (entries.length >= MAX_ENTRIES) break;
      const d = Object.getOwnPropertyDescriptor(args, k);
      const v: unknown = d !== undefined && 'value' in d ? d.value : undefined;
      let name: string;
      if (allowed !== undefined) {
        if (!allowed.has(k)) {
          undeclared++;
          continue;
        }
        name = k;
      }
      else name = SAFE_KEY.test(k) && maskSecrets(k) === k ? k : `_key${i}`;
      i++;
      const desc: ArgDescriptor = describe(v);
      if (raw.has(k) && typeof v === 'string') {
        const masked = Array.from(maskSecrets(v)).slice(0, RAW_MAX_CHARS).join('');
        entries.push([name, { ...desc, value: masked }]);
      } else {
        entries.push([name, desc]);
      }
    }
    if (undeclared > 0) entries.push(['_undeclared', undeclared]);
    return Object.fromEntries(entries);
  } catch {
    return { _: { type: 'other', len: null } };
  }
}
