// Strict argument parser. Errors carry fixed codes; argument values and unknown option names are never echoed.

export type FlagKind = 'value' | 'bool';

export interface CommandSpec {
  flags: Readonly<Record<string, FlagKind>>;
  positionals: number;
}

export type UsageCode = 'unknown_option' | 'missing_value' | 'duplicate_option' | 'unexpected_argument' | 'missing_argument' | 'invalid_value' | 'missing_option';

/** Usage / configuration error (exit 2). `option` is always a name from our own spec, never operator input. */
export class UsageError extends Error {
  code: UsageCode;
  option: string | null;
  constructor(code: UsageCode, option: string | null = null) {
    super(code);
    this.name = 'UsageError';
    this.code = code;
    this.option = option;
  }
}

export interface Parsed {
  flags: Map<string, string | true>;
  positionals: string[];
}

export const GLOBAL_FLAGS: Readonly<Record<string, FlagKind>> = { '--json': 'bool', '--no-color': 'bool' };

export function parseArgs(argv: readonly string[], spec: CommandSpec): Parsed {
  const flags = new Map<string, string | true>();
  const positionals: string[] = [];
  const all: Record<string, FlagKind> = { ...GLOBAL_FLAGS, ...spec.flags };
  let rest = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (rest || !a.startsWith('--')) {
      positionals.push(a);
      continue;
    }
    if (a === '--') {
      rest = true;
      continue;
    }
    const eq = a.indexOf('=');
    const name = eq === -1 ? a : a.slice(0, eq);
    if (!Object.hasOwn(all, name)) throw new UsageError('unknown_option');
    const kind = all[name] as FlagKind;
    if (flags.has(name)) throw new UsageError('duplicate_option', name);
    if (kind === 'bool') {
      if (eq !== -1) throw new UsageError('invalid_value', name);
      flags.set(name, true);
      continue;
    }
    if (eq !== -1) {
      flags.set(name, a.slice(eq + 1));
      continue;
    }
    const next = argv[i + 1];
    // a following token that looks like an option is a missing value (use --opt=value to pass such a value)
    if (next === undefined || next.startsWith('--')) throw new UsageError('missing_value', name);
    flags.set(name, next);
    i++;
  }
  if (positionals.length > spec.positionals) throw new UsageError('unexpected_argument');
  if (positionals.length < spec.positionals) throw new UsageError('missing_argument');
  return { flags, positionals };
}

export function flagStr(p: Parsed, name: string): string | undefined {
  const v = p.flags.get(name);
  return typeof v === 'string' ? v : undefined;
}

export function flagBool(p: Parsed, name: string): boolean {
  return p.flags.get(name) === true;
}

export function requireStr(p: Parsed, name: string): string {
  const v = flagStr(p, name);
  if (v === undefined) throw new UsageError('missing_option', name);
  if (v === '') throw new UsageError('invalid_value', name);
  return v;
}

/** Non-empty string option; empty string is invalid. */
export function optStr(p: Parsed, name: string): string | undefined {
  const v = flagStr(p, name);
  if (v === '') throw new UsageError('invalid_value', name);
  return v;
}

/** Strict non-negative decimal integer option within [min, max]. */
export function flagInt(p: Parsed, name: string, min: number, max: number): number | undefined {
  const v = flagStr(p, name);
  if (v === undefined) return undefined;
  if (!/^(0|[1-9][0-9]{0,15})$/.test(v)) throw new UsageError('invalid_value', name);
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < min || n > max) throw new UsageError('invalid_value', name);
  return n;
}
