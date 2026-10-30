// Policy loader (spec §1, §2, §7). Strict validation, JCS hash, deep freeze, compiled form.
import { createHash } from 'node:crypto';
import { PolicyError, show } from './errors.ts';
import type { PolicyErrorCode } from './errors.ts';
import { parseStrictJson, wellFormed } from './json.ts';
import type { JsonValue } from './json.ts';
import { jcs } from './jcs.ts';
import { isCanonicalHostname, normalizePath } from './matchers.ts';
import type { CompiledPredicate, Scalar } from './matchers.ts';

export type PolicyMode = 'enforce' | 'monitor_only';
export type ArgType = 'string' | 'number' | 'boolean' | 'string[]';
export type Effect = 'permit' | 'deny';

export interface PolicyToolDoc {
  readonly risk: 'low' | 'medium' | 'high';
  readonly external_effect: boolean;
  readonly read_only: boolean;
  readonly fail_mode: 'closed' | 'open_on_audit_failure';
  readonly args: { readonly [name: string]: { readonly type: ArgType; readonly optional?: boolean } };
  readonly schema_hash?: string;
}

export interface PolicyRuleDoc {
  readonly id: string;
  readonly effect: Effect;
  readonly reason_code: string;
  readonly match: { readonly [k: string]: unknown };
}

export interface PolicyDocument {
  readonly policy_schema_version: 1;
  readonly name: string;
  readonly mode: PolicyMode;
  readonly tools: { readonly [name: string]: PolicyToolDoc };
  readonly rules: readonly PolicyRuleDoc[];
}

export interface LoadedPolicy {
  readonly name: string;
  readonly mode: PolicyMode;
  readonly policy_version: string;
  readonly document: PolicyDocument;
}

export interface ToolInfo {
  readonly risk: 'low' | 'medium' | 'high';
  readonly external_effect: boolean;
  readonly read_only: boolean;
  readonly fail_mode: 'closed' | 'open_on_audit_failure';
}

export interface CompiledTool {
  readonly name: string;
  readonly externalEffect: boolean;
  readonly info: ToolInfo;
  readonly args: ReadonlyMap<string, { readonly type: ArgType; readonly optional: boolean }>;
}

export interface CompiledRule {
  readonly id: string;
  readonly effect: Effect;
  readonly reasonCode: string;
  readonly agents?: ReadonlySet<string>;
  readonly scopesAny?: ReadonlySet<string>;
  readonly tools?: ReadonlySet<string>;
  readonly sessionTainted?: boolean;
  /** sorted by arg name */
  readonly args: readonly (readonly [string, CompiledPredicate])[];
  /** sorted by arg name */
  readonly provenance: readonly (readonly [string, { readonly allIn?: ReadonlySet<string>; readonly anyIn?: ReadonlySet<string> }])[];
}

export interface CompiledPolicy {
  readonly version: string;
  readonly mode: PolicyMode;
  readonly tools: ReadonlyMap<string, CompiledTool>;
  /** sorted ascending by id */
  readonly rules: readonly CompiledRule[];
}

const registry = new WeakMap<object, CompiledPolicy>();

/** Returns the compiled form for a policy created by loadPolicy, else undefined. */
export function compiledPolicyOf(policy: unknown): CompiledPolicy | undefined {
  if (typeof policy !== 'object' || policy === null) return undefined;
  return registry.get(policy);
}

const MAX_BYTES = 1024 * 1024;
const MAX_RULES = 1000;
const MAX_LIST = 256;
const IDENT = /^[A-Za-z0-9_.:-]{1,64}$/;
const IDENT_NOCOLON = /^[A-Za-z0-9_.-]{1,64}$/;

type Obj = { [k: string]: JsonValue };

function err(code: PolicyErrorCode, path: string, message: string): never {
  throw new PolicyError(code, path, message);
}

function isObj(v: JsonValue | undefined): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function asObj(v: JsonValue | undefined, path: string): Obj {
  if (!isObj(v)) return err('invalid_type', path, 'expected an object');
  return v;
}

function checkKeys(o: Obj, path: string, required: readonly string[], optional: readonly string[]): void {
  for (const k of Object.keys(o)) {
    if (!required.includes(k) && !optional.includes(k)) {
      err('unknown_key', `${path}.${k.length <= 40 ? k : '<long key>'}`, 'unknown key');
    }
  }
  for (const k of required) {
    if (!Object.hasOwn(o, k)) err('missing_key', `${path}.${k}`, 'required key is missing');
  }
}

function asIdent(v: JsonValue | undefined, path: string, colon: boolean): string {
  if (typeof v !== 'string') return err('invalid_type', path, 'expected a string');
  if (!(colon ? IDENT : IDENT_NOCOLON).test(v)) {
    return err('invalid_identifier', path, `invalid identifier ${show(v)}`);
  }
  return v;
}

function asBool(v: JsonValue | undefined, path: string): boolean {
  if (typeof v !== 'boolean') return err('invalid_type', path, 'expected a boolean');
  return v;
}

function asEnum<T extends string>(v: JsonValue | undefined, path: string, allowed: readonly T[]): T {
  if (typeof v !== 'string') return err('invalid_type', path, 'expected a string');
  if (!(allowed as readonly string[]).includes(v)) return err('invalid_value', path, `must be one of ${allowed.join('|')}`);
  return v as T;
}

function asList(v: JsonValue | undefined, path: string, max: number): JsonValue[] {
  if (!Array.isArray(v)) return err('invalid_type', path, 'expected an array');
  if (v.length > max) return err('limit_exceeded', path, `more than ${max} entries`);
  if (v.length === 0) return err('invalid_value', path, 'empty list is not allowed');
  return v;
}

function identSet(v: JsonValue | undefined, path: string, colon: boolean): Set<string> {
  const out = new Set<string>();
  asList(v, path, MAX_LIST).forEach((x, i) => out.add(asIdent(x, `${path}[${i}]`, colon)));
  return out;
}

function asScalar(v: JsonValue | undefined, path: string): Scalar {
  if (typeof v === 'string') return v;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return v;
  return err('invalid_type', path, 'expected a string, number or boolean');
}

function asNumber(v: JsonValue | undefined, path: string): number {
  if (typeof v !== 'number' || !Number.isFinite(v)) return err('invalid_type', path, 'expected a finite number');
  return v;
}

const FORMS = ['url', 'email', 'host'] as const;

function checkTypes(pred: CompiledPredicate, types: readonly ArgType[], path: string): void {
  const kindOf = (t: ArgType): 'string' | 'number' | 'boolean' => (t === 'string[]' ? 'string' : t);
  let want: 'string' | 'number' | 'boolean' | undefined;
  switch (pred.kind) {
    case 'range': want = 'number'; break;
    case 'glob': case 'max_length': case 'domain_suffix': case 'domain_exact': case 'path_within': want = 'string'; break;
    case 'equals': want = typeof pred.value as 'string' | 'number' | 'boolean'; break;
    case 'in': want = typeof pred.values[0] as 'string' | 'number' | 'boolean'; break;
  }
  if (pred.kind === 'in' && !pred.values.every((x) => typeof x === want)) {
    err('invalid_predicate', path, 'in: values must all have the argument type');
  }
  for (const t of types) {
    if (kindOf(t) !== want) err('invalid_predicate', path, 'predicate does not fit the declared argument type');
  }
}

function compilePredicate(v: JsonValue | undefined, path: string): CompiledPredicate {
  const o = asObj(v, path);
  const keys = Object.keys(o).filter((k) => k !== 'accept');
  if (keys.length !== 1) return err('invalid_predicate', path, 'a predicate must have exactly one operator');
  const op = keys[0] as string;
  if (Object.hasOwn(o, 'accept') && op !== 'domain_suffix' && op !== 'domain_exact') {
    return err('unknown_key', `${path}.accept`, 'accept is only valid for domain predicates');
  }
  const arg = o[op];
  const p = `${path}.${op}`;
  switch (op) {
    case 'equals': {
      const value = asScalar(arg, p);
      return { kind: 'equals', value: typeof value === 'string' ? value.normalize('NFC') : value };
    }
    case 'in': {
      const values = asList(arg, p, MAX_LIST).map((x, i) => {
        const s = asScalar(x, `${p}[${i}]`);
        return typeof s === 'string' ? s.normalize('NFC') : s;
      });
      return { kind: 'in', values };
    }
    case 'glob': {
      if (typeof arg !== 'string') return err('invalid_type', p, 'expected a string');
      if (arg.length > 256) return err('limit_exceeded', p, 'glob pattern longer than 256');
      const cps = Array.from(arg.normalize('NFC'));
      if (cps.filter((c) => c === '*').length > 4) return err('limit_exceeded', p, 'glob has more than 4 wildcards');
      return { kind: 'glob', pattern: cps };
    }
    case 'range': {
      const r = asObj(arg, p);
      checkKeys(r, p, [], ['min', 'max']);
      if (!Object.hasOwn(r, 'min') && !Object.hasOwn(r, 'max')) return err('invalid_predicate', p, 'range needs min or max');
      const out: { kind: 'range'; min?: number; max?: number } = { kind: 'range' };
      if (Object.hasOwn(r, 'min')) out.min = asNumber(r['min'], `${p}.min`);
      if (Object.hasOwn(r, 'max')) out.max = asNumber(r['max'], `${p}.max`);
      if (out.min !== undefined && out.max !== undefined && out.min > out.max) {
        return err('invalid_value', p, 'min is greater than max');
      }
      return out;
    }
    case 'max_length': {
      if (typeof arg !== 'number' || !Number.isInteger(arg) || arg < 0) {
        return err('invalid_value', p, 'expected a non-negative integer');
      }
      return { kind: 'max_length', max: arg };
    }
    case 'domain_suffix':
    case 'domain_exact': {
      if (typeof arg !== 'string') return err('invalid_type', p, 'expected a string');
      if (!isCanonicalHostname(arg)) return err('invalid_value', p, `not a lowercase ASCII hostname: ${show(arg)}`);
      if (!Object.hasOwn(o, 'accept')) return err('missing_key', `${path}.accept`, 'accept is required');
      const acc = asList(o['accept'], `${path}.accept`, MAX_LIST * 1000).map((x, i) => asEnum(x, `${path}.accept[${i}]`, FORMS));
      return { kind: op, host: arg, accept: [...new Set(acc)] };
    }
    case 'path_within': {
      const r = asObj(arg, p);
      checkKeys(r, p, ['root', 'case_insensitive'], []);
      const root = r['root'];
      if (typeof root !== 'string') return err('invalid_type', `${p}.root`, 'expected a string');
      const ci = asBool(r['case_insensitive'], `${p}.case_insensitive`);
      if (normalizePath(root) !== root) return err('invalid_value', `${p}.root`, 'root must be absolute and already normalised');
      return { kind: 'path_within', root: ci ? root.toLowerCase() : root, caseInsensitive: ci };
    }
    default:
      return err('invalid_predicate', path, `unknown predicate ${show(op)}`);
  }
}

function immutable(): never {
  throw new TypeError('compiled policy is immutable');
}

/** Freeze arrays/objects and make Maps/Sets reject mutation, recursively. */
function lock<T>(v: T): T {
  if (typeof v !== 'object' || v === null || Object.isFrozen(v)) return v;
  if (v instanceof Map) {
    for (const m of ['set', 'delete', 'clear']) Object.defineProperty(v, m, { value: immutable });
    for (const [a, b] of v) { lock(a); lock(b); }
  } else if (v instanceof Set) {
    for (const m of ['add', 'delete', 'clear']) Object.defineProperty(v, m, { value: immutable });
    for (const a of v) lock(a);
  } else {
    for (const key of Object.keys(v)) lock((v as Record<string, unknown>)[key]);
  }
  return Object.freeze(v);
}

function deepFreeze<T>(v: T): T {
  if (typeof v === 'object' && v !== null && !Object.isFrozen(v)) {
    Object.freeze(v);
    for (const k of Object.keys(v)) deepFreeze((v as Record<string, unknown>)[k]);
  }
  return v;
}

function compile(doc: Obj, version: string): CompiledPolicy {
  checkKeys(doc, '$', ['policy_schema_version', 'name', 'mode', 'tools', 'rules'], []);
  if (doc['policy_schema_version'] !== 1) err('invalid_value', '$.policy_schema_version', 'must be 1');
  asIdent(doc['name'], '$.name', true);
  const mode = asEnum(doc['mode'], '$.mode', ['enforce', 'monitor_only'] as const);

  const toolsObj = asObj(doc['tools'], '$.tools');
  const tools = new Map<string, CompiledTool>();
  for (const tname of Object.keys(toolsObj)) {
    const tp = `$.tools.${tname.length <= 40 ? tname : '<long>'}`;
    asIdent(tname, tp, false);
    const t = asObj(toolsObj[tname], tp);
    checkKeys(t, tp, ['risk', 'external_effect', 'read_only', 'fail_mode', 'args'], ['schema_hash']);
    const risk = asEnum(t['risk'], `${tp}.risk`, ['low', 'medium', 'high'] as const);
    const external = asBool(t['external_effect'], `${tp}.external_effect`);
    const readOnly = asBool(t['read_only'], `${tp}.read_only`);
    const failMode = asEnum(t['fail_mode'], `${tp}.fail_mode`, ['closed', 'open_on_audit_failure'] as const);
    if (failMode === 'open_on_audit_failure' && !(risk === 'low' && readOnly)) {
      err('invalid_fail_mode', `${tp}.fail_mode`, 'open_on_audit_failure requires risk=low and read_only=true');
    }
    if (Object.hasOwn(t, 'schema_hash') && typeof t['schema_hash'] !== 'string') {
      err('invalid_type', `${tp}.schema_hash`, 'expected a string');
    }
    const argsObj = asObj(t['args'], `${tp}.args`);
    const args = new Map<string, { type: ArgType; optional: boolean }>();
    for (const aname of Object.keys(argsObj)) {
      const ap = `${tp}.args.${aname.length <= 40 ? aname : '<long>'}`;
      asIdent(aname, ap, false);
      const a = asObj(argsObj[aname], ap);
      checkKeys(a, ap, ['type'], ['optional']);
      const type = asEnum(a['type'], `${ap}.type`, ['string', 'number', 'boolean', 'string[]'] as const);
      const optional = Object.hasOwn(a, 'optional') ? asBool(a['optional'], `${ap}.optional`) : false;
      args.set(aname, { type, optional });
    }
    tools.set(tname, { name: tname, externalEffect: external, info: { risk, external_effect: external, read_only: readOnly, fail_mode: failMode }, args });
  }

  if (!Array.isArray(doc['rules'])) err('invalid_type', '$.rules', 'expected an array');
  const rulesIn = doc['rules'] as JsonValue[];
  if (rulesIn.length > MAX_RULES) err('limit_exceeded', '$.rules', `more than ${MAX_RULES} rules`);
  const ids = new Set<string>();
  const rules: CompiledRule[] = [];
  rulesIn.forEach((rv, idx) => {
    const rp = `$.rules[${idx}]`;
    const r = asObj(rv, rp);
    checkKeys(r, rp, ['id', 'effect', 'reason_code', 'match'], []);
    const id = asIdent(r['id'], `${rp}.id`, true);
    if (ids.has(id)) err('duplicate_id', `${rp}.id`, `duplicate rule id ${show(id)}`);
    ids.add(id);
    const effect = asEnum(r['effect'], `${rp}.effect`, ['permit', 'deny'] as const);
    const reasonCode = asIdent(r['reason_code'], `${rp}.reason_code`, true);
    const m = asObj(r['match'], `${rp}.match`);
    const mp = `${rp}.match`;
    if (Object.keys(m).length === 0) err('empty_match', mp, 'match must not be empty');
    checkKeys(m, mp, [], ['agents', 'scopes_any', 'tools', 'args', 'provenance', 'session_tainted']);

    const agents = Object.hasOwn(m, 'agents') ? identSet(m['agents'], `${mp}.agents`, true) : undefined;
    const scopesAny = Object.hasOwn(m, 'scopes_any') ? identSet(m['scopes_any'], `${mp}.scopes_any`, true) : undefined;
    const toolSet = Object.hasOwn(m, 'tools') ? identSet(m['tools'], `${mp}.tools`, false) : undefined;
    if (toolSet) {
      for (const t of toolSet) if (!tools.has(t)) err('unknown_tool', `${mp}.tools`, `unknown tool ${show(t)}`);
    }
    const sessionTainted = Object.hasOwn(m, 'session_tainted') ? asBool(m['session_tainted'], `${mp}.session_tainted`) : undefined;

    const declared = (argName: string, path: string): ArgType[] => {
      const scope = toolSet ? [...toolSet] : [...tools.keys()];
      const ok = toolSet
        ? scope.every((t) => tools.get(t)?.args.has(argName) === true)
        : scope.some((t) => tools.get(t)?.args.has(argName) === true);
      if (!ok) err('unknown_arg', path, `argument ${show(argName)} is not declared for the matched tool(s)`);
      const types: ArgType[] = [];
      for (const t of scope) {
        const d = tools.get(t)?.args.get(argName);
        if (d) types.push(d.type);
      }
      return types;
    };

    const args: [string, CompiledPredicate][] = [];
    if (Object.hasOwn(m, 'args')) {
      const ao = asObj(m['args'], `${mp}.args`);
      const names = Object.keys(ao).sort();
      if (names.length === 0) err('empty_match', `${mp}.args`, 'args must not be empty');
      for (const an of names) {
        const ap = `${mp}.args.${an.length <= 40 ? an : '<long>'}`;
        asIdent(an, ap, false);
        const types = declared(an, ap);
        const pred = compilePredicate(ao[an], ap);
        checkTypes(pred, types, ap);
        args.push([an, pred]);
      }
    }
    const provenance: [string, { allIn?: ReadonlySet<string>; anyIn?: ReadonlySet<string> }][] = [];
    if (Object.hasOwn(m, 'provenance')) {
      const po = asObj(m['provenance'], `${mp}.provenance`);
      const names = Object.keys(po).sort();
      if (names.length === 0) err('empty_match', `${mp}.provenance`, 'provenance must not be empty');
      for (const an of names) {
        const pp = `${mp}.provenance.${an.length <= 40 ? an : '<long>'}`;
        asIdent(an, pp, false);
        declared(an, pp);
        const spec = asObj(po[an], pp);
        checkKeys(spec, pp, [], ['all_in', 'any_in']);
        if (Object.keys(spec).length === 0) err('empty_match', pp, 'provenance spec needs all_in or any_in');
        const entry: { allIn?: ReadonlySet<string>; anyIn?: ReadonlySet<string> } = {};
        if (Object.hasOwn(spec, 'all_in')) entry.allIn = identSet(spec['all_in'], `${pp}.all_in`, true);
        if (Object.hasOwn(spec, 'any_in')) entry.anyIn = identSet(spec['any_in'], `${pp}.any_in`, true);
        provenance.push([an, entry]);
      }
    }
    const compiled: {
      -readonly [K in keyof CompiledRule]: CompiledRule[K];
    } = { id, effect, reasonCode, args, provenance };
    if (agents) compiled.agents = agents;
    if (scopesAny) compiled.scopesAny = scopesAny;
    if (toolSet) compiled.tools = toolSet;
    if (sessionTainted !== undefined) compiled.sessionTainted = sessionTainted;
    rules.push(compiled);
  });
  rules.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return { version, mode, tools, rules };
}

/**
 * Load a policy from bytes (read exactly once) or a string. Throws PolicyError.
 * The version hashes JCS(parsed document, rules sorted by id), so key order / whitespace do not matter.
 */
export function loadPolicy(bytes: Uint8Array | string): LoadedPolicy {
  let text: string;
  if (typeof bytes === 'string') {
    if (!wellFormed(bytes)) throw new PolicyError('invalid_encoding', '$', 'input contains a lone surrogate');
    if (Buffer.byteLength(bytes, 'utf8') > MAX_BYTES) throw new PolicyError('limit_exceeded', '$', 'policy larger than 1 MiB');
    text = bytes;
  } else if (bytes instanceof Uint8Array) {
    const copy = Uint8Array.from(bytes); // single read of the caller's buffer
    if (copy.length > MAX_BYTES) throw new PolicyError('limit_exceeded', '$', 'policy larger than 1 MiB');
    try {
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(copy);
    } catch {
      throw new PolicyError('invalid_encoding', '$', 'policy is not valid UTF-8');
    }
  } else {
    throw new PolicyError('invalid_type', '$', 'expected bytes or string');
  }
  const parsed = parseStrictJson(text, { maxDepth: 8, maxItems: MAX_RULES });
  const doc = asObj(parsed, '$');
  const compiled0 = compile(doc, '');
  // rules sorted by id (ids are unique and validated) so reordering rules keeps the version
  const sortedRules = [...(doc['rules'] as Obj[])].sort((x, y) => ((x['id'] as string) < (y['id'] as string) ? -1 : 1));
  const version = 'sha256:' + createHash('sha256').update(jcs({ ...doc, rules: sortedRules }), 'utf8').digest('hex');
  const compiled: CompiledPolicy = lock({ ...compiled0, version });
  const document = deepFreeze(doc as unknown as PolicyDocument);
  const loaded: LoadedPolicy = Object.freeze({
    name: document.name,
    mode: document.mode,
    policy_version: version,
    document,
  });
  registry.set(loaded, compiled);
  return loaded;
}
