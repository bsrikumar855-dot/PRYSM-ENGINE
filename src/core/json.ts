// Strict JSON parser: rejects duplicate keys, __proto__/constructor/prototype keys, BOM,
// control / zero-width / bidi characters, lone surrogates, non-finite numbers, excess depth.
import { PolicyError } from './errors.ts';

export type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

export const FORBIDDEN_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

/** Control (C0, DEL, C1), zero-width, and bidi control characters (spec §1). */
/**
 * Spec 11.14: any Cf, Zl, Zp, Cc, Co, Cn code point, and any space separator (Zs) other than U+0020.
 * Lone surrogates (Cs) are reported separately as invalid_encoding.
 */
export const FORBIDDEN_CHARS =
  /[\p{Cf}\p{Zl}\p{Zp}\p{Cc}\p{Co}\p{Cn}]|(?!\u0020)\p{Zs}|[\u034f\ufe00-\ufe0f]|\p{Default_Ignorable_Code_Point}|[\u115f\u1160\u3164\uffa0\u2800]/u; // + variation selectors / CGJ kept from spec 10.7 (stricter union)

export function checkString(s: string, path: string): void {
  if (FORBIDDEN_CHARS.test(s)) {
    throw new PolicyError('forbidden_char', path, 'string contains a forbidden character');
  }
  if (!wellFormed(s)) {
    throw new PolicyError('invalid_encoding', path, 'string contains a lone surrogate');
  }
}

export interface JsonLimits {
  maxDepth: number;
  maxItems: number;
}

const NUMBER_RE = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

export function parseStrictJson(text: string, limits: JsonLimits = { maxDepth: 8, maxItems: 1000 }): JsonValue {
  if (text.charCodeAt(0) === 0xfeff) throw new PolicyError('bom', '$', 'byte order mark is not allowed');
  let i = 0;

  const fail = (code: 'invalid_json' | 'duplicate_key' | 'forbidden_key' | 'limit_exceeded' | 'forbidden_char', path: string, msg: string): never => {
    throw new PolicyError(code, path, `${msg} (offset ${i})`);
  };

  const ws = (): void => {
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09) i++;
      else break;
    }
  };

  const str = (path: string): string => {
    // text[i] === '"'
    i++;
    let out = '';
    let start = i;
    for (;;) {
      if (i >= text.length) return fail('invalid_json', path, 'unterminated string');
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        out += text.slice(start, i);
        i++;
        break;
      }
      if (c < 0x20) return fail('forbidden_char', path, 'raw control character in string');
      if (c === 0x5c) {
        out += text.slice(start, i);
        i++;
        const e = text[i];
        i++;
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            const hex = text.slice(i, i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) return fail('invalid_json', path, 'bad unicode escape');
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default:
            return fail('invalid_json', path, 'bad escape');
        }
        start = i;
        continue;
      }
      i++;
    }
    checkString(out, path);
    return out;
  };

  const value = (path: string, depth: number): JsonValue => {
    ws();
    if (i >= text.length) return fail('invalid_json', path, 'unexpected end of input');
    const c = text[i];
    if (c === '{') return obj(path, depth + 1);
    if (c === '[') return arr(path, depth + 1);
    if (c === '"') return str(path);
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    NUMBER_RE.lastIndex = i;
    const m = NUMBER_RE.exec(text);
    if (m === null) return fail('invalid_json', path, 'unexpected token');
    i += m[0].length;
    const n = Number(m[0]);
    if (!Number.isFinite(n)) return fail('invalid_json', path, 'number out of range');
    return n === 0 ? 0 : n; // normalise -0
  };

  const arr = (path: string, depth: number): JsonValue => {
    if (depth > limits.maxDepth) return fail('limit_exceeded', path, 'nesting too deep');
    i++; // [
    const out: JsonValue[] = [];
    ws();
    if (text[i] === ']') { i++; return out; }
    for (;;) {
      if (out.length >= limits.maxItems) return fail('limit_exceeded', path, 'too many array items');
      out.push(value(`${path}[${out.length}]`, depth));
      ws();
      const c = text[i];
      if (c === ',') { i++; continue; }
      if (c === ']') { i++; return out; }
      return fail('invalid_json', path, 'expected , or ]');
    }
  };

  const obj = (path: string, depth: number): JsonValue => {
    if (depth > limits.maxDepth) return fail('limit_exceeded', path, 'nesting too deep');
    i++; // {
    const out: { [k: string]: JsonValue } = {};
    let count = 0;
    ws();
    if (text[i] === '}') { i++; return out; }
    for (;;) {
      ws();
      if (text[i] !== '"') return fail('invalid_json', path, 'expected string key');
      const key = str(path);
      const kp = `${path}.${key.length <= 40 ? key : '<long key>'}`;
      if (FORBIDDEN_KEYS.has(key)) return fail('forbidden_key', kp, 'forbidden key');
      if (Object.hasOwn(out, key)) return fail('duplicate_key', kp, 'duplicate key');
      if (++count > limits.maxItems) return fail('limit_exceeded', path, 'too many object keys');
      ws();
      if (text[i] !== ':') return fail('invalid_json', kp, 'expected :');
      i++;
      out[key] = value(kp, depth);
      ws();
      const c = text[i];
      if (c === ',') { i++; continue; }
      if (c === '}') { i++; return out; }
      return fail('invalid_json', path, 'expected , or }');
    }
  };

  const result = value('$', 0);
  ws();
  if (i < text.length) fail('invalid_json', '$', 'trailing content');
  return result;
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
/** True if the string has no lone surrogates. */
export function wellFormed(s: string): boolean {
  return !LONE_SURROGATE.test(s);
}
