// Terminal-safe text for CLI output. Every value that comes from the store, a policy, a request file or an
// operator-supplied path goes through here (stdout and stderr). \p{Cc}, \p{Cf}, \p{Zl}, \p{Zp} and lone surrogates
// become '?'. The CLI never emits ANSI colour codes.

const UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/u;

/** Escape an arbitrary value for one line of terminal output. */
export function esc(v: unknown): string {
  const s = typeof v === 'string' ? v : String(v);
  let out = '';
  for (const ch of s) out += UNSAFE.test(ch) ? '?' : ch;
  return out;
}

/** esc() for optional values: null/undefined/empty become '-'. */
export function cell(v: unknown): string {
  if (v === null || v === undefined || v === '') return '-';
  return esc(v);
}

const JSON_UNSAFE = new RegExp('[' + [[0x7f, 0x9f], [0xad, 0xad], [0x61c, 0x61c], [0x180e, 0x180e], [0x200b, 0x200f], [0x2028, 0x2029], [0x202a, 0x202e], [0x2060, 0x2069], [0xfeff, 0xfeff], [0xfff9, 0xfffb]].map(([a, b]) => String.fromCharCode(a as number) + '-' + String.fromCharCode(b as number)).join('') + ']', 'g');

/** JSON.stringify whose output is also terminal-safe (extra characters become \uXXXX; still valid JSON). */
export function jsonLine(v: unknown): string {
  return JSON.stringify(v).replace(JSON_UNSAFE, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

/** ISO time for a stored ts_ms, or '-' when it is not a representable date. */
export function iso(ms: unknown): string {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return '-';
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? '-' : d.toISOString();
}
