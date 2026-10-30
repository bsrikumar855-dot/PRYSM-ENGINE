// RFC 8785 JSON Canonicalization Scheme.
// Keys sorted by UTF-16 code units (default string sort); numbers use ECMAScript Number::toString;
// strings use JSON.stringify (well-formed: lone surrogates are escaped).

export function jcs(value: unknown): string {
  return canon(value, 0);
}

function canon(v: unknown, depth: number): string {
  if (depth > 64) throw new TypeError('jcs: nesting too deep');
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean':
      return v ? 'true' : 'false';
    case 'string':
      return JSON.stringify(v);
    case 'number':
      if (!Number.isFinite(v)) throw new TypeError('jcs: non-finite number');
      return String(v === 0 ? 0 : v);
    case 'object': {
      if (Array.isArray(v)) {
        const parts: string[] = [];
        for (let i = 0; i < v.length; i++) parts.push(canon(v[i], depth + 1));
        return `[${parts.join(',')}]`;
      }
      const o = v as Record<string, unknown>;
      const keys = Object.keys(o).sort();
      const parts: string[] = [];
      for (const k of keys) parts.push(`${JSON.stringify(k)}:${canon(o[k], depth + 1)}`);
      return `{${parts.join(',')}}`;
    }
    default:
      throw new TypeError(`jcs: unsupported type ${typeof v}`);
  }
}
