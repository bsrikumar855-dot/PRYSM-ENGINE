// Independent strict JSON parser for the reference policy loader.
// Written from POLICY-SPEC.md only. Detects duplicate keys, forbidden keys
// (__proto__, constructor, prototype) and depth > 8; objects are null-prototype.

export type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

export class JsonError extends Error {
  readonly pos: number;
  constructor(message: string, pos: number) {
    super(message);
    this.name = "JsonError";
    this.pos = pos;
  }
}

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const MAX_DEPTH = 8;

export function parseStrictJson(text: string): JsonValue {
  let i = 0;
  const n = text.length;

  const fail = (msg: string): never => {
    throw new JsonError(msg, i);
  };
  const ws = (): void => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  const parseString = (): string => {
    // text[i] === '"'
    i++;
    let out = "";
    let start = i;
    for (;;) {
      if (i >= n) fail("unterminated string");
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        out += text.slice(start, i);
        i++;
        return out;
      }
      if (c < 0x20) fail("control char in string");
      if (c === 0x5c) {
        out += text.slice(start, i);
        i++;
        const e = text[i];
        i++;
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = text.slice(i, i + 4);
            if (!/^[0-9A-Fa-f]{4}$/.test(hex)) fail("bad unicode escape");
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default:
            fail("bad escape");
        }
        start = i;
        continue;
      }
      i++;
    }
  };

  const NUM = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

  const parseValue = (depth: number): JsonValue => {
    ws();
    if (i >= n) fail("unexpected end");
    const c = text[i];
    if (c === "{") {
      if (depth + 1 > MAX_DEPTH) fail("too deep");
      i++;
      const obj: { [k: string]: JsonValue } = Object.create(null);
      ws();
      if (text[i] === "}") {
        i++;
        return obj;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail("expected key");
        const key = parseString();
        if (FORBIDDEN_KEYS.has(key)) fail("forbidden key");
        if (key in obj) fail("duplicate key");
        ws();
        if (text[i] !== ":") fail("expected colon");
        i++;
        obj[key] = parseValue(depth + 1);
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return obj;
        }
        fail("expected , or }");
      }
    }
    if (c === "[") {
      if (depth + 1 > MAX_DEPTH) fail("too deep");
      i++;
      const arr: JsonValue[] = [];
      ws();
      if (text[i] === "]") {
        i++;
        return arr;
      }
      for (;;) {
        arr.push(parseValue(depth + 1));
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return arr;
        }
        fail("expected , or ]");
      }
    }
    if (c === '"') return parseString();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return null;
    }
    NUM.lastIndex = i;
    const m = NUM.exec(text);
    if (!m) return fail("unexpected token");
    i += m[0].length;
    return Number(m[0]);
  };

  const v = parseValue(0);
  ws();
  if (i < n) fail("trailing content");
  return v;
}
