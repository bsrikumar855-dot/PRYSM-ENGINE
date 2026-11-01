// Safe, deterministic description of arbitrary (possibly hostile) JS values, for digests and reports.
// Never invokes getters or proxy traps.
import { createHash } from "node:crypto";
import { types } from "node:util";

function strDesc(s: string, full: boolean): string {
  const j = JSON.stringify(s);
  if (full || j.length <= 160) return j;
  const sha = createHash("sha256").update(s).digest("hex").slice(0, 10);
  return `"<str len=${s.length} head=${JSON.stringify(s.slice(0, 24)).slice(1, -1)} sha=${sha}>"`;
}

export function describe(v: unknown, full = false, seen: Set<object> = new Set(), depth = 0): string {
  if (v === undefined) return "undefined";
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean": return String(v);
    case "number": return Object.is(v, -0) ? "-0" : String(v);
    case "bigint": return `${v}n`;
    case "symbol": return "<symbol>";
    case "function": return "<function>";
    case "string": return strDesc(v, full);
    default: break;
  }
  const o = v as object;
  if (types.isProxy(o)) return "<proxy>";
  if (seen.has(o)) return "<cycle>";
  if (depth > 40) return "<deep>";
  seen.add(o);
  try {
    if (Array.isArray(o)) {
      const keys = Reflect.ownKeys(o);
      const parts: string[] = [];
      for (let i = 0; i < o.length; i++) {
        const d = Object.getOwnPropertyDescriptor(o, String(i));
        if (!d) parts.push("<hole>");
        else if (!("value" in d)) parts.push("<accessor>");
        else parts.push(describe(d.value, full, seen, depth + 1));
      }
      const extra = keys.filter((k) => typeof k === "symbol" || (k !== "length" && !/^[0-9]+$/.test(k))).length;
      const tag = Object.getPrototypeOf(o) === Array.prototype ? "" : "<arraysub>";
      return `${tag}[${parts.join(",")}${extra > 0 ? ",<extra-props>" : ""}]`;
    }
    const proto = Object.getPrototypeOf(o);
    let tag = "";
    if (proto === null) tag = "<nullproto>";
    else if (proto !== Object.prototype) tag = `<${(Object.getOwnPropertyDescriptor(proto, "constructor")?.value as { name?: string } | undefined)?.name ?? "proto"}>`;
    const parts: string[] = [];
    for (const k of Reflect.ownKeys(o)) {
      if (typeof k === "symbol") {
        parts.push("<symbolkey>");
        continue;
      }
      const d = Object.getOwnPropertyDescriptor(o, k) as PropertyDescriptor;
      const flag = d.enumerable ? "" : "<hidden>";
      parts.push(`${flag}${strDesc(k, full)}:${"value" in d ? describe(d.value, full, seen, depth + 1) : "<accessor>"}`);
    }
    return `${tag}{${parts.join(",")}}`;
  } finally {
    seen.delete(o);
  }
}
