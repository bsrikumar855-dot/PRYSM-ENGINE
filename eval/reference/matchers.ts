// Independent matchers written from POLICY-SPEC.md §2, §3, §4, §10.3, §11.

import { domainToASCII } from "node:url";

export type Tri = "match" | "no_match" | "unparseable";

export class WorkBudget {
  static readonly LIMIT = 5_000_000;
  used = 0;
  charge(n: number): void {
    this.used += n;
    if (this.used > WorkBudget.LIMIT) throw new BudgetExceeded();
  }
}

export class BudgetExceeded extends Error {
  constructor() {
    super("work budget exceeded");
    this.name = "BudgetExceeded";
  }
}

export function codePoints(s: string): number[] {
  const out: number[] = [];
  for (const ch of s) out.push(ch.codePointAt(0) as number);
  return out;
}

// ---- glob (§2): '*' any run of code points, '?' exactly one code point ----
export function refGlob(pattern: readonly number[], text: string, budget?: WorkBudget): boolean {
  const t = codePoints(text.normalize("NFC"));
  const STAR = 0x2a;
  const Q = 0x3f;
  let p = 0;
  let s = 0;
  let starP = -1;
  let starS = 0;
  while (s < t.length) {
    budget?.charge(1);
    const pc = p < pattern.length ? (pattern[p] as number) : -1;
    if (p < pattern.length && pc === STAR) {
      starP = p;
      starS = s;
      p++;
    } else if (p < pattern.length && (pc === Q || pc === t[s])) {
      p++;
      s++;
    } else if (starP >= 0) {
      p = starP + 1;
      starS++;
      s = starS;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === STAR) p++;
  return p === pattern.length;
}

// ---- host extraction (§3) ----
export type HostForm = "url" | "email" | "host";
export interface HostResult {
  form: HostForm;
  host: string | null; // null => unparseable
}

const LOCAL_RE = /^[A-Za-z0-9._+-]{1,64}$/;

function normaliseHost(h: string): string | null {
  let a: string;
  try {
    a = domainToASCII(h);
  } catch {
    return null;
  }
  if (a === "") return null;
  a = a.toLowerCase();
  if (a.endsWith(".")) a = a.slice(0, -1);
  if (a === "") return null;
  if (a.length > 253) return null;
  const labels = a.split(".");
  for (const l of labels) {
    if (l.length === 0 || l.length > 63) return null;
    if (!/^[a-z0-9-]+$/.test(l)) return null;
    if (l.startsWith("-") || l.endsWith("-")) return null;
  }
  const last = labels[labels.length - 1] as string;
  if (/^[0-9]+$/.test(last)) return null;
  return a;
}

export function refHostFromString(raw: string): HostResult {
  const form: HostForm = raw.includes("://") ? "url" : raw.includes("@") ? "email" : "host";
  const bad: HostResult = { form, host: null };
  // pre-checks
  for (let k = 0; k < raw.length; k++) {
    const c = raw.charCodeAt(k);
    if (c > 0x7f) return bad;
    if (c <= 0x20 || c === 0x7f) return bad; // control or whitespace (space included)
    if (c === 0x5c || c === 0x25) return bad; // backslash, percent
  }
  let host: string;
  if (form === "url") {
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      return bad;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") return bad;
    if (u.username !== "" || u.password !== "") return bad;
    host = u.hostname;
  } else if (form === "email") {
    const parts = raw.split("@");
    if (parts.length !== 2) return bad;
    const local = parts[0] as string;
    host = parts[1] as string;
    if (!LOCAL_RE.test(local)) return bad;
    if (/[/?#:[\]]/.test(host)) return bad;
  } else {
    if (/[/?#:[\]@]/.test(raw)) return bad;
    host = raw;
  }
  const norm = normaliseHost(host);
  return { form, host: norm };
}

export function refMatchHost(
  raw: string,
  mode: "suffix" | "exact",
  value: string,
  accept: ReadonlySet<string>,
  cache?: Map<string, HostResult>,
  budget?: WorkBudget,
): Tri {
  let r = cache?.get(raw);
  if (!r) {
    budget?.charge(raw.length);
    r = refHostFromString(raw);
    cache?.set(raw, r);
  }
  if (!accept.has(r.form)) return "unparseable";
  if (r.host === null) return "unparseable";
  if (mode === "exact") return r.host === value ? "match" : "no_match";
  return r.host === value || r.host.endsWith("." + value) ? "match" : "no_match";
}

// ---- path_within (§4, §10.3, §10.10, §11) ----
export interface NormPath {
  prefix: string; // "" or "C:"
  segs: string[];
}

const RESERVED = new Set([
  "con", "prn", "aux", "nul", "conin$", "conout$",
  "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
  "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
]);

function isReserved(seg: string): boolean {
  const l = seg.toLowerCase();
  if (RESERVED.has(l)) return true;
  const dot = l.indexOf(".");
  if (dot > 0 && RESERVED.has(l.slice(0, dot))) return true;
  return false;
}

export function refNormalizePath(valueIn: string): NormPath | null {
  const value = valueIn.normalize("NFC");
  // step 1
  for (let k = 0; k < value.length; k++) {
    const c = value.charCodeAt(k);
    if (c > 0x7f) return null; // §10.3 ASCII only
    if (c < 0x20 || c === 0x7f) return null; // NUL / control (§11.15)
    const ch = value[k] as string;
    if (ch === "%" && /^[0-9A-Fa-f]{2}$/.test(value.slice(k + 1, k + 3))) return null;
    if (ch === "?" || ch === "*" || ch === '"' || ch === "<" || ch === ">" || ch === "|") return null;
    if (ch === ":") {
      if (!(k === 1 && /^[A-Za-z]$/.test(value[0] as string))) return null;
    }
  }
  if (value.startsWith("\\\\") || value.startsWith("//")) return null;
  // step 2
  const v = value.replace(/\\/g, "/");
  if (v.startsWith("//")) return null; // covers `/\` and `\/` starts (§10.10) after conversion
  let prefix = "";
  let rest: string;
  if (v.startsWith("/")) {
    rest = v;
  } else if (/^[A-Za-z]:\//.test(v)) {
    prefix = (v[0] as string).toUpperCase() + ":";
    rest = v.slice(2);
  } else {
    return null;
  }
  // step 3
  const segs: string[] = [];
  for (const seg of rest.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (segs.length === 0) return null;
      segs.pop();
      continue;
    }
    // checks on every segment encountered (deny-safe reading, see report)
    if (isReserved(seg)) return null;
    if (seg.endsWith(".") || seg.endsWith(" ")) return null;
    if (/^[^.]{1,8}~\d+/.test(seg)) return null;
    segs.push(seg);
  }
  return { prefix, segs };
}

export function refMatchPath(
  valueIn: string,
  root: string,
  caseInsensitive: boolean,
  cache?: Map<string, NormPath | null>,
  budget?: WorkBudget,
): Tri {
  let np: NormPath | null | undefined = cache?.get(valueIn);
  if (np === undefined) {
    budget?.charge(valueIn.length);
    np = refNormalizePath(valueIn);
    cache?.set(valueIn, np);
  }
  if (np === null) return "unparseable";
  let norm = np.prefix + (np.segs.length ? "/" + np.segs.join("/") : "/");
  let r = root;
  if (caseInsensitive) {
    norm = norm.toLowerCase();
    r = r.toLowerCase();
  }
  if (r === "/") return np.prefix === "" ? "match" : "no_match";
  if (norm === r || norm.startsWith(r + "/")) return "match";
  return "no_match";
}
