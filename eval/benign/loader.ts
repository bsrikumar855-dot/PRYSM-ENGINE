// expected.effect is "permit" except for category "intended-deny-legit" (legitimate but intentionally refused), which is "deny".
// Loads the optional benign set eval/benign/*.jsonl. Tolerates a missing or empty directory.
// Schema: {"id","class":"benign","category"?,"request":{tool,args,ctx},"expected":{"effect":"permit"},"why","source"}
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

export const INTENDED_DENY = "intended-deny-legit";

export interface BenignCase {
  id: string; class: "benign"; category?: string; request: { tool: string; args: any; ctx: any };
  expected: { effect: "permit" | "deny"; reason_code?: string }; why?: string; source?: string;
}
export interface BenignLoad {
  present: boolean; cases: BenignCase[]; files: string[];
  /** Malformed lines / schema violations. Reported, never silently dropped. */
  errors: { file: string; line: number; message: string }[];
  duplicates_overridden: number;
}

export function validateBenign(x: any): string | null {
  if (x === null || typeof x !== "object" || Array.isArray(x)) return "not an object";
  if (typeof x.id !== "string" || x.id === "") return "id must be a non-empty string";
  if (x.class !== "benign") return 'class must be "benign"';
  const r = x.request;
  if (r === null || typeof r !== "object" || Array.isArray(r)) return "request must be an object";
  if (typeof r.tool !== "string") return "request.tool must be a string";
  if (r.args === null || typeof r.args !== "object" || Array.isArray(r.args)) return "request.args must be an object";
  if (r.ctx !== undefined && (r.ctx === null || typeof r.ctx !== "object" || Array.isArray(r.ctx))) return "request.ctx must be an object";
  if (x.category !== undefined && typeof x.category !== "string") return "category must be a string";
  // Only the intended-deny-legit category may expect deny; every other category must expect permit.
  if (x.category === INTENDED_DENY) { if (x.expected?.effect !== "deny") return 'expected.effect must be "deny" for category intended-deny-legit'; }
  else if (x.expected?.effect !== "permit") return 'expected.effect must be "permit"';
  return null;
}

export function loadBenign(dir: string): BenignLoad {
  const out: BenignLoad = { present: false, cases: [], files: [], errors: [], duplicates_overridden: 0 };
  try { if (!existsSync(dir) || !statSync(dir).isDirectory()) return out; } catch { return out; }
  const files = readdirSync(dir).filter((f) => f.endsWith(".jsonl")).sort();
  const map = new Map<string, BenignCase>();
  for (const f of files) {
    let text: string;
    try { text = readFileSync(join(dir, f), "utf8"); } catch (e) { out.errors.push({ file: f, line: 0, message: "unreadable: " + String((e as Error).message) }); continue; }
    out.files.push(f);
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      if (!line.trim()) continue;
      let obj: any;
      try { obj = JSON.parse(line); } catch { out.errors.push({ file: f, line: i + 1, message: "invalid JSON" }); continue; }
      const bad = validateBenign(obj);
      if (bad) { out.errors.push({ file: f, line: i + 1, message: bad }); continue; }
      if (map.has(obj.id)) out.duplicates_overridden++;
      map.set(obj.id, obj as BenignCase);
    }
  }
  out.cases = [...map.values()];
  out.present = out.cases.length > 0;
  return out;
}
