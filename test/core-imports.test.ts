// A-19: src/core must stay free of I/O, network, process and storage dependencies.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const coreDir = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "core");
const ALLOWED_BARE = new Set(["node:url", "node:crypto"]);
const FORBIDDEN_CALLS = [/\bfetch\b/, /\bgetBuiltinModule\b/, /\bperformance\b/, /\bIntl\b/, /\btoLocale\w*/, /\blocaleCompare\b/, /\bnew Date\b/, /\bglobalThis\b/, /\bfetch\s*\(/, /\bchild_process\b/, /\bXMLHttpRequest\b/, /\bWebSocket\b/, /\bprocess\.(env|exit|binding)\b/, /\beval\s*\(/, /\bnew Function\b/, /\bDate\.now\b/, /\bMath\.random\b/];

test("src/core imports only allowed modules (no net/http/fs/sqlite/child_process)", () => {
  for (const f of readdirSync(coreDir).filter((x) => x.endsWith(".ts"))) {
    const src = readFileSync(join(coreDir, f), "utf8");
    const specs = [...src.matchAll(/(?:import|export)\s[^;]*?from\s+["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)|require\(\s*["']([^"']+)["']\s*\)/g)]
      .map((m) => m[1] ?? m[2] ?? m[3]!);
    for (const s of specs) {
      const ok = (s.startsWith("./") && !s.slice(2).includes("/") && !s.includes("..")) || ALLOWED_BARE.has(s);
      assert.ok(ok, `${f} imports forbidden module "${s}"`);
    }
  }
});

test("src/core uses no clock, randomness, network or dynamic code (decide() determinism)", () => {
  for (const f of readdirSync(coreDir).filter((x) => x.endsWith(".ts"))) {
    const src = readFileSync(join(coreDir, f), "utf8");
    for (const re of FORBIDDEN_CALLS) assert.ok(!re.test(src), `${f} matches forbidden pattern ${re}`);
  }
});
