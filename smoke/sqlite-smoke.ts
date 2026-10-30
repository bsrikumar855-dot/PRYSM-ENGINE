// M0 gate: does node:sqlite support what the audit store needs on this machine?
// Checks: open, WAL, synchronous=FULL, BEGIN IMMEDIATE, concurrent reader,
// competing writer gets bounded SQLITE_BUSY, crash recovery (kill mid-transaction).
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import assert from "node:assert/strict";

const dir = mkdtempSync(join(tmpdir(), "prysm-smoke-"));
const file = join(dir, "t.db");
const results: [string, boolean, string][] = [];
const check = (name: string, fn: () => void | Promise<void>) =>
  Promise.resolve()
    .then(fn)
    .then(() => results.push([name, true, ""]))
    .catch((e) => results.push([name, false, String(e?.message ?? e)]));

const open = () => {
  const db = new DatabaseSync(file, { timeout: 500 });
  db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;");
  return db;
};

try {
  const w = open();
  w.exec("CREATE TABLE IF NOT EXISTS e(seq INTEGER PRIMARY KEY, v TEXT NOT NULL)");

  await check("WAL + synchronous=FULL", () => {
    const j = w.prepare("PRAGMA journal_mode").get() as { journal_mode: string };
    const s = w.prepare("PRAGMA synchronous").get() as { synchronous: number };
    assert.equal(j.journal_mode, "wal");
    assert.equal(s.synchronous, 2); // FULL
  });

  await check("BEGIN IMMEDIATE read-tail-then-insert", () => {
    w.exec("BEGIN IMMEDIATE");
    const tail = w.prepare("SELECT max(seq) AS m FROM e").get() as { m: number | null };
    w.prepare("INSERT INTO e(v) VALUES (?)").run(`after:${tail.m ?? 0}`);
    w.exec("COMMIT");
    assert.equal((w.prepare("SELECT count(*) AS c FROM e").get() as { c: number }).c, 1);
  });

  await check("concurrent reader sees committed rows while writer holds a txn", () => {
    const r = new DatabaseSync(file, { readOnly: true });
    w.exec("BEGIN IMMEDIATE");
    w.prepare("INSERT INTO e(v) VALUES ('uncommitted')").run();
    const c = (r.prepare("SELECT count(*) AS c FROM e").get() as { c: number }).c;
    assert.equal(c, 1, "reader must not see uncommitted row");
    w.exec("ROLLBACK");
    r.close();
  });

  await check("second writer gets bounded SQLITE_BUSY (no hang)", () => {
    const w2 = open();
    w.exec("BEGIN IMMEDIATE");
    const t0 = Date.now();
    assert.throws(() => w2.exec("BEGIN IMMEDIATE"), /locked|busy/i);
    const dt = Date.now() - t0;
    assert.ok(dt < 3000, `busy wait too long: ${dt}ms`);
    w.exec("ROLLBACK");
    w2.close();
  });

  await check("UPDATE/DELETE blocked by trigger", () => {
    w.exec(`CREATE TRIGGER IF NOT EXISTS no_upd BEFORE UPDATE ON e BEGIN SELECT RAISE(ABORT,'append-only'); END;
            CREATE TRIGGER IF NOT EXISTS no_del BEFORE DELETE ON e BEGIN SELECT RAISE(ABORT,'append-only'); END;`);
    assert.throws(() => w.exec("UPDATE e SET v='x'"), /append-only/);
    assert.throws(() => w.exec("DELETE FROM e"), /append-only/);
  });
  w.close();

  await check("crash recovery: killed writer leaves committed rows, no partial txn", async () => {
    const child = `
      import { DatabaseSync } from "node:sqlite";
      const db = new DatabaseSync(${JSON.stringify(file)}, { timeout: 500 });
      db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;");
      db.prepare("INSERT INTO e(v) VALUES ('committed-before-crash')").run();
      db.exec("BEGIN IMMEDIATE");
      db.prepare("INSERT INTO e(v) VALUES ('never-committed')").run();
      console.log("READY");
      setInterval(() => {}, 1000);`;
    const p = spawn(process.execPath, ["--no-warnings", "--input-type=module", "-e", child]);
    await new Promise<void>((res, rej) => {
      p.stdout.on("data", (d) => String(d).includes("READY") && res());
      p.on("error", rej);
      setTimeout(() => rej(new Error("child timeout")), 8000);
    });
    p.kill("SIGKILL");
    await new Promise((r) => p.on("exit", r));
    const db = open();
    const vals = (db.prepare("SELECT v FROM e ORDER BY seq").all() as { v: string }[]).map((x) => x.v);
    db.close();
    assert.ok(vals.includes("committed-before-crash"));
    assert.ok(!vals.includes("never-committed"));
  });
} finally {
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* Windows may hold WAL handles briefly */ }
}

for (const [n, ok, msg] of results) console.log(`${ok ? "PASS" : "FAIL"}  ${n}${ok ? "" : "  -> " + msg}`);
console.log(`node ${process.version}, platform ${process.platform}`);
process.exit(results.every((r) => r[1]) ? 0 : 1);
