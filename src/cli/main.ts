// PRYSM CLI dispatcher (REPORT-SPEC §1). Exit codes: 0 success; 1 verification/lookup failure; 2 usage/config error.
// Messages never echo argument values, keys or file contents; operator-supplied text is never printed unescaped.
import { createHash } from 'node:crypto';
import { basename } from 'node:path';
import { StoreError } from '../store/index.ts';
import type { QueryOptions, Store, StoredEvent, VerifyOptions } from '../store/index.ts';
import { parseArgs, flagBool, flagInt, flagStr, optStr, requireStr, UsageError } from './args.ts';
import type { CommandSpec, Parsed } from './args.ts';
import { CliExit, MAX_POLICY_BYTES, loadPolicyBytes, loadPolicyFile, openReadOnly, readAnchorFile, readAnchorLog, readBounded, readExpectedFile, readExpectedLog } from './files.ts';
import type { ExpectedCheckpoint } from './files.ts';
import { checkOutPath, fileStartsWith, writeAtomic } from './outpath.ts';
import type { Io } from './files.ts';
import { explain } from './explain.ts';
import { simulate } from './simulate.ts';
import { cell, esc, iso, jsonLine } from './text.ts';

export const USAGE = `usage: prysm <command> [options]

commands:
  validate <policy.json> [--sha256 <hex>]
      Validate a policy file. With --sha256 the file bytes must hash to the given SHA-256 (else exit 2).
  events --db <file> [--kind k] [--tool t] [--session s] [--effect permit|deny] [--after-seq n]
         [--limit n (default 50, 1..1000)] [--tail] [--count] [--json]
      List events ascending by seq (--tail: the newest N, still ascending); --count prints the number of matches.
  explain <decision_id|unique prefix of >= 8 chars> --db <file> [--policy <file>] [--json]
      Explain one decision. Rule detail is shown only when --policy has the same policy_version as the row.
  verify-chain --db <file> [--anchor <file> | --anchor-log <file>] [--expect-pruned <file> | --expect-pruned-log <file>]
               [--allow-pruned] [--json]
      Verify the hash chain. Exit 0 only when ok. --allow-pruned accepts ANY pruning (development only).
      Without --anchor, tail truncation and full rewrites are not detectable.
  anchor --db <file> [--out <file>] [--force] [--no-verify]
         [--anchor <file> | --anchor-log <file>] [--expect-pruned <file> | --expect-pruned-log <file>] [--allow-pruned]
      Verifies the chain first with the same inputs as verify-chain (exit 1 on errors; --no-verify disables the check, last resort). Print the store anchor (genesis_hash, head_seq, head_hash, ts_ms). Store it where an attacker with
      access to the database cannot rewrite it. Warnings are printed to stderr as notes.
  simulate --policy <A.json> [--policy-b <B.json>] --requests <file.jsonl> [--json]
      Evaluate request lines {tool,args,ctx[,id]} against one or two policies (max 10 MiB, 100000 lines).
  report --db <file> [--policy <file>] [--out report.html] [--max-events n (default 500, max 5000)]
         [--anchor <file> | --anchor-log <file>] [--expect-pruned <file> | --expect-pruned-log <file>]
         [--allow-pruned] [--title t] [--scan-limit n (default 2000000, min 1000)] [--force]
      Write a static, self-contained HTML report. Refuses to overwrite a file not created by report unless --force.
  help
      Show this text.

notes: a value that starts with -- must be given as --opt=value. Read-only opens may leave empty -wal/-shm side files
       next to the database (SQLite WAL mode); they are harmless and are not suppressed.

global options: --db <file>, --key-path <file> (default <db>.key; read-only commands never create it),
                --json (machine output), --no-color (accepted; output never uses colour)
exit codes: 0 success, 1 verification/lookup failure, 2 usage or configuration error`;

const STORE_FLAGS = { '--db': 'value', '--key-path': 'value' } as const;

const SPECS: Readonly<Record<string, CommandSpec>> = {
  validate: { positionals: 1, flags: { '--sha256': 'value' } },
  events: {
    positionals: 0,
    flags: {
      ...STORE_FLAGS, '--kind': 'value', '--tool': 'value', '--session': 'value', '--effect': 'value',
      '--after-seq': 'value', '--limit': 'value', '--count': 'bool', '--tail': 'bool',
    },
  },
  explain: { positionals: 1, flags: { ...STORE_FLAGS, '--policy': 'value' } },
  'verify-chain': {
    positionals: 0,
    flags: { ...STORE_FLAGS, '--anchor': 'value', '--anchor-log': 'value', '--expect-pruned': 'value', '--expect-pruned-log': 'value', '--allow-pruned': 'bool' },
  },
  anchor: {
    positionals: 0,
    flags: {
      ...STORE_FLAGS, '--out': 'value', '--force': 'bool', '--no-verify': 'bool', '--anchor': 'value', '--anchor-log': 'value',
      '--expect-pruned': 'value', '--expect-pruned-log': 'value', '--allow-pruned': 'bool',
    },
  },
  simulate: { positionals: 0, flags: { '--policy': 'value', '--policy-b': 'value', '--requests': 'value' } },
  report: {
    positionals: 0,
    flags: {
      ...STORE_FLAGS, '--policy': 'value', '--out': 'value', '--max-events': 'value', '--anchor': 'value',
      '--anchor-log': 'value', '--expect-pruned': 'value', '--expect-pruned-log': 'value', '--allow-pruned': 'bool', '--title': 'value', '--force': 'bool', '--scan-limit': 'value',
    },
  },
};

const KINDS = ['decision', 'tool_result', 'policy_activate', 'checkpoint'] as const;
const EFFECTS = ['permit', 'deny'] as const;
const REPORT_MARKER = '<!-- prysm-report v1 -->';
const REPORT_START = '<!doctype html>' + REPORT_MARKER;

function loadAnchor(p: Parsed): ReturnType<typeof readAnchorFile> | undefined {
  const f = optStr(p, '--anchor');
  const l = optStr(p, '--anchor-log');
  if (f !== undefined && l !== undefined) throw new UsageError('invalid_value', '--anchor');
  if (f !== undefined) return readAnchorFile(f, '--anchor');
  if (l !== undefined) return readAnchorLog(l, '--anchor-log');
  return undefined;
}

function loadExpected(p: Parsed): ExpectedCheckpoint[] | undefined {
  const f = optStr(p, '--expect-pruned');
  const l = optStr(p, '--expect-pruned-log');
  if (f !== undefined && l !== undefined) throw new UsageError('invalid_value', '--expect-pruned');
  if (f !== undefined) return readExpectedFile(f, '--expect-pruned');
  if (l !== undefined) return readExpectedLog(l, '--expect-pruned-log');
  return undefined;
}

function protectedFor(p: Parsed, db: string, keyPath: string | undefined): string[] {
  const out = [db, db + '-wal', db + '-shm', keyPath ?? db + '.key'];
  for (const f of ['--policy', '--anchor', '--anchor-log', '--expect-pruned', '--expect-pruned-log']) {
    const v = flagStr(p, f);
    if (v !== undefined && v !== '') out.push(v);
  }
  return out;
}
const SHA_RE = /^[0-9a-fA-F]{64}$/;

function usageMessage(e: UsageError): string {
  const o = e.option === null ? '' : `${e.option}: `;
  switch (e.code) {
    case 'unknown_option': return 'unknown option';
    case 'missing_value': return `${o}option requires a value`;
    case 'duplicate_option': return `${o}option given more than once`;
    case 'unexpected_argument': return 'unexpected argument';
    case 'missing_argument': return 'missing argument';
    case 'invalid_value': return `${o}invalid value`;
    case 'missing_option': return `${o}option is required`;
  }
}

function pickEnum<T extends string>(p: Parsed, name: string, allowed: readonly T[]): T | undefined {
  const v = flagStr(p, name);
  if (v === undefined) return undefined;
  if (!(allowed as readonly string[]).includes(v)) throw new UsageError('invalid_value', name);
  return v as T;
}

function dbOf(p: Parsed): { db: string; keyPath: string | undefined } {
  return { db: requireStr(p, '--db'), keyPath: optStr(p, '--key-path') };
}

// ---------- validate ----------
function cmdValidate(p: Parsed, io: Io): number {
  const file = p.positionals[0] as string;
  const want = flagStr(p, '--sha256');
  if (want !== undefined && !SHA_RE.test(want)) throw new UsageError('invalid_value', '--sha256');
  const json = flagBool(p, '--json');
  const bytes = readBounded(file, MAX_POLICY_BYTES, 'policy');
  if (want !== undefined) {
    const got = createHash('sha256').update(bytes).digest('hex');
    if (got !== want.toLowerCase()) throw new CliExit(2, '--sha256: file hash does not match');
  }
  const policy = loadPolicyBytes(bytes, 'policy'); // same bytes that were hashed
  const rules = policy.document.rules.length;
  const tools = Object.keys(policy.document.tools).length;
  if (json) io.out(jsonLine({ ok: true, name: policy.name, policy_version: policy.policy_version, rules, tools, mode: policy.mode }));
  else io.out(`valid  ${policy.policy_version}  rules=${rules} tools=${tools} mode=${policy.mode}`);
  return 0;
}

// ---------- events ----------
function eventFilter(p: Parsed): QueryOptions {
  const q: QueryOptions = {};
  const kind = pickEnum(p, '--kind', KINDS);
  if (kind !== undefined) q.kind = kind;
  const tool = flagStr(p, '--tool');
  if (tool !== undefined) q.tool = tool;
  const session = flagStr(p, '--session');
  if (session !== undefined) q.sessionId = session;
  const effect = pickEnum(p, '--effect', EFFECTS);
  if (effect !== undefined) q.effect = effect;
  const after = flagInt(p, '--after-seq', 0, Number.MAX_SAFE_INTEGER);
  if (after !== undefined) q.afterSeq = after;
  return q;
}

const PAGE = 10000;

function countMatching(store: Store, q: QueryOptions): number {
  let after = q.afterSeq ?? 0;
  let total = 0;
  for (;;) {
    const rows = store.query({ ...q, afterSeq: after, limit: PAGE });
    total += rows.length;
    if (rows.length < PAGE) return total;
    after = (rows[rows.length - 1] as StoredEvent).seq;
  }
}

function eventLine(r: StoredEvent): string {
  const did = r.kind === 'decision' ? r.id : r.decision_id;
  return [
    String(r.seq), iso(r.ts_ms), cell(r.kind), `${cell(r.effect)}/${cell(r.enforcement)}`, cell(r.reason_code), cell(r.tool),
    did === null ? '-' : esc(Array.from(did).slice(0, 8).join('')),
  ].join('  ');
}

function cmdEvents(p: Parsed, io: Io): number {
  const { db, keyPath } = dbOf(p);
  const q = eventFilter(p);
  const limit = flagInt(p, '--limit', 1, 1000);
  const json = flagBool(p, '--json');
  const count = flagBool(p, '--count');
  const tail = flagBool(p, '--tail');
  const store = openReadOnly(db, keyPath);
  try {
    if (count) {
      const n = countMatching(store, q);
      io.out(json ? jsonLine({ count: n }) : String(n));
      return 0;
    }
    const n = limit ?? 50;
    let rows: StoredEvent[];
    if (tail) {
      rows = [];
      let after = q.afterSeq ?? 0;
      for (;;) {
        const page = store.query({ ...q, afterSeq: after, limit: PAGE });
        rows = rows.concat(page).slice(-n);
        if (page.length < PAGE) break;
        after = (page[page.length - 1] as StoredEvent).seq;
      }
    } else rows = store.query({ ...q, limit: n });
    for (const r of rows) io.out(json ? jsonLine(r) : eventLine(r));
    return 0;
  } finally {
    store.close();
  }
}

// ---------- explain ----------
function cmdExplain(p: Parsed, io: Io): number {
  const { db, keyPath } = dbOf(p);
  const id = p.positionals[0] as string;
  const policyPath = optStr(p, '--policy');
  const policy = policyPath === undefined ? undefined : loadPolicyFile(policyPath, '--policy').policy;
  const store = openReadOnly(db, keyPath);
  try {
    return explain(store, id, policy, flagBool(p, '--json'), io);
  } finally {
    store.close();
  }
}

// ---------- verify-chain ----------
const NOTE_CODES = new Set(['key_colocated', 'key_unprotected', 'anchor_pruned', 'prune_flag_reset']);

function cmdVerify(p: Parsed, io: Io): number {
  const { db, keyPath } = dbOf(p);
  const allowPruned = flagBool(p, '--allow-pruned');
  const json = flagBool(p, '--json');
  // syntax first: every input file is parsed and shape-checked before the store is opened or anything is verified
  const anchor = loadAnchor(p);
  const expected = loadExpected(p);
  const store = openReadOnly(db, keyPath);
  try {
    const vo: VerifyOptions = {};
    if (anchor !== undefined) vo.anchor = anchor;
    if (expected !== undefined) vo.expectPruned = expected;
    if (allowPruned) vo.allowPruned = true;
    let r;
    try {
      r = store.verify(vo);
    } catch (e) {
      throw new CliExit(2, `verify failed (${e instanceof StoreError ? e.code : 'unknown'})`);
    }
    if (json) {
      io.out(jsonLine({
        ok: r.ok, errors: r.errors, warnings: r.warnings, head_seq: r.head_seq, head_hash: r.head_hash, checkpoints: r.checkpoints,
      }));
    } else {
      if (allowPruned) io.err('warning: --allow-pruned accepts any pruning without an external record; development only');
      const isNote = (w: { code: string }): boolean => NOTE_CODES.has(w.code) || (w.code === 'history_pruned' && expected !== undefined);
      io.out(r.ok ? 'OK' : 'FAILED');
      for (const e of r.errors) io.out(`error seq=${e.seq} code=${esc(e.code)}`);
      for (const w of r.warnings) if (!isNote(w)) io.out(`warning seq=${w.seq} code=${esc(w.code)}`);
      io.out(`head seq=${r.head_seq} hash=${esc(r.head_hash)}  count=${r.count}`);
      for (const c of r.checkpoints) io.out(`checkpoint seq=${c.seq} through_seq=${c.through_seq} last_hash=${esc(c.last_hash)}`);
      const notes = r.warnings.filter(isNote).map((w) => `  seq=${w.seq} code=${esc(w.code)}`);
      if (anchor === undefined) notes.push('  no anchor supplied; tail truncation and full rewrites are not detectable without an external anchor');
      if (notes.length > 0) {
        io.out('notes:');
        for (const n of notes) io.out(n);
      }
    }
    return r.ok ? 0 : 1;
  } finally {
    store.close();
  }
}

// ---------- anchor ----------
function cmdAnchor(p: Parsed, io: Io): number {
  const { db, keyPath } = dbOf(p);
  const out = optStr(p, '--out');
  const force = flagBool(p, '--force');
  const target = out === undefined ? undefined : checkOutPath(out, protectedFor(p, db, keyPath));
  const prevAnchor = loadAnchor(p);
  const expected = loadExpected(p);
  const allowPruned = flagBool(p, '--allow-pruned');
  if (target !== undefined && target.exists && !force) throw new CliExit(2, '--out: file exists (use --force to overwrite)');
  const store = openReadOnly(db, keyPath);
  let line: string;
  try {
    if (!flagBool(p, '--no-verify')) {
      // an anchor must never bless a broken chain: verify first (errors => exit 1, codes only)
      let v;
      const vo: VerifyOptions = {};
      if (prevAnchor !== undefined) vo.anchor = prevAnchor;
      if (expected !== undefined) vo.expectPruned = expected;
      if (allowPruned) vo.allowPruned = true;
      try {
        v = store.verify(vo);
      } catch (e) {
        throw new CliExit(2, `verify failed (${e instanceof StoreError ? e.code : 'unknown'})`);
      }
      if (!v.ok) {
        const codes = [...new Set(v.errors.map((e) => esc(e.code)))].join(', ');
        const pruned = v.errors.some((e) => e.code === 'history_pruned' || e.code === 'checkpoint_missing');
        throw new CliExit(1, `chain does not verify (${codes}); no anchor written` + (pruned
          ? '. Pruned history needs the externally logged checkpoint: pass --expect-pruned-log <log> (or --expect-pruned <file>) with the checkpoint lines from the proxy/guard log. --no-verify disables the integrity check entirely; use it only as a last resort'
          : '. --no-verify disables the integrity check entirely; use it only as a last resort'));
      }
      for (const w of v.warnings) io.err(`note: seq=${w.seq} code=${esc(w.code)}`);
    }
    line = JSON.stringify(store.anchor());
  } catch (e) {
    if (e instanceof CliExit) throw e;
    throw new CliExit(2, `anchor failed (${e instanceof StoreError ? e.code : 'unknown'})`);
  } finally {
    store.close();
  }
  if (target !== undefined) writeAtomic(target.abs, line + String.fromCharCode(10));
  io.out(line);
  return 0;
}

// ---------- simulate ----------
function cmdSimulate(p: Parsed, io: Io): number {
  const a = loadPolicyFile(requireStr(p, '--policy'), '--policy').policy;
  const bPath = optStr(p, '--policy-b');
  const b = bPath === undefined ? undefined : loadPolicyFile(bPath, '--policy-b').policy;
  const req = requireStr(p, '--requests');
  return simulate(a, b, req, flagBool(p, '--json'), io);
}

async function cmdReport(p: Parsed, io: Io): Promise<number> {
  const { db, keyPath } = dbOf(p);
  const out = optStr(p, '--out') ?? 'prysm-report.html';
  const force = flagBool(p, '--force');
  const maxEvents = flagInt(p, '--max-events', 1, 5000) ?? 500;
  const title = optStr(p, '--title');
  const scanLimit = flagInt(p, '--scan-limit', 1000, Number.MAX_SAFE_INTEGER);
  if (title !== undefined && Array.from(title).length > 200) throw new UsageError('invalid_value', '--title');
  const policyPath = optStr(p, '--policy');
  const policy = policyPath === undefined ? undefined : loadPolicyFile(policyPath, '--policy').policy;
  const anchor = loadAnchor(p);
  const expected = loadExpected(p);

  // refuse protected paths / links / devices before doing any work; foreign files need --force
  const target = checkOutPath(out, protectedFor(p, db, keyPath));
  if (target.exists && !force && !fileStartsWith(target.abs, REPORT_START)) {
    throw new CliExit(2, '--out: file exists and was not created by report (use --force to overwrite)');
  }

  let mod: typeof import('../report/index.ts');
  try {
    mod = await import('../report/index.ts');
  } catch {
    throw new CliExit(2, 'report module is not available');
  }
  const store = openReadOnly(db, keyPath);
  let html: string;
  try {
    const data = mod.buildReportData(store, {
      maxEvents,
      ...(scanLimit !== undefined ? { scanLimit } : {}),
      generatedMs: Date.now(),
      dbName: basename(db),
      ...(policy !== undefined ? { policy } : {}),
      ...(anchor !== undefined ? { anchor } : {}),
      ...(expected !== undefined ? { expectPruned: expected } : {}),
      ...(flagBool(p, '--allow-pruned') ? { allowPruned: true } : {}),
      ...(title !== undefined ? { title } : {}),
    });
    html = mod.renderReportHtml(data);
  } catch (e) {
    throw new CliExit(2, `report failed (${e instanceof StoreError ? e.code : 'internal'})`);
  } finally {
    store.close();
  }
  if (!html.startsWith(REPORT_START)) throw new CliExit(2, 'report output is missing its marker');
  writeAtomic(target.abs, html);
  const bytes = Buffer.byteLength(html, 'utf8');
  io.out(flagBool(p, '--json') ? jsonLine({ ok: true, out, bytes }) : `report written: ${esc(out)} (${bytes} bytes)`);
  return 0;
}

// ---------- dispatch ----------
export async function run(argv: readonly string[], io: Io): Promise<number> {
  const cmd = argv[0];
  if (cmd === undefined) {
    io.err(USAGE);
    return 2;
  }
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') {
    io.out(USAGE);
    return 0;
  }
  if (!Object.hasOwn(SPECS, cmd)) {
    io.err('unknown command');
    io.err(USAGE);
    return 2;
  }
  const rest = argv.slice(1);
  if (rest[0] === '--help' || rest[0] === '-h') {
    io.out(USAGE);
    return 0;
  }
  const json = rest.includes('--json');
  try {
    const p = parseArgs(rest, SPECS[cmd] as CommandSpec);
    switch (cmd) {
      case 'validate': return cmdValidate(p, io);
      case 'events': return cmdEvents(p, io);
      case 'explain': return cmdExplain(p, io);
      case 'verify-chain': return cmdVerify(p, io);
      case 'anchor': return cmdAnchor(p, io);
      case 'simulate': return cmdSimulate(p, io);
      case 'report': return await cmdReport(p, io);
      default: return 2;
    }
  } catch (e) {
    return fail(e, json, io);
  }
}

function fail(e: unknown, _json: boolean, io: Io): number {
  if (e instanceof CliExit) {
    // only lookup misses and verification failures are exit 1; everything else is 2
    io.err('error: ' + esc(e.message));
    return e.exitCode;
  }
  if (e instanceof UsageError) io.err('usage error: ' + usageMessage(e));
  else if (e instanceof StoreError) io.err(`error: store error: ${e.code}`);
  else io.err('error: internal error');
  return 2;
}
