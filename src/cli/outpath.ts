// Safe output files for `report --out` and `anchor --out` (REPORT-SPEC §4.1): refuse protected inputs, links, devices,
// NTFS streams and non-regular files; write a temp file in the same directory, then rename. --force never overrides
// the protected-path or link refusals.
import { closeSync, lstatSync, openSync, readSync, realpathSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { basename, dirname, join, resolve } from 'node:path';
import { CliExit } from './files.ts';

const DEVICE = /^(con|prn|aux|nul|conin\$|conout\$|com[0-9]|lpt[0-9])$/i;

function canonical(p: string): string | null {
  const abs = resolve(p);
  try {
    return realpathSync.native(abs);
  } catch {
    try {
      return join(realpathSync.native(dirname(abs)), basename(abs));
    } catch {
      return null;
    }
  }
}

const norm = (p: string): string => (process.platform === 'win32' ? p.toLowerCase() : p);

function identity(p: string): string | null {
  try {
    const st = statSync(p, { bigint: true });
    return st.ino === 0n ? null : `${st.dev}:${st.ino}`;
  } catch {
    return null;
  }
}

export interface OutCheck {
  /** An existing regular file that would be replaced. */
  exists: boolean;
  abs: string;
}

/** Validate `out`; `protectedPaths` are the DB, -wal/-shm, key file and every input file of the command. */
export function checkOutPath(out: string, protectedPaths: readonly string[]): OutCheck {
  const refuse = (why: string): never => {
    throw new CliExit(2, `--out: ${why}`);
  };
  if (out === '' || out.includes('\0')) return refuse('invalid path');
  const BS = String.fromCharCode(92);
  if (out.startsWith(BS + BS + '.' + BS) || out.startsWith(BS + BS + '?' + BS) || out.startsWith('//./') || out.startsWith('//?/')) return refuse('device path refused');
  if (out.replace(/^[A-Za-z]:/, '').includes(':')) return refuse('alternate data streams are refused');
  const rawBase = basename(out);
  if (rawBase.endsWith('.') || rawBase.endsWith(' ') || out.endsWith(' ') || out.endsWith('.')) return refuse('names ending in a dot or space are refused');
  const base = rawBase.replace(/[. ]+$/, '');
  if (DEVICE.test(base.replace(/\..*$/, ''))) return refuse('device names are refused');
  const abs = resolve(out);
  let exists = false;
  try {
    const st = lstatSync(abs);
    if (st.isSymbolicLink()) return refuse('symbolic links are refused');
    if (!st.isFile()) return refuse('exists and is not a regular file');
    exists = true;
  } catch (e) {
    if ((e as { code?: unknown } | null)?.code !== 'ENOENT') return refuse('cannot inspect path');
  }
  const canon = canonical(abs);
  if (canon === null) return refuse('parent directory does not exist');
  const outId = exists ? identity(abs) : null;
  for (const p of protectedPaths) {
    const c = canonical(p);
    if (c !== null && norm(c) === norm(canon)) return refuse('refusing to overwrite an input of this command');
    if (outId !== null && identity(p) === outId) return refuse('refusing to overwrite an input of this command');
  }
  return { exists, abs };
}

/** True only when the file STARTS with `start` (no BOM, no leading whitespace). */
export function fileStartsWith(path: string, start: string): boolean {
  let fd: number | undefined;
  try {
    fd = openSync(path, 'r');
    const buf = Buffer.alloc(200);
    const n = readSync(fd, buf, 0, 200, 0);
    return buf.subarray(0, n).toString('utf8').startsWith(start);
  } catch {
    return false;
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* ignore */ }
  }
}

/** Temp file in the same directory + atomic rename. */
export function writeAtomic(abs: string, data: string): void {
  const tmp = join(dirname(abs), `.${basename(abs)}.tmp-${randomBytes(6).toString('hex')}`);
  try {
    writeFileSync(tmp, data, { flag: 'wx' });
    renameSync(tmp, abs);
  } catch {
    try { unlinkSync(tmp); } catch { /* ignore */ }
    throw new CliExit(2, '--out: cannot write file');
  }
}
