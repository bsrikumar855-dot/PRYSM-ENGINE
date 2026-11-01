// `simulate`: evaluate an explicit request file against one or two policies (recorded traffic cannot be replayed:
// the store keeps digests only).
import { evaluate } from '../core/index.ts';
import type { LoadedPolicy } from '../core/index.ts';
import { CliExit, readBounded } from './files.ts';
import type { Io } from './files.ts';
import { esc, jsonLine } from './text.ts';

export const MAX_REQUEST_FILE_BYTES = 10 * 1024 * 1024;
export const MAX_REQUEST_LINES = 100_000;
const ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const LIST_CAP = 1000;

interface Verdict {
  effect: 'permit' | 'deny';
  reason: string;
}

function decisionOf(policy: LoadedPolicy, req: unknown): Verdict {
  const d = evaluate(policy, req).decision;
  return { effect: d.effect, reason: d.reason_code };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function simulate(a: LoadedPolicy, b: LoadedPolicy | undefined, requestsPath: string, json: boolean, io: Io): number {
  const text = readBounded(requestsPath, MAX_REQUEST_FILE_BYTES, '--requests').toString('utf8');
  const lines = text.split('\n');
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  if (lines.length > MAX_REQUEST_LINES) throw new CliExit(2, '--requests: too many lines');

  let total = 0;
  let invalid = 0;
  let permit = 0;
  let deny = 0;
  let changed = 0;
  const p2d: string[] = [];
  const d2p: string[] = [];
  const out = (human: string, machine: unknown): void => io.out(json ? jsonLine(machine) : human);

  for (let i = 0; i < lines.length; i++) {
    const n = i + 1;
    const raw = (lines[i] as string).replace(/\r$/, '');
    if (raw.trim() === '') continue;
    const bad = (code: string): void => {
      invalid++;
      out(`line ${n}  INVALID  ${code}`, { line: n, invalid: code });
    };
    let obj: unknown;
    try {
      obj = JSON.parse(raw);
    } catch {
      bad('not_json');
      continue;
    }
    if (!isPlainObject(obj)) {
      bad('not_object');
      continue;
    }
    const { id: rawId, ...req } = obj;
    // the id is only a label: a missing or unusable one falls back to the 1-based line number
    const id = typeof rawId === 'string' && ID_RE.test(rawId) ? rawId : String(n);
    total++;
    const ra = decisionOf(a, req);
    if (ra.effect === 'permit') permit++;
    else deny++;
    let head = `${esc(id)}  A:${ra.effect}/${esc(ra.reason)}`;
    const rec: Record<string, unknown> = { line: n, id, a: { effect: ra.effect, reason_code: ra.reason } };
    if (b !== undefined) {
      const rb = decisionOf(b, req);
      const ch = ra.effect !== rb.effect || ra.reason !== rb.reason;
      head += `  B:${rb.effect}/${esc(rb.reason)}`;
      if (ch) {
        head += '  CHANGED';
        changed++;
        if (ra.effect !== rb.effect) (ra.effect === 'permit' ? p2d : d2p).push(id);
      }
      rec['b'] = { effect: rb.effect, reason_code: rb.reason };
      rec['changed'] = ch;
    }
    out(head, rec);
  }

  const capped = (ids: readonly string[]): string => ids.slice(0, LIST_CAP).map(esc).join(', ') + (ids.length > LIST_CAP ? ` (+${ids.length - LIST_CAP} more)` : '');
  if (json) {
    io.out(jsonLine({
      summary: {
        total, invalid, a_permit: permit, a_deny: deny,
        ...(b !== undefined ? { changed, permit_to_deny: p2d.length, deny_to_permit: d2p.length, permit_to_deny_ids: p2d.slice(0, LIST_CAP), deny_to_permit_ids: d2p.slice(0, LIST_CAP) } : {}),
      },
    }));
  } else if (b !== undefined) {
    io.out(`summary: total=${total} invalid=${invalid} changed=${changed} permit->deny=${p2d.length} deny->permit=${d2p.length}`);
    if (p2d.length > 0) io.out('permit->deny: ' + capped(p2d));
    if (d2p.length > 0) io.out('deny->permit: ' + capped(d2p));
  } else {
    io.out(`summary: total=${total} invalid=${invalid} permit=${permit} deny=${deny}`);
  }
  return 0;
}
