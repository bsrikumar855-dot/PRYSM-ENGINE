// Guard test kit: temp store, policy, counting tools, captured sink, store fault wrappers.
import { loadPolicy } from '../../src/core/index.ts';
import type { LoadedPolicy } from '../../src/core/index.ts';
import { openStore, StoreError } from '../../src/store/index.ts';
import type { Store, NewEvent, StoredEvent, StoreErrorCode } from '../../src/store/index.ts';
import { createGuardWithAdmin } from '../../src/guard/index.ts';
import type { Guard, GuardAdmin, CreateGuardOptions } from '../../src/guard/index.ts';
import { POLICY_DOC } from './policy.ts';
import { tmpDir, dbPath } from './tmp.ts';

export const KEY = new Uint8Array(32).fill(5);

export interface Kit {
  dir: string;
  path: string;
  store: Store;
  policy: LoadedPolicy;
  guard: Guard;
  admin: GuardAdmin;
  lines: string[];
  calls: Record<string, unknown[][]>;
  count(tool: string): number;
  rows(): StoredEvent[];
  decisionRows(): StoredEvent[];
}

export type ToolMap = CreateGuardOptions['tools'];

export interface KitOptions {
  mode?: 'enforce' | 'monitor_only';
  extraRules?: unknown[];
  wrap?: (s: Store) => Store;
  tools?: (calls: Kit['calls']) => ToolMap;
  rawFields?: Record<string, string[]>;
  clock?: () => number;
  guardOpts?: Partial<CreateGuardOptions>;
  sink?: (line: string) => void;
  store?: Store;
  policy?: LoadedPolicy;
}

export function defaultTools(calls: Kit['calls']): ToolMap {
  const mk = (name: string, ret: unknown) => (args: unknown): unknown => {
    (calls[name] ??= []).push([args]);
    return ret;
  };
  return {
    search_docs: mk('search_docs', 'docs-result'),
    read_file: mk('read_file', 'file-contents'),
    send_email: mk('send_email', { sent: true }),
    set_discount: mk('set_discount', { ok: true }),
    note: mk('note', 'noted'),
    denied_by_default: mk('denied_by_default', 'dbd'),
    ghost: mk('ghost', 'ghost'),
  } as ToolMap;
}

export function kit(o: KitOptions = {}): Kit {
  const dir = tmpDir();
  const path = dbPath(dir);
  const lines: string[] = [];
  const calls: Kit['calls'] = {};
  const store = o.store ?? openStore({ path, hmacKey: KEY });
  const policy = o.policy ?? loadPolicy(JSON.stringify(POLICY_DOC(o.mode ?? 'enforce', o.extraRules ?? [])));
  const { guard, admin } = createGuardWithAdmin({
    policy,
    store: o.wrap ? o.wrap(store) : store,
    agentId: 'agent-1',
    tools: (o.tools ?? defaultTools)(calls),
    secondarySink: o.sink ?? ((l) => { lines.push(l); }),
    ...(o.rawFields ? { rawFields: o.rawFields } : {}),
    ...(o.clock ? { clock: o.clock } : {}),
    ...(o.guardOpts ?? {}),
  });
  return {
    dir, path, store, policy, guard, admin, lines, calls,
    count: (t) => (calls[t] ?? []).length,
    rows: () => store.iterate({ limit: 100000 }),
    decisionRows: () => store.iterate({ limit: 100000 }).filter((r) => r.kind === 'decision'),
  };
}

/** Wrap a store so selected appends throw (fault injection). Everything else delegates. */
export function faulty(store: Store, shouldFail: (ev: NewEvent) => boolean, code: StoreErrorCode = 'io'): Store {
  return {
    ...store,
    append(ev: NewEvent): StoredEvent {
      if (shouldFail(ev)) throw new StoreError(code);
      return store.append(ev);
    },
    appendShort(ev: NewEvent): StoredEvent {
      if (shouldFail(ev)) throw new StoreError(code);
      return store.appendShort(ev);
    },
  };
}
