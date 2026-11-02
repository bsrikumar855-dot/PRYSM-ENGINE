// Scripted mock model + agent loop. SCRIPTED MOCK MODEL: it proves the gate, not model behaviour.
// The model is a pure function of the history (no randomness, no network). The loop reaches tools only through an Executor.
import type { GuardSession } from '../../src/guard/index.ts';
import type { Args, ToolImpl } from './tools.ts';

export interface Outcome {
  tool: string;
  args: Args;
  status: 'ok' | 'blocked' | 'error';
  /** Agent-visible reason for a block (denied, unknown_tool, invalid_request, unavailable), or an error class. */
  reason: string | null;
  decisionId: string | null;
  /** What the model sees as the tool observation. */
  text: string;
}

export interface Turn { action: Action; outcome: Outcome }
export type Action =
  | { kind: 'call'; tool: string; args: Args; note?: string }
  | { kind: 'final'; text: string };
export type Step = Action | ((history: readonly Turn[]) => Action);

export interface Model { next(history: readonly Turn[]): Action }

/** Plays the script in order; a step that is a function may look at the history (still deterministic). */
export function scriptedModel(steps: readonly Step[]): Model {
  return {
    next(history) {
      const s = steps[history.length];
      if (s === undefined) return { kind: 'final', text: 'script finished' };
      return typeof s === 'function' ? s(history) : s;
    },
  };
}

function visibleText(observation: string): string {
  try {
    const v = JSON.parse(observation) as { hits?: { text?: string }[] };
    if (Array.isArray(v.hits)) return v.hits.map((h) => String(h.text ?? '')).join(' ');
  } catch { /* not JSON: use it as is */ }
  return observation;
}

/**
 * The mock's "injection-following" rule: if the observation of the given turn contains `call <tool> {json}`, it obeys it.
 * This is scripted behaviour standing in for a model that was successfully injected.
 */
export function injectedCall(history: readonly Turn[], index: number): Action {
  const t = history[index];
  const m = t === undefined ? null : /call (\w+) (\{[^}]*\})/.exec(visibleText(t.outcome.text));
  if (m === null) return { kind: 'final', text: 'no injected instruction found' };
  return { kind: 'call', tool: m[1] as string, args: JSON.parse(m[2] as string) as Args, note: 'obeys instruction found in a tool result' };
}

export interface Executor { run(tool: string, args: Args): Promise<Outcome> }

export interface AgentRun { turns: Turn[]; stoppedBy: 'final' | 'step_budget' }

export const firstBlocked: { atS: number | null; tool: string | null } = { atS: null, tool: null };

export async function runAgent(
  model: Model, exec: Executor, opts: { maxSteps?: number; onTurn?: (t: Turn, i: number) => void } = {},
): Promise<AgentRun> {
  const maxSteps = opts.maxSteps ?? 12;
  const turns: Turn[] = [];
  for (let i = 0; i < maxSteps; i++) {
    const action = model.next(turns);
    if (action.kind === 'final') return { turns, stoppedBy: 'final' };
    const outcome = await exec.run(action.tool, action.args);
    if (outcome.status === 'blocked' && firstBlocked.atS === null) {
      firstBlocked.atS = process.uptime();
      firstBlocked.tool = action.tool;
    }
    const turn = { action, outcome };
    turns.push(turn);
    opts.onTurn?.(turn, i);
  }
  return { turns, stoppedBy: 'step_budget' };
}

/**
 * In-process executor: every call goes through guard.session(...).call. The host asserts provenance for send_email.to:
 * `trusted-user` only if the address appeared in the user's own request, else `model-generated`.
 */
export function guardExecutor(session: GuardSession, host: { userId: string; scopes: string[]; userAddresses: string[] }): Executor {
  return {
    async run(tool, args) {
      const ctx: { userId: string; scopes: string[]; provenance?: Record<string, string[]> } = { userId: host.userId, scopes: host.scopes };
      if (tool === 'send_email' && typeof args['to'] === 'string') {
        ctx.provenance = { to: [host.userAddresses.includes(args['to']) ? 'trusted-user' : 'model-generated'] };
      }
      const r = await session.call(tool, args, ctx);
      if (r.ok) return { tool, args, status: 'ok', reason: null, decisionId: r.decision_id, text: JSON.stringify(r.value) };
      if (r.blocked) return { tool, args, status: 'blocked', reason: r.reason_code, decisionId: r.decision_id, text: `blocked: ${r.reason_code}` };
      return { tool, args, status: 'error', reason: r.error, decisionId: r.decision_id, text: `error: ${r.error}` };
    },
  };
}

/** The unguarded arm: the same tools, called directly, no policy, no audit. Only for the with/without comparison. */
export function directExecutor(tools: Record<string, ToolImpl>): Executor {
  return {
    async run(tool, args) {
      const fn = Object.hasOwn(tools, tool) ? tools[tool] : undefined;
      if (fn === undefined) return { tool, args, status: 'error', reason: 'unknown_tool', decisionId: null, text: 'error: unknown_tool' };
      try {
        return { tool, args, status: 'ok', reason: null, decisionId: null, text: JSON.stringify(await fn(args)) };
      } catch (e) {
        return { tool, args, status: 'error', reason: 'tool_error', decisionId: null, text: 'tool error' };
      }
    },
  };
}
