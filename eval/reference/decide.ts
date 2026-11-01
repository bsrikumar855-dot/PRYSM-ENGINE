// Independent decide(), from POLICY-SPEC.md §6, §10, §11.

import {
  BudgetExceeded,
  WorkBudget,
  refGlob,
  refMatchHost,
  refMatchPath,
  type HostResult,
  type NormPath,
  type Tri,
} from "./matchers.ts";
import type { Literal, Pred, RefPolicy, RefRule, RefTool } from "./policy.ts";
import { refSnapshot, refValidateShape, RefRequestError, type RefRequest } from "./request.ts";

export type Effect = "permit" | "deny";
export interface RefDecision {
  effect: Effect;
  reason_code: string;
  matched: { deny: string[]; permit: string[] };
}

const deny = (reason_code: string, matched = { deny: [] as string[], permit: [] as string[] }): RefDecision => ({
  effect: "deny",
  reason_code,
  matched,
});

interface Ctx {
  budget: WorkBudget;
  hostCache: Map<string, HostResult>;
  pathCache: Map<string, NormPath | null>;
}

function evalScalar(p: Pred, v: unknown, c: Ctx): Tri {
  switch (p.kind) {
    case "equals": {
      if (typeof v !== typeof p.value) return "no_match";
      return v === p.value ? "match" : "no_match";
    }
    case "in": {
      for (const lit of p.values) {
        if (typeof v === typeof lit && v === lit) return "match";
      }
      return "no_match";
    }
    case "glob":
      if (typeof v !== "string") return "no_match";
      return refGlob(p.pattern, v, c.budget) ? "match" : "no_match";
    case "range":
      if (typeof v !== "number") return "no_match";
      if (p.min !== undefined && v < p.min) return "no_match";
      if (p.max !== undefined && v > p.max) return "no_match";
      return "match";
    case "max_length": {
      if (typeof v !== "string") return "no_match";
      let n = 0;
      for (const _ of v) n++;
      return n <= p.n ? "match" : "no_match";
    }
    case "domain":
      if (typeof v !== "string") return "no_match";
      return refMatchHost(v, p.mode, p.value, p.accept, c.hostCache, c.budget);
    case "path_within":
      if (typeof v !== "string") return "no_match";
      return refMatchPath(v, p.root, p.ci, c.pathCache, c.budget);
  }
}

function predHolds(p: Pred, v: unknown, effect: Effect, c: Ctx): boolean {
  const ok = (t: Tri): boolean => (effect === "deny" ? t !== "no_match" : t === "match");
  if (Array.isArray(v)) {
    if (v.length === 0) return false;
    if (effect === "deny") return v.some((el) => ok(evalScalar(p, el, c)));
    return v.every((el) => ok(evalScalar(p, el, c)));
  }
  return ok(evalScalar(p, v, c));
}

function ruleMatches(rule: RefRule, req: RefRequest, c: Ctx): boolean {
  if (rule.agents && !rule.agents.includes(req.ctx.agentId)) return false;
  if (rule.scopes_any && !req.ctx.scopes.some((s) => (rule.scopes_any as string[]).includes(s))) return false;
  if (rule.tools && !rule.tools.includes(req.tool)) return false;
  if (rule.session_tainted !== undefined) {
    if (rule.session_tainted !== (req.ctx.sessionTainted === true)) return false;
  }
  if (rule.args) {
    for (const [an, pred] of rule.args) {
      if (!Object.hasOwn(req.args, an)) return false;
      if (!predHolds(pred, req.args[an], rule.effect, c)) return false;
    }
  }
  if (rule.provenance) {
    for (const [an, cl] of rule.provenance) {
      if (!Object.hasOwn(req.args, an)) return false;
      const given = Object.hasOwn(req.ctx.provenance, an) ? (req.ctx.provenance[an] as string[]) : [];
      const labels = given.length > 0 ? given : ["untrusted:unknown"];
      if (cl.all_in && !labels.every((l) => (cl.all_in as string[]).includes(l))) return false;
      if (cl.any_in && !labels.some((l) => (cl.any_in as string[]).includes(l))) return false;
    }
  }
  return true;
}

function typeOk(t: string, v: unknown): boolean {
  switch (t) {
    case "string": return typeof v === "string";
    case "number": return typeof v === "number" && Number.isFinite(v);
    case "boolean": return typeof v === "boolean";
    default: return Array.isArray(v) && v.every((x) => typeof x === "string");
  }
}

export function refDecide(policy: RefPolicy, raw: unknown): RefDecision {
  try {
    if (!policy || (policy as { refPolicy?: unknown }).refPolicy !== true) return deny("engine_error");
    let req: RefRequest;
    try {
      req = refValidateShape(refSnapshot(raw));
    } catch (e) {
      if (e instanceof RefRequestError) return deny(e.code);
      throw e;
    }
    const tool: RefTool | undefined = policy.tools.get(req.tool);
    if (!tool) return deny("unknown_tool");
    for (const k of Object.keys(req.args)) if (!tool.args.has(k)) return deny("invalid_args");
    for (const [an, a] of tool.args) {
      if (!Object.hasOwn(req.args, an)) {
        if (!a.optional) return deny("invalid_args");
      } else if (!typeOk(a.type, req.args[an])) return deny("invalid_args");
    }
    for (const k of Object.keys(req.ctx.provenance)) if (!tool.args.has(k)) return deny("invalid_request");

    const c: Ctx = { budget: new WorkBudget(), hostCache: new Map(), pathCache: new Map() };
    const D: RefRule[] = [];
    const P: RefRule[] = [];
    for (const rule of policy.rules) {
      if (ruleMatches(rule, req, c)) (rule.effect === "deny" ? D : P).push(rule);
    }
    const ids = (rs: RefRule[]): string[] => rs.map((r) => r.id).sort();
    const matched = { deny: ids(D), permit: ids(P) };
    if (D.length > 0) return { effect: "deny", reason_code: "denied_by_rule", matched };
    if (req.ctx.sessionTainted === true && tool.external_effect) {
      if (P.some((r) => r.session_tainted === true)) return { effect: "permit", reason_code: "permitted", matched };
      return { effect: "deny", reason_code: "tainted_session", matched };
    }
    if (P.length > 0) return { effect: "permit", reason_code: "permitted", matched };
    return { effect: "deny", reason_code: "default_deny", matched };
  } catch (e) {
    if (e instanceof BudgetExceeded) return deny("limit_exceeded");
    return deny("engine_error");
  }
}

export type { Literal };
