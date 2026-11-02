// Differential harness: independent reference implementation vs production engine (public API only).
//   npm run diff -- [--cases N] [--seed S] [--quick] [--out FILE] [--fail-on-diff]
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { loadPolicy, decide } from "../../src/core/index.ts";
import {
  refDecide as baseRefDecide,
  refFaultKinds,
  refLoadPolicy as baseRefLoad,
  type RefDecision,
  type RefPolicy,
} from "../reference/index.ts";
import { describe } from "./describe.ts";
import { genPolicy, genPolicyCase, type GenPolicy } from "./gen-policy.ts";
import { genCase } from "./gen-request.ts";
import { derive, seedFrom } from "./prng.ts";

export const HARNESS_VERSION = "2";

/** Reference hooks, for harness self-tests (fault injection into the REFERENCE side only). */
export interface RefHooks {
  decide?: (p: RefPolicy, raw: unknown) => RefDecision;
  load?: (input: string | Uint8Array) => RefPolicy;
}
let hooks: RefHooks = {};
const refDecide = (p: RefPolicy, raw: unknown): RefDecision => (hooks.decide ?? baseRefDecide)(p, raw);
const refLoadPolicy = (input: string | Uint8Array): RefPolicy => (hooks.load ?? baseRefLoad)(input);

/** sha256 of each eval/reference/*.ts file, so reports are attributable to an exact reference implementation. */
export function referenceHashes(): Record<string, string> {
  const dir = new URL("../reference/", import.meta.url);
  const out: Record<string, string> = {};
  for (const name of readdirSync(dir).filter((n) => n.endsWith(".ts")).sort()) {
    out[name] = createHash("sha256").update(readFileSync(new URL(name, dir))).digest("hex");
  }
  return out;
}

export const DEFAULT_SEED = 20261102;
export const DEFAULT_CASES = 100_000;
export const QUICK_CASES = 5_000;
const PER_POLICY = 20;const MAX_DISTINCT = 30;

export interface DiffOptions {
  cases: number;
  seed: number | string;
  perPolicy?: number;
  maxDistinct?: number;
  /** inject faults into the reference (self-tests only) */
  refHooks?: RefHooks;
  minimise?: boolean;
  log?: (s: string) => void;
}

interface Outcome {
  effect: string;
  reason: string;
  matched?: { deny: string[]; permit: string[] };
}

interface DecideExample {
  signature: string;
  kind: string;
  count: number;
  family: string;
  policy_index: number;
  request_index: number;
  ref: Outcome;
  prod: Outcome;
  policy: unknown;
  request: string;
  minimised?: { policy: unknown; request: string; evaluations: number };
}

interface LoadExample {
  signature: string;
  count: number;
  name: string;
  expect: string;
  ref: string;
  prod: string;
  input: string;
}

export interface DiffReport {
  tool: "prysm-diff";
  harness_version: string;
  reference_files_sha256: Record<string, string>;
  seed: number;
  seed_arg: string;
  cases: number;
  policies: number;
  per_policy: number;
  case_digest: string;
  result_digest: string;
  elapsed_ms: { total: number; ref: number; prod: number };
  load: {
    valid_policies: number;
    valid_agree: number;
    valid_disagree: number;
    mutated_policies: number;
    mutated_agree: number;
    mutated_disagree: number;
    mutated_both_contradict_expectation: number;
    mutated_by_name: Record<string, { n: number; ref_accept: number; prod_accept: number; expect: string }>;
  };
  decide: {
    compared: number;
    agree: number;
    disagree: number;
    effect_mismatch: number;
    reason_mismatch_same_effect: number;
    equivalent_multifault_code_difference: number;
    matched_mismatch_same_decision: number;
    prod_threw: number;
    ref_engine_error: number;
    outcome_histogram: Record<string, number>;
    disagreements_by_family: Record<string, number>;
  };
  distinct_decide_signatures: number;
  distinct_load_signatures: number;
  decide_disagreements: DecideExample[];
  load_disagreements: LoadExample[];
  load_expectation_misses: LoadExample[];
}

function outcomeOfRef(p: RefPolicy, req: unknown): Outcome {
  const d = refDecide(p, req);
  return { effect: d.effect, reason: d.reason_code, matched: d.matched };
}

function outcomeOfProd(p: unknown, req: unknown): Outcome {
  try {
    const d = decide(p as never, req as never) as unknown as {
      effect: string;
      reason_code: string;
      matched?: { deny?: string[]; permit?: string[] };
    };
    const out: Outcome = { effect: d.effect, reason: d.reason_code };
    if (d.matched) out.matched = { deny: [...(d.matched.deny ?? [])], permit: [...(d.matched.permit ?? [])] };
    return out;
  } catch (e) {
    return { effect: "THROW", reason: e instanceof Error ? e.message.slice(0, 80) : "throw" };
  }
}

const RULE_EVALUATED = new Set(["permitted", "denied_by_rule", "default_deny", "tainted_session"]);

function classify(r: Outcome, p: Outcome): string | null {
  if (r.effect !== p.effect) return "effect_mismatch";
  if (r.reason !== p.reason) {
    const pair = new Set([r.reason, p.reason]);
    return pair.size === 2 && pair.has("invalid_request") && pair.has("limit_exceeded") ? "precedence_invalid_vs_limit" : "reason_mismatch";
  }
  if (RULE_EVALUATED.has(r.reason) && r.matched && p.matched) {
    if (JSON.stringify(r.matched) !== JSON.stringify(p.matched)) return "matched_mismatch";
  }
  return null;
}

function tryLoad<T>(f: () => T): { ok: true; v: T } | { ok: false; err: string } {
  try {
    return { ok: true, v: f() };
  } catch (e) {
    const x = e as { code?: string; path?: string; message?: string };
    const msg = `${x.code ?? ""} ${x.path ?? ""} ${(x.message ?? String(e)).slice(0, 80)}`.trim();
    return { ok: false, err: msg };
  }
}

function inputDesc(input: string | Uint8Array): string {
  const s = typeof input === "string" ? input : `<bytes:${input.length}> ` + Buffer.from(input.subarray(0, 120)).toString("latin1");
  return s.length > 600 ? s.slice(0, 600) + `…(${s.length} chars)` : s;
}

// ---------- minimisation ----------
type J = unknown;

function jsonClone(v: J): J {
  return JSON.parse(JSON.stringify(v));
}

function isJsonLossless(v: J): boolean {
  if (v === undefined) return false;
  try {
    return describe(jsonClone(v), true) === describe(v, true);
  } catch {
    return false;
  }
}

function candidates(root: J): Array<{ path: Array<string | number>; kind: string }> {
  const out: Array<{ path: Array<string | number>; kind: string }> = [];
  const walk = (v: J, path: Array<string | number>): void => {
    if (Array.isArray(v)) {
      v.forEach((_, i) => out.push({ path: [...path, i], kind: "delete" }));
      v.forEach((x, i) => walk(x, [...path, i]));
    } else if (typeof v === "object" && v !== null) {
      for (const k of Object.keys(v)) out.push({ path: [...path, k], kind: "delete" });
      for (const k of Object.keys(v)) walk((v as Record<string, J>)[k], [...path, k]);
    } else if (typeof v === "string" && v.length > 0) {
      out.push({ path, kind: "first-half" });
      out.push({ path, kind: "second-half" });
      out.push({ path, kind: "drop-last" });
      out.push({ path, kind: "drop-first" });
    }
  };
  walk(root, []);
  return out;
}

function applyEdit(root: J, path: Array<string | number>, kind: string): J {
  const c = jsonClone(root) as J;
  if (path.length === 0) return c;
  let parent = c as Record<string | number, J>;
  for (let i = 0; i < path.length - 1; i++) parent = parent[path[i] as string] as Record<string | number, J>;
  const last = path[path.length - 1] as string | number;
  if (kind === "delete") {
    if (Array.isArray(parent)) (parent as unknown as J[]).splice(last as number, 1);
    else delete parent[last];
  } else {
    const s = parent[last] as string;
    const cps = [...s];
    const h = Math.floor(cps.length / 2);
    parent[last] =
      kind === "first-half" ? cps.slice(0, h).join("")
      : kind === "second-half" ? cps.slice(h).join("")
      : kind === "drop-last" ? cps.slice(0, -1).join("")
      : cps.slice(1).join("");
  }
  return c;
}

function minimise(
  doc: J,
  request: unknown,
  want: { ref: string; prod: string },
  budget = 400,
): { policy: unknown; request: unknown; evaluations: number } | null {
  let evals = 0;
  const fails = (d: J, r: unknown): boolean => {
    if (evals >= budget) return false;
    evals++;
    const text = JSON.stringify(d);
    const a = tryLoad(() => refLoadPolicy(text));
    const b = tryLoad(() => loadPolicy(text));
    if (!a.ok || !b.ok) return false;
    const ro = outcomeOfRef(a.v, r);
    const po = outcomeOfProd(b.v, r);
    return `${ro.effect}/${ro.reason}` === want.ref && `${po.effect}/${po.reason}` === want.prod;
  };
  let curDoc = doc;
  let curReq = request;
  const reqOk = isJsonLossless(request);
  if (!fails(curDoc, curReq)) return null;
  // policy: drop rules, then tools
  for (let changed = true; changed; ) {
    changed = false;
    const d = curDoc as { rules: J[]; tools: Record<string, J> };
    for (let i = 0; i < d.rules.length; i++) {
      const nd = jsonClone(curDoc) as { rules: J[] };
      nd.rules.splice(i, 1);
      if (fails(nd, curReq)) {
        curDoc = nd;
        changed = true;
        break;
      }
    }
    if (changed) continue;
    for (const t of Object.keys(d.tools)) {
      const nd = jsonClone(curDoc) as { tools: Record<string, J> };
      delete nd.tools[t];
      if (fails(nd, curReq)) {
        curDoc = nd;
        changed = true;
        break;
      }
    }
  }
  if (reqOk) {
    for (let changed = true; changed && evals < budget; ) {
      changed = false;
      for (const c of candidates(curReq)) {
        const nr = applyEdit(curReq, c.path, c.kind);
        if (fails(curDoc, nr)) {
          curReq = nr;
          changed = true;
          break;
        }
        if (evals >= budget) break;
      }
    }
  }
  return { policy: curDoc, request: curReq, evaluations: evals };
}

// ---------- main run ----------
export function runDiff(opts: DiffOptions): DiffReport {
  const saved = hooks;
  hooks = opts.refHooks ?? {};
  try {
    return runDiffInner(opts);
  } finally {
    hooks = saved;
  }
}

function runDiffInner(opts: DiffOptions): DiffReport {
  const t0 = Date.now();
  const seed = seedFrom(opts.seed);
  const per = opts.perPolicy ?? PER_POLICY;
  const maxDistinct = opts.maxDistinct ?? MAX_DISTINCT;
  const nPolicies = Math.ceil(opts.cases / per);
  const caseHash = createHash("sha256");
  const resultHash = createHash("sha256");
  let refMs = 0;
  let prodMs = 0;

  const rep: DiffReport = {
    tool: "prysm-diff",
    harness_version: HARNESS_VERSION,
    reference_files_sha256: referenceHashes(),
    seed,
    seed_arg: String(opts.seed),
    cases: 0,
    policies: nPolicies,
    per_policy: per,
    case_digest: "",
    result_digest: "",
    elapsed_ms: { total: 0, ref: 0, prod: 0 },
    load: {
      valid_policies: 0, valid_agree: 0, valid_disagree: 0,
      mutated_policies: 0, mutated_agree: 0, mutated_disagree: 0, mutated_both_contradict_expectation: 0,
      mutated_by_name: {},
    },
    decide: {
      compared: 0, agree: 0, disagree: 0, effect_mismatch: 0, reason_mismatch_same_effect: 0,
      equivalent_multifault_code_difference: 0,
      matched_mismatch_same_decision: 0, prod_threw: 0, ref_engine_error: 0,
      outcome_histogram: {}, disagreements_by_family: {},
    },
    distinct_decide_signatures: 0,
    distinct_load_signatures: 0,
    decide_disagreements: [],
    load_disagreements: [],
    load_expectation_misses: [],
  };

  const dSig = new Map<string, DecideExample>();
  const dRaw = new Map<string, { doc: unknown; request: unknown; ref: Outcome; prod: Outcome }>();
  const lSig = new Map<string, LoadExample>();
  const lMiss = new Map<string, LoadExample>();
  const loadSigSeen = new Set<string>();

  for (let pi = 0; pi < nPolicies; pi++) {
    const gp: GenPolicy = genPolicy(derive(seed, pi, 0));
    caseHash.update("P" + gp.text + "\n");
    const a = tryLoad(() => refLoadPolicy(gp.text));
    const b = tryLoad(() => loadPolicy(gp.text));
    rep.load.valid_policies++;
    if (a.ok && b.ok) rep.load.valid_agree++;
    else {
      rep.load.valid_disagree++;
      const sig = `valid-policy:ref=${a.ok ? "accept" : "reject"}:prod=${b.ok ? "accept" : "reject"}`;
      loadSigSeen.add(sig);
      const ex = lSig.get(sig);
      if (ex) ex.count++;
      else if (lSig.size < maxDistinct) {
        lSig.set(sig, {
          signature: sig, count: 1, name: "generated-valid", expect: "accept",
          ref: a.ok ? "accept" : "reject: " + a.err, prod: b.ok ? "accept" : "reject: " + b.err, input: inputDesc(gp.text),
        });
      }
    }

    if (a.ok && b.ok) {
      for (let ri = 0; ri < per && rep.cases < opts.cases; ri++) {
        const c = genCase(derive(seed, pi, ri + 1), gp);
        const rd = describe(c.request, true);
        caseHash.update(`R${c.family}|${rd}\n`);
        rep.cases++;
        rep.decide.compared++;

        const t1 = process.hrtime.bigint();
        const ro = outcomeOfRef(a.v, c.request);
        const t2 = process.hrtime.bigint();
        const po = outcomeOfProd(b.v, c.request);
        const t3 = process.hrtime.bigint();
        refMs += Number(t2 - t1) / 1e6;
        prodMs += Number(t3 - t2) / 1e6;

        resultHash.update(`${ro.effect}/${ro.reason}|${po.effect}/${po.reason}\n`);
        const hk = `${ro.effect}/${ro.reason}`;
        rep.decide.outcome_histogram[hk] = (rep.decide.outcome_histogram[hk] ?? 0) + 1;
        if (ro.reason === "engine_error") rep.decide.ref_engine_error++;
        if (po.effect === "THROW") rep.decide.prod_threw++;
        let kind = classify(ro, po);
        if (kind === "precedence_invalid_vs_limit") {
          // v1.5 §13.1: equivalent only if the request really carries both a limit fault and a validity fault
          const fk = refFaultKinds(c.request);
          if (fk.limit && fk.invalid) {
            rep.decide.equivalent_multifault_code_difference++;
            continue;
          }
          kind = "reason_mismatch";
        }
        if (!kind) {
          rep.decide.agree++;
          continue;
        }
        rep.decide.disagree++;
        if (kind === "effect_mismatch") rep.decide.effect_mismatch++;
        else if (kind === "reason_mismatch") rep.decide.reason_mismatch_same_effect++;
        else rep.decide.matched_mismatch_same_decision++;
        rep.decide.disagreements_by_family[c.family] = (rep.decide.disagreements_by_family[c.family] ?? 0) + 1;
        const matchedSig = kind === "matched_mismatch" ? `|matched` : "";
        const sig = `${c.family}|ref:${ro.effect}/${ro.reason}|prod:${po.effect}/${po.reason}${matchedSig}`;
        const ex = dSig.get(sig);
        if (ex) ex.count++;
        else {
          if (dSig.size < maxDistinct) {
            dSig.set(sig, {
              signature: sig, kind, count: 1, family: c.family, policy_index: pi, request_index: ri,
              ref: ro, prod: po, policy: gp.doc, request: describe(c.request, false),
            });
            dRaw.set(sig, { doc: gp.doc, request: c.request, ref: ro, prod: po });
          }
          loadSigSeen.add("d:" + sig);
        }
      }
    } else {
      // policies that disagree on loading cannot be compared on decide; still consume case budget deterministically
      rep.cases = Math.min(opts.cases, rep.cases);
    }

    // one mutated (mostly invalid) policy per generated policy, load agreement only
    const pc = genPolicyCase(derive(seed, pi, 1_000_000), gp);
    caseHash.update(`M${pc.name}|${inputDesc(pc.input)}\n`);
    const ma = tryLoad(() => refLoadPolicy(pc.input));
    const mb = tryLoad(() => loadPolicy(pc.input));
    rep.load.mutated_policies++;
    const stat = (rep.load.mutated_by_name[pc.name] ??= { n: 0, ref_accept: 0, prod_accept: 0, expect: pc.expect });
    stat.n++;
    if (ma.ok) stat.ref_accept++;
    if (mb.ok) stat.prod_accept++;
    resultHash.update(`M${pc.name}:${ma.ok}:${mb.ok}\n`);
    if (ma.ok === mb.ok) rep.load.mutated_agree++;
    else {
      rep.load.mutated_disagree++;
      const sig = `mutation:${pc.name}:ref=${ma.ok ? "accept" : "reject"}:prod=${mb.ok ? "accept" : "reject"}`;
      const ex = lSig.get(sig);
      if (ex) ex.count++;
      else if (lSig.size < maxDistinct * 2) {
        lSig.set(sig, {
          signature: sig, count: 1, name: pc.name, expect: pc.expect,
          ref: ma.ok ? "accept" : "reject: " + ma.err, prod: mb.ok ? "accept" : "reject: " + mb.err, input: inputDesc(pc.input),
        });
      }
      loadSigSeen.add(sig);
    }
    const bothAccept = ma.ok && mb.ok;
    const bothReject = !ma.ok && !mb.ok;
    if ((pc.expect === "reject" && bothAccept) || (pc.expect === "accept" && bothReject)) {
      rep.load.mutated_both_contradict_expectation++;
      const sig = `expectation:${pc.name}:expected=${pc.expect}:both=${bothAccept ? "accept" : "reject"}`;
      const ex = lMiss.get(sig);
      if (ex) ex.count++;
      else if (lMiss.size < maxDistinct) {
        lMiss.set(sig, {
          signature: sig, count: 1, name: pc.name, expect: pc.expect,
          ref: ma.ok ? "accept" : "reject: " + (ma as { err: string }).err,
          prod: mb.ok ? "accept" : "reject: " + (mb as { err: string }).err, input: inputDesc(pc.input),
        });
      }
    }
  }

  // minimise first MAX_DISTINCT distinct decide signatures
  if (opts.minimise !== false) {
    for (const [sig, ex] of dSig) {
      const raw = dRaw.get(sig);
      if (!raw) continue;
      const m = minimise(raw.doc, raw.request, {
        ref: `${raw.ref.effect}/${raw.ref.reason}`,
        prod: `${raw.prod.effect}/${raw.prod.reason}`,
      });
      if (m) ex.minimised = { policy: m.policy, request: describe(m.request, false), evaluations: m.evaluations };
    }
  }

  rep.distinct_decide_signatures = [...loadSigSeen].filter((s) => s.startsWith("d:")).length;
  rep.distinct_load_signatures = [...loadSigSeen].filter((s) => !s.startsWith("d:")).length;
  rep.decide_disagreements = [...dSig.values()];
  rep.load_disagreements = [...lSig.values()];
  rep.load_expectation_misses = [...lMiss.values()];
  rep.case_digest = "sha256:" + caseHash.digest("hex");
  rep.result_digest = "sha256:" + resultHash.digest("hex");
  rep.elapsed_ms = { total: Date.now() - t0, ref: Math.round(refMs), prod: Math.round(prodMs) };
  opts.log?.(`done: ${rep.cases} cases`);
  return rep;
}

// ---------- CLI ----------
function parseArgs(argv: string[]): { cases: number; seed: string; seeds: string[]; out?: string; failOnDiff: boolean; quick: boolean } {
  let cases = DEFAULT_CASES;
  let casesGiven = false;
  let seed = String(DEFAULT_SEED);
  let seeds: string[] = [];
  let out: string | undefined;
  let failOnDiff = false;
  let quick = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a === "--cases") {
      cases = Number(argv[++i]);
      casesGiven = true;
    } else if (a === "--seed") seed = String(argv[++i]);
    else if (a === "--seeds") seeds = String(argv[++i]).split(",").filter((x) => x !== "");
    else if (a === "--out") out = argv[++i];
    else if (a === "--quick") quick = true;
    else if (a === "--fail-on-diff") failOnDiff = true;
    else throw new Error(`unknown argument ${a}`);
  }
  if (quick && !casesGiven) cases = QUICK_CASES;
  if (!Number.isInteger(cases) || cases < 1) throw new Error("--cases must be a positive integer");
  return { cases, seed, seeds, ...(out !== undefined ? { out } : {}), failOnDiff, quick };
}

function summary(r: DiffReport): string {
  const l = r.load;
  const d = r.decide;
  const lines = [
    `seed=${r.seed_arg} (numeric ${r.seed})  cases=${r.cases}  policies=${r.policies}`,
    `case_digest=${r.case_digest}`,
    `decide: compared=${d.compared} agree=${d.agree} equivalent-multifault=${d.equivalent_multifault_code_difference} disagree=${d.disagree} (effect=${d.effect_mismatch}, reason=${d.reason_mismatch_same_effect}, matched-ids=${d.matched_mismatch_same_decision}) prod_threw=${d.prod_threw} ref_engine_error=${d.ref_engine_error}`,
    `load(valid generated): ${l.valid_agree}/${l.valid_policies} agree, ${l.valid_disagree} disagree`,
    `load(mutated): ${l.mutated_agree}/${l.mutated_policies} agree, ${l.mutated_disagree} disagree, both-contradict-expectation=${l.mutated_both_contradict_expectation}`,
    `distinct decide signatures=${r.distinct_decide_signatures}  distinct load signatures=${r.distinct_load_signatures}`,
    `time: total=${r.elapsed_ms.total}ms ref=${r.elapsed_ms.ref}ms prod=${r.elapsed_ms.prod}ms`,
  ];
  for (const e of r.decide_disagreements) lines.push(`  [decide x${e.count}] ${e.signature}`);
  for (const e of r.load_disagreements) lines.push(`  [load x${e.count}] ${e.signature}`);
  for (const e of r.load_expectation_misses) lines.push(`  [expectation x${e.count}] ${e.signature}`);
  return lines.join("\n");
}

const isMain = process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error((e as Error).message);
    process.exit(2);
  }
  const list = args.seeds.length > 0 ? args.seeds : [args.seed];
  let anyDiff = false;
  for (const sd of list) {
    console.log(`prysm differential run: seed=${sd} cases=${args.cases}${args.quick ? " (quick)" : ""}`);
    const report = runDiff({ cases: args.cases, seed: sd });
    console.log(summary(report));
    if (args.out) {
      const p = resolve(list.length > 1 ? args.out.replace(/(\.json)?$/, `-seed${sd}$1`) : args.out);
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, JSON.stringify(report, null, 2) + "\n");
      console.log(`report written to ${p}`);
    }
    if (report.decide.disagree > 0 || report.load.valid_disagree > 0 || report.load.mutated_disagree > 0) anyDiff = true;
  }
  process.exit(args.failOnDiff && anyDiff ? 1 : 0);
}
