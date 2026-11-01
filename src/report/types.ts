// Report data model (REPORT-SPEC §2). Plain, JSON-serialisable values only. Every string here may be
// attacker-influenced (tool names, session ids, reason codes, args_redacted keys): the renderer escapes all of them.
import type { Anchor, VerifyIssue } from '../store/index.ts';
import type { LoadedPolicy } from '../core/index.ts';

export interface BuildReportOptions {
  /** Optional policy used for rule detail; shown only for rows whose policy_version equals policy.policy_version. */
  policy?: LoadedPolicy;
  /** Window size for the decisions explorer and the event log (default 500, clamped to 1..5000). */
  maxEvents?: number;
  anchor?: Anchor;
  expectPruned?: { through_seq: number; last_hash: string } | { through_seq: number; last_hash: string }[];
  allowPruned?: boolean;
  /** Newest rows scanned for metrics (default 2 000 000). */
  scanLimit?: number;
  title?: string;
  /** Generation time. Never read from the clock inside this package. */
  generatedMs: number;
  /** Database file name; only the basename is kept. */
  dbName: string;
}

export interface CountRow {
  name: string;
  count: number;
}

export interface ResultView {
  seq: number;
  id: string;
  status: string | null;
  error_class: string | null;
  result_type: string | null;
  result_len: number | null;
}

export interface RuleDetail {
  id: string;
  found: boolean;
  effect: string | null;
  reason_code: string | null;
  summary: string[];
}

export interface DecisionView {
  /** Unique in-page anchor id (without '#'), derived from the first 8 characters of the decision id. */
  anchor: string;
  seq: number;
  id: string;
  ts_ms: number;
  session_id: string | null;
  agent_id: string | null;
  tool: string | null;
  effect: string | null;
  enforcement: string | null;
  reason_code: string | null;
  reason_class: string;
  rule_ids: string[];
  policy_version: string | null;
  risk: string | null;
  session_tainted: boolean | null;
  provenance: string | null;
  args_redacted: string | null;
  latency_us: number | null;
  will_execute: boolean;
  dropped_before: string | null;
  verdict: string;
  why: string;
  results: ResultView[];
  /** 'shown' = rules below come from the supplied policy (versions equal). */
  rule_detail: 'shown' | 'version_mismatch' | 'no_policy';
  rules: RuleDetail[];
}

export interface EventView {
  seq: number;
  id: string;
  ts_ms: number;
  kind: string;
  effect: string | null;
  enforcement: string | null;
  reason_code: string | null;
  tool: string | null;
  decision_id: string | null;
  /** In-page anchor of the linked decision when that decision is inside the decisions window. */
  decision_anchor: string | null;
}

export interface ActivationView {
  seq: number;
  ts_ms: number;
  event: string;
  policy_version: string | null;
  mode: string | null;
  rule_count: number | null;
  details: string;
}

export interface PostureView {
  seq: number;
  ts_ms: number;
  fields: { key: string; value: string }[];
}

export interface VerifyView {
  ok: boolean;
  count: number;
  head_seq: number;
  head_hash: string;
  pruned_through: number | null;
  errors: VerifyIssue[];
  warnings: VerifyIssue[];
  checkpoints: number;
  /** Set when verify itself could not run (the report still renders, as FAILED). */
  unavailable: boolean;
}

export interface ReasonRow {
  group: string;
  code: string;
  count: number;
}

export interface Metrics {
  /** Rows inside the metrics scan (equals the store total unless the scan was truncated). */
  events_total: number;
  by_kind: CountRow[];
  decisions_total: number;
  by_effect: CountRow[];
  by_enforcement: CountRow[];
  /** effect=deny and enforcement=enforced. */
  denied: number;
  /** effect=deny and enforcement=monitor_only (reported separately). */
  would_be_denied: number;
  enforced_decisions: number;
  /** denied / enforced_decisions, or null when there are none. */
  deny_rate: number | null;
  reason_classes: ReasonRow[];
  /** Enforced denies whose tool name is the unknown marker (not a real name). */
  unknown_tool_names: number;
  top_denied_tools: CountRow[];
  top_rules: CountRow[];
  sessions: number;
  tainted_decisions: number;
  tainted_share: number | null;
  dropped_before_total: number;
  dropped_before_by_class: CountRow[];
  tool_results: { ok: number; error: number; timeout: number; other: number; total: number };
}

export interface LatencyView {
  n: number;
  p50: number | null;
  p95: number | null;
  p99: number | null;
  max: number | null;
}

export interface ReportData {
  title: string;
  generated_ms: number;
  db_name: string;
  schema_version: string;
  head: { seq: number; hash: string } | null;
  genesis_hash: string | null;
  anchor_info: { genesis_hash: string; head_seq: number; head_hash: string } | null;
  expected_pruned: { through_seq: number; last_hash: string }[];
  checkpoints: { seq: number; through_seq: number; last_hash: string }[];
  scan: { scanned: number; total: number; truncated: boolean };
  too_large: boolean;
  verify: VerifyView;
  anchor_supplied: boolean;
  expected_pruned_supplied: boolean;
  allow_pruned: boolean;
  key_protection: string | null;
  policy: { name: string; policy_version: string; mode: string; rule_count: number } | null;
  posture_config: PostureView | null;
  posture_client: PostureView | null;
  metrics: Metrics;
  latency: LatencyView;
  activations: ActivationView[];
  activations_total: number;
  top_policy_version: string | null;
  decisions: DecisionView[];
  events: EventView[];
  window: {
    requested: number;
    effective: number;
    activations_shown: number;
    decisions_shown: number;
    decisions_total: number;
    events_shown: number;
    events_total: number;
    shrunk: boolean;
  };
  /** Set when stored rows could not be decoded (metrics are then empty); a stable code, never a value. */
  read_error: string | null;
}
