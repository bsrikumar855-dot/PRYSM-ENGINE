// Audit-row accounting. A case whose store has fewer rows than the path implies is not measuring what it claims to
// (for example result rows silently rate-limited), so it FAILS instead of just recording the numbers.

export interface RowAccounting {
  calls_total: number;
  rows_per_call: number;
  rows_expected_min: number;
  rows_expected_max: number;
  audit_rows: number;
}

/** Slack above the minimum for rows that are not per call (policy_activate, tool pins, list rows, ...). */
export const EXTRA_ROWS_ALLOWED = 16;
/** Fraction of the per-call rows that may be missing before the case fails. */
export const MISSING_TOLERANCE = 0.001;

export function expectedRows(calls: number, rowsPerCall: number): { min: number; max: number } {
  return { min: Math.floor(calls * rowsPerCall * (1 - MISSING_TOLERANCE)), max: calls * rowsPerCall + EXTRA_ROWS_ALLOWED };
}

/** Returns the accounting record (to store in the result) or throws when rows are missing or surplus. */
export function checkRows(label: string, calls: number, rowsPerCall: number, actual: number): RowAccounting {
  const { min, max } = expectedRows(calls, rowsPerCall);
  const rec: RowAccounting = { calls_total: calls, rows_per_call: rowsPerCall, rows_expected_min: min, rows_expected_max: max, audit_rows: actual };
  if (actual < min || actual > max) {
    throw new Error(`${label}: audit row accounting failed: ${actual} rows for ${calls} calls (expected ${min}..${max}, about ${rowsPerCall} per call)`);
  }
  return rec;
}
