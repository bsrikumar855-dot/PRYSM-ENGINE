// Error types for the PRYSM core. No I/O, no node imports.

export type PolicyErrorCode =
  | 'invalid_json'
  | 'invalid_encoding'
  | 'bom'
  | 'duplicate_key'
  | 'forbidden_key'
  | 'forbidden_char'
  | 'limit_exceeded'
  | 'unknown_key'
  | 'missing_key'
  | 'invalid_type'
  | 'invalid_value'
  | 'invalid_identifier'
  | 'duplicate_id'
  | 'unknown_tool'
  | 'unknown_arg'
  | 'empty_match'
  | 'invalid_fail_mode'
  | 'invalid_predicate';

/** Show a value in a message only if it is short (spec §8: never echo > 40 chars). */
export function show(v: unknown): string {
  if (typeof v === 'string') return v.length <= 40 ? JSON.stringify(v) : '<long string>';
  if (typeof v === 'number' || typeof v === 'boolean' || v === null) return String(v);
  return `<${typeof v}>`;
}

export class PolicyError extends Error {
  code: PolicyErrorCode;
  path: string;
  constructor(code: PolicyErrorCode, path: string, message: string) {
    super(message);
    this.name = 'PolicyError';
    this.code = code;
    this.path = path;
  }
}

export type RequestErrorCode = 'invalid_request' | 'limit_exceeded';

export class RequestError extends Error {
  code: RequestErrorCode;
  path: string;
  constructor(code: RequestErrorCode, path: string, message: string) {
    super(message);
    this.name = 'RequestError';
    this.code = code;
    this.path = path;
  }
}
