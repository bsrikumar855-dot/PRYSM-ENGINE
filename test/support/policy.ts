// Shared guard-test policy.
export const TOOLS = {
  search_docs: { risk: 'low', external_effect: false, read_only: true, fail_mode: 'open_on_audit_failure', args: { query: { type: 'string' } } },
  read_file: { risk: 'medium', external_effect: false, read_only: true, fail_mode: 'closed', args: { path: { type: 'string' } } },
  send_email: {
    risk: 'high', external_effect: true, read_only: false, fail_mode: 'closed',
    args: { to: { type: 'string' }, subject: { type: 'string' }, body: { type: 'string' }, cc: { type: 'string', optional: true } },
  },
  set_discount: { risk: 'high', external_effect: true, read_only: false, fail_mode: 'closed', args: { percent: { type: 'number' } } },
  note: { risk: 'low', external_effect: false, read_only: false, fail_mode: 'closed', args: { text: { type: 'string' }, tags: { type: 'string[]', optional: true } } },
  denied_by_default: { risk: 'low', external_effect: false, read_only: true, fail_mode: 'closed', args: { x: { type: 'string' } } },
} as const;

export function rule(effect: 'permit' | 'deny', id: string, match: Record<string, unknown>) {
  return { id, effect, reason_code: 'r_' + id.replace(/[^A-Za-z0-9]/g, '_'), match };
}

export function POLICY_DOC(mode: 'enforce' | 'monitor_only' = 'enforce', extraRules: unknown[] = []): Record<string, unknown> {
  return {
    policy_schema_version: 1,
    name: 'guard-test',
    mode,
    tools: TOOLS,
    rules: [
      rule('permit', 'p.search', { tools: ['search_docs'] }),
      rule('permit', 'p.read', { tools: ['read_file'] }),
      rule('permit', 'p.email', { tools: ['send_email'] }),
      rule('permit', 'p.discount', { tools: ['set_discount'] }),
      rule('permit', 'p.note', { tools: ['note'] }),
      rule('deny', 'd.secret', { tools: ['read_file'], args: { path: { glob: '/secret*' } } }),
      ...extraRules,
    ],
  };
}
