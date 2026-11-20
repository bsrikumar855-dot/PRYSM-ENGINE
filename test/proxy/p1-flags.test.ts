// P1 CLI flags (critical review minor 13): parsing of the three production-hardening flags and their defaults.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from '../../src/proxy/index.ts';

const base = ['--policy', 'p', '--db', 'd'];

test('P1 flags: defaults leave every hardening on (no opt-out fields set)', () => {
  const c = parseArgs([...base, '--', 'server']);
  assert.equal(c.taintForwarded, undefined);
  assert.equal(c.allowUnprotectedKey, undefined);
  assert.equal(c.forwardInstructions, undefined);
});

test('P1 flags: each opt-out maps to its option, alone and together, in any order', () => {
  assert.equal(parseArgs([...base, '--no-taint-forwarded', '--', 's']).taintForwarded, false);
  assert.equal(parseArgs([...base, '--allow-unprotected-key', '--', 's']).allowUnprotectedKey, true);
  assert.equal(parseArgs([...base, '--forward-instructions', '--', 's']).forwardInstructions, true);
  const all = parseArgs(['--forward-instructions', ...base, '--allow-unprotected-key', '--no-taint-forwarded', '--', 's']);
  assert.deepEqual([all.taintForwarded, all.allowUnprotectedKey, all.forwardInstructions], [false, true, true]);
});

test('P1 flags: they take no value, and flags after -- belong to the server command', () => {
  const c = parseArgs([...base, '--no-taint-forwarded', '--', 's', '--allow-unprotected-key']);
  assert.equal(c.allowUnprotectedKey, undefined);
  assert.deepEqual(c.server.args, ['--allow-unprotected-key']);
  assert.throws(() => parseArgs([...base, '--taint-forwarded', '--', 's']), /unknown_flag/);
});
