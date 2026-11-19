// S-09: a crashed earlier --out write leaves `.<name>.tmp-<hex>`; the next write removes stale ones (older than
// 10 minutes) for the same target and touches nothing else.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, utimesSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { runCli, guardFixture } from '../support/cli-kit.ts';
import { cleanup } from '../support/tmp.ts';

after(cleanup);

test('S-09: stale temp files for the same --out target are swept; fresh ones and other files are kept', async () => {
  const fx = await guardFixture();
  const out = join(fx.dir, 'r.html');
  const stale = join(fx.dir, '.r.html.tmp-0123456789ab');
  const fresh = join(fx.dir, '.r.html.tmp-ba9876543210');
  const other = join(fx.dir, '.other.html.tmp-0123456789ab');
  const lookalike = join(fx.dir, '.r.html.tmp-notours');
  for (const f of [stale, fresh, other, lookalike]) writeFileSync(f, 'x');
  const old = (Date.now() - 60 * 60_000) / 1000;
  for (const f of [stale, other, lookalike]) utimesSync(f, old, old);
  const r = await runCli(['report', '--db', fx.db, '--out', out]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(existsSync(out), true);
  assert.equal(existsSync(stale), false, 'stale temp for this target removed');
  assert.equal(existsSync(fresh), true, 'a fresh temp (possibly another writer) is kept');
  assert.equal(existsSync(other), true, 'temps for other targets are kept');
  assert.equal(existsSync(lookalike), true, 'names outside the exact pattern are kept');
});
