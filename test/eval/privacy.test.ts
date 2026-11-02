import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

function* walk(dir: string): Generator<string> {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) yield* walk(p);
    else if (p.endsWith('.json')) yield p;
  }
}

test('committed benchmark and differential results contain no personal paths (M5-01)', () => {
  const bad = /[A-Za-z]:\{1,2}Users|\/Users\/|\/home\//;
  for (const root of ['bench/results', 'eval/diff/reports']) {
    for (const f of walk(root)) assert.equal(bad.test(readFileSync(f, 'utf8')), false, f);
  }
});
