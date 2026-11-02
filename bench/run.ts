// `npm run bench` (full protocol) / `npm run bench:quick` (reduced iterations).
// Flags: --quick, --smoke (tiny, tests), --only W1,W4.permit (case ids / workloads), --out <dir>.
process.removeAllListeners('warning');
const { parseOptions, childMain, parentMain } = await import('./lib/orchestrate.ts');

try {
  const o = parseOptions(process.argv.slice(2));
  if (o.child !== null) await childMain(o);
  else {
    const r = await parentMain(o);
    if (r.summary.failures.length > 0) process.exitCode = 1; // a failed run (including row-accounting failures) fails the benchmark
  }
} catch (e) {
  process.stderr.write(`bench: ${(e as Error).message}\n`);
  process.exitCode = 1;
}
