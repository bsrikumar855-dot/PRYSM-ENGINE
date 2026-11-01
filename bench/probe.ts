// Runs one PRYSM CLI command in-process (the same entry the `prysm` bin uses) and prints one JSON line with its
// duration and the process peak RSS. Used by W8 so memory can be attributed to the command alone.
// Usage: node probe.ts <cli args...>
process.removeAllListeners('warning');
const hr = process.hrtime.bigint;
const { run } = await import('../src/cli/main.ts');
const outLines: string[] = [];
const errLines: string[] = [];
const t0 = hr();
const code = await run(process.argv.slice(2), { out: (l) => { outLines.push(l); }, err: (l) => { errLines.push(l); } });
const ms = Number(hr() - t0) / 1e6;
process.stdout.write('PROBE ' + JSON.stringify({
  exit_code: code,
  inproc_ms: ms,
  // process.resourceUsage().maxRSS is in KiB (peak working set on Windows)
  peak_rss_mb: process.resourceUsage().maxRSS / 1024,
  stdout_first_line: (outLines[0] ?? '').slice(0, 120),
  stderr_lines: errLines.length,
}) + '\n');
