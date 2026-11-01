// Entry point: `node src/cli/bin.ts <command> ...` (package.json bin: prysm).
// node:sqlite prints an ExperimentalWarning on import; drop the default warning printer before it is loaded so
// stderr carries only PRYSM messages. Exit code is set via exitCode so piped stdout is never truncated.
// A closed pipe (`| head`) ends quietly with exit code 0.
process.removeAllListeners('warning');
let closed = false;
process.stdout.on('error', () => { closed = true; });
process.stderr.on('error', () => { /* ignore */ });

const { run } = await import('./main.ts');
const code = await run(process.argv.slice(2), {
  out: (line) => { if (!closed) process.stdout.write(line + String.fromCharCode(10)); },
  err: (line) => { process.stderr.write(line + String.fromCharCode(10)); },
});
process.exitCode = closed ? 0 : code;
