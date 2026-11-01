// CLI: node src/proxy/bin.ts --policy <file> --db <file> [flags] -- <server-command> [args...]
// Exit codes: 0 client EOF, 1 server exit, 2 bad flags / configuration, 70 uncaught exception.
import { ArgsError, parseArgs } from './args.ts';
import { createProxy, ProxyConfigError } from './proxy.ts';
import type { ProxyHandle } from './proxy.ts';

function exit(code: number): never {
  process.stdout.write('', () => { process.exit(code); });
  setTimeout(() => process.exit(code), 500).unref();
  return undefined as never;
}

let handle: ProxyHandle | undefined;
let fatalSeen = false;
const onFatal = (): void => {
  if (fatalSeen) return;
  fatalSeen = true;
  try {
    if (handle !== undefined) handle.fatal();
    else process.stderr.write('{"prysm":"proxy_fatal"}\n');
  } catch { /* nothing more can be done */ }
  process.exit(70);
};
process.on('uncaughtException', onFatal);
process.on('unhandledRejection', onFatal);

try {
  const cfg = parseArgs(process.argv.slice(2));
  handle = createProxy({ ...cfg, clientIn: process.stdin, clientOut: process.stdout });
} catch (e) {
  const code = e instanceof ArgsError || e instanceof ProxyConfigError ? e.code : 'startup_failed';
  process.stderr.write('prysm-proxy: ' + code + '\n');
  process.exit(2);
}
if (handle !== undefined) {
  const h = handle;
  void h.done.then((c) => { exit(c); });
  // orderly shutdown (same path as client EOF): abort, close server stdin, grace, kill tree, anchor line, exit 0
  for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => { void h.stop(); });
  // test seam for the exit-70 path (uncaught exception); inert unless the operator sets it
  if (process.env['PRYSM_PROXY_TEST_FATAL'] === '1') setImmediate(() => { throw new Error('test fatal'); });
}
