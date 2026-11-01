// Child process for W5 (4 processes appending to one store).
// Protocol on stdin/stdout: prints READY; on "warm" appends <warmup> rows and prints WARM; on "go" appends <iters> timed
// rows and prints one JSON line {samplesNs, wallNs}. Usage: node append-worker.ts <db> <tag> <warmup> <iters> <seed>
import { openBenchStore } from '../lib/guardkit.ts';
import { mulberry32 } from '../lib/prng.ts';
import { decisionRow } from '../lib/rows.ts';
import { dirname, basename } from 'node:path';

const [db, tag, warmupS, itersS, seedS] = process.argv.slice(2) as [string, string, string, string, string];
const warmup = Number(warmupS);
const iters = Number(itersS);
const rng = mulberry32(Number(seedS));
const store = openBenchStore(dirname(db), 'FULL', basename(db));
const hr = process.hrtime.bigint;

let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk: string) => {
  buf += chunk;
  for (;;) {
    const nl = buf.indexOf('\n');
    if (nl < 0) return;
    const cmd = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (cmd === 'warm') {
      for (let i = 0; i < warmup; i++) store.append(decisionRow(rng, tag + 'w', i));
      process.stdout.write('WARM\n');
    } else if (cmd === 'go') {
      const samplesNs: number[] = new Array<number>(iters);
      const w0 = hr();
      for (let i = 0; i < iters; i++) {
        const row = decisionRow(rng, tag, i);
        const t0 = hr();
        store.append(row);
        samplesNs[i] = Number(hr() - t0);
      }
      const wallNs = Number(hr() - w0);
      store.close();
      process.stdout.write(JSON.stringify({ samplesNs, wallNs }) + '\n', () => { process.exit(0); });
    }
  }
});
process.stdout.write('READY\n');
