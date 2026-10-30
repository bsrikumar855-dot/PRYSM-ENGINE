// Child process: appends N events to a shared DB (used by the concurrency test).
import { openStore } from '../../src/store/index.ts';

const [path, tag, nStr] = process.argv.slice(2) as [string, string, string];
const store = openStore({ path, busyTimeoutMs: 20000 });
const n = Number(nStr);
for (let i = 0; i < n; i++) {
  store.append({ id: `${tag}-${i}`, kind: 'decision', effect: 'deny', agent_id: tag, outcome: { i } });
}
store.close();
process.stdout.write('DONE\n');
