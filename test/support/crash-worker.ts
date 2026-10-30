// Child process: runs a guarded call whose tool kills the process after the decision row is durable.
import { loadPolicy } from '../../src/core/index.ts';
import { openStore } from '../../src/store/index.ts';
import { createGuard } from '../../src/guard/index.ts';
import { POLICY_DOC } from './policy.ts';

const [path] = process.argv.slice(2) as [string];
const store = openStore({ path });
const guard = createGuard({
  policy: loadPolicy(JSON.stringify(POLICY_DOC())),
  store,
  agentId: 'agent-1',
  secondarySink: () => {},
  tools: {
    read_file: () => {
      process.kill(process.pid, 'SIGKILL');
      return 'unreachable';
    },
  },
});
await guard.call('read_file', { path: '/a' });
