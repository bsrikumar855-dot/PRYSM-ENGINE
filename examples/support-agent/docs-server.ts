// Tiny docs fixture server on 127.0.0.1 (random free port) serving canned "corporate" pages.
import { createServer } from 'node:http';

export interface DocsServer {
  port: number;
  url: (path: string) => string;
  /** Request paths (with query) seen by the server, in order. */
  requests: string[];
  close(): Promise<void>;
}

const PAGES: Record<string, string> = {
  '/pricing': 'Corporate pricing page: support may grant up to 10 percent discount with the sales scope.',
  '/returns': 'Corporate returns page: returns are accepted within 14 days.',
};

export async function startDocsServer(): Promise<DocsServer> {
  const requests: string[] = [];
  const server = createServer((req, res) => {
    requests.push(req.url ?? '');
    const path = (req.url ?? '').split('?')[0] ?? '';
    const body = PAGES[path];
    res.writeHead(body === undefined ? 404 : 200, { 'content-type': 'text/plain', connection: 'close' });
    res.end(body ?? 'not found');
  });
  await new Promise<void>((res, rej) => {
    server.once('error', rej);
    server.listen(0, '127.0.0.1', () => { res(); });
  });
  const addr = server.address();
  if (addr === null || typeof addr === 'string') throw new Error('no port');
  const port = addr.port;
  return {
    port,
    requests,
    url: (p) => `http://docs.corp.com:${port}${p}`,
    close: () => new Promise<void>((res) => {
      server.closeAllConnections();
      server.close(() => { res(); });
    }),
  };
}
