// Test helpers. Every test file prefers its own slice of 5950-5999; the search wraps over the whole range if a port is busy.
import http from 'node:http';
import net from 'node:net';

export const BASES = { api: 5950, tester: 5958, checker: 5966, safety: 5974, misc: 5982, ui: 5990 };

const isFree = (port) => new Promise((resolve) => {
  const s = net.createServer();
  s.once('error', () => resolve(false));
  s.listen(port, '127.0.0.1', () => s.close(() => resolve(true)));
});

// A run of `count` consecutive free loopback ports in 5950-5999. Each file prefers its own slice (BASES) but the search
// wraps over the whole range, so a port held by another agent or a parallel run only moves the search along. The search
// resumes after the last run handed out, so a port is not reused right after a test closed a server on it.
const FIRST = 5950; const LAST = 5999;
const cursor = {};
export async function freeBase(slice, count = 8) {
  const begin = cursor[slice] ?? BASES[slice];
  const span = LAST - FIRST + 1;
  for (let i = 0; i < span; i += 1) {
    const start = FIRST + ((begin - FIRST + i) % span);
    if (start + count - 1 > LAST) continue;
    let ok = true;
    for (let p = start; p < start + count && ok; p += 1) ok = await isFree(p);
    if (ok) { cursor[slice] = start + count; return start; }
  }
  throw new Error(`no ${count} free ports in ${FIRST}-${LAST}`);
}

// Like fetch, but lets a test set the Host header. Resolves { status, headers, json, raw }.
export function request(port, method, path, { headers = {}, body, host } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
    const req = http.request({ host: '127.0.0.1', port, method, path, agent: false, headers: { ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}), ...(host ? { host } : {}), ...headers } }, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => { let json = null; try { json = JSON.parse(raw); } catch { /* not json */ } resolve({ status: res.statusCode, headers: res.headers, json, raw }); });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// Starts the whole app (stubs + API) on a free run of ports inside one slice: the API on base, the six stubs on base+1..base+6.
export async function startTestApp(slice, opts = {}) {
  const { startHttpServer } = await import('../src/app.js');
  // Another process can take a port between the check and the bind: retry on the next run of ports.
  let base; let app;
  for (let attempt = 0; ; attempt += 1) {
    base = await freeBase(slice, 8);
    try { app = await startHttpServer({ port: base, stubBase: base + 1, ...opts }); break; } catch (e) { if (e.code !== 'EADDRINUSE' || attempt >= 5) throw e; }
  }
  return { port: app.port, runtime: app.runtime, base, close: app.close, post: (p, body, o) => request(app.port, 'POST', p, { body, ...o }), get: (p, o) => request(app.port, 'GET', p, o) };
}
