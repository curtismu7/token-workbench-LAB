// Test helpers. Every test file owns a distinct slice of 5950-5999 so files running in parallel never collide.
import http from 'node:http';
import net from 'node:net';

export const BASES = { api: 5950, tester: 5960, checker: 5970, safety: 5980, misc: 5990 };
const SLICE_END = { api: 5959, tester: 5969, checker: 5979, safety: 5989, misc: 5999 };

const isFree = (port) => new Promise((resolve) => {
  const s = net.createServer();
  s.once('error', () => resolve(false));
  s.listen(port, '127.0.0.1', () => s.close(() => resolve(true)));
});

// A run of `count` consecutive free loopback ports inside the file's own slice of 5950-5999. The search resumes
// after the last run handed out (and wraps), so a port is not reused right after a test closed a server on it.
const cursor = {};
export async function freeBase(slice, count = 8) {
  const first = BASES[slice]; const last = SLICE_END[slice];
  const starts = [];
  for (let s = cursor[slice] ?? first; s + count - 1 <= last; s += 1) starts.push(s);
  for (let s = first; s < (cursor[slice] ?? first) && s + count - 1 <= last; s += 1) starts.push(s);
  for (const start of starts) {
    let ok = true;
    for (let p = start; p < start + count && ok; p += 1) ok = await isFree(p);
    if (ok) { cursor[slice] = start + count; return start; }
  }
  throw new Error(`no ${count} free ports in ${first}-${last}`);
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
  const base = await freeBase(slice, 8);
  const app = await startHttpServer({ port: base, stubBase: base + 1, ...opts });
  return { port: app.port, runtime: app.runtime, base, close: app.close, post: (p, body, o) => request(app.port, 'POST', p, { body, ...o }), get: (p, o) => request(app.port, 'GET', p, o) };
}
