import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startTestApp, request, freeBase } from './helpers.js';
import { guardNetwork } from './netguard.js';
import { startHttpServer } from '../src/app.js';
import { createRuntime } from '../src/runtime.js';

const srcDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src');
const sources = (dir = srcDir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? sources(path.join(dir, e.name)) : e.name.endsWith('.js') ? [path.join(dir, e.name)] : []));

test('the server binds loopback by default, refuses another address without TW_BIND, and really listens on 127.0.0.1 only', async (t) => {
  await assert.rejects(startHttpServer({ port: 1, host: '0.0.0.0', env: {} }), /loopback only/);
  const app = await startTestApp('safety'); t.after(app.close);
  // Reachable on loopback; the listener address is 127.0.0.1.
  assert.equal((await app.get('/api/health')).status, 200);
  const addr = await new Promise((resolve) => { const s = net.connect(app.port, '127.0.0.1', () => { resolve(s.remoteAddress); s.destroy(); }); });
  assert.equal(addr, '127.0.0.1');
});

test('every port in use is inside 5900-5999', async (t) => {
  const app = await startTestApp('safety'); t.after(app.close);
  assert.ok([app.port, ...app.runtime.ports].every((p) => p >= 5900 && p <= 5999));
  assert.equal(app.runtime.ports.length, 6);
});

test('Host guard: non-loopback, missing and malformed Host headers get 421', async (t) => {
  const app = await startTestApp('safety'); t.after(app.close);
  for (const host of ['evil.example.com', 'evil.example.com:5910', '127.0.0.1.evil.com', 'localhost.evil.com', '127.999.999.999', '[::1]junk', '10.0.0.1:5910', '0.0.0.0']) {
    const r = await request(app.port, 'GET', '/api/health', { host });
    assert.equal(r.status, 421, host);
  }
  for (const host of [`127.0.0.1:${app.port}`, `localhost:${app.port}`, '127.0.0.1']) assert.equal((await request(app.port, 'GET', '/api/health', { host })).status, 200, host);
  // HTTP/1.0 request without a Host header
  const raw = await new Promise((resolve) => { const s = net.connect(app.port, '127.0.0.1', () => s.write('GET /api/health HTTP/1.0\r\n\r\n')); let d = ''; s.on('data', (c) => { d += c; }); s.on('close', () => resolve(d)); });
  assert.match(raw, /^HTTP\/1\.1 421/);
});

test('CSRF: a cross-origin or cross-site POST is refused, same-origin is accepted', async (t) => {
  const app = await startTestApp('safety'); t.after(app.close);
  const body = { sample: 'agent' };
  const origin = `http://127.0.0.1:${app.port}`;
  const refused = [
    { 'sec-fetch-site': 'cross-site' }, { origin: 'http://evil.example.com' }, { origin: 'null' }, { origin: 'https://127.0.0.1:' + app.port },
    { origin: 'http://127.0.0.1:9' }, { origin: `http://localhost:${app.port}` }, { origin: `${origin}/` }, { origin: `http://user:pw@127.0.0.1:${app.port}` },
  ];
  for (const headers of refused) {
    const r = await app.post('/api/mint', body, { headers });
    assert.equal(r.status, 403, JSON.stringify(headers));
  }
  for (const headers of [{}, { origin }, { 'sec-fetch-site': 'same-origin', origin }, { 'sec-fetch-site': 'none' }]) assert.equal((await app.post('/api/mint', body, { headers })).status, 200, JSON.stringify(headers));
  // refusing happens before the handler runs: a refused tester run runs nothing
  const before = app.runtime.rs.stats.requests;
  assert.equal((await app.post('/api/tester/run', { case: 'all' }, { headers: { 'sec-fetch-site': 'cross-site' } })).status, 403);
  assert.equal(app.runtime.rs.stats.requests, before);
});

test('a request body must be application/json (415), including text/plain "simple" requests', async (t) => {
  const app = await startTestApp('safety'); t.after(app.close);
  for (const ct of ['text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x', 'application/jsonp']) {
    const r = await app.post('/api/decode', '{"token":"x"}', { headers: { 'content-type': ct } });
    assert.equal(r.status, 415, ct);
  }
  assert.equal((await app.post('/api/decode', '{"token":"x"}', { headers: { 'content-type': 'application/json; charset=utf-8' } })).status, 400);
});

test('credentials are refused on every API route: Authorization, Proxy-Authorization and X-Api-Key, even on health and GET', async (t) => {
  const app = await startTestApp('safety'); t.after(app.close);
  const token = (await app.post('/api/mint', { sample: 'agent' })).json.token;
  for (const h of ['authorization', 'proxy-authorization', 'x-api-key']) {
    for (const [method, p, body] of [['GET', '/api/health'], ['GET', '/api/meta'], ['POST', '/api/decode', { token }], ['POST', '/api/tester/run', { case: 'good' }], ['POST', '/api/checker/run', { profile: 'good' }]]) {
      const r = await request(app.port, method, p, { body, headers: { [h]: `Bearer ${token}` } });
      assert.equal(r.status, 400, `${h} ${p}`);
      assert.equal(r.json.error, 'credentials_not_accepted');
      assert.equal(r.raw.includes(token), false, 'the token is never echoed');
    }
  }
});

test('default mode: decode, mint, the whole tester, both checker packs on all profiles and the flows make zero non-loopback connections', async (t) => {
  const app = await startTestApp('safety'); t.after(app.close);
  const guard = guardNetwork(); t.after(() => guard.restore());
  const token = (await app.post('/api/mint', { sample: 'dpop' })).json.token;
  assert.equal((await app.post('/api/decode', { token, verify: true })).status, 200);
  assert.equal((await app.post('/api/tester/run', { case: 'all' })).status, 200);
  for (const profile of ['good', 'loose-redirect', 'implicit-ropc', 'no-pkce', 'missing-metadata']) assert.equal((await app.post('/api/checker/run', { profile })).status, 200);
  assert.equal((await app.post('/api/checker/run', { target: 'http://203.0.113.5/' })).status, 400);
  assert.equal((await app.post('/api/checker/run', { target: 'http://example.com/' })).status, 400);
  assert.equal((await app.get('/api/flows/compare')).status, 200);
  guard.restore();
  assert.deepEqual(guard.attempts, []);
});

test('the guard itself works: it records and blocks a non-loopback socket, lookup and fetch', async (t) => {
  const guard = guardNetwork(); t.after(() => guard.restore());
  await assert.rejects(fetch('http://example.com/'), /network blocked/);
  assert.throws(() => net.connect(80, '203.0.113.5'), /network blocked/);
  guard.restore();
  assert.deepEqual(guard.attempts.sort(), ['fetch:example.com', 'socket:203.0.113.5']);
});

test('source scan: only http.js opens outbound connections; no fs writes; no environment-supplied target', () => {
  for (const f of sources()) {
    const text = fs.readFileSync(f, 'utf8');
    const name = path.relative(srcDir, f);
    if (name !== 'http.js') {
      assert.doesNotMatch(text, /\bfetch\(/, `${name} must not call fetch`);
      assert.doesNotMatch(text, /http\.request\(|https\.request|node:https|net\.connect|node:dns|node:child_process|WebSocket/, `${name} must not open its own connections or processes`);
    }
    assert.doesNotMatch(text, /writeFile|appendFile|createWriteStream|mkdirSync|\.writeSync/, `${name} must not write files`);
    assert.doesNotMatch(text, /process\.env\.\w*(TARGET|URL|PROXY)/i, `${name} takes no target from the environment`);
  }
});

test('private keys exist only in memory: nothing exports a private key and no key material is in the repo', () => {
  const keys = fs.readFileSync(path.join(srcDir, 'keys.js'), 'utf8');
  assert.doesNotMatch(keys, /privateKey\.export|\.export\(\{[^}]*pkcs8|\.export\(\{[^}]*type:/);
  const root = path.resolve(srcDir, '../..');
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (['node_modules', '.git'].includes(e.name) ? [] : e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
  for (const f of walk(root)) {
    assert.doesNotMatch(f, /\.(pem|key|p12|pfx|jks)$/, f);
    if (/\.(js|mjs|json|md|yml)$/.test(f) && !f.endsWith('safety.test.js') && !f.endsWith('package-lock.json')) assert.doesNotMatch(fs.readFileSync(f, 'utf8'), /-----BEGIN [A-Z ]*PRIVATE KEY-----/, f);
  }
});

test('the stub keys are different on every start and the JWKS has no private part', async (t) => {
  const base = await freeBase('safety', 8);
  const a = await createRuntime({ stubBase: base + 1 });
  const ka = a.keyring.jwks().keys[0];
  await a.close();
  const b = await createRuntime({ stubBase: base + 1 });
  t.after(() => b.close());
  assert.notEqual(ka.x, b.keyring.jwks().keys[0].x);
  assert.equal(ka.d, undefined);
});

test('no token is written to stdout/stderr/console by decode, mint, the tester or a failing request', async (t) => {
  const app = await startTestApp('safety'); t.after(app.close);
  const out = [];
  const grab = (orig) => (chunk, ...rest) => { out.push(String(chunk)); return orig(chunk, ...rest); };
  const so = process.stdout.write.bind(process.stdout); const se = process.stderr.write.bind(process.stderr);
  process.stdout.write = grab(so); process.stderr.write = grab(se);
  t.after(() => { process.stdout.write = so; process.stderr.write = se; });
  const token = (await app.post('/api/mint', { sample: 'agent' })).json.token;
  await app.post('/api/decode', { token, verify: true });
  await app.post('/api/decode', `{"token":"${token}`); // broken JSON containing the token
  const t1 = (await app.post('/api/tester/run', { case: 'all' })).json.results.map((r) => r.token).filter(Boolean);
  process.stdout.write = so; process.stderr.write = se;
  const joined = out.join('');
  for (const tok of [token, ...t1]) for (const part of tok.split('.').filter((p) => p.length > 20)) assert.equal(joined.includes(part), false);
});
