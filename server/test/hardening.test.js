// TW2 fix pass: pins for the limits and guards the review found unpinned. Each test here was checked to FAIL when the
// code it names is reverted (see CHANGELOG, step TW2).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { startTestApp, request, freeBase } from './helpers.js';
import { loopbackRequest, connectHostname } from '../src/http.js';
import { createRuntime } from '../src/runtime.js';
import { startHttpServer, UI_CSP } from '../src/app.js';
import { bindHost, parseHost } from '../src/safety.js';
import { MAX_TOKEN_CHARS, b64uJson, parseJwt, verifyEs256 } from '../src/jwt.js';
import { inertValue, revealText } from '../src/sanitize.js';
import { runCase } from '../src/tester.js';
import { runChecks } from '../src/doctor.js';
import { BCP_RULES } from '../src/checker.js';

const listen = (handler, port) => new Promise((resolve) => { const s = http.createServer(handler).listen(port, '127.0.0.1', () => resolve(s)); });
const stop = (s) => new Promise((r) => { s.closeAllConnections?.(); s.close(r); });
const raw = (port, text) => new Promise((resolve) => { const s = net.connect(port, '127.0.0.1', () => s.write(text)); let d = ''; s.on('data', (c) => { d += c; }); s.on('close', () => resolve(d)); s.on('error', () => resolve(d)); setTimeout(() => s.destroy(), 3000).unref(); });

// ---------- outbound client: total deadline, body cap, localhost mapping ----------
test('http.js: the timeout is a TOTAL deadline, so a server that drips bytes cannot hold a request', async (t) => {
  const port = await freeBase('misc', 1);
  const srv = await listen((_req, res) => { res.writeHead(200); const iv = setInterval(() => res.write(' '), 80); res.on('close', () => clearInterval(iv)); }, port); t.after(() => stop(srv));
  const t0 = Date.now();
  await assert.rejects(loopbackRequest(`http://127.0.0.1:${port}/`, { timeoutMs: 400 }), (e) => e.code === 'ETIMEDOUT');
  assert.ok(Date.now() - t0 < 1500, `gave up after ${Date.now() - t0} ms`);
});

test('http.js: the default deadline is 2 s, for a server that never answers', { timeout: 10000 }, async (t) => {
  const port = await freeBase('misc', 1);
  const srv = await listen(() => {}, port); t.after(() => stop(srv));
  const t0 = Date.now();
  await assert.rejects(loopbackRequest(`http://127.0.0.1:${port}/`), (e) => e.code === 'ETIMEDOUT');
  const took = Date.now() - t0;
  assert.ok(took >= 1800 && took < 4000, `took ${took} ms`);
});

test('the checker answers within seconds against a slow-drip loopback target and the run queue is free afterwards', { timeout: 20000 }, async (t) => {
  const app = await startTestApp('misc'); t.after(app.close);
  const port = await freeBase('misc', 1);
  const srv = await listen((_req, res) => { res.writeHead(200); const iv = setInterval(() => res.write(' '), 100); res.on('close', () => clearInterval(iv)); }, port); t.after(() => stop(srv));
  const t0 = Date.now();
  const r = await app.post('/api/checker/run', { target: `http://127.0.0.1:${port}`, pack: 'bcp' });
  assert.equal(r.status, 200);
  assert.ok(Date.now() - t0 < 8000, `took ${Date.now() - t0} ms`);
  assert.equal((await app.post('/api/tester/run', { case: 'good' })).status, 200);
});

test('http.js: a response is capped at 64 KiB (or maxBytes) and marked truncated', async (t) => {
  const port = await freeBase('misc', 1);
  const srv = await listen((_req, res) => { res.writeHead(200); res.end('x'.repeat(200000)); }, port); t.after(() => stop(srv));
  const big = await loopbackRequest(`http://127.0.0.1:${port}/`);
  assert.equal(big.truncated, true);
  assert.ok(big.text.length > 0 && big.text.length <= 65536, `kept ${big.text.length}`);
  const small = await loopbackRequest(`http://127.0.0.1:${port}/`, { maxBytes: 100 });
  assert.equal(small.truncated, true);
  assert.ok(small.text.length <= 100);
  const okPort = await freeBase('misc', 1);
  const ok = await listen((_req, res) => res.end('hi'), okPort); t.after(() => stop(ok));
  const fine = await loopbackRequest(`http://127.0.0.1:${okPort}/`);
  assert.deepEqual([fine.truncated, fine.text], [false, 'hi']);
});

test('http.js: "localhost" is connected as 127.0.0.1 and brackets are stripped', () => {
  assert.equal(connectHostname('localhost'), '127.0.0.1');
  assert.equal(connectHostname('[::1]'), '::1');
  assert.equal(connectHostname('127.0.0.5'), '127.0.0.5');
});

// ---------- bind to loopback ----------
test('every listener (API, resource stub, five authorization-server stubs) is bound to 127.0.0.1, not a wildcard', async (t) => {
  assert.equal(bindHost({}), '127.0.0.1');
  const app = await startTestApp('safety'); t.after(app.close);
  const rt = app.runtime;
  const hosts = [rt.rs.host, ...Object.values(rt.authServers).map((s) => s.host)];
  assert.equal(hosts.length, 6);
  assert.deepEqual([...new Set(hosts)], ['127.0.0.1']);
  const api = await startHttpServer({ port: await freeBase('safety', 1), stubBase: await freeBase('safety', 7) }); t.after(api.close);
  assert.equal(api.host, '127.0.0.1');
  // and from the outside: no non-loopback address of this machine reaches any of the ports
  const external = Object.values(os.networkInterfaces()).flat().filter((i) => i && i.family === 'IPv4' && !i.internal).map((i) => i.address);
  for (const ip of external) {
    for (const port of [app.port, ...rt.ports]) {
      const reached = await new Promise((resolve) => { const s = net.connect({ host: ip, port, timeout: 1500 }, () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); s.on('timeout', () => { s.destroy(); resolve(false); }); });
      assert.equal(reached, false, `${ip}:${port} must not accept connections`);
    }
  }
});

// ---------- Host guard ----------
test('parseHost: anchored at both ends, port 1-65535', () => {
  for (const h of ['x.localhost', 'evil.com.localhost', 'foo.127.0.0.1', 'x.127.0.0.1:5910', 'a[::1]', 'localhost:0', '127.0.0.1:0', '127.0.0.1:65536', 'localhost.', '']) assert.equal(parseHost(h), null, h);
  for (const h of ['localhost', 'LOCALHOST:5910', '127.0.0.1:1', '127.9.9.9:65535', '[::1]:5910']) assert.notEqual(parseHost(h), null, h);
});

test('Host guard: a duplicate Host header and an absolute-form request target are refused', async (t) => {
  const app = await startTestApp('safety'); t.after(app.close);
  assert.match(await raw(app.port, `GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: evil.example.com\r\nConnection: close\r\n\r\n`), /^HTTP\/1\.1 421/);
  assert.match(await raw(app.port, `GET http://evil.example.com/api/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`), /^HTTP\/1\.1 421/);
  assert.match(await raw(app.port, `GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`), /^HTTP\/1\.1 200/);
});

test('the stub resource server and every stub authorization server refuse a non-loopback Host (421)', async (t) => {
  const app = await startTestApp('safety'); t.after(app.close);
  const rt = app.runtime;
  const targets = [[rt.rs.port, 'POST', '/mcp'], [rt.rs.port, 'GET', '/issuer/.well-known/jwks.json'], ...Object.values(rt.authServers).map((s) => [s.port, 'GET', '/authorize'])];
  for (const [port, method, p] of targets) {
    for (const host of ['evil.example.com', `evil.example.com:${port}`, 'x.localhost']) {
      const r = await request(port, method, p, { host, body: method === 'POST' ? {} : undefined });
      assert.equal(r.status, 421, `${port} ${p} ${host}`);
    }
    assert.notEqual((await request(port, method, p, { host: `127.0.0.1:${port}`, body: method === 'POST' ? {} : undefined })).status, 421, `${port} ${p} with a loopback Host`);
  }
});

test('chunked bodies are held to the JSON-only rule too (415)', async (t) => {
  const app = await startTestApp('safety'); t.after(app.close);
  const head = (ct) => `POST /api/decode HTTP/1.1\r\nHost: 127.0.0.1:${app.port}\r\nContent-Type: ${ct}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n`;
  assert.match(await raw(app.port, `${head('text/plain')}5\r\nhello\r\n0\r\n\r\n`), /^HTTP\/1\.1 415/);
  assert.match(await raw(app.port, `${head('application/json')}5\r\nhello\r\n0\r\n\r\n`), /^HTTP\/1\.1 400/);
});

// ---------- validator ----------
const { validateToken } = await import('../src/validator.js');
const { createKeyring } = await import('../src/keys.js');
{
  const ISS = 'http://127.0.0.1:1/issuer'; const AUD = 'http://127.0.0.1:1/mcp';
  const keyring = createKeyring({ issuer: ISS }); const NOW = 1_800_000_000;
  const policy = { issuer: ISS, audience: AUD, requiredScope: 'mcp:tools', requireActor: true, jwks: () => keyring.jwks(), now: () => NOW };
  const good = (over = {}) => ({ iss: ISS, sub: 'u', aud: AUD, scope: 'mcp:tools', act: { sub: 'a' }, iat: NOW, exp: NOW + 300, ...over });
  const run = (over) => validateToken(keyring.sign({}, good(over)), policy);

  test('validator: scope is matched as a whole token, never as a substring, and must be a string', () => {
    for (const scope of ['mcp:tools-admin', 'xmcp:tools', 'mcp:toolsmcp:tools', 'mcp:read mcp:tools-x', ['mcp:tools'], undefined]) assert.equal(run({ scope }).failed_check, 'scope', JSON.stringify(scope));
    assert.equal(run({ scope: 'mcp:read   mcp:tools' }).ok, true);
  });
  test('validator: audience is matched exactly, never as a substring', () => {
    for (const aud of [`${AUD}-evil`, `evil${AUD}`, [`${AUD}-evil`], AUD.slice(0, -1)]) assert.equal(run({ aud }).failed_check, 'aud', JSON.stringify(aud));
    assert.equal(run({ aud: AUD }).ok, true);
  });
  test('validator: the 5 s leeway boundaries are exact', () => {
    assert.equal(run({ exp: NOW - 5 }).failed_check, 'exp');
    assert.equal(run({ exp: NOW - 4 }).ok, true);
    assert.equal(run({ nbf: NOW + 5 }).ok, true);
    assert.equal(run({ nbf: NOW + 6 }).failed_check, 'nbf');
  });
}

// ---------- jwt.js ----------
const padded = (n) => `${b64uJson({ alg: 'ES256' })}.${b64uJson({ pad: 'x'.repeat(n) })}.AAAA`;
test('jwt: the length cap is exactly MAX_TOKEN_CHARS and applies to otherwise valid tokens', () => {
  assert.equal(MAX_TOKEN_CHARS, 8192);
  let n = 6000; while (padded(n + 1).length <= MAX_TOKEN_CHARS) n += 1;
  assert.equal(parseJwt(padded(n)).ok, true);
  const over = parseJwt(padded(n + 1));
  assert.equal(over.ok, false);
  assert.match(over.reason, /longer than 8192/);
  assert.equal(parseJwt(padded(9000)).ok, false);
});
test('jwt: only base64url characters and dots are accepted', () => {
  const [h, p, s] = padded(3).split('.');
  assert.equal(parseJwt(`${h}.${p}.${s}`).ok, true);
  for (const t of [`${h}.${p}=.${s}`, `${h}.${p.slice(0, 4)} ${p.slice(4)}.${s}`, `${h}.${p.slice(0, 4)}\n${p.slice(4)}.${s}`, `${h}.${p}.${s}+`, `${h}!.${p}.${s}`, `${h}/.${p}.${s}`]) {
    const r = parseJwt(t);
    assert.equal(r.ok, false, JSON.stringify(t));
    assert.match(r.reason, /base64url/);
  }
});
test('jwt: signature verification fails closed on a bad key, a bad signature and garbage', () => {
  const ring = createKeyring({ issuer: 'http://127.0.0.1:1/i' });
  const tok = ring.sign({}, { a: 1 }); const [h, p, s] = tok.split('.');
  const jwk = ring.jwks().keys[0];
  assert.equal(verifyEs256(`${h}.${p}`, s, jwk), true);
  assert.equal(verifyEs256(`${h}.${p}`, s.replace(/.$/, s.endsWith('A') ? 'B' : 'A'), jwk), false);
  assert.equal(verifyEs256(`${h}.${p}`, s, { kty: 'EC', crv: 'P-256', x: 'bad', y: 'bad' }), false);
  assert.equal(verifyEs256(`${h}.${p}`, s, null), false);
  assert.equal(verifyEs256(`${h}.${p}`, '!!', jwk), false);
});

// ---------- sanitize ----------
test('sanitize: control characters are revealed, newlines and tabs are kept, length is capped', () => {
  assert.equal(revealText('a\u0001b\u007fc\u0085d'), 'a[U+0001]b[U+007F]c[U+0085]d');
  assert.equal(revealText('a\nb\tc'), 'a\nb\tc');
  assert.equal(revealText('a\u202eb'), 'a[U+202E]b');
  assert.equal(revealText('x'.repeat(30), 10), `${'x'.repeat(10)}…`);
});
test('sanitize: inertValue bounds depth (6), arrays (100), keys (50), key length (128) and reveals keys', () => {
  const nest = (n, leaf) => (n === 0 ? leaf : { a: nest(n - 1, leaf) });
  const walk = (v, n) => (n === 0 ? v : walk(v.a, n - 1));
  assert.equal(walk(inertValue(nest(6, 'leaf')), 6), 'leaf');
  assert.equal(walk(inertValue(nest(7, 'leaf')), 6), '[truncated]');
  assert.equal(inertValue(Array.from({ length: 150 }, (_, i) => i)).length, 100);
  assert.equal(Object.keys(inertValue(Object.fromEntries(Array.from({ length: 80 }, (_, i) => [`k${i}`, i])))).length, 50);
  assert.deepEqual(Object.keys(inertValue({ 'a\u202eb': 1 })), ['a[U+202E]b']);
  assert.equal(Object.keys(inertValue({ ['k'.repeat(200)]: 1 }))[0].length, 129);
  assert.equal(inertValue(undefined), undefined);
  assert.equal(inertValue('a\u0001'), 'a[U+0001]');
});

// ---------- tester verdict, against a fake resource server ----------
async function fakeCtx(t) {
  const base = await freeBase('misc', 8);
  const rt = await createRuntime({ stubBase: base + 1 }); t.after(() => rt.close());
  const state = { answer: null };
  const srv = await listen((req, res) => { req.resume(); state.answer(res); }, base + 7); t.after(() => stop(srv));
  return { ctx: { ...rt.testerCtx, rsUrl: `http://127.0.0.1:${base + 7}/mcp` }, set: (a) => { state.answer = a; } };
}
const answer = (status, headers, body) => (res) => { res.writeHead(status, { 'content-type': 'application/json', ...headers }); res.end(JSON.stringify(body)); };
const WWW = 'Bearer error="invalid_token"';
const AUD_OK = { error: 'invalid_token', error_description: 'x', failed_check: 'aud', checks: [] };

test('tester verdict: pass only when status, body error, WWW-Authenticate error, failed check and the 401 challenge all match', async (t) => {
  const f = await fakeCtx(t);
  const verdict = async (st, headers, body) => { f.set(answer(st, headers, body)); return (await runCase('wrong-audience', f.ctx)).pass; };
  assert.equal(await verdict(401, { 'www-authenticate': WWW }, AUD_OK), true);
  assert.equal(await verdict(403, { 'www-authenticate': WWW }, AUD_OK), false, 'wrong status');
  assert.equal(await verdict(401, { 'www-authenticate': WWW }, { ...AUD_OK, error: 'invalid_request' }), false, 'wrong body error');
  assert.equal(await verdict(401, { 'www-authenticate': 'Bearer error="invalid_request"' }, AUD_OK), false, 'wrong header error');
  assert.equal(await verdict(401, { 'www-authenticate': 'Bearer realm="x"' }, AUD_OK), false, 'no header error');
  assert.equal(await verdict(401, { 'www-authenticate': WWW }, { ...AUD_OK, failed_check: 'exp' }), false, 'rejected by the wrong check');
  assert.equal(await verdict(401, {}, AUD_OK), false, 'a 401 without a WWW-Authenticate challenge');
  // the no-token case expects a bare 401 challenge and names no error code
  const none = async (headers) => { f.set(answer(401, headers, { failed_check: 'missing' })); return (await runCase('no-token', f.ctx)).pass; };
  assert.equal(await none({ 'www-authenticate': 'Bearer realm="x"' }), true);
  assert.equal(await none({}), false);
});

test('tester: every string taken from the resource server is made inert before it is returned', async (t) => {
  const evil = 'a\u202eb\u0001c';
  const f = await fakeCtx(t);
  f.set(answer(401, { 'www-authenticate': `Bearer error="invalid_token", d="x\u0085y"` }, { error: 'invalid_token', error_description: evil, failed_check: 'au\u202ed', checks: [{ id: evil, label: evil, pass: false }] }));
  const r = await runCase('wrong-audience', f.ctx);
  const text = JSON.stringify(r.actual);
  assert.match(r.actual.wwwAuthenticate, /\[U\+0085\]/);
  assert.match(r.actual.error_description, /a\[U\+202E\]b\[U\+0001\]c/);
  assert.match(r.actual.failed_check, /\[U\+202E\]/);
  assert.doesNotMatch(text, /[\u202e\u0001\u0085]/);
  assert.equal(r.pass, false);
});

// ---------- API: prototype keys, body shape, headers, errors ----------
test('hostile object-prototype names are a 400, never a 500 and never a signed token', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  for (const sample of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf']) {
    const r = await app.post('/api/mint', { sample });
    assert.equal(r.status, 400, sample);
    assert.equal(r.json.error, 'bad_request');
    assert.equal(r.json.token, undefined);
  }
  assert.equal((await app.post('/api/mint', '{"sample":{"toString":1}}')).status, 400);
  for (const profile of ['constructor', '__proto__', 'hasOwnProperty', 'toString']) {
    const r = await app.post('/api/checker/run', { profile });
    assert.equal(r.status, 400, profile);
    assert.equal(r.json.error, 'bad_request', `${profile}: a profile-id error, not a misleading target_refused`);
    assert.match(r.json.message, /profile must be one of/);
  }
});

test('a body must be a plain JSON object with only the listed fields', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  const arr = await app.post('/api/mint', []);
  assert.equal(arr.status, 400);
  assert.match(arr.json.message, /must be a JSON object/);
  assert.equal((await app.post('/api/mint', ['agent'])).status, 400);
  assert.equal((await app.post('/api/mint', 'null')).status, 400);
  const extra = await app.post('/api/mint', { sample: 'agent', password: 'x' });
  assert.equal(extra.status, 400);
  assert.match(extra.json.message, /unexpected field/);
  assert.equal(extra.json.token, undefined);
  assert.equal((await app.post('/api/mint', { sample: 'agent' })).status, 200);
});

test('a broken JSON body is a 400 with its own message; an oversized body is a 413', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  const broken = await app.post('/api/decode', '{"token":');
  assert.equal(broken.status, 400);
  assert.equal(broken.json.message, 'request body is not valid JSON');
  assert.equal((await app.post('/api/decode', { token: 'x'.repeat(20000) })).status, 413);
});

test('response headers: no-store, no-referrer, nosniff and a locked-down CSP on the API; the exact UI_CSP on the UI', async (t) => {
  const dist = fs.mkdtempSync(path.join(os.tmpdir(), 'tw-dist-')); t.after(() => { try { fs.chmodSync(path.join(dist, 'locked'), 0o700); } catch { /* absent */ } fs.rmSync(dist, { recursive: true, force: true }); });
  fs.writeFileSync(path.join(dist, 'index.html'), '<!doctype html><title>ui</title>');
  const app = await startTestApp('ui', { webDist: dist }); t.after(app.close);
  for (const p of ['/api/health', '/api/meta', '/api/nothing', '/']) {
    const h = (await app.get(p)).headers;
    assert.equal(h['cache-control'], 'no-store', p);
    assert.equal(h['referrer-policy'], 'no-referrer', p);
    assert.equal(h['x-content-type-options'], 'nosniff', p);
    assert.equal(h['x-powered-by'], undefined);
  }
  assert.equal((await app.get('/api/meta')).headers['content-security-policy'], "default-src 'none'");
  const csp = (await app.get('/')).headers['content-security-policy'];
  assert.equal(csp, UI_CSP);
  for (const d of ["object-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'", "default-src 'self'"]) assert.ok(csp.includes(d), d);
});

test('the outer error handler answers 500 {error:"server_error"} and leaks no path, message or stack', async (t) => {
  if (process.getuid?.() === 0) return t.skip('root can read an unreadable directory');
  const dist = fs.mkdtempSync(path.join(os.tmpdir(), 'tw-dist-')); t.after(() => { try { fs.chmodSync(path.join(dist, 'locked'), 0o700); } catch { /* absent */ } fs.rmSync(dist, { recursive: true, force: true }); });
  fs.writeFileSync(path.join(dist, 'index.html'), '<!doctype html><title>ui</title>');
  fs.mkdirSync(path.join(dist, 'locked')); fs.chmodSync(path.join(dist, 'locked'), 0o000);
  const app = await startTestApp('ui', { webDist: dist }); t.after(app.close);
  const r = await app.get('/locked/x');
  assert.equal(r.status, 500);
  assert.deepEqual(r.json, { error: 'server_error' });
  assert.doesNotMatch(r.raw, /EACCES|locked|tw-dist|\bat \w|node_modules/);
});

test('health: only GET is allowed (405 for POST), and a doctor bind failure is reported as a failure', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  const r = await app.post('/api/health', {});
  assert.equal(r.status, 405);
  assert.equal(r.headers.allow, 'GET');
  const env = { get TW_BIND() { throw new Error('bind check exploded'); } };
  const bind = runChecks({ env }).find((c) => c.id === 'bind');
  assert.equal(bind.level, 'fail');
  assert.match(bind.detail, /exploded/);
});

// ---------- queue and store caps ----------
test('the run queue: one runs, one waits, the third is refused, and it drains', async (t) => {
  const base = await freeBase('misc', 8);
  const rt = await createRuntime({ stubBase: base + 1 }); t.after(() => rt.close());
  let release; const gate = new Promise((r) => { release = r; });
  const a = rt.enqueue(() => gate); const b = rt.enqueue(async () => 'b');
  await assert.rejects(rt.enqueue(async () => 'c'), (e) => e.code === 'run_queue_full');
  release('a'); assert.deepEqual([await a, await b], ['a', 'b']);
  assert.equal(await rt.enqueue(async () => 'd'), 'd');
});

test('stub authorization server: the code store holds 500 entries, oldest evicted first', { timeout: 30000 }, async (t) => {
  const app = await startTestApp('misc'); t.after(app.close);
  const port = app.runtime.authServers['no-pkce'].port;
  const q = 'response_type=code&client_id=demo-client&redirect_uri=' + encodeURIComponent('https://client.example/cb');
  const codes = [];
  for (let i = 0; i < 501; i += 1) { const r = await request(port, 'GET', `/authorize?${q}`); codes.push(new URL(r.headers.location).searchParams.get('code')); }
  const exch = (code) => request(port, 'POST', '/token', { headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code, client_id: 'demo-client', redirect_uri: 'https://client.example/cb' }).toString() });
  assert.equal((await exch(codes[0])).json.error, 'invalid_grant', 'the oldest code was evicted');
  assert.equal((await exch(codes[500])).status, 200, 'the newest is kept');
  assert.equal((await exch(codes[1])).status, 200, 'the second oldest is still there');
});

test('stub servers cap request bodies at 4 KiB', async (t) => {
  const app = await startTestApp('misc'); t.after(app.close);
  const big = 'x'.repeat(5000);
  const rs = await request(app.runtime.rs.port, 'POST', '/mcp', { body: { pad: big } });
  assert.equal(rs.json.error, 'bad_request');
  assert.equal((await request(app.runtime.rs.port, 'POST', '/mcp', { body: { pad: 'x'.repeat(100) } })).json.error, 'invalid_request', 'a small body reaches the handler');
  const as = (body) => request(app.runtime.authServers.good.port, 'POST', '/token', { headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  assert.equal((await as(`grant_type=password&pad=${big}`)).json.error, 'bad_request');
  assert.equal((await as('grant_type=password')).json.error, 'unsupported_grant_type');
});

// ---------- decode shows every claim; BCP honesty ----------
test('decode lists claims the workbench does not know, with inert names and values', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  const tok = `${b64uJson({ alg: 'none' })}.${b64uJson({ iss: 'i', sub: 's', name: 'Ada', 'we\u202eird': 'v\u0001' })}.`;
  const r = await app.post('/api/decode', { token: tok });
  const names = r.json.claims.map((c) => c.name);
  assert.ok(names.includes('name'));
  assert.ok(names.includes('we[U+202E]ird'));
  assert.equal(r.json.claims.find((c) => c.name === 'name').value, 'Ada');
  assert.equal(r.json.claims.find((c) => c.name === 'we[U+202E]ird').value, 'v[U+0001]');
});

test('the RFC 9700 pack cites RFC numbers only (section numbers were not verified) and says so', async (t) => {
  assert.ok(BCP_RULES.length > 0);
  for (const r of BCP_RULES) assert.doesNotMatch(r.rfc, /\d\.\d/, `${r.id}: ${r.rfc}`);
  const app = await startTestApp('api'); t.after(app.close);
  assert.match((await app.get('/api/meta')).json.rules.bcpNote, /not section numbers/);
  const run = (await app.post('/api/checker/run', { profile: 'good', pack: 'bcp' })).json;
  assert.match(run.packs.bcp.note, /section numbers/);
});
