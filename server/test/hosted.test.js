// Rule 18: the hosted, simulated build (MODE=se-mock). Isolation per workspace, refusal of live features, the banner.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, startTestApp } from './helpers.js';
import { createWorkspaces } from '../src/workspaces.js';
import { runChecks } from '../src/doctor.js';
import { startHttpServer } from '../src/app.js';
import { loopbackRequest } from '../src/http.js';

const PUBLIC = 'https://workbench.example';
const SE = { MODE: 'se-mock', TW_PUBLIC_ORIGIN: PUBLIC };
const seEnv = (extra = {}) => ({ ...process.env, ...SE, ...extra });
const ws = (id) => ({ headers: { 'x-workspace-id': id } });
const hosted = (t, opts = {}) => startTestApp('misc', { env: seEnv(), ...opts }).then((a) => { t.after(a.close); return a; });

test('local mode: no banner, no mode in health, and the workspace header is ignored (one runtime)', async (t) => {
  const app = await startTestApp('misc'); t.after(app.close);
  const meta = (await app.get('/api/meta')).json;
  assert.equal(meta.deployMode, 'local'); assert.equal(meta.hosted, false); assert.equal(meta.banner, null);
  const h = (await app.get('/api/health')).json;
  assert.equal(h.mode, undefined);
  const other = (await app.get('/api/meta', ws('someone-else'))).json;
  assert.equal(other.issuer, meta.issuer, 'same runtime');
  assert.equal(other.workspace, 'default');
  assert.equal((await app.get('/api/meta', ws('Not Valid!!'))).status, 200, 'ignored, not validated, in local mode');
  assert.equal(app.runtime.ports.length, 6);
});

test('se-mock: health stays demo-health/1 and carries the mode; meta serves the hosted-and-simulated banner', async (t) => {
  const app = await hosted(t);
  const h = (await app.get('/api/health')).json;
  assert.equal(h.schema, 'demo-health/1'); assert.equal(h.state, 'ready'); assert.equal(h.runtime, 'offline'); assert.equal(h.mode, 'se-mock');
  const m = (await app.get('/api/meta')).json;
  assert.equal(m.deployMode, 'se-mock'); assert.equal(m.hosted, true); assert.equal(m.workspace, 'default');
  assert.match(m.banner, /^HOSTED SIMULATION/); assert.match(m.banner, /Nothing real is contacted/);
});

test('isolation: keys, tokens, resource server, stub code stores and results of one workspace are invisible to another', async (t) => {
  const app = await hosted(t);
  const A = ws('visitor-a'); const B = ws('visitor-b');
  const [ma, mb, md] = await Promise.all([app.get('/api/meta', A), app.get('/api/meta', B), app.get('/api/meta')]);
  assert.equal(new Set([ma.json.issuer, mb.json.issuer, md.json.issuer]).size, 3, 'three issuers');
  assert.equal(new Set([...ma.json.ports, ...mb.json.ports, ...md.json.ports]).size, 18, 'no shared stub port');
  assert.notDeepEqual((await app.get('/api/jwks', A)).json, (await app.get('/api/jwks', B)).json);

  // A token minted in A verifies in A only, and A's resource server is not B's.
  const tokenA = (await app.post('/api/mint', { sample: 'agent' }, A)).json.token;
  assert.equal((await app.post('/api/decode', { token: tokenA, verify: true }, A)).json.signature.state, 'valid_stub_jwks');
  assert.equal((await app.post('/api/decode', { token: tokenA, verify: true }, B)).json.signature.state, 'invalid');
  assert.equal((await app.post('/api/decode', { token: tokenA, verify: true })).json.signature.state, 'invalid');
  const rsB = mb.json.ports[5];
  const call = (port, token) => loopbackRequest(`http://127.0.0.1:${port}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' });
  assert.equal((await call(ma.json.ports[5], tokenA)).status, 200, 'A\'s own resource server accepts it');
  assert.equal((await call(rsB, tokenA)).status, 401, 'B refuses A\'s token');

  // An authorization code issued by A's stub is unknown to B's stub.
  const q = new URLSearchParams({ response_type: 'code', client_id: 'demo-client', redirect_uri: 'https://client.example/cb', state: 's' }).toString();
  const authz = (m) => loopbackRequest(`${m.json.profiles[3].url}/authorize?${q}`);
  const red = await authz(ma);
  const code = new URL(red.headers.location).searchParams.get('code');
  assert.ok(code);
  const exchange = (m) => loopbackRequest(`${m.json.profiles[3].url}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code, client_id: 'demo-client', redirect_uri: 'https://client.example/cb' }).toString() });
  assert.equal(JSON.parse((await exchange(mb)).text).error, 'invalid_grant', 'B does not know the code');
  assert.equal((await exchange(ma)).status, 200, 'A does');

  // Runs and results are per workspace and work inside the process (stubs on loopback).
  const runA = (await app.post('/api/tester/run', { case: 'all' }, A)).json;
  assert.equal(runA.summary.passed, 15); assert.equal(runA.resource, ma.json.resource);
  const runB = (await app.post('/api/checker/run', { profile: 'loose-redirect' }, B)).json;
  assert.equal(runB.profile, 'loose-redirect');
  assert.ok(!JSON.stringify(runB).includes(`127.0.0.1:${ma.json.ports[1]}`), 'B\'s result never mentions A\'s stub');
  assert.ok(!JSON.stringify(runA).includes(`127.0.0.1:${mb.json.ports[5]}`), 'A\'s result never mentions B\'s resource server');
});

test('the run queue is per workspace: a busy workspace does not block or 429 another', async (t) => {
  const app = await hosted(t);
  const A = ws('queue-a'); const B = ws('queue-b');
  const first = [1, 2, 3, 4].map(() => app.post('/api/tester/run', { case: 'all' }, A));
  const other = await app.post('/api/tester/run', { case: 'good' }, B);
  assert.equal(other.status, 200);
  const codes = (await Promise.all(first)).map((r) => r.status).sort();
  assert.ok(codes.includes(429), 'A\'s own third run is refused');
  assert.ok(!codes.every((c) => c === 429));
});

test('hostile workspace ids are rejected with 400 and create nothing', async (t) => {
  const app = await hosted(t);
    const sizeBefore = (await request(app.port, 'GET', '/api/meta', ws('ok-one'))).status;
  assert.equal(sizeBefore, 200);
  const hostile = ['', ' ', 'A', 'UPPER', '-lead', '../etc/passwd', 'a/b', 'a b', 'a.b', 'a_b', 'a;b', 'a,b', 'a'.repeat(33), 'default\u0000x', 'é', '__proto__', 'a%2e', '<script>', 'x\ty'];
  for (const id of hostile) {
    try {
      const r = await request(app.port, 'GET', '/api/meta', ws(id));
      assert.equal(r.status, 400, JSON.stringify(id));
    } catch (e) { assert.match(String(e.code || e.message), /ERR_INVALID_CHAR|Invalid character|invalid/i, JSON.stringify(id)); } // the client itself refused to send it
  }
  const dup = await request(app.port, 'GET', '/api/meta', { headers: { 'x-workspace-id': ['aa', 'bb'] } });
  assert.equal(dup.status, 400, 'two ids in one request');
  const post = await app.post('/api/mint', { sample: 'user' }, ws('Bad Id'));
  assert.equal(post.status, 400);
  assert.equal(await sizeOf(app), 2, 'only default and ok-one exist');
  assert.equal((await app.get('/api/meta', ws('a'.repeat(32)))).status, 200, '32 characters is the limit');
});
const sizeOf = async (app) => app.workspaces.size;

test('cap and eviction over HTTP: past the cap the least recently used idle workspace is dropped and its listeners closed; default is never evicted', async (t) => {
  const app = await hosted(t, { workspaceOptions: { max: 3 } });
  const meta = (id) => app.get('/api/meta', ws(id)).then((r) => r.json);
  const a = await meta('ws-a'); const b = await meta('ws-b');
  assert.equal(app.workspaces.size, 3);
  await meta('ws-a'); // touch a: b is now the least recently used
  const c = await meta('ws-c');
  assert.equal(app.workspaces.size, 3);
  assert.deepEqual(app.workspaces.ids().sort(), ['default', 'ws-a', 'ws-c']);
  await assert.rejects(call(b.ports[5]), /ECONNREFUSED|request_failed/, 'evicted workspace listeners are closed');
  assert.equal((await call(a.ports[5])).status, 401, 'a is alive');
  const b2 = await meta('ws-b'); // comes back as a NEW workspace
  assert.notEqual(b2.issuer, b.issuer); assert.ok(c.issuer);
  assert.ok(app.workspaces.ids().includes('default'));
  const keyA1 = (await app.get('/api/jwks', ws('ws-a'))).json.keys[0].kid;
  assert.ok(keyA1);
  async function call(port) { return loopbackRequest(`http://127.0.0.1:${port}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }); }
});

test('cap over HTTP: when every other workspace is busy the request is refused with 503, not queued', async (t) => {
  const app = await hosted(t, { workspaceOptions: { max: 2 } });
  await app.get('/api/meta', ws('busy-a'));
  const running = app.post('/api/tester/run', { case: 'all' }, ws('busy-a'));
  await new Promise((r) => { setTimeout(r, 5); }); // let the run start
  const r = await app.get('/api/meta', ws('newcomer'));
  if (r.status === 200) { await running; return t.skip('the run finished before the newcomer arrived (machine too fast)'); }
  assert.equal(r.status, 503); assert.equal(r.json.error, 'workspace_cap'); assert.ok(r.headers['retry-after']);
  await running;
});

test('registry unit: cap, LRU order, TTL sweep, busy workspaces are kept, default is pinned, concurrent first use makes one runtime', async () => {
  let t = 1000; let made = 0; const closed = [];
  const mk = (busy = false) => { made += 1; const id = made; return { id, busy: () => busy, close: async () => { closed.push(id); } }; };
  const def = { id: 'def', close: async () => closed.push('def') };
  const reg = createWorkspaces({ defaultRuntime: def, create: () => mk(), max: 3, ttlMs: 100, now: () => t, sweepMs: 1e9 });
  const [r1, r2] = await Promise.all([reg.get('x'), reg.get('x')]);
  assert.equal(r1, r2); assert.equal(made, 1);
  assert.equal(await reg.get('default'), def);
  await reg.get('y'); t += 10;
  await reg.get('z'); // cap 3: default + y + z... x evicted (least recently used)
  assert.deepEqual(reg.ids().sort(), ['default', 'y', 'z']); assert.deepEqual(closed, [1]);
  t += 1000; reg.sweep(); await new Promise((r) => { setImmediate(r); });
  assert.deepEqual(reg.ids(), ['default'], 'TTL: idle workspaces dropped, default kept');
  assert.equal(closed.length, 3);
  // busy workspaces survive the TTL and block eviction
  const busyReg = createWorkspaces({ defaultRuntime: def, create: () => mk(true), max: 2, ttlMs: 100, now: () => t, sweepMs: 1e9 });
  await busyReg.get('b1'); t += 1000; busyReg.sweep();
  assert.deepEqual(busyReg.ids(), ['default', 'b1']);
  await assert.rejects(busyReg.get('b2'), (e) => e.code === 'workspace_cap');
  // a failed create leaves nothing behind
  const failing = createWorkspaces({ defaultRuntime: def, create: async () => { throw new Error('no ports'); }, max: 2, now: () => t, sweepMs: 1e9 });
  await assert.rejects(failing.get('f'), /no ports/);
  await new Promise((r) => { setImmediate(r); });
  assert.deepEqual(failing.ids(), ['default']);
  await reg.closeAll(); await busyReg.closeAll(); await failing.closeAll();
});

test('se-mock refuses a user-typed checker target, even a loopback one; stub profiles still work', async (t) => {
  const app = await hosted(t);
  const own = (await app.get('/api/meta')).json.profiles[0].url;
  for (const target of [own, 'http://127.0.0.1:1/', 'http://localhost:9/', 'https://evil.example/']) {
    const r = await app.post('/api/checker/run', { target });
    assert.equal(r.status, 400, target); assert.equal(r.json.error, 'target_refused'); assert.equal(r.json.reason, 'hosted_build');
    assert.match(r.json.message, /hosted demo/);
  }
  assert.equal((await app.post('/api/checker/run', { profile: 'good', pack: 'bcp' })).status, 200);
});

test('se-mock origin: the configured https origin is accepted behind the ingress; any other origin, and cross-site, is refused', async (t) => {
  const app = await hosted(t);
  const post = (headers) => app.post('/api/mint', { sample: 'user' }, { headers });
  assert.equal((await post({ origin: PUBLIC })).status, 200);
  assert.equal((await post({ origin: 'https://other.example' })).status, 403);
  assert.equal((await post({ origin: 'http://workbench.example' })).status, 403);
  assert.equal((await post({ origin: PUBLIC, 'sec-fetch-site': 'cross-site' })).status, 403);
  const local = await startTestApp('misc'); t.after(local.close);
  assert.equal((await local.post('/api/mint', { sample: 'user' }, { headers: { origin: PUBLIC } })).status, 403, 'local mode accepts loopback origins only');
});

test('se-mock refuses live flags and a bad MODE or origin: doctor fails and startup throws', async () => {
  for (const flag of ['TW_LIVE', 'TW_ALLOW_REMOTE', 'TW_ALLOW_TARGETS', 'TW_CHECKER_TARGETS', 'LIVE']) {
    const env = { ...SE, [flag]: '1' };
    const c = runChecks({ env }).find((x) => x.id === 'deploy-mode');
    assert.equal(c.level, 'fail', flag); assert.match(c.detail, new RegExp(flag));
    await assert.rejects(startHttpServer({ port: 0, env, stubBase: 5990 }), /refusing to start.*live features are refused/, flag);
  }
  for (const MODE of ['live', 'prod', 'se-mock ', 'SE-MOCK', 'mock']) {
    assert.equal(runChecks({ env: { MODE } }).find((x) => x.id === 'deploy-mode').level, 'fail', MODE);
    await assert.rejects(startHttpServer({ port: 0, env: { MODE }, stubBase: 5990 }), /MODE=.*not available/);
  }
  for (const TW_PUBLIC_ORIGIN of ['http://x.example', 'https://x.example/path', 'https://u:p@x.example', 'not a url']) {
    assert.equal(runChecks({ env: { ...SE, TW_PUBLIC_ORIGIN } }).find((x) => x.id === 'deploy-mode').level, 'fail', TW_PUBLIC_ORIGIN);
  }
  assert.equal(runChecks({ env: SE }).find((x) => x.id === 'deploy-mode').level, 'pass');
  assert.equal(runChecks({ env: {} }).find((x) => x.id === 'deploy-mode').level, 'pass');
  assert.equal(runChecks({ env: { TW_LIVE: '1' } }).find((x) => x.id === 'deploy-mode').level, 'pass', 'local mode does not consult them');
});

test('registry unit: a workspace still being created is never evicted by a newcomer', async () => {
  const closed = []; let n = 0;
  const def = { close: async () => {} };
  const reg = createWorkspaces({ defaultRuntime: def, max: 2, sweepMs: 1e9,
    create: () => new Promise((res) => { const id = ++n; setTimeout(() => res({ id, busy: () => false, close: async () => { closed.push(id); } }), 30); }) });
  const a = reg.get('a');
  await assert.rejects(reg.get('b'), (e) => e.code === 'workspace_cap');
  assert.equal((await a).id, 1); assert.deepEqual(closed, []); assert.deepEqual(reg.ids(), ['default', 'a']);
  await reg.closeAll();
});
