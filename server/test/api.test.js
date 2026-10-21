import test from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp } from './helpers.js';
import { b64uJson } from '../src/jwt.js';

const mint = async (app, sample) => (await app.post('/api/mint', { sample })).json.token;

test('GET /api/health is demo-health/1 and ready', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  const r = await app.get('/api/health');
  assert.equal(r.status, 200);
  assert.equal(r.json.schema, 'demo-health/1');
  assert.equal(r.json.state, 'ready');
  assert.equal(r.json.runtime, 'offline');
  assert.equal(r.headers['cache-control'], 'no-store');
});

test('decode: a minted agent token is decoded and explained, with the signature not verified by default', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  const token = await mint(app, 'agent');
  const r = await app.post('/api/decode', { token });
  assert.equal(r.status, 200);
  assert.equal(r.json.header.alg, 'ES256');
  assert.equal(r.json.payload.sub, 'user-123');
  assert.equal(r.json.payload.aud, app.runtime.ids.resource);
  assert.equal(r.json.signature.state, 'not_verified');
  assert.match(r.json.signature.note, /anyone can write any claims/);
  const names = r.json.claims.map((c) => c.name);
  for (const n of ['alg', 'kid', 'iss', 'sub', 'aud', 'scope', 'act', 'exp', 'cnf']) assert.ok(names.includes(n), n);
  assert.equal(r.json.time.expired, false);
  assert.ok(r.json.claims.every((c) => c.meaning.length > 10));
});

test('decode with verify: valid only for a stub-signed token; tampered, rogue-key and unknown-kid tokens are invalid', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  const token = await mint(app, 'agent');
  assert.equal((await app.post('/api/decode', { token, verify: true })).json.signature.state, 'valid_stub_jwks');
  const [h, p, s] = token.split('.');
  const edited = `${h}.${b64uJson({ ...JSON.parse(Buffer.from(p, 'base64url')), scope: 'admin' })}.${s}`;
  assert.equal((await app.post('/api/decode', { token: edited, verify: true })).json.signature.state, 'invalid');
  const rogue = app.runtime.keyring.signWithRogueKey({}, { sub: 'x' });
  assert.equal((await app.post('/api/decode', { token: rogue, verify: true })).json.signature.state, 'invalid');
  const unknown = app.runtime.keyring.signWithRogueKey({ kid: 'other' }, { sub: 'x' });
  assert.match((await app.post('/api/decode', { token: unknown, verify: true })).json.signature.note, /not in this app's stub JWKS/);
  const none = `${b64uJson({ alg: 'none' })}.${b64uJson({ sub: 'x' })}.`;
  const d = await app.post('/api/decode', { token: none, verify: true });
  assert.equal(d.json.signature.state, 'invalid');
  assert.equal(d.json.claims.find((c) => c.name === 'alg').level, 'danger');
});

test('decode covers each sample: DPoP and mTLS binding, user vs agent, expired', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  const dec = async (s) => (await app.post('/api/decode', { token: await mint(app, s) })).json;
  assert.ok((await dec('dpop')).claims.some((c) => c.name === 'cnf.jkt'));
  assert.ok((await dec('mtls')).claims.some((c) => c.name === 'cnf.x5t#S256'));
  assert.ok(!(await dec('user')).claims.some((c) => c.name === 'act'));
  const exp = await dec('expired');
  assert.equal(exp.time.expired, true);
  assert.match(exp.claims.find((c) => c.name === 'exp').meaning, /Expired/);
  assert.equal((await app.post('/api/mint', { sample: 'nope' })).status, 400);
});

test('decode: non-JWTs, oversized tokens and extra fields are refused', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  assert.equal((await app.post('/api/decode', { token: 'opaque-token-value' })).json.error, 'not_a_jwt');
  assert.equal((await app.post('/api/decode', { token: 12 })).status, 400);
  assert.equal((await app.post('/api/decode', {})).status, 400);
  assert.equal((await app.post('/api/decode', { token: 'a'.repeat(9000) })).status, 400);
  assert.equal((await app.post('/api/decode', { token: await mint(app, 'user'), verify: 'yes' })).status, 400);
  assert.equal((await app.post('/api/decode', { token: await mint(app, 'user'), client_secret: 'x' })).status, 400);
  assert.equal((await app.post('/api/decode', [1, 2])).status, 400);
  assert.equal((await app.post('/api/decode', 'not json{')).status, 400);
  assert.equal((await app.post('/api/decode', { token: 'a'.repeat(20000) })).status, 413);
});

test('flows: list, compare and run through the API', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  assert.equal((await app.get('/api/flows')).json.mechanisms.length, 6);
  const c = (await app.get('/api/flows/compare')).json;
  assert.equal(c.rows.length, 6);
  const off = (await app.post('/api/flows/run', { mechanism: 'dpop', protected: false })).json;
  const on = (await app.post('/api/flows/run', { mechanism: 'dpop', protected: true })).json;
  assert.equal(off.attack.outcome, 'attack_succeeds');
  assert.equal(on.attack.outcome, 'attack_blocked');
  assert.equal((await app.post('/api/flows/run', { mechanism: 'dpop' })).status, 400);
  assert.equal((await app.post('/api/flows/run', { mechanism: 'nope', protected: true })).status, 400);
});

test('meta lists the profiles, ports and rules; unknown endpoints are JSON 404', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  const m = (await app.get('/api/meta')).json;
  assert.equal(m.mode, 'mock');
  assert.equal(m.profiles.length, 5);
  assert.ok(m.ports.every((p) => p >= 5900 && p <= 5999));
  assert.equal((await app.get('/api/nope')).status, 404);
  assert.equal((await app.get('/nope')).status, 404);
});

test('responses are JSON with nosniff and a locked-down CSP', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  const r = await app.get('/api/flows');
  assert.match(r.headers['content-type'], /application\/json/);
  assert.equal(r.headers['x-content-type-options'], 'nosniff');
  assert.equal(r.headers['content-security-policy'], "default-src 'none'");
  assert.equal(r.headers['x-powered-by'], undefined);
});

test('a third concurrent run gets 429 with Retry-After', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  const results = await Promise.all(Array.from({ length: 8 }, () => app.post('/api/tester/run', { case: 'all' })));
  const codes = results.map((r) => r.status);
  assert.ok(codes.includes(200));
  assert.ok(codes.includes(429), `got ${codes}`);
  assert.equal(results.find((r) => r.status === 429).headers['retry-after'], '2');
  assert.ok(codes.every((c) => c === 200 || c === 429));
  assert.equal((await app.post('/api/tester/run', { case: 'good' })).status, 200, 'the queue drains');
});

test('a 500 never leaks the message or a stack, and never logs the token', async (t) => {
  const app = await startTestApp('api'); t.after(app.close);
  const token = await mint(app, 'agent');
  const logged = [];
  const orig = console.error; console.error = (...a) => logged.push(a.join(' '));
  t.after(() => { console.error = orig; });
  // Force a failure inside a handler that has seen the token: break the keyring.
  const realJwks = app.runtime.keyring.jwks;
  app.runtime.keyring.jwks = () => { throw new Error(`secret-detail ${token}`); };
  const r = await app.post('/api/decode', { token, verify: true });
  app.runtime.keyring.jwks = realJwks;
  assert.equal(r.status, 500);
  assert.deepEqual(r.json, { error: 'server_error' });
  assert.doesNotMatch(r.raw, /secret-detail|at Object|node_modules/);
  assert.ok(logged.length >= 1);
  assert.doesNotMatch(logged.join('\n'), /secret-detail/);
  assert.equal(logged.join('\n').includes(token), false);
});
