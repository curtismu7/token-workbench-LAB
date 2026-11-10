// Real mode (rule 19) against an in-process stub issuer on loopback. Nothing here contacts a real tenant: the app's
// netguard is given a fetch that maps the configured https://idp.example origin to the stub's loopback port and refuses
// every other host. The guardNetwork() helper also blocks and records any non-loopback socket, DNS lookup or fetch.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { startTestApp } from './helpers.js';
import { guardNetwork } from './netguard.js';
import { realConfigFrom, metadataRules } from '../src/real.js';
import { createNetguard, NetguardRefused } from '../src/netguard.js';
import { runChecks } from '../src/doctor.js';

const ISSUER = 'https://idp.example/as';
const CLIENT_ID = 'tw-real-client';
const SECRET = 'S3cret-value_never-shown+/=';
const REAL_ENV = { TW_REAL: '1', TW_REAL_ISSUER: ISSUER, TW_REAL_CLIENT_ID: CLIENT_ID, TW_REAL_CLIENT_SECRET: SECRET, TW_REAL_SCOPE: 'tw:read' };
const b64u = (b) => Buffer.from(b).toString('base64url');
const basic = (id, s) => `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(s)}`).toString('base64')}`;

// A stub authorization server that behaves like a small PingOne/PingFederate: discovery, JWKS (RS256), client_credentials
// and RFC 7662 introspection. `stub.fault` switches on one failure at a time.
async function startStubIssuer() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'stub-rs-1', alg: 'RS256', use: 'sig' };
  const issued = new Set();
  const seen = [];
  const stub = { fault: null, seen, issued, secret: SECRET };
  const sign = (payload) => {
    const input = `${b64u(JSON.stringify({ alg: 'RS256', kid: 'stub-rs-1', typ: 'JWT' }))}.${b64u(JSON.stringify(payload))}`;
    return `${input}.${b64u(crypto.sign('sha256', Buffer.from(input), privateKey))}`;
  };
  stub.sign = sign;
  stub.signAs = (kid, payload) => {
    const input = `${b64u(JSON.stringify({ alg: 'RS256', kid }))}.${b64u(JSON.stringify(payload))}`;
    return `${input}.${b64u(crypto.sign('sha256', Buffer.from(input), privateKey))}`;
  };
  const clientOk = (req, form) => {
    if (stub.fault === 'bad-secret') return false;
    if (req.headers.authorization) return req.headers.authorization === basic(CLIENT_ID, stub.secret);
    return form.get('client_id') === CLIENT_ID && form.get('client_secret') === stub.secret;
  };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const form = new URLSearchParams(body);
      seen.push({ method: req.method, url: req.url, authorization: req.headers.authorization || null, form: Object.fromEntries(form) });
      const json = (status, o, extra = {}) => { res.writeHead(status, { 'content-type': 'application/json', ...extra }); res.end(JSON.stringify(o)); };
      if (req.url === '/as/.well-known/openid-configuration') {
        if (stub.fault === 'redirect') { res.writeHead(302, { location: 'https://elsewhere.example/' }); return res.end(); }
        return json(200, {
          issuer: stub.fault === 'wrong-issuer' ? 'https://other.example/as' : ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: stub.fault === 'evil-endpoint' ? 'https://evil.example/token' : `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/jwks`, introspection_endpoint: `${ISSUER}/introspect`,
          response_types_supported: ['code', 'id_token', 'code id_token'], grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
          code_challenge_methods_supported: ['S256'], pushed_authorization_request_endpoint: `${ISSUER}/par`, dpop_signing_alg_values_supported: ['ES256'],
        });
      }
      if (req.url === '/as/jwks') {
        if (stub.fault === 'huge') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(`{"keys":[],"pad":"${'x'.repeat(600 * 1024)}"}`); }
        return json(200, { keys: [jwk] });
      }
      if (req.url === '/as/token' && req.method === 'POST' && stub.fault === 'echo-all') {
        // The worst issuer: the secret as the error code (it reaches the 502 message) and the raw form body echoed back.
        return json(400, { error: stub.secret.slice(0, 50), error_description: body, json_echo: JSON.stringify(stub.secret) }, { 'www-authenticate': `Basic realm="${req.headers.authorization || ''}"` });
      }
      if (req.url === '/as/introspect' && stub.fault === 'echo-all') return json(200, { active: false, echoed: body });
      if (req.url === '/as/token' && req.method === 'POST') {
        if (!clientOk(req, form)) {
          // A misbehaving server that echoes the credentials it was sent: the lab must scrub them.
          return json(401, { error: 'invalid_client', error_description: `bad client: ${req.headers.authorization || ''} ${form.get('client_secret') || ''} ${SECRET}` });
        }
        const now = Math.floor(Date.now() / 1000);
        const token = sign({ iss: ISSUER, sub: CLIENT_ID, client_id: CLIENT_ID, aud: ['https://api.example'], scope: form.get('scope') || '', iat: now, exp: now + 3600 });
        issued.add(token);
        return json(200, { access_token: token, token_type: 'Bearer', expires_in: 3600 }, { 'cache-control': 'no-store' });
      }
      if (req.url === '/as/introspect' && req.method === 'POST') {
        if (!clientOk(req, form)) return json(401, { error: 'invalid_client' });
        return json(200, issued.has(form.get('token')) ? { active: true, client_id: CLIENT_ID, scope: 'tw:read' } : { active: false });
      }
      return json(404, { error: 'not_found' });
    });
  });
  await new Promise((r) => { server.listen(0, '127.0.0.1', r); });
  stub.port = server.address().port;
  stub.close = () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); });
  return stub;
}

// The fetch the app's netguard calls in Real mode: https://idp.example -> the stub's loopback port; anything else is
// recorded and refused (it must never be reached: the netguard refuses first).
function stubFetch(stub) {
  const calls = []; const foreign = [];
  const f = (url, init) => {
    const u = new URL(url);
    calls.push(url);
    if (u.origin !== 'https://idp.example') { foreign.push(url); return Promise.reject(new Error('foreign host')); }
    return fetch(`http://127.0.0.1:${stub.port}${u.pathname}${u.search}`, init);
  };
  return { fetch: f, calls, foreign };
}

async function realApp(t, env = REAL_ENV) {
  const net = guardNetwork(); t.after(() => net.restore());
  const stub = await startStubIssuer(); t.after(stub.close);
  const rf = stubFetch(stub);
  const app = await startTestApp('misc', { env: { ...process.env, ...env }, realFetch: rf.fetch }); t.after(app.close);
  return { app, stub, rf, net };
}
const noSecret = (raw, label) => {
  for (const v of [SECRET, encodeURIComponent(SECRET), basic(CLIENT_ID, SECRET).slice(6)]) assert.ok(!raw.includes(v), `${label}: the client secret leaked`);
};

test('Real configured: starts in Real, /api/info names the settings but never the secret or client id', async (t) => {
  const { app, net } = await realApp(t);
  const info = await app.get('/api/info');
  assert.equal(info.json.source, 'real'); assert.equal(info.json.realAvailable, true);
  assert.equal(info.json.real.issuer, ISSUER); assert.equal(info.json.real.issuerOrigin, 'https://idp.example');
  assert.deepEqual(info.json.real.missing, []);
  noSecret(info.raw, 'info'); assert.ok(!info.raw.includes(CLIENT_ID), 'client id not shown');
  assert.equal((await app.get('/api/meta')).json.source, 'real');
  assert.deepEqual(net.attempts, []);
});

test('Real mint: a REAL client_credentials token, raw, with a trace of the HTTP exchanges and no secret in it', async (t) => {
  const { app, stub, rf, net } = await realApp(t);
  const r = await app.post('/api/mint', { sample: 'client_credentials' });
  assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.source, 'real'); assert.equal(r.json.label, 'REAL');
  assert.ok(stub.issued.has(r.json.token), 'the raw token the stub issued is returned');
  assert.deepEqual(r.json.trace.map((e) => e.step), ['discovery', 'token (client_credentials)']);
  const tok = r.json.trace[1];
  assert.equal(tok.method, 'POST'); assert.equal(tok.status, 200); assert.equal(tok.url, `${ISSUER}/token`);
  assert.match(tok.request.headers.authorization, /^Basic \[client secret: write-only, not shown\]$/);
  assert.match(tok.request.body, /grant_type=client_credentials/); assert.match(tok.request.body, /scope=tw%3Aread/);
  assert.match(tok.response.body, /access_token/);
  noSecret(r.raw, 'mint');
  assert.equal(stub.seen.find((s) => s.url === '/as/token').authorization, basic(CLIENT_ID, SECRET), 'the stub got the real credentials');
  assert.deepEqual(rf.foreign, []); assert.deepEqual(net.attempts, []);
  // Mock samples are refused in Real (no silent fallback to a stub token).
  assert.equal((await app.post('/api/mint', { sample: 'agent' })).status, 400);
});

test('Real decode verifies against the issuer\'s real JWKS; a tampered token is invalid; introspection asks the issuer', async (t) => {
  const { app, stub, net } = await realApp(t);
  const { token } = (await app.post('/api/mint', { sample: 'client_credentials' })).json;
  const ok = await app.post('/api/decode', { token, verify: true });
  assert.equal(ok.status, 200, ok.raw); assert.equal(ok.json.source, 'real');
  assert.equal(ok.json.signature.state, 'valid_real_jwks'); assert.match(ok.json.signature.note, /iss matches/);
  assert.deepEqual(ok.json.trace.map((e) => e.step), ['discovery', 'jwks']);
  const [h, p, s] = token.split('.');
  const forged = `${h}.${b64u(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url')), scope: 'admin' }))}.${s}`;
  assert.equal((await app.post('/api/decode', { token: forged, verify: true })).json.signature.state, 'invalid');
  const noKid = stub.sign({ iss: ISSUER }).replace(/^[^.]+/, b64u(JSON.stringify({ alg: 'RS256', kid: 'unknown' })));
  assert.equal((await app.post('/api/decode', { token: noKid, verify: true })).json.signature.state, 'invalid');
  // Correctly signed by the issuer's key but naming a kid the JWKS does not have: never verified against another key.
  const otherKid = stub.signAs('unknown', { iss: ISSUER });
  const ok2 = await app.post('/api/decode', { token: otherKid, verify: true });
  assert.equal(ok2.json.signature.state, 'invalid'); assert.match(ok2.json.signature.note, /not in the issuer's JWKS/);
  const hs = `${b64u(JSON.stringify({ alg: 'HS256' }))}.${b64u('{}')}.x`;
  assert.match((await app.post('/api/decode', { token: hs, verify: true })).json.signature.note, /not verified here/);
  const nv = await app.post('/api/decode', { token, verify: false });
  assert.equal(nv.json.signature.state, 'not_verified'); assert.equal(nv.json.trace, undefined);

  const act = await app.post('/api/introspect', { token });
  assert.equal(act.status, 200, act.raw); assert.equal(act.json.source, 'real'); assert.equal(act.json.active, true);
  assert.deepEqual(act.json.trace.map((e) => e.step), ['discovery', 'introspection']);
  assert.equal((await app.post('/api/introspect', { token: forged })).json.active, false);
  noSecret(act.raw, 'introspect');
  assert.deepEqual(net.attempts, []);
});

test('Real checker reads the issuer\'s metadata only; active-probe rules are not_checked; profile and target are refused', async (t) => {
  const { app, stub, net } = await realApp(t);
  const r = await app.post('/api/checker/run', { pack: 'both' });
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.source, 'real'); assert.equal(r.json.target, ISSUER);
  const bcp = Object.fromEntries(r.json.packs.bcp.rules.map((x) => [x.id, x.status]));
  assert.equal(bcp.metadata, 'pass'); assert.equal(bcp['s256-only'], 'pass'); assert.equal(bcp['no-ropc'], 'pass'); assert.equal(bcp['iss-param'], 'fail');
  for (const id of ['exact-redirect', 'pkce-required', 'pkce-downgrade', 'single-use-code']) assert.equal(bcp[id], 'not_checked', id);
  const fapi = Object.fromEntries(r.json.packs.fapi.rules.map((x) => [x.id, x.status]));
  assert.equal(fapi['fapi-par-published'], 'pass'); assert.equal(fapi['fapi-par-required'], 'fail'); assert.equal(fapi['fapi-sender-constrained'], 'pass');
  assert.equal(r.json.packs.bcp.summary.notChecked, 4);
  assert.deepEqual(stub.seen.map((x) => x.url), ['/as/.well-known/openid-configuration'], 'one GET of public metadata, no probes');
  assert.equal((await app.post('/api/checker/run', { profile: 'good' })).status, 400);
  assert.equal((await app.post('/api/checker/run', { target: 'http://127.0.0.1:5999' })).status, 400);
  assert.deepEqual(net.attempts, []);
});

test('metadataRules: plain PKCE, the password grant and implicit are failed from metadata', () => {
  const r = metadataRules({ issuer: ISSUER, authorization_endpoint: 'a', token_endpoint: 't', response_types_supported: ['code', 'token'], grant_types_supported: ['password'], code_challenge_methods_supported: ['plain', 'S256'] }, ISSUER);
  assert.equal(r['s256-only'].status, 'fail'); assert.equal(r['no-ropc'].status, 'fail'); assert.equal(r['no-implicit'].status, 'fail');
  assert.equal(r['fapi-no-implicit-ropc'].status, 'fail'); assert.equal(r['fapi-pkce-s256'].status, 'fail');
  assert.equal(metadataRules({ issuer: 'https://x.example' }, ISSUER).metadata.status, 'fail');
});

test('client_secret_post: the secret goes in the form to the issuer and is shown only as the write-only marker', async (t) => {
  const { app, stub } = await realApp(t, { ...REAL_ENV, TW_REAL_TOKEN_AUTH: 'client_secret_post' });
  const r = await app.post('/api/mint', { sample: 'client_credentials' });
  assert.equal(r.status, 200, r.raw);
  const sent = stub.seen.find((s) => s.url === '/as/token');
  assert.equal(sent.authorization, null); assert.equal(sent.form.client_secret, SECRET);
  assert.match(r.json.trace[1].request.body, /client_secret=%5Bclient\+secret%3A\+write-only%2C\+not\+shown%5D/);
  noSecret(r.raw, 'post');
});

test('Real failures: wrong secret, an issuer that echoes the secret, a wrong issuer and a redirect give 502 with the trace and no secret', async (t) => {
  const { app, stub, net } = await realApp(t);
  const logs = []; const orig = [console.log, console.error, console.warn];
  console.log = console.error = console.warn = (...a) => { logs.push(a.join(' ')); };
  t.after(() => { [console.log, console.error, console.warn] = orig; });

  stub.fault = 'bad-secret';
  const bad = await app.post('/api/mint', { sample: 'client_credentials' });
  assert.equal(bad.status, 502); assert.equal(bad.json.error, 'real_error'); assert.match(bad.json.message, /token endpoint answered 401 \(invalid_client\)/);
  assert.equal(bad.json.trace.at(-1).status, 401);
  assert.match(bad.json.trace.at(-1).response.body, /\[redacted\]/, 'the echoed secret is scrubbed');
  noSecret(bad.raw, 'bad-secret');

  stub.fault = 'wrong-issuer';
  const wi = await app.post('/api/introspect', { token: 'a.b.c' });
  assert.equal(wi.status, 502); assert.match(wi.json.message, /different issuer/);

  stub.fault = 'redirect';
  const rd = await app.post('/api/checker/run', {});
  assert.equal(rd.status, 502); assert.equal(rd.json.trace[0].status, 302); assert.match(rd.json.trace[0].note, /never followed/);
  assert.ok(!stub.seen.some((s) => s.url.includes('elsewhere')));

  stub.fault = null;
  assert.equal((await app.post('/api/mint', { sample: 'client_credentials' })).status, 200);
  for (const l of logs) noSecret(l, 'log');
  assert.deepEqual(net.attempts, []);
});

test('the netguard refuses an endpoint on any other host, even when the issuer\'s own metadata names it', async (t) => {
  const { app, stub, rf, net } = await realApp(t);
  stub.fault = 'evil-endpoint';
  const r = await app.post('/api/mint', { sample: 'client_credentials' });
  assert.equal(r.status, 502); assert.match(r.json.message, /refused by the netguard: .*only reach the configured issuer/);
  assert.equal(r.json.trace.at(-1).url, 'https://evil.example/token'); assert.equal(r.json.trace.at(-1).status, undefined);
  assert.deepEqual(rf.foreign, [], 'the fetch was never called for the foreign host');
  assert.deepEqual(net.attempts, []);
});

test('netguard unit: Mock refuses everything; Real allows only the configured https origin; the self-test never fetches', async () => {
  let mode = 'mock'; const fetched = [];
  const g = createNetguard({ mode: () => mode, allowedOrigin: 'https://idp.example', realFetch: async (u) => { fetched.push(u); return new Response('{}'); } });
  await assert.rejects(g.request('https://idp.example/as/jwks'), (e) => e instanceof NetguardRefused && e.reason === 'mock_mode');
  mode = 'real';
  for (const [u, reason] of [['https://other.example/', 'other_origin'], ['http://idp.example/', 'not_https'], ['https://u:p@idp.example/', 'credentials_in_url'], ['https://idp.example.evil.example/', 'other_origin'], ['https://idp.example:444/', 'other_origin'], ['not a url', 'bad_url']]) {
    assert.throws(() => g.check(u), (e) => e instanceof NetguardRefused && e.reason === reason, u);
  }
  assert.deepEqual(fetched, []);
  assert.equal((await g.request('https://idp.example/as/jwks')).status, 200);
  assert.deepEqual(fetched, ['https://idp.example/as/jwks']);
  for (const m of ['mock', 'real']) { mode = m; const st = g.selfTest(); assert.equal(st.ok, true, m); }
  assert.equal(fetched.length, 1, 'self-test made no call');
  const none = createNetguard({ mode: () => 'real', allowedOrigin: null, realFetch: async () => { throw new Error('no'); } });
  assert.throws(() => none.check('https://idp.example/'), (e) => e.reason === 'not_configured');
});

test('toggle: Real -> Mock -> Real; Mock makes no real call at all and labels its tokens MOCK', async (t) => {
  const { app, rf, net } = await realApp(t);
  const toMock = await app.post('/api/mode', { source: 'mock' });
  assert.equal(toMock.status, 200); assert.equal(toMock.json.source, 'mock'); assert.equal(toMock.json.realAvailable, true);
  const before = rf.calls.length;
  const m = await app.post('/api/mint', { sample: 'agent' });
  assert.equal(m.json.label, 'MOCK'); assert.equal(m.json.source, 'mock');
  assert.equal((await app.post('/api/decode', { token: m.json.token, verify: true })).json.signature.state, 'valid_stub_jwks');
  const mi = await app.post('/api/introspect', { token: m.json.token });
  assert.equal(mi.json.source, 'mock'); assert.equal(mi.json.active, true); assert.match(mi.json.note, /no HTTP request/);
  assert.equal((await app.post('/api/checker/run', { profile: 'good', pack: 'bcp' })).json.source, 'mock');
  assert.equal((await app.post('/api/mint', { sample: 'client_credentials' })).status, 400);
  assert.equal(rf.calls.length, before, 'Mock never reached the real fetch');
  const back = await app.post('/api/mode', { source: 'real' });
  assert.equal(back.json.source, 'real');
  assert.equal((await app.post('/api/mint', { sample: 'client_credentials' })).json.label, 'REAL');
  assert.deepEqual(net.attempts, []);
});

test('mock introspection: expired, forged and foreign tokens are inactive', async (t) => {
  const app = await startTestApp('misc'); t.after(app.close);
  const exp = (await app.post('/api/mint', { sample: 'expired' })).json.token;
  assert.equal((await app.post('/api/introspect', { token: exp })).json.active, false);
  assert.equal((await app.post('/api/introspect', { token: 'not-a-jwt' })).json.active, false);
  const good = (await app.post('/api/mint', { sample: 'user' })).json.token;
  const [h, p] = good.split('.');
  assert.equal((await app.post('/api/introspect', { token: `${h}.${p}.AAAA` })).json.active, false);
  for (const body of [{}, { token: '' }, { token: 1 }, { token: good, extra: 1 }, { token: 'x'.repeat(9000) }]) assert.equal((await app.post('/api/introspect', body)).status, 400, JSON.stringify(body).slice(0, 40));
});

test('Real not configured: Real is refused (409) naming each missing setting; nothing is fetched', async (t) => {
  const { app, rf } = await realApp(t, { TW_REAL: '1', TW_REAL_ISSUER: ISSUER, TW_REAL_CLIENT_ID: CLIENT_ID, TW_REAL_CLIENT_SECRET: '' });
  const info = (await app.get('/api/info')).json;
  assert.equal(info.source, 'mock'); assert.equal(info.realAvailable, false); assert.deepEqual(info.real.missing, ['TW_REAL_CLIENT_SECRET']);
  assert.equal(info.real.issuer, null, 'an incomplete configuration exposes no issuer');
  const r = await app.post('/api/mode', { source: 'real' });
  assert.equal(r.status, 409); assert.equal(r.json.error, 'real_not_configured'); assert.match(r.json.message, /TW_REAL_CLIENT_SECRET is not set/); assert.match(r.json.message, /\.env file beside docker-compose\.yml/);
  assert.equal((await app.post('/api/mint', { sample: 'client_credentials' })).status, 400);
  assert.deepEqual(rf.calls, []);
});

test('realConfigFrom: opt-in is exactly TW_REAL=1; the issuer must be https with a host name; bad values are named, never echoed', () => {
  assert.equal(realConfigFrom({}).available, false);
  assert.equal(realConfigFrom({ ...REAL_ENV, TW_REAL: 'true' }).available, false);
  assert.equal(realConfigFrom({ ...REAL_ENV, TW_REAL: '' }).optedIn, false);
  assert.equal(realConfigFrom(REAL_ENV).available, true);
  for (const issuer of ['http://idp.example/as', 'https://127.0.0.1/as', 'https://[::1]/as', 'https://localhost/as', 'https://a.localhost/', 'https://u:p@idp.example/', 'https://idp.example/as?x=1', 'https://idp.example/#f', 'notaurl', 'https://169.254.169.254/']) {
    const c = realConfigFrom({ ...REAL_ENV, TW_REAL_ISSUER: issuer });
    assert.equal(c.available, false, issuer); assert.ok(c.missing.includes('TW_REAL_ISSUER'), issuer);
  }
  assert.equal(realConfigFrom({ ...REAL_ENV, TW_REAL_ISSUER: `${ISSUER}/` }).issuer, ISSUER);
  assert.equal(realConfigFrom({ ...REAL_ENV, TW_REAL_TOKEN_AUTH: 'private_key_jwt' }).available, false);
  assert.equal(realConfigFrom({ ...REAL_ENV, TW_REAL_SCOPE: 'a  b' }).available, false);
  const badSecret = realConfigFrom({ ...REAL_ENV, TW_REAL_CLIENT_SECRET: 'x\ny' });
  assert.equal(badSecret.available, false); assert.ok(!JSON.stringify(badSecret).includes('x\ny'));
  const c = realConfigFrom(REAL_ENV);
  noSecret(JSON.stringify(c), 'config JSON'); assert.ok(!JSON.stringify(c).includes(CLIENT_ID));
});

test('doctor states: off, opted in but incomplete, configured, and refused in se-mock; values are never printed', () => {
  const by = (env) => Object.fromEntries(runChecks({ env }).map((c) => [c.id, c]));
  const off = by({});
  assert.equal(off.real.level, 'info'); assert.match(off.real.detail, /TW_REAL is not set/); assert.equal(off.netguard.level, 'pass'); assert.match(off.netguard.detail, /Mock makes no real outbound call/);
  const part = by({ TW_REAL: '1', TW_REAL_ISSUER: ISSUER, TW_REAL_CLIENT_ID: CLIENT_ID });
  assert.equal(part.real.level, 'info'); assert.match(part.real.detail, /TW_REAL_CLIENT_SECRET is not set/); assert.doesNotMatch(part.real.detail, /TW_REAL_ISSUER is not set/);
  const on = by(REAL_ENV);
  assert.equal(on.real.level, 'pass'); assert.match(on.real.detail, /issuer origin https:\/\/idp\.example/); assert.match(on.netguard.detail, /only the configured issuer origin/);
  const all = JSON.stringify(runChecks({ env: REAL_ENV })); noSecret(all, 'doctor'); assert.ok(!all.includes(CLIENT_ID), 'doctor never prints the client id');
  const se = by({ MODE: 'se-mock', ...REAL_ENV });
  assert.equal(se['deploy-mode'].level, 'fail'); assert.match(se['deploy-mode'].detail, /TW_REAL_CLIENT_SECRET is set: live features are refused/); assert.match(se.real.detail, /refused in the hosted build/);
  assert.ok(Object.values(by({ TW_REAL: '1' })).every((c) => c.level !== 'fail'), 'an incomplete Real never stops the lab');
});

test('hosted (se-mock) refuses to start with a Real setting', async () => {
  await assert.rejects(startTestApp('misc', { env: { ...process.env, MODE: 'se-mock', TW_PUBLIC_ORIGIN: 'https://workbench.example', TW_REAL: '1' } }), /TW_REAL is set: live features are refused/);
});

test('health says runtime live while Real is on and offline in Mock (health contract)', async (t) => {
  const { app } = await realApp(t);
  assert.equal((await app.get('/api/health')).json.runtime, 'live');
  await app.post('/api/mode', { source: 'mock' });
  assert.equal((await app.get('/api/health')).json.runtime, 'offline');
});

test('an issuer that echoes the secret everywhere (error code, form body, JSON-escaped, Basic header) leaks nothing: basic and post, a secret with ~ and quotes', async (t) => {
  for (const auth of ['client_secret_basic', 'client_secret_post']) {
    const secret = 'abc~DEF.ghi_JKL-mno~PQR "q" \\ (x)*!\'';
    const { app, stub } = await realApp(t, { ...REAL_ENV, TW_REAL_CLIENT_SECRET: secret, TW_REAL_TOKEN_AUTH: auth });
    stub.secret = secret; stub.fault = 'echo-all';
    const forms = [secret, encodeURIComponent(secret), new URLSearchParams({ s: secret }).toString().slice(2), JSON.stringify(secret).slice(1, -1), Buffer.from(secret).toString('base64'), basic(CLIENT_ID, secret).slice(6), secret.slice(0, 50)];
    const mint = await app.post('/api/mint', { sample: 'client_credentials' });
    assert.equal(mint.status, 502, auth);
    const intro = await app.post('/api/introspect', { token: 'a.b.c' });
    assert.equal(intro.status, 200, auth);
    for (const raw of [mint.raw, intro.raw]) for (const f of forms) assert.ok(!raw.includes(f), `${auth}: an encoding of the secret leaked`);
    assert.match(mint.json.message, /\[redacted\]/, 'the 502 message itself is scrubbed');
  }
});

test('the netguard caps a response body at 256 KiB; a truncated JWKS is never trusted', async (t) => {
  const { app, stub } = await realApp(t);
  const { token } = (await app.post('/api/mint', { sample: 'client_credentials' })).json;
  stub.fault = 'huge';
  const r = await app.post('/api/decode', { token, verify: true });
  assert.equal(r.status, 502); assert.match(r.json.message, /JWKS endpoint answered 200/);
  const j = r.json.trace.at(-1);
  assert.equal(j.response.truncated, true); assert.ok(j.response.body.length <= 256 * 1024, String(j.response.body.length));
});

test('the hosted build never turns Real on, even if handed a complete Real configuration', async (t) => {
  const { createApp } = await import('../src/app.js');
  const { createRuntime } = await import('../src/runtime.js');
  const rt = await createRuntime({ ephemeral: true }); t.after(rt.close);
  const app = createApp({ runtime: rt, deployMode: 'se-mock', real: realConfigFrom(REAL_ENV), webDist: null, realFetch: () => { throw new Error('must not fetch'); } });
  const server = app.listen(0, '127.0.0.1'); await new Promise((r) => { server.once('listening', r); });
  t.after(async () => { await app.workspaces?.closeAll(); await new Promise((r) => { server.closeAllConnections?.(); server.close(r); }); });
  const { request } = await import('./helpers.js');
  const info = await request(server.address().port, 'GET', '/api/info');
  assert.equal(info.json.realAvailable, false); assert.equal(info.json.source, 'mock'); assert.equal(info.json.real, null);
  assert.equal(app.netguard.allowedOrigin, null);
});

test('issuer normalisation: case is folded so discovery matches; trailing-dot localhost and spaces are refused', () => {
  assert.equal(realConfigFrom({ ...REAL_ENV, TW_REAL_ISSUER: 'HTTPS://IDP.EXAMPLE/as' }).issuer, ISSUER);
  for (const issuer of ['https://localhost./as', 'https://foo.localhost./', 'https://idp.example/a s', 'https://127.0.0.1./as']) assert.equal(realConfigFrom({ ...REAL_ENV, TW_REAL_ISSUER: issuer }).available, false, issuer);
});
