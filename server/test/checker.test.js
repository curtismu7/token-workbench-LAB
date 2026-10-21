import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { startTestApp, freeBase } from './helpers.js';
import { guardNetwork } from './netguard.js';
import { runChecker } from '../src/checker.js';

// Expected pass (p) / fail (f) per rule, in the order of BCP_RULES and FAPI_RULES.
const BCP = ['metadata', 'exact-redirect', 'pkce-required', 'pkce-downgrade', 's256-only', 'no-ropc', 'no-implicit', 'single-use-code', 'iss-param'];
const FAPI = ['fapi-par-published', 'fapi-par-required', 'fapi-pkce-s256', 'fapi-sender-constrained', 'fapi-no-implicit-ropc', 'fapi-exact-redirect', 'fapi-iss'];
const EXPECTED = {
  good: { bcp: 'ppppppppp', fapi: 'ppppppp' },
  'loose-redirect': { bcp: 'pfppppppp', fapi: 'pppppfp' },
  'implicit-ropc': { bcp: 'ppppp' + 'ff' + 'pp', fapi: 'ppppfpp' },
  'no-pkce': { bcp: 'p' + 'p' + 'fff' + 'ppp' + 'p', fapi: 'ffffppp' },
  'missing-metadata': { bcp: 'f' + 'pppppppf', fapi: 'ffpfppf' },
};
const pattern = (pack) => pack.rules.map((r) => (r.status === 'pass' ? 'p' : r.status === 'fail' ? 'f' : '?')).join('');

test('each stub profile gives its expected pass/fail pattern in both rule packs', async (t) => {
  const app = await startTestApp('checker'); t.after(app.close);
  for (const [profile, exp] of Object.entries(EXPECTED)) {
    const r = await app.post('/api/checker/run', { profile });
    assert.equal(r.status, 200, profile);
    assert.deepEqual(r.json.packs.bcp.rules.map((x) => x.id), BCP);
    assert.deepEqual(r.json.packs.fapi.rules.map((x) => x.id), FAPI);
    assert.equal(pattern(r.json.packs.bcp), exp.bcp, `${profile} bcp: ${r.json.packs.bcp.rules.map((x) => `${x.id}=${x.status}`)}`);
    assert.equal(pattern(r.json.packs.fapi), exp.fapi, `${profile} fapi: ${r.json.packs.fapi.rules.map((x) => `${x.id}=${x.status}`)}`);
    for (const rule of [...r.json.packs.bcp.rules, ...r.json.packs.fapi.rules]) { assert.ok(rule.evidence.length > 3 && rule.why && rule.rfc, `${profile} ${rule.id}`); }
  }
});

test('the FAPI 2.0 pack is marked UNVERIFIED in the result and the notes say so', async (t) => {
  const app = await startTestApp('checker'); t.after(app.close);
  const r = (await app.post('/api/checker/run', { profile: 'good' })).json;
  assert.equal(r.packs.fapi.unverified, true);
  assert.equal(r.packs.bcp.unverified, false);
  assert.match(r.packs.fapi.note, /^UNVERIFIED/);
  assert.match(JSON.stringify((await app.get('/api/meta')).json.rules.fapiNote), /UNVERIFIED/);
});

test('a single pack can be requested', async (t) => {
  const app = await startTestApp('checker'); t.after(app.close);
  const r = (await app.post('/api/checker/run', { profile: 'good', pack: 'bcp' })).json;
  assert.deepEqual(Object.keys(r.packs), ['bcp']);
  assert.equal((await app.post('/api/checker/run', { profile: 'good', pack: 'x' })).status, 400);
});

test('remote and malformed targets are refused (400 target_refused) and open no connection', async (t) => {
  const app = await startTestApp('checker'); t.after(app.close);
  const guard = guardNetwork(); t.after(() => guard.restore());
  for (const target of ['http://example.com', 'https://auth.example.com/', 'http://10.0.0.5:8080', 'http://169.254.169.254/', 'http://127.0.0.1.evil.com', 'http://user:pw@127.0.0.1:5911', 'ftp://127.0.0.1', 'nonsense']) {
    const r = await app.post('/api/checker/run', { target });
    assert.equal(r.status, 400, target);
    assert.equal(r.json.error, 'target_refused', target);
    assert.ok(r.json.reason, target);
  }
  assert.deepEqual(guard.attempts, []);
});

test('exactly one of profile or target; unknown profile; extra fields (credentials) are refused', async (t) => {
  const app = await startTestApp('checker'); t.after(app.close);
  assert.equal((await app.post('/api/checker/run', {})).status, 400);
  assert.equal((await app.post('/api/checker/run', { profile: 'good', target: 'http://127.0.0.1:1' })).status, 400);
  assert.equal((await app.post('/api/checker/run', { profile: 'nope' })).status, 400);
  for (const extra of ['client_secret', 'password', 'authorization', 'token']) assert.equal((await app.post('/api/checker/run', { profile: 'good', [extra]: 'x' })).status, 400, extra);
});

test('a user-supplied loopback target works (any loopback AS, here one on a different port)', async (t) => {
  const app = await startTestApp('checker'); t.after(app.close);
  const r = await app.post('/api/checker/run', { target: `http://127.0.0.1:${app.runtime.authServers["no-pkce"].port}/` });
  assert.equal(r.status, 200);
  assert.equal(pattern(r.json.packs.bcp), EXPECTED['no-pkce'].bcp);
});

test('a loopback server whose metadata points at remote endpoints: the remote endpoints are refused, nothing is connected', async (t) => {
  const port = await freeBase('checker', 1);
  const requests = [];
  const evil = http.createServer((req, res) => {
    requests.push(req.url);
    if (req.url.startsWith('/.well-known/oauth-authorization-server')) {
      res.setHeader('content-type', 'application/json');
      return res.end(JSON.stringify({ issuer: `http://127.0.0.1:${port}`, authorization_endpoint: 'http://203.0.113.9/authorize', token_endpoint: 'http://203.0.113.9/token', response_types_supported: ['code'], pushed_authorization_request_endpoint: 'http://203.0.113.9/par' }));
    }
    res.statusCode = 404; res.end('{}');
  });
  await new Promise((r) => evil.listen(port, '127.0.0.1', r));
  t.after(() => { evil.closeAllConnections(); evil.close(); });
  const guard = guardNetwork(); t.after(() => guard.restore());
  const r = await runChecker({ target: `http://127.0.0.1:${port}` });
  guard.restore();
  assert.deepEqual(guard.attempts, [], 'no non-loopback socket, DNS lookup or fetch');
  const exact = r.packs.bcp.rules.find((x) => x.id === 'exact-redirect');
  assert.equal(exact.status, 'error');
  assert.match(exact.evidence, /non-loopback endpoint/);
  assert.equal(r.packs.bcp.rules.find((x) => x.id === 'metadata').status, 'pass');
  assert.deepEqual(requests, ['/.well-known/oauth-authorization-server'], 'only the metadata document was requested from the local server');
});

test('server-provided text in the evidence is inert and bounded', async (t) => {
  const port = await freeBase('checker', 1);
  const sneaky = `bad${String.fromCharCode(0x202e)}${String.fromCharCode(0x200b)}`.repeat(200);
  const srv = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url.startsWith('/.well-known/oauth-authorization-server')) return res.end(JSON.stringify({ issuer: sneaky, authorization_endpoint: `http://127.0.0.1:${port}/a`, token_endpoint: `http://127.0.0.1:${port}/t`, response_types_supported: ['code'] }));
    res.statusCode = 400; res.end(JSON.stringify({ error: sneaky, error_description: sneaky }));
  });
  await new Promise((r) => srv.listen(port, '127.0.0.1', r));
  t.after(() => { srv.closeAllConnections(); srv.close(); });
  const r = await runChecker({ target: `http://127.0.0.1:${port}` });
  const text = JSON.stringify(r);
  assert.doesNotMatch(text, /[‮​]/);
  assert.match(text, /\[U\+202E\]/);
  for (const rule of r.packs.bcp.rules) assert.ok(rule.evidence.length <= 205, rule.id);
});

test('an unreachable loopback target yields error results, not a crash', async (t) => {
  const app = await startTestApp('checker'); t.after(app.close);
  const port = await freeBase('checker', 1);
  const r = await app.post('/api/checker/run', { target: `http://127.0.0.1:${port}` });
  assert.equal(r.status, 200);
  assert.equal(r.json.unreachable, true);
  for (const pack of ['bcp', 'fapi']) assert.ok(r.json.packs[pack].rules.every((x) => x.status === 'error'), `${pack}: nothing answered, so no rule may be judged pass or fail`);
  assert.equal(r.json.requests, 2, 'only the two discovery requests were made');
});
