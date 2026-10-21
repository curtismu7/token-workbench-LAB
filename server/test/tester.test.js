import test from 'node:test';
import assert from 'node:assert/strict';
import { CASES } from '../src/tester.js';
import { startTestApp } from './helpers.js';

test('the good token is accepted and every wrong-token case gets its expected rejection', async (t) => {
  const app = await startTestApp('tester'); t.after(app.close);
  const r = await app.post('/api/tester/run', { case: 'all' });
  assert.equal(r.status, 200);
  assert.equal(r.json.results.length, CASES.length);
  const by = Object.fromEntries(r.json.results.map((x) => [x.id, x]));
  assert.equal(r.json.summary.failed, 0, JSON.stringify(r.json.results.filter((x) => !x.pass).map((x) => [x.id, x.actual.status, x.actual.failed_check])));

  assert.equal(by.good.actual.status, 200);
  assert.equal(by.good.accepted, true);
  const rejected = {
    'wrong-scope': [403, 'insufficient_scope', 'scope'], 'wrong-audience': [401, 'invalid_token', 'aud'], expired: [401, 'invalid_token', 'exp'],
    'not-yet-valid': [401, 'invalid_token', 'nbf'], 'wrong-issuer': [401, 'invalid_token', 'iss'], 'alg-none': [401, 'invalid_token', 'alg'],
    'alg-confusion-hs256': [401, 'invalid_token', 'alg'], 'user-vs-agent': [403, 'insufficient_scope', 'actor'], 'tampered-signature': [401, 'invalid_token', 'signature'],
    'forged-signature': [401, 'invalid_token', 'signature'], 'unknown-kid': [401, 'invalid_token', 'kid'], 'rfc8707-passthrough': [401, 'invalid_token', 'aud'], malformed: [401, 'invalid_token', 'format'],
  };
  for (const [id, [status, error, check]] of Object.entries(rejected)) {
    const a = by[id].actual;
    assert.equal(a.status, status, id); assert.equal(a.error, error, id); assert.equal(a.failed_check, check, id);
    assert.equal(a.wwwError, error, `${id}: WWW-Authenticate error`);
    assert.match(a.wwwAuthenticate, /^Bearer realm="tw-mcp"/);
    assert.match(a.wwwAuthenticate, /resource_metadata="http:\/\/127\.0\.0\.1:\d+\/\.well-known\/oauth-protected-resource"/);
    assert.ok(a.error_description.length > 10, id);
    assert.equal(by[id].accepted, false, id);
    assert.ok(by[id].teaches.length > 40);
  }
  assert.match(by['wrong-scope'].actual.wwwAuthenticate, /scope="mcp:tools"/);
  assert.equal(by['no-token'].actual.status, 401);
  assert.equal(by['no-token'].actual.wwwError, null, 'no error code when no credentials were sent');
  assert.match(by['no-token'].actual.wwwAuthenticate, /^Bearer/);
});

test('insufficient_scope is 403 and invalid_token is 401, never the other way round', async (t) => {
  const app = await startTestApp('tester'); t.after(app.close);
  for (const id of ['wrong-scope', 'user-vs-agent']) { const r = (await app.post('/api/tester/run', { case: id })).json.results[0]; assert.equal(r.actual.status, 403); }
  for (const id of ['expired', 'wrong-audience', 'alg-none']) { const r = (await app.post('/api/tester/run', { case: id })).json.results[0]; assert.equal(r.actual.status, 401); }
});

test('the tester proves a case fails when the server behaves wrongly (a lenient resource server)', async (t) => {
  // Build a context whose resource server uses a different audience: every token's aud no longer matches, so the control fails.
  const app = await startTestApp('tester'); t.after(app.close);
  const { runCase } = await import('../src/tester.js');
  const r = await runCase('good', { ...app.runtime.testerCtx, ids: { ...app.runtime.ids, resource: 'http://127.0.0.1:1/else' } });
  assert.equal(r.pass, false);
  assert.equal(r.actual.status, 401);
});

test('an unknown case, a bad body and an extra field are refused', async (t) => {
  const app = await startTestApp('tester'); t.after(app.close);
  assert.equal((await app.post('/api/tester/run', { case: 'nope' })).status, 400);
  assert.equal((await app.post('/api/tester/run', { case: 5 })).status, 400);
  assert.equal((await app.post('/api/tester/run', { case: 'good', token: 'x' })).status, 400);
  assert.equal((await app.get('/api/tester/cases')).json.cases.length, CASES.length);
});

test('the stub resource server publishes protected-resource metadata and its JWKS carries no private key', async (t) => {
  const app = await startTestApp('tester'); t.after(app.close);
  const meta = await (await fetch(`http://127.0.0.1:${app.runtime.rs.port}/.well-known/oauth-protected-resource`)).json();
  assert.equal(meta.resource, app.runtime.ids.resource);
  const jwks = (await app.get('/api/jwks')).json;
  assert.equal(jwks.keys.length, 1);
  assert.equal(jwks.keys[0].d, undefined);
  assert.doesNotMatch(JSON.stringify(jwks), /"d"|PRIVATE/);
});
