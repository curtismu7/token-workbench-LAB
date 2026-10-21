import test from 'node:test';
import assert from 'node:assert/strict';
import { validateToken } from '../src/validator.js';
import { createKeyring } from '../src/keys.js';
import { b64uJson } from '../src/jwt.js';

const ISS = 'http://127.0.0.1:1/issuer'; const AUD = 'http://127.0.0.1:1/mcp';
const keyring = createKeyring({ issuer: ISS });
const NOW = 1_800_000_000;
const policy = { issuer: ISS, audience: AUD, requiredScope: 'mcp:tools', requireActor: true, jwks: () => keyring.jwks(), now: () => NOW };
const good = (over = {}) => ({ iss: ISS, sub: 'u', aud: AUD, scope: 'mcp:tools', act: { sub: 'a' }, iat: NOW, exp: NOW + 300, ...over });
const check = (token) => validateToken(token, policy);

test('a good token is accepted and every check ran', () => {
  const v = check(keyring.sign({}, good()));
  assert.equal(v.ok, true);
  assert.deepEqual(v.checks.map((c) => c.id), ['format', 'alg', 'kid', 'signature', 'iss', 'exp', 'nbf', 'aud', 'actor', 'scope']);
});

test('alg none is rejected by the alg check, not by a later one', () => {
  const none = `${b64uJson({ alg: 'none', kid: keyring.kid })}.${b64uJson(good())}.`;
  const v = check(none);
  assert.equal(v.ok, false);
  assert.equal(v.failed_check, 'alg');
  assert.equal(v.status, 401);
  assert.match(v.error_description, /unsigned/);
  // case variants and a token with a signature part but alg none
  for (const alg of ['None', 'NONE', 'nOnE']) assert.equal(check(`${b64uJson({ alg, kid: keyring.kid })}.${b64uJson(good())}.AAAA`).failed_check, 'alg');
});

test('an expired token is rejected by the exp check; a token with no exp too', () => {
  assert.equal(check(keyring.sign({}, good({ exp: NOW - 60 }))).failed_check, 'exp');
  assert.equal(check(keyring.sign({}, good({ exp: undefined }))).failed_check, 'exp');
  assert.equal(check(keyring.sign({}, good({ exp: NOW - 2 }))).ok, true, 'within the 5 s leeway');
});

test('a token for another audience is rejected by the aud check, an array containing ours is accepted', () => {
  assert.equal(check(keyring.sign({}, good({ aud: 'http://127.0.0.1:1/other' }))).failed_check, 'aud');
  assert.equal(check(keyring.sign({}, good({ aud: undefined }))).failed_check, 'aud');
  assert.equal(check(keyring.sign({}, good({ aud: ['x', AUD] }))).ok, true);
});

test('issuer, nbf, scope, actor, kid and signature each have their own rejection', () => {
  const expect = (over, id, status) => { const v = check(keyring.sign({}, good(over))); assert.equal(v.failed_check, id); assert.equal(v.status, status); return v; };
  expect({ iss: 'http://elsewhere' }, 'iss', 401);
  expect({ nbf: NOW + 600 }, 'nbf', 401);
  assert.equal(expect({ scope: 'mcp:read' }, 'scope', 403).error, 'insufficient_scope');
  assert.equal(expect({ act: undefined }, 'actor', 403).error, 'insufficient_scope');
  assert.equal(check(keyring.signWithRogueKey({ kid: 'nope' }, good())).failed_check, 'kid');
  assert.equal(check(keyring.signWithRogueKey({}, good())).failed_check, 'signature');
});

test('garbage never throws', () => {
  for (const t of [undefined, null, '', 'x', '..', {}, 42]) assert.equal(check(t).failed_check, 'format');
});
