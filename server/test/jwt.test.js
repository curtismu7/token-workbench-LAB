import test from 'node:test';
import assert from 'node:assert/strict';
import { b64uJson, explainClaims, jwkThumbprint, parseJwt, timeStatus } from '../src/jwt.js';
import { createKeyring } from '../src/keys.js';
import { inertValue } from '../src/sanitize.js';

const keyring = createKeyring({ issuer: 'http://127.0.0.1:1/issuer' });
const NOW = 1_800_000_000;

test('parseJwt reads a minted token and refuses malformed input without throwing', () => {
  const tok = keyring.sign({}, { sub: 'u', exp: NOW + 60 });
  const p = parseJwt(tok);
  assert.equal(p.ok, true);
  assert.equal(p.header.alg, 'ES256');
  assert.equal(p.payload.sub, 'u');
  for (const bad of [undefined, null, '', 'a.b', 'a.b.c.d', 'x y.z.w', 123, `${b64uJson([1])}.${b64uJson({})}.`, 'a'.repeat(9000)]) assert.equal(parseJwt(bad).ok, false, String(bad).slice(0, 20));
});

test('explainClaims covers alg none, bearer, DPoP, mTLS, actor, expiry and not-yet-valid', () => {
  const by = (header, payload) => Object.fromEntries(explainClaims(header, payload, NOW).map((c) => [c.name, c]));
  assert.equal(by({ alg: 'none' }, {}).alg.level, 'danger');
  assert.equal(by({ alg: 'HS256' }, {}).alg.level, 'warn');
  assert.match(by({ alg: 'ES256' }, {}).cnf.meaning, /bearer token/);
  assert.match(by({}, { cnf: { jkt: 'abc' } })['cnf.jkt'].meaning, /DPoP/);
  assert.match(by({}, { cnf: { 'x5t#S256': 'abc' } })['cnf.x5t#S256'].meaning, /mutual TLS/);
  assert.match(by({}, { act: { sub: 'agent-1' } }).act.meaning, /agent-1/);
  assert.equal(by({}, { exp: NOW - 10 }).exp.level, 'danger');
  assert.match(by({}, { exp: NOW - 10 }).exp.meaning, /Expired 10 s ago/);
  assert.equal(by({}, { exp: NOW + 10 }).exp.level, 'info');
  assert.equal(by({}, { nbf: NOW + 100 }).nbf.level, 'danger');
  assert.match(by({}, { aud: ['a', 'b'] }).aud.meaning, /a, b/);
  assert.equal(by({}, { exp: 'soon' }).exp.level, 'warn');
});

test('timeStatus', () => {
  assert.deepEqual(timeStatus({ exp: NOW - 1 }, NOW), { hasExp: true, expired: true, secondsToExpiry: -1, notYetValid: false });
  assert.equal(timeStatus({ nbf: NOW + 5 }, NOW).notYetValid, true);
  assert.equal(timeStatus({}, NOW).hasExp, false);
});

test('claim values with hidden characters are shown inert in explanations', () => {
  const sneaky = `agent${String.fromCharCode(0x202e)}7${String.fromCharCode(0x200b)}`;
  const c = explainClaims({}, { sub: sneaky }, NOW).find((x) => x.name === 'sub');
  assert.doesNotMatch(JSON.stringify(c), /[‮​]/);
  assert.match(c.value, /\[U\+202E\]/);
  assert.match(c.meaning, /\[U\+202E\]/);
  assert.doesNotMatch(JSON.stringify(inertValue({ a: [sneaky] })), /[‮]/);
});

test('the DPoP thumbprint is deterministic and key-specific', () => {
  const a = createKeyring({ issuer: 'x' }); const b = createKeyring({ issuer: 'x' });
  assert.equal(a.clientJkt, a.clientJkt);
  assert.notEqual(a.clientJkt, b.clientJkt);
  assert.equal(jwkThumbprint({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }), jwkThumbprint({ y: 'y', x: 'x', crv: 'P-256', kty: 'EC' }));
});
