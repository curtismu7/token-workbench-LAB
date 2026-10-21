import test from 'node:test';
import assert from 'node:assert/strict';
import { compare, listMechanisms, runFlow } from '../src/catalog.js';

test('the catalog lists PAR, RAR, DPoP, mTLS, JAR and PKCE', () => {
  assert.deepEqual(listMechanisms().map((m) => m.id).sort(), ['dpop', 'jar', 'mtls', 'par', 'pkce', 'rar']);
  for (const m of listMechanisms()) { assert.ok(m.rfc && m.adds && m.attack.title && m.limits); }
});

test('every mechanism: the attack succeeds without the protection and is blocked with it', () => {
  for (const m of listMechanisms()) {
    const off = runFlow(m.id, false); const on = runFlow(m.id, true);
    assert.equal(off.attack.outcome, 'attack_succeeds', `${m.id} without`);
    assert.equal(off.pass, false);
    assert.equal(on.attack.outcome, 'attack_blocked', `${m.id} with`);
    assert.equal(on.pass, true);
    assert.ok(off.attack.reason && on.attack.reason);
    assert.ok(on.steps.some((s) => s.evil), `${m.id} shows the attacker step`);
  }
});

test('the protected trace differs from the unprotected one and steps are numbered from 1', () => {
  for (const m of listMechanisms()) {
    const off = runFlow(m.id, false); const on = runFlow(m.id, true);
    assert.notDeepEqual(off.steps.map((s) => s.label), on.steps.map((s) => s.label), m.id);
    assert.deepEqual(on.steps.map((s) => s.n), on.steps.map((_, i) => i + 1));
  }
});

test('compare() returns one row per mechanism with both outcomes and says it is simulated', () => {
  const c = compare();
  assert.equal(c.simulated, true);
  assert.equal(c.rows.length, 6);
  for (const r of c.rows) { assert.equal(r.without.pass, false); assert.equal(r.with.pass, true); }
});

test('an unknown mechanism is an error', () => {
  assert.throws(() => runFlow('nope', true), { code: 'unknown_mechanism' });
});
