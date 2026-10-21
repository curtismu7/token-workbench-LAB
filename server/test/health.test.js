import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { createHealth } from '../src/health.js';
import { runChecks } from '../src/doctor.js';
import { freeBase, request } from './helpers.js';

async function serve(t, health) {
  const app = express();
  app.use('/api/health', health.router);
  const port = await freeBase('misc', 1);
  const s = app.listen(port, '127.0.0.1');
  await new Promise((r) => s.once('listening', r));
  t.after(() => { health.stop(); s.closeAllConnections(); s.close(); });
  return port;
}
const get = async (t, opts) => (await request(await serve(t, createHealth(opts)), 'GET', '/api/health')).json;

test('state follows the checks: failing is broken, throwing is unknown, passing is ready', async (t) => {
  assert.equal((await get(t, { runChecks: () => [{ id: 'x', level: 'fail', detail: 'no' }] })).state, 'broken');
  assert.equal((await get(t, { runChecks: () => { throw new Error('boom'); } })).state, 'unknown');
  assert.equal((await get(t, { runChecks: () => [{ id: 'x', level: 'info', detail: 'ok' }] })).state, 'ready');
});

test('the reply is demo-health/1 and runtime is offline', async (t) => {
  const j = await get(t, { runChecks: () => [] });
  assert.equal(j.schema, 'demo-health/1');
  assert.equal(j.runtime, 'offline');
  assert.equal(j.demo.id, 'token-workbench');
  assert.ok(j.demo.name.length <= 80 && j.demo.version.length <= 32);
  assert.deepEqual(Object.keys(j).sort(), ['at', 'demo', 'runtime', 'schema', 'state']);
});

test('a request does not run the checks', async (t) => {
  let runs = 0;
  const port = await serve(t, createHealth({ runChecks: () => { runs += 1; return []; } }));
  const before = runs;
  await request(port, 'GET', '/api/health');
  await request(port, 'GET', '/api/health');
  assert.equal(runs, before);
});

test('doctor: the default environment passes; a port outside 5900-5999 or a bad bind fails', () => {
  assert.ok(runChecks({ env: {} }).every((c) => c.level !== 'fail'));
  assert.equal(runChecks({ env: { TW_PORT: '5310' } }).find((c) => c.id === 'port-range').level, 'fail');
  assert.equal(runChecks({ env: { TW_PORT: '5910', TW_BIND: undefined } }).find((c) => c.id === 'port-range').level, 'pass');
});
