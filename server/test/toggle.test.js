// Rule 19: the Mock/Real toggle's API. Without the owner's Real settings Real is unavailable (409, naming the settings); the
// hosted build cannot be switched. Real with settings: real.test.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp } from './helpers.js';

const SE = { ...process.env, MODE: 'se-mock', TW_PUBLIC_ORIGIN: 'https://workbench.example' };

test('local, Real not configured: /api/info says Mock with no Real; /api/mode keeps Mock, refuses Real (409) and bad bodies (400)', async (t) => {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('TW_REAL')));
  const app = await startTestApp('misc', { env }); t.after(app.close);
  const info = (await app.get('/api/info')).json;
  assert.equal(info.source, 'mock'); assert.equal(info.realAvailable, false); assert.equal(info.hosted, false); assert.equal(info.mode, 'local');
  const keep = await app.post('/api/mode', { source: 'mock' });
  assert.equal(keep.status, 200); assert.equal(keep.json.source, 'mock');
  const real = await app.post('/api/mode', { source: 'real' });
  assert.equal(real.status, 409); assert.match(real.json.message, /Real is not configured/);
  for (const name of ['TW_REAL', 'TW_REAL_ISSUER', 'TW_REAL_CLIENT_ID', 'TW_REAL_CLIENT_SECRET']) assert.ok(info.real.missing.includes(name), name);
  assert.equal((await app.get('/api/info')).json.source, 'mock', 'a refused switch leaves Mock on');
  for (const body of [{}, { source: 'live' }, { source: 'mock', extra: 1 }, []]) assert.equal((await app.post('/api/mode', body)).status, 400, JSON.stringify(body));
});

test('hosted (se-mock): reports Mock only and refuses every switch (403)', async (t) => {
  const app = await startTestApp('misc', { env: SE }); t.after(app.close);
  const info = (await app.get('/api/info')).json;
  assert.equal(info.hosted, true); assert.equal(info.source, 'mock'); assert.equal(info.realAvailable, false); assert.equal(info.mode, 'se-mock');
  assert.equal((await app.post('/api/mode', { source: 'real' })).status, 403);
  assert.equal((await app.post('/api/mode', { source: 'mock' })).status, 403);
});
