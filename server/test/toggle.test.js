// Rule 19: the Mock/Real toggle's API. This app is mock only, so Real is never available and the hosted build cannot be switched.
import test from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp } from './helpers.js';

const SE = { ...process.env, MODE: 'se-mock', TW_PUBLIC_ORIGIN: 'https://workbench.example' };

test('local: /api/info says Mock with no Real; /api/mode keeps Mock, refuses Real (409) and bad bodies (400)', async (t) => {
  const app = await startTestApp('misc'); t.after(app.close);
  const info = (await app.get('/api/info')).json;
  assert.equal(info.source, 'mock'); assert.equal(info.realAvailable, false); assert.equal(info.hosted, false); assert.equal(info.mode, 'local');
  const keep = await app.post('/api/mode', { source: 'mock' });
  assert.equal(keep.status, 200); assert.equal(keep.json.source, 'mock');
  const real = await app.post('/api/mode', { source: 'real' });
  assert.equal(real.status, 409); assert.match(real.json.message, /no live version/);
  for (const body of [{}, { source: 'live' }, { source: 'mock', extra: 1 }, []]) assert.equal((await app.post('/api/mode', body)).status, 400, JSON.stringify(body));
});

test('hosted (se-mock): reports Mock only and refuses every switch (403)', async (t) => {
  const app = await startTestApp('misc', { env: SE }); t.after(app.close);
  const info = (await app.get('/api/info')).json;
  assert.equal(info.hosted, true); assert.equal(info.source, 'mock'); assert.equal(info.realAvailable, false); assert.equal(info.mode, 'se-mock');
  assert.equal((await app.post('/api/mode', { source: 'real' })).status, 403);
  assert.equal((await app.post('/api/mode', { source: 'mock' })).status, 403);
});
