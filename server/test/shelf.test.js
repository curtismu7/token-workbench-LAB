// The header "Shelf" button needs GET /api/shelf to be reachable, here with no web build (the test app serves the API only).
import test from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp } from './helpers.js';

test('GET /api/shelf returns SHELF_URL with the trailing slash trimmed, and a POST is refused', async (t) => {
  const saved = process.env.SHELF_URL;
  process.env.SHELF_URL = 'https://shelf.example:8443/';
  const app = await startTestApp('misc');
  t.after(async () => {
    await app.close();
    if (saved === undefined) delete process.env.SHELF_URL; else process.env.SHELF_URL = saved;
  });
  const r = await app.get('/api/shelf');
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { shelfUrl: 'https://shelf.example:8443' });
  const p = await app.post('/api/shelf', {});
  assert.notEqual(p.status, 200);
});
