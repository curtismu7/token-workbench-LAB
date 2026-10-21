import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startTestApp } from './helpers.js';

const tmpDist = (t) => {
  const dist = fs.mkdtempSync(path.join(os.tmpdir(), 'tw-dist-'));
  t.after(() => fs.rmSync(dist, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dist, 'index.html'), '<!doctype html><title>ui</title>');
  fs.mkdirSync(path.join(dist, 'assets'));
  fs.writeFileSync(path.join(dist, 'assets', 'a.js'), 'console.log(1)');
  fs.writeFileSync(path.join(dist, '.secret'), 'x');
  return dist;
};

test('the built UI is served by the server itself with a same-origin CSP, and the Host and Origin guards still apply', async (t) => {
  const app = await startTestApp('ui', { webDist: tmpDist(t) }); t.after(app.close);
  const root = await app.get('/');
  assert.equal(root.status, 200);
  assert.match(root.headers['content-type'], /text\/html/);
  const csp = root.headers['content-security-policy'];
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /connect-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.doesNotMatch(csp, /unsafe-eval|script-src[^;]*unsafe-inline|https?:|\*/);
  assert.equal(root.headers['x-content-type-options'], 'nosniff');
  assert.equal((await app.get('/assets/a.js')).status, 200);
  assert.equal((await app.get('/.secret')).status, 404);
  assert.equal((await app.get('/', { host: 'evil.example.com' })).status, 421);
  assert.equal((await app.get('/assets/a.js', { host: 'evil.example.com' })).status, 421);
  assert.ok((await app.get('/%ZZ')).status < 500);
  assert.equal((await app.post('/', {}, { headers: { origin: 'http://evil.example' } })).status, 403);
  // the API keeps default-src 'none'
  assert.equal((await app.get('/api/health')).headers['content-security-policy'], "default-src 'none'");
  assert.equal((await app.get('/api/nothing')).headers['content-security-policy'], "default-src 'none'");
});

test('without a built UI, GET / is a JSON 404', async (t) => {
  const app = await startTestApp('ui', { webDist: path.join(os.tmpdir(), 'tw-no-such-dist') }); t.after(app.close);
  const res = await app.get('/');
  assert.equal(res.status, 404);
  assert.equal(res.json.error, 'not_found');
});
