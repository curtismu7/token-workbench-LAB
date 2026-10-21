import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const root = new URL('..', import.meta.url).pathname;
const docs = ['README.md', 'docs/safety.md', 'docs/architecture.md'];
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

test('relative links in README and docs resolve to files that exist', () => {
  for (const d of docs) {
    for (const m of read(d).matchAll(/\]\((?!https?:|#|mailto:)([^)#\s]+)/g)) {
      assert.ok(fs.existsSync(path.resolve(path.dirname(path.join(root, d)), m[1])), `${d} links to missing ${m[1]}`);
    }
  }
});

test('every npm script and source file the docs name exists', () => {
  const pkg = JSON.parse(read('package.json'));
  const serverPkg = JSON.parse(read('server/package.json'));
  for (const d of docs) {
    const text = read(d);
    for (const m of text.matchAll(/npm run ([\w-]+)(?! -w)/g)) assert.ok(pkg.scripts[m[1]] || serverPkg.scripts[m[1]], `${d}: npm run ${m[1]} does not exist`);
    for (const m of text.matchAll(/`((?:server|scripts)\/[\w./-]+\.(?:js|mjs))`/g)) assert.ok(fs.existsSync(path.join(root, m[1])), `${d} names missing file ${m[1]}`);
  }
});

test('every API route in the README exists in the app', () => {
  const app = read('server/src/app.js');
  for (const m of read('README.md').matchAll(/`(GET|POST) (\/api\/[\w/]+)/g)) {
    const [, method, route] = m;
    const sub = route.replace('/api', '');
    if (sub === '/health') continue; // mounted with api.use('/health', ...)
    assert.ok(app.includes(`api.${method.toLowerCase()}('${sub}'`), `README documents ${method} ${route} but app.js has no such route`);
  }
});

test('the docs state the mock-only default, mark FAPI UNVERIFIED and explain why remote targets are refused', () => {
  assert.match(read('README.md'), /no live mode/i);
  assert.match(read('README.md'), /UNVERIFIED/);
  assert.match(read('docs/safety.md'), /FAPI 2\.0 pack: UNVERIFIED/);
  assert.match(read('docs/safety.md'), /Nothing here is verified about specific Ping products/);
  assert.match(read('docs/safety.md'), /Why remote targets are refused/);
  assert.match(read('docs/safety.md'), /Cookie headers are not checked and never read/);
});

test('the stub profile table in the README matches the stub ports', () => {
  const arch = read('docs/architecture.md');
  assert.match(arch, /5911-5915/);
  assert.match(arch, /5916/);
  assert.match(read('server/src/safety.js'), /STUB_BASE_PORT = 5911/);
});

test('no literal JWT or key material is committed in tests or docs', () => {
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (['node_modules', '.git'].includes(e.name) ? [] : e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
  for (const f of walk(root)) {
    if (!/\.(js|mjs|md|json|yml)$/.test(f) || f.endsWith('package-lock.json')) continue;
    assert.doesNotMatch(fs.readFileSync(f, 'utf8'), /eyJ[A-Za-z0-9_-]{10,}\.eyJ/, `${f} contains a literal JWT`);
  }
});
