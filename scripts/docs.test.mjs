import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const root = new URL('..', import.meta.url).pathname;
const docs = ['README.md', 'docs/safety.md', 'docs/architecture.md', 'docs/k8s.md'];
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

test('the docs state the Mock default and the Real opt-in, mark FAPI UNVERIFIED and explain why remote targets are refused', () => {
  const readme = read('README.md');
  assert.match(readme, /Mock is the default; Real stays off unless the owner sets/);
  assert.match(readme, /## Real mode/);
  for (const name of ['TW_REAL', 'TW_REAL_ISSUER', 'TW_REAL_CLIENT_ID', 'TW_REAL_CLIENT_SECRET', 'TW_REAL_SCOPE', 'TW_REAL_TOKEN_AUTH']) {
    assert.match(readme, new RegExp(`\\| \`${name}\` \\|`), `README documents ${name}`);
    assert.match(read('.env.example'), new RegExp(`^${name}=`, 'm'), `.env.example lists ${name}`);
  }
  assert.doesNotMatch(read('.env.example'), /^TW_REAL_CLIENT_(ID|SECRET)=\S/m, '.env.example carries no client id or secret value');
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

test('CLAUDE.md and the talk track exist and mention the app port', () => {
  for (const f of ['CLAUDE.md', 'docs/talk-track.md']) {
    assert.ok(fs.existsSync(path.join(root, f)), `${f} is missing`);
    assert.match(read(f), /5910/, `${f} does not mention port 5910`);
  }
});

test('docs/k8s.md covers the rule 18 build: refused live features, isolation, the owner approval and residual risks', () => {
  const k = read('docs/k8s.md');
  for (const re of [/MODE=se-mock/, /owner-approved/i, /OWNER_APPROVED=1/, /Residual risks/, /X-Workspace-Id/, /hosted_build/, /HOSTED SIMULATION/, /Every piece of state/, /UNVERIFIED/]) assert.match(k, re);
  for (const f of ['server/src/keys.js', 'server/src/runtime.js', 'server/src/stubs/authserver.js', 'server/src/stubs/resource.js', 'server/src/checker.js', 'server/src/health.js', 'server/src/workspaces.js']) assert.ok(k.includes(f), `state table misses ${f}`);
});
