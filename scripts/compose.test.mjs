import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';

// Every published port must be bound to loopback on the host. A small line parser (no YAML dependency):
// the list items under each `ports:` key.
export function publishedPorts(text) {
  const out = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)ports:\s*$/.exec(lines[i]);
    if (!m) continue;
    for (let j = i + 1; j < lines.length; j++) {
      const item = /^\s*-\s*["']?([^"'\s#]+)["']?/.exec(lines[j]);
      if (!item || lines[j].search(/\S/) <= m[1].length) break;
      out.push(item[1]);
    }
  }
  return out;
}

const compose = fs.readFileSync(new URL('../docker-compose.yml', import.meta.url), 'utf8');
const code = compose.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');

test('docker-compose.yml publishes only on 127.0.0.1, in 5900-5999', () => {
  const ports = publishedPorts(compose);
  assert.ok(ports.length > 0, 'the parser found the published port');
  for (const p of ports) {
    assert.match(p, /^127\.0\.0\.1:/, `${p} must start with 127.0.0.1:`);
    for (const n of p.replace(/^127\.0\.0\.1:/, '').match(/\d+/g).map(Number)) assert.ok(n >= 5900 && n <= 5999, `${p}: port ${n} outside 5900-5999`);
  }
});

test('the parser flags an unbound or wildcard publish', () => {
  for (const bad of ['- "5910:5910"', '- "0.0.0.0:5910:5910"', '- 5910']) {
    const ports = publishedPorts(`services:\n  a:\n    ports:\n      ${bad}\n`);
    assert.equal(ports.length, 1);
    assert.doesNotMatch(ports[0], /^127\.0\.0\.1:/);
  }
});

test('compose gives the container no host access: no mounts, docker socket, host network, privilege or live mode', () => {
  assert.doesNotMatch(code, /^\s*volumes:/m);
  assert.doesNotMatch(code, /docker\.sock/);
  assert.doesNotMatch(code, /network_mode|privileged|pid:\s*host|TW_LIVE/);
  assert.match(code, /read_only:\s*true/);
  assert.match(code, /cap_drop:\s*\[ALL\]/);
  assert.match(code, /no-new-privileges:true/);
});

test('the Dockerfile runs as non-root and carries no host-inspection tools', () => {
  const df = fs.readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8').split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  assert.match(df, /^USER node$/m);
  assert.doesNotMatch(df, /docker-cli|lsof|procps/);
});

test('the Dockerfile installs production dependencies only, ships server/src, and sets no live mode', () => {
  const df = fs.readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8').split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  assert.match(df, /npm ci --omit=dev/);
  assert.match(df, /COPY server\/src server\/src/);
  assert.doesNotMatch(df, /TW_LIVE/);
});

test('the healthcheck uses /api/health, in compose and in the image', () => {
  assert.match(code, /\/api\/health/);
  const df = fs.readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8').split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  assert.match(df, /^HEALTHCHECK .*\/api\/health/m);
});

test('the Dockerfile builds web/dist in a first stage and ships it; no key, cert or env file is copied in', () => {
  const df = fs.readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8').split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  assert.match(df, /^FROM node:\S+ AS build$/m);
  assert.match(df, /RUN npm run build -w web/);
  assert.match(df, /COPY --from=build \/app\/web\/dist web\/dist/);
  assert.equal((df.match(/^FROM /gm) || []).length, 2);
  assert.doesNotMatch(df, /COPY\s+(?:--\S+\s+)*\.\s/, 'no wholesale COPY . (it would bake in anything in the checkout)');
  assert.doesNotMatch(df, /\.(pem|key|p12|env)\b|COPY .*\.env/);
  const ignore = fs.readFileSync(new URL('../.dockerignore', import.meta.url), 'utf8');
  for (const pat of ['.env', '*.pem', '*.key', 'node_modules', '.git']) assert.ok(ignore.split('\n').includes(pat), `.dockerignore lists ${pat}`);
});

test('the image runs on the documented port only (EXPOSE 5910, TW_PORT 5910)', () => {
  const df = fs.readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8');
  assert.match(df, /^EXPOSE 5910$/m);
  assert.match(df, /TW_PORT=5910/);
  assert.doesNotMatch(df, /EXPOSE (?!5910$)/m);
});

test('docker-compose.yml passes a usable SHELF_URL into the container (the shelf button needs it)', () => {
  assert.match(compose, /^\s*SHELF_URL: \$\{SHELF_URL:-http:\/\/127\.0\.0\.1:4400\}\s*$/m);
});
