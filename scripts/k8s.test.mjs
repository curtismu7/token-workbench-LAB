// Rule 18 (mock-only SE build): the manifests keep their safety properties. Text checks, no cluster, no yaml dependency.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const read = (f) => fs.readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
const dep = read('k8s/deployment.yaml');
const FILES = ['k8s/deployment.yaml', 'k8s/service.yaml', 'k8s/ingress.yaml'];
const run = (args, env) => spawnSync('bash', ['k8s/deploy.sh', ...args], { cwd: new URL('..', import.meta.url).pathname, env: { PATH: process.env.PATH, ...env }, encoding: 'utf8' });

test('the deployment is mock-only (MODE=se-mock), non-root, read-only, limited, one replica and probed on /api/health', () => {
  for (const re of [/name: MODE, value: se-mock/, /runAsNonRoot: true/, /readOnlyRootFilesystem: true/, /allowPrivilegeEscalation: false/, /drop: \["ALL"\]/,
    /limits: \{ cpu: \d+m, memory: \d+Mi \}/, /requests: \{ cpu: \d+m, memory: \d+Mi \}/, /automountServiceAccountToken: false/, /seccompProfile/,
    /name: TW_PUBLIC_ORIGIN, value: "https:\/\/__SE_HOST__"/, /containerPort: 5910/]) assert.match(dep, re);
  assert.match(dep, /readinessProbe:\n\s+httpGet: \{ path: \/api\/health/);
  assert.match(dep, /livenessProbe:\n\s+httpGet: \{ path: \/api\/health/);
  assert.equal((dep.match(/path: \/api\/health/g) || []).length, 2, 'readiness and liveness');
  assert.match(dep, /replicas: 1\b/);
  assert.match(dep, /image: __IMAGE__/);
  assert.doesNotMatch(dep, /image: \S*:(latest|HEAD)\b/);
  assert.doesNotMatch(dep, /MODE, value: (local|live|prod|mock)\b/i);
});

test('no hostPath, privileged container, host network, added capability, secret or real host sits in the manifests', () => {
  for (const f of [...FILES, 'k8s/deploy.sh']) {
    const t = read(f);
    assert.doesNotMatch(t, /hostPath|hostNetwork|hostPID|hostIPC|privileged: true|add: \[|secretKeyRef|kind: Secret|password|(^|\s)token:|apiKey|ping-devops|ghcr\.io\/[a-z]|docker\.sock/i, f);
    assert.doesNotMatch(t, /runAsUser: 0\b|runAsNonRoot: false|readOnlyRootFilesystem: false|allowPrivilegeEscalation: true/, f);
  }
  assert.match(read('k8s/ingress.yaml'), /host: __SE_HOST__/, 'the host is supplied, never defaulted');
});

test('manifests use only the __IMAGE__ / __SE_HOST__ tokens: no namespace field, no ${...} forms', () => {
  for (const f of FILES) {
    const t = read(f);
    assert.doesNotMatch(t, /^\s*namespace:/m, f);
    assert.doesNotMatch(t, /\$\{[^}]*\}/, f);
    for (const tok of t.match(/__[A-Z0-9_]+__/g) || []) assert.ok(['__IMAGE__', '__SE_HOST__'].includes(tok), `${f}: ${tok}`);
  }
  assert.doesNotMatch(read('k8s/deploy.sh'), /envsubst/);
});

test('the Dockerfile is one image for both forms: two stages, non-root, MODE not forced to se-mock (local is the default)', () => {
  const d = read('Dockerfile');
  assert.equal((d.match(/^FROM /gm) || []).length, 2, 'the same two stages as standalone');
  assert.match(d, /USER node/);
  assert.doesNotMatch(d, /MODE=/);
  assert.doesNotMatch(read('docker-compose.yml'), /MODE/);
});

const ok = { NAMESPACE: 'demo-ns', IMAGE: 'registry.example/team/token-workbench:abc1234', SE_HOST: 'workbench.demo.example' };
const without = (k) => { const e = { ...ok }; delete e[k]; return e; };

test('deploy.sh --dry-run renders with valid values: exit 0, no token left, image and host present, no approval or kubectl needed', () => {
  const r = run(['--dry-run'], ok);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /image: registry\.example\/team\/token-workbench:abc1234/);
  assert.match(r.stdout, /host: workbench\.demo\.example/);
  assert.match(r.stdout, /value: "https:\/\/workbench\.demo\.example"/);
  assert.match(r.stdout, /no cluster contacted/);
  assert.doesNotMatch(r.stdout, /__[A-Z0-9_]+__|\$\{/);
  assert.doesNotMatch(r.stdout, /^\s*namespace:/m);
});

test('deploy.sh needs an explicit flag, and --apply needs the owner approval before anything else (the test never runs --apply with approval, so kubectl is never reached)', () => {
  assert.equal(run([], ok).status, 2, 'no flag');
  assert.equal(run(['--bogus'], ok).status, 2);
  for (const OWNER_APPROVED of [undefined, '0', 'yes', '']) {
    const r = run(['--apply'], { ...ok, ...(OWNER_APPROVED === undefined ? {} : { OWNER_APPROVED }) });
    assert.equal(r.status, 2, String(OWNER_APPROVED));
    assert.match(r.stderr, /owner-approved/);
  }
});

test('deploy.sh refuses a missing value, a mutable or malformed image, or a bad host or namespace', () => {
  for (const k of ['NAMESPACE', 'IMAGE', 'SE_HOST']) assert.notEqual(run(['--dry-run'], without(k)).status, 0, `missing ${k}`);
  for (const IMAGE of ['registry.example/x:latest', 'registry.example/x:HEAD', 'registry.example/x', 'registry.example/x:', 'reg;rm/x:1', 'reg|x/y:1', 'reg/x:1\nfoo']) assert.equal(run(['--dry-run'], { ...ok, IMAGE }).status, 2, JSON.stringify(IMAGE));
  for (const SE_HOST of ['Bad Host', 'a|b.example', 'a/b.example', 'a&b.example', 'a\\b.example', 'a.example\nb.example', '']) assert.notEqual(run(['--dry-run'], { ...ok, SE_HOST }).status, 0, JSON.stringify(SE_HOST));
  for (const NAMESPACE of ['', 'Demo', '-ns', 'ns-', 'a_b', 'a.b', 'a|b', 'ns\nx', 'a'.repeat(64)]) assert.notEqual(run(['--dry-run'], { ...ok, NAMESPACE }).status, 0, JSON.stringify(NAMESPACE));
});

test('deploy.sh --dry-run fails when a rendered manifest keeps a stray __TOKEN__ (temp copy, tracked files untouched)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'k8s-copy-'));
  try {
    fs.cpSync(fileURLToPath(new URL('../k8s', import.meta.url)), tmp, { recursive: true });
    fs.appendFileSync(path.join(tmp, 'service.yaml'), '# stray __EXTRA_TOKEN__\n');
    const r = spawnSync('bash', [path.join(tmp, 'deploy.sh'), '--dry-run'], { env: { PATH: process.env.PATH, ...ok }, encoding: 'utf8' });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /__EXTRA_TOKEN__/);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('deploy.sh refuses an untagged image whose registry has a port, and a malformed host; manifest comments do not contain raw tokens', () => {
  let r = run(['--dry-run'], { ...ok, IMAGE: 'r.example:5000/a' });
  assert.equal(r.status, 2, r.stderr); assert.match(r.stderr, /no tag/);
  assert.equal(run(['--dry-run'], { ...ok, IMAGE: 'r.example:5000/a:1' }).status, 0);
  for (const h of ['..', '.a', 'a..b', '-a', 'a-']) assert.equal(run(['--dry-run'], { ...ok, SE_HOST: h }).status, 2, h);
  r = run(['--dry-run'], ok);
  assert.equal(r.status, 0);
  assert.doesNotMatch(r.stdout, /^#.*__[A-Z_]+__/m);
});
