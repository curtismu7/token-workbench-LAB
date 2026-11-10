#!/usr/bin/env node
// Real-browser run of REAL mode, without any real tenant: the lab runs in this process with TW_REAL settings pointing at
// https://idp.example/as, and its netguard is handed a fetch that maps exactly that origin to a stub issuer on loopback
// (discovery, JWKS, client_credentials, introspection). Anything else is refused and counted. Drives headless Chromium in
// light at 1280px and dark at 375px: REAL banner and badge, REAL token label, trace with the secret only as a marker,
// JWKS verify, introspection, metadata-only checker, stubs-only notes, toggle both ways, no secret in the DOM.
//
//   npm run build && npm run e2e:real      (ports 5920-5926; E2E_SHOTS=<dir> for screenshots)
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { startHttpServer } from '../server/src/app.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const shots = process.env.E2E_SHOTS || path.join(root, '.data', 'e2e-screenshots');
if (!fs.existsSync(path.join(root, 'web', 'dist', 'index.html'))) { console.error('Run `npm run build` first.'); process.exit(2); }
fs.mkdirSync(shots, { recursive: true });
let failures = 0;
const check = (ok, what) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${what}`); if (!ok) failures += 1; };

const ISSUER = 'https://idp.example/as';
const SECRET = `e2e~${crypto.randomBytes(9).toString('base64url')}`; // made up per run; never a real credential
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'e2e-1', alg: 'RS256' };
const b64u = (b) => Buffer.from(b).toString('base64url');
const issued = new Set();
const stub = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const j = (s, o) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (req.url === '/as/.well-known/openid-configuration') return j(200, { issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token`, jwks_uri: `${ISSUER}/jwks`, introspection_endpoint: `${ISSUER}/introspect`, response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'client_credentials'], code_challenge_methods_supported: ['S256'] });
    if (req.url === '/as/jwks') return j(200, { keys: [jwk] });
    if (req.url === '/as/token') {
      if (req.headers.authorization !== `Basic ${Buffer.from(`e2e-client:${encodeURIComponent(SECRET)}`).toString('base64')}`) return j(401, { error: 'invalid_client' });
      const now = Math.floor(Date.now() / 1000);
      const input = `${b64u(JSON.stringify({ alg: 'RS256', kid: 'e2e-1' }))}.${b64u(JSON.stringify({ iss: ISSUER, sub: 'e2e-client', client_id: 'e2e-client', aud: 'https://api.example', scope: 'tw:read', iat: now, exp: now + 3600 }))}`;
      const t = `${input}.${b64u(crypto.sign('sha256', Buffer.from(input), privateKey))}`;
      issued.add(t);
      return j(200, { access_token: t, token_type: 'Bearer', expires_in: 3600 });
    }
    if (req.url === '/as/introspect') return j(200, { active: issued.has(new URLSearchParams(body).get('token')) });
    return j(404, { error: 'not_found' });
  });
});
await new Promise((r) => { stub.listen(0, '127.0.0.1', r); });
const foreign = [];
const realFetch = (url, init) => {
  const u = new URL(url);
  if (u.origin !== 'https://idp.example') { foreign.push(url); return Promise.reject(new Error('foreign host')); }
  return fetch(`http://127.0.0.1:${stub.address().port}${u.pathname}${u.search}`, init);
};
const env = { ...process.env, TW_REAL: '1', TW_REAL_ISSUER: ISSUER, TW_REAL_CLIENT_ID: 'e2e-client', TW_REAL_CLIENT_SECRET: SECRET, TW_REAL_SCOPE: '', TW_REAL_TOKEN_AUTH: '' };
const app = await startHttpServer({ port: 5920, stubBase: 5921, env, realFetch });
const browser = await chromium.launch({ executablePath: process.env.E2E_CHROMIUM || undefined });
const secretForms = [SECRET, encodeURIComponent(SECRET), Buffer.from(`e2e-client:${encodeURIComponent(SECRET)}`).toString('base64')];
try {
  for (const [scheme, width] of [['light', 1280], ['dark', 375]]) {
    const page = await browser.newPage({ viewport: { width, height: 900 }, colorScheme: scheme });
    const errors = []; const offOrigin = [];
    page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    page.on('pageerror', (e) => errors.push(e.message));
    page.on('request', (r) => { if (!r.url().startsWith(app.url.replace(/\/$/, '')) && !/^(data|blob):/.test(r.url())) offOrigin.push(r.url()); });
    const tag = `[${scheme} ${width}px]`;
    await page.goto(app.url);
    await page.getByTestId('mode-banner').filter({ hasText: 'REAL:' }).waitFor();
    check(await page.evaluate(() => document.querySelector('.banner')?.dataset.state === 'live'), `${tag} the REAL banner is first and marked live`);
    check((await page.getByTestId('mode-badge').innerText()).startsWith('REAL'), `${tag} the header badge says REAL`);
    check((await page.getByTestId('mode-real').getAttribute('aria-pressed')) === 'true', `${tag} the toggle shows Real pressed`);
    await page.getByRole('button', { name: 'REAL client_credentials token' }).click();
    await page.getByTestId('trace').waitFor();
    check((await page.getByTestId('token-label').innerText()) === 'REAL', `${tag} the issued token is labelled REAL`);
    await page.locator('[data-testid=trace] li[data-step="token (client_credentials)"] summary', { hasText: 'Request' }).click();
    check((await page.getByTestId('trace').innerText()).includes('Basic [client secret: write-only, not shown]'), `${tag} the trace shows the client authentication as a write-only marker`);
    await page.getByLabel("Verify the signature against the issuer's real JWKS").check();
    await page.getByRole('button', { name: 'Decode', exact: true }).click();
    await page.locator('.badge', { hasText: "Signature valid (issuer's real JWKS)" }).waitFor();
    check(true, `${tag} the token verifies against the issuer's JWKS`);
    await page.getByRole('button', { name: 'Introspect at the issuer' }).click();
    const ir = await page.getByTestId('introspect-result').innerText();
    check(/ACTIVE/.test(ir) && /REAL/.test(ir) && !/NOT ACTIVE/.test(ir), `${tag} introspection at the issuer says ACTIVE, REAL`);
    await page.screenshot({ path: path.join(shots, `real-decode-${scheme}.png`), fullPage: true });
    check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${tag} no horizontal page scroll on Decode / Trace with the trace open`);
    await page.getByRole('button', { name: 'Profile checker', exact: true }).click();
    await page.getByRole('button', { name: "Check the issuer's metadata" }).click();
    await page.getByTestId('checker-result').waitFor();
    check((await page.getByText('NOT CHECKED', { exact: true }).count()) > 0 && (await page.getByRole('radio').count()) === 0, `${tag} the checker judges metadata only, with NOT CHECKED rules and no stub choice`);
    await page.screenshot({ path: path.join(shots, `real-checker-${scheme}.png`), fullPage: true });
    await page.getByRole('button', { name: 'Wrong-token tester', exact: true }).click();
    check(await page.getByTestId('real-note').first().isVisible(), `${tag} the tester says it has no Real version`);
    const html = await page.content();
    check(secretForms.every((f) => !html.includes(f)), `${tag} the client secret is nowhere in the page`);
    await page.getByTestId('mode-mock').click();
    await page.getByTestId('mode-banner').filter({ hasText: 'MOCK:' }).waitFor();
    await page.getByRole('button', { name: 'Decode / Trace', exact: true }).click();
    check((await page.getByTestId('trace').count()) === 0 && (await page.getByRole('button', { name: 'DPoP-bound' }).count()) === 1, `${tag} switching to Mock clears the REAL trace and brings back the stub samples`);
    await page.getByTestId('mode-real').click();
    await page.getByTestId('mode-banner').filter({ hasText: 'REAL:' }).waitFor();
    check(true, `${tag} switching back to Real works without a restart`);
    check(offOrigin.length === 0, `${tag} the browser made no off-origin request ${JSON.stringify(offOrigin)}`);
    check(errors.length === 0, `${tag} no page or console errors ${JSON.stringify(errors)}`);
    await page.close();
  }
  check(foreign.length === 0, `the lab never asked for any host but the configured issuer ${JSON.stringify(foreign)}`);
} catch (e) {
  console.error(e); failures += 1;
} finally {
  await browser.close(); await app.close(); stub.close();
}
console.log(failures ? `\n${failures} check(s) FAILED` : '\nall checks passed');
process.exit(failures ? 1 : 0);
