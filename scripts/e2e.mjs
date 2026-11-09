#!/usr/bin/env node
// Real-browser run of the web UI against the real server, which serves the UI itself (server/src/index.js): all four tabs,
// keyboard-only reach, hostile text shown as text, Simulate/Reset on the diagram, dark and light screenshots, no console
// errors, no request that leaves the origin, no horizontal scroll at 390px.
//
//   npm run build            (once; the server serves web/dist)
//   npm run e2e              starts the server on E2E_PORT (default 5940; the stubs use 5911-5916), drives it, stops it
//   E2E_SHOTS=/some/dir      where screenshots go (default .data/e2e-screenshots, git-ignored)
//
// Uses the Chromium the installed Playwright resolves (`npx playwright install chromium` if missing). Stop any other
// running token-workbench first: the stub ports are fixed.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const shots = process.env.E2E_SHOTS || path.join(root, '.data', 'e2e-screenshots');
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
let failures = 0;
const check = (ok, what) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${what}`); if (!ok) failures += 1; };

const port = Number(process.env.E2E_PORT) || 5940;
if (!(port >= 5900 && port <= 5999)) { console.error('E2E_PORT must be in 5900-5999'); process.exit(2); }
const base = `http://127.0.0.1:${port}`;
if (!fs.existsSync(path.join(root, 'web', 'dist', 'index.html'))) { console.error('Run `npm run build` first.'); process.exit(2); }
// The stub ports are fixed (5911-5916): say so plainly instead of printing a stack trace if something already holds one.
const busy = [];
for (let p = 5911; p <= 5916; p += 1) if (!await new Promise((res) => { const s = net.createServer(); s.once('error', () => res(false)); s.listen(p, '127.0.0.1', () => s.close(() => res(true))); })) busy.push(p);
if (busy.length) { console.error(`stub port(s) ${busy.join(', ')} are in use (another token-workbench or e2e run?). Stop it and retry.`); process.exit(2); }
// Mock only: any Real setting from the shell or the lab's .env is blanked (an empty value is not an opt-in and is not
// overwritten by the .env file), so this run never contacts a real issuer.
const realBlank = Object.fromEntries(['TW_REAL', 'TW_REAL_ISSUER', 'TW_REAL_CLIENT_ID', 'TW_REAL_CLIENT_SECRET', 'TW_REAL_SCOPE', 'TW_REAL_TOKEN_AUTH'].map((k) => [k, '']));
const server = spawn(process.execPath, ['server/src/index.js'], { cwd: root, env: { ...process.env, ...realBlank, TW_PORT: String(port) }, stdio: 'inherit' });
let up = false;
for (let i = 0; i < 60 && !up; i++) { try { up = (await fetch(`${base}/api/health`)).ok; } catch { await sleep(250); } }
if (!up) { server.kill(); console.error('server did not start'); process.exit(2); }
fs.mkdirSync(shots, { recursive: true });

const browser = await chromium.launch({ executablePath: process.env.E2E_CHROMIUM || undefined });
try {
  const page = await browser.newPage({ viewport: { width: 1360, height: 900 }, colorScheme: 'light' });
  const external = []; const errors = []; const dialogs = [];
  page.on('request', (r) => { if (!r.url().startsWith(base) && !/^(data|blob):/.test(r.url())) external.push(r.url()); });
  page.on('pageerror', (e) => errors.push(e.message));
  const badApi = []; // non-2xx API answers; the browser logs each as a console error, so the ones the run causes on purpose are matched below
  page.on('response', (r) => { if (r.url().startsWith(base) && r.status() >= 400) badApi.push(`${r.status()} ${new URL(r.url()).pathname}`); });
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('dialog', (d) => { dialogs.push(d.message()); d.dismiss(); });
  const shot = (name) => page.screenshot({ path: path.join(shots, `${name}.png`), fullPage: true });
  const active = () => page.evaluate(() => `${document.activeElement?.tagName}|${document.activeElement?.textContent?.trim().slice(0, 40)}`);
  const live = () => page.getByTestId('live');
  const tab = (name) => page.getByRole('button', { name, exact: true });
  const noHScroll = () => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);

  const resp = await page.goto(`${base}/`);
  const csp = resp.headers()['content-security-policy'] || '';
  check(/default-src 'self'/.test(csp) && !/unsafe-eval/.test(csp), 'the UI is served with a same-origin CSP');
  await page.getByTestId('mode-badge').waitFor();
  check((await page.getByTestId('mode-badge').innerText()).includes('DEMO'), 'header shows the DEMO badge');
  // Rule 19 without Real settings: MOCK banner first, Real disabled naming the settings, the "Real not configured" card.
  check(await page.evaluate(() => document.querySelector('.banner')?.dataset.testid === 'mode-banner' && document.querySelector('.banner').textContent.startsWith('MOCK:')), 'the MOCK banner is the first banner');
  await page.getByTestId('mode-mock').and(page.locator('[aria-pressed="true"]')).waitFor();
  check(await page.getByTestId('mode-real').isDisabled(), 'Real is disabled without the owner\'s settings');
  check(/TW_REAL_ISSUER/.test(await page.getByTestId('mode-real').getAttribute('title')), 'the Real button\'s tooltip names the settings');

  // Keyboard only: skip link, then Tab through the four tabs and the theme button.
  await page.keyboard.press('Tab');
  check((await active()).includes('Skip to content'), 'first Tab stop is the skip link');
  const reached = [];
  for (let i = 0; i < 8; i++) { await page.keyboard.press('Tab'); reached.push(await active()); }
  for (const n of ['Decode / Trace', 'Wrong-token tester', 'Profile checker', 'Flow catalog']) check(reached.some((r) => r.endsWith(`|${n}`)), `Tab reaches the "${n}" tab`);
  await page.getByTestId('real-status').locator('summary').click();
  const rs = await page.getByTestId('real-status').innerText();
  check(/Real not configured/.test(rs) && /TW_REAL_CLIENT_SECRET/.test(rs) && /docker-compose\.yml/.test(rs), 'the "Real not configured" card lists the settings and where they go');

  // 1. Decode: mint a DPoP token by keyboard-reachable button, then decode with verification.
  await page.getByRole('button', { name: 'DPoP-bound' }).focus();
  await page.keyboard.press('Enter');
  await page.getByTestId('decode-result').waitFor();
  check((await page.getByLabel('Token (JWT)').inputValue()).split('.').length === 3, 'minting fills the token box with a JWT');
  check((await page.getByTestId('decode-result').innerText()).includes('Signature NOT checked'), 'by default the signature is reported as not checked');
  check((await page.getByTestId('cnf-note').innerText()).toLowerCase().includes('not enforced'), 'cnf binding is explained as decoded, not enforced');
  check(/Expires in/.test(await page.getByTestId('countdown').innerText()), 'expiry countdown is shown');
  const t1 = await page.getByTestId('countdown').innerText();
  await sleep(2200);
  check((await page.getByTestId('countdown').innerText()) !== t1, 'the countdown ticks');
  await page.getByLabel('Verify the signature against the stub JWKS').check();
  await page.getByRole('button', { name: 'Decode', exact: true }).click();
  await page.locator('.badge', { hasText: 'Signature valid (stub JWKS)' }).waitFor();
  check(true, 'verify against the stub JWKS gives "Signature valid (stub JWKS)"');
  check((await page.locator('tbody tr').count()) >= 8, 'claims table has the claims with explanations');
  // Tamper: change one character of the payload and decode again.
  const tok = await page.getByLabel('Token (JWT)').inputValue();
  const [h, p, s] = tok.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString()); payload.scope = '<img src=x onerror=alert(1)> admin';
  await page.getByLabel('Token (JWT)').fill(`${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`);
  await page.getByRole('button', { name: 'Decode', exact: true }).click();
  await page.locator('.badge', { hasText: 'Signature INVALID' }).waitFor();
  check((await page.locator('main img').count()) === 0, 'a tampered token is flagged INVALID and its markup stays text (no <img> element)');
  check((await page.locator('code', { hasText: '<img src=x' }).count()) > 0, 'the hostile string is visible as text');
  await page.getByRole('button', { name: 'DPoP-bound' }).click();
  await page.locator('.badge', { hasText: 'Signature valid (stub JWKS)' }).waitFor();
  check((await page.getByTestId('token-label').innerText()) === 'MOCK', 'a minted stub token is labelled MOCK');
  await page.getByRole('button', { name: 'Introspect (stub issuer)' }).click();
  await page.getByTestId('introspect-result').waitFor();
  const ir = await page.getByTestId('introspect-result').innerText();
  check(/ACTIVE/.test(ir) && /MOCK/.test(ir) && !/NOT ACTIVE/.test(ir), 'mock introspection says ACTIVE and MOCK');
  await shot('1-decode-light');

  // 2. Wrong-token tester
  await tab('Wrong-token tester').click();
  await page.getByRole('button', { name: /Run all/ }).click();
  await page.getByTestId('tester-summary').waitFor();
  const sum = await page.getByTestId('tester-summary').innerText();
  check(/15 of 15 correct/.test(sum), `tester summary: "${sum}"`);
  check((await page.locator('tr[data-case]').count()) === 15, 'fifteen case rows');
  check((await page.locator('tr[data-case] .badge--ok').count()) === 15, 'every row says PASS');
  check((await live().innerText()).includes('15 of 15'), 'the result is announced in the live region');
  const row = page.locator('tr[data-case="wrong-audience"]');
  check((await row.innerText()).includes('401') && (await row.innerText()).includes('rejected by: aud'), 'wrong-audience row shows expected and actual with the rejecting check');
  await page.locator('tr.detail-row', { has: page.locator('summary', { hasText: 'Wrong audience' }) }).locator('summary').first().click();
  const det = await page.getByTestId('detail-wrong-audience').innerText();
  check(/WWW-Authenticate/.test(det) && /error="invalid_token"/.test(det) && /REJECTED HERE/.test(det), 'detail shows the WWW-Authenticate error and the check that rejected it');
  await shot('2-tester-light');

  // 3. Profile checker
  await tab('Profile checker').click();
  await page.getByRole('radio', { name: /No PKCE enforcement/ }).first().check();
  await page.getByRole('button', { name: 'Run checker' }).click();
  await page.getByTestId('checker-result').waitFor();
  check((await page.getByTestId('pack-fapi').innerText()).includes('UNVERIFIED'), 'the FAPI 2.0 pack carries the UNVERIFIED badge');
  check((await page.locator('tr[data-rule="pkce-required"]').innerText()).includes('FAIL'), 'no-pkce profile fails pkce-required, with evidence');
  check((await page.locator('tr[data-rule="metadata"]').innerText()).includes('PASS'), 'and passes metadata');
  await page.getByRole('radio', { name: /loopback URL/i }).check();
  await page.getByRole('textbox', { name: 'Loopback URL' }).fill('http://example.com');
  await page.getByRole('button', { name: 'Run checker' }).click();
  await page.getByRole('alert').waitFor();
  check(/loopback|refused|not allowed/i.test(await page.getByRole('alert').innerText()), `a non-loopback target is refused: "${await page.getByRole('alert').innerText()}"`);
  await shot('3-checker-light');

  // 4. Flow catalog
  await tab('Flow catalog').click();
  await page.getByTestId('compare').waitFor();
  check((await page.getByText('SIMULATION', { exact: true }).count()) === 1, 'SIMULATION badge is visible');
  check((await page.locator('[data-testid="compare"] tbody tr').count()) === 6, 'six mechanisms side by side');
  await page.locator('.react-flow__node').first().waitFor();
  await page.getByTestId('side-on').waitFor();
  check((await page.locator('.react-flow__node').count()) === 5, 'five diagram boxes');
  const node = page.locator('.react-flow__node', { hasText: 'Authorization server' }).first();
  await node.scrollIntoViewIfNeeded();
  const before = await node.boundingBox();
  await page.mouse.move(before.x + before.width / 2, before.y + before.height / 2);
  await page.mouse.down(); await page.mouse.move(before.x + before.width / 2 + 50, before.y + before.height / 2 + 70, { steps: 6 }); await page.mouse.up();
  const after = await node.boundingBox();
  check(Math.abs(after.x - before.x) > 15 || Math.abs(after.y - before.y) > 15, 'a box can be dragged');
  await page.getByLabel('Speed').selectOption('4');
  await page.getByRole('button', { name: 'Simulate' }).click();
  await page.getByTestId('caption').filter({ hasText: 'Step 1 of' }).waitFor();
  check((await page.locator('.fbox.on').count()) > 0, 'Simulate highlights boxes');
  await page.getByTestId('caption').filter({ hasText: /Attack (blocked|succeeded)/ }).waitFor({ timeout: 15000 });
  check(/Attack blocked/.test(await page.getByTestId('caption').innerText()), 'DPoP with protection ends with "Attack blocked"');
  await page.getByLabel(/With /).uncheck();
  await page.getByRole('button', { name: 'Simulate' }).click();
  await page.getByTestId('caption').filter({ hasText: /Attack succeeded/ }).waitFor({ timeout: 15000 });
  check(true, 'without protection the same attack succeeds');
  await shot('4-flows-light');
  await page.getByRole('button', { name: 'Reset', exact: true }).click();
  check((await page.getByTestId('caption').innerText()).includes('Press Simulate') && (await page.locator('.fbox.on').count()) === 0, 'Reset clears the diagram');
  await tab('Flow catalog').click();

  // Dark theme
  await page.getByTestId('theme').selectOption('dark'); // the theme control is a select (Auto / Light / Dark)
  check((await page.evaluate(() => document.documentElement.dataset.theme)) === 'dark', 'theme toggles to dark');
  await shot('5-flows-dark');
  await tab('Decode / Trace').click(); await shot('6-decode-dark');
  await tab('Wrong-token tester').click(); await shot('7-tester-dark');
  await tab('Profile checker').click(); await shot('8-checker-dark');

  // Narrow viewport on every tab
  await page.setViewportSize({ width: 390, height: 800 });
  for (const n of ['Decode / Trace', 'Wrong-token tester', 'Profile checker', 'Flow catalog']) {
    await tab(n).click();
    check(await noHScroll(), `no horizontal page scroll at 390px on "${n}"`);
  }
  await shot('9-phone-flows-dark');

  check(external.length === 0, `no request left the origin ${JSON.stringify(external)}`);
  const expectedRefusals = ['400 /api/checker/run']; // the non-loopback target we sent on purpose
  check(JSON.stringify(badApi) === JSON.stringify(expectedRefusals), `the only error answer was the deliberate target refusal ${JSON.stringify(badApi)}`);
  const unexpected = errors.filter((e) => !/^Failed to load resource: the server responded with a status of 400/.test(e));
  check(unexpected.length === 0 && errors.length === expectedRefusals.length, `no page or console errors besides the deliberate refusal ${JSON.stringify(errors)}`);
  check(dialogs.length === 0, 'no JavaScript dialog fired');
} catch (e) {
  console.error(e); failures += 1;
} finally {
  await browser.close();
  server.kill('SIGTERM');
}
console.log(failures ? `\n${failures} check(s) FAILED` : '\nall checks passed');
console.log(`screenshots: ${shots}`);
process.exit(failures ? 1 : 0);
