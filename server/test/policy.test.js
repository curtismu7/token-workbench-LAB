import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateTarget } from '../src/policy.js';
import { loopbackRequest, TargetRefused } from '../src/http.js';
import { isLoopbackHost, parseHost, portInRange, assertBindAllowed } from '../src/safety.js';

test('the target policy allows http loopback hosts only', () => {
  for (const ok of ['http://127.0.0.1:5911', 'http://localhost:5911/x', 'http://[::1]:5911', 'http://127.1.2.3/']) assert.equal(evaluateTarget(ok).allowed, true, ok);
  const refused = {
    'https://127.0.0.1:5911': 'unsupported_scheme', 'ftp://127.0.0.1': 'unsupported_scheme', 'not a url': 'invalid_url',
    'http://example.com': 'not_loopback', 'http://127.0.0.1.evil.com': 'not_loopback', 'http://localhost.evil.com': 'not_loopback',
    'http://10.0.0.5': 'not_loopback', 'http://192.168.1.1': 'not_loopback', 'http://169.254.169.254': 'not_loopback', 'http://0.0.0.0': 'not_loopback',
    'http://[::ffff:8.8.8.8]': 'not_loopback', 'http://user:pw@127.0.0.1:5911': 'credentials_not_allowed',
  };
  for (const [url, reason] of Object.entries(refused)) {
    const ev = evaluateTarget(url);
    assert.equal(ev.allowed, false, url);
    assert.equal(ev.reason, reason, url);
  }
});

test('the HTTP client refuses a remote target before any socket is opened', async () => {
  for (const url of ['http://example.com/', 'http://10.1.2.3:80/', 'https://127.0.0.1:5911/']) {
    await assert.rejects(loopbackRequest(url), (e) => e instanceof TargetRefused);
  }
});

test('loopback and port-range helpers', () => {
  assert.equal(isLoopbackHost('127.0.0.1'), true);
  assert.equal(isLoopbackHost('128.0.0.1'), false);
  assert.equal(portInRange(5910), true);
  assert.equal(portInRange(5899), false);
  assert.equal(portInRange(6000), false);
  assert.equal(parseHost('127.999.999.999'), null);
  assert.throws(() => assertBindAllowed('0.0.0.0', {}), /loopback only/);
  assert.equal(assertBindAllowed('0.0.0.0', { TW_BIND: '0.0.0.0' }), '0.0.0.0');
});
