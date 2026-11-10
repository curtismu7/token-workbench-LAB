// The netguard: the only door to a real server. Real mode (owner opt-in, real.js) hands every outbound request to the
// request() here, and here only. In Mock mode every request is refused before the real fetch is reached, so Mock opens no
// socket off loopback at all. In Real mode a request may go to exactly one origin: the configured issuer's (https, no
// credentials in the URL). Redirects are reported, never followed; every exchange has a total deadline and a body cap.
// It counts what it did, for the self-test, the doctor and the tests.

export const TIMEOUT_MS = 10_000;
export const MAX_BODY_BYTES = 256 * 1024;

export class NetguardRefused extends Error {
  constructor(reason, message) { super(message); this.name = 'NetguardRefused'; this.code = 'netguard_refused'; this.reason = reason; }
}

// mode: () => 'mock' | 'real'. allowedOrigin: the configured issuer's origin, or null when Real is not configured.
export function createNetguard({ mode, allowedOrigin = null, realFetch = globalThis.fetch, timeoutMs = TIMEOUT_MS, maxBytes = MAX_BODY_BYTES }) {
  const stats = { realCalls: 0, refused: 0 };

  // Synchronous policy: throws NetguardRefused, returns the parsed URL when the request may go out.
  function check(target) {
    const refuse = (reason, message) => { stats.refused += 1; throw new NetguardRefused(reason, message); };
    if (mode() !== 'real') refuse('mock_mode', 'Mock mode: no real outbound calls');
    if (!allowedOrigin) refuse('not_configured', 'Real is not configured, so no outbound call is allowed');
    let url;
    try { url = new URL(target); } catch { return refuse('bad_url', 'Not a URL'); }
    if (url.protocol !== 'https:') refuse('not_https', 'Outbound calls are https only');
    if (url.username || url.password) refuse('credentials_in_url', 'Outbound URLs must not carry credentials');
    if (url.origin !== allowedOrigin) refuse('other_origin', 'Outbound calls may only reach the configured issuer');
    return url;
  }

  async function readCapped(response) {
    if (!response.body) return { text: '', truncated: false };
    const reader = response.body.getReader();
    const chunks = []; let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (total + value.length > maxBytes) { chunks.push(value.subarray(0, maxBytes - total)); await reader.cancel().catch(() => {}); return { text: Buffer.concat(chunks).toString('utf8'), truncated: true }; }
      chunks.push(value); total += value.length;
    }
    return { text: Buffer.concat(chunks).toString('utf8'), truncated: false };
  }

  // -> { status, headers (Headers), text, truncated, redirect (true when a 3xx was not followed) }
  async function request(target, { method = 'GET', headers = {}, body } = {}) {
    const url = check(target);
    stats.realCalls += 1;
    let response;
    try {
      response = await realFetch(url.toString(), { method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
    } catch {
      throw Object.assign(new Error('the issuer did not answer'), { code: 'unreachable' });
    }
    let read;
    try { read = await readCapped(response); } catch { throw Object.assign(new Error('the issuer stopped answering mid-reply'), { code: 'unreachable' }); }
    return { status: response.status, headers: response.headers, ...read, redirect: response.status >= 300 && response.status < 400 };
  }

  // Proves the guard holds without touching the network: a foreign origin is refused in every mode, and in Mock mode
  // even the configured issuer is refused. Never calls the real fetch; leaves the counters as they were.
  function selfTest() {
    const before = { ...stats };
    const refuses = (u) => { try { check(u); return false; } catch (e) { return e instanceof NetguardRefused; } };
    const checks = [
      { name: 'a foreign origin is refused', ok: refuses('https://other-host.invalid/') },
      { name: 'plain http is refused', ok: refuses(allowedOrigin ? allowedOrigin.replace(/^https:/, 'http:') : 'http://idp.invalid/') },
    ];
    if (mode() !== 'real') checks.push({ name: 'Mock mode refuses even the configured issuer', ok: refuses(allowedOrigin || 'https://idp.invalid/') });
    checks.push({ name: 'the real fetch was not called by the self-test', ok: stats.realCalls === before.realCalls });
    Object.assign(stats, before);
    return { ok: checks.every((c) => c.ok), checks };
  }

  return { check, request, selfTest, stats: () => ({ ...stats }), allowedOrigin };
}
