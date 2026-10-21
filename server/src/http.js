// The only outbound HTTP client. Loopback http only (policy.js), no redirect following, short timeout, capped body.
// It sends only the headers it is given; it never adds credentials.
import http from 'node:http';
import { evaluateTarget, REFUSAL_TEXT } from './policy.js';

export class TargetRefused extends Error {
  constructor(reason) { super(REFUSAL_TEXT[reason] || 'target refused'); this.name = 'TargetRefused'; this.code = 'target_refused'; this.reason = reason; }
}

// "localhost" is connected as 127.0.0.1 (it could resolve elsewhere); IPv6 brackets are stripped.
export const connectHostname = (h) => (h === 'localhost' ? '127.0.0.1' : h.replace(/^\[|\]$/g, ''));

export function loopbackRequest(target, { method = 'GET', headers = {}, body, timeoutMs = 2000, maxBytes = 65536 } = {}) {
  const ev = evaluateTarget(target);
  if (!ev.allowed) return Promise.reject(new TargetRefused(ev.reason));
  const url = new URL(ev.normalizedUrl);
  const hostname = connectHostname(url.hostname);
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(body);
    let settled = false; let timedOut = false;
    // timeoutMs is a TOTAL deadline for the whole exchange, not an idle timeout: a server that drips one byte at a time
    // cannot hold a run (and the shared run queue) past it.
    const deadline = setTimeout(() => { timedOut = true; req.destroy(); }, timeoutMs);
    const settle = (fn, v) => { if (settled) return; settled = true; clearTimeout(deadline); fn(v); };
    const fail = (code) => settle(reject, Object.assign(new Error(code), { code }));
    const req = http.request({
      hostname, port: url.port || 80, path: `${url.pathname}${url.search}`, method, agent: false,
      headers: { connection: 'close', ...headers, ...(payload ? { 'content-length': payload.length } : {}) },
    }, (res) => {
      const chunks = []; let size = 0; let truncated = false;
      res.on('data', (c) => {
        size += c.length;
        if (size > maxBytes) { truncated = true; res.destroy(); return; }
        chunks.push(c);
      });
      const done = () => (timedOut ? fail('ETIMEDOUT') : settle(resolve, { status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8'), truncated }));
      res.on('end', done);
      res.on('close', done);
    });
    req.on('error', (e) => fail(timedOut ? 'ETIMEDOUT' : e.code || 'request_failed'));
    if (payload) req.write(payload);
    req.end();
  });
}

export const parseJson = (text) => { try { return JSON.parse(text); } catch { return null; } };
