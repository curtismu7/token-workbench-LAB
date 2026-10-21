// The only outbound HTTP client. Loopback http only (policy.js), no redirect following, short timeout, capped body.
// It sends only the headers it is given; it never adds credentials.
import http from 'node:http';
import { evaluateTarget, REFUSAL_TEXT } from './policy.js';

export class TargetRefused extends Error {
  constructor(reason) { super(REFUSAL_TEXT[reason] || 'target refused'); this.name = 'TargetRefused'; this.code = 'target_refused'; this.reason = reason; }
}

export function loopbackRequest(target, { method = 'GET', headers = {}, body, timeoutMs = 2000, maxBytes = 65536 } = {}) {
  const ev = evaluateTarget(target);
  if (!ev.allowed) return Promise.reject(new TargetRefused(ev.reason));
  const url = new URL(ev.normalizedUrl);
  const hostname = url.hostname === 'localhost' ? '127.0.0.1' : url.hostname.replace(/^\[|\]$/g, '');
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(body);
    const req = http.request({
      hostname, port: url.port || 80, path: `${url.pathname}${url.search}`, method, agent: false, timeout: timeoutMs,
      headers: { connection: 'close', ...headers, ...(payload ? { 'content-length': payload.length } : {}) },
    }, (res) => {
      const chunks = []; let size = 0; let truncated = false;
      res.on('data', (c) => {
        size += c.length;
        if (size > maxBytes) { truncated = true; res.destroy(); return; }
        chunks.push(c);
      });
      const done = () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8'), truncated });
      res.on('end', done);
      res.on('close', done);
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    req.on('error', (e) => reject(Object.assign(new Error(e.code || 'request failed'), { code: e.code || 'request_failed' })));
    if (payload) req.write(payload);
    req.end();
  });
}

export const parseJson = (text) => { try { return JSON.parse(text); } catch { return null; } };
