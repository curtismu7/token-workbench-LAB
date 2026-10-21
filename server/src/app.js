// One Express app: the API under /api. createApp() is what the tests use.
// Every server-provided string shown back is made inert (sanitize.js) and served as JSON only.
// The token under test is DATA in a JSON body: it is never read from a header, never logged, never sent anywhere
// except (for the tester) to the stub resource server on loopback.
import express from 'express';
import { createHealth } from './health.js';
import { createRuntime } from './runtime.js';
import { assertBindAllowed, bindHost, credentialGuard, hostGuard, originGuard, serverPort } from './safety.js';
import { explainClaims, parseJwt, timeStatus, verifyEs256, MAX_TOKEN_CHARS } from './jwt.js';
import { inertValue, revealText } from './sanitize.js';
import { caseList, runAll, runCase } from './tester.js';
import { BCP_RULES, FAPI_RULES, FAPI_NOTE, runChecker } from './checker.js';
import { PROFILES, PROFILE_ORDER } from './stubs/authserver.js';
import { compare, listMechanisms, runFlow } from './catalog.js';
import { TargetRefused } from './http.js';
import { evaluateTarget } from './policy.js';
import { ALLOWED_ALGS } from './validator.js';

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const bad = (res, message, status = 400, error) => res.status(status).json({ error: error || (status === 404 ? 'not_found' : 'bad_request'), message });
const API_HEADERS = { 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'", 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' };

// A POST body must be a plain JSON object with only the listed keys. Anything else (including a password or secret
// field) is refused, never ignored.
function takeBody(req, res, allowed) {
  const b = req.body ?? {};
  if (typeof b !== 'object' || Array.isArray(b) || b === null) { bad(res, 'the request body must be a JSON object'); return null; }
  const extra = Object.keys(b).filter((k) => !allowed.includes(k));
  if (extra.length) { bad(res, `unexpected field(s): ${extra.map((k) => revealText(k, 40)).join(', ')}. Allowed: ${allowed.join(', ') || 'none'}`); return null; }
  return b;
}

const SAMPLES = {
  agent: { title: 'Agent token (delegated, bearer)', make: (c, t) => ({ iss: c.ids.issuer, sub: 'user-123', aud: c.ids.resource, scope: 'mcp:tools', act: { sub: 'agent-7' }, client_id: 'agent-7', iat: t, nbf: t, exp: t + 300, jti: 'sample' }) },
  user: { title: 'User token (no actor, bearer)', make: (c, t) => ({ iss: c.ids.issuer, sub: 'user-123', aud: c.ids.resource, scope: 'mcp:tools', client_id: 'web-app', iat: t, nbf: t, exp: t + 300 }) },
  dpop: { title: 'DPoP-bound agent token (cnf.jkt)', make: (c, t) => ({ iss: c.ids.issuer, sub: 'user-123', aud: c.ids.resource, scope: 'mcp:tools', act: { sub: 'agent-7' }, client_id: 'agent-7', iat: t, exp: t + 300, cnf: { jkt: c.keyring.clientJkt } }) },
  mtls: { title: 'mTLS-bound agent token (cnf x5t#S256)', make: (c, t) => ({ iss: c.ids.issuer, sub: 'user-123', aud: c.ids.resource, scope: 'mcp:tools', act: { sub: 'agent-7' }, iat: t, exp: t + 300, cnf: { 'x5t#S256': c.keyring.clientJkt } }) },
  expired: { title: 'Expired token', make: (c, t) => ({ iss: c.ids.issuer, sub: 'user-123', aud: c.ids.resource, scope: 'mcp:tools', iat: t - 7200, exp: t - 3600 }) },
};

export function createApp({ runtime, health = createHealth() } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(hostGuard);
  app.use(originGuard);
  app.use((_req, res, next) => { res.set(API_HEADERS); next(); });

  const api = express.Router();
  api.use(credentialGuard);
  api.use('/health', health.router);
  api.use(express.json({ limit: '16kb' }));

  api.get('/meta', (_req, res) => res.json({
    mode: runtime.mode, issuer: runtime.ids.issuer, resource: runtime.ids.resource, jwksUrl: runtime.rs.jwksUrl,
    allowedAlgs: ALLOWED_ALGS, maxTokenChars: MAX_TOKEN_CHARS, ports: runtime.ports,
    profiles: PROFILE_ORDER.map((id) => ({ id, title: PROFILES[id].title, blurb: PROFILES[id].blurb, url: runtime.authServers[id].url })),
    rules: { bcp: BCP_RULES.map(({ id, title, rfc }) => ({ id, title, rfc })), fapi: FAPI_RULES.map(({ id, title, rfc }) => ({ id, title, rfc })), fapiNote: FAPI_NOTE },
  }));
  api.get('/jwks', (_req, res) => res.json(runtime.keyring.jwks()));

  // --- decode / mint ---
  api.post('/mint', wrap((req, res) => {
    const b = takeBody(req, res, ['sample']); if (!b) return;
    const s = SAMPLES[b.sample];
    if (!s) return bad(res, `sample must be one of: ${Object.keys(SAMPLES).join(', ')}`);
    const t = Math.floor(runtime.now());
    // Raw token on purpose: this is a debugging tool. It is signed by a stub key that exists only in this process.
    res.json({ sample: b.sample, title: s.title, token: runtime.keyring.sign({}, s.make(runtime.testerCtx, t)) });
  }));

  api.post('/decode', wrap((req, res) => {
    const b = takeBody(req, res, ['token', 'verify']); if (!b) return;
    if (b.verify !== undefined && typeof b.verify !== 'boolean') return bad(res, 'verify must be true or false');
    const p = parseJwt(b.token);
    if (!p.ok) return bad(res, `${p.reason}. Opaque (non-JWT) tokens cannot be decoded offline.`, 400, 'not_a_jwt');
    const nowSec = Math.floor(runtime.now());
    let signature = { state: 'not_verified', note: 'The signature was not checked. Decoding shows what the token SAYS; anyone can write any claims. Nothing here is trusted until the signature is verified against the issuer\'s real keys.' };
    if (b.verify) {
      const jwk = typeof p.header.kid === 'string' ? runtime.keyring.jwks().keys.find((k) => k.kid === p.header.kid) : null;
      if (!ALLOWED_ALGS.includes(p.header.alg)) signature = { state: 'invalid', note: `Algorithm ${revealText(String(p.header.alg), 20)} is not verified here (only ${ALLOWED_ALGS.join(', ')}).` };
      else if (!jwk) signature = { state: 'invalid', note: 'The key id is not in this app\'s stub JWKS, so it cannot be verified here. Tokens from a real issuer need that issuer\'s JWKS, which this tool never fetches.' };
      else if (verifyEs256(p.signingInput, p.signature, jwk)) signature = { state: 'valid_stub_jwks', note: 'The signature verifies against the stub issuer\'s key (generated in memory in this process). That proves only that this app signed it.' };
      else signature = { state: 'invalid', note: 'The signature does not verify against the stub issuer\'s key.' };
    }
    res.json({ header: inertValue(p.header), payload: inertValue(p.payload), claims: explainClaims(p.header, p.payload, nowSec), time: timeStatus(p.payload, nowSec), signature, signaturePresent: p.signature.length > 0 });
  }));

  // --- wrong-token tester ---
  api.get('/tester/cases', (_req, res) => res.json({ cases: caseList() }));
  api.post('/tester/run', wrap(async (req, res) => {
    const b = takeBody(req, res, ['case']); if (!b) return;
    if (typeof b.case !== 'string') return bad(res, 'case must be a case id or "all"');
    if (b.case !== 'all' && !caseList().some((c) => c.id === b.case)) return bad(res, 'no such case');
    const result = await runtime.enqueue(() => (b.case === 'all' ? runAll(runtime.testerCtx) : runCase(b.case, runtime.testerCtx).then((r) => ({ results: [r], summary: { total: 1, passed: r.pass ? 1 : 0, failed: r.pass ? 0 : 1 } }))));
    res.json({ resource: runtime.ids.resource, ...result });
  }));

  // --- OAuth profile checker ---
  api.post('/checker/run', wrap(async (req, res) => {
    const b = takeBody(req, res, ['profile', 'target', 'pack']); if (!b) return;
    if ((b.profile === undefined) === (b.target === undefined)) return bad(res, 'send exactly one of profile (a stub profile id) or target (a loopback http URL)');
    const pack = b.pack ?? 'both';
    if (!['bcp', 'fapi', 'both'].includes(pack)) return bad(res, 'pack must be bcp, fapi or both');
    let target;
    if (b.profile !== undefined) {
      if (typeof b.profile !== 'string' || !runtime.authServers[b.profile]) return bad(res, `profile must be one of: ${PROFILE_ORDER.join(', ')}`);
      target = runtime.authServers[b.profile].url;
    } else {
      if (typeof b.target !== 'string' || b.target.length > 200) return bad(res, 'target must be a URL string of at most 200 characters');
      const ev = evaluateTarget(b.target);
      if (!ev.allowed) return res.status(400).json({ error: 'target_refused', reason: ev.reason, message: new TargetRefused(ev.reason).message });
      target = ev.normalizedUrl;
    }
    const result = await runtime.enqueue(() => runChecker({ target, packs: pack === 'both' ? ['bcp', 'fapi'] : [pack] }));
    res.json({ profile: b.profile ?? null, ...result });
  }));

  // --- flow catalog (C2) ---
  api.get('/flows', (_req, res) => res.json({ simulated: true, mechanisms: listMechanisms() }));
  api.get('/flows/compare', (_req, res) => res.json(compare()));
  api.post('/flows/run', wrap((req, res) => {
    const b = takeBody(req, res, ['mechanism', 'protected']); if (!b) return;
    if (typeof b.protected !== 'boolean') return bad(res, 'protected must be true or false');
    if (!listMechanisms().some((m) => m.id === b.mechanism)) return bad(res, 'no such mechanism');
    res.json(runFlow(b.mechanism, b.protected));
  }));

  api.use((_req, res) => bad(res, 'no such endpoint', 404));
  api.use((err, _req, res, _next) => {
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'payload_too_large', message: 'request body is too large' });
    if (err.type === 'entity.parse.failed') return bad(res, 'request body is not valid JSON');
    if (err.code === 'run_queue_full') return res.set('Retry-After', '2').status(429).json({ error: 'run_queue_full', message: 'a run is in progress and another is already queued; try again shortly' });
    if (err instanceof TargetRefused) return res.status(400).json({ error: 'target_refused', reason: err.reason, message: err.message });
    if (err instanceof URIError || err.status === 400) return bad(res, 'malformed request');
    // Log the error class only: a message could echo part of a token.
    console.error('[token-workbench] api error:', err?.name || 'Error', err?.code || '');
    return res.status(500).json({ error: 'server_error' });
  });
  app.use('/api', api);
  app.use((_req, res) => bad(res, 'no such endpoint', 404));
  app.use((err, _req, res, _next) => (err instanceof URIError || err.status === 400 ? bad(res, 'malformed request') : res.status(500).json({ error: 'server_error' })));
  return app;
}

// Boot on `port`. Refuses a non-loopback host unless TW_BIND is set.
export async function startHttpServer({ port = serverPort(), host = bindHost(), env = process.env, runtime, stubBase } = {}) {
  assertBindAllowed(host, env);
  const rt = runtime || await createRuntime({ stubBase });
  const health = createHealth({ env });
  return new Promise((resolve, reject) => {
    const httpServer = createApp({ runtime: rt, health }).listen(port, host);
    httpServer.once('error', async (e) => { health.stop(); await rt.close(); reject(e); });
    httpServer.once('listening', () => {
      const { port: bound } = httpServer.address();
      resolve({
        port: bound, runtime: rt, url: `http://127.0.0.1:${bound}/`,
        close: async () => { health.stop(); await new Promise((r) => { httpServer.closeAllConnections?.(); httpServer.close(r); }); await rt.close(); },
      });
    });
  });
}
