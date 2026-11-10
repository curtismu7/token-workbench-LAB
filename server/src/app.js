// One Express app: the API under /api. createApp() is what the tests use.
// Every server-provided string shown back is made inert (sanitize.js) and served as JSON only.
// The token under test is DATA in a JSON body: it is never read from a header, never logged, never sent anywhere
// except (for the tester) to the stub resource server on loopback.
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHealth } from './health.js';
import { createRuntime } from './runtime.js';
import { loadCustomer, DEFAULT_CUSTOMER } from './customer.js';
import { assertBindAllowed, bindHost, credentialGuard, makeHostGuard, makeOriginGuard, serverPort } from './safety.js';
import { allowedHostsFrom, bannerText, liveFlagProblems, modeFrom, publicOriginFrom } from './config.js';
import { DEFAULT_WORKSPACE, WORKSPACE_RE, createWorkspaces } from './workspaces.js';
import { explainClaims, parseJwt, timeStatus, verifyEs256, MAX_TOKEN_CHARS } from './jwt.js';
import { inertValue, revealText } from './sanitize.js';
import { caseList, runAll, runCase } from './tester.js';
import { BCP_RULES, BCP_NOTE, FAPI_RULES, FAPI_NOTE, runChecker } from './checker.js';
import { PROFILES, PROFILE_ORDER } from './stubs/authserver.js';
import { compare, listMechanisms, runFlow } from './catalog.js';
import { TargetRefused } from './http.js';
import { evaluateTarget } from './policy.js';
import { ALLOWED_ALGS } from './validator.js';
import { shelfInfo } from './shelfLink.js';
import { createNetguard } from './netguard.js';
import { RealError, createRealClient, realConfigFrom, realPublicView } from './real.js';

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const bad = (res, message, status = 400, error) => res.status(status).json({ error: error || (status === 404 ? 'not_found' : 'bad_request'), message });
export const DEFAULT_WEB_DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../web/dist');
// The built UI: same-origin scripts, styles, images and fetches only. (style-src allows inline styles: React Flow sets them.)
export const UI_CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
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

// webDist: directory with the built UI (web/dist). null disables static serving; a missing directory serves JSON 404 at /.
// deployMode 'local' (default): one runtime, the X-Workspace-Id header is ignored. 'se-mock': one runtime per workspace id
// (workspaces.js), user-typed checker targets refused. createWorkspaceRuntime builds the runtime of a new workspace.
// real: the Real-mode settings (real.js, from the environment; not configured by default). realFetch: the fetch the
// netguard uses in Real mode (tests pass one that reaches an in-process stub issuer on loopback).
export function createApp({ runtime, health = createHealth(), webDist = DEFAULT_WEB_DIST, deployMode = 'local', publicOrigin = null, allowedHosts = new Set(), workspaceOptions = {}, createWorkspaceRuntime = () => createRuntime({ ephemeral: true }), customer = loadCustomer(), real = realConfigFrom({}), realFetch } = {}) {
  const hosted = deployMode === 'se-mock';
  // Rule 19: the server-side mode. Real only in the local build and only when the owner configured it; the default is
  // Real when configured, else Mock. The netguard refuses every outbound call unless the mode is Real.
  const realOk = !hosted && real.available;
  let source = realOk ? 'real' : 'mock';
  const guard = createNetguard({ mode: () => source, allowedOrigin: realOk ? real.origin : null, ...(realFetch ? { realFetch } : {}) });
  const realClient = createRealClient({ config: real, guard });
  health.setRuntime?.(() => (source === 'real' ? 'live' : 'offline'));
  // Every Real answer (result, error message, trace) leaves through here: the whole JSON is scrubbed of the client
  // secret in every encoding, so an issuer that echoes it (in a message, a header, even a token field) cannot leak it.
  const sendReal = (res, body, status = 200) => res.status(status).type('application/json').send(real.scrub(JSON.stringify(body)));
  const workspaces = hosted ? createWorkspaces({ defaultRuntime: runtime, create: createWorkspaceRuntime, ...workspaceOptions }) : null;
  const app = express();
  app.workspaces = workspaces;
  app.netguard = guard;
  app.source = () => source;
  app.disable('x-powered-by');
  app.use(makeHostGuard(allowedHosts));
  app.use(makeOriginGuard(publicOrigin, allowedHosts));
  app.use((_req, res, next) => { res.set(API_HEADERS); next(); });
  if (webDist && fs.existsSync(path.join(webDist, 'index.html'))) {
    app.use(express.static(webDist, {
      index: 'index.html', dotfiles: 'ignore',
      setHeaders: (res) => res.set({ ...API_HEADERS, 'Content-Security-Policy': UI_CSP }),
    }));
  }

  const api = express.Router();
  api.use(credentialGuard);
  api.use('/health', health.router);
  api.use(express.json({ limit: '16kb' }));
  // The workspace this request works in. All state (keys, stubs, run queue, results) hangs off req.rt.
  api.use(wrap(async (req, res, next) => {
    if (!hosted) { req.rt = runtime; req.workspaceId = DEFAULT_WORKSPACE; return next(); }
    const id = req.headers['x-workspace-id'];
    if (id !== undefined && (typeof id !== 'string' || !WORKSPACE_RE.test(id))) return bad(res, 'X-Workspace-Id must be 1-32 characters of a-z, 0-9 and hyphen, starting with a letter or digit');
    req.workspaceId = id ?? DEFAULT_WORKSPACE;
    req.rt = await workspaces.get(req.workspaceId);
    return next();
  }));

  api.get('/meta', (req, res) => res.json({
    mode: req.rt.mode, source, deployMode, hosted, workspace: req.workspaceId, banner: bannerText(deployMode), issuer: req.rt.ids.issuer, resource: req.rt.ids.resource, jwksUrl: req.rt.rs.jwksUrl,
    allowedAlgs: ALLOWED_ALGS, maxTokenChars: MAX_TOKEN_CHARS, ports: req.rt.ports,
    profiles: PROFILE_ORDER.map((id) => ({ id, title: PROFILES[id].title, blurb: PROFILES[id].blurb, url: req.rt.authServers[id].url })),
    rules: { bcp: BCP_RULES.map(({ id, title, rfc }) => ({ id, title, rfc })), fapi: FAPI_RULES.map(({ id, title, rfc }) => ({ id, title, rfc })), fapiNote: FAPI_NOTE, bcpNote: BCP_NOTE },
    customer: { ...DEFAULT_CUSTOMER, ...customer },
  }));
  // Rule 19: the Mock/Real toggle's API. Real needs the owner's opt-in settings (real.js); the page gets their names and
  // what is missing, never a value of the secret or the client id.
  const infoBody = () => ({ mode: deployMode, hosted, source, realAvailable: realOk, real: hosted ? null : realPublicView(real) });
  api.get('/info', (_req, res) => res.json(infoBody()));
  api.post('/mode', (req, res) => {
    const b = req.body;
    if (b === null || typeof b !== 'object' || Array.isArray(b) || Object.keys(b).length !== 1 || !['mock', 'real'].includes(b.source)) return bad(res, 'body must be exactly {source: "mock" or "real"}');
    if (hosted) return bad(res, 'The hosted build is Mock only and cannot be switched.', 403);
    if (b.source === 'real' && !realOk) return bad(res, `Real is not configured: ${real.problems.join('; ')}. ${realPublicView(real).howTo}`, 409, 'real_not_configured');
    source = b.source;
    return res.json(infoBody());
  });

  // Reset (rule 3): POST /api/reset drops every non-default workspace runtime and stops
  // the default's stub servers' in-flight state. The fixtures are static data.
  api.post('/reset', wrap(async (req, res) => {
    if (workspaces && req.workspaceId === DEFAULT_WORKSPACE) {
      const ids = workspaces.ids().filter((id) => id !== DEFAULT_WORKSPACE);
      for (const id of ids) workspaces.dropForReset(id);
      res.json({ ok: true, cleared: ids.length, note: 'workspaces beyond the default are closed; the fixtures never change' });
    } else {
      res.json({ ok: true, cleared: 0, note: 'hosted builds scope reset to the default workspace only' });
    }
  }));
  api.get('/jwks', (req, res) => res.json(req.rt.keyring.jwks()));

  // --- decode / mint ---
  api.post('/mint', wrap(async (req, res) => {
    const b = takeBody(req, res, ['sample']); if (!b) return;
    if (source === 'real') {
      if (b.sample !== 'client_credentials') return bad(res, 'In Real the only sample is client_credentials: a token from the configured issuer');
      const r = await realClient.token();
      // Raw token on purpose (education). It is a REAL token from the configured issuer: never logged, never stored.
      return sendReal(res, { source: 'real', label: 'REAL', sample: 'client_credentials', title: 'REAL access token (client_credentials)', token: r.token, tokenType: r.tokenType, expiresIn: r.expiresIn, trace: r.trace });
    }
    const s = typeof b.sample === 'string' && Object.hasOwn(SAMPLES, b.sample) ? SAMPLES[b.sample] : null;
    if (!s) return bad(res, `sample must be one of: ${Object.keys(SAMPLES).join(', ')}`);
    const t = Math.floor(req.rt.now());
    // Raw token on purpose: this is a debugging tool. It is signed by a stub key that exists only in this process.
    res.json({ source: 'mock', label: 'MOCK', sample: b.sample, title: s.title, token: req.rt.keyring.sign({}, s.make(req.rt.testerCtx, t)) });
  }));

  api.post('/decode', wrap(async (req, res) => {
    const b = takeBody(req, res, ['token', 'verify']); if (!b) return;
    if (b.verify !== undefined && typeof b.verify !== 'boolean') return bad(res, 'verify must be true or false');
    const p = parseJwt(b.token);
    if (!p.ok) return bad(res, `${p.reason}. Opaque (non-JWT) tokens cannot be decoded offline.`, 400, 'not_a_jwt');
    const nowSec = Math.floor(req.rt.now());
    let signature = { state: 'not_verified', note: 'The signature was not checked. Decoding shows what the token SAYS; anyone can write any claims. Nothing here is trusted until the signature is verified against the issuer\'s real keys.' };
    let trace;
    if (b.verify && source === 'real') ({ signature, trace } = await realClient.verify(p));
    else if (b.verify) {
      const jwk = typeof p.header.kid === 'string' ? req.rt.keyring.jwks().keys.find((k) => k.kid === p.header.kid) : null;
      if (!ALLOWED_ALGS.includes(p.header.alg)) signature = { state: 'invalid', note: `Algorithm ${revealText(String(p.header.alg), 20)} is not verified here (only ${ALLOWED_ALGS.join(', ')}).` };
      else if (!jwk) signature = { state: 'invalid', note: 'The key id is not in this app\'s stub JWKS, so it cannot be verified here. Tokens from a real issuer need that issuer\'s JWKS, which this tool never fetches.' };
      else if (verifyEs256(p.signingInput, p.signature, jwk)) signature = { state: 'valid_stub_jwks', note: 'The signature verifies against the stub issuer\'s key (generated in memory in this process). That proves only that this app signed it.' };
      else signature = { state: 'invalid', note: 'The signature does not verify against the stub issuer\'s key.' };
    }
    (source === 'real' ? (body) => sendReal(res, body) : (body) => res.json(body))({ source, ...(trace ? { trace } : {}), header: inertValue(p.header), payload: inertValue(p.payload), claims: explainClaims(p.header, p.payload, nowSec), time: timeStatus(p.payload, nowSec), signature, signaturePresent: p.signature.length > 0 });
  }));

  // --- introspection (RFC 7662) ---
  // Mock: the stub issuer answers in this process (signature against the stub keys, iss, exp and nbf). Real: the configured
  // issuer's introspection_endpoint, authenticated as the configured client.
  api.post('/introspect', wrap(async (req, res) => {
    const b = takeBody(req, res, ['token']); if (!b) return;
    if (typeof b.token !== 'string' || !b.token.trim() || b.token.length > MAX_TOKEN_CHARS) return bad(res, `token must be a non-empty string of at most ${MAX_TOKEN_CHARS} characters`);
    if (source === 'real') { const r = await realClient.introspect(b.token.trim()); return sendReal(res, { source: 'real', active: r.active, trace: r.trace }); }
    const p = parseJwt(b.token);
    const nowSec = Math.floor(req.rt.now());
    const jwk = p.ok && typeof p.header.kid === 'string' ? req.rt.keyring.jwks().keys.find((k) => k.kid === p.header.kid) : null;
    const t = p.ok ? timeStatus(p.payload, nowSec) : null;
    const active = Boolean(p.ok && ALLOWED_ALGS.includes(p.header.alg) && jwk && verifyEs256(p.signingInput, p.signature, jwk) && p.payload.iss === req.rt.ids.issuer && !t.expired && !t.notYetValid);
    const pick = ['iss', 'sub', 'aud', 'scope', 'client_id', 'exp', 'iat', 'nbf', 'jti', 'act', 'cnf'];
    const response = active ? { active: true, ...inertValue(Object.fromEntries(pick.filter((k) => p.payload[k] !== undefined).map((k) => [k, p.payload[k]]))) } : { active: false };
    res.json({ source: 'mock', active, response, note: 'MOCK: the stub issuer answered in this process; no HTTP request was made.' });
  }));

  // --- wrong-token tester ---
  api.get('/tester/cases', (_req, res) => res.json({ cases: caseList() }));
  api.post('/tester/run', wrap(async (req, res) => {
    const b = takeBody(req, res, ['case']); if (!b) return;
    if (typeof b.case !== 'string') return bad(res, 'case must be a case id or "all"');
    if (b.case !== 'all' && !caseList().some((c) => c.id === b.case)) return bad(res, 'no such case');
    const result = await req.rt.enqueue(() => (b.case === 'all' ? runAll(req.rt.testerCtx) : runCase(b.case, req.rt.testerCtx).then((r) => ({ results: [r], summary: { total: 1, passed: r.pass ? 1 : 0, failed: r.pass ? 0 : 1 } }))));
    res.json({ source: 'mock', resource: req.rt.ids.resource, ...result });
  }));

  // --- OAuth profile checker ---
  api.post('/checker/run', wrap(async (req, res) => {
    const b = takeBody(req, res, ['profile', 'target', 'pack']); if (!b) return;
    if (source === 'real') {
      if (b.profile !== undefined || b.target !== undefined) return bad(res, 'In Real the checker reads the configured issuer\'s metadata: send only pack');
      const pk = b.pack ?? 'both';
      if (!['bcp', 'fapi', 'both'].includes(pk)) return bad(res, 'pack must be bcp, fapi or both');
      return sendReal(res, { profile: null, ...await realClient.checkMetadata(pk === 'both' ? ['bcp', 'fapi'] : [pk]) });
    }
    if ((b.profile === undefined) === (b.target === undefined)) return bad(res, 'send exactly one of profile (a stub profile id) or target (a loopback http URL)');
    const pack = b.pack ?? 'both';
    if (!['bcp', 'fapi', 'both'].includes(pack)) return bad(res, 'pack must be bcp, fapi or both');
    let target;
    if (hosted && b.target !== undefined) return res.status(400).json({ error: 'target_refused', reason: 'hosted_build', message: new TargetRefused('hosted_build').message });
    if (b.profile !== undefined) {
      if (typeof b.profile !== 'string' || !Object.hasOwn(req.rt.authServers, b.profile)) return bad(res, `profile must be one of: ${PROFILE_ORDER.join(', ')}`);
      target = req.rt.authServers[b.profile].url;
    } else {
      if (typeof b.target !== 'string' || b.target.length > 200) return bad(res, 'target must be a URL string of at most 200 characters');
      const ev = evaluateTarget(b.target);
      if (!ev.allowed) return res.status(400).json({ error: 'target_refused', reason: ev.reason, message: new TargetRefused(ev.reason).message });
      target = ev.normalizedUrl;
    }
    const result = await req.rt.enqueue(() => runChecker({ target, packs: pack === 'both' ? ['bcp', 'fapi'] : [pack] }));
    res.json({ source: 'mock', profile: b.profile ?? null, ...result });
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
    if (err.code === 'workspace_cap') return res.set('Retry-After', '30').status(503).json({ error: 'workspace_cap', message: 'the hosted demo has too many active workspaces right now; try again in a few minutes' });
    if (err.code === 'run_queue_full') return res.set('Retry-After', '2').status(429).json({ error: 'run_queue_full', message: 'a run is in progress and another is already queued; try again shortly' });
    // A Real call that failed: the issuer's answer (or the netguard's refusal) and the trace so far, secret already scrubbed.
    if (err instanceof RealError) return sendReal(res, { error: 'real_error', source: 'real', message: err.message, trace: err.trace }, 502);
    if (err instanceof TargetRefused) return res.status(400).json({ error: 'target_refused', reason: err.reason, message: err.message });
    if (err instanceof URIError || err.status === 400) return bad(res, 'malformed request');
    // Log the error class only: a message could echo part of a token.
    console.error('[token-workbench] api error:', err?.name || 'Error', err?.code || '');
    return res.status(500).json({ error: 'server_error' });
  });
  app.get('/api/shelf', (_req, res) => { res.set('Cache-Control', 'no-store'); res.json(shelfInfo()); }); // the header "Shelf" button
  app.use('/api', api);
  app.use((_req, res) => bad(res, 'no such endpoint', 404));
  app.use((err, _req, res, _next) => (err instanceof URIError || err.status === 400 ? bad(res, 'malformed request') : res.status(500).json({ error: 'server_error' })));
  return app;
}

// Boot on `port`. Refuses a non-loopback host unless TW_BIND is set.
// MODE (env) picks local or se-mock; a live flag in se-mock stops the start.
export async function startHttpServer({ port = serverPort(), host = bindHost(), env = process.env, runtime, stubBase, webDist, workspaceOptions, realFetch } = {}) {
  assertBindAllowed(host, env);
  const deployMode = modeFrom(env);
  const problems = liveFlagProblems(env);
  if (problems.length) throw new Error(`refusing to start: ${problems.join('; ')}`);
  const publicOrigin = deployMode === 'se-mock' ? publicOriginFrom(env) : null;
  const allowedHosts = allowedHostsFrom(env); // before the stubs start: a bad name must not leave servers running
  const rt = runtime || await createRuntime({ stubBase });
  const health = createHealth({ env });
  return new Promise((resolve, reject) => {
    const real = realConfigFrom(deployMode === 'se-mock' ? {} : env);
    const app = createApp({ runtime: rt, health, deployMode, publicOrigin, allowedHosts, workspaceOptions, real, ...(realFetch ? { realFetch } : {}), ...(webDist !== undefined ? { webDist } : {}) });
    const httpServer = app.listen(port, host);
    httpServer.once('error', async (e) => { health.stop(); await app.workspaces?.closeAll(); await rt.close(); reject(e); });
    httpServer.once('listening', () => {
      const { port: bound } = httpServer.address();
      resolve({
        port: bound, host: httpServer.address().address, runtime: rt, workspaces: app.workspaces, netguard: app.netguard, source: app.source(), deployMode, url: `http://127.0.0.1:${bound}/`,
        close: async () => { health.stop(); await new Promise((r) => { httpServer.closeAllConnections?.(); httpServer.close(r); }); await app.workspaces?.closeAll(); await rt.close(); },
      });
    });
  });
}
