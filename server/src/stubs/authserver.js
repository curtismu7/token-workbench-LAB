// Stub OAuth authorization servers for the profile checker. Five profiles, each a small in-process HTTP server on
// loopback. They are TEACHING stubs: they implement just enough of /authorize, /token and /par to be probed, and
// each profile deliberately gets some rules right and others wrong. They issue no real tokens.
import crypto from 'node:crypto';
import express from 'express';
import { hostGuard } from '../safety.js';

export const CLIENT_ID = 'demo-client';
export const REGISTERED_REDIRECT = 'https://client.example/cb';

const GOOD = {
  title: 'Good: RFC 9700 + FAPI 2.0 style', blurb: 'Exact redirect match, PKCE (S256 only) required, PAR required, no implicit or password grant, single-use codes, iss response parameter, sender-constrained (DPoP) tokens advertised.',
  redirectMatch: 'exact', allowImplicit: false, allowPassword: false, requirePkce: true, allowPlain: false, enforceVerifier: true,
  singleUse: true, issParam: true, metadata: true, par: 'required', senderConstrained: true,
};
export const PROFILES = {
  good: GOOD,
  'loose-redirect': { ...GOOD, title: 'Loose redirect-URI matching', blurb: 'Accepts any redirect URI that starts with the registered one (prefix match). Everything else as the good profile.', redirectMatch: 'prefix' },
  'implicit-ropc': { ...GOOD, title: 'Implicit and password grants allowed', blurb: 'Still offers response_type=token (implicit) and grant_type=password (ROPC). Everything else as the good profile.', allowImplicit: true, allowPassword: true },
  'no-pkce': { ...GOOD, title: 'No PKCE enforcement, plain allowed', blurb: 'PKCE is optional, the "plain" method is accepted, and the token endpoint does not demand the verifier. No PAR, no sender-constrained tokens.', requirePkce: false, allowPlain: true, enforceVerifier: false, par: 'none', senderConstrained: false },
  'missing-metadata': { ...GOOD, title: 'No metadata, no iss parameter', blurb: 'Publishes no authorization-server metadata and omits the iss response parameter. The endpoints work at conventional paths.', metadata: false, issParam: false, par: 'none', senderConstrained: false },
};
export const PROFILE_ORDER = ['good', 'loose-redirect', 'implicit-ropc', 'no-pkce', 'missing-metadata'];

const MAX_STORE = 500;
const sha256b64u = (s) => crypto.createHash('sha256').update(s).digest('base64url');
const rand = () => crypto.randomBytes(12).toString('base64url');

export function startAuthServer({ port, profile }) {
  const cfg = PROFILES[profile];
  const origin = `http://127.0.0.1:${port}`;
  const issuer = origin;
  const codes = new Map(); // code -> { challenge, method, redirect, used }
  const pushed = new Map(); // request_uri -> params
  const remember = (m, k, v) => { if (m.size >= MAX_STORE) m.delete(m.keys().next().value); m.set(k, v); };

  const app = express();
  app.disable('x-powered-by');
  app.use(hostGuard);
  app.use(express.urlencoded({ extended: false, limit: '4kb' }));

  if (cfg.metadata) {
    app.get('/.well-known/oauth-authorization-server', (_req, res) => {
      const m = {
        issuer, authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token`,
        response_types_supported: cfg.allowImplicit ? ['code', 'token'] : ['code'],
        grant_types_supported: cfg.allowPassword ? ['authorization_code', 'password'] : ['authorization_code'],
        code_challenge_methods_supported: cfg.allowPlain ? ['plain', 'S256'] : ['S256'],
        authorization_response_iss_parameter_supported: cfg.issParam,
      };
      if (cfg.par !== 'none') { m.pushed_authorization_request_endpoint = `${origin}/par`; m.require_pushed_authorization_requests = cfg.par === 'required'; }
      if (cfg.senderConstrained) { m.dpop_signing_alg_values_supported = ['ES256']; m.tls_client_certificate_bound_access_tokens = true; }
      res.json(m);
    });
  }

  // Validate authorization-request parameters; returns an error string or null. The same rules run for /authorize and /par.
  function validate(p) {
    if (p.client_id !== CLIENT_ID) return 'unknown client_id';
    const r = p.redirect_uri;
    const okRedirect = typeof r === 'string' && (cfg.redirectMatch === 'exact' ? r === REGISTERED_REDIRECT : r.startsWith(REGISTERED_REDIRECT));
    if (!okRedirect) return 'redirect_uri does not match a registered redirect URI';
    if (p.response_type === 'token') { if (!cfg.allowImplicit) return 'unsupported_response_type: implicit is disabled'; return null; }
    if (p.response_type !== 'code') return 'unsupported_response_type';
    if (p.code_challenge === undefined) return cfg.requirePkce ? 'code_challenge is required (PKCE)' : null;
    const m = p.code_challenge_method ?? 'plain';
    if (m === 'S256') return null;
    if (m === 'plain' && cfg.allowPlain) return null;
    return 'code_challenge_method must be S256';
  }

  function issue(p) {
    if (p.response_type === 'token') return `${p.redirect_uri}#access_token=${rand()}&token_type=Bearer${p.state ? `&state=${encodeURIComponent(p.state)}` : ''}`;
    const code = rand();
    remember(codes, code, { challenge: p.code_challenge, method: p.code_challenge === undefined ? null : p.code_challenge_method ?? 'plain', redirect: p.redirect_uri, used: false });
    const q = new URLSearchParams({ code });
    if (p.state) q.set('state', p.state);
    if (cfg.issParam) q.set('iss', issuer);
    return `${p.redirect_uri}${p.redirect_uri.includes('?') ? '&' : '?'}${q}`;
  }

  const oerr = (res, status, error, error_description) => res.status(status).json({ error, error_description });

  app.get('/authorize', (req, res) => {
    let p = Object.fromEntries(Object.entries(req.query).filter(([, v]) => typeof v === 'string'));
    if (p.request_uri !== undefined) {
      const stored = pushed.get(p.request_uri);
      if (!stored || p.client_id !== CLIENT_ID) return oerr(res, 400, 'invalid_request_uri', 'unknown or expired request_uri');
      p = { ...stored };
    } else if (cfg.par === 'required') return oerr(res, 400, 'invalid_request', 'this server requires pushed authorization requests (PAR)');
    const err = validate(p);
    if (err) return oerr(res, 400, 'invalid_request', err); // never redirect to an unvalidated redirect_uri
    return res.redirect(302, issue(p));
  });

  if (cfg.par !== 'none') {
    app.post('/par', (req, res) => {
      const p = { ...req.body };
      const err = validate(p);
      if (err) return oerr(res, 400, 'invalid_request', err);
      const request_uri = `urn:ietf:params:oauth:request_uri:${rand()}`;
      remember(pushed, request_uri, p);
      res.status(201).json({ request_uri, expires_in: 60 });
    });
  }

  app.post('/token', (req, res) => {
    const b = req.body || {};
    if (b.grant_type === 'password') {
      if (!cfg.allowPassword) return oerr(res, 400, 'unsupported_grant_type', 'the password grant is not supported');
      return res.json({ access_token: rand(), token_type: 'Bearer', expires_in: 300 });
    }
    if (b.grant_type !== 'authorization_code') return oerr(res, 400, 'unsupported_grant_type', 'unsupported grant_type');
    const rec = codes.get(b.code);
    if (!rec || b.client_id !== CLIENT_ID) return oerr(res, 400, 'invalid_grant', 'unknown code');
    if (cfg.singleUse && rec.used) return oerr(res, 400, 'invalid_grant', 'code already used');
    if (rec.redirect !== b.redirect_uri) return oerr(res, 400, 'invalid_grant', 'redirect_uri mismatch');
    if (cfg.enforceVerifier && rec.challenge !== undefined) {
      const v = b.code_verifier;
      const ok = typeof v === 'string' && (rec.method === 'S256' ? sha256b64u(v) === rec.challenge : v === rec.challenge);
      if (!ok) return oerr(res, 400, 'invalid_grant', 'PKCE verification failed');
    }
    rec.used = true;
    return res.json({ access_token: rand(), token_type: cfg.senderConstrained ? 'DPoP' : 'Bearer', expires_in: 300 });
  });

  app.use((_req, res) => res.status(404).json({ error: 'not_found' }));
  app.use((_err, _req, res, _next) => res.status(400).json({ error: 'bad_request' }));

  return new Promise((resolve, reject) => {
    const server = app.listen(port, '127.0.0.1');
    server.once('error', reject);
    server.once('listening', () => resolve({
      port, profile, url: origin, title: cfg.title, blurb: cfg.blurb,
      close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
    }));
  });
}
