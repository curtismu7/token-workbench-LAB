// Real sign-in (owner opt-in, extends rule 19): an authorization-code + PKCE S256 sign-in at the configured issuer
// with response_mode=pi.flow — the login stays in this lab's UI, no redirect is ever followed or served — then the
// code for tokens (access, ID and refresh). The username comes from TW_REAL_USERNAME (default demouser); the password
// is a function argument typed in the Sign in dialog, used once in one request body and kept nowhere: not stored,
// not logged, not returned, not in a step. Every outbound call goes through the same netguard as the rest of Real,
// so only the configured issuer's origin is ever contacted. The user client's secret lives in the closure and is
// scrubbed from every trace by the same config.scrub as the client_credentials client.
import { createHash, randomBytes } from 'node:crypto';

const CONTROL = /[\u0000-\u001f\u007f]/;
const FLOW_ID = /^[A-Za-z0-9-]{1,64}$/;
const PW_TYPE = 'application/vnd.pingidentity.usernamePassword.check+json';
export const SIGN_IN_SCOPES = 'openid profile email';
export const PASSWORD_SHOWN = '[typed by you in the Sign in dialog: sent once to the issuer, never stored, logged or shown]';
const SECRET_SHOWN = 'Basic [write-only: the client secret is never shown]';
const REFRESH_SHOWN = '[the refresh token: shown raw in the token list, never put in a trace]';
const short = (v) => (typeof v === 'string' && v.length > 10 ? `${v.slice(0, 6)}...` : '[short]');
const str = (v, n = 300) => (typeof v === 'string' ? v.slice(0, n) : null);
const plain = (v, max) => (typeof v === 'string' && v.length > 0 && v.length <= max && !CONTROL.test(v) ? v : null);
const maskCookie = (c) => String(c).split(';')[0].replace(/=(.*)$/, (_m, v) => `=${short(v)}`);

export function decodeJwt(raw) {
  const parts = String(raw).split('.');
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return header && claims && typeof claims === 'object' ? { header, claims } : null;
  } catch { return null; }
}

// The redirect URI the IdP app must list. pi.flow never redirects: the IdP only checks that it matches the app;
// nothing is ever served there.
export const realSigninRedirectUri = 'https://local.ping-devops.com:8443/token-workbench/auth/callback';

// Optional settings on top of the client_credentials config: the sign-in is available only when the user client is
// configured. Names only, never values.
export function realSigninFrom(config, env = process.env) {
  const clientId = String(env.TW_REAL_3LO_CLIENT_ID || '');
  const secret = String(env.TW_REAL_3LO_CLIENT_SECRET || '');
  const username = String(env.TW_REAL_USERNAME || 'demouser');
  const problems = [];
  if (!clientId) problems.push('TW_REAL_3LO_CLIENT_ID is not set');
  else if (!/^[\x21-\x7e]{1,256}$/.test(clientId)) problems.push('TW_REAL_3LO_CLIENT_ID must be printable ASCII with no spaces');
  if (!secret) problems.push('TW_REAL_3LO_CLIENT_SECRET is not set');
  else if (secret.length > 1024 || CONTROL.test(secret)) problems.push('TW_REAL_3LO_CLIENT_SECRET must be 1 to 1024 characters with no control characters (value not shown)');
  if (!plain(username, 200)) problems.push('TW_REAL_USERNAME must be 1 to 200 characters with no control characters');
  return { available: config.available && problems.length === 0, problems, username, clientIdSet: Boolean(clientId), secretSet: Boolean(secret), signinAvailable: problems.length === 0, signinProblems: problems, signinUsername: username, signinClientId: clientId, signinSecret: secret, signinRedirectUri: realSigninRedirectUri };
}

export const REAL_SIGNIN_SETTINGS = [
  { name: 'TW_REAL_3LO_CLIENT_ID', required: false, about: 'for Sign in: a client allowed the authorization-code and refresh-token grants' },
  { name: 'TW_REAL_3LO_CLIENT_SECRET', required: false, about: 'that client\'s secret (write-only: never shown or logged)' },
  { name: 'TW_REAL_USERNAME', required: false, about: 'the user who signs in (default demouser); the password is typed in the dialog' },
];

export class SignInError extends Error {
  constructor(message, trace = []) { super(message); this.name = 'SignInError'; this.code = 'signin_error'; this.trace = trace; }
}

// One sign-in session per workspace: the three tokens and the step trace. The password is never here.
export function createRealSignin({ config, guard, now = Date.now }) {
  const sessions = new Map(); // workspace -> { access, idToken, refresh, header, claims, idClaims, expiresAt, steps }
  let inFlight = 0;
  const scrub = (t) => config.scrub(t);

  const basicValue = Buffer.from(`${encodeURIComponent(config.signinClientId)}:${encodeURIComponent(config.signinSecret)}`).toString('base64');
  const auth = () => ({ headers: { authorization: `Basic ${basicValue}` }, shown: { headers: { authorization: SECRET_SHOWN } } });

  // After the password has been sent, the issuer's free text is never passed on (it could echo what was typed): codes only.
  const errorOf = (r, sent) => {
    if (!r.json) return r.unreachable ? { note: 'no answer' } : { note: 'the answer was not a JSON object' };
    if (sent) return { error: str(r.json.error, 80) ?? str(r.json.code, 80), detail_code: str(r.json.details?.[0]?.code, 80) };
    return { error: str(r.json.error) ?? str(r.json.code), error_description: str(r.json.error_description) ?? str(r.json.message) ?? str(r.json.details?.[0]?.message) };
  };

  async function idp(t, step, url, { method = 'GET', headers = {}, shownHeaders = headers, body, shownBody } = {}) {
    const tp = `00-${randomBytes(16).toString('hex')}-${randomBytes(8).toString('hex')}-01`;
    const entry = { step, method, url: scrub(url), request: { headers: { ...shownHeaders, traceparent: tp }, ...(shownBody !== undefined ? { body: shownBody } : {}) } };
    t.entries.push(entry);
    let r;
    try { r = await guard.request(url, { method, headers: { ...headers, traceparent: tp }, body }); } catch (e) {
      entry.error = e.reason ? `refused by the netguard: ${e.message}` : e.message || 'request failed';
      throw new SignInError(entry.error, t.entries);
    }
    entry.status = r.status;
    entry.response = { body: r.truncated ? null : (() => { try { const j = JSON.parse(r.text); return j && typeof j === 'object' ? { id: str(j.id, 64), status: str(j.status, 64), ...(j.status === 'COMPLETED' || j.access_token ? {} : errorOf({ json: j }, false)) } : errorOf({ json: null }, false); } catch { return errorOf({ json: null }, false); } })() };
    if (r.redirect) entry.note = 'a redirect was answered; it is reported, never followed';
    return { status: r.status, json: r.truncated ? null : (() => { try { const j = JSON.parse(r.text); return j && typeof j === 'object' && !Array.isArray(j) ? j : null; } catch { return null; } })(), cookies: typeof r.headers.getSetCookie === 'function' ? r.headers.getSetCookie() : [], redirect: r.redirect };
  }

  const sessionOf = (ws) => {
    const s = sessions.get(ws);
    if (!s) return null;
    if (s.expiresAt <= now()) { sessions.delete(ws); return null; }
    return s;
  };

  // password: what the person typed. Returns the three tokens raw plus the trace, or throws SignInError.
  async function signIn(ws, password) {
    if (!config.available) throw new SignInError('Real is not configured', []);
    if (!config.signinAvailable) throw new SignInError(`Sign in is not configured: ${config.signinProblems.join('; ')}`, []);
    if (inFlight >= 2) throw new SignInError('two Real sign-ins are already in flight; wait for one to finish', []);
    inFlight += 1;
    const t = { entries: [] };
    const jar = new Map();
    const keep = (cookies) => { for (const c of cookies) { const pair = String(c).split(';')[0]; const i = pair.indexOf('='); if (i > 0) jar.set(pair.slice(0, i).trim(), pair.slice(i + 1)); } };
    const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    const shownCookie = () => [...jar].map(([k, v]) => `${k}=${short(v)}`).join('; ');
    let sent = false;
    const scrubTyped = (v) => (typeof password === 'string' && password.length >= 4 ? JSON.parse(JSON.stringify(v).split(JSON.stringify(password).slice(1, -1)).join('[the password]')) : v);
    try {
      // 1. authorize with response_mode=pi.flow: the answer is JSON (a flow), not a redirect.
      const verifier = randomBytes(32).toString('base64url');
      const state = randomBytes(12).toString('base64url');
      const nonce = randomBytes(12).toString('base64url');
      const query = { response_type: 'code', client_id: config.signinClientId, redirect_uri: config.signinRedirectUri, scope: SIGN_IN_SCOPES, response_mode: 'pi.flow', code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', state, nonce };
      const a = await idp(t, 'authorize (response_mode=pi.flow, PKCE S256)', `${config.issuer}/as/authorize?${new URLSearchParams(query)}`, { headers: { accept: 'application/json' }, shownBody: { query: { ...query, state: short(state), nonce: short(nonce) } } });
      keep(a.cookies);
      if (a.redirect) throw new SignInError('the issuer answered the sign-in with a redirect; the lab never follows one', t.entries);
      if (a.status !== 200 || !a.json || !FLOW_ID.test(String(a.json.id || ''))) throw new SignInError(`the issuer refused to start the sign-in (HTTP ${a.status})`, t.entries);
      let flow = a.json;
      const flowId = a.json.id;
      if (flow.status !== 'USERNAME_PASSWORD_REQUIRED' && flow.status !== 'COMPLETED') throw new SignInError('the issuer asked for a sign-in step this lab does not drive (only username and password). Check the sign-on policy.', t.entries);
      // 2. username and password, once, through the flows API.
      if (flow.status === 'USERNAME_PASSWORD_REQUIRED') {
        if (!plain(password, 256)) throw new SignInError('type the password (1 to 256 characters)', t.entries);
        sent = true;
        const r = await idp(t, 'flows API: username and password', `${config.issuer}/flows/${flowId}`, {
          method: 'POST',
          headers: { 'content-type': PW_TYPE, accept: '*/*', ...(jar.size ? { cookie: cookieHeader() } : {}) },
          body: JSON.stringify({ username: config.signinUsername, password }),
          shownBody: { username: config.signinUsername, password: PASSWORD_SHOWN },
        });
        keep(r.cookies);
        if (r.status === 400 || r.status === 401) throw new SignInError('the issuer did not accept the username or password', t.entries);
        if (r.status !== 200 || !r.json) throw new SignInError(`the issuer refused the sign-in (HTTP ${r.status})`, t.entries);
        flow = r.json;
        if (flow.status !== 'COMPLETED') throw new SignInError('the issuer asked for a step after the password that this lab does not drive (for example MFA). Check the sign-on policy.', t.entries);
      }
      // 3. the code: in the completed flow, or from resume with the flow's cookies.
      let code = str(flow.authorizeResponse?.code, 2000);
      let gotState = flow.authorizeResponse?.state;
      if (!code) {
        const r = await idp(t, 'resume: the authorization code', `${config.issuer}/as/resume?flowId=${encodeURIComponent(flowId)}`, { headers: { accept: 'application/json', ...(jar.size ? { cookie: cookieHeader() } : {}) }, shownHeaders: { accept: 'application/json', cookie: shownCookie() } });
        code = str(r.json?.authorizeResponse?.code, 2000); gotState = r.json?.authorizeResponse?.state;
        if (r.status !== 200 || !code) throw new SignInError(`the issuer did not hand back an authorization code (HTTP ${r.status})`, t.entries);
      }
      if (gotState !== state) throw new SignInError('the authorization code came back without the state the lab sent; the lab refuses it', t.entries);
      // 4. the code for the three tokens (the client's secret in the Authorization header only).
      const a2 = auth();
      const form = { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: config.signinRedirectUri };
      const shownForm = { grant_type: 'authorization_code', code: short(code), code_verifier: '[the PKCE verifier, never shown]', redirect_uri: config.signinRedirectUri };
      const tok = await idp(t, "token: the code for the user's tokens", `${config.issuer}/as/token`, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json', ...a2.headers }, shownHeaders: { 'content-type': 'application/x-www-form-urlencoded', ...a2.shown.headers }, body: new URLSearchParams(form).toString(), shownBody: shownForm,
      });
      const at = typeof tok.json?.access_token === 'string' ? tok.json.access_token : null;
      const rt = typeof tok.json?.refresh_token === 'string' ? tok.json.refresh_token : null;
      if (tok.status !== 200 || !at) throw new SignInError(`the issuer did not issue the user's tokens (HTTP ${tok.status})`, t.entries);
      const idToken = typeof tok.json.id_token === 'string' ? tok.json.id_token : null;
      const idClaims = idToken ? decodeJwt(idToken)?.claims ?? null : null;
      if (idClaims && idClaims.nonce !== nonce) throw new SignInError('the ID token does not carry the nonce the lab sent; the lab refuses it', t.entries);
      const dec = decodeJwt(at);
      const life = Number.isFinite(tok.json.expires_in) && tok.json.expires_in > 0 ? Math.min(tok.json.expires_in, 24 * 3600) : 3600;
      const session = { access: at, idToken, refresh: rt, header: dec?.header ?? null, claims: dec?.claims ?? null, idClaims, expiresAt: now() + life * 1000, steps: scrubTyped(t.entries) };
      sessions.set(ws, session);
      return { ok: true, tokens: tokensOf(session), trace: session.steps };
    } catch (e) {
      if (e instanceof SignInError) { e.trace = scrubTyped(e.trace || t.entries); throw e; }
      throw new SignInError(scrubTyped(e.message), scrubTyped(t.entries));
    } finally { inFlight -= 1; }
  }

  // grant_type=refresh_token: a new access (and ID) token. The refresh token itself is only sent, never shown in a trace.
  async function refresh(ws) {
    const s = sessionOf(ws);
    if (!s) throw new SignInError('no sign-in session: Sign in first', []);
    if (!s.refresh) throw new SignInError('the issuer issued no refresh token, so there is nothing to exchange', []);
    const t = { entries: [] };
    const a = auth();
    const tok = await idp(t, 'token (refresh_token)', `${config.issuer}/as/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json', ...a.headers }, shownHeaders: { 'content-type': 'application/x-www-form-urlencoded', ...a.shown.headers },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: s.refresh }).toString(),
      shownBody: { grant_type: 'refresh_token', refresh_token: REFRESH_SHOWN },
    });
    if (tok.status !== 200 || typeof tok.json?.access_token !== 'string') throw new SignInError(`the issuer refused the refresh (HTTP ${tok.status})`, t.entries);
    const dec = decodeJwt(tok.json.access_token);
    s.access = tok.json.access_token; s.header = dec?.header ?? null; s.claims = dec?.claims ?? null;
    if (typeof tok.json.id_token === 'string') { s.idToken = tok.json.id_token; s.idClaims = decodeJwt(tok.json.id_token)?.claims ?? null; }
    if (typeof tok.json.refresh_token === 'string') s.refresh = tok.json.refresh_token;
    const life = Number.isFinite(tok.json.expires_in) && tok.json.expires_in > 0 ? Math.min(tok.json.expires_in, 24 * 3600) : 3600;
    s.expiresAt = now() + life * 1000;
    return { ok: true, tokens: tokensOf(s), trace: t.entries };
  }

  const tokensOf = (s) => ([
    { kind: 'access', label: 'Access token (REAL)', token: s.access, header: s.header, claims: s.claims },
    { kind: 'id', label: 'ID token (REAL)', token: s.idToken, header: s.idToken ? decodeJwt(s.idToken)?.header ?? null : null, claims: s.idClaims },
    { kind: 'refresh', label: 'Refresh token (REAL)', token: s.refresh, header: null, claims: null },
  ]);

  return {
    available: () => config.available && config.signinAvailable,
    problems: () => config.signinProblems,
    username: () => config.signinUsername,
    session: sessionOf,
    signIn, refresh,
    signOut: (ws) => sessions.delete(ws),
  };
}
