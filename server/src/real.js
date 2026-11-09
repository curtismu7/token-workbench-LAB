// Real mode (rule 19): the same Decode / Trace and Profile checker operations against a real PingOne or PingFederate
// issuer that the OWNER configures. Off unless TW_REAL=1 and every setting below is valid. Settings come from the
// environment only (the lab's own .env beside docker-compose.yml, read at start); nothing is read from any other file.
// The client secret is write-only: it lives in a closure, is never returned, never logged and is scrubbed from every
// trace this module produces. Every request goes through the netguard (netguard.js), which allows only the configured
// issuer's origin.
import crypto from 'node:crypto';
import { BCP_RULES, BCP_NOTE, FAPI_RULES, FAPI_NOTE } from './checker.js';
import { revealText } from './sanitize.js';

// The setting names, in the order the owner fills them in. Values are never printed anywhere.
export const REAL_SETTINGS = [
  { name: 'TW_REAL', required: true, about: 'set to 1 to opt in to Real' },
  { name: 'TW_REAL_ISSUER', required: true, about: 'the issuer URL, https with a host name (PingOne: https://auth.pingone.<region>/<environment id>/as; PingFederate: its base URL)' },
  { name: 'TW_REAL_CLIENT_ID', required: true, about: 'a client that may use the client_credentials grant' },
  { name: 'TW_REAL_CLIENT_SECRET', required: true, about: 'that client\'s secret (write-only: never shown or logged)' },
  { name: 'TW_REAL_SCOPE', required: false, about: 'optional scopes for the client_credentials request, space separated' },
  { name: 'TW_REAL_TOKEN_AUTH', required: false, about: 'optional: client_secret_basic (default) or client_secret_post' },
];
export const REAL_ENV_NAMES = REAL_SETTINGS.map((s) => s.name);
export const REAL_HOW_TO = 'Real is configured in the .env file beside docker-compose.yml (repo root): set TW_REAL=1, TW_REAL_ISSUER, TW_REAL_CLIENT_ID and TW_REAL_CLIENT_SECRET (optional TW_REAL_SCOPE, TW_REAL_TOKEN_AUTH), then restart the lab. See the README section "Real mode".';
export const REAL_ALGS = ['RS256', 'ES256'];
const TOKEN_AUTHS = ['client_secret_basic', 'client_secret_post'];
const CONTROL = /[\u0000-\u001f\u007f]/;
const SECRET_SHOWN = '[client secret: write-only, not shown]';

// An IP literal or localhost is refused as an issuer: Real is for a named PingOne or PingFederate host, and this keeps a
// typo from pointing the lab at link-local or private services. (A name that resolves to one cannot be seen here.)
const isDirectAddress = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.startsWith('[') || h === 'localhost' || h.endsWith('.localhost');

export function checkIssuer(value) {
  if (typeof value !== 'string' || !value || value.length > 512 || CONTROL.test(value)) return { problem: 'TW_REAL_ISSUER must be a URL of 1 to 512 characters' };
  let u;
  try { u = new URL(value); } catch { return { problem: 'TW_REAL_ISSUER is not a URL' }; }
  if (u.protocol !== 'https:') return { problem: 'TW_REAL_ISSUER must be https' };
  if (u.username || u.password) return { problem: 'TW_REAL_ISSUER must not carry credentials' };
  if (u.search || u.hash) return { problem: 'TW_REAL_ISSUER must not have a query or fragment' };
  if (isDirectAddress(u.hostname.toLowerCase())) return { problem: 'TW_REAL_ISSUER must use a host name, not an IP address or localhost' };
  return { issuer: value.replace(/\/+$/, ''), origin: u.origin };
}

// -> { optedIn, available, problems: [text], missing: [setting names], issuer, origin, clientId, scope, tokenAuth,
//      auth(): the client authentication for a token-endpoint request, scrub(text): removes the secret from text }
export function realConfigFrom(env = process.env) {
  const v = (k) => (env[k] === undefined ? '' : String(env[k]));
  const problems = []; const missing = [];
  const optedIn = v('TW_REAL') === '1';
  if (!optedIn) { problems.push(v('TW_REAL') ? 'TW_REAL must be exactly 1 to opt in' : 'TW_REAL is not set: Real is off until the owner opts in'); missing.push('TW_REAL'); }
  let issuer = null; let origin = null;
  if (!v('TW_REAL_ISSUER')) { problems.push('TW_REAL_ISSUER is not set'); missing.push('TW_REAL_ISSUER'); } else {
    const c = checkIssuer(v('TW_REAL_ISSUER'));
    if (c.problem) { problems.push(c.problem); missing.push('TW_REAL_ISSUER'); } else ({ issuer, origin } = c);
  }
  const clientId = v('TW_REAL_CLIENT_ID');
  if (!clientId) { problems.push('TW_REAL_CLIENT_ID is not set'); missing.push('TW_REAL_CLIENT_ID'); } else if (!/^[\x21-\x7e]{1,256}$/.test(clientId)) { problems.push('TW_REAL_CLIENT_ID must be printable ASCII with no spaces'); missing.push('TW_REAL_CLIENT_ID'); }
  const secret = v('TW_REAL_CLIENT_SECRET');
  if (!secret) { problems.push('TW_REAL_CLIENT_SECRET is not set'); missing.push('TW_REAL_CLIENT_SECRET'); } else if (secret.length > 1024 || CONTROL.test(secret)) { problems.push('TW_REAL_CLIENT_SECRET must be 1 to 1024 characters with no control characters (value not shown)'); missing.push('TW_REAL_CLIENT_SECRET'); }
  const scope = v('TW_REAL_SCOPE');
  if (scope && !/^[\x21\x23-\x5b\x5d-\x7e]+( [\x21\x23-\x5b\x5d-\x7e]+)*$/.test(scope)) { problems.push('TW_REAL_SCOPE must be space-separated scope tokens'); missing.push('TW_REAL_SCOPE'); }
  const tokenAuth = v('TW_REAL_TOKEN_AUTH') || 'client_secret_basic';
  if (!TOKEN_AUTHS.includes(tokenAuth)) { problems.push(`TW_REAL_TOKEN_AUTH must be ${TOKEN_AUTHS.join(' or ')}`); missing.push('TW_REAL_TOKEN_AUTH'); }
  const available = problems.length === 0;

  // The secret never leaves this closure except inside the outgoing request built by auth().
  const forms = secret ? [secret, encodeURIComponent(secret), Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`).toString('base64')] : [];
  const scrub = (text) => { let t = String(text); for (const f of forms) if (f) t = t.split(f).join('[redacted]'); return t; };
  const auth = () => (tokenAuth === 'client_secret_post'
    ? { headers: {}, form: { client_id: clientId, client_secret: secret }, shown: { headers: {}, form: { client_id: clientId, client_secret: SECRET_SHOWN } } }
    : { headers: { authorization: `Basic ${forms[2]}` }, form: {}, shown: { headers: { authorization: `Basic ${SECRET_SHOWN}` }, form: {} } });
  const config = { optedIn, available, problems, missing, issuer: available ? issuer : null, origin: available ? origin : null, clientIdSet: Boolean(clientId), secretSet: Boolean(secret), scope: available ? scope : '', tokenAuth };
  Object.defineProperties(config, { auth: { value: auth, enumerable: false }, scrub: { value: scrub, enumerable: false }, clientId: { value: clientId, enumerable: false } });
  return config;
}

// What the page may see about Real: never the secret, never the client id.
export const realPublicView = (c) => ({ available: c.available, optedIn: c.optedIn, issuer: c.issuer, issuerOrigin: c.origin, tokenAuth: c.tokenAuth, settings: REAL_SETTINGS, missing: c.missing, problems: c.problems, howTo: REAL_HOW_TO });

const SHOW_RESPONSE_HEADERS = ['content-type', 'cache-control', 'pragma', 'www-authenticate', 'dpop-nonce'];
const formBody = (o) => new URLSearchParams(o).toString();
const parse = (t) => { try { const j = JSON.parse(t); return j && typeof j === 'object' && !Array.isArray(j) ? j : null; } catch { return null; } };
const traceparent = () => `00-${crypto.randomBytes(16).toString('hex')}-${crypto.randomBytes(8).toString('hex')}-01`;

export class RealError extends Error {
  constructor(message, trace = []) { super(message); this.name = 'RealError'; this.code = 'real_error'; this.trace = trace; }
}

// One Real operation records every HTTP exchange it made as a trace (the "live token flow log"): method, URL, the
// request headers and body as sent (client authentication replaced by a write-only marker), status, selected response
// headers and the raw response body. Tokens are shown raw on purpose; the client secret never appears.
export function createRealClient({ config, guard }) {
  function newTrace() {
    const entries = [];
    async function send(step, url, { method = 'GET', headers = {}, shownHeaders = headers, form, shownForm = form } = {}) {
      const tp = traceparent();
      const reqHeaders = { accept: 'application/json', traceparent: tp, ...(form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}), ...headers };
      const entry = { step, method, url: config.scrub(url), request: { headers: { accept: 'application/json', traceparent: tp, ...(form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}), ...shownHeaders }, body: shownForm ? formBody(shownForm) : null } };
      entries.push(entry);
      try {
        const r = await guard.request(url, { method, headers: reqHeaders, body: form ? formBody(form) : undefined });
        entry.status = r.status;
        entry.response = { headers: Object.fromEntries(SHOW_RESPONSE_HEADERS.filter((h) => r.headers.get(h) !== null).map((h) => [h, config.scrub(revealText(r.headers.get(h), 500))])), body: config.scrub(r.text), truncated: r.truncated };
        if (r.redirect) entry.note = 'a redirect was answered; it is reported, never followed';
        return { status: r.status, json: r.truncated ? null : parse(r.text), redirect: r.redirect };
      } catch (e) {
        entry.error = e.reason ? `refused by the netguard: ${e.message}` : e.message || 'request failed';
        throw new RealError(entry.error, entries);
      }
    }
    return { entries, send };
  }

  const issuerMatches = (meta) => typeof meta?.issuer === 'string' && meta.issuer.replace(/\/+$/, '') === config.issuer;

  async function discover(t) {
    const url = `${config.issuer}/.well-known/openid-configuration`;
    const r = await t.send('discovery', url);
    if (r.status !== 200 || !r.json) throw new RealError(`discovery answered ${r.status}${r.json ? '' : ' without a JSON object'}`, t.entries);
    if (!issuerMatches(r.json)) throw new RealError('the discovery document names a different issuer than TW_REAL_ISSUER, so nothing from it is trusted', t.entries);
    return { meta: r.json, url };
  }
  const endpoint = (meta, key, t) => {
    const v = meta[key];
    if (typeof v !== 'string') throw new RealError(`the issuer's metadata has no ${key}`, t.entries);
    return v;
  };

  // client_credentials: a REAL access token from the configured issuer.
  async function token() {
    const t = newTrace();
    const { meta } = await discover(t);
    const a = config.auth();
    const form = { grant_type: 'client_credentials', ...(config.scope ? { scope: config.scope } : {}), ...a.form };
    const shownForm = { grant_type: 'client_credentials', ...(config.scope ? { scope: config.scope } : {}), ...a.shown.form };
    const r = await t.send('token (client_credentials)', endpoint(meta, 'token_endpoint', t), { method: 'POST', headers: a.headers, shownHeaders: a.shown.headers, form, shownForm });
    if (r.status !== 200 || typeof r.json?.access_token !== 'string') throw new RealError(`the token endpoint answered ${r.status}${typeof r.json?.error === 'string' ? ` (${revealText(r.json.error, 60)})` : ''}`, t.entries);
    return { token: r.json.access_token, tokenType: typeof r.json.token_type === 'string' ? revealText(r.json.token_type, 40) : null, expiresIn: Number.isFinite(r.json.expires_in) ? r.json.expires_in : null, trace: t.entries };
  }

  // Signature check against the issuer's real JWKS (fetched now, never cached).
  async function verify(parsed) {
    const t = newTrace();
    const alg = parsed.header.alg;
    if (!REAL_ALGS.includes(alg)) return { signature: { state: 'invalid', note: `Algorithm ${revealText(String(alg), 20)} is not verified here (only ${REAL_ALGS.join(', ')}).` }, trace: t.entries };
    const { meta } = await discover(t);
    const r = await t.send('jwks', endpoint(meta, 'jwks_uri', t));
    if (r.status !== 200 || !Array.isArray(r.json?.keys)) throw new RealError(`the JWKS endpoint answered ${r.status}`, t.entries);
    const jwk = typeof parsed.header.kid === 'string' ? r.json.keys.find((k) => k && k.kid === parsed.header.kid) : null;
    if (!jwk) return { signature: { state: 'invalid', note: 'The key id (kid) is not in the issuer\'s JWKS, so the signature cannot be verified.' }, trace: t.entries };
    const ok = verifyWithJwk(alg, parsed.signingInput, parsed.signature, jwk);
    const issNote = parsed.payload.iss === config.issuer ? 'iss matches TW_REAL_ISSUER.' : 'iss does NOT match TW_REAL_ISSUER.';
    return { signature: ok
      ? { state: 'valid_real_jwks', note: `The signature verifies against the configured issuer's real JWKS (key ${revealText(parsed.header.kid, 80)}). ${issNote} A valid signature does not mean the token is still active: introspect it to ask the issuer.` }
      : { state: 'invalid', note: 'The signature does not verify against the issuer\'s real JWKS.' }, trace: t.entries };
  }

  // RFC 7662 introspection with the configured client.
  async function introspect(tok) {
    const t = newTrace();
    const { meta } = await discover(t);
    const a = config.auth();
    const r = await t.send('introspection', endpoint(meta, 'introspection_endpoint', t), { method: 'POST', headers: a.headers, shownHeaders: a.shown.headers, form: { token: tok, token_type_hint: 'access_token', ...a.form }, shownForm: { token: tok, token_type_hint: 'access_token', ...a.shown.form } });
    if (r.status !== 200 || typeof r.json?.active !== 'boolean') throw new RealError(`the introspection endpoint answered ${r.status}`, t.entries);
    return { active: r.json.active, trace: t.entries };
  }

  // The checker's two packs, judged from the issuer's PUBLISHED metadata only. Rules that need active probes (sending
  // crafted authorization and token requests) are not run against a real issuer: they report not_checked.
  async function checkMetadata(packs) {
    const t = newTrace();
    const { meta, url } = await discover(t);
    const out = { source: 'real', target: config.issuer, unreachable: false, metadata: { found: true, url: url.slice(config.origin.length) }, packs: {}, trace: t.entries };
    const results = metadataRules(meta, config.issuer);
    const pick = (rules) => rules.map((r) => ({ id: r.id, title: r.title, rfc: r.rfc, why: r.why, ...results[r.id] }));
    const summarise = (rules) => ({ total: rules.length, passed: rules.filter((r) => r.status === 'pass').length, failed: rules.filter((r) => r.status === 'fail').length, errors: 0, notChecked: rules.filter((r) => r.status === 'not_checked').length });
    if (packs.includes('bcp')) { const rules = pick(BCP_RULES); out.packs.bcp = { title: 'OAuth 2.0 Security BCP (RFC 9700)', unverified: false, note: `${BCP_NOTE} REAL: judged from the issuer's published metadata only.`, rules, summary: summarise(rules) }; }
    if (packs.includes('fapi')) { const rules = pick(FAPI_RULES); out.packs.fapi = { title: 'FAPI 2.0 (simplified)', unverified: true, note: `${FAPI_NOTE} REAL: judged from the issuer's published metadata only.`, rules, summary: summarise(rules) }; }
    out.requests = t.entries.length;
    return out;
  }

  return { token, verify, introspect, checkMetadata };
}

export function verifyWithJwk(alg, signingInput, signatureB64u, jwk) {
  try {
    let key;
    if (alg === 'RS256' && jwk.kty === 'RSA' && typeof jwk.n === 'string' && typeof jwk.e === 'string') key = crypto.createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
    else if (alg === 'ES256' && jwk.kty === 'EC' && jwk.crv === 'P-256' && typeof jwk.x === 'string' && typeof jwk.y === 'string') key = crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
    else return false;
    const sig = Buffer.from(signatureB64u, 'base64url');
    return alg === 'RS256' ? crypto.verify('sha256', Buffer.from(signingInput), key, sig) : crypto.verify('sha256', Buffer.from(signingInput), { key, dsaEncoding: 'ieee-p1363' }, sig);
  } catch { return false; }
}

const NOT_CHECKED = (why) => ({ status: 'not_checked', evidence: `not checked in Real: ${why}` });
const ACTIVE = 'it needs active probes (crafted authorization and token requests), which this lab never sends to a real issuer';
export function metadataRules(meta, issuer) {
  const list = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : null);
  const pass = (e) => ({ status: 'pass', evidence: revealText(e, 200) }); const fail = (e) => ({ status: 'fail', evidence: revealText(e, 200) });
  const missing = ['issuer', 'authorization_endpoint', 'token_endpoint', 'response_types_supported'].filter((k) => meta[k] === undefined);
  const methods = list(meta.code_challenge_methods_supported);
  const grants = list(meta.grant_types_supported);
  const responses = list(meta.response_types_supported);
  const s256 = !methods ? fail('metadata does not list code_challenge_methods_supported') : methods.includes('plain') ? fail('metadata advertises code_challenge_method "plain"') : methods.includes('S256') ? pass('metadata advertises S256 and not plain (advertised only)') : fail('metadata does not advertise S256');
  const ropc = !grants ? NOT_CHECKED('metadata does not list grant_types_supported') : grants.includes('password') ? fail('metadata advertises grant_type "password"') : pass('metadata does not advertise the password grant (advertised only)');
  const implicit = !responses ? NOT_CHECKED('metadata does not list response_types_supported') : responses.some((r) => r.split(' ').includes('token')) ? fail('metadata lists a response type that returns "token" in the redirect') : pass('no response type returns an access token in the redirect (advertised only)');
  const iss = meta.authorization_response_iss_parameter_supported === true ? pass('metadata sets authorization_response_iss_parameter_supported=true (advertised only)') : fail('metadata does not set authorization_response_iss_parameter_supported=true');
  const dpop = (list(meta.dpop_signing_alg_values_supported) || []).length > 0; const mtls = meta.tls_client_certificate_bound_access_tokens === true;
  const both = (a, b, ok) => (a.status === 'fail' || b.status === 'fail' ? fail([a, b].filter((x) => x.status === 'fail').map((x) => x.evidence).join('; ')) : a.status === 'pass' && b.status === 'pass' ? pass(ok) : NOT_CHECKED([a, b].filter((x) => x.status !== 'pass').map((x) => x.evidence.replace(/^not checked in Real: /, '')).join('; ')));
  return {
    metadata: missing.length ? fail(`metadata lacks: ${missing.join(', ')}`) : String(meta.issuer).replace(/\/+$/, '') !== issuer ? fail('metadata issuer does not match TW_REAL_ISSUER') : pass('published at /.well-known/openid-configuration, issuer matches TW_REAL_ISSUER'),
    'exact-redirect': NOT_CHECKED(ACTIVE), 'pkce-required': NOT_CHECKED(ACTIVE), 'pkce-downgrade': NOT_CHECKED(ACTIVE), 'single-use-code': NOT_CHECKED(ACTIVE),
    's256-only': s256, 'no-ropc': ropc, 'no-implicit': implicit, 'iss-param': iss,
    'fapi-par-published': typeof meta.pushed_authorization_request_endpoint === 'string' ? pass('metadata publishes pushed_authorization_request_endpoint (advertised only, not exercised)') : fail('metadata has no pushed_authorization_request_endpoint'),
    'fapi-par-required': meta.require_pushed_authorization_requests === true ? pass('metadata sets require_pushed_authorization_requests=true (advertised only)') : fail('metadata does not set require_pushed_authorization_requests=true'),
    'fapi-pkce-s256': s256.status === 'fail' ? s256 : NOT_CHECKED(`S256 is advertised and plain is not, but whether PKCE is REQUIRED: ${ACTIVE}`),
    'fapi-sender-constrained': dpop || mtls ? pass(`metadata advertises ${[dpop && 'DPoP', mtls && 'mTLS-bound tokens'].filter(Boolean).join(' and ')} (advertised only, not exercised)`) : fail('metadata advertises neither DPoP nor certificate-bound access tokens'),
    'fapi-no-implicit-ropc': both(implicit, ropc, 'neither implicit nor password grant is advertised (advertised only)'),
    'fapi-exact-redirect': NOT_CHECKED(ACTIVE), 'fapi-iss': iss,
  };
}
