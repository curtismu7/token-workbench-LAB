// OAuth profile checker (C20). Probes a loopback authorization server with the same kind of requests an attacker or a
// careless client would send, and scores two rule packs: the RFC 9700 BCP pack and a FAPI 2.0 pack.
// Every request goes through http.js (loopback http only, no redirect following). No credentials are sent: the probes
// use a public client_id and throw-away values.
import crypto from 'node:crypto';
import { loopbackRequest, parseJson, TargetRefused } from './http.js';
import { evaluateTarget } from './policy.js';
import { revealText } from './sanitize.js';
import { CLIENT_ID, REGISTERED_REDIRECT } from './stubs/authserver.js';

export const BCP_RULES = [
  { id: 'metadata', title: 'Authorization-server metadata is published', rfc: 'RFC 8414', why: 'Clients and tools find endpoints and capabilities from metadata. Without it they hard-code guesses, and capability checks (PKCE methods, iss support) cannot be made.' },
  { id: 'exact-redirect', title: 'Redirect URIs match exactly', rfc: 'RFC 9700 2.1', why: 'Prefix or pattern matching lets an attacker who controls any path or query under the registered URI receive the authorization code.' },
  { id: 'pkce-required', title: 'PKCE is required', rfc: 'RFC 9700 2.1.1, RFC 7636', why: 'A stolen authorization code is useless without the verifier, but only if the server refuses requests that skip PKCE.' },
  { id: 'pkce-downgrade', title: 'PKCE downgrade is rejected at the token endpoint', rfc: 'RFC 9700 2.1.1', why: 'If a code issued with a challenge can be redeemed without the verifier (or with a wrong one), PKCE protects nothing.' },
  { id: 's256-only', title: 'Only S256 is accepted', rfc: 'RFC 9700 2.1.1', why: 'The "plain" method sends the verifier itself as the challenge, so anyone who sees the request can redeem the code.' },
  { id: 'no-ropc', title: 'Password (ROPC) grant is off', rfc: 'RFC 9700 2.4', why: 'The password grant hands the user\'s credentials to the client and bypasses MFA and consent.' },
  { id: 'no-implicit', title: 'Implicit (response_type=token) is off', rfc: 'RFC 9700 2.1.2', why: 'Implicit puts the access token in the URL fragment, where history, referrers and scripts can reach it.' },
  { id: 'single-use-code', title: 'Authorization codes are single-use', rfc: 'RFC 6749 4.1.2, RFC 9700 4.5', why: 'A code that can be redeemed twice turns any leak or replay into a second set of tokens.' },
  { id: 'iss-param', title: 'iss is returned in the authorization response', rfc: 'RFC 9207', why: 'The iss parameter lets a client detect a response from the wrong authorization server (mix-up attacks).' },
];
export const FAPI_RULES = [
  { id: 'fapi-par-published', title: 'PAR endpoint is published and works', rfc: 'RFC 9126', why: 'Pushed authorization requests keep request parameters out of the browser and let the server validate them before any redirect.' },
  { id: 'fapi-par-required', title: 'PAR is required (a plain authorize request is refused)', rfc: 'RFC 9126, FAPI 2.0', why: 'Offering PAR is not enough; the profile expects that requests not pushed are refused.' },
  { id: 'fapi-pkce-s256', title: 'PKCE required, S256 only', rfc: 'RFC 7636, FAPI 2.0', why: 'FAPI 2.0 requires PKCE with S256 for every authorization-code request.' },
  { id: 'fapi-sender-constrained', title: 'Sender-constrained tokens are advertised (DPoP or mTLS)', rfc: 'RFC 9449, RFC 8705', why: 'Sender-constrained tokens cannot be replayed by someone who merely steals them. EVIDENCE IS METADATA ONLY: this checker does not exercise DPoP or mTLS.' },
  { id: 'fapi-no-implicit-ropc', title: 'No implicit and no password grant', rfc: 'FAPI 2.0', why: 'Only the authorization-code flow is allowed.' },
  { id: 'fapi-exact-redirect', title: 'Redirect URIs match exactly', rfc: 'FAPI 2.0, RFC 9700', why: 'As in the BCP pack.' },
  { id: 'fapi-iss', title: 'iss is returned in the authorization response', rfc: 'RFC 9207, FAPI 2.0', why: 'As in the BCP pack.' },
];
export const FAPI_NOTE = 'UNVERIFIED: this FAPI 2.0 pack is a simplified reading of the profile written for this demo, not a conformance suite, and it has not been checked against the FAPI 2.0 text line by line. Do not use it to claim that any product is or is not FAPI 2.0 compliant.';

const inert = (v, n = 200) => revealText(v, n);
const b64u = (b) => Buffer.from(b).toString('base64url');
const newVerifier = () => b64u(crypto.randomBytes(32));
const s256 = (v) => b64u(crypto.createHash('sha256').update(v).digest());
const form = (o) => new URLSearchParams(o).toString();

export async function runChecker({ target, packs = ['bcp', 'fapi'] }) {
  const ev = evaluateTarget(target);
  if (!ev.allowed) throw new TargetRefused(ev.reason);
  const base = new URL(ev.normalizedUrl);
  const origin = base.origin;
  let requests = 0;
  const call = (url, opts) => { requests += 1; return loopbackRequest(url, opts); };

  // --- discovery ---
  let meta = null; let metaUrl = null;
  for (const p of ['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration']) {
    try {
      const r = await call(`${origin}${p}`);
      const j = r.status === 200 ? parseJson(r.text) : null;
      if (j && typeof j === 'object' && !Array.isArray(j)) { meta = j; metaUrl = `${origin}${p}`; break; }
    } catch (e) { if (e instanceof TargetRefused) throw e; }
  }
  const str = (v) => (typeof v === 'string' ? v : null);
  const authzEp = str(meta?.authorization_endpoint) || `${origin}/authorize`;
  const tokenEp = str(meta?.token_endpoint) || `${origin}/token`;
  const parEp = str(meta?.pushed_authorization_request_endpoint);
  const parRequired = meta?.require_pushed_authorization_requests === true && parEp !== null;
  const list = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []);

  // --- probe helpers (memoised so the two packs share evidence) ---
  const memo = new Map();
  const once = (key, fn) => { if (!memo.has(key)) memo.set(key, fn()); return memo.get(key); };
  const validParams = (over = {}) => { const verifier = newVerifier(); return { verifier, params: { response_type: 'code', client_id: CLIENT_ID, redirect_uri: REGISTERED_REDIRECT, state: 'tw-state', code_challenge: s256(verifier), code_challenge_method: 'S256', ...over } }; };
  const stripUndef = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));

  // Sends an authorization request (through PAR when the server requires it). Never follows the redirect.
  async function authorize(params, { direct = false } = {}) {
    params = stripUndef(params);
    let query = params; let stage = 'authorize';
    if (parRequired && !direct) {
      stage = 'par';
      const pr = await call(parEp, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form(params) });
      const pj = parseJson(pr.text);
      if (pr.status < 200 || pr.status >= 300 || typeof pj?.request_uri !== 'string') return { accepted: false, stage, status: pr.status, error: str(pj?.error_description) || str(pj?.error) };
      query = { client_id: params.client_id, request_uri: pj.request_uri }; stage = 'authorize';
    }
    const r = await call(`${authzEp}${authzEp.includes('?') ? '&' : '?'}${form(query)}`);
    const loc = r.headers.location;
    if (![301, 302, 303, 307, 308].includes(r.status) || typeof loc !== 'string') {
      const j = parseJson(r.text);
      return { accepted: false, stage, status: r.status, error: str(j?.error_description) || str(j?.error) };
    }
    let u = null; try { u = new URL(loc); } catch { /* unparseable */ }
    const code = u?.searchParams.get('code') ?? null;
    const fragToken = u ? new URLSearchParams(u.hash.replace(/^#/, '')).has('access_token') : false;
    const error = u?.searchParams.get('error') ?? null;
    return { accepted: Boolean(code) || fragToken, code, fragToken, iss: u?.searchParams.get('iss') ?? null, redirectedTo: u ? `${u.origin}${u.pathname}` : null, status: r.status, stage, error };
  }
  async function exchange(code, verifier, redirect = REGISTERED_REDIRECT) {
    const r = await call(tokenEp, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form(stripUndef({ grant_type: 'authorization_code', code, redirect_uri: redirect, client_id: CLIENT_ID, code_verifier: verifier })) });
    const j = parseJson(r.text);
    return { issued: typeof j?.access_token === 'string', status: r.status, error: str(j?.error) };
  }
  const control = () => once('control', async () => { const v = validParams(); const a = await authorize(v.params); return { ...a, verifier: v.verifier }; });

  const pass = (evidence) => ({ status: 'pass', evidence: inert(evidence) });
  const fail = (evidence) => ({ status: 'fail', evidence: inert(evidence) });
  const err = (evidence) => ({ status: 'error', evidence: inert(evidence) });
  const needControl = async () => { const c = await control(); return c.accepted ? null : err(`could not get a valid authorization request accepted (${c.stage} ${c.status}${c.error ? `: ${c.error}` : ''}), so this rule cannot be judged`); };

  const probes = {
    metadata: async () => {
      if (!meta) return fail('no metadata at /.well-known/oauth-authorization-server or /.well-known/openid-configuration');
      const missing = ['issuer', 'authorization_endpoint', 'token_endpoint', 'response_types_supported'].filter((k) => meta[k] === undefined);
      if (missing.length) return fail(`metadata at ${metaUrl} lacks: ${missing.join(', ')}`);
      if (str(meta.issuer)?.replace(/\/$/, '') !== origin) return fail(`metadata issuer ${inert(meta.issuer, 80)} does not match the URL it was fetched from`);
      return pass(`found at ${metaUrl.replace(origin, '')}, issuer matches`);
    },
    'exact-redirect': () => once('exact-redirect', async () => {
      const bad = await needControl(); if (bad) return bad;
      const accepted = [];
      for (const r of [`${REGISTERED_REDIRECT}/evil`, `${REGISTERED_REDIRECT}?next=attacker`]) {
        const a = await authorize(validParams({ redirect_uri: r }).params);
        if (a.accepted) accepted.push(r);
      }
      return accepted.length ? fail(`accepted a redirect URI that is not the registered one: ${accepted.join(' ; ')}`) : pass('rejected a longer path and an added query on the registered redirect URI');
    }),
    'pkce-required': async () => {
      const bad = await needControl(); if (bad) return bad;
      const a = await authorize(validParams({ code_challenge: undefined, code_challenge_method: undefined }).params);
      return a.accepted ? fail('issued an authorization code for a request with no code_challenge') : pass(`rejected a request without code_challenge${a.error ? ` (${a.error})` : ''}`);
    },
    'pkce-downgrade': async () => {
      const bad = await needControl(); if (bad) return bad;
      const v = validParams(); const a = await authorize(v.params);
      if (!a.accepted) return err('could not obtain a code to test the downgrade');
      const noVerifier = await exchange(a.code, undefined);
      if (noVerifier.issued) return fail('redeemed a code that was issued with a challenge without sending code_verifier');
      const w = validParams(); const a2 = await authorize(w.params);
      if (!a2.accepted) return err('could not obtain a second code');
      const wrong = await exchange(a2.code, newVerifier());
      if (wrong.issued) return fail('redeemed a code with a wrong code_verifier');
      return pass('refused a missing and a wrong code_verifier');
    },
    's256-only': async () => {
      const bad = await needControl(); if (bad) return bad;
      const verifier = newVerifier();
      const a = await authorize(validParams({ code_challenge: verifier, code_challenge_method: 'plain' }).params);
      const advertised = list(meta?.code_challenge_methods_supported).includes('plain');
      if (a.accepted) return fail('accepted code_challenge_method=plain');
      if (advertised) return fail('rejected plain in practice, but metadata still advertises "plain"');
      return pass('rejected code_challenge_method=plain');
    },
    'no-ropc': async () => {
      const r = await call(tokenEp, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form({ grant_type: 'password', client_id: CLIENT_ID, username: 'tw-probe-user', password: 'tw-probe-value' }) });
      const j = parseJson(r.text);
      if (typeof j?.access_token === 'string') return fail('issued an access token for grant_type=password');
      return pass(`refused grant_type=password (${r.status}${j?.error ? ` ${inert(j.error, 40)}` : ''})`);
    },
    'no-implicit': async () => {
      const bad = await needControl(); if (bad) return bad;
      const a = await authorize(validParams({ response_type: 'token', code_challenge: undefined, code_challenge_method: undefined }).params);
      if (a.accepted) return fail('answered response_type=token with an access token in the redirect');
      if (list(meta?.response_types_supported).includes('token')) return fail('refused in practice, but metadata still lists response_type "token"');
      return pass('refused response_type=token');
    },
    'single-use-code': async () => {
      const bad = await needControl(); if (bad) return bad;
      const v = validParams(); const a = await authorize(v.params);
      if (!a.accepted) return err('could not obtain a code');
      const first = await exchange(a.code, v.verifier);
      if (!first.issued) return err(`the first redemption with a correct verifier failed (${first.status}${first.error ? ` ${first.error}` : ''}), so reuse cannot be judged`);
      const second = await exchange(a.code, v.verifier);
      return second.issued ? fail('the same authorization code was redeemed twice') : pass('a second redemption of the same code was refused');
    },
    'iss-param': async () => {
      const bad = await needControl(); if (bad) return bad;
      const c = await control();
      if (!c.iss) return fail(`the authorization response has no iss parameter${meta ? '' : ' (and there is no metadata to advertise it)'}`);
      if (meta && str(meta.issuer) && c.iss !== meta.issuer) return fail('the iss parameter differs from the issuer in metadata');
      return pass('the authorization response carries iss');
    },
    'fapi-par-published': async () => {
      if (!parEp) return fail('metadata has no pushed_authorization_request_endpoint');
      const r = await call(parEp, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form(validParams().params) });
      const j = parseJson(r.text);
      return r.status === 201 && typeof j?.request_uri === 'string' ? pass('PAR accepted a valid request and returned a request_uri') : fail(`PAR endpoint answered ${r.status} to a valid request`);
    },
    'fapi-par-required': async () => {
      if (meta?.require_pushed_authorization_requests !== true) return fail('metadata does not set require_pushed_authorization_requests=true');
      const a = await authorize(validParams().params, { direct: true });
      return a.accepted ? fail('accepted a plain authorize request that was not pushed') : pass('refused a plain authorize request that was not pushed');
    },
    'fapi-pkce-s256': async () => {
      const [r, s] = [await probes['pkce-required'](), await probes['s256-only']()];
      if (r.status === 'pass' && s.status === 'pass') return pass('PKCE is required and plain is refused');
      return r.status === 'error' || s.status === 'error' ? err(`${r.evidence}; ${s.evidence}`) : fail(`${r.status === 'pass' ? '' : `${r.evidence}; `}${s.status === 'pass' ? '' : s.evidence}`);
    },
    'fapi-sender-constrained': async () => {
      const dpop = list(meta?.dpop_signing_alg_values_supported).length > 0;
      const mtls = meta?.tls_client_certificate_bound_access_tokens === true;
      return dpop || mtls ? pass(`metadata advertises ${[dpop && 'DPoP', mtls && 'mTLS-bound tokens'].filter(Boolean).join(' and ')} (advertised only, not exercised)`) : fail('metadata advertises neither DPoP nor certificate-bound access tokens');
    },
    'fapi-no-implicit-ropc': async () => {
      const [a, b] = [await probes['no-implicit'](), await probes['no-ropc']()];
      if (a.status === 'pass' && b.status === 'pass') return pass('implicit and password grants are refused');
      return a.status === 'error' || b.status === 'error' ? err(`${a.evidence}; ${b.evidence}`) : fail([a, b].filter((x) => x.status === 'fail').map((x) => x.evidence).join('; '));
    },
    'fapi-exact-redirect': () => probes['exact-redirect'](),
    'fapi-iss': () => probes['iss-param'](),
  };

  async function evaluate(rule) {
    try { return { id: rule.id, title: rule.title, rfc: rule.rfc, why: rule.why, ...await probes[rule.id]() }; }
    catch (e) {
      const ev = e instanceof TargetRefused ? `refused to contact ${e.reason === 'not_loopback' ? 'a non-loopback endpoint named in the metadata' : 'that endpoint'}: ${e.message}` : `request failed (${inert(e.code || 'error', 40)})`;
      return { id: rule.id, title: rule.title, rfc: rule.rfc, why: rule.why, status: 'error', evidence: ev };
    }
  }
  const summarise = (rules) => {
    const count = (s) => rules.filter((r) => r.status === s).length;
    return { total: rules.length, passed: count('pass'), failed: count('fail'), errors: count('error') };
  };

  const out = { target: origin, metadata: { found: Boolean(meta), url: metaUrl ? metaUrl.replace(origin, '') : null }, packs: {} };
  if (packs.includes('bcp')) { const rules = []; for (const r of BCP_RULES) rules.push(await evaluate(r)); out.packs.bcp = { title: 'OAuth 2.0 Security BCP (RFC 9700)', unverified: false, rules, summary: summarise(rules) }; }
  if (packs.includes('fapi')) { const rules = []; for (const r of FAPI_RULES) rules.push(await evaluate(r)); out.packs.fapi = { title: 'FAPI 2.0 (simplified)', unverified: true, note: FAPI_NOTE, rules, summary: summarise(rules) }; }
  out.requests = requests;
  return out;
}
