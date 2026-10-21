// Wrong-token rejection tester (C23). Mints tokens with the stub issuer and sends each one to the stub resource
// server over loopback. Each case says which answer a correct resource server must give.
import { b64uJson, parseJwt, b64u } from './jwt.js';
import { loopbackRequest, parseJson } from './http.js';
import { inertValue, revealText } from './sanitize.js';
import crypto from 'node:crypto';
import { REQUIRED_SCOPE } from './stubs/resource.js';

// ctx: { keyring, ids:{issuer,resource,downstream}, now:()=>seconds, rsUrl }
const claims = (ctx, over = {}) => {
  const t = Math.floor(ctx.now());
  return { iss: ctx.ids.issuer, sub: 'user-123', aud: ctx.ids.resource, scope: REQUIRED_SCOPE, act: { sub: 'agent-7' }, client_id: 'agent-7', iat: t, nbf: t, exp: t + 300, jti: crypto.randomUUID(), ...over };
};
const drop = (o, k) => { const c = { ...o }; delete c[k]; return c; };

export const CASES = [
  { id: 'good', title: 'Correct token (control)', expect: { status: 200 }, teaches: 'Issuer, audience, scope, expiry and actor all match, so the call is accepted. If this fails, every other result is meaningless.',
    mint: (c) => c.keyring.sign({}, claims(c)) },
  { id: 'wrong-scope', title: 'Wrong scope', expect: { status: 403, error: 'insufficient_scope', failed: 'scope' }, teaches: 'The token is genuine but lacks the permission this call needs. The right answer is 403 with error="insufficient_scope" (not 401): re-authenticating would not help, asking for more scope would.',
    mint: (c) => c.keyring.sign({}, claims(c, { scope: 'mcp:read' })) },
  { id: 'wrong-audience', title: 'Wrong audience', expect: { status: 401, error: 'invalid_token', failed: 'aud' }, teaches: 'The token was issued for a different API. A resource server must check that its own identifier is in aud (RFC 8707, RFC 9068), or any token from the same issuer works everywhere.',
    mint: (c) => c.keyring.sign({}, claims(c, { aud: 'http://127.0.0.1:1/some-other-api' })) },
  { id: 'expired', title: 'Expired token', expect: { status: 401, error: 'invalid_token', failed: 'exp' }, teaches: 'exp is in the past. The signature is still valid, which is why the expiry check matters: a leaked token should stop working on its own.',
    mint: (c) => { const t = Math.floor(c.now()); return c.keyring.sign({}, claims(c, { iat: t - 7200, nbf: t - 7200, exp: t - 3600 })); } },
  { id: 'not-yet-valid', title: 'Not yet valid (nbf)', expect: { status: 401, error: 'invalid_token', failed: 'nbf' }, teaches: 'nbf is in the future. Rare, but a validator that ignores it accepts tokens before their time.',
    mint: (c) => { const t = Math.floor(c.now()); return c.keyring.sign({}, claims(c, { nbf: t + 3600, exp: t + 7200 })); } },
  { id: 'wrong-issuer', title: 'Wrong issuer', expect: { status: 401, error: 'invalid_token', failed: 'iss' }, teaches: 'Correctly signed, but by an issuer this server does not trust. Trusting any issuer whose signature checks out lets anyone mint their own tokens.',
    mint: (c) => c.keyring.sign({}, claims(c, { iss: 'http://127.0.0.1:1/other-issuer' })) },
  { id: 'alg-none', title: 'alg = none (unsigned)', expect: { status: 401, error: 'invalid_token', failed: 'alg' }, teaches: 'An unsigned token whose header says alg "none". Libraries that honour the header accept it. The server must use an algorithm allow-list.',
    mint: (c) => `${b64uJson({ alg: 'none', typ: 'at+jwt', kid: c.keyring.kid })}.${b64uJson(claims(c))}.` },
  { id: 'alg-confusion-hs256', title: 'Algorithm confusion (HS256 with the public key)', expect: { status: 401, error: 'invalid_token', failed: 'alg' }, teaches: 'The attacker signs with HMAC, using the issuer\'s PUBLIC key as the secret. A validator that lets the header pick the algorithm verifies it with that same public key and accepts it.',
    mint: (c) => { const head = b64uJson({ alg: 'HS256', typ: 'at+jwt', kid: c.keyring.kid }); const body = b64uJson(claims(c)); return `${head}.${body}.${b64u(crypto.createHmac('sha256', c.keyring.publicKeyAsHmacSecret()).update(`${head}.${body}`).digest())}`; } },
  { id: 'user-vs-agent', title: 'User token where an agent token is required', expect: { status: 403, error: 'insufficient_scope', failed: 'actor' }, teaches: 'A valid token for the user directly (no "act" claim), sent to a tool that is for delegated agents only. Distinguishing user and agent calls is how an audit can say who really acted. (Demo policy: the stub answers 403 insufficient_scope; RFC 6750 has no dedicated code for this.)',
    mint: (c) => c.keyring.sign({}, drop(claims(c), 'act')) },
  { id: 'tampered-signature', title: 'Tampered payload (signature no longer matches)', expect: { status: 401, error: 'invalid_token', failed: 'signature' }, teaches: 'A good token whose payload was edited to add a scope after signing. The signature covers the payload, so any edit breaks it.',
    mint: (c) => { const p = parseJwt(c.keyring.sign({}, claims(c, { scope: 'mcp:read' }))); return `${p.parts[0]}.${b64uJson({ ...p.payload, scope: `${p.payload.scope} ${REQUIRED_SCOPE}` })}.${p.parts[2]}`; } },
  { id: 'forged-signature', title: 'Signed by an attacker key (claims the real kid)', expect: { status: 401, error: 'invalid_token', failed: 'signature' }, teaches: 'Perfect claims, but signed with a different private key while naming the real key id. Only the signature check can catch it.',
    mint: (c) => c.keyring.signWithRogueKey({}, claims(c)) },
  { id: 'unknown-kid', title: 'Unknown signing key (kid)', expect: { status: 401, error: 'invalid_token', failed: 'kid' }, teaches: 'The header names a key the server has never heard of. It must not fetch a key from wherever the token points (jku/x5u) and must reject.',
    mint: (c) => c.keyring.signWithRogueKey({ kid: 'attacker-key' }, claims(c)) },
  { id: 'rfc8707-passthrough', title: 'RFC 8707 passthrough: a token meant for the downstream API', expect: { status: 401, error: 'invalid_token', failed: 'aud' }, teaches: 'An MCP server must not accept, or forward, a token issued for another resource ("token passthrough"). It needs a token whose audience is itself, and gets a separate one for the downstream API through token exchange. Here a downstream-API token is sent to the MCP server.',
    mint: (c) => c.keyring.sign({}, claims(c, { aud: c.ids.downstream, scope: 'downstream:read' })) },
  { id: 'malformed', title: 'Not a JWT at all', expect: { status: 401, error: 'invalid_token', failed: 'format' }, teaches: 'Garbage in the Authorization header must be a clean 401, not a crash or a 500.',
    mint: () => 'not-a-jwt' },
  { id: 'no-token', title: 'No token', expect: { status: 401, failed: 'missing' }, teaches: 'RFC 6750: with no credentials the 401 challenge carries no error code. The resource_metadata URL (RFC 9728) tells the client where to start.',
    mint: () => null },
];

export const caseList = () => CASES.map(({ id, title, teaches, expect }) => ({ id, title, teaches, expect }));

const wwwAttr = (header, name) => new RegExp(`${name}="([^"]*)"`).exec(header || '')?.[1] ?? null;

export async function runCase(id, ctx) {
  const c = CASES.find((x) => x.id === id);
  if (!c) { const e = new Error('no such case'); e.code = 'unknown_case'; throw e; }
  const token = c.mint(ctx);
  const headers = { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) };
  const res = await loopbackRequest(ctx.rsUrl, { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: {} } }) });
  const body = parseJson(res.text) || {};
  const www = res.headers['www-authenticate'] || null;
  const actual = {
    status: res.status,
    error: typeof body.error === 'string' ? revealText(body.error, 64) : null,
    error_description: typeof body.error_description === 'string' ? revealText(body.error_description, 400) : null,
    failed_check: typeof body.failed_check === 'string' ? revealText(body.failed_check, 32) : null,
    wwwAuthenticate: www === null ? null : revealText(www, 600),
    wwwError: wwwAttr(www, 'error'),
    checks: inertValue(Array.isArray(body.checks) ? body.checks : []),
  };
  const exp = c.expect;
  const pass = actual.status === exp.status
    && (exp.error === undefined || (actual.error === exp.error && actual.wwwError === exp.error))
    && (exp.failed === undefined || actual.failed_check === exp.failed)
    && (exp.status !== 401 || www !== null);
  return { id: c.id, title: c.title, teaches: c.teaches, expect: exp, actual, pass, accepted: res.status === 200, token };
}

export async function runAll(ctx) {
  const results = [];
  for (const c of CASES) results.push(await runCase(c.id, ctx));
  return { results, summary: { total: results.length, passed: results.filter((r) => r.pass).length, failed: results.filter((r) => !r.pass).length } };
}
