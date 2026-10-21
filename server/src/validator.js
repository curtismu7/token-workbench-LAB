// The stub resource server's token validator. Fails closed; the first failing check decides the answer.
// Each check has an id so the tester (and the tests) can tell WHICH rule rejected a token, not only that it was rejected.
import { parseJwt, verifyEs256 } from './jwt.js';

export const ALLOWED_ALGS = ['ES256']; // an allow-list, never "whatever the header says"
const LEEWAY_S = 5;

const aud = (v) => (Array.isArray(v) ? v : v === undefined ? [] : [v]);

// policy: { issuer, audience, requiredScope, requireActor, jwks (function returning { keys }), now (function, seconds) }
// Returns { ok, status, error, error_description, failed_check, checks:[{id,label,pass}] }.
export function validateToken(token, policy) {
  const checks = [];
  const fail = (id, label, status, error, error_description) => {
    checks.push({ id, label, pass: false });
    return { ok: false, status, error, error_description, failed_check: id, checks };
  };
  const pass = (id, label) => checks.push({ id, label, pass: true });
  const now = policy.now();

  const parsed = parseJwt(token);
  if (!parsed.ok) return fail('format', 'well-formed JWT', 401, 'invalid_token', `The token is not a well-formed JWT (${parsed.reason}).`);
  pass('format', 'well-formed JWT');

  const { header, payload } = parsed;
  if (typeof header.alg !== 'string' || !ALLOWED_ALGS.includes(header.alg)) {
    const none = String(header.alg).toLowerCase() === 'none';
    return fail('alg', 'algorithm on the allow-list', 401, 'invalid_token', none
      ? 'The token is unsigned (alg "none"). Unsigned tokens are never accepted.'
      : `The signing algorithm is not accepted here (allowed: ${ALLOWED_ALGS.join(', ')}).`);
  }
  pass('alg', 'algorithm on the allow-list');

  const jwk = policy.jwks().keys.find((k) => typeof header.kid === 'string' && k.kid === header.kid);
  if (!jwk) return fail('kid', 'signing key is in the issuer JWKS', 401, 'invalid_token', 'The token names a signing key that this server does not trust.');
  pass('kid', 'signing key is in the issuer JWKS');

  if (!verifyEs256(parsed.signingInput, parsed.signature, jwk)) return fail('signature', 'signature verifies', 401, 'invalid_token', 'The signature does not verify: the token was altered or was not signed by the issuer.');
  pass('signature', 'signature verifies');

  if (payload.iss !== policy.issuer) return fail('iss', 'issuer is trusted', 401, 'invalid_token', 'The token was issued by an issuer this server does not trust.');
  pass('iss', 'issuer is trusted');

  if (typeof payload.exp !== 'number' || payload.exp + LEEWAY_S <= now) return fail('exp', 'not expired', 401, 'invalid_token', typeof payload.exp === 'number' ? 'The token has expired.' : 'The token has no expiry (exp).');
  pass('exp', 'not expired');

  if (typeof payload.nbf === 'number' && payload.nbf - LEEWAY_S > now) return fail('nbf', 'already valid (nbf)', 401, 'invalid_token', 'The token is not valid yet (nbf is in the future).');
  pass('nbf', 'already valid (nbf)');

  if (!aud(payload.aud).includes(policy.audience)) return fail('aud', 'audience is this resource', 401, 'invalid_token', 'The token was issued for a different audience (resource). A token for another API must not be accepted here or passed through (RFC 8707).');
  pass('aud', 'audience is this resource');

  if (policy.requireActor && !(payload.act && typeof payload.act === 'object' && (payload.act.sub || payload.act.client_id))) {
    return fail('actor', 'token is an agent (act) token', 403, 'insufficient_scope', 'This tool accepts delegated agent tokens (with an "act" claim). A plain user token is not accepted for agent calls.');
  }
  if (policy.requireActor) pass('actor', 'token is an agent (act) token');

  const scopes = typeof payload.scope === 'string' ? payload.scope.split(/\s+/) : [];
  if (!scopes.includes(policy.requiredScope)) return fail('scope', 'has the required scope', 403, 'insufficient_scope', `The token does not carry the scope this call needs (${policy.requiredScope}).`);
  pass('scope', 'has the required scope');

  return { ok: true, status: 200, claims: payload, checks };
}

