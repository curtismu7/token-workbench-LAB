// Offline JWT handling: parse, explain, sign (stub keys only), verify (stub JWKS only). No network, no logging.
import crypto from 'node:crypto';
import { inertValue, revealText } from './sanitize.js';

export const b64u = (buf) => Buffer.from(buf).toString('base64url');
const fromB64u = (s) => Buffer.from(s, 'base64url');
export const b64uJson = (obj) => b64u(JSON.stringify(obj));

// P-256 key pair built from an ECDH key, kept in memory only (the crypto keygen helpers abort on Node 20 in CI).
export function generateEcKeyPair() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const pub = ecdh.getPublicKey();
  const d = Buffer.alloc(32); ecdh.getPrivateKey().copy(d, 32 - ecdh.getPrivateKey().length);
  const jwk = { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
  return {
    publicKey: crypto.createPublicKey({ key: jwk, format: 'jwk' }),
    privateKey: crypto.createPrivateKey({ key: { ...jwk, d: b64u(d) }, format: 'jwk' }),
  };
}

export const MAX_TOKEN_CHARS = 8192;
const TOKEN_CHARS = /^[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/;

// parseJwt: structure only. Never throws; returns { ok:false, reason } for anything that is not a three-part JWT
// with JSON object header and payload.
export function parseJwt(token) {
  if (typeof token !== 'string' || !token) return { ok: false, reason: 'token must be a non-empty string' };
  const t = token.trim();
  if (t.length > MAX_TOKEN_CHARS) return { ok: false, reason: `token is longer than ${MAX_TOKEN_CHARS} characters` };
  if (!TOKEN_CHARS.test(t)) return { ok: false, reason: 'not a compact JWS: expected three base64url parts separated by dots' };
  const [h, p, s] = t.split('.');
  let header; let payload;
  try { header = JSON.parse(fromB64u(h).toString('utf8')); } catch { return { ok: false, reason: 'header is not base64url JSON' }; }
  try { payload = JSON.parse(fromB64u(p).toString('utf8')); } catch { return { ok: false, reason: 'payload is not base64url JSON' }; }
  const isObj = (o) => o && typeof o === 'object' && !Array.isArray(o);
  if (!isObj(header) || !isObj(payload)) return { ok: false, reason: 'header and payload must be JSON objects' };
  return { ok: true, header, payload, signingInput: `${h}.${p}`, signature: s, parts: [h, p, s] };
}

export function signJwt(header, payload, privateKey) {
  const input = `${b64uJson(header)}.${b64uJson(payload)}`;
  const sig = crypto.sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${b64u(sig)}`;
}

export function verifyEs256(signingInput, signatureB64u, jwk) {
  try {
    const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    return crypto.verify('sha256', Buffer.from(signingInput), { key, dsaEncoding: 'ieee-p1363' }, fromB64u(signatureB64u));
  } catch { return false; }
}

// RFC 7638 thumbprint of an EC public JWK (used for cnf.jkt).
export function jwkThumbprint(jwk) {
  const canon = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return b64u(crypto.createHash('sha256').update(canon).digest());
}

const KNOWN_CLAIMS = new Set(['iss', 'sub', 'aud', 'scope', 'scp', 'client_id', 'azp', 'act', 'may_act', 'cnf', 'iat', 'nbf', 'exp', 'jti']);
const fmtTime = (secs) => new Date(secs * 1000).toISOString();
const asList = (v) => (Array.isArray(v) ? v : v === undefined ? [] : [v]);

// Plain-English explanation of each claim that is present. Server-generated text; claim VALUES that are echoed are
// made inert (hidden characters shown as [U+XXXX], bounded).
export function explainClaims(header, payload, nowSec) {
  const out = [];
  const add = (name, value, meaning, level = 'info') => out.push({ name, value: inertValue(value), meaning, level });
  const q = (v) => revealText(typeof v === 'string' ? v : JSON.stringify(v), 120);

  if ('alg' in header) {
    const alg = String(header.alg);
    if (alg.toLowerCase() === 'none') add('alg', header.alg, 'alg "none" means the token is unsigned. Anyone can write one. A resource server must reject it.', 'danger');
    else if (/^HS/i.test(alg)) add('alg', header.alg, 'A shared-secret (HMAC) algorithm. Only a party holding the secret can verify it; an API that accepts both HS and public-key algorithms can be tricked (algorithm confusion).', 'warn');
    else add('alg', header.alg, `The signature algorithm. ${revealText(alg, 20)} is a public-key signature: the issuer signs with a private key, anyone can verify with the published key.`);
  }
  if ('kid' in header) add('kid', header.kid, 'The key id: which key in the issuer\'s JWKS signed this token.');
  if ('typ' in header) add('typ', header.typ, 'The token type. "at+jwt" (RFC 9068) marks a JWT access token so an ID token cannot be replayed as one.');
  if ('iss' in payload) add('iss', payload.iss, `The issuer: who created the token (${q(payload.iss)}). A resource server accepts only issuers it trusts.`);
  if ('sub' in payload) add('sub', payload.sub, `The subject: who the token is about (${q(payload.sub)}). For a user token this is the user; for a client-credentials token it is the client.`);
  if ('aud' in payload) {
    const list = asList(payload.aud);
    add('aud', payload.aud, `The audience: which resource server(s) may accept this token (${list.map(q).join(', ')}). A server must reject a token whose audience does not include itself (RFC 8707, RFC 9068).`);
  }
  if ('scope' in payload) {
    add('scope', payload.scope, `The permissions granted: ${typeof payload.scope === 'string' ? payload.scope.split(/\s+/).filter(Boolean).map(q).join(', ') || '(none)' : q(payload.scope)}. A call that needs a scope not in this list should get 403 insufficient_scope.`);
  }
  if ('scp' in payload) add('scp', payload.scp, 'The permissions granted (some issuers use "scp" instead of "scope").');
  if ('client_id' in payload) add('client_id', payload.client_id, `The OAuth client the token was issued to (${q(payload.client_id)}).`);
  if ('azp' in payload) add('azp', payload.azp, `The authorized party: the client the token was issued to (${q(payload.azp)}).`);
  if ('act' in payload) {
    const actor = payload.act && typeof payload.act === 'object' ? payload.act.sub ?? payload.act.client_id : undefined;
    add('act', payload.act, `The actor (RFC 8693 delegation): ${actor === undefined ? 'someone' : q(actor)} is acting on behalf of the subject. A token with "act" is an agent acting for a user; a token without it is the user's own.`);
  }
  if ('may_act' in payload) add('may_act', payload.may_act, 'Names who is allowed to act for this subject (RFC 8693): permission to delegate, not delegation itself.');
  if ('cnf' in payload) {
    const cnf = payload.cnf && typeof payload.cnf === 'object' ? payload.cnf : {};
    if ('jkt' in cnf) add('cnf.jkt', cnf.jkt, 'Sender-constrained with DPoP (RFC 9449): the token is bound to a key whose thumbprint is this value. A thief without the key cannot use it.');
    else if ('x5t#S256' in cnf) add('cnf.x5t#S256', cnf['x5t#S256'], 'Sender-constrained with mutual TLS (RFC 8705): the token is bound to this client certificate thumbprint.');
    else add('cnf', payload.cnf, 'A confirmation claim (RFC 7800): binds the token to a proof-of-possession key.');
  } else {
    add('cnf', null, 'No cnf claim: this is a bearer token. Whoever holds it can use it (not bound to a DPoP key or a client certificate).', 'warn');
  }
  for (const [name, label] of [['iat', 'issued at'], ['nbf', 'not valid before'], ['exp', 'expires']]) {
    if (!(name in payload)) continue;
    const v = payload[name];
    if (typeof v !== 'number' || !Number.isFinite(v)) { add(name, v, `${name} must be a number of seconds since 1970; this value is not.`, 'warn'); continue; }
    let meaning = `${label}: ${fmtTime(v)}.`;
    let level = 'info';
    if (name === 'exp') { if (v <= nowSec) { meaning += ` Expired ${Math.round(nowSec - v)} s ago.`; level = 'danger'; } else meaning += ` Valid for another ${Math.round(v - nowSec)} s.`; }
    if (name === 'nbf' && v > nowSec) { meaning += ` Not yet valid: ${Math.round(v - nowSec)} s to go.`; level = 'danger'; }
    add(name, v, meaning, level);
  }
  if ('jti' in payload) add('jti', payload.jti, 'A unique token id, usable to detect replay or to revoke one token.');
  // Any other claim is listed too (bounded), so nothing in the payload is hidden from the table.
  let extra = 0;
  for (const [k, v] of Object.entries(payload)) {
    if (KNOWN_CLAIMS.has(k)) continue;
    if ((extra += 1) > 50) break;
    add(revealText(k, 128), v, 'A claim this workbench does not explain. Shown as the token carries it.');
  }
  return out;
}

export function timeStatus(payload, nowSec) {
  const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
  const exp = num(payload.exp); const nbf = num(payload.nbf);
  return {
    hasExp: exp !== null, expired: exp !== null && exp <= nowSec, secondsToExpiry: exp === null ? null : Math.round(exp - nowSec),
    notYetValid: nbf !== null && nbf > nowSec,
  };
}
