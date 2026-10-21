// C2: token-flow comparison. A small data-driven catalog of six mechanisms and a mock flow runner.
// Each mechanism names ONE attack it defends against, lists the steps of the flow (some only with or only without the
// protection) and has a `decide` function that actually computes the attack outcome from hashes or signatures built
// in memory, so the verdict is derived, not typed in. Nothing here touches a network; keys and certificates are
// generated per run and thrown away.
import crypto from 'node:crypto';
import { b64u, jwkThumbprint, signJwt, verifyEs256, parseJwt } from './jwt.js';

const sha = (s) => crypto.createHash('sha256').update(s).digest();
const ec = () => { const k = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); return { priv: k.privateKey, jwk: k.publicKey.export({ format: 'jwk' }) }; };
const rnd = () => b64u(crypto.randomBytes(24));

// Actors: client, browser, as (authorization server), rs (resource server), attacker.
// when: 'both' (default) | 'protected' | 'unprotected'. `evil: true` marks a step the attacker performs.
export const MECHANISMS = [
  {
    id: 'pkce', name: 'PKCE', rfc: 'RFC 7636', adds: 'A one-time secret (code_verifier) proves the party redeeming the code is the one that started the flow.',
    attack: { id: 'code-interception', title: 'Authorization code interception', description: 'An attacker who can read the redirect (a malicious app on the device, a leaked log, a rogue browser extension) steals the authorization code and redeems it first.' },
    limits: 'Does not authenticate the client, does not bind the access token to anything, and does nothing if the attacker can also read the verifier.',
    steps: [
      { from: 'client', to: 'client', label: 'Create code_verifier and send its S256 hash as code_challenge', when: 'protected' },
      { from: 'client', to: 'as', label: 'GET /authorize (response_type=code, redirect_uri)', when: 'unprotected' },
      { from: 'client', to: 'as', label: 'GET /authorize (+ code_challenge, method S256)', when: 'protected' },
      { from: 'as', to: 'browser', label: '302 redirect_uri?code=...' },
      { from: 'attacker', to: 'as', label: 'POST /token with the stolen code', evil: true },
    ],
    decide(p) {
      const verifier = rnd(); const challenge = b64u(sha(verifier)); const attackerGuess = rnd();
      const checked = p ? b64u(sha(attackerGuess)) === challenge : true; // without PKCE nothing is checked
      return checked ? { succeeds: true, reason: 'The server had no challenge to compare against, so the stolen code was redeemed.' }
        : { succeeds: false, reason: 'S256(attacker verifier) does not equal the stored code_challenge, so the token request was refused (invalid_grant).' };
    },
  },
  {
    id: 'par', name: 'PAR', rfc: 'RFC 9126', adds: 'The client sends the authorization request directly to the server (back channel) and the browser carries only a short request_uri.',
    attack: { id: 'param-tampering', title: 'Authorization request tampering in the browser', description: 'Request parameters in the URL can be read and edited by the browser, an extension or a malicious link. The attacker widens the scope before the user approves.' },
    limits: 'Does not stop a stolen token or a stolen code; it protects the request, not the response.',
    steps: [
      { from: 'client', to: 'as', label: 'POST /par (client-authenticated, scope=read)', when: 'protected' },
      { from: 'as', to: 'client', label: '201 request_uri=urn:...:abc', when: 'protected' },
      { from: 'client', to: 'browser', label: 'redirect to /authorize?scope=read&redirect_uri=...', when: 'unprotected' },
      { from: 'client', to: 'browser', label: 'redirect to /authorize?client_id&request_uri', when: 'protected' },
      { from: 'attacker', to: 'browser', label: 'edit the URL: scope=read admin', evil: true },
      { from: 'browser', to: 'as', label: 'GET /authorize (as edited)' },
    ],
    decide(p) {
      const original = { scope: 'read' };
      const inUrl = { scope: 'read admin' };
      const effective = p ? original : inUrl; // with PAR the server uses what was pushed, the URL has no scope to edit
      return effective.scope !== original.scope ? { succeeds: true, reason: 'The server read scope from the edited URL and showed the user a consent for "read admin".' }
        : { succeeds: false, reason: 'The server used the parameters stored at PAR time (scope=read); anything edited in the URL is ignored.' };
    },
  },
  {
    id: 'rar', name: 'RAR', rfc: 'RFC 9396', adds: 'authorization_details describe exactly what is allowed (type, amount, recipient) instead of a broad scope.',
    attack: { id: 'overbroad-token', title: 'Over-broad token reuse', description: 'A token granted for "payments" is used for a different, larger payment than the user approved.' },
    limits: 'The resource server must actually compare the request with authorization_details; the protocol only carries them.',
    steps: [
      { from: 'client', to: 'as', label: 'authorize: scope=payments', when: 'unprotected' },
      { from: 'client', to: 'as', label: 'authorize: authorization_details=[{type:payment, amount:10, creditor:A}]', when: 'protected' },
      { from: 'as', to: 'client', label: 'access token (scope payments)', when: 'unprotected' },
      { from: 'as', to: 'client', label: 'access token carrying the authorization_details', when: 'protected' },
      { from: 'attacker', to: 'rs', label: 'POST /pay amount=5000 creditor=B with that token', evil: true },
    ],
    decide(p) {
      const approved = { type: 'payment', amount: 10, creditor: 'A' }; const attempt = { amount: 5000, creditor: 'B' };
      const permitted = p ? attempt.amount <= approved.amount && attempt.creditor === approved.creditor : true;
      return permitted ? { succeeds: true, reason: 'The token only said "payments", so the resource server had nothing finer to check and paid 5000 to B.' }
        : { succeeds: false, reason: 'The request (5000 to B) is outside the approved details (10 to A), so the resource server refused it.' };
    },
  },
  {
    id: 'dpop', name: 'DPoP', rfc: 'RFC 9449', adds: 'The access token is bound to a client key (cnf.jkt); every request carries a signed proof from that key.',
    attack: { id: 'token-theft-replay', title: 'Stolen access token replay', description: 'An attacker obtains the access token (log, proxy, compromised API) and presents it to the resource server.' },
    limits: 'Does not stop an attacker who also steals the private key, or a malicious client on the same device that can use the key.',
    steps: [
      { from: 'client', to: 'as', label: 'POST /token (+ DPoP proof signed by the client key)', when: 'protected' },
      { from: 'client', to: 'as', label: 'POST /token', when: 'unprotected' },
      { from: 'as', to: 'client', label: 'access token with cnf.jkt = thumbprint(client key)', when: 'protected' },
      { from: 'as', to: 'client', label: 'bearer access token (no cnf)', when: 'unprotected' },
      { from: 'attacker', to: 'rs', label: 'GET /api with the stolen token (and a proof from the attacker\'s own key)', evil: true },
    ],
    decide(p) {
      const client = ec(); const attacker = ec();
      const cnfJkt = jwkThumbprint(client.jwk);
      const proofKeyJkt = jwkThumbprint(attacker.jwk);
      const accepted = p ? proofKeyJkt === cnfJkt : true;
      return accepted ? { succeeds: true, reason: 'A bearer token works for whoever holds it, so the replay was accepted.' }
        : { succeeds: false, reason: 'The proof key thumbprint does not match the token\'s cnf.jkt, so the resource server refused the stolen token.' };
    },
  },
  {
    id: 'mtls', name: 'mTLS', rfc: 'RFC 8705', adds: 'The access token is bound to the client\'s TLS certificate (cnf["x5t#S256"]).',
    attack: { id: 'token-theft-replay', title: 'Stolen access token replay', description: 'The same theft as for DPoP, answered at the TLS layer instead of with a per-request proof.' },
    limits: 'Needs client certificates and a TLS termination that passes them on; a mock certificate is used here, no TLS is performed.',
    steps: [
      { from: 'client', to: 'as', label: 'POST /token over mutual TLS (client certificate)', when: 'protected' },
      { from: 'client', to: 'as', label: 'POST /token', when: 'unprotected' },
      { from: 'as', to: 'client', label: 'access token with cnf x5t#S256 = hash(client certificate)', when: 'protected' },
      { from: 'as', to: 'client', label: 'bearer access token (no cnf)', when: 'unprotected' },
      { from: 'attacker', to: 'rs', label: 'call the API with the stolen token over the attacker\'s own TLS connection', evil: true },
    ],
    decide(p) {
      const clientCert = crypto.randomBytes(64); const attackerCert = crypto.randomBytes(64); // stand-ins for DER certificates
      const bound = b64u(sha(clientCert));
      const accepted = p ? b64u(sha(attackerCert)) === bound : true;
      return accepted ? { succeeds: true, reason: 'Nothing tied the token to a certificate, so the attacker\'s call was accepted.' }
        : { succeeds: false, reason: 'The certificate presented in the TLS handshake does not hash to the token\'s x5t#S256, so the call was refused.' };
    },
  },
  {
    id: 'jar', name: 'JAR', rfc: 'RFC 9101', adds: 'The authorization request is a signed JWT (request object), so the server can tell who wrote it and that it was not changed.',
    attack: { id: 'request-forgery', title: 'Forged or altered authorization request', description: 'An attacker alters the request parameters on the way (redirect_uri, scope) or builds a request pretending to be the client.' },
    limits: 'Protects integrity and origin of the request; still needs PKCE/PAR for the code and a way to register the client\'s keys. Simulated here with an ES256 signature.',
    steps: [
      { from: 'client', to: 'client', label: 'Sign the request parameters as a JWT with the client key', when: 'protected' },
      { from: 'client', to: 'browser', label: 'redirect to /authorize?client_id&request=<signed JWT>', when: 'protected' },
      { from: 'client', to: 'browser', label: 'redirect to /authorize?client_id&redirect_uri&scope (plain parameters)', when: 'unprotected' },
      { from: 'attacker', to: 'browser', label: 'change redirect_uri to the attacker\'s page', evil: true },
      { from: 'browser', to: 'as', label: 'GET /authorize (as altered)' },
    ],
    decide(p) {
      const client = ec();
      const header = { alg: 'ES256', typ: 'oauth-authz-req+jwt', kid: 'client-1' };
      const good = signJwt(header, { client_id: 'c1', redirect_uri: 'https://client.example/cb', scope: 'read' }, client.priv);
      const parts = parseJwt(good);
      const altered = `${parts.parts[0]}.${b64u(JSON.stringify({ ...parts.payload, redirect_uri: 'https://attacker.example/steal' }))}.${parts.parts[2]}`;
      const a = parseJwt(altered);
      const intact = p ? verifyEs256(a.signingInput, a.signature, client.jwk) : true; // plain parameters have nothing to verify
      return intact ? { succeeds: true, reason: 'The plain parameters carried no signature, so the server accepted the attacker\'s redirect_uri.' }
        : { succeeds: false, reason: 'The signature over the request object no longer verifies after the edit, so the server rejected the request.' };
    },
  },
];

const publicEntry = ({ id, name, rfc, adds, attack, limits }) => ({ id, name, rfc, adds, attack, limits });
export const listMechanisms = () => MECHANISMS.map(publicEntry);

export function runFlow(id, protectedFlag) {
  const m = MECHANISMS.find((x) => x.id === id);
  if (!m) { const e = new Error('no such mechanism'); e.code = 'unknown_mechanism'; throw e; }
  const p = Boolean(protectedFlag);
  const steps = m.steps.filter((s) => (s.when ?? 'both') === 'both' || s.when === (p ? 'protected' : 'unprotected')).map((s, i) => ({ n: i + 1, from: s.from, to: s.to, label: s.label, evil: Boolean(s.evil) }));
  const d = m.decide(p);
  const outcome = d.succeeds ? 'attack_succeeds' : 'attack_blocked';
  return { mechanism: publicEntry(m), protected: p, steps, attack: { ...m.attack, outcome, reason: d.reason }, pass: !d.succeeds, simulated: true };
}

// Side by side: every mechanism with and without its protection.
export function compare() {
  return {
    simulated: true,
    rows: MECHANISMS.map((m) => {
      const off = runFlow(m.id, false); const on = runFlow(m.id, true);
      return { ...publicEntry(m), without: { outcome: off.attack.outcome, pass: off.pass }, with: { outcome: on.attack.outcome, pass: on.pass } };
    }),
  };
}
