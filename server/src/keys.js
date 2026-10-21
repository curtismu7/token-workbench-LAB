// Stub issuer keys. Generated in memory at startup; the private keys are never written anywhere and never returned.
import crypto from 'node:crypto';
import { jwkThumbprint, signJwt } from './jwt.js';

// Identifiers of the stub issuer and resources, derived from the port the resource server listens on.
export const identifiers = (port) => ({ issuer: `http://127.0.0.1:${port}/issuer`, resource: `http://127.0.0.1:${port}/mcp`, downstream: `http://127.0.0.1:${port}/downstream-api` });

export function createKeyring({ issuer }) {
  const gen = () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const main = gen(); const rogue = gen(); const client = gen();
  const kid = `tw-${crypto.randomBytes(4).toString('hex')}`;
  const publicJwk = { ...main.publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'ES256' };
  const clientJwk = client.publicKey.export({ format: 'jwk' });
  return {
    issuer, kid,
    jwks: () => ({ keys: [{ ...publicJwk }] }),
    clientJkt: jwkThumbprint(clientJwk), // a stand-in DPoP key thumbprint for sample tokens
    sign: (header, payload) => signJwt({ alg: 'ES256', typ: 'at+jwt', kid, ...header }, payload, main.privateKey),
    signWithRogueKey: (header, payload) => signJwt({ alg: 'ES256', typ: 'at+jwt', kid, ...header }, payload, rogue.privateKey),
    // The public key's x coordinate used as an HMAC secret: the classic algorithm-confusion attack.
    publicKeyAsHmacSecret: () => Buffer.from(publicJwk.x, 'base64url'),
  };
}
