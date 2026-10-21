// Stub MCP-style resource server + stub issuer (JWKS), in this process, loopback only.
//   POST /mcp                                      JSON-RPC (tools/list, tools/call); needs a Bearer token
//   GET  /.well-known/oauth-protected-resource     RFC 9728 metadata
//   GET  /issuer/.well-known/jwks.json             the stub issuer's public keys
// Validates with validator.js; the error answers carry RFC 6750 WWW-Authenticate challenges.
import express from 'express';
import { hostGuard } from '../safety.js';
import { validateToken } from '../validator.js';
import { identifiers } from '../keys.js';

export const REQUIRED_SCOPE = 'mcp:tools';

export function startResourceServer({ port, keyring, audience = identifiers(port).resource, now = () => Date.now() / 1000 }) {
  const app = express();
  app.disable('x-powered-by');
  app.use(hostGuard);
  const origin = `http://127.0.0.1:${port}`;
  const metadataUrl = `${origin}/.well-known/oauth-protected-resource`;
  const policy = { issuer: keyring.issuer, audience, requiredScope: REQUIRED_SCOPE, requireActor: true, jwks: () => keyring.jwks(), now };
  const stats = { requests: 0 };

  app.get('/.well-known/oauth-protected-resource', (_req, res) => res.json({ resource: audience, authorization_servers: [keyring.issuer], scopes_supported: [REQUIRED_SCOPE], bearer_methods_supported: ['header'] }));
  app.get('/issuer/.well-known/jwks.json', (_req, res) => res.json(keyring.jwks()));

  app.post('/mcp', express.json({ limit: '4kb' }), (req, res) => {
    stats.requests += 1;
    const challenge = (attrs) => `Bearer realm="tw-mcp"${attrs ? `, ${attrs}` : ''}, resource_metadata="${metadataUrl}"`;
    const header = req.headers.authorization;
    const m = typeof header === 'string' ? /^Bearer\s+(\S+)$/i.exec(header) : null;
    if (!m) {
      return res.set('WWW-Authenticate', challenge('')).status(401).json({ error: 'invalid_request', error_description: 'No bearer token was sent.', failed_check: 'missing', checks: [{ id: 'missing', label: 'bearer token present', pass: false }] });
    }
    const v = validateToken(m[1], policy);
    if (!v.ok) {
      const scope = v.error === 'insufficient_scope' ? `, scope="${REQUIRED_SCOPE}"` : '';
      return res.set('WWW-Authenticate', challenge(`error="${v.error}", error_description="${v.error_description.replace(/"/g, "'")}"${scope}`))
        .status(v.status).json({ error: v.error, error_description: v.error_description, failed_check: v.failed_check, checks: v.checks });
    }
    const { id = null, method } = req.body || {};
    if (method === 'tools/list') return res.json({ jsonrpc: '2.0', id, result: { tools: [{ name: 'echo', description: 'Echoes its input.' }] }, checks: v.checks });
    if (method === 'tools/call') return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'echo: ok' }] }, checks: v.checks });
    return res.status(400).json({ jsonrpc: '2.0', id, error: { code: -32601, message: 'method not found' } });
  });
  app.use((_req, res) => res.status(404).json({ error: 'not_found' }));
  app.use((_err, _req, res, _next) => res.status(400).json({ error: 'bad_request' }));

  return new Promise((resolve, reject) => {
    const server = app.listen(port, '127.0.0.1');
    server.once('error', reject);
    server.once('listening', () => resolve({
      port, host: server.address().address, url: `${origin}/mcp`, jwksUrl: `${origin}/issuer/.well-known/jwks.json`, stats,
      close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
    }));
  });
}
