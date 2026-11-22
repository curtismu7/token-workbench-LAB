#!/usr/bin/env node
// Token Workbench LAB companion MCP server (stdio).
//
// Exposes the lab's HTTP routes as MCP tools: decode a token, run the checker
// packs, run the tester cases, and mint the real client_credentials sample.
// The lab stays the single source of state; this server is a thin proxy.
//
// Configuration:
//   TW_LAB_BASE  base URL of a running Token Workbench LAB (default http://localhost:5910)
//
// Run: node mcp/server.mjs

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const BASE = (process.env.TW_LAB_BASE || 'http://localhost:5910').replace(/\/+$/, '');
const ORIGIN = process.env.TW_LAB_ORIGIN || 'http://localhost:5910';

async function call(path, { method = 'GET', body } = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      origin: ORIGIN,
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text }; }
  return { status: res.status, body: json };
}

const text = (r) => ({ content: [{ type: 'text', text: JSON.stringify(r, null, 2) }] });

const server = new McpServer({
  name: 'token-workbench-lab',
  version: '0.1.0',
  title: 'Token Workbench LAB tools',
  description: 'Drive Token Workbench LAB: decode tokens with per-claim meaning, run the BCP/FAPI checker packs against the configured issuer, run the tester case suite against the lab\'s stubs, and mint the real client_credentials sample.',
});

server.registerTool('tw_health', {
  title: 'Lab health',
  description: 'Check the lab is running and report its runtime state.',
  inputSchema: {},
}, async () => text(await call('/api/health')));

server.registerTool('tw_info', {
  title: 'Build info',
  description: 'Mode, source (mock or real), the configured issuer and stub profiles — never a secret.',
  inputSchema: {},
}, async () => text(await call('/api/info')));

server.registerTool('tw_decode', {
  title: 'Decode a token',
  description: 'Decode a JWT (header, payload, claims with per-claim meaning and RFC citations). Opaque (non-JWT) tokens answer 400 not_a_jwt.',
  inputSchema: { token: z.string().describe('Compact JWT to decode') },
}, async ({ token }) => text(await call('/api/decode', { method: 'POST', body: { token } })));

server.registerTool('tw_mint', {
  title: 'Mint the client_credentials sample',
  description: 'Mint a real access token from the configured issuer (Real mode; needs the PingOne worker settings). In mock mode the lab says what it would do instead.',
  inputSchema: {},
}, async () => text(await call('/api/mint', { method: 'POST', body: { sample: 'client_credentials' } })));

server.registerTool('tw_introspect', {
  title: 'Introspect a token',
  description: 'Introspect a token at the configured issuer (Real mode).',
  inputSchema: { token: z.string() },
}, async ({ token }) => text(await call('/api/introspect', { method: 'POST', body: { token } })));

server.registerTool('tw_tester_cases', {
  title: 'Tester cases',
  description: 'The tester case list (good token, expired, wrong audience, wrong scope, ...).',
  inputSchema: {},
}, async () => text(await call('/api/tester/cases')));

server.registerTool('tw_tester_run', {
  title: 'Run tester cases',
  description: 'Run one case by id (from tw_tester_cases) or "all", against the lab\'s stub resource server.',
  inputSchema: { caseId: z.string().describe('A case id, or "all"') },
}, async ({ caseId }) => text(await call('/api/tester/run', { method: 'POST', body: { case: caseId } })));

server.registerTool('tw_checker_run', {
  title: 'Run a checker pack',
  description: 'Run the checker against the configured issuer. pack: bcp, fapi or both.',
  inputSchema: { pack: z.enum(['bcp', 'fapi', 'both']).default('bcp') },
}, async ({ pack }) => text(await call('/api/checker/run', { method: 'POST', body: { pack } })));

server.registerTool('tw_flows', {
  title: 'Flow mechanisms (simulated)',
  description: 'The simulated OAuth/OIDC mechanism catalog and comparison. Simulated by design.',
  inputSchema: {},
}, async () => text(await call('/api/flows/compare')));

const transport = new StdioServerTransport();
await server.connect(transport);
