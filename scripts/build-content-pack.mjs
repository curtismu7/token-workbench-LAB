#!/usr/bin/env node
/**
 * Generates content-pack.json (repo root). Format: docs/content-pack.schema.json (a copy of the Learning Hub / ID-JAG kit schema).
 * Glossary from content/terms.json, stories from content/stories.json (same text as web/src/components/Story.jsx; a test checks that),
 * cards for the four UI tabs. Deterministic: lists sorted by id, 2-space JSON, no timestamps. The git commit is recorded only when
 * passed (--commit=<sha>), so a plain run is reproducible.
 *
 * Sources: none. The RFC numbers named in the glossary were not checked against the RFC text (no network), so the pack lists no source and claims none verified.
 *
 *   node scripts/build-content-pack.mjs [--commit=<sha>]
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const PACK_PATH = path.join(ROOT, 'content-pack.json');
const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

// The UI has four tabs and no deep links, so every card opens the app root.
const CARDS = [
  { id: 'decode', label: 'Decode and trace a token', description: 'Mint a sample token or paste one, read each claim in plain English, and check the signature against the stub keys.', group: 'try-it', href: '/', terms: ['decode-vs-verify', 'audience', 'sender-constrained-token', 'inert-text'], story: 'S01' },
  { id: 'tester', label: 'Wrong-token tester', description: 'Send fifteen tokens (one correct, fourteen wrong) to the stub resource server and compare expected with actual.', group: 'try-it', href: '/', terms: ['wrong-token-tester', 'alg-confusion', 'audience', 'www-authenticate', 'fail-closed'], story: 'S02' },
  { id: 'checker', label: 'OAuth profile checker', description: 'Run the RFC 9700 pack and the UNVERIFIED FAPI 2.0 pack against five stub authorization servers.', group: 'try-it', href: '/', terms: ['oauth-profile-checker', 'rfc-9700-pack', 'fapi-2-0-unverified', 'mock-only'], story: 'S03' },
  { id: 'flows', label: 'Token-flow comparison', description: 'PKCE, PAR, RAR, DPoP, mTLS and JAR with and without protection, as a movable diagram with Simulate. A simulation.', group: 'concept', href: '/', terms: ['pkce', 'par', 'rar', 'dpop', 'jar', 'flow-catalog-simulation'], story: 'S04' },
];

export function buildPack({ commit } = {}) {
  const pkg = readJson('package.json');
  const stories = readJson('content/stories.json').sort(byId);
  const ids = new Set(stories.map((s) => s.id));
  const pack = {
    schema: 'demo-content-pack/1',
    id: 'token-workbench',
    title: 'Token Workbench',
    version: pkg.version,
    ...(commit ? { source: { repo: 'token-workbench', commit } } : {}),
    demo: { id: 'token-workbench', name: 'Token Workbench', catalog: 'C2', baseUrl: 'http://localhost:5910', doctor: '/api/health', tags: ['oauth', 'jwt', 'token', 'mock-only', 'simulation'] },
    glossary: readJson('content/terms.json').sort(byId),
    sources: [],
    cards: CARDS.map(({ href, ...c }) => ({ ...c, action: { type: 'route', href } })).sort(byId),
    diagrams: [{ id: 'flows', label: 'Token-flow comparison', href: '/' }],
    stories,
  };
  for (const c of pack.cards) if (c.story && !ids.has(c.story)) throw new Error(`card ${c.id} names unknown story ${c.story}`);
  return pack;
}

export const serialize = (pack) => `${JSON.stringify(pack, null, 2)}\n`;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const commit = process.argv.find((a) => a.startsWith('--commit='))?.slice(9);
  fs.writeFileSync(PACK_PATH, serialize(buildPack({ commit })));
  console.log(`wrote ${path.relative(process.cwd(), PACK_PATH) || PACK_PATH}`);
}
