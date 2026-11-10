import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { PACK_PATH, buildPack, serialize } from './build-content-pack.mjs';
import { validatePack } from './validate-content-pack.mjs';

test('content-pack.json is exactly what the generator produces (run: npm run content-pack)', () => {
  assert.equal(fs.readFileSync(PACK_PATH, 'utf8'), serialize(buildPack()), 'content-pack.json is stale; regenerate it and commit the result');
});

test('the generator is deterministic', () => assert.equal(serialize(buildPack()), serialize(buildPack())));

test('content-pack.json validates against docs/content-pack.schema.json', () => {
  assert.deepEqual(validatePack(JSON.parse(fs.readFileSync(PACK_PATH, 'utf8'))), []);
});

test('the validator rejects a broken pack', () => {
  const pack = buildPack();
  pack.cards[0].terms = ['no-such-term'];
  delete pack.title;
  assert.ok(validatePack(pack).length >= 2);
});

test('the pack covers the app and carries the caveats: decode vs verify, wrong tokens, UNVERIFIED FAPI, simulation, mock only', () => {
  const pack = buildPack();
  for (const id of ['decode-vs-verify', 'wrong-token-tester', 'oauth-profile-checker', 'fapi-2-0-unverified', 'flow-catalog-simulation', 'mock-only', 'pkce', 'par', 'rar', 'dpop', 'jar', 'inert-text']) assert.ok(pack.glossary.some((g) => g.id === id), id);
  assert.deepEqual(pack.sources, []);
  assert.equal(pack.demo.baseUrl, 'http://localhost:5910');
  assert.equal(pack.demo.catalog, 'C2');
  const text = (id) => pack.glossary.find((g) => g.id === id).definition;
  assert.match(text('fapi-2-0-unverified'), /not a conformance suite/);
  assert.match(pack.glossary.find((g) => g.id === 'fapi-2-0-unverified').term, /UNVERIFIED/);
  assert.match(text('flow-catalog-simulation'), /does not run the real protocols and models no product/);
  assert.match(text('rfc-9700-pack'), /only RFC numbers are cited/);
  assert.match(text('mock-only'), /no live mode/);
  assert.match(text('real-mode'), /Off unless the owner sets TW_REAL=1/);
  assert.match(text('real-mode'), /origin only/);
  assert.match(text('real-mode'), /client secret is never shown/);
  assert.match(pack.stories.find((s) => s.id === 'S03').say, /UNVERIFIED/);
  assert.match(pack.stories.find((s) => s.id === 'S04').say, /simulation/);
});

test('every card is covered by a tab of the UI and names a real story', () => {
  const app = fs.readFileSync(new URL('../web/src/App.jsx', import.meta.url), 'utf8');
  for (const c of buildPack().cards) assert.ok(app.includes(`["${c.id}",`), `App.jsx has no tab ${c.id}`);
});

test('every story says exactly what the UI story strip says', () => {
  const jsx = fs.readFileSync(new URL('../web/src/components/Story.jsx', import.meta.url), 'utf8');
  for (const s of buildPack().stories) assert.ok(jsx.includes(`"${s.say}"`), `Story.jsx does not carry the text of ${s.id}`);
});

test('a commit is recorded only when passed', () => {
  assert.equal(buildPack().source, undefined);
  assert.equal(buildPack({ commit: 'abc1234' }).source.commit, 'abc1234');
});
