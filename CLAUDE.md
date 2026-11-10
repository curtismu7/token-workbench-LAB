# CLAUDE.md

Token Workbench is a workbench for OAuth and JWT tokens (tier: Tester), Mock by default with an owner opt-in Real mode (`TW_REAL*` in the lab's `.env`; README "Real mode"). It decodes and explains a token offline, sends 15 wrong tokens to a stub resource server, checks five stub authorization servers against OAuth rules, and compares PKCE, PAR, RAR, DPoP, mTLS and JAR with and without protection. Everything runs in-process on loopback. Details are in [README.md](README.md), [docs/safety.md](docs/safety.md) and [docs/architecture.md](docs/architecture.md); do not copy them here.

## Commands (from package.json)

```bash
npm install
npm test             # server (node:test) + web (vitest) + node --test scripts/*.test.mjs
npm run build        # web/dist, served by the server at /
npm run doctor       # node, bind, port range, free ports
npm run e2e          # real Chromium on port 5940; build first
npm run e2e:real     # Real mode in Chromium against a stub issuer on loopback (ports 5920-5926); build first
npm run content-pack # regenerate and validate content-pack.json
npm start            # http://127.0.0.1:5910/  (TW_PORT; must be in 5900-5999)
```

Port 5910 is the app; stubs use fixed ports 5911-5916, so `npm start` and `npm run e2e` cannot run together. Port range is 5900-5999.

## Rules that bite here

- Loopback only, with the Host and Origin guards. Mock: no real network, no real tenants; the only outbound target the checker accepts is a user-typed loopback `http://` URL.
- Real is owner-run. Agents and tests NEVER use a real tenant: Real tests use stub issuers on loopback (`server/test/real.test.js` hands the app a `realFetch` that maps `https://idp.example` to a loopback stub). Every Real request goes through `server/src/netguard.js` (configured issuer origin only); no other module may reach the real fetch (`safety.test.js` source scan).
- The client secret is write-only: it stays in the closure in `real.js`, is scrubbed from every trace, and never appears in `/api/info`, the doctor, logs or errors. Never add it to a response.
- Server-provided text is rendered inert (React text nodes, never HTML).
- Test scripts use globs (`node --test scripts/*.test.mjs`), never a directory.
- Never use `crypto.generateKeyPairSync` or async `generateKeyPair` for EC keys (SIGABRT on Node 20 in CI); use `createECDH` + `createPrivateKey`/`createPublicKey` or fixtures.
- Never parse `node:test` stdout; use the exit code.
- History scan `git log -p --all | grep -cF -f ~/.config/demo-kit/forbidden-strings.txt` must print 0. Never print that list.
- gitleaks runs in the pre-commit hook (`.githooks/pre-commit`); keep it installed.
- Docker is OrbStack only, never Docker Desktop. Compose publishes `127.0.0.1` only.
- Minted tokens are labelled mock; the FAPI 2.0 pack is UNVERIFIED. Any claim about a Ping product is UNVERIFIED unless it has a source.

## Hosted mock build (rule 18)

- Same image, `MODE=local` (default) or `MODE=se-mock`. In se-mock: workspace per `X-Workspace-Id` (`server/src/workspaces.js`; all state hangs off `req.rt`, so a new handler must use `req.rt`, never the boot `runtime`), typed checker targets refused, live flags refuse startup, banner via `/api/meta`.
- `k8s/` has the manifests (tokens `__IMAGE__`, `__SE_HOST__` only) and `deploy.sh`. NEVER run `k8s/deploy.sh --apply` or kubectl: the first SE deploy is owner-approved. `--dry-run` is safe.
- Pinned by `server/test/hosted.test.js`, `web/src/Hosted.test.jsx`, `scripts/k8s.test.mjs`. Details and the state inventory: [docs/k8s.md](docs/k8s.md).

## Where the safety claims are pinned

- `server/test/safety.test.js`, `server/test/hardening.test.js`: loopback bind, port range, Host/Origin, listeners.
- `server/test/netguard.js` and the tests using it: zero outbound calls.
- `server/test/ui.test.js`, `web/src/Honesty.test.jsx`: inert text and the simulation/UNVERIFIED labels.
- `scripts/compose.test.mjs`: Docker publishes loopback only.
- `scripts/docs.test.mjs`: docs name real scripts, files, routes and the UNVERIFIED wording.

## Shelf and content pack

- Shelf entry: `docs/shelf-entry.json`, checked by `scripts/shelf-entry.test.mjs`. Edit `composeFile` per checkout; the catalog id is C2.
- Content pack: edit `content/*.json`, run `npm run content-pack`, commit `content-pack.json`. Story text must match the UI story strip (a test checks it).
- Presenter script: [docs/talk-track.md](docs/talk-track.md).
