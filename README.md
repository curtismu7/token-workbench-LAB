# Token Workbench

A mock-only workbench for OAuth and JWT tokens. It decodes and explains a token offline, tests what a resource server does when it is sent the wrong token, checks stub authorization servers against OAuth security rules, and compares PAR, RAR, DPoP, mTLS, JAR and PKCE with and without the protection.

Everything runs against stubs inside this process, on loopback. Nothing real is contacted: no tenant, no real authorization server, no network.

## Status

Steps 1 to 3 are done: the core server and API, the web UI, and the packaging (Docker image with the UI, Learning Hub content pack, demo shelf entry). There is no CI and no GitHub repo; everything is local.

Built and tested:

- Token decode and explain (`POST /api/decode`): header and payload offline, each claim explained in plain English (`alg`, `kid`, `iss`, `sub`, `aud`, `scope`, `act`, `azp`, `cnf` with DPoP/mTLS binding, `exp`, `nbf`, `iat`, `jti`). The signature is not checked unless you ask (`verify: true`), and then only against the stub issuer's keys.
- Wrong-token rejection tester (`POST /api/tester/run`): 15 cases against a stub MCP-style resource server, each with the expected status, `WWW-Authenticate` challenge and a lesson.
- OAuth profile checker (`POST /api/checker/run`): an RFC 9700 BCP pack and a simplified FAPI 2.0 pack against five stub authorization servers, or against a loopback server you point it at.
- Token-flow catalog (`/api/flows`): six mechanisms, each run as a mock flow with and without its protection.
- `GET /api/health` (`demo-health/1`), a doctor, Docker files.

- The web UI (React + Vite, served by the server itself at `/`): four tabs. **Decode / Trace** (paste or mint a token, claims table with a plain-English line per claim, expiry countdown, signature status against the stub JWKS, `cnf` binding explained as decoded and not enforced). **Wrong-token tester** (the 15 cases, expected vs actual, the `WWW-Authenticate` error, the check that rejected it, a teach-me per case). **Profile checker** (a stub profile or a loopback URL, the BCP pack and the FAPI 2.0 pack with an UNVERIFIED badge, pass/fail and evidence per rule). **Flow catalog** (PKCE, PAR, RAR, DPoP, mTLS, JAR with and without protection on a React Flow diagram with draggable boxes, Simulate, Reset and speed, badged SIMULATION). Dark and light themes, no purple, keyboard reachable, results announced in a live region. Every server-provided string is rendered as text, never as HTML.

Packaging (step 3): a two-stage Dockerfile builds `web/dist` and ships it, so `GET /` returns the UI inside the container; `content-pack.json` for the Learning Hub; `docs/shelf-entry.json` for the demo shelf. Not built: CI.

Not verified: the FAPI 2.0 rule pack is **UNVERIFIED** and the flow catalog is a **simulation** (see [docs/safety.md](docs/safety.md)); no claim in this repo about any specific Ping product has been checked. The Docker image was built and run on OrbStack in step 3 (compose build and up, container healthy, `GET /` returns the UI, a tester run through the API gave 15 of 15, a foreign `Host` got 421, a foreign `Origin` got 403, the port was published on `127.0.0.1` only, then compose down and the image removed); that is a manual check and not part of `npm test`.

## Run it

```bash
npm install
npm run doctor      # node, bind, port range, free ports (server 5910, stubs 5911-5916)
npm test            # server (node:test), web (vitest) and script tests
npm run build       # builds web/dist, which the server serves at /
npm start           # http://127.0.0.1:5910/  (TW_PORT to change; ports 5900-5999 only)
npm run dev         # Vite dev server on 5930, proxying /api to the server on 5910 (start the server first)
npm run e2e         # real Chromium against the real server on 5940; needs npm run build first and a Playwright browser (`npx playwright install chromium`, once)
```

Ports: the stubs use fixed ports 5911-5916 (no override), so `npm start` and `npm run e2e` cannot run at the same time, and two clones cannot both run the app. The server tests pick free runs of ports in 5950-5999 (they move past a busy port), so parallel test runs mostly coexist, but a very crowded range can still fail with `no 8 free ports`; stop the other runs and retry.

```bash
curl -s http://127.0.0.1:5910/api/health
curl -s -X POST -H 'content-type: application/json' -d '{"sample":"dpop"}' http://127.0.0.1:5910/api/mint
curl -s -X POST -H 'content-type: application/json' -d '{"token":"<paste the token>","verify":true}' http://127.0.0.1:5910/api/decode
curl -s -X POST -H 'content-type: application/json' -d '{"case":"all"}' http://127.0.0.1:5910/api/tester/run
curl -s -X POST -H 'content-type: application/json' -d '{"profile":"loose-redirect"}' http://127.0.0.1:5910/api/checker/run
curl -s http://127.0.0.1:5910/api/flows/compare
```

## API

All POST bodies are JSON objects with a fixed set of fields; any other field (a password, a secret, an `Authorization` header) is refused, not ignored.

| Route | Does |
| --- | --- |
| `GET /api/health` | `demo-health/1`; `runtime` is always `offline`. |
| `GET /api/meta` | Mode, issuer, resource, stub profiles, ports, rule lists. |
| `GET /api/jwks` | The stub issuer's public key set (the private keys exist only in memory). |
| `POST /api/mint` `{sample}` | A signed sample token: `agent`, `user`, `dpop`, `mtls` or `expired`. The raw token is returned on purpose. |
| `POST /api/decode` `{token, verify?}` | Header, payload (inert text), explained claims, time status, signature state. Tokens longer than 8192 characters are refused. |
| `GET /api/tester/cases` | The 15 cases and what each teaches. |
| `POST /api/tester/run` `{case}` | `case` is a case id or `all`. Returns, per case, the minted token, the expected and actual answer, the failed check and `pass`. |
| `POST /api/checker/run` `{profile \| target, pack?}` | `profile` is a stub id (`good`, `loose-redirect`, `implicit-ropc`, `no-pkce`, `missing-metadata`); `target` is an `http://` loopback URL. `pack` is `bcp`, `fapi` or `both` (default). |
| `GET /api/flows`, `GET /api/flows/compare`, `POST /api/flows/run` `{mechanism, protected}` | The catalog, the side-by-side table, and one mock flow with its step trace and attack outcome. |

Checker and tester runs share one queue: one runs, one may wait, a third gets 429 with `Retry-After`.

### Stub profiles (ports 5911-5915) and expected results

| Profile | Port | BCP pack failures | FAPI pack failures |
| --- | --- | --- | --- |
| `good` | 5911 | none | none |
| `loose-redirect` | 5912 | exact-redirect | exact-redirect |
| `implicit-ropc` | 5913 | no-ropc, no-implicit | no-implicit-ropc |
| `no-pkce` | 5914 | pkce-required, pkce-downgrade, s256-only | par-published, par-required, pkce-s256, sender-constrained |
| `missing-metadata` | 5915 | metadata, iss-param | par-published, par-required, sender-constrained, iss |

The stub resource server and issuer is on 5916 (`POST /mcp`, `GET /.well-known/oauth-protected-resource`, `GET /issuer/.well-known/jwks.json`).

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `TW_PORT` | `5910` | API port; must be in 5900-5999. |
| `TW_BIND` | unset | Bind address. Unset means `127.0.0.1`. The container sets `0.0.0.0` and publishes on loopback only. |

| `MODE` | `local` | `local` (the standalone) or `se-mock` (the hosted, simulated build for the SE k8s cluster, see below). Anything else stops startup. |
| `TW_PUBLIC_ORIGIN` | unset | se-mock only: the one https origin of the hosted build, accepted for POSTs behind the ingress. |

There is no live mode and no setting that changes where the tools connect. A `.env` file at the repo root is read for local runs (never commit it).

## Docker

```bash
HOST_PORT=5910 docker compose up --build -d      # OrbStack; http://127.0.0.1:5910/api/health
```

The port is published on `127.0.0.1` only (pinned by `scripts/compose.test.mjs`). The image is built in two stages (the first builds the UI), runs as the non-root `node` user with a read-only filesystem and no capabilities, has a healthcheck on `/api/health`, mounts nothing and copies in no key: the stub signing keys are generated in memory at startup. Port 5910 and the stub ports 5911-5916 must be free on the host only for the host-run mode; in the container the stubs live on the container's own loopback.

## Learning Hub content pack and demo shelf entry

```bash
npm run content-pack    # regenerates content-pack.json from content/ and validates it (ajv) against docs/content-pack.schema.json
```

`content-pack.json` (format `demo-content-pack/1`) has a glossary, four cards (one per tab) and four stories whose text is the same as the UI story strip (a test checks it). It states the UNVERIFIED FAPI 2.0 pack and the simulation caveats in the text. It lists no sources: the RFC numbers it names were not checked against the RFC text. `docs/content-pack.schema.json` is a copy of the schema used by the Learning Hub kit (copied from the mcp-discovery repo, itself a copy of the AI-DEMO2 research schema; keep the copies in step). `scripts/build-content-pack.mjs` and `scripts/validate-content-pack.mjs` are patterns copied from mcp-discovery.

`docs/shelf-entry.json` is an entry for the demo shelf registry (port 5910, `/api/health`). `scripts/lib/shelf-registry-rules.mjs` is a copy of the shelf's validation rules, tested in `scripts/shelf-entry.test.mjs`; the shelf's own `validateDemos` was also run once, read-only, against the file. The catalog id is **C2** because the shelf accepts one id per demo and C2 is the wave-1 row (kind `Demo`); this app also covers C20 (profile checker) and C23 (wrong-token tester), whose "planned" cards will stay on the shelf. Edit `composeFile` to your checkout's absolute path before adding it to `.data/demos.local.json`.

## Hosted mock build for the SE cluster (rule 18)

The same image runs as a mock-only hosted build with `MODE=se-mock`: every visitor gets a private in-memory workspace (header `X-Workspace-Id`, capped and evicted after idling), the profile checker accepts the built-in stubs only (a typed target is refused), a live flag in the environment stops startup, and the UI shows a "HOSTED SIMULATION" banner on every tab. Manifests and the deploy script are in `k8s/`; nothing has been deployed, and the first deploy needs the owner's approval (`k8s/deploy.sh --dry-run` renders, `--apply` needs `OWNER_APPROVED=1`). Full details, the state inventory and residual risks: [docs/k8s.md](docs/k8s.md).

More: [docs/k8s.md](docs/k8s.md), [docs/safety.md](docs/safety.md), [docs/architecture.md](docs/architecture.md), [CHANGELOG.md](CHANGELOG.md). MIT licensed.
