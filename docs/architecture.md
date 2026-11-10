# Architecture

One Node process (Express, ESM). It starts the stubs and the API together and talks to the stubs over real loopback HTTP, so the HTTP behaviour you see (status codes, `WWW-Authenticate`, redirects) is real HTTP, not function calls.

```
client (the web UI served from web/dist, or curl)
   |  JSON over HTTP, 127.0.0.1:5910
   v
API (server/src/app.js)  host guard -> origin/CSRF guard -> credential guard -> JSON body (16 KB)
   |-- decode / mint ......... jwt.js, keys.js (in-memory ES256 keys)
   |-- tester ................ tester.js --http.js--> stub resource server + issuer :5916 (validator.js)
   |-- checker ............... checker.js --http.js--> stub authorization server :5911-5915 (or a loopback target)
   |-- flows ................. catalog.js (pure, in-memory)
   |-- Real (owner opt-in) ... real.js --netguard.js--> the configured issuer's origin only (https)
   and runtime.js: starts the stubs, owns the run queue
```

## Ports

All in 5900-5999. `5910` API. `5911-5915` the five authorization-server profiles (`good`, `loose-redirect`, `implicit-ropc`, `no-pkce`, `missing-metadata`). `5916` stub resource server and issuer. `5917-5919` reserved for the stubs. `5930` reserved for the Vite dev server, `5940` for the e2e script, `5920-5926` for the Real e2e script (`scripts/e2e-real.mjs`). Tests take a free run of ports from `5950-5997`, each test file in its own 8-port slice.

## Modules (`server/src`)

| File | Role |
| --- | --- |
| `safety.js` | Loopback test, Host/Origin/credential guards, port rules. Pure. |
| `policy.js`, `http.js` | The outbound target policy and the only outbound HTTP client. |
| `jwt.js` | Parse, sign, verify (ES256), thumbprint, explain claims. Offline. |
| `keys.js` | Per-start ES256 keys: the issuer key, an attacker key, a client key. Public JWKS only is exposed. |
| `validator.js` | The resource server's token validation, one named check at a time. |
| `stubs/resource.js` | Stub MCP-style resource server (`POST /mcp`), protected-resource metadata, JWKS. |
| `tester.js` | The 15 wrong-token cases and the runner. |
| `stubs/authserver.js` | The five authorization-server profiles (`/authorize`, `/token`, `/par`, metadata). |
| `checker.js` | The probe engine and the two rule packs. |
| `catalog.js` | The six mechanisms as data, a `decide` function each, `runFlow`, `compare`. |
| `runtime.js` | Starts and stops the stubs, owns the run queue. |
| `real.js` | Real mode: the `TW_REAL*` settings (secret kept in a closure, scrubbed from traces), and the Real operations (client_credentials, JWKS verify, introspection, metadata-only checker), each returning its trace. |
| `netguard.js` | The only door to a real host. Mock: refuses everything. Real: https to the configured issuer's origin only, no redirects, 10 s deadline, 256 KiB cap. Self-test used by the doctor. |
| `app.js`, `index.js`, `health.js`, `doctor.js`, `sanitize.js` | API, entry point, `demo-health/1`, preflight, inert text. |

## The tester

Each case mints a token with the stub issuer, sends it as `Authorization: Bearer` to `POST /mcp` on the stub resource server and compares the answer with what a correct server must say: status, the `error` in the body and in `WWW-Authenticate`, and the id of the check that rejected it (`failed_check`). Comparing the failing check, not just the status, is what stops a rejection for the wrong reason from passing (an unsigned token that is also rejected later for its signature would otherwise look the same).

## The checker

1. Fetch metadata (`/.well-known/oauth-authorization-server`, then `/.well-known/openid-configuration`). If there is none, use `/authorize` and `/token`.
2. Probe. A valid request is sent first as a control; if the server will not accept even that, rules that depend on it report `error` rather than a misleading pass. If the metadata says PAR is required, probes are pushed through `/par` first.
3. Each rule is `pass`, `fail` or `error` with a short evidence string (server text made inert) and the RFC section. Probe results are shared between the packs.

## The flow catalog

A mechanism is data (name, RFC, the attack it stops, a list of steps tagged `protected` / `unprotected`) plus a `decide(protected)` function that builds the relevant keys, hashes or signatures in memory and returns whether the attack succeeds. `runFlow` filters the steps and calls `decide`; `compare` runs every mechanism both ways. Output is rendered by the web step.

## Not here yet

Step 3: content pack, shelf entry, a web build stage in the Dockerfile, CI.

## The web UI (`web/`)

React 18 + Vite, `@xyflow/react` 12.12.0 for the diagram, vitest and testing-library for tests. The server serves `web/dist` at `/` with a same-origin-only CSP (`default-src 'self'`, no inline script, no `unsafe-eval`; inline styles are allowed because React Flow sets them), on the same host and Origin guards as the API. The API keeps `default-src 'none'`.

| File | Role |
| --- | --- |
| `web/src/lib/api.js` | The only place that calls `fetch`: JSON bodies, `credentials: "omit"`, no credential headers. |
| `web/src/components/Decode.jsx` | Paste or mint a token, claims table, countdown, signature badge, `cnf` note. |
| `web/src/components/Tester.jsx` | The 15-case matrix: expected vs actual, challenge, rejecting check, lesson. |
| `web/src/components/Checker.jsx` | Profile choice or loopback URL, both rule packs, UNVERIFIED badge on FAPI. |
| `web/src/components/Flows.jsx` | Comparison table, with/without side by side, the React Flow diagram with Simulate, Reset and speed. |
| `web/src/components/Story.jsx`, `Badge.jsx` | The four-step story strip; outcome words with colour. |

Server strings (claims, headers, evidence, error text) are only ever rendered as React text nodes. A test feeds an `<img onerror>` string through the decode tab and asserts no element is created. `scripts/e2e.mjs` drives the built UI in headless Chromium: all four tabs, keyboard-only reach, hostile text, drag, Simulate and Reset, no console errors, no request that leaves the origin, no horizontal scroll at 390px, and dark and light screenshots.
