# Architecture

One Node process (Express, ESM). It starts the stubs and the API together and talks to the stubs over real loopback HTTP, so the HTTP behaviour you see (status codes, `WWW-Authenticate`, redirects) is real HTTP, not function calls.

```
client (curl / later the web UI)
   |  JSON over HTTP, 127.0.0.1:5910
   v
API (server/src/app.js)  host guard -> origin/CSRF guard -> credential guard -> JSON body (16 KB)
   |-- decode / mint ......... jwt.js, keys.js (in-memory ES256 keys)
   |-- tester ................ tester.js --http.js--> stub resource server + issuer :5916 (validator.js)
   |-- checker ............... checker.js --http.js--> stub authorization server :5911-5915 (or a loopback target)
   |-- flows ................. catalog.js (pure, in-memory)
   and runtime.js: starts the stubs, owns the run queue
```

## Ports

All in 5900-5999. `5910` API. `5911-5915` the five authorization-server profiles (`good`, `loose-redirect`, `implicit-ropc`, `no-pkce`, `missing-metadata`). `5916` stub resource server and issuer. `5917-5919` reserved for the stubs. `5930` reserved for the Vite dev server, `5940` for the e2e script (step 2). Tests take a free run of ports from `5950-5999`, each test file in its own slice.

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

Step 2: the React + Vite UI (dark/light, token decode view, tester table, checker scorecard, flow diagrams). Step 3: content pack, shelf entry, e2e.
