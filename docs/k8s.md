# Hosted mock build for the SE cluster (rule 18)

Token Workbench ships in two forms from the SAME image and Dockerfile:

- **Local standalone** (`MODE` unset, same as `MODE=local`): what the README describes. One runtime, stubs on 5911-5916, any loopback `http://` target for the profile checker.
- **Hosted mock build** (`MODE=se-mock`): for the US SE k8s cluster, so SEs can use it in a browser without installing anything. Everything is simulated, every visitor gets a private workspace, and nothing live exists to turn on.

Nothing in this repo has been deployed. The first deploy of each app to the SE cluster is **owner-approved**; `k8s/deploy.sh` will not apply anything without `--apply` and `OWNER_APPROVED=1`.

## What `MODE=se-mock` changes

| Area | Behaviour |
| --- | --- |
| Config | `MODE` is `local` (default) or `se-mock`. Any other value (`live`, `prod`, `mock`, `SE-MOCK` ...) stops startup and fails `npm run doctor` and `/api/health` (`broken`). Real (a runtime toggle of the local build) is refused: any `TW_REAL*` setting stops startup in se-mock. |
| Live flags | In se-mock, setting any of `TW_LIVE`, `TW_ALLOW_REMOTE`, `TW_ALLOW_TARGETS`, `TW_CHECKER_TARGETS`, `LIVE` is refused at startup and by doctor. (This app never honoured them; refusing them stops a manifest edit from implying a live capability.) |
| Checker targets | A user-typed `target` is refused for every URL, loopback included (`400 target_refused`, reason `hosted_build`). Only the five built-in stub profiles of the visitor's own workspace can be checked. The local build still accepts a loopback `http://` URL. |
| `.env` | Not read in se-mock. |
| Workspaces | One complete runtime per workspace id (below). The local build ignores the header. |
| Banner | `GET /api/meta` serves `banner` ("HOSTED SIMULATION ..."), `hosted: true` and `deployMode: "se-mock"`. The UI shows it above the header, so it is on every tab. There is no separate presenter mode: the story strip is the presenter view and sits under the same banner. The local build serves `banner: null` and shows nothing extra. |
| Health | Still `demo-health/1`, global (not per workspace). In se-mock it also carries `mode: "se-mock"`; the local reply keeps its exact shape. |
| Origin check | The ingress rewrites the Host header to `127.0.0.1:5910` (the app accepts loopback Hosts only), so a browser POST arrives with `Origin: https://<SE host>`. `TW_PUBLIC_ORIGIN` (rendered from `SE_HOST` into the manifest) names that one https origin and it is accepted in addition to loopback origins. Cross-site fetches and every other origin stay refused. |

## Workspaces and isolation

The browser creates one id per tab (`ws-` plus 16 hex characters, kept in `sessionStorage`) and sends it as `X-Workspace-Id` on every request. The id is a label, not a credential: it unlocks nothing, everything behind it is synthetic. Missing header means workspace `default`.

- Validation: `^[a-z0-9][a-z0-9-]{0,31}$` (1-32 characters of a-z, 0-9, hyphen, not starting with a hyphen). Anything else, an empty header or two ids in one request gets `400` and creates nothing.
- Cap: 20 workspaces (including `default`). Past the cap the least recently used **idle** workspace is evicted and its listeners are closed; if every other workspace is mid-run the new one is refused with `503 workspace_cap` and `Retry-After`.
- TTL: a workspace idle for 30 minutes is dropped on the next request or the 60 s sweep. `default` is never evicted. A workspace with a run in progress is never evicted. An evicted id that comes back is a brand new workspace (new keys: tokens minted before no longer verify).
- Each extra workspace starts its own 5 stub authorization servers and its own stub resource server on free ports of the pod's loopback (the `default` workspace keeps 5911-5916). They are bound to `127.0.0.1`, are not published by the Service, and keep their Host guard.
- Tests (`server/test/hosted.test.js`): two workspaces have different issuers, JWKS and ports; a token minted in A does not verify in B and B's resource server refuses it; a code issued by A's stub is unknown to B's; A's tester and checker results never mention B's stubs; A's run queue does not block or 429 B; hostile ids are rejected; cap, LRU eviction, TTL, busy protection and concurrent first use are pinned in a registry unit test. The isolation test fails if the per-workspace lookup is replaced by the shared runtime.

### Every piece of state, and where it lives

| State | Where | In se-mock |
| --- | --- | --- |
| Stub issuer keys (main, rogue, client) and `kid` | `server/src/keys.js`, built by `createRuntime` | per workspace |
| Issuer / resource identifiers (derived from the resource port) | `server/src/runtime.js` | per workspace |
| Five stub authorization servers: issued `codes`, pushed requests (`/par`) | `server/src/stubs/authserver.js` (closure maps, 500 entry cap) | per workspace |
| Stub resource server and its request counter | `server/src/stubs/resource.js` | per workspace |
| Run queue (one running, one waiting, third gets 429) | `server/src/runtime.js` | per workspace |
| Checker evidence memo | `server/src/checker.js`, local to one run | per run, discarded |
| Tester and checker results | returned in the response, never stored | none |
| Sample tokens, cases, profiles, rule packs, flow catalog | module constants, never mutated | shared, read-only |
| Health state | `server/src/health.js` | global by design: no visitor data |
| Workspace registry | `server/src/workspaces.js` | the isolation mechanism itself |
| Browser: theme, workspace id | `localStorage` `tw-theme`, `sessionStorage` `tw-workspace` | per browser / per tab |

## Compiled out or refused

- No live mode, no real outbound call (the only HTTP client talks to loopback), no credentials accepted (`Authorization`, `Proxy-Authorization`, `X-API-Key` are refused), no secret, tenant id or `~/.config/demo-kit` file in the image or manifests, no hostPath, nothing privileged.
- The Docker image is unchanged except for what the code does with `MODE`; `MODE` is not baked into the Dockerfile, so a plain `docker run` or compose is the local standalone.

## How the owner deploys (after approving)

1. Build the image from this repo's Dockerfile and push it to the registry the SE cluster pulls from, with an immutable tag (a commit sha). Docker on OrbStack only. This repo does not push images.
2. Dry run (renders the manifests, contacts nothing, needs no kubectl):

   ```bash
   NAMESPACE=<ns> IMAGE=<registry>/<repo>/token-workbench:<sha> SE_HOST=<host> k8s/deploy.sh --dry-run
   ```

   `NAMESPACE` has no default (which namespace the SE cluster uses is an owner decision, UNVERIFIED). The manifests carry only the literal tokens `__IMAGE__` and `__SE_HOST__` (also inside `TW_PUBLIC_ORIGIN`); the script validates the values, renders with sed and fails if any `__TOKEN__` is left. Ingress class and TLS are not set in the manifest and are owner decisions to add (UNVERIFIED).
3. Apply, only after approval:

   ```bash
   OWNER_APPROVED=1 NAMESPACE=<ns> IMAGE=... SE_HOST=<host> k8s/deploy.sh --apply
   ```

4. Verify by content, not by a 200: `https://<SE host>/api/meta` must say `"hosted": true`, `"deployMode": "se-mock"` and carry the HOSTED SIMULATION banner; `/api/health` must say `"mode": "se-mock"`. Check that the registry manifest and the pod's `imageID` match `IMAGE`, then prove the UI in a real browser (banner on all four tabs, a tester run of 15 of 15, the checker refusing a typed URL) before handing over the full `https://` URL.

The Deployment has 1 replica (state is in memory, per workspace), non-root user 1000, `readOnlyRootFilesystem`, all capabilities dropped, no privilege escalation, `RuntimeDefault` seccomp, no service account token, CPU and memory requests and limits, and `/api/health` liveness and readiness probes (with `Host: 127.0.0.1:5910`). `scripts/k8s.test.mjs` pins all of this and the deploy script's refusals.

## Residual risks

- A workspace id is a label. Anyone who knows or guesses another visitor's id (16 random hex characters per tab; the `default` workspace has a known id) can see and use that workspace. The data is synthetic; there is no real secret to leak. The `default` workspace is shared by anyone who sends no header (for example `curl`).
- Flooding new workspace ids evicts other visitors' idle workspaces (least recently used first, past the cap of 20), so their keys and tokens are dropped and a token minted earlier then fails verification. Availability only: nothing is read or changed across workspaces.
- State is in memory, one pod: a restart or an eviction resets everything. More replicas would split a visitor's workspace across pods, so replicas stay at 1.
- Memory and listeners scale with workspaces (6 listeners and 3 small EC keys each); the cap of 20 and the memory limit bound that. At the cap with every workspace busy, a newcomer gets 503 until a run ends.
- The ingress Host rewrite is nginx-specific (an annotation). Another ingress controller needs the equivalent, otherwise every request gets `403 bad_host`. UNVERIFIED on the SE cluster: the owner proves it on the first deploy by checking the content of `/api/meta`. There is no NetworkPolicy; the app makes no outbound calls, so that would be defence in depth only.
- Stub servers on ephemeral ports are reachable by anything inside the same pod; there is only one container. They hold synthetic data only.
- No rate limiting beyond the per-workspace run queue and the workspace cap.
