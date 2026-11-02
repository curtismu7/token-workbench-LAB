# The forbidden-string gate

The kit is meant to be shared, so no identifier from another project's tenant may appear in a tracked file. `npm run check:forbidden`
(`scripts/check-forbidden-strings.mjs`) fails when a tracked file contains

- any line of the **forbidden-strings list** (matched case-insensitively; a hit is reported as `file:line entry #N`, never as the value),
- a UUID in docs or examples that `scripts/forbidden-allowlist.json` does not list, or
- a private Ping hostname that the allowlist does not list.

The list itself holds the very identifiers it guards against, so it is **never committed**.

## Where CI gets the list

The `forbidden-strings` job in `.github/workflows/ci.yml` takes the list from the first of these that exists:

1. a `FORBIDDEN_STRINGS` repository secret (one string per line), or
2. the file named by `FORBIDDEN_STRINGS_FILE`.

With neither, the job fails under `CI=true`: the gate cannot be skipped. CI runs on GitHub-hosted runners, so the secret is the source there.

## Build the list

The list is one identifier per line (tenant, environment and client ids and hostnames from other projects). Keep it outside any repository, for
example `~/.config/demo-kit/forbidden-strings.txt` with mode 600, and paste the same lines into the `FORBIDDEN_STRINGS` repository secret.

## Run it locally with the real list

```sh
FORBIDDEN_STRINGS_FILE=~/.config/demo-kit/forbidden-strings.txt npm run check:forbidden
```

Without `FORBIDDEN_STRINGS_FILE` the exact-string check is skipped locally (with a notice) and the host and UUID checks still run.
