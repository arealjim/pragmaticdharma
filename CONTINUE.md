# Continue

_Updated: 2026-07-19_

## State

Platform hub is live and stable. v2 registry-driven rewrite: Slice 0 and Slice 1 both complete and deployed. Session-revocation Gap 1 (24h JWT TTL + lazy /login refresh) was deployed earlier the same day.

**Slice 1 complete (deployed, version edefe64f):** `worker.js` now imports `KNOWN_PROJECTS`, `REDIRECT_ALLOWLIST`, `HOST_TO_PROJECT`, `KID_TO_BINDING`, `CSP_CONNECT_SRC_HOSTS` from `src/registry.js` instead of defining its own literals. Deleted the dead `getSigningKey` helper and the `v2-slice-0` freeze-export block. `test/v2-registry.test.mjs` rewritten to assert shape/values directly against the registry (the old worker-vs-registry equality check became trivially true once both sides shared one source). 29/29 unit tests green, local `wrangler dev` smoke test green, post-deploy production check confirmed the CSP `connect-src` header matches the registry-derived hosts exactly.

**Known gap:** the live 45-check `test-auth.js` integration suite was NOT run before/after this deploy — this session had no access to the production `JWT_SECRET_*` values (Cloudflare Secrets Store is write-only; most services' keys aren't mirrored in the local vault). Deploy safety instead rested on: the Slice-0 equality tests (now folded into Slice 1's registry-shape tests), a clean `node --check`, a local `wrangler dev` smoke test, and a post-deploy production smoke test (CSP header, redirect-allowlist behavior, unauthenticated gate responses on all subdomains). If Jim wants the full JWT suite run, it needs a session/machine with the `JWT_SECRET_*` values, or Jim providing them.

**Go-ahead shape:** Jim wanted a check-in after Slice 1's flip deploy before continuing slices 2–4. That check-in is now due.

## Next step

Wait for Jim's go-ahead, then continue with:
- Slice 2 — wrangler.toml codegen (scripts/gen-wrangler.mjs; no binding changes)
- Slice 3 — pages + admin from registry ({{cards}} substitution; GET /api/admin/projects)
- Slice 4 — tests + CLI (test-auth.js matrix generated from registry; `pd projects`; `pd add-project`)
- Slice 5 (optional) — module split into src/ layout

## Prompt

```
Work in ~/workspace/pragmaticdharma. Read TODO.md and CONTINUE.md.
Slice 1 is done and deployed. If Jim has given the go-ahead, continue with
v2 Slice 2 — wrangler.toml codegen: write scripts/gen-wrangler.mjs that
generates wrangler.toml's secrets_store_secrets bindings from
projects.config.mjs (JWT_SECRET_<KID> entries), diff against the current
wrangler.toml to confirm no binding changes, and wire it as a `predeploy`
or documented manual step. No binding changes should occur in this slice —
it's establishing the registry as the single source for config generation.
```
