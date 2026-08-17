# Continue

_Updated: 2026-08-17_

## State

**2026-08-17: v2 registry-driven rewrite Slices 2-4 — code-complete and unit-tested, committed, NOT deployed.** Jim's go-ahead for slices 2-4 (autonomous, slice-by-slice, no mid-build check-in; router stays zero-dep; the three security-cleanup scars stay descoped to standalone TODOs) landed 2026-08-17. This session ran in an isolated dispatch VM with **no npm registry egress and no Cloudflare credentials at all** — stricter than the Slice 1 session's gap (which could at least run `wrangler dev` locally). So all three slices are done as far as code + `npm test` can prove, but none of it has touched production. 78/78 unit tests green (was 66 at the top of this session).

- **Slice 2** (`b8c960e`): `scripts/gen-wrangler.mjs` regenerates wrangler.toml's `[[secrets_store_secrets]]` block from the registry; wired as `npm run predeploy`. Reordered the existing block to match generator output (a pure reorder — confirmed the binding/secret_name/store_id set is unchanged).
- **Slice 3** (`8c05b54`): index.html's 9 live-project cards replaced with a `{{cards}}` placeholder rendered by `src/registry.js`'s `renderCards()`; new `GET /api/admin/projects`; admin.html fetches its project list instead of a hardcoded literal. Found and fixed two data-entry drifts in the registry while verifying against the live page: shield/health/sentinel were marked `status: 'hidden'` but are actually advertised (`'live'`); PROJECTS reordered to match index-page card order. One real (minor, cosmetic) page change: the "Meditation Resources" static card moved from 6th to 10th position, since it isn't a registry project and can't sit inside a single `{{cards}}` placeholder at its old interleaved spot.
- **Slice 4** (latest commit): `test-auth.js`'s matrix + required-keys list generated from `testMatrixProjects()`. Found two more drifts: `practice` had a JWT key fetched but was never actually in the tested `sites` list (zero live coverage, silently); `health`/`ego-assessment`'s registry `testProbe` didn't match the endpoints actually probed — corrected to match. `./pd projects` and `./pd add-project <key>` added, manually verified end-to-end against a scratch copy (not the real repo). CLAUDE.md's Quick Reference/Testing/site-list updated to match current reality.

**New gap surfaced by this work** (not introduced by it — the old hand-maintained matrix had the same hole, just silently): **sentinel has zero live-suite coverage.** It's `customAuthTest: true` (admin-email allowlist enforced in sentinel-web, invisible to the platform registry) so it can't join the generic matrix as-is; needs a hand-written policy test like `testReviewSite`/`testBoardReviewSite`.

## Next step

**Deploy Slices 2-4 together**, from a session with Cloudflare credentials:
1. `npm run deploy` (predeploy regenerates + checks wrangler.toml is clean, then `wrangler deploy`).
2. Smoke-check: index page cards render correctly (should look identical to before except the Resources card's new position), `/admin` project badges load from `/api/admin/projects`, `./pd projects` output looks right.
3. Run the live `test-auth.js` suite if the JWT secrets are reachable from that session (they haven't been reachable from any session so far — flag to Jim if this is still blocked).
4. Then either close out v2 (Slice 5 — module split — is optional and can be deferred indefinitely) or pick it up.
5. Separately: write sentinel's live-suite policy test once its exact allowlist behavior can be verified against the deployed site.

## Prompt

```
Work in ~/workspace/pragmaticdharma. Read TODO.md and CONTINUE.md.
v2 registry rewrite Slices 0-4 are all code-complete, unit-tested, and
committed on main, but Slices 2-4 have never been deployed (built in
sandboxes with no Cloudflare credentials). From a session that HAS
Cloudflare Secrets Store access: run `npm run deploy`, smoke-check the
index page + /admin page + `./pd projects`, and if the JWT_SECRET_* values
are reachable, run `node test-auth.js` and report the result. Then decide
with Jim whether to pick up optional Slice 5 (module split) or close out v2.
```
