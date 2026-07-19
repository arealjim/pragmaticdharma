# Continue

_Updated: 2026-07-19_

## State

Platform hub is live and stable. v2 registry-driven rewrite is in progress — design approved by Jim, Slice 0 complete (no deploy, test-only). The session-revocation Gap 1 (24h JWT TTL + lazy /login refresh) was deployed earlier today.

**Slice 0 complete:** `projects.config.mjs` (11-project registry) + `src/registry.js` (derivations + import-time validation) + `test/v2-registry.test.mjs` (5 equality tests). All 29 tests green.

**Go-ahead shape:** Jim wants a check-in after Slice 1's flip deploy before continuing slices 2–4.

**Pending ## Now items (not v2):**
- Untracked v2 design docs on framework (docs/v2-registry-schema.md, prompts/v2-registry-rewrite.md — not present on biggie)
- docs/ai-development-guide.md rewrite (web#8)

## Next step

Execute **Slice 1 — flip the worker**: replace the five literals in worker.js with imports from `src/registry.js`, delete `getSigningKey` + dead exports, run `npm test` + `node test-auth.js` (live, 45 checks) before and after, deploy. Then signal Jim for check-in before continuing.

Files that change in Slice 1:
- `worker.js` — replace `KNOWN_PROJECTS`, `REDIRECT_ALLOWLIST`, `redirectUrlToProject`/`HOST_TO_PROJECT`, `KID_TO_BINDING`, `CSP_CONNECT_SRC_HOSTS` literals with imports from `./src/registry.js`; delete `getSigningKey`; remove the `v2-slice-0` exports block; remove the `v2-slice-0` extraction comments from the extracted consts (now just imports)
- `test/v2-registry.test.mjs` — update imports (both sides now from src/registry.js); keep the size/count assertions; drop the worker.js import side OR keep it (it re-exports from registry after the flip, so equality is trivially true but harmless)

## Prompt

```
Work in ~/workspace/pragmaticdharma. Read TODO.md and CONTINUE.md.
Execute v2 Slice 1 — flip the worker:
1. In worker.js, replace the five literal data structures (KNOWN_PROJECTS, REDIRECT_ALLOWLIST,
   HOST_TO_PROJECT/redirectUrlToProject, KID_TO_BINDING, CSP_CONNECT_SRC_HOSTS) with imports
   from ./src/registry.js. Remove the v2-slice-0 extraction consts and the v2-slice-0 exports
   block at the bottom. Delete the getSigningKey function (no callers — see TODO item). Also
   remove the trailing dead exports for it.
2. Update test/v2-registry.test.mjs: both sides now come from src/registry.js, so simplify or
   drop the worker.js import side (the test should still verify the derived structures have the
   right sizes/values, just against the registry directly).
3. Run npm test — must stay 29/29 green (or equivalent after test simplification).
4. Run node test-auth.js (live integration tests, all 45 checks must pass).
5. Deploy: npm run deploy.
6. Run node test-auth.js again after deploy.
7. Signal Jim for check-in: ~/workspace/cto/bin/signal thread needs-jim e0321e5cf9fb
   "Slice 1 deployed and green (29 unit + 45 live). Ready for slices 2–4 (wrangler codegen,
   pages from registry, test-auth generation + pd add-project). Nod to continue?"
8. Update TODO.md (mark slice 1 done) and CONTINUE.md, commit and push.
```
