# Design: v2 registry-driven rewrite

Status: DESIGN — written 2026-07-18 (fable farewell prep), not yet reviewed by Jim. Prep only; execution is a later session.

This is the design-session output that `prompts/v2-registry-rewrite.md` calls for (it names the output `docs/v2-design.md`; it lives here instead — TODO.md pointer corrected). It builds on `docs/v2-registry-schema.md` (2026-07-04), which remains the schema of record; deltas to it are flagged below. Context: `docs/ARCHITECTURE.md`, worker.js.

## Problem

Onboarding or changing a sub-project touches ~7 hand-synced sites in this repo — `KNOWN_PROJECTS` (worker.js:37), `REDIRECT_ALLOWLIST` (:44), `redirectUrlToProject` (:70), `KID_TO_BINDING` (:952), the CSP `connect-src` (:103), index.html cards, admin.html's project list — plus `[[secrets_store_secrets]]` blocks in wrangler.toml and the test-auth.js matrix. Nothing enforces consistency, and each omission fails differently (a host missing from `REDIRECT_ALLOWLIST` silently drops the post-login redirect to `/`). The v2 goal: **one registry entry + one deploy** per project, everything else derived.

## Constraints

- **Every external contract is frozen:** all URLs, the `pd_session` cookie name/domain/claim shape (`sub, email, name, role, projects[], sessionToken` + `kid` header), `/api/refresh-session` semantics, D1 db `pragmaticdharma` (schema + live rows), Secrets Store ids, gating semantics, Resend/Discord. **No sub-project worker may need any change to survive this rewrite.**
- Project `key`s, `kid`s, and the ego-assessment/psychology key≠subdomain split are baked into D1 `user_projects`, live JWT claims, and `open_beta:<key>` config keys — the registry must reproduce today's values exactly.
- No new paid services; no bundler beyond what wrangler already does (ESM imports + text modules).
- The working tree is shared with parallel sessions; slices must be small, individually shippable, and test-frozen before behavior moves.

## What the registry drives vs what stays put

**Registry-driven (derived, per `v2-registry-schema.md`'s table):** project identity (key/subdomain/kid), redirect allowlist, host→project map, kid→secret-binding map, CSP `connect-src` additions, index cards, admin project list + beta toggles, wrangler.toml secrets blocks (codegen — the one site TOML can't import from), test-auth.js matrix, `pd` CLI project listing.

**Explicitly NOT registry-driven (stays where it is):** the Hub's route table (fixed platform surface — /login, /api/*, /admin; the registry describes *projects*, not *routes*); D1 authorization state (`user_projects` grants stay admin-managed via `./pd approve`); DNS records; each sub-project's own worker, verifier copy, and wrangler.toml; Secrets Store *values* (created out-of-band, vault-recorded); psyche (Model B, not in the registry at all — do not add it "for completeness"; an entry would imply hub gating that must never exist).

## The schema — adopted, with three corrections

`projects.config.mjs` + derivations module as drafted in `docs/v2-registry-schema.md`. It survived re-verification against today's worker.js with three deltas:

1. **The allowlist snapshot is 13 hosts, not 12.** The schema's migration constraint says "current 12-host set exactly" — `review.pragmaticdharma.org` was added after the draft (now 1 apex + retreats + 11 project hosts). Not a schema-shape problem, but it proves the point: **the frozen-snapshot equality tests must be generated from the live code at slice time, never copied from a doc.**
2. **`adminConnect` today = health + ego-assessment only** (CSP `connect-src`, worker.js:103) — matches the draft; keep. But note the CSP also carries `'unsafe-inline'` (M2 comment): that fix is **out of v2 scope** (see below), so the registry only derives `connect-src`, not the whole CSP string. Derive the two host entries, keep the rest of the header literal.
3. **`status: 'hidden'`** must be the value for sentinel/review-style projects that are gated but not advertised — confirm during slice 3 that today's index.html card set maps cleanly onto `live`/`soon`/`hidden` for all 11 projects before rendering cards from the registry; any mismatch is a data-entry question, not a schema change.

Everything else stands: `kidBindingOverride` (sole user: sentinel, with mandatory dated `notes`), self-validation at import time (fail deploy, not runtime), `pd add-project` flow, key≠subdomain support.

## Decisions the schema deferred — now decided

1. **Router: stay zero-dep.** Recommendation, firm: the pain this rewrite addresses is registry duplication, not routing. worker.js's ladder is ~25 branches and fully greppable; Hono buys ergonomics at the price of a dependency, an abstraction layer under the auth-critical path, and diff noise across every handler. Revisit only if the route count doubles. (Ask 1 confirms.)
2. **Pages: text-module imports + `{{cards}}` substitution**, as the schema recommends. No render-function framework. Keep generated markup byte-compatible with today's `.card`/`.project-badge` classes so zero CSS/JS churn.
3. **`repo`/`notes` → generated docs section: no.** Nice-to-have, cut. The registry file itself is readable; a codegen'd doc section is one more sync surface — the disease we're curing.

## worker.js refactor shape

Minimal, mechanical module split — and only *after* the registry lands (slices below). Target layout:

```
projects.config.mjs      # the registry (data only, heavily commented)
src/registry.js          # derivations + import-time validation
src/jwt.js               # signJWT/verifyJWT/getSigningKeyForKid/kidForRedirect
src/auth-handlers.js     # signup/login/verify/session/refresh/logout
src/admin.js             # /api/admin/* + CSRF guard
src/pages.js             # html assembly, nav injection, {{cards}}
src/retention.js         # runRetentionSweep
worker.js                # fetch() ladder + scheduled() — imports the above
```

Handlers consume the registry only through `src/registry.js` exports (`KNOWN_PROJECTS`, `HOST_TO_PROJECT`, `REDIRECT_ALLOWLIST`, `KID_TO_BINDING`, `CSP_CONNECT_SRC`, `publicProjects()`, `adminProjects()`) — no handler reads `PROJECTS` raw, so the entry shape can evolve behind the derivations. wrangler bundles ESM imports natively; no build step appears.

Candor note vs the prompt: requirement #5 says close the scars "in-flight" — CSP nonces, `kid` check in the shared verifier, parameterized `pd` queries. **Recommend cutting all three from v2** (Ask 2). They are real, but each touches a different risk surface (page markup; 11 sub-repo verifier copies; CLI SQL), none is caused by the duplication problem, and bundling them turns a mechanical, snapshot-verifiable refactor into a behavior-changing one. The two that *are* in: dead-code deletion (`getSigningKey`, trailing exports — both already TODO'd) and the sentinel key restoration (sequenced after cutover, per the schema; now also specced in `docs/design-session-revocation.md`).

## Migration path — ordered slices, each shippable

Existing behavior gets frozen by tests *first*; every subsequent slice must leave those tests green and is deployable alone. No side-by-side worker or staging subdomain needed — the prompt's zero-downtime constraint is met by making every deploy a proven no-op on behavior, which is strictly safer than a big-bang cutover with a parallel deployment. (If a slice can't prove no-op-ness, it's too big; split it.)

- **Slice 0 — freeze (test-only, no deploy).** Write `projects.config.mjs` + `src/registry.js` with today's 11 projects. Add equality tests: each derived structure deep-equals the *live literals exported from worker.js* (temporarily export them for the test). Snapshot the 13-host allowlist from code. ~2–3h.
- **Slice 1 — flip the worker.** Replace the five literals in worker.js (`KNOWN_PROJECTS`, `REDIRECT_ALLOWLIST`, `redirectUrlToProject`, `KID_TO_BINDING`, CSP connect-src hosts) with registry imports; delete `getSigningKey` + audited dead exports. `npm test` + `node test-auth.js` (live, all 45 checks) before/after. Deploy. This is the highest-value slice: after it, the four failure-differently maps cannot disagree. ~2–3h.
- **Slice 2 — wrangler.toml codegen.** `scripts/gen-wrangler.mjs` rewriting only the marked block; `npm run deploy` = gen → git-diff-clean check → wrangler deploy; unit test asserting generated block matches registry. Deploy (no binding changes — generator must reproduce the current file byte-for-byte first time). ~2h.
- **Slice 3 — pages + admin from registry.** `{{cards}}` substitution in index.html; new `GET /api/admin/projects` (admin-gated) serialized from the registry; admin.html fetches it instead of its literal list. Byte-compare rendered cards against current HTML in a test before deleting the static markup. ~3h.
- **Slice 4 — tests + CLI.** test-auth.js matrix generated from registry (`gate` + `testProbe`); `pd projects`; then `pd add-project <key>` per the schema's 6-step flow (registry append + codegen + secret creation attempt with dashboard-fallback instructions + printed manual checklist). ~3–4h.
- **Slice 5 — module split** (the `src/` layout above). Pure code motion, no logic edits; `npm test` + test-auth.js green. Optional, deferrable indefinitely without harming slices 0–4. ~2h.
- **Post-cutover, separate change:** sentinel `JWT_SECRET_SENTINEL` creation + override deletion (two-repo flip; runbook in `design-session-revocation.md`). CLAUDE.md rewrite (prompt constraint: current-state only + "add a project" walkthrough) lands with slice 4, when `pd add-project` makes the walkthrough true.

Total: roughly 14–17 focused hours across 5–6 sessions, each ending deployed-and-green.

## What explicitly does NOT change in v2

No URL, cookie, claim, or redirect behavior. No D1 schema or data migration. No new Secrets Store entries (sentinel's is a separate post-cutover change). No router framework, no bundler, no npm runtime deps. No CSP tightening beyond deriving `connect-src`. No changes in any sub-project repo. No psyche involvement. No auth-logic changes at all — the revocation redesign (`design-session-revocation.md`) is a sibling project; if both are approved, land revocation first or second but **not interleaved with v2 slices** (both edit worker.js; sequence, don't merge).

## Risks

- **Derived ≠ literal at slice 1** → a project silently loses login redirect or key lookup. Mitigation: slice 0's equality tests + live test-auth.js run before and after the flip deploy.
- **Codegen drift** (hand-edit inside the generated wrangler.toml block) → predeploy git-diff-clean check fails the deploy; that's the designed behavior, document it in CLAUDE.md.
- **Card markup drift** in slice 3 breaking styling → byte-compare test before deleting static HTML.
- **Secrets Store CLI still broken** for `pd add-project` step 4 → the flow already treats dashboard as the expected fallback (sentinel scar institutionalized as a printed checklist).
- **Parallel-session collisions** in this shared tree → each slice stages only its own files; slices are small enough to land same-day.

## Open questions for Jim (zero-context asks)

**Ask 1 — router.** Context: the platform worker routes ~25 URL patterns with plain if-statements; the rewrite could adopt Hono, the standard Workers micro-framework, or keep zero dependencies. This design recommends zero-dep: the code is small, auth-critical, and dependency-free today. Question: keep zero-dep routing? Yes → no dependency ever enters the auth path; No (prefer Hono) → nicer handler ergonomics, one npm dependency to track, ~a day extra migration.

**Ask 2 — scar scope.** Context: the original v2 prompt bundles three security cleanups (CSP nonces on inline scripts, a `kid` check in every sub-app's verifier copy, parameterized SQL in the `pd` admin CLI) into the rewrite. This design recommends splitting them out so v2 stays a provable no-behavior-change refactor; they'd become three small standalone TODO items instead. Question: OK to descope them from v2? Yes → v2 ships faster and safer, scars tracked separately; No → they ride along, v2 becomes behavior-changing and needs deeper per-slice verification.

**Ask 3 — go-ahead shape.** Context: the migration is 5 slices, each independently deployable and test-frozen, ~14–17h total; Jim's standing rule is push/deploy autonomous but this rewrite touches the login path for every platform app. Question: once you approve this design, may slices 0–4 proceed under the normal autonomous-deploy rule (slice-by-slice, test-auth.js green before and after each deploy), or do you want a check-in after slice 1's flip deploy? Autonomous → steady background progress; Check-in → one pause after the riskiest slice, rest proceeds on your nod.
