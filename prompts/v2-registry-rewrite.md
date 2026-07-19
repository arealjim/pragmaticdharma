# pragmaticdharma v2 — registry-driven rewrite design

**Run from:** `~/workspace/pragmaticdharma` on framework.
**Mode:** Design session first (produce `docs/v2-design.md` + migration plan). Implementation only after the design is approved in a follow-up session.

## Goal

Redesign the platform so that adding or updating a hosted sub-project is **one registry entry + one deploy**, while preserving every external contract. The rewrite is a restructure around a single source of truth — the auth design is already good and should be kept, not reinvented.

## Background (verified 2026-07-04 — do not re-survey)

- `worker.js` is 1320 lines, no framework, hand-rolled routing ladder. Pages imported as text modules.
- Auth: passwordless magic-link + 6-digit code (Resend), JWT HMAC-SHA256 in `pd_session` cookie (`Domain=.pragmaticdharma.org`, 30d), `projects[]` claim, per-service `kid` → 11 `JWT_SECRET_<SERVICE>` keys in Secrets Store. Sub-projects verify locally via `shared/auth-cloudflare.js` and bounce to `/api/refresh-session` on stale claims.
- **The core pain:** registering a project touches ~7 sites in this repo (`KNOWN_PROJECTS`, `REDIRECT_ALLOWLIST`, `redirectUrlToProject`, `KID_TO_BINDING`, `[[secrets_store_secrets]]`, index.html card, admin.html toggle) plus Secrets Store key creation, sub-worker deploy, DNS, test-auth.js, sometimes CSP.
- Known scars: `sentinel` kid maps to the platform key (rotation independence broken, temp since 2026-05-25); CSP still `'unsafe-inline'`; two parallel JWT impls (worker.js internal vs shared/auth-cloudflare.js); `verifyJWT` in shared lib doesn't check `kid`; admin CLI (`pd`) escapes SQL rather than parameterizing; dead code (`getSigningKey`, unused exports); comments reference a retired H/M/L/Task tracker.

## Design requirements

1. **Single project registry** — the schema is already designed and grounded in the current code: see `docs/v2-registry-schema.md` (2026-07-04). Start from it rather than re-deriving; it maps each of the 7 duplication sites to its v2 mechanism (only wrangler.toml needs codegen; everything else imports the registry), specifies the entry shape incl. the ego-assessment/psychology key≠subdomain split and the sentinel `kidBindingOverride`, and defines the `pd add-project` flow.
2. **One-command onboarding:** `pd add-project <key>` scaffolds registry entry, creates the Secrets Store key, prints the DNS + sub-worker checklist. Target: under 10 minutes from idea to gated beta.
3. **Preserve exactly:** all URLs (`*.pragmaticdharma.org`, `/login /signup /admin /resources /api/*`), the `pd_session` cookie name/domain/JWT claim shape (`sub,email,name,role,projects[],sessionToken,kid`), `/api/refresh-session` semantics, D1 db `pragmaticdharma` (all 7 tables, live users + grants), Secrets Store ids, gating semantics (per-user grants, global + per-project open-beta, admin approval, 30-day session), Resend + Discord integrations. Sub-project workers must not need changes to survive the rewrite.
4. **Structure:** split worker.js into modules (router, auth, admin api, pages); pick router approach deliberately (Hono is the obvious candidate on Workers — evaluate vs staying zero-dep); one JWT implementation shared with sub-projects; delete dead code and tracker-archaeology comments.
5. **Close the scars in-flight:** dedicated `JWT_SECRET_SENTINEL`, CSP nonces (kill `unsafe-inline`), `kid` check in shared verifier, parameterized queries in `pd`.
6. **Tests:** keep/extend `test-auth.js` so the full matrix (N projects × gate styles × beta modes) is generated from the registry too.

## Constraints

- Zero-downtime migration path: new worker must be deployable side-by-side and cut over per-route or via a staging subdomain before flipping production.
- No new paid services. D1 + Secrets Store + Resend stay.
- CLAUDE.md gets rewritten as part of this: current-state only, plus a step-by-step "add a project" section; fix the 7-vs-10 sub-project inconsistencies; move the sentinel-workaround paragraph to a dated note in docs/.

## Report when done (design session)

`docs/v2-design.md` containing: registry schema, module layout, codegen plan, migration/cutover sequence, scar-fix list, and an explicit "contracts preserved" checklist. Plus a rough effort estimate per phase.
