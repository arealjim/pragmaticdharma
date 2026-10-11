# Auth on pragmaticdharma.org — the design, simplified

*2026-07-17 · companion to `ARCHITECTURE.md` (which describes what exists; this
describes the rule going forward). Written for Jim first, builders second.*

## The whole model in one paragraph

There is **one login system** (the Hub at pragmaticdharma.org: magic-link email
login → `pd_session` cookie valid across `*.pragmaticdharma.org`) and **one
deliberate exception** (psyche, which runs its own separate login on purpose,
as a privacy wall around psychological data). Everything that feels like "many
auth flows" is one of those two, plus drift. The goal of this design is that
every future app is a one-word decision — *platform* or *isolated* — and each
word comes with exactly one recipe.

## Tier 1 — platform apps (hub SSO)

Log in once at pragmaticdharma.org, use every platform app. Mechanics (detail
in ARCHITECTURE.md §3):

- Hub sets `pd_session`, an HS256 JWT cookie on `.pragmaticdharma.org`,
  signed with a **per-service key** (`kid`) so a compromised app can only
  forge tokens for itself.
- Each app ("relying party") verifies the cookie **locally** with its own
  secret — no callback to the Hub on normal requests.
- If the token is for the wrong service or lacks the project grant, the app
  bounces the browser through the Hub (`/api/refresh-session`), which re-reads
  the database and re-issues the cookie. The user usually never notices.

Current Tier-1 apps: astrology, discern, mind-reader, shield, practice,
**health (tcm)** — health is a completely standard relying party (earlier fleet
notes calling it an oddity were wrong; verified in code 2026-07-17), and
ego-assessment (legacy, frozen — keep running, no new auth work).

**The recipe for a new Tier-1 app:** copy the canonical verifier
(`shared/auth-cloudflare.js` or `shared/auth-flask.py`), add the app to the
Hub's `KNOWN_PROJECTS` + `REDIRECT_ALLOWLIST` + a `JWT_SECRET_<APP>` key, grant
users in `user_projects`. Nothing else.

## Tier 2 — isolated apps (own auth, on purpose)

psyche has its own D1, its own magic-link login, no `pd_session`, and an e2e
test (`tests/separation.e2e.ts`) that fails if it ever talks to another pd
host. That is a **feature**: a data breach or bug on the platform side cannot
reach psyche's data, and vice versa. The cost is a second login for Jim's
users, paid deliberately.

**Policy:** an app is Tier 2 only when it holds data sensitive enough to
justify its own blast radius (psychological/health-adjacent content). Nothing
else gets its own auth. Never "unify" psyche into the Hub for convenience.

## The three real weaknesses (and the fixes)

*Status as of 2026-10-11. Weakness 1 was fixed on 2026-07-19, before this
doc's proposal reached Jim, which is why the doc read as if it were still open.*

1. **Revocation doesn't propagate.** **FIXED 2026-07-19.** The JWT `exp` is
   24 h (`JWT_TTL_SECONDS = 86400`), the Hub session stays 30 days, and an
   expired JWT is silently re-minted at `/login` (`verifyJWTForRefresh` →
   `handleRefreshSession`), which re-checks `revoked_at` and the user's status.
   Revocation therefore lands within a day, with no new magic-link email.
   Design: `docs/design-session-revocation.md`.

2. **Verifier drift.** Workers can't share code across deployments, so every
   app inlines its own copy of the canonical verifier, and copies drift.
   **BUILT 2026-10-11:** `scripts/auth-drift.mjs` extracts `verifyJWT`,
   `base64urlDecode` and `hasProjectAccess` from each relying party's committed
   code (its bare repo on biggie), normalizes away formatting, and hashes each
   against `shared/auth-cloudflare.js`. Which apps it checks is derived: a
   registry project whose host resolves is live, and offline apps are skipped.
   `shared/verifier-copies.json` says where each app's copy lives and records
   deliberate deviations (review requires an explicit project grant). A live
   app with no row there fails, so a restored app is noticed. It shows up as
   the fleet-health invariant **"pd auth: verifier drift"**, which surfaces a
   failure and never blocks a deploy. It checks committed code, not the
   deployed bundle.

3. **Hub hygiene.** **DONE**, in two passes. 2026-07-30 added the tests
   (signup/admin/refresh/redirect) and removed the dead code. 2026-10-11 added:
   - **POST-only logout.** `GET /api/logout` signs nobody out. It serves a
     one-button "Sign out?" page that POSTs, which closes logout-CSRF. Sign-out
     links already vendored into sub-project nav bars keep working, at the cost
     of one extra click, so no sub-app had to be redeployed.
   - **Turnstile on `/api/login`**, using the Hub's own widget and never
     psyche's (widget `pd-hub`, live since 2026-10-11). It stays inert until the worker has both `TURNSTILE_SITE_KEY`
     and `TURNSTILE_SECRET`. Once both are set it fails closed: no token, a bad
     token or a siteverify outage all mean no email goes out. The login page's
     CSP admits `challenges.cloudflare.com` only while it is configured.

## What this design deliberately does NOT do

- No third-party identity provider, no OAuth — magic-link fits a
  tens-of-users platform and keeps the whole system explainable in a page.
- No shared session store for relying parties. Local JWT verification is why
  the apps stay simple and fast, and the 24-hour exp makes that safe enough.
- No auth changes to ego-assessment (frozen legacy) or psyche (isolation is
  the point).

## Decision status

- **Fixes #2 + #3:** approved by Jim 2026-10-11 (spine ak-0a3b0a83), built
  and deployed the same day (hub version `2273cf3d`).
- **Fix #1:** already live since 2026-07-19 (see above).
- **The two-tier policy (Tier 1 / Tier 2 above):** NOT adopted yet. Jim folded
  it into a sit-down on which pd services are being kept (spine ak-7072af98).
  Until that sit-down, the tier sections describe how things are today and are
  not yet a standing rule.
