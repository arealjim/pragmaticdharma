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

1. **Revocation doesn't propagate.** Relying parties trust an unexpired JWT
   for up to 30 days; Hub-side logout/revocation only stops the Hub itself.
   **Fix (build):** shorten the JWT `exp` to ~24 h while keeping the 30-day
   Hub session. An expired JWT already triggers the refresh-session bounce,
   which re-checks `revoked_at` + user status at the Hub — so revocation
   becomes effective within a day, with no new infrastructure and no per-app
   Hub callbacks. Users still stay logged in for 30 days.

2. **Verifier drift.** Workers can't share code across deployments, so every
   app keeps its own *copy* of the canonical verifier, and copies drift.
   **Fix (build):** stamp `AUTH_VERSION` in the canonical files and add a
   small check script (runnable by CI or the fleet-health report) that hashes
   each app's copy against canonical and goes red on mismatch.

3. **Hub hygiene.** `GET /api/logout` mutates state (logout-CSRF), no bot
   protection on `/api/login`, dead code, and thin test coverage on
   signup/admin/refresh paths — all already itemized in `TODO.md ## Later`.
   **Fix (build):** one batched hardening pass.

## What this design deliberately does NOT do

- No third-party identity provider, no OAuth — magic-link fits a
  tens-of-users platform and keeps the whole system explainable in a page.
- No shared session store for relying parties — local JWT verification is why
  apps stay simple and fast; the 24-hour exp makes it safe enough.
- No auth changes to ego-assessment (frozen legacy) or psyche (isolation is
  the point).

## Decision status

Proposed to Jim via the cto review board (2026-07-17): adopt the two-tier
policy (this doc), build fix #1 (short-lived JWT), build fixes #2+#3 (drift
check + hardening batch). Update this section when decided.
