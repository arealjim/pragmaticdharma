# pragmaticdharma

Platform portal and auth system for pragmaticdharma.org. Serves the landing page, handles user signup/login (magic link via Resend), admin approval workflow, and provides shared JWT auth for sub-projects.

## Quick Reference

```bash
npm run dev              # Local dev server (wrangler dev)
npm run deploy           # Deploy to Cloudflare Workers
npm run db:migrate       # Apply schema.sql to remote D1

./pd approve EMAIL       # Approve a pending user
./pd reject EMAIL        # Reject a user
./pd users               # List all users
./pd pending             # List pending signups
./pd beta on|off         # Toggle open beta
./pd logs [PROJECT] [N]  # Show access logs
./pd config              # Show config values
```

## Architecture

- **Cloudflare Worker** at `pragmaticdharma.org` — static pages + auth API + admin API
- **D1 database** (`pragmaticdharma`) — users, magic_links, sessions, access_logs, config
- **JWT cookies** on `.pragmaticdharma.org` — shared across all sub-project Workers
- Sub-projects validate JWTs locally using the shared `JWT_SECRET`

## Auth Flow

1. User signs up (`POST /api/signup`) — inserted as `pending` (or auto-approved if open_beta)
2. Admin approves via `./pd approve EMAIL` or `POST /api/admin/approve`
3. User logs in (`POST /api/login`) — Resend sends email with 6-digit code + magic link
4. User verifies via code (`POST /api/verify`) or clicks link (`GET /api/verify/:token`)
5. JWT cookie set on `.pragmaticdharma.org`, 30-day expiry

### Session refresh

Project access changes (via admin dashboard or `user-projects` API) take effect immediately thanks to the `GET /api/refresh-session` endpoint. When a sub-project middleware detects a valid JWT that lacks the required project, it redirects to this endpoint, which re-reads projects from D1 and re-issues the JWT — transparent to the user.

## Sub-Projects

All 7 sub-projects are now Cloudflare Workers (Pages migration complete 2026-04-25). Each verifies JWTs with its own per-service key (Task #2 — `kid` claim selects the right key).

| Subdomain | Worker | Auth Style | Notes |
|-----------|--------|------------|-------|
| shield.pragmaticdharma.org | `psychic-shield` | worker-gate (302/403) | Briefing reader; D1 + KV |
| mindreader.pragmaticdharma.org | `mind-reader-workers` | worker-gate (302/403) | Biometric SPA; on-device ML, no Claude |
| psychtools.pragmaticdharma.org | `psychtools-workers` | worker-gate (302/403) | DBT skills; static + /api/feedback |
| astrology.pragmaticdharma.org | `astrology-workers` | worker-gate (302/403) | Frontend + devbox Claude proxy at `astrology-api.pragmaticdharma.org` |
| practice.pragmaticdharma.org | `practice-workers` | worker-gate (302/403) | Frontend + devbox Claude proxy at `practice-api.pragmaticdharma.org` |
| psychology.pragmaticdharma.org | `ego-assessment-workers` | api-gate (401) | Ego development assessment; Anthropic API |
| health.pragmaticdharma.org | `tcm-tracker` (Flask via cloudflared) | api-gate (401) | Health tracking on devbox |

The legacy magic-link auth (ego_session) was retired. Subdomain `ego-assessment.pages.dev` is going away once the old Pages project is deleted.

## Secrets

All platform secrets live in **Cloudflare Secrets Store** under store name `pragmaticdharma` (id `626a023faf5e4be98729d2f4b9849f09`). Each service binds only its own keys; the platform Worker holds all of them so it can sign JWTs for any destination.

**Per-service JWT signing keys** (one per service, named `JWT_SECRET_<SERVICE>`):
- `JWT_SECRET_PRAGMATICDHARMA`, `JWT_SECRET_EGO_ASSESSMENT`, `JWT_SECRET_SHIELD`, `JWT_SECRET_MINDREADER`, `JWT_SECRET_PSYCHTOOLS`, `JWT_SECRET_ASTROLOGY`, `JWT_SECRET_PRACTICE`, `JWT_SECRET_HEALTH`
- The platform Worker sets `kid: <service>` in the JWT header so each verifier picks the right key.

**Other shared secrets:** `OWNER_EMAIL`.

**Per-service plain Worker secrets** (still on `wrangler secret put` until next rotation): `RESEND_API_KEY` and `DISCORD_WEBHOOK_URL` on `pragmaticdharma`. Code reads via `getSecret(env, name)` which handles both binding types transparently.

⚠️ Platform Worker `compatibility_date` must be `2026-04-01` or later for Secrets Store bindings to work — older dates break `.get()`.

## Files

```
worker.js           # Main Worker (~500 lines): routing, auth, admin, JWT, Resend, Discord
schema.sql          # D1 schema (users, magic_links, sessions, access_logs, config)
wrangler.toml       # Worker config + D1 binding
package.json        # Wrangler dev dependency
pd                  # Admin CLI (bash, wraps wrangler d1 execute)
test-auth.js        # Auth enforcement integration tests (42 tests across all subdomains)
pages/
  index.html        # Landing page (project cards)
  login.html        # Login form (email + 6-digit code)
  signup.html       # Signup form (name, email, note)
  resources.html    # Meditation maps (from original index.html)
shared/
  auth-cloudflare.js  # Canonical JWT auth for Cloudflare Workers/Pages
  auth-flask.py       # Canonical JWT auth for Python/Flask
  nav-bar.html        # Platform navigation bar template
  README.md           # Auth & nav integration guide
```

## Testing

Auth enforcement integration tests verify that all 6 subdomains correctly grant/deny access based on JWT `projects` claims.

```bash
# Per-service JWT keys after Task #2 — one env var per service.
# Or use a single JWT_SECRET as a fallback for all (pre-Task-#2 mode).
JWT_SECRET_SHIELD=… JWT_SECRET_MINDREADER=… JWT_SECRET_PSYCHTOOLS=… \
JWT_SECRET_ASTROLOGY=… JWT_SECRET_EGO_ASSESSMENT=… \
JWT_SECRET_PRACTICE=… JWT_SECRET_HEALTH=… \
node test-auth.js
```

Tests 7 scenarios per subdomain × 6 sites = 42 + 3 ego critical-endpoint tests = 45 total.

Two auth styles are tested:
- **worker-gate** (shield, mindreader, psychtools, astrology, practice): unauthenticated → 302 redirect, wrong project → 302 to `/api/refresh-session` (re-issues JWT), then 403 if still denied. Tests accept either 302 or 403 for the project-denied case.
- **api-gate** (ego-assessment, health): all auth failures → 401 (project-denied = unauthenticated at API level)

## Code Conventions

- Single-file Worker (no bundler, no framework)
- HTML pages imported as text modules via wrangler rules
- All SQL uses `.bind()` prepared statements
- Discord notifications are fire-and-forget (`.catch(() => {})`)
- JWT: HMAC-SHA256 via Web Crypto API

## D1 Database

Database name: `pragmaticdharma`
Database ID: `d5bfd74e-5105-4136-a876-7d42e588d3d5`

Shared by both the platform worker and the psychic-shield worker.
