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

| Subdomain | Worker/App | Auth | Auth Style |
|-----------|------------|------|------------|
| shield.pragmaticdharma.org | psychic-shield (Cloudflare Worker) | JWT + legacy token auth | worker-gate (302/403) |
| mindreader.pragmaticdharma.org | mind-reader (Cloudflare Pages) | JWT SSO | worker-gate (302/403) |
| health.pragmaticdharma.org | tcm-tracker (Flask via cloudflared tunnel) | JWT SSO (replaces password auth) | api-gate (401) |
| psychology.pragmaticdharma.org | ego-assessment (Cloudflare Pages) | JWT SSO + existing magic link auth | api-gate (401) |
| ego-assessment.pages.dev | ego-assessment (Cloudflare Pages) | Magic link auth only (no SSO cookie on this domain) | — |

## Secrets

Set via `wrangler secret put <NAME>`:
- `JWT_SECRET` — HMAC-SHA256 signing key (32 hex bytes), shared across all 5 services (pragmaticdharma, psychic-shield, ego-assessment, mind-reader, tcm-tracker)
- `RESEND_API_KEY` — Resend transactional email API key
- `DISCORD_WEBHOOK_URL` — Discord webhook for signup/access notifications

## Files

```
worker.js           # Main Worker (~500 lines): routing, auth, admin, JWT, Resend, Discord
schema.sql          # D1 schema (users, magic_links, sessions, access_logs, config)
wrangler.toml       # Worker config + D1 binding
package.json        # Wrangler dev dependency
pd                  # Admin CLI (bash, wraps wrangler d1 execute)
test-auth.js        # Auth enforcement integration tests (28 tests across all subdomains)
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

Auth enforcement integration tests verify that all 4 subdomains correctly grant/deny access based on JWT `projects` claims.

```bash
JWT_SECRET=<value> node test-auth.js
```

Tests 7 scenarios per subdomain (28 total): no cookie, expired JWT, missing project, valid access, malformed JWT, backward-compat (no projects claim), empty projects array.

Two auth styles are tested:
- **worker-gate** (shield): unauthenticated → 302 redirect, wrong project → 403
- **worker-gate** (mindreader): unauthenticated → 302 redirect, wrong project → 302 to `/api/refresh-session` (re-issues JWT), then 403 if still denied
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
