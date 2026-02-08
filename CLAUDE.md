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

## Sub-Projects

| Subdomain | Worker | Status |
|-----------|--------|--------|
| shield.pragmaticdharma.org | psychic-shield | JWT + legacy token auth |
| health.pragmaticdharma.org | tcm-tracker | Untouched (cloudflared tunnel) |
| ego-assessment.pages.dev | ego-dev | Untouched (own auth) |

## Secrets

Set via `wrangler secret put <NAME>`:
- `JWT_SECRET` — HMAC-SHA256 signing key (32 hex bytes), shared with shield worker
- `RESEND_API_KEY` — Resend transactional email API key
- `DISCORD_WEBHOOK_URL` — Discord webhook for signup/access notifications

## Files

```
worker.js           # Main Worker (~500 lines): routing, auth, admin, JWT, Resend, Discord
schema.sql          # D1 schema (users, magic_links, sessions, access_logs, config)
wrangler.toml       # Worker config + D1 binding
package.json        # Wrangler dev dependency
pd                  # Admin CLI (bash, wraps wrangler d1 execute)
pages/
  index.html        # Landing page (project cards)
  login.html        # Login form (email + 6-digit code)
  signup.html       # Signup form (name, email, note)
  resources.html    # Meditation maps (from original index.html)
```

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
