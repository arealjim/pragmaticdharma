# pragmaticdharma

> **Facts** · runs-on: Cloudflare edge · deploys-to: pragmaticdharma.org · depends-on: none (it's the hub; subprojects depend on it) · map: `machine-setup/docs/portfolio-map.md`

> **Role** · app developer (platform hub — auth + shared infra for all pd subprojects) · **Autonomy:** build/test/deploy autonomously; unreviewed proposals queue in `cto/REVIEW.md` first · **Always Jim's:** auth/access-control semantics (user approvals, allowlists, JWT/session policy, `./pd` admin actions) and user-facing announcements/emails · **Cadence:** on demand

Platform portal and auth system for pragmaticdharma.org. Serves the landing page, handles user signup/login (magic link via Resend), admin approval workflow, and provides shared JWT auth for sub-projects.

Deep reference: `docs/ARCHITECTURE.md` (operator manual — component map, login + JWT-verification sequence diagrams, D1 retention schedule, what breaks if the Worker is down).

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
- **JWT cookies** (`pd_session`) on `.pragmaticdharma.org` — each sub-project verifies locally against its own per-service `JWT_SECRET_<SERVICE>` (no callback to this Worker per request)
- Admin/access changes take effect immediately via `GET /api/refresh-session`, which re-reads `user_projects` from D1 and re-issues the JWT

Full login sequence, JWT-verification sequence, D1 retention schedule, and failure-mode analysis: `docs/ARCHITECTURE.md`.

## Sub-Projects

All 11 sub-projects are Cloudflare Workers (Pages migration complete 2026-04-25; discern added 2026-06-12; review added 2026-07-17). Each verifies JWTs with its own per-service key (`kid` claim selects the right key).

| Subdomain | Worker | Auth Style | Notes |
|-----------|--------|------------|-------|
| shield.pragmaticdharma.org | `psychic-shield` | worker-gate (302/403) | Briefing reader; D1 + KV |
| mindreader.pragmaticdharma.org | `mind-reader-workers` | worker-gate (302/403) | Biometric SPA; on-device ML, no Claude |
| psychtools.pragmaticdharma.org | `psychtools-workers` | worker-gate (302/403) | DBT skills; static + /api/feedback |
| astrology.pragmaticdharma.org | `astrology-workers` | worker-gate (302/403) | Frontend + biggie Claude proxy at `astrology-api.pragmaticdharma.org` |
| practice.pragmaticdharma.org | `practice-workers` | worker-gate (302/403) | Frontend + biggie Claude proxy at `practice-api.pragmaticdharma.org` |
| sentinel.pragmaticdharma.org | `sentinel-web` | worker-gate (302/403) + admin-email allowlist | Admin-only preparedness dashboard; reads `sentinel_*` tables in shared D1 |
| psychology.pragmaticdharma.org | `ego-assessment-workers` | api-gate (401) | Ego development assessment; Anthropic API |
| health.pragmaticdharma.org | `tcm-tracker` (Flask via cloudflared) | api-gate (401) | Health tracking on biggie |
| bromnichord.pragmaticdharma.org | `bromnichord-workers` | worker-gate (302/403) | Chiptune omnichord instrument; static assets only |
| discern.pragmaticdharma.org | `discern-workers` | worker-gate (302/403) | Calibration training game (~/workspace/discern); static assets only, localStorage data |
| review.pragmaticdharma.org | `review-workers` | worker-gate (302/403) | Business-ops review dashboard (majordomo project); own D1 `review-db`; `/api/ingest` accepts bearer `INGEST_TOKEN_REVIEW` from odf-application-pipeline |

The legacy magic-link auth (ego_session) was retired. Subdomain `ego-assessment.pages.dev` is going away once the old Pages project is deleted.

**Sentinel temporary signing-key state (2026-05-25):** `KID_TO_BINDING['sentinel']` currently maps to `JWT_SECRET_PRAGMATICDHARMA` rather than a per-project `JWT_SECRET_SENTINEL`. The wrangler secrets-store beta CLI couldn't create the per-project entry (defaulted to local-only mode without `--remote`); the keepass DB password to retry via dashboard wasn't immediately available. Sentinel-web's `wrangler.toml` binds its `JWT_SECRET` to the same `JWT_SECRET_PRAGMATICDHARMA` entry so sign value ≡ verify value. To restore per-project rotation independence: create `JWT_SECRET_SENTINEL` via the dashboard, then flip `KID_TO_BINDING['sentinel']` in this repo AND `secret_name` in `~/workspace/sentinel-web/wrangler.toml` in the same change.

## Secrets

All platform secrets live in **Cloudflare Secrets Store** under store name `pragmaticdharma` (id `626a023faf5e4be98729d2f4b9849f09`). Each service binds only its own keys; the platform Worker holds all of them so it can sign JWTs for any destination.

**Per-service JWT signing keys** (one per service, named `JWT_SECRET_<SERVICE>`):
- `JWT_SECRET_PRAGMATICDHARMA`, `JWT_SECRET_EGO_ASSESSMENT`, `JWT_SECRET_SHIELD`, `JWT_SECRET_MINDREADER`, `JWT_SECRET_PSYCHTOOLS`, `JWT_SECRET_ASTROLOGY`, `JWT_SECRET_PRACTICE`, `JWT_SECRET_HEALTH`, `JWT_SECRET_BROMNICHORD`, `JWT_SECRET_DISCERN`, `JWT_SECRET_REVIEW`
- `JWT_SECRET_DISCERN` (created 2026-06-12) has its own random value — the beta secrets-store CLI now works with `--remote`, so the sentinel workaround wasn't needed.
- The platform Worker sets `kid: <service>` in the JWT header so each verifier picks the right key.

**Per-service ingest tokens** (bearer auth for machine-to-machine ingest, held by the receiving worker — not the platform hub):
- `INGEST_TOKEN_REVIEW` — held by `review-workers`; presented by odf-application-pipeline when pushing decisions to `/api/ingest`.

**Other shared secrets:** `OWNER_EMAIL`.

**Per-service plain Worker secrets** (still on `wrangler secret put` until next rotation): `DISCORD_WEBHOOK_URL` on `pragmaticdharma` (signup notifications + retention-sweep alerts). `RESEND_API_KEY` was migrated to Secrets Store on 2026-04-25 as `PRAGMATICDHARMA_RESEND_API_KEY`. Code reads via `getSecret(env, name)` which handles both binding types transparently.

⚠️ Platform Worker `compatibility_date` must be `2026-04-01` or later for Secrets Store bindings to work — older dates break `.get()`.

## Files

```
worker.js           # Main Worker (~500 lines): routing, auth, admin, JWT, Resend, Discord
schema.sql          # D1 schema (users, magic_links, sessions, access_logs, config)
wrangler.toml       # Worker config + D1 binding
package.json        # Wrangler dev dependency
pd                  # Admin CLI (bash, wraps wrangler d1 execute)
test-auth.js        # Auth enforcement integration tests (45 tests across 6 subdomains + ego criticals)
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
docs/
  ai-development-guide.md          # Phase 3: patterns, gotchas, security checklist
reviews/
  2026-04-23-<service>.md          # Phase 1 audit reports
  remediation-status-2026-04-25.md # Master remediation tracker (closed + deferred)
```

For deferred items: prompt files live at `~/prompts/`. See the remediation tracker for which prompts cover which findings.

## Testing

**Unit tests** (local, no network): `npm test` — runs `test/*.test.mjs` under `node --test` against the real worker fetch handler, with an in-memory D1 (node:sqlite adapter, `test/fake-d1.mjs`) and stubbed outbound fetch. Loader hooks in `test/register-stubs.mjs` stub the wrangler text-module imports. Covers the auth flows: magic-link/code verify (atomic single-use), token hash-at-rest, logout revocation, retention sweep.

**Integration tests** (live): auth enforcement tests verify that all 6 subdomains correctly grant/deny access based on JWT `projects` claims.

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
