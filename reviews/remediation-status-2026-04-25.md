# Phase 1 Security Audit — Remediation Status

**Audit date:** 2026-04-23
**Last update:** 2026-04-25

## Executive summary

The 2026-04-23 multi-project security audit identified **11 Critical, 34 High, 62 Medium, 69 Low** findings across 9 projects. As of 2026-04-25:

- **All 11 Critical findings: closed.**
- **All 34 High findings: closed** (some via Phase 2 platform migration: Pages → Workers, Secrets Store, per-service JWT keys with `kid` claim).
- **44 of 62 Medium findings: closed.** Remaining Medium items are tracked below; most are documentation/process-level or require schema changes.
- **40+ of 69 Low findings: closed** (the rest are nits).
- **Phase 3 documentation:** complete — see `docs/ai-development-guide.md`.
- **Phase 2 migration:** complete — all 7 sub-projects are Cloudflare Workers (no Pages projects in production); secrets in Cloudflare Secrets Store; per-service JWT keys with `kid` routing.
- **Auth enforcement tests:** 45/45 passing.

## What landed in Phase 2 + chip session

### Platform-wide changes
- All 7 sub-services migrated from Cloudflare Pages → Workers.
- All shared secrets in Cloudflare Secrets Store under store `pragmaticdharma` (id `626a023faf5e4be98729d2f4b9849f09`).
- Per-service JWT signing keys with `kid` header claim (`kid: shield`, `kid: ego-assessment`, etc.). Platform Worker holds all keys; sub-services hold only their own.
- `compatibility_date` ≥ 2026-04-01 on every Worker (Secrets Store binding requirement).
- `getSecret(env, name)` duck-typed helper that handles both async Secrets Store bindings and plain string env vars.
- `kid`-aware test-auth.js — 45 scenarios across 6 sites + 3 ego critical-endpoint tests.

### pragmaticdharma (platform Worker)
- H1 CSRF protection on state-changing admin endpoints
- H2 JWT revocation check on every verify
- H3 Bash SQL injection eliminated via `sql_escape()` in `pd` admin CLI
- H4 `sessionToken` claim added in handleVerifyCode
- H5 Magic-link brute-force mitigation via `verify_failures` table
- H6 Explicit REDIRECT_ALLOWLIST (no more wildcard subdomain match)
- H7 XSS escape (`<>&`) in nav inline-script JSON
- M1 Per-IP signup rate limit
- M2 CSP header
- M3 Admin pending-list HTML escape
- M4 Daily access_logs PII retention sweep (cron 04:00 UTC)
- M6 Refresh-session re-checks user `status`, not just expiry
- M7/M8 Admin config allowlist (read + write)
- M10 Rejected re-signup cooldown
- L1 `bind(...params)` instead of fragile arity branching
- L2 Per-IP login rate limit BEFORE user lookup (closes email-enumeration via 429-vs-403)
- L3 Magic-link token charset validation (`/^[0-9a-f]{64}$/`)
- L4 `generateCode` reject-and-retry to remove modulo bias
- L6 `shared/auth-flask.py` except cleanup with DEBUG log
- RESEND_API_KEY migrated to Secrets Store

### ego-development-app-api
- H-new-1..H-new-5 IDOR + prompt-injection fixes across `responses`, `sessions`, `response`, `visit`, `delete-request`, `deep-analysis`, `assessments/score`, `score-batch`, `stem-stats`
- M-new-4 SRI hash on chart.js@4.4.1
- M-new-5 No internal-error leakage in `/api/deep-analysis` 500 responses
- M-new-7 Expanded `_routes.json` exclusions
- L-new-1 `crypto.randomUUID()` replacing `Math.random()` in deep-analysis
- L-new-3 `X-XSS-Protection: 0` (legacy filter disabled, CSP carries the load)

### psychic-shield
- C1, C2 Real secrets removed from `.env` and `tokens.json`
- H1 Drop API-key-via-query-param support
- H2 Per-IP rate limit on API-key auth
- H3 Use canonical shared JWT module
- H4 Daily Claude budget guard with 75%/100% Discord alerts
- M1 Retry preamble no longer compounds across attempts
- M2 FTS5 sanitizer rewrite (`buildFtsQuery` — phrase-quote each token)
- M4 Defensive JSON-in-HTML escape in nav inline-script
- M5 Prompt-injection wrapping (nonce-tagged delimiters) in analyzer + story_analyzer + alerts
- M6 Discord webhook per-user rate limit (15-min lookback in access_logs)
- M8 Daemon `_dispatch` always reschedules with exponential backoff (capped 8x)

### mind-reader
- H1 Validated parent origin + dropped `'*'` postMessage targetOrigin
- H2 (same as above — origin captured before broadcast)
- H3 Camera no longer auto-inits — only on validated `mr:init` postMessage
- H7-equivalent Defensive nav inline-script escape
- Strengthened CSP with `default-src 'self'`, embed-mode-aware `Permissions-Policy: camera=(self), microphone=(self)`, `X-Frame-Options: DENY` outside embed mode

### astrology
- H7-equivalent Nav inline-script escape
- M2 Full security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- M4 `?? null` instead of `|| null` for lat/lng (latitude 0 / Greenwich no longer NULL'd)
- Devbox Claude proxy now uses per-service JWT key via `EnvironmentFile=/etc/astrology-claude/env`

### practice-hub
- Same JWT/proxy migration as astrology
- H7-equivalent Nav inline-script escape
- M-6 Full security headers
- L-1 Nav-bar `innerHTML` text escape now covers `&`/`>` not just `<`

### psychtools
- H7-equivalent Nav inline-script escape
- Full security headers (mirrored)

### tcm-tracker (health)
- bwrap sandbox fix on Claude CLI subprocesses
- Migrated to its own per-service JWT key (`JWT_SECRET_HEALTH`)
- ResMed password rotated; Oura entries removed (Oura passwords were broken)

### radio
- Service decommissioned

## Deferred items — see prompt files in `~/prompts/`

| Finding | Project | Why deferred | Prompt file |
|---|---|---|---|
| M3 (nonce CSP) | psychic-shield | Needs full briefing-template audit; break risk outweighs current defensive value | `~/prompts/shield-m3-nonce-csp.md` |
| M-new-3 (server-side session-completion check) | ego-development | Needs schema-aware response-count check + expected-stem-count source-of-truth | `~/prompts/ego-m-new-3-session-completion.md` |
| M-new-8 (delete-request feedback table) | ego-development | Needs schema migration + admin UI updates | `~/prompts/ego-m-new-8-delete-request-feedback.md` |
| Platform DISCORD_WEBHOOK_URL → Secrets Store | pragmaticdharma | Best done at next webhook rotation | `~/prompts/platform-discord-webhook-secrets-store.md` |
| Daemon as systemd unit | psychic-shield | Operational/fleet item, not code | `~/prompts/shield-daemon-systemd.md` |
| Polar H10 + HRV WIP review | mind-reader | Unrelated WIP from prior session, needs human review before commit | `~/prompts/mind-reader-polar-h10-review.md` |

Items not on this short list — astrology M-1, M-3, M-6 (audit log), L-x; practice-hub L-2..L-5; ego M-new-1..2, 6 — are documented in the original review files under `reviews/2026-04-23-*.md` and remain open. They are lower severity and most require either docs/process work or larger refactors. Triage them in a future Phase 4.

## Where to find things

- **Original audit reports:** `reviews/2026-04-23-<service>.md`
- **AI-development guide (canonical patterns):** `docs/ai-development-guide.md`
- **Auth enforcement tests:** `test-auth.js` (run with `set -a && . /tmp/pd_per_service_keys.env && set +a && node test-auth.js`)
- **Per-service JWT key backup:** in KeePass under `Pragmatic Dharma/JWT_SECRETS_PER_SERVICE` (also in `/tmp/pd_per_service_keys.env` as a working copy)
- **Deferred prompts:** `~/prompts/` (each item above)
