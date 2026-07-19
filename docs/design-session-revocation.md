# Design: pd_session revocation + signing-key rotation

Status: IMPLEMENTED — design approved and built 2026-07-19. See Decisions section below.

## Decisions (2026-07-19)

**Ask 1 — token lifetime:** YES — 24h is acceptable. Built as specced: `JWT_TTL_SECONDS = 86400`, cookie `Max-Age` stays 30d, lazy-refresh at `/login` keeps UX silent.

**Ask 2 — ego-assessment frontend:** Jim directed: "actually let's take down ego-assessment and not show it on the pd webpage anymore. it's outdated and we're moving our concerns." Action taken: removed the Ego Development card from `pages/index.html`. The app remains live at `psychology.pragmaticdharma.org` (its auth needs no change — api-gate, 401s on expiry, not worker-gate). No pd-sso hook added.

**Ask 3 — sentinel signing key:** YES — schedule the dashboard step in a session with Jim present. Sentinel restoration is tracked in TODO.md ## Now; Jim needs to be at the Cloudflare dashboard to create `JWT_SECRET_SENTINEL` in the Secrets Store, then Claude deploys the two-repo change.

Covers Gaps 1 and 4 from `cto/docs/pd-auth-delta.md`. Companion reading: `docs/AUTH-DESIGN.md` (which proposed the direction this doc makes concrete), `docs/ARCHITECTURE.md` §3/§6.

## Problem

The Hub (worker.js) mints `pd_session`, an HS256 JWT cookie with `exp` = 30 days (`signJWT`, worker.js:995) and cookie `Max-Age=2592000` (`sessionCookie`, :1125). Relying parties — astrology, discern, mind-reader, shield, psychtools, practice, bromnichord, sentinel, review (Workers, `shared/auth-cloudflare.js` copies), ego-assessment (api-gate), and health/tcm-tracker (Flask, `shared/auth-flask.py`) — verify **locally**: signature + `exp` + `projects[]` claim only. None of them consults the Hub's `sessions.revoked_at`.

Consequences:

1. **Revocation doesn't propagate (Gap 1).** Logout (`handleLogout`, :749) and admin-reject flip state in D1, and the Hub's own `verifyJWT` (:1039) honors it — but every relying party keeps accepting the JWT until its own 30-day expiry. The failure mode that matters: an admin rejects a user, or a session is known-compromised, and it *must actually die* everywhere.
2. **No rotation story for signing keys (Gap 4 adjacent).** The `kid` header + `KID_TO_BINDING` (:952) give per-service keys, but there is no written procedure for rotating a key, and sentinel still rides on `JWT_SECRET_PRAGMATICDHARMA` (open TODO since 2026-05-25).

psyche is out of scope by design (own auth, own D1, no pd_session — Model B). It is precedent that immediate server-side revocation is achievable when the session row is the only authority; this design gets Model A close to that without giving up local verification.

## Constraints

- Relying parties are **separate Cloudflare Worker deployments** (plus one Flask app on biggie). They cannot import Hub code; every mechanism must ship as edits to each repo's own copy — so the winning design minimizes per-repo edits.
- D1 lives only at the Hub. health/tcm has no Cloudflare bindings at all (Flask behind cloudflared) — any design requiring a KV/D1 binding at the relying party excludes health.
- Tiny current user base, but a real multi-user platform: design for correctness, not scale.
- Cost ~zero. No new paid services.
- The Hub must not become a per-request dependency — today, relying parties survive a Hub outage for logged-in users (ARCHITECTURE §5 "what breaks"), and that property is worth keeping.

## Options weighed

**(a) Short-lived JWTs + refresh through the Hub.** Shrink JWT `exp` to hours; keep the 30-day session row as the authority; an expired JWT forces a bounce through the Hub, which re-checks `revoked_at` + user status and re-mints. Revocation converges within one JWT lifetime. Per-request verification stays local; the Hub is touched ~once/day/user.

**(b) Revocation-check callback from relying parties.** Each relying party calls a Hub endpoint (`/api/check-session`) per request or on a cache interval. Immediate revocation, but: the Hub becomes an availability and latency dependency for every app; every one of ~11 relying-party repos grows callback + caching code (and each copy can drift, the exact disease `shared/` already has); the Flask app needs a parallel implementation. Most code for the least architectural gain.

**(c) Shared KV denylist.** Hub writes revoked session hashes to a KV namespace; relying parties bind the same namespace (same Cloudflare account — this genuinely works across deployments) and check per request. ~60s revocation via KV eventual consistency. But health/tcm cannot bind KV (Flask), so it needs a callback anyway — two mechanisms; every Worker repo gains a binding + lookup code; denylist TTL bookkeeping; and it only handles explicit revocation, not "admin changed grants" (which refresh handles for free).

**Decision: (a)**, with **key rotation as the break-glass immediate kill**. (a) wins because the refresh machinery already exists (`/api/refresh-session` + `pd-sso.js` client), the Hub-outage independence survives, and — with the Hub-side lazy-refresh trick below — worker-gate relying parties need **zero code changes**. (b) and (c) both spend their complexity buying sub-hour revocation latency, which we don't need routinely because a truly compromised session/key can be killed *instantly* by rotating that service's signing key (all outstanding JWTs for that kid die at once; users just re-login via magic link). Routine revocation converging in ≤24h + instant break-glass beats always-on infrastructure at this scale.

## The design

### Token lifetimes

| Thing | Today | New |
|---|---|---|
| JWT `exp` (worker.js:995) | 30 days | **24 hours** |
| Cookie `Max-Age` (:1125) | 30 days | **30 days (unchanged)** — the cookie must outlive the JWT so the expired JWT is still presented for refresh |
| `sessions.expires_at` row (:641, :1094) | 30 days | 30 days (unchanged) — absolute cap; no sliding, no rotation (psyche-style rotation is a non-goal here; the 30-day row is the hard ceiling) |
| Magic links | 15 min | unchanged |

Net UX: login once per 30 days as today; one silent 302 round-trip through the Hub per app per ~24h.

### Refresh flow (Hub-side changes only)

1. **`verifyJWTForRefresh(env, token)`** — new helper: same as `verifyJWT` but skips the `exp` check. The session row is the authority instead: the D1 lookup must find the row, `revoked_at IS NULL`, **and `expires_at > now`** (the current `verifyJWT` doesn't check row expiry — with 30d exp that was redundant; for refresh it is load-bearing). Signature and `kid` checks stay strict.
2. **`handleRefreshSession` (:697)** switches from `verifyJWT` to `verifyJWTForRefresh`. It already re-reads `users.status` (M6, :715) and `user_projects`, preserves `sessionToken` (H4, :724), and re-signs for `kidForRedirect(redirect)`. No other change.
3. **Lazy refresh at `GET /login`** — this is the trick that spares the relying parties. Today an expired JWT makes a worker-gate app 302 to `https://pragmaticdharma.org/login?redirect=...` (the "unauthenticated" path). New behavior in the `/login` handler: if a `pd_session` cookie is present, attempt `verifyJWTForRefresh`; on success, behave exactly like `handleRefreshSession` (re-mint for the redirect's kid, 302 back) instead of serving the login page. On failure (no cookie / revoked / row expired / user not approved), serve the login page as today. Result: expired-but-live sessions silently re-mint; dead sessions land on the login form.
4. **Loop guard.** If a relying party's key is misconfigured, it will bounce a freshly minted cookie straight back to `/login`, which would re-mint forever. Guard: when `/login` silently redirects, set `pd_lr=1; Path=/login; Max-Age=30; Secure; HttpOnly` (host-only cookie). If `/login` is hit with `pd_lr` present, clear it and serve the login page. Bounded at 2 hops per 30s; a healthy flow clears naturally.
5. `signJWT` (:995): `exp: now + 24 * 60 * 60`. One constant, named (`JWT_TTL_SECONDS`).

### What each relying party must change

- **Worker-gate apps (astrology, discern, mind-reader, shield, psychtools, practice, bromnichord, sentinel-web, review): nothing.** Their existing expired→login-redirect path now transparently refreshes at the Hub. Verify each still redirects with the `redirect` param intact (that's the current documented behavior; confirm per repo during rollout, don't assume).
- **api-gate apps (ego-assessment, health/tcm):** they 401 on an expired JWT; recovery is client-side via `pd-sso.js` (`tokenPresentButInvalid` → `refreshNow()` → `/api/refresh-session`). Required per repo: confirm the session-status endpoint reports `tokenPresentButInvalid: true` for an *expired* (not just wrong-kid) cookie, and that pages load `pd-sso.js` with auto mode. If ego-assessment's frontend doesn't — ego is frozen; see Ask 2.
- **No relying party needs new bindings, secrets, or verifier changes.** `shared/auth-cloudflare.js` / `auth-flask.py` are untouched (they already reject expired tokens, which is exactly what we want).

### Key rotation runbook (the kid mechanism, made operational)

Rotation model: **hard rotation per kid**. Hub and relying party bind the *same* Secrets Store entry (store `626a023faf5e4be98729d2f4b9849f09`), and `getSecret` reads it at runtime — updating the value rotates both sides together without redeploys (the Hub's per-`env` secret cache lasts one isolate lifetime; expect propagation within minutes, verify before declaring done). All outstanding JWTs signed with that kid die instantly; affected users re-login by magic link (cheap at this user count). With 24h JWTs the blast radius of *not* rotating is also small — rotation is for compromise, not hygiene.

Per-key procedure (also the break-glass "kill every session on app X now"):
1. `vault gen 64` → new value (never in chat/argv; pipe it).
2. Update the Secrets Store entry `JWT_SECRET_<SERVICE>` — dashboard first (the 2026-05-25 sentinel scar: the beta `wrangler secrets-store` CLI failed on create; try CLI, fall back to dashboard without burning time).
3. `vault set cto/...` (or the platform's KeePassXC home for JWT keys) with the same value; commit+push the credentials repo.
4. Verify: `node test-auth.js --only <service>` (needs secrets exported) — old JWT rejected, fresh login works.
5. To kill **all** platform sessions: rotate `JWT_SECRET_PRAGMATICDHARMA` plus each per-service key, or (softer) `UPDATE sessions SET revoked_at = datetime('now')` via `./pd`/wrangler d1 — the D1 route revokes at the Hub immediately and everywhere within 24h; the key route is instant everywhere.

**Sentinel restoration (open TODO, folds in here):** create `JWT_SECRET_SENTINEL` in the Secrets Store (dashboard; value = `vault gen 64`, stored in vault), then in one change: flip `KID_TO_BINDING['sentinel']` in worker.js and `secret_name` in `~/workspace/sentinel-web/wrangler.toml`, deploy both. Existing sentinel-kid cookies fail signature → users re-login (or lazy-refresh re-mints if their session row is alive — the Hub verifies with the *new* binding, so pre-flip cookies signed with the platform key still fail; expect one re-login). Do this before or with the 24h-exp deploy; it's the same muscle.

### Failure modes

- **Hub down:** logged-in users now lose access after ≤24h instead of ≤30d (JWTs expire and can't refresh). Accepted trade — a >24h Hub outage is already a platform-down event (no logins anywhere). Documented change to ARCHITECTURE §5.
- **Clock skew:** Workers share Cloudflare time; the Flask verifier uses host time — biggie runs NTP; 24h granularity makes skew irrelevant.
- **Revoked-but-cached:** none — relying parties never cache verification across requests.
- **Legacy 30-day JWTs in the wild at deploy time:** remain valid until their own exp (up to 30 days post-deploy). Acceptable: revocation coverage phases in. To force it, rotate keys (above) or accept the tail.

### Verifying revocation end-to-end (definition of done)

1. Login to astrology; confirm access. `./pd reject <email>` (or `UPDATE sessions SET revoked_at=...` for the logout case).
2. Hand-mint an expired-exp JWT for the same sessionToken (test-auth.js already holds the secrets; add a `--mint-expired` helper) and present it to astrology → expect 302 to `/login` → expect the Hub to serve the login *page* (not a silent re-mint) because the session is dead. For a *live* session, the same expired JWT must produce a silent re-mint and land back authenticated.
3. Repeat step 2's live-session case against health (api-gate/Flask path, via pd-sso in a browser).
4. Add unit tests at the Hub: `verifyJWTForRefresh` accepts expired-sig-valid + live row; rejects revoked row, expired row, rejected user; `/login` loop guard caps at one silent redirect per 30s.

### Rollout order

1. Hub unit tests for the new paths (red), then `verifyJWTForRefresh`, `/login` lazy refresh + loop guard, `JWT_TTL_SECONDS = 86400`. Deploy Hub. (Worker-gate apps benefit immediately; nothing else deployed.)
2. Sentinel key restoration (independent, same session or adjacent).
3. Per-repo verification sweep: each worker-gate app's expired-cookie path preserves the redirect param; each api-gate app reports `tokenPresentButInvalid` on expiry. Fix only where broken.
4. End-to-end verification (above); update ARCHITECTURE.md §3b/§5 and AUTH-DESIGN.md "Decision status"; close TODO items.

## Open questions for Jim (zero-context asks)

**Ask 1 — token lifetime.** Context: today, logging someone out (or admin-rejecting them) at pragmaticdharma.org doesn't lock them out of the sub-apps until their token dies — up to 30 days. This design shrinks that to 24 hours by making tokens short-lived and silently renewed, with no user-visible change. Shorter (e.g. 1h) means faster lockout but a hub round-trip per app per hour. Question: is 24h an acceptable worst-case for routine revocation, given instant break-glass exists via key rotation? Yes → build as specced. No, want tighter → we set 1–6h; costs nothing but slightly more redirect traffic.

**Ask 2 — ego-assessment (frozen legacy).** Context: ego-assessment is deliberately frozen — "no new auth work". Under this design its *server* needs nothing, but if its frontend doesn't already run the pd-sso resync script, its users may hit a daily login prompt instead of a silent refresh once tokens go 24h. Question: if verification shows ego's frontend lacks the resync hook, may we make that one-line change (add the script tag) despite the freeze? Yes → one-line edit, no auth logic touched. No → ego users may re-login daily; everything else unaffected.

**Ask 3 — sentinel signing key.** Context: sentinel has reused the platform's signing key since 2026-05-25 because the Secrets Store CLI failed; fixing it needs one new secret created in the Cloudflare dashboard (Claude has no dashboard session — needs you logged in, ~2 minutes) plus a coordinated two-repo deploy Claude can do. Question: OK to schedule the dashboard step in a session with you present, before the revocation deploy? Yes → it rides along at no extra cost. No/later → revocation design ships anyway; sentinel stays on the shared key (documented exception continues).
