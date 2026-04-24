# Security + Code Quality Review: pragmaticdharma Platform
*Review date: 2026-04-23 — report-only, no code changes*

## 1. Executive Summary

- **Broadly safe to launch**, but contains several **HIGH-severity issues around CSRF on admin mutations, code injection in `pd` bash CLI, and missing revocation checks on JWT verification** that should be fixed before broad rollout.
- JWT implementation is correct (HMAC-SHA256 explicitly required, `alg=none`/RS256 rejected, constant-time compare via Web Crypto for JS and `hmac.compare_digest` for Python, 30-day `exp` enforced).
- No SQL injection found in `worker.js` — all queries use `.bind()`. However the `pd` bash CLI interpolates email into SQL; benign for a local admin tool but still a code-quality defect.
- Static pages are safe from server-side XSS (no user-derived HTML is rendered by the Worker besides `{{PROJECT_NAME}}` which is a constant). Client-side admin UI uses an `esc()` helper but has an attribute-escaping bug.
- Rate limiting is **weak**: global 20 signups/hour is easy to DoS, and no per-IP limit exists — Resend invoice and Discord webhook can be flooded.

## 2. CRITICAL Findings

None. No issues warrant blocking public launch outright, but several HIGH items below should be fixed in the next sprint.

## 3. HIGH Findings

### H1. No CSRF protection on state-changing admin endpoints
**File:** `worker.js:156-158`, `worker.js:515-646`
**Description:** `POST /api/admin/approve`, `/reject`, `/create-user`, `/user-projects`, `/config` are authenticated only by the `pd_session` cookie set with `SameSite=Lax` (`worker.js:758`). `SameSite=Lax` does **not** block cross-origin `POST` via form submission from top-level navigation, and — more importantly — an attacker-controlled sub-page on any `*.pragmaticdharma.org` sub-project (e.g., a future compromised sub-app) could issue same-site fetches with credentials to `/api/admin/config` while an admin is signed in.
**Attack scenario:** XSS on any sub-project (e.g. `shield.pragmaticdharma.org`) → attacker's script on that origin calls `fetch('https://pragmaticdharma.org/api/admin/config', {method:'POST', credentials:'include', body:'{"open_beta":"true"}'})`. Because the cookie is `Domain=.pragmaticdharma.org`, this succeeds.
**Fix:** Require a CSRF token bound to the JWT for `POST /api/admin/*` OR change admin cookie scope to `Domain=pragmaticdharma.org` (host-only, no leading dot) with `SameSite=Strict`. At minimum add an `Origin`/`Referer` check on admin POSTs: reject unless `Origin === 'https://pragmaticdharma.org'`.

### H2. JWT revocation check missing on every verify
**File:** `worker.js:668-693`, `shared/auth-cloudflare.js:35-71`
**Description:** `verifyJWT` only validates signature + `exp`. The `sessions` table has a `revoked_at` column (`schema.sql:39`) and `/api/logout` sets it (`worker.js:497-498`), but **no code path consults `sessions.revoked_at`**. A stolen/exfiltrated JWT remains valid for up to 30 days even after user logs out. Also, when an admin changes `projects`, `role`, or rejects a user, their still-valid JWT retains the old claims — `/api/refresh-session` is opt-in (sub-projects must redirect to it), so a user who no longer has access can keep using it.
**Attack scenario:** (a) User logs out on a shared computer; a prior session cookie captured by keylogger/browser extension still authenticates for 30 days. (b) Admin demotes a user; the user keeps admin role in their JWT until `exp`.
**Fix:** Include `sessionToken` in *all* JWTs (currently only set in `createSessionAndRedirect`, not in `handleVerifyCode` at `worker.js:402-408` nor `handleRefreshSession` at `worker.js:471-477`). Then in `verifyJWT` (or a wrapper), check `SELECT revoked_at, expires_at FROM sessions WHERE token=?` and reject if revoked or expired. For admin role changes, add a `users.token_version` column and include it in JWT, bumping on role/status change.

### H3. Bash SQL injection risk in `pd` admin CLI
**File:** `pd:65, 74, 87, 91, 111, 113`
**Description:** The bash CLI interpolates variables directly into SQL: `run_sql "UPDATE users SET status = 'approved' ... WHERE email = '$EMAIL';"`. Although `approve`/`reject` validate email format with a regex, `logs` passes `$PROJECT` and `$LIMIT` directly after weak regex validation, and email strings containing `'` (even if blocked by regex `[a-zA-Z0-9._%+-]`) could slip through future regex changes. This is local-only code run by the server admin, but the pattern is dangerous.
**Fix:** Use `wrangler d1 execute --command "SELECT * WHERE email = ?"` with parameterized bindings if supported, or build the SQL in a Python helper that quotes values via D1's API. At minimum, strongly assert inputs with stricter allowlisting before interpolation.

### H4. `handleVerifyCode` JWT omits `sessionToken`, breaking logout revocation
**File:** `worker.js:395-414`
**Description:** Verifying via the 6-digit code path issues a JWT **without** `sessionToken` in the payload. Consequently `handleLogout` (`worker.js:495-498`) silently no-ops for these sessions — `UPDATE sessions SET revoked_at ... WHERE token = ?` is called with `undefined`, so logout does not actually revoke anything server-side. The magic-link path (`worker.js:745`) includes it correctly.
**Attack scenario:** User signs in with 6-digit code, then clicks "Sign Out" — cookie is cleared client-side but the DB session is never marked revoked (moot today since verify doesn't check, but important once H2 is fixed).
**Fix:** Include `sessionToken: sessionToken` in the payload at `worker.js:402-408`, mirroring `createSessionAndRedirect`.

### H5. Magic-link brute-force window allows 6-digit code guessing
**File:** `worker.js:367-379`
**Description:** `handleVerifyCode` queries `WHERE code = ? AND email = ? AND used_at IS NULL`. There is a `setTimeout(r, 1000)` throttle on failure (`worker.js:373, 377`), but no per-email attempt counter. A 6-digit code has ~1M possibilities; at one attempt/sec = ~11.5 days to exhaust. More concerning: concurrent requests all block on `await setTimeout`, so an attacker can run N parallel connections and effectively bypass the 1-sec throttle (each request is slowed by 1s, but 100 parallel requests = 100 attempts/sec). Cloudflare will eventually throttle, but this is not a defense.
**Fix:** Track failure count per `email` in a D1 table; after 5 failures within 15 minutes, invalidate all active magic_links for that email and require a new one. Don't rely on `setTimeout` for rate limiting in a stateless Worker.

### H6. Open redirect surface via `redirect` param on login (subtle)
**File:** `worker.js:19-25`, `pages/login.html:73`, `pages/signup.html:66`
**Description:** `validateRedirectUrl` restricts redirect URLs to `https://*.pragmaticdharma.org(/.*)?`. Regex `[a-z0-9-]+` is strict enough (no `@`, no `:`), so straight open-redirect is blocked. However if any sub-domain ever hosts attacker-controlled content or a redirector (e.g. a future Cloudflare Pages preview URL like `pr-123.pages.dev` is *not* covered, but someone could subdomain-hijack `foo.pragmaticdharma.org` via a dangling DNS record), the login form will happily send users there post-auth. Also, the **fragment** portion is stripped by `new URL(...)` in `redirectUrlToProject` but preserved in the raw string used for redirect, enabling `#javascript:alert(1)` no-op but also odd edge cases.
**Fix:** Maintain an explicit allowlist of subdomains (the same `KNOWN_PROJECTS` map you already have at `worker.js:29-38`) and reject any redirect whose hostname isn't in the list. Audit DNS for dangling CNAMEs.

### H7. XSS injection via `name` field on nav bar (server-side)
**File:** `worker.js:60-78`, `shared/nav-bar.html:30-40`
**Description:** `injectPlatformNav` serializes `{name, email, role}` via `JSON.stringify` into an inline `<script>window.__PD_USER=${userData};</script>`. `JSON.stringify` does NOT escape `</script>` — a user with `name = "</script><script>alert(1)</script>"` would break out. The signup endpoint validates `name.length > 100` but not content (`worker.js:193-195`). The nav script does call `name.replace(/</g,'&lt;')` when rendering (`nav-bar.html:35`), but that's after the initial JSON parse, so the XSS fires on the injection, not the render.
**Attack scenario:** Attacker signs up with crafted name, gets approved, logs in — every page they visit with the nav injected (which is every page including `/`, `/resources`, `/admin`, `retreats.pragmaticdharma.org`) executes their XSS. Much worse: if another user *views that user's profile* via a future feature, stored XSS hits them.
**Fix:** At `worker.js:73`, escape `</` in the JSON. Replace `JSON.stringify(userData)` with:
```js
JSON.stringify(userData).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026')
```
Or set a strict CSP with `script-src 'self' 'nonce-...'` (currently there is **no CSP header** — see M2).

## 4. MEDIUM Findings

### M1. Weak rate limiting — Resend/Discord flooding attack
**File:** `worker.js:172-180`, `worker.js:281-287`
**Description:** Global 20 signups/hour is trivially reached by a single attacker, but more importantly: each signup fires a Discord webhook (`worker.js:251`, `worker.js:212`) and (if open_beta is on) can trigger auto-approval emails. No per-IP or per-email limit on signup. Attackers can pre-emptively DoS the 20/hr global cap to lock out real users, or flood Discord with fake signups until you rate-limit yourself.
**Fix:** Add per-IP limit (5/hour) and per-email-domain limit. Use Cloudflare Turnstile on signup form. Consider throttling Discord to 1 notification per minute max (batch).

### M2. No CSP, no Permissions-Policy
**File:** `worker.js:47-54`
**Description:** `HTML_HEADERS` has HSTS, `X-Frame-Options: DENY`, `nosniff`, `referrer-policy`, but **no `Content-Security-Policy`**. Inline scripts (in nav bar, admin.html, login.html, signup.html) would need nonces to migrate, but even a basic `default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'` would protect against external injection.
**Fix:** Add CSP with `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://psychology.pragmaticdharma.org https://health.pragmaticdharma.org; frame-ancestors 'none'; base-uri 'self'`.

### M3. Admin HTML attribute injection in `pending` table
**File:** `pages/admin.html:248-249`
**Description:** `onclick="doAction('approve','" + esc(u.email) + "',this)"` uses the `esc()` helper which only replaces via `textContent`; but when the escaped string is then injected inside a single-quoted JS string inside an HTML attribute, a user with an email like `a'); alert(1); //@b.com` … actually, emails are regex-validated server-side, so literal `'` is blocked. Low real risk but the pattern is fragile.
**Fix:** Use event delegation (store `data-email="..."` which `esc()` does handle correctly and use `addEventListener`) rather than inline `onclick` with concatenated JS strings.

### M4. Access logs retain PII (IP, email, UA) indefinitely
**File:** `schema.sql:48-66`, `worker.js:613-624`
**Description:** `access_logs` stores `user_email`, `ip_address`, `country`, `city`, `region`, `isp`, `user_agent` with no retention policy, no automatic purge. For a users-only platform, this grows unbounded and is a high-value target if D1 is ever compromised. There's also no row-level access (admin read-only is only at the app layer).
**Fix:** Cron job (Workers Cron Trigger) to delete rows older than 30 days. Consider hashing IP addresses if long-term analytics aren't needed. Document data retention in a privacy policy.

### M5. Cookie `SameSite=Lax` instead of `Strict` on shared SSO cookie
**File:** `worker.js:758`
**Description:** The `.pragmaticdharma.org` cookie with `SameSite=Lax` is sent on top-level cross-origin GET navigations. Combined with H1 (no CSRF token), this widens attack surface. For a multi-subdomain SSO, `Lax` is typical, but state-changing endpoints must then be CSRF-defended.
**Fix:** Either (a) add CSRF protection (see H1), or (b) add a second, host-only cookie for admin routes only, with `SameSite=Strict`.

### M6. `/api/refresh-session` only expires 30-day JWT but doesn't re-check user status
**File:** `worker.js:445-486`
**Description:** It re-reads `projects` from DB, but if the user's `status` has flipped to `rejected`, no check is done — the re-issued JWT still grants access. Line 462 reads `status` is not selected. Same for `role` — if an admin was demoted, the refresh endpoint re-signs the old `role` (it reads from `users` so this specific case is fine, but the status check is missing).
**Fix:** At `worker.js:462`, add `status` to the SELECT and return 302 to `/login` if `status !== 'approved'`.

### M7. Discord webhook URL and Resend API key exposure via admin `/api/admin/config`
**File:** `worker.js:627-634`
**Description:** `GET /api/admin/config` returns **all** config values. If someone ever stores a secret in D1 config (currently only `open_beta:*` but nothing prevents future misuse), it will leak to any admin. More concretely, `open_beta` flags across all projects are harmless, but worth a defensive allowlist.
**Fix:** Explicitly filter which keys are admin-readable; whitelist `open_beta*` only.

### M8. `POST /api/admin/config` writes any key/value without schema validation
**File:** `worker.js:636-643`
**Description:** Accepts arbitrary key/value pairs. A compromised admin account or CSRF (see H1) could set arbitrary config that may poison future code paths expecting specific keys.
**Fix:** Add an explicit allowlist of config keys.

### M9. `handleSession` returns PII without re-authenticating freshness
**File:** `worker.js:421-438`
**Description:** Uses only JWT payload (not DB), so returns stale `email`/`name`/`role`. Less a vuln, more of a stale-data issue; but combined with H2, a revoked session will still return a valid `user` object.
**Fix:** Either document that this is cached, or add a `refresh=1` query param to force re-read from DB.

### M10. Signup allows re-signup for rejected users without additional friction
**File:** `worker.js:209-214`
**Description:** If a user is rejected, any subsequent signup request with the same email **silently resets status to pending** and triggers another Discord notification. A rejected user can re-spam admins indefinitely.
**Fix:** After N rejections, block the email permanently (or require admin unblock); limit re-signups to once per week.

## 5. LOW Findings / Nits

- **L1:** `worker.js:619-623` — The `access-logs` query mixes a conditional WHERE with a hardcoded LIMIT param index. The `params.length === 2 ? .bind(p0,p1) : .bind(p0)` branching is fragile. Use `stmt.bind(...params)` spread instead.
- **L2:** `worker.js:270-277` — Generic error on login prevents email enumeration via the happy path, but the rate-limit response at line 286 (`'Too many login attempts'`) only fires for *existing* approved users (because the rate check is after the user lookup), leaking existence. Move the rate check before the user lookup, or always apply it.
- **L3:** `worker.js:321-323` — `token.length !== 64` check is correct for hex-encoded 32 bytes, but doesn't validate the charset. Use `/^[0-9a-f]{64}$/.test(token)`.
- **L4:** `worker.js:787-790` — `generateCode` uses `num % 1000000` which has modulo bias (2^24=16777216, 16777216/1000000 = 16 remainder 777216; codes 000000-777215 are slightly more likely). Fine for this use case but cryptographically cleaner to reject-and-retry.
- **L5:** `worker.js:790` — `padStart(6, '0')` on `num % 1000000` — the resulting string's leading zeros do provide 10^6 uniform across all 6-digit strings once modulo bias is ignored.
- **L6:** `shared/auth-flask.py:67` — `except (json.JSONDecodeError, KeyError, UnicodeDecodeError, Exception)` — `Exception` swallows everything; the earlier types are redundant. Either list specific types or use bare `except Exception`. Also, silently swallowing on auth failure is correct, but log at DEBUG for observability.
- **L7:** `worker.js:986-991` — CORS allows only `https://pragmaticdharma.org`, but admin panel fetches from `health.pragmaticdharma.org` and `psychology.pragmaticdharma.org` in `admin.html:203, 217, 267, 369`. Those sub-projects must set their own CORS. Verify.
- **L8:** `worker.js:655` — `exp: now + 30 * 24 * 60 * 60` — 30-day JWT is long for an SSO cookie. Consider 7 days with sliding refresh via `/api/refresh-session`.
- **L9:** `worker.js:690` — `} catch {` — swallows errors silently. Consider `catch (e) { console.error('JWT verify error:', e.message); }` for operability.
- **L10:** `worker.js:568-571` — `create-user` doesn't notify Discord; `approve` also doesn't. Inconsistent with signup notifications.
- **L11:** `worker.js:209-211` — `UPDATE users SET ... status = 'pending'` on re-signup does not re-issue Discord notification for `approved` users who somehow got re-signed up, but this path is guarded above; fine.
- **L12:** `wrangler.toml` — no `[vars]` block (secrets properly external). Good. No issue.
- **L13:** `schema.sql:83` — Only one default config row. No default `admin` role is bootstrapped; must be set manually via SQL. Document in CLAUDE.md.
- **L14:** `worker.js:17` vs `admin.html:260` — `KNOWN_PROJECTS` duplicated; single source of truth would be good.
- **L15:** `worker.js:498` — `.catch(() => {})` silently swallows logout DB errors. Worth logging.
- **L16:** `pages/admin.html:136` — `data.user.role !== 'admin'` is a client-side check; server enforces it at `worker.js:520` which is fine, but worth noting the UI trust boundary.

## 6. Code Quality & Maintainability

- **Single-file Worker (1007 lines)** is still tractable, with clear section dividers. Good naming, consistent `.bind()` usage. **Approaching the limit** where splitting into `auth.js`, `admin.js`, `email.js` modules would help.
- **JWT logic duplicated** across `worker.js:668-693` and `shared/auth-cloudflare.js:35-71`. Worker doesn't import the shared module — should consolidate to one source.
- **Error handling inconsistent:** some paths return JSON errors, some redirect to HTML error pages (`redirectWithError`), some `.catch(() => {})`. Pick a convention.
- **Magic values:** 30 days, 15 minutes, 20/hour, 3/hour, 1000ms, 5 minutes — extract to `const` block at top.
- **No structured logging:** `console.error` with ad-hoc strings. Consider a `log(level, event, ctx)` helper.
- **`fire-and-forget` Resend & Discord calls** use `.catch(() => {})` silently — you'll never know when delivery is failing.

## 7. Test Coverage Gaps

`test-auth.js` covers the 42 scenarios listed in the header, all testing **JWT-based auth enforcement at the subdomain level**. Missing:

- **No tests for the main Worker's auth flows:** signup, login, verify (code or link), refresh-session, logout.
- **No test for rate limits** (20 signups/hour, 3 magic links/hour).
- **No test for admin authorization** — can a non-admin JWT hit `/api/admin/*`?
- **No test for CSRF** — can cross-origin POSTs to `/api/admin/*` succeed?
- **No test for magic-link single-use** — does a used token get rejected?
- **No test for magic-link expiry** (15 min).
- **No test for the `redirect` param allow-list** — do bad redirects (e.g., `//evil.com`, `https://evil.com`, `https://foo.pragmaticdharma.org.evil.com`) get rejected?
- **No test for session revocation** — does logout actually block the JWT from future use? (Today the answer is "no" — see H2.)
- **No negative test for JWT with `alg: none` or `alg: RS256`** — both should be rejected (they are, but no test asserts it).

## 8. Prioritized Remediation List

1. **Fix H7 (XSS via name in nav bar script injection)** — trivial fix, high impact. Escape `<`/`>`/`&` in the JSON at `worker.js:73`.
2. **Fix H1 (CSRF on admin POSTs)** — add `Origin: https://pragmaticdharma.org` check in `handleAdmin` before processing any POST.
3. **Fix H2 (JWT revocation not checked)** — add `sessions.revoked_at` lookup in `verifyJWT`, bump a `user.token_version` on role/status changes.
4. **Fix H4 (code-path JWT missing sessionToken)** — add `sessionToken` to the payload at `worker.js:402-408` and `worker.js:471-477`.
5. **Fix M6 (refresh-session misses status check)** — add `status` check in `handleRefreshSession`.
6. **Add CSP header (M2)** — baseline policy to prevent future inline injection.
7. **Fix H5 (magic-link code brute force)** — per-email failure counter, invalidate all links after 5 failures.
8. **Fix M1 (per-IP signup rate limit + Turnstile)** — prevent Discord/Resend flooding.
9. **Rework pd CLI (H3)** — use parameterized queries or drop interpolation via python helper.
10. **Consolidate JWT code (M/L)** — make `worker.js` import from `shared/auth-cloudflare.js` to remove duplication.

Also worth: add retention policy on `access_logs` (M4), explicit config-key allowlist (M7/M8), and strengthen test coverage in `test-auth.js` for the main Worker flows.

---

**Claude API usage:** None found in this project (verified via grep on `worker.js`). Cost analysis N/A.
