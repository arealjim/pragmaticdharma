# AI-Assisted Development Guide for pragmaticdharma.org

Patterns, gotchas, and a security checklist distilled from the Phase 1 security audit (2026-04-23) and Phase 2 platform-wide migration to Cloudflare Workers + Secrets Store (2026-04-24/25). Use this as the standard reference when an AI assistant (or human) is working on any service in this platform.

---

## 1. Platform shape

Every user-facing service is a **Cloudflare Worker** deployed via `wrangler deploy`. There are no Cloudflare Pages projects in production — all five Pages-Functions apps were migrated. Static assets ship via `[assets]` blocks in `wrangler.toml`.

Services and their Worker names:

| Domain | Worker | Type |
|---|---|---|
| `pragmaticdharma.org` | `pragmaticdharma` | Platform: landing + auth + admin |
| `psychology.pragmaticdharma.org` | `ego-assessment-workers` | Ego development assessment |
| `shield.pragmaticdharma.org` | `psychic-shield` | Briefing reader |
| `mindreader.pragmaticdharma.org` | `mind-reader-workers` | On-device biometric SPA |
| `psychtools.pragmaticdharma.org` | `psychtools-workers` | DBT skills practice |
| `astrology.pragmaticdharma.org` | `astrology-workers` | Transit interpreter (frontend) |
| `practice.pragmaticdharma.org` | `practice-workers` | Cycle-aware task management (frontend) |
| `health.pragmaticdharma.org` | `tcm-tracker` (Flask via cloudflared) | Health tracking |

Two services have devbox-side Node proxies for the Claude CLI (`astrology-api.pragmaticdharma.org`, `practice-api.pragmaticdharma.org`) reachable via cloudflared tunnel. They run as systemd units on devbox.

---

## 2. Authentication — every service must follow this pattern

### 2.1 JWT verification

The platform Worker (`pragmaticdharma`) issues JWTs signed with the shared `JWT_SECRET` from the Cloudflare Secrets Store. Sub-services verify the JWT and check that the user's `projects` claim includes their project key.

**Don't reimplement JWT verification in each project.** The canonical implementations are at:
- `pragmaticdharma/shared/auth-cloudflare.js` (Workers / Pages Functions)
- `pragmaticdharma/shared/auth-flask.py` (Python services)

In practice each Worker has its own copy today (the import path doesn't ship across project boundaries). When changing the JWT format (algorithm, claims, key rotation), update the canonical source first, then sync each copy and bump versions in lockstep.

### 2.2 Two auth styles

- **`worker-gate`** (most projects): the middleware redirects unauthenticated requests to `https://pragmaticdharma.org/login` with a `?redirect=` param. Wrong-project JWTs first 302-redirect to `/api/refresh-session` (which re-issues the JWT with fresh project claims from D1), then 403 if access is still denied.
- **`api-gate`** (ego-assessment, health-tracker): every API failure returns 401. Project-denied is treated the same as unauthenticated.

`test-auth.js` in the platform repo encodes the expected status codes for each style. Run it after every auth-touching change.

### 2.3 The `getSecret(env, name)` helper

Every Worker has this helper at `functions/utils/secrets.js` (or inlined for single-file Workers). It is **the only correct way to read a secret in this platform**:

```js
const jwtSecret = await getSecret(env, 'JWT_SECRET');
```

Why: it duck-types the binding. With a Secrets Store binding, `env.JWT_SECRET` is an object whose `.get()` is async. With plain `wrangler secret put` (legacy), `env.JWT_SECRET` is a string. The helper unwraps both forms identically and caches per-request.

**Never write `env.JWT_SECRET` directly.** That breaks the moment a secret is migrated to the Store.

### 2.4 Project claim check on every request

Sub-services must verify the JWT includes their project key:

```js
function hasProjectAccess(payload, project) {
  if (!payload.projects) return true;  // legacy JWT compat
  return Array.isArray(payload.projects) && payload.projects.includes(project);
}
```

The legacy-JWT exception (no `projects` claim → universal access) exists for backward compat with JWTs issued before the claim was introduced. Once all in-flight JWTs have expired (30 days post-rollout), this branch can be tightened.

---

## 3. Secrets — Cloudflare Secrets Store

### 3.1 Store

There is one store for the platform: `pragmaticdharma`, ID `626a023faf5e4be98729d2f4b9849f09`. Inspect it with:

```bash
wrangler secrets-store secret list 626a023faf5e4be98729d2f4b9849f09 --remote
```

### 3.2 Naming conventions

- **Shared across services** — bare names: `JWT_SECRET`, `OWNER_EMAIL`.
- **Service-specific** — prefix with the service name: `EGO_ANTHROPIC_API_KEY`, `PSYCHTOOLS_DISCORD_WEBHOOK_URL`, `ASTROLOGY_SHIELD_API_KEY`.

When binding in `wrangler.toml`, the store entry name and the Worker `binding` name don't have to match:

```toml
[[secrets_store_secrets]]
binding     = "ANTHROPIC_API_KEY"        # how code reads it: env.ANTHROPIC_API_KEY
store_id    = "626a023faf5e4be98729d2f4b9849f09"
secret_name = "EGO_ANTHROPIC_API_KEY"    # store entry
```

This means several services can have a different `secret_name` value but use the same `binding` in their code — `await getSecret(env, 'DISCORD_WEBHOOK_URL')` just works.

### 3.3 Required compatibility_date

⚠️ **Critical gotcha.** Secrets Store bindings only behave correctly with `compatibility_date = "2026-04-01"` (or later) in `wrangler.toml`. With an older date — e.g. `"2024-01-01"` — the Worker runtime treats the binding as a Service Binding (Fetcher), and `env.X.get()` errors with `Failed to execute 'get' on 'Fetcher': parameter 1 is not of type 'string'.` This was the longest-debugged issue of the migration. Always use a recent date.

### 3.4 Adding a new secret

```bash
STORE_ID=626a023faf5e4be98729d2f4b9849f09

# Pipe the value (avoids interactive prompt)
printf '%s' "$VALUE" | wrangler secrets-store secret create "$STORE_ID" \
  --name MY_NEW_SECRET --scopes workers --remote

# Bind it in the Worker's wrangler.toml:
# [[secrets_store_secrets]]
# binding     = "MY_NEW_SECRET"
# store_id    = "626a023faf5e4be98729d2f4b9849f09"
# secret_name = "MY_NEW_SECRET"
```

---

## 4. The `body.userId` / `?userId=` IDOR class — always derive from session

Five separate IDOR vulnerabilities in the Phase 1 audit traced to the same anti-pattern:

```js
// ❌ BAD — anyone can pass any userId
const userId = session?.userId || body.userId || queryUserId;
```

The "fall back for backward compatibility" comment was wrong: it broke auth entirely.

```js
// ✅ GOOD — require session, derive userId only from it
const session = await validateSession(request, env);
if (!session) return new Response(JSON.stringify({error: 'Authentication required'}), {status: 401});
const userId = session.userId;
```

Apply this rule to every endpoint that touches per-user data. There is no scenario where reading a userId from request body or URL is correct.

---

## 5. Endpoints that spend Claude API tokens

Every endpoint that calls the Anthropic API or `claude` CLI **must** include all four of these:

1. **Authentication** — `validateSession()` returns 401 before any spend. (Critical class of bug from the audit: Ego's `/api/deep-analysis` had no auth and accepted any user_id, enabling unauthenticated Opus 4 spend.)
2. **Project-claim check** — even if the JWT is valid, reject if the user lacks the project's claim.
3. **Per-user rate limit** — sliding hourly window backed by D1 or in-memory `Map`. See `astrology/server/index.js` `checkRateLimit` for the canonical pattern.
4. **Concurrency cap** — max N concurrent Claude calls in flight per Worker. See `astrology/server/index.js` `MAX_CONCURRENT_CLAUDE`.

For services that shell out to the `claude` CLI subprocess (devbox proxies, `tcm-tracker`):

5. **Sandbox via bubblewrap** — tcm-tracker's `src/sandbox.py` is the reference. Use `--clearenv` + explicit `--setenv` whitelist (HOME, USER, PATH, LANG, LC_ALL, TERM) so a prompt-injected Claude can't read inherited Flask environment via `/proc/self/environ`. Also `--tmpfs` over secret directories like `/etc/<service>/`.

---

## 6. Pages → Workers migration recipe

Five Pages projects were migrated in Phase 2. The recipe:

1. **Stash WIP**, create branch `workers-migration`.

2. **Add `functions/utils/secrets.js`** with the `getSecret` helper (copy from any existing project).

3. **Refactor every `env.<SECRET>` read** to `await getSecret(env, '<SECRET>')`. Watch for synchronous helper functions (e.g., `checkAdminAuth`) — those need to become async, with `await` added at every call site.

4. **Rewrite `wrangler.toml`** to Workers-native:
   ```toml
   name = "<project>-workers"
   main = "./dist/worker/index.js"        # or dist-worker/index.js for Vite projects
   compatibility_date = "2026-04-01"
   compatibility_flags = ["nodejs_compat"]

   [assets]
   directory = "./"                        # or ./dist for Vite projects
   binding = "ASSETS"
   run_worker_first = true                 # auth/middleware runs before asset delivery

   [[secrets_store_secrets]]               # one block per secret
   ...
   ```

5. **Add `.assetsignore`** at repo root listing every file/dir that lives in the assets root but shouldn't ship to edge: `functions/`, `wrangler.toml`, `package.json`, `node_modules/`, `dist/`, `tests/`, `*.md`, etc.

6. **Update `package.json` scripts**:
   ```json
   "build": "wrangler pages functions build --outdir=./dist/worker/",
   "deploy": "npm run build && wrangler deploy"
   ```
   For Vite projects: chain `vite build && wrangler pages functions build --outdir=./dist-worker/`.

7. **Deploy to `workers.dev` first** to test:
   ```bash
   npx wrangler deploy
   curl https://<name>-workers.jim-8ab.workers.dev/
   ```

8. **Atomic domain switchover**:

   ```bash
   ZONE=2d94f668855a6f2cd56c8b847c2b7c54
   ACCT=8abba65bb724f110903658d7aa4aa030

   # Find the orphan DNS record Pages will leave behind
   DNS_ID=$(curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
     "https://api.cloudflare.com/client/v4/zones/$ZONE/dns_records?name=<host>" \
     | python3 -c "import sys,json; print(json.load(sys.stdin)['result'][0]['id'])")

   # Unbind from Pages
   curl -s -X DELETE -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
     "https://api.cloudflare.com/client/v4/accounts/$ACCT/pages/projects/<old-pages-name>/domains/<host>"

   # IMPORTANT: also delete the DNS record. The Worker bind otherwise refuses
   # with code 100117 ("hostname has externally managed DNS records") even with
   # override_existing_dns_record:true. This wasn't documented anywhere.
   curl -s -X DELETE -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
     "https://api.cloudflare.com/client/v4/zones/$ZONE/dns_records/$DNS_ID"

   # Bind to Worker
   curl -s -X PUT -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d "{\"zone_id\":\"$ZONE\",\"hostname\":\"<host>\",\"service\":\"<worker>\",\"environment\":\"production\"}" \
     "https://api.cloudflare.com/client/v4/accounts/$ACCT/workers/domains"
   ```

   The window between unbind and bind is ~2-3 seconds.

9. **Verify** with `JWT_SECRET=… node ~/workspace/pragmaticdharma/test-auth.js`. Expect 45/45.

10. **Don't delete the old Pages project for 48 hours** — keep it as rollback safety. To roll back: reverse the API calls and re-add the original `ego-assessment.pages.dev` CNAME.

---

## 7. Security review checklist for new services

Before exposing a new service publicly, confirm each item:

### Authentication
- [ ] Verifies `pd_session` JWT against `JWT_SECRET` from Secrets Store
- [ ] Checks `projects` claim includes the service key
- [ ] Has `_middleware.js` (Pages-derived) or `validateSession()` call (api-gate) on every protected route
- [ ] `compatibility_date >= 2026-04-01` in wrangler.toml
- [ ] No `env.X` direct reads of secrets — always `await getSecret(env, 'X')`

### IDOR / authorization
- [ ] No endpoint reads `userId` from request body or query — always from `session.userId`
- [ ] When updating a row owned by a user, the WHERE clause filters by `session.userId`
- [ ] Returned data is filtered to the authenticated user's records (no `is_public` bypass via raw query)

### Claude API spend (if applicable)
- [ ] Auth required before any Claude call
- [ ] Per-user hourly rate limit (D1 or in-memory)
- [ ] Concurrency cap on subprocess spawns
- [ ] `max_tokens` is set to a tight bound (typical output × 2, not the 16K default)
- [ ] Inputs that get embedded into prompts are wrapped in delimiters and the system prompt instructs Claude to treat them as data
- [ ] If using the `claude` CLI: bubblewrap with `--clearenv` + minimal `--setenv` whitelist

### Cookie/session hygiene
- [ ] Session cookies are `Secure; HttpOnly; SameSite=Lax` at minimum
- [ ] `Domain=.pragmaticdharma.org` cookies are CSRF-defended on every state-changing endpoint (Origin/Referer check or CSRF token)
- [ ] JWTs include `sessionToken` claim so revocation works

### Data hygiene
- [ ] `.env`, schema files, source code paths are in `.assetsignore`
- [ ] Logs do not contain secrets, raw JWTs, or unhashed IPs
- [ ] PII tables have a documented retention policy (cron purge)

### Discord webhooks / Resend / Anthropic
- [ ] All API keys live in the Secrets Store
- [ ] Webhook URLs treated as secrets (they grant posting rights)

### CSP / headers
- [ ] CSP set: `default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`
- [ ] HSTS, X-Content-Type-Options, X-Frame-Options=DENY, Referrer-Policy

---

## 8. When to break the rules

These patterns are defaults, not laws. Skip them only with a written justification in the commit message. Common legitimate exceptions:

- **Read-only public endpoints** (e.g. `/api/leaderboard`) may skip auth, but should still rate-limit.
- **Public-facing display endpoints** that don't touch per-user data may skip the IDOR rules.
- **Local-only dev mode** may bypass JWT checks behind a `wrangler dev`-only env flag, but never in production.

If you find yourself adding a `body.userId` fallback "for compatibility," stop and ask why. There's almost never a real reason.

---

## 9. Where to find things

| What | Where |
|---|---|
| Phase 1 security reviews (per project) | `pragmaticdharma/reviews/2026-04-23-*.md` |
| Auth integration tests | `pragmaticdharma/test-auth.js` |
| Secret store ID | `626a023faf5e4be98729d2f4b9849f09` |
| Canonical JWT verifier (JS) | `pragmaticdharma/shared/auth-cloudflare.js` |
| Canonical JWT verifier (Python) | `pragmaticdharma/shared/auth-flask.py` |
| Bubblewrap reference | `tcm-tracker/src/sandbox.py` |
| Rate-limit + concurrency cap reference | `astrology/server/index.js` |
| Active task list (this initiative) | `TaskList` in this Claude session |

---

*Last updated 2026-04-25 after the platform migration to Workers + Secrets Store.*
