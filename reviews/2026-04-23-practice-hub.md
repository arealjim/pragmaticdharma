# Practice Hub — Security, Code Quality & Claude-Cost Review

**Date:** 2026-04-23
**Reviewer:** Claude (Opus 4.7, 1M context)
**Repo:** `/home/radmin/workspace/practice-hub`
**Subdomain:** `practice.pragmaticdharma.org`
**Status:** Newly registered with platform (commit `a452bab`). Core CRUD implemented, chat/timeline views still placeholders (Phase 4).

---

## 1. Project Summary

Practice Hub is a cycle-aware life management / tasking app that ties task planning to:
- TCM organ clock (12 two-hour windows, five-element mapping)
- 24 Jie Qi solar terms and sacred days
- Astrological transits (astronomy-engine, client-side)
- Cross-domain context from TCM Tracker, Astrology app, Psychic Shield

**Stack**
- Frontend: Svelte 5 + Vite SPA, deployed to Cloudflare Pages
- Backend (web): Cloudflare Pages Functions (`functions/`) for CRUD + auth middleware
- Backend (Claude): Local Node.js HTTP server on devbox, `server/index.js`, listens on `127.0.0.1:8082`, exposed via cloudflared tunnel at `practice-api.pragmaticdharma.org`
- Auth: JWT SSO via `pragmaticdharma.org` — worker-gate pattern, project key `practice`
- Data: D1 (`practice-hub`, id `45c79b48-48bb-4d3f-8f3e-461b92632eef`) + cross-reads of TCM SQLite + astrology JSON + shield briefings

**Claude usage:** Yes. Four endpoints — `/parse` (haiku), `/schedule` (sonnet), `/chat` (sonnet), `/briefing` (sonnet). Invoked via the `claude -p` CLI on devbox, which uses the **Claude Max subscription** (no per-call API billing).

---

## 2. Findings — Counts by Severity

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High     | 3 |
| Medium   | 6 |
| Low      | 5 |
| Info     | 3 |
| **Total**| **18** |

---

## 3. Critical

### C-1. JWT_SECRET committed to repository in plaintext (two places)

The shared platform-wide JWT signing key is checked into git in two files:

- `wrangler.toml` lines 5-6: `[vars]` block with `JWT_SECRET = "bc61de..."`
- `server/practice-hub.service` line 13: `Environment=JWT_SECRET=bc61de...`

Anyone with read access to this repo (or to any of the sister repos that embed the same approach) obtains the single symmetric key used to **forge arbitrary JWTs for every pragmaticdharma.org service** — psychic-shield, mind-reader, tcm-tracker, ego-assessment, astrology, and the platform itself. With a forged JWT an attacker can:
- impersonate any user (set `sub`, `email`, arbitrary `projects` claim)
- grant themselves admin (`role`)
- bypass every worker-gate and api-gate across the platform

The CLAUDE.md file for this project explicitly documents this as a deliberate workaround for the Cloudflare Pages Functions secrets bug (dashboard-set secrets don't populate `env` when `pages_build_output_dir` is set). That trade-off is platform-wide policy — but it means the git repo **must** be private and its threat model must assume the secret is as sensitive as any compromised prod credential.

**If this repo is pushed to GitHub (even private), it is one leak / mis-configured collaborator / compromised dev machine away from total platform auth compromise.** Consider:

1. Rotating `JWT_SECRET` and moving it out of `wrangler.toml` — the Cloudflare Pages secrets bug can be worked around by using a **Worker** (not a Pages project) or by binding secrets through `wrangler pages secret put` + building with Pages Functions that consume env through `context.env` (test carefully — per CLAUDE.md, plain `[vars]` is the accepted workaround).
2. At minimum: confirm this repo is **devbox-only** (gcrypt backup) and **never** pushed to GitHub in plaintext. Verify `projects.json` in machine-setup for `practice-hub` — it's not currently in the assigned list seen in `~/workspace/CLAUDE.md`, so remote type is undefined. Decide and enforce.
3. Remove `JWT_SECRET` from `server/practice-hub.service` — hardcoding it in a systemd unit file means the secret is **permanently in the git history** even after rotation. Load it from a file (`EnvironmentFile=`) or from a KeePassXC-sourced drop-in that isn't committed.

---

## 4. High

### H-1. Devbox Claude proxy does not check `hasProjectAccess(payload, 'practice')`

`server/index.js` (the devbox proxy behind `practice-api.pragmaticdharma.org`) validates JWT signature and expiry — but never checks `payload.projects.includes('practice')`. Any user holding any valid pragmaticdharma.org JWT (even one whose `projects` claim is `['shield']` or `['health']`) can hit `POST /parse`, `/schedule`, `/chat`, `/briefing` directly, bypassing the Pages middleware gate.

Impact:
- Users without practice access can invoke Claude on devbox — generates Claude Max subscription load, surfaces cross-domain context (TCM mood data, astro data, shield briefings) for the `userId` they pass.
- Crucially, the server uses `payload.sub` as `userId` — so the cross-domain reads are limited to the caller's own data, which is ok. But it still grants feature access to users who haven't been granted `practice`.

**Fix** (`server/index.js`, after line 354):
```js
const projects = payload.projects;
if (Array.isArray(projects) && !projects.includes('practice')) {
  respond(403);
  res.writeHead(403);
  res.end(JSON.stringify({ error: 'No access to practice' }));
  return;
}
```
Note: preserve the platform's backward-compat semantics — if `projects` is absent entirely, grant access (matches `shared/auth-cloudflare.js` `hasProjectAccess`).

### H-2. `userId` interpolated into sqlite3 shell command (defense-in-depth SQL/shell injection risk)

`server/tcm-reader.js` builds its sqlite3 queries by interpolating `userId` into a shell-executed command:
```js
execSync(`sqlite3 "${TCM_DB}" "SELECT data_dir FROM users WHERE id='${userId.replace(/'/g, "''")}' LIMIT 1"`, ...)
```
Similar patterns on lines 44 and 61 of `tcm-reader.js`.

The `.replace(/'/g, "''")` escapes single quotes for SQL, but:
- It does **not** escape shell metacharacters (`"`, `` ` ``, `$`, `\`, `;`, newline) — anything in `userId` that ends the outer double-quoted SQL string can inject shell.
- It does not sanitise the `days` parameter (line 44) — `days` is a function argument passed as `7`, so currently safe, but anyone later wiring a user-controllable value in will have a shell-RCE vector.

Today `userId` is `payload.sub`, which the platform issues as UUID hex — so in practice the surface is closed. But it's one refactor away from a full shell-exec compromise of the devbox.

**Fix:** switch to `child_process.execFileSync('sqlite3', [TCM_DB, query])` passing `query` as a separate arg with `?` placeholders, or shell out to a small helper using `better-sqlite3` (already appropriate since the file is on local disk).

### H-3. No rate limiting / per-user quota on Claude endpoints

`POST /api/chat`, `/chat/parse`, `/chat/schedule`, `/briefing` all forward to the devbox Claude CLI with zero throttling. An authenticated user can script an infinite loop and:
- drive the Claude Max subscription rate-limits to saturation, breaking Claude for all six platform services that share the subscription (mind-reader, astrology, tcm-tracker, ego-assessment, etc.)
- exhaust devbox CPU — each call spawns a `claude` child process with `timeout: 120000` (120s). A dozen concurrent calls would stack.

Since this uses Claude Max (no $ cost), the risk is **service-availability for the whole platform**, not API billing. Still high impact.

**Fix:** simple in-memory sliding-window limiter keyed on `payload.sub`. Start with 20 requests/hour per user, 3 concurrent. Persist to D1 if durability is needed, but for abuse control in-memory is fine.

---

## 5. Medium

### M-1. `chat` endpoint passes full user message history into a single prompt (prompt-injection surface)

`handleChat` in `server/index.js` takes `body.messages` (client-controlled array) and joins up to 20 messages into one flat prompt. Any user can embed prompt-injection strings (`"Ignore previous instructions and …"`) but they are attacking only their own Claude session — **except** that the assembled context includes real TCM mood entries, health goals, and shield briefing data. Injection could surface that data via the response (self-dox) but more importantly could cause the model to emit content that is inserted into timeline entries or task titles (downstream second-order XSS if those entries are later rendered with `{@html}`). Today no such `@html` sink exists (Svelte default escapes), so risk is bounded — but flag for future.

**Fix:** wrap user messages in XML/fence delimiters and instruct Claude to treat them as untrusted input. E.g.:
```
<user-turn>
{{ content }}
</user-turn>
```

### M-2. `handleParse` embeds raw user text into prompt unquoted/unfenced

`functions/api/tasks.js` POST path allows `body.raw` — passed through to `/parse`, where `server/index.js` templates it in as `Input: "${raw}"`. A string containing `"` inside raw closes the Input quote and injects arbitrary prompt content. Low harm (parser returns JSON, not free-form), but the resulting JSON is stored in D1 — attacker-controlled `title`/`description`/`tags` fields. Those eventually render in Svelte (currently safely escaped), so no active exploit — flag for defence-in-depth.

**Fix:** fence user content: ``` Input: <<<INPUT\n${raw}\n>>>INPUT ```.

### M-3. `compute-daily-cycles.js` cron script is a no-op placeholder

`scripts/compute-daily-cycles.js` is documented in CLAUDE.md as run daily at 06:00 via cron, but the body is a TODO stub. If the cron is actually installed on devbox, it just logs and exits. If not installed, no harm. Verify cron state, and if the intent is daily Claude pre-computation, build it with auth + rate-limit awareness before wiring up a cron that will fire N Sonnet calls per active user daily.

### M-4. `preferences.todoist_api_key` stored in plaintext in D1

`schema.sql` line 103 stores a Todoist API key per user in plaintext. If D1 is ever dumped (leaked backup, misconfigured admin endpoint, future `GET /api/admin/preferences`), every user's Todoist key is exposed. Same for `calendar_ics_url` which may contain an iCal secret URL.

**Fix:** encrypt at rest with a server-side key (stored in Cloudflare secret binding, rotated independently of JWT_SECRET), or at minimum isolate these columns and never surface them in `/api/preferences` GET. Currently the GET endpoint happily returns the whole row — so the user can read their own key back in plaintext, and any XSS against the app (none present today) would exfiltrate it.

### M-5. Service worker serves `/index.html` as offline fallback for unauthenticated users

`public/sw.js` caches `/index.html` and falls back to it on any fetch failure. Since auth is enforced server-side by the Pages middleware, an attacker who somehow reaches a cached response won't get API data — but a stale client who lost auth may see the shell UI with no clear sign-in prompt. Minor UX issue, not a security hole.

### M-6. No `_headers` file / no CSP / no security headers

There is no `public/_headers` or `dist/_headers`. The app ships with Cloudflare's defaults only — no `Content-Security-Policy`, no `X-Content-Type-Options: nosniff`, no `Referrer-Policy`, no `Permissions-Policy`. Given that the middleware injects inline `<script>` into HTML responses (for the nav bar user data), a strict CSP would need `'unsafe-inline'` or a nonce — but at minimum add:

```
/*
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  X-Frame-Options: DENY
```

---

## 6. Low

### L-1. Nav-bar injection escapes only `<`, not `&`

`functions/_middleware.js` line 106: `u.name.replace(/</g,'&lt;')` — doesn't escape `&`, `"`, or `>`. Within a text node only `<` and `&` matter; `&` un-escaped could produce odd rendering but isn't a security bug (the name ultimately came from the user's own JWT). Trivial cleanup.

### L-2. Shield briefing is truncated at 500 chars mid-sentence

`server/shield-reader.js` truncates summaries at exactly 500 chars — may mid-word-cut, may mid-JSON if the field happens to be a stringified object. Fine for context injection into Claude (Claude handles partial text well), but consider truncating on a word boundary.

### L-3. CORS `Access-Control-Allow-Origin` hardcoded but also `Allow-Credentials: true`

`server/index.js` sets `Access-Control-Allow-Origin: https://practice.pragmaticdharma.org` together with `Access-Control-Allow-Credentials: true`. Since origin is a fixed single string, this is CORS-compliant. But note: the server actually accepts auth from `X-Proxy-Auth` header (not cookie) — the `credentials: true` declaration is cosmetic. Not a bug, just noise.

### L-4. `handleParse` fallback catches parse errors silently and returns `{ title: raw }`

If Claude returns malformed JSON, the task POST path silently falls back to `title = raw`. This is fine, but the *caller* in `functions/api/tasks.js` has its own fallback that does the same when `res.ok` is false. Result: two overlapping fallbacks, only one of which is ever used. Consolidate.

### L-5. Cloudflare D1 `daily_cycles` table has no automatic retention policy

`daily_cycles` is keyed on `(user_id, date)` and grows unbounded. Schema has no TTL or pruning logic. If generated daily for many users, rows accumulate. D1 is cheap, so this is a monitoring flag rather than a bug — but worth a simple `DELETE WHERE date < date('now', '-180 days')` in a future maintenance script.

---

## 7. Informational

### I-1. Backward-compat path: JWT without `projects` claim grants access everywhere

Middleware and (when H-1 is fixed) the devbox proxy follow the canonical `hasProjectAccess` semantics: **no `projects` claim = full access**. This matches the rest of the platform and is deliberate for old JWT compat. Worth reminding: any user with a pre-per-project JWT (before `projects` gating existed) gets Practice Hub access by default. Rotate / re-issue all sessions to enforce per-project gating platform-wide when convenient.

### I-2. No test suite

There are no unit tests, no auth-enforcement tests, no D1 mocks. The sister project `pragmaticdharma/test-auth.js` pattern would benefit this project — a 7-case matrix (no cookie / expired / missing project / valid / malformed / no-projects-claim / empty-projects) would catch H-1-class bugs automatically. Consider extending `test-auth.js` to include practice-hub once H-1 is fixed.

### I-3. `functions/api/chat.js` duplicates `functions/api/chat/parse.js` and `chat/schedule.js`

Three files (`chat.js`, `chat/parse.js`, `chat/schedule.js`) are near-identical proxy shells differing only in the target path and body shape. Factor to one helper or pick one routing style. Cosmetic.

---

## 8. Claude API Cost Analysis

### 8.1 Model & billing

Practice Hub calls Claude **via the `claude -p` CLI** spawned as a child process. The `claude` binary on devbox is logged into the Claude Max subscription — there is **no per-token API billing**. Cost is accounted in two ways:

1. **Claude Max rate-limit consumption** — shared across all six platform services that use the same CLI login.
2. **Devbox CPU/memory for child processes** — one `node_modules`-free CLI spawn per request, up to 120s timeout.

### 8.2 Volume estimates

| Endpoint | Model | Prompt size | Trigger | Est. freq/user/day |
|----------|-------|-------------|---------|--------------------|
| `/parse` | haiku | ~400 tok    | Each NL task creation | 5-20 |
| `/schedule` | sonnet | ~2-4 KB context + 500 tok instr | Daily briefing or on-demand | 1-3 |
| `/chat` | sonnet | Up to 20 messages of history × avg 200 tok | Each chat turn | 5-50 (Phase 4 not yet live) |
| `/briefing` | sonnet | ~2-4 KB context + 300 tok instr | Daily morning briefing | 1 |

For 1 active user today: ~10-25 Sonnet calls/day + ~10-20 Haiku calls/day — comfortably inside Claude Max limits. For 10 active users with chat live: ~250 Sonnet calls/day — approaches the Claude Max 5-hour rolling window cap if users cluster in the same evening.

### 8.3 Recommendations (Claude Max, not $-billed)

1. **Implement prompt caching for the context block.** `assembleContext(userId)` rebuilds the same TCM/astro/shield context for each call in a burst — if the user hits `/schedule` then `/chat` twice within a minute, that's 3× duplication. Cache assembled context per-user for 5 minutes in-memory (simple Map with TTL). Saves ~40% of the prompt bytes on chat-heavy sessions. *Note: the CLI does not yet support Anthropic prompt-caching breakpoints, but reducing recomputation still helps devbox CPU and cuts per-call tokens.*

2. **Switch `/briefing` from daily-on-demand to scheduled-once-daily with D1 cache.** The `daily_cycles` table (`briefing` column) already exists for exactly this. Compute once at 06:00 via a **real** `compute-daily-cycles.js` cron, store in D1, and serve GET `/api/cycles?date=today` instead of calling Claude every time the user loads the app. Cuts `/briefing` Sonnet calls by ~N× where N is number of page reloads/day.

3. **Truncate `/chat` history.** Currently `messages.slice(-20)` — 20 messages × ~200 tok = 4 KB of conversation added to every chat prompt. Drop to `slice(-6)` or implement summarisation: when history > 10 messages, replace older turns with a 1-sentence "Earlier the user discussed X" summary line (one cheap haiku call, reused for many turns). Cuts per-turn prompt size by ~60% for long sessions.

**Minor extras:**
- Add per-user concurrency limiter (H-3) to prevent a single user saturating Claude Max for all six platform services.
- Log token counts (stdout/stderr parsing of `claude` CLI output) so you can observe actual consumption rather than estimating.
- Consider downgrading `/schedule` from sonnet to haiku — structured JSON output is a task haiku handles well, and the prompt is structured enough that sonnet's reasoning advantage is modest.

---

## 9. Positive Observations

- **D1 usage uses `.bind()` everywhere** — every SQL statement in `functions/api/*.js` uses parameter binding, no string concatenation. Good.
- **UPDATE/DELETE queries include `AND user_id = ?`** on every row-mutation query — no IDOR on `tasks`, `goals`, `projects`, `preferences`.
- **`userId` sourced only from `data.user.sub`** (JWT) — no body/query fallback. Correctly resists the "IDOR via body userId" pattern flagged in sister projects.
- **Middleware is a close clone of canonical `shared/auth-cloudflare.js`** — verifyJWT, parseCookie, hasProjectAccess all match. Minor drift: inline instead of import. Acceptable for a Pages project where `shared/` isn't directly importable, but consider a build-time copy step to prevent divergence.
- **Devbox server binds to `127.0.0.1`** — only reachable via cloudflared tunnel. Good hardening.
- **Soft delete for tasks** (status = 'cancelled') rather than hard DELETE — good for user undo/audit.
- **`hasProjectAccess` includes backward-compat** matching canonical semantics.
- **Refresh-session flow wired correctly** — 302 to `/api/refresh-session` with `pd_refreshed` cookie guard to prevent redirect loops.

---

## 10. Summary & Prioritised Fixes

| Priority | Fix | File | Effort |
|----------|-----|------|--------|
| **P0** | Confirm this repo is devbox-only (not on GitHub plaintext). Consider rotating `JWT_SECRET` and moving it out of the systemd unit file's git history. | policy + `server/practice-hub.service` | low-med |
| **P0** | Add project-access check to devbox proxy | `server/index.js` post-verifyJWT | trivial |
| **P1** | Replace shell `execSync` with `execFile` + sqlite query binding, or switch to `better-sqlite3` | `server/tcm-reader.js` | low |
| **P1** | Per-user rate limit on Claude proxy endpoints | `server/index.js` | low |
| **P2** | Add D1-cached briefing (`daily_cycles.briefing`) + real compute-daily-cycles cron | `scripts/`, `functions/api/briefing.js` | med |
| **P2** | Fence user content in all prompts to mitigate prompt injection | `server/index.js` | trivial |
| **P2** | Encrypt `todoist_api_key` at rest; do not return in GET /preferences | `functions/api/preferences.js`, `schema.sql` | med |
| **P3** | Add `_headers` with CSP/nosniff/referrer-policy | `public/_headers` | trivial |
| **P3** | Extend `test-auth.js` to cover `practice.pragmaticdharma.org` | `pragmaticdharma/test-auth.js` | low |
| **P3** | Slice chat history shorter; cache assembled context; consider haiku for `/schedule` | `server/index.js` | low |

---
*End of report.*
