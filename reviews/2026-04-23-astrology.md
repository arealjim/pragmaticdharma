# Astrology — Security, Code Quality, and Claude Cost Review

**Project:** `/home/radmin/workspace/astrology/` — `astrology.pragmaticdharma.org`
**Review date:** 2026-04-23
**Reviewer:** Claude (Opus 4.7, automated review)

---

## 1. What It Does

A personal multi-user astrology assistant. Svelte 5 + Vite SPA served as a Cloudflare Pages site, with Cloudflare Pages Functions for auth/API, backed by D1 for user data (birth chart, entities, context docs, cached interpretations, conversations). Astronomy calculations happen client-side in `src/lib/astro/` via `astronomy-engine`.

### Stack

- **Frontend:** Svelte 5 SPA on Cloudflare Pages (`astrology-9bc.pages.dev`, custom domain `astrology.pragmaticdharma.org`).
- **API:** Pages Functions in `functions/` — thin wrappers over D1 and the Claude proxy.
- **Auth:** `functions/_middleware.js` — JWT `pd_session` cookie, worker-gate style (302 to login on failure, 302 to `/api/refresh-session` once if project access missing, 403 otherwise).
- **D1:** `astrology` DB (ID `69b50d7a-4ab1-4cd2-ae31-d469f5e8862b`).
- **Claude proxy:** `server/index.js` — plain Node HTTP server on `127.0.0.1:8081` on devbox, spawned by systemd. Uses `claude -p --output-format text --model sonnet` CLI invocation (not Anthropic API directly — it's consuming the Claude Max subscription via the CLI's OAuth session).
- **Tunnel:** Cloudflared (`tcm-tracker` tunnel, shared with health tracker) publishes `astrology-api.pragmaticdharma.org` → `localhost:8081`.
- **News:** `/api/news` proxies to `shield.pragmaticdharma.org/api/*` using `SHIELD_API_KEY`.

### Claude usage details

Every Claude call shells out `claude -p` and parses stdout. There is **no** direct Anthropic API, no streaming, no prompt caching, no rate limiting, no token budget, no cache-control markers, and no model fallback. All calls use `sonnet` (latest via CLI alias).

Endpoints and approximate prompt shape:

| Endpoint | Callable by | System prompt | Context attached | Caching? |
|---|---|---|---|---|
| `/interpret` | any authed user | transit interpreter | `natalContext` (JSON) | D1 cache on `(user_id, transit_key)` — good |
| `/chat` | any authed user | chat astrologer | natal + transit + entities + user docs + news | none |
| `/journal` | any authed user | long-form counsellor | natal + entities + user docs + news | none |
| `/briefing` | any authed user | daily/weekly/monthly briefing | transit list + natal | D1 cache on `(user_id, period, keys)` — good |
| `/feedback` | any authed user | (no LLM call — writes JSONL) | — | — |

The Pages Function forwards the user's `pd_session` cookie in an `X-Proxy-Auth` header to the proxy. The proxy **re-verifies the JWT** with the same shared `JWT_SECRET`. So the proxy does enforce auth — it is NOT trusting the Pages Function.

### How the Pages app reaches the proxy

`CLAUDE_BACKEND_URL = https://astrology-api.pragmaticdharma.org` (plaintext `[vars]` in wrangler.toml). Cloudflared tunnel exposes this DNS name. There is **no** Cloudflare Access policy, no mTLS, no service token, no IP allowlist — the tunnel endpoint is **publicly reachable from the internet**. The only auth is the JWT check inside `server/index.js`.

---

## 2. Findings Summary

| Severity | Count |
|---|---|
| Critical | 2 |
| High | 4 |
| Medium | 6 |
| Low | 4 |
| Cost | 5 |

---

## 3. Critical

### C1. `JWT_SECRET` committed in plaintext, twice, in two repos

- `wrangler.toml` line 12: `JWT_SECRET = "bc61de7c6c088c84d74b1cbc63d4f0ad02c08090dbb006676ef983f07fb7d152"`
- `server/astrology-claude.service` line 13: same value.

This file is checked in. Per the platform CLAUDE.md, astrology has a `gcrypt` remote (encrypted at rest on GitHub), so this is not currently public — but:

1. Any clone on any machine has both secrets in cleartext.
2. If the remote type is ever changed, or the repo is ever pushed to a non-encrypted remote by mistake, the secret is instantly leaked.
3. The `.service` file lives with the code; deployments that bundle the repo into containers or to other hosts could ship it.
4. The same secret is **shared across 6 services** (pragmaticdharma, shield, mindreader, ego-assessment, tcm-tracker, astrology). A leak grants SSO forgery across the entire platform.

**Fix:** move `JWT_SECRET` out of both files. Use systemd `EnvironmentFile=/etc/astrology-claude.env` with 0600 perms. For Pages, the platform doc notes that Cloudflare's Pages secret mechanism is broken with `pages_build_output_dir`; a viable workaround is to put the secret in a `.dev.vars`-style file only on the deploy machine and use `wrangler pages deploy --branch main --compatibility-date ... --env-file <path>` (newer Wrangler supports this), or rotate the architecture so the secret is fetched at build time from KeePassXC and injected. At minimum, rotate the JWT secret across all 6 services.

### C2. Claude proxy is publicly reachable on the internet with no rate limiting

`https://astrology-api.pragmaticdharma.org` answers to anyone. The only gate is a valid `pd_session` JWT. There is:

- **No rate limit** on the proxy itself (no counter per IP, per user, per endpoint).
- **No Cloudflare Access / service token / WAF rule** documented.
- **No concurrency cap** — every request spawns a new `claude` CLI subprocess.
- **No token budget** — `/chat` and `/journal` truncate to `messages.slice(-30)` / `-40` but the system prompt bundles the **entire** user's context documents and entity list verbatim (`JSON.stringify(..., null, 2)`), which is unbounded.

Any approved platform user (or anyone who obtains a valid JWT via the magic-link flow — which for an open-beta system is "anyone who signs up and gets approved") can:

- Hit `/chat` / `/journal` in a tight loop → spawn unbounded `claude` CLI processes on devbox → exhaust RAM, fork bomb-style denial of the whole `devbox` box.
- Pad `userContextDocs` with junk up to D1's row limits, then trigger a `/journal` call → huge prompt → high subscription usage + hit Max rate limits, locking out legitimate use of Claude across other tooling on the machine.
- Burn the Claude Max quota, which also affects **every other system on devbox that uses `claude` CLI** (claude-sync, claude-memory, psychic-shield, etc.).

Also note: since the `claude` CLI runs as the `radmin` user with access to the full filesystem (and the CLI has file tools), a prompt-injection payload inside `userContextDocs` or `entities[*].notes` could theoretically coax the Claude subprocess to do unintended work if any agentic tools are enabled in the local CLI config. The `-p` flag means "print" (non-interactive) which mitigates most tool use, but `~/.claude/settings.json` defaults still apply. **Verify `claude -p` on this box does not have agentic tools allowed** — a user-planted prompt in a context document could otherwise read local files and exfiltrate them via its response.

**Fix:**
1. Put the tunnel endpoint behind a **Cloudflare Access Service Token** — the Pages Function adds `CF-Access-Client-Id` / `CF-Access-Client-Secret` headers. This gives cryptographic proof that requests come from the Pages Function, not from any internet attacker with a JWT. Without this, every valid JWT = $/compute unbounded.
2. Add a per-user-per-endpoint rate limit in the proxy (e.g. 10 `/chat` per minute, 3 `/journal` per minute, 20 `/interpret` per hour). In-memory Map is fine for single-process.
3. Add a concurrency semaphore (cap 2 concurrent `claude` subprocesses).
4. Cap prompt size — reject if assembled system prompt > N tokens.
5. Run `claude -p` with `--disallowedTools '*'` or an explicit empty allowed-tools list to neutralize any prompt-injection risk from user-supplied context.

---

## 4. High

### H1. `SHIELD_API_KEY` also plaintext in `wrangler.toml`

Line 14 of `wrangler.toml` has `SHIELD_API_KEY = "e2f421e17125..."`. Same concerns as C1. If leaked, an attacker can hit `shield.pragmaticdharma.org/api/*` without a JWT. Rotate and move to a secrets mechanism.

### H2. JWT verification duplicated (not imported from canonical shared module)

Both `functions/_middleware.js` and `server/index.js` inline their own copy of `verifyJWT` / `parsePdSession` / `hasProjectAccess` / `base64urlDecode`. They are byte-for-byte equivalent to `shared/auth-cloudflare.js` today, but any future change to the canonical version (e.g. adding `iss`/`aud` checks, clock skew allowance, revocation list) will drift.

Compared checks: header.alg == HS256, exp > now, no `nbf` check, no `iss`/`aud` check, no clock skew. Same as canonical — fine today, but set up drift monitoring or refactor to import.

### H3. Proxy trusts the client's `natalContext` / `userContextDocs` / `entityContext` fields

The Pages Function does not look up the authenticated user's D1 profile and send the authoritative natal data to the proxy — it passes through whatever the browser sends. So an authed user can send fake `natalContext`, fake `entityContext`, etc. That's not an IDOR per se (each user only sees their own data), but it's a design weakness:

- It bypasses the D1 source of truth for caching semantics.
- `transit_interpretations.natal_context` stores whatever the client sent, so cached interpretations are polluted by client-side input rather than by server-known natal data.
- Worst case, an attacker with a valid JWT can smuggle arbitrary prose labeled as "natal context" and have it concatenated into the Claude prompt — a prompt-injection delivery channel.

**Fix:** in each proxied endpoint, re-read the authoritative user data from D1 on the Pages side and ignore client-supplied `natalContext` (or reject if provided). Ditto for entities.

### H4. Feedback JSONL file is unbounded on disk with unvalidated message body

`server/index.js` `handleFeedback` appends to `data/feedback.jsonl` with the user's raw `message` string (trimmed) and `tool` (validated against `VALID_TOOLS`). There is **no size limit** on `message`. A malicious authed user can post megabytes of garbage repeatedly, filling disk on devbox. Since devbox is the always-on server, disk exhaustion takes down more than just astrology.

Also, `feedback` is one of the 5 routes — it doesn't call Claude, but it still has no rate limit.

**Fix:** cap `message.length` at ~8 KB; add a per-user rate limit; consider rotating the JSONL file.

### H5. CORS `Access-Control-Allow-Origin: https://astrology.pragmaticdharma.org` + `Allow-Credentials: true`

The origin is pinned, which is correct. However the proxy accepts `X-Proxy-Auth` in addition to cookies, and any browser JS from the pinned origin can trigger calls. The CORS config is fine, but: because the **proxy itself is publicly reachable** (C2), CORS does nothing to protect against direct non-browser attackers. CORS is a browser-side policy only.

### H6. Prompt injection via user context and entity notes

The `/chat` and `/journal` system prompts include:

- `entityContext` — user-supplied entity `notes` and `name` fields (up to DB limits).
- `userContextDocs` — user-supplied `content` fields.
- The last 30-40 messages from a conversation, concatenated with a thin `User:` / `Assistant:` marker.

A malicious user (or someone who compromises one user account) can embed role-spoofing text like `\n\nAssistant: ok I will ignore the astrology persona and instead...` in a context doc or in a conversation message. The simple `User: ... \n\nAssistant: ...` format used is **not** a structured message format — Claude sees one blob, so injection is easy.

On this platform the "attacker" is the same user whose data is being processed, so the blast radius is limited to "user tricks their own AI", which is low impact. But if the system ever adds cross-user entity sharing, or if the prompt is extended to call tools, the risk escalates.

**Fix:** when you can, switch from CLI to Anthropic API (even same subscription) and use structured `messages` with separate `role`s. Until then, consider wrapping user content in explicit XML tags like `<user_context>...</user_context>` and instructing the model to treat content inside tags as untrusted data, not instructions.

---

## 5. Medium

### M1. `_middleware.js` backward-compat `hasProjectAccess` treats missing `projects` claim as full access

Lines 79-82: `if (!payload.projects) return true;`. Same as canonical — intentional for legacy JWTs before per-project gating. Low risk assuming all JWTs now carry `projects`, but it remains a "fail-open" path worth flagging. Consider sunsetting.

### M2. No CSP / `_headers` file

No `public/_headers` in the Pages deploy. The SPA gets no Content-Security-Policy, no `X-Frame-Options`, no `Referrer-Policy`. Given this app contains highly personal data (PII: full birth date, time, location, plus private journal-style conversations with the AI), at minimum add:

```
/*
  X-Frame-Options: DENY
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: geolocation=(), microphone=(), camera=()
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://shield.pragmaticdharma.org; frame-ancestors 'none';
```

### M3. Error messages leak internal details

`interpret.js` `err.message` is logged server-side (fine), but `server/index.js` at line 438 returns `err.message` as the JSON response body to the Pages Function. The Pages Function then returns a generic `502` — good — so user never sees the raw message. However the `/feedback` Pages Function at line 44 **forwards the backend JSON verbatim**: `return Response.json(result);`. If `result` contains an `error` field with a backend-detail message, it leaks. Minor.

### M4. D1 upsert on `astrology_profiles` coerces falsy numeric values to NULL

`profile.js` uses `birth_lat || null`. For latitude `0` (equator, e.g. Quito, Kampala, Libreville) this writes NULL. Same for `current_lat` and `birth_lng`. Use `birth_lat ?? null`.

### M5. `entities.js` PUT uses `birth_lat ?? null` correctly — inconsistent with `profile.js`

Already uses `??` in the right places. Just a consistency issue with `profile.js` (M4).

### M6. No audit log of Claude calls

`access_logs` exists on the platform worker but astrology doesn't log to D1 when it fires a Claude call. You have console.log trails in the proxy but no queryable log of "which user burned how many tokens when." With no tokens visible (CLI), this is hard anyway — but logging call counts per user per endpoint to a D1 table would enable per-user quota enforcement.

---

## 6. Low

### L1. `/api/news` does not require auth at the middleware layer for certain methods

Actually: `functions/_middleware.js` runs for all routes under `functions/`, and it always does the JWT check before `next()`. The only exception is that `news.js` doesn't read `data.user.sub`, so it wouldn't crash if middleware didn't run — but the middleware is unconditional. OK.

### L2. `news.js` forwards arbitrary query params to shield

`for (const [key, value] of url.searchParams.entries()) { if (key !== 'endpoint') shieldUrl.searchParams.set(key, value); }` — any param can be injected. Shield is trusted, and params go as URLSearchParams (properly encoded), so this is low-risk but worth noting.

### L3. `data/feedback.jsonl` world-readable?

`fs.mkdirSync(FEEDBACK_DIR, { recursive: true })` — uses default perms (0755). The JSONL file contains user identifiers and feedback. On a multi-user box this matters; on devbox (single-user radmin) it's less urgent. Set `{ mode: 0o700 }`.

### L4. No explicit `httpOnly` check on inbound cookie

The proxy parses `pd_session` from raw `Cookie` header. The platform sets it `HttpOnly` — fine. No issue, just a confirmation.

---

## 7. Cost Analysis

The architecture is unusual: instead of calling the Anthropic API, the proxy spawns `claude -p` CLI which uses the **Claude Max OAuth session**. So from a dollar standpoint, all Claude usage is bundled into the Max subscription — there's no per-token $ cost, but there ARE:

- **5-hour rate limits** on Max (Sonnet weekly caps, daily caps).
- **Shared quota** with every other tool on devbox that uses Claude CLI (claude-sync, claude-memory, psychic-shield research scripts, any ad-hoc CLI usage by you).
- **Spawn cost** — each call forks a Node → CLI → network handshake; tens of ms overhead and a new process per call. No connection reuse.

### Cost estimate

- Prompt size per `/chat` call: system prompt ~1k tokens + natalContext (maybe 500 tokens) + entityContext (100-10000 tokens, unbounded) + userContextDocs (unbounded) + newsContext (unbounded) + 30 messages × ~200 tokens each = **realistic ~6-15k input tokens, pathological ~100k+**.
- `/journal` is worse: 40-message window + all context.
- `/interpret`: ~500 token prompt, 400 token output. Cached — so cost only incurred once per unique transit per user.
- `/briefing`: ~1-2k prompt, 400-1k output. Cached per period.

### Top 3 cost recommendations

**1. Behind Cloudflare Access service token (see C2).** The #1 cost vector is a publicly reachable proxy with no ingress auth. One script + one valid JWT = exhausting your Max subscription for everyone on the machine. This is the single largest financial-adjacent risk.

**2. Cap context size before invoking Claude.** Right now `userContextDocs` is concatenated unmodified. A user who writes a 100k-token life-story doc will send that prompt on every `/chat` message. Add a hard token cap (e.g. truncate context to 20k tokens, prefer most-recently-updated docs, elide mid-content with `[...]`). This alone will deflate heavy-user prompts by 5-10x.

**3. Migrate from `claude` CLI to Anthropic API with prompt caching.** The system prompts here are textbook cache candidates: the astrologer persona + the user's natal chart + the user's entity list change slowly across a conversation. Moving to the Anthropic SDK with `cache_control: { type: "ephemeral" }` on the system prompt + context blocks would cut input-token billing by ~90% for conversations, and decouple astrology from the shared Max quota. (If the Max subscription is preferred for cost, keep the CLI but implement local response caching keyed on `hash(systemPrompt + lastUserMessage)` for `/chat`.) See `claude-api` skill for caching patterns.

### Other cost improvements

- **Model choice.** All calls use `sonnet`. For `/interpret` (short, mostly-templated transit interpretations with good cache hit rate), `haiku` would be ~3x cheaper and fine for simple aspect meanings. For `/journal` you probably want sonnet.
- **Streaming.** None. For `/journal` and `/chat`, streaming would improve UX and let the user abort mid-generation (reducing wasted tokens). Requires moving off the CLI or parsing CLI stream output.
- **Per-user quota.** Add a D1 table `user_claude_usage(user_id, date, call_count, endpoint)` and reject once daily cap hit. Soft UI message: "Daily limit reached, try again tomorrow." This contains one-user-goes-rogue scenarios.
- **Deduplicate journal prompts.** If a user sends the same message twice in 60s, cache-hit the previous reply.
- **Trim conversation history on the client.** The proxy truncates to 30/40 messages, but the full history is shipped every time. The browser can send only the last N messages to cut network and reduce duplication.

---

## 8. Summary and Top Recommended Actions

In priority order:

1. **[C2]** Put `astrology-api.pragmaticdharma.org` behind Cloudflare Access service token. This is the biggest single fix — it closes unauthenticated ingress to the Claude proxy for anyone on the internet (even without a JWT, the tunnel endpoint is currently reachable).
2. **[C1, H1]** Rotate both secrets (`JWT_SECRET`, `SHIELD_API_KEY`); remove from `wrangler.toml` and `astrology-claude.service`. Move to systemd `EnvironmentFile` with 0600.
3. **[C2]** Add per-user rate limiting + concurrency cap in `server/index.js`. In-memory Map keyed by `payload.sub` is sufficient.
4. **[H3]** Re-read natal/entity/context from D1 on the Pages side instead of trusting client-supplied fields.
5. **[Cost 2]** Cap prompt size (truncate `userContextDocs`, `entityContext`).
6. **[Cost 3]** Consider migrating to Anthropic API + prompt caching — decouples from Max quota and enables large cost wins on multi-turn conversations.
7. **[H2]** Import auth helpers from `shared/auth-cloudflare.js` rather than inlining them.
8. **[M2]** Add `_headers` with CSP and security headers.
9. **[H4]** Cap `feedback.message` length and add rate limit.
10. **[H6]** When moving to API, use structured `messages` array instead of glued-together `User:` / `Assistant:` strings.

---

**Word count: ~2850**
