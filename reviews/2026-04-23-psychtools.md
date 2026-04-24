# Comprehensive Review — PsychTools (DBT Skills Practice Suite)
*Review date: 2026-04-23 — report-only, no code changes.*

## 1. Project Summary

**psychtools.pragmaticdharma.org** — an interactive DBT (Dialectical Behavior Therapy) skills-practice suite. Plain HTML/CSS/JS (ES modules, no framework, no bundler) deployed to **Cloudflare Pages**. JWT SSO gate via the Pages Functions middleware `functions/_middleware.js` (worker-gate style, `PROJECT_KEY='psychtools'`). Persistence is split:

- **Client-side:** all tool answers/progress saved to `localStorage` under the `pt_` namespace.
- **Server-side:** a single D1-backed endpoint `POST /api/feedback` writes to a `feedback` table and fans out to Discord.

Thirty-four DBT tool modules (chain analysis, DEAR MAN, TIPP, self-soothe, etc.), registered via a central `tool-registry.js` and routed by a hash router (`#/tool-name`).

**Claude API usage:** None. `grep -rn anthropic|claude|api.anthropic` returned zero hits. The tools are purely interactive UI — no LLM calls. **There is no Claude cost surface at all for this project today.**

Platform registration confirmed in `/home/radmin/workspace/pragmaticdharma/worker.js:17` (`KNOWN_PROJECTS`) and `:34` (domain map). Auth style = **worker-gate** (302 to login; if project missing, 302 to `/api/refresh-session` with `pd_refreshed` cookie guard, then 403).

No vendored code from `ego-development-app-api`. The JWT verifier in `_middleware.js` is an independent byte-for-byte copy of the canonical `shared/auth-cloudflare.js`. None of the ego-development CRITICAL/HIGH findings (unauth Claude endpoint, body-userId IDOR, stem-stats poisoning, prompt injection) propagated here — none of those endpoints or surfaces exist in psychtools.

## 2. Executive Summary

- **Safe for public launch? Mostly yes — with two fixes.** One HIGH (secrets committed in plaintext to `wrangler.toml`), one MEDIUM (client-rendered XSS in textarea/inline templates when users paste crafted HTML into their own answers), one MEDIUM (missing D1 `feedback` schema — runtime error), the rest are LOW nits.
- Auth gate is implemented correctly and matches the canonical verifier in `shared/auth-cloudflare.js` (alg pinned to HS256, exp checked, HMAC verified via Web Crypto).
- **No Claude usage** ⇒ no Claude-cost findings. This section of the report is short by design.
- Attack surface is tiny: one authenticated POST endpoint (`/api/feedback`), one D1 binding, one Discord webhook.
- PII sensitivity note: while this app does not send DBT worksheet content to any server, a future feature that does would be handling **high-sensitivity mental-health data** (suicide-risk context, trauma content). Current architecture is correctly zero-trust server-side — keep it that way.

## 3. Findings by Severity

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 4 |
| LOW | 7 |

## 4. HIGH Findings

### H1. JWT_SECRET and Discord webhook committed in `wrangler.toml` [vars]
**Severity:** HIGH (secret exposure)
**File:** `wrangler.toml:8-9`

```toml
[vars]
JWT_SECRET = "bc61de7c6c088c84d74b1cbc63d4f0ad02c08090dbb006676ef983f07fb7d152"
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1477399837807738965/F-EEBO8DuRtRj72yOx_7d21t4-eyiRnfagyc695ZpBbdctOSM_QgMUwSJzNn5wR2QM8d"
```

This is a *known Cloudflare-Pages tooling bug* documented in the workspace CLAUDE.md ("wrangler pages secret put does not surface in Functions env when `pages_build_output_dir` is set"), so putting these values in `[vars]` is the documented workaround. **However:**

1. `JWT_SECRET` is the **platform-wide shared HMAC key** used by all 6 services (pragmaticdharma, psychic-shield, ego-assessment, mind-reader, tcm-tracker, astrology). Per `/home/radmin/workspace/pragmaticdharma/CLAUDE.md`, it's stored in `~/workspace/credentials.kdbx`. Committing it to a repo — even if the repo is `gcrypt`-encrypted at rest on GitHub — means any developer checkout (including backups, rsync, laptop steals, git worktrees) exposes the ability to **forge JWTs for the entire platform**. An attacker with this secret can mint a token with `projects: ["shield","health","mindreader","ego-assessment","astrology","psychtools"]` and `role: "admin"` and access every sub-project.
2. `DISCORD_WEBHOOK_URL` is lower severity but also sensitive — it permits posting arbitrary messages into the ops Discord channel.
3. The same pattern appears elsewhere (per ego-development review) — this is a platform-hygiene issue, not just psychtools-specific.
4. `_routes.json` does list `/wrangler.toml` under `exclude`, so the file is not served to visitors of the deployed site. The leak path is the **repo contents**, not HTTP fetch.

**Fix options:**
- Move secrets into Cloudflare Pages project settings via the dashboard (set as "environment variables" — the dashboard form does inject them into Functions env reliably; the documented bug is specifically with `wrangler pages secret put`). Confirm with a local `console.log(Object.keys(env))` check during `wrangler pages dev` or at a deployed debug endpoint.
- Or keep the `[vars]` workaround but exclude `wrangler.toml` from git (`.gitignore`) and ship a `wrangler.example.toml` template; rotate the leaked `JWT_SECRET` across all 6 services once a safe distribution channel exists.
- **Rotate `JWT_SECRET` immediately if the repo has ever been on a public remote.** (`projects.json` lists psychtools under `devbox` — bare repo only — so exposure is limited to local fleet machines + gcrypt backup, but any machine compromise = platform compromise.)

This finding applies equally to every sub-project that uses the `[vars]` workaround. Fix once, platform-wide.

## 5. MEDIUM Findings

### M1. Stored-value XSS via user-typed textarea content reflected through `innerHTML`
**Severity:** MEDIUM (self-XSS / stored on device)
**Files:** `js/ui.js:301, 416, 485`; and inline per-tool templates (`validation-guide.js:64`, `check-the-facts.js:34`, `chain-analysis.js` via `textareaGroup`, etc.)

User input is persisted to localStorage and on subsequent renders is interpolated directly into HTML template literals:

```js
// ui.js:485 (textareaGroup)
<textarea class="form-textarea" rows="3">${data[key] || ''}</textarea>

// ui.js:301 (renderFourSquare)
<textarea ... placeholder="${cell.placeholder || '…'}">${data[`cell${i}`] || ''}</textarea>

// ui.js:416 (renderMythChallenger)
<textarea ... rows="2" placeholder="…">${data[`r${i}`] || ''}</textarea>
```

If a user types `</textarea><img src=x onerror=alert(1)>` into any tool, the string is JSON-serialized into `localStorage.pt_<toolId>`, and on the next render of the same tool the closing `</textarea>` tag in the stored string terminates the HTML textarea element, then the `<img onerror>` fires. This is a **classic template-string XSS into textarea content** — the `</textarea>` escape does work because text-mode parsing is terminated by a case-insensitive `</textarea`.

**Impact (realistic):**
- **Self-XSS only today.** No server-side storage of textarea content, no cross-user sharing, no admin dashboard that renders it. An attacker who can already run JS in the victim's browser can already read localStorage, so self-XSS is not a credential escalation.
- **But:** the platform nav bar injected by `_middleware.js` sets `window.__PD_USER` (`_middleware.js:135`) with the user's **name, email, role**. A self-XSS payload could exfiltrate that data — not directly the JWT (it's HttpOnly and on `.pragmaticdharma.org`), but PII about who the victim is.
- **More importantly:** future features almost certainly will ship DBT content server-side (e.g., sharing worksheets with a therapist, or syncing across devices via the platform D1). The moment a second user can view another user's stored data, this becomes stored cross-user XSS.
- `_headers` has NO CSP (`/home/radmin/workspace/psychtools/_headers` only sets `X-Content-Type-Options`, `X-Frame-Options`, legacy `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`). No `Content-Security-Policy` header exists to constrain inline script execution or `img onerror` network callbacks.

**Fix:**
- Replace HTML-template interpolation of user input with `textContent` / DOM `value` assignment (textareas have `.value`; use it for data, use innerHTML only for the skeleton).
- Pattern: build the empty template with `innerHTML`, then `container.querySelector('textarea').value = data[key] || '';`.
- Add a `Content-Security-Policy` header to `_headers`: `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://pragmaticdharma.org; frame-ancestors 'none'; base-uri 'self'`. (Note: the nav bar injection uses inline `<script>` and inline `<style>` via `_middleware.js:88-125`, so `'unsafe-inline'` is currently required; ideally move the nav bar to an external asset so CSP can drop `'unsafe-inline'`.)

### M2. Missing D1 schema — `/api/feedback` POST will throw on first call
**Severity:** MEDIUM (functionality / error-handling)
**File:** `functions/api/feedback.js:45-53`, repo root

```js
await env.DB.prepare(
  'INSERT INTO feedback (tool_id, tool_name, feedback, errors, url) VALUES (?, ?, ?, ?, ?)'
).bind(...).run();
```

There is **no `schema.sql`, no `migrations/` folder, no seed script** anywhere in the repo. `wrangler.toml:11-14` binds D1 database `psychtools` (id `9538b0a7-b3a3-4353-af3b-6dc6a7a6a0d7`) but the `feedback` table schema is neither defined in source nor documented. Unless the table was created out-of-band via `wrangler d1 execute --command`, every feedback submission will fail with a SQL error — and the code currently responds **after** attempting both the D1 INSERT and the Discord post, so the 500 path leaks `Internal error` and Discord may or may not have been called.

**Fix:** Add `schema.sql` at repo root with `CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, tool_id TEXT, tool_name TEXT, feedback TEXT, errors TEXT, url TEXT, created_at TEXT DEFAULT (datetime('now')));` and a `npm run db:migrate` script matching the pattern in pragmaticdharma. Apply to the remote D1.

### M3. JWT verification reimplemented locally instead of importing `shared/auth-cloudflare.js`
**Severity:** MEDIUM (drift / maintenance)
**File:** `functions/_middleware.js:39-77` vs `/home/radmin/workspace/pragmaticdharma/shared/auth-cloudflare.js:35-96`

Byte-for-byte identical today (I diffed `parsePdSession`, `verifyJWT`, `base64urlDecode`, `hasProjectAccess`). But the shared module is explicitly marked "canonical — shared across pragmaticdharma.org" and `M-new-1` in the ego-development review flagged the same drift risk there. If pragmaticdharma adds `iss`/`aud` claim checks, algorithm allow-list tightening, or key rotation logic, every sub-project with a private copy falls out of sync silently.

**Fix:** Import from `shared/auth-cloudflare.js` as a vendored copy checked in under `functions/_shared/`, or publish the shared module as a package and `import` it. Same recommendation as for ego-development and psychic-shield.

### M4. `/api/feedback` leaks internal errors in 500 response
**Severity:** MEDIUM (information disclosure — minor)
**File:** `functions/api/feedback.js:73-79`

```js
} catch (err) {
  console.error('Feedback handler error:', err);
  return new Response(JSON.stringify({ error: 'Internal error' }), {
    status: 500, ...
  });
}
```

The JSON response is generic (good), but at `:62-66` a Discord-webhook failure returns `{ error: 'Failed to send feedback' }` with the Discord status code and body text logged server-side. No user impact, but the server-side log retains the webhook response body which could contain Discord-internal error details. Minor.

**Fix:** Strip status and body from logs; log only that the call failed.

## 6. LOW Findings / nits

- **L1.** `_headers` sets `X-XSS-Protection: 1; mode=block`. This header is deprecated and can introduce vulnerabilities in older browsers. Modern guidance: `X-XSS-Protection: 0` paired with a real CSP. Same as ego-development `L-new-3`.
- **L2.** `_headers` lacks CSP entirely. See M1 fix.
- **L3.** `_headers` lacks `Strict-Transport-Security`. Cloudflare applies edge HSTS for `pragmaticdharma.org` if enabled at zone level, but explicit `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` in `_headers` is belt-and-braces.
- **L4.** `DBT-manual.pdf` (4 MB) is in the repo root and correctly excluded by `_routes.json:4`. Consider moving to `/docs/` or `.gitignore` with a note — bulky asset in git history. CLAUDE.md already says "DBT manual is reference only, never copy"; the file doesn't need to be deployed.
- **L5.** `feedback.js` has no rate limiting. An authenticated user could script the submission of thousands of feedback rows / Discord messages. Cost = 1 Discord webhook + 1 D1 write per call; not cheap at scale. Add a per-user / per-IP rate limit (e.g. 10/hour) — the platform's `access_logs` could be consulted, or use a simple D1 row-per-user counter. Feedback submissions are low-volume by nature so rate-limit budget can be tight.
- **L6.** `feedback.js:24` truncates feedback text to 1024 chars for Discord, but the **D1 insert stores the full untruncated string** (`:50` passes `feedback.trim()` without a length cap). With no max length on the textarea client-side, a single POST could insert MBs. Add a server-side cap (e.g. 10,000 chars) before the D1 insert.
- **L7.** `router.js:102` renders `toolId` (from `location.hash`) into HTML: `<p>The tool "${toolId}" doesn't exist yet.</p>`. This is DOM-based XSS via URL fragment — `#/%3Cimg%20src=x%20onerror=alert(1)%3E` would load. Impact: same as M1 (self-XSS) but triggered by a malicious link rather than stored data. Wrap in `textContent` or escape. Low because no cookies/data are reachable without existing account compromise.

## 7. Code Quality & Maintainability

Generally strong. The architecture is clean and deliberate:

- Central `tool-registry.js` keeps tool metadata uniform.
- Reusable UI patterns in `ui.js` (wizard, questionnaire, guided practice, four-square, tabs, checklist, myth-challenger, slider, textarea) — good reuse across 34 tools.
- localStorage abstraction in `storage.js` is small, defensive (try/catch on quota errors), and correctly namespaced with `pt_`.
- Tests exist (`tests/test-tools.js`, `tests/test-ui-patterns.js`) totaling ~52 KB — well-above-average for the pragmaticdharma fleet.
- Middleware is small (195 lines), single-purpose, and matches the shared auth contract.
- Feedback endpoint is simple and correctly uses `.bind()` prepared statements (no SQL injection path).

Minor nits:
- **Router XSS (L7).** Fix when touching `renderTool`.
- **UI patterns use HTML template strings heavily.** This is the root cause of M1 and L7. A minor refactor to build DOM via `document.createElement` for user-data-bearing elements would eliminate the class.
- **Duplication in tool-level renders.** `self-soothe.js`, `improve-moment.js`, `mindfulness-what.js`, `mindfulness-how.js` all reimplement similar multi-panel layouts with `panel.innerHTML = \`<div class="card">…\``. Consider extracting a `renderPanelGrid()` helper alongside `renderTabs`.
- **CLAUDE.md** is accurate and current. Well-maintained.

## 8. Platform Integration

- **Registered correctly** in `pragmaticdharma/worker.js:17, 34`.
- Middleware redirects to `pragmaticdharma.org/login` on no-cookie and to `/api/refresh-session` on missing-project (with single-attempt `pd_refreshed` cookie guard). This matches the canonical pattern and is aligned with `mind-reader`'s flow.
- **Platform nav bar injection** is correctly done (`_middleware.js:127-138`) — HTML content-type check guards against binary corruption; user-data is JSON.stringified for safe script embedding (though `name.replace(/</g,'&lt;')` in the nav script is incomplete — doesn't escape quotes, so a name containing `"><script>` could break out of the outer `<span>`. Minor; same issue exists in other sub-projects' nav bars; likely a platform-shared template to fix once).
- **No access-log wiring.** Per `worker.js:613`, platform access logs pull from the `access_logs` table, which is populated by the main pragmaticdharma worker during SSO issuance, not by each sub-project. psychtools doesn't (and shouldn't) log to this table itself. Just noting that per-tool telemetry doesn't surface to `./pd logs psychtools` — all you'll see is auth events.

## 9. Threat-Model Mapping

| Threat | Finding | Status |
|---|---|---|
| Auth bypass | JWT verifier matches canonical (`shared/auth-cloudflare.js`). Middleware fires on all paths. | **Controlled** |
| IDOR | No endpoint accepts `userId` from query/body. Feedback endpoint is anonymous w.r.t. user (doesn't record `user_email` — see note below). | **Not present** |
| Claude cost abuse | No Claude API integration exists. | **N/A** |
| Prompt injection | No LLM involvement. Any future Claude integration must gate on session + use XML-tagged user content (see ego-development `H-new-2`). | **N/A today** |
| SQL injection | Only 1 query; uses `.bind()` prepared statement. | **Controlled** |
| XSS | Self-XSS via stored localStorage content (M1, L7). | **Present — fixable** |
| CSRF | `/api/feedback` requires `Content-Type: application/json`, which requires a preflight and SameSite=Lax cookie. JWT cookie SameSite not verified here but set by parent worker. | **Mitigated** |
| Admin gating | No admin endpoints exist in psychtools. | **N/A** |
| Rate limiting | None (L5). Low-value abuse target. | **Missing — LOW** |
| PII handling | DBT worksheet content (potentially trauma/suicide-related) stays 100% on-device in localStorage. No server-side PII beyond the JWT payload surfaced into `window.__PD_USER` on page load. | **Good** |
| Secrets in repo | `JWT_SECRET`, `DISCORD_WEBHOOK_URL` in `[vars]` (H1). | **Present — HIGH** |

Feedback note: `/api/feedback` does **not** attach the authenticated user's email/user_id to the stored row or Discord message. That's deliberate for privacy (good) but means admins can't triage an issue back to a user. If that's intentional (feedback is meant anonymous), leave it. If unintended, pull `email` from `payload` in a new middleware wrapper — but a consent notice should accompany the change since users are submitting mental-health context.

## 10. Claude API Cost Analysis

**Not applicable.** psychtools does not call Claude or any LLM. No prompts, no `anthropic` SDK import, no fetch to `api.anthropic.com`, no model identifier strings anywhere in the codebase.

If Claude is added in the future (e.g., a "reflect on my chain analysis" feature), baseline recommendations:

1. **Use Haiku 3.5 or Sonnet 4, not Opus.** DBT reflection/summary is summarization-shaped, not frontier-reasoning-shaped. Opus cost is ~5× Sonnet for marginal quality on this task class.
2. **Enable prompt caching on any static system prompt.** The DBT framework prompt will be static across all users — cache it with `cache_control: {"type":"ephemeral"}`.
3. **Hard per-user daily rate limit on any endpoint that calls Claude.** Assessment-style endpoints on the platform (ego-development `/api/deep-analysis`) previously had abuse patterns — learn from that: always require session, always cap per-user-per-day, always cap `max_tokens` tight to expected output.
4. **Validate model output against a schema.** DBT responses flowing back to the user must not include direct clinical advice; a schema-check + regex filter at minimum.
5. **Wrap user-supplied response text in XML tags with a nonce** to mitigate prompt injection (same as recommended for ego-development `H-new-2`).

Top 3 cost recs (hypothetical, since no Claude today):
1. **Default model = Haiku 3.5** for any reflection/summary feature (~10× cheaper than Opus, 3× cheaper than Sonnet on input).
2. **Prompt caching on the DBT framework system prompt** — cached reads are 10% of base input cost once the system prompt is >1024 tokens.
3. **Per-user daily cap** + `max_tokens` ≤ 2048 on any generative endpoint; never allow unauth Claude calls.

## 11. Prioritized Remediation List

1. **H1 — Remove `JWT_SECRET` and `DISCORD_WEBHOOK_URL` from committed `wrangler.toml`.** Move to Pages project-env via dashboard. **Rotate `JWT_SECRET` platform-wide if this repo was ever on a public remote.** (Likely not — devbox-only per `projects.json` — but verify.)
2. **M2 — Add `schema.sql` for the `feedback` table and apply to the remote D1.** Without this, the endpoint is silently broken.
3. **M1 / L7 — Escape user-typed content and URL-hash content before HTML interpolation.** Refactor `textareaGroup`, `renderFourSquare`, `renderMythChallenger`, `renderTool` fallback path to use `textContent` or `textarea.value`, not template strings. Add CSP to `_headers`.
4. **M3 — Replace the local JWT-verification copy with an import from `shared/auth-cloudflare.js`** (vendored under `functions/_shared/` for Pages Functions). Platform-wide recommendation.
5. **L5 / L6 — Add server-side length cap (≤10k chars) and per-user rate limit (≤10/hr) on `/api/feedback`.**
6. **L1 — Drop `X-XSS-Protection` or set to `0`; replace with real CSP.**
7. **M4 — Tighten error logging on Discord-webhook-fail path.**
8. **L4 — Move `DBT-manual.pdf` out of the deployed tree; consider `.gitignore`.**

## 12. Bottom Line

psychtools is a **small, clean, low-risk** deployment. The attack surface is mostly client-side (localStorage), the one server endpoint is simple and auth-gated, and there is no Claude/LLM cost exposure today. The single HIGH finding is a platform-wide hygiene issue (`JWT_SECRET` in `[vars]`) that applies equally to sibling projects and is the most impactful fix to make. The MEDIUM XSS items are fixable with a small refactor to the 3 affected UI helpers. No critical issues, no IDOR, no prompt injection, no Claude abuse vector — a nice delta from the ego-development review.

Given the high sensitivity of the domain (DBT is used by people in crisis, per the app's own 988 footer), I'd especially encourage the CSP hardening and the `textContent` refactor before any feature lands that sends worksheet content to a server, even for a single user's own cross-device sync.
