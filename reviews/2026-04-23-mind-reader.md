# Security + Code Quality + Claude API Cost Review — mind-reader

**Date:** 2026-04-23
**Reviewer:** Claude (Opus 4.7, 1M ctx)
**Scope:** `/home/radmin/workspace/mind-reader` at HEAD (deploy commit Feb 28, latest tile edit Mar 15)
**Live:** https://mindreader.pragmaticdharma.org (Cloudflare Pages)

---

## Executive Summary

Mind Reader is a **browser-based biometric sensor platform** — Svelte 5 + Vite SPA deployed to Cloudflare Pages. It runs 51+ sensors (face/pose/hand landmarks via MediaPipe, audio via AnalyserNode, browser behavior) entirely **client-side**. A Cloudflare Pages Function (`functions/_middleware.js`) gates access with a JWT cookie (`pd_session`) and injects a platform nav bar. An embed mode (`?embed=1`) streams sensor data to a parent iframe (psychology.pragmaticdharma.org) via `postMessage`.

**Claude API usage: NONE.** All inference is client-side via MediaPipe TFLite models. There is no outbound Claude/Anthropic call anywhere in source, functions, or dependencies (`@anthropic-ai/sdk` is not in `package.json`). This review therefore covers the **cost section as "N/A with hardening guidance"** and focuses on the auth gate, embed contract, secrets hygiene, and code quality.

### Findings by severity

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High     | 3 |
| Medium   | 5 |
| Low      | 4 |
| **Total**| **13** |

### Most important finding

**JWT_SECRET is committed in plaintext to `wrangler.toml`** (line 8), a file tracked in git. Although the git remote is gcrypt-encrypted (reducing external exposure), the secret is also the **shared HMAC signing key for all 6 platform services** (pragmaticdharma, psychic-shield, ego-assessment, mind-reader, tcm-tracker, astrology). Any disclosure — backup leakage, a future un-encrypted remote, filesystem compromise of any dev machine, CI logs — lets an attacker forge a valid `pd_session` cookie for **every subdomain, every user, including admin**. This is the same finding flagged in the ego-assessment review and is a systemic platform-level exposure.

---

## Critical

### C1 — JWT_SECRET committed to wrangler.toml (shared across 6 services)

- **File:** `wrangler.toml:8`
- **Evidence:**
  ```toml
  [vars]
  JWT_SECRET = "bc61de7c6c088c84d74b1cbc63d4f0ad02c08090dbb006676ef983f07fb7d152"
  ```
- **Description:** The shared JWT signing key is in a `[vars]` block in `wrangler.toml`, which is tracked by git and deployed as a plain environment variable to Cloudflare Pages. The comment in the file even acknowledges this is a workaround for a known Cloudflare Pages bug where secrets set via `wrangler pages secret put` do not appear in Functions runtime env when `pages_build_output_dir` is set (documented in platform CLAUDE.md). The workaround is technically correct for functionality, but keeping the secret in a tracked file is not required — a local untracked `wrangler.toml` with `.gitignore` entry, or build-time substitution, is both possible and safer.
- **Attack scenario:** Any of these exposures leaks the key:
  1. A future `git push` to a non-gcrypt remote (mirror, fork, CI cache).
  2. A developer's laptop compromise reveals `~/workspace/mind-reader/wrangler.toml`.
  3. A Cloudflare Pages build log or deployment dashboard snapshot.
  4. The gcrypt passphrase itself leaks.
  With the key, an attacker forges `pd_session = eyJ...` JWTs with `{sub: admin-user-id, projects: ["*"], exp: <far future>}`, then hits `pragmaticdharma.org/admin/*` to approve attacker accounts, read user PII (names, emails, signup notes), or pivot to `health.pragmaticdharma.org` where TCM health records live.
- **Fix (ordered):**
  1. **Rotate `JWT_SECRET`** across all 6 services immediately (keepassxc → `wrangler secret put JWT_SECRET` on the platform worker; for Pages projects, fix the Cloudflare bug per step 2 first).
  2. Evaluate Cloudflare's updated Pages/Functions secret handling — the `pages_build_output_dir` bug may be fixed by 2026. Test `wrangler pages secret put JWT_SECRET` + remove `[vars]`.
  3. If the bug persists, move the secret to a **build-time injection** pattern: read from `process.env.JWT_SECRET` at build (via `vite define`) or a Cloudflare Worker-style binding migration.
  4. Add `wrangler.toml` to `.gitignore` and commit a sanitized `wrangler.example.toml` instead.
  5. All commits that touched the `JWT_SECRET` line are now compromised; key rotation (step 1) is the only mitigation since git history can't be scrubbed retroactively.

---

## High

### H1 — JWT verification duplicated instead of imported from shared module

- **File:** `functions/_middleware.js:20-82`
- **Description:** The middleware re-implements `parsePdSession`, `parseCookie`, `base64urlDecode`, `verifyJWT`, and `hasProjectAccess` inline, rather than importing them from `/home/radmin/workspace/pragmaticdharma/shared/auth-cloudflare.js`. Byte-comparison: the logic is functionally equivalent (same HS256 check, same exp check, same backward-compat `projects` handling). Drift risk is real: the shared module exposes `getSessionFromRequest(request, env)` which guards against missing `env.JWT_SECRET` by returning `null` early; the middleware's `verifyJWT(token, env.JWT_SECRET)` would pass `undefined` to `crypto.subtle.importKey` and throw, which the outer try-catch swallows into a login redirect. Functionally OK, but if the shared module ever gets a security fix (e.g., constant-time comparison, algorithm allow-list, additional claim validation) this copy will NOT receive it.
- **Attack scenario:** A future bug is found in `verifyJWT` (say, an algorithm confusion — attacker crafts `{alg:"none"}`). The shared module is patched; mind-reader's copy is missed in the sweep and remains vulnerable for weeks.
- **Fix:** Import from shared. For Pages Functions, symlinks don't deploy — copy the file into the repo at build time (e.g., a `prebuild` script: `cp ../pragmaticdharma/shared/auth-cloudflare.js functions/_auth.js`) OR publish the shared module to an internal npm package and depend on it. If inlining must stay, add a unit test that asserts byte-equivalence of the two files.

### H2 — postMessage `targetOrigin: '*'` leaks sensor data to any parent frame

- **File:** `src/lib/embed/message-handler.js:49`
- **Evidence:**
  ```js
  window.parent.postMessage({ type, version, source: 'mindreader', timestamp, payload }, '*')
  ```
- **Description:** Inbound messages are origin-checked (`VALID_ORIGIN_PATTERN = /(?:^|\.)pragmaticdharma\.org$/`), but outbound `postMessage` uses wildcard `'*'`. If mind-reader is ever embedded in a hostile or even legitimate-but-untrusted iframe (misconfig, referrer spoof after a redirect, a future CSP `frame-ancestors` loosening), every 1-second sensor update — heart rate, stress index, voice stress, emotion labels, cognitive load — gets delivered to the malicious parent. This is PII-grade biometric data.
- **Attack scenario:** Attacker tricks a user into clicking `https://evil.example/embed.html` where `evil.example` iframes `https://mindreader.pragmaticdharma.org/?embed=1` with spoofed CSP bypass. Mind Reader's middleware already restricts `frame-ancestors` to psychology.pragmaticdharma.org + ego-assessment.pages.dev (good!), but the `postMessage '*'` is belt-and-suspenders that's been unbuckled. If the CSP is ever widened, data exfiltrates.
- **Fix:** Track the validated parent origin from the first incoming `mr:init` and use it as `targetOrigin`:
  ```js
  let validatedParentOrigin = null
  // in handleMessage: validatedParentOrigin = event.origin (after VALID_ORIGIN_PATTERN check)
  // in postToParent: window.parent.postMessage({...}, validatedParentOrigin ?? 'https://psychology.pragmaticdharma.org')
  ```

### H3 — 2-second auto-init enables camera without explicit parent handshake

- **File:** `src/components/phases/EmbedPhase.svelte:154`
- **Evidence:**
  ```js
  // Auto-init with defaults after 2s if no mr:init received
  initTimeout = setTimeout(() => initialize({}), 2000)
  ```
- **Description:** In embed mode, the app auto-requests camera permission 2s after mount if no `mr:init` message arrives. This is a UX convenience but couples consent to the mere act of being iframed — the parent never has to ask for camera intent. Combined with H2, if an unvetted parent ever loads this iframe, the user may see a camera prompt they didn't expect (harder phishing vector).
- **Attack scenario:** User is already on `psychology.pragmaticdharma.org` mid-assessment. A cross-site-timing or navigation attack causes mind-reader to be reloaded in a tab where the user doesn't expect it; 2 seconds later they get a camera prompt. Low-exploit, but violates principle of explicit consent.
- **Fix:** Remove the auto-init; require `mr:init` from the parent. Parents must explicitly declare intent. If a "ready without explicit init" path is needed for a non-assessment embed, add a URL param like `?autoinit=1` and document it.

---

## Medium

### M1 — Nav-bar user display builds HTML via innerHTML from JWT payload

- **File:** `functions/_middleware.js:118`
- **Evidence:**
  ```js
  el.innerHTML = '<span>' + u.name.replace(/</g,'&lt;') + '</span>...'
  ```
- **Description:** The user name is pulled from `window.__PD_USER` (JSON-encoded from the JWT payload at line 131-135) and `.replace(/</g,'&lt;')` is applied. This escapes `<` only — not `"`, `>`, `&`, or `'`. A name like `foo" onmouseover="alert(1)"` would still escape `<` but since it's inserted inside `<span>...</span>`, those chars can't break out. Practically safe for this specific sink, but brittle — any future change (e.g., putting the name in an attribute) breaks it. Also, the JWT payload itself is controlled by the trusted platform worker, so the attacker would need to be the platform worker (i.e., already fully compromised).
- **Attack scenario:** If a future attacker gains the ability to set arbitrary `name` on a user record and the nav-bar markup moves the span into an attribute context, XSS.
- **Fix:** Use DOM APIs, not innerHTML:
  ```js
  const nameSpan = document.createElement('span')
  nameSpan.textContent = u.name
  el.replaceChildren(nameSpan, signOutLink)
  ```

### M2 — `pd_refreshed` one-shot cookie has Max-Age=60 but no user-facing bail-out

- **File:** `functions/_middleware.js:169`
- **Description:** The middleware redirects unauthorized-but-authenticated users to `/api/refresh-session` and sets `pd_refreshed=1; Max-Age=60`. After refresh, if the user still lacks access, the 403 page says "Contact admin." Good. But if the refresh endpoint is down (platform worker incident), the cookie persists for 60s and the user sees a 403 instead of a transient error — no distinction between "genuinely denied" and "refresh failed." The user doesn't know to retry in a minute.
- **Attack scenario:** Not security — availability/UX.
- **Fix:** In the 403 branch, include a "Try again in a minute if this seems wrong" line; or detect whether the refresh attempt actually returned (harder without a callback URL).

### M3 — `window.__mindreader` is a large mutable global

- **Files:** `src/components/phases/SetupPhase.svelte:85`, `src/lib/mediapipe/detection-loop.js:191`, `src/lib/sensors/vision/gaze-direction.js:110`, `src/components/phases/SessionPhase.svelte:12,65`, `src/components/tiles/WebcamTile.svelte:72`
- **Description:** Cross-phase state (sensorManager, detectionLoop, last frame data) is placed on `window.__mindreader`. Any third-party script that ever lands on this page (analytics, future embed, a dependency's CDN script) can read/mutate these objects. Currently mind-reader loads zero third-party scripts other than MediaPipe's WASM (which is loaded via the SDK, not a tag), so this is low-risk today. But it violates the isolation that Svelte's reactivity is otherwise giving you.
- **Attack scenario:** A future dependency bloat adds a script (e.g., a telemetry vendor) that reads biometric frame data from `window.__mindreader._lastFrameData`.
- **Fix:** Replace with a Svelte context (`setContext`/`getContext`) or a dedicated store module imported where needed. No globals.

### M4 — MediaPipe WASM loaded from jsdelivr with `@latest` tag

- **File:** `src/lib/mediapipe/face-landmarker.js:13`
- **Evidence:** `'https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@latest/wasm'`
- **Description:** Pinning to `@latest` means a compromise of the CDN account, or an unexpected breaking release, instantly affects all users. No SRI hash is possible for `@latest`. Rest of the MediaPipe models are pinned to `/float16/1/` paths (implicitly versioned) but this WASM isn't.
- **Attack scenario:** jsdelivr account takeover → attacker publishes a malicious `tasks-vision` version → mind-reader users execute attacker JS in the context of pragmaticdharma.org subdomain, can read the `pd_session` cookie (wait — JWT cookie is `HttpOnly`, so actually not readable from JS; but still can exfiltrate biometric data, camera stream, IndexedDB recordings).
- **Fix:** Pin to the exact version already in `package.json` (`^0.10.32`):
  ```js
  'https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.32/wasm'
  ```
  Better: self-host the WASM files by copying to `public/mediapipe-wasm/` and pointing to a same-origin path. Eliminates CDN supply chain dep entirely.

### M5 — No Content-Security-Policy beyond frame-ancestors (embed only)

- **Files:** `public/_headers`, `functions/_middleware.js:195`
- **Description:** `_headers` sets `X-Content-Type-Options`, `X-Frame-Options: DENY`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy: camera=(self), microphone=(self)`. Good baseline, but no `Content-Security-Policy` on the non-embed flow. Note: `X-Frame-Options: DENY` in `_headers` + the embed middleware's `CSP: frame-ancestors ...` may conflict — browsers treat `frame-ancestors` as overriding `X-Frame-Options`, so this likely works as intended, but it's brittle.
- **Attack scenario:** An XSS bug anywhere — say a future feature that injects user input — executes with no CSP restrictions (can exfiltrate to any origin).
- **Fix:** Add to `_headers`:
  ```
  Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; worker-src 'self' blob:; connect-src 'self' https://storage.googleapis.com https://cdn.jsdelivr.net https://pragmaticdharma.org; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; media-src 'self' blob:; frame-ancestors 'none';
  ```
  (Adjust `frame-ancestors` in embed mode as currently done.) Remove `X-Frame-Options` since CSP supersedes it.

---

## Low

### L1 — `X-XSS-Protection` header is deprecated and can introduce vulnerabilities

- **File:** `public/_headers:4`
- **Description:** Modern browsers have removed or ignore this header; in older Chrome it could even be abused via the XSS-Auditor. Safe to remove; CSP replaces it.
- **Fix:** Delete the line.

### L2 — MediaPipe WASM loaded from third-party origin (supply chain surface)

- **File:** `src/lib/mediapipe/*.js`
- **Description:** All MediaPipe models come from `storage.googleapis.com/mediapipe-models/...`. This is Google's official bucket but adds a cross-origin dependency. Self-hosting during build would remove it.
- **Fix:** (Optional) Add a build step that downloads the `.task` files during `npm run build` and rewrites URLs to `/models/*`. Benefit: privacy (no Google request on every user load), perf (CF cache), resilience.

### L3 — No rate limit on embed postMessage bursts (DoS of parent)

- **Files:** `src/lib/embed/data-streamer.js`, `src/lib/embed/message-handler.js`
- **Description:** A malicious parent could send 10k `mr:snapshot` messages per second; each triggers a stats computation over the buffer. CPU abuse of the user's own device, not a server issue, but still worth a guard.
- **Fix:** Rate-limit `takeSnapshot()` to e.g. 1/second with a token bucket; return silently or with a `mr:error code:'rate-limit'` when exceeded.

### L4 — `destroyAll()` in embed mode is synchronous; media tracks may leak if handler throws

- **File:** `src/components/phases/EmbedPhase.svelte:127-141`
- **Description:** If any of `streamer.destroy()`, `detectionLoop.destroy()`, `sensorManager.destroy()` throws, the camera MediaStream tracks at the end are never stopped — red "recording" indicator stays on.
- **Fix:** Wrap each step in try/catch, always run `videoEl?.srcObject?.getTracks().forEach(t => t.stop())` in a `finally`.

---

## Code Quality

- **Architecture is clean.** 3-phase state machine (SETUP→CALIBRATION→SESSION) with a separate EMBED phase. Separation of concerns between sensors, MediaPipe layer, recording, and UI is well-modeled.
- **Zero Claude API usage.** All inference is on-device — this is a privacy and cost win.
- **Tests.** 386+ Vitest tests with fixture replay is substantial; good test discipline. CLAUDE.md enumerates them clearly. The middleware itself is not unit-tested here (it IS covered by `test-auth.js` in the platform repo — verified in platform CLAUDE.md).
- **Svelte 5 runes used correctly** (`$state`, `$props`) — nothing obviously wrong.
- **IndexedDB recording** is straightforward; no encryption at rest (biometric data is sensitive but local-only, acceptable).
- **Global `window.__mindreader`** (M3) is the biggest code smell; everything else is tidy.
- **Duplicated JWT verification** (H1) — a repo-wide pattern, should be addressed once across all sub-projects.
- **Magic values:** `MAX_BUFFER_SIZE = 300`, `WINDOW_MS = 30000`, the 5120-byte payload limit, `2000ms` auto-init timeout — all could be config-ified but are well-commented.
- **Embed contract-schema.json** is excellent — versioned envelope, explicit message types, good API hygiene. Nice work.
- **`EmbedPhase.svelte`** handles error codes (`camera-denied`/`mic-denied`/`model-load-failed`/`sensor-error`/`not-supported`) cleanly.
- **Deploy flow** is documented in `.claude/commands/deploy.md` — good automation.

Minor nits:
- `message-handler.js:17` uses `new URL(event.origin).hostname` but `event.origin` is already an origin (scheme://host:port), so `new URL(origin).hostname` works but constructs a URL object per message. Cache the regex check or use `event.origin.endsWith('.pragmaticdharma.org') || event.origin === 'https://pragmaticdharma.org'`.
- `snapshot.js:104` `durations.length > 0 ? ...` uses a nested ternary — readable but could be extracted.

---

## Claude API Cost Analysis

**N/A — mind-reader does not call the Claude API or any external inference API.**

All 51+ sensors run entirely in the browser:
- **Vision sensors** use MediaPipe TFLite models (face-landmarker float16, ~3MB; pose/hand optional) via the user's device GPU/CPU.
- **Audio sensors** use Web Audio API `AnalyserNode` for FFT and time-domain analysis.
- **Browser sensors** hook event listeners (keyboard, mouse, scroll, device motion).
- **Derived sensors** compute from upstream sensor outputs in topological order — pure JS math.
- **Speech-to-text** sensor uses browser-native `SpeechRecognition` (if available), not a cloud API.

Cost exposure: **$0 per inference, $0 per user-hour**. This is the optimal architecture for a real-time biometric dashboard — privacy-preserving and infinitely scalable.

### Forward guidance (if you ever DO add Claude)

If a future feature adds Claude (e.g., "summarize my session" or "what do these biometrics suggest?"), adopt these patterns from day one:

1. **Model choice:** Use **Sonnet 4.6** (or Haiku for short reactions). Never Opus for biometric summaries — a 30-second session produces ~2KB of structured data, and summarization is shallow reasoning. Opus would be 6-7x more expensive for no quality gain.
2. **Prompt caching:** If a system prompt describes the 51 sensors and interpretive guidelines (likely 2-4k tokens), add a `cache_control: {"type":"ephemeral"}` breakpoint at its end. 90% cost discount on subsequent calls within 5 minutes. For long-lived sessions, the 1-hour cache extension is relevant.
3. **Rate limit server-side.** Put the Claude call behind a Pages Function with per-user-per-minute limits (e.g., 1 summary per 30 seconds). Use Durable Objects or KV for counters. Never expose `ANTHROPIC_API_KEY` to the browser.
4. **Batch API:** For the fixture-replay flow, if users ever request "analyze all my recorded sessions" (batch), use the Batch API for 50% discount.
5. **Token budget ceilings:** Set `max_tokens` on every call; never pass raw sensor buffers (use the windowed stats from `snapshot.js` — already small & dense).

**Estimated monthly cost if naively implemented** (1 summary per session, 100 sessions/day, Sonnet 4.6, 4k input + 500 output, no caching):
- Input: 100 × 30 × 4000 = 12M tokens × $3/Mtok = **$36/mo**
- Output: 100 × 30 × 500 = 1.5M tokens × $15/Mtok = **$22/mo**
- **~$58/mo** — with caching (90% input discount) drops to ~$25/mo.

But **today, cost is $0** and should stay that way as long as on-device MediaPipe covers requirements.

---

## Top 10 Remediation (prioritized)

1. **[C1] Rotate `JWT_SECRET`** across all 6 services AND move it out of `wrangler.toml [vars]` (use Cloudflare secret binding or build-time injection). Add `wrangler.toml` to `.gitignore`. This is platform-wide — one rotation fixes all services.
2. **[H1] Consolidate JWT verification.** Copy `/home/radmin/workspace/pragmaticdharma/shared/auth-cloudflare.js` into `functions/_auth.js` via a prebuild script; delete the duplicated code in `_middleware.js`. Add a CI check that the files match.
3. **[H2] Fix `postMessage` target origin.** Capture validated parent origin on `mr:init`, use it instead of `'*'` in `postToParent`.
4. **[H3] Remove 2-second auto-init** in embed mode; require explicit `mr:init`.
5. **[M4] Pin MediaPipe WASM version.** Change `@latest` to `@0.10.32`; better — self-host.
6. **[M5] Add a proper CSP header.** Default-deny, explicit allow-lists for scripts/connect/worker/etc. Remove `X-Frame-Options` and `X-XSS-Protection` (L1).
7. **[M1] Replace `innerHTML` in nav bar** with DOM APIs (`textContent` + `replaceChildren`).
8. **[M3] Kill `window.__mindreader`.** Migrate to Svelte context or a dedicated store module.
9. **[L3] Rate-limit embed snapshot requests** (1/sec with token bucket, return `mr:error code:rate-limit` when exceeded).
10. **[L4] Make `destroyAll()` robust** — wrap each step in try/catch, run MediaStream cleanup in `finally`.

---

## Files referenced

- `/home/radmin/workspace/mind-reader/wrangler.toml`
- `/home/radmin/workspace/mind-reader/functions/_middleware.js`
- `/home/radmin/workspace/mind-reader/public/_headers`
- `/home/radmin/workspace/mind-reader/src/App.svelte`
- `/home/radmin/workspace/mind-reader/src/components/phases/SetupPhase.svelte`
- `/home/radmin/workspace/mind-reader/src/components/phases/SessionPhase.svelte`
- `/home/radmin/workspace/mind-reader/src/components/phases/CalibrationPhase.svelte`
- `/home/radmin/workspace/mind-reader/src/components/phases/EmbedPhase.svelte`
- `/home/radmin/workspace/mind-reader/src/lib/embed/message-handler.js`
- `/home/radmin/workspace/mind-reader/src/lib/embed/data-streamer.js`
- `/home/radmin/workspace/mind-reader/src/lib/embed/snapshot.js`
- `/home/radmin/workspace/mind-reader/src/lib/embed/contract-schema.json`
- `/home/radmin/workspace/mind-reader/src/lib/recording/video-recorder.js`
- `/home/radmin/workspace/mind-reader/src/lib/mediapipe/face-landmarker.js`
- `/home/radmin/workspace/pragmaticdharma/shared/auth-cloudflare.js` (reference for H1)
