# TODO

## Now
- [ ] Commit the untracked v2 design docs + push (platform's plan of record lives in one working tree) — docs/v2-registry-schema.md and prompts/v2-registry-rewrite.md exist only on framework's checkout; not present on biggie (review-pass 2026-07-17 web#5, approved by Jim 2026-07-16)
  Resume: On framework, `git add docs/v2-registry-schema.md prompts/v2-registry-rewrite.md && git commit -m "chore: track v2 design artifacts" && git push origin main`.
- [x] Document the `review` service in the service table and secrets list (review-pass 2026-07-17 web#5, approved by Jim 2026-07-16) — DONE 2026-07-19: added review.pragmaticdharma.org row to Sub-Projects table and JWT_SECRET_REVIEW + INGEST_TOKEN_REVIEW to Secrets section in CLAUDE.md
- [ ] Rewrite-or-demote docs/ai-development-guide.md (single-JWT claim, devbox references, wrong service counts); stop routing live tracking through the frozen 04-25 remediation snapshot (review-pass 2026-07-17 web#8, approved by Jim 2026-07-16)
  Resume: Read ~/workspace/pragmaticdharma/CLAUDE.md and CONTINUE.md. Fix
  docs/ai-development-guide.md: correct the single-JWT claim to the current per-project-JWT
  reality (verify against CLAUDE.md and the code, don't guess), replace devbox references with
  biggie (devbox is retired), fix the wrong service counts, and either rewrite it accurately or
  demote it with a clear "HISTORICAL — superseded, see CLAUDE.md" banner. Then stop routing
  live tracking through the frozen reviews/remediation-status-2026-04-25.md snapshot: move any
  still-open items it tracks into this TODO.md ## Later and mark the snapshot file frozen/
  historical at its top. Docs-only diff: no code changes, no deploys, no secrets. This checkout
  may carry unrelated uncommitted modifications — leave them untouched; `git add` only files
  you edited. Update TODO.md/CONTINUE.md, commit and push (git push origin main).

## Later
- [ ] Restore per-project JWT signing-key independence for sentinel — **needs Jim at the Cloudflare dashboard** (Jim approved 2026-07-19): (1) log into Cloudflare dashboard → Secrets Store `pragmaticdharma` → create `JWT_SECRET_SENTINEL` with value from `vault gen 64` (store in vault too); (2) Claude deploys: flip `KID_TO_BINDING['sentinel']` in this repo and `secret_name` in `~/workspace/sentinel-web/wrangler.toml` in one coordinated change. Signal Jim when ready to coordinate. (see CLAUDE.md, "Sentinel temporary signing-key state", open since 2026-05-25)
- [ ] Migrate `DISCORD_WEBHOOK_URL` from a plain Worker secret to Cloudflare Secrets Store — best done at the next webhook rotation (see `reviews/remediation-status-2026-04-25.md` deferred-items table)
- [ ] v2 registry-driven rewrite — design approved 2026-07-19 (docs/design-v2-registry.md); check-in after slice 1. **Slice 0 in progress:**
  - [x] Slice 0 — freeze: projects.config.mjs + src/registry.js + test/v2-registry.test.mjs (equality tests green; no deploy)
  - [ ] Slice 1 — flip: replace 5 literals in worker.js with registry imports; delete getSigningKey + dead exports; npm test + test-auth.js green before and after; DEPLOY — then check in with Jim
  - [ ] Slice 2 — wrangler.toml codegen (scripts/gen-wrangler.mjs; no binding changes)
  - [ ] Slice 3 — pages + admin from registry ({{cards}} substitution; GET /api/admin/projects)
  - [ ] Slice 4 — tests + CLI (test-auth.js matrix from registry; pd projects; pd add-project)
  - [ ] Slice 5 (optional) — module split into src/ layout
- [ ] CSP nonces for inline scripts: replace `'unsafe-inline'` in `script-src` / `style-src` with per-response nonces in `admin.html` and `login.html`. Currently allowed because those pages carry inline scripts; the CSP M2 comment marks this as a follow-up. (descoped from v2 2026-07-19 — v2 only derives `connect-src`, leaves the rest literal)
- [ ] `kid` header check in sub-project verifier copies: each sub-project's `shared/auth-cloudflare.js` should reject JWTs whose `kid` doesn't match the expected service name, preventing cross-service token replay. Currently no verifier checks `kid` after accepting it for key selection. (descoped from v2 2026-07-19)
- [ ] Parameterized SQL in the `pd` admin CLI: `pd` (bash script) passes user input into `wrangler d1 execute` shell commands — should use `--input` / heredoc with `?` placeholders or at minimum quote-escape all user-supplied values. Low exploitability (local admin tool), but good hygiene. (descoped from v2 2026-07-19)
- [ ] Triage remaining lower-severity Phase 1 security-audit findings not covered by a deferred-prompt file (astrology M-1/M-3/M-6, practice-hub L-2..L-5, ego-development M-new-1/2/6) — see `reviews/remediation-status-2026-04-25.md` "Items not on this short list" (spans multiple sibling repos; only the pragmaticdharma-side triage/tracking is this project's concern)
- [ ] Remove dead code in `worker.js`: `getSigningKey(env)` (~line 1059, comment says "legacy helper retained only for callers that still expect a single key") has no callers left — `signJWT`/`verifyJWT` always go through `getSigningKeyForKid`. Confirm nothing depends on it, then delete it (found writing `docs/ARCHITECTURE.md`, 2026-07-17)
- [ ] Confirm whether anything actually imports `worker.js`'s trailing `export { verifyJWT, getJWTFromCookie, signJWT, accessEmbed, formatLocation, notifyDiscord }` — this repo's own docs say sibling Workers can't import across separate Cloudflare deployments, so this export list may be dead surface left from an earlier single-deployment assumption. Remove if nothing uses it (found 2026-07-17)
- [ ] Add test coverage for `handleSignup` (per-IP/global rate limits, 30-day rejected-user cooldown, open-beta auto-approval), `handleAdmin` (CSRF Origin/Referer guard, approve/reject, the `config` key allowlist), `handleRefreshSession`, and `validateRedirectUrl`'s allowlist behavior — `npm test` currently only covers the magic-link/session/retention core (found 2026-07-17)
- [ ] `GET /api/logout` mutates state (revokes the D1 session row) on a GET request, in addition to the existing `POST /api/logout` — make it POST-only so a bare `<img src>`/link-prefetch/third-party page can't force a logout (low severity, cheap fix; found 2026-07-17)
- [ ] Add `"type": "module"` to `package.json` — every `npm test` run currently prints a `MODULE_TYPELESS_PACKAGE_JSON` Node warning per test file (found 2026-07-17)
- [x] Gap 1 revocation: 24h JWT TTL + lazy-refresh at `/login` — DONE 2026-07-19: `JWT_TTL_SECONDS=86400`, `verifyJWTForRefresh`, loop guard, `handleRefreshSession` updated; 24 unit tests green; deployed. Design: `docs/design-session-revocation.md`.
- [ ] Add bot protection (Turnstile or similar) to the Hub's own `/api/login` — it has per-IP (20/hour) and per-email (3/hour) throttles but no CAPTCHA, so a botnet-scale IP pool can still slow-probe emails or burn the Resend quota. psyche already has this (see `cto/docs/pd-auth-delta.md` "Gap 5"); found again 2026-07-17

### Content extraction (folded from EXTRACTION_LIST.md 2026-07-12; background/context in `docs/extraction-notes.md`)
- [ ] Write up the SPUDS protocol (sharing-circle format — exists on paper somewhere); clarify PPODS status (defunct?)
- [ ] ODF connection — how to present/plug Open Dharma Foundation (opendharmafoundation.org)
- [ ] Sangha directory — mental map of in-person communities + who to connect people to (SPUDS, PPODS, Evolving Ground Boulder, SF Dharma Community — add who-each-is-for context; matching criteria in extraction-notes)
- [ ] Consolidate collected chat explanations scattered across conversations
- [ ] Recommendations with who-they're-for context: books, teachers (Tucker Peck, Joe Evans, Dr. Nida Chenagtsang), retreat centers, non-toxic online communities
- [ ] Explanations to write (each = one piece, pragmatic/scientific register): what is emptiness · Cook-Greuter + emptiness · shamatha how-to · how attention works · body scanning · lucid dreaming · acquired appearance quickly · dark night and what to do · freedom of vs from perspective · "we are not all one" (naive sense) · meditation ≠ stopping thoughts · you can learn to feel good (and must) · celebrate remembering, don't self-flagellate · learning to let go · meditation brings the full experience incl. the bad parts · math/physics/CS framings · controlled movement + attention investigation (original contribution)

## Done
- [x] Remove ego-assessment card from landing page (`pages/index.html`) — DONE 2026-07-19 per Jim: "outdated and we're moving our concerns." App still live at psychology.pragmaticdharma.org but no longer listed on the portal.
- [x] 24h JWT TTL + lazy /login refresh (session revocation Gap 1) — deployed 2026-07-19
