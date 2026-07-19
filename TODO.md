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
- [ ] Restore per-project JWT signing-key independence for sentinel: create `JWT_SECRET_SENTINEL` via the Cloudflare dashboard, then flip `KID_TO_BINDING['sentinel']` in this repo and `secret_name` in `~/workspace/sentinel-web/wrangler.toml` together (see CLAUDE.md, "Sentinel temporary signing-key state", open since 2026-05-25)
- [ ] Migrate `DISCORD_WEBHOOK_URL` from a plain Worker secret to Cloudflare Secrets Store — best done at the next webhook rotation (see `reviews/remediation-status-2026-04-25.md` deferred-items table)
- [ ] v2 registry-driven rewrite (design-first): collapse project onboarding to one registry entry + one deploy. Schema already drafted (`docs/v2-registry-schema.md`, `prompts/v2-registry-rewrite.md`); the design-session output (`docs/design-v2-registry.md`) is now written; implementation hasn't started
  Design written 2026-07-18: docs/design-v2-registry.md (fable farewell prep)
- [ ] Triage remaining lower-severity Phase 1 security-audit findings not covered by a deferred-prompt file (astrology M-1/M-3/M-6, practice-hub L-2..L-5, ego-development M-new-1/2/6) — see `reviews/remediation-status-2026-04-25.md` "Items not on this short list" (spans multiple sibling repos; only the pragmaticdharma-side triage/tracking is this project's concern)
- [ ] Remove dead code in `worker.js`: `getSigningKey(env)` (~line 1059, comment says "legacy helper retained only for callers that still expect a single key") has no callers left — `signJWT`/`verifyJWT` always go through `getSigningKeyForKid`. Confirm nothing depends on it, then delete it (found writing `docs/ARCHITECTURE.md`, 2026-07-17)
- [ ] Confirm whether anything actually imports `worker.js`'s trailing `export { verifyJWT, getJWTFromCookie, signJWT, accessEmbed, formatLocation, notifyDiscord }` — this repo's own docs say sibling Workers can't import across separate Cloudflare deployments, so this export list may be dead surface left from an earlier single-deployment assumption. Remove if nothing uses it (found 2026-07-17)
- [ ] Add test coverage for `handleSignup` (per-IP/global rate limits, 30-day rejected-user cooldown, open-beta auto-approval), `handleAdmin` (CSRF Origin/Referer guard, approve/reject, the `config` key allowlist), `handleRefreshSession`, and `validateRedirectUrl`'s allowlist behavior — `npm test` currently only covers the magic-link/session/retention core (found 2026-07-17)
- [ ] `GET /api/logout` mutates state (revokes the D1 session row) on a GET request, in addition to the existing `POST /api/logout` — make it POST-only so a bare `<img src>`/link-prefetch/third-party page can't force a logout (low severity, cheap fix; found 2026-07-17)
- [ ] Add `"type": "module"` to `package.json` — every `npm test` run currently prints a `MODULE_TYPELESS_PACKAGE_JSON` Node warning per test file (found 2026-07-17)
- [ ] Owner decision needed: relying parties (ego-assessment, astrology, discern, mind-reader, and health/tcm-tracker, which is a full relying party too) verify `pd_session` locally and never check the Hub's `sessions.revoked_at` — a logout or admin-reject at the Hub doesn't take effect at a relying party until that JWT's own 30-day expiry. Documented in `cto/docs/pd-auth-delta.md` as "Gap 1"; needs a design choice (short-lived JWTs + forced refresh vs. a revocation-check callback vs. a shared denylist) before it gets coded (surfaced again while writing `docs/ARCHITECTURE.md`, 2026-07-17)
  Design written 2026-07-18: docs/design-session-revocation.md (fable farewell prep)
- [ ] Add bot protection (Turnstile or similar) to the Hub's own `/api/login` — it has per-IP (20/hour) and per-email (3/hour) throttles but no CAPTCHA, so a botnet-scale IP pool can still slow-probe emails or burn the Resend quota. psyche already has this (see `cto/docs/pd-auth-delta.md` "Gap 5"); found again 2026-07-17

### Content extraction (folded from EXTRACTION_LIST.md 2026-07-12; background/context in `docs/extraction-notes.md`)
- [ ] Write up the SPUDS protocol (sharing-circle format — exists on paper somewhere); clarify PPODS status (defunct?)
- [ ] ODF connection — how to present/plug Open Dharma Foundation (opendharmafoundation.org)
- [ ] Sangha directory — mental map of in-person communities + who to connect people to (SPUDS, PPODS, Evolving Ground Boulder, SF Dharma Community — add who-each-is-for context; matching criteria in extraction-notes)
- [ ] Consolidate collected chat explanations scattered across conversations
- [ ] Recommendations with who-they're-for context: books, teachers (Tucker Peck, Joe Evans, Dr. Nida Chenagtsang), retreat centers, non-toxic online communities
- [ ] Explanations to write (each = one piece, pragmatic/scientific register): what is emptiness · Cook-Greuter + emptiness · shamatha how-to · how attention works · body scanning · lucid dreaming · acquired appearance quickly · dark night and what to do · freedom of vs from perspective · "we are not all one" (naive sense) · meditation ≠ stopping thoughts · you can learn to feel good (and must) · celebrate remembering, don't self-flagellate · learning to let go · meditation brings the full experience incl. the bad parts · math/physics/CS framings · controlled movement + attention investigation (original contribution)

## Done
