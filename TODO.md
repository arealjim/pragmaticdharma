# TODO

## Now

## Later
- [ ] Restore per-project JWT signing-key independence for sentinel: create `JWT_SECRET_SENTINEL` via the Cloudflare dashboard, then flip `KID_TO_BINDING['sentinel']` in this repo and `secret_name` in `~/workspace/sentinel-web/wrangler.toml` together (see CLAUDE.md, "Sentinel temporary signing-key state", open since 2026-05-25)
- [ ] Migrate `DISCORD_WEBHOOK_URL` from a plain Worker secret to Cloudflare Secrets Store — best done at the next webhook rotation (see `reviews/remediation-status-2026-04-25.md` deferred-items table)
- [ ] v2 registry-driven rewrite (design-first): collapse project onboarding to one registry entry + one deploy. Schema already drafted (`docs/v2-registry-schema.md`, `prompts/v2-registry-rewrite.md`); the design-session output (`docs/v2-design.md`) has not been produced yet and implementation hasn't started
- [ ] Triage remaining lower-severity Phase 1 security-audit findings not covered by a deferred-prompt file (astrology M-1/M-3/M-6, practice-hub L-2..L-5, ego-development M-new-1/2/6) — see `reviews/remediation-status-2026-04-25.md` "Items not on this short list" (spans multiple sibling repos; only the pragmaticdharma-side triage/tracking is this project's concern)

## Done
