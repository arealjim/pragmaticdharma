# TODO

## Now

## Later
- [ ] Restore per-project JWT signing-key independence for sentinel: create `JWT_SECRET_SENTINEL` via the Cloudflare dashboard, then flip `KID_TO_BINDING['sentinel']` in this repo and `secret_name` in `~/workspace/sentinel-web/wrangler.toml` together (see CLAUDE.md, "Sentinel temporary signing-key state", open since 2026-05-25)
- [ ] Migrate `DISCORD_WEBHOOK_URL` from a plain Worker secret to Cloudflare Secrets Store — best done at the next webhook rotation (see `reviews/remediation-status-2026-04-25.md` deferred-items table)
- [ ] v2 registry-driven rewrite (design-first): collapse project onboarding to one registry entry + one deploy. Schema already drafted (`docs/v2-registry-schema.md`, `prompts/v2-registry-rewrite.md`); the design-session output (`docs/v2-design.md`) has not been produced yet and implementation hasn't started
- [ ] Triage remaining lower-severity Phase 1 security-audit findings not covered by a deferred-prompt file (astrology M-1/M-3/M-6, practice-hub L-2..L-5, ego-development M-new-1/2/6) — see `reviews/remediation-status-2026-04-25.md` "Items not on this short list" (spans multiple sibling repos; only the pragmaticdharma-side triage/tracking is this project's concern)

### Content extraction (folded from EXTRACTION_LIST.md 2026-07-12; background/context in `docs/extraction-notes.md`)
- [ ] Write up the SPUDS protocol (sharing-circle format — exists on paper somewhere); clarify PPODS status (defunct?)
- [ ] ODF connection — how to present/plug Open Dharma Foundation (opendharmafoundation.org)
- [ ] Sangha directory — mental map of in-person communities + who to connect people to (SPUDS, PPODS, Evolving Ground Boulder, SF Dharma Community — add who-each-is-for context; matching criteria in extraction-notes)
- [ ] Consolidate collected chat explanations scattered across conversations
- [ ] Recommendations with who-they're-for context: books, teachers (Tucker Peck, Joe Evans, Dr. Nida Chenagtsang), retreat centers, non-toxic online communities
- [ ] Explanations to write (each = one piece, pragmatic/scientific register): what is emptiness · Cook-Greuter + emptiness · shamatha how-to · how attention works · body scanning · lucid dreaming · acquired appearance quickly · dark night and what to do · freedom of vs from perspective · "we are not all one" (naive sense) · meditation ≠ stopping thoughts · you can learn to feel good (and must) · celebrate remembering, don't self-flagellate · learning to let go · meditation brings the full experience incl. the bad parts · math/physics/CS framings · controlled movement + attention investigation (original contribution)

## Done
