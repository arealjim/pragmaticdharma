# Continue

_Updated: 2026-07-19_

## State
Platform hub is live and stable. One doc fix landed today: `review` service (review.pragmaticdharma.org — `review-workers`, D1 `review-db`, `JWT_SECRET_REVIEW` + `INGEST_TOKEN_REVIEW`) added to CLAUDE.md's Sub-Projects table and Secrets section. Two ## Now items remain: the untracked v2 design docs (exist only on framework; must be committed there) and the ai-development-guide.md rewrite (web#8).

## Next step
Pick up web#8 (docs/ai-development-guide.md rewrite): correct the single-JWT claim, replace devbox references with biggie, fix wrong service counts, add historical banner or rewrite.

## Prompt
```
Work in ~/workspace/pragmaticdharma. Read TODO.md and CONTINUE.md.
Fix docs/ai-development-guide.md: correct the single-JWT claim to the current
per-project-JWT reality (verify against CLAUDE.md and the code, don't guess),
replace devbox references with biggie (devbox is retired), fix the wrong service
counts, and either rewrite it accurately or demote it with a clear
"HISTORICAL — superseded, see CLAUDE.md" banner. Then stop routing live tracking
through the frozen reviews/remediation-status-2026-04-25.md snapshot: move any
still-open items it tracks into this TODO.md ## Later and mark the snapshot file
frozen/historical at its top. Docs-only diff: no code changes, no deploys, no
secrets. This checkout may carry unrelated uncommitted modifications — leave them
untouched; `git add` only files you edited. Update TODO.md/CONTINUE.md, commit
and push (git push origin main).
```
