# v2 project registry — schema design (2026-07-04)

Companion to `prompts/v2-registry-rewrite.md`. This is the core design artifact: one module
replaces every place a project is currently hand-registered.

## Design insight

Of the ~7 duplication sites, **only `wrangler.toml` needs code generation** (TOML can't import
JS). Everything else can consume the registry directly at runtime, build, or test time, because
the worker, the admin UI, the tests, and the `pd` CLI are all JS-adjacent:

| Current site | v2 mechanism |
|---|---|
| `KNOWN_PROJECTS` (worker.js:33) | computed: `PROJECTS.map(p => p.key)` |
| `REDIRECT_ALLOWLIST` (worker.js:40) | computed: apex + platform hosts + project hosts |
| `redirectUrlToProject` map (worker.js:65) | computed: host→key from entries |
| `KID_TO_BINDING` (worker.js:896) | computed: `kid → binding(kid)` with per-entry override |
| CSP `connect-src` (worker.js CSP_HEADER) | computed: hosts where `adminConnect: true` |
| index.html project cards | rendered by the worker from registry (cards are already served by the worker; template + loop, no codegen) |
| admin.html `ALL_PROJECTS` + beta toggles | admin JS fetches `/api/admin/projects` (registry serialized), renders badges/toggles from it |
| `[[secrets_store_secrets]]` blocks (wrangler.toml) | **codegen**: `scripts/gen-wrangler.mjs` rewrites a marked section; predeploy check fails if dirty |
| test-auth.js matrix (lines ~279) | imports registry; expectations derived from `gate` + `testProbe` |
| `pd` CLI project listing | `pd projects` shells out to `node -p` over the registry |

## Schema

`projects.config.mjs` (plain ESM, imported by worker, tests, scripts):

```js
export const PLATFORM = {
  apexHost: 'pragmaticdharma.org',
  // redirect-allowlisted hosts that are NOT projects (H6 allowlist stays exact, no wildcards)
  extraPlatformHosts: ['retreats.pragmaticdharma.org'],
  platformKid: 'pragmaticdharma',   // binding JWT_SECRET_PRAGMATICDHARMA
};

export const PROJECTS = [
  {
    // --- identity (immutable once live; migration must preserve current values) ---
    key: 'shield',              // stable ID: user_projects rows, JWT projects[] claim, `open_beta:<key>` config keys
    subdomain: 'shield',        // host = `${subdomain}.${apexHost}`. key ≠ subdomain is legal:
                                //   ego-assessment lives at psychology.pragmaticdharma.org
    kid: 'shield',              // JWT key id sub-worker signs/verifies with (usually === key)

    // --- auth/gating ---
    gate: 'worker-gate',        // 'worker-gate' (unauth→302, denied→403) | 'api-gate' (all→401)
    kidBindingOverride: null,   // normally binding = `JWT_SECRET_${kid.toUpperCase().replaceAll('-','_')}`.
                                // Escape hatch for documented exceptions — today only sentinel,
                                // which temporarily reuses JWT_SECRET_PRAGMATICDHARMA (2026-05-25
                                // secrets-store CLI failure). v2 goal: create JWT_SECRET_SENTINEL
                                // and delete the only use of this field.
    adminConnect: false,        // true → host added to platform CSP connect-src (admin.html
                                // cross-fetches this project's API). Today: health, ego-assessment.

    // --- presentation ---
    name: 'Shield',             // display: index card, admin badge, test name
    description: 'Automated daily intelligence briefing. Collects news, …',
    status: 'live',             // 'live' | 'soon' (card w/ badge, not linked) | 'hidden' (no card;
                                // still gate-able — for private betas that shouldn't be advertised)

    // --- ops metadata (never read by the worker) ---
    testProbe: '/',             // path test-auth.js hits; api-gate projects probe an API route
                                //   (e.g. ego-assessment: '/api/profile', health: '/api/mood/trends')
    repo: '~/workspace/psychic-shield',   // where the sub-project source lives
    notes: '',                  // dated freeform exceptions only
  },
  // … 9 more entries; current values from worker.js:33-85, :896-921, test-auth.js:279-286
];
```

### Derivations module (`src/registry.js`)

```js
export const KNOWN_PROJECTS, HOST_TO_PROJECT, REDIRECT_ALLOWLIST,
             KID_TO_BINDING, CSP_CONNECT_SRC, publicProjects(), adminProjects()
```

Self-validates at import (fail deploy, not runtime): unique `key`/`subdomain`/`kid`; status in
enum; every `kidBindingOverride` carries a non-empty `notes`; `testProbe` starts with `/`.
A unit test asserts wrangler.toml's generated section matches the registry (catches hand-edits).

### wrangler.toml codegen

`scripts/gen-wrangler.mjs` rewrites only the block between
`# --- BEGIN GENERATED SECRETS (gen-wrangler.mjs) ---` / `# --- END GENERATED ---`:
one `[[secrets_store_secrets]]` per unique binding (platform key, Resend key, then per-project
keys; overrides collapse — sentinel today adds no block). `npm run deploy` = gen → git-diff-clean
check → wrangler deploy.

## `pd add-project <key>` flow

1. Collect `name`, `subdomain` (default = key), `gate`, `description` (flags or prompts).
2. Append entry to `projects.config.mjs` with `status: 'soon'`, `adminConnect: false`.
3. `gen-wrangler.mjs` → new secrets block.
4. Generate 64-hex secret; attempt `wrangler secrets-store secret create`; on failure (the beta
   CLI caused the sentinel scar) print exact dashboard steps + the value once for KeePassXC.
5. Print remaining manual checklist: DNS/route for the subdomain; sub-worker snippet
   (kid, binding name, `hasProjectAccess(payload, '<key>')`, refresh-bounce URL); grant yourself
   access (`pd approve` / badge); `node test-auth.js --only <key>`.
6. `npm run deploy` (platform). Flip `status` to `'live'` when the card should show.

Steps 1–3 + 6 are automatic; 4 is semi-automatic; 5 is irreducibly manual (DNS + sub-repo) but
becomes a printed checklist instead of tribal knowledge. Estimated: <10 min platform-side.

## Migration constraints (verified against current code)

- Keys, kids, and the ego-assessment/psychology split are **frozen** — they're baked into D1
  `user_projects` rows, live JWT `projects[]` claims, `open_beta:<key>` config keys, and
  sub-worker deployments. Registry must reproduce today's values exactly; v2 changes behavior
  for none of them.
- `REDIRECT_ALLOWLIST` computed form must equal the current 12-host set exactly (H6 audit
  posture: exact hosts, no wildcard). Add a test comparing against a frozen snapshot at cutover.
- Sentinel: keep override at cutover; creating `JWT_SECRET_SENTINEL` + flipping sentinel-web is
  its own small change (also update `sentinel-web/wrangler.toml`), sequenced after cutover.
- Index/admin move from static HTML to registry-rendered: keep markup/classes identical
  (`.card`, `.project-badge`, toggle rows) so no CSS/JS churn in the same change.

## Decisions deferred to the rewrite session

1. Router: stay zero-dep (current ladder, modularized) vs Hono. Registry design is agnostic.
2. Whether `pages/*.html` stay text-module imports with a tiny `{{cards}}` substitution, or move
   to small render functions. Recommend substitution first — smallest diff, same contract.
3. Whether `repo`/`notes` metadata should also drive a generated "platform map" doc section in
   CLAUDE.md (nice-to-have).
