// Registry of all platform sub-projects.
// This is the single source of truth: add one entry here + one deploy to onboard
// a new project. Handlers consume derived structures from src/registry.js, not
// this file directly. See docs/design-v2-registry.md for the design.
//
// Field reference:
//   key            — D1 user_projects key, JWT claims key, open_beta config key
//   subdomain      — hostname prefix (host = `${subdomain}.pragmaticdharma.org`)
//   kid            — JWT kid header value; defaults to key when identical
//   kidBindingOverride — (optional) override the default JWT_SECRET_<KID> binding name;
//                        requires kidBindingOverrideNotes explaining why + date
//   gate           — 'worker-gate' (302/403 redirect) | 'api-gate' (401 JSON)
//   status         — 'live' (shown on index) | 'soon' | 'hidden' (gated, not advertised)
//                    confirm mapping against index.html cards in slice 3 before rendering
//   adminConnect   — true if admin.html cross-fetches this service's API (goes in CSP connect-src)
//   label          — human name for admin UI and future generated docs
//   testProbe      — path that must return 200 when authed (used by test-auth.js in slice 4)

export const PROJECTS = [
  // ── health ───────────────────────────────────────────────────────────────────
  // TCM health tracker — Flask service on biggie via cloudflared
  // gate: api-gate because it's a JSON API, not a web app
  {
    key:          'health',
    subdomain:    'health',
    kid:          'health',
    gate:         'api-gate',
    status:       'hidden',
    adminConnect: true,     // admin.html cross-fetches /api/* on this service
    label:        'Health Tracker',
    testProbe:    '/',
  },

  // ── shield ───────────────────────────────────────────────────────────────────
  // Psychic Shield — preparedness briefing reader
  {
    key:          'shield',
    subdomain:    'shield',
    kid:          'shield',
    gate:         'worker-gate',
    status:       'hidden',
    adminConnect: false,
    label:        'Psychic Shield',
    testProbe:    '/',
  },

  // ── ego-assessment ───────────────────────────────────────────────────────────
  // Ego development assessment — key ≠ subdomain (host is psychology.*)
  // Removed from landing page 2026-07-19; still live at psychology.pragmaticdharma.org
  {
    key:          'ego-assessment',
    subdomain:    'psychology',    // key ≠ subdomain: D1/claims use 'ego-assessment'
    kid:          'ego-assessment',
    gate:         'api-gate',
    status:       'hidden',
    adminConnect: true,     // admin.html cross-fetches /api/* on this service
    label:        'Ego Assessment',
    testProbe:    '/api/assess',
  },

  // ── mindreader ───────────────────────────────────────────────────────────────
  // Biometric SPA — webcam/mic sensor platform
  {
    key:          'mindreader',
    subdomain:    'mindreader',
    kid:          'mindreader',
    gate:         'worker-gate',
    status:       'live',
    adminConnect: false,
    label:        'Mind Reader',
    testProbe:    '/',
  },

  // ── psychtools ───────────────────────────────────────────────────────────────
  // DBT skills reference
  {
    key:          'psychtools',
    subdomain:    'psychtools',
    kid:          'psychtools',
    gate:         'worker-gate',
    status:       'live',
    adminConnect: false,
    label:        'Psych Tools',
    testProbe:    '/',
  },

  // ── astrology ────────────────────────────────────────────────────────────────
  // Astrology frontend + biggie Claude proxy
  {
    key:          'astrology',
    subdomain:    'astrology',
    kid:          'astrology',
    gate:         'worker-gate',
    status:       'live',
    adminConnect: false,
    label:        'Astrology',
    testProbe:    '/',
  },

  // ── practice ─────────────────────────────────────────────────────────────────
  // Practice Hub — meditation/reflection frontend + biggie Claude proxy
  {
    key:          'practice',
    subdomain:    'practice',
    kid:          'practice',
    gate:         'worker-gate',
    status:       'live',
    adminConnect: false,
    label:        'Practice Hub',
    testProbe:    '/',
  },

  // ── sentinel ─────────────────────────────────────────────────────────────────
  // Preparedness dashboard — admin-email allowlist; hidden from index
  // kidBindingOverride: JWT_SECRET_SENTINEL does not yet exist in the Secrets Store
  // (creation blocked by secrets-store CLI bug 2026-05-25; dashboard workaround pending).
  // Restore: create JWT_SECRET_SENTINEL via dashboard, flip override here + in
  // sentinel-web/wrangler.toml in one coordinated change. See CLAUDE.md.
  {
    key:                    'sentinel',
    subdomain:              'sentinel',
    kid:                    'sentinel',
    kidBindingOverride:     'JWT_SECRET_PRAGMATICDHARMA',
    kidBindingOverrideNotes: '2026-05-25: JWT_SECRET_SENTINEL not yet in Secrets Store; shares hub binding until restored. See CLAUDE.md "Sentinel temporary signing-key state".',
    gate:                   'worker-gate',
    status:                 'hidden',
    adminConnect:           false,
    label:                  'Sentinel',
    testProbe:              '/',
  },

  // ── bromnichord ──────────────────────────────────────────────────────────────
  // Chiptune omnichord instrument — static assets only
  {
    key:          'bromnichord',
    subdomain:    'bromnichord',
    kid:          'bromnichord',
    gate:         'worker-gate',
    status:       'live',
    adminConnect: false,
    label:        'Bromnichord',
    testProbe:    '/',
  },

  // ── discern ──────────────────────────────────────────────────────────────────
  // Calibration training game — static assets, localStorage data
  {
    key:          'discern',
    subdomain:    'discern',
    kid:          'discern',
    gate:         'worker-gate',
    status:       'live',
    adminConnect: false,
    label:        'Discern',
    testProbe:    '/',
  },

  // ── review ───────────────────────────────────────────────────────────────────
  // Business-ops review dashboard (majordomo project) — hidden from index
  {
    key:          'review',
    subdomain:    'review',
    kid:          'review',
    gate:         'worker-gate',
    status:       'hidden',
    adminConnect: false,
    label:        'Review',
    testProbe:    '/',
  },
];
