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
//   adminConnect   — true if admin.html cross-fetches this service's API (goes in CSP connect-src)
//   label          — human name for docs / test-auth.js test names
//   adminLabel     — short badge text for the admin per-user project-grant UI
//                    (GET /api/admin/projects) — required for every project, since
//                    admin manages grants for hidden/gated projects too
//   cardTitle      — index-page card <h3> text — required when status is 'live' or 'soon'
//   cardDescription — index-page card <p> text (raw HTML — may contain entities like
//                    &mdash;, rendered unescaped) — required when status is 'live' or 'soon'
//   testProbe      — path that must return 200 when authed (used by test-auth.js in slice 4)
//
// PROJECTS order also drives index-page card order (for live/soon projects) and
// wrangler.toml's generated secrets block order (scripts/gen-wrangler.mjs) — it's
// presentation ordering only, nothing auth-relevant depends on array position.

export const PROJECTS = [
  // ── shield ───────────────────────────────────────────────────────────────────
  // Psychic Shield — preparedness briefing reader
  {
    key:          'shield',
    subdomain:    'shield',
    kid:          'shield',
    gate:         'worker-gate',
    status:       'live',
    adminConnect: false,
    label:        'Psychic Shield',
    adminLabel:   'Shield',
    cardTitle:       'Shield',
    cardDescription: 'Automated daily intelligence briefing. Collects news, Reddit discussions, market data, and conflict reports from 33+ sources, synthesized by AI into a security-focused morning brief.',
    testProbe:    '/',
  },

  // ── health ───────────────────────────────────────────────────────────────────
  // TCM health tracker — Flask service on biggie via cloudflared
  // gate: api-gate because it's a JSON API, not a web app
  {
    key:          'health',
    subdomain:    'health',
    kid:          'health',
    gate:         'api-gate',
    status:       'live',
    adminConnect: true,     // admin.html cross-fetches /api/* on this service
    label:        'Health Tracker',
    adminLabel:   'Health',
    cardTitle:       'Health Tracker',
    cardDescription: 'Traditional Chinese Medicine body mapping and symptom tracking. Log daily observations and track patterns over time.',
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
    adminLabel:   'Ego',
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
    adminLabel:   'Mind Reader',
    cardTitle:       'Mind Reader',
    cardDescription: 'Gaze-guided therapeutic tool. Tracks emotions, heart rate, and physiological signals via webcam while guiding your gaze across the screen.',
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
    adminLabel:   'PsychTools',
    cardTitle:       'PsychTools',
    cardDescription: 'Interactive DBT skills practice suite. 35 tools across mindfulness, interpersonal effectiveness, emotion regulation, and distress tolerance.',
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
    adminLabel:   'Discern',
    cardTitle:       'Discern',
    cardDescription: 'Calibration training game. Judge claims as true or false, state your confidence, and see how well your certainty tracks reality &mdash; trains spotting misinformation without sliding into blanket cynicism.',
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
    adminLabel:   'Practice',
    cardTitle:       'Practice Hub',
    cardDescription: 'Cycle-aware life management. Tasks and goals aligned with TCM organ clock, lunar phases, solar terms, and astrological transits. Natural language task entry with Five Element energy tagging.',
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
    adminLabel:   'Astrology',
    cardTitle:       'Transit Viewer',
    cardDescription: 'Personalized astrological transit timeline. Enter your birth data, see a Gantt-chart of upcoming planetary transits, and get AI-powered interpretations and interactive chat.',
    testProbe:    '/',
  },

  // ── sentinel ─────────────────────────────────────────────────────────────────
  // Preparedness dashboard — admin-email allowlist. Advertised on the index page
  // (status 'live'); the admin-email allowlist, not index visibility, is what
  // actually restricts access.
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
    status:                 'live',
    adminConnect:           false,
    label:                  'Sentinel',
    adminLabel:             'Sentinel',
    cardTitle:       'Sentinel',
    cardDescription: 'Preparedness scenarios, predictions, and daily assessment.',
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
    adminLabel:   'Bromnichord',
    cardTitle:       'Bromnichord',
    cardDescription: 'Browser omnichord with 8-bit chiptune voices. Pick chords on a circle-of-fifths wheel, set arpeggios, and strum a 10-segment light beam — all wrapped in psychedelic audio-reactive visuals.',
    testProbe:    '/',
  },

  // ── review ───────────────────────────────────────────────────────────────────
  // Business-ops review dashboard (majordomo project) — hidden from index.
  // Full admin app at review.* — staff only (role==='admin' + email allowlist in
  // majordomo review-app/worker.js). Board members hold `boardreview` (below),
  // NOT this claim, since 2026-07-27 hardening (todo-board card 5d077131052f).
  {
    key:          'review',
    subdomain:    'review',
    kid:          'review',
    gate:         'worker-gate',
    status:       'hidden',
    adminConnect: false,
    label:        'Review',
    adminLabel:   'Review (staff)',
    testProbe:    '/',
  },

  // ── boardreview ──────────────────────────────────────────────────────────────
  // Read-only board mirror, served by the SAME majordomo worker as `review`
  // (behaviour keys off the request host) but as its own least-privilege claim —
  // holding it does NOT admit to the full admin app at review.* (see majordomo
  // review-app/worker.js isAuthorized). Deliberately not its own host on `review`
  // via aliasHosts: a distinct project key lets grants be scoped to board members
  // only. kidBindingOverride: reuses JWT_SECRET_REVIEW rather than provisioning a
  // new Secrets Store secret — majordomo's review-app already verifies both hosts
  // with that one binding, so no majordomo wrangler.toml change is needed.
  {
    key:                     'boardreview',
    subdomain:               'boardreview',
    kid:                     'boardreview',
    kidBindingOverride:      'JWT_SECRET_REVIEW',
    kidBindingOverrideNotes: '2026-07-27: shares the review kid\'s secret on purpose — majordomo review-app verifies both review.* and boardreview.* with the single JWT_SECRET_REVIEW binding; only the project *claim* differs (least-privilege split, not a key rotation). Board grants: todo-board card 5d077131052f.',
    gate:                    'worker-gate',
    status:                  'hidden',
    adminConnect:            false,
    label:                   'Board Review',
    adminLabel:              'Board Review',
    testProbe:               '/',
  },
];
