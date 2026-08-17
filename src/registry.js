// Derivation layer for the project registry.
// Consumers import named structures from here; no handler reads PROJECTS directly.
// Throws at import time if projects.config.mjs is invalid — fail deploy, not runtime.

import { PROJECTS } from '../projects.config.mjs';

// ── import-time validation ───────────────────────────────────────────────────

const VALID_GATES = new Set(['worker-gate', 'api-gate']);
const VALID_STATUSES = new Set(['live', 'soon', 'hidden']);

(function validate(projects) {
  const keys = new Set();
  const subdomains = new Set();
  const kids = new Set();
  const hosts = new Set();  // every host (subdomain + aliasHosts) must be unique
  for (const p of projects) {
    if (!p.key || !p.subdomain || !p.kid || !p.gate || !p.status || typeof p.adminConnect !== 'boolean' || !p.adminLabel) {
      throw new Error(`registry: project missing required field(s): ${JSON.stringify(p)}`);
    }
    if (!VALID_GATES.has(p.gate)) throw new Error(`registry: unknown gate '${p.gate}' for key '${p.key}'`);
    if (!VALID_STATUSES.has(p.status)) throw new Error(`registry: unknown status '${p.status}' for key '${p.key}'`);
    if ((p.status === 'live' || p.status === 'soon') && (!p.cardTitle || !p.cardDescription)) {
      throw new Error(`registry: project '${p.key}' has status '${p.status}' but no cardTitle/cardDescription`);
    }
    if (!p.testProbe || !p.testProbe.startsWith('/')) {
      throw new Error(`registry: project '${p.key}' testProbe must start with '/'`);
    }
    if (p.kidBindingOverride && !p.kidBindingOverrideNotes) {
      throw new Error(`registry: kidBindingOverride on '${p.key}' requires kidBindingOverrideNotes`);
    }
    if (keys.has(p.key)) throw new Error(`registry: duplicate key '${p.key}'`);
    if (subdomains.has(p.subdomain)) throw new Error(`registry: duplicate subdomain '${p.subdomain}'`);
    if (kids.has(p.kid)) throw new Error(`registry: duplicate kid '${p.kid}'`);
    keys.add(p.key);
    subdomains.add(p.subdomain);
    kids.add(p.kid);
    const primaryHost = `${p.subdomain}.pragmaticdharma.org`;
    if (hosts.has(primaryHost)) throw new Error(`registry: duplicate host '${primaryHost}'`);
    hosts.add(primaryHost);
    // aliasHosts — extra hostnames served by the SAME worker under the SAME
    // project key/kid (e.g. review's read-only board mirror). They inherit the
    // project's kid, so their JWTs verify against the same JWT_SECRET_<KID>.
    if (p.aliasHosts !== undefined) {
      if (!Array.isArray(p.aliasHosts) || p.aliasHosts.some(h => typeof h !== 'string' || !h)) {
        throw new Error(`registry: aliasHosts on '${p.key}' must be an array of non-empty strings`);
      }
      for (const h of p.aliasHosts) {
        if (hosts.has(h)) throw new Error(`registry: duplicate host '${h}' (aliasHosts on '${p.key}')`);
        hosts.add(h);
      }
    }
  }
})(PROJECTS);

// ── derived structures ───────────────────────────────────────────────────────

// Ordered list of project keys — drives KNOWN_PROJECTS in the worker.
export const KNOWN_PROJECTS = PROJECTS.map(p => p.key);

// Explicit allowlist of redirect destinations (apex + retreats + all project hosts).
// Two static entries exist outside the project list (hub pages, not sub-projects).
export const REDIRECT_ALLOWLIST = new Set([
  'pragmaticdharma.org',
  'retreats.pragmaticdharma.org',
  ...PROJECTS.map(p => `${p.subdomain}.pragmaticdharma.org`),
  ...PROJECTS.flatMap(p => p.aliasHosts ?? []),
]);

// Host → project key map for post-login redirect routing. aliasHosts resolve to
// their project's key (and therefore its kid), so a JWT minted for the mirror
// host is signed with the same key the worker verifies with.
export const HOST_TO_PROJECT = Object.fromEntries([
  ...PROJECTS.map(p => [`${p.subdomain}.pragmaticdharma.org`, p.key]),
  ...PROJECTS.flatMap(p => (p.aliasHosts ?? []).map(h => [h, p.key])),
]);

// kid → Secrets Store binding name.
// The platform hub ('pragmaticdharma') entry is fixed — it signs the initial session JWT.
// Each project entry uses JWT_SECRET_<KID_UPPER> by convention, or kidBindingOverride.
function kidToDefaultBinding(kid) {
  return 'JWT_SECRET_' + kid.toUpperCase().replace(/-/g, '_');
}

export const KID_TO_BINDING = {
  'pragmaticdharma': 'JWT_SECRET_PRAGMATICDHARMA',
  ...Object.fromEntries(
    PROJECTS.map(p => [p.kid, p.kidBindingOverride ?? kidToDefaultBinding(p.kid)])
  ),
};

// Full HTTPS URLs for projects whose APIs admin.html cross-fetches (CSP connect-src).
export const CSP_CONNECT_SRC_HOSTS = PROJECTS
  .filter(p => p.adminConnect)
  .map(p => `https://${p.subdomain}.pragmaticdharma.org`);

// ── project views ────────────────────────────────────────────────────────────

// Projects shown on the public index page (status live or soon).
export function publicProjects() {
  return PROJECTS.filter(p => p.status === 'live' || p.status === 'soon');
}

// All projects — for admin UI lists and the test-auth.js matrix.
export function adminProjects() {
  return [...PROJECTS];
}

// Projects covered by test-auth.js's generic matrix ("has the project claim
// -> 200"). Excludes customAuthTest projects (review, boardreview, sentinel),
// which have gating beyond platform project membership and get a
// hand-written policy test instead.
export function testMatrixProjects() {
  return PROJECTS.filter(p => !p.customAuthTest);
}

// ── rendering (index-page cards, admin project list) ────────────────────────

// Renders the index-page project cards (v2 Slice 3). cardDescription is
// trusted, developer-authored markup (may contain HTML entities like
// &mdash;) — rendered as-is, not HTML-escaped, matching the literal card
// markup this replaced. Markup/classes are unchanged from the pre-Slice-3
// static cards so no CSS/JS churn; see test/registry-render.test.mjs for
// the byte-compare against the original per-project card text.
export function renderCards() {
  return publicProjects().map(p => {
    const statusClass = p.status === 'soon' ? 'soon' : 'live';
    const statusLabel = p.status === 'soon' ? 'Soon' : 'Live';
    const inner = `    <div class="card">\n` +
      `      <h3>${p.cardTitle}</h3>\n` +
      `      <p>${p.cardDescription}</p>\n` +
      `      <span class="status ${statusClass}">${statusLabel}</span>\n` +
      `    </div>`;
    // 'soon' projects show a card with a badge but aren't linked yet.
    if (p.status === 'soon') {
      return `  <div class="card-link">\n${inner}\n  </div>`;
    }
    return `  <a class="card-link" href="https://${p.subdomain}.pragmaticdharma.org">\n${inner}\n  </a>`;
  }).join('\n\n');
}

// Serializes the registry for GET /api/admin/projects — the admin page's
// per-user project-grant badges (ALL_PROJECTS + PROJECT_LABELS) fetch this
// instead of carrying a hardcoded literal that drifts from the registry.
export function adminProjectsJSON() {
  return adminProjects().map(p => ({ key: p.key, label: p.adminLabel }));
}
