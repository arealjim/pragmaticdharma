#!/usr/bin/env node
/**
 * Auth enforcement integration tests for pragmaticdharma.org subdomains.
 *
 * Crafts JWTs with different `projects` arrays and hits each subdomain
 * to verify access is correctly granted or denied.
 *
 * Usage: JWT_SECRET=<value> node test-auth.js
 *
 * Requires Node 18+ (for fetch, crypto.subtle).
 */

const crypto = require('crypto');

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

function base64urlEncode(data) {
  const str = typeof data === 'string' ? data : Buffer.from(data).toString('base64');
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signJWT(payload, secret, kid) {
  const header = kid ? { alg: 'HS256', typ: 'JWT', kid } : { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64urlEncode(Buffer.from(JSON.stringify(header)).toString('base64'));
  const encodedPayload = base64urlEncode(Buffer.from(JSON.stringify(payload)).toString('base64'));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput));
  const encodedSig = base64urlEncode(Buffer.from(sig).toString('base64'));

  return `${encodedHeader}.${encodedPayload}.${encodedSig}`;
}

function makePayload(projects, opts = {}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: 'test-user-id',
    email: 'test@example.com',
    name: 'Test User',
    role: 'user',
    iat: now,
    exp: opts.expired ? now - 3600 : now + 3600,
  };
  if (projects !== undefined) {
    payload.projects = projects;
  }
  return payload;
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

const COLORS = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
  reset: '\x1b[0m',
  bold: '\x1b[1m',
};

function pass(label) {
  return `  ${COLORS.green}PASS${COLORS.reset} ${label}`;
}

function fail(label, detail) {
  return `  ${COLORS.red}FAIL${COLORS.reset} ${label}${detail ? ` ${COLORS.dim}(${detail})${COLORS.reset}` : ''}`;
}

/**
 * Check if a response status matches one of the expected statuses.
 */
function statusMatches(actual, expected) {
  return expected.includes(actual);
}

/**
 * Auth styles:
 * - 'worker-gate': Cloudflare Worker middleware. Unauth → 302, wrong project → 403.
 *     (shield, mindreader)
 * - 'api-gate': Auth checked at API level. All failures → 401, project-denied = unauth.
 *     (ego-assessment via validateSession, health via Flask @require_auth on API routes)
 *
 * Per-service JWT keys (Task #2): each site verifies with its own per-service
 * key, so the test JWT must be signed with that key + kid header. The kid
 * matches the project key in most cases (kid='shield' for psychic-shield,
 * kid='mindreader' for mind-reader, etc.) — except ego-assessment which uses
 * kid='ego-assessment' to match the platform's KID_TO_BINDING map.
 */

/**
 * Run all 7 test scenarios against a single site.
 * Returns { passed, failed, results[] }.
 */
async function testSite(name, url, projectKey, secret, authStyle, kid) {
  const results = [];
  let passed = 0;
  let failed = 0;

  console.log(`\n${COLORS.cyan}${COLORS.bold}${name}${COLORS.reset} ${COLORS.dim}${url}${COLORS.reset}`);

  // Helper to run a single scenario
  async function scenario(label, cookie, expectedStatuses) {
    try {
      const headers = {};
      if (cookie) {
        headers['Cookie'] = `pd_session=${cookie}`;
      }
      const resp = await fetch(url, {
        method: 'GET',
        headers,
        redirect: 'manual',
      });
      const status = resp.status;
      if (statusMatches(status, expectedStatuses)) {
        console.log(pass(`${label} → ${status}`));
        passed++;
        results.push({ label, status, ok: true });
      } else {
        console.log(fail(`${label} → ${status}`, `expected ${expectedStatuses.join('|')}`));
        failed++;
        results.push({ label, status, ok: false, expected: expectedStatuses });
      }
    } catch (err) {
      console.log(fail(`${label} → ERROR`, err.message));
      failed++;
      results.push({ label, status: 'ERR', ok: false, error: err.message });
    }
  }

  // Expected statuses depend on auth style. worker-gate workers redirect
  // wrong-project to /api/refresh-session (302) — which then 403s if still
  // denied — so accept either.
  const unauthExpected = authStyle === 'api-gate' ? [401] : [302, 301, 401];
  const projectDeniedExpected = authStyle === 'api-gate' ? [401, 403] : [302, 403];

  // 1. No cookie
  await scenario('No cookie', null, unauthExpected);

  // 2. Expired JWT
  const expiredToken = await signJWT(makePayload([projectKey], { expired: true }), secret, kid);
  await scenario('Expired JWT', expiredToken, unauthExpected);

  // 3. Valid JWT, missing project
  const wrongProjectToken = await signJWT(makePayload(['other-project']), secret, kid);
  await scenario('Valid JWT, missing project', wrongProjectToken, projectDeniedExpected);

  // 4. Valid JWT, has project → 200
  const validToken = await signJWT(makePayload([projectKey]), secret, kid);
  await scenario('Valid JWT, has project', validToken, [200]);

  // 5. Malformed JWT
  await scenario('Malformed JWT', 'this.is.not-a-valid-jwt', unauthExpected);

  // 6. No projects claim (backward compat) → 200
  const noProjectsToken = await signJWT(makePayload(undefined), secret, kid);
  await scenario('No projects claim (compat)', noProjectsToken, [200]);

  // 7. Empty projects array
  const emptyProjectsToken = await signJWT(makePayload([]), secret, kid);
  await scenario('Empty projects array', emptyProjectsToken, projectDeniedExpected);

  return { passed, failed, results };
}

/**
 * Critical-endpoint auth tests for ego-development-app-api.
 *
 * Targets endpoints identified in the 2026-04-23 security review as
 * unauthenticated when they must not be. These tests assert the fix contract:
 * every unauthenticated call to these endpoints must return 401.
 */
async function testEgoCriticals() {
  console.log(`\n${COLORS.cyan}${COLORS.bold}Ego Assessment — Critical unauth endpoints${COLORS.reset}`);
  let passed = 0;
  let failed = 0;

  async function requireStatus(label, method, url, body, expected) {
    try {
      const opts = { method, headers: {}, redirect: 'manual' };
      if (body !== undefined) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
      }
      const resp = await fetch(url, opts);
      const status = resp.status;
      if (statusMatches(status, expected)) {
        console.log(pass(`${label} → ${status}`));
        passed++;
      } else {
        console.log(fail(`${label} → ${status}`, `expected ${expected.join('|')}`));
        failed++;
      }
    } catch (err) {
      console.log(fail(`${label} → ERROR`, err.message));
      failed++;
    }
  }

  // C2 — stem-stats POST must require auth (empty scores avoids any DB mutation)
  await requireStatus(
    'POST /api/stem-stats (no cookie)',
    'POST',
    'https://psychology.pragmaticdharma.org/api/stem-stats',
    { scores: {} },
    [401]
  );

  // C1 — deep-analysis GET must require auth (use nonexistent user_id to avoid side effects)
  await requireStatus(
    'GET /api/deep-analysis?user_id=... (no cookie)',
    'GET',
    'https://psychology.pragmaticdharma.org/api/deep-analysis?user_id=auth-test-nonexistent',
    undefined,
    [401]
  );

  // C1 — deep-analysis POST must require auth (nonexistent user_id will fail eligibility anyway,
  // but fix should reject at auth layer before any DB or Claude call)
  await requireStatus(
    'POST /api/deep-analysis start (no cookie)',
    'POST',
    'https://psychology.pragmaticdharma.org/api/deep-analysis',
    { action: 'start', user_id: 'auth-test-nonexistent', analysis_type: 'adaptive' },
    [401]
  );

  return { passed, failed };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

// Read each per-service JWT key from env, falling back to JWT_SECRET for any
// site whose key isn't explicitly set. Test JWTs need the same key the site
// itself verifies with (per-service post-Task #2).
function readKeys() {
  const fallback = process.env.JWT_SECRET;
  return {
    shield:           process.env.JWT_SECRET_SHIELD          || fallback,
    mindreader:       process.env.JWT_SECRET_MINDREADER      || fallback,
    psychtools:       process.env.JWT_SECRET_PSYCHTOOLS      || fallback,
    astrology:        process.env.JWT_SECRET_ASTROLOGY       || fallback,
    'ego-assessment': process.env.JWT_SECRET_EGO_ASSESSMENT  || fallback,
    practice:         process.env.JWT_SECRET_PRACTICE        || fallback,
    health:           process.env.JWT_SECRET_HEALTH          || fallback,
    bromnichord:      process.env.JWT_SECRET_BROMNICHORD     || fallback,
  };
}

async function main() {
  const keys = readKeys();
  const allKeysPresent = Object.values(keys).every(k => !!k);
  if (!allKeysPresent) {
    console.error(`${COLORS.red}Error: per-service JWT keys required. Set:${COLORS.reset}`);
    console.error('  JWT_SECRET_SHIELD, JWT_SECRET_MINDREADER, JWT_SECRET_PSYCHTOOLS,');
    console.error('  JWT_SECRET_ASTROLOGY, JWT_SECRET_EGO_ASSESSMENT, JWT_SECRET_PRACTICE,');
    console.error('  JWT_SECRET_HEALTH, JWT_SECRET_BROMNICHORD (or JWT_SECRET as a single fallback for all).');
    process.exit(2);
  }

  console.log(`${COLORS.bold}Auth Enforcement Tests${COLORS.reset}`);
  console.log(`${COLORS.dim}Testing 7 sites × 7 scenarios + 3 ego critical-endpoint tests = 52 tests${COLORS.reset}`);

  const sites = [
    { name: 'Psychic Shield', url: 'https://shield.pragmaticdharma.org/',                   projectKey: 'shield',          authStyle: 'worker-gate', kid: 'shield' },
    { name: 'Mind Reader',    url: 'https://mindreader.pragmaticdharma.org/',               projectKey: 'mindreader',      authStyle: 'worker-gate', kid: 'mindreader' },
    { name: 'PsychTools',     url: 'https://psychtools.pragmaticdharma.org/',               projectKey: 'psychtools',      authStyle: 'worker-gate', kid: 'psychtools' },
    { name: 'Bromnichord',    url: 'https://bromnichord.pragmaticdharma.org/',              projectKey: 'bromnichord',     authStyle: 'worker-gate', kid: 'bromnichord' },
    { name: 'Transit Viewer', url: 'https://astrology.pragmaticdharma.org/',                projectKey: 'astrology',       authStyle: 'worker-gate', kid: 'astrology' },
    { name: 'Ego Assessment', url: 'https://psychology.pragmaticdharma.org/api/profile',    projectKey: 'ego-assessment',  authStyle: 'api-gate',    kid: 'ego-assessment' },
    { name: 'Health Tracker', url: 'https://health.pragmaticdharma.org/api/mood/trends',    projectKey: 'health',          authStyle: 'api-gate',    kid: 'health' },
  ];

  let totalPassed = 0;
  let totalFailed = 0;

  for (const site of sites) {
    const secret = keys[site.kid];
    const { passed, failed } = await testSite(site.name, site.url, site.projectKey, secret, site.authStyle, site.kid);
    totalPassed += passed;
    totalFailed += failed;
  }

  const ego = await testEgoCriticals();
  totalPassed += ego.passed;
  totalFailed += ego.failed;

  // Summary
  console.log(`\n${COLORS.bold}Summary${COLORS.reset}`);
  console.log(`  ${COLORS.green}${totalPassed} passed${COLORS.reset}`);
  if (totalFailed > 0) {
    console.log(`  ${COLORS.red}${totalFailed} failed${COLORS.reset}`);
  }
  console.log();

  process.exit(totalFailed > 0 ? 1 : 0);
}

main();
