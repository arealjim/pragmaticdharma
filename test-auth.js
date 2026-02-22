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

async function signJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
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
 */

/**
 * Run all 7 test scenarios against a single site.
 * Returns { passed, failed, results[] }.
 */
async function testSite(name, url, projectKey, secret, authStyle) {
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

  // Expected statuses depend on auth style
  const unauthExpected = authStyle === 'api-gate' ? [401] : [302, 301, 401];
  const projectDeniedExpected = authStyle === 'api-gate' ? [401, 403] : [403];

  // 1. No cookie
  await scenario('No cookie', null, unauthExpected);

  // 2. Expired JWT
  const expiredToken = await signJWT(makePayload([projectKey], { expired: true }), secret);
  await scenario('Expired JWT', expiredToken, unauthExpected);

  // 3. Valid JWT, missing project
  const wrongProjectToken = await signJWT(makePayload(['other-project']), secret);
  await scenario('Valid JWT, missing project', wrongProjectToken, projectDeniedExpected);

  // 4. Valid JWT, has project → 200
  const validToken = await signJWT(makePayload([projectKey]), secret);
  await scenario('Valid JWT, has project', validToken, [200]);

  // 5. Malformed JWT
  await scenario('Malformed JWT', 'this.is.not-a-valid-jwt', unauthExpected);

  // 6. No projects claim (backward compat) → 200
  const noProjectsToken = await signJWT(makePayload(undefined), secret);
  await scenario('No projects claim (compat)', noProjectsToken, [200]);

  // 7. Empty projects array
  const emptyProjectsToken = await signJWT(makePayload([]), secret);
  await scenario('Empty projects array', emptyProjectsToken, projectDeniedExpected);

  return { passed, failed, results };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    console.error(`${COLORS.red}Error: JWT_SECRET environment variable is required.${COLORS.reset}`);
    console.error('Usage: JWT_SECRET=<value> node test-auth.js');
    process.exit(2);
  }

  console.log(`${COLORS.bold}Auth Enforcement Tests${COLORS.reset}`);
  console.log(`${COLORS.dim}Testing 4 sites × 7 scenarios = 28 tests${COLORS.reset}`);

  const sites = [
    { name: 'Psychic Shield', url: 'https://shield.pragmaticdharma.org/', projectKey: 'shield', authStyle: 'worker-gate' },
    { name: 'Mind Reader', url: 'https://mindreader.pragmaticdharma.org/', projectKey: 'mindreader', authStyle: 'worker-gate' },
    { name: 'Ego Assessment', url: 'https://psychology.pragmaticdharma.org/api/profile', projectKey: 'ego-assessment', authStyle: 'api-gate' },
    { name: 'Health Tracker', url: 'https://health.pragmaticdharma.org/api/mood/trends', projectKey: 'health', authStyle: 'api-gate' },
  ];

  let totalPassed = 0;
  let totalFailed = 0;

  for (const site of sites) {
    const { passed, failed } = await testSite(site.name, site.url, site.projectKey, secret, site.authStyle);
    totalPassed += passed;
    totalFailed += failed;
  }

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
