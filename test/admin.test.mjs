// handleAdmin coverage: the H1 CSRF Origin/Referer guard on state-changing
// methods, admin-JWT authz, approve/reject paths, and the M7/M8 config key
// allowlist. TODO item "found 2026-07-17".
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import worker, { signJWT } from '../worker.js';
import { makeEnv, seedUser, stubOutboundFetch, ORIGIN } from './helpers.mjs';
import { KNOWN_PROJECTS } from '../src/registry.js';

const PLATFORM_ORIGIN = 'https://pragmaticdharma.org';

let env, mail, adminJwt;

beforeEach(async () => {
  env = makeEnv();
  mail = stubOutboundFetch();
  const adminId = seedUser(env, { email: 'admin@example.com', name: 'Admin', role: 'admin' });
  // No sessionToken claim → verifyJWT skips the sessions-table lookup; the
  // revocation path has its own coverage in token-hashing.test.mjs.
  adminJwt = await signJWT(env, { sub: adminId, email: 'admin@example.com', name: 'Admin', role: 'admin', projects: [] });
});

afterEach(() => mail.restore());

function adminPost(route, body, { jwt = adminJwt, headers = {} } = {}) {
  return worker.fetch(
    new Request(`${ORIGIN}/api/admin/${route}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(jwt ? { Cookie: `pd_session=${jwt}` } : {}), ...headers },
      body: JSON.stringify(body),
    }),
    env
  );
}

function adminGet(route, { jwt = adminJwt } = {}) {
  return worker.fetch(
    new Request(`${ORIGIN}/api/admin/${route}`, {
      headers: jwt ? { Cookie: `pd_session=${jwt}` } : {},
    }),
    env
  );
}

// ---------------------------------------------------------------------------
// H1 CSRF guard (state-changing methods only)
// ---------------------------------------------------------------------------

test('POST with no Origin and no Referer → 403 CSRF, even with a valid admin JWT', async () => {
  const resp = await adminPost('approve', { email: 'x@example.com' });
  assert.equal(resp.status, 403);
  assert.match((await resp.json()).error, /CSRF/);
});

test('POST with a foreign Origin → 403 CSRF', async () => {
  const resp = await adminPost('approve', { email: 'x@example.com' }, { headers: { Origin: 'https://evil.example.com' } });
  assert.equal(resp.status, 403);
  assert.match((await resp.json()).error, /CSRF/);
});

test('POST with a sub-project Origin → 403 CSRF (compromised sibling cannot drive admin)', async () => {
  const resp = await adminPost('approve', { email: 'x@example.com' }, { headers: { Origin: 'https://shield.pragmaticdharma.org' } });
  assert.equal(resp.status, 403);
});

test('POST with the platform Origin passes the guard', async () => {
  seedUser(env, { email: 'p@example.com', status: 'pending' });
  const resp = await adminPost('approve', { email: 'p@example.com' }, { headers: { Origin: PLATFORM_ORIGIN } });
  assert.equal(resp.status, 200);
});

test('POST with no Origin but a platform Referer passes the guard', async () => {
  seedUser(env, { email: 'p@example.com', status: 'pending' });
  const resp = await adminPost('approve', { email: 'p@example.com' }, { headers: { Referer: `${PLATFORM_ORIGIN}/admin` } });
  assert.equal(resp.status, 200);
});

test('GET routes are exempt from the CSRF guard', async () => {
  const resp = await adminGet('pending');
  assert.equal(resp.status, 200);
});

// ---------------------------------------------------------------------------
// Authz
// ---------------------------------------------------------------------------

test('no JWT → 401; non-admin JWT → 403', async () => {
  const anon = await adminGet('users', { jwt: null });
  assert.equal(anon.status, 401);

  const userId = seedUser(env, { email: 'user@example.com', role: 'user' });
  const userJwt = await signJWT(env, { sub: userId, email: 'user@example.com', name: 'U', role: 'user', projects: [] });
  const forbidden = await adminGet('users', { jwt: userJwt });
  assert.equal(forbidden.status, 403);
});

// ---------------------------------------------------------------------------
// approve / reject
// ---------------------------------------------------------------------------

test('approve: pending user becomes approved, gets every project, approval email sent', async () => {
  seedUser(env, { email: 'new@example.com', status: 'pending' });
  const resp = await adminPost('approve', { email: 'new@example.com' }, { headers: { Origin: PLATFORM_ORIGIN } });
  assert.equal(resp.status, 200);
  assert.deepEqual(await resp.json(), { ok: true });

  const user = env.DB._sqlite.prepare("SELECT * FROM users WHERE email = 'new@example.com'").get();
  assert.equal(user.status, 'approved');
  const grants = env.DB._sqlite.prepare('SELECT project FROM user_projects WHERE user_id = ?').all(user.id).map((r) => r.project);
  assert.deepEqual(grants.sort(), [...KNOWN_PROJECTS].sort());
  assert.ok(mail.calls.some((c) => c.url.includes('api.resend.com')), 'approval email attempted via Resend');
});

test('approve without an email → 400', async () => {
  const resp = await adminPost('approve', {}, { headers: { Origin: PLATFORM_ORIGIN } });
  assert.equal(resp.status, 400);
});

test('reject: user status flips to rejected', async () => {
  seedUser(env, { email: 'bad@example.com', status: 'pending' });
  const resp = await adminPost('reject', { email: 'bad@example.com' }, { headers: { Origin: PLATFORM_ORIGIN } });
  assert.equal(resp.status, 200);
  const user = env.DB._sqlite.prepare("SELECT status FROM users WHERE email = 'bad@example.com'").get();
  assert.equal(user.status, 'rejected');
});

// ---------------------------------------------------------------------------
// M7/M8 config key allowlist
// ---------------------------------------------------------------------------

test('config POST accepts open_beta and open_beta:<project> keys', async () => {
  const resp = await adminPost('config', { open_beta: 'true', 'open_beta:shield': 'true' }, { headers: { Origin: PLATFORM_ORIGIN } });
  assert.equal(resp.status, 200);
  // node:sqlite rows have a null prototype; rebuild as plain objects for deepEqual.
  const rows = env.DB._sqlite.prepare('SELECT key, value FROM config ORDER BY key').all()
    .map((r) => ({ key: r.key, value: r.value }));
  assert.deepEqual(rows, [
    { key: 'open_beta', value: 'true' },
    { key: 'open_beta:shield', value: 'true' },
  ]);
});

test('config POST rejects keys outside the allowlist and does not write them', async () => {
  const resp = await adminPost(
    'config',
    { open_beta: 'true', evil_key: 'x', open_betamax: 'y' },
    { headers: { Origin: PLATFORM_ORIGIN } }
  );
  assert.equal(resp.status, 400);
  const body = await resp.json();
  assert.deepEqual(body.rejected.sort(), ['evil_key', 'open_betamax'], 'prefix match must not accept open_betamax');
  const keys = env.DB._sqlite.prepare('SELECT key FROM config').all().map((r) => r.key);
  assert.deepEqual(keys, ['open_beta'], 'allowlisted key written, everything else dropped');
});

test('config GET filters out rows that are not allowlisted', async () => {
  // schema.sql pre-seeds open_beta='false'; add only the stray key.
  env.DB._sqlite.prepare("INSERT INTO config (key, value) VALUES ('some_secret', 'hunter2')").run();
  const resp = await adminGet('config');
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.deepEqual(body.config, { open_beta: 'false' }, 'non-allowlisted rows must never leave the API');
});
