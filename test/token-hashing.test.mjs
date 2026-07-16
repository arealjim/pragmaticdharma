// Gap 2 (docs/pd-auth-delta.md): session + magic-link tokens are stored as
// SHA-256 hashes in D1. Raw tokens live only in the email link / JWT cookie.
// Also covers the legacy raw-row fallback (rows minted before the deploy).
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import worker, { verifyJWT, signJWT } from '../worker.js';
import { makeEnv, seedUser, stubOutboundFetch, requestMagicLink, getCookie, sha256Hex, ORIGIN } from './helpers.mjs';

let env, mail, userId;
const EMAIL = 'user@example.com';

beforeEach(() => {
  env = makeEnv();
  userId = seedUser(env, { email: EMAIL, projects: ['shield'] });
  mail = stubOutboundFetch();
});

afterEach(() => mail.restore());

function decodeJwtPayload(jwt) {
  const [, payload] = jwt.split('.');
  return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
}

test('magic-link token is stored hashed, not raw', async () => {
  const { rawToken } = await requestMagicLink(worker, env, mail, EMAIL);

  const row = env.DB._sqlite.prepare('SELECT token FROM magic_links').get();
  assert.notEqual(row.token, rawToken, 'raw token must not be at rest');
  assert.equal(row.token, await sha256Hex(rawToken));

  // And the raw token from the email still verifies (lookup hashes first).
  const resp = await worker.fetch(new Request(`${ORIGIN}/api/verify/${rawToken}`), env);
  assert.equal(resp.status, 302);
});

test('session token is stored hashed; JWT carries the raw token', async () => {
  const { rawToken } = await requestMagicLink(worker, env, mail, EMAIL);
  const resp = await worker.fetch(new Request(`${ORIGIN}/api/verify/${rawToken}`), env);
  const jwt = getCookie(resp);
  const { sessionToken } = decodeJwtPayload(jwt);

  const row = env.DB._sqlite.prepare('SELECT token FROM sessions').get();
  assert.notEqual(row.token, sessionToken, 'raw session token must not be at rest');
  assert.equal(row.token, await sha256Hex(sessionToken));

  // Revocation check still resolves the hashed row.
  assert.ok(await verifyJWT(env, jwt), 'JWT verifies against hashed session row');
});

test('logout revokes the hashed session row and kills the JWT', async () => {
  const { rawToken } = await requestMagicLink(worker, env, mail, EMAIL);
  const login = await worker.fetch(new Request(`${ORIGIN}/api/verify/${rawToken}`), env);
  const jwt = getCookie(login);
  assert.ok(await verifyJWT(env, jwt));

  const logout = await worker.fetch(new Request(`${ORIGIN}/api/logout`, { headers: { Cookie: `pd_session=${jwt}` } }), env);
  assert.equal(logout.status, 302);

  const row = env.DB._sqlite.prepare('SELECT revoked_at FROM sessions').get();
  assert.ok(row.revoked_at, 'session row revoked');
  assert.equal(await verifyJWT(env, jwt), null, 'revoked JWT no longer verifies at the hub');
});

test('legacy raw magic-link row still verifies (pre-deploy fallback)', async () => {
  const raw = 'a'.repeat(64);
  env.DB._sqlite.prepare('INSERT INTO magic_links (token, code, email, user_id, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(raw, '123456', EMAIL, userId, new Date(Date.now() + 15 * 60000).toISOString());

  const resp = await worker.fetch(new Request(`${ORIGIN}/api/verify/${raw}`), env);
  assert.equal(resp.status, 302);
  assert.ok(getCookie(resp));
});

test('legacy raw session row still verifies and can be revoked (pre-deploy fallback)', async () => {
  const raw = 'b'.repeat(64);
  env.DB._sqlite.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .run(raw, userId, new Date(Date.now() + 30 * 86400000).toISOString());
  const jwt = await signJWT(env, {
    sub: userId, email: EMAIL, name: 'Test User', role: 'user', projects: ['shield'], sessionToken: raw,
  });

  assert.ok(await verifyJWT(env, jwt), 'legacy raw session row accepted');

  const logout = await worker.fetch(new Request(`${ORIGIN}/api/logout`, { headers: { Cookie: `pd_session=${jwt}` } }), env);
  assert.equal(logout.status, 302);
  const row = env.DB._sqlite.prepare('SELECT revoked_at FROM sessions WHERE token = ?').get(raw);
  assert.ok(row.revoked_at, 'legacy row revoked');
  assert.equal(await verifyJWT(env, jwt), null);
});

test('JWT with an unknown session token is rejected', async () => {
  const jwt = await signJWT(env, {
    sub: userId, email: EMAIL, name: 'Test User', role: 'user', projects: ['shield'], sessionToken: 'c'.repeat(64),
  });
  assert.equal(await verifyJWT(env, jwt), null);
});
