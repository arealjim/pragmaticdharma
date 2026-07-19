// Covers the 24h JWT TTL + lazy-refresh design (docs/design-session-revocation.md).
// Tests verifyJWTForRefresh and the /login lazy-refresh + loop-guard paths.
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import worker, { verifyJWT, verifyJWTForRefresh, signJWT } from '../worker.js';
import { makeEnv, seedUser, stubOutboundFetch, sha256Hex, mintExpiredJWT, getCookie, ORIGIN } from './helpers.mjs';

const EMAIL = 'user@example.com';
let env, mail, userId;

beforeEach(() => {
  env = makeEnv();
  userId = seedUser(env, { email: EMAIL, projects: ['shield'] });
  mail = stubOutboundFetch();
});

afterEach(() => mail.restore());

// Helper: insert a live session row and return the raw sessionToken string
async function seedSession(expiresInDays = 30) {
  const raw = 'sess-' + Math.random().toString(36).slice(2);
  const expiresAt = new Date(Date.now() + expiresInDays * 86400000).toISOString();
  env.DB._sqlite.prepare(
    'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
  ).run(await sha256Hex(raw), userId, expiresAt);
  return raw;
}

// ---------------------------------------------------------------------------
// verifyJWTForRefresh
// ---------------------------------------------------------------------------

test('verifyJWTForRefresh accepts a non-expired JWT (skips exp is not the only case)', async () => {
  const sessionToken = await seedSession();
  const jwt = await signJWT(env, { sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken });
  assert.ok(await verifyJWTForRefresh(env, jwt), 'live JWT should verify for refresh');
});

test('verifyJWTForRefresh accepts an expired JWT with a live session row', async () => {
  const sessionToken = await seedSession();
  const expiredJwt = await mintExpiredJWT(env, {
    sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken,
  });
  // verifyJWT should reject it (exp in the past)
  assert.equal(await verifyJWT(env, expiredJwt), null, 'verifyJWT must reject expired token');
  // verifyJWTForRefresh should accept it (live session row)
  assert.ok(await verifyJWTForRefresh(env, expiredJwt), 'verifyJWTForRefresh must accept expired token with live row');
});

test('verifyJWTForRefresh rejects a revoked session', async () => {
  const sessionToken = await seedSession();
  env.DB._sqlite.prepare("UPDATE sessions SET revoked_at = datetime('now') WHERE token = ?")
    .run(await sha256Hex(sessionToken));
  const expiredJwt = await mintExpiredJWT(env, {
    sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken,
  });
  assert.equal(await verifyJWTForRefresh(env, expiredJwt), null, 'revoked session must be rejected');
});

test('verifyJWTForRefresh rejects when session row is past its own expires_at', async () => {
  const sessionToken = await seedSession(-1); // expired yesterday
  const expiredJwt = await mintExpiredJWT(env, {
    sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken,
  });
  assert.equal(await verifyJWTForRefresh(env, expiredJwt), null, 'row-expired session must be rejected');
});

test('verifyJWTForRefresh rejects bad signature', async () => {
  const sessionToken = await seedSession();
  const expiredJwt = await mintExpiredJWT(env, {
    sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken,
  });
  const tampered = expiredJwt.slice(0, -4) + 'XXXX';
  assert.equal(await verifyJWTForRefresh(env, tampered), null, 'tampered signature must be rejected');
});

// ---------------------------------------------------------------------------
// JWT_TTL_SECONDS: newly minted JWTs must expire in ~24h
// ---------------------------------------------------------------------------

test('newly minted JWT expires within 24h + 5s clock skew', async () => {
  const jwt = await signJWT(env, { sub: userId, email: EMAIL, name: 'T', role: 'user', projects: [] });
  const parts = jwt.split('.');
  const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
  const now = Math.floor(Date.now() / 1000);
  assert.ok(payload.exp > now, 'exp must be in the future');
  assert.ok(payload.exp <= now + 86400 + 5, 'exp must be within 24h + 5s skew');
});

// ---------------------------------------------------------------------------
// GET /login lazy refresh
// ---------------------------------------------------------------------------

test('/login without a redirect param serves login page even with a valid session', async () => {
  const sessionToken = await seedSession();
  const jwt = await signJWT(env, { sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken });
  const req = new Request(`${ORIGIN}/login`, { headers: { Cookie: `pd_session=${jwt}` } });
  const resp = await worker.fetch(req, env);
  assert.equal(resp.status, 200, 'no redirect without redirect param');
  assert.equal(resp.headers.get('location'), null, 'must not redirect');
});

test('/login with redirect + expired JWT + live session → silent 302 back to redirect', async () => {
  const sessionToken = await seedSession();
  const expiredJwt = await mintExpiredJWT(env, {
    sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken,
  });
  const redirectUrl = 'https://shield.pragmaticdharma.org/';
  const req = new Request(
    `${ORIGIN}/login?redirect=${encodeURIComponent(redirectUrl)}`,
    { headers: { Cookie: `pd_session=${expiredJwt}` } }
  );
  const resp = await worker.fetch(req, env);
  assert.equal(resp.status, 302, 'must redirect');
  assert.equal(resp.headers.get('location'), redirectUrl, 'must redirect to the requested URL');
  const newJwt = getCookie(resp);
  assert.ok(newJwt, 'must set a new pd_session cookie');
  assert.ok(await verifyJWT(env, newJwt), 'new JWT must verify');
});

test('/login lazy refresh sets pd_lr loop-guard cookie on silent redirect', async () => {
  const sessionToken = await seedSession();
  const expiredJwt = await mintExpiredJWT(env, {
    sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken,
  });
  const req = new Request(
    `${ORIGIN}/login?redirect=${encodeURIComponent('https://shield.pragmaticdharma.org/')}`,
    { headers: { Cookie: `pd_session=${expiredJwt}` } }
  );
  const resp = await worker.fetch(req, env);
  assert.equal(resp.status, 302);
  const setCookies = resp.headers.getSetCookie ? resp.headers.getSetCookie()
    : [resp.headers.get('set-cookie') || ''];
  const lrCookie = setCookies.find(c => c.startsWith('pd_lr=1'));
  assert.ok(lrCookie, 'must set pd_lr=1 loop-guard cookie');
});

test('/login loop guard: pd_lr cookie present → serve login page, clear guard', async () => {
  const sessionToken = await seedSession();
  const expiredJwt = await mintExpiredJWT(env, {
    sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken,
  });
  const req = new Request(
    `${ORIGIN}/login?redirect=${encodeURIComponent('https://shield.pragmaticdharma.org/')}`,
    { headers: { Cookie: `pd_session=${expiredJwt}; pd_lr=1` } }
  );
  const resp = await worker.fetch(req, env);
  assert.equal(resp.status, 200, 'loop guard must prevent redirect and serve login page');
  assert.equal(resp.headers.get('location'), null, 'must not redirect');
  const setCookies = resp.headers.getSetCookie ? resp.headers.getSetCookie()
    : [resp.headers.get('set-cookie') || ''];
  const clearCookie = setCookies.find(c => c.startsWith('pd_lr=;') || (c.startsWith('pd_lr=') && c.includes('Max-Age=0')));
  assert.ok(clearCookie, 'must clear the pd_lr cookie');
});

test('/login with redirect + revoked session → serve login page', async () => {
  const sessionToken = await seedSession();
  env.DB._sqlite.prepare("UPDATE sessions SET revoked_at = datetime('now') WHERE token = ?")
    .run(await sha256Hex(sessionToken));
  const expiredJwt = await mintExpiredJWT(env, {
    sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken,
  });
  const req = new Request(
    `${ORIGIN}/login?redirect=${encodeURIComponent('https://shield.pragmaticdharma.org/')}`,
    { headers: { Cookie: `pd_session=${expiredJwt}` } }
  );
  const resp = await worker.fetch(req, env);
  assert.equal(resp.status, 200, 'revoked session must land on login page');
  assert.equal(resp.headers.get('location'), null, 'must not redirect');
});
