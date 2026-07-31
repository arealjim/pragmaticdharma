// handleRefreshSession coverage (fresh-claims re-issue, M6 status re-check,
// kid re-selection, sessionToken preservation) plus direct unit tests for
// validateRedirectUrl's allowlist. TODO item "found 2026-07-17".
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import worker, { verifyJWT, signJWT, validateRedirectUrl } from '../worker.js';
import { makeEnv, seedUser, stubOutboundFetch, sha256Hex, getCookie, ORIGIN } from './helpers.mjs';

const EMAIL = 'user@example.com';
const LOGIN_BASE = 'https://pragmaticdharma.org/login';

let env, mail, userId;

beforeEach(() => {
  env = makeEnv();
  userId = seedUser(env, { email: EMAIL, projects: ['shield'] });
  mail = stubOutboundFetch();
});

afterEach(() => mail.restore());

async function seedSession(uid = userId) {
  const raw = 'sess-' + Math.random().toString(36).slice(2);
  const expiresAt = new Date(Date.now() + 30 * 86400000).toISOString();
  env.DB._sqlite.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .run(await sha256Hex(raw), uid, expiresAt);
  return raw;
}

function refreshRequest(redirect, jwt) {
  const url = redirect
    ? `${ORIGIN}/api/refresh-session?redirect=${encodeURIComponent(redirect)}`
    : `${ORIGIN}/api/refresh-session`;
  return new Request(url, { headers: jwt ? { Cookie: `pd_session=${jwt}` } : {} });
}

function decodeJwt(jwt) {
  const [h, p] = jwt.split('.');
  const un64 = (s) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/')));
  return { header: un64(h), payload: un64(p) };
}

// ---------------------------------------------------------------------------
// handleRefreshSession
// ---------------------------------------------------------------------------

test('no cookie → 302 to login, preserving a valid redirect', async () => {
  const redirect = 'https://shield.pragmaticdharma.org/';
  const resp = await worker.fetch(refreshRequest(redirect, null), env);
  assert.equal(resp.status, 302);
  assert.equal(resp.headers.get('location'), `${LOGIN_BASE}?redirect=${encodeURIComponent(redirect)}`);
});

test('revoked session → 302 to login, no new cookie', async () => {
  const sessionToken = await seedSession();
  env.DB._sqlite.prepare("UPDATE sessions SET revoked_at = datetime('now')").run();
  const jwt = await signJWT(env, { sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken });
  const resp = await worker.fetch(refreshRequest('https://shield.pragmaticdharma.org/', jwt), env);
  assert.equal(resp.status, 302);
  assert.ok(resp.headers.get('location').startsWith(LOGIN_BASE));
  assert.equal(getCookie(resp), null);
});

test('M6: user rejected after JWT issue → 302 to login, no re-issue', async () => {
  const sessionToken = await seedSession();
  const jwt = await signJWT(env, { sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken });
  env.DB._sqlite.prepare("UPDATE users SET status = 'rejected' WHERE id = ?").run(userId);
  const resp = await worker.fetch(refreshRequest('https://shield.pragmaticdharma.org/', jwt), env);
  assert.equal(resp.status, 302);
  assert.ok(resp.headers.get('location').startsWith(LOGIN_BASE));
  assert.equal(getCookie(resp), null);
});

test('valid refresh re-reads projects from D1 and preserves sessionToken', async () => {
  const sessionToken = await seedSession();
  const jwt = await signJWT(env, { sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken });
  // Admin grants a new project after the JWT was minted.
  env.DB._sqlite.prepare('INSERT INTO user_projects (user_id, project) VALUES (?, ?)').run(userId, 'astrology');

  const redirect = 'https://shield.pragmaticdharma.org/briefing';
  const resp = await worker.fetch(refreshRequest(redirect, jwt), env);
  assert.equal(resp.status, 302);
  assert.equal(resp.headers.get('location'), redirect);

  const newJwt = getCookie(resp);
  assert.ok(newJwt, 'must set a fresh pd_session cookie');
  const { payload } = decodeJwt(newJwt);
  assert.deepEqual(payload.projects.sort(), ['astrology', 'shield'], 'claims re-read from D1');
  assert.equal(payload.sessionToken, sessionToken, 'H4: sessionToken preserved so revocation still works');
  assert.ok(await verifyJWT(env, newJwt), 'new JWT verifies');
});

test('redirect destination selects the signing kid (Task #2)', async () => {
  const sessionToken = await seedSession();
  const jwt = await signJWT(env, { sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken });
  const resp = await worker.fetch(refreshRequest('https://shield.pragmaticdharma.org/', jwt), env);
  const { header } = decodeJwt(getCookie(resp));
  assert.equal(header.kid, 'shield', 'JWT re-signed with the destination service key');
});

test('disallowed redirect is dropped: lands on / with a platform-kid JWT', async () => {
  const sessionToken = await seedSession();
  const jwt = await signJWT(env, { sub: userId, email: EMAIL, name: 'T', role: 'user', projects: ['shield'], sessionToken });
  const resp = await worker.fetch(refreshRequest('https://evil.example.com/', jwt), env);
  assert.equal(resp.status, 302);
  assert.equal(resp.headers.get('location'), '/', 'unlisted host must not be used as a redirect');
  const { header } = decodeJwt(getCookie(resp));
  assert.equal(header.kid, 'pragmaticdharma');
});

// ---------------------------------------------------------------------------
// validateRedirectUrl allowlist
// ---------------------------------------------------------------------------

test('validateRedirectUrl accepts allowlisted https hosts', () => {
  for (const url of [
    'https://pragmaticdharma.org/',
    'https://retreats.pragmaticdharma.org/schedule',
    'https://shield.pragmaticdharma.org/briefing?d=today',
    'https://boardreview.pragmaticdharma.org/',
  ]) {
    assert.equal(validateRedirectUrl(url), url, `${url} should be allowed`);
  }
});

test('validateRedirectUrl rejects non-https schemes', () => {
  assert.equal(validateRedirectUrl('http://shield.pragmaticdharma.org/'), '');
  assert.equal(validateRedirectUrl('javascript:alert(1)'), '');
  assert.equal(validateRedirectUrl('//shield.pragmaticdharma.org/'), '');
});

test('validateRedirectUrl rejects hosts outside the allowlist', () => {
  assert.equal(validateRedirectUrl('https://evil.example.com/'), '');
  assert.equal(validateRedirectUrl('https://pragmaticdharma.org.evil.com/'), '', 'suffix-spoofed host');
  assert.equal(validateRedirectUrl('https://shield.pragmaticdharma.org.evil.com/'), '', 'prefix-spoofed host');
  assert.equal(validateRedirectUrl('https://unknown.pragmaticdharma.org/'), '', 'unregistered subdomain');
});

test('validateRedirectUrl rejects garbage input', () => {
  assert.equal(validateRedirectUrl(''), '');
  assert.equal(validateRedirectUrl(null), '');
  assert.equal(validateRedirectUrl(undefined), '');
  assert.equal(validateRedirectUrl(42), '');
  assert.equal(validateRedirectUrl('not a url'), '');
});
