// /api/logout method contract (2026-10-11): only POST signs out. GET changes
// nothing — it serves a one-button confirm page that POSTs back — because
// sub-project nav bars still link here with a plain <a href>. See the router
// comment in worker.js.
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import worker, { verifyJWT, signJWT } from '../worker.js';
import { makeEnv, seedUser, stubOutboundFetch, sha256Hex, ORIGIN } from './helpers.mjs';

let env, mail, userId;

beforeEach(() => {
  env = makeEnv();
  userId = seedUser(env, { email: 'user@example.com' });
  mail = stubOutboundFetch();
});

afterEach(() => mail.restore());

async function mintSessionJwt() {
  const raw = 'sess-' + Math.random().toString(36).slice(2);
  const expiresAt = new Date(Date.now() + 30 * 86400000).toISOString();
  env.DB._sqlite.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .run(await sha256Hex(raw), userId, expiresAt);
  return signJWT(env, { sub: userId, email: 'user@example.com', name: 'T', role: 'user', projects: [], sessionToken: raw });
}

test('POST /api/logout revokes the session and clears the cookie', async () => {
  const jwt = await mintSessionJwt();
  const resp = await worker.fetch(
    new Request(`${ORIGIN}/api/logout`, { method: 'POST', headers: { Cookie: `pd_session=${jwt}` } }),
    env
  );
  assert.equal(resp.status, 302);
  assert.match(resp.headers.get('set-cookie'), /pd_session=;.*Max-Age=0/);
  assert.equal(await verifyJWT(env, jwt), null, 'JWT dead after POST logout');
});

test('GET /api/logout does not sign out: it serves the confirm page', async () => {
  const jwt = await mintSessionJwt();
  const resp = await worker.fetch(
    new Request(`${ORIGIN}/api/logout`, { headers: { Cookie: `pd_session=${jwt}` } }),
    env
  );
  assert.equal(resp.status, 200);
  assert.match(resp.headers.get('content-type'), /text\/html/);
  assert.equal(resp.headers.get('set-cookie'), null, 'GET must not clear the cookie');
  assert.ok(await verifyJWT(env, jwt), 'session still alive after GET (logout-CSRF closed)');
});

test('GET /api/logout with no session just goes home', async () => {
  const resp = await worker.fetch(new Request(`${ORIGIN}/api/logout`), env);
  assert.equal(resp.status, 302);
  assert.equal(resp.headers.get('location'), `${ORIGIN}/`);
});
