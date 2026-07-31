// /api/logout method contract. POST is the canonical form. GET is DEPRECATED
// but deliberately retained: the shared nav-bar "Sign out" is a plain <a href>
// (GET) baked into every deployed sub-project worker — see the router comment
// in worker.js. If GET is ever removed, this file is the test to flip.
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

test('GET /api/logout still works (deprecated, load-bearing for nav-bar <a href>)', async () => {
  const jwt = await mintSessionJwt();
  const resp = await worker.fetch(
    new Request(`${ORIGIN}/api/logout`, { headers: { Cookie: `pd_session=${jwt}` } }),
    env
  );
  assert.equal(resp.status, 302, 'GET must keep working until every sibling nav bar POSTs');
  assert.equal(await verifyJWT(env, jwt), null, 'JWT dead after GET logout');
});
