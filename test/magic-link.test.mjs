// Gap 3 (docs/pd-auth-delta.md): magic-link single-use must be atomic.
// Covers both verify paths (link click GET /api/verify/:token and 6-digit
// code POST /api/verify): happy path, reuse, and the concurrent double-claim
// race the old SELECT-then-UPDATE allowed.
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import worker, { verifyJWT } from '../worker.js';
import { makeEnv, seedUser, stubOutboundFetch, requestMagicLink, jsonRequest, getCookie, ORIGIN } from './helpers.mjs';

let env, mail;
const EMAIL = 'user@example.com';

beforeEach(() => {
  env = makeEnv();
  seedUser(env, { email: EMAIL, projects: ['shield'] });
  mail = stubOutboundFetch();
});

afterEach(() => mail.restore());

test('magic link click mints a session exactly once', async () => {
  const { rawToken } = await requestMagicLink(worker, env, mail, EMAIL);

  const first = await worker.fetch(new Request(`${ORIGIN}/api/verify/${rawToken}`), env);
  assert.equal(first.status, 302);
  const jwt = getCookie(first);
  assert.ok(jwt, 'expected pd_session cookie');
  const payload = await verifyJWT(env, jwt);
  assert.ok(payload, 'JWT must verify');
  assert.equal(payload.email, EMAIL);
  assert.ok(payload.sessionToken, 'JWT carries a session token');

  // Reuse is rejected.
  const second = await worker.fetch(new Request(`${ORIGIN}/api/verify/${rawToken}`), env);
  assert.equal(second.status, 400);
  assert.equal(getCookie(second), null);
});

test('concurrent double-click mints exactly one session', async () => {
  const { rawToken } = await requestMagicLink(worker, env, mail, EMAIL);

  const responses = await Promise.all([
    worker.fetch(new Request(`${ORIGIN}/api/verify/${rawToken}`), env),
    worker.fetch(new Request(`${ORIGIN}/api/verify/${rawToken}`), env),
  ]);
  const successes = responses.filter((r) => r.status === 302);
  assert.equal(successes.length, 1, `expected exactly one 302, got ${responses.map((r) => r.status)}`);

  const sessions = env.DB._sqlite.prepare('SELECT COUNT(*) AS cnt FROM sessions').get();
  assert.equal(sessions.cnt, 1, 'exactly one session row minted');
});

test('expired link is rejected', async () => {
  const { rawToken } = await requestMagicLink(worker, env, mail, EMAIL);
  env.DB._sqlite.prepare('UPDATE magic_links SET expires_at = ?').run(new Date(Date.now() - 60000).toISOString());

  const resp = await worker.fetch(new Request(`${ORIGIN}/api/verify/${rawToken}`), env);
  assert.equal(resp.status, 400);
  assert.equal(getCookie(resp), null);
});

test('6-digit code mints a session exactly once', async () => {
  const { code } = await requestMagicLink(worker, env, mail, EMAIL);

  const first = await worker.fetch(jsonRequest('/api/verify', { email: EMAIL, code }), env);
  assert.equal(first.status, 200);
  const jwt = getCookie(first);
  assert.ok(jwt, 'expected pd_session cookie');
  assert.ok(await verifyJWT(env, jwt), 'JWT must verify');

  // Reuse is rejected.
  const second = await worker.fetch(jsonRequest('/api/verify', { email: EMAIL, code }), env);
  assert.equal(second.status, 401);
});

test('concurrent code submissions mint exactly one session', async () => {
  const { code } = await requestMagicLink(worker, env, mail, EMAIL);

  const responses = await Promise.all([
    worker.fetch(jsonRequest('/api/verify', { email: EMAIL, code }), env),
    worker.fetch(jsonRequest('/api/verify', { email: EMAIL, code }), env),
  ]);
  const successes = responses.filter((r) => r.status === 200);
  assert.equal(successes.length, 1, `expected exactly one 200, got ${responses.map((r) => r.status)}`);

  const sessions = env.DB._sqlite.prepare('SELECT COUNT(*) AS cnt FROM sessions').get();
  assert.equal(sessions.cnt, 1, 'exactly one session row minted');
});

test('wrong code five times burns the active links (H5 regression)', async () => {
  await requestMagicLink(worker, env, mail, EMAIL);

  for (let i = 0; i < 5; i++) {
    const resp = await worker.fetch(jsonRequest('/api/verify', { email: EMAIL, code: '000000' }), env);
    assert.ok([401, 429].includes(resp.status));
  }
  const active = env.DB._sqlite.prepare('SELECT COUNT(*) AS cnt FROM magic_links WHERE used_at IS NULL').get();
  assert.equal(active.cnt, 0, 'all links burned after 5 failures');
});
