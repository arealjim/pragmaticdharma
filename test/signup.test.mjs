// handleSignup coverage: per-IP + global rate limits, input validation,
// duplicate handling, the M10 30-day rejected-user cooldown, and open-beta
// auto-approval (global and per-project). TODO item "found 2026-07-17".
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import worker from '../worker.js';
import { makeEnv, stubOutboundFetch, jsonRequest, ORIGIN } from './helpers.mjs';
import { KNOWN_PROJECTS } from '../src/registry.js';

let env, mail;

beforeEach(() => {
  env = makeEnv();
  // makeEnv() sets no webhook, which silently disables notifyDiscord — bind one
  // so the Discord-notification assertions actually exercise the code path.
  env.DISCORD_WEBHOOK_URL = 'https://discord.test/webhook';
  mail = stubOutboundFetch();
});

afterEach(() => mail.restore());

function signupRequest(body, ip = '203.0.113.9') {
  return jsonRequest('/api/signup', body, { 'CF-Connecting-IP': ip });
}

function getUser(email) {
  return env.DB._sqlite.prepare('SELECT * FROM users WHERE email = ?').get(email);
}

function getGrants(email) {
  return env.DB._sqlite.prepare(
    'SELECT project FROM user_projects JOIN users ON users.id = user_projects.user_id WHERE users.email = ?'
  ).all(email).map((r) => r.project);
}

function discordCalls() {
  return mail.calls.filter((c) => c.url.includes('discord'));
}

// ---------------------------------------------------------------------------
// Rate limits
// ---------------------------------------------------------------------------

test('per-IP limit: 6th signup attempt from one IP within an hour → 429', async () => {
  for (let i = 0; i < 5; i++) {
    const resp = await worker.fetch(signupRequest({ name: `U${i}`, email: `u${i}@example.com` }), env);
    assert.equal(resp.status, 200, `attempt ${i + 1} should pass the IP limit`);
  }
  const sixth = await worker.fetch(signupRequest({ name: 'U6', email: 'u6@example.com' }), env);
  assert.equal(sixth.status, 429);
  assert.match((await sixth.json()).error, /your IP/i);
  assert.equal(getUser('u6@example.com'), undefined, 'blocked signup must not create a user');
});

test('per-IP limit counts attempts, not successes (garbage JSON still burns the budget)', async () => {
  for (let i = 0; i < 5; i++) {
    const resp = await worker.fetch(
      new Request(`${ORIGIN}/api/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.9' },
        body: 'not json',
      }),
      env
    );
    assert.equal(resp.status, 400);
  }
  const next = await worker.fetch(signupRequest({ name: 'Real', email: 'real@example.com' }), env);
  assert.equal(next.status, 429, 'failed attempts still count toward the per-IP cap');
});

test('per-IP limit is per IP: a different IP is unaffected', async () => {
  env.DB._sqlite.prepare(
    "INSERT INTO access_logs (project, ip_address, path) " +
    "SELECT 'platform-signup', '203.0.113.9', '/api/signup' FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5)"
  ).run();
  const blocked = await worker.fetch(signupRequest({ name: 'A', email: 'a@example.com' }, '203.0.113.9'), env);
  assert.equal(blocked.status, 429);
  const allowed = await worker.fetch(signupRequest({ name: 'B', email: 'b@example.com' }, '198.51.100.7'), env);
  assert.equal(allowed.status, 200);
});

test('global limit: 20 users created in the last hour → 429 (backstop)', async () => {
  const insert = env.DB._sqlite.prepare('INSERT INTO users (email, name, status) VALUES (?, ?, ?)');
  for (let i = 0; i < 20; i++) insert.run(`bulk${i}@example.com`, `Bulk ${i}`, 'pending');
  const resp = await worker.fetch(signupRequest({ name: 'Late', email: 'late@example.com' }), env);
  assert.equal(resp.status, 429);
  assert.match((await resp.json()).error, /Too many signups/);
});

// ---------------------------------------------------------------------------
// Validation + duplicates
// ---------------------------------------------------------------------------

test('missing name or invalid email → 400', async () => {
  const noName = await worker.fetch(signupRequest({ email: 'x@example.com' }), env);
  assert.equal(noName.status, 400);
  const badEmail = await worker.fetch(signupRequest({ name: 'X', email: 'not-an-email' }, '198.51.100.1'), env);
  assert.equal(badEmail.status, 400);
});

test('existing approved or pending user → 409', async () => {
  env.DB._sqlite.prepare("INSERT INTO users (email, name, status) VALUES ('ok@example.com', 'Ok', 'approved')").run();
  env.DB._sqlite.prepare("INSERT INTO users (email, name, status) VALUES ('wait@example.com', 'Wait', 'pending')").run();
  const approved = await worker.fetch(signupRequest({ name: 'Ok', email: 'ok@example.com' }), env);
  assert.equal(approved.status, 409);
  const pending = await worker.fetch(signupRequest({ name: 'Wait', email: 'wait@example.com' }, '198.51.100.2'), env);
  assert.equal(pending.status, 409);
});

// ---------------------------------------------------------------------------
// M10: rejected-user 30-day cooldown
// ---------------------------------------------------------------------------

test('rejected user inside 30-day cooldown: generic ok, no status change, no Discord', async () => {
  env.DB._sqlite.prepare(
    "INSERT INTO users (email, name, status, updated_at) VALUES ('rej@example.com', 'Rej', 'rejected', datetime('now', '-5 days'))"
  ).run();
  const resp = await worker.fetch(signupRequest({ name: 'Rej Again', email: 'rej@example.com' }), env);
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.deepEqual(body, { ok: true, autoApproved: false }, 'must be indistinguishable from a fresh signup');
  assert.equal(getUser('rej@example.com').status, 'rejected', 'status must not change during cooldown');
  assert.equal(discordCalls().length, 0, 'no admin-channel notification during cooldown');
});

test('rejected user past the 30-day cooldown: re-signup accepted, back to pending, Discord fired', async () => {
  env.DB._sqlite.prepare(
    "INSERT INTO users (email, name, status, updated_at) VALUES ('old@example.com', 'Old Name', 'rejected', datetime('now', '-31 days'))"
  ).run();
  const resp = await worker.fetch(signupRequest({ name: 'New Name', email: 'old@example.com', note: 'please' }), env);
  assert.equal(resp.status, 200);
  assert.deepEqual(await resp.json(), { ok: true, autoApproved: false });
  const user = getUser('old@example.com');
  assert.equal(user.status, 'pending');
  assert.equal(user.name, 'New Name');
  assert.equal(discordCalls().length, 1, 're-signup notification fired after cooldown');
});

// ---------------------------------------------------------------------------
// Open-beta auto-approval
// ---------------------------------------------------------------------------

test('no beta: fresh signup lands pending with no project grants', async () => {
  const resp = await worker.fetch(signupRequest({ name: 'P', email: 'p@example.com' }), env);
  assert.equal(resp.status, 200);
  assert.deepEqual(await resp.json(), { ok: true, autoApproved: false });
  assert.equal(getUser('p@example.com').status, 'pending');
  assert.deepEqual(getGrants('p@example.com'), []);
});

test('global open beta: auto-approved with every known project granted', async () => {
  env.DB._sqlite.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('open_beta', 'true')").run();
  const resp = await worker.fetch(signupRequest({ name: 'Beta', email: 'beta@example.com' }), env);
  assert.equal(resp.status, 200);
  assert.deepEqual(await resp.json(), { ok: true, autoApproved: true });
  assert.equal(getUser('beta@example.com').status, 'approved');
  assert.deepEqual(getGrants('beta@example.com').sort(), [...KNOWN_PROJECTS].sort());
});

test('per-project open beta: redirect URL maps to project key, grants only that project', async () => {
  env.DB._sqlite.prepare("INSERT INTO config (key, value) VALUES ('open_beta:shield', 'true')").run();
  const resp = await worker.fetch(
    signupRequest({ name: 'S', email: 's@example.com', project: 'https://shield.pragmaticdharma.org/briefing' }),
    env
  );
  assert.equal(resp.status, 200);
  assert.deepEqual(await resp.json(), { ok: true, autoApproved: true });
  assert.equal(getUser('s@example.com').status, 'approved');
  assert.deepEqual(getGrants('s@example.com'), ['shield']);
});

test('per-project beta for an unknown project key does not auto-approve', async () => {
  env.DB._sqlite.prepare("INSERT INTO config (key, value) VALUES ('open_beta:shield', 'true')").run();
  const resp = await worker.fetch(
    signupRequest({ name: 'N', email: 'n@example.com', project: 'https://evil.example.com/' }),
    env
  );
  assert.equal(resp.status, 200);
  assert.deepEqual(await resp.json(), { ok: true, autoApproved: false });
  assert.equal(getUser('n@example.com').status, 'pending');
});
