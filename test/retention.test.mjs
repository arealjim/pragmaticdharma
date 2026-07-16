// Retention sweep (M4 + pd-auth-delta gap 2 follow-through): the daily cron
// purges stale access_logs and now also expired magic_links / sessions rows.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import worker from '../worker.js';
import { makeEnv, seedUser } from './helpers.mjs';

function iso(msFromNow) {
  return new Date(Date.now() + msFromNow).toISOString();
}

test('scheduled sweep purges expired auth rows but keeps live ones', async () => {
  const env = makeEnv();
  const userId = seedUser(env);
  const db = env.DB._sqlite;
  const DAY = 86400000;

  // Magic links: one stale (2 days old), one fresh.
  db.prepare("INSERT INTO magic_links (token, code, email, user_id, expires_at, created_at) VALUES (?, '111111', 'user@example.com', ?, ?, datetime('now', '-2 days'))")
    .run('stale-link', userId, iso(-2 * DAY + 900000));
  db.prepare("INSERT INTO magic_links (token, code, email, user_id, expires_at) VALUES (?, '222222', 'user@example.com', ?, ?)")
    .run('fresh-link', userId, iso(900000));

  // Sessions: one expired 10 days ago, one expired yesterday (inside the
  // 7-day grace), one live.
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run('long-dead', userId, iso(-10 * DAY));
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run('just-dead', userId, iso(-1 * DAY));
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run('live', userId, iso(30 * DAY));

  // Access logs: one 100 days old, one fresh (M4 regression check).
  db.prepare("INSERT INTO access_logs (project, created_at) VALUES ('platform-login', datetime('now', '-100 days'))").run();
  db.prepare("INSERT INTO access_logs (project) VALUES ('platform-login')").run();

  const pending = [];
  await worker.scheduled({}, env, { waitUntil: (p) => pending.push(p) });
  await Promise.all(pending);

  const links = db.prepare('SELECT token FROM magic_links ORDER BY token').all().map((r) => r.token);
  assert.deepEqual(links, ['fresh-link']);

  const sessions = db.prepare('SELECT token FROM sessions ORDER BY token').all().map((r) => r.token);
  assert.deepEqual(sessions, ['just-dead', 'live']);

  const logs = db.prepare('SELECT COUNT(*) AS cnt FROM access_logs').get();
  assert.equal(logs.cnt, 1);
});
