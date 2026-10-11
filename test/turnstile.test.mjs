// Turnstile bot check on POST /api/login (2026-10-11, AUTH-DESIGN.md fix #3).
// Inert until BOTH TURNSTILE_SITE_KEY and TURNSTILE_SECRET are set; once on it
// fails closed — no token, a rejected token, or a siteverify outage all stop
// the login before any email is sent.
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import worker from '../worker.js';
import { makeEnv, seedUser, jsonRequest, ORIGIN } from './helpers.mjs';

const EMAIL = 'user@example.com';
let env, calls, verdict, original;

beforeEach(() => {
  env = makeEnv();
  seedUser(env, { email: EMAIL });
  calls = [];
  verdict = 'pass';
  original = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    calls.push({ url: String(url), body: opts.body ? JSON.parse(opts.body) : null });
    if (String(url).includes('challenges.cloudflare.com')) {
      if (verdict === 'down') throw new Error('network');
      return Response.json({ success: verdict === 'pass' });
    }
    return Response.json({ ok: true });
  };
});

afterEach(() => { globalThis.fetch = original; });

const sentEmail = () => calls.some(c => c.url.includes('api.resend.com'));
const verifyCalls = () => calls.filter(c => c.url.includes('challenges.cloudflare.com'));
const configure = () => { env.TURNSTILE_SITE_KEY = '0x-site'; env.TURNSTILE_SECRET = '0x-secret'; };

test('unconfigured: login works with no token and siteverify is never called', async () => {
  const resp = await worker.fetch(jsonRequest('/api/login', { email: EMAIL }), env);
  assert.equal(resp.status, 200);
  assert.equal(verifyCalls().length, 0);
  assert.ok(sentEmail());
});

test('half-configured (secret only) is treated as off, not as reject-everything', async () => {
  env.TURNSTILE_SECRET = '0x-secret';
  const resp = await worker.fetch(jsonRequest('/api/login', { email: EMAIL }), env);
  assert.equal(resp.status, 200);
  assert.equal(verifyCalls().length, 0);
});

test('configured: a passing token logs in, and the secret + token reach siteverify', async () => {
  configure();
  const resp = await worker.fetch(jsonRequest('/api/login', { email: EMAIL, turnstileToken: 'tok' }), env);
  assert.equal(resp.status, 200);
  const [v] = verifyCalls();
  assert.equal(v.body.secret, '0x-secret');
  assert.equal(v.body.response, 'tok');
  assert.ok(sentEmail());
});

test('configured: missing token is rejected without calling siteverify or sending mail', async () => {
  configure();
  const resp = await worker.fetch(jsonRequest('/api/login', { email: EMAIL }), env);
  assert.equal(resp.status, 403);
  assert.equal(verifyCalls().length, 0);
  assert.ok(!sentEmail());
});

test('configured: a failing token is rejected', async () => {
  configure();
  verdict = 'fail';
  const resp = await worker.fetch(jsonRequest('/api/login', { email: EMAIL, turnstileToken: 'bad' }), env);
  assert.equal(resp.status, 403);
  assert.ok(!sentEmail());
});

test('configured: siteverify outage fails closed', async () => {
  configure();
  verdict = 'down';
  const resp = await worker.fetch(jsonRequest('/api/login', { email: EMAIL, turnstileToken: 'tok' }), env);
  assert.equal(resp.status, 403);
  assert.ok(!sentEmail());
});

test('login page CSP admits Cloudflare only when configured', async () => {
  const off = await worker.fetch(new Request(`${ORIGIN}/login`), env);
  assert.doesNotMatch(off.headers.get('content-security-policy'), /challenges\.cloudflare\.com/);
  env = { ...env };   // getSecret caches per env object; prod env never changes mid-life
  configure();
  const on = await worker.fetch(new Request(`${ORIGIN}/login`), env);
  const csp = on.headers.get('content-security-policy');
  assert.match(csp, /script-src [^;]*https:\/\/challenges\.cloudflare\.com/);
  assert.match(csp, /frame-src https:\/\/challenges\.cloudflare\.com/);
});
