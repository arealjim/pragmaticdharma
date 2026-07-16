// Shared helpers for worker unit tests: env construction, outbound-fetch
// stubbing (Resend capture), and flow drivers for login/verify.
import { createFakeD1 } from './fake-d1.mjs';

export const TEST_SECRET = 'unit-test-jwt-secret-not-a-real-key';
export const ORIGIN = 'https://pragmaticdharma.org';

export function makeEnv() {
  const db = createFakeD1();
  return {
    DB: db,
    // getSecret() accepts plain string bindings, so tests can inject secrets
    // without a Secrets Store. All kids sign with the same test key here.
    JWT_SECRET_PRAGMATICDHARMA: TEST_SECRET,
    RESEND_API_KEY: 'test-resend-key',
  };
}

export function seedUser(env, { email = 'user@example.com', name = 'Test User', role = 'user', status = 'approved', projects = [] } = {}) {
  const db = env.DB._sqlite;
  db.prepare('INSERT INTO users (email, name, status, role) VALUES (?, ?, ?, ?)').run(email, name, status, role);
  const row = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  for (const p of projects) {
    db.prepare('INSERT INTO user_projects (user_id, project) VALUES (?, ?)').run(row.id, p);
  }
  return row.id;
}

// Stub global fetch so Resend/Discord calls never leave the process. Captures
// every outbound request; returns the emails sent (parsed magic link + code).
export function stubOutboundFetch() {
  const original = globalThis.fetch;
  const calls = [];
  const emails = [];
  globalThis.fetch = async (url, opts = {}) => {
    calls.push({ url: String(url), opts });
    if (String(url).includes('api.resend.com')) {
      const body = JSON.parse(opts.body);
      const text = body.text || '';
      const codeMatch = text.match(/login code is: (\d{6})/);
      const linkMatch = text.match(/use this link: (\S+)/);
      emails.push({
        to: body.to,
        code: codeMatch ? codeMatch[1] : null,
        magicLink: linkMatch ? linkMatch[1] : null,
      });
    }
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  return {
    calls,
    emails,
    restore() { globalThis.fetch = original; },
  };
}

export async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

export function jsonRequest(path, body, headers = {}) {
  return new Request(`${ORIGIN}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

// Drives POST /api/login for `email` and returns { code, magicLink, rawToken }.
export async function requestMagicLink(worker, env, mail, email) {
  const before = mail.emails.length;
  const resp = await worker.fetch(jsonRequest('/api/login', { email }), env);
  if (resp.status !== 200) {
    throw new Error(`login failed: ${resp.status} ${await resp.text()}`);
  }
  const sent = mail.emails[before];
  const rawToken = sent.magicLink.split('/api/verify/')[1].split('?')[0];
  return { ...sent, rawToken };
}

export function getCookie(resp, name = 'pd_session') {
  const setCookie = resp.headers.get('set-cookie') || '';
  const m = setCookie.match(new RegExp(`${name}=([^;]*)`));
  return m ? m[1] : null;
}
