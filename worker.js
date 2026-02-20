// Pragmatic Dharma Platform Worker
// Serves landing page, auth API, admin API
// D1 database for users, sessions, access logs

// =========================================================================
// STATIC PAGES (loaded from pages/ at build time via import)
// =========================================================================

import INDEX_HTML from './pages/index.html';
import LOGIN_HTML from './pages/login.html';
import SIGNUP_HTML from './pages/signup.html';
import RESOURCES_HTML from './pages/resources.html';
import ADMIN_HTML from './pages/admin.html';
import RETREATS_HTML from './pages/retreats.html';

const KNOWN_PROJECTS = ['health', 'shield', 'ego-assessment', 'mindreader'];

function validateRedirectUrl(url) {
  if (!url || typeof url !== 'string') return '';
  url = url.trim();
  // Allow only https://*.pragmaticdharma.org paths
  if (/^https:\/\/[a-z0-9-]+\.pragmaticdharma\.org(\/.*)?$/.test(url)) return url;
  return '';
}

function redirectUrlToProject(url) {
  // Map subdomain URLs to project keys
  const map = {
    'health.pragmaticdharma.org': 'health',
    'shield.pragmaticdharma.org': 'shield',
    'psychology.pragmaticdharma.org': 'ego-assessment',
  };
  try {
    const host = new URL(url).hostname;
    return map[host] || null;
  } catch {
    return null;
  }
}

const HTML_HEADERS = {
  'content-type': 'text/html; charset=utf-8',
  'cache-control': 'no-store',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
};

// =========================================================================
// MAIN HANDLER
// =========================================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // Health check
    if (path === '/health') {
      return new Response('ok', { headers: { 'content-type': 'text/plain' } });
    }

    // Subdomain routing: retreats.pragmaticdharma.org
    const host = url.hostname;
    if (host === 'retreats.pragmaticdharma.org') {
      return htmlResponse(RETREATS_HTML);
    }

    try {
      // Static pages
      if (method === 'GET' && (path === '/' || path === '')) {
        return htmlResponse(INDEX_HTML);
      }
      if (method === 'GET' && path === '/resources') {
        return htmlResponse(RESOURCES_HTML);
      }
      if (method === 'GET' && path === '/login') {
        return htmlResponse(LOGIN_HTML);
      }
      if (method === 'GET' && path === '/signup') {
        return htmlResponse(SIGNUP_HTML);
      }
      if (method === 'GET' && path === '/admin') {
        return htmlResponse(ADMIN_HTML);
      }

      // Auth API
      if (method === 'POST' && path === '/api/signup') {
        return handleSignup(request, env);
      }
      if (method === 'POST' && path === '/api/login') {
        return handleLogin(request, env);
      }
      if (method === 'GET' && path.startsWith('/api/verify/')) {
        const token = path.slice('/api/verify/'.length);
        return handleVerifyLink(token, request, env);
      }
      if (method === 'POST' && path === '/api/verify') {
        return handleVerifyCode(request, env);
      }
      if (method === 'GET' && path === '/api/session') {
        return handleSession(request, env);
      }
      if (method === 'GET' && path === '/api/logout') {
        return handleLogout(request, env);
      }
      if (method === 'POST' && path === '/api/logout') {
        return handleLogout(request, env);
      }

      // Admin API
      if (path.startsWith('/api/admin/')) {
        return handleAdmin(request, env, path, method);
      }

      return new Response('Not Found', { status: 404 });
    } catch (err) {
      console.error('Handler error:', err);
      return jsonResponse({ error: 'Internal error' }, 500);
    }
  },
};

// =========================================================================
// SIGNUP
// =========================================================================

async function handleSignup(request, env) {
  // Global signup rate limit: max 20 per hour
  const oneHourAgo = new Date(Date.now() - 3600000).toISOString();
  const signupCount = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM users WHERE created_at > ?'
  ).bind(oneHourAgo).first();
  if (signupCount && signupCount.cnt >= 20) {
    return jsonResponse({ error: 'Too many signups. Please try again later.' }, 429);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400);
  }

  const name = (body.name || '').trim();
  const email = (body.email || '').trim().toLowerCase();
  const note = (body.note || '').trim();

  if (!name || name.length > 100) {
    return jsonResponse({ error: 'Name is required (max 100 chars)' }, 400);
  }
  if (!email || !email.includes('@') || email.length > 200) {
    return jsonResponse({ error: 'Valid email is required' }, 400);
  }

  // Check if user already exists
  const existing = await env.DB.prepare('SELECT id, status FROM users WHERE email = ?').bind(email).first();
  if (existing) {
    if (existing.status === 'approved') {
      return jsonResponse({ error: 'Account already exists. Try signing in.' }, 409);
    }
    if (existing.status === 'pending') {
      return jsonResponse({ error: 'Request already pending. You\'ll be notified when approved.' }, 409);
    }
    // Rejected — allow re-signup
    await env.DB.prepare('UPDATE users SET name = ?, note = ?, status = \'pending\', updated_at = datetime(\'now\') WHERE id = ?')
      .bind(name, note || null, existing.id).run();
    await notifyDiscord(env, signupEmbed(name, email, note, 're-signup'));
    return jsonResponse({ ok: true, autoApproved: false });
  }

  // Check open beta — per-project or global
  const project = (body.project || '').trim();
  let openBeta = await getConfig(env, 'open_beta') === 'true';
  let grantProject = null;
  if (!openBeta && project) {
    // Map redirect URLs to project keys
    const projectKey = redirectUrlToProject(project) || project;
    if (KNOWN_PROJECTS.indexOf(projectKey) !== -1) {
      const perProject = await getConfig(env, 'open_beta:' + projectKey) === 'true';
      if (perProject) {
        openBeta = true;
        grantProject = projectKey;
      }
    }
  }
  const status = openBeta ? 'approved' : 'pending';

  await env.DB.prepare('INSERT INTO users (email, name, status, note) VALUES (?, ?, ?, ?)')
    .bind(email, name, status, note || null).run();

  if (openBeta) {
    const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (user) {
      if (grantProject) {
        // Per-project beta: grant only that project
        await env.DB.prepare('INSERT OR IGNORE INTO user_projects (user_id, project) VALUES (?, ?)').bind(user.id, grantProject).run();
      } else {
        // Global beta: grant all projects
        for (const p of KNOWN_PROJECTS) {
          await env.DB.prepare('INSERT OR IGNORE INTO user_projects (user_id, project) VALUES (?, ?)').bind(user.id, p).run();
        }
      }
    }
  }

  await notifyDiscord(env, signupEmbed(name, email, note, openBeta ? ('auto-approved (open beta' + (grantProject ? ': ' + grantProject : '') + ')') : 'pending'));

  return jsonResponse({ ok: true, autoApproved: openBeta });
}

// =========================================================================
// LOGIN (send magic link + code)
// =========================================================================

async function handleLogin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400);
  }

  const email = (body.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    return jsonResponse({ error: 'Valid email is required' }, 400);
  }

  // Check user exists and is approved
  const user = await env.DB.prepare('SELECT id, status, role FROM users WHERE email = ?').bind(email).first();
  if (!user || user.status !== 'approved') {
    // Generic error to prevent email enumeration
    return jsonResponse({ error: 'Unable to sign in. Check your email or request access first.' }, 403);
  }

  // Rate limit: 3 magic links per email per hour
  const oneHourAgo = new Date(Date.now() - 3600000).toISOString();
  const recentCount = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM magic_links WHERE email = ? AND created_at > ?'
  ).bind(email, oneHourAgo).first();
  if (recentCount && recentCount.cnt >= 3) {
    return jsonResponse({ error: 'Too many login attempts. Try again in an hour.' }, 429);
  }

  // Generate token + 6-digit code
  const token = generateToken();
  const code = generateCode();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

  await env.DB.prepare(
    'INSERT INTO magic_links (token, code, email, user_id, expires_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(token, code, email, user.id, expiresAt).run();

  // Send email via Resend
  const baseUrl = new URL(request.url).origin;
  const redirect = validateRedirectUrl(body.redirect);
  let magicLink = `${baseUrl}/api/verify/${token}`;
  if (redirect) magicLink += '?redirect=' + encodeURIComponent(redirect);
  const sent = await sendMagicLinkEmail(env, email, magicLink, code);

  if (!sent) {
    return jsonResponse({ error: 'Failed to send email. Try again.' }, 500);
  }

  return jsonResponse({ ok: true });
}

// =========================================================================
// VERIFY (magic link click)
// =========================================================================

async function handleVerifyLink(token, request, env) {
  // Strip query params from token if present
  const qIdx = token.indexOf('?');
  if (qIdx !== -1) token = token.slice(0, qIdx);

  if (!token || token.length !== 64) {
    return redirectWithError('Invalid link');
  }

  const link = await env.DB.prepare(
    'SELECT token, email, user_id, expires_at, used_at FROM magic_links WHERE token = ?'
  ).bind(token).first();

  if (!link || link.used_at) {
    return redirectWithError('Link expired or already used');
  }
  if (new Date(link.expires_at) < new Date()) {
    return redirectWithError('Link expired');
  }

  // Mark used
  await env.DB.prepare('UPDATE magic_links SET used_at = datetime(\'now\') WHERE token = ?').bind(token).run();

  // Read redirect from query param
  const url = new URL(request.url);
  const redirect = validateRedirectUrl(url.searchParams.get('redirect'));

  // Create session + JWT
  return createSessionAndRedirect(link.user_id, link.email, request, env, redirect);
}

// =========================================================================
// VERIFY (6-digit code)
// =========================================================================

async function handleVerifyCode(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400);
  }

  const email = (body.email || '').trim().toLowerCase();
  const code = (body.code || '').trim();
  const redirect = validateRedirectUrl(body.redirect);

  if (!email || !code || code.length !== 6) {
    return jsonResponse({ error: 'Email and 6-digit code required' }, 400);
  }

  // Find matching unused, unexpired magic link by code + email
  const link = await env.DB.prepare(
    'SELECT token, email, user_id, expires_at, used_at FROM magic_links WHERE code = ? AND email = ? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1'
  ).bind(code, email).first();

  if (!link) {
    await new Promise(r => setTimeout(r, 1000)); // Throttle brute force
    return jsonResponse({ error: 'Invalid or expired code' }, 401);
  }
  if (new Date(link.expires_at) < new Date()) {
    await new Promise(r => setTimeout(r, 1000));
    return jsonResponse({ error: 'Code expired. Request a new one.' }, 401);
  }

  // Mark used
  await env.DB.prepare('UPDATE magic_links SET used_at = datetime(\'now\') WHERE token = ?').bind(link.token).run();

  // Create session + JWT
  const user = await env.DB.prepare('SELECT id, email, name, role FROM users WHERE id = ?').bind(link.user_id).first();
  if (!user) {
    return jsonResponse({ error: 'User not found' }, 404);
  }

  const sessionToken = generateToken();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ua = request.headers.get('User-Agent') || 'unknown';

  await env.DB.prepare(
    'INSERT INTO sessions (token, user_id, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)'
  ).bind(sessionToken, user.id, expiresAt, ip, ua).run();

  const projectRows = await env.DB.prepare('SELECT project FROM user_projects WHERE user_id = ?').bind(user.id).all();
  const projects = projectRows.results.map(function(r) { return r.project; });

  const jwt = await signJWT(env, {
    sub: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    projects: projects,
  });

  return jsonResponse(
    { ok: true, redirect: redirect || '/' },
    200,
    { 'Set-Cookie': sessionCookie(jwt) }
  );
}

// =========================================================================
// SESSION
// =========================================================================

async function handleSession(request, env) {
  const jwt = getJWTFromCookie(request);
  if (!jwt) {
    return jsonResponse({ user: null });
  }

  const payload = await verifyJWT(env, jwt);
  if (!payload) {
    return jsonResponse({ user: null });
  }

  return jsonResponse({
    user: {
      email: payload.email,
      name: payload.name,
      role: payload.role,
    }
  });
}

// =========================================================================
// LOGOUT
// =========================================================================

async function handleLogout(request, env) {
  const jwt = getJWTFromCookie(request);
  if (jwt) {
    const payload = await verifyJWT(env, jwt);
    if (payload && payload.sessionToken) {
      await env.DB.prepare('UPDATE sessions SET revoked_at = datetime(\'now\') WHERE token = ?')
        .bind(payload.sessionToken).run().catch(() => {});
    }
  }

  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/',
      'Set-Cookie': 'pd_session=; Domain=.pragmaticdharma.org; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
    },
  });
}

// =========================================================================
// ADMIN API
// =========================================================================

async function handleAdmin(request, env, path, method) {
  // Require admin JWT
  const jwt = getJWTFromCookie(request);
  if (!jwt) return jsonResponse({ error: 'Unauthorized' }, 401);
  const payload = await verifyJWT(env, jwt);
  if (!payload || payload.role !== 'admin') return jsonResponse({ error: 'Forbidden' }, 403);

  const route = path.replace('/api/admin/', '');

  if (method === 'GET' && route === 'pending') {
    const rows = await env.DB.prepare('SELECT email, name, note, created_at FROM users WHERE status = \'pending\' ORDER BY created_at DESC').all();
    return jsonResponse({ users: rows.results });
  }

  if (method === 'GET' && route === 'users') {
    const rows = await env.DB.prepare('SELECT id, email, name, status, role, created_at FROM users ORDER BY created_at DESC').all();
    // Attach project access for each user
    const projectRows = await env.DB.prepare('SELECT user_id, project FROM user_projects').all();
    const projectMap = {};
    for (const row of projectRows.results) {
      if (!projectMap[row.user_id]) projectMap[row.user_id] = [];
      projectMap[row.user_id].push(row.project);
    }
    const users = rows.results.map(function(u) {
      return { id: u.id, email: u.email, name: u.name, status: u.status, role: u.role, created_at: u.created_at, projects: projectMap[u.id] || [] };
    });
    return jsonResponse({ users: users });
  }

  if (method === 'POST' && route === 'approve') {
    const body = await request.json();
    const email = (body.email || '').trim().toLowerCase();
    if (!email) return jsonResponse({ error: 'Email required' }, 400);
    await env.DB.prepare('UPDATE users SET status = \'approved\', updated_at = datetime(\'now\') WHERE email = ?').bind(email).run();
    const user = await env.DB.prepare('SELECT id, name FROM users WHERE email = ?').bind(email).first();
    if (user) {
      // Grant all projects by default
      for (const project of KNOWN_PROJECTS) {
        await env.DB.prepare('INSERT OR IGNORE INTO user_projects (user_id, project) VALUES (?, ?)').bind(user.id, project).run();
      }
    }
    sendApprovalEmail(env, email, user ? user.name : '').catch(() => {});
    return jsonResponse({ ok: true });
  }

  if (method === 'POST' && route === 'create-user') {
    const body = await request.json();
    const name = (body.name || '').trim();
    const email = (body.email || '').trim().toLowerCase();
    if (!name || !email || !email.includes('@')) return jsonResponse({ error: 'Name and valid email required' }, 400);
    const existing = await env.DB.prepare('SELECT id, status FROM users WHERE email = ?').bind(email).first();
    if (existing) return jsonResponse({ error: 'User already exists' }, 409);
    const result = await env.DB.prepare('INSERT INTO users (email, name, status) VALUES (?, ?, \'approved\')').bind(email, name).run();
    const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (user) {
      for (const project of KNOWN_PROJECTS) {
        await env.DB.prepare('INSERT OR IGNORE INTO user_projects (user_id, project) VALUES (?, ?)').bind(user.id, project).run();
      }
    }
    return jsonResponse({ ok: true });
  }

  if (method === 'POST' && route === 'reject') {
    const body = await request.json();
    const email = (body.email || '').trim().toLowerCase();
    if (!email) return jsonResponse({ error: 'Email required' }, 400);
    await env.DB.prepare('UPDATE users SET status = \'rejected\', updated_at = datetime(\'now\') WHERE email = ?').bind(email).run();
    return jsonResponse({ ok: true });
  }

  if (method === 'GET' && route === 'user-projects') {
    const url = new URL(request.url);
    const userId = url.searchParams.get('user_id');
    if (!userId) return jsonResponse({ error: 'user_id required' }, 400);
    const rows = await env.DB.prepare('SELECT project FROM user_projects WHERE user_id = ?').bind(userId).all();
    return jsonResponse({ projects: rows.results.map(function(r) { return r.project; }) });
  }

  if (method === 'POST' && route === 'user-projects') {
    const body = await request.json();
    const userId = body.user_id;
    const projects = body.projects;
    if (!userId || !Array.isArray(projects)) return jsonResponse({ error: 'user_id and projects[] required' }, 400);
    // Validate projects
    const valid = projects.filter(function(p) { return KNOWN_PROJECTS.indexOf(p) !== -1; });
    // Replace: delete all then insert selected
    await env.DB.prepare('DELETE FROM user_projects WHERE user_id = ?').bind(userId).run();
    for (const project of valid) {
      await env.DB.prepare('INSERT INTO user_projects (user_id, project) VALUES (?, ?)').bind(userId, project).run();
    }
    return jsonResponse({ ok: true, projects: valid });
  }

  if (method === 'GET' && route.startsWith('access-logs')) {
    const url = new URL(request.url);
    const project = url.searchParams.get('project');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 200);

    let query = 'SELECT user_email, project, path, ip_address, country, city, isp, user_agent, created_at FROM access_logs';
    const params = [];
    if (project) {
      query += ' WHERE project = ?';
      params.push(project);
    }
    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);

    const stmt = env.DB.prepare(query);
    const rows = params.length === 2 ? await stmt.bind(params[0], params[1]).all() : await stmt.bind(params[0]).all();
    return jsonResponse({ logs: rows.results });
  }

  if (method === 'GET' && route === 'config') {
    const rows = await env.DB.prepare('SELECT key, value FROM config ORDER BY key').all();
    const config = {};
    for (const row of rows.results) {
      config[row.key] = row.value;
    }
    return jsonResponse({ config: config });
  }

  if (method === 'POST' && route === 'config') {
    const body = await request.json();
    for (const [key, value] of Object.entries(body)) {
      await env.DB.prepare('INSERT INTO config (key, value, updated_at) VALUES (?, ?, datetime(\'now\')) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime(\'now\')')
        .bind(key, String(value), String(value)).run();
    }
    return jsonResponse({ ok: true });
  }

  return jsonResponse({ error: 'Not found' }, 404);
}

// =========================================================================
// JWT (HMAC-SHA256 via Web Crypto)
// =========================================================================

async function signJWT(env, payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const claims = { ...payload, iat: now, exp: now + 30 * 24 * 60 * 60 };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(claims));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const key = await getSigningKey(env);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput));
  const encodedSig = base64url(sig);

  return `${signingInput}.${encodedSig}`;
}

async function verifyJWT(env, token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [encodedHeader, encodedPayload, encodedSig] = parts;

    // Validate header algorithm
    const header = JSON.parse(atob(encodedHeader.replace(/-/g, '+').replace(/_/g, '/')));
    if (header.alg !== 'HS256') return null;

    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const key = await getSigningKey(env);
    const sig = base64urlDecode(encodedSig);
    const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(signingInput));
    if (!valid) return null;

    const payload = JSON.parse(atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/')));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;

    return payload;
  } catch {
    return null;
  }
}

async function getSigningKey(env) {
  const secret = env.JWT_SECRET;
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

function base64url(input) {
  const data = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str) {
  const padded = str + '='.repeat((4 - str.length % 4) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  return new Uint8Array([...binary].map(c => c.charCodeAt(0)));
}

// =========================================================================
// SESSION HELPERS
// =========================================================================

async function createSessionAndRedirect(userId, email, request, env, redirect) {
  const user = await env.DB.prepare('SELECT id, email, name, role FROM users WHERE id = ?').bind(userId).first();
  if (!user) return redirectWithError('User not found');

  const sessionToken = generateToken();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ua = request.headers.get('User-Agent') || 'unknown';

  await env.DB.prepare(
    'INSERT INTO sessions (token, user_id, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)'
  ).bind(sessionToken, user.id, expiresAt, ip, ua).run();

  const projectRows = await env.DB.prepare('SELECT project FROM user_projects WHERE user_id = ?').bind(user.id).all();
  const projects = projectRows.results.map(function(r) { return r.project; });

  const jwt = await signJWT(env, {
    sub: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    projects: projects,
    sessionToken: sessionToken,
  });

  return new Response(null, {
    status: 302,
    headers: {
      'Location': redirect || '/',
      'Set-Cookie': sessionCookie(jwt),
    },
  });
}

function sessionCookie(jwt) {
  return `pd_session=${jwt}; Domain=.pragmaticdharma.org; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`;
}

function getJWTFromCookie(request) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(';').map(c => c.trim());
  for (const cookie of cookies) {
    const eq = cookie.indexOf('=');
    if (eq === -1) continue;
    if (cookie.slice(0, eq) === 'pd_session') {
      return cookie.slice(eq + 1);
    }
  }
  return null;
}

// =========================================================================
// CRYPTO HELPERS
// =========================================================================

function generateToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

function generateCode() {
  const array = new Uint8Array(3);
  crypto.getRandomValues(array);
  const num = (array[0] << 16) | (array[1] << 8) | array[2];
  return String(num % 1000000).padStart(6, '0');
}

// =========================================================================
// RESEND EMAIL
// =========================================================================

async function sendMagicLinkEmail(env, email, magicLink, code) {
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) {
    console.error('RESEND_API_KEY not configured');
    return false;
  }

  const fromEmail = env.FROM_EMAIL || 'noreply@pragmaticdharma.org';

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: `Pragmatic Dharma <${fromEmail}>`,
        to: [email],
        subject: `Your login code: ${code}`,
        html: `
          <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #333;">Sign in to Pragmatic Dharma</h2>
            <p style="color: #666; font-size: 16px;">Use this code to sign in:</p>
            <div style="background: #f5f5f5; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
              <span style="font-size: 32px; font-weight: bold; letter-spacing: 4px; color: #333;">${code}</span>
            </div>
            <p style="color: #666; font-size: 16px;">Or click this link:</p>
            <p>
              <a href="${magicLink}" style="display: inline-block; background: #0d7377; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500;">Sign In</a>
            </p>
            <p style="color: #999; font-size: 14px; margin-top: 30px;">This link expires in 15 minutes. If you didn't request this, you can safely ignore this email.</p>
          </div>
        `,
        text: `Your Pragmatic Dharma login code is: ${code}\n\nOr use this link: ${magicLink}\n\nThis link expires in 15 minutes.`
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Resend API error:', errorText);
      return false;
    }
    return true;
  } catch (error) {
    console.error('Email send error:', error.message);
    return false;
  }
}

async function sendApprovalEmail(env, email, name) {
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) {
    console.error('RESEND_API_KEY not configured');
    return false;
  }

  const fromEmail = env.FROM_EMAIL || 'noreply@pragmaticdharma.org';
  const greeting = name ? `Hi ${name},` : 'Hi,';

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: `Pragmatic Dharma <${fromEmail}>`,
        to: [email],
        subject: "You've been approved — Pragmatic Dharma",
        html: `
          <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #333;">Welcome to Pragmatic Dharma</h2>
            <p style="color: #666; font-size: 16px;">${greeting}</p>
            <p style="color: #666; font-size: 16px;">Your access request has been approved. You can now sign in and start using the platform.</p>
            <p style="margin: 24px 0;">
              <a href="https://pragmaticdharma.org/login" style="display: inline-block; background: #0d7377; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500;">Sign In</a>
            </p>
            <p style="color: #999; font-size: 14px; margin-top: 30px;">If you didn't request access, you can safely ignore this email.</p>
          </div>
        `,
        text: `${greeting}\n\nYour access request has been approved. You can now sign in at https://pragmaticdharma.org/login\n\nIf you didn't request access, you can safely ignore this email.`
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Resend API error (approval):', errorText);
      return false;
    }
    return true;
  } catch (error) {
    console.error('Approval email error:', error.message);
    return false;
  }
}

// =========================================================================
// DISCORD NOTIFICATIONS
// =========================================================================

async function notifyDiscord(env, embed) {
  const webhookUrl = env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [embed] }),
    });
  } catch (e) {
    console.error('Discord notification failed:', e.message);
  }
}

function signupEmbed(name, email, note, status) {
  const fields = [
    { name: 'Name', value: name, inline: true },
    { name: 'Email', value: email, inline: true },
    { name: 'Status', value: status, inline: true },
  ];
  if (note) {
    fields.push({ name: 'Note', value: note.slice(0, 500) });
  }
  return {
    title: 'New Signup Request',
    color: 0x64ffda,
    fields,
    timestamp: new Date().toISOString(),
    footer: { text: 'pragmaticdharma.org' },
  };
}

function accessEmbed(user, project, path, geo) {
  return {
    title: 'Access',
    color: 0x3498db,
    fields: [
      { name: 'User', value: `${user.name} (${user.email})`, inline: true },
      { name: 'Project', value: project, inline: true },
      { name: 'Path', value: path || '/', inline: true },
      { name: 'Location', value: formatLocation(geo), inline: true },
      { name: 'ISP', value: geo.isp || 'Unknown', inline: true },
      { name: 'IP', value: `\`${geo.ip}\``, inline: true },
    ],
    timestamp: new Date().toISOString(),
    footer: { text: 'pragmaticdharma.org' },
  };
}

function formatLocation(geo) {
  const parts = [];
  if (geo.city && geo.city !== 'Unknown') parts.push(geo.city);
  if (geo.region && geo.region !== 'Unknown' && geo.region !== geo.city) parts.push(geo.region);
  if (geo.country && geo.country !== 'Unknown') parts.push(geo.country);
  return parts.length > 0 ? parts.join(', ') : 'Unknown location';
}

// =========================================================================
// CONFIG HELPERS
// =========================================================================

async function getConfig(env, key) {
  const row = await env.DB.prepare('SELECT value FROM config WHERE key = ?').bind(key).first();
  return row ? row.value : null;
}

// =========================================================================
// RESPONSE HELPERS
// =========================================================================

function htmlResponse(html) {
  return new Response(html, { headers: HTML_HEADERS });
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      ...corsHeaders(),
      ...extraHeaders,
    },
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': 'https://pragmaticdharma.org',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function redirectWithError(msg) {
  const safe = escapeHtml(msg);
  return new Response(`<html><body><p>${safe}</p><p><a href="/login">Try again</a></p></body></html>`, {
    status: 400,
    headers: HTML_HEADERS,
  });
}

// Export for use by sub-project workers
export { verifyJWT, getJWTFromCookie, signJWT, accessEmbed, formatLocation, notifyDiscord };
