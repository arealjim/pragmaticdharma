/**
 * Canonical JWT authentication for Cloudflare Workers/Pages.
 * Shared across all pragmaticdharma.org sub-projects.
 *
 * HMAC-SHA256 verification via Web Crypto API.
 * Expects JWT_SECRET in env (Cloudflare secret binding).
 */

/**
 * Extract pd_session cookie value from a Request.
 * @param {Request} request
 * @returns {string|null}
 */
export function parsePdSession(request) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(';');
  for (const cookie of cookies) {
    const trimmed = cookie.trim();
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    if (trimmed.slice(0, eq) === 'pd_session') {
      return trimmed.slice(eq + 1);
    }
  }
  return null;
}

/**
 * Verify a JWT token using HMAC-SHA256 via Web Crypto API.
 * @param {string} token - The raw JWT string
 * @param {string} secret - The shared JWT_SECRET
 * @returns {Promise<object|null>} Decoded payload or null
 */
export async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [encodedHeader, encodedPayload, encodedSig] = parts;

    // Validate header algorithm
    const header = JSON.parse(atob(encodedHeader.replace(/-/g, '+').replace(/_/g, '/')));
    if (header.alg !== 'HS256') return null;

    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const sig = base64urlDecode(encodedSig);
    const valid = await crypto.subtle.verify(
      'HMAC', key, sig, new TextEncoder().encode(signingInput)
    );
    if (!valid) return null;

    const payload = JSON.parse(atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/')));

    // Check expiration
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;

    return payload;
  } catch {
    return null;
  }
}

/**
 * Parse cookie + verify JWT in one step.
 * @param {Request} request
 * @param {object} env - Must have env.JWT_SECRET
 * @returns {Promise<object|null>} Decoded payload or null
 */
export async function getSessionFromRequest(request, env) {
  if (!env.JWT_SECRET) return null;
  const token = parsePdSession(request);
  if (!token) return null;
  return verifyJWT(token, env.JWT_SECRET);
}

/**
 * Check if a JWT payload grants access to a specific project.
 * Backward-compat: no `projects` claim = full access (old JWTs before per-project gating).
 * @param {object} payload - Decoded JWT payload
 * @param {string} project - Project key (e.g. 'shield', 'health', 'ego-assessment', 'mindreader')
 * @returns {boolean}
 */
export function hasProjectAccess(payload, project) {
  if (!payload.projects) return true;
  return Array.isArray(payload.projects) && payload.projects.includes(project);
}

/**
 * Build the login redirect URL for unauthenticated users.
 * @param {string} returnUrl - URL to redirect back to after login
 * @returns {string}
 */
export function loginRedirectUrl(returnUrl) {
  return `https://pragmaticdharma.org/login?redirect=${encodeURIComponent(returnUrl)}`;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function base64urlDecode(str) {
  const padded = str + '='.repeat((4 - str.length % 4) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  return new Uint8Array([...binary].map(c => c.charCodeAt(0)));
}
