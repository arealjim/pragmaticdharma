# Shared Auth & Navigation — pragmaticdharma.org

Canonical templates shared across all sub-projects.

## Files

| File | Purpose |
|------|---------|
| `auth-cloudflare.js` | JWT verification for Cloudflare Workers/Pages (Web Crypto API) |
| `auth-flask.py` | JWT verification for Python/Flask services (stdlib) |
| `nav-bar.html` | Self-contained platform navigation bar (HTML + inline CSS/JS) |

## Auth Module API

Both modules expose the same interface:

| Function | Description |
|----------|-------------|
| `parsePdSession(request)` / `parse_pd_session(cookies)` | Extract `pd_session` cookie value |
| `verifyJWT(token, secret)` / `verify_jwt(token, secret)` | HMAC-SHA256 verify, returns payload or null |
| `getSessionFromRequest(request, env)` / `get_session_from_request(cookies, secret)` | Cookie parse + verify in one call |
| `hasProjectAccess(payload, project)` / `has_project_access(payload, project)` | Check `projects` claim (backward-compat: missing claim = full access) |
| `loginRedirectUrl(returnUrl)` / `login_redirect_url(return_url)` | Build `pragmaticdharma.org/login?redirect=...` URL |

## Nav Bar Integration

### The `__PD_USER` Contract

The nav bar reads `window.__PD_USER` to display the authenticated user's name and a "Sign out" link. If the global is not set, it shows "Sign in" instead.

Each project's server must inject this before the nav bar HTML:

```html
<script>window.__PD_USER = {"name":"Jim","email":"jim@example.com","role":"admin"};</script>
```

The `{{PROJECT_NAME}}` placeholder in the nav bar HTML must be replaced with the project's display name (e.g. "Shield", "Health Tracker").

### Integration Patterns

#### Cloudflare Worker (string replacement)

```js
function injectPlatformNav(html, payload, projectName) {
  const navHtml = NAV_BAR_HTML.replace('{{PROJECT_NAME}}', projectName);
  const userScript = payload
    ? `<script>window.__PD_USER=${JSON.stringify({
        name: payload.name, email: payload.email, role: payload.role
      })};</script>`
    : '';
  return html.replace('</body>', userScript + navHtml + '</body>');
}
```

#### Cloudflare Pages Middleware

```js
export async function onRequest(context) {
  const response = await context.next();
  if (!response.headers.get('content-type')?.includes('text/html')) return response;

  const payload = await getSessionFromRequest(context.request, context.env);
  const html = await response.text();
  return new Response(injectPlatformNav(html, payload, 'Project Name'), {
    status: response.status,
    headers: response.headers,
  });
}
```

#### Flask (Jinja context processor)

```python
@app.context_processor
def inject_pd_user():
    user = get_current_user()
    if user:
        return {'pd_user_json': json.dumps({
            'name': user.get('display_name', ''),
            'email': user.get('email', ''),
            'role': 'admin' if user.get('is_admin') else 'user',
        })}
    return {'pd_user_json': None}
```

Then in templates:

```html
{% if pd_user_json %}
<script>window.__PD_USER = {{ pd_user_json | safe }};</script>
{% endif %}
<!-- paste nav-bar.html content here, with PROJECT_NAME already replaced -->
```
