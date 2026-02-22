"""
Canonical JWT authentication for Python/Flask services.
Shared across all pragmaticdharma.org sub-projects.

HMAC-SHA256 verification using the standard library.
Expects JWT_SECRET as an environment variable or passed directly.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Optional
from urllib.parse import quote


def base64url_decode(s: str) -> bytes:
    """Decode a base64url-encoded string."""
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)


def verify_jwt(token: str, secret: str) -> Optional[dict]:
    """
    Verify a JWT token using HMAC-SHA256.

    Returns the payload dict on success, None on failure.
    """
    if not secret:
        return None

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        encoded_header, encoded_payload, encoded_sig = parts

        # Validate header algorithm
        header = json.loads(base64url_decode(encoded_header))
        if header.get("alg") != "HS256":
            return None

        signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")

        expected_sig = hmac.new(
            secret.encode("utf-8"),
            signing_input,
            hashlib.sha256,
        ).digest()

        actual_sig = base64url_decode(encoded_sig)

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload = json.loads(base64url_decode(encoded_payload))

        # Check expiration
        if "exp" not in payload or payload["exp"] < int(time.time()):
            return None

        return payload
    except (json.JSONDecodeError, KeyError, UnicodeDecodeError, Exception):
        return None


def parse_pd_session(cookies: dict) -> Optional[str]:
    """
    Extract pd_session cookie value from a cookie dict.

    For Flask: pass ``request.cookies``.
    """
    return cookies.get("pd_session")


def get_session_from_request(cookies: dict, secret: str) -> Optional[dict]:
    """
    Parse pd_session cookie and verify JWT in one step.

    For Flask: ``get_session_from_request(request.cookies, JWT_SECRET)``.
    """
    token = parse_pd_session(cookies)
    if not token:
        return None
    return verify_jwt(token, secret)


def has_project_access(payload: dict, project: str) -> bool:
    """
    Check if a JWT payload grants access to a specific project.

    Backward-compat: no ``projects`` claim = full access.
    """
    projects = payload.get("projects")
    if projects is None:
        return True
    return isinstance(projects, list) and project in projects


def login_redirect_url(return_url: str) -> str:
    """Build the login redirect URL for unauthenticated users."""
    return f"https://pragmaticdharma.org/login?redirect={quote(return_url, safe='')}"
