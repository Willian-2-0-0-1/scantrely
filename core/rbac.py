#!/usr/bin/env python3
"""
RBAC + API Key authentication middleware for ASM Platform.
Supports: JWT session tokens (dashboard) + API keys (external integrations) + OAuth2 (SSO).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import request, jsonify, g

# ── Constants ───────────────────────────────────────────────────────────────────

ROLES = {
    "viewer":       {"read": True,  "scan": False, "admin": False},
    "analyst":      {"read": True,  "scan": True,  "admin": False},
    "super_admin":  {"read": True,  "scan": True,  "admin": True},
}

# ── JWT helpers ─────────────────────────────────────────────────────────────────

def _jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET", "asm-secret-change-me-in-production")
    if secret == "asm-secret-change-me-in-production":
        import sys
        print(
            "[SECURITY WARNING] JWT_SECRET is using the default insecure value. "
            "Set the JWT_SECRET environment variable to a strong random string "
            "before exposing this service on a network.",
            file=sys.stderr,
        )
    return secret


def create_session_token(username: str, role: str, company_ids: list[str] | None = None) -> str:
    """Create a signed JWT-like session token."""
    import base64, secrets
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": username,
        "role": role,
        "cids": company_ids or [],
        "iat": int(time.time()),
        "exp": int(time.time()) + 86400,  # 24h
        "jti": secrets.token_hex(8),
    }).encode()).decode().rstrip("=")
    sig = hmac.new(_jwt_secret().encode(), f"{header}.{payload}".encode(), hashlib.sha256).hexdigest()
    return f"{header}.{payload}.{sig}"


def verify_session_token(token: str) -> dict | None:
    """Verify JWT token. Returns payload dict or None."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, sig = parts
        expected = hmac.new(_jwt_secret().encode(), f"{header}.{payload}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        import base64
        data = json.loads(base64.urlsafe_b64decode(payload + "=="))
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None


def create_api_key_hash(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()


# ── Scope helpers ──────────────────────────────────────────────────────────────

def _normalize_company_scope(raw) -> list[str] | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = []
    if not isinstance(raw, list):
        raw = []
    return [str(cid) for cid in raw if str(cid).strip()]


def _company_scope_allows(cid: str | None) -> bool:
    if not cid:
        return True
    if getattr(g, "role", "viewer") == "super_admin":
        return True
    scoped = _normalize_company_scope(getattr(g, "company_ids", []))
    if scoped is None:
        return True
    if not scoped:
        return False
    return cid in scoped or "*" in scoped


# ── Decorators ──────────────────────────────────────────────────────────────────

def require_auth(fn):
    """Require JWT session OR API key. Sets g.user, g.role, g.company_ids."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        g.user = None
        g.role = "viewer"
        g.company_ids = []

        # 1. JWT session token
        token = request.headers.get("x-auth-token") or request.cookies.get("session")
        if token:
            payload = verify_session_token(token)
            if payload:
                g.user = payload["sub"]
                g.role = payload["role"]
                g.company_ids = _normalize_company_scope(payload.get("cids", [])) or []
                if g.role == "super_admin":
                    g.company_ids = None
                requested = []
                view_args = request.view_args or {}
                for key in ("cid", "company_id", "company"):
                    if kwargs.get(key):
                        requested.append(str(kwargs.get(key)))
                    if view_args.get(key):
                        requested.append(str(view_args.get(key)))
                    if request.args.get(key):
                        requested.append(str(request.args.get(key)))
                if requested:
                    for cid in requested:
                        if not _company_scope_allows(cid):
                            return jsonify({"error": "Forbidden — company not in scope"}), 403
                return fn(*args, **kwargs)

        # 2. API key
        api_key = request.headers.get("x-api-key")
        if api_key:
            try:
                from database import ASMDatabase as _DB
                db = _DB.__new__(_DB)
                if hasattr(db, "validate_api_key"):
                    key_info = db.validate_api_key(api_key)
                    if key_info:
                        g.user = f"api:{key_info.get('name', 'unknown')}"
                        g.role = "analyst"
                        g.company_ids = [key_info.get("company_id")] if key_info.get("company_id") else []
                        requested = []
                        view_args = request.view_args or {}
                        for key in ("cid", "company_id", "company"):
                            if kwargs.get(key):
                                requested.append(str(kwargs.get(key)))
                            if view_args.get(key):
                                requested.append(str(view_args.get(key)))
                            if request.args.get(key):
                                requested.append(str(request.args.get(key)))
                        if requested:
                            for cid in requested:
                                if not _company_scope_allows(cid):
                                    return jsonify({"error": "Forbidden — company not in scope"}), 403
                        return fn(*args, **kwargs)
            except Exception:
                pass

        return jsonify({"error": "Unauthorized — please log in"}), 401
    return wrapper


def require_role(min_role: str = "viewer"):
    """Require minimum role level."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            role_levels = {"viewer": 0, "analyst": 1, "super_admin": 2}
            if role_levels.get(g.role, 0) < role_levels.get(min_role, 0):
                return jsonify({"error": "Forbidden — insufficient permissions"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_company_access(fn):
    """Ensure user has access to the requested company (from URL cid param)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if g.role == "super_admin":
            return fn(*args, **kwargs)
        cid = kwargs.get("cid") or kwargs.get("company_id") or kwargs.get("company")
        if cid and not _company_scope_allows(str(cid)):
            return jsonify({"error": "Forbidden — company not in scope"}), 403
        return fn(*args, **kwargs)
    return wrapper


# ── OAuth2 (Google / Microsoft) ─────────────────────────────────────────────────

def get_google_oauth_url(redirect_uri: str) -> str:
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    if not client_id:
        return ""
    return (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        "&response_type=code"
        "&scope=openid%20email%20profile"
    )


def exchange_google_code(code: str, redirect_uri: str) -> dict | None:
    """Exchange authorization code for user info. Returns {email, name, sub} or None."""
    import urllib.request as ur
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        return None

    # Exchange code for token
    token_data = ur.urlopen(
        ur.Request(
            "https://oauth2.googleapis.com/token",
            data=json.dumps({
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            }).encode(),
            headers={"Content-Type": "application/json"},
        )
    ).read()
    token = json.loads(token_data).get("access_token")
    if not token:
        return None

    # Get user info
    user_data = ur.urlopen(
        ur.Request(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).read()
    return json.loads(user_data)
