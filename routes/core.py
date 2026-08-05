#!/usr/bin/env python3
"""
Core Flask routes for auth, admin management, presets, and settings.
"""

from __future__ import annotations

import json
import secrets
import threading as _threading
import time
import uuid
from collections import defaultdict
from datetime import datetime

from flask import Blueprint, jsonify, request

# ── Login rate limiting ───────────────────────────────────────────────────────
_login_fail_lock = _threading.Lock()
_login_failures: dict = defaultdict(list)
_LOGIN_MAX = 10      # max failed attempts before lockout
_LOGIN_LOCKOUT = 900 # lockout window in seconds (15 min)

def _is_login_blocked(ip: str) -> bool:
    now = time.time()
    cutoff = now - _LOGIN_LOCKOUT
    with _login_fail_lock:
        _login_failures[ip] = [t for t in _login_failures[ip] if t > cutoff]
        return len(_login_failures[ip]) >= _LOGIN_MAX

def _record_login_failure(ip: str):
    with _login_fail_lock:
        _login_failures[ip].append(time.time())

def _clear_login_failures(ip: str):
    with _login_fail_lock:
        _login_failures.pop(ip, None)

# ── API key masking ───────────────────────────────────────────────────────────
_MASK = "****"

def _mask_key(val: str) -> str:
    """Return masked version of an API key for safe display."""
    if not val:
        return val
    if len(val) <= 8:
        return _MASK
    return val[:4] + _MASK + val[-4:]

def _is_masked(val: str) -> bool:
    return _MASK in str(val or "")


def create_core_blueprint(
    *,
    session_ttl: int,
    sessions: dict[str, dict],
    load_admins,
    save_admins,
    hash_pw,
    check_pw,
    get_session,
    require_auth,
    require_super_admin,
    audit,
    get_settings,
    save_settings,
    settings_keys,
    public_settings_keys=None,
    db=None,
):
    bp = Blueprint("core_routes", __name__)
    public_settings_keys = set(public_settings_keys or [])

    @bp.route("/api/presets", methods=["GET"])
    @require_auth
    def api_presets():
        return jsonify([{"id": "bug_bounty", "label": "Bug Bounty"}])

    @bp.route("/api/auth/login", methods=["POST"])
    def api_login():
        ip = request.remote_addr or "0.0.0.0"
        if _is_login_blocked(ip):
            return jsonify({"error": "Too many failed attempts. Try again later."}), 429

        body = request.get_json(force=True) or {}
        username = (body.get("username") or "").strip().lower()
        password = body.get("password") or ""
        if not username or not password:
            return jsonify({"error": "username and password required"}), 400

        admins = load_admins()
        admin = next((a for a in admins if a["username"].lower() == username), None)
        if not admin or not check_pw(password, admin.get("password_hash", "")):
            _record_login_failure(ip)
            time.sleep(0.5)
            return jsonify({"error": "Invalid credentials"}), 401

        _clear_login_failures(ip)
        token = secrets.token_urlsafe(32)
        
        # Parse company permissions
        scoped_raw = admin.get("scoped_companies", [])
        scoped_companies = scoped_raw if isinstance(scoped_raw, list) else json.loads(scoped_raw) if isinstance(scoped_raw, str) else []
        
        # Super admin sees all companies (empty list = all access)
        if admin["role"] == "super_admin":
            scoped_companies = None  # null = unrestricted
        
        sess_data = {
            "admin_id": admin["id"],
            "username": admin["username"],
            "role": admin["role"],
            "scoped_companies": scoped_companies,
            "expires_at": time.time() + session_ttl,
        }
        sessions[token] = sess_data
        if db is not None:
            try:
                db.save_session(token, sess_data)
            except Exception:
                pass

        admin["last_login"] = datetime.now().isoformat(timespec="seconds")
        save_admins(admins)
        audit("login", username)

        resp = jsonify({
            "ok": True,
            "token": token,
            "username": admin["username"],
            "role": admin["role"],
            "scoped_companies": scoped_companies,
        })
        resp.set_cookie("asm_token", token, max_age=session_ttl, httponly=True,
                        samesite="Lax", secure=request.is_secure)
        return resp

    @bp.route("/api/auth/logout", methods=["POST"])
    def api_logout():
        token = request.headers.get("X-Auth-Token") or request.cookies.get("asm_token")
        if token:
            sessions.pop(token, None)
            if db is not None:
                try:
                    db.delete_session(token)
                except Exception:
                    pass
        resp = jsonify({"ok": True})
        resp.delete_cookie("asm_token")
        return resp

    @bp.route("/api/auth/me", methods=["GET"])
    def api_me():
        sess = get_session()
        if not sess:
            return jsonify({"error": "Unauthorized"}), 401
        return jsonify({
            "username": sess["username"],
            "role": sess["role"],
            "admin_id": sess["admin_id"],
            "scoped_companies": sess.get("scoped_companies"),
        })

    @bp.route("/api/admins", methods=["GET"])
    @require_super_admin
    def api_list_admins():
        admins = load_admins()
        return jsonify([{k: v for k, v in admin.items() if k != "password_hash"} for admin in admins])

    @bp.route("/api/admins", methods=["POST"])
    @require_super_admin
    def api_create_admin():
        body = request.get_json(force=True) or {}
        username = (body.get("username") or "").strip().lower()
        password = body.get("password") or ""
        email = (body.get("email") or "").strip()
        role = body.get("role", "analyst")

        if not username or not password:
            return jsonify({"error": "username and password required"}), 400
        if role not in ("super_admin", "analyst"):
            return jsonify({"error": "role must be super_admin or analyst"}), 400
        if role == "super_admin" and body.get("scoped_companies"):
            return jsonify({"error": "super_admin cannot be scoped"}), 400
        if len(password) < 8:
            return jsonify({"error": "password must be at least 8 characters"}), 400

        admins = load_admins()
        if any(admin["username"].lower() == username for admin in admins):
            return jsonify({"error": "Username already exists"}), 409

        scoped = body.get("scoped_companies", [])
        if not isinstance(scoped, list):
            scoped = []

        new_admin = {
            "id": uuid.uuid4().hex,
            "username": username,
            "email": email,
            "password_hash": hash_pw(password),
            "role": role,
            "scoped_companies": scoped,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "last_login": None,
        }
        admins.append(new_admin)
        save_admins(admins)
        return jsonify({k: v for k, v in new_admin.items() if k != "password_hash"}), 201

    @bp.route("/api/admins/<aid>", methods=["PUT"])
    @require_super_admin
    def api_update_admin(aid: str):
        body = request.get_json(force=True) or {}
        admins = load_admins()
        admin = next((a for a in admins if a["id"] == aid), None)
        if not admin:
            return jsonify({"error": "Admin not found"}), 404

        sess = get_session()
        if sess and sess["admin_id"] == aid and body.get("role") and body["role"] != admin["role"]:
            return jsonify({"error": "Cannot change your own role"}), 400

        if body.get("email") is not None:
            admin["email"] = body["email"].strip()
        if body.get("role") in ("super_admin", "analyst"):
            admin["role"] = body["role"]
        if "scoped_companies" in body:
            scoped = body["scoped_companies"]
            admin["scoped_companies"] = scoped if isinstance(scoped, list) else []
        if body.get("password"):
            if len(body["password"]) < 8:
                return jsonify({"error": "Password must be at least 8 characters"}), 400
            admin["password_hash"] = hash_pw(body["password"])
            for token, session in list(sessions.items()):
                if session["admin_id"] == aid:
                    sessions.pop(token, None)

        save_admins(admins)
        return jsonify({k: v for k, v in admin.items() if k != "password_hash"})

    @bp.route("/api/admins/<aid>", methods=["DELETE"])
    @require_super_admin
    def api_delete_admin(aid: str):
        sess = get_session()
        if sess and sess["admin_id"] == aid:
            return jsonify({"error": "Cannot delete your own account"}), 400

        admins = load_admins()
        if sum(1 for admin in admins if admin["role"] == "super_admin") <= 1:
            target = next((admin for admin in admins if admin["id"] == aid), None)
            if target and target["role"] == "super_admin":
                return jsonify({"error": "Cannot delete the last super_admin"}), 400

        admins = [admin for admin in admins if admin["id"] != aid]
        save_admins(admins)

        for token, session in list(sessions.items()):
            if session["admin_id"] == aid:
                sessions.pop(token, None)

        return jsonify({"ok": True})

    @bp.route("/api/settings", methods=["GET"])
    @require_auth
    def api_get_settings():
        raw = get_settings()
        return jsonify({k: (v if k in public_settings_keys else _mask_key(v)) for k, v in raw.items()})

    @bp.route("/api/settings/status", methods=["GET"])
    @require_auth
    def api_settings_status():
        """Return which API keys are configured (bool), without revealing values."""
        raw = get_settings()
        return jsonify({k: bool(v) for k, v in raw.items()})

    @bp.route("/api/ai/enrich-finding", methods=["POST"])
    @require_auth
    def api_ai_enrich_finding():
        """Use Hermes Agent / any OpenRouter-compatible chat completions API to
        refine CVSS, CWE, mitigation guidance and a PoC writeup for a finding."""
        import requests as _requests

        cfg = get_settings()
        base_url = (cfg.get("hermes_base_url") or "http://127.0.0.1:8642/v1").rstrip("/")
        api_key = cfg.get("hermes_api_key", "")
        model = cfg.get("hermes_model") or "hermes-agent"

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        body = request.get_json(force=True) or {}
        finding = body.get("finding") or {}

        prompt = (
            "You are a senior application security researcher writing a bug bounty report. "
            "Given the finding below, respond with a concise markdown writeup containing exactly these sections: "
            "'## CVSS' (give a CVSS 3.1 base score, severity label and vector string, with one-line justification), "
            "'## CWE' (the most specific applicable CWE id and name), "
            "'## Mitigation' (3-5 actionable bullet points), and "
            "'## Proof of Concept' (a ready-to-paste PoC description suitable for a HackerOne or Bugcrowd report, "
            "including steps to reproduce and impact). Be specific to the finding's host/URL/category when possible.\n\n"
            f"Finding:\n{json.dumps(finding, indent=2)}"
        )

        try:
            resp = _requests.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": 800,
                },
                timeout=60,
            )
        except Exception as e:
            return jsonify({"error": f"Failed to reach Hermes Agent at {base_url}: {e}"}), 502

        if not resp.ok:
            return jsonify({"error": f"Hermes API error {resp.status_code}: {resp.text[:300]}"}), 502

        try:
            data = resp.json()
            text = data["choices"][0]["message"]["content"]
        except Exception:
            return jsonify({"error": "Unexpected response format from Hermes API"}), 502

        return jsonify({"text": text})

    @bp.route("/api/settings", methods=["POST", "PUT"])
    @require_auth
    def api_save_settings():
        body = request.get_json(force=True) or {}
        # Skip masked values (unchanged keys returned from GET /api/settings)
        updates = {
            key: body[key]
            for key in settings_keys
            if key in body and not _is_masked(body[key])
        }
        if updates:
            save_settings(updates)
        return jsonify({"ok": True})

    return bp
