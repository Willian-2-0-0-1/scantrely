#!/usr/bin/env python3
"""
Extra product routes: 2FA, invites, OpenAPI, slash commands, web push,
custom Nuclei templates, DefectDojo push.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from flask import Blueprint, Response, g, jsonify, request


_OPENAPI = {
    "openapi": "3.0.3",
    "info": {
        "title": "Scantrely ASM API",
        "version": "1.3.11",
        "description": "Local External Attack Surface Monitoring API.",
    },
    "servers": [{"url": "/", "description": "Local"}],
    "components": {
        "securitySchemes": {
            "token": {"type": "apiKey", "in": "header", "name": "X-Auth-Token"},
        }
    },
    "security": [{"token": []}],
    "paths": {
        "/health": {"get": {"summary": "Deep health (sqlite, disk, bin, watchdog, circuits)", "security": []}},
        "/api/health": {"get": {"summary": "Same payload as /health", "security": []}},
        "/api/auth/login": {"post": {"summary": "Login", "security": []}},
        "/api/auth/logout": {"post": {"summary": "Logout"}},
        "/api/auth/me": {"get": {"summary": "Current session"}},
        "/api/auth/2fa/setup": {"post": {"summary": "Start TOTP enrollment"}},
        "/api/auth/2fa/enable": {"post": {"summary": "Confirm TOTP"}},
        "/api/auth/2fa/disable": {"post": {"summary": "Disable TOTP"}},
        "/api/admins": {"get": {"summary": "List admins"}, "post": {"summary": "Create admin"}},
        "/api/admins/invite": {"post": {"summary": "Invite user with company scope"}},
        "/api/companies": {"get": {"summary": "List companies"}},
        "/api/recon/{cid}/pipeline": {
            "post": {"summary": "Start pipeline"},
            "get": {"summary": "Pipeline status"},
            "delete": {"summary": "Stop pipeline"},
        },
        "/api/recon/{cid}/pipeline/{module}": {"delete": {"summary": "Cancel one module"}},
        "/api/recon/{cid}/pipeline/stream": {"get": {"summary": "SSE pipeline log"}},
        "/api/export/{cid}": {"get": {"summary": "Export json/csv/html/sarif/pdf"}},
        "/api/export/{cid}/defectdojo": {"post": {"summary": "Push findings to DefectDojo"}},
        "/api/alert-rules/{cid}": {"get": {"summary": "Alert rules"}, "post": {"summary": "Create rule"}},
        "/api/stats-history/{cid}": {"get": {"summary": "Historical scan stats"}},
        "/api/integrations/slash": {"post": {"summary": "Slack/Discord /scan command"}},
        "/api/intel/exposure": {"post": {"summary": "Live infostealer OSINT lookup by domain or email"}},
        "/api/recon/{cid}/exposure": {
            "get": {"summary": "Stored infostealer exposure for a company"},
            "post": {"summary": "Lookup and save domain exposure for a company"},
        },
        "/api/openapi.json": {"get": {"summary": "This specification"}},
    },
}


def create_extras_blueprint(
    *,
    require_auth,
    require_super_admin,
    get_session,
    load_admins,
    save_admins,
    hash_pw,
    get_settings,
    check_pw=None,
    save_settings=None,
    settings_keys=None,
    db=None,
    base_dir=None,
    load_companies=None,
    job_scheduler=None,
    pipeline_state=None,
    pipeline_phases=None,
    audit=None,
    get_company_data=None,
    sessions=None,
    session_ttl=86400,
):
    bp = Blueprint("extras_routes", __name__)
    base = Path(base_dir) if base_dir else Path(".")
    settings_keys = set(settings_keys or [])

    def _audit(action, target="", details=""):
        if audit:
            try:
                audit(action, target, details)
            except Exception:
                pass

    @bp.route("/api/openapi.json", methods=["GET"])
    @require_auth
    def api_openapi():
        return jsonify(_OPENAPI)

    @bp.route("/api/docs", methods=["GET"])
    @require_auth
    def api_docs():
        html = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Scantrely API</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;margin:32px}
a{color:#00e5ff}pre{background:#1e293b;padding:16px;border-radius:8px;overflow:auto}</style>
</head><body><h1>Scantrely OpenAPI</h1>
<p>Spec JSON: <a href="/api/openapi.json">/api/openapi.json</a></p>
<p>Auth: header <code>X-Auth-Token</code> or cookie <code>asm_token</code>.</p>
</body></html>"""
        return Response(html, mimetype="text/html")

    @bp.route("/api/auth/2fa/setup", methods=["POST"])
    @require_auth
    def api_2fa_setup():
        try:
            import pyotp
        except ImportError:
            return jsonify({"error": "pyotp not installed"}), 500
        sess = get_session() or {}
        admins = load_admins()
        admin = next((a for a in admins if a.get("id") == sess.get("admin_id")), None)
        if not admin:
            return jsonify({"error": "Admin not found"}), 404
        secret = pyotp.random_base32()
        admin["totp_secret"] = secret
        admin["totp_enabled"] = False
        save_admins(admins)
        uri = pyotp.TOTP(secret).provisioning_uri(name=admin["username"], issuer_name="Scantrely")
        _audit("2fa_setup", admin["username"])
        return jsonify({"ok": True, "secret": secret, "otpauth_url": uri})

    @bp.route("/api/auth/2fa/enable", methods=["POST"])
    @require_auth
    def api_2fa_enable():
        try:
            import pyotp
        except ImportError:
            return jsonify({"error": "pyotp not installed"}), 500
        body = request.get_json(force=True) or {}
        code = (body.get("totp_code") or body.get("code") or "").strip()
        sess = get_session() or {}
        admins = load_admins()
        admin = next((a for a in admins if a.get("id") == sess.get("admin_id")), None)
        if not admin or not admin.get("totp_secret"):
            return jsonify({"error": "Run /api/auth/2fa/setup first"}), 400
        if not pyotp.TOTP(admin["totp_secret"]).verify(code, valid_window=1):
            return jsonify({"error": "Invalid code"}), 400
        admin["totp_enabled"] = True
        save_admins(admins)
        _audit("2fa_enable", admin["username"])
        return jsonify({"ok": True, "totp_enabled": True})

    @bp.route("/api/auth/2fa/disable", methods=["POST"])
    @require_auth
    def api_2fa_disable():
        body = request.get_json(force=True) or {}
        password = body.get("password") or ""
        sess = get_session() or {}
        admins = load_admins()
        admin = next((a for a in admins if a.get("id") == sess.get("admin_id")), None)
        if not admin:
            return jsonify({"error": "Admin not found"}), 404
        if not password:
            return jsonify({"error": "password required"}), 400
        if not check_pw or not check_pw(password, admin.get("password_hash", "")):
            return jsonify({"error": "Invalid password"}), 401
        admin["totp_enabled"] = False
        admin["totp_secret"] = ""
        save_admins(admins)
        _audit("2fa_disable", admin["username"])
        return jsonify({"ok": True, "totp_enabled": False})

    @bp.route("/api/admins/invite", methods=["POST"])
    @require_super_admin
    def api_invite_admin():
        if db is None or not hasattr(db, "create_invite"):
            return jsonify({"error": "invites unavailable"}), 500
        body = request.get_json(force=True) or {}
        username = (body.get("username") or "").strip().lower()
        email = (body.get("email") or "").strip()
        role = body.get("role") or "analyst"
        scoped = body.get("scoped_companies") or body.get("company_ids") or []
        if not username:
            return jsonify({"error": "username required"}), 400
        if role not in ("super_admin", "analyst"):
            return jsonify({"error": "invalid role"}), 400
        if role == "super_admin":
            scoped = []
        if not isinstance(scoped, list):
            scoped = []
        admins = load_admins()
        if any(a["username"].lower() == username for a in admins):
            return jsonify({"error": "Username already exists"}), 409
        sess = get_session() or {}
        invite = db.create_invite(username, email, role, scoped, sess.get("username", ""))
        origin = request.host_url.rstrip("/")
        invite["url"] = f"{origin}/?invite={invite['token']}"
        _audit("invite_create", username)
        return jsonify(invite), 201

    @bp.route("/api/auth/invite/<token>", methods=["GET"])
    def api_get_invite(token: str):
        if db is None:
            return jsonify({"error": "unavailable"}), 500
        inv = db.get_invite(token)
        if not inv:
            return jsonify({"error": "Invite not found"}), 404
        if inv.get("used_at"):
            return jsonify({"error": "Invite already used"}), 410
        return jsonify({
            "username": inv.get("username"),
            "email": inv.get("email"),
            "role": inv.get("role"),
            "expires_at": inv.get("expires_at"),
        })

    @bp.route("/api/auth/invite/<token>/accept", methods=["POST"])
    def api_accept_invite(token: str):
        if db is None:
            return jsonify({"error": "unavailable"}), 500
        inv = db.get_invite(token)
        if not inv:
            return jsonify({"error": "Invite not found"}), 404
        if inv.get("used_at"):
            return jsonify({"error": "Invite already used"}), 410
        expires = inv.get("expires_at") or ""
        try:
            if expires and datetime.fromisoformat(expires) < datetime.now():
                return jsonify({"error": "Invite expired"}), 410
        except Exception:
            pass
        body = request.get_json(force=True) or {}
        password = body.get("password") or ""
        if len(password) < 8:
            return jsonify({"error": "password must be at least 8 characters"}), 400
        admins = load_admins()
        if any(a["username"].lower() == inv["username"].lower() for a in admins):
            return jsonify({"error": "Username already exists"}), 409
        new_admin = {
            "id": uuid.uuid4().hex,
            "username": inv["username"],
            "email": inv.get("email") or "",
            "password_hash": hash_pw(password),
            "role": inv.get("role") or "analyst",
            "scoped_companies": inv.get("scoped_companies") or [],
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "last_login": None,
            "totp_secret": "",
            "totp_enabled": False,
        }
        admins.append(new_admin)
        save_admins(admins)
        db.mark_invite_used(token)
        _audit("invite_accept", new_admin["username"])
        return jsonify({k: v for k, v in new_admin.items() if k != "password_hash"}), 201

    @bp.route("/api/integrations/slash", methods=["POST"])
    def api_slash_scan():
        settings = get_settings() if get_settings else {}
        expected = (settings.get("slash_token") or os.environ.get("ASM_SLASH_TOKEN") or "").strip()
        provided = (
            request.headers.get("X-Slash-Token")
            or request.headers.get("Authorization", "").replace("Bearer ", "")
            or (request.get_json(silent=True) or {}).get("token")
            or request.form.get("token")
            or ""
        ).strip()
        if not expected or not secrets.compare_digest(expected, provided):
            return jsonify({"error": "Unauthorized slash token"}), 401
        body = request.get_json(silent=True) or {}
        text = (body.get("text") or request.form.get("text") or "").strip()
        text = re.sub(r"^/scan\s+", "", text, flags=re.I).strip()
        domain = text.split()[0] if text else ""
        domain = domain.strip().lower().strip(".")
        if not domain or "." not in domain:
            return jsonify({"error": "usage: /scan <domain>"}), 400
        companies = load_companies() if load_companies else []
        company = next(
            (c for c in companies if domain in [str(d).lower() for d in (c.get("domains") or [])]),
            None,
        )
        if not company:
            company = next((c for c in companies if domain in (c.get("name") or "").lower()), None)
        if not company:
            return jsonify({"error": f"No company scoped to {domain}"}), 404
        cid = company["id"]
        options = {"mode": "balanced", "profile": "bug_bounty", "domains": [domain]}
        if pipeline_state is not None:
            pipeline_state[cid] = {
                "status": "queued",
                "phase_idx": 0,
                "log": [{"ts": datetime.now().isoformat(timespec="seconds"),
                         "msg": f"Slash /scan {domain}"}],
                "started_at": datetime.now().isoformat(timespec="seconds"),
            }
        job_id = ""
        if job_scheduler:
            job = job_scheduler.enqueue_pipeline(cid, options=options, created_by="slash", target=domain)
            job_id = job.get("id", "")
        _audit("slash_scan", cid, domain)
        return jsonify({"ok": True, "company_id": cid, "domain": domain, "job_id": job_id}), 202

    @bp.route("/api/push/vapid", methods=["GET"])
    @require_auth
    def api_push_vapid():
        settings = get_settings() if get_settings else {}
        pub = settings.get("vapid_public_key") or ""
        return jsonify({"publicKey": pub, "configured": bool(pub)})

    @bp.route("/api/push/subscribe", methods=["POST"])
    @require_auth
    def api_push_subscribe():
        if db is None:
            return jsonify({"error": "unavailable"}), 500
        body = request.get_json(force=True) or {}
        endpoint = body.get("endpoint") or ""
        keys = body.get("keys") or {}
        if not endpoint:
            return jsonify({"error": "endpoint required"}), 400
        sess = get_session() or {}
        sub_id = db.save_push_subscription(sess.get("admin_id", ""), endpoint, keys)
        return jsonify({"ok": True, "id": sub_id})

    @bp.route("/api/push/unsubscribe", methods=["POST"])
    @require_auth
    def api_push_unsubscribe():
        if db is None:
            return jsonify({"error": "unavailable"}), 500
        body = request.get_json(force=True) or {}
        db.delete_push_subscription(body.get("endpoint") or "")
        return jsonify({"ok": True})

    @bp.route("/api/recon/<cid>/nuclei-templates", methods=["GET"])
    @require_auth
    def api_list_nuclei_templates(cid: str):
        root = base / "data" / "custom-templates" / cid
        if not root.is_dir():
            return jsonify({"templates": []})
        files = [p.name for p in root.iterdir() if p.suffix.lower() in {".yaml", ".yml"}]
        return jsonify({"templates": sorted(files)})

    @bp.route("/api/recon/<cid>/nuclei-templates", methods=["POST"])
    @require_auth
    def api_upload_nuclei_template(cid: str):
        root = base / "data" / "custom-templates" / cid
        root.mkdir(parents=True, exist_ok=True)
        uploaded = request.files.get("file") or request.files.get("template")
        if uploaded and uploaded.filename:
            name = Path(uploaded.filename).name
            if not name.lower().endswith((".yaml", ".yml")):
                return jsonify({"error": "only .yaml/.yml allowed"}), 400
            dest = root / name
            uploaded.save(str(dest))
            _audit("nuclei_template_upload", cid, name)
            return jsonify({"ok": True, "name": name})
        body = request.get_json(silent=True) or {}
        name = Path(body.get("name") or "custom.yaml").name
        content = body.get("content") or ""
        if not name.lower().endswith((".yaml", ".yml")):
            return jsonify({"error": "only .yaml/.yml allowed"}), 400
        if not content.strip():
            return jsonify({"error": "content required"}), 400
        (root / name).write_text(content, encoding="utf-8")
        _audit("nuclei_template_upload", cid, name)
        return jsonify({"ok": True, "name": name})

    @bp.route("/api/recon/<cid>/nuclei-templates/<name>", methods=["DELETE"])
    @require_auth
    def api_delete_nuclei_template(cid: str, name: str):
        name = Path(name).name
        path = base / "data" / "custom-templates" / cid / name
        if path.is_file():
            path.unlink()
        return jsonify({"ok": True})

    @bp.route("/api/export/<cid>/defectdojo", methods=["POST"])
    @require_auth
    def api_push_defectdojo(cid: str):
        settings = get_settings() if get_settings else {}
        body = request.get_json(silent=True) or {}
        url = (body.get("url") or settings.get("defectdojo_url") or "").rstrip("/")
        token = body.get("token") or settings.get("defectdojo_token") or ""
        product = body.get("product") or settings.get("defectdojo_product") or ""
        if not url or not token:
            return jsonify({"error": "defectdojo_url and defectdojo_token required"}), 400
        company = get_company_data(cid) if get_company_data else None
        if not company:
            return jsonify({"error": "No data"}), 404
        findings = company.get("findings") or []
        payload = {
            "scan_type": "Generic Findings Import",
            "product_name": product or company.get("name") or cid,
            "engagement_name": f"Scantrely {datetime.now().date()}",
            "auto_create_context": True,
            "verified": False,
            "active": True,
            "close_old_findings": False,
            "findings": [
                {
                    "title": f.get("title") or "Finding",
                    "severity": (f.get("severity") or "info").capitalize(),
                    "description": f.get("desc") or f.get("description") or "",
                    "file_path": f.get("host") or "",
                    "unique_id_from_tool": f.get("id") or f.get("title") or "",
                }
                for f in findings
            ],
        }
        from urllib.parse import urlparse
        from utils.circuit_breaker import CircuitOpen, guarded_urlopen
        try:
            import urllib.request
            host = urlparse(url).netloc.split(":")[0] or "defectdojo"
            req = urllib.request.Request(
                f"{url}/api/v2/import-scan/",
                data=json.dumps(payload).encode(),
                headers={
                    "Authorization": f"Token {token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with guarded_urlopen(req, timeout=30, name=host) as resp:
                raw = resp.read()[:4000]
            _audit("defectdojo_push", cid, f"findings={len(findings)}")
            return jsonify({"ok": True, "pushed": len(findings), "response": raw.decode("utf-8", "ignore")[:500]})
        except CircuitOpen as e:
            return jsonify({"error": str(e), "circuit": "open"}), 503
        except Exception as e:
            return jsonify({"error": str(e), "hint": "Check DefectDojo URL/token. Generic JSON import may need a file multipart."}), 502

    return bp
