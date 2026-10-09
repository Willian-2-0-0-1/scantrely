#!/usr/bin/env python3
"""
Asset and tooling Flask routes for companies, tools, validation, and checkpoints.
"""

from __future__ import annotations

import re
import logging as _logging
_log = _logging.getLogger('scantrely.assets')
import socket
import threading
import uuid
from datetime import datetime

from flask import Blueprint, jsonify, request

try:
    from core.targets import normalize_domain, normalize_domain_list
except ImportError:  # compatibility with legacy direct imports in tests
    from targets import normalize_domain, normalize_domain_list


def create_asset_blueprint(
    *,
    require_auth,
    load_companies,
    save_companies,
    get_settings,
    save_settings,
    get_company_data,
    tools_available,
    tool_registry,
    tool_run_results,
    checkpoints_available,
    checkpoints_module,
    load_hosts_for_company,
    checkpoint_jobs,
    db=None,
    scans_dir=None,
):
    bp = Blueprint("asset_routes", __name__)

    @bp.route("/api/companies", methods=["GET"])
    @require_auth
    def api_get_companies():
        return jsonify(load_companies())

    @bp.route("/api/companies", methods=["POST"])
    @require_auth
    def api_add_company():
        body = request.get_json(force=True)
        name = (body.get("name") or "").strip()
        domains, domain_errors = normalize_domain_list(body.get("domains") or [])
        if not name:
            return jsonify({"error": "name required"}), 400
        if domain_errors:
            return jsonify({"error": "Invalid domain format", "details": domain_errors}), 400

        companies = load_companies()
        cid = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        if any(company["id"] == cid for company in companies):
            return jsonify({"error": "Company ID already exists"}), 409

        company = {
            "id": cid,
            "name": name,
            "domains": domains,
            "color": body.get("color", "#00c9a7"),
            "tags": body.get("tags", []),
        }
        companies.append(company)
        save_companies(companies)
        return jsonify(company), 201

    @bp.route("/api/companies/<cid>", methods=["PUT"])
    @require_auth
    def api_update_company(cid: str):
        body = request.get_json(force=True) or {}
        companies = load_companies()
        company = next((item for item in companies if item["id"] == cid), None)
        if not company:
            return jsonify({"error": "Company not found"}), 404
        if "name" in body and body["name"].strip():
            company["name"] = body["name"].strip()
        if "domains" in body:
            new_domains, domain_errors = normalize_domain_list(body["domains"] or [])
            if domain_errors:
                return jsonify({"error": "Invalid domain format", "details": domain_errors}), 400
            company["domains"] = new_domains
        if "color" in body:
            company["color"] = body["color"]
        if "tags" in body:
            company["tags"] = body["tags"]
        save_companies(companies)
        return jsonify(company)

    @bp.route("/api/companies/<cid>", methods=["DELETE"])
    @require_auth
    def api_delete_company(cid: str):
        import shutil as _shutil
        # Wipe all DB records for this company
        if db is not None:
            try:
                db.delete_company_data(cid)
            except Exception as e:
                return jsonify({"error": f"DB delete failed: {e}"}), 500
        else:
            # Fallback: just remove from companies list
            companies = [c for c in load_companies() if c["id"] != cid]
            save_companies(companies)

        # Remove scan files from disk
        if scans_dir is not None:
            company_scans = scans_dir / cid
            if company_scans.exists():
                try:
                    _shutil.rmtree(company_scans)
                except Exception:
                    _log.debug('assets.py:117 erro ignorado', exc_info=True)

        return jsonify({"ok": True})

    @bp.route("/api/tools/status", methods=["GET"])
    @require_auth
    def api_tools_status():
        if not tools_available:
            return jsonify({"error": "tools module not available"}), 500
        category = request.args.get("category")
        data = tool_registry.status()
        try:
            from utils.tool_gate import snapshot as _gate_snapshot, DEFAULT_TOOL_LIMIT
            gates = {item["tool"]: item for item in _gate_snapshot()}
            for tool in data:
                tool["gate"] = gates.get(tool["name"], {"limit": DEFAULT_TOOL_LIMIT, "active": 0, "queued": 0})
        except Exception:
            _log.debug('assets.py:134 erro ignorado', exc_info=True)
        if category:
            data = [tool for tool in data if tool["category"] == category]
        return jsonify(data)

    @bp.route("/api/tools/run", methods=["POST"])
    @require_auth
    def api_tools_run():
        if not tools_available:
            return jsonify({"error": "tools module not available"}), 500
        body = request.get_json(force=True) or {}
        name = body.get("tool", "").strip()
        target = body.get("target", "").strip()
        opts = body.get("opts", {})
        if not name or not target:
            return jsonify({"error": "tool and target required"}), 400

        tool = tool_registry.get(name)
        if not tool:
            return jsonify({"error": f"Unknown tool: {name}"}), 404

        if not re.match(r'^[a-zA-Z0-9._:\-\/\[\]]+$', target):
            return jsonify({"error": "Invalid target format"}), 400

        job_key = f"{name}:{target}"
        if tool_run_results.get(job_key, {}).get("status") == "running":
            return jsonify({"error": "Already running"}), 409

        cfg = get_settings()
        for key in (
            "shodan_key", "github_token", "hibp_key", "dehashed_key",
            "censys_api_id", "censys_api_secret", "securitytrails_key",
            "virustotal_key", "fullhunt_key",
        ):
            if key not in opts and cfg.get(key):
                opts[key] = cfg[key]

        tool_run_results[job_key] = {
            "status": "running",
            "tool": name,
            "target": target,
            "started_at": datetime.now().isoformat(timespec="seconds"),
        }

        def _run():
            result = tool.run(target, opts)
            tool_run_results[job_key] = result.to_dict()
            tool_run_results[job_key]["status"] = "error" if result.error else "done"

        threading.Thread(target=_run, daemon=True).start()
        return jsonify({"ok": True, "job_key": job_key}), 202

    @bp.route("/api/tools/result", methods=["GET"])
    @require_auth
    def api_tools_result():
        tool = request.args.get("tool", "")
        target = request.args.get("target", "")
        key = f"{tool}:{target}"
        result = tool_run_results.get(key)
        if not result:
            return jsonify({"status": "not_run"}), 200
        return jsonify(result)

    @bp.route("/api/validate-domains", methods=["POST"])
    @require_auth
    def api_validate_domains():
        domains = (request.get_json(force=True) or {}).get("domains", [])
        results = []
        for domain in domains[:20]:
            normalized = normalize_domain(str(domain), allow_wildcard=True)
            if not normalized.ok:
                results.append({"domain": str(domain), "ok": False, "error": normalized.error})
                continue
            if normalized.wildcard and "*" in normalized.value:
                results.append({"domain": normalized.value, "ok": True, "wildcard": True, "ip": None})
                continue
            try:
                ip = socket.gethostbyname(normalized.value)
                results.append({"domain": normalized.value, "ok": True, "ip": ip, "wildcard": normalized.wildcard})
            except Exception as exc:
                results.append({"domain": normalized.value, "ok": False, "error": str(exc), "wildcard": normalized.wildcard})
        return jsonify(results)

    @bp.route("/api/checkpoints/<company_id>", methods=["GET"])
    @require_auth
    def api_get_checkpoints(company_id: str):
        if not checkpoints_available:
            return jsonify({"error": "checkpoints module not available"}), 500
        fps = checkpoints_module.load_checkpoints(company_id)
        if not fps:
            return jsonify({"company_id": company_id, "total": 0, "fingerprints": {}})
        return jsonify({
            "company_id": company_id,
            "total": len(fps),
            "fingerprints": {
                url: {
                    "status_code": fp.status_code,
                    "title": fp.title,
                    "server": fp.server,
                    "content_hash": fp.content_hash,
                    "js_hash": fp.js_hash,
                    "headers_hash": fp.headers_hash,
                    "js_count": len(fp.js_urls),
                    "timestamp": fp.timestamp,
                }
                for url, fp in fps.items()
            },
        })

    @bp.route("/api/checkpoints/<company_id>/scan", methods=["POST"])
    @require_auth
    def api_run_checkpoint_scan(company_id: str):
        if not checkpoints_available:
            return jsonify({"error": "checkpoints module not available"}), 500

        body = request.get_json(force=True) or {}
        hosts = body.get("hosts") or []
        if not hosts:
            hosts = load_hosts_for_company(company_id)
        if not hosts:
            return jsonify({"error": "No hosts found for this company. Run a scan first."}), 400

        scan_id = uuid.uuid4().hex[:8]
        checkpoint_jobs[scan_id] = {
            "status": "running",
            "company_id": company_id,
            "total": len(hosts),
            "done": 0,
            "result": None,
        }

        def _run():
            def progress(done, total, url):
                checkpoint_jobs[scan_id]["done"] = done

            result = checkpoints_module.run_checkpoint_scan(
                company_id, hosts, max_workers=min(20, max(5, len(hosts) // 10 + 1)), progress_cb=progress
            )
            diff = result["diff"]
            checkpoint_jobs[scan_id].update({
                "status": "done",
                "summary": result["summary"],
                "first_run": result["first_run"],
                "total_fingerprinted": result["total_fingerprinted"],
                "needs_rescan": diff.needs_rescan,
                "new": diff.new,
                "changed": diff.changed,
                "unchanged_count": len(diff.unchanged),
                "removed": diff.removed,
                "change_details": diff.change_details,
            })

        threading.Thread(target=_run, daemon=True).start()
        return jsonify({"scan_id": scan_id, "total_hosts": len(hosts)}), 202

    @bp.route("/api/checkpoints/job/<scan_id>", methods=["GET"])
    @require_auth
    def api_checkpoint_job(scan_id: str):
        job = checkpoint_jobs.get(scan_id)
        if not job:
            return jsonify({"error": "Not found"}), 404
        return jsonify(job)

    @bp.route("/api/companies/bulk-import", methods=["POST"])
    @require_auth
    def api_bulk_import():
        body = request.get_json(force=True) or {}
        entries = body.get("companies", [])
        if not isinstance(entries, list):
            return jsonify({"error": "companies must be a list"}), 400

        companies = load_companies()
        existing_ids = {c["id"] for c in companies}
        added, skipped, errors = [], [], []

        for entry in entries:
            name = (entry.get("name") or "").strip()
            if not name:
                errors.append({"entry": entry, "error": "name required"})
                continue

            raw = entry.get("domains", [])
            domains, domain_errors = normalize_domain_list(raw)
            if domain_errors:
                errors.append({"entry": entry, "error": "Invalid domains", "details": domain_errors})
                continue

            cid = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
            if cid in existing_ids:
                skipped.append({"id": cid, "name": name})
                continue

            now = datetime.now().isoformat(timespec="seconds")
            company = {
                "id": cid, "name": name, "domains": domains,
                "color": entry.get("color", "#00c9a7"),
                "tags": entry.get("tags", []),
                "created_at": now, "updated_at": now,
            }
            companies.append(company)
            existing_ids.add(cid)
            added.append({"id": cid, "name": name})

        if added:
            save_companies(companies)

        return jsonify({"added": added, "skipped": skipped, "errors": errors})

    return bp
