#!/usr/bin/env python3
"""
Recon and pipeline Flask routes.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path

import time

from flask import Blueprint, Response, abort, g, jsonify, request, send_file, stream_with_context

from playwright_agent.asm_bridge import build_playwright_job_options


_SCAN_DATA_KEYS = (
    "hosts", "findings", "stats", "waf_coverage", "asns", "emails",
    "cve_findings", "cve_summary", "shodan_hosts", "breach_data",
    "supply_chain_findings", "supply_chain_summary", "supply_chain_libs",
    "ct_subdomains", "port_scan", "secrets_findings", "screenshots_count",
    "pipeline_ran_at", "not_done", "skipped_modules",
    # crawl / JS / tech
    "wayback_data", "urlfinder_data", "js_data", "tech_index", "tech_summary",
    "tech_versions", "tech_queried",
    # infra
    "asn_data", "cidr_ranges", "asn_numbers", "dns_data",
    "headers_data", "leaks_data", "api_exposure", "waf_results",
)

_SSE_MAX_RUNTIME = 4 * 3600  # 4 hours max SSE stream
_PIPELINE_PROFILES = {"bug_bounty"}
_FINAL_JOB_STATUSES = {"done", "error", "cancelled", "stopped"}

def create_recon_blueprint(
    *,
    require_auth,
    recon_available,
    recon_modules,
    self_contained_modules,
    run_recon_handler,
    load_companies,
    get_settings,
    pipeline_state,
    pipeline_phases,
    run_pipeline_handler,
    recon_results,
    load_asm_data,
    save_asm_data,
    get_tool_logs=None,
    clear_tool_logs=None,
    get_tool_log_detail=None,
    clear_checkpoints=None,
    load_pipeline_state=None,
    base_dir=None,
    job_scheduler=None,
    db=None,
):
    bp = Blueprint("recon_routes", __name__)

    # Keys whose values are secrets (API tokens, auth cookies) — never expose them.
    _SECRET_HINTS = ("token", "key", "secret", "password", "passwd", "credential", "cookie", "auth_state")
    # Keys holding server filesystem paths — relativize to the project root so we
    # don't leak the absolute install path (e.g. /mnt/.../asm) to the client.
    _PATH_KEYS = ("output", "evidence_dir", "job_root", "report_path", "session_path", "base_dir")

    def _sanitize_job(job):
        """Strip secrets and absolute server paths from a job's options before returning it."""
        if not isinstance(job, dict):
            return job
        opts = job.get("options")
        if not isinstance(opts, dict):
            return job
        base = str(base_dir or "")
        clean = {}
        for k, v in opts.items():
            kl = str(k).lower()
            if any(hint in kl for hint in _SECRET_HINTS):
                clean[k] = "***" if v else ""
            elif k in _PATH_KEYS and isinstance(v, str) and v:
                try:
                    clean[k] = str(Path(v).relative_to(base)) if base else v
                except Exception:
                    parts = [p for p in v.replace("\\", "/").split("/") if p]
                    clean[k] = "/".join(parts[-4:]) if len(parts) > 4 else v
            else:
                clean[k] = v
        out = dict(job)
        out["options"] = clean
        return out

    @bp.route("/api/recon/modules", methods=["GET"])
    @require_auth
    def api_recon_modules():
        return jsonify([{"id": key, "label": value[0], "eta": value[1]} for key, value in recon_modules.items()])

    @bp.route("/api/recon/pipeline/profiles", methods=["GET"])
    @require_auth
    def api_pipeline_profiles():
        return jsonify({
            "bug_bounty": {
                "description": "Bug bounty pipeline: discovery, validation, prioritization, browser evidence, checks and reporting.",
                "active": True,
                "phases": [
                    "discovery", "validation", "intel", "cleanup", "fingerprint",
                    "js_discovery", "api_mapping", "browser", "bug_checks",
                    "ports_services", "nuclei",
                ],
            },
        })

    @bp.route("/api/recon/<cid>/<module>", methods=["POST"])
    @require_auth
    def api_run_recon(cid: str, module: str):
        if module in {"playwright", "playwright_recon"}:
            return api_run_playwright(cid)
        if module not in recon_modules:
            return jsonify({"error": f"Unknown module: {module}"}), 400

        companies = load_companies()
        company = next((item for item in companies if item["id"] == cid), None)
        if not company:
            return jsonify({"error": "Company not found"}), 404

        if module not in self_contained_modules and not recon_available:
            return jsonify({"error": "recon module not available"}), 500

        body = request.get_json(force=True) or {}

        def _opt(key: str, env: str = ""):
            return body.get(key) or get_settings().get(key, "") or os.environ.get(env or key.upper(), "")

        options = {
            "github_token": _opt("github_token", "GITHUB_TOKEN"),
            "shodan_key": _opt("shodan_key", "SHODAN_API_KEY"),
            "hibp_key": _opt("hibp_key", "HIBP_API_KEY"),
            "dehashed_key": _opt("dehashed_key", "DEHASHED_API_KEY"),
            "nvd_key": _opt("nvd_key", "NVD_API_KEY"),
        }

        return run_recon_handler(cid, module, company, options)

    @bp.route("/api/recon/<cid>/pipeline", methods=["POST"])
    @require_auth
    def api_run_pipeline(cid: str):
        if not recon_available:
            return jsonify({"error": "recon module not available"}), 500

        companies = load_companies()
        company = next((item for item in companies if item["id"] == cid), None)
        if not company:
            return jsonify({"error": "Company not found"}), 404

        current_status = pipeline_state.get(cid, {}).get("status")
        if current_status in {"queued", "running"}:
            return jsonify({"error": "Pipeline already running"}), 409

        body = request.get_json(force=True) or {}

        def _opt(key: str, env: str = ""):
            return body.get(key) or get_settings().get(key, "") or os.environ.get(env or key.upper(), "")

        body_domains = body.get("domains")
        if isinstance(body_domains, str):
            body_domains = [body_domains]
        domain_source = body_domains if isinstance(body_domains, list) and body_domains else (company.get("domains") or [])
        domains = [str(domain).strip() for domain in domain_source if str(domain).strip()]
        domains = list(dict.fromkeys(domains))
        queue_domains = body.get("queue_domains")
        # queue_domains: each domain becomes a separate pipeline job.
        # With ASM_JOB_WORKERS=1, domains process one at a time serially.
        # Default: auto-enable when >1 domain (avoids memory explosion from
        # parallel fan-out across hundreds/thousands of domains).
        profile = str(body.get("profile") or body.get("pipeline_profile") or "bug_bounty").strip().lower()
        if queue_domains is None:
            queue_domains = len(domains) > 1
        else:
            queue_domains = bool(queue_domains)

        options = {
            "github_token":  _opt("github_token", "GITHUB_TOKEN"),
            "shodan_key":    _opt("shodan_key", "SHODAN_API_KEY"),
            "hibp_key":      _opt("hibp_key", "HIBP_API_KEY"),
            "dehashed_key":  _opt("dehashed_key", "DEHASHED_API_KEY"),
            "nvd_key":       _opt("nvd_key", "NVD_API_KEY"),
            "otx_key":       _opt("otx_key", "OTX_KEY"),
            "wpscan_token":  _opt("wpscan_token", "WPSCAN_TOKEN"),
            "hunter_key":    _opt("hunter_key", "HUNTER_KEY"),
            "intelx_key":    _opt("intelx_key", "INTELX_KEY"),
            "whoisxml_key":  _opt("whoisxml_key", "WHOISXML_KEY"),
            # Censys API — stored as censys_api_id/censys_api_secret, read by pipeline as censys_id/censys_secret
            "censys_id":     _opt("censys_api_id", "CENSYS_API_ID"),
            "censys_secret": _opt("censys_api_secret", "CENSYS_API_SECRET"),
            # Scan mode from settings (stealth/balanced/fast) — used by dns_brute and other modules
            "scan_mode":     _opt("asm_scan_mode", "ASM_SCAN_MODE") or body.get("mode", "balanced"),
            "mode": body.get("mode", "balanced"),
            "queue_domains": queue_domains,
            "profile": "bug_bounty",
            "pipeline_profile": "bug_bounty",
            "active": True,
        }
        if profile not in _PIPELINE_PROFILES:
            return jsonify({"error": f"Invalid profile: {profile}", "profiles": sorted(_PIPELINE_PROFILES)}), 400
        if domains:
            options["domains"] = domains
        pipeline_state[cid] = {
            "status": "queued" if job_scheduler else "running",
            "phase_idx": 0,
            "phase_id": "",
            "phase_label": "",
            "host_count": 0,
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "finished_at": None,
            "log": [],
            "queue_mode": "per_domain" if queue_domains else "single_job",
            "queue_total": len(domains) if queue_domains else 1,
        }

        if job_scheduler:
            sess = getattr(g, "session", {}) or {}
            if queue_domains and len(domains) > 1:
                jobs = job_scheduler.enqueue_pipeline_queue(
                    cid,
                    domains,
                    options=options,
                    created_by=sess.get("username", ""),
                )
                if not jobs:
                    pipeline_state[cid]["status"] = "idle"
                    return jsonify({"error": "All domains are already queued or running"}), 409
                pipeline_state[cid]["job_id"] = jobs[0]["id"]
                pipeline_state[cid]["queue_job_ids"] = [job["id"] for job in jobs[:100]]
                pipeline_state[cid]["log"].append({
                    "ts": datetime.now().isoformat(timespec="seconds"),
                    "msg": f"Queued {len(jobs)} domain jobs for pipeline",
                })
                return jsonify({
                    "ok": True,
                    "company_id": cid,
                    "job_id": jobs[0]["id"],
                    "queued_jobs": len(jobs),
                    "queue_mode": "per_domain",
                    "status": "queued",
                    "phases": len(pipeline_phases),
                }), 202

            job = job_scheduler.enqueue_pipeline(
                cid,
                options=options,
                created_by=sess.get("username", ""),
                target=domains[0] if len(domains) == 1 else "",
            )
            pipeline_state[cid]["job_id"] = job["id"]
            pipeline_state[cid]["log"].append({
                "ts": datetime.now().isoformat(timespec="seconds"),
                "msg": f"Pipeline queued as job {job['id']}",
            })
            return jsonify({
                "ok": True,
                "company_id": cid,
                "job_id": job["id"],
                "deduped": bool(job.get("deduped")),
                "status": job["status"],
                "phases": len(pipeline_phases),
            }), 202

        run_pipeline_handler(cid, company, options)
        return jsonify({"ok": True, "company_id": cid, "phases": len(pipeline_phases)}), 202

    @bp.route("/api/recon/<cid>/playwright", methods=["POST"])
    @require_auth
    def api_run_playwright(cid: str):
        if not job_scheduler:
            return jsonify({"error": "job queue not available"}), 503

        companies = load_companies()
        company = next((item for item in companies if item["id"] == cid), None)
        if not company:
            return jsonify({"error": "Company not found"}), 404

        state = pipeline_state.get(cid) if pipeline_state else None
        if not state and load_pipeline_state:
            state = load_pipeline_state(cid)
        if not state or state.get("status") not in {"done", "done_with_issues"}:
            return jsonify({
                "error": "Playwright Recon requires a completed bug bounty pipeline scan first",
                "pipeline_status": (state or {}).get("status", "not_run"),
            }), 409

        body = request.get_json(force=True) or {}
        try:
            options = build_playwright_job_options(company, overrides=body, settings=get_settings())
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

        # JobScheduler owns per-job output paths; do not persist user overrides here.
        options.pop("output", None)
        options.pop("evidence_dir", None)

        sess = getattr(g, "session", {}) or {}
        job = job_scheduler.enqueue_playwright_recon(
            cid,
            options=options,
            created_by=sess.get("username", ""),
        )
        return jsonify({
            "ok": True,
            "company_id": cid,
            "job_id": job["id"],
            "deduped": bool(job.get("deduped")),
            "status": job["status"],
            "job_type": job["job_type"],
            "target": job.get("target", ""),
        }), 202

    @bp.route("/api/recon/<cid>/pipeline", methods=["DELETE"])
    @require_auth
    def api_stop_pipeline(cid: str):
        state = pipeline_state.get(cid)
        if state is None:
            state = {}
            pipeline_state[cid] = state
        state["status"] = "stopped"
        state["finished_at"] = datetime.now().isoformat(timespec="seconds")
        state.setdefault("log", []).append({
            "ts": datetime.now().isoformat(timespec="seconds"),
            "msg": "⏹ Pipeline stopped by user"
        })
        if db is not None:
            try:
                cancelled = db.cancel_pending_jobs(company_id=cid, job_type="pipeline")
                pw_cancelled = db.cancel_pending_jobs(company_id=cid, job_type="playwright_recon")
                total = (cancelled or 0) + (pw_cancelled or 0)
                if total:
                    state.setdefault("log", []).append({
                        "ts": datetime.now().isoformat(timespec="seconds"),
                        "msg": f"Cancelled {total} pending queued jobs (pipeline + playwright)",
                    })
            except Exception:
                pass
        return jsonify({"ok": True, "company_id": cid})

    @bp.route("/api/recon/<cid>/pipeline/cancel", methods=["POST"])
    @require_auth
    def api_cancel_pipeline(cid: str):
        """Alias for frontend stopScan() — delegates to DELETE /pipeline handler"""
        return api_stop_pipeline(cid)

    @bp.route("/api/recon/cancel-all", methods=["POST"])
    @require_auth
    def api_cancel_all_pipelines():
        now = datetime.now().isoformat(timespec="seconds")
        cancelled_cids = []
        for cid, ps in list(pipeline_state.items()):
            if ps.get("status") in {"queued", "running"}:
                ps["status"] = "stopped"
                ps["finished_at"] = now
                ps.setdefault("log", []).append({
                    "ts": now,
                    "msg": "⏹ Pipeline parado pelo usuário (cancelar todos)",
                })
                cancelled_cids.append(cid)
        db_cancelled = 0
        if db is not None:
            try:
                db_cancelled = db.cancel_all_pending_jobs()
            except Exception:
                pass
        return jsonify({"ok": True, "stopped": len(cancelled_cids), "db_cancelled": db_cancelled, "cids": cancelled_cids})

    @bp.route("/api/recon/scan-all", methods=["POST"])
    @require_auth
    def api_scan_all_pipelines():
        if not recon_available:
            return jsonify({"error": "recon module not available"}), 500
        companies = load_companies()
        if not companies:
            return jsonify({"ok": True, "started": 0, "skipped": 0, "cids": []})
        body = request.get_json(force=True) or {}
        settings = get_settings()
        def _opt(key, env=""):
            return body.get(key) or settings.get(key, "") or os.environ.get(env or key.upper(), "")
        options_base = {
            "github_token":  _opt("github_token", "GITHUB_TOKEN"),
            "shodan_key":    _opt("shodan_key", "SHODAN_API_KEY"),
            "hibp_key":      _opt("hibp_key", "HIBP_API_KEY"),
            "dehashed_key":  _opt("dehashed_key", "DEHASHED_API_KEY"),
            "nvd_key":       _opt("nvd_key", "NVD_API_KEY"),
            "otx_key":       _opt("otx_key", "OTX_KEY"),
            "wpscan_token":  _opt("wpscan_token", "WPSCAN_TOKEN"),
            "hunter_key":    _opt("hunter_key", "HUNTER_KEY"),
            "intelx_key":    _opt("intelx_key", "INTELX_KEY"),
            "whoisxml_key":  _opt("whoisxml_key", "WHOISXML_KEY"),
            "mode": body.get("mode", "balanced"),
            "profile": "bug_bounty",
            "pipeline_profile": "bug_bounty",
            "active": True,
        }
        sess = getattr(g, "session", {}) or {}
        started_cids = []
        skipped = 0
        now = datetime.now().isoformat(timespec="seconds")
        for company in companies:
            cid = company.get("id")
            if not cid:
                continue
            if pipeline_state.get(cid, {}).get("status") in {"queued", "running"}:
                skipped += 1
                continue
            domains = list(dict.fromkeys(
                str(d).strip() for d in (company.get("domains") or []) if str(d).strip()
            ))
            if not domains:
                skipped += 1
                continue
            queue_domains = len(domains) > 1
            options = {**options_base, "domains": domains, "queue_domains": queue_domains}
            pipeline_state[cid] = {
                "status": "queued" if job_scheduler else "running",
                "phase_idx": 0, "phase_id": "", "phase_label": "",
                "host_count": 0, "started_at": now, "finished_at": None, "log": [],
                "queue_mode": "per_domain" if queue_domains else "single_job",
                "queue_total": len(domains) if queue_domains else 1,
            }
            try:
                if job_scheduler:
                    if queue_domains:
                        jobs = job_scheduler.enqueue_pipeline_queue(
                            cid, domains, options=options, created_by=sess.get("username", ""))
                        if jobs:
                            pipeline_state[cid]["job_id"] = jobs[0]["id"]
                            started_cids.append(cid)
                        else:
                            pipeline_state[cid]["status"] = "idle"
                            skipped += 1
                    else:
                        job = job_scheduler.enqueue_pipeline(
                            cid, options=options, created_by=sess.get("username", ""),
                            target=domains[0])
                        pipeline_state[cid]["job_id"] = job["id"]
                        started_cids.append(cid)
                else:
                    threading.Thread(
                        target=run_pipeline_handler, args=(cid, company, options), daemon=True
                    ).start()
                    started_cids.append(cid)
            except Exception:
                pipeline_state[cid]["status"] = "idle"
                skipped += 1
        return jsonify({"ok": True, "started": len(started_cids), "skipped": skipped, "cids": started_cids})

    @bp.route("/api/recon/<cid>/pipeline", methods=["GET"])
    @require_auth
    def api_pipeline_status(cid: str):
        state = pipeline_state.get(cid)
        if not state and load_pipeline_state:
            state = load_pipeline_state(cid)
        if not state or not isinstance(state, dict):
            return jsonify({"status": "not_run"})

        state_not_done = {
            item.get("module"): item
            for item in (state.get("not_done", []) or [])
            if isinstance(item, dict) and item.get("module")
        }
        state_skipped = {
            item.get("module"): item
            for item in (state.get("skipped_modules", []) or [])
            if isinstance(item, dict) and item.get("module")
        }

        phases_status = []
        for phase in pipeline_phases:
            modules = []
            for module in phase["modules"]:
                result = recon_results.get(f"{cid}:{module}", {})
                fallback = state_not_done.get(module) or state_skipped.get(module) or {}
                status = result.get("status") or fallback.get("status") or "not_run"
                modules.append({
                    "module": module,
                    "status": status,
                    "reason": result.get("reason") or result.get("error") or fallback.get("reason", ""),
                    "finished_at": result.get("finished_at") or fallback.get("finished_at"),
                })
            phases_status.append({
                "id": phase["id"],
                "label": phase["label"],
                "modules": modules,
                "done": all(mod["status"] in ("done", "error", "timeout", "skipped") for mod in modules),
            })

        return jsonify({
            "status": state.get("status", "running"),
            "job_id": state.get("job_id", ""),
            "queue_mode": state.get("queue_mode", ""),
            "queue_total": state.get("queue_total", 0),
            "queue_job_ids": state.get("queue_job_ids", [])[:100],
            "phase_idx": state.get("phase_idx", 0),
            "phase_label": state.get("phase_label", ""),
            "host_count": state.get("host_count", 0),
            "started_at": state.get("started_at"),
            "finished_at": state.get("finished_at"),
            "not_done": state.get("not_done", []),
            "skipped_modules": state.get("skipped_modules", []),
            "log": state.get("log", [])[-30:],
            "mullvad_ip": state.get("mullvad_ip", ""),
            "phases": phases_status,
        })

    @bp.route("/api/jobs", methods=["GET"])
    @require_auth
    def api_jobs():
        if not db:
            return jsonify([])
        sess = getattr(g, "session", {}) or {}
        scope = sess.get("scoped_companies")
        is_super = sess.get("role") == "super_admin"
        company_id = request.args.get("company_id", "")
        status = request.args.get("status", "")
        job_type = request.args.get("job_type", "")
        target = request.args.get("target", "")
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
        include_total = request.args.get("include_total", "") in {"1", "true", "yes"}
        if not is_super and scope is not None and not scope:
            return jsonify({"jobs": [], "total": 0, "limit": limit, "offset": offset} if include_total else [])
        if company_id and not is_super and scope is not None and "*" not in scope and company_id not in scope:
            return jsonify({"error": "Forbidden — company not in scope"}), 403
        if not company_id and not is_super and scope is not None and "*" not in scope:
            # Restrict the visible job list to the caller's companies.
            jobs = db.list_jobs(
                status=status,
                job_type=job_type,
                target=target,
                limit=max(limit + offset, limit),
            )
            visible = [_sanitize_job(job) for job in jobs if job.get("company_id") in scope]
            paged = visible[offset:offset + limit]
            if include_total:
                return jsonify({"jobs": paged, "total": len(visible), "limit": limit, "offset": offset})
            return jsonify(paged)
        jobs = [_sanitize_job(job) for job in db.list_jobs(
            company_id=company_id,
            status=status,
            job_type=job_type,
            target=target,
            limit=limit,
            offset=offset,
        )]
        if include_total:
            total = db.count_jobs(company_id=company_id, status=status, job_type=job_type, target=target)
            return jsonify({"jobs": jobs, "total": total, "limit": limit, "offset": offset})
        return jsonify(jobs)

    @bp.route("/api/jobs/summary", methods=["GET"])
    @require_auth
    def api_jobs_summary():
        """Per-company job counts grouped by status (one card per company)."""
        if not db or not hasattr(db, "job_company_summary"):
            return jsonify([])
        sess = getattr(g, "session", {}) or {}
        scope = sess.get("scoped_companies")
        is_super = sess.get("role") == "super_admin"
        rows = db.job_company_summary()
        if not is_super and scope is not None and "*" not in scope:
            allowed = set(scope or [])
            rows = [r for r in rows if r.get("company_id") in allowed]
        return jsonify(rows)

    @bp.route("/api/jobs", methods=["DELETE"])
    @require_auth
    def api_delete_jobs():
        if not db:
            return jsonify({"error": "job queue not available"}), 404
        if not hasattr(db, "delete_jobs"):
            return jsonify({"error": "job delete not available"}), 503
        sess = getattr(g, "session", {}) or {}
        scope = sess.get("scoped_companies")
        is_super = sess.get("role") == "super_admin"
        company_id = request.args.get("company_id", "")
        status = request.args.get("status", "")
        job_type = request.args.get("job_type", "")
        target = request.args.get("target", "")
        if status not in _FINAL_JOB_STATUSES:
            return jsonify({
                "error": "Bulk delete requires a final status",
                "allowed_statuses": sorted(_FINAL_JOB_STATUSES),
            }), 400
        if company_id and not is_super and scope is not None and "*" not in scope and company_id not in scope:
            return jsonify({"error": "Forbidden — company not in scope"}), 403
        if not company_id and not is_super and scope is not None and "*" not in scope:
            total = 0
            for cid in (scope or []):
                total += db.delete_jobs(company_id=cid, status=status, job_type=job_type, target=target)
            return jsonify({"ok": True, "deleted": total})
        deleted = db.delete_jobs(company_id=company_id, status=status, job_type=job_type, target=target)
        return jsonify({"ok": True, "deleted": deleted})

    @bp.route("/api/jobs/<job_id>", methods=["GET"])
    @require_auth
    def api_job_detail(job_id: str):
        if not db:
            return jsonify({"error": "job queue not available"}), 404
        job = db.get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        sess = getattr(g, "session", {}) or {}
        scope = sess.get("scoped_companies")
        if sess.get("role") != "super_admin" and scope is not None:
            if not scope or ("*" not in scope and job.get("company_id") not in scope):
                return jsonify({"error": "Forbidden — company not in scope"}), 403
        return jsonify(_sanitize_job(job))

    @bp.route("/api/jobs/<job_id>", methods=["DELETE"])
    @require_auth
    def api_cancel_job(job_id: str):
        if not db:
            return jsonify({"error": "job queue not available"}), 404
        job = db.get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        sess = getattr(g, "session", {}) or {}
        scope = sess.get("scoped_companies")
        if sess.get("role") != "super_admin" and scope is not None:
            if not scope or ("*" not in scope and job.get("company_id") not in scope):
                return jsonify({"error": "Forbidden — company not in scope"}), 403
        if job.get("status") in _FINAL_JOB_STATUSES and hasattr(db, "delete_job"):
            if db.delete_job(job_id):
                return jsonify({"ok": True, "job_id": job_id, "deleted": True})
            return jsonify({"error": "Job not found"}), 404
        if db.cancel_job(job_id, reason="cancelled by user"):
            return jsonify({"ok": True, "job_id": job_id})
        return jsonify({"error": "Only pending jobs can be cancelled; only final jobs can be deleted"}), 409

    @bp.route("/api/jobs/<job_id>/artifact/<kind>", methods=["GET"])
    @require_auth
    def api_job_artifact(job_id: str, kind: str):
        if not db:
            return jsonify({"error": "job queue not available"}), 404
        job = db.get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        sess = getattr(g, "session", {}) or {}
        scope = sess.get("scoped_companies")
        if sess.get("role") != "super_admin" and scope is not None:
            if not scope or ("*" not in scope and job.get("company_id") not in scope):
                return jsonify({"error": "Forbidden — company not in scope"}), 403
        if job.get("job_type") != "playwright_recon":
            return jsonify({"error": "Artifacts available only for Playwright Recon jobs"}), 404

        options = job.get("options", {}) or {}
        root = Path(str(options.get("job_root") or "")).expanduser()
        if not root or not root.exists():
            return jsonify({"error": "Job artifacts not available"}), 404

        # The enqueued options often have empty output/evidence_dir (they are
        # resolved only at run time), so fall back to the canonical layout under
        # job_root: <root>/report.md and <root>/evidence/. Otherwise empty paths
        # resolve outside root and the containment check below 403s every request.
        if kind == "report":
            output = str(options.get("output") or "")
            path = Path(output).expanduser() if output else (root / "report.md")
            mime = "text/markdown; charset=utf-8"
            download_name = f"{job_id}-report.md"
        elif kind == "session":
            evidence_str = str(options.get("evidence_dir") or "")
            evidence_dir = Path(evidence_str).expanduser() if evidence_str else (root / "evidence")
            path = evidence_dir / "session.json"
            if not path.exists():
                partial = evidence_dir / "session.partial.json"
                if partial.exists():
                    path = partial
            mime = "application/json; charset=utf-8"
            download_name = f"{job_id}-session.json"
        else:
            return jsonify({"error": "Unknown artifact kind"}), 400

        try:
            resolved = path.resolve()
            resolved.relative_to(root.resolve())
        except Exception:
            return jsonify({"error": "Artifact path rejected"}), 403

        if not resolved.exists():
            return jsonify({"error": "Artifact not found"}), 404

        return send_file(str(resolved), mimetype=mime, as_attachment=False, download_name=download_name)

    @bp.route("/api/recon/<cid>/pipeline/stream")
    @require_auth
    def api_pipeline_stream(cid: str):
        def _generate():
            sent = 0
            deadline = time.time() + _SSE_MAX_RUNTIME
            while True:
                if time.time() >= deadline:
                    yield 'data: {"done": true, "reason": "stream_timeout"}\n\n'
                    break
                state = pipeline_state.get(cid, {})
                log = state.get("log", [])
                for entry in log[sent:]:
                    yield f"data: {json.dumps(entry)}\n\n"
                sent = len(log)
                if state.get("status") in ("done", "error"):
                    yield 'data: {"done": true}\n\n'
                    break
                time.sleep(1)

        return Response(
            stream_with_context(_generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @bp.route("/api/recon/<cid>/tool-logs", methods=["GET"])
    @require_auth
    def api_tool_logs(cid: str):
        logs = get_tool_logs(cid) if get_tool_logs else []
        return jsonify(logs)

    @bp.route("/api/recon/<cid>/tool-logs", methods=["DELETE"])
    @require_auth
    def api_clear_tool_logs(cid: str):
        if clear_tool_logs:
            clear_tool_logs(cid)
        return jsonify({"ok": True})

    @bp.route("/api/recon/<cid>/tool-logs/<int:run_id>", methods=["GET"])
    @require_auth
    def api_tool_log_detail(cid: str, run_id: int):
        """Full tool run detail with stderr/stdout."""
        # Try the dedicated method first, fall back to scanning the log list
        if get_tool_log_detail:
            detail = get_tool_log_detail(cid, run_id)
            if detail:
                return jsonify(detail)
        # Fallback: scan from standard log list
        logs = get_tool_logs(cid) if get_tool_logs else []
        for log in logs:
            if log.get("run_id") == run_id:
                return jsonify(log)
        return jsonify({"error": "Tool run not found"}), 404

    # Frontend alias — calls /api/tool-logs/<cid> instead of /api/recon/<cid>/tool-logs
    @bp.route("/api/tool-logs/<cid>", methods=["GET"])
    @require_auth
    def api_tool_logs_short(cid: str):
        logs = get_tool_logs(cid) if get_tool_logs else []
        return jsonify(logs)

    @bp.route("/api/tool-logs/<cid>", methods=["DELETE"])
    @require_auth
    def api_clear_tool_logs_short(cid: str):
        if clear_tool_logs:
            clear_tool_logs(cid)
        return jsonify({"ok": True})

    @bp.route("/api/tool-logs/<cid>/<int:run_id>", methods=["GET"])
    @require_auth
    def api_tool_log_detail_short(cid: str, run_id: int):
        """Full tool run detail (short path alias)."""
        if get_tool_log_detail:
            detail = get_tool_log_detail(cid, run_id)
            if detail:
                return jsonify(detail)
        logs = get_tool_logs(cid) if get_tool_logs else []
        for log in logs:
            if log.get("run_id") == run_id:
                return jsonify(log)
        return jsonify({"error": "Tool run not found"}), 404

    @bp.route("/api/live-output/<cid>", methods=["GET"])
    @require_auth
    def api_live_output(cid: str):
        """Real-time tool stdout/stderr lines since a timestamp.
        Pass ?since=<unix_ts> to get only new lines. Returns all buffered lines if omitted."""
        from utils.command_runner import live_read_all
        since = request.args.get("since", "0", type=float)
        lines = live_read_all(cid, since)
        return jsonify({"lines": lines, "ts": time.time()})

    @bp.route("/api/recon/<cid>/<module>", methods=["GET", "DELETE"])
    @require_auth
    def api_get_recon(cid: str, module: str):
        if request.method == "DELETE" and module == "data":
            data = load_asm_data()
            co = next((c for c in data.get("companies", []) if c.get("id") == cid), None)
            if co is None:
                return jsonify({"error": "Company not found"}), 404
            pipeline_state[cid] = {
                "status": "stopped",
                "reason": "project data cleared",
                "updated_at": datetime.now().isoformat(timespec="seconds"),
            }
            for mod in list(recon_results.keys()):
                if mod.startswith(f"{cid}:"):
                    recon_results.pop(mod, None)
            deleted = {}
            if db and hasattr(db, "reset_company_scan_data"):
                deleted = db.reset_company_scan_data(cid)
            else:
                for key in _SCAN_DATA_KEYS:
                    co.pop(key, None)
                for key in ("last_scan", "generated", "pipeline_ran_at"):
                    co.pop(key, None)
                save_asm_data(data)
            pipeline_state.pop(cid, None)
            if clear_checkpoints:
                clear_checkpoints(cid)
            if clear_tool_logs:
                clear_tool_logs(cid)
            try:
                from utils.command_runner import live_clear
                live_clear(cid)
            except Exception:
                pass
            # Remove every scan artifact for this company from disk: checkpoints,
            # screenshots, scan history, Playwright output, and pipeline_state.
            if base_dir:
                import shutil as _shutil
                import re as _re
                if not _re.match(r"^[a-zA-Z0-9_-]+$", cid):
                    abort(400)
                company_scan_dir = base_dir / "scans" / cid
                if company_scan_dir.exists() and company_scan_dir.resolve().is_relative_to((base_dir / "scans").resolve()):
                    _shutil.rmtree(company_scan_dir)
                snapshots_dir = base_dir / "data" / "snapshots"
                for suffix in ("", "_prev"):
                    path = snapshots_dir / f"{cid}{suffix}.json"
                    path.unlink(missing_ok=True)
            return jsonify({"ok": True, "reset": True, "deleted": deleted})
        result = recon_results.get(f"{cid}:{module}")
        if not result:
            return jsonify({"status": "not_run"}), 200
        return jsonify(result)

    @bp.route("/api/recon/<cid>", methods=["GET"])
    @require_auth
    def api_get_all_recon(cid: str):
        summary = {}
        for module in recon_modules:
            result = recon_results.get(f"{cid}:{module}", {})
            summary[module] = {
                "status": result.get("status", "not_run"),
                "finished_at": result.get("finished_at"),
            }
        return jsonify(summary)

    return bp
