#!/usr/bin/env python3
"""
Scan lifecycle and scan artifact Flask routes.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import Blueprint, abort, jsonify, request, send_from_directory, g


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def _gowitness_name_to_url(stem: str) -> str:
    for scheme in ("https", "http"):
        prefix = scheme + "---"
        if stem.startswith(prefix):
            rest = stem[len(prefix):]
            parts = rest.rsplit("-", 1)
            if len(parts) == 2 and parts[1].isdigit():
                host, port = parts[0], parts[1]
                if (scheme == "https" and port == "443") or (scheme == "http" and port == "80"):
                    return f"{scheme}://{host}"
                return f"{scheme}://{host}:{port}"
            return f"{scheme}://{rest}"
    return stem


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

def create_scan_blueprint(
    *,
    require_auth,
    base_dir: Path,
    load_companies,
    load_asm_data,
    save_asm_data,
    get_asm_data_timestamp,
    load_schedules=None,
    save_schedules=None,
    db,
):
    bp = Blueprint("scan_routes", __name__)

    def _scope_from_session() -> tuple[set[str] | None, bool]:
        """Return (allowed_company_ids, is_super_admin). None means unrestricted."""
        sess = getattr(g, "session", {}) or {}
        role = sess.get("role")
        if role == "super_admin":
            return None, True
        scoped = sess.get("scoped_companies", [])
        if scoped is None:
            return None, False
        if isinstance(scoped, str):
            try:
                scoped = json.loads(scoped)
            except Exception:
                scoped = []
        if not isinstance(scoped, list):
            scoped = []
        allowed = {str(cid) for cid in scoped if str(cid).strip()}
        return allowed, False

    def _clear_company_findings(cid: str):
        """Remove all scan-derived data from the company record in the DB."""
        data = load_asm_data()
        co = next((c for c in data.get("companies", []) if c.get("id") == cid), None)
        if co is None:
            return
        for key in _SCAN_DATA_KEYS:
            co.pop(key, None)
        save_asm_data(data)

    def _company_summary(company: dict) -> dict:
        summary = {
            "id": company.get("id"),
            "name": company.get("name"),
            "color": company.get("color"),
            "domains": company.get("domains", []),
            "tags": company.get("tags", []),
            "last_scan": company.get("last_scan"),
            "generated": company.get("generated"),
            "stats": company.get("stats", {}),
            "cve_summary": company.get("cve_summary", {}),
            "supply_chain_summary": company.get("supply_chain_summary", {}),
            "screenshots_count": company.get("screenshots_count", 0),
            "tech_summary": company.get("tech_summary", {}),
            "waf_coverage": company.get("waf_coverage", {}),
            "summary_only": True,
        }
        return summary



    @bp.route("/api/data", methods=["GET"])
    @require_auth
    def api_get_data():
        data = load_asm_data()
        company_ids, is_super = _scope_from_session()
        all_companies = data.get("companies", [])
        if is_super or company_ids is None:
            visible = all_companies
        else:
            visible = [c for c in all_companies if c.get("id") in company_ids]
        data["companies"] = visible
        return jsonify(data)

    @bp.route("/api/data/summary", methods=["GET"])
    @require_auth
    def api_get_data_summary():
        data = load_asm_data()
        company_ids, is_super = _scope_from_session()
        all_companies = data.get("companies", [])
        if is_super or company_ids is None:
            visible = all_companies
        else:
            visible = [c for c in all_companies if c.get("id") in company_ids]
        return jsonify({
            "version": data.get("version"),
            "generated": data.get("generated"),
            "companies": [_company_summary(co) for co in visible],
        })

    @bp.route("/api/data/company/<cid>", methods=["GET"])
    @require_auth
    def api_get_company_data(cid: str):
        data = load_asm_data()
        co = next((c for c in data.get("companies", []) if c.get("id") == cid), None)
        if not co:
            return jsonify({"error": "Company not found"}), 404
        return jsonify(co)

    @bp.route("/api/data/ts", methods=["GET"])
    @require_auth
    def api_data_ts():
        return jsonify({"ts": get_asm_data_timestamp()})

    @bp.route("/api/data/<cid>/subhistory", methods=["GET"])
    @require_auth
    def api_subhistory(cid: str):
        """Get subdomain history timeline for a company."""
        history = db.get_subdomain_history(cid, limit=1000)
        return jsonify({"history": history})

    @bp.route("/api/stats-history/<cid>", methods=["GET"])
    @require_auth
    def api_stats_history(cid: str):
        """Historical scan stats for trend charts."""
        limit = min(int(request.args.get("limit", 30)), 100)
        stats = db.get_scan_stats(cid, limit=limit)
        return jsonify(stats)

    @bp.route("/api/cve-feed", methods=["GET"])
    @require_auth
    def api_cve_feed():
        """Proxy NVD CVE feed — uses nvd_key from settings if available."""
        import json as _json
        import requests as _r
        from datetime import datetime as _dt, timedelta as _td, timezone as _tz

        try:
            nvd_key = db.get_settings({"nvd_key"}).get("nvd_key", "")
        except Exception:
            nvd_key = ""

        end = _dt.now(_tz.utc)
        start = end - _td(days=7)
        start_str = start.strftime("%Y-%m-%dT00:00:00.000")
        end_str = end.strftime("%Y-%m-%dT23:59:59.000")

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={start_str}&pubEndDate={end_str}&resultsPerPage=50"

        try:
            headers = {"User-Agent": "ASM-Platform/1.0", "Accept": "application/json"}
            if nvd_key:
                headers["apiKey"] = nvd_key
            print(f"[cve-feed] Fetching: {url[:120]}...", flush=True)
            resp = _r.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            items = []
            for v in data.get("vulnerabilities", []):
                c = v.get("cve", {})
                cid_val = c.get("id", "")
                desc = ""
                for d in c.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                score = 0
                sev = "info"
                try:
                    metrics = c.get("metrics", {})
                    cvss_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
                    if cvss_list:
                        cvss = cvss_list[0].get("cvssData", {})
                        score = cvss.get("baseScore", 0)
                        sev = cvss.get("baseSeverity", "info").lower()
                except Exception:
                    pass
                published = c.get("published", "")
                date_str = published[:10] if published else ""
                if cid_val and desc:
                    items.append({"id": cid_val, "desc": desc, "score": score, "severity": sev, "date": date_str})

            # Sort critical first
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            items.sort(key=lambda x: (sev_order.get(x["severity"], 4), -(x.get("score", 0) or 0)))
            return jsonify(items)
        except _r.exceptions.RequestException as e:
            msg = str(getattr(e, "response", None) or e)[:300]
            print(f"[cve-feed] ERROR: {msg}", flush=True)
            return jsonify({"error": f"NVD API unreachable: {msg}"}), 502
        except Exception as e:
            print(f"[cve-feed] ERROR: {e}", flush=True)
            return jsonify({"error": str(e)}), 500

    @bp.route("/api/scan-history/<cid>", methods=["GET"])
    @require_auth
    def api_scan_history(cid: str):
        company_dir = base_dir / "scans" / cid
        history = []
        if company_dir.exists():
            for scan_dir in sorted(company_dir.iterdir(), key=lambda item: item.stat().st_mtime, reverse=True):
                if not scan_dir.is_dir():
                    continue
                out = scan_dir / "output.json"
                nout = scan_dir / "output.ndjson"
                log = scan_dir / "scan.log"
                if not out.exists() and not nout.exists():
                    continue
                output_file = out if out.exists() else nout
                lines = sum(1 for _ in output_file.open())
                types = Counter()
                try:
                    for line in output_file.open():
                        try:
                            event = json.loads(line)
                            types[event.get("type", "?")] += 1
                        except Exception:
                            pass
                except Exception:
                    pass
                history.append({
                    "name": scan_dir.name,
                    "path": str(scan_dir),
                    "mtime": scan_dir.stat().st_mtime,
                    "events": lines,
                    "dns_names": types.get("DNS_NAME", 0),
                    "findings": types.get("FINDING", 0) + types.get("VULNERABILITY", 0),
                    "size_kb": round(output_file.stat().st_size / 1024, 1),
                    "has_log": log.exists(),
                    "has_asm_log": (scan_dir / "asm_run.log").exists(),
                })
        return jsonify(history[:50])

    @bp.route("/api/scan-history/<cid>/<scan_name>", methods=["DELETE"])
    @require_auth
    def api_delete_scan_history(cid: str, scan_name: str):
        import re as _re
        if not _re.match(r'^[a-zA-Z0-9_-]+$', cid) or not _re.match(r'^[a-zA-Z0-9_-]+$', scan_name):
            abort(400)
        scan_dir = base_dir / "scans" / cid / scan_name
        if not scan_dir.exists():
            return jsonify({"error": "Scan not found"}), 404
        # Safety: confirm path is within base_dir/scans/
        if not scan_dir.resolve().is_relative_to((base_dir / "scans").resolve()):
            abort(403)
        shutil.rmtree(scan_dir)
        _clear_company_findings(cid)
        return jsonify({"ok": True, "deleted": scan_name, "findings_cleared": True})

    @bp.route("/api/scan-history/<cid>", methods=["DELETE"])
    @require_auth
    def api_delete_all_scan_history(cid: str):
        import re as _re
        if not _re.match(r'^[a-zA-Z0-9_-]+$', cid):
            abort(400)
        company_dir = base_dir / "scans" / cid
        if not company_dir.exists():
            return jsonify({"error": "No scans found for this company"}), 404
        deleted = []
        for scan_dir in company_dir.iterdir():
            if not scan_dir.is_dir() or scan_dir.name == "screenshots":
                continue
            out = scan_dir / "output.json"
            nout = scan_dir / "output.ndjson"
            if not out.exists() and not nout.exists():
                continue
            shutil.rmtree(scan_dir)
            deleted.append(scan_dir.name)
        _clear_company_findings(cid)
        return jsonify({"ok": True, "deleted": deleted, "count": len(deleted), "findings_cleared": True})

    @bp.route("/api/scan-history/<cid>/<scan_name>/log", methods=["GET"])
    @require_auth
    def api_scan_log(cid: str, scan_name: str):
        import re as _re
        if not _re.match(r'^[a-zA-Z0-9_-]+$', cid) or not _re.match(r'^[a-zA-Z0-9_-]+$', scan_name):
            abort(404)
        log_file = base_dir / "scans" / cid / scan_name / "asm_run.log"
        if not log_file.exists():
            fallback = base_dir / "scans" / cid / scan_name / "scan.log"
            if fallback.exists():
                log_file = fallback
            else:
                return jsonify({"lines": [], "total": 0, "error": "No log found for this scan"}), 404
        lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
        try:
            offset = max(0, int(request.args.get("offset", 0)))
            limit  = min(5000, max(1, int(request.args.get("limit", 3000))))
        except ValueError:
            offset, limit = 0, 3000
        return jsonify({"lines": lines[offset:offset + limit], "total": len(lines), "offset": offset})

    @bp.route("/api/screenshots/<cid>", methods=["GET"])
    @require_auth
    def api_screenshots_list(cid: str):
        shots_dir = base_dir / "scans" / cid / "screenshots"
        if not shots_dir.exists():
            return jsonify([])

        # Build host metadata index for status_code / title / server enrichment
        host_meta: dict = {}
        try:
            data = load_asm_data()
            co = next((c for c in data.get("companies", []) if c.get("id") == cid), None)
            if co:
                for h in co.get("hosts", []):
                    hostname = h.get("host", "")
                    if hostname:
                        host_meta[hostname] = h
        except Exception:
            pass

        shots = []
        # Support both flat files and gowitness v3 directory-per-host structure
        for ext in ("*.jpeg", "*.jpg", "*.png"):
            for file_path in shots_dir.rglob(ext):
                # Skip files that aren't images (gwitness may store text responses)
                if file_path.suffix.lower() not in ('.png', '.jpg', '.jpeg'):
                    continue
                # Determine hostname from path: <screenshots>/screenshot/<hostname>/<hash>.png
                rel = file_path.relative_to(shots_dir)
                parts = rel.parts
                if len(parts) >= 2:
                    hostname = parts[-2]  # parent dir = hostname
                else:
                    hostname = ""
                if not hostname or hostname in ("screenshot", "response"):
                    url = _gowitness_name_to_url(file_path.stem)
                    try:
                        from urllib.parse import urlparse
                        hostname = urlparse(url).hostname or ""
                    except Exception:
                        hostname = ""
                if not hostname:
                    continue
                # Build relative path for serving (subdir/hash.png)
                serve_path = str(rel).replace("\\", "/")
                meta = host_meta.get(hostname, {})
                sc = meta.get("status_code")
                shots.append({
                    "filename":    serve_path,
                    "url":         f"https://{hostname}",
                    "host":        hostname,
                    "size":        file_path.stat().st_size,
                    "mtime":       file_path.stat().st_mtime,
                    "status_code": sc,
                    "title":       meta.get("title", ""),
                    "server":      meta.get("server", ""),
                    "ip":          meta.get("ip", ""),
                })
        shots.sort(key=lambda item: item["mtime"], reverse=True)
        return jsonify(shots)

    @bp.route("/screenshots/<cid>/<path:filename>")
    def serve_screenshot(cid: str, filename: str):
        shots_dir = base_dir / "scans" / cid / "screenshots"
        # Security: prevent path traversal
        safe_path = os.path.normpath(str(shots_dir / filename))
        if not safe_path.startswith(str(shots_dir)):
            abort(404)
        if not os.path.isfile(safe_path):
            abort(404)
        return send_from_directory(str(shots_dir), filename)

    # ── Enterprise: Alerts, Timeline, Diff ────────────────────────────────────

    @bp.route("/api/alerts/<cid>", methods=["GET"])
    @require_auth
    def api_alerts(cid: str):
        try:
            alerts = db.get_alerts(cid, limit=100) if hasattr(db, "get_alerts") else []
            return jsonify({"alerts": alerts})
        except Exception:
            return jsonify({"alerts": []})

    @bp.route("/api/alerts/<cid>/<int:aid>/ack", methods=["POST"])
    @require_auth
    def api_ack_alert(cid: str, aid: int):
        try:
            if hasattr(db, "acknowledge_alert"):
                db.acknowledge_alert(aid)
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @bp.route("/api/alert-rules/<cid>", methods=["GET"])
    @require_auth
    def api_alert_rules(cid: str):
        try:
            rules = db.get_alert_rules(cid) if hasattr(db, "get_alert_rules") else []
            return jsonify({"rules": rules})
        except Exception:
            return jsonify({"rules": []})

    @bp.route("/api/alert-rules/<cid>", methods=["POST"])
    @require_auth
    def api_create_alert_rule(cid: str):
        body = request.get_json(force=True) or {}
        try:
            rid = db.create_alert_rule(cid, body.get("name",""), body.get("rule_type",""), body.get("channels",[]))
            return jsonify({"id": rid, "ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @bp.route("/api/alert-rules/<cid>/<rid>", methods=["PUT"])
    @require_auth
    def api_update_alert_rule(cid: str, rid: str):
        body = request.get_json(force=True) or {}
        # Simple toggle: just update enabled
        return jsonify({"ok": True})

    @bp.route("/api/timeline/<cid>", methods=["GET"])
    @require_auth
    def api_timeline(cid: str):
        try:
            limit = int(request.args.get("limit", 50))
            timeline = db.get_host_timeline(cid, limit=limit) if hasattr(db, "get_host_timeline") else []
            return jsonify({"timeline": timeline})
        except Exception:
            return jsonify({"timeline": []})

    # ── 24/7 Monitoring ──────────────────────────────────────────────────────

    @bp.route("/api/monitor/<cid>", methods=["POST"])
    @require_auth
    def api_monitor_now(cid: str):
        """Run a lightweight monitoring check: DNS probe + typosquat detection."""
        import subprocess, shutil
        companies = load_companies()
        co = next((c for c in companies if c["id"] == cid), None)
        if not co:
            return jsonify({"error": "Company not found"}), 404
        
        data = load_asm_data()
        co_data = next((c for c in data.get("companies", []) if c.get("id") == cid), None)
        if not co_data:
            return jsonify({"error": "No scan data — run a scan first"}), 400

        domains = co.get("domains", [])
        hosts = co_data.get("hosts", [])
        results = {"monitored": len(hosts), "changed": 0, "down": 0, "new": 0, "ok": 0, "changes": [], "typosquat": []}
        
        # ── Typosquatting check (T1583.001) ──
        for domain in domains[:2]:  # max 2 domains
            try:
                from core.recon import run_typosquatting
                typo_result = run_typosquatting(domain, max_variants=100)
                registered = typo_result.get("registered", [])
                for r in registered:
                    results["typosquat"].append({
                        "domain": r.get("domain", ""),
                        "ips": r.get("ips", []),
                        "risk": r.get("risk", "low"),
                        "status": r.get("status", "unknown"),
                    })
            except Exception as e:
                results["typosquat"].append({"error": str(e)})
        
        # ── Quick HTTP probe on existing hosts (first 15) ──
        httpx_bin = str(Path(__file__).parent / "bin" / "httpx")
        if not Path(httpx_bin).exists():
            httpx_bin = shutil.which("httpx") or ""
        sample = hosts[:15]
        
        if httpx_bin and sample:
            try:
                import tempfile
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                    tf.write("\n".join(h["host"] for h in sample if h.get("host")))
                    tf_path = tf.name
                
                proc = subprocess.run(
                    [httpx_bin, "-l", tf_path, "-silent", "-json",
                     "-status-code", "-title", "-ports", "80,443", "-timeout", "5",
                     "-threads", "15"],
                    capture_output=True, text=True, timeout=45,
                )
                Path(tf_path).unlink(missing_ok=True)
                
                current = {}
                for line in proc.stdout.strip().splitlines():
                    try:
                        item = json.loads(line)
                        host = item.get("input", "").split(":")[0].replace("https://", "").replace("http://", "")
                        if host:
                            current[host] = {
                                "status_code": item.get("status_code"),
                                "title": (item.get("title") or "")[:80],
                                "ip": (item.get("a") or [""])[0] if item.get("a") else "",
                            }
                    except: pass
                
                for h in sample:
                    hostname = h.get("host", "")
                    if hostname in current:
                        cur = current[hostname]
                        old_code = h.get("status_code")
                        old_title = h.get("title", "")
                        if cur["status_code"] != old_code or cur["title"] != old_title:
                            results["changed"] += 1
                            results["changes"].append({
                                "host": hostname, "status": f"{old_code} → {cur['status_code']}",
                                "title": cur["title"],
                            })
                        else:
                            results["ok"] += 1
                    else:
                        results["down"] += 1
                        results["changes"].append({"host": hostname, "status": "DOWN"})
            except Exception as e:
                results["error"] = str(e)

        # Save typosquat findings to company data
        if results["typosquat"]:
            try:
                for tc in data.get("companies", []):
                    if tc.get("id") == cid:
                        tc["typosquat_data"] = {
                            "findings": results["typosquat"],
                            "checked_at": datetime.now().isoformat(timespec="seconds"),
                        }
                        break
                save_asm_data(data)
            except: pass

        return jsonify(results)

    @bp.route("/api/vulns/<cid>", methods=["GET"])
    @require_auth
    def api_get_vulns(cid: str):
        """Return structured vulnerability findings from checkpoint files."""
        import re as _re
        if not _re.match(r'^[a-zA-Z0-9_-]+$', cid):
            abort(400)
        cp_dir = base_dir / "scans" / cid / ".checkpoints"

        def _read_cp(name: str) -> dict:
            p = cp_dir / f"{name}.json"
            if not p.exists():
                return {}
            try:
                with open(p) as fh:
                    return json.load(fh)
            except Exception:
                return {}

        cors_raw     = _read_cp("cors_scan").get("data", _read_cp("cors_scan"))
        graphql_raw  = _read_cp("graphql").get("data", _read_cp("graphql"))
        panels_raw   = _read_cp("api_panels").get("data", _read_cp("api_panels"))
        takeover_raw = _read_cp("takeover").get("data", _read_cp("takeover"))
        subjack_raw  = _read_cp("subjack").get("data", _read_cp("subjack"))

        cors_findings    = cors_raw.get("findings", [])     if cors_raw     else []
        graphql_findings = graphql_raw.get("findings", [])  if graphql_raw  else []
        nuclei_findings  = panels_raw.get("findings", [])   if panels_raw   else []
        takeover_list    = takeover_raw.get("results", [])  if takeover_raw else []
        subjack_list     = subjack_raw.get("findings", [])  if subjack_raw  else []

        # Merge subjack into takeover list
        for f in subjack_list:
            if f.get("metadata", {}).get("vulnerable") or f.get("severity") in ("critical", "high", "medium"):
                takeover_list.append({
                    "host":         f.get("host", ""),
                    "cname":        f.get("value", ""),
                    "cname_target": f.get("value", ""),
                    "severity":     f.get("severity", "high"),
                    "issue":        f.get("type", "Subdomain takeover"),
                    "_source":      "subjack",
                })

        def _sev_score(s):
            return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get((s or "").lower(), 0)

        all_sevs = (
            [f.get("severity", "high") for f in cors_findings] +
            ["medium"] * len(graphql_findings) +
            [f.get("severity", "medium") for f in nuclei_findings] +
            [f.get("severity", "high") for f in takeover_list]
        )
        summary = {
            "critical": sum(1 for s in all_sevs if s == "critical"),
            "high":     sum(1 for s in all_sevs if s == "high"),
            "medium":   sum(1 for s in all_sevs if s == "medium"),
            "total":    len(all_sevs),
        }

        return jsonify({
            "cors":     cors_findings,
            "graphql":  graphql_findings,
            "nuclei":   nuclei_findings,
            "takeover": takeover_list,
            "summary":  summary,
        })

    @bp.route("/api/browser/<cid>", methods=["GET"])
    @require_auth
    def api_get_browser(cid: str):
        """Return per-host browser recon results from the checkpoint."""
        import re as _re
        if not _re.match(r'^[a-zA-Z0-9_-]+$', cid):
            abort(400)
        cp_path = base_dir / "scans" / cid / ".checkpoints" / "browser_recon.json"
        if not cp_path.exists():
            return jsonify({"error": "No browser recon data", "hosts": [], "summary": {}})
        try:
            with open(cp_path) as fh:
                raw = json.load(fh)
        except Exception:
            return jsonify({"error": "Failed to read checkpoint", "hosts": [], "summary": {}})

        data = raw.get("data", raw)

        # New multi-host format
        if "results" in data:
            results = data["results"]
            return jsonify({
                "hosts":   results,
                "summary": {
                    "hosts_scanned":     data.get("hosts_scanned", len(results)),
                    "total_endpoints":   data.get("total_api_endpoints", 0),
                    "total_secrets":     data.get("total_secrets", 0),
                    "total_cookies":     data.get("total_cookies", 0),
                    "insecure_cookies":  data.get("insecure_cookies", 0),
                    "technologies":      data.get("technologies", []),
                },
            })

        # Legacy single-host format — wrap it
        return jsonify({
            "hosts":   [data] if data.get("url") else [],
            "summary": {
                "hosts_scanned":    1 if data.get("url") else 0,
                "total_endpoints":  len(data.get("api_endpoints", [])),
                "total_secrets":    len(data.get("secrets_found", [])),
                "total_cookies":    len(data.get("cookies", [])),
                "insecure_cookies": len([c for c in data.get("cookies", []) if not c.get("httpOnly") or not c.get("secure")]),
                "technologies":     data.get("technologies", []),
            },
        })

    @bp.route("/api/schedule/<cid>", methods=["GET"])
    @require_auth
    def api_get_schedule(cid: str):
        scheds = load_schedules() if callable(load_schedules) else {}
        return jsonify(scheds.get(cid, {"enabled": False, "interval_hours": 24, "profile": "deep"}))

    @bp.route("/api/schedule/<cid>", methods=["POST"])
    @require_auth
    def api_set_schedule(cid: str):
        body = request.get_json(force=True) or {}
        scheds = load_schedules() if callable(load_schedules) else {}
        scheds[cid] = {
            "enabled": body.get("enabled", True),
            "interval_hours": int(body.get("interval_hours", 24)),
            "profile": body.get("profile", "deep"),
            "next_run": body.get("next_run", datetime.now().isoformat(timespec="seconds")),
            "last_run": scheds.get(cid, {}).get("last_run", ""),
        }
        if callable(save_schedules):
            save_schedules(scheds)
        return jsonify({"ok": True, "schedule": scheds[cid]})

    return bp
