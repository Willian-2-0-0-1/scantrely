#!/usr/bin/env python3
"""
Reporting Flask routes for risk, exports, and aggregated findings.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from html import escape as _esc

from flask import Blueprint, Response, jsonify, request, g


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def findings_to_sarif(company: dict) -> dict:
    findings = company.get("findings") or []
    rules = {}
    results = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rule_id = str(finding.get("module") or finding.get("category") or "finding")[:64] or "finding"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule_id},
            }
        uri = finding.get("url") or finding.get("host") or company.get("name") or "unknown"
        if uri and not str(uri).startswith(("http://", "https://", "file:")):
            uri = f"https://{uri}"
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(str(finding.get("severity", "info")).lower(), "note"),
            "message": {"text": finding.get("title") or finding.get("desc") or "Finding"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                }
            }],
            "properties": {
                "severity": finding.get("severity", ""),
                "host": finding.get("host", ""),
                "category": finding.get("category", ""),
            },
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Scantrely",
                    "version": "1.3.11",
                    "informationUri": "https://github.com/Willian-2-0-0-1/scantrely",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def _render_report_html(company: dict, findings: list, risk: dict) -> str:
    sev_color = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#3b82f6", "info": "#6b7280"}
    f_rows = ""
    for finding in sorted(findings, key=lambda item: ["critical", "high", "medium", "low", "info"].index(item.get("severity", "info"))):
        color = sev_color.get(finding.get("severity", "info"), "#6b7280")
        f_rows += (
            f'<tr><td style="color:{color};font-weight:700">{_esc(finding.get("severity", "").upper())}</td>'
            f'<td>{_esc(finding.get("category", ""))}</td><td>{_esc(finding.get("title", ""))}</td>'
            f'<td>{_esc(finding.get("host", ""))}</td><td>{_esc(finding.get("desc", "")[:120])}</td></tr>\n'
        )
    h_rows = ""
    for host in company.get("hosts", [])[:200]:
        if not isinstance(host, dict):
            continue
        ports = _esc(", ".join(str(port) for port in host.get("ports", [])))
        h_rows += (
            f'<tr><td>{_esc(host.get("host", ""))}</td><td>{_esc(host.get("ip", ""))}</td>'
            f'<td>{ports}</td><td>{_esc(host.get("waf", ""))}</td>'
            f'<td>{_esc(", ".join(host.get("technologies", [])[:3]))}</td></tr>\n'
        )
    cov = company.get("edge_coverage") or {}
    cov_html = ""
    if cov.get("total"):
        warn = "" if cov.get("negatives_meaningful") else (
            '<p style="color:#f97316;font-weight:700">A maior parte dos testes n\u00e3o chegou na aplica\u00e7\u00e3o: '
            'a aus\u00eancia de achados abaixo n\u00e3o prova que ela \u00e9 segura.</p>')
        mod_rows = "".join(
            f'<tr><td>{_esc(m)}</td><td>{c.get("reached_application", 0)}/{c.get("total", 0)}</td>'
            f'<td>{c.get("edge_blocked", 0)}</td><td>{c.get("edge_throttled", 0)}</td></tr>'
            for m, c in (cov.get("by_module") or {}).items())
        cov_html = (
            f'<h2>Cobertura dos testes</h2><p>{_esc(cov.get("summary", ""))}</p>{warn}'
            '<table><tr><th>M\u00f3dulo</th><th>Chegaram na aplica\u00e7\u00e3o</th><th>Bloqueadas pela borda</th><th>Limitadas</th></tr>'
            f'{mod_rows}</table>')
    score = risk["score"]
    score_color = sev_color.get(risk["label"].lower(), "#6b7280")
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>ASM Report — {company['name']}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:40px;background:#0f172a;color:#e2e8f0}}
h1{{color:#00c9a7}}h2{{color:#94a3b8;border-bottom:1px solid #334155;padding-bottom:6px}}
table{{width:100%;border-collapse:collapse;margin:16px 0;font-size:.85rem}}
th{{background:#1e293b;padding:8px 12px;text-align:left;color:#94a3b8}}
td{{padding:7px 12px;border-bottom:1px solid #1e293b}}
.score{{font-size:3rem;font-weight:900;color:{score_color}}}
.badge{{display:inline-block;padding:2px 10px;border-radius:20px;font-size:.75rem;font-weight:700}}
</style></head><body>
<h1>Attack Surface Report — {company['name']}</h1>
<p style="color:#64748b">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} · Last scan: {company.get('last_scan','?')}</p>
<h2>Risk Score</h2>
<div class="score">{score}</div>
<span class="badge" style="background:{score_color}">{risk['label']}</span>
<p>{risk['breakdown']['critical_findings']} critical · {risk['breakdown']['high_findings']} high ·
{risk['breakdown']['medium_findings']} medium · {risk['breakdown']['low_findings']} low findings</p>
<h2>Summary</h2>
<table><tr>
<th>Subdomains</th><th>Live Hosts</th><th>Open Ports</th><th>WAF Protected</th><th>Findings</th>
</tr><tr>
<td>{company['stats'].get('subdomains',0)}</td><td>{company['stats'].get('live_hosts',0)}</td>
<td>{company['stats'].get('open_ports',0)}</td><td>{company['stats'].get('waf_protected',0)}</td>
<td>{len(findings)}</td>
</tr></table>
{cov_html}
<h2>Findings ({len(findings)})</h2>
<table><tr><th>Severity</th><th>Category</th><th>Title</th><th>Host</th><th>Description</th></tr>
{f_rows or '<tr><td colspan="5" style="color:#64748b">No findings</td></tr>'}
</table>
<h2>Hosts ({len(company.get('hosts',[]))})</h2>
<table><tr><th>Host</th><th>IP</th><th>Ports</th><th>WAF</th><th>Technologies</th></tr>
{h_rows or '<tr><td colspan="5" style="color:#64748b">No hosts</td></tr>'}
</table>
<p style="color:#334155;font-size:.75rem;margin-top:40px">Generated by ASM Platform</p>
</body></html>"""


def create_reporting_blueprint(
    *,
    require_auth,
    get_company_data,
    compute_risk_score,
    load_whitelist,
    load_asm_data,
    audit,
    base_dir=None,
):
    bp = Blueprint("reporting_routes", __name__)

    @bp.route("/api/risk/<cid>", methods=["GET"])
    @require_auth
    def api_risk(cid: str):
        company = get_company_data(cid)
        if not company:
            return jsonify({"error": "No data for this company"}), 404
        return jsonify(compute_risk_score(company))

    @bp.route("/api/export/<cid>", methods=["GET"])
    @require_auth
    def api_export(cid: str):
        fmt = request.args.get("format", "json")
        company = get_company_data(cid)
        if not company:
            return jsonify({"error": "No data"}), 404

        audit("export", cid, f"format={fmt}")

        if fmt == "json":
            return Response(
                json_dumps(company, indent=2),
                mimetype="application/json",
                headers={"Content-Disposition": f'attachment; filename="{cid}_asm.json"'},
            )

        if fmt == "csv_findings":
            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(["severity", "category", "title", "host", "url", "desc", "module"])
            for finding in company.get("findings", []):
                writer.writerow([
                    finding.get("severity", ""),
                    finding.get("category", ""),
                    finding.get("title", ""),
                    finding.get("host", ""),
                    finding.get("url", ""),
                    finding.get("desc", ""),
                    finding.get("module", ""),
                ])
            return Response(
                out.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": f'attachment; filename="{cid}_findings.csv"'},
            )

        if fmt == "csv_hosts":
            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(["host", "ip", "ports", "waf", "cdn", "technologies", "status_code", "title", "cert_expiry"])
            for host in company.get("hosts", []):
                if not isinstance(host, dict):
                    writer.writerow([host])
                    continue
                writer.writerow([
                    host.get("host", ""),
                    host.get("ip", ""),
                    "|".join(str(port) for port in host.get("ports", [])),
                    host.get("waf", ""),
                    host.get("cdn", ""),
                    "|".join(host.get("technologies", [])),
                    host.get("status_code", ""),
                    host.get("title", ""),
                    host.get("cert_expiry", ""),
                ])
            return Response(
                out.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": f'attachment; filename="{cid}_hosts.csv"'},
            )

        if fmt == "html":
            risk = compute_risk_score(company)
            whitelist = load_whitelist().get(cid, [])
            suppressed = {(entry["host"], entry["title"]) for entry in whitelist}
            active_findings = [
                finding for finding in company.get("findings", [])
                if (finding.get("host", ""), finding.get("title", "")) not in suppressed
            ]
            html = _render_report_html(company, active_findings, risk)
            return Response(
                html,
                mimetype="text/html",
                headers={"Content-Disposition": f'attachment; filename="{cid}_report.html"'},
            )

        if fmt == "sarif":
            payload = findings_to_sarif(company)
            return Response(
                json.dumps(payload, indent=2, ensure_ascii=False),
                mimetype="application/sarif+json",
                headers={"Content-Disposition": f'attachment; filename="{cid}_findings.sarif"'},
            )

        if fmt == "pdf":
            risk = compute_risk_score(company)
            whitelist = load_whitelist().get(cid, [])
            suppressed = {(entry["host"], entry["title"]) for entry in whitelist}
            active_findings = [
                finding for finding in company.get("findings", [])
                if (finding.get("host", ""), finding.get("title", "")) not in suppressed
            ]
            html = _render_report_html(company, active_findings, risk)
            try:
                from playwright.sync_api import sync_playwright
            except ImportError:
                return jsonify({"error": "playwright not installed"}), 500
            try:
                with sync_playwright() as pw:
                    browser = pw.chromium.launch()
                    page = browser.new_page()
                    page.set_content(html, wait_until="load")
                    pdf_bytes = page.pdf(format="A4", print_background=True)
                    browser.close()
            except Exception as e:
                return jsonify({"error": f"PDF generation failed: {e}"}), 500
            return Response(
                pdf_bytes,
                mimetype="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{cid}_report.pdf"'},
            )

        return jsonify({"error": f"Unknown format: {fmt}"}), 400

    @bp.route("/api/findings/all", methods=["GET"])
    @require_auth
    def api_findings_all():
        data = load_asm_data()
        sev = request.args.get("severity", "")
        cat = request.args.get("category", "")
        company_id = request.args.get("company", "")
        sess = getattr(g, "session", {}) or {}
        scope = sess.get("scoped_companies")
        is_super = sess.get("role") == "super_admin"
        if not is_super and scope is not None and not scope:
            return jsonify([])
        result = []
        whitelist_all = load_whitelist()
        for company in data.get("companies", []):
            if not is_super and scope is not None and "*" not in scope and company.get("id") not in scope:
                continue
            suppressed = {(entry["host"], entry["title"]) for entry in whitelist_all.get(company["id"], [])}
            for finding in company.get("findings", []):
                if (finding.get("host", ""), finding.get("title", "")) in suppressed:
                    continue
                if sev and finding.get("severity", "") != sev:
                    continue
                if cat and finding.get("category", "") != cat:
                    continue
                if company_id and company["id"] != company_id:
                    continue
                result.append({**finding, "company_id": company["id"], "company_name": company["name"]})
        result.sort(key=lambda item: ["critical", "high", "medium", "low", "info"].index(item.get("severity", "info")))
        return jsonify(result)

    return bp


def json_dumps(data: dict, indent: int | None = None) -> str:
    return json.dumps(data, indent=indent, ensure_ascii=False)
