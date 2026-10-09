"""Shodan Intelligence — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
import json
import os
import time
from core.reconlib.asn import _extract_public_ips
from core.reconlib.base import http_get

# ── Shodan Intelligence ──

def run_shodan(ips: list, api_key: str = None) -> dict:
    """Query Shodan for open ports, banners, and CVEs per IP."""
    if not api_key:
        # Try env
        api_key = os.environ.get("SHODAN_API_KEY","")
    if not api_key:
        return {"error": "No Shodan API key — set SHODAN_API_KEY env var", "results": []}

    results = []
    unique_ips = _extract_public_ips(ips)

    for ip in unique_ips:
        status, body, _ = http_get(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            timeout=10, retries=2,
        )
        if status == 401:
            return {"error": "Invalid Shodan API key", "results": results}
        if status == 404:
            results.append({"ip": ip, "severity": "info", "ports": [], "vulns": [], "not_indexed": True})
            time.sleep(1)
            continue
        if status != 200 or not body:
            results.append({"ip": ip, "error": f"HTTP {status}", "severity": "info", "ports": [], "vulns": []})
            time.sleep(1)
            continue
        try:
            data = json.loads(body)
            ports     = data.get("ports", [])
            vulns     = list(data.get("vulns", {}).keys())
            results.append({
                "ip":        ip,
                "org":       data.get("org", ""),
                "isp":       data.get("isp", ""),
                "country":   data.get("country_name", ""),
                "city":      data.get("city", ""),
                "ports":     ports,
                "vulns":     vulns,
                "tags":      data.get("tags", []),
                "hostnames": data.get("hostnames", []),
                "os":        data.get("os", ""),
                "severity":  "critical" if vulns else ("high" if any(p in ports for p in [22, 3389, 3306, 5432, 6379, 27017]) else "medium"),
            })
        except Exception as e:
            results.append({"ip": ip, "error": str(e), "severity": "info", "ports": [], "vulns": []})
        time.sleep(1)  # Shodan rate limit

    total_vulns = sum(len(r.get("vulns",[])) for r in results)
    return {
        "results":     sorted(results, key=lambda r: ["critical","high","medium","info"].index(r.get("severity","info"))),
        "total_ips":   len(unique_ips),
        "total_vulns": total_vulns,
        "scanned_at":  datetime.now().isoformat(timespec="seconds"),
    }
