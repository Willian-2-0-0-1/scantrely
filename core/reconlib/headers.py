"""Vendor / Edge Appliance Fingerprinting — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from datetime import datetime
import re
from core.reconlib.base import MODULE_BUDGET_S, _log, http_get

# ── Security Headers ──

HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "desc": "HSTS — forces HTTPS connections",
        "missing_sev": "high",
        "check": lambda v: (
            "missing max-age" if "max-age" not in v.lower() else
            "max-age too short (<1y)" if re.search(r"max-age=(\d+)", v, re.I) and
                int(re.search(r"max-age=(\d+)", v, re.I).group(1)) < 31536000 else None
        ),
    },
    "Content-Security-Policy": {
        "desc": "CSP — prevents XSS and data injection",
        "missing_sev": "high",
        "check": lambda v: (
            "unsafe-inline in script-src" if "unsafe-inline" in v else
            "unsafe-eval in script-src" if "unsafe-eval" in v else None
        ),
    },
    "X-Frame-Options": {
        "desc": "Prevents clickjacking",
        "missing_sev": "medium",
        "check": lambda v: (
            "ALLOW-FROM is deprecated" if "ALLOW-FROM" in v.upper() else None
        ),
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME sniffing",
        "missing_sev": "medium",
        "check": lambda v: (
            "should be 'nosniff'" if v.strip().lower() != "nosniff" else None
        ),
    },
    "Referrer-Policy": {
        "desc": "Controls referrer information",
        "missing_sev": "low",
        "check": lambda v: (
            "unsafe-url leaks full URL" if v.strip().lower() == "unsafe-url" else None
        ),
    },
    "Permissions-Policy": {
        "desc": "Controls browser features",
        "missing_sev": "low",
        "check": lambda v: None,
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS filter (deprecated)",
        "missing_sev": "info",
        "check": lambda v: (
            "mode=block recommended" if "mode=block" not in v else None
        ),
    },
    "Cross-Origin-Opener-Policy": {
        "desc": "Prevents cross-origin window attacks",
        "missing_sev": "low",
        "check": lambda v: None,
    },
    "Cross-Origin-Resource-Policy": {
        "desc": "Controls cross-origin resource sharing",
        "missing_sev": "low",
        "check": lambda v: None,
    },
}


def _fetch_headers(url: str, timeout: int = 6) -> tuple:
    status, _, resp_h = http_get(url, timeout=timeout, retries=1, return_headers=True)
    return resp_h, status, url


def run_security_headers(host: str) -> dict:
    """Analyse HTTP security headers for a single host."""
    url = f"https://{host}" if not host.startswith("http") else host
    headers, status, final_url = _fetch_headers(url)
    # normalise header keys to Title-Case
    headers_norm = {k.title(): v for k, v in headers.items()}

    findings = []
    scores   = []

    for hdr, meta in HEADER_CHECKS.items():
        val = headers_norm.get(hdr)
        if val is None:
            findings.append({
                "header":   hdr,
                "present":  False,
                "value":    None,
                "severity": meta["missing_sev"],
                "issue":    f"Missing — {meta['desc']}",
            })
            scores.append(meta["missing_sev"])
        else:
            issue = meta["check"](val)
            sev   = "medium" if issue else "pass"
            findings.append({
                "header":   hdr,
                "present":  True,
                "value":    val[:200],
                "severity": sev,
                "issue":    issue or "OK",
            })
            if issue:
                scores.append(sev)

    # Cookie security
    cookie_issues = []
    for k, v in headers_norm.items():
        if k.lower() == "set-cookie":
            if "secure" not in v.lower():
                cookie_issues.append({"cookie": v[:80], "issue": "Missing Secure flag", "severity": "high"})
            if "httponly" not in v.lower():
                cookie_issues.append({"cookie": v[:80], "issue": "Missing HttpOnly flag", "severity": "medium"})
            if "samesite" not in v.lower():
                cookie_issues.append({"cookie": v[:80], "issue": "Missing SameSite flag", "severity": "medium"})

    sev_order = ["critical","high","medium","low","info","pass"]
    overall = min(scores, key=lambda s: sev_order.index(s)) if scores else "pass"

    return {
        "host":          host,
        "url":           final_url,
        "status":        status,
        "findings":      findings,
        "cookie_issues": cookie_issues,
        "overall":       overall,
        "score":         sum({"critical":0,"high":20,"medium":10,"low":5,"info":2,"pass":100}.get(s,0) for s in scores) // max(len(scores),1),
        "scanned_at":    datetime.now().isoformat(timespec="seconds"),
    }



# ── Vendor / Edge Appliance Fingerprinting ──

_VENDOR_FINGERPRINTS = [
    # name, paths, response_signature, severity, cve_note
    ("Citrix Netscaler / ADC", ["/vpn/index.html", "/logon/LogonPoint/tmindex.html", "/citrix/", "/logon/LogonPoint/index.html"],
     ["Citrix", "Netscaler", "ADC", "netscaler", "logonpoint"], "critical",
     "CVE-2023-3519 RCE, CVE-2019-19781 path traversal — both KEV-listed"),
    ("F5 BIG-IP", ["/tmui/login.jsp", "/tmui/", "/mgmt/tm/sys/"],
     ["BIG-IP", "bigip", "tmui", "F5 Networks"], "critical",
     "CVE-2022-1388 auth bypass RCE, CVE-2023-46747 — KEV-listed"),
    ("Pulse Secure / Ivanti Connect", ["/dana-na/", "/dana-na/auth/url_default/welcome.cgi", "/dana-na/auth/url_default/welcome.cgi?p=user-conf"],
     ["Pulse Secure", "Ivanti", "dana-na", "welcome.cgi"], "critical",
     "CVE-2024-21887 command injection, CVE-2023-46805 auth bypass — chained, both KEV"),
    ("FortiGate / FortiOS", ["/remote/login", "/remote/info", "/api/v2/"],
     ["FortiGate", "FortiOS", "fortinet"], "critical",
     "CVE-2024-21762 RCE, CVE-2022-42475 heap-based RCE — both KEV"),
    ("PaloAlto GlobalProtect", ["/global-protect/", "/global-protect/login.esp", "/global-protect/portal/css/login.css"],
     ["GlobalProtect", "Palo Alto", "PAN-OS"], "critical",
     "CVE-2024-3400 command injection RCE — KEV-listed"),
    ("Cisco ASA / AnyConnect", ["/+CSCOE+/", "/CSCOE/index.html", "/webvpn.html", "/+CSCOE+/portal.html"],
     ["Cisco", "CSCOE", "AnyConnect", "webvpn"], "high",
     "CVE-2020-3452 file read, CVE-2018-0101 RCE"),
    ("VMware vCenter / ESXi", ["/ui/", "/vsphere-client/", "/sdk/"],
     ["VMware", "vCenter", "vSphere", "ESXi"], "critical",
     "CVE-2021-21972 RCE, CVE-2021-21985 RCE — KEV-listed"),
    ("Microsoft Exchange OWA", ["/owa/", "/owa/auth/logon.aspx", "/ecp/", "/autodiscover/"],
     ["Outlook Web", "Exchange", "owa", "Outlook Web App"], "high",
     "ProxyShell, ProxyLogon, ProxyNotShell — multiple KEV-listed CVEs"),
    ("Jenkins", ["/jenkins/", "/jenkins/login", "/script"],
     ["Jenkins", "jenkins"], "medium",
     "CVE-2024-23897 file read, CVE-2018-1000861 RCE"),
    ("Apache Tomcat", ["/manager/html", "/host-manager/html"],
     ["Tomcat", "Apache Tomcat", "Web Application Manager"], "medium",
     "CVE-2025-24813 path traversal RCE — KEV-listed"),
    ("Jupyter", ["/tree", "/lab", "/login?next=%2Ftree%3F"],
     ["Jupyter", "jupyter", "JupyterLab"], "medium",
     "Often unauthenticated; grants interactive Python shell"),
    ("Grafana", ["/login", "/api/health"],
     ["Grafana", "grafana"], "low",
     "Monitoring dashboard; CVE-2021-43798 path traversal"),
]


def run_vendor_fingerprint(hosts: list) -> dict:
    """Probe known vendor paths on each host to fingerprint edge appliances."""
    import concurrent.futures
    results = []
    targets = [h if isinstance(h, str) else h.get("host", "") for h in hosts]
    targets = [t for t in targets if t][:100]

    def _probe_host(host: str) -> list:
        host_results = []
        for proto in ["https", "http"]:
            for vendor_name, paths, sigs, severity, cve_note in _VENDOR_FINGERPRINTS:
                for path in paths[:3]:
                    try:
                        url = f"{proto}://{host}{path}"
                        status, body, _ = http_get(url, timeout=4, retries=1)
                        if status and body:
                            body_lower = body[:2000].decode("utf-8", "ignore").lower()
                            for sig in sigs:
                                if sig.lower() in body_lower:
                                    host_results.append({
                                        "host": host,
                                        "vendor": vendor_name,
                                        "url": url,
                                        "status": status,
                                        "severity": severity,
                                        "cve_note": cve_note,
                                    })
                                    break
                    except Exception:
                        continue
        return host_results

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=20)
    try:
        futures = {pool.submit(_probe_host, h): h for h in targets}
        try:
            for fut in concurrent.futures.as_completed(futures, timeout=MODULE_BUDGET_S):
                try:
                    results.extend(fut.result())
                except Exception:
                    _log.debug('recon.py:2064 erro ignorado', exc_info=True)
        except concurrent.futures.TimeoutError:
            pass  # timeout — return partial results collected so far
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    return {
        "findings": results,
        "vendors_found": sorted(set(r["vendor"] for r in results)),
        "total": len(results),
        "scanned_hosts": len(targets),
    }



def run_headers_bulk(hosts: list, max_hosts: int = 200) -> dict:
    """Analyse headers for live HTTPS hosts (capped for speed)."""
    targets = [
        h["host"] for h in hosts
        if 443 in h.get("ports", []) or "443" in h.get("ports", [])
        or h.get("status_code") is not None
    ][:max_hosts]
    results = []
    with ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(run_security_headers, h): h for h in targets}
        for fut in as_completed(futures):
            results.append(fut.result())

    # Summary stats
    missing_hsts  = sum(1 for r in results for f in r["findings"]
                        if f["header"] == "Strict-Transport-Security" and not f["present"])
    missing_csp   = sum(1 for r in results for f in r["findings"]
                        if f["header"] == "Content-Security-Policy" and not f["present"])
    cookie_issues = sum(len(r["cookie_issues"]) for r in results)

    return {
        "results":      sorted(results, key=lambda r: r.get("score",100)),
        "total_hosts":  len(results),
        "missing_hsts": missing_hsts,
        "missing_csp":  missing_csp,
        "cookie_issues": cookie_issues,
        "scanned_at":   datetime.now().isoformat(timespec="seconds"),
    }
