"""SALESFORCE RECON — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
import base64
import json
import re
import shutil
from core.reconlib.base import _log, http_get, subprocess

try:  # dnspython: checagem de CNAME do salesforce_recon (antes: NameError engolido)
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None


def _is_responsive(h: dict) -> bool:
    """Mesma regra de core.pipeline._is_responsive (não importado aqui para evitar ciclo)."""
    return bool(h.get("status_code") is not None or h.get("ports") or h.get("title"))

# ── SALESFORCE RECON ──────────────────────────────────────────────────────────

_SALESFORCE_PATTERNS = [
    r"\.my\.salesforce\.com$",
    r"\.my\.salesforce-setup\.com$",
    r"\.force\.com$",
    r"\.salesforce\.com$",
    r"\.cloudforce\.com$",
    r"\.database\.com$",
    r"\.site\.com$",  # force.com sites
]


_SALESFORCE_COMMUNITY_CHECKS = [
    "/s/",                                  # Community URL base
    "/services/apexrest/",                  # REST API exposed
    "/services/data/v",                     # REST API version endpoint
    "/s/global-search/%40uri?query=",       # Guest search (misconfig)
    "/sfsites/aura",                        # Aura framework
    "/webruntime",                          # LWR framework
    "/_nc_external/identity/session/",      # Session endpoint
    "/idp/endpoint/HttpPost",               # SAML endpoint
    "/.well-known/org-issuer-id",           # Org issuer
    "/s/sfsites/aura?r=",                   # Aura guest access
]


_SALESFORCE_ADMIN_CHECKS = [
    "/_ui/common/apex/debug/ApexCSIPage",   # Debug console
    "/soap/",                                # SOAP API info
    "/p/setup/custent/CustomizePage",       # Setup page (should be auth-walled)
    "/secur/logout.jsp",                    # Logout redirect vuln
    "/_ui/identity/verification/method",    # MFA verification page
    "/setup/forcecomHomepage.apexp",        # Setup homepage
    "/ui/setup/Setup",                      # Classic setup
    "/c/",                                  # Custom domain community
]



def _is_salesforce_host(host: str) -> bool:
    for pattern in _SALESFORCE_PATTERNS:
        if re.search(pattern, host, re.IGNORECASE):
            return True
    return False



def run_salesforce_recon(hosts: list, domains: list = None) -> dict:
    """Detect and scan Salesforce instances for common misconfigurations.

    Two-phase approach:
      1. DISCOVERY: probe subdomain patterns + check CNAME/DNS for SF redirects
      2. ANALYSIS: check Community guest access, exposed Aura/LWR, debug mode,
         CORS, API version disclosure, open redirect vectors, and more.

    Returns dict with keys: findings, total, salesforce_hosts, discovered, hosts_scanned, scanned_at
    """
    findings = []
    scanned = 0
    discovered = 0

    # ── Phase 1: DISCOVERY ─────────────────────────────────────────────────
    sf_hosts = [h for h in hosts if _is_salesforce_host(h.get("host", ""))]

    # Probe common Salesforce subdomain patterns for each target domain
    if domains:
        for domain in domains[:20]:
            base = domain.split(".")[0]
            sf_subdomain_patterns = [
                f"{base}.my.salesforce.com",
                f"{base}.force.com",
                f"{base}.cloudforce.com",
                f"{base}.salesforce.com",
                f"{base}-community.force.com",
                f"{base}-uat.my.salesforce.com",
                f"{base}-dev.my.salesforce.com",
                f"{base}-staging.my.salesforce.com",
                f"cs-{base}.force.com",
                f"c.{base}.force.com",
                f"{base}.secure.force.com",
                f"login.{base}.force.com",
                f"www.{base}.my.salesforce.com",
            ]
            for probe_host in sf_subdomain_patterns[:8]:  # limit per domain
                if any(h.get("host") == probe_host for h in sf_hosts):
                    continue  # already known
                try:
                    status, body, _ = http_get(f"https://{probe_host}", timeout=5, retries=0)
                    if status and status < 500:
                        sf_hosts.append({"host": probe_host, "status_code": status, "ip": "", "ports": []})
                        discovered += 1
                        findings.append({
                            "type": "salesforce_discovered",
                            "severity": "info",
                            "title": f"Salesforce instance discovered: {probe_host}",
                            "host": probe_host,
                            "module": "salesforce_recon",
                        })
                except Exception:
                    _log.debug('recon.py:10595 erro ignorado', exc_info=True)

    # Also check non-SF hosts for DNS CNAME / HTTP redirect to Salesforce
    if not sf_hosts or len(sf_hosts) < 10:
        for h in hosts[:100]:
            host = h.get("host", "")
            if not host or _is_salesforce_host(host):
                continue
            try:
                # DNS CNAME check
                try:
                    answers = dns.resolver.resolve(host, "CNAME")
                    for rdata in answers:
                        target = str(rdata.target).rstrip(".")
                        if _is_salesforce_host(target):
                            sf_hosts.append(h)
                            discovered += 1
                            findings.append({
                                "type": "salesforce_cname",
                                "severity": "medium",
                                "title": f"DNS CNAME to Salesforce: {host} -> {target}",
                                "host": host,
                                "value": target,
                                "module": "salesforce_recon",
                            })
                            break
                except Exception:
                    _log.debug('recon.py:10622 erro ignorado', exc_info=True)

                # HTTP redirect check
                status, body, headers = http_get(f"https://{host}", timeout=5, retries=0)
                if status in (301, 302) and headers:
                    location = str(headers.get("Location", ""))
                    if _is_salesforce_host(location):
                        sf_hosts.append(h)
                        discovered += 1
                        findings.append({
                            "type": "salesforce_redirect",
                            "severity": "low",
                            "title": f"HTTP redirect to Salesforce: {host} -> {location}",
                            "host": host,
                            "value": location,
                            "module": "salesforce_recon",
                        })
            except Exception:
                _log.debug('recon.py:10640 erro ignorado', exc_info=True)

    sf_hosts = sf_hosts[:30]  # cap

    # ── Phase 2: ANALYSIS ────────────────────────────────────────────────
    for h in sf_hosts:
        host = h.get("host", "")
        scheme = "https"

        # 1. Fingerprint the org: get instance info
        try:
            status, body, headers = http_get(f"{scheme}://{host}", timeout=8, retries=1)
            if status:
                scanned += 1
                sf_content = (body or "")[:2000]

                # Detect Salesforce version/flavor
                if "Salesforce" in sf_content or "sfdc" in sf_content.lower():
                    findings.append({
                        "type": "salesforce_detected",
                        "severity": "info",
                        "title": f"Salesforce instance: {host}",
                        "host": host,
                        "module": "salesforce_recon",
                    })
        except Exception:
            _log.debug('recon.py:10666 erro ignorado', exc_info=True)

        # 2. Community guest user checks
        for check_path in _SALESFORCE_COMMUNITY_CHECKS[:6]:  # most important checks
            try:
                url = f"{scheme}://{host}{check_path}"
                status, body, headers = http_get(url, timeout=6, retries=0)

                if check_path == "/services/data/v" and status == 200:
                    # API version disclosure
                    findings.append({
                        "type": "salesforce_api_exposed",
                        "severity": "medium",
                        "title": f"Salesforce REST API version exposed: {host}/services/data/v",
                        "host": host,
                        "url": url,
                        "module": "salesforce_recon",
                    })

                elif check_path.startswith("/s/global-search") and status == 200:
                    findings.append({
                        "type": "salesforce_guest_search",
                        "severity": "high",
                        "title": f"Salesforce Community guest search enabled: {host}",
                        "host": host,
                        "url": url,
                        "module": "salesforce_recon",
                    })

                elif check_path == "/sfsites/aura" and status in (200, 302):
                    findings.append({
                        "type": "salesforce_aura_exposed",
                        "severity": "medium",
                        "title": f"Salesforce Aura framework exposed (check for guest-accessible components): {host}",
                        "host": host,
                        "url": url,
                        "module": "salesforce_recon",
                    })

                elif check_path.startswith("/services/apexrest/") and status in (200, 401, 403, 405):
                    if status in (200, 405):  # 405 = endpoint exists but method wrong = exposed
                        findings.append({
                            "type": "salesforce_apex_rest",
                            "severity": "high",
                            "title": f"Salesforce Apex REST endpoint accessible: {host}/services/apexrest/",
                            "host": host,
                            "url": url,
                            "module": "salesforce_recon",
                        })

            except Exception:
                _log.debug('recon.py:10717 erro ignorado', exc_info=True)

        # 3. Admin/debug page checks
        for check_path in _SALESFORCE_ADMIN_CHECKS[:5]:
            try:
                url = f"{scheme}://{host}{check_path}"
                status, body, _ = http_get(url, timeout=5, retries=0)

                if check_path == "/_ui/common/apex/debug/ApexCSIPage" and status == 200:
                    findings.append({
                        "type": "salesforce_debug_console",
                        "severity": "high",
                        "title": f"Salesforce Debug Console exposed: {host}",
                        "host": host,
                        "url": url,
                        "module": "salesforce_recon",
                    })

                elif "/secur/logout.jsp" in check_path and status == 200:
                    findings.append({
                        "type": "salesforce_logout_open_redirect",
                        "severity": "medium",
                        "title": f"Salesforce logout page — potential open redirect via retURL parameter: {host}",
                        "host": host,
                        "url": url,
                        "module": "salesforce_recon",
                    })

                elif "/setup/" in check_path and status in (200, 302):
                    findings.append({
                        "type": "salesforce_setup_exposed",
                        "severity": "high",
                        "title": f"Salesforce Setup page accessible (should be auth-walled): {host}{check_path}",
                        "host": host,
                        "url": url,
                        "module": "salesforce_recon",
                    })

            except Exception:
                _log.debug('recon.py:10756 erro ignorado', exc_info=True)

        # 4. CORS check
        try:
            status, body, headers = http_get(f"{scheme}://{host}", timeout=5, retries=0,
                                             extra_headers={"Origin": "https://evil.com"})
            acao = (headers or {}).get("Access-Control-Allow-Origin", "")
            if acao == "*" or acao == "https://evil.com":
                findings.append({
                    "type": "salesforce_cors_misconfig",
                    "severity": "medium",
                    "title": f"Salesforce CORS misconfiguration: reflects Origin ({acao})",
                    "host": host,
                    "module": "salesforce_recon",
                })
        except Exception:
            _log.debug('recon.py:10772 erro ignorado', exc_info=True)

    return {
        "findings": findings,
        "total": len(findings),
        "salesforce_hosts": len(sf_hosts),
        "discovered": discovered,
        "hosts_scanned": scanned,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



def run_jwt_analysis(hosts: list, js_files: list = None) -> dict:
    """Analyze JWT tokens already extracted from the js module (no re-download)."""
    findings = []
    tokens = set()

    if js_files:
        for jf in js_files:
            if not isinstance(jf, dict):
                continue
            try:
                for s in jf.get("secrets") or []:
                    if not isinstance(s, dict):
                        continue
                    if s.get("type") not in ("jwt_token", "jwt_bearer"):
                        continue
                    raw = str(s.get("value") or "").strip()
                    tok = raw.split()[-1] if " " in raw else raw
                    if tok.startswith("eyJ") and tok.count(".") == 2:
                        tokens.add(tok)
                content = jf.get("content", "") or ""
                if content:
                    for match in re.finditer(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", content):
                        tokens.add(match.group(0))
            except Exception:
                _log.debug('recon.py:10808 erro ignorado', exc_info=True)

    # Analyze each token
    for token in list(tokens)[:10]:
        try:
            # Decode header without verification
            parts = token.split(".")
            if len(parts) >= 2:
                header = base64.urlsafe_b64decode(parts[0] + "==").decode()
                payload_data = base64.urlsafe_b64decode(parts[1] + "==").decode()
                header_json = json.loads(header)
                payload_json = json.loads(payload_data)
                alg = header_json.get("alg", "none")
                if alg.lower() == "none":
                    findings.append({
                        "type": "jwt_none_alg",
                        "severity": "critical",
                        "title": f"JWT with 'none' algorithm — bypass authentication",
                        "value": token[:60] + "...",
                        "module": "jwt_analysis",
                    })
                elif alg.lower().startswith("hs"):
                    findings.append({
                        "type": "jwt_hs_weak",
                        "severity": "medium",
                        "title": f"JWT uses HMAC-SHA — potential key brute-force",
                        "value": token[:60] + "...",
                        "metadata": {"alg": alg, "kid": header_json.get("kid", "")},
                        "module": "jwt_analysis",
                    })
                else:
                    findings.append({
                        "type": "jwt_info",
                        "severity": "low",
                        "title": f"JWT found: {payload_json.get('sub','?')} ({alg})",
                        "value": token[:60] + "...",
                        "module": "jwt_analysis",
                    })
        except Exception:
            _log.debug('recon.py:10847 erro ignorado', exc_info=True)

    return {
        "findings": findings,
        "total": len(findings),
        "tokens_found": len(tokens),
        "tokens_analyzed": len(tokens),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



def run_xss_scan(hosts: list, mode: str = "balanced") -> dict:
    """Scan live web hosts for XSS vulnerabilities using dalfox and XSStrike."""
    findings = []
    scanned = 0
    dalfox_bin = shutil.which("dalfox")
    xsstrike_bin = shutil.which("xsstrike")

    live = [h for h in hosts if _is_responsive(h)][:25]  # cap at 25 hosts

    # Quick dalfox scan on each live host
    if dalfox_bin:
        for h in live[:15]:
            host = h.get("host", "")
            url = f"https://{host}" if h.get("status_code") == 200 else f"http://{host}"
            try:
                result = subprocess.run(
                    [dalfox_bin, "url", url, "--silence", "--skip-mining-all",
                     "--timeout", "5", "--delay", "100", "--waf-evasion",
                     "--worker", "3", "--format", "json"],
                    capture_output=True, text=True, timeout=120
                )
                if result.stdout.strip():
                    try:
                        data = json.loads(result.stdout)
                        for item in (data if isinstance(data, list) else [data]):
                            findings.append({
                                "type": "xss_reflected",
                                "severity": item.get("severity", "medium"),
                                "title": f"XSS: {item.get('param','?')} @ {host}",
                                "host": host,
                                "value": item.get("payload", ""),
                                "url": item.get("url", url),
                                "tool": "dalfox",
                                "module": "xss_scan",
                            })
                    except json.JSONDecodeError:
                        pass
                scanned += 1
            except Exception:
                _log.debug('recon.py:10897 erro ignorado', exc_info=True)

    # Quick XSStrike on a few hosts
    if xsstrike_bin and scanned < len(live):
        for h in live[scanned:scanned + 5]:
            host = h.get("host", "")
            url = f"https://{host}" if h.get("status_code") == 200 else f"http://{host}"
            try:
                result = subprocess.run(
                    [xsstrike_bin, "-u", url, "--crawl", "-l", "1", "--skip",
                     "--console-log-level", "vuln", "--threads", "3"],
                    capture_output=True, text=True, timeout=120
                )
                for line in result.stdout.strip().splitlines():
                    if "VULNERABLE" in line.upper() or "XSS" in line.upper():
                        findings.append({
                            "type": "xss",
                            "severity": "high",
                            "title": f"XSStrike: {line.strip()[:120]}",
                            "host": host,
                            "tool": "xsstrike",
                            "module": "xss_scan",
                        })
                scanned += 1
            except Exception:
                _log.debug('recon.py:10922 erro ignorado', exc_info=True)

    return {
        "findings": findings,
        "total": len(findings),
        "hosts_scanned": scanned,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }
