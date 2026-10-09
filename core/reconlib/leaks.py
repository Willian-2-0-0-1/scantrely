"""Leaks & Secrets — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
import os
import re
import time
from core.reconlib.base import UA, _log, http_get, subprocess
from core.reconlib.jsrecon import _JS_SECRET_PATTERNS

# ── Leaks & Secrets ──

def _dns_resolves(hostname: str, timeout: int = 3) -> bool:
    """Check if hostname resolves via dig (avoids glibc DNS hangs)."""
    try:
        r = subprocess.run(
            ["dig", "+short", "+time=1", "+tries=1", "A", hostname],
            capture_output=True, text=True, timeout=timeout,
        )
        return bool(r.stdout.strip() and not r.stdout.strip().startswith(";"))
    except Exception:
        return False



def _is_high_value_github_file(path: str) -> bool:
    """True if the file path suggests it commonly holds credentials."""
    high_value_exts  = {".env", ".properties", ".cfg", ".ini", ".netrc",
                        ".npmrc", ".pypirc", ".htpasswd", ".secret"}
    high_value_names = {".env.local", ".env.production", ".env.staging",
                        ".env.development", ".env.test", "credentials",
                        "secrets.yml", "secrets.yaml", "secrets.json"}
    p = path.lower()
    _, ext = os.path.splitext(p)
    basename = os.path.basename(p)
    return (ext in high_value_exts or basename in high_value_names
            or "secret" in basename or "credential" in basename
            or "password" in basename)



def _fetch_and_scan_github_file(api_url: str, auth_headers: dict) -> list:
    """Fetch a file from the GitHub Contents API and scan for secret patterns."""
    import base64
    if not api_url:
        return []
    try:
        extra = {k: v for k, v in auth_headers.items() if k != "User-Agent"}
        status, body, _ = http_get(api_url, timeout=8, retries=0, extra_headers=extra)
        if status != 200 or not body:
            return []
        data    = json.loads(body)
        encoded = data.get("content", "")
        if not encoded:
            return []
        content = base64.b64decode(encoded.replace("\n", "")).decode("utf-8", "ignore")[:60000]
        matches = []
        seen    = set()
        for pattern, ptype, sev in _JS_SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                val = m.group(0)[:120]
                key = (ptype, val[:40])
                if key not in seen:
                    seen.add(key)
                    start = max(0, m.start() - 60)
                    end   = min(len(content), m.end() + 40)
                    ctx   = content[start:end].replace("\n", " ").strip()[:200]
                    matches.append({"type": ptype, "severity": sev, "context": ctx})
        return matches
    except Exception:
        return []



def search_github(domain: str, token: str = None) -> dict:
    """GitHub code search for secrets mentioning the domain."""
    if not _dns_resolves("api.github.com"):
        return {"results": [], "errors": ["api.github.com unreachable"], "authenticated": False}

    headers = {"User-Agent": UA, "Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    company = domain.split(".")[0]  # "portoseguro" from "portoseguro.com.br"

    # Each entry: (query_string, base_severity)
    # Using file qualifiers (extension:, filename:) to target credential-bearing files
    # and avoid noise from READMEs, tests, docs.
    queries = [
        # .env files — highest signal
        (f'"{domain}" extension:env',                                "high"),
        (f'"{domain}" filename:.env',                                "high"),
        (f'"{domain}" filename:.env.local OR filename:.env.production', "high"),
        # Database / connection strings
        (f'"{domain}" DATABASE_URL OR DB_PASSWORD OR DB_PASS',       "high"),
        (f'"{domain}" jdbc:mysql OR jdbc:postgresql OR jdbc:oracle',  "high"),
        # Config files with explicit credential keywords
        (f'"{domain}" extension:yml password OR secret',             "medium"),
        (f'"{domain}" extension:yaml password OR secret',            "medium"),
        (f'"{domain}" extension:json api_key OR password OR secret',  "medium"),
        (f'"{domain}" extension:properties password',                "medium"),
        (f'"{domain}" filename:config.php password OR DB_PASS',       "medium"),
        # Private key material
        (f'"{domain}" "BEGIN PRIVATE KEY"',                          "critical"),
        (f'"{domain}" "BEGIN RSA PRIVATE KEY"',                      "critical"),
        # Company name in .env files (catches internal repos without full domain)
        (f'"{company}" extension:env password OR secret OR key',     "high"),
        # SMTP / mail credentials
        (f'"{domain}" SMTP_PASSWORD OR MAIL_PASSWORD OR smtp://',    "medium"),
    ]

    results = []
    errors  = []
    seen    = set()  # dedup by "repo:filepath"

    for q, base_severity in queries:
        try:
            enc = q.replace('"', '%22').replace(' ', '+')
            url = f"https://api.github.com/search/code?q={enc}&per_page=10&sort=indexed"
            status, body, _ = http_get(url, timeout=12,
                                       extra_headers={k: v for k, v in headers.items()
                                                      if k != "User-Agent"})
            if status == 403:
                errors.append("GitHub rate limit reached — add a token in Settings")
                break
            if status != 200 or not body:
                errors.append(f"Query '{q}': HTTP {status}")
                time.sleep(3)
                continue

            data = json.loads(body)
            for item in data.get("items", []):
                repo     = item.get("repository", {})
                fullname = repo.get("full_name", "")
                filepath = item.get("path", "")

                # Skip forks — they duplicate the original repo's code
                if repo.get("fork"):
                    continue

                key = f"{fullname}:{filepath}"
                if key in seen:
                    continue
                seen.add(key)

                # Validate content when authenticated (eliminates most false positives)
                validated = []
                if token:
                    validated = _fetch_and_scan_github_file(item.get("url", ""), headers)

                if validated:
                    severity = max(
                        (v["severity"] for v in validated),
                        key=lambda s: {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(s, 0),
                    )
                elif base_severity == "critical":
                    severity = "critical"
                elif _is_high_value_github_file(filepath):
                    severity = "high"
                else:
                    severity = base_severity

                results.append({
                    "query":             q,
                    "repo":              fullname,
                    "file":              filepath,
                    "url":               item.get("html_url", ""),
                    "severity":          severity,
                    "validated_secrets": validated,
                })

            time.sleep(2)  # GitHub rate limit
        except Exception as e:
            errors.append(str(e))
            break

    return {"results": results, "errors": errors,
            "authenticated": token is not None}


def search_codebase_leaks(domain: str) -> dict:
    """Search for domain mentions in public paste/code sites (no auth required)."""
    results = []
    if not _dns_resolves("api.hackertarget.com"):
        return {"results": []}
    # GreyNoise / PublicWWW alternatives — use HackerTarget which is free
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        status, raw, _ = http_get(url, timeout=10)
        body = raw.decode("utf-8", "ignore") if raw else ""
        for line in body.strip().splitlines()[:50]:
            if "," in line:
                host, ip = line.split(",",1)
                results.append({"source":"hackertarget","type":"subdomain",
                                 "host": host.strip(), "ip": ip.strip()})
    except Exception:
        _log.debug('recon.py:1797 erro ignorado', exc_info=True)
    return {"results": results}


from core.verification import looks_like_git


def check_exposed_git(hosts: list) -> list:
    """Quick check for exposed .git directories."""
    exposed = []
    targets = [h["host"] for h in hosts if h.get("ports") and "443" in h["ports"]]

    def check(host):
        for path in ["/.git/config", "/.git/HEAD"]:
            status, body, _ = http_get(f"https://{host}{path}", timeout=3, retries=0)
            # HTTP 200 sozinho não prova nada: SPA/soft-404 devolve HTML para qualquer caminho.
            if status == 200 and body and looks_like_git(path, body):
                return {"host": host, "path": path, "severity": "critical", "verified": True,
                        "snippet": body[:100].decode("utf-8", "ignore")}
        return None

    with ThreadPoolExecutor(max_workers=30) as pool:
        for res in pool.map(check, targets):
            if res:
                exposed.append(res)
    return exposed


def run_leaks_recon(domain: str, hosts: list, github_token: str = None) -> dict:
    git_exposed = check_exposed_git(hosts)
    github      = search_github(domain, token=github_token)
    hackertarget = search_codebase_leaks(domain)
    return {
        "domain":      domain,
        "git_exposed": git_exposed,
        "github":      github,
        "hackertarget":hackertarget,
        "total_findings": len(git_exposed) + len(github.get("results",[])),
        "scanned_at":  datetime.now().isoformat(timespec="seconds"),
    }
