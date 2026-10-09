"""Postman Collections Exposure — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
import json
import re
import time
import urllib.error
import urllib.request
from core.reconlib.base import UA, _log, http_get
from core.reconlib.leaks import _dns_resolves

# ── Postman Collections Exposure ──

# Regex patterns to detect secrets inside Postman collection JSON
_POSTMAN_SECRET_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']'), "password", "critical"),
    (re.compile(r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']([^"\']{8,})["\']'), "api_key", "high"),
    (re.compile(r'(?i)(token|access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*["\']([A-Za-z0-9_.~+/\-]{16,})["\']'), "token", "high"),
    (re.compile(r'(?i)(secret|client[_-]?secret)\s*[=:]\s*["\']([^"\']{8,})["\']'), "secret", "high"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_access_key", "critical"),
    (re.compile(r'(?i)(Authorization|X-Api-Key|X-Auth-Token)["\']\s*:\s*["\']([^"\']{8,})'), "auth_header", "high"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{80,}'), "github_token", "critical"),
    (re.compile(r'(?i)(basic\s+)([A-Za-z0-9+/]{16,}={0,2})'), "basic_auth", "high"),
]


_POSTMAN_SEARCH_URL  = "https://www.postman.com/_api/search"

_POSTMAN_GATEWAY_URL = "https://documenter.gw.postman.com/api/collections"

_POSTMAN_DOC_URL     = "https://documenter.getpostman.com/view"



def _postman_scan_collection_json(raw: bytes, source_url: str) -> list:
    """Parse a Postman collection JSON blob and extract secrets + endpoints."""
    findings = []
    try:
        text = raw.decode("utf-8", "ignore")
        data = json.loads(text)
    except Exception:
        return findings

    # Walk the full text for secret patterns
    for pat, kind, sev in _POSTMAN_SECRET_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(0)
            # Skip obvious placeholders / template vars
            if re.search(r'\{\{|\$\{|<YOUR|EXAMPLE|REPLACE|xxx|null', val, re.I):
                continue
            findings.append({
                "type":     "postman_secret",
                "kind":     kind,
                "severity": sev,
                "value":    val[:120],
                "source":   source_url,
            })

    # Extract base URLs from collection variables
    def _walk_vars(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str) and ("http" in v.lower() or "{{" in v):
                    yield k, v
                else:
                    yield from _walk_vars(v)
        elif isinstance(node, list):
            for item in node:
                yield from _walk_vars(item)

    base_urls = set()
    for k, v in _walk_vars(data.get("variable", data.get("variables", []))):
        if "http" in v.lower():
            base_urls.add(v[:200])

    if base_urls:
        findings.append({
            "type":     "postman_endpoints",
            "kind":     "base_url",
            "severity": "info",
            "value":    ", ".join(sorted(base_urls)[:5]),
            "source":   source_url,
        })

    return findings



def _postman_public_search(query: str) -> list:
    """Search Postman public API for collections matching `query`."""
    results = []
    try:
        params = f"q={urllib.request.quote(query)}&type=collection&queryType=searchInput"
        url = f"{_POSTMAN_SEARCH_URL}?{params}"
        status, body, _ = http_get(url, timeout=12,
                                   extra_headers={"x-app-version": "9.0.0-flat"})
        if status != 200 or not body:
            return results
        data = json.loads(body)
        for item in data.get("data", []):
            doc = item.get("document", {})
            col_id    = doc.get("id", "")
            col_name  = doc.get("name", "")
            owner     = doc.get("owner", "") or doc.get("publisherHandle", "")
            pub_url   = doc.get("externalLink", "") or f"https://www.postman.com/collection/{col_id}"
            if col_id:
                results.append({
                    "id":     col_id,
                    "name":   col_name,
                    "owner":  owner,
                    "url":    pub_url,
                })
    except Exception:
        _log.debug('recon.py:8336 erro ignorado', exc_info=True)
    return results



def _postman_fetch_collection(user_id: str, col_id: str) -> bytes:
    """Try to fetch raw JSON from Postman documenter gateway."""
    url = f"{_POSTMAN_GATEWAY_URL}/{user_id}/{col_id}"
    try:
        status, body, _ = http_get(url, timeout=15)
        if status == 200 and body and body.strip().startswith(b"{"):
            return body
    except Exception:
        _log.debug('recon.py:8348 erro ignorado', exc_info=True)
    return b""



def _github_postman_search(domain: str, company: str, token: str = None) -> list:
    """Search GitHub for committed Postman collection/environment files."""
    if not _dns_resolves("api.github.com"):
        return []

    headers = {"User-Agent": UA, "Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    queries = [
        f'"{domain}" filename:postman_collection.json',
        f'"{domain}" filename:postman_environment.json',
        f'"{company}" filename:postman_collection.json',
        f'"{domain}" extension:json postman',
    ]

    results = []
    seen = set()
    for q in queries:
        try:
            enc = q.replace('"', '%22').replace(' ', '+')
            url = f"https://api.github.com/search/code?q={enc}&per_page=10"
            status, body, _ = http_get(url, timeout=12,
                                       extra_headers={k: v for k, v in headers.items()
                                                      if k != "User-Agent"})
            if status == 403:
                break
            if status != 200 or not body:
                time.sleep(2)
                continue
            data = json.loads(body)
            for item in data.get("items", []):
                repo     = item.get("repository", {})
                fullname = repo.get("full_name", "")
                filepath = item.get("path", "")
                html_url = item.get("html_url", "")
                key = f"{fullname}:{filepath}"
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "repo":     fullname,
                    "file":     filepath,
                    "url":      html_url,
                    "raw_url":  item.get("url", ""),
                    "private":  repo.get("private", False),
                })
            time.sleep(1.5)
        except Exception:
            _log.debug('recon.py:8401 erro ignorado', exc_info=True)
    return results



def run_postman_collections(domain: str, company_name: str = "",
                            github_token: str = None) -> dict:
    """
    Search for publicly exposed Postman collections related to the target.

    Searches:
    - Postman public API (collection search by domain / company name)
    - GitHub committed postman_collection.json / postman_environment.json
    - Parses found collections for hardcoded secrets, tokens, base URLs

    Returns dict with keys: collections, github_hits, secrets, findings, total, scanned_at
    """
    company = company_name or domain.split(".")[0]
    queries = list({domain, company})  # deduplicated

    # 1. Postman public search
    raw_collections: list[dict] = []
    for q in queries:
        hits = _postman_public_search(q)
        for h in hits:
            if not any(c["id"] == h["id"] for c in raw_collections):
                raw_collections.append(h)
        time.sleep(1)

    # 2. GitHub committed files
    github_hits = _github_postman_search(domain, company, github_token)

    # 3. Parse secrets from GitHub raw files (when token available)
    all_secrets: list[dict] = []
    if github_token:
        gh_headers = {
            "User-Agent": UA,
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3.raw",
        }
        for gh in github_hits[:10]:
            raw_url = gh.get("raw_url", "")
            if not raw_url:
                continue
            try:
                status, body, _ = http_get(raw_url, timeout=12,
                                           extra_headers={k: v for k, v in gh_headers.items()
                                                          if k != "User-Agent"})
                if status == 200 and body:
                    secrets = _postman_scan_collection_json(body, gh.get("url", ""))
                    for s in secrets:
                        s["repo"] = gh.get("repo", "")
                    all_secrets.extend(secrets)
                time.sleep(1)
            except Exception:
                _log.debug('recon.py:8455 erro ignorado', exc_info=True)

    # 4. Build normalized findings list
    findings: list[dict] = []
    seen_keys: set = set()

    # Collections found on Postman
    for col in raw_collections:
        key = f"postman-col-{col['id']}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        findings.append({
            "type":     "postman_collection",
            "kind":     "public_collection",
            "severity": "medium",
            "title":    f"Postman Collection Exposed: {col['name'] or col['id']}",
            "desc":     f"Public Postman collection owned by '{col['owner']}' references the target. "
                        f"May contain API endpoints, auth flows, or sensitive data.",
            "value":    col["url"],
            "url":      col["url"],
            "host":     domain,
            "module":   "postman_collections",
            "category": "leaks",
            "metadata": {"collection_id": col["id"], "owner": col["owner"]},
        })

    # GitHub committed collections
    for gh in github_hits:
        key = f"postman-gh-{gh['repo']}-{gh['file']}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        findings.append({
            "type":     "postman_github",
            "kind":     "committed_collection",
            "severity": "high",
            "title":    f"Postman Collection on GitHub: {gh['repo']}",
            "desc":     f"File `{gh['file']}` committed to {'private' if gh['private'] else 'public'} "
                        f"repo '{gh['repo']}'. May expose API structure and credentials.",
            "value":    gh["url"],
            "url":      gh["url"],
            "host":     domain,
            "module":   "postman_collections",
            "category": "leaks",
            "metadata": {"repo": gh["repo"], "file": gh["file"]},
        })

    # Hardcoded secrets in collections
    secret_severity_map = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": -1}
    for s in all_secrets:
        key = f"postman-secret-{s['kind']}-{s['value'][:40]}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        findings.append({
            "type":     "postman_secret",
            "kind":     s["kind"],
            "severity": s["severity"],
            "title":    f"Hardcoded {s['kind'].replace('_', ' ').title()} in Postman Collection",
            "desc":     f"Found in repo '{s.get('repo','')}': `{s['value'][:80]}`",
            "value":    s["value"][:120],
            "url":      s.get("source", ""),
            "host":     domain,
            "module":   "postman_collections",
            "category": "credentials",
            "metadata": {"kind": s["kind"], "repo": s.get("repo", "")},
        })

    # Overall severity
    max_sev = "info"
    for f in findings:
        if secret_severity_map.get(f["severity"], -1) > secret_severity_map.get(max_sev, -1):
            max_sev = f["severity"]

    return {
        "domain":       domain,
        "collections":  raw_collections,
        "github_hits":  github_hits,
        "secrets":      all_secrets,
        "findings":     findings,
        "total":        len(findings),
        "severity":     max_sev,
        "scanned_at":   datetime.now().isoformat(timespec="seconds"),
    }
