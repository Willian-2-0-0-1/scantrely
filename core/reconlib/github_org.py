"""GitHub Code Search — Subdomain Discovery (Bug Bounty) — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
import json
import os
import re
import time
from core.reconlib.base import _http_get_json, http_get
from core.reconlib.leaks import _dns_resolves

# ── GitHub Org Repository Discovery ──

def run_github_repos(domains: list, token: str = "") -> dict:
    """
    Enumerate public GitHub repositories belonging to the target organization.
    Uses GitHub Search + Org API to find all repos, then scans each for
    secrets and sensitive filenames.
    """
    import urllib.parse as _up

    headers = {"User-Agent": "ASM-Platform/1.0", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def _gh_get(url: str) -> dict | list | None:
        data = _http_get_json(url, timeout=10, extra_headers=headers)
        if isinstance(data, (dict, list)):
            return data
        return None

    # Derive candidate org names from domains
    orgs: set[str] = set()
    for d in domains:
        base = d.split(".")[0].lower()
        orgs.add(base)
        # Also try without hyphens/underscores
        orgs.add(base.replace("-", "").replace("_", ""))

    all_repos: list[dict] = []
    secrets_found: list[dict] = []
    sensitive_files: list[dict] = []
    found_orgs: list[str] = []

    _SENSITIVE_FILES = re.compile(
        r'\.env$|\.env\.|secrets?\.|credentials?\.|config\.(json|yaml|yml|xml)$'
        r'|\.pem$|\.key$|id_rsa|\.aws|\.ssh|docker-compose\.yml$'
        r'|terraform\.tfvars$|\.tfstate$|kube.*config$',
        re.I
    )

    for org in sorted(orgs)[:6]:
        # Check if org exists on GitHub
        org_data = _gh_get(f"https://api.github.com/orgs/{org}")
        if not isinstance(org_data, dict) or org_data.get("message") == "Not Found":
            continue
        found_orgs.append(org)
        public_repos = org_data.get("public_repos", 0)

        # Fetch repo list (up to 100)
        repos_data = _gh_get(f"https://api.github.com/orgs/{org}/repos?per_page=100&sort=updated")
        if not isinstance(repos_data, list):
            continue

        for repo in repos_data:
            repo_name  = repo.get("full_name", "")
            repo_url   = repo.get("html_url", "")
            updated_at = repo.get("updated_at", "")[:10]
            is_fork    = repo.get("fork", False)
            default_br = repo.get("default_branch", "main")
            stars      = repo.get("stargazers_count", 0)

            all_repos.append({
                "name":       repo_name,
                "url":        repo_url,
                "updated_at": updated_at,
                "fork":       is_fork,
                "stars":      stars,
                "language":   repo.get("language", ""),
                "private":    repo.get("private", False),
            })

            # Scan tree for sensitive filenames (top-level only, fast)
            tree_data = _gh_get(
                f"https://api.github.com/repos/{repo_name}/git/trees/{default_br}?recursive=0"
            )
            if isinstance(tree_data, dict):
                for item in tree_data.get("tree", [])[:200]:
                    fname = item.get("path", "")
                    if _SENSITIVE_FILES.search(fname):
                        sensitive_files.append({
                            "repo":  repo_name,
                            "file":  fname,
                            "url":   f"{repo_url}/blob/{default_br}/{fname}",
                            "severity": "high",
                        })

        # GitHub code search for secrets in org repos
        _SECRET_QUERIES = [
            ("AWS key",         f'org:{org} "AKIA" language:python language:javascript language:yaml'),
            ("Private key",     f'org:{org} "BEGIN RSA PRIVATE KEY"'),
            ("DB credentials",  f'org:{org} "DB_PASSWORD" OR "DATABASE_URL" filename:.env'),
            ("API tokens",      f'org:{org} "api_key" OR "api_secret" OR "client_secret" extension:json extension:yaml'),
        ]
        for query_label, query in _SECRET_QUERIES:
            result = _gh_get(
                "https://api.github.com/search/code?" +
                _up.urlencode({"q": query, "per_page": "5"})
            )
            if isinstance(result, dict) and result.get("total_count", 0) > 0:
                for item in result.get("items", [])[:3]:
                    secrets_found.append({
                        "query":    query_label,
                        "repo":     item.get("repository", {}).get("full_name", ""),
                        "file":     item.get("name", ""),
                        "url":      item.get("html_url", ""),
                        "severity": "high",
                    })

    findings: list[dict] = []
    for sf in sensitive_files:
        findings.append({
            "type":     "github_sensitive_file",
            "title":    f"Arquivo sensível em repo público: {sf['file']} ({sf['repo']})",
            "severity": sf["severity"],
            "category": "leaks",
            "desc":     f"Arquivo `{sf['file']}` encontrado no repositório público `{sf['repo']}`. Pode conter segredos ou configurações internas.",
            "url":      sf["url"],
            "value":    sf["url"],
            "host":     domains[0] if domains else "",
        })
    for sf in secrets_found:
        findings.append({
            "type":     "github_secret_pattern",
            "title":    f"Padrão de segredo em GitHub: {sf['query']} ({sf['repo']})",
            "severity": "critical",
            "category": "leaks",
            "desc":     f"GitHub code search encontrou padrão '{sf['query']}' em `{sf['file']}` do repo `{sf['repo']}`.",
            "url":      sf["url"],
            "value":    sf["url"],
            "host":     domains[0] if domains else "",
        })

    return {
        "orgs_found":       found_orgs,
        "total_repos":      len(all_repos),
        "repos":            all_repos[:50],
        "sensitive_files":  sensitive_files,
        "secrets_found":    secrets_found,
        "findings":         findings,
        "scanned_at":       datetime.now().isoformat(timespec="seconds"),
    }



# ── GitHub Code Search — Subdomain Discovery (Bug Bounty) ──

def run_github_subdomains(domains, github_token: str = "") -> dict:
    """
    Mine subdomains from public source code via GitHub code search. Distinct from
    the secret-oriented GitHub search (run_leaks_recon): here we extract any
    `*.<domain>` hostname appearing in indexed code — CI configs, JS, docs, infra.

    Code search requires authentication; without a token results are empty.
    Returned `subdomains` are auto-merged into the host pool by the pipeline.
    """
    if isinstance(domains, str):
        domains = [domains]
    github_token = github_token or os.environ.get("GITHUB_TOKEN", "")
    now = datetime.now().isoformat(timespec="seconds")

    if not _dns_resolves("api.github.com"):
        return {"domains": domains, "found": [], "subdomains": [], "count": 0,
                "authenticated": bool(github_token),
                "errors": ["api.github.com unreachable"], "scanned_at": now}

    import urllib.parse as _up
    headers = {"Accept": "application/vnd.github.v3.text-match+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    found  = {}     # subdomain -> set(repos)
    errors = []

    for domain in domains:
        domain = str(domain).lower().strip().strip(".")
        if not domain:
            continue
        sub_re = re.compile(
            r"([a-z0-9](?:[a-z0-9\-]{0,62}\.)+" + re.escape(domain) + r")\b", re.I
        )
        for page in range(1, 6):
            q   = _up.quote(f'"{domain}"')
            url = f"https://api.github.com/search/code?q={q}&per_page=50&page={page}"
            try:
                status, body, _ = http_get(url, timeout=15, retries=1, extra_headers=headers)
            except Exception as exc:
                errors.append(f"{domain} p{page}: {exc}")
                break
            if status == 401:
                errors.append("GitHub auth requerida — configure github_token nas Settings")
                break
            if status == 403:
                errors.append("GitHub rate limit (code search: ~10 req/min) — aguarde")
                break
            if status == 422:
                break   # no more results
            if status != 200 or not body:
                errors.append(f"{domain} p{page}: HTTP {status}")
                break
            try:
                data = json.loads(body)
            except Exception:
                break
            github_items = data.get("items", []) or []
            if not github_items:
                break
            for item in github_items:
                repo = item.get("repository", {}).get("full_name", "")
                blob = item.get("path", "") or ""
                for tm in item.get("text_matches", []) or []:
                    blob += "\n" + (tm.get("fragment", "") or "")
                for m in sub_re.findall(blob):
                    sub = m.lower().strip(".")
                    if sub and sub != domain:
                        found.setdefault(sub, set()).add(repo)
            if len(github_items) < 50:
                break
            time.sleep(2)   # respect code-search rate limit

    results = [
        {"subdomain": s, "repos": sorted(r)[:5], "repo_count": len(r)}
        for s, r in sorted(found.items())
    ]
    return {
        "domains": domains,
        "found": results,
        "subdomains": sorted(found.keys()),
        "count": len(results),
        "authenticated": bool(github_token),
        "errors": errors,
        "scanned_at": now,
    }
