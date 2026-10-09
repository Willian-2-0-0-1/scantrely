"""Exposed Services — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from core.reconlib.base import http_get

# ── Exposed Services ──

EXPOSED_PATHS = {
    "Admin Panels": [
        "/admin","/administrator","/wp-admin","/wp-login.php",
        "/phpmyadmin","/pma","/adminer.php","/manager/html",
        "/admin/login","/admin/dashboard","/admin/console",
        "/cp","/panel","/cpanel","/webadmin","/siteadmin",
    ],
    "API Documentation": [
        "/swagger-ui.html","/swagger-ui/","/swagger/","/api-docs",
        "/swagger.json","/openapi.json","/openapi.yaml",
        "/v1/api-docs","/v2/api-docs","/v3/api-docs",
        "/graphql","/graphiql","/__graphql","/api/graphql","/playground",
        "/api/v1/","/api/v2/","/api/",
    ],
    "Monitoring & DevOps": [
        "/actuator","/actuator/health","/actuator/env","/actuator/beans",
        "/actuator/mappings","/actuator/loggers","/actuator/threaddump",
        "/metrics","/health","/status","/info","/ping",
        "/kibana","/grafana","/jenkins","/sonarqube","/consul",
        "/prometheus","/jaeger","/zipkin","/hawtio","/jolokia",
    ],
    "Sensitive Files": [
        "/.git/config","/.git/HEAD","/.git/COMMIT_EDITMSG",
        "/.env","/.env.local","/.env.prod","/.env.backup",
        "/phpinfo.php","/info.php","/test.php","/config.php",
        "/wp-config.php","/configuration.php","/config.yml","/config.yaml",
        "/backup.zip","/backup.sql","/dump.sql","/db.sql",
        "/.htaccess","/.htpasswd","/web.config",
        "/crossdomain.xml","/clientaccesspolicy.xml",
        "/.well-known/security.txt",
    ],
    "Auth & Identity": [
        "/login","/signin","/sign-in","/auth","/sso",
        "/oauth","/oauth2","/oauth/authorize","/oidc","/saml",
        "/portal","/dashboard","/console","/account",
        "/forgot-password","/reset-password","/register",
    ],
    "Cloud & Infra": [
        "/server-status","/server-info",
        "/_cat/indices","/_cluster/health","/_nodes",
        "/solr/","/redis/",
        "/trace","/TRACE",
        "/.aws/credentials","/.ssh/authorized_keys",
    ],
}


def _probe_url(url: str, timeout: int = 4) -> dict | None:
    status, body, resp_h = http_get(url, timeout=timeout, retries=0)
    if status == 0:
        return None
    if status in (404, 400, 405, 501):
        return None
    ctype  = resp_h.get("Content-Type", resp_h.get("content-type", ""))
    length = int(resp_h.get("Content-Length", resp_h.get("content-length", 0)) or 0)
    snippet = body[:512].decode("utf-8", "ignore")
    return {"status": status, "content_type": ctype, "length": length, "snippet": snippet[:200]}


def run_services_recon(host: str, timeout: int = 5) -> list:
    """Probe a single host for common exposed paths (parallel)."""
    results = []
    tasks = []
    for category, paths in EXPOSED_PATHS.items():
        for path in paths:
            tasks.append((category, path, f"https://{host}{path}"))

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_probe_url, url, timeout): (cat, path, url)
                   for cat, path, url in tasks}
        for fut in as_completed(futures):
            cat, path, url = futures[fut]
            result = fut.result()
            if result:
                sev = "high" if result["status"] == 200 else "medium"
                # Upgrade severity for specific paths
                if any(x in path for x in [".git",".env","sql","config","backup",
                                            "wp-config","phpmyadmin","adminer"]):
                    sev = "critical" if result["status"] == 200 else "high"
                results.append({
                    "url":      url,
                    "path":     path,
                    "category": cat,
                    "status":   result["status"],
                    "length":   result["length"],
                    "snippet":  result.get("snippet",""),
                    "severity": sev,
                })
    return sorted(results, key=lambda x: ["critical","high","medium","low"].index(x["severity"]))
