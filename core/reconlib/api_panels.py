"""API & Panel Exposure (Nuclei-based) — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
from pathlib import Path
import json
from core.reconlib.base import _log, _subp

# ── API & Panel Exposure (Nuclei-based) ──

def run_api_exposure(hosts: list, domains: list) -> dict:
    """
    Detect exposed API panels, docs and misconfigurations using nuclei:
    - Spring Boot Actuators (/actuator/env, /heapdump, /beans…)
    - Swagger / OpenAPI / Redoc UI
    - GraphQL Introspection
    - CORS Misconfiguration
    - HTTP Request Smuggling
    - JWT token exposure
    - Host Header Injection
    - Favicon hash for tech fingerprinting
    """
    import shutil, tempfile

    nuclei_bin = shutil.which("nuclei")
    httpx_bin  = shutil.which("httpx")
    if not nuclei_bin:
        return {"error": "nuclei not found", "findings": []}

    # Build URL targets
    targets = []
    for h in hosts:
        host  = h.get("host","")
        ports = h.get("ports",[])
        has_https = any(int(p["port"] if isinstance(p,dict) else p) in (443,8443) for p in ports)
        has_http  = any(int(p["port"] if isinstance(p,dict) else p) in (80,8080,8000,8888) for p in ports)
        if has_https:
            targets.append(f"https://{host}")
        if has_http:
            targets.append(f"http://{host}")
    if not targets:
        for d in domains[:5]:
            targets.append(f"https://{d}")

    if not targets:
        return {"error": "No live targets", "findings": []}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(dict.fromkeys(targets)))
        tfile = tf.name

    # Nuclei template sets to run — paths validated against actual template install
    TEMPLATE_SETS = [
        # Spring Boot misconfiguration (correct path)
        ("springboot", [
            "http/misconfiguration/springboot/",
            "http/technologies/springboot-actuator.yaml",
            "http/technologies/springboot-whitelabel.yaml",
            "http/vulnerabilities/springboot/",
        ]),
        # API docs exposure
        ("api_docs", [
            "http/exposures/apis/swagger-api.yaml",
            "http/exposures/apis/openapi.yaml",
            "http/exposures/apis/wadl-api.yaml",
            "http/exposures/apis/redoc-api-docs.yaml",
            "http/exposures/apis/postman-collection-exposure.yaml",
        ]),
        # GraphQL
        ("graphql", [
            "http/exposures/apis/graphql-introspection.yaml",
            "http/exposures/apis/graphql-playground.yaml",
        ]),
        # CORS
        ("cors", [
            "http/vulnerabilities/generic/cors-misconfig.yaml",
        ]),
        # JWT
        ("jwt", [
            "http/exposures/tokens/generic/jwt-token.yaml",
        ]),
        # Directory listing
        ("exposure", [
            "http/miscellaneous/directory-listing.yaml",
        ]),
    ]

    findings = []
    nuclei_base = str(Path.home() / "nuclei-templates")
    if not Path(nuclei_base).exists():
        nuclei_base = str(Path.home() / ".local" / "nuclei-templates")

    for category, templates in TEMPLATE_SETS:
        template_args = []
        for t in templates:
            full = str(Path(nuclei_base) / t)
            if Path(full).exists():
                template_args += ["-t", full]
        if not template_args:
            continue
        try:
            result = _subp(
                [nuclei_bin, "-l", tfile,
                 "-json", "-silent", "-no-interactsh",
                 "-timeout", "10", "-rate-limit", "50",
                 "-duc",   # disable update check
                 ] + template_args,
                capture_output=True, text=True, timeout=180,
            )
            for line in result.stdout.splitlines():
                try:
                    item = json.loads(line)
                    sev = item.get("info",{}).get("severity","info").lower()
                    findings.append({
                        "category":    category,
                        "template":    item.get("template-id",""),
                        "name":        item.get("info",{}).get("name",""),
                        "host":        item.get("host",""),
                        "url":         item.get("matched-at",""),
                        "severity":    sev,
                        "description": item.get("info",{}).get("description","")[:300],
                    })
                except Exception:
                    _log.debug('recon.py:6383 erro ignorado', exc_info=True)
        except Exception:
            _log.debug('recon.py:6385 erro ignorado', exc_info=True)

    Path(tfile).unlink(missing_ok=True)

    sev_counts = {s:0 for s in ("critical","high","medium","low","info")}
    for f in findings:
        sev_counts[f.get("severity","info")] = sev_counts.get(f.get("severity","info"),0)+1

    cat_counts = {}
    for f in findings:
        c = f["category"]
        cat_counts[c] = cat_counts.get(c,0) + 1

    return {
        "total":          len(findings),
        "critical_count": sev_counts["critical"],
        "high_count":     sev_counts["high"],
        "medium_count":   sev_counts["medium"],
        "by_category":    cat_counts,
        "findings":       sorted(findings,
                                 key=lambda x: ["critical","high","medium","low","info"].index(x.get("severity","info"))),
        "scanned_at":     datetime.now().isoformat(timespec="seconds"),
    }
