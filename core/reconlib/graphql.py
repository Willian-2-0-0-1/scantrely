"""GraphQL Discovery — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
from core.reconlib.base import _log, _random_ua, http_get
from core.reconlib.edge import Coverage, classify, fetch_baseline

# ── GraphQL Discovery ──

def run_graphql_discovery(hosts: list, domains: list) -> dict:
    """Discover GraphQL endpoints and test introspection + playground exposure."""
    import json as _json_inner
    import concurrent.futures as _cf

    PATHS = [
        "/graphql", "/graphiql", "/api/graphql", "/__graphql",
        "/gql", "/v1/graphql", "/v2/graphql", "/graph",
    ]
    INTROSPECTION = b'{"query":"{__schema{types{name}}}"}'
    PLAYGROUND_KW = {"graphiql", "graphql playground", "altair", "__schema", "introspection"}

    cov = Coverage()
    findings: list[dict] = []
    endpoints_found: list[str] = []
    seen: set[str] = set()

    targets: list[tuple[str, str]] = []
    for h in hosts[:20]:
        if not isinstance(h, dict):
            continue
        hhost = h.get("host", "")
        ports = h.get("ports", [])
        pnums = []
        for p in ports:
            try:
                pnums.append(int(p["port"] if isinstance(p, dict) else p))
            except Exception:
                _log.debug('recon.py:8158 erro ignorado', exc_info=True)
        scheme = "https" if (443 in pnums or 8443 in pnums or not pnums) else "http"
        targets.append((f"{scheme}://{hhost}", hhost))
    for d in domains[:5]:
        targets.append((f"https://{d}", d))

    import requests as _req_mod
    import urllib3; urllib3.disable_warnings()

    def _probe_host(base_host_pair):
        base, host = base_host_pair
        local_findings = []
        local_endpoints = []
        ref = fetch_baseline(base, 5, get=http_get)
        if ref is not None:
            cov.add(ref.verdict)
        if ref is None or ref.edge_blocked:   # host fora, ou borda barrando até caminho inexistente
            return local_findings, local_endpoints
        for path in PATHS:
            url = f"{base}{path}"
            try:
                status, raw, hdrs = http_get(url, timeout=5, retries=0)
                if not status:
                    continue
                verdict = classify(status, hdrs, raw)
                cov.add(verdict)
                if verdict.edge or ref.matches(status, raw, hdrs):
                    continue
                body = (raw or b"").decode("utf-8", "ignore")
                is_playground = status == 200 and bool(body) and any(kw in body.lower() for kw in PLAYGROUND_KW)
                introspection_works = False
                schema_types: list[str] = []
                if status == 200:
                    try:
                        iresp = _req_mod.post(
                            url, data=INTROSPECTION,
                            headers={"Content-Type": "application/json", "User-Agent": _random_ua()},
                            timeout=5, verify=False, allow_redirects=False,
                        )
                        parsed = _json_inner.loads(iresp.text)
                        types = parsed.get("data", {}).get("__schema", {}).get("types", [])
                        if types:
                            introspection_works = True
                            schema_types = [t.get("name", "") for t in types
                                            if not t.get("name", "").startswith("__")][:20]
                    except Exception:
                        _log.debug('recon.py:8194 erro ignorado', exc_info=True)
                if not (is_playground or introspection_works):
                    continue
                parts = []
                if introspection_works: parts.append("Introspection Enabled")
                if is_playground:      parts.append("Playground Exposed")
                sev = "critical" if introspection_works else "high"
                desc = f"GraphQL endpoint at {url}."
                if introspection_works:
                    desc += f" Introspection: {len(schema_types)} types ({', '.join(schema_types[:6])})."
                if is_playground:
                    desc += " Interactive playground accessible without auth."
                local_findings.append({
                    "type": "graphql", "host": host, "url": url, "path": path,
                    "status": status, "introspection": introspection_works,
                    "playground": is_playground, "schema_types": schema_types,
                    "severity": sev, "category": "GraphQL",
                    "title": f"GraphQL {' + '.join(parts)}: {host}",
                    "desc": desc,
                })
                local_endpoints.append(url)
                break  # one confirmed endpoint per host is enough
            except Exception:
                continue
        return local_findings, local_endpoints

    # Run probes in parallel with a hard 3-minute cap
    with _cf.ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(_probe_host, t): t for t in targets}
        for fut in _cf.as_completed(futs, timeout=180):
            try:
                lf, le = fut.result()
                findings.extend(lf)
                endpoints_found.extend(le)
            except Exception:
                _log.debug('recon.py:8229 erro ignorado', exc_info=True)

    return {
        "total_found": len(findings),
        "endpoints": endpoints_found,
        "findings": findings,
        "coverage": cov.as_dict(),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }
