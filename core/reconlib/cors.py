"""CORS Misconfiguration Scanner — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
from core.reconlib.base import _log, http_get
from core.reconlib.waf import _is_waf_challenge_body

# ── CORS Misconfiguration Scanner ──

def run_cors_scan(hosts: list) -> dict:
    """Test CORS misconfigurations: origin reflection, null origin, prefix/suffix bypasses."""

    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings: list[dict] = []
    tested = 0

    live = [h for h in hosts if isinstance(h, dict) and (h.get("status_code") or h.get("ports"))][:60]

    for h in live:
        host = h.get("host", "")
        if not host:
            continue
        ports = h.get("ports", [])
        port_nums = []
        for p in ports:
            try:
                port_nums.append(int(p["port"] if isinstance(p, dict) else p))
            except Exception:
                _log.debug('recon.py:7184 erro ignorado', exc_info=True)
        scheme = "https" if (443 in port_nums or 8443 in port_nums or not port_nums) else "http"
        base_url = f"{scheme}://{host}"
        parts = host.split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

        test_cases = [
            ("evil_reflection",   f"https://evil.com",                "high"),
            ("null_origin",       "null",                             "high"),
            ("pre_domain_bypass", f"https://evil{base_domain}",      "high"),
            ("sub_bypass",        f"https://evil.{base_domain}",     "medium"),
            ("http_bypass",       f"http://{host}",                   "medium"),
        ]

        worst: dict | None = None
        for test_name, origin, base_sev in test_cases:
            tested += 1
            try:
                status, body, hdrs = http_get(
                    base_url,
                    timeout=8,
                    retries=0,
                    extra_headers={"Origin": origin, "Accept": "*/*"},
                )
                if status == 0:
                    continue
                hdrs = hdrs or {}
                body_snip = (body or b"")[:2048].decode("utf-8", "ignore")

                acao = hdrs.get("access-control-allow-origin", "") or hdrs.get("Access-Control-Allow-Origin", "")
                acac = (hdrs.get("access-control-allow-credentials", "") or hdrs.get("Access-Control-Allow-Credentials", "")).lower()

                if not acao:
                    continue
                reflected = acao == origin or acao == "*"
                if not reflected:
                    continue
                # Skip generic WAF/CDN challenge pages — a reflected ACAO on a
                # block page is not the application's real CORS policy.
                if _is_waf_challenge_body(body_snip):
                    continue

                has_creds = acac == "true"
                # CORS nunca é crítico/alto: no máximo médio (a exploração depende de um endpoint autenticado).
                if acao == "*" and not has_creds:
                    sev = "low"
                else:
                    sev = "medium" if (has_creds or base_sev in ("high", "medium")) else base_sev

                # Resposta de erro (4xx/5xx) na raiz — típico de API gateway — reflete o CORS sem provar impacto:
                # rebaixa um nível e deixa isso explícito (o impacto depende de um endpoint autenticado).
                err_note = ""
                if status >= 400:
                    sev = {"medium": "low"}.get(sev, sev)
                    err_note = f" (resposta HTTP {status} na raiz: confirme em um endpoint autenticado)"

                candidate = {
                    "type": "cors", "host": host, "url": base_url,
                    "test": test_name, "origin_sent": origin,
                    "acao": acao, "acac": acac or "not set",
                    "severity": sev, "category": "CORS",
                    "title": f"CORS Misconfiguration ({test_name}): {host}",
                    "desc": (
                        f"{host} reflects origin '{origin}'. "
                        f"Access-Control-Allow-Origin: {acao}. "
                        f"Access-Control-Allow-Credentials: {acac or 'not set'}.{err_note}"
                    ),

                    "request_raw":  ("GET / HTTP/1.1\r\nHost: " + host + "\r\nOrigin: " + origin + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*"),
                    "response_raw": ("HTTP/1.1 (see headers)\r\n" + "\r\n".join(k + ": " + v for k, v in hdrs.items() if k.lower() != "set-cookie") + "\r\n\r\n" + body_snip[:600]),
                    "matched": acao,
                }
                if worst is None or SEV_ORDER.get(sev, 4) < SEV_ORDER.get(worst["severity"], 4):
                    worst = candidate
            except Exception:
                continue

        if worst:
            findings.append(worst)

    return {
        "total_tested": tested,
        "vulnerable": len(findings),
        "findings": findings,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }
