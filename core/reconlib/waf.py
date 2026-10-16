"""WAF / CDN challenge page detection (shared false-positive filter) — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from datetime import datetime
import re
from core.reconlib.base import _log, _subp
from core.reconlib.base import http_get
from core.reconlib.edge import EDGE_BLOCKED, classify, is_edge_page

# ── WAF Detection ──
# Quem é a borda e se ela agiu vem de `edge.classify`: `cf-ray` etc. só identificam o fabricante
# (há CDN na frente); marca de enforcement ou texto de bloqueio dizem que a requisição foi barrada.

_PROBE_QUERY = "/?id=1%27%20OR%20%271%27%3D%271"
_BLOCK_CODES = (403, 406, 429, 503)


def _detect_waf(host: str) -> dict:
    """Detect WAF/CDN: fabricante pelos sinais da resposta normal e da sondagem maliciosa."""
    url = f"https://{host}" if not host.startswith("http") else host
    status, body, hdrs = http_get(url, timeout=6, retries=1)
    normal = classify(status, hdrs, body)
    block_status, block_body, block_hdrs = http_get(f"{url}{_PROBE_QUERY}", timeout=6, retries=1)
    probe = classify(block_status, block_hdrs, block_body)

    detected = []
    for v in (probe, normal):
        if v.vendor and v.vendor not in detected:
            detected.append(v.vendor)
    # a borda agiu sobre a sondagem mas não se identificou, ou só a sondagem foi barrada
    if not detected and (probe.edge or (block_status in _BLOCK_CODES and status not in _BLOCK_CODES and status)):
        detected.append("Unknown WAF (blocked malicious request)")

    # Run wafw00f if available
    wafw00f_result = None
    try:
        w = _subp(
            ["wafw00f", "-a", url, "-o", "-"],
            capture_output=True, text=True, timeout=15,
        )
        if w.returncode == 0:
            matches = re.findall(r"is behind (.+?)(?:\n|$)", w.stdout)
            if matches:
                wafw00f_result = matches
                detected = list(set(detected + matches))
    except Exception:
        _log.debug('recon.py:4016 erro ignorado', exc_info=True)

    return {
        "host":    host,
        "wafs":    detected,
        "protected": len(detected) > 0,
        "block_status": block_status,
        "probe_blocked": probe.origin == EDGE_BLOCKED,   # a borda barrou a sondagem (não é só CDN na frente)
        "probe_reason": probe.reason if probe.edge else "",
        "wafw00f": wafw00f_result,
    }


def run_waf_detection(hosts: list) -> dict:
    """Detect WAFs across live HTTPS hosts."""
    targets = [h["host"] for h in hosts if 443 in h.get("ports", []) or "443" in h.get("ports", []) or h.get("status_code") is not None]
    results = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_detect_waf, h): h for h in targets}
        for fut in as_completed(futures):
            results.append(fut.result())

    protected   = sum(1 for r in results if r["protected"])
    unprotected = len(results) - protected
    waf_counts: dict[str,int] = {}
    for r in results:
        for w in r["wafs"]:
            waf_counts[w] = waf_counts.get(w, 0) + 1

    return {
        "results":     results,
        "protected":   protected,
        "unprotected": unprotected,
        "waf_counts":  dict(sorted(waf_counts.items(), key=lambda x: -x[1])),
        "scanned_at":  datetime.now().isoformat(timespec="seconds"),
    }



# ── WAF / CDN challenge page detection (shared false-positive filter) ──

def _is_waf_challenge_body(body: str, status: int = 0, headers: dict | None = None) -> bool:
    """True se a resposta é página de bloqueio/desafio da borda e não conteúdo da aplicação.
    Evita falso positivo em CORS / takeover, onde a página do WAF seria confundida com a resposta
    (ou assinatura) do próprio alvo. Passe `status` e `headers`: sem eles só marca de enforcement vale."""
    return bool(body) and is_edge_page(body, status, headers)
