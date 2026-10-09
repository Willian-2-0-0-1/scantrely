"""Wayback / GAU — Historical URL Mining — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
from pathlib import Path
import re
from core.reconlib.base import _log, _subp, http_get
from core.reconlib.leaks import _dns_resolves

# ── Wayback / GAU — Historical URL Mining ──

_INTERESTING_EXT  = {".bak",".sql",".gz",".tar",".zip",".env",".log",
                     ".config",".conf",".xml",".yaml",".yml",".json",".key",".pem"}

_INTERESTING_PATH = [".git/",".env","wp-config","phpinfo","admin","backup",
                     "config","secret","password","token","apikey","swagger",
                     "graphql","actuator","debug","test","staging"]


def _wayback_cdx_urls(domain: str, limit: int) -> list:
    """Fetch historical URLs from Wayback Machine CDX API."""
    if not _dns_resolves("web.archive.org"):
        return []
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
        f"&limit={limit}&filter=statuscode:200"
    )
    try:
        status, raw, _ = http_get(url, timeout=30, retries=2)
        if status == 200 and raw:
            return [u.strip() for u in raw.decode("utf-8", "ignore").splitlines() if u.strip()]
    except Exception:
        _log.debug('recon.py:3830 erro ignorado', exc_info=True)
    return []



_VERIFY_MAX = 60   # teto de sondagens ao vivo por scan (só caminhos de alto risco)


def _verify_live(items: list) -> None:
    """URL do arquivo histórico não é prova de exposição: sonda ao vivo os caminhos de alto risco e
    grava `live_status`/`verified` (verified só se o conteúdo confirma o arquivo sensível)."""
    from concurrent.futures import ThreadPoolExecutor

    from core.verification import HIGH_RISK_PATH, classify_live

    targets = [u for u in items if HIGH_RISK_PATH.search(u.get("path") or "")][:_VERIFY_MAX]

    def probe(u):
        try:
            status, body, _ = http_get(u["url"], timeout=4, retries=0)
        except Exception:
            status, body = 0, b""
        u.update(classify_live(u.get("path") or "", status, body))

    if targets:
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(probe, targets))


def run_wayback(domain: str, limit: int = 5000, hosts: list = None) -> dict:
    """Mine historical URLs via gau (with Wayback CDX fallback) for sensitive paths.
    Runs on root domain; CDX also covers all subdomains via wildcard query.
    """
    import shutil as _shutil
    all_urls: list = []
    gau_ok = _shutil.which("gau") is not None
    if gau_ok:
        try:
            proc = _subp(
                ["gau", "--threads", "5", "--timeout", "20", "--retries", "1",
                 "--blacklist", "png,jpg,gif,css,woff,woff2,ttf,eot,svg,ico,mp4,mp3,zip,gz",
                 domain],
                capture_output=True, text=True, timeout=180,
            )
            all_urls = [u.strip() for u in proc.stdout.strip().splitlines() if u.strip()][:limit]
        except Exception:
            _log.debug('recon.py:3851 erro ignorado', exc_info=True)

    # CDX wildcard query already covers all subdomains (*.domain)
    if not all_urls:
        all_urls = _wayback_cdx_urls(domain, limit)

    interesting = []
    subdomains_found = set()
    for url in all_urls:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if host.endswith(domain):
                subdomains_found.add(host)

            path = parsed.path.lower()
            ext  = Path(path).suffix.lower()
            is_interesting = (
                ext in _INTERESTING_EXT or
                any(p in path for p in _INTERESTING_PATH) or
                parsed.query and any(p in parsed.query.lower()
                                     for p in ["debug","token","key","secret","admin"])
            )
            if is_interesting:
                interesting.append({
                    "url":  url,
                    "host": host,
                    "path": path,
                    "type": ext if ext in _INTERESTING_EXT else "path",
                })
        except Exception:
            _log.debug('recon.py:3883 erro ignorado', exc_info=True)

    # Deduplicate by path pattern
    seen_paths = set()
    deduped = []
    for u in interesting:
        key = re.sub(r"\d+", "N", u["path"])
        if key not in seen_paths:
            seen_paths.add(key)
            deduped.append(u)

    interesting_out = deduped[:200]
    _verify_live(interesting_out)

    return {
        "domain":         domain,
        "total_urls":     len(all_urls),
        "interesting":    interesting_out,
        "interesting_count": len(deduped),
        "subdomains":     sorted(subdomains_found),
        "scanned_at":     datetime.now().isoformat(timespec="seconds"),
    }
