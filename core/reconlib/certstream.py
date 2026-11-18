"""CertStream Monitor (one-shot snapshot) — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
import json
from core.reconlib.base import _log, http_get

# ── CertStream Monitor (one-shot snapshot) ──

def _listen(urls: list, duration_sec: int, matches) -> tuple:
    """Escuta o primeiro servidor CertStream que responder por `duration_sec` s. -> (achados, erro|None)."""
    import time
    import websocket                       # websocket-client; sem ele o chamador cai no crt.sh
    from core.certmonitor import extract_names
    deadline = time.monotonic() + duration_sec
    found, last_err = [], None
    for url in urls:
        if deadline - time.monotonic() <= 1:
            break
        try:
            ws = websocket.create_connection(url, timeout=5)
        except Exception as e:
            last_err = f"{url}: {e}"
            continue
        try:
            ws.settimeout(2)
            while time.monotonic() < deadline:
                try:
                    raw = ws.recv()
                except websocket.WebSocketTimeoutException:
                    continue
                if not raw:
                    break
                try:
                    names, meta = extract_names(json.loads(raw))
                except ValueError:
                    continue
                for name in names:
                    if matches(name):
                        found.append({
                            "domain": str(name).lstrip("*."), "cn": str(name),
                            "issuer": str(meta.get("issuer", ""))[:60],
                            "not_before": meta.get("not_before") or "", "not_after": meta.get("not_after") or "",
                            "source": "certstream",
                        })
            last_err = None
            break
        except Exception as e:
            last_err = f"{url}: {e}"
        finally:
            try:
                ws.close()
            except Exception:
                _log.debug("certstream: close falhou", exc_info=True)
    return found, last_err


def run_certstream_snapshot(domains: list, duration_sec: int = 60) -> dict:
    """
    Listen to CertStream for `duration_sec` seconds and collect any new
    certificates matching the target domains.
    Se o monitor contínuo (core/certmonitor.py) estiver conectado, usa o que ele já viu; senão escuta
    por conta própria. Cai no crt.sh se não houver websocket-client ou nada for visto.
    """

    new_certs = []
    errors    = []

    # Match the company domains themselves (portoseguro.com.br stays
    # portoseguro.com.br — not the public suffix .com.br).
    base_domains = set()
    for d in domains or []:
        d = str(d or "").strip().lower().lstrip(".")
        if d:
            base_domains.add(d)

    def _matches(cn: str) -> bool:
        if not cn:
            return False
        cn = cn.lower().lstrip("*.")
        return any(cn == b or cn.endswith("." + b) for b in base_domains)

    def _from_crtsh() -> None:
        for d in list(base_domains)[:3]:
            try:
                url = f"https://crt.sh/?q=%25.{d}&output=json"
                status, body, _ = http_get(url, timeout=15)
                if status != 200 or not body:
                    continue
                data = json.loads(body)
                if not isinstance(data, list):
                    continue
                for entry in data[:50]:
                    if not isinstance(entry, dict):
                        continue
                    name = entry.get("name_value", "").replace("*.", "").strip()
                    if name and _matches(name.split()[0] if name else ""):
                        new_certs.append({
                            "domain":     name.split()[0],
                            "cn":         entry.get("common_name", ""),
                            "issuer":     str(entry.get("issuer_name", ""))[:60],
                            "not_before": entry.get("not_before", ""),
                            "not_after":  entry.get("not_after", ""),
                            "source":     "crt.sh",
                        })
            except Exception as e:
                errors.append(str(e))

    try:
        from core.certmonitor import get_monitor, resolve_urls
        mon = get_monitor()
        if mon is not None and mon.is_connected():
            # o monitor contínuo já está escutando: aproveita o que ele viu em vez de escutar de novo
            for r in mon.recent_for(base_domains):
                new_certs.append({
                    "domain": r["host"], "cn": r["cn"], "issuer": str(r.get("issuer") or "")[:60],
                    "not_before": r.get("not_before", ""), "not_after": r.get("not_after", ""),
                    "source": "certstream-monitor",
                })
        else:
            found, err = _listen(resolve_urls(None), duration_sec, _matches)
            new_certs = found
            if err:
                errors.append(err)
        if not new_certs:
            _from_crtsh()

    except ImportError:
        _from_crtsh()
    except Exception as e:
        errors.append(f"certstream: {e}")
        _from_crtsh()

    # Deduplicate by domain
    seen = set()
    unique = []
    for c in new_certs:
        key = c["domain"]
        if key not in seen:
            seen.add(key)
            unique.append(c)

    return {
        "total":      len(unique),
        "duration_s": duration_sec,
        "new_certs":  unique[:200],
        "errors":     errors,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }
