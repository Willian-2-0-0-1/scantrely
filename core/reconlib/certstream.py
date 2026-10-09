"""CertStream Monitor (one-shot snapshot) — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
import json
from core.reconlib.base import _log, http_get

# ── CertStream Monitor (one-shot snapshot) ──

def run_certstream_snapshot(domains: list, duration_sec: int = 60) -> dict:
    """
    Listen to CertStream for `duration_sec` seconds and collect any new
    certificates matching the target domains. Requires certstream package.
    Falls back to crt.sh polling if certstream not available.
    """
    import urllib.request, threading

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
        import certstream
        found = []

        def _cb(msg, ctx):
            try:
                leaf = msg.get("data", {}).get("leaf_cert", {})
                subject = leaf.get("subject") or {}
                cn = subject.get("CN", "") if isinstance(subject, dict) else ""
                issuer = leaf.get("issuer") or {}
                issuer_o = issuer.get("O", "") if isinstance(issuer, dict) else ""
                sans = leaf.get("all_domains") or []
                for name in ([cn] + list(sans)):
                    if _matches(name):
                        found.append({
                            "domain":     str(name).lstrip("*."),
                            "cn":         cn,
                            "issuer":     issuer_o,
                            "not_before": leaf.get("not_before", ""),
                            "not_after":  leaf.get("not_after", ""),
                            "source":     "certstream",
                        })
            except Exception:
                _log.debug('recon.py:6486 erro ignorado', exc_info=True)

        t = threading.Thread(
            target=certstream.listen_for_events,
            args=(_cb,),
            kwargs={"url": "wss://certstream.calidog.io/"},
            daemon=True,
        )
        t.start()
        t.join(timeout=duration_sec)
        new_certs = found
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
