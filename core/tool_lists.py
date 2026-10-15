"""Listas prontas para ferramentas de teste manual (nuclei, httpx, ffuf, dalfox, Burp).

Uma linha por item, sem duplicata, já dentro do escopo da empresa e sem o que estiver em
"fora do escopo" (core/scope.py).
"""
from __future__ import annotations

from urllib.parse import urlsplit

from core.scope import is_excluded

KINDS = ("hosts", "urls", "endpoints", "params")
_HTTPS_PORTS = {"443", "8443"}


def _in_scope(host: str, domains, excluded) -> bool:
    h = (host or "").lower().strip(".")
    if not h or is_excluded(h, excluded):
        return False
    return any(h == d or h.endswith("." + d) for d in (str(x).lower().strip(".") for x in domains or []) if d)


def base_urls(row: dict) -> list[str]:
    """URL base de cada porta HTTP viva do host (porta padrão omitida)."""
    host = row.get("host", "")
    ports = [str(p.get("port") if isinstance(p, dict) else p) for p in row.get("ports") or []]
    if not ports:
        return [f"https://{host}"]
    out = []
    for p in ports:
        scheme = "https" if p in _HTTPS_PORTS else "http"
        default = (scheme == "https" and p == "443") or (scheme == "http" and p == "80")
        out.append(f"{scheme}://{host}" if default else f"{scheme}://{host}:{p}")
    return out


def endpoint_urls(endpoints: list[dict]) -> list[str]:
    """URLs absolutas dos endpoints (caminho relativo vira https://host/caminho)."""
    out = []
    for e in endpoints or []:
        raw = str(e.get("url") or "").strip()
        if raw.startswith(("http://", "https://")):
            out.append(raw)
        elif raw.startswith("/") and e.get("host"):
            out.append(f"https://{e['host']}{raw}")
    return out


def build_list(kind: str, rows: list[dict], endpoints: list[dict], domains, excluded) -> list[str]:
    if kind not in KINDS:
        raise ValueError(kind)
    items: list[str] = []
    if kind == "hosts":
        items = [r["host"] for r in rows if r.get("host")]
    elif kind == "urls":
        items = [u for r in rows if r.get("host") for u in base_urls(r)]
    else:
        items = endpoint_urls(endpoints)
        if kind == "params":
            items = [u for u in items if "?" in u and "=" in u.split("?", 1)[1]]
    seen, out = set(), []
    for it in items:
        host = urlsplit(it).hostname if "://" in it else it
        if it not in seen and _in_scope(host or "", domains, excluded):
            seen.add(it)
            out.append(it)
    return sorted(out)
