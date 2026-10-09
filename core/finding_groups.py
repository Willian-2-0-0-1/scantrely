"""Achados confirmados agrupados — lógica da aba Vulnerabilidades, no servidor.

O navegador antes baixava a empresa inteira e filtrava/agrupava/ordenava tudo; agora pede só a página.
As regras são as mesmas do front (`_confirmedVulnFindings`, `_normalizeFindingTitle`, `_hashId`),
com uma correção: grupos críticos agora vêm primeiro (o front usava `rank||4`, que tratava
"critical"=0 como 4 e jogava os críticos para o fim).
"""
from __future__ import annotations

import re
from collections import OrderedDict

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
TRIAGE_STATUSES = ("open", "in_progress", "fixed", "accepted_risk")
_NOISE = re.compile(r"phish|typosquat|intel|osint|leak|brand|whois|monitor|newsletter|marketing|scan noise", re.I)
_IP = re.compile(r"\b\d+\.\d+\.\d+\.\d+\b")
_PORT = re.compile(r":\d{2,5}\b")
_BAD_STATUS = ("false", "ignor", "dismiss", "duplicate", "invalid")
_INACTIVE = ("not_seen", "resolved")   # ciclo de vida: ver core/finding_lifecycle.py


def _s(v) -> str:
    return "" if v is None else str(v)


def is_confirmed(f: dict, *, include_inactive: bool = False) -> bool:
    status = _s(f.get("status")).lower()
    if any(w in status for w in _BAD_STATUS):
        return False
    if status in _INACTIVE and not include_inactive:
        return False
    if f.get("type") == "secret" or f.get("category") == "secrets":
        return True
    if f.get("type") in ("git_exposed", "vendor_fingerprint", "default_creds"):
        return True
    text = " ".join(_s(x) for x in (
        f.get("title"), f.get("name"), f.get("category"), f.get("type"),
        "" if f.get("module") == "surface_intel" else f.get("module"),
        f.get("desc"), f.get("description"), f.get("impact"), f.get("endpoint"),
    )).lower()
    return not _NOISE.search(text)


def normalize_title(title, host) -> str:
    if not title:
        return "?"
    t = str(title)
    if host and str(host) in t:
        t = t.replace(str(host), "<HOST>", 1)
    t = _IP.sub("<IP>", t)
    return _PORT.sub(":<PORT>", t)


def hash_id(title: str, host: str = "", sev: str = "") -> str:
    """Mesma chave de triagem do front (`_hashId`): hash de 32 bits sobre unidades UTF-16."""
    data = f"{title}|{host}|{sev}".encode("utf-16-le")
    h = 0
    for i in range(0, len(data), 2):
        unit = data[i] | (data[i + 1] << 8)
        h = ((h << 5) - h + unit) & 0xFFFFFFFF
    if h >= 0x80000000:
        h -= 0x100000000
    return "f" + format(abs(h), "x").rjust(8, "0")


def _matches(f: dict, q: str, sev: str, cat: str) -> bool:
    if q:
        hay = " ".join(_s(x) for x in (f.get("title"), f.get("host"), f.get("desc") or f.get("description"), f.get("category"))).lower()
        if q not in hay:
            return False
    return (not sev or f.get("severity") == sev) and (not cat or f.get("category") == cat)


def build_groups(findings: list[dict], *, q: str = "", severity: str = "", category: str = "",
                 triage: str = "", triage_map: dict | None = None, page: int = 1, per_page: int = 25,
                 view: str = "active") -> dict:
    """view="active" (padrão) | "stale": só os não vistos/resolvidos em scans recentes."""
    triage_map = triage_map or {}
    stale_view = view == "stale"
    confirmed = [f for f in (findings or [])
                 if is_confirmed(f, include_inactive=stale_view) and (_s(f.get("status")) in _INACTIVE) == stale_view]
    q = (q or "").strip().lower()

    sev_counts = {s: sum(1 for f in confirmed if f.get("severity") == s) for s in ("critical", "high", "medium", "low")}
    categories = sorted({f["category"] for f in confirmed if f.get("category")})

    groups: "OrderedDict[str, list[dict]]" = OrderedDict()
    for f in confirmed:
        if _matches(f, q, severity, category):
            groups.setdefault(normalize_title(f.get("title") or "", f.get("host") or ""), []).append(f)

    entries = []
    for key, items in groups.items():
        tkey = hash_id(key)
        status = (triage_map.get(tkey) or {}).get("status") or "open"
        if triage and status != triage:
            continue
        top = min((SEV_RANK.get(f.get("severity"), 4) for f in items))
        entries.append({"key": key, "triage_key": tkey, "triage_status": status, "count": len(items),
                        "severity": next(k for k, v in SEV_RANK.items() if v == top), "findings": items, "_rank": top})
    entries.sort(key=lambda e: (e["_rank"], -e["count"]))

    per_page = max(1, min(int(per_page or 25), 100))
    pages = max(1, -(-len(entries) // per_page))
    page = max(1, min(int(page or 1), pages))
    chunk = entries[(page - 1) * per_page: page * per_page]
    for e in chunk:
        e.pop("_rank", None)
    return {
        "groups": chunk, "total_groups": len(entries), "total_findings": sum(e["count"] for e in entries),
        "page": page, "pages": pages, "per_page": per_page,
        "confirmed_total": len(confirmed), "stale_total": sum(1 for f in (findings or []) if _s(f.get("status")) in _INACTIVE), "severity": sev_counts, "categories": categories,
    }
