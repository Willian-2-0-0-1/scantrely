"""Matriz de ativos no servidor: um host por linha, com agregados de achados/CVE/secrets/endpoints.

Espelha a lógica que antes rodava no navegador (`_buildSubdomainInventory`, `_hostRiskInfo`,
`_hostInfraSignals`, `buildUnifiedEndpoints`…). A paridade com o JavaScript é conferida em
tests/test_asset_matrix_parity.py (roda o código do front no node sobre dados reais).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

SEV_KEYS = ("critical", "high", "medium", "low")
ADMIN_PORT_LABELS = {"21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP", "3306": "MySQL", "5432": "PG",
                     "6379": "Redis", "27017": "Mongo", "9200": "ES", "2082": "cPanel", "2083": "cPanel SSL",
                     "2086": "WHM", "2087": "WHM SSL", "2095": "Webmail", "2096": "Webmail SSL",
                     "8080": "HTTP Alt", "8443": "HTTPS Alt", "8880": "HTTP Alt"}
WEB_PORTS = {"80", "443", "8000", "8008", "8080", "8081", "8088", "8443", "8880"}
HIGH_RISK_PORT_LABELS = {"21": "FTP — plaintext file transfer", "22": "SSH", "23": "Telnet — plaintext shell", "25": "SMTP",
                         "110": "POP3 — plaintext email", "143": "IMAP — plaintext email", "3306": "MySQL",
                         "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB", "9200": "Elasticsearch",
                         "2082": "cPanel", "2083": "cPanel SSL", "2086": "WHM", "2087": "WHM SSL",
                         "2095": "Webmail", "2096": "Webmail SSL"}
_RISK_SERVICE_RE = re.compile(r"ssh|ftp|telnet|mysql|postgres|redis|mongo|elastic|imap|pop3|smtp|cpanel|whm|webmail", re.I)


def _t(v) -> str:
    """String(v||"") do JS."""
    return "" if not v else str(v)


def _or(*vals):
    """a || b || c do JS (valores falsos viram o próximo)."""
    for v in vals:
        if v:
            return v
    return vals[-1] if vals else ""


# ── nomes de host ──────────────────────────────────────────────────────────
def normalize_domain(raw) -> str:
    s = _t(raw).strip()
    s = re.sub(r"^https?://", "", s, flags=re.I)
    s = re.sub(r"/.*$", "", s)
    s = re.sub(r"^\*\.", "", s)
    s = re.sub(r"\.$", "", s)
    return s.lower()


_HOSTISH = re.compile(r"^[a-z0-9._-]+\.[a-z]{2,}$", re.I)


def host_from_any(value) -> str:
    raw = _t(value).strip()
    if not raw:
        return ""
    if re.match(r"^https?://", raw, re.I):
        try:
            return normalize_domain(urlparse(raw).hostname or "")
        except ValueError:
            return ""
    return normalize_domain(raw) if _HOSTISH.match(raw.split("/")[0]) else ""


# ── filtros de ruído (iguais aos do front) ────────────────────────────────
_MIME_RE = re.compile(r"^(text|application|image|audio|video|font|multipart)/[a-z0-9.+-]+$", re.I)
_DATEMASK_RE = re.compile(r"^(?:MM|dd|yyyy|yy|HH|mm|ss|\d{2,4}|9{2,4})[/.\\-](?:MM|dd|yyyy|yy|HH|mm|ss|\d{2,4}|9{2,4})")
_TZ_RE = re.compile(r"^[A-Z][a-zA-Z]+/[A-Z][a-zA-Z_]+$")
_SDK_RE = re.compile(r"^(firebase|react|rxjs|vue|angular|@angular|@babel|core-js|lodash)/")


def js_path_noise(path) -> bool:
    s = _t(path).strip()
    if not s:
        return True
    if re.match(r"^https?://", s, re.I) or (s.startswith("//") and len(s) > 3 and s[2] != "/"):
        return False
    if s[0] == "/" and (len(s) < 2 or s[1] != "/"):
        return False
    if _MIME_RE.search(s) or _DATEMASK_RE.search(s) or _TZ_RE.search(s) or "__bundle__" in s or _SDK_RE.search(s):
        return True
    if s.startswith("./") or s.startswith("../") or s.startswith("..") or "/../" in s or "/./" in s:
        return True
    return False


_FP_PWD_RE = re.compile(r"(%filtered%|wrong.?password|forgot.?password|invalid.?password|missing.?password|need.?password|change.?password|reset.?password|show.?password|confirm.?password|enter.?password|password.?hint|password.?set|create.?password|redefine.?password|new.?password|old.?password|repeat.?password)", re.I)
_FP_LABEL_RE = re.compile(r"^[A-Z][A-Z0-9_\-]{3,}$|^[a-z][a-z0-9_]{4,}[a-z0-9]$")
_JS_NOISE_HOSTS = {"aadcdn.msauth.net", "aadcdn.msftauth.net", "ok1static.oktacdn.com", "use.fontawesome.com",
                   "cdn-prod.securiti.ai", "scripts.clarity.ms"}
_JS_NOISE_SFX = (".securiti.ai", ".clarity.ms", ".hotjar.com", ".googleapis.com", ".gstatic.com",
                 ".googletagmanager.com", ".google-analytics.com", ".recaptcha.net")


def fp_js_secret(stype, value) -> bool:
    v = value or ""
    if stype == "password":
        inner = re.sub(r"""['"]$""", "", re.sub(r"""^(?:password|passwd|pwd)\s*[=:]\s*['"]""", "", v, flags=re.I))
        if _FP_PWD_RE.search(inner):
            return True
        if re.match(r"^[A-Z][A-Z0-9_\-.]+$", inner) or re.match(r"^[a-z][a-z\-.]+$", inner):
            return True
        if re.match(r"""^['"']?passwords?['"']?$""", inner, re.I):
            return True
        if re.search(r"[\[\]{}&|?]|\.substring\(|\+[a-z]+\.", inner):
            return True
        return bool(re.match(r"^[A-Za-z][A-Za-z ]+$", inner))
    if stype in ("access_token", "secret_key", "api_key"):
        inner = re.sub(r"""['"]$""", "", re.sub(r"""^[\w\-]+\s*[=:]\s*['"]""", "", v, flags=re.I))
        return bool(_FP_LABEL_RE.search(inner))
    if stype == "internal_ip":
        m = re.search(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", v)
        return True if not m else any(int(o) > 255 for o in m.groups())
    return False


def js_host_noise(host) -> bool:
    h = _t(host).lower()
    return h in _JS_NOISE_HOSTS or any(h.endswith(s) for s in _JS_NOISE_SFX)


# ── endpoints e secrets por host (mesma ordem de fontes e dedupe do front) ──
def unified_endpoints_and_secrets(co: dict) -> tuple[list[dict], list[dict]]:
    eps: list[dict] = []
    secrets: list[dict] = []

    def add(raw, method, source, host=""):
        if not raw or not isinstance(raw, str):
            return
        if source == "js" and js_path_noise(raw):
            return
        eps.append({"url": raw, "method": str(method or "GET").upper(), "host": host or ""})

    def obj(x):
        return isinstance(x, dict)

    wb = (co.get("wayback_data") or {}).get("interesting")
    if wb:
        for u in wb:
            add(u if isinstance(u, str) else _or(u.get("url"), ""), "GET", "wayback", (u.get("host") or "") if obj(u) else "")
    for u in (co.get("urlfinder_data") or {}).get("urls") or []:
        add(u if isinstance(u, str) else _or(u.get("url"), u.get("path"), ""), "GET", "urlfinder", (u.get("host") or "") if obj(u) else "")
    pm = co.get("param_mine_data")
    if pm:
        for it in pm.get("findings") or pm.get("parameters") or pm.get("results") or []:
            raw = it if isinstance(it, str) else _or(it.get("url"), it.get("path"), "")
            if raw:
                add(raw, "GET", "param_mine", (it.get("host") or "") if obj(it) else "")
    bc = co.get("browser_crawl_data")
    if bc:
        for u in bc.get("urls") or []:
            add(u if isinstance(u, str) else _or(u.get("url"), ""), "GET", "browser_crawl", (u.get("host") or "") if obj(u) else "")
        for e in bc.get("api_endpoints") or []:
            add(e if isinstance(e, str) else _or(e.get("url"), ""), (e.get("method") or "GET") if obj(e) else "GET", "browser_crawl_xhr")
        for r in bc.get("results") or []:
            for u in r.get("urls") or []:
                add(u, "GET", "browser_crawl", r.get("host") or "")
            for e in r.get("api_endpoints") or []:
                add(e.get("url") or "", e.get("method") or "GET", "browser_crawl_xhr", r.get("host") or "")
    jd = co.get("js_data") or {}
    for js in jd.get("js_files") or []:
        for ep in js.get("endpoints") or []:
            e_url = ep if isinstance(ep, str) else _or(ep.get("url"), ep.get("endpoint"), ep.get("path"), "")
            if not e_url:
                continue
            add(e_url, ((ep.get("method") or "GET") if obj(ep) else "GET").upper(), "js", js.get("host") or "")
        for s in js.get("secrets") or []:
            val = s if isinstance(s, str) else _or(s.get("value"), s.get("secret"), "")
            stype = (s.get("type") or "Unknown") if obj(s) else "Unknown"
            if not val or fp_js_secret(stype, val) or js_host_noise(js.get("host") or ""):
                continue
            secrets.append({"type": stype, "value": val, "file": js.get("file") or js.get("url") or "",
                            "host": js.get("host") or "", "url": js.get("url") or js.get("file") or ""})
    for sf in co.get("secrets_findings") or []:
        if not obj(sf):
            continue
        meta = sf.get("metadata") or {}
        val = sf.get("value") or ""
        stype = _or(meta.get("secret_type"), sf.get("type") if sf.get("type") != "secret" else "", "secret")
        if not val or fp_js_secret(stype, val) or js_host_noise(sf.get("host") or ""):
            continue
        secrets.append({"type": stype, "value": val, "file": meta.get("source_url") or "", "host": sf.get("host") or "",
                        "url": meta.get("source_url") or ""})
    for e in jd.get("runtime_network") or []:
        add(e if isinstance(e, str) else _or(e.get("url"), ""), (e.get("method") or "GET") if obj(e) else "GET", "playwright_runtime")
    for u in jd.get("runtime_js_urls") or []:
        add(u if isinstance(u, str) else _or(u.get("url"), ""), "GET", "playwright_runtime_js")
    for f in (co.get("api_exposure") or {}).get("findings") or []:
        raw = f.get("url") or ""
        if raw:
            eps.append({"url": raw, "method": f.get("method") or "—", "host": f.get("host") or ""})

    seen, uniq = set(), []
    for ep in eps:
        if not ep["url"] or not isinstance(ep["url"], str):
            continue
        k = ep["method"] + "|" + ep["url"]
        if k not in seen:
            seen.add(k)
            uniq.append(ep)
    seen_s, uniq_s = set(), []
    for s in secrets:
        k = "|".join(str(s.get(x) or "") for x in ("type", "value")) + "|" + str(s.get("file") or s.get("url") or "") + "|" + str(s.get("host") or "")
        if k not in seen_s:
            seen_s.add(k)
            uniq_s.append(s)
    return uniq, uniq_s


def finding_host_set(f: dict) -> set[str]:
    hosts = {host_from_any(h) for h in (f.get("affected_hosts") or []) if isinstance(f.get("affected_hosts"), list)}
    hosts |= {host_from_any(f.get(k)) for k in ("host", "domain", "url")}
    hosts.discard("")
    return hosts


def compute_aggregates(co: dict) -> dict[str, dict]:
    agg: dict[str, dict] = {}

    def slot(h):
        if not h:
            return None
        return agg.setdefault(h, {"sev": {s: 0 for s in SEV_KEYS}, "findings": 0, "cve": 0, "secrets": 0, "endpoints": 0, "score": 0})

    for f in co.get("findings") or []:
        sev = _t(f.get("severity") or "info").lower()
        for h in finding_host_set(f):
            a = slot(h)
            if sev in SEV_KEYS:
                a["sev"][sev] += 1
                a["findings"] += 1
            if f.get("type") == "cve":
                a["cve"] += 1
    eps, secrets = unified_endpoints_and_secrets(co)
    for ep in eps:
        a = slot(host_from_any(ep["host"]) or host_from_any(ep["url"]))
        if a:
            a["endpoints"] += 1
    for s in secrets:
        a = slot(host_from_any(s["host"]) or host_from_any(s["url"]))
        if a:
            a["secrets"] += 1
    for a in agg.values():
        a["score"] = a["sev"]["critical"] * 1000 + a["sev"]["high"] * 100 + a["sev"]["medium"] * 10 + a["sev"]["low"]
    return agg


# ── inventário (hosts + CT + histórico) ────────────────────────────────────
def _is_ip(h: str) -> bool:
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", h))


def build_inventory(co: dict, history: list[dict] | None = None) -> list[dict]:
    merged: dict[str, dict] = {}
    tech_by_host: dict[str, list] = {}
    for tech, hosts in (co.get("tech_index") or {}).items():
        for h in hosts or []:
            nh = normalize_domain(h)
            if nh and tech not in tech_by_host.setdefault(nh, []):
                tech_by_host[nh].append(tech)

    def add(item: dict, source: str):
        host = normalize_domain(_or(item.get("host"), item.get("subdomain"), item.get("domain"), ""))
        if not host or _is_ip(host):
            return
        ex = merged.get(host)
        if ex is None:
            ex = merged[host] = {
                "host": host, "ip": item.get("ip") or "", "status_code": item.get("status_code"),
                "content_length": item.get("content_length"),
                "ports": list(item["ports"]) if isinstance(item.get("ports"), list) else [],
                "port_details": list(item["port_details"]) if isinstance(item.get("port_details"), list) else [],
                "waf": item.get("waf") or "Direct", "cloud_provider": item.get("cloud_provider") or "",
                "cert_info": item.get("cert_info"), "technologies": list(item["technologies"]) if isinstance(item.get("technologies"), list) else [],
                "title": item.get("title") or "", "screenshot": item.get("screenshot") or "",
                "risk": _or(item.get("risk"), item.get("risk_level"), item.get("severity"), ""), "sources": [],
            }
        if not ex["ip"] and item.get("ip"):
            ex["ip"] = item["ip"]
        if ex["status_code"] is None and item.get("status_code") is not None:
            ex["status_code"] = item["status_code"]
        if ex["content_length"] is None and item.get("content_length") is not None:
            ex["content_length"] = item["content_length"]
        for p in item.get("ports") or [] if isinstance(item.get("ports"), list) else []:
            if p not in ex["ports"]:
                ex["ports"].append(p)
        for p in item.get("port_details") or [] if isinstance(item.get("port_details"), list) else []:
            port = str(p.get("port") if isinstance(p, dict) and p.get("port") else p or "")
            if port and not any(str((x.get("port") if isinstance(x, dict) and x.get("port") else x) or "") == port for x in ex["port_details"]):
                ex["port_details"].append(p)
        for t in item.get("technologies") or [] if isinstance(item.get("technologies"), list) else []:
            if t not in ex["technologies"]:
                ex["technologies"].append(t)
        for t in tech_by_host.get(host, []):
            if t not in ex["technologies"]:
                ex["technologies"].append(t)
        if not ex["title"] and item.get("title"):
            ex["title"] = item["title"]
        if not ex["risk"] and _or(item.get("risk"), item.get("risk_level"), item.get("severity"), ""):
            ex["risk"] = _or(item.get("risk"), item.get("risk_level"), item.get("severity"))
        if not ex["waf"] and item.get("waf"):
            ex["waf"] = item["waf"]
        if not ex["cloud_provider"] and item.get("cloud_provider"):
            ex["cloud_provider"] = item["cloud_provider"]
        if not ex["cert_info"] and item.get("cert_info"):
            ex["cert_info"] = item["cert_info"]
        if not ex["screenshot"] and item.get("screenshot"):
            ex["screenshot"] = item["screenshot"]
        if source and source not in ex["sources"]:
            ex["sources"].append(source)

    for h in co.get("hosts") or []:
        add(h, "validated" if h.get("status_code") is not None else "host")
    for s in co.get("ct_subdomains") or []:
        add({"host": s} if isinstance(s, str) else s, "ct")
    for s in history or []:
        add({"host": s.get("subdomain"), "status_code": 200 if s.get("is_alive") else None}, s.get("source") or "history")
    return sorted(merged.values(), key=lambda h: h["host"])


def is_active(h: dict) -> bool:
    try:
        return float(h.get("status_code")) > 0
    except (TypeError, ValueError):
        return False


def match_domain(host: str, domain_set: set[str]) -> str:
    h = normalize_domain(host)
    if not h:
        return ""
    if h in domain_set:
        return h
    parts = h.split(".")
    for i in range(1, len(parts)):
        cand = ".".join(parts[i:])
        if cand in domain_set:
            return cand
    return ""


# ── portas, infra e tecnologias ────────────────────────────────────────────
def port_service_label(port, service="") -> str:
    p = str(port or "").strip()
    if p in HIGH_RISK_PORT_LABELS:
        return HIGH_RISK_PORT_LABELS[p]
    if service:
        return service
    if p in ADMIN_PORT_LABELS:
        return ADMIN_PORT_LABELS[p]
    return {"80": "HTTP", "443": "HTTPS"}.get(p, "")


def is_high_risk_port(port, service="") -> bool:
    p = str(port or "").strip()
    if not p or p in WEB_PORTS:
        return False
    if p in HIGH_RISK_PORT_LABELS:
        return True
    return bool(_RISK_SERVICE_RE.search(str(service or "")))


def open_ports(h: dict) -> list[dict]:
    by_port: dict[str, dict] = {}
    for p in h.get("ports") if isinstance(h.get("ports"), list) else []:
        port = str(p or "").strip()
        if port:
            by_port[port] = {"port": port, "service": port_service_label(port)}
    for item in h.get("port_details") if isinstance(h.get("port_details"), list) else []:
        port = str((item.get("port") if isinstance(item, dict) else item) or "").strip()
        if not port:
            continue
        svc = (item.get("service") or item.get("name") or "") if isinstance(item, dict) else ""
        by_port[port] = {"port": port, "service": port_service_label(port, svc),
                         "category": (item.get("category") or "") if isinstance(item, dict) else ""}
    return sorted(by_port.values(), key=lambda x: int(x["port"]) if x["port"].isdigit() else 0)


def cloud_label(value) -> str:
    v = _t(value).strip()
    if not v:
        return ""
    if re.search(r"gcp|google", v, re.I):
        return "Cloud GCP"
    if re.search(r"aws|amazon", v, re.I):
        return "Cloud AWS"
    if re.search(r"azure|microsoft", v, re.I):
        return "Cloud Azure"
    if re.search(r"cloudflare", v, re.I):
        return "Cloudflare"
    return f"Cloud {v}"


def infra_signals(h: dict) -> list[dict]:
    signals: list[dict] = []
    waf = _t(h.get("waf") or "Direct").strip()
    cloud = cloud_label(h.get("cloud_provider") or "")

    def add(label, cls, title=""):
        if not label or any(s["label"].lower() == label.lower() for s in signals):
            return
        signals.append({"label": label, "cls": cls, "title": title})

    if not waf or re.match(r"^direct$", waf, re.I):
        add("Sem WAF", "direct", "Direct: sem WAF/CDN identificado")
    elif re.search(r"direct", waf, re.I):
        add("Sem WAF", "direct", waf)
    elif re.search(r"unknown waf", waf, re.I):
        add("WAF desconhecido", "unknown", waf)
    elif re.search(r"cloudflare", waf, re.I):
        add("CDN Cloudflare", "cloud", waf)
    elif re.search(r"cloudfront|aws", waf, re.I):
        add("CDN AWS", "cloud", waf)
    elif re.search(r"gcp|google", waf, re.I):
        add("Cloud GCP", "cloud", waf)
    elif re.search(r"imperva|incapsula", waf, re.I):
        add("WAF Imperva", "waf", waf)
    elif re.search(r"akamai", waf, re.I):
        add("CDN Akamai", "cloud", waf)
    else:
        add(f"WAF {waf}", "waf", waf)
    if cloud:
        add(cloud, "cloud", h.get("cloud_provider") or cloud)
    tech_text = " ".join(str(t) for t in (h.get("technologies") or []))
    if re.search(r"cloudflare", tech_text, re.I):
        add("CDN Cloudflare", "cloud", "Detected in technologies")
    if re.search(r"gcp|google cloud", tech_text, re.I):
        add("Cloud GCP", "cloud", "Detected in technologies")
    if re.search(r"aws|amazon|cloudfront", tech_text, re.I):
        add("Cloud AWS", "cloud", "Detected in technologies")
    if re.search(r"azure|microsoft", tech_text, re.I):
        add("Cloud Azure", "cloud", "Detected in technologies")
    return signals


def tech_labels(h: dict) -> list[str]:
    labels = [s["label"] for s in infra_signals(h)]
    for t in h.get("technologies") or []:
        label = _t(t).strip()
        low = label.lower()
        if "CDN Cloudflare" in labels and low == "cloudflare":
            continue
        if "Cloud AWS" in labels and re.match(r"^(aws|amazon|amazon cloudfront|aws cloudfront)$", label, re.I):
            continue
        if "Cloud GCP" in labels and re.match(r"^(gcp|google cloud)$", label, re.I):
            continue
        if "Cloud Azure" in labels and re.match(r"^(azure|microsoft azure)$", label, re.I):
            continue
        if label and not any(x.lower() == label.lower() for x in labels):
            labels.append(label)
    return labels


def risk_info(h: dict, risk_map: dict[str, dict]) -> dict:
    direct = _t(_or(h.get("risk"), h.get("risk_level"), h.get("severity"), "")).lower()
    if direct in ("critical", "high", "medium"):
        return {"risk": True, "severity": direct, "label": direct}
    fnd = risk_map.get(h["host"])
    if fnd and fnd["severity"] in ("critical", "high", "medium"):
        return {"risk": True, "severity": fnd["severity"], "label": fnd["title"] or fnd["severity"]}
    try:
        sc = float(h.get("status_code") or 0)
    except (TypeError, ValueError):
        sc = 0
    if sc >= 500:
        return {"risk": True, "severity": "high", "label": "5xx"}
    for p in open_ports(h):
        if is_high_risk_port(p["port"], p["service"]):
            return {"risk": True, "severity": "high", "label": port_service_label(p["port"], p["service"]) or f"Port {p['port']}"}
    return {"risk": False, "severity": "", "label": ""}


def finding_risk_map(co: dict) -> dict[str, dict]:
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    out: dict[str, dict] = {}
    for f in co.get("findings") or []:
        sev = _t(f.get("severity") or "info").lower()
        cand = {host_from_any(f.get("host")), host_from_any(f.get("domain"))}
        # o front só olha host, domain e o hostname da url (não affected_hosts)
        cand.add(host_from_any(f.get("url")) if f.get("url") else "")
        for h in cand:
            if not h:
                continue
            prev = out.get(h)
            if not prev or rank.get(sev, 0) > rank.get(prev["severity"], 0):
                out[h] = {"severity": sev, "title": f.get("title") or f.get("category") or "Finding"}
    return out


# ── linhas, filtros, ordenação e página ────────────────────────────────────
def build_rows(co: dict, history: list[dict] | None = None) -> list[dict]:
    inv = [h for h in build_inventory(co, history) if is_active(h)]
    agg = compute_aggregates(co)
    rmap = finding_risk_map(co)
    domain_set = {normalize_domain(d) for d in co.get("domains") or []}
    rows = []
    for h in inv:
        a = agg.get(h["host"])
        h["_agg"] = a
        h["_domain"] = match_domain(h["host"], domain_set)
        h["_risk"] = risk_info(h, rmap)
        rows.append(h)
    return rows


def _agg(h):
    return h.get("_agg") or {"sev": {s: 0 for s in SEV_KEYS}, "findings": 0, "cve": 0, "secrets": 0, "endpoints": 0, "score": 0}


FIND_FILTERS = {
    "any": lambda h: _agg(h)["findings"] > 0,
    "critical": lambda h: _agg(h)["sev"]["critical"] > 0,
    "high": lambda h: _agg(h)["sev"]["critical"] + _agg(h)["sev"]["high"] > 0,
    "medium": lambda h: _agg(h)["sev"]["critical"] + _agg(h)["sev"]["high"] + _agg(h)["sev"]["medium"] > 0,
    "none": lambda h: _agg(h)["findings"] == 0,
}
HAS_FILTERS = {
    "secrets": lambda h: _agg(h)["secrets"] > 0,
    "cve": lambda h: _agg(h)["cve"] > 0,
    "endpoints": lambda h: _agg(h)["endpoints"] > 0,
    "riskport": lambda h: any(is_high_risk_port(p["port"], p["service"]) for p in open_ports(h)),
    "nowaf": lambda h: not h.get("waf") or bool(re.match(r"^direct$", str(h["waf"]), re.I)),
    "shot": lambda h: bool(h.get("screenshot")),
}
SORT_KEYS = {
    "url": lambda h: h["host"], "status": lambda h: float(h.get("status_code") or 0), "domain": lambda h: h.get("_domain") or "",
    "findings": lambda h: _agg(h)["score"], "cve": lambda h: _agg(h)["cve"], "secrets": lambda h: _agg(h)["secrets"],
    "endpoints": lambda h: _agg(h)["endpoints"], "ports": lambda h: len(open_ports(h)),
    "infra": lambda h: str(h.get("waf") or "Direct"), "tech": lambda h: len(h.get("technologies") or []),
    "title": lambda h: h.get("title") or "", "ip": lambda h: h.get("ip") or "",
}


def filter_rows(rows: list[dict], *, q="", status="", tech="", port="", risk="", waf="", find="", has="", domain="") -> list[dict]:
    q = (q or "").lower()
    out = []
    for h in rows:
        labels = tech_labels(h)
        if q and not (q in h["host"].lower() or q in (h.get("ip") or "") or q in (h.get("title") or "").lower()
                      or q in ",".join(labels).lower()
                      or any(q in p["port"] or q in (p.get("service") or "").lower() for p in open_ports(h))):
            continue
        if status and not (h.get("status_code") and int(float(h["status_code"]) // 100) == int(status)):
            continue
        if tech and tech not in labels:
            continue
        if port and not any(p["port"] == str(port) for p in open_ports(h)):
            continue
        if risk and (bool(h["_risk"]["risk"]) != (risk == "risk")):
            continue
        if waf and waf not in (h.get("waf") or "Direct"):
            continue
        if find and find in FIND_FILTERS and not FIND_FILTERS[find](h):
            continue
        if has and has in HAS_FILTERS and not HAS_FILTERS[has](h):
            continue
        if domain and h.get("_domain") != domain:
            continue
        out.append(h)
    return out


def sort_rows(rows: list[dict], key="url", asc=True) -> list[dict]:
    fn = SORT_KEYS.get(key, SORT_KEYS["url"])
    return sorted(rows, key=lambda h: (fn(h) if isinstance(fn(h), (int, float)) else str(fn(h)).casefold()), reverse=not asc)


def facets(rows: list[dict]) -> dict:
    tech_counts: dict[str, int] = {}
    port_counts: dict[str, int] = {}
    status = {"2": 0, "3": 0, "4": 0, "5": 0}
    for h in rows:
        for t in tech_labels(h):
            tech_counts[t] = tech_counts.get(t, 0) + 1
        for p in open_ports(h):
            port_counts[p["port"]] = port_counts.get(p["port"], 0) + 1
        sc = h.get("status_code")
        if sc:
            g = str(int(float(sc) // 100))
            if g in status:
                status[g] += 1
    chips = {
        "critical": sum(1 for h in rows if FIND_FILTERS["critical"](h)), "high": sum(1 for h in rows if FIND_FILTERS["high"](h)),
        "secrets": sum(1 for h in rows if HAS_FILTERS["secrets"](h)), "cve": sum(1 for h in rows if HAS_FILTERS["cve"](h)),
        "riskport": sum(1 for h in rows if HAS_FILTERS["riskport"](h)), "nowaf": sum(1 for h in rows if HAS_FILTERS["nowaf"](h)),
    }
    return {
        "tech": sorted(tech_counts.items(), key=lambda kv: -kv[1])[:40],
        "ports": sorted(port_counts.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0),
        "domains": sorted({h["_domain"] for h in rows if h.get("_domain")}),
        "status": status, "chips": chips, "total": len(rows),
    }


def query(rows: list[dict], *, sort="url", asc=True, page=1, per_page=50, **flt) -> dict:
    filtered = sort_rows(filter_rows(rows, **flt), sort, asc)
    per_page = max(1, min(int(per_page or 50), 500))
    pages = max(1, -(-len(filtered) // per_page))
    page = max(1, min(int(page or 1), pages))
    return {"items": filtered[(page - 1) * per_page: page * per_page], "total": len(filtered), "page": page,
            "pages": pages, "per_page": per_page, "facets": facets(rows)}


def url_of(h: dict) -> str:
    ports = [str(p) for p in (h.get("ports") or [])]
    scheme = "https" if (h.get("status_code") or "443" in ports or "80" not in ports) else "http"
    return f"{scheme}://{h['host']}/"


def export_rows(rows: list[dict]) -> list[dict]:
    """Linhas planas para CSV/JSON (mesmas colunas da exportação do front)."""
    out = []
    for h in rows:
        a = _agg(h)
        out.append({
            "host": h["host"], "url": url_of(h), "status": h.get("status_code") if h.get("status_code") is not None else "",
            "domain": h.get("_domain") or "", "ip": h.get("ip") or "", "title": h.get("title") or "",
            "critical": a["sev"]["critical"], "high": a["sev"]["high"], "medium": a["sev"]["medium"], "low": a["sev"]["low"],
            "cve": a["cve"], "secrets": a["secrets"], "endpoints": a["endpoints"],
            "ports": "|".join(p["port"] for p in open_ports(h)), "waf": h.get("waf") or "Direct",
            "cloud": h.get("cloud_provider") or "", "technologies": "|".join(str(t) for t in (h.get("technologies") or [])),
        })
    return out
