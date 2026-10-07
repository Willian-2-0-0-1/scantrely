#!/usr/bin/env python3
"""Passive attack-surface intel equivalent to a VirusTotal domain view.

Built from public DNS, Certificate Transparency and HTTP headers — no VirusTotal
key required. Captures A/CNAME/NS, CDN/S3/Azure/Imperva fronting, staging and
API hosts, CSP third-party origins, CORS wildcard+credentials, and a relation
graph for the dashboard.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Iterable
from urllib.parse import urlparse

CDN_CNAME_RULES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\.cloudfront\.net$", re.I), "aws_cloudfront", "AWS CloudFront"),
    (re.compile(r"s3[.-].*\.amazonaws\.com$", re.I), "aws_s3", "AWS S3"),
    (re.compile(r"\.elb\.amazonaws\.com$", re.I), "aws_elb", "AWS ELB"),
    (re.compile(r"\.execute-api\.[a-z0-9-]+\.amazonaws\.com$", re.I), "aws_apigw", "AWS API Gateway"),
    (re.compile(r"\.azurefd\.net$", re.I), "azure_frontdoor", "Azure Front Door"),
    (re.compile(r"\.azurewebsites\.net$", re.I), "azure_app", "Azure App Service"),
    (re.compile(r"\.blob\.core\.windows\.net$", re.I), "azure_blob", "Azure Blob Storage"),
    (re.compile(r"\.trafficmanager\.net$", re.I), "azure_tm", "Azure Traffic Manager"),
    (re.compile(r"\.cloudapp\.azure\.com$", re.I), "azure_cloudapp", "Azure Cloud App"),
    (re.compile(r"\.impervadns\.net$", re.I), "imperva", "Imperva"),
    (re.compile(r"\.incapdns\.net$", re.I), "imperva", "Imperva"),
    (re.compile(r"\.cloudflare\.net$", re.I), "cloudflare", "Cloudflare"),
    (re.compile(r"\.akamaiedge\.net$", re.I), "akamai", "Akamai"),
    (re.compile(r"\.fastly\.net$", re.I), "fastly", "Fastly"),
    (re.compile(r"\.googleusercontent\.com$", re.I), "gcp", "Google"),
]

INTERESTING_PREFIXES = (
    "www", "catalogo", "hml", "homolog", "homologacao", "staging", "stage",
    "dev", "qa", "test", "sandbox", "api", "apigateway", "gateway", "graphql",
    "static", "staticblob", "blob", "cdn", "assets", "media", "img", "images",
    "admin", "app", "loja", "experiencias", "experiencia", "hotsite", "portal",
    "auth", "login", "sso", "idp", "ws", "m", "mobile",
)

STAGING_RE = re.compile(
    r"(^|[.-])(hml|homolog|homologacao|staging|stage|dev|qa|test|sandbox|hotsitehml)([.-]|$)",
    re.I,
)
API_RE = re.compile(r"(^|[.-])(api|apigateway|gateway|graphql)([.-]|$)", re.I)
BLOB_RE = re.compile(r"(staticblob|blob\.core|s3[.-]|static|cdn|assets)", re.I)
HOST_IN_TEXT = re.compile(
    r"https?://([a-z0-9][a-z0-9._-]+\.[a-z]{2,})(?::\d+)?",
    re.I,
)
HOST_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]*\.[a-z]{2,}$", re.I)

# CSP hosts that are tracking/CDN boilerplate — keep in the relation graph,
# skip as attack-surface findings so real third parties stand out.
CSP_NOISE_SUFFIXES = (
    "googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
    "google.com", "google.com.br", "jsdelivr.net", "cdnjs.cloudflare.com",
    "jquery.com", "unpkg.com", "bootstrapcdn.com", "fontawesome.com",
    "typekit.net", "hotjar.com", "cookiepro.com", "cookielaw.org",
    "smartlook.com", "rawgit.com", "momentjs.com", "swagger.io",
    "cloudflare.com", "facebook.net", "facebook.com", "twitter.com",
    "doubleclick.net", "googlesyndication.com", "youtube.com", "ytimg.com",
    "cloudfront.net",
)

SUPPLY_CHAIN_HINTS = (
    "webpremios", "vertem", "hotsite", "loyalty", "azurewebsites.net",
    "azurefd.net", "salesforce.com", "force.com", "shopify.com",
    "zendesk.com", "okta.com", "auth0.com", "onelogin.com",
    "vtex.com", "vtexcommercestable.com.br",
)


def classify_cname(target: str) -> tuple[str, str]:
    t = (target or "").strip().rstrip(".").lower()
    if not t:
        return "", ""
    for rx, kind, label in CDN_CNAME_RULES:
        if rx.search(t):
            return kind, label
    return "", ""


def parse_csp_hosts(csp: str) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for raw in HOST_IN_TEXT.findall(csp or ""):
        h = raw.strip().lower().rstrip(".")
        if h and h not in seen:
            seen.add(h)
            hosts.append(h)
    return hosts


def noisy_csp_host(host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in CSP_NOISE_SUFFIXES)


def supply_chain_host(host: str) -> bool:
    h = (host or "").lower()
    return any(hint in h for hint in SUPPLY_CHAIN_HINTS)


def owners_of(host: str, records: list[dict], domains: list[str]) -> list[str]:
    """Map a CDN hostname back to in-scope aliases (VT view is on the alias)."""
    h = (host or "").lower().rstrip(".")
    aliases = [
        r["host"] for r in records
        if (r.get("cname") or "").lower().rstrip(".") == h
    ]
    in_scope = [a for a in aliases if _in_scope(a, domains)]
    if in_scope:
        return in_scope
    if aliases:
        return aliases
    return [h]


def _scope_of(domains: Iterable[str]) -> list[str]:
    out = []
    for d in domains or []:
        d = str(d or "").strip().lower().rstrip(".")
        if d and d not in out:
            out.append(d)
    return out


def _in_scope(host: str, domains: list[str]) -> bool:
    h = (host or "").lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in domains)


def _finding(key, ftype, title, severity, host, desc, **extra):
    row = {
        "key": key,
        "type": ftype,
        "title": title,
        "severity": severity,
        "category": extra.pop("category", "attack_surface"),
        "host": host,
        "desc": desc,
        "module": "surface_intel",
        "value": extra.pop("value", host),
    }
    row.update(extra)
    return row


def _dns_lookup(names: list[str]) -> dict[str, dict]:
    from core.recon import _dns_batch

    queries = []
    for n in names:
        for rtype in ("A", "AAAA", "CNAME", "NS"):
            queries.append((n, rtype, None))
    raw = _dns_batch(queries)
    by_host: dict[str, dict] = {}
    for (name, rtype), values in raw.items():
        rec = by_host.setdefault(name.lower().rstrip("."), {"A": [], "AAAA": [], "CNAME": [], "NS": []})
        if rtype in rec:
            for v in values:
                v = str(v).strip().rstrip(".")
                if v and v not in rec[rtype]:
                    rec[rtype].append(v)
    return by_host


def _http_probe(host: str) -> dict:
    from core.recon import http_get

    url = f"https://{host}/"
    extra = {"Origin": "https://evil.example"}
    try:
        status, body, hdrs = http_get(url, timeout=10, retries=1, extra_headers=extra)
    except Exception as exc:
        return {"host": host, "url": url, "status": 0, "error": str(exc)[:200], "headers": {}}
    raw = body or b""
    headers = {str(k).lower(): str(v) for k, v in (hdrs or {}).items()}
    snippet = raw[:800].decode("utf-8", "ignore")
    return {
        "host": host,
        "url": url,
        "status": status or 0,
        "headers": headers,
        "server": headers.get("server", ""),
        "via": headers.get("via", ""),
        "acao": headers.get("access-control-allow-origin", ""),
        "acac": headers.get("access-control-allow-credentials", ""),
        "csp": headers.get("content-security-policy", ""),
        "hsts": headers.get("strict-transport-security", ""),
        "xfo": headers.get("x-frame-options", ""),
        "x_amz": {k: v for k, v in headers.items() if k.startswith("x-amz") or k in ("x-cache",)},
        "s3_listable": b"<ListBucketResult" in raw[:8000],
        "body_len": len(raw),
        "title": _html_title(snippet),
        "error": "" if status else "no-response",
    }


def _html_title(html: str) -> str:
    m = re.search(r"<title[^>]*>([^<]{1,120})</title>", html or "", re.I)
    return (m.group(1).strip() if m else "")[:120]


def run_surface_intel(domains, hosts=None) -> dict:
    """Build a VT-style domain view from DNS + CT + HTTP, without VirusTotal."""
    domains = _scope_of(domains if not isinstance(domains, str) else [domains])
    now = datetime.now().isoformat(timespec="seconds")
    if not domains:
        return {"subdomains": [], "findings": [], "records": [], "graph": [], "related": [],
                "scanned_at": now, "reason": "no domains"}

    candidates: list[str] = []
    seen: set[str] = set()

    def add_name(n: str):
        n = (n or "").strip().lower().lstrip("*.").rstrip(".")
        if not n or n in seen:
            return
        seen.add(n)
        candidates.append(n)

    for d in domains:
        add_name(d)
        for pfx in INTERESTING_PREFIXES:
            add_name(f"{pfx}.{d}")
    for h in hosts or []:
        if isinstance(h, dict):
            add_name(h.get("host") or "")
        else:
            add_name(str(h))

    dns = _dns_lookup(candidates[:120])
    # VirusTotal "Last DNS records" on an alias is the CNAME target's A/NS.
    follow: list[str] = []
    seen_follow: set[str] = set()
    for rec in dns.values():
        for cn in rec.get("CNAME") or []:
            cn = str(cn).lower().rstrip(".")
            if cn and cn not in dns and cn not in seen_follow:
                seen_follow.add(cn)
                follow.append(cn)
    if follow:
        dns.update(_dns_lookup(follow[:80]))

    records = []
    subdomains = []
    graph = []
    findings = []
    related = []
    related_seen: set[str] = set()
    http_targets: list[str] = []

    for name in candidates:
        rec = dns.get(name) or {"A": [], "AAAA": [], "CNAME": [], "NS": []}
        cname = (rec.get("CNAME") or [None])[0] or ""
        cname = str(cname).lower().rstrip(".")
        tgt = dns.get(cname) or {} if cname else {}
        kind, label = classify_cname(cname)
        a_via = ""
        ns_via = ""
        a_recs = list(rec.get("A") or [])
        aaaa_recs = list(rec.get("AAAA") or [])
        ns = list(rec.get("NS") or [])
        if not a_recs and tgt.get("A"):
            a_recs = list(tgt.get("A") or [])
            a_via = "cname"
        if not aaaa_recs and tgt.get("AAAA"):
            aaaa_recs = list(tgt.get("AAAA") or [])
        if not ns and tgt.get("NS"):
            ns = list(tgt.get("NS") or [])
            ns_via = "cname_target"
        ips = a_recs + aaaa_recs
        exists = bool(ips or cname or ns)
        row = {
            "host": name,
            "a": a_recs,
            "aaaa": aaaa_recs,
            "cname": cname,
            "ns": ns,
            "a_via": a_via,
            "ns_via": ns_via,
            "cdn_kind": kind,
            "cdn": label,
            "exists": exists,
        }
        records.append(row)
        if exists and _in_scope(name, domains):
            subdomains.append(name)
            http_targets.append(name)
            if cname:
                http_targets.append(cname)
                graph.append({"from": name, "to": cname, "rel": "cname"})
                if label:
                    graph.append({"from": name, "to": label, "rel": "cdn"})
            for ip in a_recs[:4]:
                graph.append({"from": name, "to": ip, "rel": "a"})
            for nsv in ns[:4]:
                graph.append({"from": name, "to": nsv, "rel": "ns"})

        if kind in ("aws_cloudfront", "aws_s3") and exists:
            findings.append(_finding(
                f"cdn-{name}", "cdn_fronted",
                f"{label} em {name}",
                "info", name,
                f"{name} aponta CNAME {cname} ({label}). IPs anycast mudam por PoP — o CNAME é o identificador estável.",
                value=cname, category="cdn",
            ))
        if kind == "aws_s3" or (kind == "aws_cloudfront"):
            pass  # HTTP probe confirms S3 origin
        if STAGING_RE.search(name) and exists:
            findings.append(_finding(
                f"staging-{name}", "staging_host",
                f"Host de homologação/staging: {name}",
                "medium", name,
                f"{name} resolve ({cname or ', '.join(ips[:3]) or 'DNS ok'}). Ambiente não-produtivo na superfície externa.",
                value=cname or ",".join(ips[:2]), category="attack_surface",
            ))
        if API_RE.search(name) and exists:
            findings.append(_finding(
                f"api-{name}", "api_gateway_host",
                f"Host de API/gateway: {name}",
                "info", name,
                f"{name} parece gateway/API ({label or cname or 'DNS'}). Vale mapear rotas, auth e CORS.",
                value=cname, category="attack_surface",
            ))
        blob_prefix = any(name.startswith(p + ".") for p in ("staticblob", "blob", "media"))
        if blob_prefix and not exists and _in_scope(name, domains) and name.count(".") >= 2:
            findings.append(_finding(
                f"nx-{name}", "dangling_name",
                f"Nome de storage/CDN sem DNS: {name}",
                "info", name,
                f"{name} não resolve agora. Prefixo típico de blob/CDN — acompanhar se aparecer em CT/histórico.",
                category="takeover",
            ))
        if kind in ("azure_frontdoor", "azure_app", "azure_blob") and exists:
            findings.append(_finding(
                f"azure-{name}", "azure_fronted",
                f"{label} em {name}",
                "info" if not STAGING_RE.search(name) else "medium",
                name,
                f"{name} CNAME {cname} ({label}).",
                value=cname, category="cloud",
            ))
        if kind == "imperva" and exists:
            findings.append(_finding(
                f"waf-{name}", "waf_fronted",
                f"Imperva/Incapsula em {name}",
                "info", name,
                f"{name} CNAME {cname}. Apex/WAF na frente; origem real pode estar em outro hostname.",
                value=cname, category="waf",
            ))

    # Dedup http targets, prefer in-scope then CNAME targets (CloudFront default cert)
    uniq_http = []
    seen_http = set()
    for h in http_targets:
        h = h.lower().rstrip(".")
        if h and h not in seen_http:
            seen_http.add(h)
            uniq_http.append(h)

    probes = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_http_probe, h): h for h in uniq_http[:40]}
        for fut in as_completed(futs):
            try:
                probes[futs[fut]] = fut.result()
            except Exception:
                continue

    rec_by_host = {r["host"]: r for r in records}

    for host, probe in probes.items():
        rec = rec_by_host.get(host)
        owners = owners_of(host, records, domains)
        hdr_server = (probe.get("server") or "").lower()
        dist_name = host if host.endswith("cloudfront.net") else (rec.get("cname") if rec else host)

        if "amazons3" in hdr_server.replace(" ", "") or "amazon s3" in hdr_server:
            for alias in owners:
                findings.append(_finding(
                    f"s3origin-{alias}", "cdn_s3_origin",
                    f"Origem Amazon S3 atrás de CDN: {alias}",
                    "medium", alias,
                    f"{alias} entrega Server: AmazonS3 via CloudFront. Vetor: bucket listing, OAC ausente, "
                    f"arquivos estáticos com dados, CORS no objeto. Distribuição: {dist_name}.",
                    value=probe.get("server"), category="cloud",
                    url=probe.get("url"),
                ))
        if probe.get("s3_listable"):
            for alias in owners:
                findings.append(_finding(
                    f"s3list-{alias}", "s3_bucket_listable",
                    f"Bucket S3 listável em {alias}",
                    "high", alias,
                    f"Resposta HTTPS contém <ListBucketResult> — listing anônimo no origin S3 "
                    f"(via {dist_name}).",
                    value="ListBucketResult", category="cloud", url=probe.get("url"),
                ))

        acao = (probe.get("acao") or "").strip()
        acac = (probe.get("acac") or "").strip().lower()
        if acao == "*" and acac in ("true", "1"):
            for alias in owners:
                findings.append(_finding(
                    f"cors-star-cred-{alias}", "cors",
                    f"CORS * com credentials em {alias}",
                    "high", alias,
                    "Access-Control-Allow-Origin: * junto com Access-Control-Allow-Credentials: true. "
                    "Combinação inválida no spec e vetor clássico de exfiltração se o browser aceitar o header em algum path. "
                    f"Visto em https://{host}/.",
                    value="* + credentials", category="cors",
                    url=probe.get("url"),
                ))
        elif acao == "*" and probe.get("status") in (200, 204, 301, 302, 401, 403, 404):
            for alias in owners:
                findings.append(_finding(
                    f"cors-star-{alias}", "cors",
                    f"CORS wildcard em {alias}",
                    "low", alias,
                    f"Access-Control-Allow-Origin: * na resposta padrão de https://{host}/.",
                    value="*", category="cors", url=probe.get("url"),
                ))
        elif acao and acao not in ("*", "null") and acac in ("true", "1") and acao.lower() not in {
            f"https://{o}" for o in owners
        } | {f"https://{host}"}:
            # Reflected / overly-broad Origin with credentials
            if "evil.example" in acao.lower() or acao.lower().startswith("http"):
                for alias in owners:
                    findings.append(_finding(
                        f"cors-reflect-{alias}", "cors",
                        f"CORS reflete Origin com credentials em {alias}",
                        "high", alias,
                        f"Origin enviado https://evil.example → ACAO {acao} com credentials. "
                        "Reflexão de Origin permite qualquer site ler respostas autenticadas.",
                        value=acao, category="cors", url=probe.get("url"),
                    ))

        csp = probe.get("csp") or ""
        for extra_host in parse_csp_hosts(csp):
            src = owners[0] if owners else host
            graph.append({"from": src, "to": extra_host, "rel": "csp"})
            if extra_host not in related_seen:
                related_seen.add(extra_host)
                related.append({"host": extra_host, "via": "csp", "source_host": src})
            if noisy_csp_host(extra_host) or extra_host == src or _in_scope(extra_host, domains):
                continue
            if STAGING_RE.search(extra_host) or "hml" in extra_host or extra_host.endswith("azurewebsites.net"):
                for alias in owners:
                    findings.append(_finding(
                        f"csp-staging-{alias}-{extra_host}", "staging_in_csp",
                        f"CSP de produção cita staging: {extra_host}",
                        "high", alias,
                        f"Content-Security-Policy de {alias} (via {host}) inclui {extra_host}. "
                        "Homologação/Azure no CSP de prod amplia a superfície "
                        "(clickjacking frame-ancestors, origem extra, ambiente mais frouxo).",
                        value=extra_host, category="attack_surface", url=probe.get("url"),
                    ))
            elif supply_chain_host(extra_host):
                for alias in owners:
                    findings.append(_finding(
                        f"csp-supply-{alias}-{extra_host}", "supply_chain_origin",
                        f"Origem de supply chain no CSP: {extra_host}",
                        "medium", alias,
                        f"{alias} confia em {extra_host} (CSP/frame-ancestors). "
                        "Plataforma terceira (fidelidade/hotsite/IdP) — compromisso dela vira vetor no ativo principal.",
                        value=extra_host, category="supply_chain", url=probe.get("url"),
                    ))
            else:
                for alias in owners:
                    findings.append(_finding(
                        f"csp-third-{alias}-{extra_host}", "csp_third_party",
                        f"Origem terceira no CSP: {extra_host}",
                        "info", alias,
                        f"{alias} confia em {extra_host} (frame-ancestors/CSP). "
                        "Compromisso dessa origem vira vetor no ativo principal.",
                        value=extra_host, category="attack_surface", url=probe.get("url"),
                    ))

        if host.endswith("cloudfront.net") and probe.get("status") in (200, 403):
            for alias in owners:
                findings.append(_finding(
                    f"cf-direct-{alias}", "cdn_default_hostname",
                    f"Hostname default CloudFront público: {host}",
                    "medium", alias,
                    f"https://{host} responde HTTP {probe.get('status')} (SPA/origem acessível sem o alias). "
                    f"Alias em escopo: {alias}. Vetor: contornar WAF/certificado custom, hotlink, origin S3.",
                    value=host, category="cdn", url=f"https://{host}/",
                ))

        if rec and rec.get("cname") and probe.get("status") == 0 and rec.get("cdn_kind") == "aws_cloudfront":
            dist = rec["cname"]
            dist_probe = probes.get(dist) or {}
            if dist_probe.get("status"):
                findings.append(_finding(
                    f"sni-fail-{host}", "tls_alias_mismatch",
                    f"TLS falha no alias {host}, distribuição CloudFront responde",
                    "medium", host,
                    f"https://{host} não completa handshake, mas https://{dist} responde HTTP {dist_probe.get('status')}. "
                    "Certificado custom/SNI no alias; a distribuição default ainda serve o conteúdo (origem S3/CloudFront).",
                    value=dist, category="tls", url=f"https://{dist}/",
                ))

        if rec is not None:
            rec["http_status"] = probe.get("status")
            rec["server"] = probe.get("server")
            rec["via"] = probe.get("via")
            rec["acao"] = probe.get("acao")
            rec["acac"] = probe.get("acac")

    # Certificate Transparency — same subdomain/history view as VT, no API key
    certs = []
    ct_names: set[str] = set()
    try:
        from core.recon import get_ct_certs
        for d in domains:
            certs.extend(get_ct_certs(d, limit=200) or [])
    except Exception:
        certs = []
    for c in certs:
        for n in c.get("names") or []:
            n = str(n).strip().lower().lstrip("*.").rstrip(".")
            if n and _in_scope(n, domains):
                ct_names.add(n)
                add_name(n)
                if n not in subdomains:
                    subdomains.append(n)
        cn = str(c.get("common_name") or "").lower()
        if "azurewebsites.net" in cn or any("azurewebsites.net" in str(x).lower() for x in (c.get("names") or [])):
            findings.append(_finding(
                f"ct-azure-{c.get('id') or cn}", "historical_azure_cert",
                "Certificado histórico em *.azurewebsites.net",
                "info", domains[0],
                f"CT mostra certificado ligado a Azure App Service ({cn or c.get('names')}). "
                "Confirma hospedagem Azure antiga — combine com hml/CSP azurefd/azurewebsites.",
                value=cn, category="cloud",
            ))

    for n in sorted(ct_names):
        if n not in seen:
            graph.append({"from": domains[0], "to": n, "rel": "ct"})

    # Dedupe findings by key
    uniq = []
    seen_k = set()
    for f in findings:
        k = f.get("key")
        if k in seen_k:
            continue
        seen_k.add(k)
        uniq.append(f)

    summary = {
        "hosts": len(subdomains),
        "cnames": sum(1 for r in records if r.get("cname")),
        "cdn": sorted({r["cdn"] for r in records if r.get("cdn")}),
        "findings": len(uniq),
        "related": len(related),
        "ct_names": len(ct_names),
        "source": "dns+ct+http (sem VirusTotal)",
    }
    return {
        "domains": domains,
        "subdomains": sorted(set(subdomains)),
        "records": records,
        "graph": graph,
        "related": related,
        "findings": uniq,
        "certs": [
            {
                "common_name": c.get("common_name"),
                "names": c.get("names"),
                "not_before": c.get("not_before"),
                "not_after": c.get("not_after"),
                "source": c.get("source"),
            }
            for c in certs[:40]
        ],
        "summary": summary,
        "count": len(subdomains),
        "scanned_at": now,
    }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "portoplus.com.br"
    out = run_surface_intel([target])
    print(json.dumps({
        "summary": out["summary"],
        "subdomains": out["subdomains"],
        "related": out["related"],
        "findings": [
            {"sev": f["severity"], "type": f["type"], "title": f["title"]}
            for f in out["findings"]
        ],
        "records": [
            {k: r[k] for k in ("host", "cname", "cdn", "a", "http_status", "server") if k in r}
            for r in out["records"] if r.get("exists")
        ],
    }, indent=2, ensure_ascii=False))
