"""Cloudflare / CDN Origin Discovery (Bug Bounty) — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
import os
import re
from core.reconlib.asn import _IP_RE, _PRIVATE_PREFIXES, detect_cloud_provider
from core.reconlib.base import _log, http_get
from core.reconlib.dnsutil import dns_records
from core.reconlib.email_sec import check_spf
from core.reconlib.typosquat import _resolve_domain

# ── Cloudflare / CDN Origin Discovery (Bug Bounty) ──

_ORIGIN_SUB_PREFIXES = [
    "direct", "origin", "origin-www", "direct-connect", "cpanel", "webmail",
    "mail", "smtp", "mx", "email", "ftp", "vpn", "remote", "server", "dev",
    "staging", "stage", "test", "uat", "old", "legacy", "autodiscover",
    "ns1", "ns2", "portal", "backend", "api-direct",
]


def _od_title(body: bytes) -> str:
    try:
        m = re.search(r"<title[^>]*>(.*?)</title>",
                      body[:4000].decode("utf-8", "ignore"), re.I | re.S)
        return m.group(1).strip()[:120] if m else ""
    except Exception:
        return ""


def run_origin_discovery(domains, hosts=None, shodan_key: str = "") -> dict:
    """
    Find the real origin IP behind Cloudflare/CDN for each domain (WAF bypass).

    Candidate origin IPs are gathered passively from DNS (MX, SPF ip4:/include:,
    and common non-proxied subdomains) and, when a Shodan key is set, from a
    certificate/hostname search. Each candidate is then verified by an HTTPS
    request carrying the target Host header and comparing the response title/status
    to the CDN-fronted baseline. Origins are reported only — never auto-scanned.

    Note: TLS SNI follows the candidate IP, so virtual-host-by-SNI origins may not
    confirm; Host-header routing still catches the common case.
    """
    if isinstance(domains, str):
        domains = [domains]
    shodan_key = shodan_key or os.environ.get("SHODAN_API_KEY", "")
    now = datetime.now().isoformat(timespec="seconds")
    import urllib.parse as _up
    results = []

    for domain in domains:
        domain = str(domain).lower().strip().strip(".")
        if not domain:
            continue

        # ── Baseline: is the apex fronted by Cloudflare/CDN? (headers are definitive) ──
        base_status, base_body, base_hdrs = http_get(f"https://{domain}/", timeout=10, retries=1)
        hdr_blob = " ".join(f"{k}:{v}" for k, v in (base_hdrs or {}).items()).lower()
        base_title = _od_title(base_body)
        fronted_by = ""
        if "cf-ray" in hdr_blob or "server:cloudflare" in hdr_blob.replace(" ", ""):
            fronted_by = "Cloudflare"
        else:
            for ip in _resolve_domain(domain):
                cdn = detect_cloud_provider(ip)
                if cdn:
                    fronted_by = cdn
                    break

        if not fronted_by:
            results.append({"domain": domain, "fronted_by": "", "skipped": True,
                            "reason": "não está atrás de CDN/WAF conhecido", "origins": []})
            continue

        # ── Gather candidate origin IPs (excluding CDN ranges) ──
        candidates = {}   # ip -> source
        def _add_ip(ip, src):
            ip = (ip or "").strip()
            if (_IP_RE.match(ip) and not ip.startswith(_PRIVATE_PREFIXES)
                    and not detect_cloud_provider(ip)):
                candidates.setdefault(ip, src)

        try:
            dns = dns_records(domain)
            for mx in dns.get("MX", []) or []:
                host = re.sub(r"^\d+\s+", "", str(mx)).strip().rstrip(".")
                for ip in _resolve_domain(host):
                    _add_ip(ip, f"MX:{host}")
        except Exception:
            _log.debug('recon.py:3608 erro ignorado', exc_info=True)

        try:
            for m in (check_spf(domain).get("mechanisms", []) or []):
                m = m.strip()
                if m.startswith("ip4:"):
                    _add_ip(m.split(":", 1)[1].split("/")[0], "SPF:ip4")
                elif m.startswith("a:") or m.startswith("include:"):
                    host = m.split(":", 1)[1]
                    for ip in _resolve_domain(host):
                        _add_ip(ip, f"SPF:{host}")
        except Exception:
            _log.debug('recon.py:3620 erro ignorado', exc_info=True)

        def _probe_sub(prefix):
            sub = f"{prefix}.{domain}"
            return [(ip, f"sub:{sub}") for ip in _resolve_domain(sub)]
        with ThreadPoolExecutor(max_workers=20) as pool:
            for res in pool.map(_probe_sub, _ORIGIN_SUB_PREFIXES):
                for ip, src in res:
                    _add_ip(ip, src)

        if shodan_key:
            try:
                q = _up.quote(f'ssl.cert.subject.CN:"{domain}"')
                s, b, _ = http_get(
                    f"https://api.shodan.io/shodan/host/search?key={shodan_key}&query={q}",
                    timeout=15, retries=1)
                if s == 200 and b:
                    for match in (json.loads(b).get("matches", []) or []):
                        _add_ip(match.get("ip_str", ""), "Shodan:cert")
            except Exception:
                _log.debug('recon.py:3640 erro ignorado', exc_info=True)

        # ── Verify candidates via Host-header request ──
        def _verify(item):
            ip, src = item
            st, bd = 0, b""
            for scheme in ("https", "http"):
                try:
                    st, bd, _ = http_get(f"{scheme}://{ip}/", timeout=8, retries=1,
                                         extra_headers={"Host": domain})
                    if st:
                        break
                except Exception:
                    continue
            title = _od_title(bd)
            conf = "unverified"
            if st and base_title and title and title == base_title:
                conf = "confirmed"
            elif (st == base_status and st in (200, 301, 302, 403)
                  and title and base_title and title[:30] == base_title[:30]):
                conf = "likely"
            elif st in (200, 301, 302):
                conf = "possible"
            return {"ip": ip, "source": src, "status": st, "title": title, "confidence": conf}

        origins = []
        items = list(candidates.items())
        if items:
            with ThreadPoolExecutor(max_workers=15) as pool:
                for v in pool.map(_verify, items):
                    origins.append(v)

        rank = {"confirmed": 0, "likely": 1, "possible": 2, "unverified": 3}
        origins.sort(key=lambda o: (rank.get(o["confidence"], 9), o["ip"]))
        verified = [o for o in origins if o["confidence"] in ("confirmed", "likely")]
        results.append({
            "domain": domain, "fronted_by": fronted_by,
            "baseline": {"status": base_status, "title": base_title},
            "candidates_checked": len(items),
            "origins": origins, "verified_origins": verified,
            "verified_count": len(verified),
        })

    return {
        "domains": domains, "results": results,
        "verified_count": sum(r.get("verified_count", 0) for r in results),
        "count": sum(len(r.get("origins", [])) for r in results),
        "scanned_at": now,
    }
