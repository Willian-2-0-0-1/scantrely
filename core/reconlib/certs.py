"""Certificate Transparency — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from datetime import datetime
import json
import re
import socket
import ssl
from core.reconlib.base import _log, http_get, subprocess
from core.reconlib.leaks import _dns_resolves

# ── Certificate Transparency ──

def get_ct_certs(domain: str, limit: int = 500) -> list:
    """Query crt.sh + certspotter + Shodan CTL for certificates issued to domain."""
    certs = _ct_from_crtsh(domain, limit)
    if not certs:
        certs = _ct_from_certspotter(domain, limit)
    # Always merge Shodan CTL — complimentary source with different coverage
    shodan_certs = _ct_from_shodan(domain, limit)
    certs = certs + shodan_certs
    # Deduplicate by (common_name, not_after)
    seen: set = set()
    deduped = []
    for c in certs:
        key = (c["common_name"], c["not_after"])
        if key not in seen:
            seen.add(key)
            deduped.append(c)
    return sorted(deduped, key=lambda c: c.get("days_left") or 9999)



def _parse_cert_dates(not_after):
    """Parse certificate expiration. Accepts ISO datetime string or Unix timestamp (int)."""
    days_left = None
    expired = expiring_soon = False
    try:
        if isinstance(not_after, (int, float)):
            exp = datetime.utcfromtimestamp(not_after)
        elif isinstance(not_after, str):
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    exp = datetime.strptime(not_after, fmt)
                    break
                except ValueError:
                    continue
            else:
                return days_left, expired, expiring_soon
        else:
            return days_left, expired, expiring_soon
        days_left = (exp - datetime.utcnow()).days
        expired       = days_left < 0
        expiring_soon = 0 <= days_left <= 30
    except Exception:
        _log.debug('recon.py:1035 erro ignorado', exc_info=True)
    return days_left, expired, expiring_soon



def _ct_from_crtsh(domain: str, limit: int) -> list:
    for query in [f"%.{domain}", domain]:
        try:
            url = f"https://crt.sh/?q={query}&output=json&deduplicate=Y"
            status, raw, _ = http_get(url, timeout=10, retries=0)
            if not raw or raw[:1] == b"<" or status not in (200, 201):
                continue
            data = json.loads(raw)
            certs = []
            for c in data[:limit]:
                not_after = c.get("not_after", "")
                days_left, expired, expiring_soon = _parse_cert_dates(not_after)
                names = c.get("name_value", "").lower().replace("\\n", "\n").splitlines()
                certs.append({
                    "id":           c.get("id"),
                    "common_name":  c.get("common_name", ""),
                    "names":        names,
                    "issuer_cn":    _cn(c.get("issuer_name", "")),
                    "not_before":   (c.get("not_before", "") or "")[:10],
                    "not_after":    (not_after or "")[:10],
                    "days_left":    days_left,
                    "expired":      expired,
                    "expiring_soon":expiring_soon,
                    "wildcard":     any(n.startswith("*.") for n in names),
                    "source":       "crt.sh",
                })
            if certs:
                return certs
        except Exception:
            continue
    return []



def _ct_from_certspotter(domain: str, limit: int) -> list:
    """Fallback: certspotter.com issuances API (public, no key needed)."""
    certs = []
    try:
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert"
        status, body, _ = http_get(url, timeout=20)
        if status not in (200, 201) or not body:
            return []
        data = json.loads(body)
        for c in data[:limit]:
            cert = c.get("cert", {})
            not_after = cert.get("not_after", "")
            not_before = cert.get("not_before", "")
            days_left, expired, expiring_soon = _parse_cert_dates(not_after)
            names = [n.lower() for n in c.get("dns_names", [])]
            issuer = c.get("issuer", {})
            issuer_cn = issuer.get("friendly_name") or issuer.get("name", "")
            common_name = names[0] if names else ""
            certs.append({
                "id":           c.get("id"),
                "common_name":  common_name,
                "names":        names,
                "issuer_cn":    issuer_cn[:60],
                "not_before":   (not_before or "")[:10],
                "not_after":    (not_after or "")[:10],
                "days_left":    days_left,
                "expired":      expired,
                "expiring_soon":expiring_soon,
                "wildcard":     any(n.startswith("*.") for n in names),
                "source":       "certspotter",
            })
    except Exception:
        _log.debug('recon.py:1104 erro ignorado', exc_info=True)
    return certs


def _ct_from_shodan(domain: str, limit: int = 500) -> list:
    """Shodan Certificate Transparency Log API — free, no key required.
    https://ctl.shodan.io/api/v1/domain/{domain}"""
    certs = []
    try:
        url = f"https://ctl.shodan.io/api/v1/domain/{domain}"
        status, body, _ = http_get(url, timeout=15)
        if status not in (200, 201) or not body:
            return []
        data = json.loads(body)
        for c in data[:limit]:
            subject_cn = (c.get("subject_cn") or "").strip().lower()
            san = c.get("san_dns_names") or []
            if not isinstance(san, list):
                san = [subject_cn] if subject_cn else []
            san = [n.strip().lower() for n in san]
            if not subject_cn and san:
                subject_cn = san[0]
            not_after = c.get("not_after")  # Unix timestamp
            not_before = c.get("not_before")  # Unix timestamp
            days_left, expired, expiring_soon = _parse_cert_dates(not_after)

            # Format ISO dates from timestamps
            na_str = ""
            nb_str = ""
            try:
                if isinstance(not_after, (int, float)) and not_after > 0:
                    na_str = datetime.utcfromtimestamp(not_after).strftime("%Y-%m-%d")
                if isinstance(not_before, (int, float)) and not_before > 0:
                    nb_str = datetime.utcfromtimestamp(not_before).strftime("%Y-%m-%d")
            except Exception:
                _log.debug('recon.py:1138 erro ignorado', exc_info=True)

            certs.append({
                "id":           c.get("hash", ""),
                "common_name":  subject_cn,
                "names":        san,
                "issuer_cn":    (c.get("issuer_cn") or "")[:120],
                "not_before":   nb_str,
                "not_after":    na_str,
                "days_left":    days_left,
                "expired":      expired,
                "expiring_soon": expiring_soon,
                "wildcard":     any(n.startswith("*.") for n in san),
                "source":       "shodan_ctl",
            })
    except Exception:
        _log.debug('recon.py:1154 erro ignorado', exc_info=True)
    return certs


def _cn(dn: str) -> str:
    m = re.search(r"CN=([^,/]+)", dn)
    return m.group(1).strip() if m else dn[:60]


def get_ssl_info(host: str, port: int = 443) -> dict:
    """Get SSL/TLS certificate info. Uses CERT_REQUIRED for real cert data; falls back to DER on failures."""
    result = {"host": host, "port": port, "reachable": False}
    if not _dns_resolves(host):
        return result

    def _parse_cert(cert: dict) -> dict:
        return {
            "subject":    dict(x[0] for x in cert.get("subject", [])),
            "issuer":     dict(x[0] for x in cert.get("issuer", [])),
            "not_after":  cert.get("notAfter", ""),
            "san":        [v for t, v in cert.get("subjectAltName", []) if t == "DNS"],
        }

    def _connect(verify: bool):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
        if not verify:
            ctx.check_hostname = False
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()
                return cert, ssock.version(), cipher

    try:
        # First try with verification (gets full parsed cert)
        try:
            cert, tls_ver, cipher = _connect(verify=True)
            self_signed = False
        except ssl.SSLCertVerificationError:
            # Invalid/self-signed cert — connect without verify but use binary_form parsing
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                    der    = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    tls_ver = ssock.version()
            # Parse DER cert via openssl x509
            import base64
            pem = "-----BEGIN CERTIFICATE-----\n" + \
                  base64.b64encode(der).decode() + \
                  "\n-----END CERTIFICATE-----\n"
            r = subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-issuer",
                 "-enddate", "-ext", "subjectAltName"],
                input=pem, capture_output=True, text=True, timeout=5,
            )
            cert = {}
            san_list = []
            for line in r.stdout.splitlines():
                if line.startswith("subject="):
                    cn = re.search(r"CN\s*=\s*([^,/\n]+)", line)
                    if cn: cert["subject"] = [[ ("commonName", cn.group(1).strip()) ]]
                elif line.startswith("issuer="):
                    o = re.search(r"O\s*=\s*([^,/\n]+)", line)
                    if o: cert["issuer"] = [[ ("organizationName", o.group(1).strip()) ]]
                elif line.startswith("notAfter="):
                    cert["notAfter"] = line.split("=",1)[1].strip()
                elif "DNS:" in line:
                    san_list = re.findall(r"DNS:([^\s,]+)", line)
            if san_list:
                cert["subjectAltName"] = [("DNS", s) for s in san_list]
            self_signed = True

        parsed = _parse_cert(cert)
        result.update({
            "reachable":   True,
            "tls_version": tls_ver,
            "cipher":      cipher[0] if cipher else "",
            "cipher_bits": cipher[2] if cipher else 0,
            "self_signed": self_signed,
            **parsed,
        })

        # Expiry check
        not_after = result.get("not_after", "")
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
            try:
                exp  = datetime.strptime(not_after.strip(), fmt)
                days = (exp - datetime.utcnow()).days
                result.update({"days_left": days, "expired": days < 0, "expiring_soon": 0 <= days <= 30})
                break
            except Exception:
                _log.debug('recon.py:1248 erro ignorado', exc_info=True)

        issues = []
        if result.get("expired"):        issues.append("Certificate EXPIRED")
        if result.get("expiring_soon"):  issues.append(f"Expires in {result.get('days_left')} days")
        if self_signed:                  issues.append("Self-signed certificate")
        if result.get("cipher_bits", 0) < 128: issues.append("Weak cipher (<128 bit)")
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            issues.append(f"Outdated TLS: {tls_ver}")
        result["issues"] = issues

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = f"Connection failed: {e}"
    except Exception as e:
        result["error"] = str(e)
    return result


def run_cert_recon(domain: str, live_hosts: list = None) -> dict:
    """CT logs + SSL analysis for domain and its known hosts."""
    certs = get_ct_certs(domain)
    # New subdomains from CT not in our hosts list
    known = set(h.get("host","") for h in (live_hosts or []))
    ct_subdomains = []
    seen_subs = set()
    for c in certs:
        for name in c.get("names",[]):
            name = name.strip().lstrip("*.")
            if name.endswith(domain) and name not in seen_subs and name not in known:
                seen_subs.add(name)
                ct_subdomains.append(name)

    # SSL probe selected hosts; if no live hosts with port 443, probe the domain itself
    ssl_results = []
    hosts_to_probe = [h["host"] for h in (live_hosts or []) if 443 in h.get("ports", []) or "443" in h.get("ports", [])]
    if not hosts_to_probe:
        hosts_to_probe = [domain]
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(get_ssl_info, h): h for h in hosts_to_probe}
        for fut in as_completed(futures):
            ssl_results.append(fut.result())

    # Aggregate issues
    total_expired  = sum(1 for s in ssl_results if s.get("expired"))
    total_expiring = sum(1 for s in ssl_results if s.get("expiring_soon"))

    return {
        "domain":          domain,
        "certs":           certs,
        "ssl_results":     ssl_results,
        "ct_subdomains":   sorted(ct_subdomains)[:100],
        "total_certs":     len(certs),
        "total_expired":   total_expired,
        "total_expiring":  total_expiring,
        "issuers":         _count_issuers(certs),
        "scanned_at":      datetime.now().isoformat(timespec="seconds"),
    }


def _count_issuers(certs: list) -> dict:
    counts: dict[str,int] = {}
    for c in certs:
        iss = c.get("issuer_cn","Unknown")
        counts[iss] = counts.get(iss,0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1])[:10])
