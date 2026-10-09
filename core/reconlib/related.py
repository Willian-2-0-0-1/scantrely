"""Reverse WHOIS — Asset Attribution (ASM) — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from datetime import datetime
import json
import os
import re
import urllib.error
import urllib.request
from core.reconlib.base import UA, _log, http_get
from core.reconlib.typosquat import _resolve_domain

# ── Related Domain Discovery ──

_BRAND_TLDS = [
    # Brazil
    ".com.br", ".net.br", ".org.br", ".br", ".gov.br", ".edu.br",
    # Latin America
    ".ar", ".com.ar", ".uy", ".com.uy", ".cl", ".com.cl", ".co", ".com.co",
    ".pe", ".com.pe", ".mx", ".com.mx", ".py", ".com.py", ".bo", ".com.bo",
    ".ec", ".com.ec", ".ve", ".com.ve", ".pa", ".com.pa", ".cr", ".co.cr",
    ".do", ".com.do",
    # Global gTLDs
    ".com", ".net", ".org", ".io", ".app", ".dev", ".cloud", ".ai",
    ".info", ".biz", ".us", ".co.uk", ".uk", ".de", ".fr", ".es", ".it",
    ".nl", ".eu", ".ca", ".au", ".in", ".jp", ".cn", ".pt", ".ch",
    ".digital", ".online", ".tech", ".site", ".store", ".live",
    ".bank", ".finance", ".seguros", ".solutions", ".security",
    ".network", ".email", ".systems", ".services", ".technology",
    ".ventures", ".capital", ".insurance", ".healthcare", ".agency",
    ".consulting", ".marketing", ".media", ".software", ".legal",
    ".business", ".company", ".enterprises", ".institute",
    ".management", ".partners", ".support", ".training",
]


_BRAND_PREFIXES = ["", "www.", "m.", "app.", "api.", "portal.", "login.",
                   "secure.", "mail.", "vpn.", "remote.", "web.", "my."]


def _related_tld_candidates(domain: str) -> set:
    """Generate TLD-variation candidates from the primary domain name."""
    parts = domain.rsplit(".", 2)
    base = parts[0]
    candidates = set()
    for tld in _BRAND_TLDS:
        candidates.add(f"{base}{tld}")
    candidates.discard(domain)
    return candidates



def _related_crtsh_org(domain: str) -> set:
    """
    Query crt.sh to find sibling domains via two methods:
    1. Wildcard search by domain base name across all TLDs (e.g. %portoseguro%)
    2. Org-name search via HTML parse of an individual cert's Subject O= field
    """
    candidates = set()
    # Extract the brand name (first label of the domain, strip country TLD parts)
    parts = domain.split(".")
    base_name = parts[0]  # e.g. "portoseguro" from "portoseguro.com.br"

    # Method A: wildcard by brand name — finds sister domains with same name, different TLD
    try:
        import urllib.parse as _up
        url = f"https://crt.sh/?q=%25{_up.quote(base_name)}%25&output=json"
        status, raw, _ = http_get(url, timeout=20, retries=2)
        if status == 200 and raw:
            certs = json.loads(raw.decode("utf-8", "ignore"))
            for cert in certs[:2000]:
                for field in (cert.get("name_value", ""), cert.get("common_name", "")):
                    for line in (field or "").split("\n"):
                        line = line.strip().lstrip("*.")
                        if not line or " " in line or len(line) > 120:
                            continue
                        p = line.split(".")
                        if len(p) >= 3 and p[-1] == "br":
                            root = ".".join(p[-3:])
                        elif len(p) >= 2:
                            root = ".".join(p[-2:])
                        else:
                            continue
                        if root != domain:
                            candidates.add(root)
    except Exception:
        _log.debug('recon.py:3141 erro ignorado', exc_info=True)

    # Method B: org-name search — parse Subject O= from cert HTML, then search by org
    try:
        import urllib.parse as _up, re as _re
        _ca_noise = {"let's encrypt", "digicert", "sectigo", "geotrust",
                     "globalsign", "amazon", "google", "microsoft", "cloudflare",
                     "cpanel", "comodo", "godaddy", "thawte", "verisign",
                     "entrust", "identrust", "zerossl", "buypass", "soluti",
                     "ac raiz", "certisign", "serasa"}

        def _extract_subject_org(html: str) -> str:
            # crt.sh HTML uses &nbsp; padding: "Subject:<BR>...organizationName&nbsp;=&nbsp;ORG<BR>"
            # Find the Subject block (before Issuer: section)
            subj_m = _re.search(r'Subject:<BR>(.*?)(?:Issuer:|</TD>|$)', html, _re.DOTALL)
            if not subj_m:
                return ""
            subj = subj_m.group(1)
            # organizationName followed by padding then = then &nbsp; then value then <BR>
            m = _re.search(r'organizationName(?:&nbsp;|\s)+=(?:&nbsp;|\s)+([^<]+)<BR>', subj)
            if not m:
                return ""
            org = m.group(1).replace("&nbsp;", " ").replace("&amp;", "&").strip()
            return org

        # Phase 1: Try to discover org name from OV cert HTML (fast-fail on crt.sh instability)
        org_found = None
        probe_hosts = [f"www.{domain}", f"mail.{domain}"]
        dv_patterns = ("let's encrypt", "r10", "r11", "r12", "r13", "e5", "e6",
                       "e7", "e8", "e9", "globalsign atlas r3 dv", "amazon",
                       "buypass", "zerossl", "google trust", "ssl.com dv")
        for probe in probe_hosts:
            url = f"https://crt.sh/?q={probe}&output=json"
            status, raw, _ = http_get(url, timeout=10, retries=1)
            if status != 200 or not raw:
                continue
            try:
                certs = json.loads(raw.decode("utf-8", "ignore"))
            except Exception:
                continue
            ov_certs = [
                c for c in certs
                if not any(p in c.get("issuer_name", "").lower() for p in dv_patterns)
            ][:5]
            for cert in ov_certs:
                cid = cert.get("id")
                if not cid:
                    continue
                hs, hr, _ = http_get(f"https://crt.sh/?id={cid}", timeout=8, retries=1)
                if hs != 200 or not hr:
                    continue
                org = _extract_subject_org(hr.decode("utf-8", "ignore"))
                if not org:
                    continue
                if any(n in org.lower() for n in _ca_noise):
                    continue
                org_found = org
                break
            if org_found:
                break

            if org_found:
                url2 = f"https://crt.sh/?o={_up.quote(org_found)}&output=json"
                s2, r2, _ = http_get(url2, timeout=25, retries=2)
                if s2 == 200 and r2:
                    try:
                        org_certs = json.loads(r2.decode("utf-8", "ignore"))
                    except Exception:
                        org_certs = []
                    for oc in org_certs[:2000]:
                        for field in (oc.get("name_value", ""), oc.get("common_name", "")):
                            for line in (field or "").split("\n"):
                                line = line.strip().lstrip("*.")
                                if not line or " " in line or len(line) > 120:
                                    continue
                                p = line.split(".")
                                if len(p) >= 3 and p[-1] == "br":
                                    root = ".".join(p[-3:])
                                elif len(p) >= 2:
                                    root = ".".join(p[-2:])
                                else:
                                    continue
                                if root != domain:
                                    candidates.add(root)
                break  # org found and processed — stop trying more probe hosts
    except Exception:
        _log.debug('recon.py:3227 erro ignorado', exc_info=True)

    return candidates



def _related_reverse_ip(domain: str) -> set:
    """
    Discover sibling domains sharing the same IP block via HackerTarget reverse-IP API.
    Falls back to a simple set of IPs resolved from the primary domain.
    """
    candidates = set()
    try:
        ips = _resolve_domain(domain)
        if not ips:
            return candidates
        for ip in ips[:3]:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            status, raw, _ = http_get(url, timeout=10, retries=1)
            if status == 200 and raw:
                for line in raw.decode("utf-8", "ignore").splitlines():
                    h = line.strip().lstrip("*.")
                    if h and "." in h and " " not in h:
                        parts = h.split(".")
                        if len(parts) >= 3 and parts[-1] == "br":
                            root = ".".join(parts[-3:])
                        elif len(parts) >= 2:
                            root = ".".join(parts[-2:])
                        else:
                            continue
                        if root != domain:
                            candidates.add(root)
    except Exception:
        _log.debug('recon.py:3259 erro ignorado', exc_info=True)
    return candidates



def run_related_domains(domain: str) -> dict:
    """
    Discover related/sister domains via three complementary methods:
    1. TLD variations of the primary domain name
    2. crt.sh reverse org-name lookup (finds subsidiaries with different brand names)
    3. HackerTarget reverse-IP lookup (finds domains sharing same infrastructure)
    """
    candidates_tld     = _related_tld_candidates(domain)
    candidates_crtsh   = _related_crtsh_org(domain)
    candidates_revip   = _related_reverse_ip(domain)

    all_candidates = candidates_tld | candidates_crtsh | candidates_revip
    all_candidates.discard(domain)

    results = []
    def check_domain(d):
        ips = _resolve_domain(d)
        if ips:
            status_code, raw, _ = http_get(f"https://{d}", timeout=5, retries=1)
            if status_code:
                title_match = re.search(r"<title>(.*?)</title>",
                                        raw[:2000].decode("utf-8", "ignore"), re.I)
                title = title_match.group(1)[:100] if title_match else ""
                return {"domain": d, "ips": ips, "https": True,
                        "title": title, "status": status_code}
            return {"domain": d, "ips": ips, "https": False, "title": "", "status": 0}
        return None

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(check_domain, d): d for d in all_candidates}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)

    return {
        "domain":          domain,
        "checked":         len(all_candidates),
        "checked_tld":     len(candidates_tld),
        "checked_crtsh":   len(candidates_crtsh),
        "checked_revip":   len(candidates_revip),
        "found":           sorted(results, key=lambda r: r["domain"]),
        "count":           len(results),
        "scanned_at":      datetime.now().isoformat(timespec="seconds"),
    }



# ── Reverse WHOIS — Asset Attribution (ASM) ──

def _rdap_registrant(domain: str) -> dict:
    """Extract registrant org/email from public RDAP (free, no key). Often redacted."""
    org = email = ""
    try:
        status, body, _ = http_get(f"https://rdap.org/domain/{domain}", timeout=12, retries=2)
        if status == 200 and body:
            data = json.loads(body)
            for ent in data.get("entities", []):
                roles = ent.get("roles", []) or []
                if "registrant" not in roles and "administrative" not in roles:
                    continue
                vcard = ent.get("vcardArray", [])
                if len(vcard) == 2 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if not isinstance(item, list) or len(item) < 4:
                            continue
                        key, val = item[0], item[3]
                        if isinstance(val, list):
                            val = val[0] if val else ""
                        if not isinstance(val, str):
                            continue
                        if key in ("org", "fn") and not org:
                            org = val
                        elif key == "email" and not email:
                            email = val
    except Exception:
        _log.debug('recon.py:3338 erro ignorado', exc_info=True)
    return {"org": org.strip(), "email": email.strip()}



def run_reverse_whois(domain: str, whoisxml_key: str = "") -> dict:
    """
    Reverse-WHOIS asset attribution (ASM): discover sibling apex domains owned by
    the same organization by pivoting on the registrant org name and e-mail.

    - Registrant identity is pulled from free public RDAP first.
    - If a WhoisXML API key is configured, its Reverse WHOIS API returns the full
      list of domains registered with the same org/e-mail.

    Sibling apexes are reported for attribution only — they are intentionally NOT
    fed into the active host pool (avoids scanning out-of-scope third-party orgs).
    """
    whoisxml_key = whoisxml_key or os.environ.get("WHOISXML_KEY", "")
    reg   = _rdap_registrant(domain)
    org   = reg["org"]
    email = reg["email"]
    now   = datetime.now().isoformat(timespec="seconds")

    terms = []
    if email and "@" in email and "redacted" not in email.lower() and "privacy" not in email.lower():
        terms.append(("email", email))
    if org and len(org) > 3 and "redacted" not in org.lower() and "privacy" not in org.lower():
        terms.append(("org", org))

    if not whoisxml_key:
        return {
            "domain": domain, "registrant_org": org, "registrant_email": email,
            "sibling_domains": [], "found": [], "count": 0, "source": "rdap-only",
            "note": "Sem WhoisXML key — apenas atribuição de registrante (RDAP). "
                    "Defina whoisxml_key nas Settings para reverse-whois completo.",
            "scanned_at": now,
        }

    if not terms:
        return {
            "domain": domain, "registrant_org": org, "registrant_email": email,
            "sibling_domains": [], "found": [], "count": 0, "source": "whoisxml",
            "note": "Registrante redacted/privacy — sem termo utilizável para reverse-whois.",
            "scanned_at": now,
        }

    seed_apex  = domain.lower().lstrip(".")
    discovered = {}   # apex -> field that matched
    errors     = []
    from utils.circuit_breaker import breaker_for as _br_for
    br = _br_for("reverse-whois.whoisxmlapi.com")

    for field, value in terms:
        payload = json.dumps({
            "apiKey": whoisxml_key,
            "mode": "purchase",
            "searchType": "current",
            "basicSearchTerms": {"include": [value]},
        }).encode()
        if not br.allow():
            errors.append(f"{field}: circuit open")
            continue
        try:
            req = urllib.request.Request(
                "https://reverse-whois.whoisxmlapi.com/api/v2",
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": UA},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=25) as resp:
                rdata = json.loads(resp.read())
            br.success()
            for d in rdata.get("domainsList", []) or []:
                d = str(d).lower().strip().strip(".")
                if d and d != seed_apex:
                    discovered.setdefault(d, field)
        except Exception as exc:
            br.failure()
            errors.append(f"{field}: {exc}")

    items = list(discovered.items())

    def _check(item):
        d, field = item
        ips = _resolve_domain(d)
        return {"domain": d, "matched_by": field, "ips": ips, "live": bool(ips)}

    found = []
    if items:
        with ThreadPoolExecutor(max_workers=20) as pool:
            for r in pool.map(_check, items):
                found.append(r)

    found.sort(key=lambda x: (not x["live"], x["domain"]))
    return {
        "domain": domain, "registrant_org": org, "registrant_email": email,
        "terms": [v for _, v in terms],
        "sibling_domains": sorted(discovered.keys()),
        "found": found,
        "count": len(found),
        "live_count": sum(1 for f in found if f["live"]),
        "source": "whoisxml", "errors": errors, "scanned_at": now,
    }
