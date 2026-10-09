"""Typosquatting — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from datetime import datetime
import re
from core.reconlib.base import _log, _subp, http_get, subprocess

# ── Typosquatting ──

# Major ccTLDs + gTLDs for domain permutation scanning
_TLD_SWAPS = {
    ".com":    [".net", ".org", ".io", ".co", ".app", ".dev", ".cloud", ".ai", ".info", ".biz", ".us", ".co.uk", ".uk", ".de", ".fr", ".es", ".it", ".nl", ".eu", ".ca", ".au", ".in", ".jp", ".cn"],
    ".com.br": [".com", ".net.br", ".org.br", ".br", ".net", ".org", ".io", ".app", ".dev"],
    ".br":     [".com.br", ".net.br", ".org.br", ".com", ".net", ".org"],
    ".net":    [".com", ".org", ".io", ".net.br"],
    ".org":    [".com", ".net", ".io"],
    ".gov.br": [".br", ".com.br"],
    ".edu.br": [".br", ".com.br"],
}


# All ccTLDs to test against the base domain name (cross-country permutations)
_CC_TLDS = [
    # Brazil
    ".br", ".com.br", ".net.br", ".org.br", ".gov.br", ".edu.br", ".mil.br",
    # Latin America
    ".ar", ".com.ar", ".net.ar", ".org.ar",
    ".uy", ".com.uy",
    ".cl", ".com.cl", ".net.cl",
    ".co", ".com.co", ".net.co", ".org.co",
    ".pe", ".com.pe", ".net.pe",
    ".mx", ".com.mx", ".net.mx", ".org.mx",
    ".py", ".com.py", ".net.py",
    ".bo", ".com.bo",
    ".ec", ".com.ec", ".net.ec",
    ".ve", ".com.ve", ".net.ve",
    ".pa", ".com.pa",
    ".cr", ".co.cr",
    ".do", ".com.do",
    ".gt", ".com.gt",
    ".hn", ".com.hn",
    ".sv", ".com.sv",
    ".ni", ".com.ni",
    # Global gTLDs
    ".com", ".net", ".org", ".io", ".co", ".app", ".dev", ".cloud", ".ai",
    ".info", ".biz", ".us", ".co.uk", ".uk", ".de", ".fr", ".es", ".it",
    ".nl", ".eu", ".ca", ".au", ".in", ".jp", ".cn", ".ru", ".pl",
    ".pt", ".ch", ".se", ".no", ".fi", ".dk", ".cz", ".at", ".be",
    ".kr", ".tw", ".hk", ".sg", ".nz", ".za",
    # Business / corporate TLDs
    ".digital", ".online", ".tech", ".site", ".store", ".live",
    ".security", ".network", ".email", ".systems", ".services",
    ".solutions", ".technology", ".ventures", ".capital", ".finance",
    ".bank", ".insurance", ".healthcare", ".agency", ".consulting",
    ".marketing", ".media", ".software", ".legal", ".accountant",
    ".associates", ".business", ".company", ".enterprises", ".expert",
    ".foundation", ".institute", ".international", ".management",
    ".partners", ".productions", ".professional", ".support", ".training",
    ".guru", ".ninja", ".pro", ".today", ".world", ".life",
]


def _typo_variants(domain: str) -> list[str]:
    """Generate typosquat variants matching dnstwist coverage."""
    parts = domain.rsplit(".", 2)
    if len(parts) < 2:
        return []

    if len(parts) == 3:
        name, tld1, tld2 = parts
        tld = f"{tld1}.{tld2}"
    else:
        name, tld = parts[0], ".".join(parts[1:])

    variants: set = set()
    current_tld = f".{tld}"

    # ── 1. Keyboard adjacency (replacement) ──
    kb_adj = {
        'a':'sq','b':'vghn','c':'xdfv','d':'erfcs','e':'wrds','f':'rtgv',
        'g':'tyhbf','h':'yujng','i':'uojk','j':'ikhnu','k':'jiol','l':'kop',
        'm':'njk','n':'bhjm','o':'ilp','p':'ol','q':'wa','r':'etdf',
        's':'adeqwz','t':'rfgy','u':'yhij','v':'cfgb','w':'qse','x':'czsd',
        'y':'tghu','z':'asx',
    }
    for i, ch in enumerate(name):
        for sub in kb_adj.get(ch, ""):
            variants.add(f"{name[:i]}{sub}{name[i+1:]}.{tld}")

    # ── 2. Omission (missing character) ──
    for i in range(len(name)):
        variants.add(f"{name[:i]}{name[i+1:]}.{tld}")

    # ── 3. Repetition (doubled character) ──
    for i, ch in enumerate(name):
        variants.add(f"{name[:i]}{ch}{ch}{name[i+1:]}.{tld}")

    # ── 4. Transposition (adjacent swap) ──
    for i in range(len(name) - 1):
        s = list(name)
        s[i], s[i+1] = s[i+1], s[i]
        variants.add(f"{''.join(s)}.{tld}")

    # ── 5. Insertion (extra char at every position) ──
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    for i in range(len(name) + 1):
        for ch in alphabet:
            candidate = f"{name[:i]}{ch}{name[i:]}.{tld}"
            # skip if it only differs by appending at end (handled by addition)
            if candidate != f"{name}{ch}.{tld}":
                variants.add(candidate)

    # ── 6. Addition (append digit/char at end / prepend at start) ──
    for ch in "0123456789":
        variants.add(f"{name}{ch}.{tld}")
        variants.add(f"{ch}{name}.{tld}")
    for ch in alphabet:
        variants.add(f"{name}{ch}.{tld}")

    # ── 7. Vowel swap ──
    vowels = "aeiou"
    for i, ch in enumerate(name):
        if ch in vowels:
            for v in vowels:
                if v != ch:
                    variants.add(f"{name[:i]}{v}{name[i+1:]}.{tld}")

    # ── 8. Bitsquatting (single-bit flip, result must be printable ASCII) ──
    valid_chars = set("abcdefghijklmnopqrstuvwxyz0123456789-")
    for i, ch in enumerate(name):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if flipped in valid_chars and flipped != ch:
                variants.add(f"{name[:i]}{flipped}{name[i+1:]}.{tld}")

    # ── 9. Homoglyph — Unicode IDN lookalikes (generates xn-- punycode) ──
    # Maps Latin char → list of Unicode homoglyphs
    _HOMOGLYPHS: dict[str, list[str]] = {
        "a": ["Ð°", "É‘"],          # Cyrillic Ð°, Latin É‘
        "c": ["Ï²", "Ñ"],          # Greek Ï², Cyrillic Ñ
        "d": ["Ô"],                    # Cyrillic Ô
        "e": ["Ðµ", "Ò½"],          # Cyrillic Ðµ, Ò½
        "g": ["É¡"],                    # Latin É¡
        "h": ["Ò»"],                    # Cyrillic Ò»
        "i": ["Ñ–", "Ó", "1"],     # Cyrillic Ñ–, Ó, digit 1
        "j": ["Ñ˜"],                    # Cyrillic Ñ˜
        "l": ["Ó", "1", "1"],     # Cyrillic Ó, digit
        "m": ["Ð¼"],                    # Cyrillic Ð¼
        "n": ["Õ¸"],                    # Armenian Õ¸
        "o": ["Ð¾", "Î¿", "0"],     # Cyrillic Ð¾, Greek Î¿, digit 0
        "p": ["Ñ€", "Ï"],          # Cyrillic Ñ€, Greek Ï
        "q": ["Õ£"],                    # Armenian Õ£
        "r": ["Ð³"],                    # Cyrillic Ð³
        "s": ["Ñ•", "5"],               # Cyrillic Ñ•
        "u": ["Ð²"],                    # Cyrillic Ð²
        "v": ["Î½"],                    # Greek Î½
        "w": ["Ñ¡"],                    # Cyrillic Ñ¡
        "x": ["Ñ…"],                    # Cyrillic Ñ…
        "y": ["Ñƒ", "Ò¯"],          # Cyrillic Ñƒ, Ò¯
        "z": ["Ê"],                    # Latin Ê
    }
    for i, ch in enumerate(name):
        for glyph in _HOMOGLYPHS.get(ch, []):
            candidate_name = name[:i] + glyph + name[i+1:]
            try:
                idn = (candidate_name + "." + tld).encode("idna").decode("ascii")
                variants.add(idn)
            except (UnicodeError, UnicodeDecodeError):
                pass

    # ── 10. Hyphenation (insert hyphen between each adjacent pair) ──
    for i in range(1, len(name)):
        variants.add(f"{name[:i]}-{name[i:]}.{tld}")

    # ── 11. TLD swaps ──
    for alt in _TLD_SWAPS.get(current_tld, []):
        variants.add(f"{name}{alt}")

    # ── 12. Cross-TLD sweep ──
    for cc_tld in _CC_TLDS:
        if cc_tld != current_tld:
            variants.add(f"{name}{cc_tld}")

    # ── 13. Common prefixes/suffixes ──
    for pfx in ["www", "m", "app", "portal", "login", "secure", "mail", "vpn"]:
        variants.add(f"{pfx}-{name}.{tld}")
        variants.add(f"{pfx}{name}.{tld}")
    for sfx in ["-br", "-brasil", "-online", "-digital", "-bank", "-app"]:
        variants.add(f"{name}{sfx}.{tld}")

    # ── 14. ASCII homograph (digit/symbol substitutions) ──
    for orig, fakes in [("o", "0"), ("i", "1l"), ("e", "3"), ("a", "@4"), ("s", "5$")]:
        for fake in fakes:
            for i, ch in enumerate(name):
                if ch == orig:
                    variants.add(f"{name[:i]}{fake}{name[i+1:]}.{tld}")

    # ── 15. Plural ──
    variants.add(f"{name}s.{tld}")

    # ── 16. Combosquatting — brand + sector keywords ──
    _SECTOR_WORDS = [
        "auto", "vida", "saude", "residencial", "banco", "bank", "seguros",
        "seguranca", "sinistro", "apolice", "previdencia", "corretor",
        "fianca", "premio", "credito", "conta", "acesso", "portal",
        "login", "cliente", "minha", "meu", "area", "atendimento",
    ]
    for word in _SECTOR_WORDS:
        variants.add(f"{name}-{word}.{tld}")
        variants.add(f"{word}-{name}.{tld}")
        variants.add(f"{name}{word}.{tld}")
        variants.add(f"{word}{name}.{tld}")

    variants.discard(domain)
    # Remove obviously invalid candidates (empty labels, too long, bad chars)
    _valid_label = re.compile(r'^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]$|^[a-z0-9]$')
    clean = set()
    for v in variants:
        label = v.split(".")[0]
        if _valid_label.match(label) and len(v) <= 253:
            clean.add(v)
    return sorted(clean)



def _resolve_domain(d: str, timeout: int = 3) -> list[str]:
    try:
        r = _subp(["dig","+short","+time=2","+tries=1","A", d],
                           capture_output=True, text=True, timeout=timeout)
        ips = [l.strip() for l in r.stdout.strip().splitlines()
               if re.match(r"^\d+\.\d+\.\d+\.\d+$", l.strip())]
        return ips
    except Exception:
        return []



_BROKER_NS = frozenset({
    "afternic", "sedoparking", "sedo.", "parkingcrew", "bodis.", "porkbun",
    "hugedomains", "dan.com", "sudos.co", "flippa", "undeveloped",
    "uniregistry", "squadhelp", "brandpa", "efty.",
})


def _check_typo(domain: str) -> dict:
    ips = _resolve_domain(domain)

    # NS lookup — catches domains with NS but no A (e.g. .uy ccTLDs)
    ns_raw = ""
    try:
        r = subprocess.run(["dig", "+short", domain, "NS"],
                           capture_output=True, text=True, timeout=4)
        ns_raw = r.stdout.strip().lower()
    except Exception:
        _log.debug('recon.py:2350 erro ignorado', exc_info=True)

    registered = len(ips) > 0 or bool(ns_raw)
    result = {"domain": domain, "registered": registered, "ips": ips, "risk": "low"}

    if not registered:
        return result

    result["risk"] = "medium"

    # MX record check — domain capable of receiving email → phishing escalation
    try:
        r = subprocess.run(["dig", "+short", domain, "MX"],
                           capture_output=True, text=True, timeout=4)
        mx_lines = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
        if mx_lines:
            result["has_mx"]    = True
            result["mx_records"] = mx_lines[:3]
    except Exception:
        _log.debug('recon.py:2369 erro ignorado', exc_info=True)

    # Broker NS fingerprint — catches squatters even without HTTP (302-only domains)
    if ns_raw and any(b in ns_raw for b in _BROKER_NS):
        result["risk"]   = "high"
        result["status"] = "broker_listed"
        return result

    if not ips:
        result["status"] = "registered_no_ip"
        return result

    # SSL certificate check — brand keyword in cert = full phishing setup
    try:
        import ssl as _ssl, socket as _socket
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE
        with _socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cn   = dict(x[0] for x in cert.get("subject", [])).get("commonName", "")
                sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                result["ssl"] = {"cn": cn, "sans": sans[:5]}
                _brand_kw = ["portoseguro", "porto-seguro", "portobank",
                             "averbeporto", "porto seguro"]
                cert_text = (cn + " " + " ".join(sans)).lower()
                if any(k in cert_text for k in _brand_kw):
                    result["ssl"]["brand_in_cert"] = True
    except Exception:
        _log.debug('recon.py:2399 erro ignorado', exc_info=True)

    # HTTP check — follow redirects, detect broker/sale landing pages
    try:
        status_code, raw, hdrs = http_get(f"http://{domain}", timeout=5, retries=1)
        if status_code:
            body      = raw[:1000].decode("utf-8", "ignore").lower()
            final_url = hdrs.get("location", "").lower() if isinstance(hdrs, dict) else ""
            broker_signals = [
                "for sale", "buy this domain", "domain for sale",
                "buy-domain", "make an offer", "purchase this domain",
                "domain is for sale", "buy domain", "domain auction",
                "synergytech.com/buy", "dan.com/", "afternic.com",
                "sedo.com/", "hugedomains.com", "undeveloped.com",
            ]
            if any(s in body or s in final_url for s in broker_signals):
                result["risk"]        = "high"
                result["status"]      = "broker_listed"
                result["status_code"] = status_code
                if final_url:
                    result["redirect_to"] = final_url[:120]
            elif any(x in body for x in ["parked", "domain expired", "lander system"]):
                result["risk"]   = "low"
                result["status"] = "parked"
            else:
                result["risk"]        = "high"
                result["status"]      = "active"
                result["status_code"] = status_code
                # Escalate: active domain with email capability = critical
                if result.get("has_mx") or result.get("ssl", {}).get("brand_in_cert"):
                    result["risk"] = "critical"
        else:
            result["status"] = "registered_unreachable"
    except Exception:
        result["status"] = "registered_unreachable"

    return result



def _whois_registrant(domain: str) -> dict:
    """Extract registrant email + org from WHOIS. Rate-limited — use sparingly."""
    try:
        w = subprocess.run(["whois", domain],
                           capture_output=True, text=True, timeout=10)
        info: dict = {}
        for line in w.stdout.splitlines():
            ll = line.lower()
            val = line.split(":", 1)[-1].strip()
            if not val:
                continue
            if not info.get("email") and any(k in ll for k in
                    ("registrant email", "owner-email", "e-mail:", "registrant e-mail")):
                info["email"] = val[:80]
            if not info.get("org") and any(k in ll for k in
                    ("registrant org", "registrant name", "owner:", "org-name")):
                info["org"] = val[:80]
        # Detect company-owned domains by registrant
        _co_kw = ["porto seguro", "portoseguro", "averbeporto", "itaú", "itau unibanco"]
        owned_text = (info.get("email", "") + " " + info.get("org", "")).lower()
        if any(k in owned_text for k in _co_kw):
            info["company_owned"] = True
        return info
    except Exception:
        return {}



def run_typosquatting(domain: str, max_variants: int = 1200,
                      extra_words: list | None = None) -> dict:
    """
    Generate typosquat variants and check if registered.
    extra_words: additional brand words to sweep all ccTLDs against.
    """
    all_variants: list = _typo_variants(domain)
    variants: set = set(all_variants[:max_variants])

    for word in (extra_words or []):
        for tld in _CC_TLDS:
            variants.add(f"{word}{tld}")

    results = []
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(_check_typo, d): d for d in variants}
        for fut in as_completed(futures):
            results.append(fut.result())

    registered = [r for r in results if r["registered"]]

    # WHOIS enrichment — only for active/broker domains, max 30 to avoid rate-limiting
    _risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    enrich_targets = sorted(
        [r for r in registered if r.get("status") in ("active", "broker_listed")],
        key=lambda r: _risk_order.get(r.get("risk", "low"), 3)
    )[:30]
    with ThreadPoolExecutor(max_workers=5) as pool:
        whois_futures = {pool.submit(_whois_registrant, r["domain"]): r
                         for r in enrich_targets}
        for fut in as_completed(whois_futures):
            rec = whois_futures[fut]
            info = fut.result()
            if info:
                rec.update(info)
                if info.get("company_owned"):
                    rec["risk"]   = "low"
                    rec["status"] = "company_owned"

    active = [r for r in registered if r.get("status") in ("active", "broker_listed")]

    return {
        "domain":           domain,
        "total_checked":    len(variants),
        "registered":       sorted(registered,
                                   key=lambda r: _risk_order.get(r.get("risk", "low"), 3)),
        "active_count":     len(active),
        "registered_count": len(registered),
        "scanned_at":       datetime.now().isoformat(timespec="seconds"),
    }



def run_opensquat_monitor(keywords: list[str], work_dir: str = "/tmp") -> dict:
    """
    Run opensquat with keyword list against fresh CT log feed.
    Returns newly-registered domains matching the brand keywords.
    """
    import tempfile, json as _json

    kw_file = f"{work_dir}/opensquat_kw.txt"
    out_file = f"{work_dir}/opensquat_out.json"
    try:
        with open(kw_file, "w") as f:
            f.write("\n".join(keywords))
    except Exception as e:
        return {"error": str(e), "findings": []}

    try:
        r = subprocess.run(
            ["opensquat", "-k", kw_file, "--ct", "--phishing",
             "--output", out_file, "--format", "json"],
            capture_output=True, text=True, timeout=300,
        )
    except FileNotFoundError:
        # opensquat not installed — try pip-installed path
        try:
            r = subprocess.run(
                ["python3", "-m", "opensquat", "-k", kw_file, "--ct",
                 "--output", out_file, "--format", "json"],
                capture_output=True, text=True, timeout=300,
            )
        except Exception as e:
            return {"error": f"opensquat not available: {e}", "findings": []}
    except subprocess.TimeoutExpired:
        return {"error": "opensquat timed out", "findings": []}

    # Parse JSON output
    findings = []
    try:
        with open(out_file) as f:
            raw = _json.load(f)
        domains = raw if isinstance(raw, list) else raw.get("domains", [])
        for entry in domains:
            d = entry if isinstance(entry, str) else entry.get("domain", "")
            if d:
                findings.append(d)
    except Exception:
        # Fallback: parse stdout line-by-line
        for line in r.stdout.splitlines():
            parts = line.strip().split(" - ")
            if len(parts) >= 2:
                d = parts[1].strip()
                if "." in d:
                    findings.append(d)

    # Enrich each new domain with _check_typo
    enriched = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_check_typo, d): d for d in findings}
        for fut in as_completed(futures):
            enriched.append(fut.result())

    return {
        "keywords":   keywords,
        "new_domains": len(findings),
        "findings":   sorted(enriched, key=lambda r: {"critical":0,"high":1,"medium":2,"low":3}.get(r.get("risk","low"),3)),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }
