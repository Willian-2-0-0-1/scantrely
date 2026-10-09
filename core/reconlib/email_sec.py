"""Email Security — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import re
import socket
from core.reconlib.base import _log, _subp, subprocess
from core.reconlib.dnsutil import _dns_batch

# ── Email Security ──

DKIM_SELECTORS = [
    "google","selector1","selector2","default","mail","dkim","k1","s1","s2",
    "email","mandrill","mailchimp","sendgrid","smtp","protonmail","pm","zoho",
    "mimecast","mimecast1","mimecast2","amazon","ses","msa","beta","corp",
]


def check_spf(domain: str) -> dict:
    result = {"record": None, "score": "missing", "issues": [], "mechanisms": []}
    try:
        r = _subp(["dig","+short","+time=2","+tries=1","TXT", domain],
                           capture_output=True, text=True, timeout=8)
        for line in r.stdout.splitlines():
            line = line.strip().strip('"')
            if line.lower().startswith("v=spf1"):
                result["record"] = line
                mechs = line.split()[1:]
                result["mechanisms"] = mechs
                all_m = next((m for m in mechs if re.match(r'^[+~\-?]?all$', m)), None)
                if all_m is None or "all" not in line:
                    result["score"] = "incomplete"
                    result["issues"].append("No 'all' mechanism — incomplete policy")
                elif all_m.startswith("+"):
                    result["score"] = "critical"
                    result["issues"].append("+all: ANY server can send email as this domain")
                elif all_m.startswith("?"):
                    result["score"] = "high"
                    result["issues"].append("?all: neutral — no enforcement, effectively spoofable")
                elif all_m.startswith("~"):
                    result["score"] = "medium"
                    result["issues"].append("~all: softfail — most providers won't reject")
                elif all_m.startswith("-"):
                    result["score"] = "pass"
                # redirect?
                if any("redirect=" in m for m in mechs):
                    result["issues"].append("Uses redirect= — check target domain's SPF")
                if any("include:" in m for m in mechs):
                    count = sum(1 for m in mechs if "include:" in m)
                    if count > 8:
                        result["issues"].append(f"WARNING: {count} includes (>10 may cause DNS lookup limit)")
                break
        if not result["record"]:
            result["score"] = "missing"
            result["issues"].append("No SPF record — domain is fully spoofable")
    except Exception as e:
        result["error"] = str(e)
    return result


def check_dmarc(domain: str) -> dict:
    result = {"record": None, "policy": None, "pct": 100,
              "rua": None, "ruf": None, "score": "missing", "issues": []}
    try:
        r = _subp(["dig","+short","+time=2","+tries=1","TXT", f"_dmarc.{domain}"],
                           capture_output=True, text=True, timeout=8)
        for line in r.stdout.splitlines():
            line = line.strip().strip('"')
            if "v=dmarc1" in line.lower():
                result["record"] = line
                tags = dict(re.findall(r'(\w+)=([^;]+)', line, re.I))
                policy = tags.get("p","none").lower()
                result["policy"] = policy
                result["pct"]    = int(tags.get("pct","100"))
                result["rua"]    = tags.get("rua","")
                result["ruf"]    = tags.get("ruf","")
                sp               = tags.get("sp", policy)

                if policy == "none":
                    result["score"] = "high"
                    result["issues"].append("p=none: monitoring only — spoofed emails are delivered")
                elif policy == "quarantine":
                    result["score"] = "medium"
                    if result["pct"] < 100:
                        result["issues"].append(f"pct={result['pct']}: only {result['pct']}% of mail is checked")
                elif policy == "reject":
                    result["score"] = "pass"
                    if result["pct"] < 100:
                        result["score"] = "medium"
                        result["issues"].append(f"pct={result['pct']}: only {result['pct']}% of mail is rejected")

                if not result["rua"]:
                    result["issues"].append("No rua= tag — no DMARC reporting configured")
                if sp == "none" and policy != "none":
                    result["issues"].append(f"sp=none: subdomain policy is weaker than main domain")
                break
        if not result["record"]:
            result["score"] = "missing"
            result["issues"].append("No DMARC record — spoofed emails bypass policy checks")
    except Exception as e:
        result["error"] = str(e)
    return result


def check_bimi(domain: str) -> dict:
    """Check BIMI (Brand Indicators for Message Identification) — bonus."""
    try:
        r = _subp(["dig","+short","+time=2","+tries=1","TXT", f"default._bimi.{domain}"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if "v=bimi1" in line.lower():
                return {"record": line.strip().strip('"'), "present": True}
    except Exception:
        _log.debug('recon.py:849 erro ignorado', exc_info=True)
    return {"present": False}


def check_dkim(domain: str) -> list:
    def _query_selector(sel: str) -> dict | None:
        try:
            r = subprocess.run(
                ["dig","+short","+time=1","+tries=1","TXT", f"{sel}._domainkey.{domain}"],
                capture_output=True, text=True, timeout=3,
            )
            txt = r.stdout.strip()
            if "v=dkim1" in txt.lower() or ("p=" in txt and len(txt) > 20):
                rec = txt.replace('"','').replace('\n',' ')[:300]
                p_match = re.search(r'p=([A-Za-z0-9+/=]+)', rec)
                key_bits = None
                if p_match:
                    import base64
                    try:
                        key_bytes = base64.b64decode(p_match.group(1) + "==")
                        key_bits = len(key_bytes) * 8
                    except Exception:
                        _log.debug('recon.py:870 erro ignorado', exc_info=True)
                return {"selector": sel, "record": rec, "key_bits": key_bits,
                        "weak": key_bits is not None and key_bits < 1024}
        except Exception:
            _log.debug('recon.py:874 erro ignorado', exc_info=True)
        return None

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = pool.map(_query_selector, DKIM_SELECTORS)
    return [r for r in results if r is not None]


def check_mx(domain: str) -> list:
    records = []
    try:
        r = _subp(["dig","+short","+time=2","+tries=1","MX", domain],
                           capture_output=True, text=True, timeout=8)
        for line in r.stdout.strip().splitlines():
            line = line.strip()
            if not line: continue
            parts = line.split()
            if len(parts) >= 2:
                prio, host = parts[0], parts[1].rstrip(".")
                # Reverse IP
                ips = []
                try:
                    for info in socket.getaddrinfo(host, None):
                        ip = info[4][0]
                        if ip not in ips: ips.append(ip)
                except Exception:
                    _log.debug('recon.py:899 erro ignorado', exc_info=True)
                records.append({"priority": prio, "host": host, "ips": ips})
    except Exception:
        _log.debug('recon.py:902 erro ignorado', exc_info=True)
    return records


def email_spoofability(spf: dict, dmarc: dict) -> str:
    spf_s   = spf.get("score","missing")
    dmarc_s = dmarc.get("score","missing")
    if spf_s == "missing" and dmarc_s == "missing": return "critical"
    if spf_s in ("critical","missing") or dmarc_s in ("missing","high"): return "high"
    if spf_s in ("high","medium","incomplete") or dmarc_s == "medium":   return "medium"
    return "low"


def run_email_recon(domain: str) -> dict:
    """Full email security analysis: SPF, DMARC, DKIM, BIMI, MX — single DNS batch."""
    spf_r   = {"record": None, "score": "missing", "issues": [], "mechanisms": []}
    dmarc_r = {"record": None, "policy": None, "pct": 100, "rua": None, "ruf": None, "score": "missing", "issues": []}
    bimi_r  = {"record": None, "score": "missing", "issues": []}
    dkim_r  = []
    mx_r    = []

    # Batch ALL email DNS queries into ONE subprocess
    dkim_selectors = ["google", "default", "selector1", "selector2", "dkim", "mail", "s1", "s2", "k1", "mandrill", "sendgrid"]
    queries = [
        (domain, "TXT", []),
        ("_dmarc." + domain, "TXT", []),
        ("default._bimi." + domain, "TXT", []),
        (domain, "MX", []),
    ] + [(f"{sel}._domainkey.{domain}", "TXT", []) for sel in dkim_selectors]

    batch = _dns_batch(queries)

    # Parse SPF
    for val in batch.get((domain, "TXT"), []):
        clean = val.strip().strip('"')
        if clean.lower().startswith("v=spf1"):
            spf_r["record"] = clean
            mechs = clean.split()[1:]
            spf_r["mechanisms"] = mechs
            all_m = next((m for m in mechs if re.match(r'^[+~\-?]?all$', m)), None)
            if all_m is None: spf_r["score"] = "incomplete"
            elif all_m.startswith("+"): spf_r["score"] = "critical"
            elif all_m.startswith("?"): spf_r["score"] = "high"
            elif all_m.startswith("~"): spf_r["score"] = "medium"
            elif all_m.startswith("-"): spf_r["score"] = "pass"
            break
    if not spf_r["record"]: spf_r["issues"].append("No SPF record")

    # Parse DMARC
    for val in batch.get(("_dmarc." + domain, "TXT"), []):
        clean = val.strip().strip('"')
        if "v=dmarc1" in clean.lower():
            dmarc_r["record"] = clean
            tags = dict(re.findall(r'(\w+)=([^;]+)', clean, re.I))
            dmarc_r["policy"] = tags.get("p", "none").lower()
            dmarc_r["pct"] = int(tags.get("pct", "100"))
            dmarc_r["rua"] = tags.get("rua", "")
            policy = dmarc_r["policy"]
            dmarc_r["score"] = "high" if policy == "none" else ("medium" if policy == "quarantine" else ("pass" if dmarc_r["pct"] >= 100 else "medium"))
            break
    if not dmarc_r["record"]: dmarc_r["issues"].append("No DMARC record")

    # Parse BIMI
    for val in batch.get(("default._bimi." + domain, "TXT"), []):
        if "v=bimi1" in val.lower():
            bimi_r["record"] = val; bimi_r["score"] = "present"; break
    if not bimi_r["record"]: bimi_r["score"] = "missing"

    # Parse DKIM
    for sel in dkim_selectors:
        for val in batch.get((f"{sel}._domainkey.{domain}", "TXT"), []):
            clean = val.strip().strip('"')
            if any(kw in clean.lower() for kw in ("v=dkim1", "k=rsa", "p=")):
                dkim_r.append({"selector": sel, "record": clean}); break

    # Parse MX
    for val in batch.get((domain, "MX"), []):
        parts = val.split()
        if parts and parts[-1].count(".") >= 1:
            mx_r.append(parts[-1])

    return {
        "domain":        domain,
        "spf":           spf_r,
        "dmarc":         dmarc_r,
        "dkim":          dkim_r,
        "mx":            mx_r,
        "bimi":          bimi_r,
        "spoofability":  email_spoofability(spf_r, dmarc_r),
        "scanned_at":    datetime.now().isoformat(timespec="seconds"),
    }
