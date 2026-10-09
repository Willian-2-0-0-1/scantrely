"""Credential / Breach Intelligence — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
import json
import re
from core.reconlib.base import _http_get_json, _log, _subp, http_get

# ── Credential / Breach Intelligence ──

def _check_leakix(domain: str) -> list:
    """Query LeakIX (free tier) for domain leaks."""
    findings = []
    try:
        url = f"https://leakix.net/domain/{domain}"
        status, body, _ = http_get(url, timeout=10,
                                   extra_headers={"Accept": "application/json"})
        if status != 200 or not body:
            return findings
        data = json.loads(body)
        for event in (data if isinstance(data, list) else [])[:20]:
            findings.append({
                "source":   "LeakIX",
                "type":     event.get("event_type","leak"),
                "host":     event.get("host",""),
                "summary":  event.get("summary","")[:200],
                "severity": "high" if event.get("severity","info") in ("high","critical") else "medium",
                "date":     event.get("time","")[:10],
            })
    except Exception:
        _log.debug('recon.py:4238 erro ignorado', exc_info=True)
    return findings



def _check_dehashed(domain: str, api_key: str = None) -> dict:
    """Query DeHashed for breach data (requires API key)."""
    if not api_key:
        return {"results": [], "note": "No DeHashed API key configured"}
    try:
        import base64
        auth = base64.b64encode(f":{api_key}".encode()).decode()
        url  = f"https://api.dehashed.com/search?query=domain%3A{domain}&size=20"
        status, body, _ = http_get(url, timeout=10,
                                   extra_headers={"Accept": "application/json",
                                                  "Authorization": f"Basic {auth}"})
        if status != 200 or not body:
            return {"results": [], "note": f"DeHashed returned HTTP {status}"}
        data = json.loads(body)
        entries = data.get("entries") or []
        return {
            "count": data.get("total",0),
            "results": [{"email": e.get("email",""), "username": e.get("username",""),
                         "database": e.get("database_name",""),
                         "hashed_password": bool(e.get("hashed_password"))} for e in entries[:20]],
        }
    except Exception as e:
        return {"error": str(e), "results": []}



def _check_hibp_domain(domain: str, api_key: str = None) -> dict:
    """Query HaveIBeenPwned domain search (v3, requires paid key)."""
    if not api_key:
        return {"results": [], "note": "No HIBP API key — domain search requires paid plan"}
    try:
        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
        status, body, _ = http_get(url, timeout=10,
                                   extra_headers={"hibp-api-key": api_key})
        if status == 404:
            return {"results": [], "count": 0, "note": "No breaches found"}
        if status == 401:
            return {"error": "Invalid HIBP API key", "results": []}
        if status != 200 or not body:
            return {"results": [], "note": f"HIBP returned HTTP {status}"}
        data = json.loads(body)
        return {"results": data, "count": len(data)}
    except Exception as e:
        return {"error": str(e), "results": []}
    return {"results": []}



def _check_trufflehog_github(domain: str) -> list:
    """Use trufflehog to scan GitHub for secrets related to domain."""
    import shutil as _shutil
    if not _shutil.which("trufflehog"):
        return []
    findings = []
    try:
        proc = _subp(
            ["trufflehog", "github", "--org", domain.split(".")[0],
             "--json", "--no-update"],
            capture_output=True, text=True, timeout=60,
        )
        for line in proc.stdout.strip().splitlines():
            try:
                item = json.loads(line)
                findings.append({
                    "source":    "trufflehog/github",
                    "type":      item.get("DetectorName","secret"),
                    "repo":      item.get("SourceMetadata",{}).get("Data",{}).get("Github",{}).get("repository",""),
                    "file":      item.get("SourceMetadata",{}).get("Data",{}).get("Github",{}).get("file",""),
                    "severity":  "critical",
                    "verified":  item.get("Verified", False),
                })
            except Exception:
                _log.debug('recon.py:4312 erro ignorado', exc_info=True)
    except Exception:
        _log.debug('recon.py:4314 erro ignorado', exc_info=True)
    return findings[:20]



_HR_URL_CAP = 40

_HR_LIST_CAP = 40

_HR_FAMILY_CAP = 20

_HR_EMAIL_CAP = 30

_HR_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)

_HR_EMAIL_RE = re.compile(
    r"^[^@\s]{1,64}@[^@\s]{1,120}\.[A-Za-z]{2,24}$"
)



def _hr_int(value, default: int = 0) -> int:
    try:
        return int(value if value is not None else default)
    except (TypeError, ValueError):
        return default



def _hr_redacted(value) -> bool:
    text = str(value or "").strip()
    return (not text) or ("*****" in text)



def classify_infostealer_query(query: str) -> tuple[str, str]:
    """Return (kind, normalized) where kind is 'domain' or 'email', else ('', '')."""
    raw = str(query or "").strip()
    if not raw or len(raw) > 200:
        return "", ""
    if "@" in raw:
        email = raw.lower()
        if _HR_EMAIL_RE.match(email):
            return "email", email
        return "", ""
    host = re.sub(r"^https?://", "", raw, flags=re.I)
    host = host.split("/")[0].split("?")[0].split("#")[0]
    host = host.split(":")[0].strip().strip(".").lower()
    if host.startswith("www."):
        host = host[4:]
    if _HR_DOMAIN_RE.match(host):
        return "domain", host
    return "", ""



_HR_SKIP_KEYS = {
    "total", "totalpass", "found", "not_found", "free", "list",
}



def _hr_qty(value):
    if isinstance(value, dict):
        if "qty" in value:
            return value.get("qty")
        if "count" in value:
            return value.get("count")
        if "_value" in value:
            return value.get("_value")
    return value



def _hr_kv_counts(raw, cap: int = _HR_FAMILY_CAP) -> dict:
    items: list[tuple[str, object]] = []
    if isinstance(raw, dict) and isinstance(raw.get("list"), list) and not any(
        k for k in raw.keys() if str(k).lower() not in _HR_SKIP_KEYS | {"list"}
    ):
        raw = raw.get("list")
    if isinstance(raw, dict):
        for key, val in raw.items():
            if str(key).lower() in _HR_SKIP_KEYS:
                continue
            items.append((str(key), _hr_qty(val)))
    elif isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, str) and entry.strip():
                items.append((entry.strip(), 1))
            elif isinstance(entry, dict):
                key = (
                    entry.get("_key")
                    or entry.get("name")
                    or entry.get("label")
                    or entry.get("keyword")
                    or entry.get("domain")
                    or ""
                )
                if "_value" in entry:
                    val = entry.get("_value")
                elif "count" in entry:
                    val = entry.get("count")
                elif "occurrence" in entry:
                    val = entry.get("occurrence")
                elif "qty" in entry:
                    val = entry.get("qty")
                else:
                    val = 1
                if key:
                    items.append((str(key), val))
    out: dict[str, int] = {}
    for key, val in items:
        if _hr_redacted(key) or str(key).lower() in _HR_SKIP_KEYS:
            continue
        out[str(key)] = _hr_int(val, 0)
    ranked = sorted(out.items(), key=lambda kv: kv[1], reverse=True)
    return dict(ranked[:cap])



def _hr_url_rows(entries, cap: int = _HR_URL_CAP) -> list:
    rows = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        url_val = str(entry.get("url") or "")
        if _hr_redacted(url_val):
            continue
        rows.append({
            "url": url_val,
            "type": str(entry.get("type") or ""),
            "occurrence": _hr_int(entry.get("occurrence"), 0),
        })
        if len(rows) >= cap:
            break
    return rows



def _hr_third_parties(raw, cap: int = _HR_LIST_CAP) -> list:
    rows = []
    if isinstance(raw, dict):
        raw = [{"_key": k, "_value": v} for k, v in raw.items()]
    for entry in raw or []:
        if isinstance(entry, str):
            domain = entry.strip()
            count = 0
        elif isinstance(entry, dict):
            domain = str(entry.get("domain") or entry.get("_key") or entry.get("name") or "").strip()
            if "occurrence" in entry:
                count = _hr_int(entry.get("occurrence"), 0)
            elif "count" in entry:
                count = _hr_int(entry.get("count"), 0)
            else:
                count = _hr_int(entry.get("_value"), 0)
        else:
            continue
        if _hr_redacted(domain):
            continue
        rows.append({"domain": domain, "count": count})
        if len(rows) >= cap:
            break
    return rows



def parse_hudsonrock_domain(data: dict, domain: str = "") -> dict:
    """Normalize Cavalier search-by-domain JSON (public OSINT, already redacted)."""
    if not isinstance(data, dict):
        return {"error": "hudsonrock unavailable"}
    inner = data.get("data") if isinstance(data.get("data"), dict) else {}
    employees = _hr_int(data.get("employees"))
    users = _hr_int(data.get("users"))
    third_parties = _hr_int(data.get("third_parties"))
    total = _hr_int(data.get("total"))
    stealers = _hr_int(data.get("totalStealers") if data.get("totalStealers") is not None else data.get("total_stealers"))
    families_raw = data.get("stealerFamilies")
    if not families_raw:
        families_raw = inner.get("stealer_families") or data.get("stealer_families")
    families = _hr_kv_counts(families_raw, _HR_FAMILY_CAP)
    employees_urls = _hr_url_rows(inner.get("employees_urls") or data.get("employees_urls"))
    clients_urls = _hr_url_rows(inner.get("clients_urls") or data.get("clients_urls"))
    apps = _hr_kv_counts(data.get("applications") or inner.get("applications"), _HR_LIST_CAP)
    av_raw = data.get("antiviruses") if data.get("antiviruses") is not None else inner.get("antiviruses")
    if isinstance(av_raw, dict) and isinstance(av_raw.get("list"), list):
        av = _hr_kv_counts(av_raw.get("list"), _HR_LIST_CAP)
    else:
        av = _hr_kv_counts(av_raw, _HR_LIST_CAP)
    severity = "info"
    if employees >= 10:
        severity = "critical"
    elif employees >= 1:
        severity = "high"
    elif users >= 1 or third_parties >= 1 or total >= 1:
        severity = "medium"
    family_names = ", ".join(list(families.keys())[:5])
    if employees:
        summary = f"{employees} employees compromised via infostealers ({family_names})" if family_names else f"{employees} employees compromised via infostealers"
    elif users:
        summary = f"{users} user compromises via infostealers"
    else:
        summary = "No employee compromises found"
    logo = data.get("logo") or ""
    if _hr_redacted(logo):
        logo = ""
    return {
        "source": "hudsonrock_cavalier",
        "kind": "domain",
        "query": domain,
        "total": total,
        "employees": employees,
        "users": users,
        "third_parties": third_parties,
        "total_stealers_global": stealers,
        "total_urls": _hr_int(data.get("totalUrls") if data.get("totalUrls") is not None else data.get("total_urls")),
        "stealer_families": families,
        "internal_urls": employees_urls,
        "employees_urls": employees_urls,
        "clients_urls": clients_urls,
        "last_employee_compromised": str(data.get("last_employee_compromised") or ""),
        "last_user_compromised": str(data.get("last_user_compromised") or ""),
        "employee_passwords": _hr_kv_counts(data.get("employeePasswords") or data.get("employee_passwords"), 12),
        "user_passwords": _hr_kv_counts(data.get("userPasswords") or data.get("user_passwords"), 12),
        "third_party_domains": _hr_third_parties(data.get("thirdPartyDomains") or data.get("third_party_domains")),
        "applications": apps,
        "antiviruses": av,
        "logo": str(logo),
        "severity": severity,
        "summary": summary,
    }



def parse_hudsonrock_email(data: dict, email: str = "") -> dict:
    """Normalize Cavalier search-by-email JSON. Skip malware_path; keep already-redacted logins."""
    if not isinstance(data, dict):
        return {"error": "hudsonrock unavailable"}
    stealers = []
    for entry in data.get("stealers") or []:
        if not isinstance(entry, dict):
            continue
        stealers.append({
            "date_compromised": str(entry.get("date_compromised") or ""),
            "computer_name": str(entry.get("computer_name") or ""),
            "operating_system": str(entry.get("operating_system") or ""),
            "ip": str(entry.get("ip") or ""),
            "antiviruses": entry.get("antiviruses") if isinstance(entry.get("antiviruses"), (list, dict, str)) else [],
            "top_logins": entry.get("top_logins") if isinstance(entry.get("top_logins"), list) else [],
            "top_passwords": entry.get("top_passwords") if isinstance(entry.get("top_passwords"), list) else [],
            "total_corporate_services": _hr_int(entry.get("total_corporate_services")),
            "total_user_services": _hr_int(entry.get("total_user_services")),
        })
        if len(stealers) >= _HR_EMAIL_CAP:
            break
    message = str(data.get("message") or "")
    corp = _hr_int(data.get("total_corporate_services"))
    user_svc = _hr_int(data.get("total_user_services"))
    severity = "high" if stealers else "info"
    return {
        "source": "hudsonrock_cavalier",
        "kind": "email",
        "query": email,
        "message": message,
        "total_corporate_services": corp,
        "total_user_services": user_svc,
        "stealers": stealers,
        "stealer_count": len(stealers),
        "severity": severity,
        "summary": message or f"{len(stealers)} infostealer records",
    }



def _check_hudsonrock(domain: str) -> dict:
    """Query HudsonRock Cavalier API for infostealer credential leaks (free, no auth)."""
    kind, value = classify_infostealer_query(domain)
    if kind != "domain":
        return {"error": "hudsonrock unavailable"}
    from urllib.parse import quote
    url = (
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
        f"?domain={quote(value, safe='')}"
    )
    data = _http_get_json(url, timeout=35)
    if not isinstance(data, dict):
        return {"error": "hudsonrock unavailable"}
    return parse_hudsonrock_domain(data, value)



def _check_hudsonrock_email(email: str) -> dict:
    kind, value = classify_infostealer_query(email)
    if kind != "email":
        return {"error": "hudsonrock unavailable"}
    from urllib.parse import quote
    url = (
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
        f"?email={quote(value, safe='')}"
    )
    data = _http_get_json(url, timeout=35)
    if not isinstance(data, dict):
        return {"error": "hudsonrock unavailable"}
    return parse_hudsonrock_email(data, value)



def lookup_infostealer(query: str) -> dict:
    """Live Cavalier lookup for a domain or email. Does not dump unredacted secrets."""
    kind, value = classify_infostealer_query(query)
    if not kind:
        return {"error": "invalid query", "query": str(query or "")}
    if kind == "email":
        return _check_hudsonrock_email(value)
    return _check_hudsonrock(value)



def run_breach_check(domain: str, hibp_key: str = None,
                     dehashed_key: str = None) -> dict:
    """Aggregate breach / credential leak intelligence."""
    leakix   = _check_leakix(domain)
    hudsonrock = _check_hudsonrock(domain)
    hibp     = _check_hibp_domain(domain, hibp_key)
    dehashed = _check_dehashed(domain, dehashed_key)
    trufflehog_results = _check_trufflehog_github(domain)

    all_findings = leakix + trufflehog_results
    total = len(all_findings) + hibp.get("count",0) + len(dehashed.get("results",[]))

    return {
        "domain":       domain,
        "leakix":       leakix,
        "hudsonrock":   hudsonrock,
        "hibp":         hibp,
        "dehashed":     dehashed,
        "trufflehog":   trufflehog_results,
        "total_findings": total,
        "severity":     "critical" if hudsonrock.get("employees",0) >= 10 or total > 10 else "high" if total > 0 else "info",
        "scanned_at":   datetime.now().isoformat(timespec="seconds"),
    }
