"""Cloud Asset Discovery — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import re
from core.reconlib.base import _log, subprocess

# ── Cloud Asset Discovery ──

def _org_name_variants(org_name: str, domains: list) -> list[str]:
    """Generate bucket name candidates from org name and domains."""
    names = set()
    # From org name
    clean = re.sub(r"[^a-z0-9]+", "-", org_name.lower()).strip("-")
    nospace = clean.replace("-","")
    names.update([clean, nospace])

    # From domains (use all of them for broader brand coverage)
    for d in domains:
        base = d.split(".")[0]
        names.add(base)
        names.update([f"{base}-prod", f"{base}-staging", f"{base}-dev",
                      f"{base}-backup", f"{base}-assets", f"{base}-static",
                      f"{base}-media", f"{base}-data", f"{base}-files",
                      f"{base}-logs", f"{base}-archive", f"{base}-uploads",
                      f"{base}-images", f"{base}-documents", f"{base}-reports",
                      f"{base}-api", f"{base}-infra", f"{base}-internal",
                      f"{base}-private", f"{base}-public", f"{base}-shared"])

    # Common suffix patterns applied to all base names
    extras = set()
    for n in list(names):
        for sfx in ["-prod", "-stg", "-dev", "-test", "-staging", "-backup",
                    "-assets", "-public", "-private", "-data", "-logs", ""]:
            extras.add(f"{n}{sfx}")
    names.update(extras)

    # Prioritize: shorter/simpler names first (more likely to be real buckets)
    return sorted(names, key=lambda x: (len(x), x))[:80]



def _curl_check(url: str) -> tuple[int, str]:
    """HTTP GET via curl, returning (status_code, response_body) — body capped at ~4KB by curl's
    own read; safe for read-only enumeration (no writes/uploads are ever performed)."""
    try:
        r = subprocess.run(
            ["curl", "-s", "-L", "--connect-timeout", "3", "-m", "5",
             "-w", "\n__HTTP_CODE__%{http_code}", "--insecure", url],
            capture_output=True, text=True, timeout=8,
        )
        out = r.stdout or ""
        marker = "\n__HTTP_CODE__"
        idx = out.rfind(marker)
        if idx == -1:
            return 0, ""
        body = out[:idx]
        code_str = out[idx + len(marker):].strip()
        code = int(code_str) if code_str.isdigit() else 0
        return code, body
    except Exception:
        return 0, ""



# Anonymous-readable ACL grants that indicate over-permissive bucket policies.
# These checks are read-only (HTTP GET on the bucket's `?acl` sub-resource) —
# no objects are ever written, modified, or deleted.
_PUBLIC_GRANTEES = re.compile(
    r'(AllUsers|AuthenticatedUsers|http://acs\.amazonaws\.com/groups/global/AllUsers|'
    r'http://acs\.amazonaws\.com/groups/global/AuthenticatedUsers)', re.I)

_WRITE_PERMS = re.compile(r'<Permission>\s*(WRITE|WRITE_ACP|FULL_CONTROL)\s*</Permission>', re.I)



def _check_anonymous_acl(acl_url: str) -> dict | None:
    """Read-only probe of a bucket's ACL sub-resource for public write grants.

    Returns details about overly-permissive ACL entries (e.g. AllUsers: WRITE)
    without performing any write operation. Returns None if the ACL is not
    readable anonymously or contains no public grants.
    """
    status, body = _curl_check(acl_url)
    if status != 200 or not body:
        return None
    grants = re.findall(r'<Grant>.*?</Grant>', body, re.S | re.I)
    public_write = []
    public_read = []
    for grant in grants:
        if not _PUBLIC_GRANTEES.search(grant):
            continue
        perms = re.findall(r'<Permission>\s*([A-Z_]+)\s*</Permission>', grant, re.I)
        for perm in perms:
            p = perm.upper()
            if p in ("WRITE", "WRITE_ACP", "FULL_CONTROL"):
                public_write.append(p)
            elif p in ("READ", "READ_ACP"):
                public_read.append(p)
    if not public_write and not public_read:
        return None
    return {"public_write_perms": sorted(set(public_write)), "public_read_perms": sorted(set(public_read))}



def _check_s3_bucket(name: str) -> dict | None:
    """Check if an S3 bucket exists and its access level."""
    urls = [f"https://{name}.s3.amazonaws.com/", f"https://s3.amazonaws.com/{name}/"]
    for url in urls:
        status, raw = _curl_check(url)
        if status == 200:
            snippet = raw[:5000] if raw else ""
            # Parse XML listing for file count, sample objects and sensitive names
            obj_count = snippet.count("<Key>")
            sample_objects = re.findall(r'<Key>([^<]+)</Key>', snippet)[:15]
            _SENS = re.compile(r'<Key>([^<]*(?:\.env|\.sql|backup|\.pem|\.key|secret|password|credential|config|dump|\.bak|\.log)[^<]*)</Key>', re.I)
            sensitive_files = _SENS.findall(snippet)
            access_detail = "public_read"
            if sensitive_files:
                access_detail = "public_read_sensitive"

            # Read-only ACL probe — checks for AllUsers/AuthenticatedUsers
            # WRITE/FULL_CONTROL grants without writing anything.
            acl = _check_anonymous_acl(url + "?acl")
            if acl and acl.get("public_write_perms"):
                access_detail = "public_write_acl"

            desc = (f"S3 bucket {name} is publicly readable ({obj_count} objects listed" +
                    (f", including {len(sensitive_files)} sensitive files: {', '.join(sensitive_files[:3])}" if sensitive_files else "") + ")")
            if acl and acl.get("public_write_perms"):
                desc += f". ACL grants anonymous {'/'.join(acl['public_write_perms'])} access — bucket can likely be written to or have its ACL modified by anyone."

            return {"name": name, "provider": "AWS S3", "url": url,
                    "access": access_detail, "severity": "critical",
                    "snippet": snippet[:500],
                    "object_count": obj_count,
                    "sample_objects": sample_objects,
                    "sensitive_files": sensitive_files[:10],
                    "acl": acl,
                    "desc": desc}
        if status == 403:
            # Bucket exists but listing is denied — still probe the ACL read-only,
            # since some buckets block listing but expose a writable ACL.
            acl = _check_anonymous_acl(urls[0] + "?acl")
            if acl and acl.get("public_write_perms"):
                return {"name": name, "provider": "AWS S3", "url": urls[0],
                        "access": "public_write_acl", "severity": "critical",
                        "snippet": "", "object_count": 0, "sample_objects": [],
                        "sensitive_files": [], "acl": acl,
                        "desc": f"S3 bucket {name} blocks listing but its ACL grants anonymous "
                                f"{'/'.join(acl['public_write_perms'])} access — bucket can likely be "
                                f"written to or have its ACL modified by anyone."}
            return {"name": name, "provider": "AWS S3", "url": urls[0],
                    "access": "exists_private", "severity": "info", "snippet": ""}
        if status in (301, 302):
            return {"name": name, "provider": "AWS S3", "url": urls[0],
                    "access": "exists_redirect", "severity": "low", "snippet": ""}
    return None



def _check_azure_blob(name: str) -> dict | None:
    """Check Azure Blob storage containers."""
    clean = re.sub(r"[^a-z0-9]", "", name.lower())[:24]
    if len(clean) < 3:
        return None
    url = f"https://{clean}.blob.core.windows.net/?comp=list"
    status, raw = _curl_check(url)
    if status == 200:
        snippet = raw[:3000] if raw else ""
        obj_count = snippet.count("<Name>")
        sample_objects = re.findall(r'<Name>([^<]+)</Name>', snippet)[:15]
        _SENS_AZ = re.compile(r'<Name>([^<]*(?:\.env|\.sql|backup|\.pem|\.key|secret|password|credential|config|dump|\.bak|\.log)[^<]*)</Name>', re.I)
        sensitive_files = _SENS_AZ.findall(snippet)
        access_detail = "public_list"
        if sensitive_files:
            access_detail = "public_list_sensitive"
        return {"name": clean, "provider": "Azure Blob", "url": url,
                "access": access_detail, "severity": "critical",
                "snippet": snippet[:500],
                "object_count": obj_count,
                "sample_objects": sample_objects,
                "sensitive_files": sensitive_files[:10],
                "desc": f"Azure Blob container {clean} is publicly listed ({obj_count} objects)" +
                        (f", including {len(sensitive_files)} sensitive files: {', '.join(sensitive_files[:3])}" if sensitive_files else "")}
    if status == 403:
        return {"name": clean, "provider": "Azure Blob", "url": url,
                "access": "exists_private", "severity": "info", "snippet": ""}
    return None



def _check_gcp_bucket(name: str) -> dict | None:
    """Check GCP Cloud Storage buckets."""
    url = f"https://storage.googleapis.com/{name}/"
    status, raw = _curl_check(url)
    if status == 200:
        snippet = raw[:3000] if raw else ""
        obj_count = snippet.count("<Key>") + snippet.count("<Name>")
        sample_objects = re.findall(r'<(?:Key|Name)>([^<]+)</(?:Key|Name)>', snippet)[:15]
        _SENS_GCP = re.compile(r'<(?:Key|Name)>([^<]*(?:\.env|\.sql|backup|\.pem|\.key|secret|password|credential|config|dump|\.bak|\.log)[^<]*)</(?:Key|Name)>', re.I)
        sensitive_files = _SENS_GCP.findall(snippet)
        access_detail = "public_read"
        if sensitive_files:
            access_detail = "public_read_sensitive"

        acl = _check_anonymous_acl(url + "?acl")
        if acl and acl.get("public_write_perms"):
            access_detail = "public_write_acl"

        desc = (f"GCP bucket {name} is publicly readable ({obj_count} objects listed)" +
                (f", including {len(sensitive_files)} sensitive files: {', '.join(sensitive_files[:3])}" if sensitive_files else ""))
        if acl and acl.get("public_write_perms"):
            desc += f". ACL grants anonymous {'/'.join(acl['public_write_perms'])} access — bucket can likely be written to or have its ACL modified by anyone."

        return {"name": name, "provider": "GCP Storage", "url": url,
                "access": access_detail, "severity": "critical",
                "snippet": snippet[:500],
                "object_count": obj_count,
                "sample_objects": sample_objects,
                "sensitive_files": sensitive_files[:10],
                "acl": acl,
                "desc": desc}
    if status == 403:
        acl = _check_anonymous_acl(url + "?acl")
        if acl and acl.get("public_write_perms"):
            return {"name": name, "provider": "GCP Storage", "url": url,
                    "access": "public_write_acl", "severity": "critical",
                    "snippet": "", "object_count": 0, "sample_objects": [],
                    "sensitive_files": [], "acl": acl,
                    "desc": f"GCP bucket {name} blocks listing but its ACL grants anonymous "
                            f"{'/'.join(acl['public_write_perms'])} access — bucket can likely be "
                            f"written to or have its ACL modified by anyone."}
        return {"name": name, "provider": "GCP Storage", "url": url,
                "access": "exists_private", "severity": "info", "snippet": ""}
    return None



def _cloud_reachable() -> bool:
    """Quick HTTP check via curl (respects connect timeout, avoids glibc DNS hangs)."""
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--connect-timeout", "3", "-m", "5",
             "https://s3.amazonaws.com/"],
            capture_output=True, text=True, timeout=8,
        )
        return r.stdout.strip() in ("200", "301", "302", "403", "404")
    except Exception:
        return False



def run_cloud_assets(domains: list, org_name: str = "") -> dict:
    """Discover cloud storage buckets for an organization."""
    if not _cloud_reachable():
        return {
            "checked": 0, "findings": [], "public_count": 0, "private_count": 0,
            "error": "Cloud providers unreachable (network/firewall)",
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
        }
    names = _org_name_variants(org_name or domains[0].split(".")[0], domains)
    findings = []
    MODULE_TIMEOUT = 45  # seconds hard cap

    def check_all(name):
        results = []
        r = _check_s3_bucket(name)
        if r: results.append(r)
        r = _check_azure_blob(name)
        if r: results.append(r)
        r = _check_gcp_bucket(name)
        if r: results.append(r)
        return results

    pool = ThreadPoolExecutor(max_workers=20)
    futures = {pool.submit(check_all, n): n for n in names}
    done, _ = __import__("concurrent.futures", fromlist=["wait"]).wait(
        futures, timeout=MODULE_TIMEOUT
    )
    pool.shutdown(wait=False, cancel_futures=True)
    for fut in done:
        try:
            findings.extend(fut.result())
        except Exception:
            _log.debug('recon.py:2855 erro ignorado', exc_info=True)

    public  = [f for f in findings if "public" in f.get("access","")]
    private = [f for f in findings if "private" in f.get("access","")]

    return {
        "checked":       len(names) * 3,
        "findings":      sorted(findings, key=lambda f: ["critical","info","low"].index(f.get("severity","low"))),
        "public_count":  len(public),
        "private_count": len(private),
        "scanned_at":    datetime.now().isoformat(timespec="seconds"),
    }
