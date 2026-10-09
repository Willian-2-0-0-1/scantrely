"""NEW MODULES: gitleaks, jwt_tool, S3Scanner, XSS — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
from pathlib import Path
import json
import re
import shutil
import tempfile
from core.reconlib.base import _log, http_get, subprocess

# ── NEW MODULES: gitleaks, jwt_tool, S3Scanner, XSS ────────────────────────────

def run_git_leaks(hosts: list, domains: list, github_token: str = None) -> dict:
    """Scan exposed .git directories and git history for secrets using gitleaks."""
    findings = []
    scanned = 0
    gitleaks_bin = shutil.which("gitleaks")

    for h in hosts[:50]:  # cap at 50 hosts
        host = h.get("host", "")
        if not host:
            continue
        for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{host}/.git/HEAD"
                status, body, _ = http_get(url, timeout=5, retries=1)
                if status == 200 and "ref:" in (body or ""):
                    # Clone and scan
                    import tempfile
                    with tempfile.TemporaryDirectory() as tmp:
                        clone_url = f"{scheme}://{host}/.git"
                        result = subprocess.run(
                            ["git", "clone", "--depth", "1", clone_url, tmp],
                            capture_output=True, text=True, timeout=60
                        )
                        if result.returncode == 0 and gitleaks_bin:
                            scan = subprocess.run(
                                [gitleaks_bin, "detect", "--source", tmp, "-f", "json", "--no-git"],
                                capture_output=True, text=True, timeout=60
                            )
                            if scan.stdout.strip():
                                try:
                                    leaks = json.loads(scan.stdout)
                                    for leak in (leaks if isinstance(leaks, list) else []):
                                        findings.append({
                                            "type": "git_leak",
                                            "severity": "high",
                                            "title": f"Git secret exposed: {leak.get('Description','')}",
                                            "host": host,
                                            "value": leak.get("Secret", ""),
                                            "file": leak.get("File", ""),
                                            "module": "git_leaks",
                                        })
                                except json.JSONDecodeError:
                                    pass
                            scanned += 1
                    break  # one scheme per host
            except Exception:
                continue

    return {
        "findings": findings,
        "total": len(findings),
        "hosts_scanned": scanned,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



def run_s3_scanner(domains: list, company_name: str = "") -> dict:
    """Check for open S3 buckets using common naming patterns."""
    findings = []
    scanned = 0
    s3_bin = shutil.which("S3Scanner") or shutil.which("s3scanner")
    names = set()
    for d in domains:
        base = d.split(".")[0]
        names.update([base, f"{base}-prod", f"{base}-dev", f"{base}-staging", f"{base}-static",
                       f"{base}-assets", f"{base}-media", f"{base}-backup", f"{base}-logs"])
    if company_name:
        slug = re.sub(r"[^a-z0-9]", "", company_name.lower())[:20]
        names.update([slug, f"{slug}-prod", f"{slug}-dev"])

    if s3_bin:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(names))
            tf_path = tf.name
        try:
            result = subprocess.run(
                [s3_bin, "-b", "-f", tf_path] if "S3Scanner" in str(s3_bin) else [s3_bin] + list(names),
                capture_output=True, text=True, timeout=120
            )
            for line in result.stdout.strip().splitlines():
                if "OPEN" in line.upper() or "200" in line:
                    parts = line.strip().split()
                    bucket = parts[0] if parts else line.strip()
                    findings.append({
                        "type": "open_s3_bucket",
                        "severity": "high",
                        "title": f"Open S3 bucket: {bucket}",
                        "value": bucket,
                        "module": "s3_scanner",
                        "category": "cloud",
                    })
                scanned += 1
        except Exception:
            _log.debug('recon.py:10470 erro ignorado', exc_info=True)
        finally:
            Path(tf_path).unlink(missing_ok=True)
    else:
        # Fallback: HTTP checks
        for name in list(names)[:20]:
            try:
                url = f"http://{name}.s3.amazonaws.com"
                status, _, _ = http_get(url, timeout=5, retries=1)
                if status == 200:
                    findings.append({
                        "type": "open_s3_bucket",
                        "severity": "high",
                        "title": f"Open S3 bucket: {name}",
                        "value": name,
                        "module": "s3_scanner",
                    })
                scanned += 1
            except Exception:
                _log.debug('recon.py:10489 erro ignorado', exc_info=True)

    return {
        "findings": findings,
        "total": len(findings),
        "hosts_scanned": scanned,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }
