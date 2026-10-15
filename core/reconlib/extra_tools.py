"""NEW MODULES: gitleaks, jwt_tool, S3Scanner, XSS — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
from pathlib import Path
import json
import re
import shutil
import tempfile
from core.reconlib.base import run_bounded, _log, http_get, subprocess

# ── NEW MODULES: gitleaks, jwt_tool, S3Scanner, XSS ────────────────────────────

_GIT_HEAD_RE = re.compile(rb"^(ref: refs/[\w./-]+|[0-9a-f]{40})\s*$")


def _looks_like_git_head(body) -> bool:
    """Conteúdo real de .git/HEAD; página de SPA/soft-200 não conta (regra: sem evidência não é achado)."""
    return bool(_GIT_HEAD_RE.match((body or b"")[:200].strip()))


def run_git_leaks(hosts: list, domains: list, github_token: str = None) -> dict:
    """Scan exposed .git directories and git history for secrets using gitleaks.

    Antes: testava `"ref:" in body` com body em bytes → TypeError engolido em todo host, então nunca
    detectava nada; e varria até 50 hosts × 2 esquemas em série (estourava os 180s do módulo).
    """
    import tempfile
    findings = []
    scanned = []
    exposed = []
    gitleaks_bin = shutil.which("gitleaks")

    def _scan_host(h):
        host = h.get("host", "")
        if not host:
            return
        for scheme in ("https", "http"):
            status, body, _ = http_get(f"{scheme}://{host}/.git/HEAD", timeout=5, retries=1)
            if not status:
                continue                       # sem resposta nesse esquema: tenta o outro
            if status == 200 and _looks_like_git_head(body):
                exposed.append(f"{scheme}://{host}/.git/")
                with tempfile.TemporaryDirectory() as tmp:
                    result = subprocess.run(["git", "clone", "--depth", "1", f"{scheme}://{host}/.git", tmp],
                                            capture_output=True, text=True, timeout=60)
                    if result.returncode == 0 and gitleaks_bin:
                        scan = subprocess.run([gitleaks_bin, "detect", "--source", tmp, "-f", "json", "--no-git"],
                                              capture_output=True, text=True, timeout=60)
                        try:
                            leaks = json.loads(scan.stdout) if scan.stdout.strip() else []
                        except json.JSONDecodeError:
                            leaks = []
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
                scanned.append(host)
            return                              # respondeu: não precisa do outro esquema

    complete = run_bounded(_scan_host, hosts[:50], workers=8, label="git_leaks")
    findings = list(findings)
    return {
        "findings": findings,
        "total": len(findings),
        "exposed_git": list(exposed),
        "hosts_scanned": len(scanned),
        "complete": complete,
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
