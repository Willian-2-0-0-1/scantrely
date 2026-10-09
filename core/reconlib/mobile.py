"""Mobile App Recon — Google Play discovery + apkleaks (Bug Bounty/ASM) — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
import os
import re
from core.reconlib.base import _log, _subp, http_get

# ── Mobile App Recon — Google Play discovery + apkleaks (Bug Bounty/ASM) ──

def _discover_play_packages(brand: str, limit: int = 15) -> list:
    """Scrape Google Play search for Android package IDs matching the brand."""
    if not brand:
        return []
    import urllib.parse as _up
    pkgs = {}
    try:
        s, b, _ = http_get(
            f"https://play.google.com/store/search?q={_up.quote(brand)}&c=apps&hl=en&gl=US",
            timeout=15, retries=2)
        if s == 200 and b:
            html = b.decode("utf-8", "ignore")
            for m in re.finditer(r"/store/apps/details\?id=([a-zA-Z][a-zA-Z0-9_.]+)", html):
                pkg = m.group(1)
                if pkg not in pkgs:
                    pkgs[pkg] = {"package": pkg,
                                 "url": f"https://play.google.com/store/apps/details?id={pkg}"}
                if len(pkgs) >= limit:
                    break
    except Exception:
        _log.debug('recon.py:3713 erro ignorado', exc_info=True)
    return list(pkgs.values())


def _parse_apkleaks_output(text: str) -> dict:
    """Parse apkleaks text output into {links:[...], secrets:[{type,value}]}."""
    links, secrets = set(), []
    current = None
    for line in text.splitlines():
        s = line.strip()
        hm = re.match(r"^\[(.+?)\]$", s)
        if hm:
            current = hm.group(1)
            continue
        if not s or current is None:
            continue
        val = s.lstrip("- ").strip()
        if not val:
            continue
        if "http" in val or current.upper() in ("LINK", "LINKS", "URI", "URL"):
            links.add(val)
        else:
            secrets.append({"type": current, "value": val[:200]})
    return {"links": sorted(links), "secrets": secrets}


def run_apk_recon(domains, company_name: str = "", apk_dir: str = "") -> dict:
    """
    Mobile attack-surface recon:
      1. Discover the org's Android packages via Google Play search (passive).
      2. If APK files exist (analyst-provided in apk_dir) and apkleaks is installed,
         extract URIs/endpoints/secrets and any *.<domain> hostnames from them.

    Degrades gracefully when apkleaks/jadx or APK files are unavailable. Extracted
    in-scope subdomains are merged into the host pool by the pipeline harvester.
    """
    if isinstance(domains, str):
        domains = [domains]
    domains = [str(d).lower().strip().strip(".") for d in domains if d]
    now = datetime.now().isoformat(timespec="seconds")
    import shutil, tempfile

    brand    = (company_name or (domains[0].split(".")[0] if domains else "")).strip()
    packages = _discover_play_packages(brand)

    apk_findings, subdomains, secrets, notes = [], set(), [], []
    apkleaks_bin = shutil.which("apkleaks")
    apk_files = []
    if apk_dir and os.path.isdir(apk_dir):
        apk_files = [os.path.join(apk_dir, f) for f in os.listdir(apk_dir)
                     if f.lower().endswith(".apk")]

    if apk_files and apkleaks_bin:
        host_res = [re.compile(r"([a-z0-9](?:[a-z0-9\-]{0,62}\.)+" + re.escape(d) + r")", re.I)
                    for d in domains]
        for apk in apk_files[:10]:
            out_path = ""
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                    out_path = tf.name
                _subp([apkleaks_bin, "-f", apk, "-o", out_path],
                      capture_output=True, text=True, timeout=600)
                with open(out_path, "r", errors="ignore") as fh:
                    parsed = _parse_apkleaks_output(fh.read())
            except Exception as exc:
                notes.append(f"apkleaks falhou em {os.path.basename(apk)}: {exc}")
                continue
            finally:
                if out_path and os.path.exists(out_path):
                    try: os.unlink(out_path)
                    except Exception:
                        _log.debug('recon.py:3782 erro ignorado', exc_info=True)
            for link in parsed["links"]:
                for rx in host_res:
                    for hm in rx.findall(link):
                        subdomains.add(hm.lower().strip("."))
            for sec in parsed["secrets"]:
                secrets.append({**sec, "apk": os.path.basename(apk)})
            apk_findings.append({"apk": os.path.basename(apk),
                                 "links": len(parsed["links"]),
                                 "secrets": len(parsed["secrets"])})
    else:
        if not apkleaks_bin:
            notes.append("apkleaks não instalado — só discovery de pacotes (rode install_tools.sh)")
        if not apk_files:
            notes.append(f"Nenhum APK em {apk_dir or 'scans/<empresa>/apks'} — "
                         "baixe os APKs dos pacotes listados para extração completa")

    return {
        "domains": domains, "brand": brand,
        "packages": packages, "package_count": len(packages),
        "apk_findings": apk_findings,
        "subdomains": sorted(subdomains),
        "secrets": secrets[:100], "secret_count": len(secrets),
        "notes": notes, "scanned_at": now,
    }
