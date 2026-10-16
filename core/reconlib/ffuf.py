"""Content Discovery via ffuf + Wordlists — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
from core.reconlib.base import _log, _subp, http_get
from core.reconlib.edge import classify, fetch_baseline
from core.verification import has_content_rule, looks_like_sensitive_file

# ── Content Discovery via ffuf + Wordlists ──
# Uses project-bundled wordlists for: directories, files, API routes, parameters.
# Runs ffuf against live hosts with smart rate limiting per mode.

_VERIFY_CAP = 60   # sondagens de confirmação por execução


def _verify_findings(findings: list) -> tuple[list, dict]:
    """Pós-filtro: hosts cuja borda barra até caminho inexistente perdem os achados (a aplicação não foi
    testada); 200 em arquivo sensível só fica se o conteúdo for o esperado."""
    from urllib.parse import urlparse
    info = {"blocked_hosts": [], "dropped": 0}
    bases: dict = {}
    kept, probes = [], 0
    for f in findings:
        u = urlparse(f.get("url") or "")
        if not u.hostname:
            kept.append(f)
            continue
        origin = f"{u.scheme}://{u.netloc}"
        f["host"] = u.hostname
        if origin not in bases:
            bases[origin] = fetch_baseline(origin, 5, get=http_get)
            if bases[origin] is not None and bases[origin].edge_blocked:
                info["blocked_hosts"].append(u.hostname)
        base = bases[origin]
        if base is not None and base.edge_blocked:
            info["dropped"] += 1
            continue
        if f.get("status") == 200 and has_content_rule(u.path) and probes < _VERIFY_CAP:
            probes += 1
            st, body, hdrs = http_get(f["url"], timeout=5, retries=0)
            if st == 200 and not classify(st, hdrs, body).edge and looks_like_sensitive_file(u.path, body):
                f["verified"] = True
            else:
                info["dropped"] += 1
                continue
        kept.append(f)
    return kept, info


def run_content_discovery(hosts: list, mode: str = "balanced") -> dict:
    """
    Discover hidden directories, files, API endpoints, and parameters
    using ffuf against live hosts with project wordlists.

    Modes: stealth (500 req/host), balanced (2k req/host), fast (10k req/host)
    """
    import shutil, tempfile, os

    ffuf_bin = shutil.which("ffuf")
    if not ffuf_bin:
        return {"error": "ffuf not found", "findings": []}

    # ── Load wordlists ──
    try:
        from tools import load_wordlist
    except ImportError:
        return {"error": "wordlist loader unavailable", "findings": []}

    MODE_CAPS  = {"stealth": 500, "balanced": 2000, "fast": 10000}
    MODE_RATE  = {"stealth": 3, "balanced": 8, "fast": 20}
    MODE_WL    = {"stealth": "small", "balanced": "medium", "fast": "large"}
    cap  = MODE_CAPS.get(mode, 2000)
    rate = MODE_RATE.get(mode, 8)
    wl_mode = MODE_WL.get(mode, "medium")

    dirs_wl  = load_wordlist("directories", wl_mode, cap)
    files_wl = load_wordlist("files", wl_mode, min(cap // 2, 3000))
    api_wl   = load_wordlist("api", wl_mode, min(cap, 5000))
    param_wl = load_wordlist("parameters", wl_mode, min(cap, 5000))

    if not any([dirs_wl, files_wl, api_wl, param_wl]):
        return {"error": "No wordlists loaded", "findings": []}

    # ── Build targets from live hosts ──
    targets = []
    for h in hosts:
        host = h.get("host", "")
        if not host:
            continue
        ports = h.get("ports", [])
        has_443 = any((p.get("port") if isinstance(p, dict) else p) == 443 for p in ports)
        has_80  = any((p.get("port") if isinstance(p, dict) else p) == 80 for p in ports)
        if has_443:
            targets.append(f"https://{host}")
        elif has_80:
            targets.append(f"http://{host}")
        elif h.get("status_code") is not None:
            targets.append(f"https://{host}")

    if not targets:
        return {"error": "No live targets", "findings": []}

    findings = []
    stats = {"dirs_scanned": 0, "files_scanned": 0, "api_scanned": 0, "params_scanned": 0,
             "dirs_found": 0, "files_found": 0, "api_found": 0, "params_found": 0}
    wl_files_created = []

    try:
        # ── 1. Directory discovery ──
        if dirs_wl:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
                wf.write("\n".join(dirs_wl))
                dirs_path = wf.name
            wl_files_created.append(dirs_path)
            for target in targets[:10]:  # cap targets to avoid scan explosion
                try:
                    r = _subp(
                        [ffuf_bin, "-u", f"{target}/FUZZ", "-w", dirs_path,
                         "-mc", "200,201,202,203,204,301,302,307,308,401,403,405,500",
                         "-rate", str(rate), "-t", "20", "-ac",
                         "-timeout", "8", "-maxtime", "120", "-noninteractive"],
                        capture_output=True, text=True, timeout=150,
                    )
                    stats["dirs_scanned"] += len(dirs_wl)
                    for line in r.stdout.splitlines():
                        line = line.strip()
                        if line and ("/" in line or "200" in line or "301" in line or "403" in line):
                            try:
                                parts = line.split()
                                if len(parts) >= 3:
                                    status = int(parts[0]) if parts[0].isdigit() else 0
                                    size   = int(parts[1]) if parts[1].isdigit() else 0
                                    url    = parts[2] if len(parts) > 2 else line
                                    if status and url:
                                        findings.append({
                                            "type": "directory", "url": url, "host": host,
                                            "status": status, "size": size, "wordlist": "directories",
                                        })
                                        stats["dirs_found"] += 1
                            except (ValueError, IndexError):
                                pass
                except Exception:
                    _log.debug('recon.py:8820 erro ignorado', exc_info=True)

        # ── 2. File/backup discovery ──
        if files_wl:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
                wf.write("\n".join(files_wl))
                files_path = wf.name
            wl_files_created.append(files_path)
            for target in targets[:8]:
                try:
                    r = _subp(
                        [ffuf_bin, "-u", f"{target}/FUZZ", "-w", files_path,
                         "-mc", "200,301,302,403",
                         "-rate", str(rate), "-t", "20", "-ac",
                         "-timeout", "8", "-maxtime", "90", "-noninteractive"],
                        capture_output=True, text=True, timeout=120,
                    )
                    stats["files_scanned"] += len(files_wl)
                    for line in r.stdout.splitlines():
                        line = line.strip()
                        if line:
                            try:
                                parts = line.split()
                                if len(parts) >= 3:
                                    status = int(parts[0]) if parts[0].isdigit() else 0
                                    url = parts[2] if len(parts) > 2 else line
                                    if status and url:
                                        findings.append({
                                            "type": "file", "url": url, "host": host,
                                            "status": status, "wordlist": "files",
                                        })
                                        stats["files_found"] += 1
                            except (ValueError, IndexError):
                                pass
                except Exception:
                    _log.debug('recon.py:8855 erro ignorado', exc_info=True)

        # ── 3. API route fuzzing ──
        if api_wl:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
                wf.write("\n".join(api_wl))
                api_path = wf.name
            wl_files_created.append(api_path)
            for target in targets[:6]:
                for prefix in ["/api", "/v1", "/v2", "/graphql", ""]:
                    try:
                        r = _subp(
                            [ffuf_bin, "-u", f"{target}{prefix}/FUZZ", "-w", api_path,
                             "-mc", "200,201,301,302,401,403,405",
                             "-rate", str(rate), "-t", "15", "-ac",
                             "-timeout", "8", "-maxtime", "90", "-noninteractive"],
                            capture_output=True, text=True, timeout=120,
                        )
                        stats["api_scanned"] += len(api_wl)
                        for line in r.stdout.splitlines():
                            line = line.strip()
                            if line:
                                try:
                                    parts = line.split()
                                    if len(parts) >= 3:
                                        status = int(parts[0]) if parts[0].isdigit() else 0
                                        url = parts[2] if len(parts) > 2 else line
                                        if status and url:
                                            findings.append({
                                                "type": "api_route", "url": url, "host": host,
                                                "status": status, "wordlist": "api",
                                            })
                                            stats["api_found"] += 1
                                except (ValueError, IndexError):
                                    pass
                    except Exception:
                        _log.debug('recon.py:8891 erro ignorado', exc_info=True)

        # ── 4. Parameter fuzzing ──
        if param_wl:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
                wf.write("\n".join(param_wl))
                param_path = wf.name
            wl_files_created.append(param_path)
            for target in targets[:5]:
                try:
                    r = _subp(
                        [ffuf_bin, "-u", f"{target}?FUZZ=1", "-w", param_path,
                         "-mc", "200,301,302,400,401,403,422,500",
                         "-rate", str(rate), "-t", "15", "-ac",
                         "-timeout", "8", "-maxtime", "90", "-noninteractive"],
                        capture_output=True, text=True, timeout=120,
                    )
                    stats["params_scanned"] += len(param_wl)
                    for line in r.stdout.splitlines():
                        line = line.strip()
                        if line and "FUZZ" not in line:
                            try:
                                parts = line.split()
                                if len(parts) >= 3:
                                    status = int(parts[0]) if parts[0].isdigit() else 0
                                    url = parts[2] if len(parts) > 2 else line
                                    if status and url:
                                        findings.append({
                                            "type": "parameter", "url": url, "host": host,
                                            "status": status, "wordlist": "parameters",
                                        })
                                        stats["params_found"] += 1
                            except (ValueError, IndexError):
                                pass
                except Exception:
                    _log.debug('recon.py:8926 erro ignorado', exc_info=True)

    finally:
        for p in wl_files_created:
            try:
                os.unlink(p)
            except Exception:
                _log.debug('recon.py:8933 erro ignorado', exc_info=True)

    findings, edge_info = _verify_findings(findings)
    stats["edge_blocked_hosts"] = edge_info["blocked_hosts"]
    stats["dropped_unverified"] = edge_info["dropped"]
    return {
        "findings": findings[:500],
        "stats": stats,
        "total_found": len(findings),
        "mode": mode,
        "wordlist_sizes": {
            "directories": len(dirs_wl), "files": len(files_wl),
            "api": len(api_wl), "parameters": len(param_wl),
        },
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }
