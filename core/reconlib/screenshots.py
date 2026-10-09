"""Screenshots — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
from pathlib import Path
from core.reconlib.base import _subp

# ── Screenshots ──

def _gowitness_v3_to_url(stem: str) -> str:
    """Reconstruct a URL from a gowitness v3 JPEG filename stem.
    v3 format: scheme---hostname-port  e.g. https---hackersec.com-443
    """
    for scheme in ("https", "http"):
        prefix = scheme + "---"
        if stem.startswith(prefix):
            rest = stem[len(prefix):]          # e.g. "hackersec.com-443"
            parts = rest.rsplit("-", 1)
            if len(parts) == 2 and parts[1].isdigit():
                host, port = parts[0], parts[1]
                if (scheme == "https" and port == "443") or (scheme == "http" and port == "80"):
                    return f"{scheme}://{host}"
                return f"{scheme}://{host}:{port}"
            return f"{scheme}://{rest}"
    return stem



def run_screenshots(hosts: list, domains: list, output_dir: str = "") -> dict:
    """
    Capture screenshots of all live web assets using gowitness.
    Falls back to httpx title/status if gowitness not available.
    """
    import shutil

    gowitness_bin = shutil.which("gowitness")
    httpx_bin     = shutil.which("httpx")

    # Build URL list
    targets = []
    for h in hosts:
        host  = h.get("host","")
        ports = h.get("ports",[])
        for p in ports:
            pn = int(p["port"] if isinstance(p,dict) else p)
            if pn in (443,8443):
                targets.append(f"https://{host}:{pn}" if pn != 443 else f"https://{host}")
            elif pn in (80,8080,8000,8001,8888):
                targets.append(f"http://{host}:{pn}" if pn not in (80,) else f"http://{host}")
    if not targets:
        for d in domains[:10]:
            targets.append(f"https://{d}")
            targets.append(f"http://{d}")

    # Deduplicate
    targets = list(dict.fromkeys(targets))[:80]

    out_dir = output_dir or str(Path.home() / ".asm" / "screenshots")
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    screenshots = []
    errors      = []

    if gowitness_bin:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(targets))
            tf_path = tf.name
        try:
            # gowitness v3 syntax: scan file -f <file> --screenshot-path <dir>
            result = _subp(
                [gowitness_bin, "scan", "file", "-f", tf_path,
                 "--screenshot-path", out_dir,
                 "-t", "10", "-T", "15", "-q"],
                capture_output=True, text=True, timeout=300,
            )
            # v3 saves .jpeg files named: scheme---host-port.jpeg
            for f in sorted(Path(out_dir).glob("*.jpeg"), key=lambda x: x.stat().st_mtime, reverse=True):
                screenshots.append({
                    "url":  _gowitness_v3_to_url(f.stem),
                    "file": str(f),
                    "size": f.stat().st_size,
                })
        except Exception as e:
            errors.append(str(e))
        finally:
            Path(tf_path).unlink(missing_ok=True)
    else:
        # Fallback: httpx with title + screenshot path info
        if httpx_bin:
            try:
                result = _subp(
                    [httpx_bin, "-silent", "-title", "-status-code",
                     "-tech-detect", "-screenshot", "-srd", out_dir,
                     "-timeout", "8", "-threads", "20"],
                    input="\n".join(targets),
                    capture_output=True, text=True, timeout=180,
                )
                for line in result.stdout.splitlines():
                    if line.strip():
                        screenshots.append({"url": line.strip(), "file": "", "size": 0})
            except Exception as e:
                errors.append(str(e))

    return {
        "total":         len(screenshots),
        "targets_tried": len(targets),
        "output_dir":    out_dir,
        "screenshots":   screenshots[:100],
        "errors":        errors[:10],
        "scanned_at":    datetime.now().isoformat(timespec="seconds"),
    }
