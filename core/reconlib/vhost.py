"""Virtual Host Discovery — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
from pathlib import Path
import json
import os
import re
from core.reconlib.base import _log, _subp

# ── Virtual Host Discovery ──

def run_vhost_discovery(hosts: list, domains: list, wordlist: str = "") -> dict:
    """
    Discover virtual hosts on each IP by fuzzing the Host header.
    Uses ffuf (primary) or gobuster vhost (fallback).
    Capped at 5 IPs × 200 wordlist entries × 30s per run to stay fast.
    """
    import shutil, tempfile, urllib.request

    ffuf_bin    = shutil.which("ffuf")
    gobuster_bin = shutil.which("gobuster")

    if not ffuf_bin and not gobuster_bin:
        return {"error": "ffuf or gobuster required", "findings": []}

    # Build wordlist: known subdomains from existing hosts + common prefixes
    common_prefixes = [
        "www","mail","smtp","pop","imap","ftp","sftp","ssh","vpn","remote",
        "admin","portal","app","api","dev","staging","test","uat","qa","prod",
        "beta","demo","cdn","static","assets","media","img","images","files",
        "upload","backup","db","database","mysql","mongo","redis","elastic",
        "kibana","grafana","jenkins","gitlab","jira","confluence","intranet",
        "internal","corp","extranet","owa","autodiscover","webmail","ns1","ns2",
        "mx","mail2","mx1","mx2","smtp2","gateway","proxy","waf","lb","loadbalancer",
        "shop","store","checkout","payment","auth","login","sso","id","accounts",
        "register","signup","blog","status","monitor","logs","reports","dashboard",
        "manage","mgmt","management","old","legacy","new","v2","api2","mobile",
        "m","wap","help","support","docs","doc","wiki","kb","forum","community",
    ]

    # Collect known subdomains from host data
    known_subs = set()
    for h in hosts:
        hostname = h.get("host","")
        if hostname:
            parts = hostname.split(".")
            if len(parts) >= 3:
                known_subs.add(parts[0])

    # Cap total wordlist at 200 entries to keep ffuf fast
    all_prefixes = sorted(set(common_prefixes) | known_subs)[:200]

    # Primary domain for vhost suffix
    primary_domain = domains[0] if domains else ""
    if not primary_domain:
        return {"error": "No domain provided", "findings": []}

    # Get unique IPs to scan (cap at 5 to stay fast)
    ips_to_scan = []
    seen_ips = set()
    for h in hosts:
        ip = h.get("ip","")
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            ips_to_scan.append({"ip": ip, "host": h.get("host",""), "ports": h.get("ports",[])})

    if not ips_to_scan:
        return {"error": "No IPs found — run a scan first", "findings": []}

    # Write wordlist to temp file
    wl_path = wordlist
    tmp_wl  = None
    if not wl_path or not Path(wl_path).exists():
        tmp_wl  = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        for p in all_prefixes:
            tmp_wl.write(f"{p}.{primary_domain}\n")
        tmp_wl.flush()
        wl_path = tmp_wl.name

    findings = []
    scanned_ips = []

    for target in ips_to_scan[:5]:   # cap at 5 IPs
        ip   = target["ip"]
        ports = target.get("ports", [])

        # Determine HTTP/HTTPS ports
        http_ports  = []
        https_ports = []
        for p in ports:
            pn = int(p["port"] if isinstance(p, dict) else p)
            if pn in (443, 8443):
                https_ports.append(pn)
            elif pn in (80, 8080, 8888, 8000, 8001):
                http_ports.append(pn)

        if not http_ports and not https_ports:
            http_ports = [80]

        for port in (https_ports or []) + (http_ports or []):
            scheme = "https" if port in (443, 8443) else "http"
            base_url = f"{scheme}://{ip}:{port}"

            if ffuf_bin:
                # ffuf cannot stream JSON to stdout ("-o -" creates a file literally
                # named "-"), so write JSON to a temp file and read it back.
                with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as of:
                    ffuf_out = of.name
                cmd = [
                    ffuf_bin,
                    "-u", base_url + "/",
                    "-H", "Host: FUZZ",
                    "-w", wl_path,
                    "-mc", "200,201,202,301,302,303,401,403,405",
                    "-fs", "0",         # filter zero-size (connection refused)
                    "-t", "30",
                    "-timeout", "5",
                    "-o", ffuf_out,
                    "-of", "json",
                    "-s",               # silent
                    "-r",               # follow redirects
                    "-noninteractive",
                ]
                try:
                    _subp(cmd, capture_output=True, text=True, timeout=30)
                    try:
                        with open(ffuf_out, "r", encoding="utf-8") as fh:
                            raw = fh.read()
                        data = json.loads(raw) if raw.strip() else {}
                    except (OSError, json.JSONDecodeError):
                        data = {}
                    for item in data.get("results", []):
                        vhost  = item.get("input",{}).get("FUZZ","") or item.get("host","")
                        status = item.get("status",0)
                        length = item.get("length",0)
                        words  = item.get("words",0)
                        if vhost and status:
                            findings.append({
                                "vhost":    vhost,
                                "ip":       ip,
                                "port":     port,
                                "scheme":   scheme,
                                "status":   status,
                                "length":   length,
                                "words":    words,
                                "url":      f"{scheme}://{vhost}",
                                "severity": "medium" if status in (200,201,202) else "low",
                            })
                except Exception:
                    _log.debug('recon.py:6664 erro ignorado', exc_info=True)
                finally:
                    try:
                        os.unlink(ffuf_out)
                    except OSError:
                        pass

            elif gobuster_bin:
                cmd = [
                    gobuster_bin, "vhost",
                    "-u", base_url,
                    "--domain", primary_domain,
                    "-w", wl_path,
                    "--append-domain",
                    "-t", "30",
                    "--timeout", "5s",
                    "-q",
                ]
                try:
                    result = _subp(cmd, capture_output=True, text=True, timeout=30)
                    for line in result.stdout.splitlines():
                        # gobuster output: "Found: sub.domain.com (Status: 200) [Size: 1234]"
                        m = re.match(r"Found:\s+([\w\.\-]+)\s+\(Status:\s*(\d+)\)", line, re.I)
                        if m:
                            vhost, status = m.group(1), int(m.group(2))
                            findings.append({
                                "vhost":    vhost,
                                "ip":       ip,
                                "port":     port,
                                "scheme":   scheme,
                                "status":   status,
                                "url":      f"{scheme}://{vhost}",
                                "severity": "medium" if status in (200,201,202) else "low",
                            })
                except Exception:
                    _log.debug('recon.py:6699 erro ignorado', exc_info=True)

        scanned_ips.append(ip)

    # Cleanup temp wordlist
    if tmp_wl:
        try:
            Path(tmp_wl.name).unlink()
        except Exception:
            _log.debug('recon.py:6708 erro ignorado', exc_info=True)

    # Deduplicate by vhost
    seen_vhosts: dict[str, dict] = {}
    for f in findings:
        key = f["vhost"]
        if key not in seen_vhosts or f["status"] < seen_vhosts[key]["status"]:
            seen_vhosts[key] = f

    unique = sorted(seen_vhosts.values(), key=lambda x: x["vhost"])
    active = [f for f in unique if f["status"] in (200,201,202,301,302,303)]

    return {
        "total":        len(unique),
        "active_count": len(active),
        "ips_scanned":  len(scanned_ips),
        "findings":     unique,
        "scanned_at":   datetime.now().isoformat(timespec="seconds"),
    }
