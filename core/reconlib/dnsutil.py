"""DNS Brute-force with Permutations — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
from pathlib import Path
import re
from core.reconlib.asn import _IP_RE
from core.reconlib.base import _log, _subp, subprocess

# ── DNS ──

def dns_records(domain: str) -> dict:
    """Full DNS enumeration: A AAAA MX TXT NS SOA CNAME SRV CAA — single dig call."""
    RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV", "CAA"]
    out = {}
    # Batch all queries into one subprocess call (vs 9 separate dig processes)
    query_args = []
    for rtype in RECORD_TYPES:
        query_args.extend([rtype, domain])
    try:
        r = _subp(
            ["dig", "+noall", "+answer", "+time=2", "+tries=1"] + query_args,
            capture_output=True, text=True, timeout=15,
        )
        current_type = None
        for line in r.stdout.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split()
            # dig +noall +answer format: name TTL IN TYPE value
            if len(parts) >= 5 and parts[2].upper() == "IN":
                rtype = parts[3].upper()
                value = " ".join(parts[4:]).rstrip(".")
                if rtype in RECORD_TYPES:
                    out.setdefault(rtype, []).append(value)
    except Exception:
        _log.debug('recon.py:442 erro ignorado', exc_info=True)
    return out



# ── Batch DNS utility — single subprocess for multiple queries ──

def _dns_batch(queries: list[tuple]) -> dict:
    """Run multiple DNS queries in ONE subprocess.

    queries: list of (domain, record_type, flags) tuples
    flags: list of extra dig args like ["+time=2", "+tries=1"]

    Returns dict mapping (domain, rtype) → list of values.
    """
    if not queries:
        return {}
    args = ["dig", "+noall", "+answer", "+time=2", "+tries=1"]
    for domain, rtype, flags in queries:
        if flags:
            args.extend(flags)
        args.extend([rtype, domain])
    result = {}
    try:
        r = _subp(args, capture_output=True, text=True, timeout=20)
        for line in r.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[2].upper() == "IN":
                rtype = parts[3].upper()
                name = parts[0].rstrip(".")
                value = " ".join(parts[4:]).rstrip(".")
                result.setdefault((name, rtype), []).append(value)
    except Exception:
        _log.debug('recon.py:474 erro ignorado', exc_info=True)
    return result


def _dns_batch_short(queries: list[tuple]) -> dict:
    """Like _dns_batch but uses +short output (single values per line, no formatting)."""
    if not queries:
        return {}
    args = ["dig", "+short", "+time=2", "+tries=1"]
    for domain, rtype, flags in queries:
        if flags:
            args.extend(flags)
        args.extend([rtype, domain])
    result = {}
    try:
        r = _subp(args, capture_output=True, text=True, timeout=15)
        # Output: one value per line, mixed types — we map by (query position)
        lines = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
        pos = 0
        for domain, rtype, flags in queries:
            values = []
            # Collect all lines until we see a line that matches next query's domain
            while pos < len(lines):
                values.append(lines[pos])
                pos += 1
            result[(domain, rtype)] = values
    except Exception:
        _log.debug('recon.py:500 erro ignorado', exc_info=True)
    return result



# ── Zone Transfer ──
def run_zone_transfer(domains: list) -> dict:
    """Attempt AXFR zone transfer against all nameservers for every domain."""
    all_subdomains: list[str] = []
    attempts = []

    for domain in domains:
        try:
            ns_r = subprocess.run(
                ["dig", "+short", "+time=3", "+tries=1", "NS", domain],
                capture_output=True, text=True, timeout=10,
            )
            nameservers = [ns.strip().rstrip(".") for ns in ns_r.stdout.strip().splitlines() if ns.strip()]
        except Exception:
            nameservers = []

        for ns in nameservers:
            attempt: dict = {"domain": domain, "ns": ns, "success": False, "records": []}
            try:
                axfr = subprocess.run(
                    ["dig", f"@{ns}", domain, "AXFR", "+time=5", "+tries=1"],
                    capture_output=True, text=True, timeout=15,
                )
                out = axfr.stdout
                failed = "Transfer failed" in out or "communications error" in out or "REFUSED" in out
                if not failed:
                    records: list[dict] = []
                    for line in out.splitlines():
                        if line.startswith(";"):
                            continue
                        parts = line.split()
                        # dig AXFR format: name TTL IN TYPE value
                        if len(parts) >= 5 and parts[2].upper() == "IN" and parts[3].upper() in ("A","AAAA","CNAME","MX","NS","TXT"):
                            name  = parts[0].rstrip(".")
                            rtype = parts[3].upper()
                            value = parts[4].rstrip(".")
                            records.append({"name": name, "type": rtype, "value": value})
                            if rtype in ("A","AAAA","CNAME") and (name.endswith(f".{domain}") or name == domain):
                                all_subdomains.append(name.lower())
                    if records:
                        attempt["success"] = True
                        attempt["records"] = records
            except Exception as exc:
                attempt["error"] = str(exc)
            attempts.append(attempt)

    subdomains = sorted(set(all_subdomains))
    return {
        "attempts":             attempts,
        "subdomains":           subdomains,
        "total_subdomains":     len(subdomains),
        "successful_transfers": sum(1 for a in attempts if a["success"]),
        "scanned_at":     datetime.now().isoformat(timespec="seconds"),
    }



# ── DNSSEC Check ──

def run_dnssec_check(domains: list) -> dict:
    """Check DNSSEC for up to 10 domains — single DNS batch call."""
    findings, results = [], []

    for domain in domains[:10]:
        queries = [
            (domain, "DNSKEY", []),
            (domain, "DS", []),
            (domain, "NSEC", []),
        ]
        batch = _dns_batch(queries)
        info = {"domain": domain, "dnssec_enabled": bool(batch.get((domain, "DNSKEY"))),
                "ds_published": bool(batch.get((domain, "DS"))),
                "validates": False, "nsec_type": None, "issues": []}

        # NSEC check
        if batch.get((domain, "NSEC")):
            info["nsec_type"] = "NSEC"
            info["issues"].append("NSEC zone walking possible")

        # NSEC3 check (only if DNSSEC enabled — one more batch)
        if info["dnssec_enabled"]:
            b2 = _dns_batch([(domain, "NSEC3PARAM", [])])
            if b2.get((domain, "NSEC3PARAM")):
                info["nsec_type"] = "NSEC3"

        # AD flag check (needs different flags, separate call — but faster)
        try:
            r = _subp(["dig", "+dnssec", "+time=2", "+tries=1", domain, "A"],
                      capture_output=True, text=True, timeout=8)
            if "flags:" in r.stdout and " ad;" in r.stdout.lower():
                info["validates"] = True
        except Exception:
            _log.debug('recon.py:3047 erro ignorado', exc_info=True)

        if not info["dnssec_enabled"]:
            info["issues"].append("DNSSEC not enabled")
            findings.append({
                "type": "dnssec", "title": f"DNSSEC: {domain}",
                "severity": "medium", "category": "dns",
                "desc": f"`{domain}` sem DNSSEC — respostas DNS podem ser forjadas.",
                "host": domain, "value": domain, "module": "dnssec",
            })
        elif info["nsec_type"] == "NSEC":
            findings.append({
                "type": "dnssec", "title": f"NSEC zone walking: {domain}",
                "severity": "low", "category": "dns",
                "desc": f"`{domain}` usa NSEC — permite enumerar subdomínios.",
                "host": domain, "value": domain, "module": "dnssec",
            })
        results.append(info)

    return {"results": results, "findings": findings, "total": len(findings),
            "scanned_at": datetime.now().isoformat(timespec="seconds")}



# ── DNS Brute-force with Permutations ──

def run_dns_bruteforce(domain: str, hosts: list, mode: str = "balanced") -> dict:
    """
    Generate subdomain permutations from known subdomains using alterx (primary),
    dnsgen/altdns (fallback), then resolve with dnsx/puredns. Backed by wordlist file.

    Modes:
      stealth  = 2k permutations   (quiet, discovery-only)
      balanced = 10k permutations  (default, good coverage)
      fast     = 50k permutations  (aggressive, uses wordlist)
    """
    import shutil, tempfile

    alterx_bin     = shutil.which("alterx")
    dnsgen_bin     = shutil.which("dnsgen")
    altdns_bin     = shutil.which("altdns")
    shuffledns_bin = shutil.which("shuffledns")
    puredns_bin    = shutil.which("puredns")
    dnsx_bin       = shutil.which("dnsx")
    massdns_bin    = shutil.which("massdns")

    # Mode cap
    MODE_CAPS = {"stealth": 2000, "balanced": 10000, "fast": 50000}
    perm_cap = MODE_CAPS.get(mode, 10000)

    # Collect known subdomains as seed
    seeds = set()
    for h in hosts:
        hostname = h.get("host","")
        if hostname and hostname.endswith(domain):
            seeds.add(hostname)
    seeds.add(domain)

    if not seeds:
        seeds = {domain}

    permutations = []

    # ── Wordlist-based permutations (external file, tiered) ──
    try:
        from tools import load_wordlist
        # Map pipeline mode to wordlist size
        wl_mode = {"stealth": "small", "balanced": "medium", "fast": "large"}.get(mode, "medium")
        wl_prefixes = load_wordlist("subdomains", wl_mode, perm_cap)
        for prefix in wl_prefixes:
            prefix = prefix.strip().rstrip(".")
            if len(prefix) > 1 and len(prefix) < 50:
                permutations.append(f"{prefix}.{domain}")
    except ImportError:
        pass

    # ── Method 0: alterx pattern-based permutations (primary, most effective) ──
    if alterx_bin and len(seeds) > 1:
        try:
            capped_seeds = sorted(seeds, key=len)[:200]
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(capped_seeds))
                tf_path = tf.name
            # alterx learns patterns from existing subdomains (e.g. api-v2-prod → api-v3-prod)
            # -enrich adds enrichment words, -limit caps output to avoid explosion
            alterx_limit = min(perm_cap * 2, 100000)
            gen_result = _subp(
                [alterx_bin, "-l", tf_path, "-enrich", "-limit", str(alterx_limit)],
                capture_output=True, text=True, timeout=60,
            )
            Path(tf_path).unlink(missing_ok=True)
            alterx_output = [l.strip() for l in gen_result.stdout.splitlines()
                             if l.strip() and l.strip().endswith(domain)]
            permutations.extend(alterx_output)
        except Exception:
            _log.debug('recon.py:6094 erro ignorado', exc_info=True)

    # ── Method 1: dnsgen permutations from known seeds ──
    if dnsgen_bin and len(seeds) > 1:
        try:
            capped_seeds = sorted(seeds, key=len)[:50]
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(capped_seeds))
                tf_path = tf.name
            gen_result = _subp(
                [dnsgen_bin, "-w", "/dev/null", tf_path],
                capture_output=True, text=True, timeout=30,
            )
            Path(tf_path).unlink(missing_ok=True)
            dnsgen_output = [l.strip() for l in gen_result.stdout.splitlines() if l.strip()]
            permutations.extend(dnsgen_output)
        except Exception:
            _log.debug('recon.py:6111 erro ignorado', exc_info=True)

    # ── Method 2: altdns mutations from known seeds ──
    if altdns_bin and len(seeds) > 1:
        try:
            capped = sorted(seeds, key=len)[:100]
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as sf:
                sf.write("\n".join(capped))
                seeds_path = sf.name
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as of:
                out_path = of.name
            _subp(
                [altdns_bin, "-i", seeds_path, "-o", out_path, "-n"],
                capture_output=True, text=True, timeout=60,
            )
            Path(seeds_path).unlink(missing_ok=True)
            try:
                altdns_subs = [l.strip() for l in Path(out_path).read_text().splitlines() if l.strip()]
                permutations.extend(altdns_subs)
            except Exception:
                _log.debug('recon.py:6131 erro ignorado', exc_info=True)
            Path(out_path).unlink(missing_ok=True)
        except Exception:
            _log.debug('recon.py:6134 erro ignorado', exc_info=True)

    # ── Fallback: hardcoded common prefixes ──
    if not permutations:
        COMMON = [
            "www","mail","smtp","ftp","vpn","remote","api","dev","staging","test","uat",
            "qa","prod","beta","admin","portal","app","shop","store","cdn","static",
            "assets","media","blog","status","monitor","internal","corp","intranet",
            "extranet","webmail","owa","autodiscover","ns1","ns2","mx","mx1","mx2",
            "git","gitlab","jenkins","jira","confluence","wiki","kb","docs","help",
            "support","dashboard","manage","mgmt","old","legacy","new","v2","api2",
            "mobile","m","auth","login","sso","id","accounts","register","signup",
            "payment","checkout","secure","ssl","cloud","aws","gcp","azure","k8s",
            "kubernetes","docker","registry","harbor","nexus","sonar","grafana",
            "kibana","elastic","redis","mysql","mongo","postgres","db","database",
        ]
        for prefix in COMMON:
            permutations.append(f"{prefix}.{domain}")
        mutations = []
        for seed in seeds:
            sub = seed.replace(f".{domain}","")
            for suffix in ["dev","staging","test","old","new","v2","api","internal"]:
                mutations.append(f"{sub}-{suffix}.{domain}")
                mutations.append(f"{suffix}-{sub}.{domain}")
        permutations.extend(mutations)

    if not permutations:
        return {"error": "No permutations generated", "findings": []}

    # ── Deduplicate + cap ──
    permutations = sorted(set(p for p in permutations if p.endswith(domain) and len(p) < 200))[:perm_cap]

    # ── Resolve with best available tool ──
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(permutations))
        perms_file = tf.name

    resolved = []
    resolver_used = "none"

    def _dnsx_produces_output(bin_path: str, test_host: str = "google.com") -> bool:
        """Sanity-check: dnsx sometimes silently produces no output on some environments."""
        try:
            r = _subp([bin_path, "-l", "/dev/stdin", "-a", "-silent"],
                      input=test_host + "\n", capture_output=True, text=True, timeout=10)
            return bool(r.stdout.strip())
        except Exception:
            return False

    if dnsx_bin and _dnsx_produces_output(dnsx_bin):
        try:
            result = _subp(
                [dnsx_bin, "-l", perms_file, "-silent", "-duc", "-a", "-resp",
                 "-retry", "1", "-threads", "100"],
                capture_output=True, text=True, timeout=300,
            )
            ansi_re = re.compile(r"\x1b\[[0-9;]*m")
            seen_hosts: dict[str, str] = {}
            for line in result.stdout.splitlines():
                line = ansi_re.sub("", line).strip()
                parts = line.split()
                if len(parts) >= 1:
                    host = parts[0].rstrip(".")
                    ip_raw = parts[-1].strip("[]") if len(parts) >= 3 else ""
                    ip = ip_raw if _IP_RE.match(ip_raw) else ""
                    if host and host.endswith(domain) and host not in seen_hosts:
                        seen_hosts[host] = ip
            resolved = [{"host": h, "ip": ip, "source": "dns_bruteforce"} for h, ip in seen_hosts.items()]
            resolver_used = "dnsx"
        except Exception:
            _log.debug('recon.py:6204 erro ignorado', exc_info=True)
    elif puredns_bin and shutil.which("massdns"):
        try:
            result = _subp(
                [puredns_bin, "resolve", perms_file, "--quiet"],
                capture_output=True, text=True, timeout=300,
            )
            seen_hosts_set: set[str] = set()
            for line in result.stdout.splitlines():
                host = line.strip()
                if host and host.endswith(domain) and host not in seen_hosts_set:
                    seen_hosts_set.add(host)
                    resolved.append({"host": host, "ip": "", "source": "dns_bruteforce"})
            if resolved:
                resolver_used = "puredns"
        except Exception:
            _log.debug('recon.py:6220 erro ignorado', exc_info=True)

    # ── Python socket fallback (threaded, uses system resolver — works behind VPN) ──
    if not resolved and resolver_used == "none":
        import socket as _socket
        from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed

        def _resolve_one(host: str):
            try:
                ip = _socket.gethostbyname(host)
                return {"host": host, "ip": ip, "source": "dns_bruteforce"}
            except Exception:
                return None

        # Cap at 5000 for the Python resolver to keep runtime reasonable
        py_cap = min(len(permutations), 5000)
        with ThreadPoolExecutor(max_workers=150) as ex:
            futures = {ex.submit(_resolve_one, h): h for h in permutations[:py_cap]}
            for fut in _as_completed(futures):
                r = fut.result()
                if r:
                    resolved.append(r)
        resolver_used = "socket"

    Path(perms_file).unlink(missing_ok=True)

    # ── Filter out already known hosts ──
    known_hosts = {h.get("host","") for h in hosts}
    new_findings = [
        {"type": "subdomain", "value": r["host"], "host": r["host"],
         "ip": r["ip"], "severity": "info", "source": "dns_bruteforce"}
        for r in resolved if r["host"] not in known_hosts
    ]

    return {
        "total_resolved":          len(resolved),
        "new_found":               len(new_findings),
        "permutations_generated":  len(permutations),
        "permutations_tried":      len(permutations),
        "alterx_used":             bool(alterx_bin),
        "seeds_count":             len(seeds),
        "resolver_used":           resolver_used,
        "mode":                    mode,
        "findings":                new_findings[:500],
        "scanned_at":              datetime.now().isoformat(timespec="seconds"),
    }
