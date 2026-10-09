"""Port Scan (nmap/naabu wrapper) — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
import json
import shutil
from core.reconlib.asn import _extract_public_ips
from core.reconlib.base import _log, _subp

# ── Port Scan (nmap/naabu wrapper) ──

_RISKY_PORTS = {
    21:    "FTP — plaintext file transfer",
    22:    "SSH",
    23:    "Telnet — plaintext protocol",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3 — plaintext email",
    143:   "IMAP — plaintext email",
    389:   "LDAP — directory service",
    443:   "HTTPS",
    445:   "SMB — Windows file sharing",
    512:   "rexec — remote exec (plaintext)",
    513:   "rlogin — remote login (plaintext)",
    514:   "rsh — remote shell (plaintext)",
    636:   "LDAPS",
    1433:  "MSSQL",
    1521:  "Oracle DB",
    2181:  "ZooKeeper — often unauthenticated",
    2375:  "Docker API — plaintext (CRITICAL)",
    2376:  "Docker TLS API",
    2379:  "etcd API — Kubernetes secrets",
    3000:  "Grafana/dev server",
    3306:  "MySQL",
    3389:  "RDP — Remote Desktop",
    4243:  "Docker API alt",
    4443:  "HTTPS-alt",
    4848:  "GlassFish Admin",
    5000:  "Dev server / Docker Registry",
    5432:  "PostgreSQL",
    5601:  "Kibana — often unauthenticated",
    5900:  "VNC — remote desktop",
    6379:  "Redis — often unauthenticated",
    7001:  "WebLogic Admin",
    7474:  "Neo4j Browser",
    8001:  "kubectl proxy",
    8080:  "HTTP-alt / Tomcat / Jenkins",
    8088:  "Hadoop YARN ResourceManager",
    8161:  "ActiveMQ Web Console",
    8443:  "HTTPS-alt",
    8888:  "Jupyter Notebook — often unauthenticated",
    9000:  "SonarQube / Portainer",
    9090:  "Prometheus — metrics exposed",
    9092:  "Kafka — often unauthenticated",
    9200:  "Elasticsearch — often unauthenticated",
    9300:  "Elasticsearch cluster",
    10250: "Kubelet API — Kubernetes node",
    10255: "Kubelet read-only",
    11211: "Memcached — often unauthenticated",
    15672: "RabbitMQ Management UI",
    27017: "MongoDB — often unauthenticated",
    27018: "MongoDB",
    50000: "Jenkins JNLP agent port",
    50070: "Hadoop NameNode",
    61616: "ActiveMQ broker",
}


_HIGH_RISK_PORTS = {
    23, 445, 512, 513, 514,       # plaintext protocols
    2375, 2379, 4243, 8001,       # container/orchestration APIs
    3389, 5900,                    # remote desktop
    6379, 9200, 27017, 11211,     # unauthenticated data stores
    10250, 50070, 8088,           # big data / kubernetes
    4848, 7001,                    # app server admins
}


_DEFAULT_SCAN_PORTS = (
    "21,22,23,25,53,80,110,143,389,443,445,"
    "512,513,514,636,1433,1521,2181,2375,2376,2379,"
    "3000,3306,3389,4243,4443,4848,5000,5432,5601,5900,"
    "6379,7001,7474,8001,8080,8088,8161,8443,8888,"
    "9000,9090,9092,9200,9300,10250,10255,11211,"
    "15672,27017,27018,50000,50070,61616"
)


def run_port_scan(hosts: list, ports: str = _DEFAULT_SCAN_PORTS,
                  tool: str = "auto") -> dict:
    """Run port scan using naabu, masscan, or nmap on target IPs."""
    unique_ips = _extract_public_ips(hosts)

    if not unique_ips:
        return {"error": "No public IPs to scan", "results": []}

    if tool == "auto":
        # nmap first — works without root; masscan needs raw sockets (root only)
        for candidate in ("naabu", "nmap", "masscan"):
            if shutil.which(candidate):
                tool = candidate; break
        else:
            tool = None

    if not tool:
        return {"error": "No port scanner found (install naabu, masscan, or nmap)", "results": []}

    # Filter out WAF/CDN proxy IPs that accept all TCP connections (false positive source).
    # Hosts with waf= "Incapsula"|"Cloudflare"|"CDN" resolve to proxy IPs, not origins.
    import ipaddress as _ipa
    _WAF_NETS = [
        # Incapsula / Imperva (full 45.223.0.0/16 belongs to Imperva/Thales)
        "45.223.0.0/16", "45.60.0.0/16", "199.83.128.0/21",
        "198.143.32.0/21", "149.126.72.0/21", "103.28.248.0/22",
        # Cloudflare
        "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13",
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
        "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "2606:4700::/32",
    ]
    _waf_networks = []
    for _net in _WAF_NETS:
        try:
            _waf_networks.append(_ipa.ip_network(_net, strict=False))
        except Exception:
            _log.debug('recon.py:4753 erro ignorado', exc_info=True)

    def _is_waf_ip(ip: str) -> bool:
        try:
            addr = _ipa.ip_address(ip)
            return any(addr in net for net in _waf_networks)
        except Exception:
            return False

    clean_ips = [ip for ip in unique_ips if not _is_waf_ip(ip)]
    if not clean_ips:
        # All IPs are WAF proxies — scan anyway with a warning
        clean_ips = unique_ips

    results = []
    try:
        if tool == "naabu":
            target_str = ",".join(clean_ips)
            proc = _subp(
                ["naabu", "-host", target_str, "-p", ports, "-json", "-silent"],
                capture_output=True, text=True, timeout=120,
            )
            for line in proc.stdout.strip().splitlines():
                try:
                    item = json.loads(line)
                    ip   = item.get("ip","")
                    port = item.get("port", 0)
                    desc = _RISKY_PORTS.get(port, "")
                    sev  = "critical" if port in _HIGH_RISK_PORTS else \
                           "high" if desc else "info"
                    results.append({"ip": ip, "port": port,
                                    "service": desc, "severity": sev})
                except Exception:
                    _log.debug('recon.py:4786 erro ignorado', exc_info=True)

        elif tool == "masscan":
            import tempfile as _tempfile, os as _os
            port_list = ports.replace(",", ",")
            ip_list = "\n".join(clean_ips)
            with _tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write(ip_list)
                hosts_file = tf.name
            try:
                proc = _subp(
                    ["masscan", "-iL", hosts_file, "-p", port_list,
                     "--rate", "1000", "--open-only", "-oJ", "-"],
                    capture_output=True, text=True, timeout=180,
                )
                import re as _re_ms
                for line in proc.stdout.strip().splitlines():
                    line = line.strip().rstrip(",")
                    if not line.startswith("{"):
                        continue
                    try:
                        item = json.loads(line)
                        ip   = item.get("ip", "")
                        ports_list = item.get("ports", [])
                        for p in ports_list:
                            port = int(p.get("port", 0))
                            desc = _RISKY_PORTS.get(port, "")
                            sev  = "critical" if port in _HIGH_RISK_PORTS else \
                                   "high" if desc else "info"
                            results.append({"ip": ip, "port": port,
                                            "service": desc, "severity": sev})
                    except Exception:
                        _log.debug('recon.py:4818 erro ignorado', exc_info=True)
            finally:
                _os.unlink(hosts_file)

        elif tool == "nmap":
            import tempfile as _tempfile, os as _os
            ip_list = "\n".join(clean_ips)
            with _tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write(ip_list)
                hosts_file = tf.name
            try:
                port_arg = ports
                proc = _subp(
                    ["nmap", "-iL", hosts_file, "-p", port_arg,
                     "--open", "-T4", "-oG", "-", "--host-timeout", "30s"],
                    capture_output=True, text=True, timeout=300,
                )
                current_ip = ""
                for line in proc.stdout.splitlines():
                    if line.startswith("Host:"):
                        # nmap -oG emits two "Host:" lines per host:
                        #   "Host: IP ()  Status: Up"
                        #   "Host: IP ()  Ports: 80/open/tcp//http///, ..."
                        parts = line.split()
                        current_ip = parts[1] if len(parts) > 1 else ""
                        if "Ports:" in line:
                            port_section = line.split("Ports:")[1].strip()
                            for entry in port_section.split(","):
                                entry = entry.strip()
                                if "open" not in entry:
                                    continue
                                try:
                                    port = int(entry.split("/")[0])
                                    desc = _RISKY_PORTS.get(port, "")
                                    sev  = "critical" if port in _HIGH_RISK_PORTS else \
                                           "high" if desc else "info"
                                    results.append({"ip": current_ip, "port": port,
                                                    "service": desc, "severity": sev})
                                except Exception:
                                    _log.debug('recon.py:4857 erro ignorado', exc_info=True)
            finally:
                _os.unlink(hosts_file)

    except Exception as e:
        return {"error": str(e), "tool": tool, "results": results}

    high_risk = [r for r in results if r["severity"] in ("critical","high")]
    return {
        "tool":          tool,
        "ips_scanned":   len(clean_ips),
        "waf_ips_skipped": len(unique_ips) - len(clean_ips),
        "results":       sorted(results, key=lambda r: r["port"]),
        "high_risk":     high_risk,
        "high_risk_count": len(high_risk),
        "scanned_at":    datetime.now().isoformat(timespec="seconds"),
    }
