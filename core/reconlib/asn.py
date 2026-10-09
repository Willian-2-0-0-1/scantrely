"""ASN / IP Intelligence — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from datetime import datetime
import json
import re
from core.reconlib.base import _log, http_get, subprocess

# ── ASN / IP Intelligence ──

def get_ip_info(ip: str) -> dict:
    """IP info via ipinfo.io (free, 50k/month)."""
    try:
        status, body, _ = http_get(f"https://ipinfo.io/{ip}/json", timeout=8)
        if status == 200 and body:
            return json.loads(body)
        return {"ip": ip, "error": f"HTTP {status}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}


def get_asn_prefixes(asn_num: str) -> list:
    """Get CIDR prefixes for an ASN via multiple APIs with fallback."""
    prefixes = []
    # Try RIPEstat
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn_num}"
        status, body, _ = http_get(url, timeout=10)
        if status == 200 and body:
            data = json.loads(body)
            for p in data.get("data",{}).get("prefixes",[]):
                prefixes.append(p.get("prefix",""))
    except Exception:
        _log.debug('recon.py:1336 erro ignorado', exc_info=True)
    if prefixes:
        return prefixes
    # Fallback: BGPView
    try:
        url = f"https://api.bgpview.io/asn/{asn_num}/prefixes"
        status, body, _ = http_get(url, timeout=10)
        if status == 200 and body:
            data = json.loads(body)
            for p in data.get("data",{}).get("ipv4_prefixes",[]):
                prefixes.append(p.get("prefix",""))
    except Exception:
        _log.debug('recon.py:1348 erro ignorado', exc_info=True)
    return prefixes



# Cloud provider IP ranges (for asset classification)
_CLOUD_RANGES = {
    "AWS": [
        "3.", "13.", "18.", "34.", "35.", "43.", "44.", "46.", "50.", "51.", "52.", "54.", "55.", "56.", "63.",
        "67.", "75.", "76.", "79.", "96.", "99.", "100.", "103.", "107.", "108.", "150.", "174.", "175.",
        "177.", "184.", "192.", "204.", "205.", "207.", "208.", "209.", "210.", "216.", "217.",
    ],
    "GCP": ["8.34.", "8.35.", "23.", "34.", "35.", "104.", "107.", "108.", "130.211.", "146.148.", "162.216.", "173.255.", "192.158.", "199.192.", "199.223."],
    "Azure": ["4.", "13.", "20.", "23.", "40.", "51.", "52.", "65.", "70.", "74.", "94.", "102.", "103.", "104.", "137.", "138.", "157.", "191.", "207.", "209."],
    "Cloudflare": ["103.21.", "103.22.", "103.31.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "104.29.", "104.30.", "104.31.", "108.162.", "162.158.", "162.159.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.", "173.245.", "188.114.", "190.93.", "197.234.", "198.41."],
    "DigitalOcean": ["45.55.", "46.101.", "64.225.", "64.226.", "64.227.", "67.205.", "68.183.", "104.131.", "104.236.", "104.248.", "107.170.", "128.199.", "134.122.", "134.209.", "137.184.", "138.68.", "138.197.", "139.59.", "142.93.", "143.110.", "143.198.", "143.244.", "144.126.", "146.190.", "147.182.", "157.230.", "157.245.", "159.65.", "159.89.", "159.203.", "159.223.", "161.35.", "164.90.", "164.92.", "165.22.", "165.227.", "165.232.", "167.71.", "167.99.", "167.172.", "170.64.", "174.138.", "178.62.", "178.128.", "188.166.", "192.34.", "192.81.", "192.241.", "198.199.", "198.211.", "206.81.", "206.189.", "207.154.", "208.68.", "209.38.", "209.97."],
}


def detect_cloud_provider(ip: str) -> str | None:
    """Classify an IP address by cloud provider."""
    for provider, prefixes in _CLOUD_RANGES.items():
        for prefix in prefixes:
            if ip.startswith(prefix):
                return provider
    return None



# Non-HTTP port → service classification for ASM inventory
_KNOWN_PORTS = {
    21: ("FTP", "File Transfer"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Remote Terminal"),
    25: ("SMTP", "Mail Transfer"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Web Server"),
    88: ("Kerberos", "Authentication"),
    110: ("POP3", "Mail Retrieval"),
    111: ("RPC", "Remote Procedure Call"),
    135: ("MSRPC", "Windows RPC"),
    139: ("NetBIOS", "File Sharing"),
    143: ("IMAP", "Mail Retrieval"),
    161: ("SNMP", "Network Management"),
    389: ("LDAP", "Directory Services"),
    443: ("HTTPS", "Secure Web Server"),
    445: ("SMB", "Windows File Sharing"),
    465: ("SMTPS", "Secure Mail Transfer"),
    514: ("Syslog", "System Logging"),
    587: ("SMTP", "Mail Submission"),
    636: ("LDAPS", "Secure Directory"),
    873: ("Rsync", "File Sync"),
    993: ("IMAPS", "Secure Mail"),
    995: ("POP3S", "Secure Mail"),
    1080: ("SOCKS", "Proxy"),
    1433: ("MSSQL", "Database"),
    1521: ("OracleDB", "Database"),
    1723: ("PPTP", "VPN"),
    1883: ("MQTT", "IoT Messaging"),
    2049: ("NFS", "Network File System"),
    2181: ("ZooKeeper", "Coordination"),
    2375: ("Docker", "Container API"),
    2376: ("Docker TLS", "Container API"),
    3000: ("Grafana", "Monitoring"),
    3128: ("Squid", "Proxy"),
    3306: ("MySQL", "Database"),
    3389: ("RDP", "Remote Desktop"),
    5000: ("Flask", "Web Framework"),
    5044: ("Logstash", "Log Shipping"),
    5432: ("PostgreSQL", "Database"),
    5601: ("Kibana", "Analytics"),
    5672: ("AMQP", "Message Queue"),
    5900: ("VNC", "Remote Desktop"),
    5984: ("CouchDB", "Database"),
    6379: ("Redis", "Cache"),
    6443: ("K8s API", "Kubernetes"),
    7001: ("WebLogic", "App Server"),
    8000: ("HTTP Alt", "Web Server"),
    8080: ("HTTP Alt", "Web Server"),
    8443: ("HTTPS Alt", "Web Server"),
    8888: ("HTTP Alt", "Web Server"),
    9000: ("SonarQube", "Code Quality"),
    9042: ("Cassandra", "Database"),
    9090: ("Prometheus", "Monitoring"),
    9200: ("Elasticsearch", "Search Engine"),
    9443: ("Portainer", "Container Mgmt"),
    11211: ("Memcached", "Cache"),
    15672: ("RabbitMQ", "Message Queue"),
    27017: ("MongoDB", "Database"),
}


def classify_service(port: int) -> dict:
    """Classify a port number into service name + category."""
    if port in _KNOWN_PORTS:
        name, cat = _KNOWN_PORTS[port]
        return {"port": port, "service": name, "category": cat}
    # Heuristic ranges
    if 1024 <= port <= 5000:
        return {"port": port, "service": f"App:{port}", "category": "Application"}
    if 5001 <= port <= 9999:
        return {"port": port, "service": f"App:{port}", "category": "Application"}
    if 30000 <= port <= 65535:
        return {"port": port, "service": f"High:{port}", "category": "Dynamic"}
    return {"port": port, "service": f"Unknown:{port}", "category": "Unknown"}


_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                     "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                     "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                     "192.168.", "127.", "169.254.")


_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")



def _extract_public_ips(hosts: list) -> list:
    """Extract unique public IPs from host objects (handles comma-separated IPs)."""
    seen: set = set()
    result = []
    for h in hosts:
        raw = h.get("ip", "") or ""
        for ip in re.split(r"[,\s]+", raw):
            ip = ip.strip()
            if ip and _IP_RE.match(ip) and not ip.startswith(_PRIVATE_PREFIXES) and ip not in seen:
                seen.add(ip)
                result.append(ip)
    return result



def run_asn_recon(hosts: list, domain: str = "") -> dict:
    """Get ASN/IP info for all unique IPs discovered."""
    ips = _extract_public_ips(hosts)
    # When no hosts yet, resolve the domain's A records directly
    if not ips and domain:
        try:
            r = subprocess.run(
                ["dig", "+short", "+time=3", "+tries=1", "A", domain],
                capture_output=True, text=True, timeout=8,
            )
            for line in r.stdout.strip().splitlines():
                ip = line.strip()
                if _IP_RE.match(ip) and not ip.startswith(_PRIVATE_PREFIXES):
                    ips.append(ip)
        except Exception:
            _log.debug('recon.py:1487 erro ignorado', exc_info=True)

    ip_data: dict[str,dict] = {}
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(get_ip_info, ip): ip for ip in ips}
        for fut in as_completed(futures):
            info = fut.result()
            ip_data[info.get("ip","")] = info

    # Group by ASN
    asn_groups: dict[str,dict] = {}
    for ip, info in ip_data.items():
        org = info.get("org","Unknown")
        asn_match = re.match(r"^(AS\d+)\s+(.*)", org)
        asn_num  = asn_match.group(1) if asn_match else "Unknown"
        asn_name = asn_match.group(2) if asn_match else org
        if asn_num not in asn_groups:
            asn_groups[asn_num] = {
                "asn":      asn_num,
                "name":     asn_name,
                "country":  info.get("country",""),
                "ips":      [],
                "prefixes": [],
            }
        asn_groups[asn_num]["ips"].append(ip)

    # Fetch prefixes for top ASNs
    for asn_num, group in list(asn_groups.items())[:5]:
        if asn_num != "Unknown":
            group["prefixes"] = get_asn_prefixes(asn_num)

    return {
        "ip_details":  ip_data,
        "asn_groups":  list(asn_groups.values()),
        "total_ips":   len(ips),
        "scanned_at":  datetime.now().isoformat(timespec="seconds"),
    }
