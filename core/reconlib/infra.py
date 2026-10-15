"""Kubernetes / Docker / etcd Infrastructure Exposure — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
from urllib.error import HTTPError
import re
from core.reconlib.base import _log, _random_ua, _subp, http_get, run_bounded, subprocess

# ── Kubernetes / Docker / etcd Infrastructure Exposure ──

# Evidência por serviço: porta aberta respondendo qualquer coisa NÃO basta. CDN (Cloudflare) aceita
# conexão em 8080/8443 e devolve página própria — sem isto viraram 9 "Kubernetes API exposta"
# críticos falsos (15/10/2026). Achado só com o corpo batendo na assinatura do serviço.
INFRA_SIGNATURES = {
    "Kubernetes": re.compile(rb'"gitVersion"|"kind"\s*:\s*"(NamespaceList|PodList|Status|APIVersions)"'),
    "Docker": re.compile(rb'^OK$|"ServerVersion"|"ApiVersion"'),
    "Docker Registry": re.compile(rb'^\{\}$|"repositories"\s*:'),
    "etcd": re.compile(rb'"etcdserver"|"etcdcluster"|"health"\s*:\s*"(true|false)"|"node"\s*:\s*\{'),
    "Elasticsearch": re.compile(rb'You Know, for Search|"cluster_name"|health status index'),
}


def infra_evidence_ok(category: str, body) -> bool:
    sig = INFRA_SIGNATURES.get(category)
    if isinstance(body, str):
        body = body.encode("utf-8", "ignore")
    return bool(sig is not None and sig.search((body or b"")[:4096].strip()))


def run_infra_exposure(hosts: list) -> dict:
    """Detect exposed container orchestration and registry infrastructure."""
    import socket as _sock

    PROBES = [
        (6443,  "Kubernetes API",          ["/version", "/api/v1/namespaces"],          "critical", "Kubernetes"),
        (8080,  "Kubernetes API (plain)",  ["/api/v1/namespaces", "/version"],          "critical", "Kubernetes"),
        (10250, "Kubelet API",             ["/pods", "/metrics"],                        "critical", "Kubernetes"),
        (10255, "Kubelet Read-only",       ["/pods", "/healthz"],                        "high",     "Kubernetes"),
        (8001,  "kubectl proxy",           ["/api/v1/namespaces"],                       "critical", "Kubernetes"),
        (2375,  "Docker API (plain)",      ["/_ping", "/v1.41/info"],                    "critical", "Docker"),
        (2376,  "Docker TLS",             ["/_ping"],                                    "high",     "Docker"),
        (4243,  "Docker Alt",             ["/_ping"],                                    "critical", "Docker"),
        (5000,  "Docker Registry",        ["/v2/", "/v2/_catalog"],                     "high",     "Docker Registry"),
        (2379,  "etcd API",               ["/version", "/v2/keys/", "/health"],         "critical", "etcd"),
        (2380,  "etcd Peer",              ["/version"],                                  "medium",   "etcd"),
        (9200,  "Elasticsearch",          ["/", "/_cat/indices?v"],                      "high",     "Elasticsearch"),
    ]

    findings: list[dict] = []
    by_ip: dict[str, str] = {}
    for h in hosts[:80]:
        if isinstance(h, dict) and h.get("ip") and h["ip"] not in by_ip:
            by_ip[h["ip"]] = h.get("host", h["ip"])

    def _probe_ip(item):
        ip, host = item
        for port, service, paths, sev, category in PROBES:
            try:
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(1.5)
                open_ = s.connect_ex((ip, port)) == 0
                s.close()
            except Exception:
                continue
            if not open_:
                continue

            accessible_paths: list[dict] = []
            for path in paths[:2]:
                try:
                    code, body, _ = http_get(f"http://{ip}:{port}{path}", timeout=5, retries=1)
                    if code and code < 500 and infra_evidence_ok(category, body):
                        preview = (body or b"")[:150].decode("utf-8", "ignore")
                        accessible_paths.append({"path": path, "status": code, "preview": preview})
                except Exception:
                    _log.debug('recon.py:7319 erro ignorado', exc_info=True)

            if not paths or accessible_paths:
                findings.append({
                    "type": "infra_exposure", "host": host, "ip": ip,
                    "port": port, "service": service, "category": category,
                    "severity": sev,
                    "title": f"Exposed {service} on {host}:{port}",
                    "desc": (
                        f"{service} accessible at {ip}:{port}. "
                        f"Paths: {[p['path'] for p in accessible_paths] or ['port open']}."
                    ),
                    "open_paths": accessible_paths,
                    "url": f"http://{ip}:{port}",
                                    "request_raw":  ("GET " + (_fp.get("path", "/") if (_fp := (accessible_paths[0] if accessible_paths else {})) else "/") + " HTTP/1.1\r\nHost: " + ip + ":" + str(port) + "\r\nUser-Agent: Mozilla/5.0") if accessible_paths else "",
                    "response_raw": ("HTTP/1.1 " + str(accessible_paths[0].get("status","")) + "\r\n\r\n" + accessible_paths[0].get("preview","")) if accessible_paths else "",
                    "matched":      service,
                })

    complete = run_bounded(_probe_ip, by_ip.items(), workers=10, label="infra_exp")
    findings = list(findings)
    return {
        "total_ips_tested": len(by_ip),
        "complete": complete,
        "vulnerable": len(findings),
        "findings": findings,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



def run_default_creds(hosts: list) -> dict:
    """
    Check exposed services for default or absent authentication.
    Covers: Redis, MongoDB, Elasticsearch, Jenkins, Tomcat admin, Jupyter.
    """
    import socket as _sock
    findings = []
    tested = set()

    _PROBES = [
        # (port, name, check_fn_name)
        (6379,  "Redis",         "redis"),
        (27017, "MongoDB",       "mongo"),
        (9200,  "Elasticsearch", "elastic"),
        (8080,  "Tomcat/Jenkins","http_admin"),
        (8888,  "Jupyter",       "jupyter"),
        (5601,  "Kibana",        "kibana"),
        (3000,  "Grafana",       "grafana"),
        (9090,  "Prometheus",    "prometheus"),
    ]

    def _tcp_open(ip, port, timeout=2):
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((ip, port))
            s.close()
            return r == 0
        except Exception:
            return False

    def _check_redis(ip, port=6379):
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            s.send(b"PING\r\n")
            resp = s.recv(64).decode("utf-8","ignore")
            s.close()
            if "+PONG" in resp or "+OK" in resp:
                return {"auth": False, "detail": "PING responded without auth", "severity": "critical"}
        except Exception:
            _log.debug('recon.py:7388 erro ignorado', exc_info=True)
        return None

    def _check_mongo(ip, port=27017):
        # MongoDB wire protocol hello
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            # OP_MSG isMaster
            hello = b'\x41\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00' \
                    b'\x00\x13\x00\x00\x00\x02isMaster\x00\x02\x00\x00\x001\x00\x00'
            s.send(hello)
            resp = s.recv(256)
            s.close()
            if len(resp) > 16:  # got a real MongoDB response
                return {"auth": False, "detail": "MongoDB responded without auth", "severity": "critical"}
        except Exception:
            _log.debug('recon.py:7406 erro ignorado', exc_info=True)
        return None

    def _check_http_admin(ip, port=8080, host=""):
        """Check for Jenkins/Tomcat open admin without credentials."""
        endpoints = [
            ("/",              ["jenkins", "tomcat", "j_security_check", "manager"]),
            ("/manager/html",  ["401", "200"]),
            ("/jenkins/",      ["jenkins", "dashboard"]),
        ]
        for path, signals in endpoints:
            try:
                sc, raw, _ = http_get(f"http://{ip}:{port}{path}", timeout=4, retries=1)
                body = (raw or b"")[:1000].decode("utf-8","ignore").lower()
                if sc == 200 and any(s in body for s in signals):
                    panel = "Jenkins" if "jenkins" in body else "Tomcat" if "tomcat" in body else "Admin panel"
                    return {"auth": False, "detail": f"{panel} accessible without authentication at :{port}{path}", "severity": "high", "url": f"http://{ip}:{port}{path}"}
                if sc == 401:
                    # Try default creds
                    import base64
                    for user, pw in [("admin","admin"),("admin","password"),("tomcat","tomcat"),("admin","tomcat"),("jenkins","jenkins")]:
                        creds = base64.b64encode(f"{user}:{pw}".encode()).decode()
                        sc2, raw2, _ = http_get(f"http://{ip}:{port}{path}", timeout=4, retries=1,
                                                 extra_headers={"Authorization": f"Basic {creds}"})
                        if sc2 == 200:
                            return {"auth": "default", "detail": f"Default credentials {user}:{pw} accepted", "severity": "critical",
                                    "credentials": f"{user}:{pw}", "url": f"http://{ip}:{port}{path}"}
            except Exception:
                _log.debug('recon.py:7434 erro ignorado', exc_info=True)
        return None

    def _check_elastic(ip, port=9200):
        try:
            sc, raw, _ = http_get(f"http://{ip}:{port}/", timeout=4, retries=1)
            if sc == 200:
                body = (raw or b"")[:500].decode("utf-8","ignore")
                if "elasticsearch" in body.lower() or "cluster_name" in body.lower():
                    # Check if indices are accessible
                    sc2, raw2, _ = http_get(f"http://{ip}:{port}/_cat/indices?v", timeout=4, retries=1)
                    if sc2 == 200:
                        return {"auth": False, "detail": "Elasticsearch indices publicly accessible", "severity": "critical",
                                "url": f"http://{ip}:{port}/_cat/indices?v"}
                    return {"auth": False, "detail": "Elasticsearch API open (indices protected)", "severity": "high",
                            "url": f"http://{ip}:{port}/"}
        except Exception:
            _log.debug('recon.py:7451 erro ignorado', exc_info=True)
        return None

    def _check_jupyter(ip, port=8888):
        try:
            sc, raw, _ = http_get(f"http://{ip}:{port}/api/kernels", timeout=4, retries=1)
            if sc == 200 and b"kernel" in (raw or b""):
                return {"auth": False, "detail": "Jupyter Notebook API accessible without token", "severity": "critical",
                        "url": f"http://{ip}:{port}/"}
        except Exception:
            _log.debug('recon.py:7461 erro ignorado', exc_info=True)
        return None

    def _check_generic_open(ip, port, name):
        try:
            sc, raw, _ = http_get(f"http://{ip}:{port}/", timeout=4, retries=1)
            if sc == 200:
                return {"auth": "unknown", "detail": f"{name} web UI accessible (no auth check performed)", "severity": "medium",
                        "url": f"http://{ip}:{port}/"}
        except Exception:
            _log.debug('recon.py:7471 erro ignorado', exc_info=True)
        return None

    _CHECK_FN = {
        "redis":      _check_redis,
        "mongo":      _check_mongo,
        "elastic":    _check_elastic,
        "http_admin": _check_http_admin,
        "jupyter":    _check_jupyter,
        "kibana":     lambda ip, port=5601: _check_generic_open(ip, port, "Kibana"),
        "grafana":    lambda ip, port=3000: _check_generic_open(ip, port, "Grafana"),
        "prometheus": lambda ip, port=9090: _check_generic_open(ip, port, "Prometheus"),
    }

    for h in hosts[:60]:
        if not isinstance(h, dict):
            continue
        ip = h.get("ip","")
        if not ip or ip in tested:
            continue
        hostname = h.get("host", ip)
        host_ports = set(str(p) for p in (h.get("ports") or []))

        for port, name, fn_key in _PROBES:
            if host_ports and str(port) not in host_ports:
                continue  # skip if we have port data and port wasn't found open
            if not _tcp_open(ip, port):
                continue
            tested.add(ip)
            check_fn = _CHECK_FN.get(fn_key)
            if not check_fn:
                continue
            try:
                result = check_fn(ip, port)
            except Exception:
                result = None
            if result:
                findings.append({
                    "host":     hostname,
                    "ip":       ip,
                    "port":     port,
                    "service":  name,
                    "severity": result.get("severity","high"),
                    "title":    f"Default/No Auth: {name} on {hostname}:{port}",
                    "desc":     result.get("detail",""),
                    "url":      result.get("url", f"http://{ip}:{port}"),
                    "credentials": result.get("credentials",""),
                    "type":     "default_creds",
                })

    return {
        "findings":    findings,
        "total":       len(findings),
        "scanned_at":  datetime.now().isoformat(timespec="seconds"),
    }



def run_waf_bypass_test(hosts: list) -> dict:
    """
    Test WAF bypass techniques against WAF-protected hosts.
    Tries IP spoofing headers, path encoding, and Host header fuzzing.
    Returns successful bypasses as critical/high findings.
    """
    import socket as _sock

    _BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Original-IP": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-Host": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
        {"X-Forwarded-For": "10.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
    ]

    findings = []
    tested = []

    # Only test hosts that have a WAF or returned 403
    candidates = [h for h in hosts if h.get("waf") or h.get("status_code") in (403, 406)][:30]

    def _test_host(h):
        host = h.get("host", "")
        if not host:
            return
        url = f"https://{host}/" if not host.startswith("http") else host
        tested.append(host)

        # Baseline request
        try:
            base_status, base_body, _ = http_get(url, timeout=8, retries=1)
        except Exception:
            return
        if not base_status:
            return  # sem resposta (timeout/circuito aberto): não há com o que comparar

        base_len = len(base_body or b"")

        for extra_h in _BYPASS_HEADERS:
            try:
                status, body, _ = http_get(url, timeout=8, retries=1, extra_headers=extra_h)
            except Exception:
                continue
            if not status:
                continue  # status 0 = falha de rede, não "passou do WAF"

            body_len = len(body or b"")
            status_change = base_status != status and status < 400
            size_change = base_len > 0 and abs(body_len - base_len) / max(base_len, 1) > 0.30
            if status_change or (size_change and status < 400):
                header_name = list(extra_h.keys())[0]
                key = f"waf-bypass-{host}-{header_name}"
                findings.append({
                    "type": "waf_bypass",
                    "host": host,
                    "title": f"WAF Bypass via {header_name}: {host}",
                    "severity": "high",
                    "category": "waf_bypass",
                    "desc": (
                        f"Header `{header_name}: {list(extra_h.values())[0]}` changed response "
                        f"from {base_status}/{base_len}B to {status}/{body_len}B. "
                        f"WAF may be bypassed — direct access to origin possible."
                    ),
                    "url": url,
                    "metadata": {
                        "header": header_name,
                        "value": list(extra_h.values())[0],
                        "baseline_status": base_status,
                        "bypass_status": status,
                        "baseline_len": base_len,
                        "bypass_len": body_len,
                    },
                })
                break  # one bypass per host is enough

    complete = run_bounded(_test_host, candidates, workers=8, label="waf_bypass")
    findings = list(findings)
    return {
        "total_tested": len(tested),
        "complete": complete,
        "bypasses_found": len(findings),
        "findings": findings,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



def run_smtp_probe(hosts: list) -> dict:
    """
    Probe SMTP services on port 25, 587, 465.
    Captures banner, EHLO response, STARTTLS availability, version disclosure.
    """
    import socket as _sock

    _SMTP_PORTS = [25, 587, 465, 2525]
    findings = []
    results = []
    by_ip: dict[str, str] = {}
    for h in hosts[:60]:
        if h.get("ip") and h["ip"] not in by_ip:
            by_ip[h["ip"]] = h.get("host", h["ip"])

    def _probe_ip(item):
        ip, host_name = item
        for port in _SMTP_PORTS:
            try:
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(4)
                if s.connect_ex((ip, port)) != 0:
                    s.close()
                    continue

                banner = s.recv(512).decode("utf-8", "ignore").strip()
                # EHLO
                try:
                    s.send(f"EHLO asm-probe.test\r\n".encode())
                    ehlo_resp = s.recv(1024).decode("utf-8", "ignore").strip()
                except Exception:
                    ehlo_resp = ""
                s.close()

                has_starttls = "STARTTLS" in ehlo_resp.upper()
                # Version disclosure: look for MTA name + version in banner
                version_match = re.search(
                    r"(Postfix|Sendmail|Exim|Exchange|ESMTP)\s*([\d\.]+)?",
                    banner, re.I
                )
                version = version_match.group(0) if version_match else ""

                rec = {
                    "host": host_name,
                    "ip": ip,
                    "port": port,
                    "banner": banner[:200],
                    "starttls": has_starttls,
                    "version": version,
                    "ehlo_caps": [l.strip() for l in ehlo_resp.splitlines() if l.startswith("250")],
                }
                results.append(rec)

                sev = "info"
                issues = []
                if version:
                    issues.append(f"Version disclosure: {version}")
                    sev = "medium"
                ehlo_ok = any(l.startswith("250") for l in ehlo_resp.splitlines())
                if ehlo_ok and not has_starttls and port in (25, 587):
                    issues.append("STARTTLS not offered — email in cleartext")
                    sev = "high"
                if port == 25 and "VRFY" in ehlo_resp.upper():
                    issues.append("VRFY command enabled — user enumeration possible")
                    sev = "medium" if sev == "info" else sev
                if port == 25 and "EXPN" in ehlo_resp.upper():
                    issues.append("EXPN command enabled — mailing list disclosure")
                    sev = "medium" if sev == "info" else sev

                if issues:
                    findings.append({
                        "type": "smtp_exposure",
                        "host": host_name,
                        "title": f"SMTP Issue on {host_name}:{port} — {issues[0]}",
                        "severity": sev,
                        "category": "services",
                        "desc": f"Port {port}: {banner[:120]}. Issues: {'; '.join(issues)}",
                        "url": f"smtp://{ip}:{port}",
                        "metadata": rec,
                    })

            except Exception:
                _log.debug('recon.py:7698 erro ignorado', exc_info=True)

    complete = run_bounded(_probe_ip, by_ip.items(), workers=10, label="smtp_probe")
    findings, results = list(findings), list(results)
    return {
        "total_ips_tested": len(by_ip),
        "complete": complete,
        "smtp_hosts": len(results),
        "findings": findings,
        "results": results,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



def run_snmp_probe(hosts: list) -> dict:
    """
    Test SNMP v1/v2c with community string 'public' on UDP port 161.
    Uses snmpget CLI if available, else raw UDP SNMPv1 GET.
    """
    import socket as _sock, struct

    findings = []
    results = []
    tested_ips: set = set()

    has_snmpget = subprocess.run(
        ["which", "snmpget"], capture_output=True
    ).returncode == 0

    def _raw_snmp_ping(ip: str, community: str = "public") -> bool:
        """Send SNMPv1 GET for sysDescr and check for response."""
        # Build minimal SNMPv1 GetRequest for OID 1.3.6.1.2.1.1.1.0 (sysDescr)
        community_bytes = community.encode()
        # OID encoding for 1.3.6.1.2.1.1.1.0
        oid_bytes = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        # VarBind: OID + NULL value
        varbind = oid_bytes + bytes([0x05, 0x00])
        varbind_list = bytes([0x30, len(varbind)]) + varbind
        # GetRequest PDU
        pdu_body = (
            bytes([0x02, 0x01, 0x00])  # request-id = 0
            + bytes([0x02, 0x01, 0x00])  # error-status = 0
            + bytes([0x02, 0x01, 0x00])  # error-index = 0
            + varbind_list
        )
        pdu = bytes([0xa0, len(pdu_body)]) + pdu_body
        # Message
        msg_body = (
            bytes([0x02, 0x01, 0x00])  # version = 0 (SNMPv1)
            + bytes([0x04, len(community_bytes)]) + community_bytes
            + pdu
        )
        packet = bytes([0x30, len(msg_body)]) + msg_body
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(packet, (ip, 161))
            data, _ = s.recvfrom(4096)
            s.close()
            return len(data) > 10  # got a response
        except Exception:
            return False

    for h in hosts[:80]:
        ip = h.get("ip", "")
        host_name = h.get("host", ip)
        if not ip or ip in tested_ips:
            continue
        tested_ips.add(ip)

        try:
            if has_snmpget:
                r = _subp(
                    ["snmpget", "-v2c", "-c", "public", "-t", "2", "-r", "1",
                     ip, "1.3.6.1.2.1.1.1.0"],
                    capture_output=True, text=True, timeout=8,
                )
                open_ = r.returncode == 0 and "STRING" in r.stdout
                output = r.stdout.strip()[:300] if open_ else ""
            else:
                open_ = _raw_snmp_ping(ip)
                output = "SNMP responded to public community string"

            if open_:
                results.append({"host": host_name, "ip": ip, "output": output})
                findings.append({
                    "type": "snmp_public",
                    "host": host_name,
                    "title": f"SNMP Public Community String: {host_name}",
                    "severity": "high",
                    "category": "services",
                    "desc": (
                        f"SNMP v1/v2c on {ip}:161 responds to community 'public'. "
                        f"Can expose system info, interface list, running processes. "
                        f"Output: {output[:200]}"
                    ),
                    "url": f"snmp://{ip}:161",
                    "metadata": {"ip": ip, "community": "public", "output": output},
                })
        except Exception:
            _log.debug('recon.py:7795 erro ignorado', exc_info=True)

    return {
        "total_ips_tested": len(tested_ips),
        "vulnerable": len(findings),
        "findings": findings,
        "results": results,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



def run_host_header_injection(hosts: list) -> dict:
    """
    Test for Host header injection / password reset poisoning.
    Sends requests with manipulated Host, X-Forwarded-Host, X-Host headers
    pointing to an external domain and looks for reflection in response body,
    Location headers, or Set-Cookie domain attributes.
    """
    _POISON_DOMAIN = "asm-probe-hhi.internal"
    _INJECT_HEADERS = [
        "X-Forwarded-Host",
        "X-Host",
        "X-Original-Host",
        "X-Rewrite-URL",
        "X-Custom-Host",
    ]
    findings = []
    tested = []

    candidates = [h for h in hosts if h.get("status_code") and h.get("status_code") < 500][:40]

    def _test_host(h):
        host = h.get("host", "")
        if not host:
            return
        tested.append(host)
        base_url = f"https://{host}/" if not host.startswith("http") else host
        misses = 0

        # Also test the password reset endpoint if we can guess it
        test_paths = ["/", "/reset-password", "/forgot-password", "/account/recover"]

        for path in test_paths[:2]:
            url = base_url.rstrip("/") + path
            for inj_header in _INJECT_HEADERS:
                try:
                    extra = {inj_header: _POISON_DOMAIN}
                    status, body, resp_h = http_get(url, timeout=8, retries=1, extra_headers=extra)
                    if not status:
                        misses += 1
                        if misses >= 2:
                            return  # host não responde: as outras 8 tentativas também cairiam no timeout
                        continue
                    body_str = (body or b"")[:3000].decode("utf-8", "ignore")

                    _hhi_req = (
                        "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n"
                        + inj_header + ": " + _POISON_DOMAIN + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*"
                    )
                    _hhi_resp_base = ("HTTP/1.1 " + str(status) + "\r\n"
                        + "\r\n".join(k + ": " + v for k, v in (resp_h or {}).items() if k.lower() != "set-cookie"))

                    # Reflection in body
                    if _POISON_DOMAIN in body_str:
                        key = f"hhi-{host}-{inj_header}"
                        findings.append({
                            "type":     "host_header_injection",
                            "host":     host,
                            "title":    f"Host Header Injection: {host} reflects {inj_header}",
                            "severity": "high",
                            "category": "injection",
                            "desc":     (
                                f"`{inj_header}: {_POISON_DOMAIN}` reflected in response body at {url}. "
                                "Password reset links may use poisoned domain -- phishing / account takeover possible."
                            ),
                            "url":      url,
                            "metadata": {"header": inj_header, "path": path, "reflection": "body"},
                            "request_raw":  _hhi_req,
                            "response_raw": _hhi_resp_base + "\r\n\r\n" + body_str[:500],
                            "matched":      _POISON_DOMAIN,
                        })
                        break

                    # Reflection in Location header
                    loc = resp_h.get("Location", resp_h.get("location", ""))
                    if _POISON_DOMAIN in loc:
                        key = f"hhi-redirect-{host}-{inj_header}"
                        findings.append({
                            "type":     "host_header_injection",
                            "host":     host,
                            "title":    f"Host Header Injection (redirect): {host}",
                            "severity": "critical",
                            "category": "injection",
                            "desc":     (
                                f"`{inj_header}: {_POISON_DOMAIN}` reflected in Location header: {loc}. "
                                "Open redirect via host header injection -- immediate password reset poisoning risk."
                            ),
                            "url":      url,
                            "metadata": {"header": inj_header, "path": path, "location": loc, "reflection": "redirect"},
                            "request_raw":  _hhi_req,
                            "response_raw": _hhi_resp_base,
                            "matched":      _POISON_DOMAIN,
                        })
                        break
                except Exception:
                    continue
            else:
                continue
            break  # found one finding for this host

    complete = run_bounded(_test_host, candidates, workers=8, label="hhi")
    findings = list(findings)
    return {
        "total_tested": len(tested),
        "complete": complete,
        "vulnerable": len(findings),
        "findings": findings,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



def run_open_redirect_check(hosts: list, urls: list | None = None) -> dict:
    """
    Test discovered URLs for open redirect vulnerabilities.
    Checks redirect parameters with an external target and follows the chain.
    """
    _REDIRECT_DOMAIN = "asm-probe-redirect.internal"
    _REDIRECT_PARAMS = [
        "redirect", "redirect_to", "redirect_uri", "redirectTo",
        "return", "return_to", "returnTo", "returnUrl", "return_url",
        "next", "next_url", "dest", "destination", "url", "goto",
        "link", "callback", "continue", "target", "ref", "referer",
        "forward", "location", "go", "rurl", "r",
    ]
    _REDIRECT_PAYLOADS = [
        f"https://{_REDIRECT_DOMAIN}",
        f"//{_REDIRECT_DOMAIN}",
        f"https://{_REDIRECT_DOMAIN}@example.com",
        f"https://example.com@{_REDIRECT_DOMAIN}",
    ]

    findings = []
    tested_urls: set = set()

    # Build URL candidates from hosts + provided urls
    candidates: list[str] = []
    if urls:
        candidates = [u for u in (urls or []) if u and any(p in u for p in _REDIRECT_PARAMS)][:100]
    if not candidates:
        for h in hosts[:20]:
            host = h.get("host", "")
            if host:
                for param in _REDIRECT_PARAMS[:5]:
                    candidates.append(f"https://{host}/?{param}=FUZZ")

    def _test_template(url_template):
        for payload in _REDIRECT_PAYLOADS[:2]:
            if "FUZZ" in url_template:
                url = url_template.replace("FUZZ", payload)
            else:
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                try:
                    parsed = urlparse(url_template)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    # Inject payload into all redirect-like params
                    for p in _REDIRECT_PARAMS:
                        if p in qs:
                            qs[p] = [payload]
                    new_query = urlencode(qs, doseq=True)
                    url = urlunparse(parsed._replace(query=new_query))
                except Exception:
                    continue

            if url in tested_urls:
                continue
            tested_urls.add(url)

            try:
                import urllib.request as _ur
                from urllib.error import HTTPError
                from utils.circuit_breaker import breaker_for as _br_for
                from urllib.parse import urlparse as _uparse

                host_for_br = _uparse(url).netloc.split(":")[0] or "http"
                br = _br_for(host_for_br)
                if not br.allow():
                    continue

                req = _ur.Request(url, headers={"User-Agent": _random_ua()})
                # Don't follow redirects — we want the raw Location header
                class _NoRedirect(_ur.HTTPRedirectHandler):
                    def redirect_request(self, *a, **kw): return None
                opener2 = _ur.build_opener(_NoRedirect())
                try:
                    with opener2.open(req, timeout=6) as resp:
                        status = resp.status
                        loc = resp.headers.get("Location","")
                    br.success()
                except HTTPError as e:
                    status = e.code
                    loc = e.headers.get("Location","") if e.headers else ""
                    if status >= 500:
                        br.failure()
                    else:
                        br.success()

                if loc and _REDIRECT_DOMAIN in loc:
                    host_name = url.split("/")[2].split("?")[0]
                    key = f"openredirect-{host_name}-{url[:80]}"
                    _or_path = url.split(host_name, 1)[-1].split("#")[0] or "/"
                    findings.append({
                        "type":     "open_redirect",
                        "host":     host_name,
                        "title":    f"Open Redirect: {host_name}",
                        "severity": "medium",
                        "category": "injection",
                        "desc":     (
                            "Redirect parameter accepted external domain. "
                            "URL: " + url[:200] + " -> Location: " + loc[:200] + ". "
                            "Can be abused for phishing, OAuth token theft."
                        ),
                        "url":      url,
                        "metadata": {"payload": payload, "location": loc},
                        "request_raw":  ("GET " + _or_path + " HTTP/1.1\r\nHost: " + host_name + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*"),
                        "response_raw": ("HTTP/1.1 " + str(status) + "\r\nLocation: " + loc),
                        "matched":      _REDIRECT_DOMAIN,
                    })
                    break  # one finding per URL template is enough
            except Exception:
                try:
                    br.failure()
                except Exception:
                    _log.debug('recon.py:8018 erro ignorado', exc_info=True)
                continue

    complete = run_bounded(_test_template, candidates[:120], workers=8, label="open_redir")
    findings = list(findings)
    return {
        "total_tested": len(tested_urls),
        "complete": complete,
        "vulnerable": len(findings),
        "findings": findings,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



def run_s3_write_check(cloud_findings: list) -> dict:
    """
    For S3 buckets already confirmed as public-readable, test write and delete access.
    Uses AWS CLI or raw HTTP PUT/DELETE to verify bucket misconfiguration severity.
    """
    findings = []
    tested = 0

    has_awscli = subprocess.run(["which", "aws"], capture_output=True).returncode == 0

    for finding in cloud_findings:
        if finding.get("type") not in ("s3_bucket", "cloud") and "s3" not in str(finding.get("url","")).lower():
            continue
        bucket = finding.get("bucket") or finding.get("name") or finding.get("value","")
        if not bucket:
            # Try to extract from URL
            url_str = finding.get("url","")
            import re as _re
            m = _re.search(r"([a-z0-9\-\.]{3,63})\.s3[^\./]*\.amazonaws\.com", url_str)
            if m:
                bucket = m.group(1)
        if not bucket:
            continue
        tested += 1

        probe_key = "asm-probe-writecheck.txt"
        probe_content = b"ASM write test - delete me"

        write_ok = False
        delete_ok = False

        if has_awscli:
            # Test write with no-sign-request (anonymous)
            wr = subprocess.run(
                ["aws", "s3", "cp", "-", f"s3://{bucket}/{probe_key}",
                 "--no-sign-request", "--no-progress"],
                input=probe_content, capture_output=True, timeout=15,
            )
            write_ok = wr.returncode == 0
            if write_ok:
                # Clean up
                subprocess.run(
                    ["aws", "s3", "rm", f"s3://{bucket}/{probe_key}", "--no-sign-request"],
                    capture_output=True, timeout=10,
                )
                delete_ok = True
        else:
            # Raw HTTP PUT — 4xx (403) is peer answered, write refused.
            import urllib.request as _ur
            from utils.circuit_breaker import CircuitOpen, guarded_urlopen
            host = f"{bucket}.s3.amazonaws.com"
            try:
                req = _ur.Request(
                    f"https://{host}/{probe_key}",
                    data=probe_content, method="PUT",
                    headers={"Content-Type": "text/plain"},
                )
                with guarded_urlopen(req, timeout=10, name=host) as r:
                    write_ok = r.status in (200, 204)
                if write_ok:
                    del_req = _ur.Request(
                        f"https://{host}/{probe_key}",
                        method="DELETE",
                    )
                    try:
                        with guarded_urlopen(del_req, timeout=10, name=host):
                            delete_ok = True
                    except Exception:
                        _log.debug('recon.py:8097 erro ignorado', exc_info=True)
            except CircuitOpen:
                pass
            except HTTPError:
                pass
            except Exception:
                _log.debug('recon.py:8103 erro ignorado', exc_info=True)

        if write_ok:
            findings.append({
                "type":     "s3_write_access",
                "host":     f"{bucket}.s3.amazonaws.com",
                "title":    f"S3 Bucket Write Access: {bucket}",
                "severity": "critical",
                "category": "cloud",
                "desc":     (
                    f"Bucket `{bucket}` allows ANONYMOUS WRITE (and delete: {delete_ok}). "
                    f"Attacker can upload malicious files, modify content, "
                    f"or use bucket for C2 infrastructure. Immediate remediation required."
                ),
                "url":      f"https://{bucket}.s3.amazonaws.com/",
                "metadata": {"bucket": bucket, "write": True, "delete": delete_ok},
            })

    return {
        "total_tested": tested,
        "critical_count": len(findings),
        "findings": findings,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }
