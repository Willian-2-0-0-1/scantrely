"""CVE Lookup via NVD API v2 — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
from core.reconlib.base import _http_get_json, _log

# ── CVE Lookup via NVD API v2 ──

# Products that are CDNs, WAFs, cloud infra, or third-party client-side services
# CVEs for these are not directly exploitable on the target's own systems
_CVE_SKIP_PRODUCTS = {
    # CDNs / WAFs / proxies
    "akamai", "akamaighost", "akamai technologies", "akamai cdn",
    "cloudflare", "cloudflare bot management", "cloudflare network error logging",
    "amazon cloudfront", "cloudfront", "fastly", "stackpath", "bunnycdn",
    "imperva", "incapsula", "sucuri", "barracuda", "f5 silverline",
    # AWS infrastructure (CDN-side, not target's code)
    "amazon alb", "amazon s3", "amazon ec2", "amazon web services", "awselb",
    "aws waf", "amazon cloudwatch",
    # Google third-party services (client-side, not target code)
    "google", "google cloud", "google maps", "google tag manager",
    "google analytics", "google fonts", "google recaptcha",
    # Microsoft / Azure CDN
    "azure", "microsoft azure", "azure cdn",
    # Generic noise
    "cdn", "waf", "basic",
    # Pure frontend tech (no exploitable server component)
    "http", "https", "html", "css", "javascript", "json", "xml",
    "bootstrap", "jquery", "webpack", "babel", "typescript", "eslint",
    "rss", "atom", "schema.org", "pwa", "amp", "open graph",
    "hsts", "http/3", "http/2", "dnssec", "ipv6",
    "https redirect", "www redirect", "font awesome", "microdata",
    "redirect", "recaptcha", "disqus",
}


# Maps common tech display names → CPE 2.3 product component for virtualMatchString queries.
# Only products with a reliable CPE mapping are listed; others fall back to keyword search.
_CPE_PRODUCT_NAMES: dict[str, str] = {
    # Web servers
    "apache":                    "http_server",
    "apache http server":        "http_server",
    "nginx":                     "nginx",
    "iis":                       "internet_information_services",
    "microsoft iis":             "internet_information_services",
    "lighttpd":                  "lighttpd",
    "caddy":                     "caddy",
    "openresty":                 "openresty",
    # App servers / frameworks
    "apache tomcat":             "tomcat",
    "tomcat":                    "tomcat",
    "jetty":                     "jetty",
    "jboss":                     "jboss",
    "wildfly":                   "wildfly",
    "glassfish":                 "glassfish",
    "weblogic":                  "weblogic",
    "websphere":                 "websphere_application_server",
    "spring":                    "spring_framework",
    "spring boot":               "spring_boot",
    "struts":                    "struts",
    "rails":                     "rails",
    "ruby on rails":             "rails",
    "django":                    "django",
    "flask":                     "flask",
    "express":                   "express",
    "laravel":                   "laravel",
    "symfony":                   "symfony",
    "wordpress":                 "wordpress",
    "drupal":                    "drupal",
    "joomla":                    "joomla!",
    "magento":                   "magento",
    "typo3":                     "typo3",
    # Databases
    "mysql":                     "mysql",
    "mariadb":                   "mariadb",
    "postgresql":                "postgresql",
    "mongodb":                   "mongodb",
    "redis":                     "redis",
    "elasticsearch":             "elasticsearch",
    "solr":                      "solr",
    # Languages / runtimes
    "php":                       "php",
    "python":                    "python",
    "ruby":                      "ruby",
    "node.js":                   "node.js",
    "nodejs":                    "node.js",
    "openssl":                   "openssl",
    "openssh":                   "openssh",
    # Network / load balancing / security
    "haproxy":                   "haproxy",
    "varnish":                   "varnish_cache",
    "squid":                     "squid",
    "citrix":                    "netscaler",
    "citrix netscaler":          "netscaler",
    "citrix adc":                "netscaler",
    "f5 big-ip":                 "big-ip",
    "fortigate":                 "fortios",
    # CMS / portals / CI
    "sharepoint":                "sharepoint_server",
    "confluence":                "confluence",
    "jira":                      "jira",
    "gitlab":                    "gitlab",
    "jenkins":                   "jenkins",
    "sonarqube":                 "sonarqube",
    "kibana":                    "kibana",
    "grafana":                   "grafana",
    "tableau":                   "tableau_server",
    "mattermost":                "mattermost",
    "nextcloud":                 "nextcloud",
    "roundcube":                 "roundcube_webmail",
    "exchange":                  "exchange_server",
    "microsoft exchange":        "exchange_server",
    "phpmyadmin":                "phpmyadmin",
    "moodle":                    "moodle",
    "cpanel":                    "cpanel",
}


# CISA KEV catalog cache — loaded once per process
_KEV_CACHE:   dict[str, bool] = {}

_KEV_LOADED:  bool = False



def _load_kev() -> None:
    """Download CISA Known Exploited Vulnerabilities catalog once per process."""
    global _KEV_LOADED
    if _KEV_LOADED:
        return
    kev_data = _http_get_json(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        timeout=20,
    )
    if isinstance(kev_data, dict):
        for vuln in kev_data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if cve_id:
                _KEV_CACHE[cve_id] = True
    _KEV_LOADED = True



def _fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Batch fetch EPSS exploit-probability scores from FIRST.org API."""
    if not cve_ids:
        return {}
    scores: dict[str, float] = {}
    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i:i + 100]
        params = "&".join(f"cve_id={c}" for c in batch)
        url = f"https://api.first.org/data/1.0/epss?{params}"
        try:
            data = _http_get_json(url, timeout=15)
            if not isinstance(data, dict):
                continue
            for entry in data.get("data", []):
                cid = entry.get("cve", "")
                try:
                    if cid:
                        scores[cid] = float(entry.get("epss", 0.0))
                except (ValueError, TypeError):
                    pass
        except Exception:
            _log.debug('recon.py:6882 erro ignorado', exc_info=True)
    return scores



def run_cve_lookup(hosts: list, nvd_key: str = "") -> dict:
    """
    Cross-reference detected technologies with NVD CVE database.

    Strategy per product:
    1. Versioned + CPE mapping: query NVD virtualMatchString — exact product:version
       match in affected configurations (no false positives from description mentions).
    2. Versioned, CPE returns 0: keyword fallback, filter to CVEs with CPE config match.
    3. Unversioned: keyword search, min_year=2020, filter by CPE config presence.
    4. Enrich all results with EPSS scores (FIRST.org) and CISA KEV flags.
    5. Sort: KEV-listed first, then EPSS×CVSS descending.
    """
    from urllib.parse import urlencode
    import time as _time

    _load_kev()

    findings: list[dict] = []
    queries_done: set[str] = set()
    headers: dict[str, str] = {"User-Agent": "ASM-Platform/1.0"}
    if nvd_key:
        headers["apiKey"] = nvd_key
    rate_delay = 0.6 if nvd_key else 6.0

    def _parse_cve_item(item: dict, product: str) -> dict | None:
        cve    = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            return None
        published = cve.get("published", "")[:10]
        descs  = cve.get("descriptions", [])
        desc   = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score, severity, vector = 0.0, "", ""
        for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            ms = metrics.get(mkey, [])
            if ms:
                cvss     = ms[0].get("cvssData", {})
                score    = cvss.get("baseScore", 0.0)
                severity = (cvss.get("baseSeverity") or ms[0].get("baseSeverity") or "").lower()
                vector   = cvss.get("vectorString", "")
                break
        if score < 4.0:
            return None
        if not severity:
            severity = "critical" if score >= 9 else "high" if score >= 7 else "medium"
        return {
            "cve_id":    cve_id,
            "product":   product,
            "score":     score,
            "severity":  severity,
            "desc":      desc[:400],
            "vector":    vector,
            "url":       f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "published": published,
            "epss":      0.0,
            "kev":       False,
        }

    def _ver_tuple(v: str) -> tuple:
        import re as _re2
        parts = []
        for p in _re2.split(r'[\.\-_]', str(v).strip())[:5]:
            try: parts.append(int(p))
            except ValueError: parts.append(0)
        return tuple(parts)

    def _version_in_range(detected: str, nodes: list) -> bool:
        """Return True if detected version is within at least one vulnerable range in the CPE nodes."""
        if not detected or not nodes:
            return True  # no info → don't filter
        dv = _ver_tuple(detected)
        for node in nodes:
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                start_i = match.get("versionStartIncluding")
                start_e = match.get("versionStartExcluding")
                end_i   = match.get("versionEndIncluding")
                end_e   = match.get("versionEndExcluding")
                try:
                    in_range = True
                    if start_i and dv < _ver_tuple(start_i): in_range = False
                    if start_e and dv <= _ver_tuple(start_e): in_range = False
                    if end_i   and dv > _ver_tuple(end_i):   in_range = False
                    if end_e   and dv >= _ver_tuple(end_e):  in_range = False
                    if in_range:
                        return True
                except Exception:
                    return True
        return False

    def _has_cpe_config(item: dict, product_hint: str) -> bool:
        """Return True if CVE configurations reference the product name, or if no configs exist."""
        ph = product_hint.lower()
        configs = item.get("cve", {}).get("configurations", [])
        if not configs:
            return True  # unanalyzed CVE — let it through
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if ph in match.get("criteria", "").lower():
                        return True
        return False

    def _query_cpe(cpe_name: str, version: str, product: str) -> list[dict]:
        """Query NVD virtualMatchString — returns only CVEs where product:version is in configs."""
        vms = f"cpe:2.3:a:*:{cpe_name}:{version}:*:*:*:*:*:*:*"
        if vms in queries_done:
            return []
        queries_done.add(vms)
        params = {"virtualMatchString": vms, "resultsPerPage": "20"}
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode(params)
        try:
            data = _http_get_json(url, timeout=20, extra_headers=headers)
            if not isinstance(data, dict):
                return []
            return [p for item in data.get("vulnerabilities", [])
                    if (p := _parse_cve_item(item, product)) is not None]
        except Exception:
            return []

    def _query_keyword(keyword: str, product: str, min_year: int) -> list[dict]:
        """Keyword search with CPE config validation to filter description-only matches."""
        if keyword in queries_done:
            return []
        queries_done.add(keyword)
        params = {"keywordSearch": keyword, "resultsPerPage": "30"}
        if not nvd_key:
            params["noRejected"] = ""
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode(params)
        try:
            data = _http_get_json(url, timeout=20, extra_headers=headers)
            if not isinstance(data, dict):
                return []
            results = []
            for item in data.get("vulnerabilities", []):
                parsed = _parse_cve_item(item, product)
                if not parsed:
                    continue
                try:
                    if int(parsed["published"][:4]) < min_year:
                        continue
                except (ValueError, TypeError):
                    pass
                if not _has_cpe_config(item, product):
                    continue
                # Version range check: if we know the exact version, filter CVEs where our version is not vulnerable
                detected_ver = tech_versions.get(product)
                if detected_ver:
                    configs = item.get("cve", {}).get("configurations", [])
                    all_nodes = [n for cfg in configs for n in cfg.get("nodes", [])]
                    if all_nodes and not _version_in_range(detected_ver, all_nodes):
                        continue
                results.append(parsed)
            return results
        except Exception:
            return []

    import re as _re

    def _parse_tech(raw: str) -> tuple[str, str | None]:
        for sep in (":", "/", " "):
            idx = raw.find(sep)
            if idx > 0:
                name = raw[:idx].strip()
                ver  = raw[idx + 1:].strip().split()[0]
                if _re.match(r'^\d[\d.]+', ver) and len(name) >= 2:
                    return name.lower(), ver
        return raw.strip().lower(), None

    tech_versions: dict[str, str | None] = {}
    product_hosts: dict[str, list[str]] = {}

    def _register(name: str, ver: str | None, hostname: str) -> None:
        name = name.strip().lower()
        if len(name) < 3 or name in _CVE_SKIP_PRODUCTS:
            return
        if name not in tech_versions or (ver and tech_versions[name] is None):
            tech_versions[name] = ver
        if hostname:
            lst = product_hosts.setdefault(name, [])
            if hostname not in lst:
                lst.append(hostname)

    for h in hosts:
        if not isinstance(h, dict):
            continue
        hostname = h.get("host", "")
        for tech in h.get("technologies", []):
            if isinstance(tech, str) and tech.strip():
                name, ver = _parse_tech(tech)
                _register(name, ver, hostname)
        server = h.get("server", "")
        if server and isinstance(server, str):
            server_clean = _re.sub(r'\s*\(.*?\)', '', server).strip()
            name, ver = _parse_tech(server_clean)
            _register(name, ver, hostname)

    products_to_query = sorted(tech_versions)[:25]
    for product in products_to_query:
        version  = tech_versions[product]
        cpe_name = _CPE_PRODUCT_NAMES.get(product)

        if version:
            if cpe_name:
                cves = _query_cpe(cpe_name, version, product)
                _time.sleep(rate_delay)
                if not cves:
                    # CPE returned nothing (version not yet in NVD) — keyword fallback
                    cves = _query_keyword(f"{product} {version}", product, min_year=2010)
                    _time.sleep(rate_delay)
            else:
                cves = _query_keyword(f"{product} {version}", product, min_year=2010)
                _time.sleep(rate_delay)
        else:
            cves = _query_keyword(product, product, min_year=2020)
            _time.sleep(rate_delay)

        affected = product_hosts.get(product, [])
        for c in cves:
            c["detected_version"] = version
            c["affected_hosts"]   = affected[:10]

        findings.extend(cves)

    # Deduplicate by CVE ID — merge affected_hosts, keep highest score
    seen: dict[str, dict] = {}
    for f in findings:
        cid = f["cve_id"]
        if cid not in seen:
            seen[cid] = f
        else:
            existing = seen[cid]
            merged = list({h for h in existing.get("affected_hosts", []) + f.get("affected_hosts", [])})
            existing["affected_hosts"] = merged[:10]
            if f["score"] > existing["score"]:
                existing["score"]    = f["score"]
                existing["severity"] = f["severity"]
                existing["vector"]   = f["vector"]

    all_unique = list(seen.values())

    # Enrich with EPSS scores
    epss_map = _fetch_epss([f["cve_id"] for f in all_unique])
    for f in all_unique:
        f["epss"] = round(epss_map.get(f["cve_id"], 0.0), 4)

    # Flag CISA KEV entries
    for f in all_unique:
        f["kev"] = _KEV_CACHE.get(f["cve_id"], False)

    # Sem versão detectada não há como saber se o alvo é vulnerável: a CVE é só "possível" (nunca crítica/alta).
    from core.finding_hygiene import unversioned_cve_severity
    for f in all_unique:
        if not f.get("detected_version"):
            f["severity_raw"] = f["severity"]
            f["severity"] = unversioned_cve_severity(f["severity"], f["kev"])
            f["verified"] = False

    # Sort: KEV first, then EPSS×CVSS descending
    all_findings = sorted(
        all_unique,
        key=lambda x: (0 if x["kev"] else 1, -(x["epss"] * x["score"]), -x["score"]),
    )

    sev_counts: dict[str, int] = {s: 0 for s in ("critical", "high", "medium", "low")}
    for f in all_findings:
        if f["severity"] in sev_counts:
            sev_counts[f["severity"]] += 1

    return {
        "total":           len(all_findings),
        "critical_count":  sev_counts["critical"],
        "high_count":      sev_counts["high"],
        "medium_count":    sev_counts["medium"],
        "low_count":       sev_counts["low"],
        "kev_count":       sum(1 for f in all_findings if f["kev"]),
        "epss_high_count": sum(1 for f in all_findings if f["epss"] >= 0.1),
        "findings":        all_findings,
        "tech_queried":    sorted(tech_versions.keys()),
        "tech_versions":   {k: v for k, v in tech_versions.items() if v},
        "scanned_at":      datetime.now().isoformat(timespec="seconds"),
    }
