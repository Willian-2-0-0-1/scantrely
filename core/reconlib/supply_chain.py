"""Supply Chain Scan — Client-side JS Library CVE Check — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from datetime import datetime
from core.reconlib.base import _http_get_json, _log

# ── Supply Chain Scan — Client-side JS Library CVE Check ──
# Scans JS/frontend libraries detected by whatweb/wappalyzer for known CVEs.
# Uses the NVD API v2 keyword search for precise product+version matching.

# Known JS libraries (vendor:product mappings and npm/PyPI equivalents)
_JS_LIBRARIES: set[str] = {
    "jquery", "jquery-ui", "jquery.migrate", "jquery-form",
    "bootstrap", "bootstrap-sass", "bootstrap-select",
    "react", "react-dom", "react-router", "react-redux", "react-native",
    "react-bootstrap", "react-select", "react-hook-form", "next.js", "next",
    "vue.js", "vue", "vuex", "vue-router", "nuxt.js", "nuxt", "vuetify",
    "angular.js", "angularjs", "angular", "angular-material", "angular-cli",
    "svelte", "sveltekit",
    "preact", "ember.js", "ember", "backbone.js", "backbone",
    "lodash", "lodash-es", "underscore.js", "underscore",
    "moment.js", "moment", "dayjs", "luxon",
    "d3.js", "d3", "three.js", "three",
    "chart.js", "chartjs", "highcharts", "highstock",
    "axios", "fetch", "whatwg-fetch", "superagent",
    "webpack", "babel", "babel-core", "babel-runtime",
    "eslint", "prettier",
    "socket.io", "socket.io-client",
    "swagger-ui", "swagger", "redoc",
    "graphql", "apollo-client", "apollo", "relay",
    "redux", "mobx", "zustand", "recoil",
    "tailwindcss", "tailwind", "postcss",
    "marked", "highlight.js", "prismjs", "prism",
    "mathjax", "katex",
    "popper.js", "popper", "core-js",
    "animate.css", "font-awesome", "line-awesome",
    "leaflet", "openlayers",
    "datatables", "datatables.net",
    "fullcalendar", "select2", "dropzone", "sortablejs",
    "gsap", "tweenmax", "tweenlite",
    "alpine.js", "alpinejs",
    "htmx", "stimulus", "turbo",
    "petite-vue", "solid.js", "solidjs",
    "lit", "lit-element", "lit-html",
    "astro",
}


def run_supply_chain_scan(hosts: list, nvd_key: str = "") -> dict:
    """Scan JS/frontend libraries for known CVEs.

    Parses technology strings from host data (e.g. 'jQuery:3.6.0'),
    filters for JS/frontend libraries, and queries NVD for each
    product@version to find exploitable client-side vulnerabilities.

    Returns:
      {"total":int, "critical":int, "high":int, "medium":int, "low":int,
       "findings":[{"cve_id":str,"library":str,"version":str,"score":float,
                    "severity":str,"desc":str,"url":str,"affected_hosts":[str]}],
       "libraries_scanned":[str], "scanned_at":str}
    """
    import time as _time
    from urllib.parse import urlencode
    import re as _re

    findings: list[dict] = []
    seen_cves: set[str] = set()

    # ── Extract JS libraries with versions from host technologies ──
    # host tech format: "product:version", "Product X.Y", "Product/1.2.3"
    lib_versions: dict[str, tuple[str, list[str]]] = {}  # {product_lower: (version, [hosts])}

    for h in hosts:
        if not isinstance(h, dict):
            continue
        hostname = h.get("host", "")
        for tech in h.get("technologies", []):
            if not isinstance(tech, str) or not tech.strip():
                continue
            tech_clean = tech.strip()

            # Parse "name:version", "name version", "name/version"
            name, version = None, None
            for sep in (":", " ", "/"):
                idx = tech_clean.find(sep)
                if idx > 0:
                    name = tech_clean[:idx].strip()
                    ver = tech_clean[idx + 1:].strip().split()[0]
                    # Version must look like a version number
                    if _re.match(r"^\d[\d.]*", ver) and len(name) >= 2:
                        version = ver
                        break
            if not name:
                name = tech_clean
            if not version:
                continue  # skip unversioned libraries

            name_lower = name.lower().rstrip("0123456789.-_ ")

            # Check if this is a known JS/frontend library
            if name_lower not in _JS_LIBRARIES:
                continue

            key = name_lower
            if key not in lib_versions:
                lib_versions[key] = (version, [])
            lib_versions[key][1].append(hostname)

    if not lib_versions:
        return {
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "findings": [], "libraries_scanned": [],
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
        }

    # ── Query NVD for each library@version ──
    headers = {"User-Agent": "ASM-Platform/1.0", "Accept": "application/json"}
    if nvd_key:
        headers["apiKey"] = nvd_key
    rate_delay = 0.6 if nvd_key else 6.0

    scanned_libs = []
    for name_lower, (version, affected_hosts) in sorted(lib_versions.items()):
        keyword = f"{name_lower} {version}"
        scanned_libs.append(f"{name_lower}@{version}")

        try:
            params = {"keywordSearch": keyword, "resultsPerPage": "15"}
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode(params)
            data = _http_get_json(url, timeout=15, extra_headers=headers)
            if not isinstance(data, dict):
                continue

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id or cve_id in seen_cves:
                    continue

                descs = cve.get("descriptions", [])
                desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

                # Score extraction
                metrics = cve.get("metrics", {})
                score, severity, vector = 0.0, "low", ""
                for mkey in ("cvssMetricV31", "cvssMetricV30"):
                    ms = metrics.get(mkey, [])
                    if ms:
                        cvss = ms[0].get("cvssData", {})
                        score = cvss.get("baseScore", 0.0)
                        severity = (cvss.get("baseSeverity") or ms[0].get("baseSeverity", "")).lower()
                        vector = cvss.get("vectorString", "")
                        break

                if score < 4.0:
                    continue  # skip low/info CVEs

                seen_cves.add(cve_id)
                findings.append({
                    "cve_id":    cve_id,
                    "library":   name_lower,
                    "version":   version,
                    "score":     score,
                    "severity":  severity or ("critical" if score >= 9 else "high" if score >= 7 else "medium"),
                    "desc":      desc[:400],
                    "vector":    vector,
                    "url":       f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "published": cve.get("published", "")[:10],
                    "affected_hosts": affected_hosts[:10],
                })
        except Exception:
            _log.debug('recon.py:724 erro ignorado', exc_info=True)

        _time.sleep(rate_delay)

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: (sev_order.get(x["severity"], 4), -(x.get("score", 0) or 0)))

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    return {
        "total":           len(findings),
        "critical":        sev_counts["critical"],
        "high":            sev_counts["high"],
        "medium":          sev_counts["medium"],
        "low":             sev_counts["low"],
        "findings":        findings,
        "libraries_scanned": scanned_libs,
        "scanned_at":      datetime.now().isoformat(timespec="seconds"),
    }
