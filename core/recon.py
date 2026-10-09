#!/usr/bin/env python3
"""ASM Recon Modules - standalone reconnaissance functions
No external pip deps beyond stdlib + tools available on Kali Linux
(dig, openssl, curl already present)

Usage as CLI:
  python3 recon.py email         portoseguro.com.br
  python3 recon.py certs         portoseguro.com.br
  python3 recon.py services      loja.portoseguro.com.br
  python3 recon.py asn           45.223.45.75
  python3 recon.py dns           portoseguro.com.br
  python3 recon.py github        portoseguro.com.br [--token ghp_xxx]
  python3 recon.py headers       portoseguro.com.br
  python3 recon.py typosquat     portoseguro.com.br
  python3 recon.py cloud         portoseguro.com.br [--org "Porto Seguro"]
  python3 recon.py related       portoseguro.com.br
  python3 recon.py wayback       portoseguro.com.br
  python3 recon.py shodan        portoseguro.com.br [--shodan-key KEY]
  python3 recon.py waf           portoseguro.com.br
  python3 recon.py breach        portoseguro.com.br [--hibp-key KEY]
  python3 recon.py takeover      portoseguro.com.br
  python3 recon.py all           portoseguro.com.br  [--token ghp_xxx]

Implementação dividida por assunto em core/reconlib/*.py; este módulo reexporta tudo
(incluindo helpers privados) para manter `from core.recon import ...` funcionando.
"""
import subprocess as _subprocess_real
import logging as _logging
import socket, ssl, json, re, time, sys, os
import shutil, tempfile, base64
import gzip, random, threading, urllib.request, urllib.error
from utils import cmd_trace as _ct
from utils import rate_limiter as _rl
from utils.tool_gate import gate_for as _gate_for
from urllib.request import urlopen, Request
from urllib.error   import URLError, HTTPError
from datetime       import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from core.reconlib.api_panels import (  # noqa: F401
    run_api_exposure,
)
from core.reconlib.asn import (  # noqa: F401
    _CLOUD_RANGES,
    _IP_RE,
    _KNOWN_PORTS,
    _PRIVATE_PREFIXES,
    _extract_public_ips,
    classify_service,
    detect_cloud_provider,
    get_asn_prefixes,
    get_ip_info,
    run_asn_recon,
)
from core.reconlib.base import (  # noqa: F401
    UA,
    _ALT_ACCEPT_LANGUAGES,
    _BLOCK_SIGNATURES,
    _BROWSER_HEADERS,
    _CFFI_AVAILABLE,
    _GatedSubprocess,
    _MAX_RATE_WAIT,
    _RATE_BASE,
    _RATE_JITTER,
    _SUBPROCESS_CONTEXT,
    _UA_POOL,
    _domain_state,
    _domain_state_lock,
    _get_domain_state,
    _http_get_json,
    _is_block_response,
    _log,
    _make_headers,
    _random_accept_language,
    _random_ua,
    _rate_wait,
    _record_block,
    _record_success,
    _subp,
    http_get,
    set_subprocess_context,
    subprocess,
)
from core.reconlib.breach import (  # noqa: F401
    _HR_DOMAIN_RE,
    _HR_EMAIL_CAP,
    _HR_EMAIL_RE,
    _HR_FAMILY_CAP,
    _HR_LIST_CAP,
    _HR_SKIP_KEYS,
    _HR_URL_CAP,
    _check_dehashed,
    _check_hibp_domain,
    _check_hudsonrock,
    _check_hudsonrock_email,
    _check_leakix,
    _check_trufflehog_github,
    _hr_int,
    _hr_kv_counts,
    _hr_qty,
    _hr_redacted,
    _hr_third_parties,
    _hr_url_rows,
    classify_infostealer_query,
    lookup_infostealer,
    parse_hudsonrock_domain,
    parse_hudsonrock_email,
    run_breach_check,
)
from core.reconlib.browser import (  # noqa: F401
    _API_PATHS,
    _BANNER_RULES,
    _CONTAINER_KEYWORDS,
    _CONTAINER_REGISTRIES,
    _DB_PROBES_EXTRA,
    _SERVICE_PROBES,
    _UDP_PORT_NAMES,
    _UDP_SCAN_PORTS,
    _banner_grab,
    _brute_container_orgs,
    _check_container_registry,
    _check_mssql,
    _check_mysql,
    _check_oracle,
    _check_postgresql,
    _derive_org_names_from_domain,
    _image_similarity,
    _parse_banner,
    _probe_swagger_endpoint,
    _pw_import,
    _run_kiterunner_on_hosts,
    run_api_discovery_extra,
    run_browser_crawl,
    run_browser_recon,
    run_bulk_dataset_scan,
    run_container_registry_scan,
    run_database_enum_extra,
    run_screenshot_diff,
    run_service_version_detect,
    run_udp_port_scan,
)
from core.reconlib.certs import (  # noqa: F401
    _cn,
    _count_issuers,
    _ct_from_certspotter,
    _ct_from_crtsh,
    _ct_from_shodan,
    _parse_cert_dates,
    get_ct_certs,
    get_ssl_info,
    run_cert_recon,
)
from core.reconlib.certstream import (  # noqa: F401
    run_certstream_snapshot,
)
from core.reconlib.cloud import (  # noqa: F401
    _PUBLIC_GRANTEES,
    _WRITE_PERMS,
    _check_anonymous_acl,
    _check_azure_blob,
    _check_gcp_bucket,
    _check_s3_bucket,
    _cloud_reachable,
    _curl_check,
    _org_name_variants,
    run_cloud_assets,
)
from core.reconlib.cors import (  # noqa: F401
    run_cors_scan,
)
from core.reconlib.cve import (  # noqa: F401
    _CPE_PRODUCT_NAMES,
    _CVE_SKIP_PRODUCTS,
    _KEV_CACHE,
    _KEV_LOADED,
    _fetch_epss,
    _load_kev,
    run_cve_lookup,
)
from core.reconlib.dnsutil import (  # noqa: F401
    _dns_batch,
    _dns_batch_short,
    dns_records,
    run_dns_bruteforce,
    run_dnssec_check,
    run_zone_transfer,
)
from core.reconlib.email_sec import (  # noqa: F401
    DKIM_SELECTORS,
    check_bimi,
    check_dkim,
    check_dmarc,
    check_mx,
    check_spf,
    email_spoofability,
    run_email_recon,
)
from core.reconlib.extra_tools import (  # noqa: F401
    run_git_leaks,
    run_s3_scanner,
)
from core.reconlib.ffuf import (  # noqa: F401
    run_content_discovery,
)
from core.reconlib.github_org import (  # noqa: F401
    run_github_repos,
    run_github_subdomains,
)
from core.reconlib.graphql import (  # noqa: F401
    run_graphql_discovery,
)
from core.reconlib.headers import (  # noqa: F401
    HEADER_CHECKS,
    _VENDOR_FINGERPRINTS,
    _fetch_headers,
    run_headers_bulk,
    run_security_headers,
    run_vendor_fingerprint,
)
from core.reconlib.infra import (  # noqa: F401
    run_default_creds,
    run_host_header_injection,
    run_infra_exposure,
    run_open_redirect_check,
    run_s3_write_check,
    run_smtp_probe,
    run_snmp_probe,
    run_waf_bypass_test,
)
from core.reconlib.jsrecon import (  # noqa: F401
    _ENDPOINT_RE,
    _FP_LABEL_RE,
    _FP_PASSWORD_RE,
    _INTERESTING_RE,
    _JS_NOISE_HOSTS,
    _JS_PATH_DATE_RE,
    _JS_PATH_MIME_RE,
    _JS_PATH_SDK_RE,
    _JS_PATH_TZ_RE,
    _JS_SECRET_PATTERNS,
    _JS_WAF_HOSTS,
    _WAF_CHALLENGE_URL_RE,
    _analyze_js_content,
    _analyze_source_map,
    _decode_jwt_unverified,
    _is_fp_secret,
    _js_host_is_noise,
    _js_path_is_noise,
    _jwt_finding_detail,
    _playwright_js_capture,
    _validate_secret,
    run_js_recon,
)
from core.reconlib.leaks import (  # noqa: F401
    _dns_resolves,
    _fetch_and_scan_github_file,
    _is_high_value_github_file,
    check_exposed_git,
    run_leaks_recon,
    search_codebase_leaks,
    search_github,
)
from core.reconlib.mobile import (  # noqa: F401
    _discover_play_packages,
    _parse_apkleaks_output,
    run_apk_recon,
)
from core.reconlib.origin import (  # noqa: F401
    _ORIGIN_SUB_PREFIXES,
    _od_title,
    run_origin_discovery,
)
from core.reconlib.portscan import (  # noqa: F401
    _DEFAULT_SCAN_PORTS,
    _HIGH_RISK_PORTS,
    _RISKY_PORTS,
    run_port_scan,
)
from core.reconlib.postman import (  # noqa: F401
    _POSTMAN_DOC_URL,
    _POSTMAN_GATEWAY_URL,
    _POSTMAN_SEARCH_URL,
    _POSTMAN_SECRET_PATTERNS,
    _github_postman_search,
    _postman_fetch_collection,
    _postman_public_search,
    _postman_scan_collection_json,
    run_postman_collections,
)
from core.reconlib.related import (  # noqa: F401
    _BRAND_PREFIXES,
    _BRAND_TLDS,
    _rdap_registrant,
    _related_crtsh_org,
    _related_reverse_ip,
    _related_tld_candidates,
    run_related_domains,
    run_reverse_whois,
)
from core.reconlib.salesforce import (  # noqa: F401
    _is_responsive,
    _SALESFORCE_ADMIN_CHECKS,
    _SALESFORCE_COMMUNITY_CHECKS,
    _SALESFORCE_PATTERNS,
    _is_salesforce_host,
    run_jwt_analysis,
    run_salesforce_recon,
    run_xss_scan,
)
from core.reconlib.scoring import (  # noqa: F401
    score_host,
)
from core.reconlib.screenshots import (  # noqa: F401
    _gowitness_v3_to_url,
    run_screenshots,
)
from core.reconlib.services import (  # noqa: F401
    EXPOSED_PATHS,
    _probe_url,
    run_services_recon,
)
from core.reconlib.shodan import (  # noqa: F401
    run_shodan,
)
from core.reconlib.supply_chain import (  # noqa: F401
    _JS_LIBRARIES,
    run_supply_chain_scan,
)
from core.reconlib.takeover import (  # noqa: F401
    _TAKEOVER_CNAME_TARGETS,
    _TAKEOVER_SIGNATURES,
    _check_takeover,
    run_takeover_check,
)
from core.reconlib.typosquat import (  # noqa: F401
    _BROKER_NS,
    _CC_TLDS,
    _TLD_SWAPS,
    _check_typo,
    _resolve_domain,
    _typo_variants,
    _whois_registrant,
    run_opensquat_monitor,
    run_typosquatting,
)
from core.reconlib.vhost import (  # noqa: F401
    run_vhost_discovery,
)
from core.reconlib.waf import (  # noqa: F401
    _WAF_CHALLENGE_SIGNATURES,
    _WAF_SIGNATURES,
    _detect_waf,
    _is_waf_challenge_body,
    run_waf_detection,
)
from core.reconlib.wayback import (  # noqa: F401
    _verify_live,
    _INTERESTING_EXT,
    _INTERESTING_PATH,
    _wayback_cdx_urls,
    run_wayback,
)
try:  # curl_cffi é opcional
    from core.reconlib.base import _cffi_requests  # noqa: F401
except ImportError:
    pass



# ── Run all for a company ──

def run_all(company: dict, hosts: list, findings: list,
            github_token: str = None, shodan_key: str = None,
            hibp_key: str = None, nvd_key: str = None,
            verbose: bool = False) -> dict:
    domain  = company["domains"][0] if company.get("domains") else ""
    domains = company.get("domains", [domain])
    org     = company.get("name", domain.split(".")[0])
    results = {}

    _v = lambda msg: print(f"  [*] {msg}") if verbose else None

    # ── Fast passive modules ──
    _v(f"Email Security — {domain}")
    results["email"] = run_email_recon(domain)

    _v(f"Full DNS Records — {domain}")
    results["dns"] = dns_records(domain)

    _v(f"Certificate Transparency — {domain}")
    results["certs"] = run_cert_recon(domain, hosts)

    _v(f"ASN / IP Intelligence")
    results["asn"] = run_asn_recon(hosts)

    _v(f"Typosquatting — {domain}")
    results["typosquat"] = run_typosquatting(domain)

    _v(f"Related Domains — {domain}")
    results["related"] = run_related_domains(domain)

    _v(f"Cloud Asset Discovery — {org}")
    results["cloud"] = run_cloud_assets(domains, org)

    _v(f"Wayback / GAU URL mining — {domain}")
    results["wayback"] = run_wayback(domain)

    _v(f"Breach / Credential Intelligence — {domain}")
    results["breach"] = run_breach_check(domain, hibp_key)

    _v(f"Leaks & Secrets")
    results["leaks"] = run_leaks_recon(domain, hosts, github_token)

    # ── Active network modules ──
    _v(f"Security Headers (up to 30 live hosts)")
    results["headers"] = run_headers_bulk(hosts)

    _v(f"WAF Detection")
    results["waf"] = run_waf_detection(hosts)

    _v(f"Subdomain Takeover check")
    results["takeover"] = run_takeover_check(hosts)

    _v(f"Port Scan")
    results["portscan"] = run_port_scan(hosts)

    _v(f"Virtual Host Discovery")
    results["vhost"] = run_vhost_discovery(hosts, domains)

    _v(f"Exposed Services & Paths (top 10 live hosts)")
    services_all = []
    for h in [h for h in hosts if h.get("ports")][:10]:
        _v(f"  probing {h['host']}")
        services_all.extend(run_services_recon(h["host"]))
    results["services"] = {
        "findings":   sorted(services_all,
                             key=lambda x: ["critical","high","medium","low"].index(x["severity"])),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }

    # ── API-dependent modules ──
    if shodan_key:
        _v(f"Shodan Intelligence")
        results["shodan"] = run_shodan(hosts, shodan_key)

    if nvd_key or True:   # NVD works without key (rate limited)
        _v(f"CVE Lookup — tech stack vs NVD")
        results["cve"] = run_cve_lookup(hosts, nvd_key or "")

    _v(f"JavaScript Recon — crawl + secret extraction")
    results["js"] = run_js_recon(domains, hosts)

    _v(f"DNS Brute-force & Permutations — {domain}")
    results["dns_brute"] = run_dns_bruteforce(domain, hosts)

    _v(f"API/Panel Exposure — nuclei scan")
    results["api_panels"] = run_api_exposure(hosts, domains)

    _v(f"CertStream — new certificate monitoring")
    results["certstream"] = run_certstream_snapshot(domains, duration_sec=60)

    _v(f"Screenshots — visual inventory")
    results["screenshot"] = run_screenshots(hosts, domains)

    # ── Risk scoring ──
    _v(f"Risk scoring hosts")
    results["host_scores"] = {h["host"]: score_host(h, findings) for h in hosts}

    return results


# ── CLI entry ──

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="ASM Recon Platform — modular recon engine")
    ap.add_argument("module", choices=[
        "email","certs","asn","services","leaks","dns",
        "headers","typosquat","cloud","related","wayback",
        "shodan","waf","breach","takeover","portscan",
        "vhost","cve","all",
    ])
    ap.add_argument("target", help="Domain or IP")
    ap.add_argument("--token",       help="GitHub token for leaks module")
    ap.add_argument("--hosts",       help="JSON file with hosts array [{host,ip,ports}]")
    ap.add_argument("--org",         help="Organisation name for cloud discovery")
    ap.add_argument("--shodan-key",  help="Shodan API key")
    ap.add_argument("--hibp-key",    help="HaveIBeenPwned API key")
    ap.add_argument("--dehashed-key",help="DeHashed API key")
    args = ap.parse_args()

    hosts = []
    if args.hosts and Path(args.hosts).exists():
        hosts = json.loads(Path(args.hosts).read_text())

    m = args.module
    if m == "email":
        print(json.dumps(run_email_recon(args.target), indent=2))
    elif m == "certs":
        print(json.dumps(run_cert_recon(args.target, hosts), indent=2))
    elif m == "asn":
        print(json.dumps(run_asn_recon(hosts or [{"ip": args.target}]), indent=2))
    elif m == "services":
        print(json.dumps(run_services_recon(args.target), indent=2))
    elif m == "leaks":
        print(json.dumps(run_leaks_recon(args.target, hosts, args.token), indent=2))
    elif m == "dns":
        print(json.dumps(dns_records(args.target), indent=2))
    elif m == "headers":
        print(json.dumps(run_security_headers(args.target), indent=2))
    elif m == "typosquat":
        print(json.dumps(run_typosquatting(args.target), indent=2))
    elif m == "cloud":
        print(json.dumps(run_cloud_assets([args.target], args.org or ""), indent=2))
    elif m == "related":
        print(json.dumps(run_related_domains(args.target), indent=2))
    elif m == "wayback":
        print(json.dumps(run_wayback(args.target), indent=2))
    elif m == "shodan":
        key = getattr(args, "shodan_key", None) or os.environ.get("SHODAN_API_KEY","")
        print(json.dumps(run_shodan(hosts or [{"ip": args.target}], key), indent=2))
    elif m == "waf":
        print(json.dumps(run_waf_detection(hosts or [{"host": args.target, "ports": ["443"]}]), indent=2))
    elif m == "breach":
        print(json.dumps(run_breach_check(args.target, getattr(args, "hibp_key", None),
                                          getattr(args, "dehashed_key", None)), indent=2))
    elif m == "takeover":
        print(json.dumps(run_takeover_check(hosts or [{"host": args.target}]), indent=2))
    elif m == "portscan":
        print(json.dumps(run_port_scan(hosts or [{"ip": args.target}]), indent=2))
    elif m == "vhost":
        print(json.dumps(run_vhost_discovery(hosts or [], [args.target]), indent=2))
    elif m == "browser":
        print(json.dumps(run_browser_recon(args.target, screenshot_dir=args.output or "/tmp"), indent=2, default=str))
    elif m == "supply_chain":
        nvd_key = os.environ.get("NVD_API_KEY","")
        print(json.dumps(run_supply_chain_scan(hosts, nvd_key), indent=2))
    elif m == "cve":
        nvd_key = os.environ.get("NVD_API_KEY","")
        print(json.dumps(run_cve_lookup(hosts, nvd_key), indent=2))
    elif m == "all":
        co = {"domains": [args.target], "name": args.org or args.target.split(".")[0]}
        nvd_key = os.environ.get("NVD_API_KEY","")
        print(json.dumps(run_all(co, hosts, [],
                                 github_token=args.token,
                                 shodan_key=getattr(args, "shodan_key", None),
                                 hibp_key=getattr(args, "hibp_key", None),
                                 nvd_key=nvd_key,
                                 verbose=True), indent=2))
