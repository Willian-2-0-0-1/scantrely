"""Subdomain Takeover Detection — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from datetime import datetime
from core.reconlib.base import _subp, http_get
from core.reconlib.typosquat import _resolve_domain
from core.reconlib.waf import _is_waf_challenge_body

# ── Subdomain Takeover Detection ──

_TAKEOVER_SIGNATURES = {
    "GitHub Pages":       ["there isn't a github pages site here","for root domain"],
    "AWS S3":             ["nosuchbucket","the specified bucket does not exist","no such key"],
    "Heroku":             ["no such app","herokucdn.com","there's nothing here"],
    "Shopify":            ["sorry, this shop is currently unavailable"],
    "Fastly":             ["fastly error: unknown domain"],
    "Ghost":              ["the thing you were looking for is no longer here"],
    "Cargo":              ["if you're moving your domain away from cargo"],
    "Tumblr":             ["there's nothing here","whatever you were looking for doesn't exist"],
    "Surge.sh":           ["project not found"],
    "Readme.io":          ["project doesnt exist... yet!"],
    "Statuspage":         ["you are being redirected","statuspage.io"],
    "Pantheon":           ["the gods are wise","pantheon.io"],
    "WP Engine":          ["the site you were looking for couldn't be found"],
    "Azure":              ["404 web site not found","azurewebsites.net"],
    "Zendesk":            ["help center closed"],
    "Intercom":           ["this page is reserved for artists"],
    "Freshdesk":          ["there is no helpdesk here"],
    "Unbounce":           ["the requested url was not found"],
    "Bitbucket":          ["repository not found"],
    # New entries
    "Vercel":             ["the deployment could not be found","this deployment has been disabled"],
    "Netlify":            ["not found - request id"],
    "Firebase":           ["there is no firebase app"],
    "Render":             ["service not found"],
    "Railway":            ["no backend was found"],
    "Fly.io":             ["404 - not found"],
    "Launchrock":         ["it looks like you may have taken a wrong turn somewhere"],
    "Pingdom":            ["sorry, couldn't find the status page"],
    "UserVoice":          ["this uservoice subdomain is currently available"],
    "Tilda":              ["domain has not been added","this website is currently not available"],
    "HubSpot":            ["does not exist"],
    "Squarespace":        ["no such account"],
    "Wix":                ["this page isn't available"],
    "JetBrains Space":    ["the page you're looking for doesn't exist"],
    "Hashnode":           ["blog not found"],
}


_TAKEOVER_CNAME_TARGETS = [
    "amazonaws.com", "azurewebsites.net", "cloudfront.net", "github.io",
    "herokuapp.com", "shopify.com", "fastly.net", "surge.sh",
    "readme.io", "statuspage.io", "pantheon.io", "wpengine.com",
    "zendesk.com", "intercom.io", "freshdesk.com", "unbounce.com",
    "bitbucket.io", "ghost.io", "cargo.site", "tumblr.com",
    # New entries
    "vercel.app", "vercel-dns.com", "netlify.app", "netlify.com",
    "firebaseapp.com", "web.app", "onrender.com", "up.railway.app",
    "fly.dev", "launchrock.com", "pingdom.net", "uservoice.com",
    "tilda.ws", "hubspotpagebuilder.com", "squarespace.com",
    "wixsite.com", "myjetbrains.com", "hashnode.network",
]


def _check_takeover(host: str) -> dict | None:
    """Check if a host is vulnerable to subdomain takeover."""
    # Get CNAME
    try:
        r = _subp(["dig","+short","+time=2","+tries=1","CNAME", host],
                           capture_output=True, text=True, timeout=5)
        cname = r.stdout.strip().rstrip(".")
    except Exception:
        cname = ""

    # Check if CNAME points to a known 3rd party service
    cname_target = None
    for target in _TAKEOVER_CNAME_TARGETS:
        if cname.endswith(target):
            cname_target = target
            break

    if not cname_target:
        return None

    # Check if host resolves
    ips = _resolve_domain(host)
    if not ips:
        # NXDOMAIN = dangling CNAME
        return {
            "host": host, "cname": cname, "cname_target": cname_target,
            "severity": "critical",
            "issue": f"NXDOMAIN — dangling CNAME to {cname_target} (unclaimed service)",
            "takeover_possible": True,
        }

    # Check response body for takeover signatures
    _, raw, _ = http_get(f"https://{host}", timeout=6, retries=1)
    if not raw:
        _, raw, _ = http_get(f"http://{host}", timeout=6, retries=1)
    body = (raw[:2000].decode("utf-8", "ignore") if raw else "").lower()

    # If the response is a generic WAF/CDN challenge page, its text can
    # accidentally match a takeover signature (e.g. "access denied",
    # "does not exist") without the host actually being unclaimed.
    if not _is_waf_challenge_body(body):
        for service, sigs in _TAKEOVER_SIGNATURES.items():
            for sig in sigs:
                if sig in body:
                    return {
                        "host": host, "cname": cname, "cname_target": cname_target,
                        "severity": "critical",
                        "issue": f"Unclaimed {service} — takeover likely possible",
                        "takeover_possible": True,
                        "service": service,
                    }

    return {
        "host": host, "cname": cname, "cname_target": cname_target,
        "severity": "medium",
        "issue": f"CNAME → {cname_target} — verify service is active",
        "takeover_possible": False,
    }



def run_takeover_check(hosts: list) -> dict:
    """Check all hosts for subdomain takeover vulnerabilities."""
    all_hosts = [h["host"] for h in hosts]
    results = []

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_check_takeover, h): h for h in all_hosts}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)

    critical = [r for r in results if r["severity"] == "critical"]
    return {
        "results":  sorted(results, key=lambda r: ["critical","medium"].index(r["severity"])),
        "critical_count": len(critical),
        "total_checked":  len(all_hosts),
        "scanned_at":     datetime.now().isoformat(timespec="seconds"),
    }
