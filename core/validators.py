"""
Validators + dedup + filtering for pipeline outputs.
No external dependencies beyond stdlib.
Applied at all merge points in pipeline.py to reduce noise.
"""

import fnmatch
import ipaddress
import re
from typing import Any


# ── RFC 1035 label: 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen ──
_RFC1035_LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def filter_subdomain(sub: str, root_domain: str) -> str | None:
    """Validate a subdomain string. Returns normalized sub or None if invalid."""
    if not isinstance(sub, str) or not sub:
        return None
    sub = sub.strip().lower().lstrip(".")
    
    # Reject wildcards (DNS wildcard patterns like *., %., etc)
    if sub.startswith("*") or sub.startswith("%"):
        return None
    
    # Must end with root_domain
    root = root_domain.lower().lstrip(".")
    if "*" in root:
        if fnmatch.fnmatchcase(sub, root):
            return sub
        return None
    if not (sub == root or sub.endswith("." + root)):
        return None
    
    # Remove trailing dot (FQDN notation)
    sub = sub.rstrip(".")
    
    # Check length limit (253 chars max for FQDN)
    if len(sub) > 253:
        return None
    
    # Check each label
    labels = sub.split(".")
    for label in labels:
        if not _RFC1035_LABEL.match(label):
            return None
    
    return sub


def filter_public_ip(ip: str) -> str | None:
    """Reject private/reserved/multicast/loopback IPs. Returns IP string or None."""
    if not isinstance(ip, str) or not ip.strip():
        return None
    ip = ip.strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
        return None
    if addr.is_unspecified:
        return None
    
    return str(addr)


def dedup_findings(findings: list[dict], kind: str = "general") -> list[dict]:
    """Deduplicate findings by a composite key depending on `kind`.

    kind options:
      - "nuclei":   (template_id, host, matched_at)
      - "subdomain": (value,)  — value is the subdomain
      - "cve":      (cve_id, library or product)
      - "secret":   (value, host)
      - "general":  (type_or_category, title_or_value, host)
    """
    seen: set[tuple] = set()
    deduped: list[dict] = []

    for f in findings:
        if kind == "nuclei":
            key = (f.get("template_id") or f.get("template", ""), f.get("host", ""), f.get("matched_at") or f.get("url", ""))
        elif kind == "subdomain":
            key = (f.get("value", "").lower().strip("."),)
        elif kind == "cve":
            key = (f.get("cve_id", ""), f.get("library", "") or f.get("product", ""))
        elif kind == "secret":
            key = (f.get("value", "")[:80], f.get("host", ""))
        else:
            # sort_key uses type->category->module fallback so different finding kinds
            # don't collapse into the same empty-string key
            sort_key = (
                f.get("type") or f.get("category") or f.get("module") or f.get("key", ""),
                (f.get("value") or f.get("title") or f.get("name") or f.get("key", ""))[:120],
                f.get("host", ""),
            )
            key = sort_key

        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped


# Nuclei templates that are allowlisted for severity="info" (pure discovery, high value)
_NUCLEI_INFO_ALLOWLIST: set[str] = {
    "tech-detect", "dns-waf-detect", "http-missing-security-headers",
    "dns-info", "http-info", "ssl-info", "whois-info",
    "ssl-issuer", "cname-service", "cname-fingerprint",
    "nameserver-fingerprint", "mx-fingerprint",
    "caa-fingerprint", "smtp-detect", "pop3-detect",
    "imap-detect", "ftp-detect", "ssh-detect", "rdp-detect",
    "dns-detect", "tls-version", "http-methods",
    "waf-detect", "cdn-detect", "cms-detect",
}


def allow_nuclei_info(finding: dict) -> bool:
    """Return True if this nuclei finding should be kept despite severity=info."""
    severity = str(finding.get("severity", "")).lower()
    if severity != "info":
        return True  # keep everything that's not info

    template_id = str(finding.get("template_id") or finding.get("template") or "").lower()
    # Keep info-level findings only if template is in allowlist
    for allowed in _NUCLEI_INFO_ALLOWLIST:
        if allowed in template_id:
            return True

    return False


def filter_nuclei_info(findings: list[dict]) -> list[dict]:
    """Remove nuclei findings with severity=info unless template is allowlisted."""
    return [f for f in findings if allow_nuclei_info(f)]
