"""
Incremental scan checkpoints — fingerprint live hosts and detect changes.

Flow:
  1. fingerprint_hosts(urls)  → dict[url, HostFingerprint]
  2. load_checkpoints(cid)    → dict[url, HostFingerprint]
  3. diff(old, new)           → CheckpointDiff
  4. save_checkpoints(cid, new)

Only hosts in diff.changed + diff.new need a deep re-scan.
"""

from __future__ import annotations
import hashlib, json, re, time, concurrent.futures
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup

CHECKPOINTS_DIR = Path(__file__).parent / "checkpoints"
CHECKPOINTS_DIR.mkdir(exist_ok=True)

# Headers that indicate tech stack / config changes worth tracking
_TRACKED_HEADERS = [
    "server", "x-powered-by", "x-frame-options", "content-security-policy",
    "strict-transport-security", "x-content-type-options", "access-control-allow-origin",
    "x-aspnet-version", "x-aspnetmvc-version",
]

# Patterns to strip from body before hashing (dynamic/session-specific content)
_DYNAMIC_PATTERNS = [
    re.compile(r'csrf[_-]?token["\']?\s*[:=]\s*["\']?[\w\-]+', re.I),
    re.compile(r'nonce=["\'][\w+/=]+["\']', re.I),
    re.compile(r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'),       # ISO timestamps
    re.compile(r'\b\d{10,13}\b'),                                    # unix timestamps
    re.compile(r'["\']?_cache_buster["\']?\s*[:=]\s*["\']?[\w]+', re.I),
    re.compile(r'viewstate["\']?\s*value=["\'][^"\']{20,}["\']', re.I),
]


@dataclass
class HostFingerprint:
    url: str
    status_code: int
    title: str
    server: str
    content_hash: str       # sha256 of normalized body
    js_hash: str            # sha256 of sorted JS src URLs
    headers_hash: str       # sha256 of tracked security headers
    content_length: int
    redirect_url: str       # final URL after redirects
    js_urls: list[str] = field(default_factory=list)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat(timespec="seconds")

    def changed_fields(self, other: "HostFingerprint") -> list[str]:
        """Return list of field names that differ between two fingerprints."""
        changes = []
        if self.status_code != other.status_code:
            changes.append("status_code")
        if self.content_hash != other.content_hash:
            changes.append("content")
        if self.js_hash != other.js_hash:
            changes.append("javascript")
        if self.headers_hash != other.headers_hash:
            changes.append("security_headers")
        if self.title != other.title:
            changes.append("title")
        if self.redirect_url != other.redirect_url:
            changes.append("redirect")
        return changes


@dataclass
class CheckpointDiff:
    new: list[str] = field(default_factory=list)          # never seen before
    changed: list[str] = field(default_factory=list)       # hash changed
    unchanged: list[str] = field(default_factory=list)     # identical
    removed: list[str] = field(default_factory=list)       # was there, now gone
    change_details: dict[str, list[str]] = field(default_factory=dict)  # url → changed fields

    @property
    def needs_rescan(self) -> list[str]:
        return self.new + self.changed

    def summary(self) -> str:
        return (f"{len(self.new)} new, {len(self.changed)} changed, "
                f"{len(self.unchanged)} unchanged, {len(self.removed)} removed")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _normalize_body(html: str) -> str:
    """Strip dynamic content before hashing."""
    for pat in _DYNAMIC_PATTERNS:
        html = pat.sub("", html)
    # Collapse whitespace
    html = re.sub(r'\s+', ' ', html)
    return html.strip()


def _extract_title(soup: BeautifulSoup) -> str:
    tag = soup.find("title")
    return tag.get_text(strip=True)[:200] if tag else ""


def _extract_js_urls(soup: BeautifulSoup, base_url: str) -> list[str]:
    urls = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"].strip()
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            src = urljoin(base_url, src)
        # Only include same-origin or relative JS (skip CDN noise that changes often)
        urls.append(src)
    return sorted(set(urls))


def fingerprint_host(url: str, timeout: int = 10) -> Optional[HostFingerprint]:
    """Fetch url and compute its fingerprint. Returns None on connection error."""
    try:
        from utils.circuit_breaker import guarded_httpx
        resp = guarded_httpx(
            "GET",
            url,
            follow_redirects=True,
            verify=True,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 ASM-Checkpoint/1.0"},
        )

        body = resp.text
        soup = BeautifulSoup(body, "html.parser")

        title = _extract_title(soup)
        js_urls = _extract_js_urls(soup, str(resp.url))
        normalized = _normalize_body(body)

        # Security-relevant headers hash
        tracked = {h: resp.headers.get(h, "") for h in _TRACKED_HEADERS}
        headers_hash = _sha256(json.dumps(tracked, sort_keys=True))

        return HostFingerprint(
            url=url,
            status_code=resp.status_code,
            title=title,
            server=resp.headers.get("server", ""),
            content_hash=_sha256(normalized),
            js_hash=_sha256("|".join(js_urls)),
            headers_hash=headers_hash,
            content_length=len(body),
            redirect_url=str(resp.url) if str(resp.url) != url else "",
            js_urls=js_urls,
        )
    except Exception:
        return None


def fingerprint_hosts(
    urls: list[str],
    max_workers: int = 20,
    timeout: int = 10,
    progress_cb=None,
) -> dict[str, HostFingerprint]:
    """Fingerprint a list of URLs concurrently. Returns {url: fingerprint}."""
    results: dict[str, HostFingerprint] = {}
    done = 0

    def _work(url):
        nonlocal done
        fp = fingerprint_host(url, timeout=timeout)
        done += 1
        if progress_cb:
            progress_cb(done, len(urls), url)
        return url, fp

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for url, fp in ex.map(_work, urls):
            if fp is not None:
                results[url] = fp

    return results


# ── Persistence ───────────────────────────────────────────────────────────────

def _checkpoint_path(company_id: str) -> Path:
    return CHECKPOINTS_DIR / f"{company_id}.json"


def load_checkpoints(company_id: str) -> dict[str, HostFingerprint]:
    path = _checkpoint_path(company_id)
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text())
        return {url: HostFingerprint(**fp) for url, fp in raw.items()}
    except Exception:
        return {}


def save_checkpoints(company_id: str, fingerprints: dict[str, HostFingerprint]):
    path = _checkpoint_path(company_id)
    data = {url: asdict(fp) for url, fp in fingerprints.items()}
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))


# ── Diff ─────────────────────────────────────────────────────────────────────

def diff_checkpoints(
    old: dict[str, HostFingerprint],
    new: dict[str, HostFingerprint],
) -> CheckpointDiff:
    result = CheckpointDiff()
    old_urls = set(old)
    new_urls = set(new)

    for url in new_urls - old_urls:
        result.new.append(url)

    for url in old_urls - new_urls:
        result.removed.append(url)

    for url in old_urls & new_urls:
        changed = new[url].changed_fields(old[url])
        if changed:
            result.changed.append(url)
            result.change_details[url] = changed
        else:
            result.unchanged.append(url)

    return result


# ── High-level scan helper ────────────────────────────────────────────────────

def run_checkpoint_scan(
    company_id: str,
    hosts: list[str],
    schemes: tuple = ("https", "http"),
    max_workers: int = 30,
    progress_cb=None,
) -> dict:
    """
    Fingerprint all hosts, compare with stored checkpoints, save new ones.

    Returns:
      {
        "diff": CheckpointDiff,
        "new_fingerprints": {url: HostFingerprint},
        "needs_rescan": [url, ...],
        "summary": "3 new, 7 changed, 142 unchanged, 0 removed",
        "first_run": bool,
      }
    """
    # Build URL list — try https first, fall back to http
    urls = []
    for h in hosts:
        if h.startswith("http://") or h.startswith("https://"):
            urls.append(h)
        else:
            for scheme in schemes:
                urls.append(f"{scheme}://{h}")

    old = load_checkpoints(company_id)
    first_run = len(old) == 0

    new_fps = fingerprint_hosts(urls, max_workers=max_workers, progress_cb=progress_cb)
    diff = diff_checkpoints(old, new_fps)
    save_checkpoints(company_id, new_fps)

    return {
        "diff": diff,
        "new_fingerprints": new_fps,
        "needs_rescan": diff.needs_rescan,
        "summary": diff.summary(),
        "first_run": first_run,
        "total_fingerprinted": len(new_fps),
    }


if __name__ == "__main__":
    import sys, argparse

    ap = argparse.ArgumentParser(description="ASM Checkpoint Scanner")
    ap.add_argument("company_id")
    ap.add_argument("hosts", nargs="+")
    ap.add_argument("--workers", type=int, default=20)
    args = ap.parse_args()

    def progress(done, total, url):
        print(f"\r[{done}/{total}] {url[:60]:<60}", end="", flush=True)

    print(f"[*] Fingerprinting {len(args.hosts)} hosts for {args.company_id}…")
    result = run_checkpoint_scan(args.company_id, args.hosts,
                                  max_workers=args.workers, progress_cb=progress)
    print()
    diff = result["diff"]
    print(f"[+] {result['summary']}")
    if diff.changed:
        print(f"\n[!] Changed hosts ({len(diff.changed)}):")
        for url in diff.changed:
            fields = diff.change_details.get(url, [])
            print(f"    {url}  [{', '.join(fields)}]")
    if diff.new:
        print(f"\n[+] New hosts ({len(diff.new)}):")
        for url in diff.new[:20]:
            print(f"    {url}")
    print(f"\n[→] Needs re-scan: {len(result['needs_rescan'])} hosts")
