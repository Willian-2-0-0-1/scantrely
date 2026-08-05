#!/usr/bin/env python3
"""
ASM Recon Modules - standalone reconnaissance functions
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
"""
import subprocess as _subprocess_real
import socket, ssl, json, re, time, sys, os
import gzip, random, threading, urllib.request, urllib.error
from utils import cmd_trace as _ct
from utils import rate_limiter as _rl
from utils.tool_gate import gate_for as _gate_for

_MAX_RATE_WAIT = float(os.environ.get("ASM_HTTP_RATE_MAX_WAIT", "30") or 30)

_SUBPROCESS_CONTEXT = threading.local()


def set_subprocess_context(db=None, cid: str = "", module: str = ""):
    _SUBPROCESS_CONTEXT.db = db
    _SUBPROCESS_CONTEXT.cid = cid or ""
    _SUBPROCESS_CONTEXT.module = module or ""


class _GatedSubprocess:
    """Transparent stand-in for the ``subprocess`` module.

    recon.py fires dig/whois/naabu/nuclei/etc. through dozens of direct
    ``subprocess.run(...)`` calls. Inside the pipeline these execute under a
    module(8) x domain(8) fan-out, so without a ceiling they can spawn 64+
    concurrent processes and lock up the host. This shim routes every
    ``subprocess.run()`` through the per-tool + global ToolGate (a bounded
    queue) while passing every other attribute (Popen, PIPE, DEVNULL,
    TimeoutExpired, CompletedProcess...) straight to the real module. Replacing
    the module-level ``subprocess`` name gates all call sites with zero edits.
    """

    def __getattr__(self, name):
        return getattr(_subprocess_real, name)

    def run(self, cmd, **kw):
        tool = "recon"
        try:
            first = cmd[0] if isinstance(cmd, (list, tuple)) and cmd else str(cmd).split()[0]
            tool = os.path.basename(str(first)) or "recon"
        except Exception:
            pass
        run_id = None
        db = getattr(_SUBPROCESS_CONTEXT, "db", None)
        company_id = getattr(_SUBPROCESS_CONTEXT, "cid", "")
        module = getattr(_SUBPROCESS_CONTEXT, "module", "")
        start = time.time()
        if db and hasattr(db, "start_tool_run"):
            try:
                argv = list(cmd) if isinstance(cmd, (list, tuple)) else str(cmd).split()
                redacted = []
                redact_next = False
                for arg in argv:
                    s = str(arg)
                    if redact_next:
                        redacted.append("<redacted>")
                        redact_next = False
                        continue
                    redacted.append(s)
                    if s.lower() in {"-token", "--token", "-key", "--key", "-H", "--header"}:
                        redact_next = True
                run_id = db.start_tool_run(
                    company_id=company_id,
                    module=module,
                    tool=tool,
                    argv=redacted,
                )
            except Exception:
                run_id = None
        with _gate_for(tool).slot():
            status = "error"
            proc = None
            # Default timeout: prevent hung subprocesses from stalling the pipeline
            if "timeout" not in kw:
                kw["timeout"] = 300
            try:
                proc = _subprocess_real.run(cmd, **kw)
                status = "done" if getattr(proc, "returncode", 1) == 0 or str(getattr(proc, "stdout", "") or "").strip() else "error"
                return proc
            except _subprocess_real.TimeoutExpired as exc:
                status = "timeout"
                proc = exc
                raise
            finally:
                if db and run_id and hasattr(db, "finish_tool_run"):
                    try:
                        stdout = getattr(proc, "stdout", "") or ""
                        stderr = getattr(proc, "stderr", "") or ""
                        if isinstance(stdout, (bytes, bytearray)):
                            stdout = stdout.decode("utf-8", errors="replace")
                        if isinstance(stderr, (bytes, bytearray)):
                            stderr = stderr.decode("utf-8", errors="replace")
                        db.finish_tool_run(
                            run_id,
                            status=status,
                            exit_code=getattr(proc, "returncode", None),
                            duration=time.time() - start,
                            stdout_tail=str(stdout)[-12000:],
                            stderr_tail=str(stderr)[-12000:],
                        )
                    except Exception:
                        pass


subprocess = _GatedSubprocess()


def _subp(cmd, **kw):
    _ct.trace(cmd)
    _rl.wait()
    return subprocess.run(cmd, **kw)


from urllib.request import urlopen, Request
from urllib.error   import URLError, HTTPError
from datetime       import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ HTTP infrastructure Ã¢â‚¬â€ rate limiting, UA rotation, retry/backoff Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]

# Alternative Accept-Language headers for bypass (rotate if blocked)
_ALT_ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "pt-BR,pt;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.5",
    "de-DE,de;q=0.9,en;q=0.5",
    "fr-FR,fr;q=0.9,en;q=0.5",
    "ja-JP,ja;q=0.9,en;q=0.5",
]

def _random_accept_language() -> str:
    return random.choice(_ALT_ACCEPT_LANGUAGES)

_BROWSER_HEADERS = {
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection":      "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest":  "document",
    "Sec-Fetch-Mode":  "navigate",
    "Sec-Fetch-Site":  "none",
    "Sec-Fetch-User":  "?1",
    "DNT":             "1",
}

# Signatures that indicate a WAF block page rather than real content
_BLOCK_SIGNATURES = [
    "access denied", "blocked", "forbidden by", "security check",
    "cloudflare ray id", "cf-ray", "__cf_bm", "akamai reference",
    "the request could not be satisfied", "request blocked",
    "incapsula incident", "radware appsec", "you have been blocked",
    "enable javascript and cookies", "checking your browser",
    "ddos protection", "just a moment", "verifying you are human",
]

# Per-domain rate state: {domain: {"lock": Lock, "last": float, "blocked_until": float}}
_domain_state: dict = {}
_domain_state_lock = threading.Lock()

# Minimum seconds between requests to the same domain (jittered)
_RATE_BASE   = 0.4   # base delay
_RATE_JITTER = 0.3   # Ã‚Â± random jitter

# curl_cffi Ã¢â‚¬â€ TLS fingerprint mimicry (optional)
try:
    from curl_cffi import requests as _cffi_requests
    _CFFI_AVAILABLE = True
except ImportError:
    _CFFI_AVAILABLE = False


def _random_ua() -> str:
    return random.choice(_UA_POOL)


def _get_domain_state(domain: str) -> dict:
    with _domain_state_lock:
        if domain not in _domain_state:
            _domain_state[domain] = {
                "lock": threading.Lock(),
                "last": 0.0,
                "blocked_until": 0.0,
                "consecutive_blocks": 0,
            }
        return _domain_state[domain]


def _rate_wait(domain: str) -> None:
    """Enforce per-domain rate limit with jitter. Respects block backoff."""
    state = _get_domain_state(domain)
    # Determine how long to sleep BEFORE acquiring the lock, then sleep outside it
    # to avoid serialising multiple threads on the same domain lock.
    sleep_backoff = 0.0
    sleep_rate    = 0.0
    with state["lock"]:
        now = time.monotonic()
        if now < state["blocked_until"]:
            sleep_backoff = state["blocked_until"] - now
            now = state["blocked_until"]  # update logical now
        lim = _rl.get_limiter()
        if lim:
            base   = lim.current_delay
            jitter = lim.jitter
        else:
            base   = _RATE_BASE
            jitter = _RATE_JITTER
        gap     = base + random.uniform(0, jitter)
        elapsed = now - state["last"]
        if elapsed < gap:
            sleep_rate = gap - elapsed
        total_sleep = sleep_backoff + sleep_rate
        if total_sleep > _MAX_RATE_WAIT:
            state["last"] = time.monotonic()
            raise TimeoutError(
                f"rate wait for {domain} exceeded {_MAX_RATE_WAIT:.1f}s "
                f"(computed {total_sleep:.1f}s)"
            )
        state["last"] = time.monotonic() + total_sleep
    # Sleep outside the lock so parallel threads on the same domain don't serialize
    if sleep_backoff > 0:
        time.sleep(sleep_backoff)
    if sleep_rate > 0:
        time.sleep(sleep_rate)


def _record_block(domain: str, status: int) -> None:
    """Back off exponentially when a WAF block is detected."""
    state = _get_domain_state(domain)
    with state["lock"]:
        state["consecutive_blocks"] += 1
        n = state["consecutive_blocks"]
        backoff = min(5 * (3 ** (n - 1)), 90)
        backoff += random.uniform(0, backoff * 0.2)
        state["blocked_until"] = time.monotonic() + backoff
    # also reduce the phase-level rate adaptively
    _rl.signal(status)


def _record_success(domain: str) -> None:
    state = _get_domain_state(domain)
    with state["lock"]:
        state["consecutive_blocks"] = 0


def _is_block_response(status: int, body: str) -> bool:
    if status in (429, 503, 403, 406):
        body_l = body.lower()
        return any(sig in body_l for sig in _BLOCK_SIGNATURES) or status == 429
    return False


def _make_headers(extra: dict | None = None) -> dict:
    h = {**_BROWSER_HEADERS, "User-Agent": _random_ua()}
    if extra:
        h.update(extra)
    return h


def http_get(url: str, timeout: int = 10, retries: int = 3,
             extra_headers: dict | None = None,
             return_headers: bool = False,
             impersonate: str = "chrome124") -> tuple[int, bytes, dict]:
    """
    Robust HTTP GET with:
    - Per-domain rate limiting + jitter
    - UA rotation + full browser headers
    - Retry with exponential backoff on 429/5xx
    - WAF block detection and domain-level backoff
    - curl_cffi TLS fingerprint when available (impersonates real browser JA3)
    Returns (status_code, body_bytes, response_headers).
    """
    from urllib.parse import urlparse
    domain = urlparse(url).netloc.split(":")[0]
    headers = _make_headers(extra_headers)
    last_exc = None

    for attempt in range(retries):
        _rate_wait(domain)
        try:
            if _CFFI_AVAILABLE:
                resp = _cffi_requests.get(
                    url, headers=headers, timeout=timeout,
                    impersonate=impersonate, allow_redirects=True,
                    verify=False,
                )
                status  = resp.status_code
                body    = resp.content
                resp_h  = dict(resp.headers)
            else:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    status = r.status
                    body   = r.read()
                    resp_h = dict(r.headers)

            body_preview = body[:1000].decode("utf-8", "ignore")
            if status in (502, 503):
                wait = 2 ** attempt + random.uniform(0, 1)
                time.sleep(wait)
                continue

            if _is_block_response(status, body_preview):
                _record_block(domain, status)
                wait = 2 ** attempt + random.uniform(0, 1)
                time.sleep(wait)
                headers = _make_headers(extra_headers)  # rotate UA on retry
                continue

            _record_success(domain)
            _rl.signal(status)
            # Auto-decompress gzip (curl_cffi doesn't always do this with custom headers)
            enc = resp_h.get("Content-Encoding", resp_h.get("content-encoding", ""))
            if "gzip" in enc or (body[:2] == b"\x1f\x8b"):
                try:
                    body = gzip.decompress(body)
                except Exception:
                    pass
            return status, body, resp_h

        except urllib.error.HTTPError as e:
            status = e.code
            body   = b""
            resp_h = dict(e.headers) if e.headers else {}
            if status == 429:
                _record_block(domain, status)
                wait = 2 ** attempt + random.uniform(0, 2)
                time.sleep(wait)
                continue
            if status in (502, 503):
                # Transient server error Ã¢â‚¬â€ retry with simple backoff, no block record
                wait = 2 ** attempt + random.uniform(0, 1)
                time.sleep(wait)
                continue
            return status, body, resp_h
        except Exception as exc:
            last_exc = exc
            wait = 2 ** attempt + random.uniform(0, 1)
            time.sleep(wait)

    return 0, b"", {}


# Legacy alias kept for backward compat Ã¢â‚¬â€ modules call UA directly
UA = _random_ua()

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ DNS Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def dns_records(domain: str) -> dict:
    """Full DNS enumeration: A AAAA MX TXT NS SOA CNAME SRV CAA Ã¢â‚¬â€ single dig call."""
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
        pass
    return out


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Batch DNS utility Ã¢â‚¬â€ single subprocess for multiple queries Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def _dns_batch(queries: list[tuple]) -> dict:
    """Run multiple DNS queries in ONE subprocess.

    queries: list of (domain, record_type, flags) tuples
    flags: list of extra dig args like ["+time=2", "+tries=1"]

    Returns dict mapping (domain, rtype) Ã¢â€ â€™ list of values.
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
        pass
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
        # Output: one value per line, mixed types Ã¢â‚¬â€ we map by (query position)
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
        pass
    return result


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Zone Transfer Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Supply Chain Scan Ã¢â‚¬â€ Client-side JS Library CVE Check Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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
    from urllib.request import urlopen, Request
    from urllib.parse import urlencode
    import re as _re

    findings: list[dict] = []
    seen_cves: set[str] = set()

    # Ã¢â€â‚¬Ã¢â€â‚¬ Extract JS libraries with versions from host technologies Ã¢â€â‚¬Ã¢â€â‚¬
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

    # Ã¢â€â‚¬Ã¢â€â‚¬ Query NVD for each library@version Ã¢â€â‚¬Ã¢â€â‚¬
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
            req = Request(url, headers=headers)
            with urlopen(req, timeout=15) as r:
                data = json.loads(r.read())

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
            pass

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


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Email Security Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

DKIM_SELECTORS = [
    "google","selector1","selector2","default","mail","dkim","k1","s1","s2",
    "email","mandrill","mailchimp","sendgrid","smtp","protonmail","pm","zoho",
    "mimecast","mimecast1","mimecast2","amazon","ses","msa","beta","corp",
]

def check_spf(domain: str) -> dict:
    result = {"record": None, "score": "missing", "issues": [], "mechanisms": []}
    try:
        r = _subp(["dig","+short","+time=2","+tries=1","TXT", domain],
                           capture_output=True, text=True, timeout=8)
        for line in r.stdout.splitlines():
            line = line.strip().strip('"')
            if line.lower().startswith("v=spf1"):
                result["record"] = line
                mechs = line.split()[1:]
                result["mechanisms"] = mechs
                all_m = next((m for m in mechs if re.match(r'^[+~\-?]?all$', m)), None)
                if all_m is None or "all" not in line:
                    result["score"] = "incomplete"
                    result["issues"].append("No 'all' mechanism Ã¢â‚¬â€ incomplete policy")
                elif all_m.startswith("+"):
                    result["score"] = "critical"
                    result["issues"].append("+all: ANY server can send email as this domain")
                elif all_m.startswith("?"):
                    result["score"] = "high"
                    result["issues"].append("?all: neutral Ã¢â‚¬â€ no enforcement, effectively spoofable")
                elif all_m.startswith("~"):
                    result["score"] = "medium"
                    result["issues"].append("~all: softfail Ã¢â‚¬â€ most providers won't reject")
                elif all_m.startswith("-"):
                    result["score"] = "pass"
                # redirect?
                if any("redirect=" in m for m in mechs):
                    result["issues"].append("Uses redirect= Ã¢â‚¬â€ check target domain's SPF")
                if any("include:" in m for m in mechs):
                    count = sum(1 for m in mechs if "include:" in m)
                    if count > 8:
                        result["issues"].append(f"WARNING: {count} includes (>10 may cause DNS lookup limit)")
                break
        if not result["record"]:
            result["score"] = "missing"
            result["issues"].append("No SPF record Ã¢â‚¬â€ domain is fully spoofable")
    except Exception as e:
        result["error"] = str(e)
    return result

def check_dmarc(domain: str) -> dict:
    result = {"record": None, "policy": None, "pct": 100,
              "rua": None, "ruf": None, "score": "missing", "issues": []}
    try:
        r = _subp(["dig","+short","+time=2","+tries=1","TXT", f"_dmarc.{domain}"],
                           capture_output=True, text=True, timeout=8)
        for line in r.stdout.splitlines():
            line = line.strip().strip('"')
            if "v=dmarc1" in line.lower():
                result["record"] = line
                tags = dict(re.findall(r'(\w+)=([^;]+)', line, re.I))
                policy = tags.get("p","none").lower()
                result["policy"] = policy
                result["pct"]    = int(tags.get("pct","100"))
                result["rua"]    = tags.get("rua","")
                result["ruf"]    = tags.get("ruf","")
                sp               = tags.get("sp", policy)

                if policy == "none":
                    result["score"] = "high"
                    result["issues"].append("p=none: monitoring only Ã¢â‚¬â€ spoofed emails are delivered")
                elif policy == "quarantine":
                    result["score"] = "medium"
                    if result["pct"] < 100:
                        result["issues"].append(f"pct={result['pct']}: only {result['pct']}% of mail is checked")
                elif policy == "reject":
                    result["score"] = "pass"
                    if result["pct"] < 100:
                        result["score"] = "medium"
                        result["issues"].append(f"pct={result['pct']}: only {result['pct']}% of mail is rejected")

                if not result["rua"]:
                    result["issues"].append("No rua= tag Ã¢â‚¬â€ no DMARC reporting configured")
                if sp == "none" and policy != "none":
                    result["issues"].append(f"sp=none: subdomain policy is weaker than main domain")
                break
        if not result["record"]:
            result["score"] = "missing"
            result["issues"].append("No DMARC record Ã¢â‚¬â€ spoofed emails bypass policy checks")
    except Exception as e:
        result["error"] = str(e)
    return result

def check_bimi(domain: str) -> dict:
    """Check BIMI (Brand Indicators for Message Identification) Ã¢â‚¬â€ bonus."""
    try:
        r = _subp(["dig","+short","+time=2","+tries=1","TXT", f"default._bimi.{domain}"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if "v=bimi1" in line.lower():
                return {"record": line.strip().strip('"'), "present": True}
    except Exception:
        pass
    return {"present": False}

def check_dkim(domain: str) -> list:
    def _query_selector(sel: str) -> dict | None:
        try:
            r = subprocess.run(
                ["dig","+short","+time=1","+tries=1","TXT", f"{sel}._domainkey.{domain}"],
                capture_output=True, text=True, timeout=3,
            )
            txt = r.stdout.strip()
            if "v=dkim1" in txt.lower() or ("p=" in txt and len(txt) > 20):
                rec = txt.replace('"','').replace('\n',' ')[:300]
                p_match = re.search(r'p=([A-Za-z0-9+/=]+)', rec)
                key_bits = None
                if p_match:
                    import base64
                    try:
                        key_bytes = base64.b64decode(p_match.group(1) + "==")
                        key_bits = len(key_bytes) * 8
                    except Exception:
                        pass
                return {"selector": sel, "record": rec, "key_bits": key_bits,
                        "weak": key_bits is not None and key_bits < 1024}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = pool.map(_query_selector, DKIM_SELECTORS)
    return [r for r in results if r is not None]

def check_mx(domain: str) -> list:
    records = []
    try:
        r = _subp(["dig","+short","+time=2","+tries=1","MX", domain],
                           capture_output=True, text=True, timeout=8)
        for line in r.stdout.strip().splitlines():
            line = line.strip()
            if not line: continue
            parts = line.split()
            if len(parts) >= 2:
                prio, host = parts[0], parts[1].rstrip(".")
                # Reverse IP
                ips = []
                try:
                    for info in socket.getaddrinfo(host, None):
                        ip = info[4][0]
                        if ip not in ips: ips.append(ip)
                except Exception:
                    pass
                records.append({"priority": prio, "host": host, "ips": ips})
    except Exception:
        pass
    return records

def email_spoofability(spf: dict, dmarc: dict) -> str:
    spf_s   = spf.get("score","missing")
    dmarc_s = dmarc.get("score","missing")
    if spf_s == "missing" and dmarc_s == "missing": return "critical"
    if spf_s in ("critical","missing") or dmarc_s in ("missing","high"): return "high"
    if spf_s in ("high","medium","incomplete") or dmarc_s == "medium":   return "medium"
    return "low"

def run_email_recon(domain: str) -> dict:
    """Full email security analysis: SPF, DMARC, DKIM, BIMI, MX Ã¢â‚¬â€ single DNS batch."""
    spf_r   = {"record": None, "score": "missing", "issues": [], "mechanisms": []}
    dmarc_r = {"record": None, "policy": None, "pct": 100, "rua": None, "ruf": None, "score": "missing", "issues": []}
    bimi_r  = {"record": None, "score": "missing", "issues": []}
    dkim_r  = []
    mx_r    = []

    # Batch ALL email DNS queries into ONE subprocess
    dkim_selectors = ["google", "default", "selector1", "selector2", "dkim", "mail", "s1", "s2", "k1", "mandrill", "sendgrid"]
    queries = [
        (domain, "TXT", []),
        ("_dmarc." + domain, "TXT", []),
        ("default._bimi." + domain, "TXT", []),
        (domain, "MX", []),
    ] + [(f"{sel}._domainkey.{domain}", "TXT", []) for sel in dkim_selectors]

    batch = _dns_batch(queries)

    # Parse SPF
    for val in batch.get((domain, "TXT"), []):
        clean = val.strip().strip('"')
        if clean.lower().startswith("v=spf1"):
            spf_r["record"] = clean
            mechs = clean.split()[1:]
            spf_r["mechanisms"] = mechs
            all_m = next((m for m in mechs if re.match(r'^[+~\-?]?all$', m)), None)
            if all_m is None: spf_r["score"] = "incomplete"
            elif all_m.startswith("+"): spf_r["score"] = "critical"
            elif all_m.startswith("?"): spf_r["score"] = "high"
            elif all_m.startswith("~"): spf_r["score"] = "medium"
            elif all_m.startswith("-"): spf_r["score"] = "pass"
            break
    if not spf_r["record"]: spf_r["issues"].append("No SPF record")

    # Parse DMARC
    for val in batch.get(("_dmarc." + domain, "TXT"), []):
        clean = val.strip().strip('"')
        if "v=dmarc1" in clean.lower():
            dmarc_r["record"] = clean
            tags = dict(re.findall(r'(\w+)=([^;]+)', clean, re.I))
            dmarc_r["policy"] = tags.get("p", "none").lower()
            dmarc_r["pct"] = int(tags.get("pct", "100"))
            dmarc_r["rua"] = tags.get("rua", "")
            policy = dmarc_r["policy"]
            dmarc_r["score"] = "high" if policy == "none" else ("medium" if policy == "quarantine" else ("pass" if dmarc_r["pct"] >= 100 else "medium"))
            break
    if not dmarc_r["record"]: dmarc_r["issues"].append("No DMARC record")

    # Parse BIMI
    for val in batch.get(("default._bimi." + domain, "TXT"), []):
        if "v=bimi1" in val.lower():
            bimi_r["record"] = val; bimi_r["score"] = "present"; break
    if not bimi_r["record"]: bimi_r["score"] = "missing"

    # Parse DKIM
    for sel in dkim_selectors:
        for val in batch.get((f"{sel}._domainkey.{domain}", "TXT"), []):
            clean = val.strip().strip('"')
            if any(kw in clean.lower() for kw in ("v=dkim1", "k=rsa", "p=")):
                dkim_r.append({"selector": sel, "record": clean}); break

    # Parse MX
    for val in batch.get((domain, "MX"), []):
        parts = val.split()
        if parts and parts[-1].count(".") >= 1:
            mx_r.append(parts[-1])

    return {
        "domain":        domain,
        "spf":           spf_r,
        "dmarc":         dmarc_r,
        "dkim":          dkim_r,
        "mx":            mx_r,
        "bimi":          bimi_r,
        "spoofability":  email_spoofability(spf_r, dmarc_r),
        "scanned_at":    datetime.now().isoformat(timespec="seconds"),
    }

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Certificate Transparency Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def get_ct_certs(domain: str, limit: int = 500) -> list:
    """Query crt.sh + certspotter + Shodan CTL for certificates issued to domain."""
    certs = _ct_from_crtsh(domain, limit)
    if not certs:
        certs = _ct_from_certspotter(domain, limit)
    # Always merge Shodan CTL Ã¢â‚¬â€ complimentary source with different coverage
    shodan_certs = _ct_from_shodan(domain, limit)
    certs = certs + shodan_certs
    # Deduplicate by (common_name, not_after)
    seen: set = set()
    deduped = []
    for c in certs:
        key = (c["common_name"], c["not_after"])
        if key not in seen:
            seen.add(key)
            deduped.append(c)
    return sorted(deduped, key=lambda c: c.get("days_left") or 9999)


def _parse_cert_dates(not_after):
    """Parse certificate expiration. Accepts ISO datetime string or Unix timestamp (int)."""
    days_left = None
    expired = expiring_soon = False
    try:
        if isinstance(not_after, (int, float)):
            exp = datetime.utcfromtimestamp(not_after)
        elif isinstance(not_after, str):
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    exp = datetime.strptime(not_after, fmt)
                    break
                except ValueError:
                    continue
            else:
                return days_left, expired, expiring_soon
        else:
            return days_left, expired, expiring_soon
        days_left = (exp - datetime.utcnow()).days
        expired       = days_left < 0
        expiring_soon = 0 <= days_left <= 30
    except Exception:
        pass
    return days_left, expired, expiring_soon


def _ct_from_crtsh(domain: str, limit: int) -> list:
    for query in [f"%.{domain}", domain]:
        try:
            url = f"https://crt.sh/?q={query}&output=json&deduplicate=Y"
            status, raw, _ = http_get(url, timeout=10, retries=0)
            if not raw or raw[:1] == b"<" or status not in (200, 201):
                continue
            data = json.loads(raw)
            certs = []
            for c in data[:limit]:
                not_after = c.get("not_after", "")
                days_left, expired, expiring_soon = _parse_cert_dates(not_after)
                names = c.get("name_value", "").lower().replace("\\n", "\n").splitlines()
                certs.append({
                    "id":           c.get("id"),
                    "common_name":  c.get("common_name", ""),
                    "names":        names,
                    "issuer_cn":    _cn(c.get("issuer_name", "")),
                    "not_before":   (c.get("not_before", "") or "")[:10],
                    "not_after":    (not_after or "")[:10],
                    "days_left":    days_left,
                    "expired":      expired,
                    "expiring_soon":expiring_soon,
                    "wildcard":     any(n.startswith("*.") for n in names),
                    "source":       "crt.sh",
                })
            if certs:
                return certs
        except Exception:
            continue
    return []


def _ct_from_certspotter(domain: str, limit: int) -> list:
    """Fallback: certspotter.com issuances API (public, no key needed)."""
    certs = []
    try:
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert"
        status, body, _ = http_get(url, timeout=20)
        if status not in (200, 201) or not body:
            return []
        data = json.loads(body)
        for c in data[:limit]:
            cert = c.get("cert", {})
            not_after = cert.get("not_after", "")
            not_before = cert.get("not_before", "")
            days_left, expired, expiring_soon = _parse_cert_dates(not_after)
            names = [n.lower() for n in c.get("dns_names", [])]
            issuer = c.get("issuer", {})
            issuer_cn = issuer.get("friendly_name") or issuer.get("name", "")
            common_name = names[0] if names else ""
            certs.append({
                "id":           c.get("id"),
                "common_name":  common_name,
                "names":        names,
                "issuer_cn":    issuer_cn[:60],
                "not_before":   (not_before or "")[:10],
                "not_after":    (not_after or "")[:10],
                "days_left":    days_left,
                "expired":      expired,
                "expiring_soon":expiring_soon,
                "wildcard":     any(n.startswith("*.") for n in names),
                "source":       "certspotter",
            })
    except Exception:
        pass
    return certs

def _ct_from_shodan(domain: str, limit: int = 500) -> list:
    """Shodan Certificate Transparency Log API Ã¢â‚¬â€ free, no key required.
    https://ctl.shodan.io/api/v1/domain/{domain}"""
    certs = []
    try:
        url = f"https://ctl.shodan.io/api/v1/domain/{domain}"
        status, body, _ = http_get(url, timeout=15)
        if status not in (200, 201) or not body:
            return []
        data = json.loads(body)
        for c in data[:limit]:
            subject_cn = (c.get("subject_cn") or "").strip().lower()
            san = c.get("san_dns_names") or []
            if not isinstance(san, list):
                san = [subject_cn] if subject_cn else []
            san = [n.strip().lower() for n in san]
            if not subject_cn and san:
                subject_cn = san[0]
            not_after = c.get("not_after")  # Unix timestamp
            not_before = c.get("not_before")  # Unix timestamp
            days_left, expired, expiring_soon = _parse_cert_dates(not_after)

            # Format ISO dates from timestamps
            na_str = ""
            nb_str = ""
            try:
                if isinstance(not_after, (int, float)) and not_after > 0:
                    na_str = datetime.utcfromtimestamp(not_after).strftime("%Y-%m-%d")
                if isinstance(not_before, (int, float)) and not_before > 0:
                    nb_str = datetime.utcfromtimestamp(not_before).strftime("%Y-%m-%d")
            except Exception:
                pass

            certs.append({
                "id":           c.get("hash", ""),
                "common_name":  subject_cn,
                "names":        san,
                "issuer_cn":    (c.get("issuer_cn") or "")[:120],
                "not_before":   nb_str,
                "not_after":    na_str,
                "days_left":    days_left,
                "expired":      expired,
                "expiring_soon": expiring_soon,
                "wildcard":     any(n.startswith("*.") for n in san),
                "source":       "shodan_ctl",
            })
    except Exception:
        pass
    return certs

def _cn(dn: str) -> str:
    m = re.search(r"CN=([^,/]+)", dn)
    return m.group(1).strip() if m else dn[:60]

def get_ssl_info(host: str, port: int = 443) -> dict:
    """Get SSL/TLS certificate info. Uses CERT_REQUIRED for real cert data; falls back to DER on failures."""
    result = {"host": host, "port": port, "reachable": False}
    if not _dns_resolves(host):
        return result

    def _parse_cert(cert: dict) -> dict:
        return {
            "subject":    dict(x[0] for x in cert.get("subject", [])),
            "issuer":     dict(x[0] for x in cert.get("issuer", [])),
            "not_after":  cert.get("notAfter", ""),
            "san":        [v for t, v in cert.get("subjectAltName", []) if t == "DNS"],
        }

    def _connect(verify: bool):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
        if not verify:
            ctx.check_hostname = False
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()
                return cert, ssock.version(), cipher

    try:
        # First try with verification (gets full parsed cert)
        try:
            cert, tls_ver, cipher = _connect(verify=True)
            self_signed = False
        except ssl.SSLCertVerificationError:
            # Invalid/self-signed cert Ã¢â‚¬â€ connect without verify but use binary_form parsing
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                    der    = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    tls_ver = ssock.version()
            # Parse DER cert via openssl x509
            import base64
            pem = "-----BEGIN CERTIFICATE-----\n" + \
                  base64.b64encode(der).decode() + \
                  "\n-----END CERTIFICATE-----\n"
            r = subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-issuer",
                 "-enddate", "-ext", "subjectAltName"],
                input=pem, capture_output=True, text=True, timeout=5,
            )
            cert = {}
            san_list = []
            for line in r.stdout.splitlines():
                if line.startswith("subject="):
                    cn = re.search(r"CN\s*=\s*([^,/\n]+)", line)
                    if cn: cert["subject"] = [[ ("commonName", cn.group(1).strip()) ]]
                elif line.startswith("issuer="):
                    o = re.search(r"O\s*=\s*([^,/\n]+)", line)
                    if o: cert["issuer"] = [[ ("organizationName", o.group(1).strip()) ]]
                elif line.startswith("notAfter="):
                    cert["notAfter"] = line.split("=",1)[1].strip()
                elif "DNS:" in line:
                    san_list = re.findall(r"DNS:([^\s,]+)", line)
            if san_list:
                cert["subjectAltName"] = [("DNS", s) for s in san_list]
            self_signed = True

        parsed = _parse_cert(cert)
        result.update({
            "reachable":   True,
            "tls_version": tls_ver,
            "cipher":      cipher[0] if cipher else "",
            "cipher_bits": cipher[2] if cipher else 0,
            "self_signed": self_signed,
            **parsed,
        })

        # Expiry check
        not_after = result.get("not_after", "")
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
            try:
                exp  = datetime.strptime(not_after.strip(), fmt)
                days = (exp - datetime.utcnow()).days
                result.update({"days_left": days, "expired": days < 0, "expiring_soon": 0 <= days <= 30})
                break
            except Exception:
                pass

        issues = []
        if result.get("expired"):        issues.append("Certificate EXPIRED")
        if result.get("expiring_soon"):  issues.append(f"Expires in {result.get('days_left')} days")
        if self_signed:                  issues.append("Self-signed certificate")
        if result.get("cipher_bits", 0) < 128: issues.append("Weak cipher (<128 bit)")
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            issues.append(f"Outdated TLS: {tls_ver}")
        result["issues"] = issues

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = f"Connection failed: {e}"
    except Exception as e:
        result["error"] = str(e)
    return result

def run_cert_recon(domain: str, live_hosts: list = None) -> dict:
    """CT logs + SSL analysis for domain and its known hosts."""
    certs = get_ct_certs(domain)
    # New subdomains from CT not in our hosts list
    known = set(h.get("host","") for h in (live_hosts or []))
    ct_subdomains = []
    seen_subs = set()
    for c in certs:
        for name in c.get("names",[]):
            name = name.strip().lstrip("*.")
            if name.endswith(domain) and name not in seen_subs and name not in known:
                seen_subs.add(name)
                ct_subdomains.append(name)

    # SSL probe selected hosts; if no live hosts with port 443, probe the domain itself
    ssl_results = []
    hosts_to_probe = [h["host"] for h in (live_hosts or []) if 443 in h.get("ports", []) or "443" in h.get("ports", [])]
    if not hosts_to_probe:
        hosts_to_probe = [domain]
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(get_ssl_info, h): h for h in hosts_to_probe}
        for fut in as_completed(futures):
            ssl_results.append(fut.result())

    # Aggregate issues
    total_expired  = sum(1 for s in ssl_results if s.get("expired"))
    total_expiring = sum(1 for s in ssl_results if s.get("expiring_soon"))

    return {
        "domain":          domain,
        "certs":           certs,
        "ssl_results":     ssl_results,
        "ct_subdomains":   sorted(ct_subdomains)[:100],
        "total_certs":     len(certs),
        "total_expired":   total_expired,
        "total_expiring":  total_expiring,
        "issuers":         _count_issuers(certs),
        "scanned_at":      datetime.now().isoformat(timespec="seconds"),
    }

def _count_issuers(certs: list) -> dict:
    counts: dict[str,int] = {}
    for c in certs:
        iss = c.get("issuer_cn","Unknown")
        counts[iss] = counts.get(iss,0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1])[:10])

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ ASN / IP Intelligence Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
        pass
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
        pass
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


# Non-HTTP port Ã¢â€ â€™ service classification for ASM inventory
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
            pass

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

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Exposed Services Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

EXPOSED_PATHS = {
    "Admin Panels": [
        "/admin","/administrator","/wp-admin","/wp-login.php",
        "/phpmyadmin","/pma","/adminer.php","/manager/html",
        "/admin/login","/admin/dashboard","/admin/console",
        "/cp","/panel","/cpanel","/webadmin","/siteadmin",
    ],
    "API Documentation": [
        "/swagger-ui.html","/swagger-ui/","/swagger/","/api-docs",
        "/swagger.json","/openapi.json","/openapi.yaml",
        "/v1/api-docs","/v2/api-docs","/v3/api-docs",
        "/graphql","/graphiql","/__graphql","/api/graphql","/playground",
        "/api/v1/","/api/v2/","/api/",
    ],
    "Monitoring & DevOps": [
        "/actuator","/actuator/health","/actuator/env","/actuator/beans",
        "/actuator/mappings","/actuator/loggers","/actuator/threaddump",
        "/metrics","/health","/status","/info","/ping",
        "/kibana","/grafana","/jenkins","/sonarqube","/consul",
        "/prometheus","/jaeger","/zipkin","/hawtio","/jolokia",
    ],
    "Sensitive Files": [
        "/.git/config","/.git/HEAD","/.git/COMMIT_EDITMSG",
        "/.env","/.env.local","/.env.prod","/.env.backup",
        "/phpinfo.php","/info.php","/test.php","/config.php",
        "/wp-config.php","/configuration.php","/config.yml","/config.yaml",
        "/backup.zip","/backup.sql","/dump.sql","/db.sql",
        "/.htaccess","/.htpasswd","/web.config",
        "/crossdomain.xml","/clientaccesspolicy.xml",
        "/.well-known/security.txt",
    ],
    "Auth & Identity": [
        "/login","/signin","/sign-in","/auth","/sso",
        "/oauth","/oauth2","/oauth/authorize","/oidc","/saml",
        "/portal","/dashboard","/console","/account",
        "/forgot-password","/reset-password","/register",
    ],
    "Cloud & Infra": [
        "/server-status","/server-info",
        "/_cat/indices","/_cluster/health","/_nodes",
        "/solr/","/redis/",
        "/trace","/TRACE",
        "/.aws/credentials","/.ssh/authorized_keys",
    ],
}

def _probe_url(url: str, timeout: int = 4) -> dict | None:
    status, body, resp_h = http_get(url, timeout=timeout, retries=0)
    if status == 0:
        return None
    if status in (404, 400, 405, 501):
        return None
    ctype  = resp_h.get("Content-Type", resp_h.get("content-type", ""))
    length = int(resp_h.get("Content-Length", resp_h.get("content-length", 0)) or 0)
    snippet = body[:512].decode("utf-8", "ignore")
    return {"status": status, "content_type": ctype, "length": length, "snippet": snippet[:200]}

def run_services_recon(host: str, timeout: int = 5) -> list:
    """Probe a single host for common exposed paths (parallel)."""
    results = []
    tasks = []
    for category, paths in EXPOSED_PATHS.items():
        for path in paths:
            tasks.append((category, path, f"https://{host}{path}"))

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_probe_url, url, timeout): (cat, path, url)
                   for cat, path, url in tasks}
        for fut in as_completed(futures):
            cat, path, url = futures[fut]
            result = fut.result()
            if result:
                sev = "high" if result["status"] == 200 else "medium"
                # Upgrade severity for specific paths
                if any(x in path for x in [".git",".env","sql","config","backup",
                                            "wp-config","phpmyadmin","adminer"]):
                    sev = "critical" if result["status"] == 200 else "high"
                results.append({
                    "url":      url,
                    "path":     path,
                    "category": cat,
                    "status":   result["status"],
                    "length":   result["length"],
                    "snippet":  result.get("snippet",""),
                    "severity": sev,
                })
    return sorted(results, key=lambda x: ["critical","high","medium","low"].index(x["severity"]))

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Leaks & Secrets Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def _dns_resolves(hostname: str, timeout: int = 3) -> bool:
    """Check if hostname resolves via dig (avoids glibc DNS hangs)."""
    try:
        r = subprocess.run(
            ["dig", "+short", "+time=1", "+tries=1", "A", hostname],
            capture_output=True, text=True, timeout=timeout,
        )
        return bool(r.stdout.strip() and not r.stdout.strip().startswith(";"))
    except Exception:
        return False


def _is_high_value_github_file(path: str) -> bool:
    """True if the file path suggests it commonly holds credentials."""
    high_value_exts  = {".env", ".properties", ".cfg", ".ini", ".netrc",
                        ".npmrc", ".pypirc", ".htpasswd", ".secret"}
    high_value_names = {".env.local", ".env.production", ".env.staging",
                        ".env.development", ".env.test", "credentials",
                        "secrets.yml", "secrets.yaml", "secrets.json"}
    p = path.lower()
    _, ext = os.path.splitext(p)
    basename = os.path.basename(p)
    return (ext in high_value_exts or basename in high_value_names
            or "secret" in basename or "credential" in basename
            or "password" in basename)


def _fetch_and_scan_github_file(api_url: str, auth_headers: dict) -> list:
    """Fetch a file from the GitHub Contents API and scan for secret patterns."""
    import base64
    if not api_url:
        return []
    try:
        extra = {k: v for k, v in auth_headers.items() if k != "User-Agent"}
        status, body, _ = http_get(api_url, timeout=8, retries=0, extra_headers=extra)
        if status != 200 or not body:
            return []
        data    = json.loads(body)
        encoded = data.get("content", "")
        if not encoded:
            return []
        content = base64.b64decode(encoded.replace("\n", "")).decode("utf-8", "ignore")[:60000]
        matches = []
        seen    = set()
        for pattern, ptype, sev in _JS_SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                val = m.group(0)[:120]
                key = (ptype, val[:40])
                if key not in seen:
                    seen.add(key)
                    start = max(0, m.start() - 60)
                    end   = min(len(content), m.end() + 40)
                    ctx   = content[start:end].replace("\n", " ").strip()[:200]
                    matches.append({"type": ptype, "severity": sev, "context": ctx})
        return matches
    except Exception:
        return []


def search_github(domain: str, token: str = None) -> dict:
    """GitHub code search for secrets mentioning the domain."""
    if not _dns_resolves("api.github.com"):
        return {"results": [], "errors": ["api.github.com unreachable"], "authenticated": False}

    headers = {"User-Agent": UA, "Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    company = domain.split(".")[0]  # "portoseguro" from "portoseguro.com.br"

    # Each entry: (query_string, base_severity)
    # Using file qualifiers (extension:, filename:) to target credential-bearing files
    # and avoid noise from READMEs, tests, docs.
    queries = [
        # .env files Ã¢â‚¬â€ highest signal
        (f'"{domain}" extension:env',                                "high"),
        (f'"{domain}" filename:.env',                                "high"),
        (f'"{domain}" filename:.env.local OR filename:.env.production', "high"),
        # Database / connection strings
        (f'"{domain}" DATABASE_URL OR DB_PASSWORD OR DB_PASS',       "high"),
        (f'"{domain}" jdbc:mysql OR jdbc:postgresql OR jdbc:oracle',  "high"),
        # Config files with explicit credential keywords
        (f'"{domain}" extension:yml password OR secret',             "medium"),
        (f'"{domain}" extension:yaml password OR secret',            "medium"),
        (f'"{domain}" extension:json api_key OR password OR secret',  "medium"),
        (f'"{domain}" extension:properties password',                "medium"),
        (f'"{domain}" filename:config.php password OR DB_PASS',       "medium"),
        # Private key material
        (f'"{domain}" "BEGIN PRIVATE KEY"',                          "critical"),
        (f'"{domain}" "BEGIN RSA PRIVATE KEY"',                      "critical"),
        # Company name in .env files (catches internal repos without full domain)
        (f'"{company}" extension:env password OR secret OR key',     "high"),
        # SMTP / mail credentials
        (f'"{domain}" SMTP_PASSWORD OR MAIL_PASSWORD OR smtp://',    "medium"),
    ]

    results = []
    errors  = []
    seen    = set()  # dedup by "repo:filepath"

    for q, base_severity in queries:
        try:
            enc = q.replace('"', '%22').replace(' ', '+')
            url = f"https://api.github.com/search/code?q={enc}&per_page=10&sort=indexed"
            status, body, _ = http_get(url, timeout=12,
                                       extra_headers={k: v for k, v in headers.items()
                                                      if k != "User-Agent"})
            if status == 403:
                errors.append("GitHub rate limit reached Ã¢â‚¬â€ add a token in Settings")
                break
            if status != 200 or not body:
                errors.append(f"Query '{q}': HTTP {status}")
                time.sleep(3)
                continue

            data = json.loads(body)
            for item in data.get("items", []):
                repo     = item.get("repository", {})
                fullname = repo.get("full_name", "")
                filepath = item.get("path", "")

                # Skip forks Ã¢â‚¬â€ they duplicate the original repo's code
                if repo.get("fork"):
                    continue

                key = f"{fullname}:{filepath}"
                if key in seen:
                    continue
                seen.add(key)

                # Validate content when authenticated (eliminates most false positives)
                validated = []
                if token:
                    validated = _fetch_and_scan_github_file(item.get("url", ""), headers)

                if validated:
                    severity = max(
                        (v["severity"] for v in validated),
                        key=lambda s: {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(s, 0),
                    )
                elif base_severity == "critical":
                    severity = "critical"
                elif _is_high_value_github_file(filepath):
                    severity = "high"
                else:
                    severity = base_severity

                results.append({
                    "query":             q,
                    "repo":              fullname,
                    "file":              filepath,
                    "url":               item.get("html_url", ""),
                    "severity":          severity,
                    "validated_secrets": validated,
                })

            time.sleep(2)  # GitHub rate limit
        except Exception as e:
            errors.append(str(e))
            break

    return {"results": results, "errors": errors,
            "authenticated": token is not None}

def search_codebase_leaks(domain: str) -> dict:
    """Search for domain mentions in public paste/code sites (no auth required)."""
    results = []
    if not _dns_resolves("api.hackertarget.com"):
        return {"results": []}
    # GreyNoise / PublicWWW alternatives Ã¢â‚¬â€ use HackerTarget which is free
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        status, raw, _ = http_get(url, timeout=10)
        body = raw.decode("utf-8", "ignore") if raw else ""
        for line in body.strip().splitlines()[:50]:
            if "," in line:
                host, ip = line.split(",",1)
                results.append({"source":"hackertarget","type":"subdomain",
                                 "host": host.strip(), "ip": ip.strip()})
    except Exception:
        pass
    return {"results": results}

def check_exposed_git(hosts: list) -> list:
    """Quick check for exposed .git directories."""
    exposed = []
    targets = [h["host"] for h in hosts if h.get("ports") and "443" in h["ports"]]

    def check(host):
        for path in ["/.git/config", "/.git/HEAD"]:
            status, body, _ = http_get(f"https://{host}{path}", timeout=3, retries=0)
            if status == 200 and body:
                return {"host": host, "path": path, "severity": "critical",
                        "snippet": body[:100].decode("utf-8", "ignore")}
        return None

    with ThreadPoolExecutor(max_workers=30) as pool:
        for res in pool.map(check, targets):
            if res:
                exposed.append(res)
    return exposed

def run_leaks_recon(domain: str, hosts: list, github_token: str = None) -> dict:
    git_exposed = check_exposed_git(hosts)
    github      = search_github(domain, token=github_token)
    hackertarget = search_codebase_leaks(domain)
    return {
        "domain":      domain,
        "git_exposed": git_exposed,
        "github":      github,
        "hackertarget":hackertarget,
        "total_findings": len(git_exposed) + len(github.get("results",[])),
        "scanned_at":  datetime.now().isoformat(timespec="seconds"),
    }

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Risk Scoring Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def score_host(host: dict, findings: list) -> int:
    """0Ã¢â‚¬â€œ100 risk score per host."""
    score = 0
    hostname = host.get("host","")

    for f in findings:
        if hostname in (f.get("host",""), f.get("url","")):
            score += {"critical":30,"high":15,"medium":5,"low":2,"info":1}.get(
                f.get("severity","info"), 1)

    waf = host.get("waf","")
    if "Direct" in waf and "Firewalled" not in waf:
        score += 20

    risky = {"21","22","23","25","110","143","3306","5432","6379","27017","9200","2375","8500"}
    score += sum(8 for p in host.get("ports",[]) if p in risky)

    return min(score, 100)

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Security Headers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "desc": "HSTS Ã¢â‚¬â€ forces HTTPS connections",
        "missing_sev": "high",
        "check": lambda v: (
            "missing max-age" if "max-age" not in v.lower() else
            "max-age too short (<1y)" if re.search(r"max-age=(\d+)", v, re.I) and
                int(re.search(r"max-age=(\d+)", v, re.I).group(1)) < 31536000 else None
        ),
    },
    "Content-Security-Policy": {
        "desc": "CSP Ã¢â‚¬â€ prevents XSS and data injection",
        "missing_sev": "high",
        "check": lambda v: (
            "unsafe-inline in script-src" if "unsafe-inline" in v else
            "unsafe-eval in script-src" if "unsafe-eval" in v else None
        ),
    },
    "X-Frame-Options": {
        "desc": "Prevents clickjacking",
        "missing_sev": "medium",
        "check": lambda v: (
            "ALLOW-FROM is deprecated" if "ALLOW-FROM" in v.upper() else None
        ),
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME sniffing",
        "missing_sev": "medium",
        "check": lambda v: (
            "should be 'nosniff'" if v.strip().lower() != "nosniff" else None
        ),
    },
    "Referrer-Policy": {
        "desc": "Controls referrer information",
        "missing_sev": "low",
        "check": lambda v: (
            "unsafe-url leaks full URL" if v.strip().lower() == "unsafe-url" else None
        ),
    },
    "Permissions-Policy": {
        "desc": "Controls browser features",
        "missing_sev": "low",
        "check": lambda v: None,
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS filter (deprecated)",
        "missing_sev": "info",
        "check": lambda v: (
            "mode=block recommended" if "mode=block" not in v else None
        ),
    },
    "Cross-Origin-Opener-Policy": {
        "desc": "Prevents cross-origin window attacks",
        "missing_sev": "low",
        "check": lambda v: None,
    },
    "Cross-Origin-Resource-Policy": {
        "desc": "Controls cross-origin resource sharing",
        "missing_sev": "low",
        "check": lambda v: None,
    },
}

def _fetch_headers(url: str, timeout: int = 6) -> tuple:
    status, _, resp_h = http_get(url, timeout=timeout, retries=1, return_headers=True)
    return resp_h, status, url

def run_security_headers(host: str) -> dict:
    """Analyse HTTP security headers for a single host."""
    url = f"https://{host}" if not host.startswith("http") else host
    headers, status, final_url = _fetch_headers(url)
    # normalise header keys to Title-Case
    headers_norm = {k.title(): v for k, v in headers.items()}

    findings = []
    scores   = []

    for hdr, meta in HEADER_CHECKS.items():
        val = headers_norm.get(hdr)
        if val is None:
            findings.append({
                "header":   hdr,
                "present":  False,
                "value":    None,
                "severity": meta["missing_sev"],
                "issue":    f"Missing Ã¢â‚¬â€ {meta['desc']}",
            })
            scores.append(meta["missing_sev"])
        else:
            issue = meta["check"](val)
            sev   = "medium" if issue else "pass"
            findings.append({
                "header":   hdr,
                "present":  True,
                "value":    val[:200],
                "severity": sev,
                "issue":    issue or "OK",
            })
            if issue:
                scores.append(sev)

    # Cookie security
    cookie_issues = []
    for k, v in headers_norm.items():
        if k.lower() == "set-cookie":
            if "secure" not in v.lower():
                cookie_issues.append({"cookie": v[:80], "issue": "Missing Secure flag", "severity": "high"})
            if "httponly" not in v.lower():
                cookie_issues.append({"cookie": v[:80], "issue": "Missing HttpOnly flag", "severity": "medium"})
            if "samesite" not in v.lower():
                cookie_issues.append({"cookie": v[:80], "issue": "Missing SameSite flag", "severity": "medium"})

    sev_order = ["critical","high","medium","low","info","pass"]
    overall = min(scores, key=lambda s: sev_order.index(s)) if scores else "pass"

    return {
        "host":          host,
        "url":           final_url,
        "status":        status,
        "findings":      findings,
        "cookie_issues": cookie_issues,
        "overall":       overall,
        "score":         sum({"critical":0,"high":20,"medium":10,"low":5,"info":2,"pass":100}.get(s,0) for s in scores) // max(len(scores),1),
        "scanned_at":    datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Vendor / Edge Appliance Fingerprinting Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

_VENDOR_FINGERPRINTS = [
    # name, paths, response_signature, severity, cve_note
    ("Citrix Netscaler / ADC", ["/vpn/index.html", "/logon/LogonPoint/tmindex.html", "/citrix/", "/logon/LogonPoint/index.html"],
     ["Citrix", "Netscaler", "ADC", "netscaler", "logonpoint"], "critical",
     "CVE-2023-3519 RCE, CVE-2019-19781 path traversal Ã¢â‚¬â€ both KEV-listed"),
    ("F5 BIG-IP", ["/tmui/login.jsp", "/tmui/", "/mgmt/tm/sys/"],
     ["BIG-IP", "bigip", "tmui", "F5 Networks"], "critical",
     "CVE-2022-1388 auth bypass RCE, CVE-2023-46747 Ã¢â‚¬â€ KEV-listed"),
    ("Pulse Secure / Ivanti Connect", ["/dana-na/", "/dana-na/auth/url_default/welcome.cgi", "/dana-na/auth/url_default/welcome.cgi?p=user-conf"],
     ["Pulse Secure", "Ivanti", "dana-na", "welcome.cgi"], "critical",
     "CVE-2024-21887 command injection, CVE-2023-46805 auth bypass Ã¢â‚¬â€ chained, both KEV"),
    ("FortiGate / FortiOS", ["/remote/login", "/remote/info", "/api/v2/"],
     ["FortiGate", "FortiOS", "fortinet"], "critical",
     "CVE-2024-21762 RCE, CVE-2022-42475 heap-based RCE Ã¢â‚¬â€ both KEV"),
    ("PaloAlto GlobalProtect", ["/global-protect/", "/global-protect/login.esp", "/global-protect/portal/css/login.css"],
     ["GlobalProtect", "Palo Alto", "PAN-OS"], "critical",
     "CVE-2024-3400 command injection RCE Ã¢â‚¬â€ KEV-listed"),
    ("Cisco ASA / AnyConnect", ["/+CSCOE+/", "/CSCOE/index.html", "/webvpn.html", "/+CSCOE+/portal.html"],
     ["Cisco", "CSCOE", "AnyConnect", "webvpn"], "high",
     "CVE-2020-3452 file read, CVE-2018-0101 RCE"),
    ("VMware vCenter / ESXi", ["/ui/", "/vsphere-client/", "/sdk/"],
     ["VMware", "vCenter", "vSphere", "ESXi"], "critical",
     "CVE-2021-21972 RCE, CVE-2021-21985 RCE Ã¢â‚¬â€ KEV-listed"),
    ("Microsoft Exchange OWA", ["/owa/", "/owa/auth/logon.aspx", "/ecp/", "/autodiscover/"],
     ["Outlook Web", "Exchange", "owa", "Outlook Web App"], "high",
     "ProxyShell, ProxyLogon, ProxyNotShell Ã¢â‚¬â€ multiple KEV-listed CVEs"),
    ("Jenkins", ["/jenkins/", "/jenkins/login", "/script"],
     ["Jenkins", "jenkins"], "medium",
     "CVE-2024-23897 file read, CVE-2018-1000861 RCE"),
    ("Apache Tomcat", ["/manager/html", "/host-manager/html"],
     ["Tomcat", "Apache Tomcat", "Web Application Manager"], "medium",
     "CVE-2025-24813 path traversal RCE Ã¢â‚¬â€ KEV-listed"),
    ("Jupyter", ["/tree", "/lab", "/login?next=%2Ftree%3F"],
     ["Jupyter", "jupyter", "JupyterLab"], "medium",
     "Often unauthenticated; grants interactive Python shell"),
    ("Grafana", ["/login", "/api/health"],
     ["Grafana", "grafana"], "low",
     "Monitoring dashboard; CVE-2021-43798 path traversal"),
]

def run_vendor_fingerprint(hosts: list) -> dict:
    """Probe known vendor paths on each host to fingerprint edge appliances."""
    import concurrent.futures
    results = []
    targets = [h if isinstance(h, str) else h.get("host", "") for h in hosts]
    targets = [t for t in targets if t][:100]

    def _probe_host(host: str) -> list:
        host_results = []
        for proto in ["https", "http"]:
            for vendor_name, paths, sigs, severity, cve_note in _VENDOR_FINGERPRINTS:
                for path in paths[:3]:
                    try:
                        url = f"{proto}://{host}{path}"
                        status, body, _ = http_get(url, timeout=4, retries=1)
                        if status and body:
                            body_lower = body[:2000].decode("utf-8", "ignore").lower()
                            for sig in sigs:
                                if sig.lower() in body_lower:
                                    host_results.append({
                                        "host": host,
                                        "vendor": vendor_name,
                                        "url": url,
                                        "status": status,
                                        "severity": severity,
                                        "cve_note": cve_note,
                                    })
                                    break
                    except Exception:
                        continue
        return host_results

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=20)
    try:
        futures = {pool.submit(_probe_host, h): h for h in targets}
        try:
            for fut in concurrent.futures.as_completed(futures, timeout=240):
                try:
                    results.extend(fut.result())
                except Exception:
                    pass
        except concurrent.futures.TimeoutError:
            pass  # timeout Ã¢â‚¬â€ return partial results collected so far
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    return {
        "findings": results,
        "vendors_found": sorted(set(r["vendor"] for r in results)),
        "total": len(results),
        "scanned_hosts": len(targets),
    }


def run_headers_bulk(hosts: list, max_hosts: int = 200) -> dict:
    """Analyse headers for live HTTPS hosts (capped for speed)."""
    targets = [
        h["host"] for h in hosts
        if 443 in h.get("ports", []) or "443" in h.get("ports", [])
        or h.get("status_code") is not None
    ][:max_hosts]
    results = []
    with ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(run_security_headers, h): h for h in targets}
        for fut in as_completed(futures):
            results.append(fut.result())

    # Summary stats
    missing_hsts  = sum(1 for r in results for f in r["findings"]
                        if f["header"] == "Strict-Transport-Security" and not f["present"])
    missing_csp   = sum(1 for r in results for f in r["findings"]
                        if f["header"] == "Content-Security-Policy" and not f["present"])
    cookie_issues = sum(len(r["cookie_issues"]) for r in results)

    return {
        "results":      sorted(results, key=lambda r: r.get("score",100)),
        "total_hosts":  len(results),
        "missing_hsts": missing_hsts,
        "missing_csp":  missing_csp,
        "cookie_issues": cookie_issues,
        "scanned_at":   datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Typosquatting Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

# Major ccTLDs + gTLDs for domain permutation scanning
_TLD_SWAPS = {
    ".com":    [".net", ".org", ".io", ".co", ".app", ".dev", ".cloud", ".ai", ".info", ".biz", ".us", ".co.uk", ".uk", ".de", ".fr", ".es", ".it", ".nl", ".eu", ".ca", ".au", ".in", ".jp", ".cn"],
    ".com.br": [".com", ".net.br", ".org.br", ".br", ".net", ".org", ".io", ".app", ".dev"],
    ".br":     [".com.br", ".net.br", ".org.br", ".com", ".net", ".org"],
    ".net":    [".com", ".org", ".io", ".net.br"],
    ".org":    [".com", ".net", ".io"],
    ".gov.br": [".br", ".com.br"],
    ".edu.br": [".br", ".com.br"],
}

# All ccTLDs to test against the base domain name (cross-country permutations)
_CC_TLDS = [
    # Brazil
    ".br", ".com.br", ".net.br", ".org.br", ".gov.br", ".edu.br", ".mil.br",
    # Latin America
    ".ar", ".com.ar", ".net.ar", ".org.ar",
    ".uy", ".com.uy",
    ".cl", ".com.cl", ".net.cl",
    ".co", ".com.co", ".net.co", ".org.co",
    ".pe", ".com.pe", ".net.pe",
    ".mx", ".com.mx", ".net.mx", ".org.mx",
    ".py", ".com.py", ".net.py",
    ".bo", ".com.bo",
    ".ec", ".com.ec", ".net.ec",
    ".ve", ".com.ve", ".net.ve",
    ".pa", ".com.pa",
    ".cr", ".co.cr",
    ".do", ".com.do",
    ".gt", ".com.gt",
    ".hn", ".com.hn",
    ".sv", ".com.sv",
    ".ni", ".com.ni",
    # Global gTLDs
    ".com", ".net", ".org", ".io", ".co", ".app", ".dev", ".cloud", ".ai",
    ".info", ".biz", ".us", ".co.uk", ".uk", ".de", ".fr", ".es", ".it",
    ".nl", ".eu", ".ca", ".au", ".in", ".jp", ".cn", ".ru", ".pl",
    ".pt", ".ch", ".se", ".no", ".fi", ".dk", ".cz", ".at", ".be",
    ".kr", ".tw", ".hk", ".sg", ".nz", ".za",
    # Business / corporate TLDs
    ".digital", ".online", ".tech", ".site", ".store", ".live",
    ".security", ".network", ".email", ".systems", ".services",
    ".solutions", ".technology", ".ventures", ".capital", ".finance",
    ".bank", ".insurance", ".healthcare", ".agency", ".consulting",
    ".marketing", ".media", ".software", ".legal", ".accountant",
    ".associates", ".business", ".company", ".enterprises", ".expert",
    ".foundation", ".institute", ".international", ".management",
    ".partners", ".productions", ".professional", ".support", ".training",
    ".guru", ".ninja", ".pro", ".today", ".world", ".life",
]

def _typo_variants(domain: str) -> list[str]:
    """Generate typosquat variants matching dnstwist coverage."""
    parts = domain.rsplit(".", 2)
    if len(parts) < 2:
        return []

    if len(parts) == 3:
        name, tld1, tld2 = parts
        tld = f"{tld1}.{tld2}"
    else:
        name, tld = parts[0], ".".join(parts[1:])

    variants: set = set()
    current_tld = f".{tld}"

    # Ã¢â€â‚¬Ã¢â€â‚¬ 1. Keyboard adjacency (replacement) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    kb_adj = {
        'a':'sq','b':'vghn','c':'xdfv','d':'erfcs','e':'wrds','f':'rtgv',
        'g':'tyhbf','h':'yujng','i':'uojk','j':'ikhnu','k':'jiol','l':'kop',
        'm':'njk','n':'bhjm','o':'ilp','p':'ol','q':'wa','r':'etdf',
        's':'adeqwz','t':'rfgy','u':'yhij','v':'cfgb','w':'qse','x':'czsd',
        'y':'tghu','z':'asx',
    }
    for i, ch in enumerate(name):
        for sub in kb_adj.get(ch, ""):
            variants.add(f"{name[:i]}{sub}{name[i+1:]}.{tld}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ 2. Omission (missing character) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    for i in range(len(name)):
        variants.add(f"{name[:i]}{name[i+1:]}.{tld}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ 3. Repetition (doubled character) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    for i, ch in enumerate(name):
        variants.add(f"{name[:i]}{ch}{ch}{name[i+1:]}.{tld}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ 4. Transposition (adjacent swap) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    for i in range(len(name) - 1):
        s = list(name)
        s[i], s[i+1] = s[i+1], s[i]
        variants.add(f"{''.join(s)}.{tld}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ 5. Insertion (extra char at every position) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    for i in range(len(name) + 1):
        for ch in alphabet:
            candidate = f"{name[:i]}{ch}{name[i:]}.{tld}"
            # skip if it only differs by appending at end (handled by addition)
            if candidate != f"{name}{ch}.{tld}":
                variants.add(candidate)

    # Ã¢â€â‚¬Ã¢â€â‚¬ 6. Addition (append digit/char at end / prepend at start) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    for ch in "0123456789":
        variants.add(f"{name}{ch}.{tld}")
        variants.add(f"{ch}{name}.{tld}")
    for ch in alphabet:
        variants.add(f"{name}{ch}.{tld}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ 7. Vowel swap Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    vowels = "aeiou"
    for i, ch in enumerate(name):
        if ch in vowels:
            for v in vowels:
                if v != ch:
                    variants.add(f"{name[:i]}{v}{name[i+1:]}.{tld}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ 8. Bitsquatting (single-bit flip, result must be printable ASCII) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    valid_chars = set("abcdefghijklmnopqrstuvwxyz0123456789-")
    for i, ch in enumerate(name):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if flipped in valid_chars and flipped != ch:
                variants.add(f"{name[:i]}{flipped}{name[i+1:]}.{tld}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ 9. Homoglyph Ã¢â‚¬â€ Unicode IDN lookalikes (generates xn-- punycode) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    # Maps Latin char Ã¢â€ â€™ list of Unicode homoglyphs
    _HOMOGLYPHS: dict[str, list[str]] = {
        "a": ["ÃÂ°", "Ã‰â€˜"],          # Cyrillic ÃÂ°, Latin Ã‰â€˜
        "c": ["ÃÂ²", "Ã‘Â"],          # Greek ÃÂ², Cyrillic Ã‘Â
        "d": ["Ã”Â"],                    # Cyrillic Ã”Â
        "e": ["ÃÂµ", "Ã’Â½"],          # Cyrillic ÃÂµ, Ã’Â½
        "g": ["Ã‰Â¡"],                    # Latin Ã‰Â¡
        "h": ["Ã’Â»"],                    # Cyrillic Ã’Â»
        "i": ["Ã‘â€“", "Ã“Â", "1"],     # Cyrillic Ã‘â€“, Ã“Â, digit 1
        "j": ["Ã‘Ëœ"],                    # Cyrillic Ã‘Ëœ
        "l": ["Ã“Â", "1", "1"],     # Cyrillic Ã“Â, digit
        "m": ["ÃÂ¼"],                    # Cyrillic ÃÂ¼
        "n": ["Ã•Â¸"],                    # Armenian Ã•Â¸
        "o": ["ÃÂ¾", "ÃŽÂ¿", "0"],     # Cyrillic ÃÂ¾, Greek ÃŽÂ¿, digit 0
        "p": ["Ã‘â‚¬", "ÃÂ"],          # Cyrillic Ã‘â‚¬, Greek ÃÂ
        "q": ["Ã•Â£"],                    # Armenian Ã•Â£
        "r": ["ÃÂ³"],                    # Cyrillic ÃÂ³
        "s": ["Ã‘â€¢", "5"],               # Cyrillic Ã‘â€¢
        "u": ["ÃÂ²"],                    # Cyrillic ÃÂ²
        "v": ["ÃŽÂ½"],                    # Greek ÃŽÂ½
        "w": ["Ã‘Â¡"],                    # Cyrillic Ã‘Â¡
        "x": ["Ã‘â€¦"],                    # Cyrillic Ã‘â€¦
        "y": ["Ã‘Æ’", "Ã’Â¯"],          # Cyrillic Ã‘Æ’, Ã’Â¯
        "z": ["ÃŠÂ"],                    # Latin ÃŠÂ
    }
    for i, ch in enumerate(name):
        for glyph in _HOMOGLYPHS.get(ch, []):
            candidate_name = name[:i] + glyph + name[i+1:]
            try:
                idn = (candidate_name + "." + tld).encode("idna").decode("ascii")
                variants.add(idn)
            except (UnicodeError, UnicodeDecodeError):
                pass

    # Ã¢â€â‚¬Ã¢â€â‚¬ 10. Hyphenation (insert hyphen between each adjacent pair) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    for i in range(1, len(name)):
        variants.add(f"{name[:i]}-{name[i:]}.{tld}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ 11. TLD swaps Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    for alt in _TLD_SWAPS.get(current_tld, []):
        variants.add(f"{name}{alt}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ 12. Cross-TLD sweep Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    for cc_tld in _CC_TLDS:
        if cc_tld != current_tld:
            variants.add(f"{name}{cc_tld}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ 13. Common prefixes/suffixes Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    for pfx in ["www", "m", "app", "portal", "login", "secure", "mail", "vpn"]:
        variants.add(f"{pfx}-{name}.{tld}")
        variants.add(f"{pfx}{name}.{tld}")
    for sfx in ["-br", "-brasil", "-online", "-digital", "-bank", "-app"]:
        variants.add(f"{name}{sfx}.{tld}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ 14. ASCII homograph (digit/symbol substitutions) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    for orig, fakes in [("o", "0"), ("i", "1l"), ("e", "3"), ("a", "@4"), ("s", "5$")]:
        for fake in fakes:
            for i, ch in enumerate(name):
                if ch == orig:
                    variants.add(f"{name[:i]}{fake}{name[i+1:]}.{tld}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ 15. Plural Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    variants.add(f"{name}s.{tld}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ 16. Combosquatting Ã¢â‚¬â€ brand + sector keywords Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    _SECTOR_WORDS = [
        "auto", "vida", "saude", "residencial", "banco", "bank", "seguros",
        "seguranca", "sinistro", "apolice", "previdencia", "corretor",
        "fianca", "premio", "credito", "conta", "acesso", "portal",
        "login", "cliente", "minha", "meu", "area", "atendimento",
    ]
    for word in _SECTOR_WORDS:
        variants.add(f"{name}-{word}.{tld}")
        variants.add(f"{word}-{name}.{tld}")
        variants.add(f"{name}{word}.{tld}")
        variants.add(f"{word}{name}.{tld}")

    variants.discard(domain)
    # Remove obviously invalid candidates (empty labels, too long, bad chars)
    _valid_label = re.compile(r'^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]$|^[a-z0-9]$')
    clean = set()
    for v in variants:
        label = v.split(".")[0]
        if _valid_label.match(label) and len(v) <= 253:
            clean.add(v)
    return sorted(clean)


def _resolve_domain(d: str, timeout: int = 3) -> list[str]:
    try:
        r = _subp(["dig","+short","+time=2","+tries=1","A", d],
                           capture_output=True, text=True, timeout=timeout)
        ips = [l.strip() for l in r.stdout.strip().splitlines()
               if re.match(r"^\d+\.\d+\.\d+\.\d+$", l.strip())]
        return ips
    except Exception:
        return []


_BROKER_NS = frozenset({
    "afternic", "sedoparking", "sedo.", "parkingcrew", "bodis.", "porkbun",
    "hugedomains", "dan.com", "sudos.co", "flippa", "undeveloped",
    "uniregistry", "squadhelp", "brandpa", "efty.",
})

def _check_typo(domain: str) -> dict:
    ips = _resolve_domain(domain)

    # NS lookup Ã¢â‚¬â€ catches domains with NS but no A (e.g. .uy ccTLDs)
    ns_raw = ""
    try:
        r = subprocess.run(["dig", "+short", domain, "NS"],
                           capture_output=True, text=True, timeout=4)
        ns_raw = r.stdout.strip().lower()
    except Exception:
        pass

    registered = len(ips) > 0 or bool(ns_raw)
    result = {"domain": domain, "registered": registered, "ips": ips, "risk": "low"}

    if not registered:
        return result

    result["risk"] = "medium"

    # MX record check Ã¢â‚¬â€ domain capable of receiving email Ã¢â€ â€™ phishing escalation
    try:
        r = subprocess.run(["dig", "+short", domain, "MX"],
                           capture_output=True, text=True, timeout=4)
        mx_lines = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
        if mx_lines:
            result["has_mx"]    = True
            result["mx_records"] = mx_lines[:3]
    except Exception:
        pass

    # Broker NS fingerprint Ã¢â‚¬â€ catches squatters even without HTTP (302-only domains)
    if ns_raw and any(b in ns_raw for b in _BROKER_NS):
        result["risk"]   = "high"
        result["status"] = "broker_listed"
        return result

    if not ips:
        result["status"] = "registered_no_ip"
        return result

    # SSL certificate check Ã¢â‚¬â€ brand keyword in cert = full phishing setup
    try:
        import ssl as _ssl, socket as _socket
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE
        with _socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cn   = dict(x[0] for x in cert.get("subject", [])).get("commonName", "")
                sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                result["ssl"] = {"cn": cn, "sans": sans[:5]}
                _brand_kw = ["portoseguro", "porto-seguro", "portobank",
                             "averbeporto", "porto seguro"]
                cert_text = (cn + " " + " ".join(sans)).lower()
                if any(k in cert_text for k in _brand_kw):
                    result["ssl"]["brand_in_cert"] = True
    except Exception:
        pass

    # HTTP check Ã¢â‚¬â€ follow redirects, detect broker/sale landing pages
    try:
        status_code, raw, hdrs = http_get(f"http://{domain}", timeout=5, retries=1)
        if status_code:
            body      = raw[:1000].decode("utf-8", "ignore").lower()
            final_url = hdrs.get("location", "").lower() if isinstance(hdrs, dict) else ""
            broker_signals = [
                "for sale", "buy this domain", "domain for sale",
                "buy-domain", "make an offer", "purchase this domain",
                "domain is for sale", "buy domain", "domain auction",
                "synergytech.com/buy", "dan.com/", "afternic.com",
                "sedo.com/", "hugedomains.com", "undeveloped.com",
            ]
            if any(s in body or s in final_url for s in broker_signals):
                result["risk"]        = "high"
                result["status"]      = "broker_listed"
                result["status_code"] = status_code
                if final_url:
                    result["redirect_to"] = final_url[:120]
            elif any(x in body for x in ["parked", "domain expired", "lander system"]):
                result["risk"]   = "low"
                result["status"] = "parked"
            else:
                result["risk"]        = "high"
                result["status"]      = "active"
                result["status_code"] = status_code
                # Escalate: active domain with email capability = critical
                if result.get("has_mx") or result.get("ssl", {}).get("brand_in_cert"):
                    result["risk"] = "critical"
        else:
            result["status"] = "registered_unreachable"
    except Exception:
        result["status"] = "registered_unreachable"

    return result


def _whois_registrant(domain: str) -> dict:
    """Extract registrant email + org from WHOIS. Rate-limited Ã¢â‚¬â€ use sparingly."""
    try:
        w = subprocess.run(["whois", domain],
                           capture_output=True, text=True, timeout=10)
        info: dict = {}
        for line in w.stdout.splitlines():
            ll = line.lower()
            val = line.split(":", 1)[-1].strip()
            if not val:
                continue
            if not info.get("email") and any(k in ll for k in
                    ("registrant email", "owner-email", "e-mail:", "registrant e-mail")):
                info["email"] = val[:80]
            if not info.get("org") and any(k in ll for k in
                    ("registrant org", "registrant name", "owner:", "org-name")):
                info["org"] = val[:80]
        # Detect company-owned domains by registrant
        _co_kw = ["porto seguro", "portoseguro", "averbeporto", "itaÃƒÂº", "itau unibanco"]
        owned_text = (info.get("email", "") + " " + info.get("org", "")).lower()
        if any(k in owned_text for k in _co_kw):
            info["company_owned"] = True
        return info
    except Exception:
        return {}


def run_typosquatting(domain: str, max_variants: int = 1200,
                      extra_words: list | None = None) -> dict:
    """
    Generate typosquat variants and check if registered.
    extra_words: additional brand words to sweep all ccTLDs against.
    """
    all_variants: list = _typo_variants(domain)
    variants: set = set(all_variants[:max_variants])

    for word in (extra_words or []):
        for tld in _CC_TLDS:
            variants.add(f"{word}{tld}")

    results = []
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(_check_typo, d): d for d in variants}
        for fut in as_completed(futures):
            results.append(fut.result())

    registered = [r for r in results if r["registered"]]

    # WHOIS enrichment Ã¢â‚¬â€ only for active/broker domains, max 30 to avoid rate-limiting
    _risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    enrich_targets = sorted(
        [r for r in registered if r.get("status") in ("active", "broker_listed")],
        key=lambda r: _risk_order.get(r.get("risk", "low"), 3)
    )[:30]
    with ThreadPoolExecutor(max_workers=5) as pool:
        whois_futures = {pool.submit(_whois_registrant, r["domain"]): r
                         for r in enrich_targets}
        for fut in as_completed(whois_futures):
            rec = whois_futures[fut]
            info = fut.result()
            if info:
                rec.update(info)
                if info.get("company_owned"):
                    rec["risk"]   = "low"
                    rec["status"] = "company_owned"

    active = [r for r in registered if r.get("status") in ("active", "broker_listed")]

    return {
        "domain":           domain,
        "total_checked":    len(variants),
        "registered":       sorted(registered,
                                   key=lambda r: _risk_order.get(r.get("risk", "low"), 3)),
        "active_count":     len(active),
        "registered_count": len(registered),
        "scanned_at":       datetime.now().isoformat(timespec="seconds"),
    }


def run_opensquat_monitor(keywords: list[str], work_dir: str = "/tmp") -> dict:
    """
    Run opensquat with keyword list against fresh CT log feed.
    Returns newly-registered domains matching the brand keywords.
    """
    import tempfile, json as _json

    kw_file = f"{work_dir}/opensquat_kw.txt"
    out_file = f"{work_dir}/opensquat_out.json"
    try:
        with open(kw_file, "w") as f:
            f.write("\n".join(keywords))
    except Exception as e:
        return {"error": str(e), "findings": []}

    try:
        r = subprocess.run(
            ["opensquat", "-k", kw_file, "--ct", "--phishing",
             "--output", out_file, "--format", "json"],
            capture_output=True, text=True, timeout=300,
        )
    except FileNotFoundError:
        # opensquat not installed Ã¢â‚¬â€ try pip-installed path
        try:
            r = subprocess.run(
                ["python3", "-m", "opensquat", "-k", kw_file, "--ct",
                 "--output", out_file, "--format", "json"],
                capture_output=True, text=True, timeout=300,
            )
        except Exception as e:
            return {"error": f"opensquat not available: {e}", "findings": []}
    except subprocess.TimeoutExpired:
        return {"error": "opensquat timed out", "findings": []}

    # Parse JSON output
    findings = []
    try:
        with open(out_file) as f:
            raw = _json.load(f)
        domains = raw if isinstance(raw, list) else raw.get("domains", [])
        for entry in domains:
            d = entry if isinstance(entry, str) else entry.get("domain", "")
            if d:
                findings.append(d)
    except Exception:
        # Fallback: parse stdout line-by-line
        for line in r.stdout.splitlines():
            parts = line.strip().split(" - ")
            if len(parts) >= 2:
                d = parts[1].strip()
                if "." in d:
                    findings.append(d)

    # Enrich each new domain with _check_typo
    enriched = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_check_typo, d): d for d in findings}
        for fut in as_completed(futures):
            enriched.append(fut.result())

    return {
        "keywords":   keywords,
        "new_domains": len(findings),
        "findings":   sorted(enriched, key=lambda r: {"critical":0,"high":1,"medium":2,"low":3}.get(r.get("risk","low"),3)),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Cloud Asset Discovery Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def _org_name_variants(org_name: str, domains: list) -> list[str]:
    """Generate bucket name candidates from org name and domains."""
    names = set()
    # From org name
    clean = re.sub(r"[^a-z0-9]+", "-", org_name.lower()).strip("-")
    nospace = clean.replace("-","")
    names.update([clean, nospace])

    # From domains (use all of them for broader brand coverage)
    for d in domains:
        base = d.split(".")[0]
        names.add(base)
        names.update([f"{base}-prod", f"{base}-staging", f"{base}-dev",
                      f"{base}-backup", f"{base}-assets", f"{base}-static",
                      f"{base}-media", f"{base}-data", f"{base}-files",
                      f"{base}-logs", f"{base}-archive", f"{base}-uploads",
                      f"{base}-images", f"{base}-documents", f"{base}-reports",
                      f"{base}-api", f"{base}-infra", f"{base}-internal",
                      f"{base}-private", f"{base}-public", f"{base}-shared"])

    # Common suffix patterns applied to all base names
    extras = set()
    for n in list(names):
        for sfx in ["-prod", "-stg", "-dev", "-test", "-staging", "-backup",
                    "-assets", "-public", "-private", "-data", "-logs", ""]:
            extras.add(f"{n}{sfx}")
    names.update(extras)

    # Prioritize: shorter/simpler names first (more likely to be real buckets)
    return sorted(names, key=lambda x: (len(x), x))[:80]


def _curl_check(url: str) -> tuple[int, str]:
    """HTTP GET via curl, returning (status_code, response_body) Ã¢â‚¬â€ body capped at ~4KB by curl's
    own read; safe for read-only enumeration (no writes/uploads are ever performed)."""
    try:
        r = subprocess.run(
            ["curl", "-s", "-L", "--connect-timeout", "3", "-m", "5",
             "-w", "\n__HTTP_CODE__%{http_code}", "--insecure", url],
            capture_output=True, text=True, timeout=8,
        )
        out = r.stdout or ""
        marker = "\n__HTTP_CODE__"
        idx = out.rfind(marker)
        if idx == -1:
            return 0, ""
        body = out[:idx]
        code_str = out[idx + len(marker):].strip()
        code = int(code_str) if code_str.isdigit() else 0
        return code, body
    except Exception:
        return 0, ""


# Anonymous-readable ACL grants that indicate over-permissive bucket policies.
# These checks are read-only (HTTP GET on the bucket's `?acl` sub-resource) Ã¢â‚¬â€
# no objects are ever written, modified, or deleted.
_PUBLIC_GRANTEES = re.compile(
    r'(AllUsers|AuthenticatedUsers|http://acs\.amazonaws\.com/groups/global/AllUsers|'
    r'http://acs\.amazonaws\.com/groups/global/AuthenticatedUsers)', re.I)
_WRITE_PERMS = re.compile(r'<Permission>\s*(WRITE|WRITE_ACP|FULL_CONTROL)\s*</Permission>', re.I)


def _check_anonymous_acl(acl_url: str) -> dict | None:
    """Read-only probe of a bucket's ACL sub-resource for public write grants.

    Returns details about overly-permissive ACL entries (e.g. AllUsers: WRITE)
    without performing any write operation. Returns None if the ACL is not
    readable anonymously or contains no public grants.
    """
    status, body = _curl_check(acl_url)
    if status != 200 or not body:
        return None
    grants = re.findall(r'<Grant>.*?</Grant>', body, re.S | re.I)
    public_write = []
    public_read = []
    for grant in grants:
        if not _PUBLIC_GRANTEES.search(grant):
            continue
        perms = re.findall(r'<Permission>\s*([A-Z_]+)\s*</Permission>', grant, re.I)
        for perm in perms:
            p = perm.upper()
            if p in ("WRITE", "WRITE_ACP", "FULL_CONTROL"):
                public_write.append(p)
            elif p in ("READ", "READ_ACP"):
                public_read.append(p)
    if not public_write and not public_read:
        return None
    return {"public_write_perms": sorted(set(public_write)), "public_read_perms": sorted(set(public_read))}


def _check_s3_bucket(name: str) -> dict | None:
    """Check if an S3 bucket exists and its access level."""
    urls = [f"https://{name}.s3.amazonaws.com/", f"https://s3.amazonaws.com/{name}/"]
    for url in urls:
        status, raw = _curl_check(url)
        if status == 200:
            snippet = raw[:5000] if raw else ""
            # Parse XML listing for file count, sample objects and sensitive names
            obj_count = snippet.count("<Key>")
            sample_objects = re.findall(r'<Key>([^<]+)</Key>', snippet)[:15]
            _SENS = re.compile(r'<Key>([^<]*(?:\.env|\.sql|backup|\.pem|\.key|secret|password|credential|config|dump|\.bak|\.log)[^<]*)</Key>', re.I)
            sensitive_files = _SENS.findall(snippet)
            access_detail = "public_read"
            if sensitive_files:
                access_detail = "public_read_sensitive"

            # Read-only ACL probe Ã¢â‚¬â€ checks for AllUsers/AuthenticatedUsers
            # WRITE/FULL_CONTROL grants without writing anything.
            acl = _check_anonymous_acl(url + "?acl")
            if acl and acl.get("public_write_perms"):
                access_detail = "public_write_acl"

            desc = (f"S3 bucket {name} is publicly readable ({obj_count} objects listed" +
                    (f", including {len(sensitive_files)} sensitive files: {', '.join(sensitive_files[:3])}" if sensitive_files else "") + ")")
            if acl and acl.get("public_write_perms"):
                desc += f". ACL grants anonymous {'/'.join(acl['public_write_perms'])} access Ã¢â‚¬â€ bucket can likely be written to or have its ACL modified by anyone."

            return {"name": name, "provider": "AWS S3", "url": url,
                    "access": access_detail, "severity": "critical",
                    "snippet": snippet[:500],
                    "object_count": obj_count,
                    "sample_objects": sample_objects,
                    "sensitive_files": sensitive_files[:10],
                    "acl": acl,
                    "desc": desc}
        if status == 403:
            # Bucket exists but listing is denied Ã¢â‚¬â€ still probe the ACL read-only,
            # since some buckets block listing but expose a writable ACL.
            acl = _check_anonymous_acl(urls[0] + "?acl")
            if acl and acl.get("public_write_perms"):
                return {"name": name, "provider": "AWS S3", "url": urls[0],
                        "access": "public_write_acl", "severity": "critical",
                        "snippet": "", "object_count": 0, "sample_objects": [],
                        "sensitive_files": [], "acl": acl,
                        "desc": f"S3 bucket {name} blocks listing but its ACL grants anonymous "
                                f"{'/'.join(acl['public_write_perms'])} access Ã¢â‚¬â€ bucket can likely be "
                                f"written to or have its ACL modified by anyone."}
            return {"name": name, "provider": "AWS S3", "url": urls[0],
                    "access": "exists_private", "severity": "info", "snippet": ""}
        if status in (301, 302):
            return {"name": name, "provider": "AWS S3", "url": urls[0],
                    "access": "exists_redirect", "severity": "low", "snippet": ""}
    return None


def _check_azure_blob(name: str) -> dict | None:
    """Check Azure Blob storage containers."""
    clean = re.sub(r"[^a-z0-9]", "", name.lower())[:24]
    if len(clean) < 3:
        return None
    url = f"https://{clean}.blob.core.windows.net/?comp=list"
    status, raw = _curl_check(url)
    if status == 200:
        snippet = raw[:3000] if raw else ""
        obj_count = snippet.count("<Name>")
        sample_objects = re.findall(r'<Name>([^<]+)</Name>', snippet)[:15]
        _SENS_AZ = re.compile(r'<Name>([^<]*(?:\.env|\.sql|backup|\.pem|\.key|secret|password|credential|config|dump|\.bak|\.log)[^<]*)</Name>', re.I)
        sensitive_files = _SENS_AZ.findall(snippet)
        access_detail = "public_list"
        if sensitive_files:
            access_detail = "public_list_sensitive"
        return {"name": clean, "provider": "Azure Blob", "url": url,
                "access": access_detail, "severity": "critical",
                "snippet": snippet[:500],
                "object_count": obj_count,
                "sample_objects": sample_objects,
                "sensitive_files": sensitive_files[:10],
                "desc": f"Azure Blob container {clean} is publicly listed ({obj_count} objects)" +
                        (f", including {len(sensitive_files)} sensitive files: {', '.join(sensitive_files[:3])}" if sensitive_files else "")}
    if status == 403:
        return {"name": clean, "provider": "Azure Blob", "url": url,
                "access": "exists_private", "severity": "info", "snippet": ""}
    return None


def _check_gcp_bucket(name: str) -> dict | None:
    """Check GCP Cloud Storage buckets."""
    url = f"https://storage.googleapis.com/{name}/"
    status, raw = _curl_check(url)
    if status == 200:
        snippet = raw[:3000] if raw else ""
        obj_count = snippet.count("<Key>") + snippet.count("<Name>")
        sample_objects = re.findall(r'<(?:Key|Name)>([^<]+)</(?:Key|Name)>', snippet)[:15]
        _SENS_GCP = re.compile(r'<(?:Key|Name)>([^<]*(?:\.env|\.sql|backup|\.pem|\.key|secret|password|credential|config|dump|\.bak|\.log)[^<]*)</(?:Key|Name)>', re.I)
        sensitive_files = _SENS_GCP.findall(snippet)
        access_detail = "public_read"
        if sensitive_files:
            access_detail = "public_read_sensitive"

        acl = _check_anonymous_acl(url + "?acl")
        if acl and acl.get("public_write_perms"):
            access_detail = "public_write_acl"

        desc = (f"GCP bucket {name} is publicly readable ({obj_count} objects listed)" +
                (f", including {len(sensitive_files)} sensitive files: {', '.join(sensitive_files[:3])}" if sensitive_files else ""))
        if acl and acl.get("public_write_perms"):
            desc += f". ACL grants anonymous {'/'.join(acl['public_write_perms'])} access Ã¢â‚¬â€ bucket can likely be written to or have its ACL modified by anyone."

        return {"name": name, "provider": "GCP Storage", "url": url,
                "access": access_detail, "severity": "critical",
                "snippet": snippet[:500],
                "object_count": obj_count,
                "sample_objects": sample_objects,
                "sensitive_files": sensitive_files[:10],
                "acl": acl,
                "desc": desc}
    if status == 403:
        acl = _check_anonymous_acl(url + "?acl")
        if acl and acl.get("public_write_perms"):
            return {"name": name, "provider": "GCP Storage", "url": url,
                    "access": "public_write_acl", "severity": "critical",
                    "snippet": "", "object_count": 0, "sample_objects": [],
                    "sensitive_files": [], "acl": acl,
                    "desc": f"GCP bucket {name} blocks listing but its ACL grants anonymous "
                            f"{'/'.join(acl['public_write_perms'])} access Ã¢â‚¬â€ bucket can likely be "
                            f"written to or have its ACL modified by anyone."}
        return {"name": name, "provider": "GCP Storage", "url": url,
                "access": "exists_private", "severity": "info", "snippet": ""}
    return None


def _cloud_reachable() -> bool:
    """Quick HTTP check via curl (respects connect timeout, avoids glibc DNS hangs)."""
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--connect-timeout", "3", "-m", "5",
             "https://s3.amazonaws.com/"],
            capture_output=True, text=True, timeout=8,
        )
        return r.stdout.strip() in ("200", "301", "302", "403", "404")
    except Exception:
        return False


def run_cloud_assets(domains: list, org_name: str = "") -> dict:
    """Discover cloud storage buckets for an organization."""
    if not _cloud_reachable():
        return {
            "checked": 0, "findings": [], "public_count": 0, "private_count": 0,
            "error": "Cloud providers unreachable (network/firewall)",
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
        }
    names = _org_name_variants(org_name or domains[0].split(".")[0], domains)
    findings = []
    MODULE_TIMEOUT = 45  # seconds hard cap

    def check_all(name):
        results = []
        r = _check_s3_bucket(name)
        if r: results.append(r)
        r = _check_azure_blob(name)
        if r: results.append(r)
        r = _check_gcp_bucket(name)
        if r: results.append(r)
        return results

    pool = ThreadPoolExecutor(max_workers=20)
    futures = {pool.submit(check_all, n): n for n in names}
    done, _ = __import__("concurrent.futures", fromlist=["wait"]).wait(
        futures, timeout=MODULE_TIMEOUT
    )
    pool.shutdown(wait=False, cancel_futures=True)
    for fut in done:
        try:
            findings.extend(fut.result())
        except Exception:
            pass

    public  = [f for f in findings if "public" in f.get("access","")]
    private = [f for f in findings if "private" in f.get("access","")]

    return {
        "checked":       len(names) * 3,
        "findings":      sorted(findings, key=lambda f: ["critical","info","low"].index(f.get("severity","low"))),
        "public_count":  len(public),
        "private_count": len(private),
        "scanned_at":    datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ GitHub Org Repository Discovery Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def run_github_repos(domains: list, token: str = "") -> dict:
    """
    Enumerate public GitHub repositories belonging to the target organization.
    Uses GitHub Search + Org API to find all repos, then scans each for
    secrets and sensitive filenames.
    """
    import urllib.request as _ur
    import urllib.parse as _up
    import json as _j

    headers = {"User-Agent": "ASM-Platform/1.0", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def _gh_get(url: str) -> dict | list | None:
        try:
            req = _ur.Request(url, headers=headers)
            with _ur.urlopen(req, timeout=10) as r:
                return _j.loads(r.read())
        except Exception:
            return None

    # Derive candidate org names from domains
    orgs: set[str] = set()
    for d in domains:
        base = d.split(".")[0].lower()
        orgs.add(base)
        # Also try without hyphens/underscores
        orgs.add(base.replace("-", "").replace("_", ""))

    all_repos: list[dict] = []
    secrets_found: list[dict] = []
    sensitive_files: list[dict] = []
    found_orgs: list[str] = []

    _SENSITIVE_FILES = re.compile(
        r'\.env$|\.env\.|secrets?\.|credentials?\.|config\.(json|yaml|yml|xml)$'
        r'|\.pem$|\.key$|id_rsa|\.aws|\.ssh|docker-compose\.yml$'
        r'|terraform\.tfvars$|\.tfstate$|kube.*config$',
        re.I
    )

    for org in sorted(orgs)[:6]:
        # Check if org exists on GitHub
        org_data = _gh_get(f"https://api.github.com/orgs/{org}")
        if not isinstance(org_data, dict) or org_data.get("message") == "Not Found":
            continue
        found_orgs.append(org)
        public_repos = org_data.get("public_repos", 0)

        # Fetch repo list (up to 100)
        repos_data = _gh_get(f"https://api.github.com/orgs/{org}/repos?per_page=100&sort=updated")
        if not isinstance(repos_data, list):
            continue

        for repo in repos_data:
            repo_name  = repo.get("full_name", "")
            repo_url   = repo.get("html_url", "")
            updated_at = repo.get("updated_at", "")[:10]
            is_fork    = repo.get("fork", False)
            default_br = repo.get("default_branch", "main")
            stars      = repo.get("stargazers_count", 0)

            all_repos.append({
                "name":       repo_name,
                "url":        repo_url,
                "updated_at": updated_at,
                "fork":       is_fork,
                "stars":      stars,
                "language":   repo.get("language", ""),
                "private":    repo.get("private", False),
            })

            # Scan tree for sensitive filenames (top-level only, fast)
            tree_data = _gh_get(
                f"https://api.github.com/repos/{repo_name}/git/trees/{default_br}?recursive=0"
            )
            if isinstance(tree_data, dict):
                for item in tree_data.get("tree", [])[:200]:
                    fname = item.get("path", "")
                    if _SENSITIVE_FILES.search(fname):
                        sensitive_files.append({
                            "repo":  repo_name,
                            "file":  fname,
                            "url":   f"{repo_url}/blob/{default_br}/{fname}",
                            "severity": "high",
                        })

        # GitHub code search for secrets in org repos
        _SECRET_QUERIES = [
            ("AWS key",         f'org:{org} "AKIA" language:python language:javascript language:yaml'),
            ("Private key",     f'org:{org} "BEGIN RSA PRIVATE KEY"'),
            ("DB credentials",  f'org:{org} "DB_PASSWORD" OR "DATABASE_URL" filename:.env'),
            ("API tokens",      f'org:{org} "api_key" OR "api_secret" OR "client_secret" extension:json extension:yaml'),
        ]
        for query_label, query in _SECRET_QUERIES:
            result = _gh_get(
                "https://api.github.com/search/code?" +
                _up.urlencode({"q": query, "per_page": "5"})
            )
            if isinstance(result, dict) and result.get("total_count", 0) > 0:
                for item in result.get("items", [])[:3]:
                    secrets_found.append({
                        "query":    query_label,
                        "repo":     item.get("repository", {}).get("full_name", ""),
                        "file":     item.get("name", ""),
                        "url":      item.get("html_url", ""),
                        "severity": "high",
                    })

    findings: list[dict] = []
    for sf in sensitive_files:
        findings.append({
            "type":     "github_sensitive_file",
            "title":    f"Arquivo sensÃƒÂ­vel em repo pÃƒÂºblico: {sf['file']} ({sf['repo']})",
            "severity": sf["severity"],
            "category": "leaks",
            "desc":     f"Arquivo `{sf['file']}` encontrado no repositÃƒÂ³rio pÃƒÂºblico `{sf['repo']}`. Pode conter segredos ou configuraÃƒÂ§ÃƒÂµes internas.",
            "url":      sf["url"],
            "value":    sf["url"],
            "host":     domains[0] if domains else "",
        })
    for sf in secrets_found:
        findings.append({
            "type":     "github_secret_pattern",
            "title":    f"PadrÃƒÂ£o de segredo em GitHub: {sf['query']} ({sf['repo']})",
            "severity": "critical",
            "category": "leaks",
            "desc":     f"GitHub code search encontrou padrÃƒÂ£o '{sf['query']}' em `{sf['file']}` do repo `{sf['repo']}`.",
            "url":      sf["url"],
            "value":    sf["url"],
            "host":     domains[0] if domains else "",
        })

    return {
        "orgs_found":       found_orgs,
        "total_repos":      len(all_repos),
        "repos":            all_repos[:50],
        "sensitive_files":  sensitive_files,
        "secrets_found":    secrets_found,
        "findings":         findings,
        "scanned_at":       datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ DNSSEC Check Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def run_dnssec_check(domains: list) -> dict:
    """Check DNSSEC for up to 10 domains Ã¢â‚¬â€ single DNS batch call."""
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

        # NSEC3 check (only if DNSSEC enabled Ã¢â‚¬â€ one more batch)
        if info["dnssec_enabled"]:
            b2 = _dns_batch([(domain, "NSEC3PARAM", [])])
            if b2.get((domain, "NSEC3PARAM")):
                info["nsec_type"] = "NSEC3"

        # AD flag check (needs different flags, separate call Ã¢â‚¬â€ but faster)
        try:
            r = _subp(["dig", "+dnssec", "+time=2", "+tries=1", domain, "A"],
                      capture_output=True, text=True, timeout=8)
            if "flags:" in r.stdout and " ad;" in r.stdout.lower():
                info["validates"] = True
        except Exception:
            pass

        if not info["dnssec_enabled"]:
            info["issues"].append("DNSSEC not enabled")
            findings.append({
                "type": "dnssec", "title": f"DNSSEC: {domain}",
                "severity": "medium", "category": "dns",
                "desc": f"`{domain}` sem DNSSEC Ã¢â‚¬â€ respostas DNS podem ser forjadas.",
                "host": domain, "value": domain, "module": "dnssec",
            })
        elif info["nsec_type"] == "NSEC":
            findings.append({
                "type": "dnssec", "title": f"NSEC zone walking: {domain}",
                "severity": "low", "category": "dns",
                "desc": f"`{domain}` usa NSEC Ã¢â‚¬â€ permite enumerar subdomÃƒÂ­nios.",
                "host": domain, "value": domain, "module": "dnssec",
            })
        results.append(info)

    return {"results": results, "findings": findings, "total": len(findings),
            "scanned_at": datetime.now().isoformat(timespec="seconds")}


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Related Domain Discovery Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

_BRAND_TLDS = [
    # Brazil
    ".com.br", ".net.br", ".org.br", ".br", ".gov.br", ".edu.br",
    # Latin America
    ".ar", ".com.ar", ".uy", ".com.uy", ".cl", ".com.cl", ".co", ".com.co",
    ".pe", ".com.pe", ".mx", ".com.mx", ".py", ".com.py", ".bo", ".com.bo",
    ".ec", ".com.ec", ".ve", ".com.ve", ".pa", ".com.pa", ".cr", ".co.cr",
    ".do", ".com.do",
    # Global gTLDs
    ".com", ".net", ".org", ".io", ".app", ".dev", ".cloud", ".ai",
    ".info", ".biz", ".us", ".co.uk", ".uk", ".de", ".fr", ".es", ".it",
    ".nl", ".eu", ".ca", ".au", ".in", ".jp", ".cn", ".pt", ".ch",
    ".digital", ".online", ".tech", ".site", ".store", ".live",
    ".bank", ".finance", ".seguros", ".solutions", ".security",
    ".network", ".email", ".systems", ".services", ".technology",
    ".ventures", ".capital", ".insurance", ".healthcare", ".agency",
    ".consulting", ".marketing", ".media", ".software", ".legal",
    ".business", ".company", ".enterprises", ".institute",
    ".management", ".partners", ".support", ".training",
]

_BRAND_PREFIXES = ["", "www.", "m.", "app.", "api.", "portal.", "login.",
                   "secure.", "mail.", "vpn.", "remote.", "web.", "my."]

def _related_tld_candidates(domain: str) -> set:
    """Generate TLD-variation candidates from the primary domain name."""
    parts = domain.rsplit(".", 2)
    base = parts[0]
    candidates = set()
    for tld in _BRAND_TLDS:
        candidates.add(f"{base}{tld}")
    candidates.discard(domain)
    return candidates


def _related_crtsh_org(domain: str) -> set:
    """
    Query crt.sh to find sibling domains via two methods:
    1. Wildcard search by domain base name across all TLDs (e.g. %portoseguro%)
    2. Org-name search via HTML parse of an individual cert's Subject O= field
    """
    candidates = set()
    # Extract the brand name (first label of the domain, strip country TLD parts)
    parts = domain.split(".")
    base_name = parts[0]  # e.g. "portoseguro" from "portoseguro.com.br"

    # Method A: wildcard by brand name Ã¢â‚¬â€ finds sister domains with same name, different TLD
    try:
        import urllib.parse as _up
        url = f"https://crt.sh/?q=%25{_up.quote(base_name)}%25&output=json"
        status, raw, _ = http_get(url, timeout=20, retries=2)
        if status == 200 and raw:
            certs = json.loads(raw.decode("utf-8", "ignore"))
            for cert in certs[:2000]:
                for field in (cert.get("name_value", ""), cert.get("common_name", "")):
                    for line in (field or "").split("\n"):
                        line = line.strip().lstrip("*.")
                        if not line or " " in line or len(line) > 120:
                            continue
                        p = line.split(".")
                        if len(p) >= 3 and p[-1] == "br":
                            root = ".".join(p[-3:])
                        elif len(p) >= 2:
                            root = ".".join(p[-2:])
                        else:
                            continue
                        if root != domain:
                            candidates.add(root)
    except Exception:
        pass

    # Method B: org-name search Ã¢â‚¬â€ parse Subject O= from cert HTML, then search by org
    try:
        import urllib.parse as _up, re as _re
        _ca_noise = {"let's encrypt", "digicert", "sectigo", "geotrust",
                     "globalsign", "amazon", "google", "microsoft", "cloudflare",
                     "cpanel", "comodo", "godaddy", "thawte", "verisign",
                     "entrust", "identrust", "zerossl", "buypass", "soluti",
                     "ac raiz", "certisign", "serasa"}

        def _extract_subject_org(html: str) -> str:
            # crt.sh HTML uses &nbsp; padding: "Subject:<BR>...organizationName&nbsp;=&nbsp;ORG<BR>"
            # Find the Subject block (before Issuer: section)
            subj_m = _re.search(r'Subject:<BR>(.*?)(?:Issuer:|</TD>|$)', html, _re.DOTALL)
            if not subj_m:
                return ""
            subj = subj_m.group(1)
            # organizationName followed by padding then = then &nbsp; then value then <BR>
            m = _re.search(r'organizationName(?:&nbsp;|\s)+=(?:&nbsp;|\s)+([^<]+)<BR>', subj)
            if not m:
                return ""
            org = m.group(1).replace("&nbsp;", " ").replace("&amp;", "&").strip()
            return org

        # Phase 1: Try to discover org name from OV cert HTML (fast-fail on crt.sh instability)
        org_found = None
        probe_hosts = [f"www.{domain}", f"mail.{domain}"]
        dv_patterns = ("let's encrypt", "r10", "r11", "r12", "r13", "e5", "e6",
                       "e7", "e8", "e9", "globalsign atlas r3 dv", "amazon",
                       "buypass", "zerossl", "google trust", "ssl.com dv")
        for probe in probe_hosts:
            url = f"https://crt.sh/?q={probe}&output=json"
            status, raw, _ = http_get(url, timeout=10, retries=1)
            if status != 200 or not raw:
                continue
            try:
                certs = json.loads(raw.decode("utf-8", "ignore"))
            except Exception:
                continue
            ov_certs = [
                c for c in certs
                if not any(p in c.get("issuer_name", "").lower() for p in dv_patterns)
            ][:5]
            for cert in ov_certs:
                cid = cert.get("id")
                if not cid:
                    continue
                hs, hr, _ = http_get(f"https://crt.sh/?id={cid}", timeout=8, retries=1)
                if hs != 200 or not hr:
                    continue
                org = _extract_subject_org(hr.decode("utf-8", "ignore"))
                if not org:
                    continue
                if any(n in org.lower() for n in _ca_noise):
                    continue
                org_found = org
                break
            if org_found:
                break

            if org_found:
                url2 = f"https://crt.sh/?o={_up.quote(org_found)}&output=json"
                s2, r2, _ = http_get(url2, timeout=25, retries=2)
                if s2 == 200 and r2:
                    try:
                        org_certs = json.loads(r2.decode("utf-8", "ignore"))
                    except Exception:
                        org_certs = []
                    for oc in org_certs[:2000]:
                        for field in (oc.get("name_value", ""), oc.get("common_name", "")):
                            for line in (field or "").split("\n"):
                                line = line.strip().lstrip("*.")
                                if not line or " " in line or len(line) > 120:
                                    continue
                                p = line.split(".")
                                if len(p) >= 3 and p[-1] == "br":
                                    root = ".".join(p[-3:])
                                elif len(p) >= 2:
                                    root = ".".join(p[-2:])
                                else:
                                    continue
                                if root != domain:
                                    candidates.add(root)
                break  # org found and processed Ã¢â‚¬â€ stop trying more probe hosts
    except Exception:
        pass

    return candidates


def _related_reverse_ip(domain: str) -> set:
    """
    Discover sibling domains sharing the same IP block via HackerTarget reverse-IP API.
    Falls back to a simple set of IPs resolved from the primary domain.
    """
    candidates = set()
    try:
        ips = _resolve_domain(domain)
        if not ips:
            return candidates
        for ip in ips[:3]:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            status, raw, _ = http_get(url, timeout=10, retries=1)
            if status == 200 and raw:
                for line in raw.decode("utf-8", "ignore").splitlines():
                    h = line.strip().lstrip("*.")
                    if h and "." in h and " " not in h:
                        parts = h.split(".")
                        if len(parts) >= 3 and parts[-1] == "br":
                            root = ".".join(parts[-3:])
                        elif len(parts) >= 2:
                            root = ".".join(parts[-2:])
                        else:
                            continue
                        if root != domain:
                            candidates.add(root)
    except Exception:
        pass
    return candidates


def run_related_domains(domain: str) -> dict:
    """
    Discover related/sister domains via three complementary methods:
    1. TLD variations of the primary domain name
    2. crt.sh reverse org-name lookup (finds subsidiaries with different brand names)
    3. HackerTarget reverse-IP lookup (finds domains sharing same infrastructure)
    """
    candidates_tld     = _related_tld_candidates(domain)
    candidates_crtsh   = _related_crtsh_org(domain)
    candidates_revip   = _related_reverse_ip(domain)

    all_candidates = candidates_tld | candidates_crtsh | candidates_revip
    all_candidates.discard(domain)

    results = []
    def check_domain(d):
        ips = _resolve_domain(d)
        if ips:
            status_code, raw, _ = http_get(f"https://{d}", timeout=5, retries=1)
            if status_code:
                title_match = re.search(r"<title>(.*?)</title>",
                                        raw[:2000].decode("utf-8", "ignore"), re.I)
                title = title_match.group(1)[:100] if title_match else ""
                return {"domain": d, "ips": ips, "https": True,
                        "title": title, "status": status_code}
            return {"domain": d, "ips": ips, "https": False, "title": "", "status": 0}
        return None

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(check_domain, d): d for d in all_candidates}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)

    return {
        "domain":          domain,
        "checked":         len(all_candidates),
        "checked_tld":     len(candidates_tld),
        "checked_crtsh":   len(candidates_crtsh),
        "checked_revip":   len(candidates_revip),
        "found":           sorted(results, key=lambda r: r["domain"]),
        "count":           len(results),
        "scanned_at":      datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Reverse WHOIS Ã¢â‚¬â€ Asset Attribution (ASM) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def _rdap_registrant(domain: str) -> dict:
    """Extract registrant org/email from public RDAP (free, no key). Often redacted."""
    org = email = ""
    try:
        status, body, _ = http_get(f"https://rdap.org/domain/{domain}", timeout=12, retries=2)
        if status == 200 and body:
            data = json.loads(body)
            for ent in data.get("entities", []):
                roles = ent.get("roles", []) or []
                if "registrant" not in roles and "administrative" not in roles:
                    continue
                vcard = ent.get("vcardArray", [])
                if len(vcard) == 2 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if not isinstance(item, list) or len(item) < 4:
                            continue
                        key, val = item[0], item[3]
                        if isinstance(val, list):
                            val = val[0] if val else ""
                        if not isinstance(val, str):
                            continue
                        if key in ("org", "fn") and not org:
                            org = val
                        elif key == "email" and not email:
                            email = val
    except Exception:
        pass
    return {"org": org.strip(), "email": email.strip()}


def run_reverse_whois(domain: str, whoisxml_key: str = "") -> dict:
    """
    Reverse-WHOIS asset attribution (ASM): discover sibling apex domains owned by
    the same organization by pivoting on the registrant org name and e-mail.

    - Registrant identity is pulled from free public RDAP first.
    - If a WhoisXML API key is configured, its Reverse WHOIS API returns the full
      list of domains registered with the same org/e-mail.

    Sibling apexes are reported for attribution only Ã¢â‚¬â€ they are intentionally NOT
    fed into the active host pool (avoids scanning out-of-scope third-party orgs).
    """
    whoisxml_key = whoisxml_key or os.environ.get("WHOISXML_KEY", "")
    reg   = _rdap_registrant(domain)
    org   = reg["org"]
    email = reg["email"]
    now   = datetime.now().isoformat(timespec="seconds")

    terms = []
    if email and "@" in email and "redacted" not in email.lower() and "privacy" not in email.lower():
        terms.append(("email", email))
    if org and len(org) > 3 and "redacted" not in org.lower() and "privacy" not in org.lower():
        terms.append(("org", org))

    if not whoisxml_key:
        return {
            "domain": domain, "registrant_org": org, "registrant_email": email,
            "sibling_domains": [], "found": [], "count": 0, "source": "rdap-only",
            "note": "Sem WhoisXML key Ã¢â‚¬â€ apenas atribuiÃƒÂ§ÃƒÂ£o de registrante (RDAP). "
                    "Defina whoisxml_key nas Settings para reverse-whois completo.",
            "scanned_at": now,
        }

    if not terms:
        return {
            "domain": domain, "registrant_org": org, "registrant_email": email,
            "sibling_domains": [], "found": [], "count": 0, "source": "whoisxml",
            "note": "Registrante redacted/privacy Ã¢â‚¬â€ sem termo utilizÃƒÂ¡vel para reverse-whois.",
            "scanned_at": now,
        }

    seed_apex  = domain.lower().lstrip(".")
    discovered = {}   # apex -> field that matched
    errors     = []

    for field, value in terms:
        payload = json.dumps({
            "apiKey": whoisxml_key,
            "mode": "purchase",
            "searchType": "current",
            "basicSearchTerms": {"include": [value]},
        }).encode()
        try:
            req = urllib.request.Request(
                "https://reverse-whois.whoisxmlapi.com/api/v2",
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": UA},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=25) as resp:
                rdata = json.loads(resp.read())
            for d in rdata.get("domainsList", []) or []:
                d = str(d).lower().strip().strip(".")
                if d and d != seed_apex:
                    discovered.setdefault(d, field)
        except Exception as exc:
            errors.append(f"{field}: {exc}")

    items = list(discovered.items())

    def _check(item):
        d, field = item
        ips = _resolve_domain(d)
        return {"domain": d, "matched_by": field, "ips": ips, "live": bool(ips)}

    found = []
    if items:
        with ThreadPoolExecutor(max_workers=20) as pool:
            for r in pool.map(_check, items):
                found.append(r)

    found.sort(key=lambda x: (not x["live"], x["domain"]))
    return {
        "domain": domain, "registrant_org": org, "registrant_email": email,
        "terms": [v for _, v in terms],
        "sibling_domains": sorted(discovered.keys()),
        "found": found,
        "count": len(found),
        "live_count": sum(1 for f in found if f["live"]),
        "source": "whoisxml", "errors": errors, "scanned_at": now,
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ GitHub Code Search Ã¢â‚¬â€ Subdomain Discovery (Bug Bounty) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def run_github_subdomains(domains, github_token: str = "") -> dict:
    """
    Mine subdomains from public source code via GitHub code search. Distinct from
    the secret-oriented GitHub search (run_leaks_recon): here we extract any
    `*.<domain>` hostname appearing in indexed code Ã¢â‚¬â€ CI configs, JS, docs, infra.

    Code search requires authentication; without a token results are empty.
    Returned `subdomains` are auto-merged into the host pool by the pipeline.
    """
    if isinstance(domains, str):
        domains = [domains]
    github_token = github_token or os.environ.get("GITHUB_TOKEN", "")
    now = datetime.now().isoformat(timespec="seconds")

    if not _dns_resolves("api.github.com"):
        return {"domains": domains, "found": [], "subdomains": [], "count": 0,
                "authenticated": bool(github_token),
                "errors": ["api.github.com unreachable"], "scanned_at": now}

    import urllib.parse as _up
    headers = {"Accept": "application/vnd.github.v3.text-match+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    found  = {}     # subdomain -> set(repos)
    errors = []

    for domain in domains:
        domain = str(domain).lower().strip().strip(".")
        if not domain:
            continue
        sub_re = re.compile(
            r"([a-z0-9](?:[a-z0-9\-]{0,62}\.)+" + re.escape(domain) + r")\b", re.I
        )
        for page in range(1, 6):
            q   = _up.quote(f'"{domain}"')
            url = f"https://api.github.com/search/code?q={q}&per_page=50&page={page}"
            try:
                status, body, _ = http_get(url, timeout=15, retries=1, extra_headers=headers)
            except Exception as exc:
                errors.append(f"{domain} p{page}: {exc}")
                break
            if status == 401:
                errors.append("GitHub auth requerida Ã¢â‚¬â€ configure github_token nas Settings")
                break
            if status == 403:
                errors.append("GitHub rate limit (code search: ~10 req/min) Ã¢â‚¬â€ aguarde")
                break
            if status == 422:
                break   # no more results
            if status != 200 or not body:
                errors.append(f"{domain} p{page}: HTTP {status}")
                break
            try:
                data = json.loads(body)
            except Exception:
                break
            github_items = data.get("items", []) or []
            if not github_items:
                break
            for item in github_items:
                repo = item.get("repository", {}).get("full_name", "")
                blob = item.get("path", "") or ""
                for tm in item.get("text_matches", []) or []:
                    blob += "\n" + (tm.get("fragment", "") or "")
                for m in sub_re.findall(blob):
                    sub = m.lower().strip(".")
                    if sub and sub != domain:
                        found.setdefault(sub, set()).add(repo)
            if len(github_items) < 50:
                break
            time.sleep(2)   # respect code-search rate limit

    results = [
        {"subdomain": s, "repos": sorted(r)[:5], "repo_count": len(r)}
        for s, r in sorted(found.items())
    ]
    return {
        "domains": domains,
        "found": results,
        "subdomains": sorted(found.keys()),
        "count": len(results),
        "authenticated": bool(github_token),
        "errors": errors,
        "scanned_at": now,
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Cloudflare / CDN Origin Discovery (Bug Bounty) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

_ORIGIN_SUB_PREFIXES = [
    "direct", "origin", "origin-www", "direct-connect", "cpanel", "webmail",
    "mail", "smtp", "mx", "email", "ftp", "vpn", "remote", "server", "dev",
    "staging", "stage", "test", "uat", "old", "legacy", "autodiscover",
    "ns1", "ns2", "portal", "backend", "api-direct",
]

def _od_title(body: bytes) -> str:
    try:
        m = re.search(r"<title[^>]*>(.*?)</title>",
                      body[:4000].decode("utf-8", "ignore"), re.I | re.S)
        return m.group(1).strip()[:120] if m else ""
    except Exception:
        return ""

def run_origin_discovery(domains, hosts=None, shodan_key: str = "") -> dict:
    """
    Find the real origin IP behind Cloudflare/CDN for each domain (WAF bypass).

    Candidate origin IPs are gathered passively from DNS (MX, SPF ip4:/include:,
    and common non-proxied subdomains) and, when a Shodan key is set, from a
    certificate/hostname search. Each candidate is then verified by an HTTPS
    request carrying the target Host header and comparing the response title/status
    to the CDN-fronted baseline. Origins are reported only Ã¢â‚¬â€ never auto-scanned.

    Note: TLS SNI follows the candidate IP, so virtual-host-by-SNI origins may not
    confirm; Host-header routing still catches the common case.
    """
    if isinstance(domains, str):
        domains = [domains]
    shodan_key = shodan_key or os.environ.get("SHODAN_API_KEY", "")
    now = datetime.now().isoformat(timespec="seconds")
    import urllib.parse as _up
    results = []

    for domain in domains:
        domain = str(domain).lower().strip().strip(".")
        if not domain:
            continue

        # Ã¢â€â‚¬Ã¢â€â‚¬ Baseline: is the apex fronted by Cloudflare/CDN? (headers are definitive) Ã¢â€â‚¬Ã¢â€â‚¬
        base_status, base_body, base_hdrs = http_get(f"https://{domain}/", timeout=10, retries=1)
        hdr_blob = " ".join(f"{k}:{v}" for k, v in (base_hdrs or {}).items()).lower()
        base_title = _od_title(base_body)
        fronted_by = ""
        if "cf-ray" in hdr_blob or "server:cloudflare" in hdr_blob.replace(" ", ""):
            fronted_by = "Cloudflare"
        else:
            for ip in _resolve_domain(domain):
                cdn = detect_cloud_provider(ip)
                if cdn:
                    fronted_by = cdn
                    break

        if not fronted_by:
            results.append({"domain": domain, "fronted_by": "", "skipped": True,
                            "reason": "nÃƒÂ£o estÃƒÂ¡ atrÃƒÂ¡s de CDN/WAF conhecido", "origins": []})
            continue

        # Ã¢â€â‚¬Ã¢â€â‚¬ Gather candidate origin IPs (excluding CDN ranges) Ã¢â€â‚¬Ã¢â€â‚¬
        candidates = {}   # ip -> source
        def _add_ip(ip, src):
            ip = (ip or "").strip()
            if (_IP_RE.match(ip) and not ip.startswith(_PRIVATE_PREFIXES)
                    and not detect_cloud_provider(ip)):
                candidates.setdefault(ip, src)

        try:
            dns = dns_records(domain)
            for mx in dns.get("MX", []) or []:
                host = re.sub(r"^\d+\s+", "", str(mx)).strip().rstrip(".")
                for ip in _resolve_domain(host):
                    _add_ip(ip, f"MX:{host}")
        except Exception:
            pass

        try:
            for m in (check_spf(domain).get("mechanisms", []) or []):
                m = m.strip()
                if m.startswith("ip4:"):
                    _add_ip(m.split(":", 1)[1].split("/")[0], "SPF:ip4")
                elif m.startswith("a:") or m.startswith("include:"):
                    host = m.split(":", 1)[1]
                    for ip in _resolve_domain(host):
                        _add_ip(ip, f"SPF:{host}")
        except Exception:
            pass

        def _probe_sub(prefix):
            sub = f"{prefix}.{domain}"
            return [(ip, f"sub:{sub}") for ip in _resolve_domain(sub)]
        with ThreadPoolExecutor(max_workers=20) as pool:
            for res in pool.map(_probe_sub, _ORIGIN_SUB_PREFIXES):
                for ip, src in res:
                    _add_ip(ip, src)

        if shodan_key:
            try:
                q = _up.quote(f'ssl.cert.subject.CN:"{domain}"')
                s, b, _ = http_get(
                    f"https://api.shodan.io/shodan/host/search?key={shodan_key}&query={q}",
                    timeout=15, retries=1)
                if s == 200 and b:
                    for match in (json.loads(b).get("matches", []) or []):
                        _add_ip(match.get("ip_str", ""), "Shodan:cert")
            except Exception:
                pass

        # Ã¢â€â‚¬Ã¢â€â‚¬ Verify candidates via Host-header request Ã¢â€â‚¬Ã¢â€â‚¬
        def _verify(item):
            ip, src = item
            st, bd = 0, b""
            for scheme in ("https", "http"):
                try:
                    st, bd, _ = http_get(f"{scheme}://{ip}/", timeout=8, retries=1,
                                         extra_headers={"Host": domain})
                    if st:
                        break
                except Exception:
                    continue
            title = _od_title(bd)
            conf = "unverified"
            if st and base_title and title and title == base_title:
                conf = "confirmed"
            elif (st == base_status and st in (200, 301, 302, 403)
                  and title and base_title and title[:30] == base_title[:30]):
                conf = "likely"
            elif st in (200, 301, 302):
                conf = "possible"
            return {"ip": ip, "source": src, "status": st, "title": title, "confidence": conf}

        origins = []
        items = list(candidates.items())
        if items:
            with ThreadPoolExecutor(max_workers=15) as pool:
                for v in pool.map(_verify, items):
                    origins.append(v)

        rank = {"confirmed": 0, "likely": 1, "possible": 2, "unverified": 3}
        origins.sort(key=lambda o: (rank.get(o["confidence"], 9), o["ip"]))
        verified = [o for o in origins if o["confidence"] in ("confirmed", "likely")]
        results.append({
            "domain": domain, "fronted_by": fronted_by,
            "baseline": {"status": base_status, "title": base_title},
            "candidates_checked": len(items),
            "origins": origins, "verified_origins": verified,
            "verified_count": len(verified),
        })

    return {
        "domains": domains, "results": results,
        "verified_count": sum(r.get("verified_count", 0) for r in results),
        "count": sum(len(r.get("origins", [])) for r in results),
        "scanned_at": now,
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Mobile App Recon Ã¢â‚¬â€ Google Play discovery + apkleaks (Bug Bounty/ASM) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def _discover_play_packages(brand: str, limit: int = 15) -> list:
    """Scrape Google Play search for Android package IDs matching the brand."""
    if not brand:
        return []
    import urllib.parse as _up
    pkgs = {}
    try:
        s, b, _ = http_get(
            f"https://play.google.com/store/search?q={_up.quote(brand)}&c=apps&hl=en&gl=US",
            timeout=15, retries=2)
        if s == 200 and b:
            html = b.decode("utf-8", "ignore")
            for m in re.finditer(r"/store/apps/details\?id=([a-zA-Z][a-zA-Z0-9_.]+)", html):
                pkg = m.group(1)
                if pkg not in pkgs:
                    pkgs[pkg] = {"package": pkg,
                                 "url": f"https://play.google.com/store/apps/details?id={pkg}"}
                if len(pkgs) >= limit:
                    break
    except Exception:
        pass
    return list(pkgs.values())

def _parse_apkleaks_output(text: str) -> dict:
    """Parse apkleaks text output into {links:[...], secrets:[{type,value}]}."""
    links, secrets = set(), []
    current = None
    for line in text.splitlines():
        s = line.strip()
        hm = re.match(r"^\[(.+?)\]$", s)
        if hm:
            current = hm.group(1)
            continue
        if not s or current is None:
            continue
        val = s.lstrip("- ").strip()
        if not val:
            continue
        if "http" in val or current.upper() in ("LINK", "LINKS", "URI", "URL"):
            links.add(val)
        else:
            secrets.append({"type": current, "value": val[:200]})
    return {"links": sorted(links), "secrets": secrets}

def run_apk_recon(domains, company_name: str = "", apk_dir: str = "") -> dict:
    """
    Mobile attack-surface recon:
      1. Discover the org's Android packages via Google Play search (passive).
      2. If APK files exist (analyst-provided in apk_dir) and apkleaks is installed,
         extract URIs/endpoints/secrets and any *.<domain> hostnames from them.

    Degrades gracefully when apkleaks/jadx or APK files are unavailable. Extracted
    in-scope subdomains are merged into the host pool by the pipeline harvester.
    """
    if isinstance(domains, str):
        domains = [domains]
    domains = [str(d).lower().strip().strip(".") for d in domains if d]
    now = datetime.now().isoformat(timespec="seconds")
    import shutil, tempfile

    brand    = (company_name or (domains[0].split(".")[0] if domains else "")).strip()
    packages = _discover_play_packages(brand)

    apk_findings, subdomains, secrets, notes = [], set(), [], []
    apkleaks_bin = shutil.which("apkleaks")
    apk_files = []
    if apk_dir and os.path.isdir(apk_dir):
        apk_files = [os.path.join(apk_dir, f) for f in os.listdir(apk_dir)
                     if f.lower().endswith(".apk")]

    if apk_files and apkleaks_bin:
        host_res = [re.compile(r"([a-z0-9](?:[a-z0-9\-]{0,62}\.)+" + re.escape(d) + r")", re.I)
                    for d in domains]
        for apk in apk_files[:10]:
            out_path = ""
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                    out_path = tf.name
                _subp([apkleaks_bin, "-f", apk, "-o", out_path],
                      capture_output=True, text=True, timeout=600)
                with open(out_path, "r", errors="ignore") as fh:
                    parsed = _parse_apkleaks_output(fh.read())
            except Exception as exc:
                notes.append(f"apkleaks falhou em {os.path.basename(apk)}: {exc}")
                continue
            finally:
                if out_path and os.path.exists(out_path):
                    try: os.unlink(out_path)
                    except Exception: pass
            for link in parsed["links"]:
                for rx in host_res:
                    for hm in rx.findall(link):
                        subdomains.add(hm.lower().strip("."))
            for sec in parsed["secrets"]:
                secrets.append({**sec, "apk": os.path.basename(apk)})
            apk_findings.append({"apk": os.path.basename(apk),
                                 "links": len(parsed["links"]),
                                 "secrets": len(parsed["secrets"])})
    else:
        if not apkleaks_bin:
            notes.append("apkleaks nÃƒÂ£o instalado Ã¢â‚¬â€ sÃƒÂ³ discovery de pacotes (rode install_tools.sh)")
        if not apk_files:
            notes.append(f"Nenhum APK em {apk_dir or 'scans/<empresa>/apks'} Ã¢â‚¬â€ "
                         "baixe os APKs dos pacotes listados para extraÃƒÂ§ÃƒÂ£o completa")

    return {
        "domains": domains, "brand": brand,
        "packages": packages, "package_count": len(packages),
        "apk_findings": apk_findings,
        "subdomains": sorted(subdomains),
        "secrets": secrets[:100], "secret_count": len(secrets),
        "notes": notes, "scanned_at": now,
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Wayback / GAU Ã¢â‚¬â€ Historical URL Mining Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

_INTERESTING_EXT  = {".bak",".sql",".gz",".tar",".zip",".env",".log",
                     ".config",".conf",".xml",".yaml",".yml",".json",".key",".pem"}
_INTERESTING_PATH = [".git/",".env","wp-config","phpinfo","admin","backup",
                     "config","secret","password","token","apikey","swagger",
                     "graphql","actuator","debug","test","staging"]

def _wayback_cdx_urls(domain: str, limit: int) -> list:
    """Fetch historical URLs from Wayback Machine CDX API."""
    if not _dns_resolves("web.archive.org"):
        return []
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
        f"&limit={limit}&filter=statuscode:200"
    )
    try:
        status, raw, _ = http_get(url, timeout=30, retries=2)
        if status == 200 and raw:
            return [u.strip() for u in raw.decode("utf-8", "ignore").splitlines() if u.strip()]
    except Exception:
        pass
    return []


def run_wayback(domain: str, limit: int = 5000, hosts: list = None) -> dict:
    """Mine historical URLs via gau (with Wayback CDX fallback) for sensitive paths.
    Runs on root domain; CDX also covers all subdomains via wildcard query.
    """
    import shutil as _shutil
    all_urls: list = []
    gau_ok = _shutil.which("gau") is not None
    if gau_ok:
        try:
            proc = _subp(
                ["gau", "--threads", "5", "--timeout", "20", "--retries", "1",
                 "--blacklist", "png,jpg,gif,css,woff,woff2,ttf,eot,svg,ico,mp4,mp3,zip,gz",
                 domain],
                capture_output=True, text=True, timeout=180,
            )
            all_urls = [u.strip() for u in proc.stdout.strip().splitlines() if u.strip()][:limit]
        except Exception:
            pass

    # CDX wildcard query already covers all subdomains (*.domain)
    if not all_urls:
        all_urls = _wayback_cdx_urls(domain, limit)

    interesting = []
    subdomains_found = set()
    for url in all_urls:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if host.endswith(domain):
                subdomains_found.add(host)

            path = parsed.path.lower()
            ext  = Path(path).suffix.lower()
            is_interesting = (
                ext in _INTERESTING_EXT or
                any(p in path for p in _INTERESTING_PATH) or
                parsed.query and any(p in parsed.query.lower()
                                     for p in ["debug","token","key","secret","admin"])
            )
            if is_interesting:
                interesting.append({
                    "url":  url,
                    "host": host,
                    "path": path,
                    "type": ext if ext in _INTERESTING_EXT else "path",
                })
        except Exception:
            pass

    # Deduplicate by path pattern
    seen_paths = set()
    deduped = []
    for u in interesting:
        key = re.sub(r"\d+", "N", u["path"])
        if key not in seen_paths:
            seen_paths.add(key)
            deduped.append(u)

    return {
        "domain":         domain,
        "total_urls":     len(all_urls),
        "interesting":    deduped[:200],
        "interesting_count": len(deduped),
        "subdomains":     sorted(subdomains_found),
        "scanned_at":     datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Shodan Intelligence Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def run_shodan(ips: list, api_key: str = None) -> dict:
    """Query Shodan for open ports, banners, and CVEs per IP."""
    if not api_key:
        # Try env
        api_key = os.environ.get("SHODAN_API_KEY","")
    if not api_key:
        return {"error": "No Shodan API key Ã¢â‚¬â€ set SHODAN_API_KEY env var", "results": []}

    results = []
    unique_ips = _extract_public_ips(ips)

    for ip in unique_ips:
        status, body, _ = http_get(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            timeout=10, retries=2,
        )
        if status == 401:
            return {"error": "Invalid Shodan API key", "results": results}
        if status == 404:
            results.append({"ip": ip, "severity": "info", "ports": [], "vulns": [], "not_indexed": True})
            time.sleep(1)
            continue
        if status != 200 or not body:
            results.append({"ip": ip, "error": f"HTTP {status}", "severity": "info", "ports": [], "vulns": []})
            time.sleep(1)
            continue
        try:
            data = json.loads(body)
            ports     = data.get("ports", [])
            vulns     = list(data.get("vulns", {}).keys())
            results.append({
                "ip":        ip,
                "org":       data.get("org", ""),
                "isp":       data.get("isp", ""),
                "country":   data.get("country_name", ""),
                "city":      data.get("city", ""),
                "ports":     ports,
                "vulns":     vulns,
                "tags":      data.get("tags", []),
                "hostnames": data.get("hostnames", []),
                "os":        data.get("os", ""),
                "severity":  "critical" if vulns else ("high" if any(p in ports for p in [22, 3389, 3306, 5432, 6379, 27017]) else "medium"),
            })
        except Exception as e:
            results.append({"ip": ip, "error": str(e), "severity": "info", "ports": [], "vulns": []})
        time.sleep(1)  # Shodan rate limit

    total_vulns = sum(len(r.get("vulns",[])) for r in results)
    return {
        "results":     sorted(results, key=lambda r: ["critical","high","medium","info"].index(r.get("severity","info"))),
        "total_ips":   len(unique_ips),
        "total_vulns": total_vulns,
        "scanned_at":  datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ WAF Detection Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

_WAF_SIGNATURES = {
    "Imperva Incapsula": ["incap_ses","visid_incap","_incap_","x-iinfo","x-cdn: imperva"],
    "Cloudflare":        ["cf-ray","cf-cache-status","__cfduid","x-cf-powered","server:cloudflare"],
    "AWS WAF":           ["x-amzn-requestid","x-amz-cf-id","x-amzn-trace-id"],
    "Akamai":            ["akamai-origin-hop","x-akamai-transformed","x-check-cacheable",
                          "akamainetbeacon","server:akamaighost","akamaiedge",
                          "ak_bmsc","bm_sz","x-akamai-ssl-client-sid"],
    "Sucuri":            ["x-sucuri-id","x-sucuri-cache"],
    "F5 BIG-IP":         ["bigipserver","ts=","f5_cspm"],
    "Barracuda":         ["barra_counter_session","barra_id"],
    "Fortinet":          ["fortigate","fortiwaf"],
    "ModSecurity":       ["mod_security","modsecurity","owasp_crs"],
    "Radware":           ["x-rdwr-pop","rdwr"],
}

def _detect_waf(host: str) -> dict:
    """Detect WAF by probing headers and responses."""
    url = f"https://{host}" if not host.startswith("http") else host
    headers_found, status, _ = _fetch_headers(url)
    headers_lower = {k.lower(): v.lower() for k, v in headers_found.items()}

    # Also try a malicious-looking request to trigger WAF
    block_url = f"{url}/?id=1%27%20OR%20%271%27%3D%271"
    block_headers, block_status, _ = _fetch_headers(block_url)

    detected = []
    all_header_str = " ".join(f"{k}:{v}" for k, v in headers_lower.items())

    for waf, sigs in _WAF_SIGNATURES.items():
        for sig in sigs:
            if sig in all_header_str:
                detected.append(waf)
                break

    # Generic detection from block page
    if block_status in (403, 406, 429, 503) and status not in (403, 406, 429, 503):
        if not detected:
            detected.append("Unknown WAF (blocked malicious request)")

    # Run wafw00f if available
    wafw00f_result = None
    try:
        w = _subp(
            ["wafw00f", "-a", url, "-o", "-"],
            capture_output=True, text=True, timeout=15,
        )
        if w.returncode == 0:
            matches = re.findall(r"is behind (.+?)(?:\n|$)", w.stdout)
            if matches:
                wafw00f_result = matches
                detected = list(set(detected + matches))
    except Exception:
        pass

    return {
        "host":    host,
        "wafs":    detected,
        "protected": len(detected) > 0,
        "block_status": block_status,
        "wafw00f": wafw00f_result,
    }

def run_waf_detection(hosts: list) -> dict:
    """Detect WAFs across live HTTPS hosts."""
    targets = [h["host"] for h in hosts if 443 in h.get("ports", []) or "443" in h.get("ports", []) or h.get("status_code") is not None]
    results = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_detect_waf, h): h for h in targets}
        for fut in as_completed(futures):
            results.append(fut.result())

    protected   = sum(1 for r in results if r["protected"])
    unprotected = len(results) - protected
    waf_counts: dict[str,int] = {}
    for r in results:
        for w in r["wafs"]:
            waf_counts[w] = waf_counts.get(w, 0) + 1

    return {
        "results":     results,
        "protected":   protected,
        "unprotected": unprotected,
        "waf_counts":  dict(sorted(waf_counts.items(), key=lambda x: -x[1])),
        "scanned_at":  datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ WAF / CDN challenge page detection (shared false-positive filter) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

_WAF_CHALLENGE_SIGNATURES = [
    "just a moment...", "attention required! | cloudflare", "cf-browser-verification",
    "checking your browser before accessing", "ddos protection by cloudflare",
    "cloudflare ray id",
    "access denied", "you don't have permission to access",
    "request unsuccessful. incapsula incident id", "incapsula incident id",
    "the request could not be satisfied", "generated by cloudfront",
    "reference #", "akamai reference",
    "sucuri website firewall", "sucuri cloudproxy",
    "this website is using a security service to protect itself",
    "perimeterx", "_px-captcha", "imperva",
    "blocked by web application firewall", "web application firewall",
    "bot detected", "automation tools detected",
]


def _is_waf_challenge_body(body: str) -> bool:
    """True if a response body looks like a generic WAF/CDN challenge or block
    page rather than the application's real content. Used to suppress
    false positives in CORS / takeover checks where a WAF intercepts the
    probe request and returns a generic page (which can otherwise be
    mistaken for the app's own response/signature)."""
    if not body:
        return False
    low = body.lower()
    return any(sig in low for sig in _WAF_CHALLENGE_SIGNATURES)


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Subdomain Takeover Detection Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
            "issue": f"NXDOMAIN Ã¢â‚¬â€ dangling CNAME to {cname_target} (unclaimed service)",
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
                        "issue": f"Unclaimed {service} Ã¢â‚¬â€ takeover likely possible",
                        "takeover_possible": True,
                        "service": service,
                    }

    return {
        "host": host, "cname": cname, "cname_target": cname_target,
        "severity": "medium",
        "issue": f"CNAME Ã¢â€ â€™ {cname_target} Ã¢â‚¬â€ verify service is active",
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


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Credential / Breach Intelligence Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def _check_leakix(domain: str) -> list:
    """Query LeakIX (free tier) for domain leaks."""
    findings = []
    try:
        url = f"https://leakix.net/domain/{domain}"
        status, body, _ = http_get(url, timeout=10,
                                   extra_headers={"Accept": "application/json"})
        if status != 200 or not body:
            return findings
        data = json.loads(body)
        for event in (data if isinstance(data, list) else [])[:20]:
            findings.append({
                "source":   "LeakIX",
                "type":     event.get("event_type","leak"),
                "host":     event.get("host",""),
                "summary":  event.get("summary","")[:200],
                "severity": "high" if event.get("severity","info") in ("high","critical") else "medium",
                "date":     event.get("time","")[:10],
            })
    except Exception:
        pass
    return findings


def _check_dehashed(domain: str, api_key: str = None) -> dict:
    """Query DeHashed for breach data (requires API key)."""
    if not api_key:
        return {"results": [], "note": "No DeHashed API key configured"}
    try:
        import base64
        auth = base64.b64encode(f":{api_key}".encode()).decode()
        url  = f"https://api.dehashed.com/search?query=domain%3A{domain}&size=20"
        status, body, _ = http_get(url, timeout=10,
                                   extra_headers={"Accept": "application/json",
                                                  "Authorization": f"Basic {auth}"})
        if status != 200 or not body:
            return {"results": [], "note": f"DeHashed returned HTTP {status}"}
        data = json.loads(body)
        entries = data.get("entries") or []
        return {
            "count": data.get("total",0),
            "results": [{"email": e.get("email",""), "username": e.get("username",""),
                         "database": e.get("database_name",""),
                         "hashed_password": bool(e.get("hashed_password"))} for e in entries[:20]],
        }
    except Exception as e:
        return {"error": str(e), "results": []}


def _check_hibp_domain(domain: str, api_key: str = None) -> dict:
    """Query HaveIBeenPwned domain search (v3, requires paid key)."""
    if not api_key:
        return {"results": [], "note": "No HIBP API key Ã¢â‚¬â€ domain search requires paid plan"}
    try:
        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
        status, body, _ = http_get(url, timeout=10,
                                   extra_headers={"hibp-api-key": api_key})
        if status == 404:
            return {"results": [], "count": 0, "note": "No breaches found"}
        if status == 401:
            return {"error": "Invalid HIBP API key", "results": []}
        if status != 200 or not body:
            return {"results": [], "note": f"HIBP returned HTTP {status}"}
        data = json.loads(body)
        return {"results": data, "count": len(data)}
    except Exception as e:
        return {"error": str(e), "results": []}
    return {"results": []}


def _check_trufflehog_github(domain: str) -> list:
    """Use trufflehog to scan GitHub for secrets related to domain."""
    import shutil as _shutil
    if not _shutil.which("trufflehog"):
        return []
    findings = []
    try:
        proc = _subp(
            ["trufflehog", "github", "--org", domain.split(".")[0],
             "--json", "--no-update"],
            capture_output=True, text=True, timeout=60,
        )
        for line in proc.stdout.strip().splitlines():
            try:
                item = json.loads(line)
                findings.append({
                    "source":    "trufflehog/github",
                    "type":      item.get("DetectorName","secret"),
                    "repo":      item.get("SourceMetadata",{}).get("Data",{}).get("Github",{}).get("repository",""),
                    "file":      item.get("SourceMetadata",{}).get("Data",{}).get("Github",{}).get("file",""),
                    "severity":  "critical",
                    "verified":  item.get("Verified", False),
                })
            except Exception:
                pass
    except Exception:
        pass
    return findings[:20]


def _check_hudsonrock(domain: str) -> dict:
    """Query HudsonRock Cavalier API for infostealer credential leaks (free, no auth)."""
    from urllib.request import urlopen, Request
    try:
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}"
        req = Request(url, headers={"User-Agent": "ASM-Platform/1.0"})
        with urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}

    employees = data.get("employees", 0)
    users = data.get("users", 0)
    third_parties = data.get("third_parties", 0)
    total = data.get("total", 0)
    stealers = data.get("totalStealers", 0)

    # Extract internal app URLs from employee_urls (redacted in free tier)
    internal_urls = []
    for entry in data.get("data", {}).get("employees_urls", []):
        url_val = entry.get("url", "")
        if url_val and "*****" not in url_val:
            internal_urls.append({"url": url_val, "type": entry.get("type", ""), "occurrence": entry.get("occurrence", 0)})

    stealer_families = {s.get("_key", ""): s.get("_value", 0) for s in data.get("data", {}).get("stealer_families", [])}

    severity = "info"
    if employees >= 10:
        severity = "critical"
    elif employees >= 1:
        severity = "high"

    return {
        "source": "hudsonrock_cavalier",
        "total": total,
        "employees": employees,
        "users": users,
        "third_parties": third_parties,
        "total_stealers_global": stealers,
        "stealer_families": stealer_families,
        "internal_urls": internal_urls,
        "severity": severity,
        "summary": f"{employees} employees compromised via infostealers ({', '.join(list(stealer_families.keys())[:5])})" if employees else "No employee compromises found",
    }


def run_breach_check(domain: str, hibp_key: str = None,
                     dehashed_key: str = None) -> dict:
    """Aggregate breach / credential leak intelligence."""
    leakix   = _check_leakix(domain)
    hudsonrock = _check_hudsonrock(domain)
    hibp     = _check_hibp_domain(domain, hibp_key)
    dehashed = _check_dehashed(domain, dehashed_key)
    trufflehog_results = _check_trufflehog_github(domain)

    all_findings = leakix + trufflehog_results
    total = len(all_findings) + hibp.get("count",0) + len(dehashed.get("results",[]))

    return {
        "domain":       domain,
        "leakix":       leakix,
        "hudsonrock":   hudsonrock,
        "hibp":         hibp,
        "dehashed":     dehashed,
        "trufflehog":   trufflehog_results,
        "total_findings": total,
        "severity":     "critical" if hudsonrock.get("employees",0) >= 10 or total > 10 else "high" if total > 0 else "info",
        "scanned_at":   datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Port Scan (nmap/naabu wrapper) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

_RISKY_PORTS = {
    21:    "FTP Ã¢â‚¬â€ plaintext file transfer",
    22:    "SSH",
    23:    "Telnet Ã¢â‚¬â€ plaintext protocol",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3 Ã¢â‚¬â€ plaintext email",
    143:   "IMAP Ã¢â‚¬â€ plaintext email",
    389:   "LDAP Ã¢â‚¬â€ directory service",
    443:   "HTTPS",
    445:   "SMB Ã¢â‚¬â€ Windows file sharing",
    512:   "rexec Ã¢â‚¬â€ remote exec (plaintext)",
    513:   "rlogin Ã¢â‚¬â€ remote login (plaintext)",
    514:   "rsh Ã¢â‚¬â€ remote shell (plaintext)",
    636:   "LDAPS",
    1433:  "MSSQL",
    1521:  "Oracle DB",
    2181:  "ZooKeeper Ã¢â‚¬â€ often unauthenticated",
    2375:  "Docker API Ã¢â‚¬â€ plaintext (CRITICAL)",
    2376:  "Docker TLS API",
    2379:  "etcd API Ã¢â‚¬â€ Kubernetes secrets",
    3000:  "Grafana/dev server",
    3306:  "MySQL",
    3389:  "RDP Ã¢â‚¬â€ Remote Desktop",
    4243:  "Docker API alt",
    4443:  "HTTPS-alt",
    4848:  "GlassFish Admin",
    5000:  "Dev server / Docker Registry",
    5432:  "PostgreSQL",
    5601:  "Kibana Ã¢â‚¬â€ often unauthenticated",
    5900:  "VNC Ã¢â‚¬â€ remote desktop",
    6379:  "Redis Ã¢â‚¬â€ often unauthenticated",
    7001:  "WebLogic Admin",
    7474:  "Neo4j Browser",
    8001:  "kubectl proxy",
    8080:  "HTTP-alt / Tomcat / Jenkins",
    8088:  "Hadoop YARN ResourceManager",
    8161:  "ActiveMQ Web Console",
    8443:  "HTTPS-alt",
    8888:  "Jupyter Notebook Ã¢â‚¬â€ often unauthenticated",
    9000:  "SonarQube / Portainer",
    9090:  "Prometheus Ã¢â‚¬â€ metrics exposed",
    9092:  "Kafka Ã¢â‚¬â€ often unauthenticated",
    9200:  "Elasticsearch Ã¢â‚¬â€ often unauthenticated",
    9300:  "Elasticsearch cluster",
    10250: "Kubelet API Ã¢â‚¬â€ Kubernetes node",
    10255: "Kubelet read-only",
    11211: "Memcached Ã¢â‚¬â€ often unauthenticated",
    15672: "RabbitMQ Management UI",
    27017: "MongoDB Ã¢â‚¬â€ often unauthenticated",
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
        # nmap first Ã¢â‚¬â€ works without root; masscan needs raw sockets (root only)
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
            pass

    def _is_waf_ip(ip: str) -> bool:
        try:
            addr = _ipa.ip_address(ip)
            return any(addr in net for net in _waf_networks)
        except Exception:
            return False

    clean_ips = [ip for ip in unique_ips if not _is_waf_ip(ip)]
    if not clean_ips:
        # All IPs are WAF proxies Ã¢â‚¬â€ scan anyway with a warning
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
                    pass

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
                        pass
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
                                    pass
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


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ JavaScript Recon Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

# Secret patterns: (regex, type, severity)
_JS_SECRET_PATTERNS = [
    # Cloud / infra keys
    (r'AKIA[0-9A-Z]{16}',                                                                   "aws_access_key",    "critical"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key[\s\'"]*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',"aws_secret",        "critical"),
    (r'AIza[0-9A-Za-z\-_]{35}',                                                             "google_api_key",    "high"),
    (r'(?i)firebase[^\n]{0,40}https://[a-zA-Z0-9\-]+\.firebaseio\.com',                     "firebase_url",      "high"),
    (r'ghp_[A-Za-z0-9]{36}',                                                                "github_token",      "critical"),
    (r'ghs_[A-Za-z0-9]{36}',                                                                "github_app_token",  "critical"),
    (r'sk_live_[A-Za-z0-9]{24,}',                                                           "stripe_live_key",   "critical"),
    (r'sk_test_[A-Za-z0-9]{24,}',                                                           "stripe_test_key",   "high"),
    (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',                                        "sendgrid_key",      "critical"),
    (r'(?i)twilio[^\n]{0,20}(?:SK|AC)[a-f0-9]{32}',                                         "twilio_key",        "critical"),
    (r'key-[a-z0-9]{32}',                                                                   "mailgun_key",       "high"),
    (r'(?i)bearer\s+eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',               "jwt_bearer",        "high"),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',                "jwt_token",         "medium"),
    # API Gateway credentials Ã¢â‚¬â€ Sensedia, Kong, Apigee, MuleSoft, AWS API GW
    # client_secret alone is high; client_id alone is medium (semi-public); both together Ã¢â€ â€™ critical (handled in _analyze_js_content)
    (r'(?i)(?:client[_-]?secret|clientSecret)\s*[=:]\s*["\']([A-Za-z0-9_\-\.@]{16,80})["\']',         "client_secret",   "high"),
    (r'(?i)(?<!["\w])client[_-]?id(?!["\w])\s*[=:]\s*["\']([A-Za-z0-9_\-\.@]{8,80})["\']',            "client_id",       "medium"),
    # Quoted-key style: {"client_id":"val"} / {"client-id":"val"} (Sensedia header injection)
    (r'["\']client[_\-]id["\']\s*:\s*["\']([A-Za-z0-9_\-\.@]{8,80})["\']',                            "client_id",       "medium"),
    (r'["\']client[_\-]secret["\']\s*:\s*["\']([A-Za-z0-9_\-\.@]{16,80})["\']',                       "client_secret",   "high"),
    # OAuth2 consumer key/secret (Sensedia / Kong / Apigee also use these names)
    (r'(?i)consumer[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-\.@]{16,80})["\']',                           "consumer_key",    "high"),
    (r'(?i)consumer[_-]?secret\s*[=:]\s*["\']([A-Za-z0-9_\-\.@]{16,80})["\']',                        "consumer_secret", "high"),
    # Generic credentials Ã¢â‚¬â€ values must contain real entropy (mixed chars, not i18n keys or snake_case labels)
    # Exclude AIza* (already caught as google_api_key) and pure snake_case/SCREAMING_SNAKE_CASE labels
    (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\'](?!AIza)([A-Za-z0-9_\-]{20,}[A-Za-z][0-9][A-Za-z0-9_\-]*)["\']', "api_key",      "high"),
    (r'(?i)(?:secret[_-]?key|secretkey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',                    "secret_key",      "high"),
    (r'(?i)(?:access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']',           "access_token",    "high"),
    # Password: require value has real entropy Ã¢â‚¬â€ must contain digit OR special char, and NOT be an i18n key pattern
    (r'(?i)(?:password|passwd)\s*[=:]\s*["\']([^\'"]{8,64})["\']',                          "password",          "high"),
    (r'(?i)authorization\s*[=:]\s*["\']Basic\s+([A-Za-z0-9+/=]{8,})["\']',                 "basic_auth",        "high"),
    # Cloud storage
    (r's3\.amazonaws\.com/([a-z0-9\-\.]{3,})',                                              "s3_bucket",         "medium"),
    (r'([a-z0-9\-]{3,})\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com',                            "s3_bucket",         "medium"),
    (r'https?://[a-z0-9\-]+\.blob\.core\.windows\.net',                                     "azure_blob",        "medium"),
    (r'gs://([a-z0-9\-_\.]+)',                                                               "gcs_bucket",        "medium"),
    # Internal network Ã¢â‚¬â€ proper octet validation (0-255 only, prevents SVG coordinate false positives)
    (r'(?<!["\'\w.])(10\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))(?!["\'\w.])', "internal_ip", "low"),
    (r'(?<!["\'\w.])(192\.168\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))(?!["\'\w.])',                                     "internal_ip", "low"),
    (r'(?<!["\'\w.])(172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))(?!["\'\w.])',                   "internal_ip", "low"),
    # Private key material
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',                                           "private_key",       "critical"),
    # Chat/webhook integrations
    (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',    "slack_webhook",     "critical"),
    (r'https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',                               "discord_webhook",   "critical"),
    (r'https://discordapp\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',                            "discord_webhook",   "critical"),
    # Email addresses in JS (contact, support, noreply Ã¢â‚¬â€ still PII/OSINT useful)
    (r'[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}',                                                       "email_address",     "low"),
    # oauth2/token endpoint with client credentials
    (r'(?i)oauth2?/token[^\n]{0,80}client_id[^\n]{0,40}',                                    "oauth_endpoint",    "medium"),
    # Database connection strings
    (r'(?i)(?:mongodb|mysql|postgresql|redis)://[a-zA-Z0-9_]+:[^@\s]+@',                    "db_connection",     "critical"),
]

# LinkFinder regex Ã¢â‚¬â€ matches the same multi-group pattern as the original tool
_ENDPOINT_RE = re.compile(
    r"""(?:"|')"""
    r"""("""
    r"""(?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,}"""   # full URLs
    r"""|(?:/|\.\./|\./)"""                                               # relative: /, ../, ./
    r"""[^"'><,;| *()(%%$^/\\\[\]]{1,}[^"'><,;|()]{1,}"""
    r"""|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}"""                     # path/to/resource.ext
    r"""\.(?:[a-zA-Z]{1,4}|action)(?:[?#][^"']{0,}|)"""
    r"""|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[?#][^"']{0,}|)"""  # REST endpoints
    r"""|[a-zA-Z0-9_\-]{1,}"""                                           # bare filenames
    r"""\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[?#][^"']{0,}|)"""
    r""")"""
    r"""(?:"|')""",
    re.VERBOSE | re.MULTILINE,
)
# Imperva / WAF bot-challenge JS URL patterns Ã¢â‚¬â€ these look like real JS files but aren't
_WAF_CHALLENGE_URL_RE = re.compile(
    r'/(?:[a-z]{1,4}-)?(?:[A-Z][a-z]+-){3,}|'   # CamelCase word-slug paths
    r'\?d=[\w.\-]+\.[a-z]{2,}$|'                  # Imperva ?d=domain fingerprint
    r'/(?:[a-z]+-){2,}(?:[A-Z][a-z]+-){2,}',     # mixed-case random word slug
)

_INTERESTING_RE = [
    (re.compile(r'graphql',          re.I), "GraphQL"),
    (re.compile(r'\.execute\s*\(',   re.I), "JS eval/exec"),
    (re.compile(r'innerHTML\s*=',    re.I), "innerHTML sink"),
    (re.compile(r'document\.write\s*\(', re.I), "document.write sink"),
    (re.compile(r'eval\s*\(',        re.I), "eval() call"),
    (re.compile(r'window\.location\s*=', re.I), "open redirect sink"),
    (re.compile(r'(?i)sql\s*[=+]\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE)', re.I), "SQL string"),
    (re.compile(r'debugger;',        re.I), "debugger statement"),
    (re.compile(r'(?i)(?:mongo|redis|postgres|mysql|oracle)(?:URI|URL|Conn|Connection)?[\s\'"]*[=:]\s*["\']', re.I), "DB connection string"),
    (re.compile(r'(?i)cors.*allow.*origin.*\*',  re.I), "CORS wildcard"),
    (re.compile(r'(?i)Access-Control-Allow-Origin[^\n]*\*', re.I), "CORS wildcard"),
]


_FP_PASSWORD_RE = re.compile(
    r'(?i)(%filtered%|wrong.?password|forgot.?password|invalid.?password|missing.?password'
    r'|need.?password|change.?password|reset.?password|show.?password|confirm.?password'
    r'|enter.?password|password.?hint|password.?set|create.?password|redefine.?password'
    r'|new.?password|old.?password|repeat.?password'
    # MSAL/Azure AD numeric error codes (e.g. PASSWORD:"80041012")
    r'|["\']?[0-9A-F]{8,}["\']?'
    # i18n key patterns used as password labels
    r'|eOTT_|OneTimePassword|NoPassword)',
)
_FP_LABEL_RE = re.compile(r'^[A-Z][A-Z0-9_\-]{3,}$|^[a-z][a-z0-9_]{4,}[a-z0-9]$')


def _is_fp_secret(ptype: str, value: str) -> bool:
    """Return True when a regex match is almost certainly a false positive."""
    if ptype == "password":
        # Strip surrounding quotes and key name to get the raw value
        inner = re.sub(r'(?i)^(?:password|passwd|pwd)\s*[=:]\s*["\']', '', value).rstrip('"\'')
        if _FP_PASSWORD_RE.search(inner):
            return True
        # Pure i18n keys: ALL_CAPS_WITH_UNDERSCORES or pure snake_case (no digits/specials)
        if re.match(r'^[A-Z][A-Z0-9_\-\.]+$', inner) or re.match(r'^[a-z][a-z\-\.]+$', inner):
            return True
        # Value is itself the word "password" or a trivial variant
        if re.match(r'^["\']?passwords?["\']?$', inner, re.I):
            return True
        # JS code fragments: code chars, .method() calls, or +var. concatenation
        if re.search(r'[\[\]{}&|?]|\.substring\(|\+[a-z]+\.', inner):
            return True
        # Sentence-like phrases: only letters and spaces, no digits or specials
        if re.match(r'^[A-Za-z][A-Za-z ]+$', inner):
            return True
        return False

    if ptype in ("access_token", "secret_key"):
        # Extract just the value portion (after the key name and delimiter)
        inner = re.sub(r'(?i)^[\w\-]+\s*[=:]\s*["\']', '', value).rstrip('"\'')
        # Pure snake_case or SCREAMING_SNAKE_CASE labels are variable name strings, not tokens
        if _FP_LABEL_RE.match(inner):
            return True
        return False

    if ptype == "api_key":
        inner = re.sub(r'(?i)^[\w\-]+\s*[=:]\s*["\']', '', value).rstrip('"\'')
        if _FP_LABEL_RE.match(inner):
            return True
        return False

    if ptype == "internal_ip":
        # Validate octets are all 0-255; stored values may have invalid octets from SVG paths
        m = re.search(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', value)
        if not m:
            return True
        return any(int(o) > 255 for o in m.groups())

    return False


def _decode_jwt_unverified(token: str) -> dict | None:
    """Best-effort decode of a JWT header+payload (no signature verification)."""
    import base64 as _b64
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        def _seg(s: str) -> bytes:
            s += "=" * (-len(s) % 4)
            return _b64.urlsafe_b64decode(s.encode())
        header = json.loads(_seg(parts[0]))
        payload = json.loads(_seg(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return {"header": header, "payload": payload}


def _jwt_finding_detail(value: str, default_sev: str) -> tuple[str, str]:
    """Re-grade a discovered JWT based on its actual claims/header to cut down
    on noise â€” most client-side JWTs are normal session tokens, not 'secrets'."""
    dec = _decode_jwt_unverified(value)
    if not dec:
        return default_sev, ""
    header, payload = dec["header"], dec["payload"]
    alg = str(header.get("alg", "")).lower()
    notes: list[str] = []
    severity = "low"

    if alg in ("none", ""):
        severity = "high"
        notes.append("alg=none â€” signature not verifiable/forgeable")

    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        if exp < time.time():
            notes.append("expired token (likely stale/example, low risk)")
        else:
            notes.append("active token, has expiry")
    else:
        severity = "medium" if severity == "low" else severity
        notes.append("no 'exp' claim â€” token may never expire")

    sensitive = [k for k in ("password", "secret", "client_secret", "private_key") if k in payload]
    if sensitive:
        severity = "high"
        notes.append(f"payload exposes sensitive field(s): {', '.join(sensitive)}")

    auth_claims = [k for k in ("role", "roles", "admin", "isAdmin", "scope", "scopes", "permissions") if k in payload]
    if auth_claims:
        if severity == "low":
            severity = "medium"
        notes.append(f"authorization claims in payload: {', '.join(auth_claims)} â€” verify server re-checks them")

    return severity, "; ".join(notes)


def _validate_secret(stype: str, value: str) -> bool:
    """Return False if the value is clearly a placeholder/false positive."""
    if not value or len(value) < 6:
        return False
    low = value.lower()
    # Generic placeholders
    _FP = {"your_key_here","your-api-key","api_key_here","insert_key","placeholder",
           "replace_me","changeme","change_me","example","sample","test","demo",
           "xxxxxxxx","00000000","11111111","12345678","abcdefgh","aaaaaaaa",
           "none","null","undefined","false","true","n/a","na","todo",
           "secret_here","token_here","<your","[your","{{","__placeholder__"}
    if any(fp in low for fp in _FP):
        return False
    # Format-specific validation
    import re as _vre
    if stype == "aws_access_key" and not _vre.match(r'^AKIA[0-9A-Z]{16}$', value):
        return False
    if stype == "github_token" and not value.startswith("ghp_"):
        return False
    if stype == "stripe_live_key" and not value.startswith("sk_live_"):
        return False
    if stype == "stripe_test_key" and not value.startswith("sk_test_"):
        return False
    if stype == "sendgrid_key" and not _vre.match(r'^SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}$', value):
        return False
    if stype == "jwt_token":
        parts = value.split(".")
        if len(parts) != 3 or not all(len(p) > 4 for p in parts):
            return False
        # Must decode to a real JWT header+payload, not just a base64-looking string
        if not _decode_jwt_unverified(value):
            return False
    # Entropy check for generic keys: must have mixed chars
    if stype in ("api_key","secret_key","access_token","password"):
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        if not (has_upper or has_lower) or not has_digit:
            return False
        # All same char = placeholder
        if len(set(value)) < 4:
            return False
    return True


# Third-party CDN / library hosts whose JS is public and never contains real secrets
_JS_NOISE_HOSTS = frozenset({
    "aadcdn.msauth.net", "aadcdn.msftauth.net",        # Microsoft MSAL
    "js.live.net", "logincdn.msauth.net",
    "ok1static.oktacdn.com", "cdn.auth0.com",          # Okta / Auth0
    "use.fontawesome.com", "kit.fontawesome.com",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    "unpkg.com", "ajax.googleapis.com",
    "static.hotjar.com", "script.hotjar.com",
    "cdn.segment.com", "cdn.segment.io",
    "js.intercomcdn.com", "widget.intercom.io",
    "cdn.newrelic.com", "js-agent.newrelic.com",
    "browser.sentry-cdn.com", "cdn.ravenjs.com",
    "www.google-analytics.com", "www.googletagmanager.com",
    "www.google.com", "www.gstatic.com",
    "snap.licdn.com", "connect.facebook.net",
    "platform.twitter.com", "assets.zendesk.com",
})


def _analyze_js_content(js_url: str, content: str) -> dict:
    """Analyze JS content and return per-file findings."""
    host = ""
    try:
        from urllib.parse import urlparse
        host = urlparse(js_url).hostname or ""
    except Exception:
        pass

    # Skip well-known third-party library hosts Ã¢â‚¬â€ they never contain real secrets
    if host in _JS_NOISE_HOSTS:
        return {"secrets": [], "endpoints": [], "urls": [], "interesting": []}

    secrets  = []
    seen_sec = set()
    for pattern, ptype, sev in _JS_SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            val = m.group(0)[:200]
            if _is_fp_secret(ptype, val):
                continue
            if not _validate_secret(ptype, val):
                continue
            key = (ptype, val[:60])
            if key not in seen_sec:
                seen_sec.add(key)
                # Get surrounding context (1 line)
                start = max(0, m.start() - 80)
                end   = min(len(content), m.end() + 40)
                ctx   = content[start:end].replace("\n", " ").replace("\r", "").strip()[:200]
                if ptype in ("jwt_token", "jwt_bearer"):
                    jwt_val = val.split()[-1] if ptype == "jwt_bearer" else val
                    sev, note = _jwt_finding_detail(jwt_val, sev)
                    if note:
                        ctx = f"{ctx} | {note}"
                secrets.append({"type": ptype, "value": val, "context": ctx, "severity": sev})

    # Endpoints / paths
    endpoints = []
    seen_ep   = set()
    for m in _ENDPOINT_RE.finditer(content):
        path = m.group(1)
        if path in seen_ep or len(path) < 4:
            continue
        # Filter out obvious non-endpoints
        if re.search(r'\.(png|jpg|gif|svg|ico|woff|ttf|eot|css|less|scss)$', path, re.I):
            continue
        if not re.search(r'[/?]', path):
            continue
        seen_ep.add(path)
        # Classify by type
        kind = "api" if re.search(r'/api/|/v\d+/|/graphql|/rest/', path, re.I) else \
               "admin" if re.search(r'/admin|/manage|/internal|/debug|/config', path, re.I) else \
               "path"
        # Classify auth: look at surrounding context in content for auth signals
        ep_start = max(0, content.find(path) - 300)
        ep_end   = min(len(content), content.find(path) + 300)
        ctx      = content[ep_start:ep_end].lower() if content.find(path) >= 0 else ""
        if re.search(r'bearer\s+|authorization.*bearer|authheader.*bearer', ctx, re.I):
            auth = "bearer"
        elif re.search(r'x-api-key|apikey.*header|api.key.*header', ctx, re.I):
            auth = "api_key_header"
        elif re.search(r'basic\s+auth|authorization.*basic', ctx, re.I):
            auth = "basic"
        elif re.search(r'oauth|client_id.*client_secret', ctx, re.I):
            auth = "oauth2"
        elif re.search(r'cookie|session|csrf', ctx, re.I):
            auth = "cookie_session"
        elif not re.search(r'auth|token|key|secret|credential|login', ctx, re.I):
            auth = "none_detected"
        else:
            auth = "unknown"
        endpoints.append({"path": path, "kind": kind, "auth": auth})

    # Absolute URLs found in code
    urls = []
    seen_url = set()
    for m in re.finditer(r'https?://[a-zA-Z0-9._\-/?=&%#+@:,;[\]~!*\'()\-]{10,300}', content):
        u = m.group(0).rstrip('.,;)\'"')
        if u not in seen_url:
            seen_url.add(u)
            urls.append(u)

    # Interesting patterns
    interesting = []
    seen_int    = set()
    for rgx, label in _INTERESTING_RE:
        if rgx.search(content) and label not in seen_int:
            seen_int.add(label)
            interesting.append(label)

    return {
        "secrets":     secrets,
        "endpoints":   endpoints[:300],
        "urls":        urls[:200],
        "interesting": interesting,
    }


def _playwright_js_capture(targets: list, timeout: int = 30) -> dict:
    """
    Use Playwright headless Chromium to capture runtime JS URLs and XHR/fetch
    network calls for each target.  Targets are processed in parallel Ã¢â‚¬â€ each
    worker thread owns its own browser instance so Playwright's sync API is
    thread-safe.

    Returns:
        {
            "runtime_js_urls": [str],
            "network_map": {"https://host": [{"method","url","type"}]},
            "error": str | None,
        }
    """
    result: dict = {"runtime_js_urls": [], "network_map": {}, "error": None}
    if not targets:
        return result

    try:
        sync_playwright, PwTimeout = _pw_import()
    except Exception as e:
        result["error"] = f"playwright unavailable: {e}"
        return result

    # WAF bot-challenge fingerprints
    _IMPERVA_RE   = re.compile(r'\?d=[\w.\-]+\.[a-z]{2,}$')
    _RANDOM_PATH_RE = re.compile(r'^/(?:[A-Z][a-z]+-){4,}')

    def _is_bot_challenge(url: str) -> bool:
        if _IMPERVA_RE.search(url):
            return True
        try:
            from urllib.parse import urlparse
            if _RANDOM_PATH_RE.match(urlparse(url).path):
                return True
        except Exception:
            pass
        return False

    _BROWSER_ARGS = [
        "--no-sandbox", "--disable-dev-shm-usage",
        "--ignore-certificate-errors", "--disable-web-security",
        "--disable-blink-features=AutomationControlled",
        "--disable-features=IsolateOrigins,site-per-process",
        "--disable-site-isolation-trials",
    ]
    _CONTEXT_KWARGS = dict(
        ignore_https_errors=True,
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        viewport={"width": 1366, "height": 768},
        locale="pt-BR",
        timezone_id="America/Sao_Paulo",
        extra_http_headers={
            "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
    )
    _INIT_SCRIPT = (
        "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
        "Object.defineProperty(navigator,'plugins',{get:()=>[1,2,3,4,5]});"
        "Object.defineProperty(navigator,'languages',{get:()=>['pt-BR','pt','en-US','en']});"
    )

    def _visit_one(target_url: str):
        """Visit a single URL in its own browser instance; return (js_set, calls_list, js_bodies)."""
        host_calls: list = []
        host_js:    set  = set()
        js_bodies:  dict = {}  # url -> text content fetched via browser (bypasses WAF)
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, args=_BROWSER_ARGS)
                context = browser.new_context(**_CONTEXT_KWARGS)
                context.add_init_script(_INIT_SCRIPT)
                page = context.new_page()

                def _on_request(req):
                    rt = req.resource_type
                    u  = req.url
                    if rt in ("xhr", "fetch"):
                        if not _is_bot_challenge(u):
                            host_calls.append({"method": req.method, "url": u, "type": rt})
                    elif rt == "script":
                        if u.endswith(".js") or ".js?" in u or ".js#" in u:
                            host_js.add(u)

                def _on_response(resp):
                    try:
                        if resp.request.resource_type == "script" and resp.status == 200:
                            u = resp.url
                            if u.endswith(".js") or ".js?" in u or ".js#" in u:
                                host_js.add(u)
                    except Exception:
                        pass

                page.on("request",  _on_request)
                page.on("response", _on_response)

                timeout_ms = timeout * 1000
                try:
                    page.goto(target_url, wait_until="networkidle", timeout=timeout_ms)
                except PwTimeout:
                    try:
                        page.goto(target_url, wait_until="domcontentloaded", timeout=15_000)
                    except Exception:
                        pass
                except Exception:
                    pass

                # Scroll to trigger lazy-loaded chunks / infinite-scroll XHR
                try:
                    page.evaluate(
                        "(function(){"
                        "var h=document.body.scrollHeight;"
                        "window.scrollTo(0,h/3);"
                        "setTimeout(function(){window.scrollTo(0,h*2/3);},500);"
                        "setTimeout(function(){window.scrollTo(0,h);},1000);"
                        "})()"
                    )
                    page.wait_for_timeout(1500)
                except Exception:
                    pass

                # Collect webpack chunk URLs from JS globals
                try:
                    chunk_urls = page.evaluate(
                        "(function(){"
                        "try{"
                        "var urls=[];"
                        "var pb=window.__webpack_public_path__||window.__publicPath__||'';"
                        "var chunks=window.webpackChunk||[];"
                        "chunks.forEach(function(c){"
                        "  if(c&&c[1])Object.keys(c[1]).forEach(function(k){"
                        "    urls.push(pb+k+'.js');"
                        "  });"
                        "});"
                        "return urls.slice(0,50)"
                        "}catch(e){return []}"
                        "})()"
                    )
                    if isinstance(chunk_urls, list):
                        for u in chunk_urls:
                            if isinstance(u, str) and u.startswith("http"):
                                host_js.add(u)
                except Exception:
                    pass

                # Fetch JS bodies via the browser's own fetch() Ã¢â‚¬â€ bypasses WAF/Imperva
                # because the request originates from the already-authenticated browser session.
                # Cap at 25 files; skip noise/CDN hosts; limit to 1.5MB per file.
                _noise_hosts_re = re.compile(
                    r'google-analytics\.com|googletagmanager\.com|hotjar\.|'
                    r'segment\.|newrelic\.|datadoghq\.|doubleclick\.|'
                    r'facebook\.com|twitter\.com|imperva\.com|incapsula\.com',
                    re.I,
                )
                candidate_urls = [
                    u for u in list(host_js)
                    if not _noise_hosts_re.search(u) and not _is_bot_challenge(u)
                ][:25]

                for js_url in candidate_urls:
                    try:
                        body = page.evaluate(
                            """async (url) => {
                                try {
                                    const r = await fetch(url, {
                                        credentials: 'include',
                                        cache: 'no-store',
                                    });
                                    if (!r.ok) return null;
                                    const t = await r.text();
                                    if (!t || t.length < 200) return null;
                                    return t.length > 1500000 ? t.slice(0, 1500000) : t;
                                } catch(e) { return null; }
                            }""",
                            js_url,
                        )
                        if body and isinstance(body, str):
                            js_bodies[js_url] = body
                    except Exception:
                        pass

                page.close()
                browser.close()
        except Exception:
            pass
        return host_js, host_calls[:200], js_bodies

    # Run all targets in parallel Ã¢â‚¬â€ cap workers so we don't OOM the box
    max_workers = min(len(targets), 8)
    runtime_js:       set  = set()
    network_map:      dict = {}
    playwright_bodies: dict = {}  # url -> JS text body captured via browser fetch
    errors: list = []

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futs = {pool.submit(_visit_one, url): url for url in targets}
            for fut in as_completed(futs):
                url = futs[fut]
                try:
                    js_set, calls, bodies = fut.result()
                    runtime_js.update(js_set)
                    network_map[url] = calls
                    playwright_bodies.update(bodies)
                except Exception as e:
                    errors.append(f"{url}: {e}")
    except Exception as e:
        result["error"] = str(e)

    result["runtime_js_urls"]      = list(runtime_js)
    result["network_map"]          = network_map
    result["playwright_js_bodies"] = playwright_bodies
    if errors:
        result["error"] = "; ".join(errors[:5])
    return result


def run_js_recon(domains: list, hosts: list) -> dict:
    """
    Discover all JS files across live hosts (katana + subjs + getJS + gau),
    capture runtime JS via Playwright, run LinkFinder endpoint extraction,
    then analyze each file for secrets, endpoints, URLs, and dangerous patterns.
    Returns per-file structured results.
    """
    import shutil, tempfile

    katana_bin = shutil.which("katana")
    subjs_bin  = shutil.which("subjs")
    getjs_bin  = shutil.which("getJS")
    gau_bin    = shutil.which("gau")

    # Build target list Ã¢â‚¬â€ prefer HTTPS, fall back to HTTP, include all live hosts
    targets = []
    seen_hosts: set = set()
    for h in hosts:
        host  = h.get("host", "")
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        ports = h.get("ports", [])
        has_https = any(int(p["port"] if isinstance(p, dict) else p) in (443, 8443) for p in ports)
        has_http  = any(int(p["port"] if isinstance(p, dict) else p) in (80, 8080, 8000) for p in ports)
        if has_https:
            targets.append(f"https://{host}")
        elif has_http:
            targets.append(f"http://{host}")
        elif h.get("status_code") is not None:
            targets.append(f"https://{host}")  # httpx-confirmed live, assume HTTPS
        if len(targets) >= 500:
            break
    if not targets:
        for d in domains[:5]:
            targets.append(f"https://{d}")

    raw_js_urls: set = set()

    # Ã¢â€â‚¬Ã¢â€â‚¬ Discovery Phase Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    # 1) katana Ã¢â‚¬â€ deep crawl, JS-aware (parses inline + external scripts)
    if katana_bin and targets:
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(targets)); tf_path = tf.name
            r = _subp(
                [katana_bin, "-list", tf_path, "-d", "5", "-jc",
                 "-ef", "png,jpg,gif,css,svg,ico,woff,ttf,webp",
                 "-silent", "-timeout", "15", "-c", "25", "-rl", "50"],
                capture_output=True, text=True, timeout=300,
            )
            Path(tf_path).unlink(missing_ok=True)
            for url in r.stdout.splitlines():
                url = url.strip()
                if url and (url.endswith(".js") or ".js?" in url or ".js#" in url):
                    raw_js_urls.add(url)
        except Exception:
            pass

    # 2) subjs Ã¢â‚¬â€ extracts <script src> tags from each host
    if subjs_bin and targets:
        try:
            r = _subp(
                [subjs_bin, "-c", "30"],
                input="\n".join(targets),
                capture_output=True, text=True, timeout=150,
            )
            for url in r.stdout.splitlines():
                url = url.strip()
                if url:
                    raw_js_urls.add(url)
        except Exception:
            pass

    # 3) getJS Ã¢â‚¬â€ another script tag extractor
    if getjs_bin and targets:
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(targets)); tf_path = tf.name
            r = _subp(
                [getjs_bin, "-input", tf_path, "-complete"],
                capture_output=True, text=True, timeout=90,
            )
            Path(tf_path).unlink(missing_ok=True)
            for url in r.stdout.splitlines():
                url = url.strip()
                if url and ("http" in url):
                    raw_js_urls.add(url)
        except Exception:
            pass

    # 4) gau Ã¢â‚¬â€ historical JS URLs from Wayback/OTX/CommonCrawl
    if gau_bin and domains:
        try:
            for d in domains[:3]:
                r = _subp(
                    [gau_bin, "--subs", "--providers", "wayback,otx,commoncrawl",
                     "--ft", "ttf,woff,css,png,jpg,gif,svg,ico", d],
                    capture_output=True, text=True, timeout=60,
                )
                for url in r.stdout.splitlines():
                    url = url.strip()
                    if url and (url.endswith(".js") or ".js?" in url):
                        raw_js_urls.add(url)
        except Exception:
            pass

    # Ã¢â€â‚¬Ã¢â€â‚¬ Playwright Runtime Capture Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    # Visit all live hosts that are likely frontend web apps.
    # Exclude: pure API gateways, hosts with error/redirect-only titles.
    _API_HOST_RE = re.compile(
        r'^(?:apis?[-.]|api-gw|gateway[-.]|gw[-.]|backend[-.]|mtls[-.])',
        re.I,
    )
    # Titles that indicate the host is NOT a real web app
    _BAD_TITLE_RE = re.compile(
        r'^(?:\d{3}\s|fastly error|bad request|forbidden|not found|'
        r'service unavailable|error|redirecting|nginx)',
        re.I,
    )

    def _pw_score(h: dict) -> int:
        """Score a host for Playwright priority. Higher = better candidate."""
        host = h.get("host", "")
        sc   = h.get("status_code") or 0
        title = h.get("title") or ""

        if _API_HOST_RE.match(host):
            return -1  # exclude API gateways
        if sc in (403, 404, 503, 500, 0):
            return 0   # likely not serving a UI
        score = 1
        if sc in (200, 301, 302):
            score += 2
        if title and not _BAD_TITLE_RE.match(title):
            score += 3  # real application title
        # Prefer hosts with 443 open
        ports = [int(p["port"] if isinstance(p, dict) else p) for p in h.get("ports", [])]
        if 443 in ports or 8443 in ports:
            score += 1
        return score

    def _pw_url(h: dict) -> str:
        ports = [int(p["port"] if isinstance(p, dict) else p) for p in h.get("ports", [])]
        if 443 in ports or 8443 in ports:
            return f"https://{h['host']}"
        return f"http://{h['host']}"

    scored = sorted(
        [(h, _pw_score(h)) for h in hosts if h.get("host")],
        key=lambda x: -x[1],
    )
    pw_targets = [_pw_url(h) for h, score in scored if score > 0][:30]
    if not pw_targets:
        pw_targets = targets[:15]

    pw_result  = _playwright_js_capture(pw_targets, timeout=25)
    runtime_network_map  = pw_result.get("network_map", {})
    playwright_js_bodies = pw_result.get("playwright_js_bodies", {})
    for u in pw_result.get("runtime_js_urls", []):
        raw_js_urls.add(u)

    # Filter out WAF bot-challenge URLs before analysis
    js_url_list = [u for u in raw_js_urls if not _WAF_CHALLENGE_URL_RE.search(u)]

    # Ã¢â€â‚¬Ã¢â€â‚¬ Analysis Phase Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    js_files = []
    total_secrets   = 0
    total_endpoints = 0
    sev_counts      = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Skip CDN/noise hosts and Imperva-proxied origins at the URL level
    _SKIP_JS_HOSTS = _JS_NOISE_HOSTS | frozenset({
        "imperva.com", "incapsula.com", "reblaze.com", "datadome.co",
    })

    def _fetch_and_analyze(url: str) -> dict | None:
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ""
            if host in _SKIP_JS_HOSTS:
                return None
            # Use a short per-request timeout; skip retries to avoid long stalls
            status, raw, hdrs = http_get(url, timeout=8, retries=1)
            if status != 200 or not raw:
                return None
            size    = len(raw)
            content = raw[:800_000].decode("utf-8", errors="ignore")
            analysis = _analyze_js_content(url, content)
            return {
                "url":         url,
                "host":        host,
                "size":        size,
                "status":      status,
                "secrets":     analysis["secrets"],
                "endpoints":   analysis["endpoints"],
                "urls":        analysis["urls"],
                "interesting": analysis["interesting"],
            }
        except Exception:
            return None

    # Cap at 200 files; prioritise first-party domains over third-party CDNs
    _domain_keywords = [d.split(".")[-2] for d in domains if "." in d] or []
    def _js_priority(u: str) -> int:
        return 0 if any(kw in u for kw in _domain_keywords) else 1

    capped_list = sorted(js_url_list, key=_js_priority)[:200]

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_fetch_and_analyze, u): u for u in capped_list}
        # Hard 4-minute overall cap so a hung fetch never blocks the pipeline
        try:
            for fut in as_completed(futures, timeout=240):
                result = fut.result()
                if result:
                    js_files.append(result)
                    total_secrets   += len(result["secrets"])
                    total_endpoints += len(result["endpoints"])
                    for s in result["secrets"]:
                        sev_counts[s.get("severity", "low")] = sev_counts.get(s.get("severity", "low"), 0) + 1
        except TimeoutError:
            pass  # some fetches didn't finish Ã¢â‚¬â€ that's fine, proceed with what we have

    # Ã¢â€â‚¬Ã¢â€â‚¬ Playwright-captured JS bodies Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    # These were fetched by the browser itself (with session cookies, correct
    # headers) so they bypass Imperva WAF that blocks direct HTTP fetches.
    # Analyse them for secrets Ã¢â‚¬â€ primarily Sensedia/API-gateway credentials.
    _seen_pw_urls = {f["url"] for f in js_files}  # don't re-analyse already-fetched files
    for pw_js_url, pw_content in playwright_js_bodies.items():
        if pw_js_url in _seen_pw_urls:
            continue
        try:
            from urllib.parse import urlparse as _urlparse
            pw_host = _urlparse(pw_js_url).hostname or ""
            analysis = _analyze_js_content(pw_js_url, pw_content[:800_000])

            # Sensedia pair escalation: client_id + client_secret in same file Ã¢â€ â€™ critical
            _secret_types = {s["type"] for s in analysis["secrets"]}
            if "client_id" in _secret_types and "client_secret" in _secret_types:
                for s in analysis["secrets"]:
                    if s["type"] in ("client_id", "client_secret", "consumer_key", "consumer_secret"):
                        s["severity"] = "critical"
                        s["note"] = "API gateway credential pair (client_id + client_secret co-located)"

            if analysis["secrets"] or analysis["endpoints"]:
                file_result = {
                    "url":         pw_js_url,
                    "host":        pw_host,
                    "size":        len(pw_content),
                    "status":      200,
                    "source":      "playwright",  # distinguishes browser-captured from direct-fetch
                    "secrets":     analysis["secrets"],
                    "endpoints":   analysis["endpoints"],
                    "urls":        analysis["urls"],
                    "interesting": analysis["interesting"],
                }
                js_files.append(file_result)
                total_secrets   += len(analysis["secrets"])
                total_endpoints += len(analysis["endpoints"])
                for s in analysis["secrets"]:
                    sev = s.get("severity", "low")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                _seen_pw_urls.add(pw_js_url)
        except Exception:
            pass

    # Sort: files with critical/high secrets first
    def _sort_key(f):
        sc = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        best = min((sc.get(s["severity"], 3) for s in f["secrets"]), default=9)
        return (best, -len(f["secrets"]))
    js_files.sort(key=_sort_key)

    # Ã¢â€â‚¬Ã¢â€â‚¬ Source map discovery Ã¢â‚¬â€ probe .js.map for every discovered .js file Ã¢â€â‚¬Ã¢â€â‚¬
    source_maps = []
    source_map_urls = set()
    for f in js_files:
        map_url = f["url"].rstrip("/") + ".map"
        if map_url not in source_map_urls:
            try:
                sc, raw, _ = http_get(map_url, timeout=4, retries=1)
                if sc == 200 and len(raw) > 100:
                    try:
                        data = json.loads(raw.decode("utf-8", "ignore"))
                        if isinstance(data, dict) and "sources" in data:
                            source_maps.append({"url": map_url, "sources_count": len(data.get("sources", [])),
                                                "file": f["url"]})
                            source_map_urls.add(map_url)
                    except Exception:
                        pass
            except Exception:
                pass

    # Flatten all XHR/fetch calls from Playwright into a deduplicated list
    all_network_calls: list = []
    seen_nc: set = set()
    for calls in runtime_network_map.values():
        for c in calls:
            key = (c["method"], c["url"])
            if key not in seen_nc:
                seen_nc.add(key)
                all_network_calls.append(c)

    return {
        "js_files":           js_files,
        "js_files_found":     len(js_url_list),
        "js_analyzed":        len(js_files),
        "source_maps":        source_maps,
        "source_maps_count":  len(source_maps),
        "total_secrets":      total_secrets,
        "total_endpoints":    total_endpoints,
        "critical_count":     sev_counts["critical"],
        "high_count":         sev_counts["high"],
        "medium_count":       sev_counts["medium"],
        # Runtime network capture (Playwright)
        "runtime_network":    all_network_calls[:500],  # XHR/fetch observed at runtime
        "runtime_network_map": runtime_network_map,     # keyed by target URL
        "runtime_js_urls":    list(pw_result.get("runtime_js_urls", []))[:500],
        "runtime_js_count":   len(pw_result.get("runtime_js_urls", [])),
        # Legacy flat fields for backward compat
        "secrets_found":      total_secrets,
        "endpoints_found":    total_endpoints,
        "scanned_at":         datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Screenshots Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def _gowitness_v3_to_url(stem: str) -> str:
    """Reconstruct a URL from a gowitness v3 JPEG filename stem.
    v3 format: scheme---hostname-port  e.g. https---hackersec.com-443
    """
    for scheme in ("https", "http"):
        prefix = scheme + "---"
        if stem.startswith(prefix):
            rest = stem[len(prefix):]          # e.g. "hackersec.com-443"
            parts = rest.rsplit("-", 1)
            if len(parts) == 2 and parts[1].isdigit():
                host, port = parts[0], parts[1]
                if (scheme == "https" and port == "443") or (scheme == "http" and port == "80"):
                    return f"{scheme}://{host}"
                return f"{scheme}://{host}:{port}"
            return f"{scheme}://{rest}"
    return stem


def run_screenshots(hosts: list, domains: list, output_dir: str = "") -> dict:
    """
    Capture screenshots of all live web assets using gowitness.
    Falls back to httpx title/status if gowitness not available.
    """
    import shutil

    gowitness_bin = shutil.which("gowitness")
    httpx_bin     = shutil.which("httpx")

    # Build URL list
    targets = []
    for h in hosts:
        host  = h.get("host","")
        ports = h.get("ports",[])
        for p in ports:
            pn = int(p["port"] if isinstance(p,dict) else p)
            if pn in (443,8443):
                targets.append(f"https://{host}:{pn}" if pn != 443 else f"https://{host}")
            elif pn in (80,8080,8000,8001,8888):
                targets.append(f"http://{host}:{pn}" if pn not in (80,) else f"http://{host}")
    if not targets:
        for d in domains[:10]:
            targets.append(f"https://{d}")
            targets.append(f"http://{d}")

    # Deduplicate
    targets = list(dict.fromkeys(targets))[:80]

    out_dir = output_dir or str(Path.home() / ".asm" / "screenshots")
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    screenshots = []
    errors      = []

    if gowitness_bin:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(targets))
            tf_path = tf.name
        try:
            # gowitness v3 syntax: scan file -f <file> --screenshot-path <dir>
            result = _subp(
                [gowitness_bin, "scan", "file", "-f", tf_path,
                 "--screenshot-path", out_dir,
                 "-t", "10", "-T", "15", "-q"],
                capture_output=True, text=True, timeout=300,
            )
            # v3 saves .jpeg files named: scheme---host-port.jpeg
            for f in sorted(Path(out_dir).glob("*.jpeg"), key=lambda x: x.stat().st_mtime, reverse=True):
                screenshots.append({
                    "url":  _gowitness_v3_to_url(f.stem),
                    "file": str(f),
                    "size": f.stat().st_size,
                })
        except Exception as e:
            errors.append(str(e))
        finally:
            Path(tf_path).unlink(missing_ok=True)
    else:
        # Fallback: httpx with title + screenshot path info
        if httpx_bin:
            try:
                result = _subp(
                    [httpx_bin, "-silent", "-title", "-status-code",
                     "-tech-detect", "-screenshot", "-srd", out_dir,
                     "-timeout", "8", "-threads", "20"],
                    input="\n".join(targets),
                    capture_output=True, text=True, timeout=180,
                )
                for line in result.stdout.splitlines():
                    if line.strip():
                        screenshots.append({"url": line.strip(), "file": "", "size": 0})
            except Exception as e:
                errors.append(str(e))

    return {
        "total":         len(screenshots),
        "targets_tried": len(targets),
        "output_dir":    out_dir,
        "screenshots":   screenshots[:100],
        "errors":        errors[:10],
        "scanned_at":    datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ DNS Brute-force with Permutations Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    # Ã¢â€â‚¬Ã¢â€â‚¬ Wordlist-based permutations (external file, tiered) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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

    # Ã¢â€â‚¬Ã¢â€â‚¬ Method 0: alterx pattern-based permutations (primary, most effective) Ã¢â€â‚¬Ã¢â€â‚¬
    if alterx_bin and len(seeds) > 1:
        try:
            capped_seeds = sorted(seeds, key=len)[:200]
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(capped_seeds))
                tf_path = tf.name
            # alterx learns patterns from existing subdomains (e.g. api-v2-prod Ã¢â€ â€™ api-v3-prod)
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
            pass

    # Ã¢â€â‚¬Ã¢â€â‚¬ Method 1: dnsgen permutations from known seeds Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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
            pass

    # Ã¢â€â‚¬Ã¢â€â‚¬ Method 2: altdns mutations from known seeds Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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
                pass
            Path(out_path).unlink(missing_ok=True)
        except Exception:
            pass

    # Ã¢â€â‚¬Ã¢â€â‚¬ Fallback: hardcoded common prefixes Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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

    # Ã¢â€â‚¬Ã¢â€â‚¬ Deduplicate + cap Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    permutations = sorted(set(p for p in permutations if p.endswith(domain) and len(p) < 200))[:perm_cap]

    # Ã¢â€â‚¬Ã¢â€â‚¬ Resolve with best available tool Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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
            pass
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
            pass

    # Ã¢â€â‚¬Ã¢â€â‚¬ Python socket fallback (threaded, uses system resolver Ã¢â‚¬â€ works behind VPN) Ã¢â€â‚¬Ã¢â€â‚¬
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

    # Ã¢â€â‚¬Ã¢â€â‚¬ Filter out already known hosts Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ API & Panel Exposure (Nuclei-based) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def run_api_exposure(hosts: list, domains: list) -> dict:
    """
    Detect exposed API panels, docs and misconfigurations using nuclei:
    - Spring Boot Actuators (/actuator/env, /heapdump, /beansÃ¢â‚¬Â¦)
    - Swagger / OpenAPI / Redoc UI
    - GraphQL Introspection
    - CORS Misconfiguration
    - HTTP Request Smuggling
    - JWT token exposure
    - Host Header Injection
    - Favicon hash for tech fingerprinting
    """
    import shutil, tempfile

    nuclei_bin = shutil.which("nuclei")
    httpx_bin  = shutil.which("httpx")
    if not nuclei_bin:
        return {"error": "nuclei not found", "findings": []}

    # Build URL targets
    targets = []
    for h in hosts:
        host  = h.get("host","")
        ports = h.get("ports",[])
        has_https = any(int(p["port"] if isinstance(p,dict) else p) in (443,8443) for p in ports)
        has_http  = any(int(p["port"] if isinstance(p,dict) else p) in (80,8080,8000,8888) for p in ports)
        if has_https:
            targets.append(f"https://{host}")
        if has_http:
            targets.append(f"http://{host}")
    if not targets:
        for d in domains[:5]:
            targets.append(f"https://{d}")

    if not targets:
        return {"error": "No live targets", "findings": []}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(dict.fromkeys(targets)))
        tfile = tf.name

    # Nuclei template sets to run Ã¢â‚¬â€ paths validated against actual template install
    TEMPLATE_SETS = [
        # Spring Boot misconfiguration (correct path)
        ("springboot", [
            "http/misconfiguration/springboot/",
            "http/technologies/springboot-actuator.yaml",
            "http/technologies/springboot-whitelabel.yaml",
            "http/vulnerabilities/springboot/",
        ]),
        # API docs exposure
        ("api_docs", [
            "http/exposures/apis/swagger-api.yaml",
            "http/exposures/apis/openapi.yaml",
            "http/exposures/apis/wadl-api.yaml",
            "http/exposures/apis/redoc-api-docs.yaml",
            "http/exposures/apis/postman-collection-exposure.yaml",
        ]),
        # GraphQL
        ("graphql", [
            "http/exposures/apis/graphql-introspection.yaml",
            "http/exposures/apis/graphql-playground.yaml",
        ]),
        # CORS
        ("cors", [
            "http/vulnerabilities/generic/cors-misconfig.yaml",
        ]),
        # JWT
        ("jwt", [
            "http/exposures/tokens/generic/jwt-token.yaml",
        ]),
        # Directory listing
        ("exposure", [
            "http/miscellaneous/directory-listing.yaml",
        ]),
    ]

    findings = []
    nuclei_base = str(Path.home() / "nuclei-templates")
    if not Path(nuclei_base).exists():
        nuclei_base = str(Path.home() / ".local" / "nuclei-templates")

    for category, templates in TEMPLATE_SETS:
        template_args = []
        for t in templates:
            full = str(Path(nuclei_base) / t)
            if Path(full).exists():
                template_args += ["-t", full]
        if not template_args:
            continue
        try:
            result = _subp(
                [nuclei_bin, "-l", tfile,
                 "-json", "-silent", "-no-interactsh",
                 "-timeout", "10", "-rate-limit", "50",
                 "-duc",   # disable update check
                 ] + template_args,
                capture_output=True, text=True, timeout=180,
            )
            for line in result.stdout.splitlines():
                try:
                    item = json.loads(line)
                    sev = item.get("info",{}).get("severity","info").lower()
                    findings.append({
                        "category":    category,
                        "template":    item.get("template-id",""),
                        "name":        item.get("info",{}).get("name",""),
                        "host":        item.get("host",""),
                        "url":         item.get("matched-at",""),
                        "severity":    sev,
                        "description": item.get("info",{}).get("description","")[:300],
                    })
                except Exception:
                    pass
        except Exception:
            pass

    Path(tfile).unlink(missing_ok=True)

    sev_counts = {s:0 for s in ("critical","high","medium","low","info")}
    for f in findings:
        sev_counts[f.get("severity","info")] = sev_counts.get(f.get("severity","info"),0)+1

    cat_counts = {}
    for f in findings:
        c = f["category"]
        cat_counts[c] = cat_counts.get(c,0) + 1

    return {
        "total":          len(findings),
        "critical_count": sev_counts["critical"],
        "high_count":     sev_counts["high"],
        "medium_count":   sev_counts["medium"],
        "by_category":    cat_counts,
        "findings":       sorted(findings,
                                 key=lambda x: ["critical","high","medium","low","info"].index(x.get("severity","info"))),
        "scanned_at":     datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ CertStream Monitor (one-shot snapshot) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def run_certstream_snapshot(domains: list, duration_sec: int = 60) -> dict:
    """
    Listen to CertStream for `duration_sec` seconds and collect any new
    certificates matching the target domains. Requires certstream package.
    Falls back to crt.sh polling if certstream not available.
    """
    import urllib.request, threading

    new_certs = []
    errors    = []

    # Build match patterns
    base_domains = set()
    for d in domains:
        parts = d.split(".")
        if len(parts) >= 2:
            base_domains.add(f".{'.'.join(parts[-2:])}")

    def _matches(cn: str) -> bool:
        if not cn:
            return False
        cn = cn.lower().lstrip("*.")
        return any(cn.endswith(bd) or cn == bd.lstrip(".") for bd in base_domains)

    # Try certstream first
    try:
        import certstream
        found = []
        done_event = threading.Event()

        def _cb(msg, ctx):
            try:
                leaf = msg.get("data",{}).get("leaf_cert",{})
                cn   = leaf.get("subject",{}).get("CN","")
                sans = leaf.get("all_domains",[])
                for name in ([cn] + sans):
                    if _matches(name):
                        found.append({
                            "domain":  name.lstrip("*."),
                            "cn":      cn,
                            "issuer":  leaf.get("issuer",{}).get("O",""),
                            "not_before": leaf.get("not_before",""),
                            "not_after":  leaf.get("not_after",""),
                            "source":  "certstream",
                        })
            except Exception:
                pass

        t = threading.Thread(
            target=certstream.listen_for_events,
            args=(_cb,),
            kwargs={"url": "wss://certstream.calidog.io/"},
            daemon=True,
        )
        t.start()
        t.join(timeout=duration_sec)
        new_certs = found

    except ImportError:
        # Fallback: crt.sh recent certs (last 24h)
        for d in domains[:3]:
            try:
                url = f"https://crt.sh/?q=%25.{d}&output=json"
                status, body, _ = http_get(url, timeout=15)
                if status != 200 or not body:
                    continue
                data = json.loads(body)
                for entry in data[:50]:
                    name = entry.get("name_value","").replace("*.",""
                                                             ).strip()
                    if name and _matches(f".{name.split('.',1)[-1]}" if "." in name else name):
                        new_certs.append({
                            "domain":    name,
                            "cn":        entry.get("common_name",""),
                            "issuer":    entry.get("issuer_name","")[:60],
                            "not_before": entry.get("not_before",""),
                            "not_after":  entry.get("not_after",""),
                            "source":    "crt.sh",
                        })
            except Exception as e:
                errors.append(str(e))

    # Deduplicate by domain
    seen = set()
    unique = []
    for c in new_certs:
        key = c["domain"]
        if key not in seen:
            seen.add(key)
            unique.append(c)

    return {
        "total":      len(unique),
        "duration_s": duration_sec,
        "new_certs":  unique[:200],
        "errors":     errors,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Virtual Host Discovery Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def run_vhost_discovery(hosts: list, domains: list, wordlist: str = "") -> dict:
    """
    Discover virtual hosts on each IP by fuzzing the Host header.
    Uses ffuf (primary) or gobuster vhost (fallback).
    Capped at 5 IPs Ãƒâ€” 200 wordlist entries Ãƒâ€” 30s per run to stay fast.
    """
    import shutil, tempfile, urllib.request

    ffuf_bin    = shutil.which("ffuf")
    gobuster_bin = shutil.which("gobuster")

    if not ffuf_bin and not gobuster_bin:
        return {"error": "ffuf or gobuster required", "findings": []}

    # Build wordlist: known subdomains from existing hosts + common prefixes
    common_prefixes = [
        "www","mail","smtp","pop","imap","ftp","sftp","ssh","vpn","remote",
        "admin","portal","app","api","dev","staging","test","uat","qa","prod",
        "beta","demo","cdn","static","assets","media","img","images","files",
        "upload","backup","db","database","mysql","mongo","redis","elastic",
        "kibana","grafana","jenkins","gitlab","jira","confluence","intranet",
        "internal","corp","extranet","owa","autodiscover","webmail","ns1","ns2",
        "mx","mail2","mx1","mx2","smtp2","gateway","proxy","waf","lb","loadbalancer",
        "shop","store","checkout","payment","auth","login","sso","id","accounts",
        "register","signup","blog","status","monitor","logs","reports","dashboard",
        "manage","mgmt","management","old","legacy","new","v2","api2","mobile",
        "m","wap","help","support","docs","doc","wiki","kb","forum","community",
    ]

    # Collect known subdomains from host data
    known_subs = set()
    for h in hosts:
        hostname = h.get("host","")
        if hostname:
            parts = hostname.split(".")
            if len(parts) >= 3:
                known_subs.add(parts[0])

    # Cap total wordlist at 200 entries to keep ffuf fast
    all_prefixes = sorted(set(common_prefixes) | known_subs)[:200]

    # Primary domain for vhost suffix
    primary_domain = domains[0] if domains else ""
    if not primary_domain:
        return {"error": "No domain provided", "findings": []}

    # Get unique IPs to scan (cap at 5 to stay fast)
    ips_to_scan = []
    seen_ips = set()
    for h in hosts:
        ip = h.get("ip","")
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            ips_to_scan.append({"ip": ip, "host": h.get("host",""), "ports": h.get("ports",[])})

    if not ips_to_scan:
        return {"error": "No IPs found Ã¢â‚¬â€ run a scan first", "findings": []}

    # Write wordlist to temp file
    wl_path = wordlist
    tmp_wl  = None
    if not wl_path or not Path(wl_path).exists():
        tmp_wl  = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        for p in all_prefixes:
            tmp_wl.write(f"{p}.{primary_domain}\n")
        tmp_wl.flush()
        wl_path = tmp_wl.name

    findings = []
    scanned_ips = []

    for target in ips_to_scan[:5]:   # cap at 5 IPs
        ip   = target["ip"]
        ports = target.get("ports", [])

        # Determine HTTP/HTTPS ports
        http_ports  = []
        https_ports = []
        for p in ports:
            pn = int(p["port"] if isinstance(p, dict) else p)
            if pn in (443, 8443):
                https_ports.append(pn)
            elif pn in (80, 8080, 8888, 8000, 8001):
                http_ports.append(pn)

        if not http_ports and not https_ports:
            http_ports = [80]

        for port in (https_ports or []) + (http_ports or []):
            scheme = "https" if port in (443, 8443) else "http"
            base_url = f"{scheme}://{ip}:{port}"

            if ffuf_bin:
                # ffuf cannot stream JSON to stdout ("-o -" creates a file literally
                # named "-"), so write JSON to a temp file and read it back.
                with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as of:
                    ffuf_out = of.name
                cmd = [
                    ffuf_bin,
                    "-u", base_url + "/",
                    "-H", "Host: FUZZ",
                    "-w", wl_path,
                    "-mc", "200,201,202,301,302,303,401,403,405",
                    "-fs", "0",         # filter zero-size (connection refused)
                    "-t", "30",
                    "-timeout", "5",
                    "-o", ffuf_out,
                    "-of", "json",
                    "-s",               # silent
                    "-r",               # follow redirects
                    "-noninteractive",
                ]
                try:
                    _subp(cmd, capture_output=True, text=True, timeout=30)
                    try:
                        with open(ffuf_out, "r", encoding="utf-8") as fh:
                            raw = fh.read()
                        data = json.loads(raw) if raw.strip() else {}
                    except (OSError, json.JSONDecodeError):
                        data = {}
                    for item in data.get("results", []):
                        vhost  = item.get("input",{}).get("FUZZ","") or item.get("host","")
                        status = item.get("status",0)
                        length = item.get("length",0)
                        words  = item.get("words",0)
                        if vhost and status:
                            findings.append({
                                "vhost":    vhost,
                                "ip":       ip,
                                "port":     port,
                                "scheme":   scheme,
                                "status":   status,
                                "length":   length,
                                "words":    words,
                                "url":      f"{scheme}://{vhost}",
                                "severity": "medium" if status in (200,201,202) else "low",
                            })
                except Exception:
                    pass
                finally:
                    try:
                        os.unlink(ffuf_out)
                    except OSError:
                        pass

            elif gobuster_bin:
                cmd = [
                    gobuster_bin, "vhost",
                    "-u", base_url,
                    "--domain", primary_domain,
                    "-w", wl_path,
                    "--append-domain",
                    "-t", "30",
                    "--timeout", "5s",
                    "-q",
                ]
                try:
                    result = _subp(cmd, capture_output=True, text=True, timeout=30)
                    for line in result.stdout.splitlines():
                        # gobuster output: "Found: sub.domain.com (Status: 200) [Size: 1234]"
                        m = re.match(r"Found:\s+([\w\.\-]+)\s+\(Status:\s*(\d+)\)", line, re.I)
                        if m:
                            vhost, status = m.group(1), int(m.group(2))
                            findings.append({
                                "vhost":    vhost,
                                "ip":       ip,
                                "port":     port,
                                "scheme":   scheme,
                                "status":   status,
                                "url":      f"{scheme}://{vhost}",
                                "severity": "medium" if status in (200,201,202) else "low",
                            })
                except Exception:
                    pass

        scanned_ips.append(ip)

    # Cleanup temp wordlist
    if tmp_wl:
        try:
            Path(tmp_wl.name).unlink()
        except Exception:
            pass

    # Deduplicate by vhost
    seen_vhosts: dict[str, dict] = {}
    for f in findings:
        key = f["vhost"]
        if key not in seen_vhosts or f["status"] < seen_vhosts[key]["status"]:
            seen_vhosts[key] = f

    unique = sorted(seen_vhosts.values(), key=lambda x: x["vhost"])
    active = [f for f in unique if f["status"] in (200,201,202,301,302,303)]

    return {
        "total":        len(unique),
        "active_count": len(active),
        "ips_scanned":  len(scanned_ips),
        "findings":     unique,
        "scanned_at":   datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ CVE Lookup via NVD API v2 Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

# Maps common tech display names Ã¢â€ â€™ CPE 2.3 product component for virtualMatchString queries.
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

# CISA KEV catalog cache Ã¢â‚¬â€ loaded once per process
_KEV_CACHE:   dict[str, bool] = {}
_KEV_LOADED:  bool = False


def _load_kev() -> None:
    """Download CISA Known Exploited Vulnerabilities catalog once per process."""
    global _KEV_LOADED
    if _KEV_LOADED:
        return
    from urllib.request import urlopen, Request as _Req
    try:
        req = _Req(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            headers={"User-Agent": "ASM-Platform/1.0"},
        )
        with urlopen(req, timeout=20) as r:
            kev_data = json.loads(r.read())
        for vuln in kev_data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if cve_id:
                _KEV_CACHE[cve_id] = True
    except Exception:
        pass
    _KEV_LOADED = True


def _fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Batch fetch EPSS exploit-probability scores from FIRST.org API."""
    if not cve_ids:
        return {}
    from urllib.request import urlopen, Request as _Req
    scores: dict[str, float] = {}
    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i:i + 100]
        params = "&".join(f"cve_id={c}" for c in batch)
        url = f"https://api.first.org/data/1.0/epss?{params}"
        try:
            req = _Req(url, headers={"User-Agent": "ASM-Platform/1.0"})
            with urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            for entry in data.get("data", []):
                cid = entry.get("cve", "")
                try:
                    if cid:
                        scores[cid] = float(entry.get("epss", 0.0))
                except (ValueError, TypeError):
                    pass
        except Exception:
            pass
    return scores


def run_cve_lookup(hosts: list, nvd_key: str = "") -> dict:
    """
    Cross-reference detected technologies with NVD CVE database.

    Strategy per product:
    1. Versioned + CPE mapping: query NVD virtualMatchString Ã¢â‚¬â€ exact product:version
       match in affected configurations (no false positives from description mentions).
    2. Versioned, CPE returns 0: keyword fallback, filter to CVEs with CPE config match.
    3. Unversioned: keyword search, min_year=2020, filter by CPE config presence.
    4. Enrich all results with EPSS scores (FIRST.org) and CISA KEV flags.
    5. Sort: KEV-listed first, then EPSSÃƒâ€”CVSS descending.
    """
    from urllib.request import urlopen, Request
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
            return True  # no info Ã¢â€ â€™ don't filter
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
            return True  # unanalyzed CVE Ã¢â‚¬â€ let it through
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if ph in match.get("criteria", "").lower():
                        return True
        return False

    def _query_cpe(cpe_name: str, version: str, product: str) -> list[dict]:
        """Query NVD virtualMatchString Ã¢â‚¬â€ returns only CVEs where product:version is in configs."""
        vms = f"cpe:2.3:a:*:{cpe_name}:{version}:*:*:*:*:*:*:*"
        if vms in queries_done:
            return []
        queries_done.add(vms)
        params = {"virtualMatchString": vms, "resultsPerPage": "20"}
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode(params)
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=20) as r:
                data = json.loads(r.read())
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
            req = Request(url, headers=headers)
            with urlopen(req, timeout=20) as r:
                data = json.loads(r.read())
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
                    # CPE returned nothing (version not yet in NVD) Ã¢â‚¬â€ keyword fallback
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

    # Deduplicate by CVE ID Ã¢â‚¬â€ merge affected_hosts, keep highest score
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

    # Sort: KEV first, then EPSSÃƒâ€”CVSS descending
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


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ CORS Misconfiguration Scanner Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def run_cors_scan(hosts: list) -> dict:
    """Test CORS misconfigurations: origin reflection, null origin, prefix/suffix bypasses."""
    import urllib.request as _urlr
    import urllib.error as _urle

    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings: list[dict] = []
    tested = 0

    live = [h for h in hosts if isinstance(h, dict) and (h.get("status_code") or h.get("ports"))][:60]

    for h in live:
        host = h.get("host", "")
        if not host:
            continue
        ports = h.get("ports", [])
        port_nums = []
        for p in ports:
            try:
                port_nums.append(int(p["port"] if isinstance(p, dict) else p))
            except Exception:
                pass
        scheme = "https" if (443 in port_nums or 8443 in port_nums or not port_nums) else "http"
        base_url = f"{scheme}://{host}"
        parts = host.split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

        test_cases = [
            ("evil_reflection",   f"https://evil.com",                "high"),
            ("null_origin",       "null",                             "high"),
            ("pre_domain_bypass", f"https://evil{base_domain}",      "high"),
            ("sub_bypass",        f"https://evil.{base_domain}",     "medium"),
            ("http_bypass",       f"http://{host}",                   "medium"),
        ]

        worst: dict | None = None
        for test_name, origin, base_sev in test_cases:
            tested += 1
            try:
                req = _urlr.Request(
                    base_url,
                    headers={"Origin": origin, "User-Agent": _random_ua(), "Accept": "*/*"},
                )
                try:
                    resp = _urlr.urlopen(req, timeout=8)
                    hdrs = dict(resp.headers)
                    body_snip = resp.read(2048).decode("utf-8", "ignore")
                except _urle.HTTPError as e:
                    hdrs = dict(e.headers) if hasattr(e, "headers") else {}
                    try:
                        body_snip = e.read(2048).decode("utf-8", "ignore")
                    except Exception:
                        body_snip = ""

                acao = hdrs.get("access-control-allow-origin", "") or hdrs.get("Access-Control-Allow-Origin", "")
                acac = (hdrs.get("access-control-allow-credentials", "") or hdrs.get("Access-Control-Allow-Credentials", "")).lower()

                if not acao:
                    continue
                reflected = acao == origin or acao == "*"
                if not reflected:
                    continue
                # Skip generic WAF/CDN challenge pages Ã¢â‚¬â€ a reflected ACAO on a
                # block page is not the application's real CORS policy.
                if _is_waf_challenge_body(body_snip):
                    continue

                has_creds = acac == "true"
                if reflected and has_creds and test_name in ("evil_reflection", "null_origin", "pre_domain_bypass"):
                    sev = "critical"
                elif reflected and has_creds:
                    sev = "high"
                elif acao == "*" and not has_creds:
                    sev = "low"
                else:
                    sev = base_sev

                candidate = {
                    "type": "cors", "host": host, "url": base_url,
                    "test": test_name, "origin_sent": origin,
                    "acao": acao, "acac": acac or "not set",
                    "severity": sev, "category": "CORS",
                    "title": f"CORS Misconfiguration ({test_name}): {host}",
                    "desc": (
                        f"{host} reflects origin '{origin}'. "
                        f"Access-Control-Allow-Origin: {acao}. "
                        f"Access-Control-Allow-Credentials: {acac or 'not set'}."
                    ),

                    "request_raw":  ("GET / HTTP/1.1\r\nHost: " + host + "\r\nOrigin: " + origin + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*"),
                    "response_raw": ("HTTP/1.1 (see headers)\r\n" + "\r\n".join(k + ": " + v for k, v in hdrs.items() if k.lower() != "set-cookie") + "\r\n\r\n" + body_snip[:600]),
                    "matched": acao,
                }
                if worst is None or SEV_ORDER.get(sev, 4) < SEV_ORDER.get(worst["severity"], 4):
                    worst = candidate
            except Exception:
                continue

        if worst:
            findings.append(worst)

    return {
        "total_tested": tested,
        "vulnerable": len(findings),
        "findings": findings,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Kubernetes / Docker / etcd Infrastructure Exposure Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
    tested_ips: set[str] = set()

    for h in hosts[:80]:
        if not isinstance(h, dict):
            continue
        ip = h.get("ip", "")
        if not ip or ip in tested_ips:
            continue
        tested_ips.add(ip)
        host = h.get("host", ip)

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
                    body, code, _ = http_get(f"http://{ip}:{port}{path}", timeout=5, retries=1)
                    if code and code < 500:
                        accessible_paths.append({"path": path, "status": code, "preview": (body or "")[:150]})
                except Exception:
                    pass

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

    return {
        "total_ips_tested": len(tested_ips),
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
            pass
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
            pass
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
                pass
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
            pass
        return None

    def _check_jupyter(ip, port=8888):
        try:
            sc, raw, _ = http_get(f"http://{ip}:{port}/api/kernels", timeout=4, retries=1)
            if sc == 200 and b"kernel" in (raw or b""):
                return {"auth": False, "detail": "Jupyter Notebook API accessible without token", "severity": "critical",
                        "url": f"http://{ip}:{port}/"}
        except Exception:
            pass
        return None

    def _check_generic_open(ip, port, name):
        try:
            sc, raw, _ = http_get(f"http://{ip}:{port}/", timeout=4, retries=1)
            if sc == 200:
                return {"auth": "unknown", "detail": f"{name} web UI accessible (no auth check performed)", "severity": "medium",
                        "url": f"http://{ip}:{port}/"}
        except Exception:
            pass
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
    tested = 0

    # Only test hosts that have a WAF or returned 403
    candidates = [h for h in hosts if h.get("waf") or h.get("status_code") in (403, 406)][:30]

    for h in candidates:
        host = h.get("host", "")
        if not host:
            continue
        url = f"https://{host}/" if not host.startswith("http") else host
        tested += 1

        # Baseline request
        try:
            base_status, base_body, _ = http_get(url, timeout=8, retries=1)
        except Exception:
            continue

        base_len = len(base_body or b"")

        for extra_h in _BYPASS_HEADERS:
            try:
                status, body, _ = http_get(url, timeout=8, retries=1, extra_headers=extra_h)
            except Exception:
                continue

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
                        f"WAF may be bypassed Ã¢â‚¬â€ direct access to origin possible."
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

    return {
        "total_tested": tested,
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
    tested_ips: set = set()

    for h in hosts[:60]:
        ip = h.get("ip", "")
        host_name = h.get("host", ip)
        if not ip or ip in tested_ips:
            continue
        tested_ips.add(ip)

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
                if not has_starttls and port in (25, 587):
                    issues.append("STARTTLS not offered Ã¢â‚¬â€ email in cleartext")
                    sev = "high"
                if port == 25 and "VRFY" in ehlo_resp.upper():
                    issues.append("VRFY command enabled Ã¢â‚¬â€ user enumeration possible")
                    sev = "medium" if sev == "info" else sev
                if port == 25 and "EXPN" in ehlo_resp.upper():
                    issues.append("EXPN command enabled Ã¢â‚¬â€ mailing list disclosure")
                    sev = "medium" if sev == "info" else sev

                if issues:
                    findings.append({
                        "type": "smtp_exposure",
                        "host": host_name,
                        "title": f"SMTP Issue on {host_name}:{port} Ã¢â‚¬â€ {issues[0]}",
                        "severity": sev,
                        "category": "services",
                        "desc": f"Port {port}: {banner[:120]}. Issues: {'; '.join(issues)}",
                        "url": f"smtp://{ip}:{port}",
                        "metadata": rec,
                    })

            except Exception:
                pass

    return {
        "total_ips_tested": len(tested_ips),
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
            pass

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
    tested = 0

    candidates = [h for h in hosts if h.get("status_code") and h.get("status_code") < 500][:40]

    for h in candidates:
        host = h.get("host", "")
        if not host:
            continue
        tested += 1
        base_url = f"https://{host}/" if not host.startswith("http") else host

        # Also test the password reset endpoint if we can guess it
        test_paths = ["/", "/reset-password", "/forgot-password", "/account/recover"]

        for path in test_paths[:2]:
            url = base_url.rstrip("/") + path
            for inj_header in _INJECT_HEADERS:
                try:
                    extra = {inj_header: _POISON_DOMAIN}
                    status, body, resp_h = http_get(url, timeout=8, retries=1, extra_headers=extra)
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

    return {
        "total_tested": tested,
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

    for url_template in candidates[:120]:
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

                req = _ur.Request(url, headers={"User-Agent": _random_ua()})
                # Don't follow redirects Ã¢â‚¬â€ we want the raw Location header
                opener = _ur.build_opener(_ur.HTTPRedirectHandler())
                class _NoRedirect(_ur.HTTPRedirectHandler):
                    def redirect_request(self, *a, **kw): return None
                opener2 = _ur.build_opener(_NoRedirect())
                try:
                    with opener2.open(req, timeout=6) as resp:
                        status = resp.status
                        loc = resp.headers.get("Location","")
                except HTTPError as e:
                    status = e.code
                    loc = e.headers.get("Location","") if e.headers else ""

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
                continue

    return {
        "total_tested": len(tested_urls),
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
            # Raw HTTP PUT
            try:
                import urllib.request as _ur
                req = _ur.Request(
                    f"https://{bucket}.s3.amazonaws.com/{probe_key}",
                    data=probe_content, method="PUT",
                    headers={"Content-Type": "text/plain"},
                )
                with _ur.urlopen(req, timeout=10) as r:
                    write_ok = r.status in (200, 204)
                if write_ok:
                    del_req = _ur.Request(
                        f"https://{bucket}.s3.amazonaws.com/{probe_key}",
                        method="DELETE",
                    )
                    try:
                        _ur.urlopen(del_req, timeout=10)
                        delete_ok = True
                    except Exception:
                        pass
            except Exception:
                pass

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


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ GraphQL Discovery Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def run_graphql_discovery(hosts: list, domains: list) -> dict:
    """Discover GraphQL endpoints and test introspection + playground exposure."""
    import json as _json_inner
    import concurrent.futures as _cf

    PATHS = [
        "/graphql", "/graphiql", "/api/graphql", "/__graphql",
        "/gql", "/v1/graphql", "/v2/graphql", "/graph",
    ]
    INTROSPECTION = b'{"query":"{__schema{types{name}}}"}'
    PLAYGROUND_KW = {"graphiql", "graphql playground", "altair", "__schema", "introspection"}

    findings: list[dict] = []
    endpoints_found: list[str] = []
    seen: set[str] = set()

    targets: list[tuple[str, str]] = []
    for h in hosts[:20]:
        if not isinstance(h, dict):
            continue
        hhost = h.get("host", "")
        ports = h.get("ports", [])
        pnums = []
        for p in ports:
            try:
                pnums.append(int(p["port"] if isinstance(p, dict) else p))
            except Exception:
                pass
        scheme = "https" if (443 in pnums or 8443 in pnums or not pnums) else "http"
        targets.append((f"{scheme}://{hhost}", hhost))
    for d in domains[:5]:
        targets.append((f"https://{d}", d))

    import requests as _req_mod
    import urllib3; urllib3.disable_warnings()

    def _probe_host(base_host_pair):
        base, host = base_host_pair
        local_findings = []
        local_endpoints = []
        for path in PATHS:
            url = f"{base}{path}"
            try:
                body, status, _ = http_get(url, timeout=5, retries=0)
                if status is None:
                    continue
                is_playground = status == 200 and body and any(kw in body.lower() for kw in PLAYGROUND_KW)
                introspection_works = False
                schema_types: list[str] = []
                if status == 200:
                    try:
                        iresp = _req_mod.post(
                            url, data=INTROSPECTION,
                            headers={"Content-Type": "application/json", "User-Agent": _random_ua()},
                            timeout=5, verify=False, allow_redirects=False,
                        )
                        parsed = _json_inner.loads(iresp.text)
                        types = parsed.get("data", {}).get("__schema", {}).get("types", [])
                        if types:
                            introspection_works = True
                            schema_types = [t.get("name", "") for t in types
                                            if not t.get("name", "").startswith("__")][:20]
                    except Exception:
                        pass
                if not (is_playground or introspection_works):
                    continue
                parts = []
                if introspection_works: parts.append("Introspection Enabled")
                if is_playground:      parts.append("Playground Exposed")
                sev = "critical" if introspection_works else "high"
                desc = f"GraphQL endpoint at {url}."
                if introspection_works:
                    desc += f" Introspection: {len(schema_types)} types ({', '.join(schema_types[:6])})."
                if is_playground:
                    desc += " Interactive playground accessible without auth."
                local_findings.append({
                    "type": "graphql", "host": host, "url": url, "path": path,
                    "status": status, "introspection": introspection_works,
                    "playground": is_playground, "schema_types": schema_types,
                    "severity": sev, "category": "GraphQL",
                    "title": f"GraphQL {' + '.join(parts)}: {host}",
                    "desc": desc,
                })
                local_endpoints.append(url)
                break  # one confirmed endpoint per host is enough
            except Exception:
                continue
        return local_findings, local_endpoints

    # Run probes in parallel with a hard 3-minute cap
    with _cf.ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(_probe_host, t): t for t in targets}
        for fut in _cf.as_completed(futs, timeout=180):
            try:
                lf, le = fut.result()
                findings.extend(lf)
                endpoints_found.extend(le)
            except Exception:
                pass

    return {
        "total_found": len(findings),
        "endpoints": endpoints_found,
        "findings": findings,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Postman Collections Exposure Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

# Regex patterns to detect secrets inside Postman collection JSON
_POSTMAN_SECRET_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']'), "password", "critical"),
    (re.compile(r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']([^"\']{8,})["\']'), "api_key", "high"),
    (re.compile(r'(?i)(token|access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*["\']([A-Za-z0-9_.~+/\-]{16,})["\']'), "token", "high"),
    (re.compile(r'(?i)(secret|client[_-]?secret)\s*[=:]\s*["\']([^"\']{8,})["\']'), "secret", "high"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_access_key", "critical"),
    (re.compile(r'(?i)(Authorization|X-Api-Key|X-Auth-Token)["\']\s*:\s*["\']([^"\']{8,})'), "auth_header", "high"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{80,}'), "github_token", "critical"),
    (re.compile(r'(?i)(basic\s+)([A-Za-z0-9+/]{16,}={0,2})'), "basic_auth", "high"),
]

_POSTMAN_SEARCH_URL  = "https://www.postman.com/_api/search"
_POSTMAN_GATEWAY_URL = "https://documenter.gw.postman.com/api/collections"
_POSTMAN_DOC_URL     = "https://documenter.getpostman.com/view"


def _postman_scan_collection_json(raw: bytes, source_url: str) -> list:
    """Parse a Postman collection JSON blob and extract secrets + endpoints."""
    findings = []
    try:
        text = raw.decode("utf-8", "ignore")
        data = json.loads(text)
    except Exception:
        return findings

    # Walk the full text for secret patterns
    for pat, kind, sev in _POSTMAN_SECRET_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(0)
            # Skip obvious placeholders / template vars
            if re.search(r'\{\{|\$\{|<YOUR|EXAMPLE|REPLACE|xxx|null', val, re.I):
                continue
            findings.append({
                "type":     "postman_secret",
                "kind":     kind,
                "severity": sev,
                "value":    val[:120],
                "source":   source_url,
            })

    # Extract base URLs from collection variables
    def _walk_vars(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str) and ("http" in v.lower() or "{{" in v):
                    yield k, v
                else:
                    yield from _walk_vars(v)
        elif isinstance(node, list):
            for item in node:
                yield from _walk_vars(item)

    base_urls = set()
    for k, v in _walk_vars(data.get("variable", data.get("variables", []))):
        if "http" in v.lower():
            base_urls.add(v[:200])

    if base_urls:
        findings.append({
            "type":     "postman_endpoints",
            "kind":     "base_url",
            "severity": "info",
            "value":    ", ".join(sorted(base_urls)[:5]),
            "source":   source_url,
        })

    return findings


def _postman_public_search(query: str) -> list:
    """Search Postman public API for collections matching `query`."""
    results = []
    try:
        params = f"q={urllib.request.quote(query)}&type=collection&queryType=searchInput"
        url = f"{_POSTMAN_SEARCH_URL}?{params}"
        status, body, _ = http_get(url, timeout=12,
                                   extra_headers={"x-app-version": "9.0.0-flat"})
        if status != 200 or not body:
            return results
        data = json.loads(body)
        for item in data.get("data", []):
            doc = item.get("document", {})
            col_id    = doc.get("id", "")
            col_name  = doc.get("name", "")
            owner     = doc.get("owner", "") or doc.get("publisherHandle", "")
            pub_url   = doc.get("externalLink", "") or f"https://www.postman.com/collection/{col_id}"
            if col_id:
                results.append({
                    "id":     col_id,
                    "name":   col_name,
                    "owner":  owner,
                    "url":    pub_url,
                })
    except Exception:
        pass
    return results


def _postman_fetch_collection(user_id: str, col_id: str) -> bytes:
    """Try to fetch raw JSON from Postman documenter gateway."""
    url = f"{_POSTMAN_GATEWAY_URL}/{user_id}/{col_id}"
    try:
        status, body, _ = http_get(url, timeout=15)
        if status == 200 and body and body.strip().startswith(b"{"):
            return body
    except Exception:
        pass
    return b""


def _github_postman_search(domain: str, company: str, token: str = None) -> list:
    """Search GitHub for committed Postman collection/environment files."""
    if not _dns_resolves("api.github.com"):
        return []

    headers = {"User-Agent": UA, "Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    queries = [
        f'"{domain}" filename:postman_collection.json',
        f'"{domain}" filename:postman_environment.json',
        f'"{company}" filename:postman_collection.json',
        f'"{domain}" extension:json postman',
    ]

    results = []
    seen = set()
    for q in queries:
        try:
            enc = q.replace('"', '%22').replace(' ', '+')
            url = f"https://api.github.com/search/code?q={enc}&per_page=10"
            status, body, _ = http_get(url, timeout=12,
                                       extra_headers={k: v for k, v in headers.items()
                                                      if k != "User-Agent"})
            if status == 403:
                break
            if status != 200 or not body:
                time.sleep(2)
                continue
            data = json.loads(body)
            for item in data.get("items", []):
                repo     = item.get("repository", {})
                fullname = repo.get("full_name", "")
                filepath = item.get("path", "")
                html_url = item.get("html_url", "")
                key = f"{fullname}:{filepath}"
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "repo":     fullname,
                    "file":     filepath,
                    "url":      html_url,
                    "raw_url":  item.get("url", ""),
                    "private":  repo.get("private", False),
                })
            time.sleep(1.5)
        except Exception:
            pass
    return results


def run_postman_collections(domain: str, company_name: str = "",
                            github_token: str = None) -> dict:
    """
    Search for publicly exposed Postman collections related to the target.

    Searches:
    - Postman public API (collection search by domain / company name)
    - GitHub committed postman_collection.json / postman_environment.json
    - Parses found collections for hardcoded secrets, tokens, base URLs

    Returns dict with keys: collections, github_hits, secrets, findings, total, scanned_at
    """
    company = company_name or domain.split(".")[0]
    queries = list({domain, company})  # deduplicated

    # 1. Postman public search
    raw_collections: list[dict] = []
    for q in queries:
        hits = _postman_public_search(q)
        for h in hits:
            if not any(c["id"] == h["id"] for c in raw_collections):
                raw_collections.append(h)
        time.sleep(1)

    # 2. GitHub committed files
    github_hits = _github_postman_search(domain, company, github_token)

    # 3. Parse secrets from GitHub raw files (when token available)
    all_secrets: list[dict] = []
    if github_token:
        gh_headers = {
            "User-Agent": UA,
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3.raw",
        }
        for gh in github_hits[:10]:
            raw_url = gh.get("raw_url", "")
            if not raw_url:
                continue
            try:
                status, body, _ = http_get(raw_url, timeout=12,
                                           extra_headers={k: v for k, v in gh_headers.items()
                                                          if k != "User-Agent"})
                if status == 200 and body:
                    secrets = _postman_scan_collection_json(body, gh.get("url", ""))
                    for s in secrets:
                        s["repo"] = gh.get("repo", "")
                    all_secrets.extend(secrets)
                time.sleep(1)
            except Exception:
                pass

    # 4. Build normalized findings list
    findings: list[dict] = []
    seen_keys: set = set()

    # Collections found on Postman
    for col in raw_collections:
        key = f"postman-col-{col['id']}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        findings.append({
            "type":     "postman_collection",
            "kind":     "public_collection",
            "severity": "medium",
            "title":    f"Postman Collection Exposed: {col['name'] or col['id']}",
            "desc":     f"Public Postman collection owned by '{col['owner']}' references the target. "
                        f"May contain API endpoints, auth flows, or sensitive data.",
            "value":    col["url"],
            "url":      col["url"],
            "host":     domain,
            "module":   "postman_collections",
            "category": "leaks",
            "metadata": {"collection_id": col["id"], "owner": col["owner"]},
        })

    # GitHub committed collections
    for gh in github_hits:
        key = f"postman-gh-{gh['repo']}-{gh['file']}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        findings.append({
            "type":     "postman_github",
            "kind":     "committed_collection",
            "severity": "high",
            "title":    f"Postman Collection on GitHub: {gh['repo']}",
            "desc":     f"File `{gh['file']}` committed to {'private' if gh['private'] else 'public'} "
                        f"repo '{gh['repo']}'. May expose API structure and credentials.",
            "value":    gh["url"],
            "url":      gh["url"],
            "host":     domain,
            "module":   "postman_collections",
            "category": "leaks",
            "metadata": {"repo": gh["repo"], "file": gh["file"]},
        })

    # Hardcoded secrets in collections
    secret_severity_map = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": -1}
    for s in all_secrets:
        key = f"postman-secret-{s['kind']}-{s['value'][:40]}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        findings.append({
            "type":     "postman_secret",
            "kind":     s["kind"],
            "severity": s["severity"],
            "title":    f"Hardcoded {s['kind'].replace('_', ' ').title()} in Postman Collection",
            "desc":     f"Found in repo '{s.get('repo','')}': `{s['value'][:80]}`",
            "value":    s["value"][:120],
            "url":      s.get("source", ""),
            "host":     domain,
            "module":   "postman_collections",
            "category": "credentials",
            "metadata": {"kind": s["kind"], "repo": s.get("repo", "")},
        })

    # Overall severity
    max_sev = "info"
    for f in findings:
        if secret_severity_map.get(f["severity"], -1) > secret_severity_map.get(max_sev, -1):
            max_sev = f["severity"]

    return {
        "domain":       domain,
        "collections":  raw_collections,
        "github_hits":  github_hits,
        "secrets":      all_secrets,
        "findings":     findings,
        "total":        len(findings),
        "severity":     max_sev,
        "scanned_at":   datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Run all for a company Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def run_all(company: dict, hosts: list, findings: list,
            github_token: str = None, shodan_key: str = None,
            hibp_key: str = None, nvd_key: str = None,
            verbose: bool = False) -> dict:
    domain  = company["domains"][0] if company.get("domains") else ""
    domains = company.get("domains", [domain])
    org     = company.get("name", domain.split(".")[0])
    results = {}

    _v = lambda msg: print(f"  [*] {msg}") if verbose else None

    # Ã¢â€â‚¬Ã¢â€â‚¬ Fast passive modules Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    _v(f"Email Security Ã¢â‚¬â€ {domain}")
    results["email"] = run_email_recon(domain)

    _v(f"Full DNS Records Ã¢â‚¬â€ {domain}")
    results["dns"] = dns_records(domain)

    _v(f"Certificate Transparency Ã¢â‚¬â€ {domain}")
    results["certs"] = run_cert_recon(domain, hosts)

    _v(f"ASN / IP Intelligence")
    results["asn"] = run_asn_recon(hosts)

    _v(f"Typosquatting Ã¢â‚¬â€ {domain}")
    results["typosquat"] = run_typosquatting(domain)

    _v(f"Related Domains Ã¢â‚¬â€ {domain}")
    results["related"] = run_related_domains(domain)

    _v(f"Cloud Asset Discovery Ã¢â‚¬â€ {org}")
    results["cloud"] = run_cloud_assets(domains, org)

    _v(f"Wayback / GAU URL mining Ã¢â‚¬â€ {domain}")
    results["wayback"] = run_wayback(domain)

    _v(f"Breach / Credential Intelligence Ã¢â‚¬â€ {domain}")
    results["breach"] = run_breach_check(domain, hibp_key)

    _v(f"Leaks & Secrets")
    results["leaks"] = run_leaks_recon(domain, hosts, github_token)

    # Ã¢â€â‚¬Ã¢â€â‚¬ Active network modules Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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

    # Ã¢â€â‚¬Ã¢â€â‚¬ API-dependent modules Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    if shodan_key:
        _v(f"Shodan Intelligence")
        results["shodan"] = run_shodan(hosts, shodan_key)

    if nvd_key or True:   # NVD works without key (rate limited)
        _v(f"CVE Lookup Ã¢â‚¬â€ tech stack vs NVD")
        results["cve"] = run_cve_lookup(hosts, nvd_key or "")

    _v(f"JavaScript Recon Ã¢â‚¬â€ crawl + secret extraction")
    results["js"] = run_js_recon(domains, hosts)

    _v(f"DNS Brute-force & Permutations Ã¢â‚¬â€ {domain}")
    results["dns_brute"] = run_dns_bruteforce(domain, hosts)

    _v(f"API/Panel Exposure Ã¢â‚¬â€ nuclei scan")
    results["api_panels"] = run_api_exposure(hosts, domains)

    _v(f"CertStream Ã¢â‚¬â€ new certificate monitoring")
    results["certstream"] = run_certstream_snapshot(domains, duration_sec=60)

    _v(f"Screenshots Ã¢â‚¬â€ visual inventory")
    results["screenshot"] = run_screenshots(hosts, domains)

    # Ã¢â€â‚¬Ã¢â€â‚¬ Risk scoring Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    _v(f"Risk scoring hosts")
    results["host_scores"] = {h["host"]: score_host(h, findings) for h in hosts}

    return results

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ CLI entry Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="ASM Recon Platform Ã¢â‚¬â€ modular recon engine")
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


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Content Discovery via ffuf + Wordlists Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
# Uses project-bundled wordlists for: directories, files, API routes, parameters.
# Runs ffuf against live hosts with smart rate limiting per mode.

def run_content_discovery(hosts: list, mode: str = "balanced") -> dict:
    """
    Discover hidden directories, files, API endpoints, and parameters
    using ffuf against live hosts with project wordlists.

    Modes: stealth (500 req/host), balanced (2k req/host), fast (10k req/host)
    """
    import shutil, tempfile, os

    ffuf_bin = shutil.which("ffuf")
    if not ffuf_bin:
        return {"error": "ffuf not found", "findings": []}

    # Ã¢â€â‚¬Ã¢â€â‚¬ Load wordlists Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    try:
        from tools import load_wordlist
    except ImportError:
        return {"error": "wordlist loader unavailable", "findings": []}

    MODE_CAPS  = {"stealth": 500, "balanced": 2000, "fast": 10000}
    MODE_RATE  = {"stealth": 3, "balanced": 8, "fast": 20}
    MODE_WL    = {"stealth": "small", "balanced": "medium", "fast": "large"}
    cap  = MODE_CAPS.get(mode, 2000)
    rate = MODE_RATE.get(mode, 8)
    wl_mode = MODE_WL.get(mode, "medium")

    dirs_wl  = load_wordlist("directories", wl_mode, cap)
    files_wl = load_wordlist("files", wl_mode, min(cap // 2, 3000))
    api_wl   = load_wordlist("api", wl_mode, min(cap, 5000))
    param_wl = load_wordlist("parameters", wl_mode, min(cap, 5000))

    if not any([dirs_wl, files_wl, api_wl, param_wl]):
        return {"error": "No wordlists loaded", "findings": []}

    # Ã¢â€â‚¬Ã¢â€â‚¬ Build targets from live hosts Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    targets = []
    for h in hosts:
        host = h.get("host", "")
        if not host:
            continue
        ports = h.get("ports", [])
        has_443 = any((p.get("port") if isinstance(p, dict) else p) == 443 for p in ports)
        has_80  = any((p.get("port") if isinstance(p, dict) else p) == 80 for p in ports)
        if has_443:
            targets.append(f"https://{host}")
        elif has_80:
            targets.append(f"http://{host}")
        elif h.get("status_code") is not None:
            targets.append(f"https://{host}")

    if not targets:
        return {"error": "No live targets", "findings": []}

    findings = []
    stats = {"dirs_scanned": 0, "files_scanned": 0, "api_scanned": 0, "params_scanned": 0,
             "dirs_found": 0, "files_found": 0, "api_found": 0, "params_found": 0}
    wl_files_created = []

    try:
        # Ã¢â€â‚¬Ã¢â€â‚¬ 1. Directory discovery Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        if dirs_wl:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
                wf.write("\n".join(dirs_wl))
                dirs_path = wf.name
            wl_files_created.append(dirs_path)
            for target in targets[:10]:  # cap targets to avoid scan explosion
                try:
                    r = _subp(
                        [ffuf_bin, "-u", f"{target}/FUZZ", "-w", dirs_path,
                         "-mc", "200,201,202,203,204,301,302,307,308,401,403,405,500",
                         "-rate", str(rate), "-t", "20", "-ac",
                         "-timeout", "8", "-maxtime", "120", "-noninteractive"],
                        capture_output=True, text=True, timeout=150,
                    )
                    stats["dirs_scanned"] += len(dirs_wl)
                    for line in r.stdout.splitlines():
                        line = line.strip()
                        if line and ("/" in line or "200" in line or "301" in line or "403" in line):
                            try:
                                parts = line.split()
                                if len(parts) >= 3:
                                    status = int(parts[0]) if parts[0].isdigit() else 0
                                    size   = int(parts[1]) if parts[1].isdigit() else 0
                                    url    = parts[2] if len(parts) > 2 else line
                                    if status and url:
                                        findings.append({
                                            "type": "directory", "url": url, "host": host,
                                            "status": status, "size": size, "wordlist": "directories",
                                        })
                                        stats["dirs_found"] += 1
                            except (ValueError, IndexError):
                                pass
                except Exception:
                    pass

        # Ã¢â€â‚¬Ã¢â€â‚¬ 2. File/backup discovery Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        if files_wl:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
                wf.write("\n".join(files_wl))
                files_path = wf.name
            wl_files_created.append(files_path)
            for target in targets[:8]:
                try:
                    r = _subp(
                        [ffuf_bin, "-u", f"{target}/FUZZ", "-w", files_path,
                         "-mc", "200,301,302,403",
                         "-rate", str(rate), "-t", "20", "-ac",
                         "-timeout", "8", "-maxtime", "90", "-noninteractive"],
                        capture_output=True, text=True, timeout=120,
                    )
                    stats["files_scanned"] += len(files_wl)
                    for line in r.stdout.splitlines():
                        line = line.strip()
                        if line:
                            try:
                                parts = line.split()
                                if len(parts) >= 3:
                                    status = int(parts[0]) if parts[0].isdigit() else 0
                                    url = parts[2] if len(parts) > 2 else line
                                    if status and url:
                                        findings.append({
                                            "type": "file", "url": url, "host": host,
                                            "status": status, "wordlist": "files",
                                        })
                                        stats["files_found"] += 1
                            except (ValueError, IndexError):
                                pass
                except Exception:
                    pass

        # Ã¢â€â‚¬Ã¢â€â‚¬ 3. API route fuzzing Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        if api_wl:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
                wf.write("\n".join(api_wl))
                api_path = wf.name
            wl_files_created.append(api_path)
            for target in targets[:6]:
                for prefix in ["/api", "/v1", "/v2", "/graphql", ""]:
                    try:
                        r = _subp(
                            [ffuf_bin, "-u", f"{target}{prefix}/FUZZ", "-w", api_path,
                             "-mc", "200,201,301,302,401,403,405",
                             "-rate", str(rate), "-t", "15", "-ac",
                             "-timeout", "8", "-maxtime", "90", "-noninteractive"],
                            capture_output=True, text=True, timeout=120,
                        )
                        stats["api_scanned"] += len(api_wl)
                        for line in r.stdout.splitlines():
                            line = line.strip()
                            if line:
                                try:
                                    parts = line.split()
                                    if len(parts) >= 3:
                                        status = int(parts[0]) if parts[0].isdigit() else 0
                                        url = parts[2] if len(parts) > 2 else line
                                        if status and url:
                                            findings.append({
                                                "type": "api_route", "url": url, "host": host,
                                                "status": status, "wordlist": "api",
                                            })
                                            stats["api_found"] += 1
                                except (ValueError, IndexError):
                                    pass
                    except Exception:
                        pass

        # Ã¢â€â‚¬Ã¢â€â‚¬ 4. Parameter fuzzing Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        if param_wl:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
                wf.write("\n".join(param_wl))
                param_path = wf.name
            wl_files_created.append(param_path)
            for target in targets[:5]:
                try:
                    r = _subp(
                        [ffuf_bin, "-u", f"{target}?FUZZ=1", "-w", param_path,
                         "-mc", "200,301,302,400,401,403,422,500",
                         "-rate", str(rate), "-t", "15", "-ac",
                         "-timeout", "8", "-maxtime", "90", "-noninteractive"],
                        capture_output=True, text=True, timeout=120,
                    )
                    stats["params_scanned"] += len(param_wl)
                    for line in r.stdout.splitlines():
                        line = line.strip()
                        if line and "FUZZ" not in line:
                            try:
                                parts = line.split()
                                if len(parts) >= 3:
                                    status = int(parts[0]) if parts[0].isdigit() else 0
                                    url = parts[2] if len(parts) > 2 else line
                                    if status and url:
                                        findings.append({
                                            "type": "parameter", "url": url, "host": host,
                                            "status": status, "wordlist": "parameters",
                                        })
                                        stats["params_found"] += 1
                            except (ValueError, IndexError):
                                pass
                except Exception:
                    pass

    finally:
        for p in wl_files_created:
            try:
                os.unlink(p)
            except Exception:
                pass

    return {
        "findings": findings[:500],
        "stats": stats,
        "total_found": len(findings),
        "mode": mode,
        "wordlist_sizes": {
            "directories": len(dirs_wl), "files": len(files_wl),
            "api": len(api_wl), "parameters": len(param_wl),
        },
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Browser Deep Recon via Playwright Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
# Uses the playwright venv at /home/kali/.asm-playwright (upstream pip, not Kali pkg).
# Falls back gracefully if unavailable.

def _pw_import():
    """Import playwright from the dedicated venv, bypassing the broken Kali system package."""
    import sys
    from pathlib import Path as _P
    venv_lib = _P("/home/kali/.asm-playwright/lib")
    site_pkg = next(venv_lib.glob("python3.*/site-packages"), None) if venv_lib.exists() else None
    if site_pkg and str(site_pkg) not in sys.path:
        sys.path.insert(0, str(site_pkg))
    from playwright.sync_api import sync_playwright, TimeoutError as PwTimeout
    return sync_playwright, PwTimeout


def run_browser_recon(target_url: str, screenshot_dir: str = "/tmp", timeout: int = 25) -> dict:
    """Launch headless Chromium via Playwright, navigate, extract recon intel.

    Returns:
      {
        "url": str,
        "status": int,
        "title": str,
        "technologies": [str],
        "api_endpoints": [{"method":str,"url":str,"type":str}],
        "secrets_found": [{"source":str,"key":str,"value_hint":str}],
        "source_maps": [str],
        "exposed_paths": [{"path":str,"status":int}],
        "cors_config": {"allow_origin":str,"allow_credentials":bool,...},
        "security_headers": {"missing":[str],"present":{str:str}},
        "third_party_services": [str],
        "developer_notes": [str],
        "screenshot": str,
        "observations": [str],
        "js_analysis": {...},
        "error": str|None,
      }
    """
    import re, os

    result = {
        "url": target_url,
        "status": 0,
        "title": "",
        "technologies": [],
        "api_endpoints": [],
        "secrets_found": [],
        "source_maps": [],
        "exposed_paths": [],
        "cors_config": {},
        "security_headers": {"missing": [], "present": {}},
        "third_party_services": [],
        "developer_notes": [],
        "screenshot": "",
        "observations": [],
        "cookies": [],
        "error": None,
    }

    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    result["url"] = target_url

    try:
        sync_playwright, PwTimeout = _pw_import()
    except Exception as e:
        result["error"] = f"playwright unavailable: {e}"
        return result

    timeout_ms = timeout * 1000
    api_endpoints = []
    nav_headers: dict = {}

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox", "--disable-dev-shm-usage",
                "--ignore-certificate-errors", "--disable-web-security",
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars", "--window-size=1366,768",
            ],
        )
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        )
        page = context.new_page()

        # Ã¢â€â‚¬Ã¢â€â‚¬ Network interception Ã¢â‚¬â€ captures ALL requests at browser level Ã¢â€â‚¬Ã¢â€â‚¬
        def _on_request(req):
            u = req.url
            rt = req.resource_type
            if rt in ("xhr", "fetch") or any(
                x in u for x in ["/api/", "/graphql", "/v1/", "/v2/", "/rest/", ".json"]
            ):
                api_endpoints.append({"method": req.method, "url": u, "type": rt})

        def _on_response(resp):
            nonlocal nav_headers
            try:
                if resp.url.rstrip("/") == target_url.rstrip("/") and not nav_headers:
                    nav_headers = dict(resp.headers)
                    result["status"] = resp.status
            except Exception:
                pass

        page.on("request", _on_request)
        page.on("response", _on_response)

        try:
            from playwright_agent.browser import goto_resilient
            _, nav_error, _, _ = goto_resilient(page, target_url, base_timeout=timeout)
            if nav_error:
                result["observations"].append(f"navigation_warning: {nav_error[:160]}")
        except Exception as e:
            result["error"] = str(e)
            browser.close()
            return result

        result["api_endpoints"] = api_endpoints[:200]

        # Helper: evaluate JS and return parsed value or ""
        def _eval(expr: str):
            try:
                val = page.evaluate(expr)
                return val if val is not None else ""
            except Exception:
                return ""

        # Ã¢â€â‚¬Ã¢â€â‚¬ Title Ã¢â€â‚¬Ã¢â€â‚¬
        try:
            result["title"] = page.title() or ""
        except Exception:
            pass

        # Ã¢â€â‚¬Ã¢â€â‚¬ 1. Source maps Ã¢â€â‚¬Ã¢â€â‚¬
        try:
            js_urls = _eval(
                "Array.from(document.querySelectorAll('script[src]')).map(s=>s.src)"
            )
            if isinstance(js_urls, list):
                for u in js_urls:
                    if isinstance(u, str) and u.endswith(".map"):
                        result["source_maps"].append(u)
        except Exception:
            pass

        # Ã¢â€â‚¬Ã¢â€â‚¬ 2. Inline secrets Ã¢â€â‚¬Ã¢â€â‚¬
        secret_patterns = [
            ("apiKey",      r'(?:api_key|apiKey|apikey|API_KEY)\s*[:=]\s*["\']([^"\'&]{8,80})["\']'),
            ("token",       r'(?:token|access_token|auth_token|bearer)\s*[:=]\s*["\']([^"\'&]{12,200})["\']'),
            ("firebase",    r'(?:firebase|FIREBASE)\s*[:=]\s*["\']([^"\'&]{8,120})["\']'),
            ("aws_key",     r'(?:AWS_ACCESS_KEY|AWSAccessKeyId)\s*[:=]\s*["\']([A-Z0-9]{16,40})["\']'),
            ("google_maps", r'(?:google_maps_key|GOOGLE_MAPS_KEY|mapsApiKey)\s*[:=]\s*["\']([A-Za-z0-9_-]{20,60})["\']'),
        ]
        try:
            blocks = _eval(
                "Array.from(document.querySelectorAll('script:not([src])')).map(s=>s.textContent)"
            )
            if isinstance(blocks, list):
                for block in blocks:
                    if not isinstance(block, str):
                        continue
                    for label, pat in secret_patterns:
                        for m in re.finditer(pat, block, re.IGNORECASE):
                            val = m.group(1) if m.lastindex else ""
                            result["secrets_found"].append({
                                "source": "inline-script",
                                "key": label,
                                "value_hint": val[:8] + "..." if len(val) > 8 else val,
                            })
        except Exception:
            pass

        # Ã¢â€â‚¬Ã¢â€â‚¬ 3. Third-party services Ã¢â€â‚¬Ã¢â€â‚¬
        known_services = {
            "google-analytics.com": "Google Analytics", "googletagmanager.com": "Google Tag Manager",
            "googleapis.com": "Google APIs",            "firebaseio.com": "Firebase",
            "stripe.com": "Stripe",                      "jsdelivr.net": "jsDelivr CDN",
            "cdnjs.cloudflare.com": "Cloudflare CDN",   "unpkg.com": "unpkg CDN",
            "amazonaws.com": "AWS",                      "azure.com": "Azure",
            "cloudfront.net": "AWS CloudFront",          "recaptcha.net": "reCAPTCHA",
            "hcaptcha.com": "hCaptcha",                  "hotjar.com": "Hotjar",
            "intercom.io": "Intercom",                   "zendesk.com": "Zendesk",
            "segment.io": "Segment",                     "sentry.io": "Sentry",
            "datadoghq.com": "DataDog",                  "newrelic.com": "New Relic",
        }
        try:
            ext_urls = _eval(
                "Array.from(document.querySelectorAll('script[src],link[href],iframe[src],img[src]'))"
                ".map(e=>e.src||e.href||'').filter(u=>u&&!u.includes(location.hostname))"
            )
            if isinstance(ext_urls, list):
                domains: set = set()
                for u in ext_urls:
                    m = re.search(r'//([^/]+)', u)
                    if m:
                        domains.add(m.group(1))
                for d in sorted(domains):
                    label = next((v for k, v in known_services.items() if k in d), d)
                    result["third_party_services"].append(label)
        except Exception:
            pass

        # Ã¢â€â‚¬Ã¢â€â‚¬ 4. Technology detection Ã¢â€â‚¬Ã¢â€â‚¬
        tech_sigs = {
            "react": "React", "vue": "Vue.js", "angular": "Angular", "jquery": "jQuery",
            "bootstrap": "Bootstrap", "tailwind": "Tailwind CSS", "next": "Next.js",
            "nuxt": "Nuxt.js", "gatsby": "Gatsby", "wordpress": "WordPress",
            "drupal": "Drupal", "laravel": "Laravel", "django": "Django",
            "flask": "Flask", "express": "Express.js", "fastapi": "FastAPI",
            "swagger": "Swagger", "redoc": "ReDoc", "graphql": "GraphQL",
            "alpinejs": "Alpine.js", "svelte": "Svelte", "preact": "Preact",
            "socket.io": "Socket.IO", "axios": "Axios",
        }
        try:
            meta_tags = _eval(
                "Array.from(document.querySelectorAll('meta[name=generator]')).map(m=>m.content||'')"
            )
            if isinstance(meta_tags, list):
                result["technologies"].extend(t for t in meta_tags if t)
            script_srcs = _eval(
                "Array.from(document.querySelectorAll('script[src]')).map(s=>s.src)"
            )
            if isinstance(script_srcs, list):
                for src in script_srcs:
                    sl = src.lower()
                    for sig, name in tech_sigs.items():
                        if sig in sl and name not in result["technologies"]:
                            result["technologies"].append(name)
        except Exception:
            pass

        # Ã¢â€â‚¬Ã¢â€â‚¬ 5. JS Deep Analysis Ã¢â€â‚¬Ã¢â€â‚¬
        js_deep = result.setdefault("js_analysis", {
            "webpack_modules": 0, "webpack_chunks": [],
            "storage_keys": {"localStorage": [], "sessionStorage": []},
            "global_variables": [], "framework_routes": [],
            "service_workers": [], "inline_event_handlers": 0,
        })

        try:
            wp = _eval(
                "(function(){try{"
                "var wp=window.webpackChunk||window.__webpack_require__||null;"
                "var mods=0,chunks=[];"
                "if(wp){if(wp.m)mods=Object.keys(wp.m).length;"
                "if(wp.c)chunks=Object.keys(wp.c).filter(k=>typeof wp.c[k]==='object');}"
                "return {modules:mods,chunks:chunks.slice(0,20)}"
                "}catch(e){return {modules:0,chunks:[]}}})()"
            )
            if isinstance(wp, dict):
                js_deep["webpack_modules"] = wp.get("modules", 0)
                js_deep["webpack_chunks"] = wp.get("chunks", [])
        except Exception:
            pass

        try:
            comps = _eval(
                "(function(){try{"
                "var comps=[];"
                "var root=document.getElementById('root')||document.getElementById('__next')||document.getElementById('app');"
                "if(root){var fk=Object.keys(root).find(k=>k.startsWith('__reactFiber')||k.startsWith('__reactInternalInstance'));"
                "if(fk){function w(n,d){if(!n||d>30)return;"
                "var name=(n.type||{}).name||(n.type||{}).displayName||(n.elementType||{}).name||'';"
                "if(name)comps.push(name);if(n.child)w(n.child,d+1);if(n.sibling)w(n.sibling,d+1);}"
                "w(root[fk],0);}}"
                "return [...new Set(comps)].slice(0,50)"
                "}catch(e){return []}})()"
            )
            if isinstance(comps, list) and comps:
                js_deep["framework_routes"] = comps
        except Exception:
            pass

        try:
            vue = _eval(
                "(function(){try{"
                "var all=document.querySelectorAll('*');"
                "for(var i=0;i<Math.min(all.length,500);i++){"
                "var el=all[i];var v=el.__vue__||el.__vue_app__||el._vnode;"
                "if(v){return [(v.$options||{}).name||el.tagName.toLowerCase()];}}"
                "var a=document.querySelector('[data-v-]')||document.querySelector('[data-v-app]');"
                "return a?['VueApp detected']:[]"
                "}catch(e){return []}})()"
            )
            if isinstance(vue, list) and vue:
                js_deep["framework_routes"].extend(vue)
        except Exception:
            pass

        try:
            storage = _eval(
                "(function(){try{"
                "var ls=[],ss=[];"
                "for(var i=0;i<localStorage.length;i++)ls.push(localStorage.key(i));"
                "for(var i=0;i<sessionStorage.length;i++)ss.push(sessionStorage.key(i));"
                "return {ls:ls.slice(0,50),ss:ss.slice(0,50)}"
                "}catch(e){return {ls:[],ss:[]}}})()"
            )
            if isinstance(storage, dict):
                js_deep["storage_keys"]["localStorage"] = storage.get("ls", [])
                js_deep["storage_keys"]["sessionStorage"] = storage.get("ss", [])
        except Exception:
            pass

        try:
            globs = _eval(
                "(function(){try{"
                "var std=new Set('Infinity NaN undefined Array ArrayBuffer Boolean DataView Date Error Function Generator Int8Array Int16Array Int32Array Intl JSON Map Math Number Object Promise Proxy RangeError ReferenceError Reflect RegExp Set SharedArrayBuffer String Symbol SyntaxError TypeError Uint8Array Uint16Array Uint32Array WeakMap WeakSet decodeURI encodeURI eval isFinite isNaN parseFloat parseInt globalThis queueMicrotask TextDecoder TextEncoder DOMException AbortController'.split(' '));"
                "var g=[];"
                "for(var k of Object.getOwnPropertyNames(window)){"
                "if(!std.has(k)&&!k.startsWith('webkit')&&!k.startsWith('__')&&k[0]!==k[0].toLowerCase()&&k!=='Window'){"
                "try{var v=window[k];if(typeof v==='function'||typeof v==='object')g.push(k);}catch(e){}}}"
                "return g.slice(0,80)"
                "}catch(e){return []}})()"
            )
            if isinstance(globs, list):
                js_deep["global_variables"] = globs
        except Exception:
            pass

        try:
            sws = _eval(
                "(async()=>{try{"
                "if(!navigator.serviceWorker)return [];"
                "var r=await navigator.serviceWorker.getRegistrations();"
                "return r.map(x=>({scope:x.scope,active:!!x.active,scriptURL:x.active?x.active.scriptURL:''}))"
                "}catch(e){return []}})()"
            )
            if isinstance(sws, list):
                js_deep["service_workers"] = sws
        except Exception:
            pass

        try:
            eh_count = _eval(
                "(function(){var c=0,all=document.querySelectorAll('*');"
                "for(var i=0;i<Math.min(all.length,500);i++){"
                "var a=all[i].getAttributeNames?all[i].getAttributeNames():[];"
                "for(var j=0;j<a.length;j++)if(/^on[a-z]+$/i.test(a[j])&&all[i].getAttribute(a[j]))c++;}"
                "return c})()"
            )
            if isinstance(eh_count, int):
                js_deep["inline_event_handlers"] = eh_count
        except Exception:
            pass

        # Observations from JS analysis
        if js_deep["webpack_modules"] > 0:
            result["observations"].append(f"Webpack: {js_deep['webpack_modules']} modules, {len(js_deep['webpack_chunks'])} chunks Ã¢â‚¬â€ source exposure possible")
        if js_deep["framework_routes"]:
            result["observations"].append(f"Framework components: {', '.join(js_deep['framework_routes'][:8])}")
        if js_deep["storage_keys"]["localStorage"]:
            ls = js_deep["storage_keys"]["localStorage"]
            result["observations"].append(f"localStorage: {len(ls)} keys Ã¢â‚¬â€ {', '.join(ls[:5])}")
        if js_deep["storage_keys"]["sessionStorage"]:
            result["observations"].append(f"sessionStorage: {len(js_deep['storage_keys']['sessionStorage'])} keys Ã¢â‚¬â€ possible auth tokens")
        if js_deep["service_workers"]:
            result["observations"].append(f"Service Workers: {', '.join(s['scope'] for s in js_deep['service_workers'][:3])}")
        if js_deep["global_variables"]:
            result["observations"].append(f"Custom globals: {', '.join(js_deep['global_variables'][:6])}")
        if js_deep["inline_event_handlers"] > 5:
            result["observations"].append(f"Inline event handlers: {js_deep['inline_event_handlers']} Ã¢â‚¬â€ possible DOM XSS surface")

        # Ã¢â€â‚¬Ã¢â€â‚¬ 6. Security headers Ã¢â‚¬â€ read from nav_headers captured at response time Ã¢â€â‚¬Ã¢â€â‚¬
        sec_headers = [
            "content-security-policy", "x-frame-options",
            "x-content-type-options", "strict-transport-security",
        ]
        for h in sec_headers:
            if nav_headers.get(h):
                result["security_headers"]["present"][h] = nav_headers[h]
            else:
                result["security_headers"]["missing"].append(h)
        acao = nav_headers.get("access-control-allow-origin", "")
        if acao:
            result["cors_config"]["allow_origin"] = acao
            result["cors_config"]["allow_credentials"] = (
                nav_headers.get("access-control-allow-credentials", "").lower() == "true"
            )
            if acao == "*":
                result["observations"].append("CORS wildcard (*) Ã¢â‚¬â€ overly permissive")
            if result["cors_config"].get("allow_credentials") and acao == "*":
                result["observations"].append("DANGER: CORS * + credentials=true Ã¢â‚¬â€ credential theft possible")

        # Ã¢â€â‚¬Ã¢â€â‚¬ 7. Developer comments / TODOs Ã¢â€â‚¬Ã¢â€â‚¬
        try:
            comments = _eval(
                "Array.from(document.querySelectorAll('*'))"
                ".flatMap(e=>Array.from(e.childNodes).filter(n=>n.nodeType===8).map(c=>c.textContent))"
            )
            if isinstance(comments, list):
                kws = {"todo", "fixme", "hack", "debug", "password", "secret", "key",
                       "token", "backdoor", "disabled", "staging", "sandbox"}
                for c in comments:
                    if isinstance(c, str) and any(kw in c.lower() for kw in kws):
                        result["developer_notes"].append(c.strip()[:200])
        except Exception:
            pass

        # Ã¢â€â‚¬Ã¢â€â‚¬ 8. Login forms Ã¢â€â‚¬Ã¢â€â‚¬
        try:
            forms = _eval(
                "Array.from(document.querySelectorAll('form')).map(f=>({"
                "action:f.action||'',"
                "inputs:Array.from(f.querySelectorAll('input')).map(i=>({type:i.type,name:i.name})),"
                "hasPassword:!!f.querySelector('input[type=password]')}))"
            )
            if isinstance(forms, list):
                for f in forms:
                    if isinstance(f, dict) and f.get("hasPassword"):
                        result["observations"].append(
                            f"Login form at {f.get('action','(page)')} Ã¢â‚¬â€ {len(f.get('inputs',[]))} inputs"
                        )
        except Exception:
            pass

        # Ã¢â€â‚¬Ã¢â€â‚¬ 9. Cookies Ã¢â€â‚¬Ã¢â€â‚¬
        try:
            cookies = context.cookies()
            result["cookies"] = [
                {
                    "name":      c["name"],
                    "domain":    c.get("domain", ""),
                    "httpOnly":  c.get("httpOnly", False),
                    "secure":    c.get("secure", False),
                    "sameSite":  c.get("sameSite", ""),
                    "path":      c.get("path", "/"),
                    "session":   not bool(c.get("expires", -1) > 0),
                }
                for c in cookies
            ]
            insecure = [c for c in result["cookies"] if not c["httpOnly"] or not c["secure"]]
            if insecure:
                result["observations"].append(
                    f"{len(insecure)} cookies with insecure flags Ã¢â‚¬â€ "
                    f"{sum(1 for c in insecure if not c['httpOnly'])} missing HttpOnly, "
                    f"{sum(1 for c in insecure if not c['secure'])} missing Secure"
                )
        except Exception:
            result["cookies"] = []

        # Ã¢â€â‚¬Ã¢â€â‚¬ 10. Screenshot Ã¢â€â‚¬Ã¢â€â‚¬
        try:
            safe = re.sub(r'[^a-zA-Z0-9]', '_', target_url)[:60]
            fname = f"browser_{safe}.png"
            fpath = os.path.join(screenshot_dir, fname)
            page.screenshot(path=fpath, full_page=False)
            result["screenshot"] = fpath
        except Exception:
            pass

        # Ã¢â€â‚¬Ã¢â€â‚¬ Security header observations Ã¢â€â‚¬Ã¢â€â‚¬
        if "content-security-policy" in result["security_headers"]["missing"]:
            result["observations"].append("Missing CSP Ã¢â‚¬â€ XSS risk")
        if "strict-transport-security" in result["security_headers"]["missing"]:
            result["observations"].append("Missing HSTS Ã¢â‚¬â€ no TLS enforcement")
        if "x-frame-options" in result["security_headers"]["missing"]:
            result["observations"].append("Missing X-Frame-Options Ã¢â‚¬â€ clickjacking possible")
        if result["source_maps"]:
            result["observations"].append(f"Source maps exposed ({len(result['source_maps'])}) Ã¢â‚¬â€ source code recoverable")
        if len(result["api_endpoints"]) > 5:
            result["observations"].append(f"{len(result['api_endpoints'])} API endpoints captured Ã¢â‚¬â€ check for unauth access")
        if result["secrets_found"]:
            result["observations"].append(f"{len(result['secrets_found'])} potential secrets in inline JS Ã¢â‚¬â€ rotate immediately")

        browser.close()

    return result


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Browser Crawler Ã¢â‚¬â€ Playwright multi-page crawl across ALL subdomains Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def run_browser_crawl(hosts, domains, max_hosts: int = 150,
                      max_pages_per_host: int = 8, timeout: int = 20,
                      workers: int = 3) -> dict:
    """
    Playwright crawler over ALL live subdomains. For each live host it renders the
    root page and follows same-host internal links (breadth-first) up to
    max_pages_per_host, executing JS so SPA routes and dynamically-injected URLs are
    captured (vs. static crawlers). Per page it collects hyperlinks, network API
    endpoints (xhr/fetch) and forms. In-scope `*.<domain>` hostnames found in links
    are returned under `subdomains` and merged into the host pool by the pipeline.

    Bounded by max_hosts / max_pages_per_host for safety; raise them for fuller
    coverage at the cost of runtime.
    """
    if isinstance(domains, str):
        domains = [domains]
    domains = [str(d).lower().strip().strip(".") for d in domains if d]
    now = datetime.now().isoformat(timespec="seconds")
    from urllib.parse import urlparse as _up

    # Ã¢â€â‚¬Ã¢â€â‚¬ Build target URLs from live hosts (dedup by host) Ã¢â€â‚¬Ã¢â€â‚¬
    LIVE = {200, 301, 302, 401, 403}
    seen_hosts, targets = set(), []
    for h in hosts or []:
        host = (h.get("host") or "").strip().lower()
        if not host or host in seen_hosts:
            continue
        if h.get("status_code", 0) not in LIVE and not h.get("ip"):
            continue
        seen_hosts.add(host)
        targets.append(h.get("url") or f"https://{host}")
        if len(targets) >= max_hosts:
            break

    if not targets:
        return {"hosts_crawled": 0, "hosts_targeted": 0, "results": [], "urls": [],
                "subdomains": [], "api_endpoints": [], "url_count": 0, "count": 0,
                "note": "nenhum host vivo para crawl", "scanned_at": now}

    try:
        sync_playwright, PwTimeout = _pw_import()
    except Exception as e:
        return {"hosts_crawled": 0, "hosts_targeted": len(targets), "results": [],
                "urls": [], "subdomains": [], "error": f"playwright unavailable: {e}",
                "scanned_at": now}

    sub_res = [re.compile(r"([a-z0-9](?:[a-z0-9\-]{0,62}\.)+" + re.escape(d) + r")", re.I)
               for d in domains]
    args = ["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors",
            "--disable-blink-features=AutomationControlled", "--window-size=1366,768"]

    def _crawl_one(base_url):
        if not base_url.startswith("http"):
            base_url = "https://" + base_url
        base_host = _up(base_url).netloc.split(":")[0].lower()
        out = {"url": base_url, "host": base_host, "pages": 0,
               "urls": set(), "api_endpoints": [], "forms": [], "error": None}
        api_seen = set()
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, args=args)
                ctx  = browser.new_context(ignore_https_errors=True, user_agent=UA)
                page = ctx.new_page()

                def _on_request(req):
                    u = req.url
                    if (req.resource_type in ("xhr", "fetch")
                            or any(x in u for x in ("/api/", "/graphql", "/v1/", "/v2/", "/rest/", ".json"))):
                        key = (req.method, u)
                        if key not in api_seen and len(out["api_endpoints"]) < 300:
                            api_seen.add(key)
                            out["api_endpoints"].append({"method": req.method, "url": u})
                page.on("request", _on_request)

                queue, visited = [base_url], set()
                while queue and len(visited) < max_pages_per_host:
                    url = queue.pop(0)
                    if url in visited:
                        continue
                    visited.add(url)
                    try:
                        from playwright_agent.browser import goto_resilient
                        _, nav_error, _, _ = goto_resilient(page, url, base_timeout=timeout)
                        if nav_error and "timeout" not in nav_error.lower():
                            continue
                        page.wait_for_timeout(800)   # deixa XHR disparar
                    except Exception:
                        continue
                    try:
                        links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)") or []
                    except Exception:
                        links = []
                    try:
                        forms = page.evaluate(
                            "() => [...document.forms].map(f => ({action: f.action, "
                            "method: (f.method||'get'), "
                            "inputs: [...f.elements].map(e=>e.name).filter(Boolean)}))"
                        ) or []
                        for fr in forms:
                            if fr.get("action") and fr not in out["forms"] and len(out["forms"]) < 100:
                                out["forms"].append(fr)
                    except Exception:
                        pass
                    for ln in links:
                        if not isinstance(ln, str) or not ln.startswith("http"):
                            continue
                        out["urls"].add(ln)
                        h = _up(ln).netloc.split(":")[0].lower()
                        if h == base_host:
                            clean = ln.split("#")[0]
                            if clean not in visited and len(queue) < max_pages_per_host * 3:
                                queue.append(clean)
                    out["pages"] = len(visited)
                browser.close()
        except Exception as e:
            out["error"] = str(e)
        out["urls"] = sorted(out["urls"])[:500]
        return out

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for r in pool.map(_crawl_one, targets):
            results.append(r)

    # Ã¢â€â‚¬Ã¢â€â‚¬ Aggregate Ã¢â€â‚¬Ã¢â€â‚¬
    all_urls, all_api, subdomains = set(), [], set()
    total_forms = 0
    for r in results:
        for u in r.get("urls", []):
            all_urls.add(u)
            host = _up(u).netloc.split(":")[0].lower()
            for rx in sub_res:
                for m in rx.findall(host):
                    subdomains.add(m.lower().strip("."))
        all_api.extend(r.get("api_endpoints", []))
        total_forms += len(r.get("forms", []))

    return {
        "hosts_crawled":  len([r for r in results if not r.get("error")]),
        "hosts_targeted": len(targets),
        "results":        results,
        "urls":           sorted(all_urls)[:5000],
        "url_count":      len(all_urls),
        "api_endpoints":  all_api[:1000],
        "api_endpoint_count": len(all_api),
        "form_count":     total_forms,
        "subdomains":     sorted(subdomains),
        "count":          len(all_urls),
        "scanned_at":     now,
    }


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# GAP 3  Ã¢â‚¬â€ Container Registry Scanning (Docker Hub, GHCR, ECR Public, Quay)
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

_CONTAINER_REGISTRIES = [
    {"name": "Docker Hub",      "api": "https://hub.docker.com/v2/repositories/{org}/",      "key_header": None},
    {"name": "GitHub Container", "api": "https://ghcr.io/v2/{org}/",                          "key_header": None},
    {"name": "Quay.io",         "api": "https://quay.io/api/v1/repository?namespace={org}",   "key_header": None},
    {"name": "ECR Public",      "api": "https://public.ecr.aws/v2/{org}/",                     "key_header": None},
]

_CONTAINER_KEYWORDS = [
    "api", "app", "web", "backend", "frontend", "worker", "service", "proxy",
    "cron", "scheduler", "migrate", "seed", "build", "deploy", "release",
    "admin", "dashboard", "monitor", "log", "metrics", "alerts", "nginx",
    "envoy", "haproxy", "traefik", "caddy",
]


def _derive_org_names_from_domain(domain: str) -> list:
    names = set()
    base = domain.lower().split(".")[0] if "." in domain else domain.lower()
    names.add(base)
    names.add(base.replace("-", ""))
    names.add(base.replace("_", ""))
    base2 = domain.replace(".", "-")
    if base2 != domain:
        names.add(base2)
    for part in domain.split(".")[:-1]:
        if len(part) > 2:
            names.add(part)
    return sorted(names, key=len)


def _check_container_registry(registry: dict, org: str, token: str = "") -> list:
    findings = []
    api_url = registry["api"].format(org=org)
    headers = {"Accept": "application/json", "User-Agent": UA}
    if registry["key_header"] and token:
        headers[registry["key_header"]] = token

    try:
        sc, raw, _ = http_get(api_url, timeout=8, retries=1, extra_headers=headers)
        if sc == 200:
            data = json.loads(raw.decode("utf-8", "ignore"))
            images = []
            if isinstance(data, dict):
                images = data.get("results", data.get("repositories", data.get("images", [])))
            elif isinstance(data, list):
                images = data
            for img in images:
                name = img.get("name", img.get("repository_name", img.get("slug", str(img))))
                desc = img.get("description", img.get("short_description", ""))
                updated = img.get("last_updated", img.get("updated_at", ""))
                pulls = img.get("pull_count", img.get("download_count", "?"))
                findings.append({
                    "type": "container_image",
                    "image": str(name),
                    "registry": registry["name"],
                    "org": org,
                    "description": str(desc)[:200],
                    "updated": str(updated),
                    "pulls": str(pulls),
                    "url": api_url.rstrip("/") + "/" + str(name),
                    "severity": "medium",
                })
    except Exception:
        pass
    return findings


def _brute_container_orgs(registry: dict, org_names: list, token: str = "") -> list:
    findings = []
    for org in org_names[:6]:
        findings.extend(_check_container_registry(registry, org, token))
        time.sleep(0.3)
    return findings


def run_container_registry_scan(domains, company_name: str = "",
                                 docker_token: str = "") -> dict:
    org_names = set()
    for d in domains if isinstance(domains, list) else [domains]:
        org_names.update(_derive_org_names_from_domain(d))
    if company_name:
        base = re.sub(r"[^a-z0-9]", "", company_name.lower())
        if base:
            org_names.add(base)
            org_names.add(base.replace(" ", ""))
    org_names = sorted(org_names, key=len)[:10]
    all_findings = []
    scanned = {}
    for reg in _CONTAINER_REGISTRIES:
        try:
            f = _brute_container_orgs(reg, org_names, docker_token)
            all_findings.extend(f)
            scanned[reg["name"]] = len(f)
        except Exception:
            scanned[reg["name"]] = 0
    critical = [f for f in all_findings if "critical" in f.get("severity", "")]
    return {
        "findings": all_findings,
        "total": len(all_findings),
        "critical_count": len(critical),
        "orgs_checked": org_names,
        "registries_scanned": scanned,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# GAP 9  Ã¢â‚¬â€ Internet-Wide Scan Dataset Ingestion (Censys bulk, Shodan bulk)
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

def run_bulk_dataset_scan(hosts: list, domains: list,
                           shodan_key: str = "", censys_id: str = "",
                           censys_secret: str = "") -> dict:
    bulk_findings = []
    domain_names = [d for d in (domains or []) if d]

    # Ã¢â€â‚¬Ã¢â€â‚¬ Shodan InternetDB (free, no key required) Ã¢â€â‚¬Ã¢â€â‚¬
    for h in hosts[:50]:
        ip = h.get("ip", "")
        if not ip:
            continue
        try:
            sc, raw, _ = http_get(
                f"https://internetdb.shodan.io/{ip}",
                timeout=5, retries=1,
            )
            if sc == 200:
                data = json.loads(raw.decode("utf-8", "ignore"))
                hostnames_found = data.get("hostnames", [])
                ports_found = data.get("ports", [])
                vulns_found = data.get("vulns", [])
                cpes_found = data.get("cpes", [])
                if ports_found or vulns_found:
                    bulk_findings.append({
                        "type": "shodan_internetdb",
                        "ip": ip,
                        "host": h.get("host", ip),
                        "ports": ports_found,
                        "vulns": vulns_found,
                        "cpes": cpes_found,
                        "hostnames": hostnames_found[:10],
                        "severity": "medium" if vulns_found else "info",
                        "source": "shodan_internetdb",
                    })
        except Exception:
            pass

    # Ã¢â€â‚¬Ã¢â€â‚¬ Censys Search API (requires id/secret) Ã¢â€â‚¬Ã¢â€â‚¬
    if censys_id and censys_secret:
        import base64
        auth = base64.b64encode(f"{censys_id}:{censys_secret}".encode()).decode()
        for domain in domain_names[:3]:
            try:
                sc, raw, _ = http_get(
                    f"https://search.censys.io/api/v2/certificates/search"
                    f"?q=parsed.names:{domain}&per_page=20",
                    timeout=10, retries=1,
                    extra_headers={
                        "Authorization": f"Basic {auth}",
                        "Accept": "application/json",
                        "User-Agent": UA,
                    },
                )
                if sc == 200:
                    data = json.loads(raw.decode("utf-8", "ignore"))
                    for hit in data.get("result", {}).get("hits", []):
                        names = hit.get("parsed", {}).get("names", [])
                        for name in names[:5]:
                            if domain in name:
                                bulk_findings.append({
                                    "type": "censys_cert",
                                    "domain": domain,
                                    "subdomain": name,
                                    "fingerprint": hit.get("fingerprint_sha256", "")[:16],
                                    "validity": hit.get("parsed", {}).get("validity_period"),
                                    "severity": "info",
                                    "source": "censys_bulk",
                                })
            except Exception:
                pass

    return {
        "findings": bulk_findings,
        "total": len(bulk_findings),
        "hosts_checked": min(len(hosts), 50),
        "has_shodan": bool(shodan_key),
        "has_censys": bool(censys_id and censys_secret),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# GAP 11 Ã¢â‚¬â€ Database Enumeration: MySQL, PostgreSQL, MSSQL, Oracle active probes
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

def _check_mysql(ip, port=3306):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return None
        # MySQL sends a greeting packet on connect
        data = s.recv(128)
        s.close()
        if len(data) >= 4:
            # MySQL greeting packet: payload length at offset 0-2, seq=0
            payload_len = data[0] | (data[1] << 8) | (data[2] << 16)
            if payload_len > 0 and len(data) > 4:
                # Extract server version (null-terminated string after protocol version)
                proto_ver = data[4]
                if proto_ver == 10:  # MySQL protocol v10
                    desc = "".join(chr(b) for b in data[5:payload_len + 4] if 32 <= b < 127).split("\x00")
                    version = desc[0] if desc else ""
                    auth_detail = "no auth (got greeting)"
                    sev = "high"
                    return {"auth": False, "detail": f"MySQL {version} Ã¢â‚¬â€ {auth_detail}", "severity": sev, "version": version}
    except Exception:
        pass
    return None


def _check_postgresql(ip, port=5432):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return None
        # PostgreSQL StartupMessage Ã¢â‚¬â€ send SSLRequest first
        # SSLRequest: length 8, protocol 80877103
        ssl_req = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
        s.send(ssl_req)
        resp = s.recv(1)
        s.close()
        if resp == b'S':
            return {"auth": "unknown", "detail": "PostgreSQL SSL supported Ã¢â‚¬â€ no auth probe", "severity": "medium"}
        elif resp == b'N':
            return {"auth": "unknown", "detail": "PostgreSQL SSL refused Ã¢â‚¬â€ no auth probe", "severity": "medium"}
        elif len(resp) > 0:
            return {"auth": "unknown", "detail": "PostgreSQL responded Ã¢â‚¬â€ no auth probe", "severity": "medium"}
    except Exception:
        pass
    return None


def _check_mssql(ip, port=1433):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return None
        # TDS Pre-Login Ã¢â‚¬â€ send empty prelogin packet
        prelogin = (
            b'\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b'
            b'\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01'
            b'\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00'
            b'\xf3\x0b\x00\x00'
        )
        s.send(prelogin)
        data = s.recv(256)
        s.close()
        if len(data) > 8:
            return {"auth": "unknown", "detail": "MSSQL TDS responded Ã¢â‚¬â€ no auth probe", "severity": "medium"}
    except Exception:
        pass
    return None


def _check_oracle(ip, port=1521):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return None
        # TNS Connect packet to get service name + version
        connect_data = (
            b'\x00\x3a\x00\x00\x01\x00\x00\x00\x01\x38\x01\x2c\x00\x00\x08\x00'
            b'\x7f\xff\xc6\x0e\x00\x00\x01\x00\x00\x00\x00\x3a\x00\x00\x08\x00'
            b'\x41\x41\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x28\x44\x45\x53\x43\x52\x49\x50'
            b'\x54\x49\x4f\x4e\x3d\x28\x43\x4f\x4e\x4e\x45\x43\x54\x5f\x44\x41'
            b'\x54\x41\x3d\x28\x43\x49\x44\x3d\x28\x50\x52\x4f\x47\x52\x41\x4d'
            b'\x3d\x41\x53\x4d\x29\x29\x29'
        )
        s.send(connect_data)
        data = s.recv(256)
        s.close()
        if len(data) > 4 and data[4] in (0x02, 0x03, 0x04):
            # Extract version string from TNS response
            raw = data.decode("latin-1", "ignore")
            body = raw[8:] if len(raw) > 8 else raw
            return {"auth": "unknown", "detail": f"Oracle TNS responded Ã¢â‚¬â€ version probe: {body[:80]}", "severity": "medium"}
    except Exception:
        pass
    return None


_DB_PROBES_EXTRA = [
    (3306, "MySQL",       "mysql",          _check_mysql),
    (5432, "PostgreSQL",  "postgresql",     _check_postgresql),
    (1433, "MSSQL",       "mssql",          _check_mssql),
    (1521, "Oracle",      "oracle",         _check_oracle),
]


def run_database_enum_extra(hosts: list) -> dict:
    """Active probe for MySQL, PostgreSQL, MSSQL, Oracle Ã¢â‚¬â€ complements run_default_creds."""
    findings = []
    tested = set()
    for h in hosts[:60]:
        if not isinstance(h, dict):
            continue
        ip = h.get("ip", "")
        if not ip or ip in tested:
            continue
        hostname = h.get("host", ip)
        host_ports = set(str(p) for p in (h.get("ports") or []))
        for port, name, _, check_fn in _DB_PROBES_EXTRA:
            if host_ports and str(port) not in host_ports:
                continue
            try:
                result = check_fn(ip, port)
            except Exception:
                result = None
            if result:
                findings.append({
                    "host": hostname, "ip": ip, "port": port, "service": name,
                    "severity": result.get("severity", "high"),
                    "title": f"Database reachable: {name} on {hostname}:{port}",
                    "desc": result.get("detail", ""),
                    "url": f"tcp://{ip}:{port}",
                    "type": "database_enum",
                })
                tested.add(ip)
    return {
        "findings": findings, "total": len(findings),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# GAP 13 Ã¢â‚¬â€ Service Version Detection (banner grabbing on open TCP ports)
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

_SERVICE_PROBES = {
    21:   ("FTP",    b""),
    22:   ("SSH",    b""),
    23:   ("Telnet", b""),
    25:   ("SMTP",   b"EHLO asm.local\r\n"),
    110:  ("POP3",   b"CAPA\r\n"),
    143:  ("IMAP",   b"A001 CAPABILITY\r\n"),
    389:  ("LDAP",   b"0\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"),
    445:  ("SMB",    b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"),
    636:  ("LDAPS",  b""),
    3389: ("RDP",    b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"),
    5900: ("VNC",    b"RFB 003.008\n"),
    8080: ("HTTP",   b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
    8443: ("HTTP",   b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
}

_BANNER_RULES = [
    (re.compile(r"SSH-([\d.]+)[-_](\w+)", re.I), "SSH"),
    (re.compile(r"([\d.]+)\s+.*?FTP", re.I), "FTP"),
    (re.compile(r"(\d+)\s+.*?SMTP", re.I), "SMTP"),
    (re.compile(r"\+OK\s+(.*?)(POP3|ready)", re.I), "POP3"),
    (re.compile(r"\*\s+OK\s+.*?IMAP.*?([\d.]+)", re.I), "IMAP"),
    (re.compile(r"(?:Postfix|Sendmail|Exim|Exchange|ESMTP)\s*([\d.]+)?", re.I), "MTA"),
    (re.compile(r"(?:nginx|Apache|IIS|lighttpd|Caddy|Tomcat|Jetty)[/\s]*([\d.]+)?", re.I), "WebServer"),
    (re.compile(r"(?:Debian|Ubuntu|CentOS|RHEL|Fedora|Amazon Linux)", re.I), "OS"),
    (re.compile(r"RFB\s+([\d.]+)", re.I), "VNC"),
    (re.compile(r"(?:Microsoft\s*)?(?:Windows\s*(?:NT|Server|200\d|201\d|202\d)\s*[\d.]*)", re.I), "Windows"),
]


def _banner_grab(ip: str, port: int, probe: bytes, timeout: float = 3.0) -> str:
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return ""
        if probe:
            s.send(probe)
        time.sleep(0.3)
        data = b""
        while True:
            try:
                chunk = s.recv(512)
                if not chunk:
                    break
                data += chunk
                if len(data) >= 1024:
                    break
            except socket.timeout:
                break
        s.close()
        return data.decode("utf-8", "ignore").replace("\r\n", " ").replace("\n", " ").strip()[:300]
    except Exception:
        return ""


def _parse_banner(banner: str) -> list:
    matches = []
    for rx, svc in _BANNER_RULES:
        m = rx.search(banner)
        if m:
            ver = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
            matches.append(f"{svc}{' ' + ver if ver else ''}")
    return matches[:5]


def run_service_version_detect(hosts: list) -> dict:
    findings = []
    tested = set()
    for h in hosts[:100]:
        if not isinstance(h, dict):
            continue
        ip = h.get("ip", "")
        if not ip or ip in tested:
            continue
        hostname = h.get("host", ip)
        host_ports = h.get("ports", [])
        for port in (host_ports if host_ports else sorted(_SERVICE_PROBES.keys())):
            port_int = int(port) if not isinstance(port, int) else port
            probe_info = _SERVICE_PROBES.get(port_int)
            if not probe_info:
                continue
            svc_name, probe_bytes = probe_info
            banner = _banner_grab(ip, port_int, probe_bytes)
            if banner:
                versions = _parse_banner(banner)
                findings.append({
                    "host": hostname, "ip": ip, "port": port_int,
                    "service": svc_name, "banner": banner,
                    "versions": versions,
                    "title": f"{svc_name} banner on {hostname}:{port_int}",
                    "severity": "info",
                    "type": "service_version",
                })
                tested.add(ip)
    return {
        "findings": findings, "total": len(findings),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# GAP 14 Ã¢â‚¬â€ UDP Port Scanning
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

_UDP_SCAN_PORTS = (
    "53,67,68,69,111,123,137,138,161,162,500,514,520,1194,1701,"
    "1812,1813,1900,2049,4500,5060,5353,5683,11211"
)

_UDP_PORT_NAMES = {
    53: "DNS", 67: "DHCPv4-server", 68: "DHCPv4-client", 69: "TFTP",
    111: "RPC/portmapper", 123: "NTP", 137: "NetBIOS-ns", 138: "NetBIOS-dgm",
    161: "SNMP", 162: "SNMP-trap", 500: "IKE/IPsec", 514: "Syslog",
    520: "RIP", 1194: "OpenVPN", 1701: "L2TP", 1812: "RADIUS", 1813: "RADIUS-acct",
    1900: "UPnP/SSDP", 2049: "NFS", 4500: "IPsec-NAT-T", 5060: "SIP",
    5353: "mDNS", 5683: "CoAP", 11211: "Memcached",
}


def run_udp_port_scan(hosts: list) -> dict:
    """Scan top UDP ports using nmap -sU (fast). Falls back to unicornscan if present."""
    unique_ips = sorted(set(
        h.get("ip", "") for h in (hosts or [])
        if isinstance(h, dict) and h.get("ip")
    ))
    if not unique_ips:
        return {"error": "no IPs to scan", "findings": [], "total": 0}

    # Check for nmap (preferred, has UDP support)
    has_nmap = subprocess.run(
        ["which", "nmap"], capture_output=True, text=True
    ).returncode == 0

    results = []
    tool_used = "none"

    if has_nmap:
        try:
            import tempfile
            ip_list = "\n".join(unique_ips[:20])
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write(ip_list)
                hosts_file = tf.name
            try:
                proc = _subp(
                    ["nmap", "-sU", "-iL", hosts_file, "-p", _UDP_SCAN_PORTS,
                     "--open", "-T4", "--host-timeout", "60s", "-oG", "-"],
                    capture_output=True, text=True, timeout=300,
                )
                tool_used = "nmap"
                current_ip = ""
                for line in proc.stdout.splitlines():
                    if line.startswith("Host:") and "Ports:" in line:
                        parts = line.split()
                        current_ip = parts[1] if len(parts) > 1 else ""
                        port_section = line.split("Ports:")[1].strip()
                        for entry in port_section.split(","):
                            entry = entry.strip()
                            if "open" not in entry:
                                continue
                            try:
                                port = int(entry.split("/")[0])
                                svc = _UDP_PORT_NAMES.get(port, "")
                                sev = "critical" if port in (161, 111, 2049, 500, 4500) else \
                                      "high" if svc else "info"
                                results.append({
                                    "ip": current_ip, "port": port,
                                    "service": svc, "severity": sev,
                                    "type": "udp_port",
                                })
                            except Exception:
                                pass
            finally:
                os.unlink(hosts_file)
        except Exception as e:
            return {"error": f"nmap UDP failed: {e}", "findings": [], "total": 0}

    # Fallback: lightweight UDP ping per port using raw socket
    if not has_nmap:
        tool_used = "raw-socket"
        for ip in unique_ips[:10]:
            for port in sorted(_UDP_PORT_NAMES.keys()):
                try:
                    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
                    s = socket.socket(family, socket.SOCK_DGRAM)
                    s.settimeout(1.0)
                    s.sendto(b"\x00", (ip, port))
                    try:
                        data, addr = s.recvfrom(64)
                        svc = _UDP_PORT_NAMES.get(port, "")
                        results.append({
                            "ip": ip, "port": port, "service": svc or "udp",
                            "severity": "high" if svc else "info",
                            "type": "udp_port",
                        })
                    except socket.timeout:
                        pass
                    s.close()
                except Exception:
                    continue

    high_risk = [r for r in results if r["severity"] in ("critical", "high")]
    return {
        "tool": tool_used,
        "ips_scanned": len(unique_ips[:20]) if has_nmap else len(unique_ips[:10]),
        "results": results,
        "high_risk": high_risk,
        "total": len(results),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# GAP 15 Ã¢â‚¬â€ API Discovery (kiterunner-based, with fallback to swagger/openapi probes)
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

_API_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api/swagger.json", "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/openapi.json", "/api/openapi.json", "/api-docs", "/api-docs.json",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api-spec.json", "/api/spec", "/api/schema",
    "/redoc", "/reference", "/docs/api", "/api/docs",
    "/.well-known/ai-plugin.json",
]


def _probe_swagger_endpoint(host: str, path: str, timeout: int = 5) -> dict | None:
    for scheme in ("https://", "http://"):
        url = f"{scheme}{host}{path}"
        try:
            sc, raw, _ = http_get(url, timeout=timeout, retries=0)
            if sc == 200:
                try:
                    data = json.loads(raw.decode("utf-8", "ignore"))
                    if isinstance(data, dict):
                        swagger_ver = data.get("swagger", data.get("openapi", ""))
                        title = data.get("info", {}).get("title", "")
                        endpoints_count = len(data.get("paths", {}))
                        return {
                            "url": url, "swagger_version": swagger_ver,
                            "title": title, "endpoints_count": endpoints_count,
                            "severity": "medium",
                        }
                except Exception:
                    if b"swagger" in (raw or b"")[:200].lower() or b"openapi" in (raw or b"")[:200].lower():
                        return {"url": url, "swagger_version": "detected", "title": "",
                                "endpoints_count": 0, "severity": "low"}
        except Exception:
            continue
    return None


def _run_kiterunner_on_hosts(hosts: list, workers: int = 5) -> list:
    """Run kiterunner if installed; fall back to swagger/openapi probes."""
    import shutil as _shutil
    has_kr = _shutil.which("kiterunner") is not None

    findings = []
    if has_kr:
        import tempfile
        target_hosts = []
        for h in hosts[:30]:
            host = h.get("host", h.get("ip", ""))
            if host:
                target_hosts.append(host)
        if target_hosts:
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                    tf.write("\n".join(target_hosts))
                    target_file = tf.name
                try:
                    proc = _subp(
                        ["kiterunner", "scan", "-f", target_file,
                         "-x", "10", "-j", "--fail-status-codes", "400-499"],
                        capture_output=True, text=True, timeout=300,
                    )
                    for line in proc.stdout.strip().splitlines():
                        try:
                            item = json.loads(line)
                            findings.append({
                                "type": "kiterunner",
                                "host": item.get("host", ""),
                                "method": item.get("method", ""),
                                "path": item.get("url", item.get("path", "")),
                                "status": item.get("status_code", 0),
                                "length": item.get("content_length", 0),
                                "severity": "info",
                                "source": "kiterunner",
                            })
                        except Exception:
                            pass
                finally:
                    os.unlink(target_file)
            except Exception:
                pass

    # Always also run swagger/openapi probes (lightweight)
    seen_hosts = set()
    for h in hosts[:50]:
        host = h.get("host", h.get("ip", ""))
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        for path in _API_PATHS:
            result = _probe_swagger_endpoint(host, path, timeout=4)
            if result:
                findings.append({
                    "type": "swagger_endpoint",
                    "host": host, "path": path,
                    "url": result["url"],
                    "swagger_version": result.get("swagger_version", ""),
                    "title": result.get("title", ""),
                    "endpoints_count": result.get("endpoints_count", 0),
                    "severity": result.get("severity", "low"),
                    "source": "swagger_probe",
                })
                break  # found one spec per host is enough

    return findings


def run_api_discovery_extra(hosts: list, domains: list) -> dict:
    findings = _run_kiterunner_on_hosts(hosts)
    return {
        "findings": findings,
        "total": len(findings),
        "hosts_probed": len(set(h.get("host", "") for h in hosts[:50] if h.get("host"))),
        "sources_used": ["swagger_probe"] + (["kiterunner"] if has_kr else []),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# GAP 16 Ã¢â‚¬â€ Screenshot Visual Diffing Between Historical Versions
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

def _image_similarity(path_a: str, path_b: str) -> float | None:
    """Compare two images using pixel hashing. Returns similarity 0.0-1.0 or None."""
    try:
        from PIL import Image
        import hashlib
        a = Image.open(path_a).convert("L").resize((64, 64))
        b = Image.open(path_b).convert("L").resize((64, 64))
        # dHash: compare adjacent pixel columns
        def _dhash(img):
            pixels = list(img.getdata())
            diff = 0
            for row in range(64):
                for col in range(63):
                    idx = row * 64 + col
                    if pixels[idx] < pixels[idx + 1]:
                        diff |= (1 << (row * 64 + col))
            return diff
        h1 = _dhash(a)
        h2 = _dhash(b)
        # Hamming distance
        xor = h1 ^ h2
        dist = xor.bit_count() if hasattr(int, "bit_count") else bin(xor).count("1")
        return 1.0 - (dist / (64 * 63))
    except Exception:
        return None


def run_screenshot_diff(hosts: list, output_dir: str,
                         previous_dir: str | None = None) -> dict:
    """Compare current screenshots against previous run. Detects visual changes."""
    findings = []
    checks = 0
    now = datetime.now().isoformat(timespec="seconds")

    if not previous_dir or not os.path.isdir(previous_dir):
        return {
            "findings": [], "total": 0,
            "note": "no previous screenshot directory for comparison",
            "scanned_at": now,
        }

    if not os.path.isdir(output_dir):
        return {
            "findings": [], "total": 0,
            "note": "current screenshot directory not found",
            "scanned_at": now,
        }

    try:
        current_files = {f for f in os.listdir(output_dir) if f.endswith(".png")}
        previous_files = {f for f in os.listdir(previous_dir) if f.endswith(".png")}
    except Exception:
        return {"findings": [], "total": 0, "error": "cannot list screenshot dirs", "scanned_at": now}

    for fname in current_files:
        if fname not in previous_files:
            findings.append({
                "type": "screenshot_diff",
                "host": re.sub(r"https?_?|_?\.png", "", fname).replace("_", ".")[:120],
                "change": "new_host",
                "detail": "new screenshot Ã¢â‚¬â€ host not in previous run",
                "severity": "info",
                "file": fname,
            })
            continue

        curr_path = os.path.join(output_dir, fname)
        prev_path = os.path.join(previous_dir, fname)
        checks += 1
        similarity = _image_similarity(curr_path, prev_path)
        if similarity is not None and similarity < 0.85:
            pct = round((1 - similarity) * 100, 1)
            findings.append({
                "type": "screenshot_diff",
                "host": re.sub(r"https?_?|_?\.png", "", fname).replace("_", ".")[:120],
                "change": f"visual_change_{pct}pct",
                "detail": f"page changed {pct}% visually since last scan",
                "severity": "medium" if similarity < 0.60 else "low",
                "file": fname,
                "similarity": round(similarity, 3),
            })

    # Also detect hosts that disappeared since last run
    for fname in previous_files - current_files:
        findings.append({
            "type": "screenshot_diff",
            "host": re.sub(r"https?_?|_?\.png", "", fname).replace("_", ".")[:120],
            "change": "host_gone",
            "detail": "host had screenshot previously but not in current run",
            "severity": "info",
            "file": fname,
        })

    return {
        "findings": findings,
        "total": len(findings),
        "comparisons_done": checks,
        "current_screenshots": len(current_files),
        "previous_screenshots": len(previous_files),
        "scanned_at": now,
    }


# â”€â”€ NEW MODULES: gitleaks, jwt_tool, S3Scanner, XSS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def run_git_leaks(hosts: list, domains: list, github_token: str = None) -> dict:
    """Scan exposed .git directories and git history for secrets using gitleaks."""
    findings = []
    scanned = 0
    gitleaks_bin = shutil.which("gitleaks")

    for h in hosts[:50]:  # cap at 50 hosts
        host = h.get("host", "")
        if not host:
            continue
        for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{host}/.git/HEAD"
                status, body, _ = http_get(url, timeout=5, retries=1)
                if status == 200 and "ref:" in (body or ""):
                    # Clone and scan
                    import tempfile
                    with tempfile.TemporaryDirectory() as tmp:
                        clone_url = f"{scheme}://{host}/.git"
                        result = subprocess.run(
                            ["git", "clone", "--depth", "1", clone_url, tmp],
                            capture_output=True, text=True, timeout=60
                        )
                        if result.returncode == 0 and gitleaks_bin:
                            scan = subprocess.run(
                                [gitleaks_bin, "detect", "--source", tmp, "-f", "json", "--no-git"],
                                capture_output=True, text=True, timeout=60
                            )
                            if scan.stdout.strip():
                                try:
                                    leaks = json.loads(scan.stdout)
                                    for leak in (leaks if isinstance(leaks, list) else []):
                                        findings.append({
                                            "type": "git_leak",
                                            "severity": "high",
                                            "title": f"Git secret exposed: {leak.get('Description','')}",
                                            "host": host,
                                            "value": leak.get("Secret", ""),
                                            "file": leak.get("File", ""),
                                            "module": "git_leaks",
                                        })
                                except json.JSONDecodeError:
                                    pass
                            scanned += 1
                    break  # one scheme per host
            except Exception:
                continue

    return {
        "findings": findings,
        "total": len(findings),
        "hosts_scanned": scanned,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


def run_s3_scanner(domains: list, company_name: str = "") -> dict:
    """Check for open S3 buckets using common naming patterns."""
    findings = []
    scanned = 0
    s3_bin = shutil.which("S3Scanner") or shutil.which("s3scanner")
    names = set()
    for d in domains:
        base = d.split(".")[0]
        names.update([base, f"{base}-prod", f"{base}-dev", f"{base}-staging", f"{base}-static",
                       f"{base}-assets", f"{base}-media", f"{base}-backup", f"{base}-logs"])
    if company_name:
        slug = re.sub(r"[^a-z0-9]", "", company_name.lower())[:20]
        names.update([slug, f"{slug}-prod", f"{slug}-dev"])

    if s3_bin:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(names))
            tf_path = tf.name
        try:
            result = subprocess.run(
                [s3_bin, "-b", "-f", tf_path] if "S3Scanner" in str(s3_bin) else [s3_bin] + list(names),
                capture_output=True, text=True, timeout=120
            )
            for line in result.stdout.strip().splitlines():
                if "OPEN" in line.upper() or "200" in line:
                    parts = line.strip().split()
                    bucket = parts[0] if parts else line.strip()
                    findings.append({
                        "type": "open_s3_bucket",
                        "severity": "high",
                        "title": f"Open S3 bucket: {bucket}",
                        "value": bucket,
                        "module": "s3_scanner",
                        "category": "cloud",
                    })
                scanned += 1
        except Exception:
            pass
        finally:
            Path(tf_path).unlink(missing_ok=True)
    else:
        # Fallback: HTTP checks
        for name in list(names)[:20]:
            try:
                url = f"http://{name}.s3.amazonaws.com"
                status, _, _ = http_get(url, timeout=5, retries=1)
                if status == 200:
                    findings.append({
                        "type": "open_s3_bucket",
                        "severity": "high",
                        "title": f"Open S3 bucket: {name}",
                        "value": name,
                        "module": "s3_scanner",
                    })
                scanned += 1
            except Exception:
                pass

    return {
        "findings": findings,
        "total": len(findings),
        "hosts_scanned": scanned,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


# â”€â”€ SALESFORCE RECON â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_SALESFORCE_PATTERNS = [
    r"\.my\.salesforce\.com$",
    r"\.my\.salesforce-setup\.com$",
    r"\.force\.com$",
    r"\.salesforce\.com$",
    r"\.cloudforce\.com$",
    r"\.database\.com$",
    r"\.site\.com$",  # force.com sites
]

_SALESFORCE_COMMUNITY_CHECKS = [
    "/s/",                                  # Community URL base
    "/services/apexrest/",                  # REST API exposed
    "/services/data/v",                     # REST API version endpoint
    "/s/global-search/%40uri?query=",       # Guest search (misconfig)
    "/sfsites/aura",                        # Aura framework
    "/webruntime",                          # LWR framework
    "/_nc_external/identity/session/",      # Session endpoint
    "/idp/endpoint/HttpPost",               # SAML endpoint
    "/.well-known/org-issuer-id",           # Org issuer
    "/s/sfsites/aura?r=",                   # Aura guest access
]

_SALESFORCE_ADMIN_CHECKS = [
    "/_ui/common/apex/debug/ApexCSIPage",   # Debug console
    "/soap/",                                # SOAP API info
    "/p/setup/custent/CustomizePage",       # Setup page (should be auth-walled)
    "/secur/logout.jsp",                    # Logout redirect vuln
    "/_ui/identity/verification/method",    # MFA verification page
    "/setup/forcecomHomepage.apexp",        # Setup homepage
    "/ui/setup/Setup",                      # Classic setup
    "/c/",                                  # Custom domain community
]


def _is_salesforce_host(host: str) -> bool:
    for pattern in _SALESFORCE_PATTERNS:
        if re.search(pattern, host, re.IGNORECASE):
            return True
    return False


def run_salesforce_recon(hosts: list, domains: list = None) -> dict:
    """Detect and scan Salesforce instances for common misconfigurations.

    Two-phase approach:
      1. DISCOVERY: probe subdomain patterns + check CNAME/DNS for SF redirects
      2. ANALYSIS: check Community guest access, exposed Aura/LWR, debug mode,
         CORS, API version disclosure, open redirect vectors, and more.

    Returns dict with keys: findings, total, salesforce_hosts, discovered, hosts_scanned, scanned_at
    """
    findings = []
    scanned = 0
    discovered = 0

    # â”€â”€ Phase 1: DISCOVERY â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    sf_hosts = [h for h in hosts if _is_salesforce_host(h.get("host", ""))]

    # Probe common Salesforce subdomain patterns for each target domain
    if domains:
        for domain in domains[:20]:
            base = domain.split(".")[0]
            sf_subdomain_patterns = [
                f"{base}.my.salesforce.com",
                f"{base}.force.com",
                f"{base}.cloudforce.com",
                f"{base}.salesforce.com",
                f"{base}-community.force.com",
                f"{base}-uat.my.salesforce.com",
                f"{base}-dev.my.salesforce.com",
                f"{base}-staging.my.salesforce.com",
                f"cs-{base}.force.com",
                f"c.{base}.force.com",
                f"{base}.secure.force.com",
                f"login.{base}.force.com",
                f"www.{base}.my.salesforce.com",
            ]
            for probe_host in sf_subdomain_patterns[:8]:  # limit per domain
                if any(h.get("host") == probe_host for h in sf_hosts):
                    continue  # already known
                try:
                    status, body, _ = http_get(f"https://{probe_host}", timeout=5, retries=0)
                    if status and status < 500:
                        sf_hosts.append({"host": probe_host, "status_code": status, "ip": "", "ports": []})
                        discovered += 1
                        findings.append({
                            "type": "salesforce_discovered",
                            "severity": "info",
                            "title": f"Salesforce instance discovered: {probe_host}",
                            "host": probe_host,
                            "module": "salesforce_recon",
                        })
                except Exception:
                    pass

    # Also check non-SF hosts for DNS CNAME / HTTP redirect to Salesforce
    if not sf_hosts or len(sf_hosts) < 10:
        for h in hosts[:100]:
            host = h.get("host", "")
            if not host or _is_salesforce_host(host):
                continue
            try:
                # DNS CNAME check
                try:
                    answers = dns.resolver.resolve(host, "CNAME")
                    for rdata in answers:
                        target = str(rdata.target).rstrip(".")
                        if _is_salesforce_host(target):
                            sf_hosts.append(h)
                            discovered += 1
                            findings.append({
                                "type": "salesforce_cname",
                                "severity": "medium",
                                "title": f"DNS CNAME to Salesforce: {host} -> {target}",
                                "host": host,
                                "value": target,
                                "module": "salesforce_recon",
                            })
                            break
                except Exception:
                    pass

                # HTTP redirect check
                status, body, headers = http_get(f"https://{host}", timeout=5, retries=0)
                if status in (301, 302) and headers:
                    location = str(headers.get("Location", ""))
                    if _is_salesforce_host(location):
                        sf_hosts.append(h)
                        discovered += 1
                        findings.append({
                            "type": "salesforce_redirect",
                            "severity": "low",
                            "title": f"HTTP redirect to Salesforce: {host} -> {location}",
                            "host": host,
                            "value": location,
                            "module": "salesforce_recon",
                        })
            except Exception:
                pass

    sf_hosts = sf_hosts[:30]  # cap

    # â”€â”€ Phase 2: ANALYSIS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    for h in sf_hosts:
        host = h.get("host", "")
        scheme = "https"

        # 1. Fingerprint the org: get instance info
        try:
            status, body, headers = http_get(f"{scheme}://{host}", timeout=8, retries=1)
            if status:
                scanned += 1
                sf_content = (body or "")[:2000]

                # Detect Salesforce version/flavor
                if "Salesforce" in sf_content or "sfdc" in sf_content.lower():
                    findings.append({
                        "type": "salesforce_detected",
                        "severity": "info",
                        "title": f"Salesforce instance: {host}",
                        "host": host,
                        "module": "salesforce_recon",
                    })
        except Exception:
            pass

        # 2. Community guest user checks
        for check_path in _SALESFORCE_COMMUNITY_CHECKS[:6]:  # most important checks
            try:
                url = f"{scheme}://{host}{check_path}"
                status, body, headers = http_get(url, timeout=6, retries=0)

                if check_path == "/services/data/v" and status == 200:
                    # API version disclosure
                    findings.append({
                        "type": "salesforce_api_exposed",
                        "severity": "medium",
                        "title": f"Salesforce REST API version exposed: {host}/services/data/v",
                        "host": host,
                        "url": url,
                        "module": "salesforce_recon",
                    })

                elif check_path.startswith("/s/global-search") and status == 200:
                    findings.append({
                        "type": "salesforce_guest_search",
                        "severity": "high",
                        "title": f"Salesforce Community guest search enabled: {host}",
                        "host": host,
                        "url": url,
                        "module": "salesforce_recon",
                    })

                elif check_path == "/sfsites/aura" and status in (200, 302):
                    findings.append({
                        "type": "salesforce_aura_exposed",
                        "severity": "medium",
                        "title": f"Salesforce Aura framework exposed (check for guest-accessible components): {host}",
                        "host": host,
                        "url": url,
                        "module": "salesforce_recon",
                    })

                elif check_path.startswith("/services/apexrest/") and status in (200, 401, 403, 405):
                    if status in (200, 405):  # 405 = endpoint exists but method wrong = exposed
                        findings.append({
                            "type": "salesforce_apex_rest",
                            "severity": "high",
                            "title": f"Salesforce Apex REST endpoint accessible: {host}/services/apexrest/",
                            "host": host,
                            "url": url,
                            "module": "salesforce_recon",
                        })

            except Exception:
                pass

        # 3. Admin/debug page checks
        for check_path in _SALESFORCE_ADMIN_CHECKS[:5]:
            try:
                url = f"{scheme}://{host}{check_path}"
                status, body, _ = http_get(url, timeout=5, retries=0)

                if check_path == "/_ui/common/apex/debug/ApexCSIPage" and status == 200:
                    findings.append({
                        "type": "salesforce_debug_console",
                        "severity": "high",
                        "title": f"Salesforce Debug Console exposed: {host}",
                        "host": host,
                        "url": url,
                        "module": "salesforce_recon",
                    })

                elif "/secur/logout.jsp" in check_path and status == 200:
                    findings.append({
                        "type": "salesforce_logout_open_redirect",
                        "severity": "medium",
                        "title": f"Salesforce logout page â€” potential open redirect via retURL parameter: {host}",
                        "host": host,
                        "url": url,
                        "module": "salesforce_recon",
                    })

                elif "/setup/" in check_path and status in (200, 302):
                    findings.append({
                        "type": "salesforce_setup_exposed",
                        "severity": "high",
                        "title": f"Salesforce Setup page accessible (should be auth-walled): {host}{check_path}",
                        "host": host,
                        "url": url,
                        "module": "salesforce_recon",
                    })

            except Exception:
                pass

        # 4. CORS check
        try:
            status, body, headers = http_get(f"{scheme}://{host}", timeout=5, retries=0,
                                             extra_headers={"Origin": "https://evil.com"})
            acao = (headers or {}).get("Access-Control-Allow-Origin", "")
            if acao == "*" or acao == "https://evil.com":
                findings.append({
                    "type": "salesforce_cors_misconfig",
                    "severity": "medium",
                    "title": f"Salesforce CORS misconfiguration: reflects Origin ({acao})",
                    "host": host,
                    "module": "salesforce_recon",
                })
        except Exception:
            pass

    return {
        "findings": findings,
        "total": len(findings),
        "salesforce_hosts": len(sf_hosts),
        "discovered": discovered,
        "hosts_scanned": scanned,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


def run_jwt_analysis(hosts: list, js_files: list = None) -> dict:
    """Analyze JWT tokens found in JS files for weaknesses using jwt_tool."""
    findings = []
    jwt_bin = shutil.which("jwt_tool")
    tokens = set()

    # Extract JWTs from JS files
    if js_files:
        for jf in js_files[:30]:
            try:
                content = jf.get("content", "") or ""
                if not content and jf.get("url"):
                    status, body, _ = http_get(jf["url"], timeout=8, retries=1)
                    if status == 200:
                        content = body or ""
                # Find JWT patterns
                for match in re.finditer(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", content):
                    tokens.add(match.group(0))
            except Exception:
                pass

    # Analyze each token
    for token in list(tokens)[:10]:
        try:
            # Decode header without verification
            parts = token.split(".")
            if len(parts) >= 2:
                header = base64.urlsafe_b64decode(parts[0] + "==").decode()
                payload_data = base64.urlsafe_b64decode(parts[1] + "==").decode()
                header_json = json.loads(header)
                payload_json = json.loads(payload_data)
                alg = header_json.get("alg", "none")
                if alg.lower() == "none":
                    findings.append({
                        "type": "jwt_none_alg",
                        "severity": "critical",
                        "title": f"JWT with 'none' algorithm â€” bypass authentication",
                        "value": token[:60] + "...",
                        "module": "jwt_analysis",
                    })
                elif alg.lower().startswith("hs"):
                    findings.append({
                        "type": "jwt_hs_weak",
                        "severity": "medium",
                        "title": f"JWT uses HMAC-SHA â€” potential key brute-force",
                        "value": token[:60] + "...",
                        "metadata": {"alg": alg, "kid": header_json.get("kid", "")},
                        "module": "jwt_analysis",
                    })
                else:
                    findings.append({
                        "type": "jwt_info",
                        "severity": "low",
                        "title": f"JWT found: {payload_json.get('sub','?')} ({alg})",
                        "value": token[:60] + "...",
                        "module": "jwt_analysis",
                    })
        except Exception:
            pass

    return {
        "findings": findings,
        "total": len(findings),
        "tokens_found": len(tokens),
        "tokens_analyzed": len(tokens),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }


def run_xss_scan(hosts: list, mode: str = "balanced") -> dict:
    """Scan live web hosts for XSS vulnerabilities using dalfox and XSStrike."""
    findings = []
    scanned = 0
    dalfox_bin = shutil.which("dalfox")
    xsstrike_bin = shutil.which("xsstrike")

    live = [h for h in hosts if _is_responsive(h)][:25]  # cap at 25 hosts

    # Quick dalfox scan on each live host
    if dalfox_bin:
        for h in live[:15]:
            host = h.get("host", "")
            url = f"https://{host}" if h.get("status_code") == 200 else f"http://{host}"
            try:
                result = subprocess.run(
                    [dalfox_bin, "url", url, "--silence", "--skip-mining-all",
                     "--timeout", "5", "--delay", "100", "--waf-evasion",
                     "--worker", "3", "--format", "json"],
                    capture_output=True, text=True, timeout=120
                )
                if result.stdout.strip():
                    try:
                        data = json.loads(result.stdout)
                        for item in (data if isinstance(data, list) else [data]):
                            findings.append({
                                "type": "xss_reflected",
                                "severity": item.get("severity", "medium"),
                                "title": f"XSS: {item.get('param','?')} @ {host}",
                                "host": host,
                                "value": item.get("payload", ""),
                                "url": item.get("url", url),
                                "tool": "dalfox",
                                "module": "xss_scan",
                            })
                    except json.JSONDecodeError:
                        pass
                scanned += 1
            except Exception:
                pass

    # Quick XSStrike on a few hosts
    if xsstrike_bin and scanned < len(live):
        for h in live[scanned:scanned + 5]:
            host = h.get("host", "")
            url = f"https://{host}" if h.get("status_code") == 200 else f"http://{host}"
            try:
                result = subprocess.run(
                    [xsstrike_bin, "-u", url, "--crawl", "-l", "1", "--skip",
                     "--console-log-level", "vuln", "--threads", "3"],
                    capture_output=True, text=True, timeout=120
                )
                for line in result.stdout.strip().splitlines():
                    if "VULNERABLE" in line.upper() or "XSS" in line.upper():
                        findings.append({
                            "type": "xss",
                            "severity": "high",
                            "title": f"XSStrike: {line.strip()[:120]}",
                            "host": host,
                            "tool": "xsstrike",
                            "module": "xss_scan",
                        })
                scanned += 1
            except Exception:
                pass

    return {
        "findings": findings,
        "total": len(findings),
        "hosts_scanned": scanned,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }
