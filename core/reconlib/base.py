"""HTTP infrastructure — rate limiting, UA rotation, retry/backoff — extraído de core/recon.py (ver core/recon.py para o índice completo)."""

import subprocess as _subprocess_real
import logging as _logging
_log = _logging.getLogger('scantrely.recon')
import socket, ssl, json, re, time, sys, os
import shutil, tempfile, base64
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
            _log.debug('recon.py:65 erro ignorado', exc_info=True)
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
                        _log.debug('recon.py:125 erro ignorado', exc_info=True)


subprocess = _GatedSubprocess()


def _subp(cmd, **kw):
    _ct.trace(cmd)
    _rl.wait()
    return subprocess.run(cmd, **kw)


from urllib.request import urlopen, Request
from urllib.error   import URLError, HTTPError
from datetime       import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as _FutTimeout
from pathlib import Path

# Abaixo dos 180s do módulo no pipeline: estourar lá descarta o resultado inteiro.
MODULE_BUDGET_S = 150.0


def run_bounded(fn, items, *, workers: int = 8, budget: float = MODULE_BUDGET_S, label: str = "") -> bool:
    """Roda fn(item) em paralelo até o prazo. fn grava nos acumuladores do chamador.

    Devolve False se o prazo acabou antes (o chamador fica com o parcial). Itens ainda na fila
    são cancelados; os que já estão em andamento terminam sozinhos, então o chamador deve
    devolver cópias dos acumuladores."""
    items = list(items)
    if not items:
        return True
    ex = ThreadPoolExecutor(max_workers=max(1, min(workers, len(items))), thread_name_prefix=f"rb-{label[:10]}")
    futures = [ex.submit(fn, it) for it in items]
    try:
        for fut in as_completed(futures, timeout=budget):
            try:
                fut.result()
            except Exception:
                _log.debug("run_bounded %s: item falhou", label, exc_info=True)
        return True
    except _FutTimeout:
        done = sum(1 for f in futures if f.done())
        _log.info("run_bounded %s: prazo de %.0fs esgotado — %s de %s itens concluídos", label, budget, done, len(items))
        return False
    finally:
        ex.shutdown(wait=False, cancel_futures=True)

# ── HTTP infrastructure — rate limiting, UA rotation, retry/backoff ──

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
_RATE_JITTER = 0.3   # ± random jitter

# curl_cffi — TLS fingerprint mimicry (optional)
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
    - Retry with exponential backoff on 429/5xx (retries=0 still does one try)
    - Circuit breaker per host (fail-fast when the dependency is open)
    - WAF block detection and domain-level backoff
    - curl_cffi TLS fingerprint when available (impersonates real browser JA3)
    Returns (status_code, body_bytes, response_headers).
    """
    from urllib.parse import urlparse
    from utils.circuit_breaker import breaker_for
    domain = urlparse(url).netloc.split(":")[0]
    headers = _make_headers(extra_headers)
    last_exc = None
    br = breaker_for(domain or "http")
    attempts = max(1, int(retries or 1))

    for attempt in range(attempts):
        if not br.allow():
            return 0, b"", {"X-Circuit-Breaker": "open"}
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
                br.failure()
                wait = 2 ** attempt + random.uniform(0, 1)
                time.sleep(wait)
                continue

            if _is_block_response(status, body_preview):
                br.failure()
                _record_block(domain, status)
                wait = 2 ** attempt + random.uniform(0, 1)
                time.sleep(wait)
                headers = _make_headers(extra_headers)  # rotate UA on retry
                continue

            br.success()
            _record_success(domain)
            _rl.signal(status)
            # Auto-decompress gzip (curl_cffi doesn't always do this with custom headers)
            enc = resp_h.get("Content-Encoding", resp_h.get("content-encoding", ""))
            if "gzip" in enc or (body[:2] == b"\x1f\x8b"):
                try:
                    body = gzip.decompress(body)
                except Exception:
                    _log.debug('recon.py:366 erro ignorado', exc_info=True)
            return status, body, resp_h

        except urllib.error.HTTPError as e:
            status = e.code
            body   = b""
            resp_h = dict(e.headers) if e.headers else {}
            if status == 429:
                br.failure()
                _record_block(domain, status)
                wait = 2 ** attempt + random.uniform(0, 2)
                time.sleep(wait)
                continue
            if status in (502, 503):
                br.failure()
                wait = 2 ** attempt + random.uniform(0, 1)
                time.sleep(wait)
                continue
            if status >= 500:
                br.failure()
            else:
                br.success()
            return status, body, resp_h
        except Exception as exc:
            br.failure()
            last_exc = exc
            wait = 2 ** attempt + random.uniform(0, 1)
            time.sleep(wait)

    return 0, b"", {}


def _http_get_json(url: str, timeout: int = 15, extra_headers: dict | None = None,
                   retries: int = 0):
    """GET JSON through ``http_get`` (timeout + per-host circuit breaker)."""
    status, body, _hdrs = http_get(
        url, timeout=timeout, retries=retries, extra_headers=extra_headers,
    )
    if status not in (200, 201) or not body:
        return None
    try:
        return json.loads(body)
    except Exception:
        return None


# Legacy alias kept for backward compat — modules call UA directly
UA = _random_ua()
