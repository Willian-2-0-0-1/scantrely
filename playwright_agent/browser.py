from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json
import time
from urllib.parse import urlparse

from .file_utils import ensure_dir
from .masking import mask_headers, mask_text
from .models import ConsoleEvent, Endpoint


def _lazy_playwright():
    # Prefer the project's dedicated venv: the Kali *system* playwright package
    # imports fine but its driver is broken at runtime ("Connection closed while
    # reading from the driver"). Same path/strategy as core/recon.py:_pw_import.
    import sys
    import os

    venv_lib = Path(os.environ.get("ASM_PLAYWRIGHT_HOME", "/home/kali/.asm-playwright")) / "lib"
    site_pkg = next(venv_lib.glob("python3.*/site-packages"), None) if venv_lib.exists() else None
    if site_pkg and str(site_pkg) not in sys.path:
        sys.path.insert(0, str(site_pkg))
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    except Exception as exc:  # pragma: no cover - import path only
        raise RuntimeError(
            "Playwright is not installed. Run: bash install_tools.sh  OR  "
            "pip install playwright && playwright install chromium && "
            "sudo apt install libnss3 libnspr4 libatk-bridge2.0-0 libatk1.0-0 "
            "libcups2 libdrm2 libdbus-1-3 libxkbcommon0 libgbm1 libasound2"
        ) from exc

    # ── VPS dependency check (fast, runs once on first import) ──
    _MISSING_VPS_LIBS = [
        ("libnss3.so",        "libnss3"),
        ("libatk-bridge-2.0.so.0", "libatk-bridge2.0-0"),
        ("libatk-1.0.so.0",   "libatk1.0-0"),
        ("libcups.so.2",      "libcups2"),
        ("libdrm.so.2",       "libdrm2"),
        ("libdbus-1.so.3",    "libdbus-1-3"),
        ("libxkbcommon.so.0", "libxkbcommon0"),
        ("libgbm.so.1",       "libgbm1"),
        ("libasound.so.2",    "libasound2"),
    ]
    missing = []
    from ctypes import cdll as _cdll
    for soname, pkg in _MISSING_VPS_LIBS:
        try:
            _cdll.LoadLibrary(soname)  # fast — ctypes caches
        except OSError:
            missing.append(pkg)
    if missing:
        raise RuntimeError(
            f"Chromium VPS deps missing: {', '.join(missing)}. "
            f"Run: bash install_tools.sh  OR  "
            f"sudo apt install {' '.join(missing)}"
        )

    return sync_playwright, PlaywrightTimeoutError


_SLOW_HOST_HINTS = (
    "mail", "webmail", "webdisk", "autodiscover", "cpanel", "cpcontacts",
    "cpcalendars", "ftp", "status", "conference", "portal", "admin", "vpn",
)


def _host_key(url: str) -> str:
    try:
        parsed = urlparse(url if url.startswith(("http://", "https://")) else f"https://{url}")
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _looks_slow_host(url: str) -> bool:
    host = _host_key(url)
    path = (url or "").lower()
    return any(part in host for part in _SLOW_HOST_HINTS) or any(
        part in path for part in ("/login", "/signin", "/auth", "/admin", "/panel")
    )


def goto_resilient(
    page,
    url: str,
    *,
    base_timeout: int = 20,
    slow_timeout: int | None = None,
    wait_until: str = "domcontentloaded",
):
    """Navigate with fallback wait states and adaptive timeouts.

    Returns (response, error, used_timeout_ms, wait_until).
    """
    import time as _time
    host_slow = _looks_slow_host(url)
    timeout_sec = slow_timeout if host_slow and slow_timeout else base_timeout
    timeout_ms = max(int(timeout_sec * 1000), 15_000)
    sequence = []
    for candidate in (wait_until or "domcontentloaded", "domcontentloaded", "load", "commit"):
        if candidate not in sequence and candidate in {"domcontentloaded", "load", "commit"}:
            sequence.append(candidate)
    attempts = [
        (sequence[0], timeout_ms),
        (sequence[1] if len(sequence) > 1 else "load", max(timeout_ms, int(timeout_ms * 1.5))),
        (sequence[2] if len(sequence) > 2 else "commit", max(timeout_ms, int(timeout_ms * 2))),
    ]
    last_error = None
    for attempt_idx, (wait_until, current_timeout) in enumerate(attempts):
        try:
            # Rate-limit guard: delay between retries so we don't hammer a 429'ing server
            if attempt_idx > 0:
                delay = 3.0 * (attempt_idx + 1)  # 3s, 6s between retries
                _time.sleep(delay)
            response = page.goto(url, wait_until=wait_until, timeout=current_timeout)
            if response and response.status == 429:
                last_error = Exception("HTTP 429 — rate limited")
                retry_after = response.headers.get("retry-after", "")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else 10.0
                _time.sleep(delay)
                continue
            return response, None, current_timeout, wait_until
        except Exception as exc:
            last_error = exc
            message = str(exc).lower()
            if not any(token in message for token in ("timeout", "navigation", "net::")):
                break
    return None, str(last_error) if last_error else "navigation failed", attempts[-1][1], attempts[-1][0]


@dataclass
class BrowserRuntime:
    headless: bool = True
    user_agent: str = ""
    storage_state: str | None = None
    trace_dir: str | None = None
    slow_mo: int = 0
    timeout: int = 20
    network_events: list[Endpoint] = field(default_factory=list)
    console_events: list[ConsoleEvent] = field(default_factory=list)
    js_bodies: dict[str, str] = field(default_factory=dict)
    page_errors: list[ConsoleEvent] = field(default_factory=list)
    downloads: list[dict[str, Any]] = field(default_factory=list)
    spa_routes: set[str] = field(default_factory=set)
    agent_events: list[dict[str, Any]] = field(default_factory=list)
    dialogs: list[dict[str, Any]] = field(default_factory=list)
    ws_messages: list[dict[str, Any]] = field(default_factory=list)
    sink_hits: list[dict[str, Any]] = field(default_factory=list)
    msg_listeners: list[dict[str, Any]] = field(default_factory=list)
    sse_endpoints: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self._pw = None
        self.browser = None
        self.context = None
        self.page = None
        self.last_response = None
        self.last_navigation_error = None
        self._host_timeout_cache: dict[str, int] = {}
        self._trace_started = False

    def __enter__(self) -> "BrowserRuntime":
        sync_playwright, _ = _lazy_playwright()
        self._pw = sync_playwright().start()
        launch_args = [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-setuid-sandbox",
            "--ignore-certificate-errors",
            "--disable-blink-features=AutomationControlled",
        ]
        self.browser = self._pw.chromium.launch(
            headless=self.headless,
            args=launch_args,
            slow_mo=self.slow_mo or 0,
        )
        kwargs: dict[str, Any] = {}
        if self.user_agent:
            kwargs["user_agent"] = self.user_agent
        if self.storage_state:
            kwargs["storage_state"] = self.storage_state
        self.context = self.browser.new_context(**kwargs)
        if self.trace_dir:
            ensure_dir(self.trace_dir)
            self.context.tracing.start(screenshots=True, snapshots=True, sources=True)
            self._trace_started = True
        self.page = self.context.new_page()
        self.install_listeners(self.page)
        self.page.add_init_script(self._init_script())
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.context and self._trace_started and self.trace_dir:
                stamp = int(time.time())
                self.context.tracing.stop(path=str(Path(self.trace_dir) / f"trace-{stamp}.zip"))
        except Exception:
            pass
        for obj in (self.page, self.context, self.browser):
            try:
                if obj:
                    obj.close()
            except Exception:
                pass
        if self._pw:
            try:
                self._pw.stop()
            except Exception:
                pass

    def _init_script(self) -> str:
        return r"""
(() => {
  window.__pentestAgentEvents = window.__pentestAgentEvents || [];
  const push = (type, payload) => {
    try { window.__pentestAgentEvents.push({type, ts: Date.now(), ...payload}); } catch (e) {}
  };
  const origFetch = window.fetch;
  if (origFetch) {
    window.fetch = async function(...args) {
      const req = args[0];
      const init = args[1] || {};
      const url = typeof req === 'string' ? req : (req && req.url ? req.url : String(req));
      push('fetch', {url, method: (init.method || 'GET').toUpperCase()});
      return origFetch.apply(this, args);
    };
  }
  const OrigXHR = window.XMLHttpRequest;
  if (OrigXHR) {
    const open = OrigXHR.prototype.open;
    const send = OrigXHR.prototype.send;
    OrigXHR.prototype.open = function(method, url) {
      this.__pa = {method, url};
      return open.apply(this, arguments);
    };
    OrigXHR.prototype.send = function(body) {
      try { push('xhr', {url: this.__pa && this.__pa.url ? this.__pa.url : '', method: this.__pa && this.__pa.method ? this.__pa.method : 'GET'}); } catch (e) {}
      return send.apply(this, arguments);
    };
  }
  const wrapConsole = (name) => {
    const orig = console[name];
    if (!orig) return;
    console[name] = function(...args) {
      try { push('console', {level: name, message: args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' ')}); } catch (e) {}
      return orig.apply(this, args);
    };
  };
  ['log','info','warn','error','debug'].forEach(wrapConsole);
  window.addEventListener('error', (e) => push('error', {message: e.message || String(e.error || e)}));
  window.addEventListener('unhandledrejection', (e) => push('rejection', {message: String(e.reason || e)}));
  const origPush = history.pushState;
  const origReplace = history.replaceState;
  if (origPush) history.pushState = function(...args) {
    try { push('route', {url: String(location.href)}); } catch (e) {}
    return origPush.apply(this, args);
  };
  if (origReplace) history.replaceState = function(...args) {
    try { push('route', {url: String(location.href)}); } catch (e) {}
    return origReplace.apply(this, args);
  };
  // ── EventSource (SSE) ──
  const OrigES = window.EventSource;
  if (OrigES) {
    window.EventSource = function(url, cfg) { try { push('sse', {url: String(url)}); } catch(e){} return new OrigES(url, cfg); };
    window.EventSource.prototype = OrigES.prototype;
  }
  // ── postMessage listener mapping (origin-check audit) ──
  const origAdd = window.addEventListener;
  window.addEventListener = function(type, listener, opts) {
    try {
      if (type === 'message' && typeof listener === 'function') {
        let src = ''; try { src = listener.toString(); } catch(e) {}
        push('msg_listener', {hasOriginCheck: /\.origin\b/.test(src), sample: src.slice(0, 160)});
      }
    } catch(e) {}
    return origAdd.apply(this, arguments);
  };
  // ── DOM sink taint: record only when a sink receives URL-derived data (DOM XSS) ──
  const taintSrc = (val) => {
    try {
      val = String(val);
      const cands = [location.hash.slice(1), location.search.slice(1)];
      for (let src of cands) {
        if (!src || src.length < 6) continue;
        let dec = src; try { dec = decodeURIComponent(src); } catch(e) {}
        if (val.indexOf(dec) >= 0 || val.indexOf(src) >= 0) return src.slice(0, 80);
      }
    } catch(e) {}
    return null;
  };
  const sinkHit = (sink, val) => { const s = taintSrc(val); if (s !== null) push('sink', {sink, source: s, sample: String(val).slice(0, 120)}); };
  try {
    const desc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (desc && desc.set) {
      Object.defineProperty(Element.prototype, 'innerHTML', {
        set(v) { sinkHit('innerHTML', v); return desc.set.call(this, v); },
        get() { return desc.get.call(this); }, configurable: true,
      });
    }
  } catch(e) {}
  try { const ow = document.write; document.write = function(v){ sinkHit('document.write', v); return ow.apply(this, arguments); }; } catch(e) {}
  try { const oe = window.eval; window.eval = function(v){ sinkHit('eval', v); return oe.call(this, v); }; } catch(e) {}
})();
"""

    def install_listeners(self, page) -> None:
        def on_request(req):
            return

        def on_response(resp):
            try:
                req = resp.request
                ctype = (resp.headers.get("content-type") or "").lower()
                interesting = (
                    resp.status >= 400
                    or "html" in ctype
                    or "json" in ctype
                    or "xml" in ctype
                    or "javascript" in ctype
                    or any(marker in resp.url.lower() for marker in ("/api/", "/graphql", "/auth", "/oauth", "/admin", "/ws", "/socket.io"))
                )
                if interesting:
                    endpoint = Endpoint(
                        url=resp.url,
                        method=(req.method or "GET").upper(),
                        status=resp.status,
                        request_headers=mask_headers(dict(req.headers)),
                        response_headers=mask_headers(dict(resp.headers)),
                        parameters={"post_data": mask_text(req.post_data or "") if getattr(req, "post_data", None) else ""},
                        content_type=resp.headers.get("content-type", ""),
                        source_page=page.url,
                    )
                    self.network_events.append(endpoint)
                if "javascript" in ctype or resp.url.endswith(".js"):
                    try:
                        body = resp.body()
                        if body and len(body) <= 8 * 1024 * 1024:
                            text = body.decode("utf-8", errors="ignore")
                            self.js_bodies[resp.url] = text
                    except Exception:
                        pass
            except Exception:
                pass

        def on_failed(req):
            try:
                self.network_events.append(
                    Endpoint(
                        url=req.url,
                        method=(req.method or "GET").upper(),
                        status=None,
                        request_headers=mask_headers(dict(req.headers)),
                        parameters={"failure": getattr(req.failure, "error_text", "") if getattr(req, "failure", None) else ""},
                        source_page=page.url,
                        notes=["request_failed"],
                    )
                )
            except Exception:
                pass

        def on_console(msg):
            try:
                loc = msg.location or {}
                self.console_events.append(
                    ConsoleEvent(
                        page_url=page.url,
                        type=msg.type or "log",
                        message=mask_text(msg.text or ""),
                        source_file=loc.get("url"),
                        line=loc.get("lineNumber"),
                        column=loc.get("columnNumber"),
                    )
                )
            except Exception:
                pass

        def on_page_error(exc):
            try:
                self.page_errors.append(
                    ConsoleEvent(
                        page_url=page.url,
                        type="exception",
                        message=mask_text(str(exc)),
                        classification="security_relevant" if "csp" in str(exc).lower() else "recon_useful",
                    )
                )
            except Exception:
                pass

        def on_dialog(dialog):
            # Record the message (so XSS execution can be confirmed) then dismiss
            # — never accept/confirm, to avoid triggering app behavior.
            try:
                self.dialogs.append({
                    "type": dialog.type,
                    "message": dialog.message,
                    "page_url": page.url,
                    "ts": int(time.time()),
                })
            except Exception:
                pass
            try:
                dialog.dismiss()
            except Exception:
                pass

        def on_download(download):
            try:
                self.downloads.append(
                    {
                        "url": download.url,
                        "suggested_filename": download.suggested_filename,
                        "ts": int(time.time()),
                    }
                )
            except Exception:
                pass

        def on_websocket(ws):
            try:
                self.ws_messages.append({"url": ws.url, "dir": "open", "page_url": page.url})
                ws.on("framesent", lambda p: self.ws_messages.append(
                    {"url": ws.url, "dir": "sent", "payload": mask_text(str(p))[:300]}))
                ws.on("framereceived", lambda p: self.ws_messages.append(
                    {"url": ws.url, "dir": "recv", "payload": mask_text(str(p))[:300]}))
            except Exception:
                pass

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("requestfailed", on_failed)
        page.on("console", on_console)
        page.on("pageerror", on_page_error)
        page.on("dialog", on_dialog)
        page.on("download", on_download)
        page.on("websocket", on_websocket)

    def goto(self, url: str, wait_until: str = "domcontentloaded"):
        assert self.page is not None
        host = _host_key(url)
        cached_timeout = self._host_timeout_cache.get(host)
        response, error, used_timeout_ms, _ = goto_resilient(
            self.page,
            url,
            base_timeout=self.timeout,
            slow_timeout=max(self.timeout * 2, 30) if cached_timeout is None else max(cached_timeout // 1000, self.timeout),
            wait_until=wait_until,
        )
        self.last_response = response
        self.last_navigation_error = error
        if error and host:
            self._host_timeout_cache[host] = max(self._host_timeout_cache.get(host, 0), used_timeout_ms)
        return self.last_response

    def harvest_agent_events(self) -> list[dict[str, Any]]:
        """Drain the in-page instrumentation buffer (window.__pentestAgentEvents).

        Recovers signals the Playwright-level listeners miss: SPA route changes
        (history.pushState/replaceState) and in-page fetch/XHR call sites. Returns
        the drained events and folds them into spa_routes / network_events.
        """
        if not self.page:
            return []
        try:
            events = self.page.evaluate(
                "() => { const e = window.__pentestAgentEvents || [];"
                " window.__pentestAgentEvents = []; return e; }"
            ) or []
        except Exception:
            return []
        for ev in events:
            etype = ev.get("type")
            url = ev.get("url")
            if etype == "route" and url:
                self.spa_routes.add(url)
            elif etype in ("fetch", "xhr") and url:
                self.network_events.append(
                    Endpoint(
                        url=url,
                        method=(ev.get("method") or "GET").upper(),
                        source_page=self.page.url,
                        notes=[f"in_page_{etype}"],
                    )
                )
            elif etype == "sink":
                self.sink_hits.append({"sink": ev.get("sink"), "source": ev.get("source"),
                                       "sample": mask_text(str(ev.get("sample", ""))), "page_url": self.page.url})
            elif etype == "msg_listener":
                self.msg_listeners.append({"hasOriginCheck": bool(ev.get("hasOriginCheck")),
                                           "sample": mask_text(str(ev.get("sample", ""))), "page_url": self.page.url})
            elif etype == "sse" and url:
                self.sse_endpoints.append({"url": url, "page_url": self.page.url})
        self.agent_events.extend(events)
        return events

    def snapshot_storage(self) -> dict[str, Any]:
        """Capture storage with VALUES (raw) + a secret scan over window globals.

        Returns raw values so the token analyzer can decode JWTs; the pipeline masks
        the persisted copy afterwards.
        """
        if not self.page:
            return {}
        try:
            return self.page.evaluate(
                r"""() => {
                    const grab = (s) => { const o = {}; try { for (let i=0;i<s.length;i++){ const k=s.key(i); o[k]=s.getItem(k); } } catch(e){} return o; };
                    const re = /eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}|api[_-]?key|secret|token|password|client[_-]?secret/i;
                    const hits = [];
                    try {
                        for (const k of Object.keys(window)) {
                            let v; try { v = window[k]; } catch(e){ continue; }
                            if (typeof v === 'string' && v.length > 12 && re.test(v)) hits.push({key:k, sample:v.slice(0,100)});
                            else if (v && typeof v === 'object') {
                                try { const s = JSON.stringify(v); if (s && s.length < 6000 && re.test(s)) hits.push({key:k, sample:s.slice(0,140)}); } catch(e){}
                            }
                            if (hits.length >= 30) break;
                        }
                    } catch(e){}
                    return {
                        cookies: document.cookie,
                        localStorage: grab(localStorage),
                        sessionStorage: grab(sessionStorage),
                        globalsSecrets: hits,
                        globals: Object.keys(window).slice(0, 200),
                    };
                }"""
            )
        except Exception:
            return {}
