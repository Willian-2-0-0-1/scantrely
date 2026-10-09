"""Mullvad VPN IP rotation for ASM scans — thread-safe, supports concurrent pipelines.

Each pipeline should create its own Rotator instance for isolation:
    rotator = Rotator(log_callback=lambda msg: ..., ip_callback=lambda ip: ...)
    rotator.rotate()
    rotator.current_ip()

For simple single-pipeline usage, module-level helpers still work:
    mr.set_log_callback(...)
    mr.rotate()
"""
from __future__ import annotations
import subprocess, time, random, re, logging, threading
import logging as _logging
_log = _logging.getLogger('scantrely.mullvad_rotator')

log = logging.getLogger("mullvad_rotator")

_COUNTRIES = [
    "us", "gb", "de", "nl", "ch", "se", "no", "fr", "ca", "au",
    "at", "be", "cz", "dk", "es", "fi", "it", "jp", "pl", "pt",
    "ro", "sg", "nz", "za",
]

_BLOCK_PATTERNS = [
    "429", "too many requests",
    "rate limit", "ratelimit", "rate-limit",
    "access denied", "forbidden",
    "cloudflare", "captcha", "recaptcha",
    "connection refused", "connection reset by peer",
    "i/o timeout", "context deadline exceeded",
    "no route to host", "network is unreachable",
    "dial tcp", "eof",
    "waf", "blocked", "security check",
    "cf-ray", "__cf_bm", "akamai",
    "request could not be satisfied",
    "just a moment", "checking your browser",
    "enable javascript", "ddos protection",
    "attention required", "challenge",
    "edge security", "imperva", "f5 networks",
    "403", "503",
]

# Global lock for the Mullvad CLI — only ONE rotate at a time across ALL pipelines
_rotation_lock = threading.Lock()


# ── Internal helpers ──────────────────────────────────────────────────────────

def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["mullvad", *args], capture_output=True, text=True, timeout=15
    )


# ── Public API — pure functions (no callbacks) ────────────────────────────────

def is_connected() -> bool:
    try:
        return "Connected" in _run("status").stdout
    except Exception:
        return False


def current_ip() -> str:
    try:
        m = re.search(r"IPv4: ([\d.]+)", _run("status", "-v").stdout)
        return m.group(1) if m else ""
    except Exception:
        return ""


def status_line() -> str:
    try:
        out = _run("status", "-v").stdout
        if "Connected" not in out:
            return "Mullvad: Disconnected"
        ip  = re.search(r"IPv4: ([\d.]+)", out)
        loc = re.search(r"Visible location:\s+(.+)", out)
        ip_str  = ip.group(1) if ip else "?"
        raw_loc = loc.group(1).strip() if loc else "?"
        loc_str = re.sub(r"\.\s*IPv4:.*", "", raw_loc).strip(" ,.")
        return f"🌐 Mullvad: {ip_str} ({loc_str})"
    except Exception:
        return "Mullvad: status unavailable"


def is_blocked(stdout: str, stderr: str) -> bool:
    """Return True if stdout/stderr contain block/rate-limit signals."""
    combined = (stdout + stderr).lower()
    return any(sig in combined for sig in _BLOCK_PATTERNS)


# ── Legacy global callbacks (for backward compat) ─────────────────────────────

_global_log_cb: callable | None = None
_global_ip_cb:  callable | None = None


def set_log_callback(fn: callable | None) -> None:
    global _global_log_cb
    _global_log_cb = fn


def set_ip_callback(fn: callable | None) -> None:
    global _global_ip_cb
    _global_ip_cb = fn


# ── Rotator class — per-pipeline instance ─────────────────────────────────────

class Rotator:
    """Per-pipeline Mullvad rotator with its own callbacks.

    Multiple pipelines each get their own Rotator instance, preventing
    callback cross-talk when 2+ scans run concurrently.
    """

    def __init__(self,
                 log_callback: callable | None = None,
                 ip_callback: callable | None = None):
        self.log_cb = log_callback
        self.ip_cb  = ip_callback

    def _emit(self, msg: str) -> None:
        print(msg, flush=True)
        if self.log_cb:
            try:
                self.log_cb(msg)
            except Exception:
                _log.debug('mullvad_rotator.py:128 erro ignorado', exc_info=True)
        elif _global_log_cb:
            try:
                _global_log_cb(msg)
            except Exception:
                _log.debug('mullvad_rotator.py:133 erro ignorado', exc_info=True)

    def _ip_update(self, ip: str) -> None:
        if self.ip_cb:
            try:
                self.ip_cb(ip)
            except Exception:
                _log.debug('mullvad_rotator.py:140 erro ignorado', exc_info=True)
        elif _global_ip_cb:
            try:
                _global_ip_cb(ip)
            except Exception:
                _log.debug('mullvad_rotator.py:145 erro ignorado', exc_info=True)

    def wait_connected(self, timeout: int = 15) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if is_connected():
                ip = current_ip()
                if ip:
                    return ip
            time.sleep(1)
        raise TimeoutError(f"Mullvad did not connect within {timeout}s")

    def rotate(self, preferred: list[str] | None = None, wait: int = 15) -> str:
        """Thread-safe rotation. Blocks until IP actually changes or all attempts exhausted."""
        with _rotation_lock:
            old_ip = current_ip()
            # If we can't determine old IP, record a sentinel so we can still detect a change
            old_ip_known = bool(old_ip)
            tried: set[str] = set()
            pool = list(preferred or _COUNTRIES)
            # Exponential connect timeouts: 10s, 13s, 17s, 20s
            connect_timeouts = [10, 13, 17, 20]

            for attempt in range(4):
                remaining = [c for c in pool if c not in tried]
                if not remaining:
                    remaining = pool
                    tried.clear()
                country = random.choice(remaining)
                tried.add(country)
                conn_timeout = connect_timeouts[min(attempt, len(connect_timeouts) - 1)]

                self._emit(f"🔄 Mullvad: rotating to {country.upper()} (attempt {attempt+1}/4, timeout {conn_timeout}s)")
                _run("disconnect")
                time.sleep(2)
                _run("relay", "set", "location", country)
                time.sleep(0.5)
                _run("connect")
                time.sleep(3)
                try:
                    new_ip = self.wait_connected(conn_timeout)
                except TimeoutError:
                    self._emit(f"⚠ Mullvad: timeout connecting to {country.upper()}, trying next...")
                    continue

                # Only accept as success if IP genuinely changed (or old was unknown)
                if not old_ip_known or new_ip != old_ip:
                    self._emit(f"🌐 Mullvad: new IP → {new_ip} ({country.upper()})")
                    self._ip_update(new_ip)
                    return new_ip
                else:
                    self._emit(f"⚠ Mullvad: IP unchanged ({new_ip}), trying different country...")

            # Last-resort: full reconnect with longer timeout
            self._emit("⚠ Mullvad: forcing full reconnect...")
            _run("disconnect")
            time.sleep(3)
            _run("connect")
            time.sleep(5)
            try:
                new_ip = self.wait_connected(25)
            except TimeoutError:
                raise RuntimeError("Mullvad failed to reconnect after all attempts")
            if old_ip_known and new_ip == old_ip:
                self._emit(f"⚠ Mullvad: reconnected but IP still {new_ip} — rotation ineffective")
            else:
                self._emit(f"🌐 Mullvad: final IP → {new_ip}")
            self._ip_update(new_ip)
            return new_ip


# ── Module-level helpers (delegate to a default Rotator) ──────────────────────

_default_rotator: Rotator | None = None


def _get_default() -> Rotator:
    global _default_rotator
    if _default_rotator is None:
        _default_rotator = Rotator()
    return _default_rotator


def rotate(preferred: list[str] | None = None, wait: int = 15) -> str:
    return _get_default().rotate(preferred, wait)


def wait_connected(timeout: int = 15) -> str:
    return _get_default().wait_connected(timeout)
