"""Per-dependency circuit breaker for outbound HTTP.

One breaker per host (or ``api:<tool>``). Closed lets traffic through;
after ``failure_threshold`` consecutive failures the breaker opens and
later calls fail immediately until ``recovery_timeout`` elapses, then a
single half-open trial is allowed.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Literal

log = logging.getLogger("scantrely.circuit")

State = Literal["closed", "open", "half_open"]

CLOSED: State = "closed"
OPEN: State = "open"
HALF_OPEN: State = "half_open"

_DEFAULT_THRESHOLD = 5
_DEFAULT_RECOVERY = 30.0


class CircuitOpen(Exception):
    """Raised when a caller wants an exception instead of a silent skip."""

    def __init__(self, name: str, retry_after: float = 0.0):
        self.name = name
        self.retry_after = retry_after
        super().__init__(f"circuit open: {name}")


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        *,
        failure_threshold: int = _DEFAULT_THRESHOLD,
        recovery_timeout: float = _DEFAULT_RECOVERY,
        half_open_max: int = 1,
    ):
        self.name = name
        self.failure_threshold = max(1, int(failure_threshold))
        self.recovery_timeout = max(0.5, float(recovery_timeout))
        self.half_open_max = max(1, int(half_open_max))
        self._lock = threading.Lock()
        self.state: State = CLOSED
        self.failures = 0
        self.opened_at = 0.0
        self._half_open_inflight = 0
        self.opened_count = 0

    def allow(self) -> bool:
        with self._lock:
            if self.state == CLOSED:
                return True
            now = time.monotonic()
            if self.state == OPEN:
                if now - self.opened_at >= self.recovery_timeout:
                    self.state = HALF_OPEN
                    self._half_open_inflight = 1
                    log.info("circuit half-open: %s", self.name)
                    return True
                return False
            if self._half_open_inflight >= self.half_open_max:
                return False
            self._half_open_inflight += 1
            return True

    def success(self) -> None:
        with self._lock:
            if self.state == HALF_OPEN:
                log.info("circuit closed: %s", self.name)
            self.state = CLOSED
            self.failures = 0
            self._half_open_inflight = 0

    def failure(self) -> None:
        with self._lock:
            self.failures += 1
            now = time.monotonic()
            if self.state == HALF_OPEN:
                self._open(now)
                return
            if self.failures >= self.failure_threshold and self.state != OPEN:
                self._open(now)

    def _open(self, now: float) -> None:
        self.state = OPEN
        self.opened_at = now
        self._half_open_inflight = 0
        self.opened_count += 1
        log.warning("circuit open: %s after %s failures", self.name, self.failures)

    def retry_after(self) -> float:
        with self._lock:
            if self.state != OPEN:
                return 0.0
            return max(0.0, self.recovery_timeout - (time.monotonic() - self.opened_at))

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "name": self.name,
                "state": self.state,
                "failures": self.failures,
                "opened_count": self.opened_count,
                "retry_after": round(self.retry_after_unlocked(), 2),
            }

    def retry_after_unlocked(self) -> float:
        if self.state != OPEN:
            return 0.0
        return max(0.0, self.recovery_timeout - (time.monotonic() - self.opened_at))


_REGISTRY: dict[str, CircuitBreaker] = {}
_REG_LOCK = threading.Lock()


def breaker_for(
    name: str,
    *,
    failure_threshold: int = _DEFAULT_THRESHOLD,
    recovery_timeout: float = _DEFAULT_RECOVERY,
) -> CircuitBreaker:
    key = (name or "unknown").strip().lower() or "unknown"
    with _REG_LOCK:
        br = _REGISTRY.get(key)
        if br is None:
            br = CircuitBreaker(
                key,
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
            )
            _REGISTRY[key] = br
        return br


def _host_key(url: str, name: str | None = None) -> str:
    from urllib.parse import urlparse
    raw = name or urlparse(url or "").netloc.split(":")[0]
    return (raw or "http").strip().lower() or "http"


def _chaos_hosts() -> set[str]:
    """Hosts forced open by ``ASM_CHAOS_HOSTS`` (comma-separated). Tests only."""
    raw = os.environ.get("ASM_CHAOS_HOSTS") or ""
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def guard_host(url: str, *, name: str | None = None) -> CircuitBreaker:
    """Return the host breaker, or raise ``CircuitOpen`` if it is open."""
    host = _host_key(url, name)
    if host in _chaos_hosts():
        raise CircuitOpen(host, retry_after=0.0)
    br = breaker_for(host)
    if not br.allow():
        raise CircuitOpen(host, retry_after=br.retry_after())
    return br


def _note_status(br: CircuitBreaker, status: int) -> None:
    if int(status or 0) >= 500:
        br.failure()
    else:
        br.success()


def guarded_urlopen(req, timeout: float = 15, *, name: str | None = None, context=None):
    """``urlopen`` with a per-host circuit breaker.

    Raises ``CircuitOpen`` without touching the network when the breaker
    is open. 2xx/3xx/4xx count as success (the peer answered). 5xx,
    timeouts and connection errors count as failure.
    """
    from urllib.error import HTTPError
    from urllib.request import urlopen

    url = getattr(req, "full_url", None) or str(req)
    br = guard_host(url, name=name)
    kwargs: dict = {"timeout": timeout}
    if context is not None:
        kwargs["context"] = context
    try:
        resp = urlopen(req, **kwargs)
        br.success()
        return resp
    except HTTPError as exc:
        _note_status(br, int(getattr(exc, "code", 0) or 0))
        raise
    except Exception:
        br.failure()
        raise


def guarded_httpx(method: str, url: str, *, name: str | None = None, **kwargs):
    """``httpx.request`` with a per-host circuit breaker.

    Same success/failure rules as ``guarded_urlopen``. Raises ``CircuitOpen``
    when the breaker is open. 4xx still returns the response (peer answered).
    """
    import httpx

    br = guard_host(url, name=name)
    try:
        resp = httpx.request(method.upper(), url, **kwargs)
        _note_status(br, int(getattr(resp, "status_code", 0) or 0))
        return resp
    except Exception:
        br.failure()
        raise


def all_snapshots() -> list[dict]:
    with _REG_LOCK:
        items = list(_REGISTRY.values())
    return [br.snapshot() for br in items]


def open_breaker_names() -> list[str]:
    return [s["name"] for s in all_snapshots() if s["state"] == "open"]


def reset_all() -> None:
    """Drop every breaker. Tests only."""
    with _REG_LOCK:
        _REGISTRY.clear()
