"""Process lifecycle: graceful drain for SIGTERM / restart.

When draining, GET /health returns 503 so a proxy can stop sending traffic
before the process exits. Single-port Flask still has a short listen-handoff
gap; this is the honest local equivalent of zero-downtime.
"""
from __future__ import annotations

import threading

_DRAIN = threading.Event()


def begin_drain() -> None:
    _DRAIN.set()


def is_draining() -> bool:
    return _DRAIN.is_set()


def reset_drain() -> None:
    """Tests only."""
    _DRAIN.clear()


def snapshot() -> dict:
    draining = is_draining()
    return {"ok": not draining, "draining": draining}
