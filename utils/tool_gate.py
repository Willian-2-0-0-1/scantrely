#!/usr/bin/env python3
"""Per-tool concurrency gates with lightweight queue metrics."""

from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager


def _lim(name: str, default: int) -> int:
    """Per-tool concurrency limit, overridable via ASM_GATE_<TOOL> env var."""
    try:
        return max(1, int(os.environ.get(f"ASM_GATE_{name.upper()}", default)))
    except (TypeError, ValueError):
        return default


# -- Global subprocess cap ----------------------------------------------------
# Master ceiling on the TOTAL number of concurrent subprocesses across ALL
# tools, regardless of per-tool limits. Even if every per-tool gate were wide
# open, no more than this many external processes run at once - this is the
# single knob that prevents the host from being fork-bombed by the
# module(8) x domain(8) = 64-thread fan-out each launching a subprocess.
# Override with ASM_GLOBAL_PROC_LIMIT.
GLOBAL_PROC_LIMIT = _lim("global_procs", int(os.environ.get("ASM_GLOBAL_PROC_LIMIT", "24") or 24))
_global_sema = threading.BoundedSemaphore(GLOBAL_PROC_LIMIT)

# Default per-tool limit for tools NOT explicitly listed below (e.g. dig, whois,
# curl, dnsx). These are cheap/network-bound, so they aren't individually
# throttled hard - the global cap above is what actually bounds them. Capping
# unknown tools at 1 (the old default) would serialize all DNS resolution and
# crawl a 35k-host sweep to a halt. Override with ASM_GATE_DEFAULT.
DEFAULT_TOOL_LIMIT = _lim("default", int(os.environ.get("ASM_GATE_DEFAULT", "8") or 8))


# Network/API-bound discovery tools get higher concurrency (they mostly wait on
# remote APIs) so bulk multi-worker sweeps actually parallelize. Heavy local
# binaries (amass/naabu/nuclei/masscan/ffuf) stay low to protect the host.
DEFAULT_LIMITS = {
    "amass": _lim("amass", 1),
    "subfinder": _lim("subfinder", 8),
    "assetfinder": _lim("assetfinder", 8),
    "httpx": _lim("httpx", 8),
    "naabu": _lim("naabu", 1),
    "nuclei": _lim("nuclei", 1),
    "gowitness": _lim("gowitness", 1),
    # whatweb/wpscan rodam como "ruby …": o gate pega o nome do executável. Ruby pesado em paralelo
    # (vários domínios ao mesmo tempo) somava com o Chrome do gowitness e o watchdog pausava o scan.
    "ruby": _lim("ruby", 1),
    # módulos Playwright rodam dentro do processo (não passam pelo gate de subprocesso) e abrem
    # 3 navegadores cada; dois domínios na fase 8 juntos passaram de load 13 em 10s (15/10/2026)
    "playwright": _lim("playwright", 1),
    "wpscan": _lim("wpscan", 1),
    "masscan": _lim("masscan", 1),
    "ffuf": _lim("ffuf", 2),
    "gau": _lim("gau", 4),
    "waybackurls": _lim("waybackurls", 4),
}


class ToolGate:
    def __init__(self, name: str, limit: int = 1):
        self.name = name
        self.limit = max(1, int(limit))
        self.active = 0
        self.queued = 0
        self._cond = threading.Condition()

    @contextmanager
    def slot(self):
        # Acquire the per-tool gate FIRST, then the global cap. Tool-first
        # ordering means a thread queued on a contended limit-1 tool (nuclei,
        # naabu...) does NOT hold a global permit while it waits, so it can't
        # starve other tools. No deadlock: a thread only ever waits on the
        # global semaphore while permits are held by *running* threads, which
        # always release them.
        self.acquire()
        _global_sema.acquire()
        try:
            yield self
        finally:
            _global_sema.release()
            self.release()

    def acquire(self, timeout: float | None = None) -> bool:
        """Espera a vaga; com timeout, devolve False se não conseguir a tempo."""
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        with self._cond:
            self.queued += 1
            try:
                while self.active >= self.limit:
                    if deadline is None:
                        self._cond.wait()
                    else:
                        left = deadline - time.monotonic()
                        if left <= 0:
                            return False
                        self._cond.wait(left)
                self.active += 1
                return True
            finally:
                self.queued = max(0, self.queued - 1)

    @contextmanager
    def try_slot(self, timeout: float):
        """Como slot(), mas desiste depois de `timeout`: rende True/False. A espera pela vaga conta no
        prazo do módulo — com dois domínios em paralelo, o segundo estourava esperando o primeiro."""
        if not self.acquire(timeout):
            yield False
            return
        _global_sema.acquire()
        try:
            yield True
        finally:
            _global_sema.release()
            self.release()

    def release(self) -> None:
        with self._cond:
            self.active = max(0, self.active - 1)
            self._cond.notify_all()

    def snapshot(self) -> dict:
        with self._cond:
            return {"tool": self.name, "limit": self.limit, "active": self.active, "queued": self.queued}


_gates: dict[str, ToolGate] = {}
_gates_lock = threading.Lock()


def gate_for(tool: str) -> ToolGate:
    name = (tool or "unknown").split("/")[-1]
    with _gates_lock:
        if name not in _gates:
            _gates[name] = ToolGate(name, DEFAULT_LIMITS.get(name, DEFAULT_TOOL_LIMIT))
        return _gates[name]


def snapshot() -> list[dict]:
    with _gates_lock:
        return [gate.snapshot() for gate in sorted(_gates.values(), key=lambda g: g.name)]


def global_snapshot() -> dict:
    """Current state of the global subprocess cap (limit + free permits)."""
    # BoundedSemaphore exposes its internal counter as _value (free permits).
    free = getattr(_global_sema, "_value", None)
    active = (GLOBAL_PROC_LIMIT - free) if isinstance(free, int) else None
    return {"limit": GLOBAL_PROC_LIMIT, "active": active}
