"""Deep health snapshot for the local ASM process.

Used by GET /health and GET /api/health. Those routes stay unauthenticated
and return a small payload: sqlite, disk, bin/, watchdog, in-flight
pipelines, Playwright path, and open circuit breakers.
"""
from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APP_VERSION = "1.3.0"


def _ok_check(ok: bool, **extra) -> dict:
    out = {"ok": bool(ok)}
    out.update(extra)
    return out


def _ping_sqlite(db) -> dict:
    if db is None:
        return _ok_check(False, error="database not configured")
    path = str(getattr(db, "db_path", "") or "")
    try:
        with db._connect() as conn:
            conn.execute("SELECT 1").fetchone()
        return _ok_check(True, path=path)
    except Exception as exc:
        return _ok_check(False, path=path, error=str(exc)[:200])


def _disk_check(path: Path) -> dict:
    try:
        path.mkdir(parents=True, exist_ok=True)
        usage = shutil.disk_usage(path)
        free_mb = int(usage.free // (1024 * 1024))
        probe = path / ".health-write"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return _ok_check(free_mb >= 256, free_mb=free_mb, path=str(path), writable=True)
    except Exception as exc:
        return _ok_check(False, path=str(path), writable=False, error=str(exc)[:200])


def _bin_check(bin_dir: Path | None) -> dict:
    if bin_dir is None:
        return _ok_check(False, error="bin dir not configured")
    if not bin_dir.is_dir():
        return _ok_check(False, path=str(bin_dir), executables=0, error="missing")
    count = 0
    try:
        for child in bin_dir.iterdir():
            if child.is_file() and os.access(child, os.X_OK):
                count += 1
    except Exception as exc:
        return _ok_check(False, path=str(bin_dir), error=str(exc)[:200])
    return _ok_check(count > 0, path=str(bin_dir), executables=count)


def _watchdog_check(job_scheduler) -> dict:
    if job_scheduler is None:
        return _ok_check(True, hold=False, started=False, note="scheduler not attached")
    started = bool(getattr(job_scheduler, "_started", False))
    ev = getattr(job_scheduler, "_safety_stop", None)
    hold = bool(ev is not None and ev.is_set())
    extra: dict[str, Any] = {
        "hold": hold,
        "started": started,
        "watchdog_enabled": bool(getattr(job_scheduler, "watchdog_enabled", False)),
        "workers": int(getattr(job_scheduler, "max_workers", 0) or 0),
    }
    if hold:
        try:
            extra["reason"] = job_scheduler._resource_violation() or "safety hold"
        except Exception:
            extra["reason"] = "safety hold"
    return _ok_check(started and not hold, **extra)


def _pipeline_check(pipeline_state) -> dict:
    running: list[str] = []
    if isinstance(pipeline_state, dict):
        for cid, state in pipeline_state.items():
            if isinstance(state, dict) and str(state.get("status") or "") == "running":
                running.append(str(cid))
    return _ok_check(True, running=len(running), companies=running[:12])


def _playwright_check(playwright_path: Path | None) -> dict:
    path = playwright_path or Path(
        os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or str(Path.home() / ".asm-playwright")
    )
    exists = path.exists()
    return _ok_check(exists, path=str(path), note="optional" if not exists else "")


def _circuit_check() -> dict:
    try:
        from utils.circuit_breaker import all_snapshots, open_breaker_names
    except Exception as exc:
        return _ok_check(True, open=[], error=str(exc)[:200])
    opened = open_breaker_names()
    return _ok_check(len(opened) == 0, open=opened, breakers=all_snapshots())


def collect_health(
    *,
    db=None,
    bin_dir: Path | str | None = None,
    scans_dir: Path | str | None = None,
    data_dir: Path | str | None = None,
    job_scheduler=None,
    pipeline_state=None,
    playwright_path: Path | str | None = None,
) -> tuple[dict, int]:
    """Return (payload, http_status). 503 when draining, or SQLite/disk unusable."""
    from utils.lifecycle import is_draining, snapshot as lifecycle_snapshot

    bin_path = Path(bin_dir) if bin_dir else None
    scans_path = Path(scans_dir) if scans_dir else None
    data_path = Path(data_dir) if data_dir else None
    pw_path = Path(playwright_path) if playwright_path else None

    checks = {
        "sqlite": _ping_sqlite(db),
        "disk": _disk_check(data_path or scans_path or Path(".")),
        "bin": _bin_check(bin_path),
        "watchdog": _watchdog_check(job_scheduler),
        "pipelines": _pipeline_check(pipeline_state),
        "playwright": _playwright_check(pw_path),
        "circuits": _circuit_check(),
        "lifecycle": lifecycle_snapshot(),
    }
    if scans_path is not None:
        checks["scans"] = _disk_check(scans_path)

    hard_fail = (not checks["sqlite"]["ok"]) or (not checks["disk"]["ok"])
    degraded_keys = [
        name
        for name, item in checks.items()
        if name not in {"pipelines"} and not item.get("ok", True)
    ]
    if is_draining():
        status = "draining"
        http_status = 503
    elif hard_fail:
        status = "fail"
        http_status = 503
    elif degraded_keys:
        status = "degraded"
        http_status = 200
    else:
        status = "ok"
        http_status = 200

    payload = {
        "status": status,
        "version": APP_VERSION,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checks": checks,
        "degraded": degraded_keys,
    }
    return payload, http_status


def register_health_routes(app, **collect_kwargs) -> None:
    """Mount unauthenticated GET /health and GET /api/health on a Flask app."""
    from flask import jsonify

    def health():
        payload, code = collect_health(**collect_kwargs)
        return jsonify(payload), code

    app.add_url_rule("/health", endpoint="health", view_func=health, methods=["GET"])
    app.add_url_rule("/api/health", endpoint="api_health", view_func=health, methods=["GET"])
