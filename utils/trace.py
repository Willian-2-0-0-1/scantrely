"""Request / pipeline trace ids (contextvars).

Flask echoes ``X-Request-Id`` / ``X-Trace-Id``. Pipeline events carry
``trace_id`` so HUD, logs and module status share one correlation id.
"""
from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar

request_id_var: ContextVar[str] = ContextVar("request_id", default="")
trace_id_var: ContextVar[str] = ContextVar("trace_id", default="")


def new_id() -> str:
    return uuid.uuid4().hex[:16]


def current_request_id() -> str:
    return request_id_var.get() or ""


def current_trace_id() -> str:
    return trace_id_var.get() or current_request_id()


def bind(request_id: str | None = None, trace_id: str | None = None) -> tuple[str, str]:
    rid = (request_id or "").strip() or new_id()
    tid = (trace_id or "").strip() or rid
    request_id_var.set(rid)
    trace_id_var.set(tid)
    return rid, tid


class TraceLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = current_request_id() or "-"
        record.trace_id = current_trace_id() or "-"
        return True


def install_log_filter(logger: logging.Logger | None = None) -> None:
    target = logger or logging.getLogger()
    if not any(isinstance(item, TraceLogFilter) for item in target.filters):
        target.addFilter(TraceLogFilter())
    for handler in target.handlers:
        if not any(isinstance(item, TraceLogFilter) for item in handler.filters):
            handler.addFilter(TraceLogFilter())


def register_trace(app) -> None:
    from flask import g, request

    @app.before_request
    def _bind_request_trace():
        incoming = (
            request.headers.get("X-Request-Id")
            or request.headers.get("X-Trace-Id")
            or ""
        )
        rid, tid = bind(incoming or None)
        g.request_id = rid
        g.trace_id = tid

    @app.after_request
    def _echo_request_trace(resp):
        rid = getattr(g, "request_id", "") or current_request_id()
        tid = getattr(g, "trace_id", "") or current_trace_id() or rid
        if rid:
            resp.headers["X-Request-Id"] = rid
        if tid:
            resp.headers["X-Trace-Id"] = tid
        return resp
