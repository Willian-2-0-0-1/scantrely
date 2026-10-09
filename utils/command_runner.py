#!/usr/bin/env python3
"""Central subprocess runner with tool gates, tracing, live output, and optional DB history."""

from __future__ import annotations

import os
import logging as _logging
_log = _logging.getLogger('scantrely.command_runner')
import subprocess
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from utils import cmd_trace
from utils.tool_gate import gate_for


MAX_CAPTURE_CHARS = 12000
_MAX_LIVE_LINES   = 2000   # max lines per live buffer (cid:module)
_SENSITIVE_MARKERS = ("token", "secret", "password", "passwd", "api-key", "apikey")

# ═══════════════════════════════════════════════════════════════════════════
#  Live output buffer — written by real-time reader threads, consumed by API
# ═══════════════════════════════════════════════════════════════════════════
_live_lock = threading.Lock()
_live_buffers: dict[str, dict[str, list[dict]]] = defaultdict(dict)
# _live_buffers[cid][module] = [{"ts": "2026-...", "stream": "stdout", "line": "..."}, ...]


def live_read(cid: str, module: str, since: float = 0) -> list[dict]:
    """Return new live output lines for a company+module since a Unix timestamp."""
    with _live_lock:
        buf = _live_buffers.get(cid, {}).get(module, [])
        result = []
        for entry in buf:
            if entry.get("_time", 0) > since:
                result.append({"ts": entry["ts"], "stream": entry["stream"], "line": entry["line"]})
        return result


def live_read_all(cid: str, since: float = 0) -> list[dict]:
    """Return new live output lines for all modules of a company since a timestamp."""
    with _live_lock:
        result = []
        for mod, buf in _live_buffers.get(cid, {}).items():
            for entry in buf:
                if entry.get("_time", 0) > since:
                    result.append({"ts": entry["ts"], "module": mod, "stream": entry["stream"], "line": entry["line"]})
        result.sort(key=lambda e: e.get("ts", ""))
        return result


def live_clear(cid: str, module: str | None = None):
    """Clear live output buffers."""
    with _live_lock:
        if module:
            _live_buffers.get(cid, {}).pop(module, None)
        else:
            _live_buffers.pop(cid, None)


def _live_append(cid: str, module: str, stream: str, line: str):
    """Append a line to the live buffer (thread-safe)."""
    now = time.time()
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now))
    with _live_lock:
        buf = _live_buffers[cid].setdefault(module, [])
        buf.append({"ts": ts, "stream": stream, "line": line, "_time": now})
        if len(buf) > _MAX_LIVE_LINES * 2:
            _live_buffers[cid][module] = buf[-_MAX_LIVE_LINES:]


@dataclass
class CommandContext:
    company_id: str = ""
    module: str = ""
    db: object | None = None


def _tool_name(argv: Sequence[str]) -> str:
    if not argv:
        return "unknown"
    return Path(str(argv[0])).name


def _redact_argv(argv: Sequence[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for arg in argv:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        lower = arg.lower()
        if any(marker in lower for marker in _SENSITIVE_MARKERS):
            if "=" in arg:
                redacted.append(arg.split("=", 1)[0] + "=<redacted>")
            else:
                redacted.append(arg)
                if arg.startswith("-"):
                    redact_next = True
            continue
        redacted.append(arg)
    return redacted


def run(
    argv: Sequence[str],
    *,
    capture_output: bool = True,
    text: bool = True,
    timeout: int | float | None = None,
    input=None,
    cwd: str | os.PathLike | None = None,
    env: dict | None = None,
    check: bool = False,
    context: CommandContext | None = None,
    **kwargs,
) -> subprocess.CompletedProcess:
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(x, str) for x in argv):
        raise ValueError("CommandRunner requires argv as a non-empty list[str]")
    if kwargs.get("shell") is True:
        raise ValueError("shell=True is not allowed")

    tool = _tool_name(argv)
    start = time.time()
    run_id = None
    ctx = context or CommandContext()
    cmd_trace.trace(list(argv))

    if ctx.db and hasattr(ctx.db, "start_tool_run"):
        try:
            run_id = ctx.db.start_tool_run(
                company_id=ctx.company_id,
                module=ctx.module,
                tool=tool,
                argv=_redact_argv(argv),
            )
        except Exception:
            run_id = None

    with gate_for(tool).slot():
        status = "error"
        error = None
        proc = None
        stdout_acc = ""
        stderr_acc = ""
        try:
            extra = dict(kwargs)
            extra.pop("shell", None)

            # Use Popen + threaded readers for real-time output streaming
            run_kwargs = {
                "text": text,
                "stdin": subprocess.DEVNULL if input is None else subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "cwd": cwd,
                "env": env,
            }
            if "stdout" in extra: run_kwargs.pop("stdout", None)
            if "stderr" in extra: run_kwargs.pop("stderr", None)
            run_kwargs.update({k: v for k, v in extra.items() if k not in ("capture_output",)})

            proc = subprocess.Popen(list(argv), **run_kwargs)

            # Write stdin if provided
            if input is not None and proc.stdin:
                try:
                    proc.stdin.write(input)
                    proc.stdin.close()
                except Exception:
                    _log.debug('command_runner.py:173 erro ignorado', exc_info=True)

            # Real-time stdout/stderr readers
            stdout_lines = []
            stderr_lines = []
            read_error = [None]

            def _read_stream(stream, acc_list, stream_name):
                try:
                    for line in iter(stream.readline, ""):
                        if not line:
                            break
                        acc_list.append(line)
                        if ctx.company_id and ctx.module:
                            _live_append(ctx.company_id, ctx.module, stream_name, line.rstrip("\n\r"))
                except Exception as e:
                    read_error[0] = e

            t_stdout = threading.Thread(target=_read_stream, args=(proc.stdout, stdout_lines, "stdout"), daemon=True)
            t_stderr = threading.Thread(target=_read_stream, args=(proc.stderr, stderr_lines, "stderr"), daemon=True)
            t_stdout.start()
            t_stderr.start()

            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                t_stdout.join(timeout=2)
                t_stderr.join(timeout=2)
                status = "timeout"
                error = subprocess.TimeoutExpired(list(argv), timeout or 0)
                stdout_acc = "".join(stdout_lines)
                stderr_acc = "".join(stderr_lines)
                raise

            t_stdout.join(timeout=5)
            t_stderr.join(timeout=5)
            stdout_acc = "".join(stdout_lines)
            stderr_acc = "".join(stderr_lines)

            if read_error[0]:
                raise read_error[0]

            # Build a CompletedProcess-compatible result
            class _ProcResult:
                def __init__(self, rc, out, err):
                    self.returncode = rc
                    self.stdout = out
                    self.stderr = err
            proc_result = _ProcResult(proc.returncode, stdout_acc, stderr_acc)

            # Some tools (theHarvester, asnmap) exit 1 with valid stdout.
            has_output = stdout_acc.strip()
            status = "done" if (proc.returncode == 0 or has_output) else "error"
            return proc_result

        except subprocess.TimeoutExpired as exc:
            status = "timeout"
            error = exc
            raise
        except Exception as exc:
            status = "error"
            error = exc
            raise
        finally:
            duration = time.time() - start
            if ctx.db and run_id and hasattr(ctx.db, "finish_tool_run"):
                exit_code = None
                if proc is not None:
                    exit_code = proc.returncode
                elif error is not None:
                    exit_code = getattr(error, "returncode", None)
                try:
                    ctx.db.finish_tool_run(
                        run_id,
                        status=status,
                        exit_code=exit_code,
                        duration=duration,
                        stdout_tail=stdout_acc[-MAX_CAPTURE_CHARS:],
                        stderr_tail=stderr_acc[-MAX_CAPTURE_CHARS:],
                    )
                except Exception:
                    _log.debug('command_runner.py:255 erro ignorado', exc_info=True)
