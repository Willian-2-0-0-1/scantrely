#!/usr/bin/env python3
"""Persistent job scheduler for ASM pipeline execution."""

from __future__ import annotations

import threading
import time
import traceback
import os
import subprocess
from datetime import datetime
import uuid
from typing import Callable

_RECON_PROCESS_NAMES = {
    "assetfinder", "subfinder", "httpx", "httpx-toolkit", "nuclei", "naabu",
    "amass", "masscan", "ffuf", "gowitness", "wpscan", "dig", "whois",
    "gau", "waybackurls",
}


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return max(1, int(default))


def _mem_available_mb() -> int:
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    # Non-Linux fallback (Windows dev boxes, etc.) so the memory watchdog
    # isn't silently a no-op outside of Linux containers.
    try:
        import psutil  # type: ignore
        return int(psutil.virtual_memory().available // (1024 * 1024))
    except Exception:
        pass
    try:
        import ctypes

        class _MEMSTAT(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = _MEMSTAT()
        stat.dwLength = ctypes.sizeof(_MEMSTAT)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):  # type: ignore[attr-defined]
            return int(stat.ullAvailPhys // (1024 * 1024))
    except Exception:
        pass
    return 999999


def _recon_process_count() -> int:
    try:
        out = subprocess.run(
            ["ps", "-eo", "comm="],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.splitlines()
        return sum(1 for item in out if item.strip() in _RECON_PROCESS_NAMES)
    except Exception:
        return 0


class JobScheduler:
    """Small persistent FIFO scheduler backed by ASMDatabase.

    Flask routes should enqueue work and return quickly. This scheduler owns the
    worker threads that claim pending jobs and execute the pipeline runner.
    """

    def __init__(
        self,
        *,
        db,
        load_companies: Callable[[], list[dict]],
        run_pipeline: Callable[[str, dict, dict], None],
        pipeline_state: dict,
        save_pipeline_state: Callable[[str], None] | None = None,
        run_playwright_recon: Callable[[str, dict, dict], dict | None] | None = None,
        get_settings: Callable[[], dict] | None = None,
        max_workers: int = 1,
        poll_interval: float = 1.0,
    ):
        self.db = db
        self.load_companies = load_companies
        self.run_pipeline = run_pipeline
        self.run_playwright_recon = run_playwright_recon
        self.pipeline_state = pipeline_state
        self.save_pipeline_state = save_pipeline_state
        self.max_workers = max(1, int(max_workers or 1))
        self.poll_interval = max(0.2, float(poll_interval or 1.0))
        self.get_settings = get_settings
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._started = False
        self._lock = threading.Lock()
        self._safety_stop = threading.Event()
        self.watchdog_enabled = os.environ.get("ASM_WATCHDOG_ENABLED", "1") != "0"
        self.watchdog_max_load = float(os.environ.get("ASM_WATCHDOG_MAX_LOAD", os.cpu_count() or 2))
        self.watchdog_min_mem_mb = _env_int("ASM_WATCHDOG_MIN_MEM_MB", 1536)
        self.watchdog_max_recon_procs = _env_int(
            "ASM_WATCHDOG_MAX_RECON_PROCS",
            _env_int("ASM_GLOBAL_PROC_LIMIT", 8) + 4,
        )

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self.db.recover_running_jobs()
            self._stop.clear()
            self._safety_stop.clear()
            for idx in range(self.max_workers):
                thread = threading.Thread(target=self._worker_loop, name=f"asm-job-worker-{idx+1}", daemon=True)
                thread.start()
                self._threads.append(thread)
            if self.watchdog_enabled:
                thread = threading.Thread(target=self._watchdog_loop, name="asm-resource-watchdog", daemon=True)
                thread.start()
                self._threads.append(thread)
            self._started = True

    def stop(self) -> None:
        self._stop.set()

    def enqueue_pipeline(
        self,
        company_id: str,
        *,
        options: dict | None = None,
        priority: int = 100,
        created_by: str = "",
        dedupe: bool = True,
        target: str = "",
    ) -> dict:
        if dedupe:
            existing = self.db.find_active_job(company_id=company_id, job_type="pipeline", target=target)
            if existing:
                return {**existing, "deduped": True}
        job_options = dict(options or {})
        job_options["profile"] = "bug_bounty"
        job_options["pipeline_profile"] = "bug_bounty"
        job_options.pop("light", None)
        job_options.pop("phases", None)
        job_options.pop("pipeline_phases", None)
        job_options["active"] = True
        job = self.db.create_job(
            job_type="pipeline",
            company_id=company_id,
            target=target or company_id,
            options=job_options,
            priority=priority,
            created_by=created_by,
        )
        job["deduped"] = False
        return job

    def enqueue_pipeline_queue(
        self,
        company_id: str,
        domains: list[str],
        *,
        options: dict | None = None,
        priority: int = 100,
        created_by: str = "",
        dedupe: bool = True,
    ) -> list[dict]:
        domains = [str(domain).strip() for domain in (domains or []) if str(domain).strip()]
        if not domains:
            return []

        active_targets = set()
        if dedupe:
            try:
                active_targets = self.db.list_active_job_targets(company_id=company_id, job_type="pipeline")
            except Exception:
                active_targets = set()

        jobs: list[dict] = []
        payloads: list[dict] = []
        for idx, domain in enumerate(domains):
            if dedupe and domain in active_targets:
                continue
            job_options = dict(options or {})
            job_options["domains"] = [domain]
            job_options["queue_domain"] = domain
            job_options["queue_batch_index"] = idx
            job_options["profile"] = "bug_bounty"
            job_options["pipeline_profile"] = "bug_bounty"
            job_options.pop("light", None)
            job_options.pop("phases", None)
            job_options.pop("pipeline_phases", None)
            job_options["active"] = True
            payloads.append({
                "job_type": "pipeline",
                "company_id": company_id,
                "target": domain,
                "options": job_options,
                "priority": priority + idx,
                "created_by": created_by,
            })

        if not payloads:
            return []

        if hasattr(self.db, "create_jobs_bulk"):
            jobs = self.db.create_jobs_bulk(payloads)
        else:
            jobs = [self.db.create_job(**payload) for payload in payloads]

        for job in jobs:
            job["deduped"] = False
        return jobs

    def enqueue_playwright_recon(
        self,
        company_id: str,
        *,
        options: dict | None = None,
        priority: int = 120,
        created_by: str = "",
        dedupe: bool = True,
    ) -> dict:
        job_id = uuid.uuid4().hex
        options = dict(options or {})
        options.setdefault("job_id", job_id)
        options.setdefault("job_root", str(self._playwright_job_root(company_id, job_id)))
        options.setdefault("evidence_dir", str(self._playwright_job_root(company_id, job_id) / "evidence"))
        options.setdefault("output", str(self._playwright_job_root(company_id, job_id) / "report.md"))
        if dedupe:
            existing = self.db.find_active_job(company_id=company_id, job_type="playwright_recon")
            if existing:
                return {**existing, "deduped": True}
        job = self.db.create_job(
            job_type="playwright_recon",
            company_id=company_id,
            target=str((options or {}).get("target_url") or (options or {}).get("url") or ""),
            options=options,
            priority=priority,
            created_by=created_by,
            job_id=job_id,
        )
        job["deduped"] = False
        return job

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self._safety_stop.is_set():
                    time.sleep(max(2.0, self.poll_interval))
                    continue
                reason = self._resource_violation()
                if reason:
                    self._trigger_safety_hold(reason)
                    continue
                job = self.db.claim_next_job()
                if not job:
                    time.sleep(self.poll_interval)
                    continue
                self._execute(job)
            except Exception:
                time.sleep(self.poll_interval)

    def _watchdog_loop(self) -> None:
        _consecutive_ok = 0
        _required_ok = 6  # 6 x 5s = 30s of clean health before auto-releasing hold
        while not self._stop.is_set():
            try:
                reason = self._resource_violation()
                if reason:
                    _consecutive_ok = 0
                    self._trigger_safety_hold(reason)
                elif self._safety_stop.is_set():
                    _consecutive_ok += 1
                    if _consecutive_ok >= _required_ok:
                        self._safety_stop.clear()
                        _consecutive_ok = 0
                        now = datetime.now().isoformat(timespec="seconds")
                        try:
                            if hasattr(self.db, "release_safety_hold"):
                                self.db.release_safety_hold()
                        except Exception:
                            pass
                        for cid, state in list(self.pipeline_state.items()):
                            if isinstance(state, dict) and state.get("status") == "stopped":
                                reason_log = str(state.get("log", [{}])[-1].get("msg", ""))
                                if "SAFETY-WATCHDOG" in reason_log:
                                    state["status"] = "queued"
                                    state.setdefault("log", []).append({"ts": now, "msg": "SAFETY-WATCHDOG released — resources healthy"})
                                    if self.save_pipeline_state:
                                        try:
                                            self.save_pipeline_state(cid)
                                        except Exception:
                                            pass
                else:
                    _consecutive_ok = 0
                self._trim_pipeline_logs()
                time.sleep(5)
            except Exception:
                time.sleep(5)

    def _trim_pipeline_logs(self, keep: int = 500) -> None:
        """Cap in-memory pipeline log lists so long-running runs across many
        concurrent company pipelines don't grow unbounded RAM usage."""
        for state in list(self.pipeline_state.values()):
            log = state.get("log") if isinstance(state, dict) else None
            if isinstance(log, list) and len(log) > keep:
                del log[: len(log) - keep]

    def _resource_violation(self) -> str:
        if not self.watchdog_enabled:
            return ""
        if hasattr(os, "getloadavg"):
            load1 = os.getloadavg()[0]
            if load1 > self.watchdog_max_load:
                return f"watchdog load {load1:.2f} > {self.watchdog_max_load:.2f}"
        mem_mb = _mem_available_mb()
        if mem_mb < self.watchdog_min_mem_mb:
            return f"watchdog mem {mem_mb}MB < {self.watchdog_min_mem_mb}MB"
        proc_count = _recon_process_count()
        if proc_count > self.watchdog_max_recon_procs:
            return f"watchdog recon_procs {proc_count} > {self.watchdog_max_recon_procs}"
        return ""

    def _trigger_safety_hold(self, reason: str) -> None:
        if self._safety_stop.is_set():
            return
        self._safety_stop.set()
        hold_reason = f"SAFETY-WATCHDOG: {reason}"
        try:
            if hasattr(self.db, "safety_hold_jobs"):
                self.db.safety_hold_jobs(reason=hold_reason)
        except Exception:
            pass
        now = datetime.now().isoformat(timespec="seconds")
        for cid, state in list(self.pipeline_state.items()):
            if isinstance(state, dict) and state.get("status") in {"queued", "running"}:
                state["status"] = "stopped"
                state["finished_at"] = now
                state.setdefault("log", []).append({"ts": now, "msg": hold_reason})
                if self.save_pipeline_state:
                    try:
                        self.save_pipeline_state(cid)
                    except Exception:
                        pass

    def _execute(self, job: dict) -> None:
        job_id = job["id"]
        company_id = job.get("company_id", "")
        try:
            job_type = job.get("job_type")
            company = self._find_company(company_id)
            if not company:
                self.db.finish_job(job_id, status="error", error="Company not found")
                return
            options = dict(job.get("options", {}) or {})
            options.setdefault("job_id", job_id)
            options.setdefault("job_type", job_type)
            if job_type == "pipeline":
                options["profile"] = "bug_bounty"
                options["pipeline_profile"] = "bug_bounty"
                options.pop("light", None)
                options.pop("phases", None)
                options.pop("pipeline_phases", None)
                options["active"] = True
                run_company = dict(company)
                scoped_domains = [str(d).strip() for d in (options.get("domains") or []) if str(d).strip()]
                if scoped_domains:
                    run_company["domains"] = scoped_domains
                state = self.pipeline_state.setdefault(company_id, {})
                state["job_id"] = job_id
                state.setdefault("log", []).append({
                    "ts": datetime.now().isoformat(timespec="seconds"),
                    "msg": f"Queued job {job_id} started" + (f" for {scoped_domains[0]}" if scoped_domains else ""),
                })
                if self.save_pipeline_state:
                    self.save_pipeline_state(company_id)
                self.run_pipeline(company_id, run_company, options)
                final_state = self.pipeline_state.get(company_id, {})
                status = final_state.get("status")
                if status == "stopped":
                    self.db.finish_job(job_id, status="cancelled")
                elif status == "error":
                    self.db.finish_job(job_id, status="error", error=self._last_log(company_id))
                else:
                    self.db.finish_job(job_id, status="done")
                    # The bug-bounty pipeline includes browser_crawl/browser_recon
                    # in-band. Do not enqueue separate follow-up jobs.
                return
            if job_type == "playwright_recon":
                if not self.run_playwright_recon:
                    self.db.finish_job(job_id, status="error", error="Playwright runner not configured")
                    return
                # Skip if pipeline was stopped by user
                state = self.pipeline_state.get(company_id, {})
                if state.get("status") == "stopped":
                    self.db.finish_job(job_id, status="cancelled")
                    return
                self.run_playwright_recon(company_id, company, options)
                self.db.finish_job(job_id, status="done")
                return
            self.db.finish_job(job_id, status="error", error=f"Unsupported job type: {job_type}")
        except Exception as exc:
            self._mark_pipeline_error(company_id, exc)
            self.db.finish_job(job_id, status="error", error=f"{exc}\n{traceback.format_exc()[-1200:]}")

    def _find_company(self, company_id: str) -> dict | None:
        for company in self.load_companies():
            if company.get("id") == company_id:
                return company
        return None

    def _playwright_job_root(self, company_id: str, job_id: str):
        from pathlib import Path

        base = Path(__file__).resolve().parent.parent / "data" / "playwright-jobs"
        return base / self._slugify(company_id) / job_id

    def _slugify(self, value: str) -> str:
        import re

        text = re.sub(r"[^a-zA-Z0-9]+", "-", value or "").strip("-").lower()
        return text or "company"

    def _last_log(self, company_id: str) -> str:
        log = self.pipeline_state.get(company_id, {}).get("log", [])
        if not log:
            return ""
        return str(log[-1].get("msg", ""))[:1000]

    def _mark_pipeline_error(self, company_id: str, exc: Exception) -> None:
        if not company_id:
            return
        state = self.pipeline_state.setdefault(company_id, {})
        if state.get("status") not in ("done", "stopped"):
            state.update({
                "status": "error",
                "finished_at": datetime.now().isoformat(timespec="seconds"),
            })
            state.setdefault("log", []).append({
                "ts": datetime.now().isoformat(timespec="seconds"),
                "msg": f"Pipeline crashed: {exc}",
            })
            if self.save_pipeline_state:
                self.save_pipeline_state(company_id)
