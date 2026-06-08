#!/usr/bin/env python3
"""
Recon execution engine: per-module runners, wappalyzer/httpx probing,
host merging, and full multi-phase pipeline orchestration.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import os
import random
import re
import shutil
import subprocess as _subprocess_real
import tempfile
import threading
import time
from urllib.parse import urlparse
from collections import defaultdict
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed_pool
from datetime import datetime
from pathlib import Path
import hashlib

BIN_DIR = Path(__file__).parent.parent / "bin"

# Max domains scanned concurrently in a single per-domain fan-out.
# Companies can have tens of thousands of domains; without this cap a
# ThreadPoolExecutor(max_workers=len(domains)) spawns one subprocess per
# domain at once (a fork bomb). Capping turns the fan-out into a bounded
# queue: all domains are submitted, only this many run at a time.
_DOMAIN_FANOUT_WORKERS = int(os.environ.get("ASM_DOMAIN_FANOUT_WORKERS", "8") or 8)

PIPELINE_PROFILES = {
    # Public pipeline for the product: discovery is only the first step. Every
    # queued domain moves through validation, prioritization, browser evidence,
    # and bug-bounty checks. Host caps are applied after scoring so expensive
    # modules focus on targets most likely to produce actionable reports.
    "bug_bounty": {
        "active": True,
        "active_max_hosts": 40,
        "crawl_max_hosts": 12,
        "skip_smart_scan": True,
    },
}

from utils import cmd_trace as _ct
from utils import rate_limiter as _rl
from utils.tool_gate import gate_for as _gate_for
from flask import jsonify

_SUBPROCESS_CONTEXT = threading.local()


class _GatedSubprocess:
    """Transparent ``subprocess`` stand-in that routes ``run()`` through the
    per-tool + global ToolGate (a bounded queue), so the heavy raw subprocess
    calls in this file (masscan, mullvad, version probes) can't escape the
    global concurrency cap. Every other attribute - including ``Popen``, which
    the nuclei streaming path uses and is gated manually at its call site -
    passes straight through to the real module."""

    def __getattr__(self, name):
        return getattr(_subprocess_real, name)

    def run(self, cmd, **kw):
        tool = "tool"
        try:
            first = cmd[0] if isinstance(cmd, (list, tuple)) and cmd else str(cmd).split()[0]
            tool = os.path.basename(str(first)) or "tool"
        except Exception:
            pass
        run_id = None
        db = getattr(_SUBPROCESS_CONTEXT, "db", None)
        company_id = getattr(_SUBPROCESS_CONTEXT, "cid", "")
        module = getattr(_SUBPROCESS_CONTEXT, "module", "")
        start = time.time()
        if db and hasattr(db, "start_tool_run"):
            try:
                redacted = []
                redact_next = False
                for arg in list(cmd) if isinstance(cmd, (list, tuple)) else str(cmd).split():
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
                        pass


subprocess = _GatedSubprocess()


def _is_responsive(h: dict) -> bool:
    """Standard host liveness check. Uses fields that are actually set during scans:
    status_code (httpx probes), ports (naabu/masscan), title (httpx)."""
    return bool(h.get("status_code") is not None or h.get("ports") or h.get("title"))


def _was_probed(h: dict) -> bool:
    """Whether the host has ever been probed by httpx (has status_code)."""
    return h.get("status_code") is not None


def _mullvad_enabled() -> bool:
    """Mullvad is optional and disabled by default."""
    return str(os.environ.get("ASM_ENABLE_MULLVAD", "")).lower() in {"1", "true", "yes", "on"}


def _classify_result_status(status: str | None, reason: str = "") -> tuple[str, str]:
    """Normalize module/tool status labels into the canonical scan vocabulary."""
    st = (status or "").strip().lower()
    msg = (reason or "").strip()
    msg_l = msg.lower()

    if st in {"done", "error", "timeout", "skipped", "stopped", "running", "queued", "cancelled"}:
        return st, msg

    if any(tok in msg_l for tok in ("no live hosts", "no hosts", "no suitable targets", "no target", "no input")):
        if "live host" in msg_l or "no hosts" in msg_l:
            return "skipped", "No live hosts"
        return "skipped", "No suitable targets"
    if any(tok in msg_l for tok in ("binary not found", "not in registry", "unsupported", "unknown command")):
        return "skipped", "Unsupported or unavailable tool"
    if any(tok in msg_l for tok in ("timeout", "timed out", "context deadline")):
        return "timeout", msg or "timeout"
    if any(tok in msg_l for tok in ("blocked", "rate limit", "429", "too many requests")):
        return "error", "blocked"
    if st:
        return st, msg
    return "done", msg


def _summarize_payload_metrics(payload) -> dict:
    """Best-effort counters for common result shapes."""
    metrics: dict[str, int] = {}
    if isinstance(payload, dict):
        for key in (
            "findings", "subdomains", "hosts", "urls", "emails", "ips",
            "parameters", "results", "entries", "matches", "interesting",
            "vulnerabilities", "files", "services",
        ):
            val = payload.get(key)
            if isinstance(val, list):
                metrics[key] = len(val)
        for key in ("count", "total", "total_urls", "total_certs", "tech_count"):
            val = payload.get(key)
            if isinstance(val, int):
                metrics[key] = val
    elif isinstance(payload, list):
        metrics["items"] = len(payload)
    return metrics


def _normalize_module_envelope(module: str, payload, *, status: str | None = None, reason: str = "") -> dict:
    """Store module output in a stable envelope while preserving raw payload."""
    if isinstance(payload, dict):
        inferred_status = payload.get("status") or status
        inferred_reason = payload.get("reason") or payload.get("error") or reason or ""

        if payload.get("skipped") is True:
            inferred_status = "skipped"
        if payload.get("unsupported") is True:
            inferred_status = "skipped"
            inferred_reason = inferred_reason or "unsupported"
        if payload.get("timeout") is True:
            inferred_status = "timeout"
        if payload.get("blocked") is True and not inferred_reason:
            inferred_reason = "blocked"

        canonical_status, canonical_reason = _classify_result_status(inferred_status, inferred_reason)
        envelope = {
            "module": module,
            "status": canonical_status,
            "reason": canonical_reason,
            "data": payload,
            "metrics": dict(payload.get("metrics") or {}) if isinstance(payload.get("metrics"), dict) else {},
            "artifacts": dict(payload.get("artifacts") or {}) if isinstance(payload.get("artifacts"), dict) else {},
            "blocked": bool(payload.get("blocked", False)),
        }
        if not envelope["metrics"]:
            envelope["metrics"] = _summarize_payload_metrics(payload)
        if not envelope["reason"] and canonical_status != "done":
            envelope["reason"] = canonical_status
        return envelope

    canonical_status, canonical_reason = _classify_result_status(status, reason)
    return {
        "module": module,
        "status": canonical_status,
        "reason": canonical_reason,
        "data": payload,
        "metrics": _summarize_payload_metrics(payload),
        "artifacts": {},
        "blocked": False,
    }


PIPELINE_PHASES = [
    {
        "id":         "discovery",
        "label":      "Fase 1 — Discovery de Superfície",
        "modules":    [
            "subfinder", "assetfinder", "certs", "alienvault_otx",
            "urlscan_io", "rapiddns", "hackertarget", "github_subdomains",
            "wayback", "urlfinder",
        ],
        "rate_phase": "passive",
        "parallel":   True,
        "merge_hosts": True,
    },
    {
        "id":         "validation",
        "label":      "Fase 2 — Validação, DNS e Escopo",
        "modules":    ["dns", "dns_brute", "leaks", "git_leaks"],
        "rate_phase": "dns",
        "parallel":   True,
        "merge_hosts": True,
        "recursive":  True,
    },
    {
        "id":         "intel",
        "label":      "Fase 3 — Intel Útil para Bug Bounty",
        "modules":    [
            "shodan", "postman_collections", "cloud", "container_registry",
            "bulk_dataset", "breach", "phishing", "dep_confusion", "s3_scanner",
        ],
        "rate_phase": "passive",
        "parallel":   True,
    },
    {
        "id":         "cleanup",
        "label":      "Fase 4 — Limpeza e Priorização",
        "modules":    [],
        "rate_phase": "passive",
        "parallel":   False,
        "internal":   True,
    },
    {
        "id":         "fingerprint",
        "label":      "Fase 5 — Fingerprint Web",
        "modules":    [
            "headers", "waf", "wappalyzer", "whatweb", "vendor_fp",
            "service_version", "favicon_hunt", "screenshot", "gowitness",
        ],
        "rate_phase": "tech",
        "parallel":   True,
        "gate":       "has_live_hosts",
    },
    {
        "id":         "js_discovery",
        "label":      "Fase 6 — JS Discovery",
        "modules":    ["js"],
        "rate_phase": "tech",
        "parallel":   False,
        "gate":       "has_live_hosts",
    },
    {
        "id":         "api_mapping",
        "label":      "Fase 7 — APIs, Endpoints e Secrets",
        "modules":    ["js_endpoints", "js_secrets", "api_discovery_extra", "graphql", "jwt_analysis"],
        "rate_phase": "tech",
        "parallel":   True,
        "gate":       "has_live_hosts",
    },
    {
        "id":         "browser",
        "label":      "Fase 8 — Playwright Browser Evidence",
        "modules":    ["browser_crawl", "browser_recon"],
        "rate_phase": "crawl",
        "parallel":   False,
        "gate":       "has_live_hosts",
    },
    {
        "id":         "bug_checks",
        "label":      "Fase 9 — Checks Leves de Bug Bounty",
        "modules":    [
            "takeover", "subjack", "cors_scan", "open_redirect",
            "host_header_injection", "infra_exposure", "cloud_enum",
            "default_creds", "dnssec", "waf_bypass", "tableau",
            "github_repos", "supply_chain", "xss_scan", "salesforce_recon",
        ],
        "rate_phase": "vulnscan",
        "parallel":   True,
        "gate":       "has_live_hosts",
    },
    {
        "id":         "ports_services",
        "label":      "Fase 10 — Portas e Serviços Priorizados",
        "modules":    ["portscan", "cloudlist", "services", "cms_scan", "database_enum_extra"],
        "rate_phase": "portscan",
        "parallel":   True,
        "gate":       "has_live_hosts",
    },
    {
        "id":         "nuclei",
        "label":      "Fase 11 — Templates Curados e Evidência Final",
        "modules":    ["cve", "api_panels", "screenshot_diff"],
        "rate_phase": "vulnscan",
        "parallel":   False,
        "gate":       "has_live_hosts",
    },
]

_MAX_PARALLEL_MODULES = 8  # max concurrent module threads per phase

SELF_CONTAINED_MODULES = {
    "wappalyzer", "dep_confusion",
    "subjack", "cloud_enum", "cloudlist",
    "param_mine", "js_endpoints", "js_secrets",
    "favicon_hunt",
    "urlfinder", "asnmap",
    "subfinder", "assetfinder", "theharvester",
    "whatweb", "gowitness",
}

_SKIP_TECHS = {
    "HSTS", "HTTP/3", "HTTP/2", "DNSSEC", "IPv6",
    "HTTPS Redirect", "WWW Redirect", "Open Graph",
}


def _brand_words(domains: list[str]) -> list[str]:
    """
    Derive extra brand keyword variants from a company's domain list.
    E.g. ['portoseguro.com.br','portobank.com.br'] → ['portobank','porto-bank','portoseguros',...]
    These are swept against all ccTLDs by run_typosquatting to catch
    brand squatting on related product names (portobank.com, porto-bank.uy, etc.)
    """
    import re as _re
    words: set = set()
    for d in domains:
        base = d.split(".")[0]  # e.g. "portoseguro", "portobank", "averbeporto"
        words.add(base)
        # Hyphenated variant: portoseguro → porto-seguro
        split = _re.sub(r"([a-z])([A-Z])", r"\1-\2", base).lower()
        hyphen = _re.sub(r"([a-zA-Z])(?=[A-Z])", r"\1-", base).lower()
        # Simple heuristic: split at common word boundaries
        for pattern in [r"(porto)(seguro|bank|net)", r"(averbe)(porto)"]:
            m = _re.match(pattern, base, _re.I)
            if m:
                words.add(m.group(1) + "-" + m.group(2))
                words.add(m.group(1) + m.group(2) + "s")  # plural
        words.add(base + "s")   # plural form: portoseguros
    # Remove the primary domain base (already covered by _typo_variants)
    primary_base = domains[0].split(".")[0] if domains else ""
    words.discard(primary_base)
    return [w.lower() for w in words if len(w) >= 4]


def _pick_key_domains(domains: list[str], max_count: int = 20) -> list[str]:
    """Select the most important domains: primary first, then distinct apexes.
    Scales to 1000+ domains without overwhelming external APIs."""
    if len(domains) <= max_count:
        return list(domains)
    primary = domains[:1] if domains else []
    apexes = []
    seen = set()
    for d in domains:
        parts = d.split(".")
        apex = ".".join(parts[-2:]) if len(parts) >= 2 else d
        if apex not in seen:
            seen.add(apex)
            apexes.append(d)
    # Deduplicate while preserving insertion order, primary first
    result = list(dict.fromkeys(primary + apexes))[:max_count]
    return result


def _run_certs_all_domains(r, domains: list[str], hosts: list) -> dict:
    """Run cert recon for every domain and merge CT subdomain lists.
    Primary domain gets full recon (CT + SSL). Secondary domains use parallel CT-only.
    """
    from core.recon import get_ct_certs as _get_ct_certs
    from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed

    def _ct_only(d: str) -> dict:
        certs = _get_ct_certs(d)
        ct_subs, seen_d = [], set()
        for c in certs:
            for name in c.get("names", []):
                name = name.strip().lstrip("*.")
                if name.endswith(d) and name not in seen_d:
                    seen_d.add(name)
                    ct_subs.append(name)
        return {"domain": d, "certs": certs, "ct_subdomains": sorted(ct_subs)[:100], "total_certs": len(certs)}

    primary = domains[0] if domains else None
    secondary = domains[1:] if len(domains) > 1 else []

    # Primary domain: full cert recon (CT + SSL probe)
    primary_result: dict = {}
    if primary:
        try:
            primary_result = r.run_cert_recon(primary, hosts)
        except Exception:
            pass

    # Secondary domains: parallel CT-only (8 workers, no SSL)
    secondary_results: list[dict] = []
    if secondary:
        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = {pool.submit(_ct_only, d): d for d in secondary}
            for fut in _as_completed(futs):
                try:
                    secondary_results.append(fut.result())
                except Exception:
                    pass

    # Merge results
    merged = primary_result or {}
    all_ct: list[str] = []
    seen_ct: set[str] = set()
    for sub in merged.get("ct_subdomains", []):
        if sub not in seen_ct:
            seen_ct.add(sub)
            all_ct.append(sub)
    for res in secondary_results:
        for sub in res.get("ct_subdomains", []):
            if sub not in seen_ct:
                seen_ct.add(sub)
                all_ct.append(sub)
        merged["total_certs"] = merged.get("total_certs", 0) + res.get("total_certs", 0)
    merged["ct_subdomains"] = sorted(all_ct)
    return merged or {"ct_subdomains": [], "scanned_at": datetime.now().isoformat(timespec="seconds")}


def _run_wayback_all_domains(r, domains: list[str]) -> dict:
    """Run wayback mining for every domain in parallel and merge interesting URLs."""
    from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed

    all_interesting: list[dict] = []
    all_subdomains: set[str] = set()
    total_urls = 0

    with ThreadPoolExecutor(max_workers=max(1, min(len(domains), _DOMAIN_FANOUT_WORKERS))) as pool:
        futs = {pool.submit(r.run_wayback, d): d for d in domains}
        for fut in _as_completed(futs):
            try:
                result = fut.result()
                all_interesting.extend(result.get("interesting", []))
                all_subdomains.update(result.get("subdomains", []))
                total_urls += result.get("total_urls", 0)
            except Exception:
                pass

    return {
        "total_urls":        total_urls,
        "interesting":       all_interesting,
        "interesting_count": len(all_interesting),
        "subdomains":        sorted(all_subdomains),
        "scanned_at":        datetime.now().isoformat(timespec="seconds"),
    }


def _normalize_finding(finding: dict, source: str = "general") -> dict:
    """Ensure a finding dict has consistent field names for frontend consumption."""
    f = dict(finding)

    # desc: unified description field (frontend reads f.desc)
    if "desc" not in f:
        f["desc"] = f.get("description") or f.get("info") or f.get("issue") or f.get("name") or ""

    # title: fallback chain name → title → key
    if "title" not in f:
        f["title"] = f.get("name") or f.get("key") or f.get("template") or "Untitled"

    # type: dedup classifier, fallback to category or source
    if "type" not in f:
        f["type"] = f.get("category") or source

    # value: dedup anchor, fallback to title or key or url
    if "value" not in f:
        f["value"] = f.get("title") or f.get("key") or f.get("host") or ""

    # module: source module for color-coding in frontend
    if "module" not in f:
        f["module"] = source

    # category: fallback to type or module
    if "category" not in f:
        f["category"] = f.get("type") or source

    # id: unique DOM id (frontend uses f.id for toggle)
    if "id" not in f:
        import hashlib
        raw = f"{f.get('type','')}|{f.get('title','')}|{f.get('host','')}|{f.get('value','')}"
        f["id"] = hashlib.md5(raw.encode()).hexdigest()[:12]

    return f


def _select_browser_targets(hosts: list, domains: list, max_targets: int = 12) -> list[str]:
    """Score and rank hosts to find the most interesting ones for browser recon."""
    INTERESTING_PATTERNS = [
        "login", "auth", "account", "portal", "admin", "dashboard",
        "app", "console", "panel", "api", "sso", "signin", "signup",
        "checkout", "payment", "secure", "manage", "my.",
    ]
    INTERESTING_TECH = {"React", "Vue.js", "Angular", "Next.js", "Nuxt.js", "Svelte"}

    scored: list[tuple[int, str]] = []

    for h in hosts:
        host   = h.get("host", "")
        sc     = h.get("status_code", 0)
        title  = (h.get("title") or "").lower()
        techs  = set(h.get("technologies") or [])
        url    = h.get("url") or f"https://{host}"

        if sc not in (200, 301, 302, 403):
            continue

        score = 0
        if sc == 200:
            score += 3
        if title and title not in ("", "access denied", "403 forbidden", "404"):
            score += 2
        lhost = host.lower()
        for pat in INTERESTING_PATTERNS:
            if pat in lhost:
                score += 4
                break
        if techs & INTERESTING_TECH:
            score += 5
        if techs:
            score += 1

        if score > 0:
            scored.append((score, url))

    seen_domains: set[str] = set()
    selected: list[str] = []
    for _, url in sorted(scored, key=lambda x: -x[0]):
        from urllib.parse import urlparse as _up
        d = _up(url).netloc
        if d not in seen_domains:
            seen_domains.add(d)
            selected.append(url)
        if len(selected) >= max_targets:
            break

    if domains:
        primary = f"https://{domains[0]}"
        if primary not in selected:
            selected.insert(0, primary)

    return selected[:max_targets]


class ReconRunner:
    """Owns recon result state and executes modules / full pipeline."""

    def __init__(
        self,
        *,
        db,
        base_dir: Path,
        get_settings,
        load_hosts_fn,
        recon_module,
        recon_available: bool,
        tool_registry=None,
    ):
        self.db                  = db
        self.base                = base_dir
        self.get_settings        = get_settings
        self._load_hosts         = load_hosts_fn
        self._recon              = recon_module
        self.recon_available     = recon_available
        self._tool_registry      = tool_registry
        self.results: dict        = {}   # "{cid}:{module}" -> result dict
        self.pipeline_state: dict = {}   # cid -> pipeline state dict
        self.tool_logs: dict      = defaultdict(list)  # cid -> [{ts,module,tool,cmd}]
        self._run_context         = threading.local()

    # ── Checkpointing ────────────────────────────────────────────────────────────

    def _checkpoint_dir(self, cid: str) -> Path:
        return self.base / "scans" / cid / ".checkpoints"

    def _checkpoint_key(self, cid: str, module: str, target: str = "") -> str:
        """Build a unique on-disk filename for per-target isolation.
        In-memory key stays as {cid}:{module} regardless of target so that
        _persist_pipeline_results and other consumers find data correctly."""
        return f"{cid}:{module}"

    def _checkpoint_filename(self, module: str, target: str = "") -> str:
        """Disk filename — includes target for per-domain isolation in queue mode."""
        if target:
            return f"{module}__{target}.json"
        return f"{module}.json"

    def _save_checkpoint(self, cid: str, module: str, target: str = ""):
        """Persist a completed module result to disk so it survives server restarts."""
        key = self._checkpoint_key(cid, module, target)
        result = self.results.get(key)
        if not result or result.get("status") != "done":
            return
        try:
            cp_dir = self._checkpoint_dir(cid)
            cp_dir.mkdir(parents=True, exist_ok=True)
            data = dict(result)
            data["module"] = module
            data["target"] = target
            (cp_dir / self._checkpoint_filename(module, target)).write_text(
                json.dumps(data, default=str), encoding="utf-8"
            )
        except Exception as e:
            print(f"[checkpoint] failed to save {key}: {e}")

    def _load_checkpoints(self, cid: str, target: str = ""):
        """Load all saved checkpoints into self.results (called at pipeline start).

        Disk is the source of truth — clear all in-memory results for this company
        first so that deleted checkpoint files actually force a re-run.

        In queue mode (target is set), only load checkpoints for this specific
        domain so that completed modules for domain A do not skip domain B.
        """
        # Evict all in-memory results for this company so deleted files take effect
        stale = [k for k in self.results if k.startswith(f"{cid}:")]
        for k in stale:
            del self.results[k]

        cp_dir = self._checkpoint_dir(cid)
        if not cp_dir.exists():
            return
        loaded = []
        for f in cp_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if data.get("status") != "done":
                    continue
                # In queue mode, skip checkpoints from other domains
                cp_target = data.get("target", "")
                if target and cp_target and cp_target != target:
                    continue
                module = data.get("module", f.stem.split("__")[0])
                key = f"{cid}:{module}"
                self.results[key] = data
                loaded.append(f.stem)
            except Exception:
                pass
        if loaded:
            print(f"[checkpoint] {cid}: retomando {len(loaded)} módulos já concluídos: {loaded}")

    def _delete_checkpoint_file(self, cid: str, module: str) -> None:
        try:
            path = self._checkpoint_dir(cid) / f"{module}.json"
            path.unlink(missing_ok=True)
        except Exception:
            pass

    def _invalidate_checkpoint_modules(self, cid: str, modules: list[str], reason: str = "") -> None:
        if not modules:
            return
        msg = f"[checkpoint] {cid}: invalidando {len(modules)} módulos"
        if reason:
            msg += f" — {reason}"
        print(msg)
        for module in modules:
            self.results.pop(f"{cid}:{module}", None)
            self._delete_checkpoint_file(cid, module)

    @staticmethod
    def _stable_hash(value) -> str:
        try:
            payload = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
        except Exception:
            payload = str(value)
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]

    def _scan_scope_hash(self, co: dict) -> str:
        scope = {
            "name": co.get("name", ""),
            "domains": sorted({str(d).strip().lower() for d in co.get("domains", []) if str(d).strip()}),
        }
        return self._stable_hash(scope)

    def _resolve_pipeline_profile(self, options: dict) -> dict:
        """Apply the single bug-bounty execution profile."""
        resolved = dict(options or {})
        profile_name = "bug_bounty"
        profile = PIPELINE_PROFILES[profile_name]
        for key, value in profile.items():
            resolved.setdefault(key, value)
        resolved["profile"] = profile_name
        resolved["pipeline_profile"] = profile_name
        resolved["active"] = True
        resolved.pop("light", None)
        resolved.pop("phases", None)
        resolved.pop("pipeline_phases", None)
        resolved.setdefault("skip_smart_scan", True)
        return resolved

    def _selected_pipeline_modules(self, options: dict) -> set[str]:
        """Return modules that the current profile/phase selection intends to run."""
        selected: set[str] = set()
        for phase in PIPELINE_PHASES:
            selected.update(list(phase.get("modules") or []))
        return selected

    @staticmethod
    def _compact_failure_text(value: str, *, limit: int = 360) -> str:
        text = re.sub(r"\s+", " ", str(value or "")).strip()
        if not text:
            return ""
        sensitive_patterns = [
            r"(?i)(token|api[_-]?key|secret|password|authorization|bearer)\s*[:=]\s*['\"]?[^'\"\s,;]+",
            r"(?i)(-token|--token|-key|--key)\s+\S+",
        ]
        for pattern in sensitive_patterns:
            text = re.sub(pattern, r"\1=<redacted>", text)
        return text[:limit] + ("..." if len(text) > limit else "")

    def _latest_tool_reason(self, cid: str, module: str) -> dict:
        if not hasattr(self.db, "latest_tool_run"):
            return {}
        try:
            run = self.db.latest_tool_run(cid, module)
        except Exception:
            return {}
        if not run:
            return {}

        status = str(run.get("status") or "").strip().lower()
        exit_code = run.get("exit_code")
        stderr = self._compact_failure_text(run.get("stderr_tail") or "")
        stdout = self._compact_failure_text(run.get("stdout_tail") or "")
        duration = run.get("duration")
        tool = str(run.get("tool") or module)

        detail = ""
        if status == "timeout":
            detail = f"{tool} timed out"
            if duration:
                detail += f" after {float(duration):.1f}s"
        elif stderr:
            detail = f"{tool} stderr: {stderr}"
        elif exit_code not in (None, 0):
            detail = f"{tool} exited with code {exit_code}"
        elif stdout:
            detail = f"{tool} output: {stdout}"
        elif status:
            detail = f"{tool} finished with status '{status}'"
        if exit_code not in (None, 0) and "exit" not in detail.lower():
            detail += f" (exit {exit_code})"

        return {
            "tool": tool,
            "tool_run_id": run.get("id"),
            "tool_status": status,
            "exit_code": exit_code,
            "duration": duration,
            "reason": detail,
        }

    def _pipeline_execution_summary(self, cid: str, options: dict) -> tuple[list[dict], list[dict]]:
        """Return (not_done, skipped) with explicit reasons for every non-done module.

        A module can only be absent from not_done if it either completed or has
        a concrete skip justification (profile/phase/gate). This prevents the
        pipeline from ending with vague "not executed" entries.
        """
        selected_modules = self._selected_pipeline_modules(options or {})
        profile = str((options or {}).get("profile") or "bug_bounty")
        not_done: list[dict] = []
        skipped: list[dict] = []

        for phase in PIPELINE_PHASES:
            phase_id = phase["id"]
            for mod in phase["modules"]:
                if selected_modules and mod not in selected_modules:
                    reason = (
                        f"Skipped by execution profile '{profile}'. "
                        f"This run selected phases/modules only; use profile='bug_bounty' or include phase '{phase_id}' to run it."
                    )
                    skipped.append({
                        "module": mod,
                        "phase": phase_id,
                        "status": "skipped",
                        "reason": reason,
                    })
                    continue

                res = self.results.get(f"{cid}:{mod}", {})
                status = res.get("status", "not_run")
                reason = res.get("reason") or res.get("error") or ""
                tool_reason = self._latest_tool_reason(cid, mod)
                if tool_reason.get("reason") and (not reason or status in {"not_run", "error", "timeout"}):
                    reason = tool_reason["reason"]
                if status == "done":
                    continue
                if status == "skipped" and reason:
                    item = {
                        "module": mod,
                        "phase": phase_id,
                        "status": status,
                        "reason": reason,
                    }
                    item.update({k: v for k, v in tool_reason.items() if k != "reason" and v not in (None, "")})
                    skipped.append(item)
                    continue
                item = {
                    "module": mod,
                    "phase": phase_id,
                    "status": status,
                    "reason": reason or "Module was selected for this run but did not produce a terminal result",
                }
                item.update({k: v for k, v in tool_reason.items() if k != "reason" and v not in (None, "")})
                not_done.append(item)

        return not_done, skipped

    @staticmethod
    def _normalize_scope_name(value: str) -> str:
        value = str(value or "").strip().lower()
        if not value:
            return ""
        if "://" in value:
            value = urlparse(value).netloc or value
        value = value.split("@")[-1].split("/")[0].split(":")[0].strip(".")
        return value

    def _host_in_scope(self, host: str, scopes: set[str]) -> bool:
        host = self._normalize_scope_name(host)
        if not host or not scopes:
            return False
        for scope in scopes:
            if not scope:
                continue
            if host == scope or host.endswith("." + scope):
                return True
        return False

    @staticmethod
    def _bug_bounty_host_score(host: dict) -> int:
        """Prioritize targets that tend to produce actionable bug-bounty reports."""
        name = str(host.get("host") or "").lower()
        title = str(host.get("title") or "").lower()
        server = str(host.get("server") or "").lower()
        waf = str(host.get("waf") or "").lower()
        techs = " ".join(str(t).lower() for t in (host.get("technologies") or host.get("tech") or []))
        haystack = " ".join([name, title, server, techs])
        score = 0

        keyword_weights = {
            "api": 30, "graphql": 35, "swagger": 35, "openapi": 35,
            "auth": 28, "login": 28, "sso": 26, "oauth": 26,
            "admin": 26, "dashboard": 22, "portal": 20, "console": 20,
            "upload": 24, "file": 16, "payment": 24, "billing": 22,
            "staging": 20, "stage": 18, "dev": 18, "test": 16, "qa": 16,
            "internal": 18, "vpn": 16, "jenkins": 24, "gitlab": 24,
            "jira": 18, "grafana": 20, "kibana": 20, "prometheus": 20,
        }
        for key, weight in keyword_weights.items():
            if key in haystack:
                score += weight

        status = host.get("status_code")
        if status in {200, 201, 204}:
            score += 12
        elif status in {301, 302, 307, 308, 401, 403}:
            score += 8
        elif status is not None:
            score += 2
        if host.get("ip"):
            score += 6
        if host.get("ports"):
            score += min(12, len(host.get("ports") or []) * 3)
        if techs:
            score += 8
        if "cloudflare" in waf or "akamai" in waf or "fastly" in waf:
            score -= 3
        if any(tok in haystack for tok in ("s3", "bucket", "blob", "storage")):
            score += 14
        return score

    def _rank_bug_bounty_hosts(self, hosts: list[dict]) -> list[dict]:
        return sorted(
            hosts or [],
            key=lambda h: (
                self._bug_bounty_host_score(h),
                1 if _is_responsive(h) else 0,
                str(h.get("host") or ""),
            ),
            reverse=True,
        )

    def _filter_hosts_for_options(self, hosts: list[dict], co: dict, options: dict) -> list[dict]:
        """Restrict bug bounty jobs to the selected domains/hosts."""
        hosts = [h for h in (hosts or []) if isinstance(h, dict)]
        if not hosts:
            return []
        if options.get("scan_all_hosts"):
            return hosts

        explicit_hosts = {
            self._normalize_scope_name(h)
            for h in (options.get("active_hosts") or options.get("hosts") or [])
            if self._normalize_scope_name(h)
        }
        domains = {
            self._normalize_scope_name(d)
            for d in (options.get("domains") or co.get("domains") or [])
            if self._normalize_scope_name(d)
        }
        active_profile = bool(options.get("active")) or str(options.get("profile", "")) == "bug_bounty"
        scoped_queue_run = bool(options.get("queue_domain"))

        if explicit_hosts:
            filtered = [h for h in hosts if self._normalize_scope_name(h.get("host", "")) in explicit_hosts]
        elif active_profile or scoped_queue_run:
            filtered = [h for h in hosts if self._host_in_scope(h.get("host", ""), domains)]
        else:
            filtered = hosts

        if str(options.get("profile") or "") == "bug_bounty":
            filtered = self._rank_bug_bounty_hosts(filtered)

        if not filtered and active_profile:
            # If the exact domain has not been discovered yet, allow the selected
            # domain itself to be probed by host-based bug bounty modules.
            now = datetime.now().isoformat(timespec="seconds")
            filtered = [
                {
                    "host": d,
                    "status_code": None,
                    "content_length": None,
                    "title": "",
                    "server": "",
                    "ip": "",
                    "technologies": [],
                    "ports": [],
                    "waf": "",
                    "cdn": False,
                    "scope_distance": 0,
                    "source": "profile_scope",
                    "discovered_at": now,
                }
                for d in sorted(domains)
            ]

        max_hosts = int(options.get("active_max_hosts") or 0)
        if max_hosts > 0 and len(filtered) > max_hosts:
            responsive = [h for h in filtered if _is_responsive(h)]
            rest = [h for h in filtered if not _is_responsive(h)]
            filtered = (responsive + rest)[:max_hosts]
        return filtered

    def _host_fingerprint_seed(self, hosts: list[dict]) -> dict:
        seed = []
        for h in hosts or []:
            if not isinstance(h, dict):
                continue
            seed.append({
                "host": (h.get("host") or "").strip().lower(),
                "ip": (h.get("ip") or "").strip(),
                "status_code": h.get("status_code"),
                "title": (h.get("title") or "")[:120],
                "server": (h.get("server") or "")[:120],
                "redirect": (h.get("redirect_url") or h.get("redirect") or "")[:180],
                "ports": sorted({int(p.get("port") if isinstance(p, dict) else p) for p in h.get("ports", []) if str(p.get("port") if isinstance(p, dict) else p).isdigit()}),
                "tech": sorted({str(t).strip().lower() for t in (h.get("tech") or h.get("technologies") or []) if str(t).strip()}),
                "source": (h.get("source") or "")[:80],
            })
        seed.sort(key=lambda item: item.get("host", ""))
        return {"hosts": seed}

    def _host_fingerprint_hash(self, hosts: list[dict]) -> str:
        return self._stable_hash(self._host_fingerprint_seed(hosts))

    def _module_checkpoint_fingerprint(self, cid: str, module: str, co: dict, hosts: list[dict], options: dict) -> str:
        domain = co["domains"][0] if co.get("domains") else ""
        domains = sorted({str(d).strip().lower() for d in co.get("domains", []) if str(d).strip()})
        js_data = co.get("js_data") or {}
        tech_index = co.get("tech_index") or {}
        tech_summary = co.get("tech_summary") or {}
        current_hosts = self._host_fingerprint_seed(hosts)
        js_manifest = []
        for jf in js_data.get("js_files", []) or []:
            if not isinstance(jf, dict):
                continue
            js_manifest.append({
                "url": (jf.get("url") or "")[:250],
                "host": (jf.get("host") or "")[:120],
                "size": jf.get("size"),
                "status": jf.get("status"),
                "source": (jf.get("source") or "")[:40],
                "endpoint_count": len(jf.get("endpoints") or []),
                "secret_count": len(jf.get("secrets") or []),
            })
        js_manifest.sort(key=lambda item: (item.get("host", ""), item.get("url", "")))

        base = {
            "module": module,
            "company": co.get("id", cid),
            "name": co.get("name", ""),
            "domain": domain,
            "domains": domains,
            "options": {
                "mode": options.get("mode"),
                "scan_mode": options.get("scan_mode"),
                "crawl_max_hosts": options.get("crawl_max_hosts"),
            },
            "hosts": current_hosts,
        }

        if module in {"passive", "intel", "supply_chain"}:
            base["domains"] = domains
            base["company_tags"] = sorted({str(t).strip().lower() for t in co.get("tags", []) if str(t).strip()})
        elif module in {"validation", "profiling", "enum_active", "portscan", "services", "vulnscan", "nuclei"}:
            base["live_host_fp"] = self._host_fingerprint_hash(hosts)
        if module in {"profiling", "js_tech", "js_analysis", "crawl", "vulnscan", "nuclei"}:
            base["js_manifest"] = js_manifest
            base["js_hash"] = self._stable_hash(js_manifest)
        if module in {"profiling", "vulnscan", "nuclei"}:
            base["tech_index_hash"] = self._stable_hash(tech_index)
            base["tech_summary_hash"] = self._stable_hash(tech_summary)
        if module in {"portscan", "services", "vulnscan", "nuclei"}:
            base["port_hash"] = self._stable_hash([
                {
                    "host": (h.get("host") or "").strip().lower(),
                    "ip": (h.get("ip") or "").strip(),
                    "ports": sorted({int(p.get("port") if isinstance(p, dict) else p) for p in h.get("ports", []) if str(p.get("port") if isinstance(p, dict) else p).isdigit()}),
                }
                for h in hosts if isinstance(h, dict)
            ])
        if module in {"browser_recon", "browser_crawl"}:
            base["runtime_network_hash"] = self._stable_hash(js_data.get("runtime_network", []))
            base["runtime_js_count"] = js_data.get("runtime_js_count", 0)
        return self._stable_hash(base)

    def _module_checkpoint_is_valid(self, cid: str, module: str, co: dict, hosts: list[dict], options: dict) -> bool:
        res = self.results.get(f"{cid}:{module}") or {}
        if res.get("status") != "done":
            return False
        saved_fp = res.get("fingerprint")
        if not saved_fp:
            return True
        current_fp = self._module_checkpoint_fingerprint(cid, module, co, hosts, options)
        return saved_fp == current_fp

    def clear_checkpoints(self, cid: str):
        """Delete all checkpoints for a company (force fresh scan)."""
        import shutil as _shutil
        cp_dir = self._checkpoint_dir(cid)
        if cp_dir.exists():
            _shutil.rmtree(cp_dir)

    # ── Command logging ──────────────────────────────────────────────────────────

    def _record_tool_log(self, cid: str, module: str, cmd: str):
        tool = cmd.split()[0].split("/")[-1] if cmd else "?"
        self.tool_logs[cid].append({
            "ts":     datetime.now().isoformat(timespec="seconds"),
            "module": module,
            "tool":   tool,
            "binary": cmd.split()[0] if cmd else "",
            "display_name": cmd.split()[0].split("/")[-1] if cmd else tool,
            "cmd":    cmd,
        })

    def _tool_run_payload(self, run: dict) -> dict:
        argv = run.get("argv", []) or []
        binary = str(argv[0]) if argv else str(run.get("tool") or "")
        display_name = Path(binary).name if binary else str(run.get("tool") or "?")
        return {
            "run_id": run.get("id"),
            "ts": run.get("started_at", ""),
            "finished_at": run.get("finished_at", ""),
            "company_id": run.get("company_id", ""),
            "module": run.get("module", ""),
            "tool": run.get("tool", ""),
            "binary": binary,
            "script": binary,
            "display_name": display_name,
            "cmd": " ".join(str(x) for x in argv),
            "argv": argv,
            "status": run.get("status", ""),
            "exit_code": run.get("exit_code"),
            "duration": run.get("duration", 0),
            "stderr_tail": run.get("stderr_tail", ""),
            "stdout_tail": run.get("stdout_tail", ""),
        }

    def _module_log_payload(self, cid: str, module: str, result: dict, *, source: str = "module") -> dict:
        status = result.get("status", "not_run")
        reason = result.get("reason") or result.get("error") or ""
        started = result.get("started_at") or result.get("ts") or ""
        finished = result.get("finished_at") or ""
        duration = result.get("duration", 0)
        stderr = reason if status in ("error", "timeout") else ""
        stdout = reason if status not in ("error", "timeout") else ""
        if not stdout and status in ("done", "skipped"):
            payload = {
                "status": status,
                "reason": reason,
                "metrics": result.get("metrics", {}),
                "data": result.get("data"),
                "artifacts": result.get("artifacts", {}),
                "blocked": result.get("blocked", False),
            }
            try:
                stdout = json.dumps(payload, ensure_ascii=False, indent=2, default=str)[-12000:]
            except Exception:
                stdout = str(payload)[-12000:]
        return {
            "run_id": None,
            "kind": "module",
            "source": source,
            "ts": started or finished,
            "finished_at": finished,
            "company_id": cid,
            "module": module,
            "tool": module,
            "binary": "",
            "script": "",
            "display_name": module,
            "cmd": f"module:{module}",
            "argv": [f"module:{module}"],
            "status": status,
            "exit_code": None,
            "duration": duration,
            "stderr_tail": stderr,
            "stdout_tail": stdout,
        }

    def get_tool_logs(self, cid: str) -> list:
        logs = list(self.tool_logs.get(cid, []))
        if hasattr(self.db, "list_tool_runs"):
            try:
                runs = self.db.list_tool_runs(cid, limit=300)
                for run in runs:
                    logs.append(self._tool_run_payload(run))
            except Exception:
                pass
        seen_modules: set[str] = set()
        for key, result in list(self.results.items()):
            if not key.startswith(f"{cid}:") or not isinstance(result, dict):
                continue
            module = key.split(":", 1)[1]
            status = result.get("status")
            if status in ("done", "error", "timeout", "skipped", "running"):
                logs.append(self._module_log_payload(cid, module, result))
                seen_modules.add(module)
        state = self.pipeline_state.get(cid) or self._load_pipeline_state(cid) or {}
        for item in (state.get("not_done", []) or []) + (state.get("skipped_modules", []) or []):
            if not isinstance(item, dict):
                continue
            module = str(item.get("module") or "").strip()
            if not module or module in seen_modules:
                continue
            logs.append(self._module_log_payload(cid, module, item, source="pipeline_state"))
            seen_modules.add(module)
        return sorted(logs, key=lambda item: item.get("ts", ""), reverse=True)[:300]

    def get_tool_log_detail(self, cid: str, run_id: int) -> dict | None:
        """Return full tool run details including stderr/stdout."""
        if hasattr(self.db, "list_tool_runs"):
            try:
                runs = self.db.list_tool_runs(cid, limit=700)
                if not runs:
                    runs = [
                        r for r in self.db.list_tool_runs("", limit=700)
                        if not str(r.get("company_id") or "").strip()
                    ]
                for run in runs:
                    if run.get("id") == run_id:
                        return self._tool_run_payload(run)
            except Exception:
                pass
        return None

    def clear_tool_logs(self, cid: str):
        self.tool_logs.pop(cid, None)
        # Also evict in-memory pipeline state and results for this company
        self.pipeline_state.pop(cid, None)
        stale = [k for k in self.results if k.startswith(f"{cid}:")]
        for k in stale:
            self.results.pop(k, None)
        if hasattr(self.db, "clear_tool_runs"):
            try:
                self.db.clear_tool_runs(cid)
            except Exception:
                pass

    def _check_blocked_and_rotate(self, cid: str, module: str, proc_stdout: str = "", proc_stderr: str = "", *, forced: bool = False) -> bool:
        """Check if a tool's output indicates rate-limiting/WAF blocking.
        If blocked AND Mullvad is connected, rotate IP and return True (retry needed).
        Set forced=True to skip output check (when blocked was already detected by caller).
        Returns False if no block detected or rotation not possible."""
        if not _mullvad_enabled():
            return False
        try:
            import mullvad_rotator as _mr
        except ImportError:
            return False

        if not forced:
            combined = (proc_stdout + proc_stderr).lower()
            if not combined or not _mr.is_blocked(proc_stdout, proc_stderr):
                return False

        if _mr.is_connected():
            rotator = (getattr(self, "_mullvad_rotators", {}) or {}).get(cid) or _mr._get_default()
            try:
                new_ip = rotator.rotate(wait=15)
                self.pipeline_state[cid]["mullvad_ip"] = new_ip
                msg = f"  🔄 {module}: block detected — IP rotated → {new_ip}, retrying..."
            except Exception as e:
                msg = f"  ⚠ {module}: block detected but rotation failed: {e}"
                self.pipeline_state[cid]["log"].append({"ts": datetime.now().isoformat(timespec="seconds"), "msg": msg})
                return False
            self.pipeline_state[cid]["log"].append({"ts": datetime.now().isoformat(timespec="seconds"), "msg": msg})
            return True
        else:
            msg = f"  ⚠ {module}: block detected — Mullvad not connected, cannot rotate"
            log_list = self.pipeline_state.get(cid, {}).get("log")
            if isinstance(log_list, list):
                log_list.append({"ts": datetime.now().isoformat(timespec="seconds"), "msg": msg})
        return False

    # ── Pipeline state persistence ────────────────────────────────────────────────

    def _save_pipeline_state(self, cid: str):
        """Persist minimal pipeline state to disk so GET /pipeline survives restarts."""
        state = self.pipeline_state.get(cid)
        if not state:
            return
        try:
            state_dir = self.base / "scans" / cid
            state_dir.mkdir(parents=True, exist_ok=True)
            minimal = {k: v for k, v in state.items() if k != "log"}
            minimal["log"] = state.get("log", [])[-200:]
            (state_dir / "pipeline_state.json").write_text(
                json.dumps(minimal, default=str), encoding="utf-8"
            )
        except Exception as e:
            print(f"[pipeline_state] save failed for {cid}: {e}")

    def _load_pipeline_state(self, cid: str) -> dict | None:
        """Load pipeline state from disk (used when in-memory state is absent)."""
        try:
            f = self.base / "scans" / cid / "pipeline_state.json"
            if f.exists():
                return json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            pass
        return None

    # ── Tool-registry helper ─────────────────────────────────────────────────────

    def _run_tool(
        self,
        tool_name: str,
        target: str,
        opts: dict | None = None,
        *,
        cid: str | None = None,
        module: str | None = None,
    ) -> dict:
        """Run a tools.py registry tool and return a findings dict."""
        if not self._tool_registry:
            raise RuntimeError("tool_registry not available")
        tool = self._tool_registry.get(tool_name)
        if not tool:
            raise RuntimeError(f"Tool '{tool_name}' not in registry")
        
        # Inject global settings for API keys mapping
        if opts is None: opts = {}
        if "settings" not in opts:
            opts["settings"] = self.get_settings()
        opts.setdefault("db", self.db)
        # Some pipeline modules fan out into their own ThreadPoolExecutor.
        # threading.local() context does not propagate to those child threads,
        # so accept explicit cid/module to keep command_runner DB logs scoped
        # to the project instead of creating company_id="" orphan rows.
        opts.setdefault("company_id", cid if cid is not None else getattr(self._run_context, "cid", ""))
        opts.setdefault("module", module if module is not None else getattr(self._run_context, "module", tool_name))

        # NOTE: per-tool concurrency gating happens inside command_runner.run()
        # (utils/command_runner.py wraps every subprocess in gate_for(tool).slot()).
        # Do NOT acquire the gate here too — that double-acquires the same
        # non-reentrant gate and deadlocks limit-1 tools (amass/naabu/nuclei…).
        result = tool.run(target, opts)
        out = result.to_dict()
        if result.error:
            raise RuntimeError(result.error)
        return out

    def _api_retry_wrapper(self, func, max_retries: int = 3, base_delay: float = 2.0):
        """Wrapper para chamadas de API com exponential backoff em erros transitórios."""
        last_error = None
        for attempt in range(max_retries):
            try:
                return func()
            except Exception as e:
                last_error = e
                error_str = str(e).lower()
                # Retry em erros transitórios (inclui 502/503 gateway errors)
                transient_codes = ["429", "502", "503", "rate limit", "timeout",
                                   "connection", "timed out", "bad gateway", "service unavailable"]
                if any(code in error_str for code in transient_codes):
                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                        time.sleep(delay)
                        continue
                raise
        raise last_error

    def _check_masscan_permission(self) -> bool:
        """Verifica se masscan pode ser executado com privilégios suficientes."""
        try:
            result = subprocess.run(
                ["masscan", "--version"],
                capture_output=True, timeout=5
            )
            if result.returncode != 0:
                return False
            # Running as root — skip sudo check
            if os.geteuid() == 0:
                return True
            test_result = subprocess.run(
                ["sudo", "-n", "masscan", "--echo"],
                capture_output=True, timeout=5
            )
            return test_result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _run_port_scan_smart(self, hosts: list, cid: str) -> dict:
        """Executa port scan usando masscan (se disponível) ou naabu."""
        # Filter to hosts with a known IP or proven responsive — avoids scanning non-resolving subdomains
        live_hosts = [h for h in hosts if h.get("ip") and _is_responsive(h)]
        if not live_hosts:
            # Broader fallback: any host with an IP (even if not probed yet)
            live_hosts = [h for h in hosts if h.get("ip")]
        if not live_hosts:
            # Last resort: all responsive hosts regardless of IP
            live_hosts = [h for h in hosts if _is_responsive(h)] or hosts

        # Usa masscan só se tiver permissão E muitos hosts (>= 50)
        if self._check_masscan_permission() and len(live_hosts) >= 50:
            try:
                return self._run_masscan_scan(live_hosts)
            except Exception as e:
                pass

        # Fallback para naabu — only scan hosts with confirmed IPs
        return self._recon.run_port_scan(live_hosts)

    def _run_masscan_scan(self, hosts: list) -> dict:
        """Executa masscan com privilégios elevados."""
        ips = list({h.get("ip") or h["host"] for h in hosts if h.get("ip") or h.get("host")})[:100]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(ips))
            tf_path = tf.name

        try:
            cmd = ["sudo", "masscan"] if os.geteuid() != 0 else ["masscan"]
            result = subprocess.run(
                cmd + ["-iL", tf_path, "-p",
                 "21,22,23,25,80,110,143,389,443,445,"
                 "512,513,514,636,1433,1521,2181,2222,2375,2376,2379,"
                 "3000,3306,3389,4243,4443,4848,5000,5432,5601,5900,"
                 "6379,7001,7474,8001,8080,8088,8161,8443,8888,"
                 "9000,9090,9092,9200,9300,10250,10255,11211,"
                 "15672,27017,27018,50000,50070,61616",
                 "-oJ", "-", "--rate", "1000"],
                capture_output=True, text=True, timeout=600
            )
            Path(tf_path).unlink(missing_ok=True)
        except Exception:
            Path(tf_path).unlink(missing_ok=True)
            raise

        results = []
        for line in result.stdout.strip().splitlines():
            try:
                if line.strip().startswith("{"):
                    item = json.loads(line)
                    results.append({
                        "ip": item.get("ip", ""),
                        "port": item.get("port", 0),
                        "proto": item.get("proto", "tcp"),
                        "status": item.get("status", "open"),
                    })
            except Exception:
                pass

        return {"results": results, "tool": "masscan"}

    # ── Internal helpers ────────────────────────────────────────────────────────

    def _run_services(self, hosts: list) -> dict:
        from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
        if not self._recon:
            return {"findings": [], "scanned_at": datetime.now().isoformat(timespec="seconds")}

        targets = [h["host"] for h in hosts if h.get("ports")]
        all_findings: list = []
        with ThreadPoolExecutor(max_workers=10) as pool:
            futs = {pool.submit(self._recon.run_services_recon, h): h for h in targets}
            for fut in _as_completed(futs):
                try:
                    all_findings.extend(fut.result())
                except Exception:
                    pass
        return {
            "findings": sorted(
                all_findings,
                key=lambda x: ["critical", "high", "medium", "low"].index(
                    x.get("severity", "low")
                ),
            ),
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
        }

    def _run_dep_confusion(self, cid: str, co: dict, options: dict) -> dict:
        token = options.get("github_token", "") or self.get_settings().get("github_token", "")
        domains = [str(d).strip() for d in (co.get("domains") or []) if str(d).strip()]
        if not domains:
            return {"status": "skipped", "reason": "No domains available for dependency confusion check"}
        timeout_s = int(os.environ.get("ASM_DEP_CONFUSION_TIMEOUT", "180") or 180)
        script = self.base / "utils" / "dep_confusion.py"
        cmd = ["python3", str(script), *domains[:5], "--company", str(co.get("name") or cid), "--json"]
        env = os.environ.copy()
        if token:
            env["GITHUB_TOKEN"] = token
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "timeout": True,
                "reason": f"dep_confusion exceeded {timeout_s}s and was killed",
                "findings": [],
                "summary": {},
            }
        if result.returncode != 0:
            return {
                "status": "error",
                "reason": (result.stderr or result.stdout or f"dep_confusion exited {result.returncode}")[-1000:],
                "findings": [],
                "summary": {},
            }
        try:
            return json.loads(result.stdout or "{}")
        except Exception:
            return {
                "status": "error",
                "reason": "dep_confusion returned invalid JSON",
                "stdout_tail": (result.stdout or "")[-1000:],
                "findings": [],
                "summary": {},
            }

    def _make_fn_map(self, cid: str, co: dict, options: dict, hosts: list) -> dict:
        """Build the module → callable map for the given execution context."""
        domain = co["domains"][0] if co.get("domains") else ""
        domains = co.get("domains", [domain])
        screenshots_dir = str(self.base / "scans" / cid / "screenshots")
        r = self._recon
        return {
            "email":         lambda: r.run_email_recon(domain),
            "certs":         lambda: _run_certs_all_domains(r, domains, hosts),
            "headers":       lambda: r.run_headers_bulk(hosts),
            "vendor_fp":     lambda: r.run_vendor_fingerprint(hosts),
            "typosquat":     lambda: r.run_typosquatting(
                                 domain,
                                 extra_words=_brand_words(domains),
                             ),
            "cloud":         lambda: r.run_cloud_assets(domains, co.get("name", "")),
            "related":       lambda: r.run_related_domains(domain),
            "reverse_whois": lambda: r.run_reverse_whois(domain, options.get("whoisxml_key", "")),
            "github_subdomains": lambda: r.run_github_subdomains(domains, options.get("github_token", "")),
            "apk_recon":     lambda: r.run_apk_recon(domains, co.get("name", ""),
                                 apk_dir=str(self.base / "scans" / cid / "apks")),
            "origin_discovery": lambda: r.run_origin_discovery(domains, hosts,
                                 options.get("shodan_key", "")),
            "wayback":       lambda: _run_wayback_all_domains(r, domains),
            "waf":           lambda: r.run_waf_detection(hosts),
            "takeover":      lambda: r.run_takeover_check(hosts),
            "breach":        lambda: r.run_breach_check(
                domain, options.get("hibp_key", ""), options.get("dehashed_key", "")
            ),
            "shodan":        lambda: self._api_retry_wrapper(
                lambda: r.run_shodan(hosts, options.get("shodan_key", ""))
            ),
            "portscan":      lambda: self._run_port_scan_smart([h for h in hosts if h.get("ip")], cid),
            "asn":           lambda: r.run_asn_recon(hosts, domain),
            "services":      lambda: self._run_services(hosts),
            "leaks":         lambda: r.run_leaks_recon(domain, hosts, options.get("github_token", "")),
            "postman_collections": lambda: r.run_postman_collections(
                domain, co.get("name", ""), options.get("github_token", "")
            ),
            "dns":           lambda: r.dns_records(domain),
            "cve":           lambda: r.run_cve_lookup(hosts, options.get("nvd_key", "")),
            "vhost":         lambda: r.run_vhost_discovery(hosts, domains),
            "js":            lambda: r.run_js_recon(domains, hosts),
            "screenshot":    lambda: r.run_screenshots(
                hosts, domains, output_dir=screenshots_dir
            ),
            "dns_brute":     lambda: r.run_dns_bruteforce(domain, hosts, mode=options.get("scan_mode", "balanced")),
            "api_panels":    lambda: self.run_api_panels_smart(cid, domain, hosts),
            "certstream":    lambda: self._api_retry_wrapper(
                lambda: r.run_certstream_snapshot(domains, duration_sec=90)
            ),
            "phishing":      lambda: r.run_phishing_monitor(domains, co.get("name", "")),
            "dep_confusion": lambda: self._run_dep_confusion(cid, co, options),
            "wappalyzer":    lambda: self._call_run_wappalyzer(cid, co, hosts, options),
            # ── New tool-registry modules ──────────────────────────────────────
            "subjack":    lambda: self._run_tool(
                "subjack", domain,
                {"hosts": hosts}
            ),
            "cms_scan":   lambda: self.run_cms_scan_smart(cid, domain, options, hosts),
            "cloud_enum": lambda: self._run_tool(
                "cloud_enum",
                re.sub(r"\.", "-", (co.get("name") or domain).lower().split(".")[0]),
            ),
            "param_mine":    lambda: self._run_tool("arjun", domain),
            "js_endpoints":  lambda: self._extract_js_endpoints_from_js_module(cid, domains, hosts),
            "js_secrets":    lambda: self._extract_js_secrets_from_js_module(cid, domains, hosts),
            "favicon_hunt":  lambda: self._api_retry_wrapper(
                lambda: self._run_tool(
                    "favicon_hash", domain,
                    {"shodan_key": options.get("shodan_key", "")},
                )
            ),
            "cloudlist":     lambda: self._run_tool("cloudlist", domain),
            "urlfinder":     lambda: self._run_tool("urlfinder", domain),
            "asnmap":        lambda: self._run_tool("asnmap", domain),
            "zone_transfer": lambda: r.run_zone_transfer(domains),
            # ── Subdomain discovery tools ─────────────────────────────────────
            "subfinder":     lambda: self.run_subfinder(cid, co, domain),
            "assetfinder":   lambda: self.run_assetfinder(cid, co, domain),
            "theharvester":  lambda: self.run_theharvester(cid, co, domain),
            "amass":         lambda: self.run_amass(cid, co, domain),
            "riddler":       lambda: self._run_free_api("riddler", domain),
            "urlscan_io":    lambda: self._run_free_api("urlscan_io", domain),
            "rapiddns":      lambda: self._run_free_api("rapiddns", domain),
            "hackertarget":  lambda: self._run_tool("hackertarget", domain),
            "alienvault_otx": lambda: self._run_tool("alienvault_otx", domain),
            "hunterio":      lambda: self._run_tool("hunterio", domain, {"settings": options}),
            "whatweb":       lambda: self.run_whatweb(cid, co, hosts),
            "gowitness":     lambda: self.run_gowitness(cid, co, hosts),
            "cors_scan":     lambda: r.run_cors_scan(hosts),
            "infra_exposure": lambda: r.run_infra_exposure(hosts),
            "default_creds": lambda: r.run_default_creds(hosts),
            "graphql":       lambda: r.run_graphql_discovery(hosts, domains),
            "browser_recon": lambda: self._browser_recon_wrapper(cid, co, hosts),
            "browser_crawl": lambda: r.run_browser_crawl(
                                 hosts, domains,
                                 max_hosts=int(options.get("crawl_max_hosts", 150))),
            "supply_chain":  lambda: r.run_supply_chain_scan(hosts, options.get("nvd_key", "")),
            "github_repos":  lambda: r.run_github_repos(domains, options.get("github_token", "")),
            "dnssec":        lambda: r.run_dnssec_check(domains),
            "waf_bypass":    lambda: r.run_waf_bypass_test(hosts),
            "smtp_probe":    lambda: r.run_smtp_probe(hosts),
            "snmp_probe":    lambda: r.run_snmp_probe(hosts),
            "host_header_injection": lambda: r.run_host_header_injection(hosts),
            "open_redirect":         lambda: r.run_open_redirect_check(hosts),
            "tableau":               lambda: self._run_tableau_check(hosts),
            # ── GAP modules — passive/active extensions ──────────────────────────
            "container_registry": lambda: r.run_container_registry_scan(
                domains, co.get("name", ""), options.get("docker_token", "")
            ),
            "bulk_dataset":       lambda: r.run_bulk_dataset_scan(
                hosts, domains,
                shodan_key=options.get("shodan_key", ""),
                censys_id=options.get("censys_id", ""),
                censys_secret=options.get("censys_secret", ""),
            ),
            "database_enum_extra": lambda: r.run_database_enum_extra(hosts),
            "service_version":    lambda: r.run_service_version_detect(hosts),
            "udp_portscan":       lambda: r.run_udp_port_scan(hosts),
            "api_discovery_extra": lambda: r.run_api_discovery_extra(hosts, domains),
            "screenshot_diff":    lambda: r.run_screenshot_diff(
                hosts, os.path.join(self.base, "scans", cid, "screenshots"),
                previous_dir=os.path.join(self.base, "scans", cid, "screenshots_prev"),
            ),
            # ── NEW MODULES: gitleaks, S3, JWT, XSS ──────────────────────────────
            "git_leaks":   lambda: r.run_git_leaks(hosts, domains, options.get("github_token", "")),
            "s3_scanner":  lambda: r.run_s3_scanner(domains, co.get("name", "")),
            "jwt_analysis": lambda: r.run_jwt_analysis(hosts, None),
            "xss_scan":    lambda: r.run_xss_scan(hosts, options.get("mode", "balanced")),
            "salesforce_recon": lambda: r.run_salesforce_recon(hosts),
        }

    def _browser_recon_wrapper(self, cid: str, co: dict, hosts: list[dict] | None = None) -> dict:
        """Multi-host browser recon: select interesting targets, run Playwright in parallel."""
        try:
            from core.recon import run_browser_recon
        except ImportError:
            return {"error": "recon module unavailable"}

        hosts  = hosts if hosts is not None else co.get("hosts", [])
        domains = co.get("domains", [])
        screenshot_dir = str(self.base / "scans" / cid / "screenshots")
        Path(screenshot_dir).mkdir(parents=True, exist_ok=True)

        targets = _select_browser_targets(hosts, domains, max_targets=12)
        if not targets:
            return {"error": "No suitable targets found", "hosts": []}

        results_per_host: list[dict] = []
        lock = threading.Lock()

        def _run_one(url: str):
            try:
                r = run_browser_recon(url, screenshot_dir=screenshot_dir, timeout=20)
                with lock:
                    results_per_host.append(r)
            except Exception as e:
                with lock:
                    results_per_host.append({"url": url, "error": str(e)})

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            list(ex.map(_run_one, targets))

        # Aggregate summary
        total_endpoints = sum(len(r.get("api_endpoints", [])) for r in results_per_host)
        total_secrets   = sum(len(r.get("secrets_found", [])) for r in results_per_host)
        total_cookies   = sum(len(r.get("cookies", [])) for r in results_per_host)
        insecure_cookies = sum(
            len([c for c in r.get("cookies", []) if not c.get("httpOnly") or not c.get("secure")])
            for r in results_per_host
        )
        all_tech = list({t for r in results_per_host for t in r.get("technologies", [])})

        return {
            "hosts_scanned": len(results_per_host),
            "total_api_endpoints": total_endpoints,
            "total_secrets": total_secrets,
            "total_cookies": total_cookies,
            "insecure_cookies": insecure_cookies,
            "technologies": all_tech,
            "results": results_per_host,
        }


    # ── Subdomain discovery: subfinder, assetfinder, theHarvester ─────────────────

    def run_subfinder(self, cid: str, co: dict, domain: str) -> dict:
        """Run subfinder on up to 20 key domains in parallel."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        all_subdomains: set[str] = set()
        domains = co.get("domains", [domain])
        any_blocked = False
        _errors: list[str] = []

        # Select key domains: primary + distinct apexes, capped at 20
        _select_domains = _pick_key_domains(domains, 20)
        if len(_select_domains) < len(domains):
            _errors.append(f"subfinder: {len(_select_domains)}/{len(domains)} domains")

        def _scan(d):
            subs = set()
            nonlocal any_blocked
            try:
                out = self._run_tool("subfinder", d, cid=cid, module="subfinder")
                if out.get("blocked"):
                    any_blocked = True
                for f in out.get("findings", []):
                    val = f.get("value") or f.get("host") or ""
                    if val and f.get("type") == "subdomain":
                        subs.add(val)
            except Exception as e:
                _errors.append(f"subfinder({d}): {e}")
            return subs

        # Limit to 8 concurrent subfinder processes to avoid overwhelming APIs
        max_w = min(len(_select_domains), 8)
        with ThreadPoolExecutor(max_workers=max_w) as ex:
            for result in as_completed([ex.submit(_scan, d) for d in _select_domains]):
                all_subdomains.update(result.result())

        subdomains = sorted(all_subdomains)
        return {
            "subdomains":    subdomains,
            "count":         len(subdomains),
            "tool":          "subfinder",
            "blocked":       any_blocked,
            "errors":        _errors,
            "scanned_at":    datetime.now().isoformat(timespec="seconds"),
        }

    def run_assetfinder(self, cid: str, co: dict, domain: str) -> dict:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        all_subdomains: set[str] = set()
        domains = co.get("domains", [domain])
        any_blocked = False
        _errors: list[str] = []

        def _scan(d):
            subs = set()
            nonlocal any_blocked
            try:
                out = self._run_tool("assetfinder", d, cid=cid, module="assetfinder")
                if out.get("blocked"): any_blocked = True
                for f in out.get("findings", []):
                    val = f.get("value") or f.get("host") or ""
                    if val and f.get("type") == "subdomain":
                        subs.add(val)
            except Exception as e:
                _errors.append(f"assetfinder({d}): {e}")
            return subs

        with ThreadPoolExecutor(max_workers=max(1, min(len(domains), _DOMAIN_FANOUT_WORKERS))) as ex:
            for result in as_completed([ex.submit(_scan, d) for d in domains]):
                all_subdomains.update(result.result())

        subdomains = sorted(all_subdomains)
        return {
            "subdomains": subdomains, "count": len(subdomains),
            "tool": "assetfinder", "blocked": any_blocked,
            "errors": _errors,
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
        }

    def run_theharvester(self, cid: str, co: dict, domain: str) -> dict:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        all_subdomains: set[str] = set()
        all_emails: set[str] = set()
        all_ips: set[str] = set()
        domains = co.get("domains", [domain])
        any_blocked = False
        _errors: list[str] = []

        # theHarvester hits public APIs — limit to 5 key domains
        _td = _pick_key_domains(domains, 5)
        if len(_td) < len(domains):
            _errors.append(f"theHarvester: {len(_td)}/{len(domains)} domains")

        def _scan(d):
            subs, emails, ips = set(), set(), set()
            nonlocal any_blocked
            try:
                out = self._run_tool("theHarvester", d, cid=cid, module="theharvester")
                if out.get("blocked"): any_blocked = True
                for f in out.get("findings", []):
                    val = f.get("value") or f.get("host") or ""
                    if f.get("type") == "subdomain" and val:
                        subs.add(val)
                    elif f.get("type") == "email" and f.get("value"):
                        emails.add(f["value"])
                    elif f.get("type") == "ip" and (f.get("value") or f.get("ip")):
                        ips.add(f.get("value") or f.get("ip"))
            except Exception as e:
                _errors.append(f"theHarvester({d}): {e}")
            return subs, emails, ips

        with ThreadPoolExecutor(max_workers=min(len(_td), 4)) as ex:
            for future in as_completed([ex.submit(_scan, d) for d in _td]):
                s, e, i = future.result()
                all_subdomains.update(s)
                all_emails.update(e)
                all_ips.update(i)

        subdomains = sorted(all_subdomains)
        return {
            "subdomains": subdomains, "emails": sorted(all_emails),
            "ips": sorted(all_ips), "count": len(subdomains),
            "tool": "theHarvester", "blocked": any_blocked,
            "errors": _errors,
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
        }

    def run_amass(self, cid: str, co: dict, domain: str) -> dict:
        """Run amass enum passive only on the primary domain + secondary domains
        that have a distinct base (not subdomains of primary).
        Amass is slow — we cap at 4 domains max to avoid timeouts."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        all_subdomains: set[str] = set()
        domains = co.get("domains", [domain])
        # Only scan distinct apex domains (not subdomains of each other)
        apexes = []
        seen = set()
        for d in domains:
            parts = d.split(".")
            if len(parts) >= 2:
                apex = ".".join(parts[-2:])  # e.g. portoseguro.com.br
            else:
                apex = d
            if apex not in seen and len(apexes) < 4:
                seen.add(apex)
                apexes.append(d)
        if len(apexes) < len(domains):
            print(f"  ↳ amass: limitado a {len(apexes)} domínios (de {len(domains)})")

        def _scan(d):
            subs = set()
            try:
                out = self._run_tool("amass", d, cid=cid, module="amass")
                for f in out.get("findings", []):
                    val = f.get("value") or f.get("host") or ""
                    if val and f.get("type") == "subdomain":
                        subs.add(val)
            except Exception:
                pass
            return subs

        with ThreadPoolExecutor(max_workers=min(len(apexes), 4)) as ex:
            for result in as_completed([ex.submit(_scan, d) for d in apexes]):
                all_subdomains.update(result.result())

        subdomains = sorted(all_subdomains)
        return {
            "subdomains": subdomains, "count": len(subdomains),
            "tool": "amass",
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
        }

    def run_bbot(self, cid: str, co: dict, domain: str) -> dict:
        """Run bbot subdomain-enum preset for every company domain."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        all_subdomains: set[str] = set()
        domains = co.get("domains", [domain])

        def _scan(d):
            subs = set()
            try:
                out = self._run_tool("bbot", d, cid=cid, module="bbot")
                for f in out.get("findings", []):
                    val = f.get("value") or f.get("host") or ""
                    if val and f.get("type") == "subdomain":
                        subs.add(val)
            except Exception:
                pass
            return subs

        with ThreadPoolExecutor(max_workers=min(len(domains), 2)) as ex:
            for result in as_completed([ex.submit(_scan, d) for d in domains]):
                all_subdomains.update(result.result())

        subdomains = sorted(all_subdomains)
        return {
            "subdomains": subdomains, "count": len(subdomains),
            "tool": "bbot", "scanned_at": datetime.now().isoformat(timespec="seconds"),
        }

    def _run_free_api(self, api_name: str, domain: str) -> dict:
        """Run a free HTTP-based subdomain API and return results."""
        import httpx
        _rl.wait()  # honor global rate limiter
        all_subdomains: set[str] = set()
        api_label = api_name
        blocked_resp = False

        try:
            if api_name == "riddler":
                # Riddler.io — deprecated (service offline as of 2026)
                # Fallback to a simple HEAD check; if available, scrape normally
                return {"subdomains": [], "count": 0, "tool": "riddler (offline — skipped)",
                        "scanned_at": datetime.now().isoformat(timespec="seconds"),
                        "blocked": False, "deprecated": True}
            elif api_name == "urlscan_io":
                resp = httpx.get(
                    "https://urlscan.io/api/v1/search/",
                    params={"q": f"domain:{domain}", "size": 100},
                    headers={"User-Agent": "ASM-Platform/1.0"},
                    timeout=20,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for r in (data.get("results") or []):
                        page = r.get("page", {})
                        url = page.get("url", "")
                        if url:
                            from urllib.parse import urlparse
                            hostname = urlparse(url).hostname or ""
                            if hostname.endswith("." + domain) or hostname == domain:
                                all_subdomains.add(hostname)
                elif resp.status_code in (429, 403, 503):
                    blocked_resp = True

            elif api_name == "rapiddns":
                resp = httpx.get(
                    f"https://rapiddns.io/subdomain/{domain}?full=1",
                    headers={"User-Agent": "ASM-Platform/1.0"},
                    timeout=25, follow_redirects=True,
                )
                if resp.status_code == 200:
                    import re
                    found = set(re.findall(rf"([a-zA-Z0-9._-]+\.{re.escape(domain)})", resp.text, re.IGNORECASE))
                    all_subdomains.update(found)
                elif resp.status_code in (429, 403, 503):
                    blocked_resp = True

            else:
                api_label = f"{api_name} (unknown)"

        except httpx.TimeoutException:
            blocked_resp = True
        except Exception:
            pass

        subdomains = sorted(all_subdomains)
        out = {
            "subdomains": subdomains, "count": len(subdomains),
            "tool": api_label, "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "blocked": blocked_resp,
        }
        if blocked_resp and not subdomains:
            out["status"] = "done"
            out["reason"] = f"{api_name} API indisponível (bloqueado/offline)"
        return out


    # ── Tech-awareness helpers ────────────────────────────────────────────────────

    def _get_detected_techs(self, cid: str) -> set[str]:
        """Return lowercase set of all technologies detected across all hosts."""
        techs: set[str] = set()
        for h in self._load_hosts(cid):
            for t in h.get("technologies", []):
                techs.add(str(t).lower())
        # Also pull from wappalyzer module result (populated before services phase)
        wap = (self.results.get(f"{cid}:wappalyzer") or {}).get("data") or {}
        for tech_name in wap.get("tech_index", {}).keys():
            techs.add(str(tech_name).lower())
        return techs

    def _get_tech_hosts(self, cid: str, *keywords: str) -> list[dict]:
        """Return hosts where any keyword appears in detected technologies."""
        out = []
        for h in self._load_hosts(cid):
            host_techs = [str(t).lower() for t in h.get("technologies", [])]
            if any(kw in tech for kw in keywords for tech in host_techs):
                out.append(h)
        return out

    # ── Tech-aware CMS scanner ────────────────────────────────────────────────────

    def run_cms_scan_smart(self, cid: str, domain: str, options: dict, hosts: list[dict] | None = None) -> dict:
        """Run CMS-specific scanners only against hosts where that CMS was detected."""
        hosts = hosts or self._load_hosts(cid)
        techs = {
            str(t).lower()
            for h in hosts
            for t in (h.get("technologies") or h.get("tech") or [])
        } or self._get_detected_techs(cid)
        results: dict = {}
        ran: list[str] = []

        # WordPress → wpscan (subprocess, no registry dependency)
        wpscan_bin = shutil.which("wpscan")
        if wpscan_bin and any("wordpress" in t for t in techs):
            wp_hosts = [
                h for h in hosts
                if any("wordpress" in str(t).lower() for t in (h.get("technologies") or h.get("tech") or []))
            ][:5]
            for h in wp_hosts:
                host = h["host"]
                url = f"https://{host}"
                try:
                    _rl.wait()
                    cmd = [wpscan_bin, "--url", url, "--no-update",
                           "--format", "json", "--no-banner", "--random-user-agent"]
                    wpscan_token = options.get("wpscan_token", "") or self.get_settings().get("wpscan_token", "")
                    if wpscan_token:
                        cmd += ["--api-token", wpscan_token]
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    try:
                        out = json.loads(r.stdout)
                        results[host] = {"tool": "wpscan", "output": out}
                        ran.append(f"wpscan:{host}")
                    except Exception:
                        if r.stdout.strip():
                            results[host] = {"tool": "wpscan", "raw": r.stdout[:2000]}
                            ran.append(f"wpscan:{host}")
                except Exception:
                    pass

        # Drupal / Joomla → droopescan (if available)
        droopescan_bin = shutil.which("droopescan")
        if droopescan_bin:
            for cms_kw, scan_type in [("drupal", "drupal"), ("joomla", "joomla")]:
                if any(cms_kw in t for t in techs):
                    cms_hosts = [
                        h for h in hosts
                        if any(cms_kw in str(t).lower() for t in (h.get("technologies") or h.get("tech") or []))
                    ][:3]
                    for h in cms_hosts:
                        host = h["host"]
                        url = f"https://{host}"
                        try:
                            _rl.wait()
                            r = subprocess.run(
                                [droopescan_bin, "scan", scan_type, "-u", url, "--quiet"],
                                capture_output=True, text=True, timeout=180,
                            )
                            results[host] = {"tool": "droopescan", "output": r.stdout[:2000]}
                            ran.append(f"droopescan:{host}")
                        except Exception:
                            pass

        if not ran:
            return {
                "skipped":   True,
                "reason":    "No CMS (WordPress/Drupal/Joomla) detected — cms_scan skipped",
                "techs_seen": sorted(techs)[:20],
                "scanned_at": datetime.now().isoformat(timespec="seconds"),
            }

        return {
            "ran":        ran,
            "results":    results,
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
        }

    # ── JS endpoints extractor (from js module data — no external tool needed) ────

    def _extract_js_endpoints_from_js_module(self, cid: str, domains: list, hosts: list) -> dict:
        """Extract JS endpoints from js module results (already computed, no re-download)."""
        js_result = (self.results.get(f"{cid}:js") or {}).get("data") or {}
        js_files  = js_result.get("js_files", [])

        findings: list[dict] = []
        seen: set[str] = set()
        for jf in js_files:
            host = jf.get("host", "")
            src  = jf.get("url", "")
            for ep in jf.get("endpoints", []):
                if isinstance(ep, dict):
                    path = ep.get("path", "")
                    kind = ep.get("kind", "path")
                else:
                    path = str(ep)
                    kind = "path"
                key = f"{host}:{path}"
                if path and key not in seen:
                    seen.add(key)
                    findings.append({
                        "type": "endpoint", "value": path, "host": host,
                        "severity": "info",
                        "metadata": {"source_url": src, "kind": kind},
                    })

        return {
            "findings":      findings,
            "count":         len(findings),
            "hosts_scanned": len({jf.get("host") for jf in js_files}),
            "js_files_used": len(js_files),
            "tool":          "js_module_extract",
            "scanned_at":    datetime.now().isoformat(timespec="seconds"),
        }

    # ── JS secrets extractor (from js module data — no external tool needed) ─────

    def _extract_js_secrets_from_js_module(self, cid: str, domains: list, hosts: list) -> dict:
        """Extract JS secrets from js module results (already computed, no re-download)."""
        js_result = (self.results.get(f"{cid}:js") or {}).get("data") or {}
        js_files  = js_result.get("js_files", [])

        findings: list[dict] = []
        seen: set[str] = set()
        for jf in js_files:
            host = jf.get("host", "")
            src  = jf.get("url", "")
            for s in jf.get("secrets", []):
                if isinstance(s, dict):
                    val   = str(s.get("value", ""))[:120]
                    stype = s.get("type", "secret")
                    sev   = s.get("severity", "high")
                    ctx   = str(s.get("context", ""))[:200]
                else:
                    val   = str(s)[:120]
                    stype = "secret"
                    sev   = "high"
                    ctx   = ""
                key = f"{host}:{stype}:{val}"
                if val and key not in seen:
                    seen.add(key)
                    findings.append({
                        "type": "secret", "value": val, "host": host,
                        "severity": sev,
                        "metadata": {"secret_type": stype, "source_url": src, "context": ctx},
                    })

        return {
            "findings":      findings,
            "count":         len(findings),
            "hosts_scanned": len({jf.get("host") for jf in js_files}),
            "js_files_used": len(js_files),
            "tool":          "js_module_extract",
            "scanned_at":    datetime.now().isoformat(timespec="seconds"),
        }

    # ── Tech-aware nuclei API panel scanner ───────────────────────────────────────

    def _run_tableau_check(self, hosts: list) -> dict:
        """Check Tableau Server instances for public dashboards and misconfigurations."""
        import urllib.request as _ur
        import ssl as _ssl

        tableau_hosts = [h for h in hosts if "tableau" in h.get("host", "").lower()]
        if not tableau_hosts:
            return {"findings": [], "hosts_checked": 0}

        findings = []
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE

        ENDPOINTS = [
            ("/api/2.3/serverinfo",                              "high",   "Tableau REST API exposed publicly"),
            ("/vizportal/api/web/v1/getPublicViewsForSite",      "high",   "Tableau public views API accessible"),
            ("/views",                                           "medium", "Tableau views directory accessible"),
            ("/#/signin",                                        "info",   "Tableau sign-in page identified"),
        ]

        for h in tableau_hosts:
            host = h.get("host", "")
            scheme = "https" if "443" in str(h.get("ports", [])) or h.get("status_code") else "https"
            base = f"{scheme}://{host}"

            for path, sev, desc in ENDPOINTS:
                try:
                    req = _ur.Request(f"{base}{path}", headers={"User-Agent": "Mozilla/5.0"})
                    with _ur.urlopen(req, timeout=8, context=ctx) as resp:
                        body = resp.read(2000).decode("utf-8", errors="ignore")
                        code = resp.status
                except Exception as e:
                    code = getattr(getattr(e, "code", None), "__int__", lambda: None)() or 0
                    body = ""

                if code and code < 500:
                    is_tableau = any(k in body.lower() for k in ("tableau", "vizportal", "tsm"))
                    findings.append({
                        "type":     "tableau_exposure",
                        "host":     host,
                        "url":      f"{base}{path}",
                        "status":   code,
                        "severity": sev,
                        "title":    f"Tableau: {desc} ({host})",
                        "desc":     f"{desc} at {base}{path} — HTTP {code}. Tableau confirmed: {is_tableau}",
                        "module":   "tableau",
                        "category": "exposure",
                    })
                    if sev in ("high", "critical"):
                        break

        return {"findings": findings, "hosts_checked": len(tableau_hosts)}

    def run_api_panels_smart(self, cid: str, domain: str, hosts: list) -> dict:
        """Run nuclei with template tags filtered to match detected technologies."""
        nuclei_bin = shutil.which("nuclei")
        if not nuclei_bin:
            return {"error": "nuclei not found", "findings": []}

        techs = self._get_detected_techs(cid)

        # Base tags always checked (tech-agnostic high-value panels)
        tags: list[str] = ["exposure", "misconfig", "default-login", "panel", "api"]

        # Conditionally add tech-specific tags
        _TAG_MAP = {
            "spring":          ["spring", "actuator"],
            "tomcat":          ["tomcat", "apache"],
            "jenkins":         ["jenkins"],
            "jira":            ["jira", "atlassian"],
            "confluence":      ["confluence", "atlassian"],
            "graphql":         ["graphql"],
            "wordpress":       ["wordpress"],
            "drupal":          ["drupal"],
            "joomla":          ["joomla"],
            "laravel":         ["laravel"],
            "django":          ["django"],
            "ruby on rails":   ["rails"],
            "asp.net":         ["asp", "iis"],
            "php":             ["php"],
            "nginx":           ["nginx"],
            "iis":             ["iis"],
            "elasticsearch":   ["elastic", "elasticsearch"],
            "kibana":          ["kibana"],
            "redis":           ["redis"],
            "mongodb":         ["mongodb", "mongo"],
            "phpmyadmin":      ["phpmyadmin"],
            "grafana":         ["grafana"],
            "gitlab":          ["gitlab"],
        }
        for tech_kw, extra_tags in _TAG_MAP.items():
            if any(tech_kw in t for t in techs):
                tags.extend(extra_tags)

        tags_str = ",".join(sorted(set(tags)))
        live_hosts = [h["host"] for h in hosts if _is_responsive(h)]
        if not live_hosts:
            return {"skipped": True, "reason": "No live hosts", "findings": []}

        # Write all targets to a temp file and run nuclei once (parallel internally)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(f"https://{h}" for h in live_hosts))
            targets_file = tf.name

        findings = []
        total_timeout = 300
        try:
            _rl.wait()
            import select as _sel
            # nuclei is a heavy local binary (gate limit 1). Hold the gate slot
            # for the whole process lifecycle - Popen returns immediately, so
            # the gate must stay acquired until the proc exits / is killed,
            # otherwise the global cap wouldn't see nuclei as running.
            with _gate_for("nuclei").slot():
                proc = _subprocess_real.Popen(
                    [nuclei_bin, "-l", targets_file,
                     "-tags", tags_str,
                     "-severity", "medium,high,critical",
                     "-jsonl", "-silent", "-no-interactsh",
                     "-timeout", "8", "-c", "10", "-retries", "1"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    text=True,
                )
                deadline = time.time() + total_timeout
                buf = ""
                while True:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    # Use select to avoid blocking past the deadline
                    ready, _, _ = _sel.select([proc.stdout], [], [], min(remaining, 1.0))
                    if ready:
                        chunk = proc.stdout.read(4096)
                        if not chunk:
                            break  # pipe closed = process done
                        buf += chunk
                        while "\n" in buf:
                            line, buf = buf.split("\n", 1)
                            try:
                                item = json.loads(line.strip())
                                host = item.get("host", "").replace("https://", "").replace("http://", "")
                                findings.append({
                                    "host":     host,
                                    "template": item.get("template-id", ""),
                                    "name":     item.get("info", {}).get("name", ""),
                                    "severity": item.get("info", {}).get("severity", "info"),
                                    "url":      item.get("matched-at", ""),
                                    "tags":     item.get("info", {}).get("tags", []),
                                })
                            except Exception:
                                pass
                    elif proc.poll() is not None:
                        break  # process exited, nothing left to read
                if proc.poll() is None:
                    proc.terminate()
                    try: proc.wait(timeout=5)
                    except Exception: proc.kill()
        except Exception:
            pass
        finally:
            Path(targets_file).unlink(missing_ok=True)

        return {
            "findings":   findings,
            "tags_used":  tags_str,
            "techs_seen": sorted(techs)[:20],
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
        }

    def run_whatweb(self, cid: str, co: dict, hosts: list) -> dict:
        """Run whatweb for technology detection."""
        whatweb_bin = shutil.which("whatweb")
        if not whatweb_bin:
            return {"error": "whatweb not found", "results": []}

        targets = [h["host"] for h in hosts if h.get("status_code") or h.get("ports") or h.get("title")]
        if not targets:
            return {"error": "No live hosts found", "results": []}

        try:
            _rl.wait()
            _ct.trace([whatweb_bin, "--log-json", "/dev/stdout"] + targets[:3])

            techs = {}
            batch_size = 10
            for i in range(0, len(targets), batch_size):
                batch = targets[i:i + batch_size]
                try:
                    result = subprocess.run(
                        [whatweb_bin, "--log-json", "/dev/stdout"] + batch,
                        capture_output=True, text=True, timeout=60
                    )
                    for line in result.stdout.strip().splitlines():
                        try:
                            item = json.loads(line)
                            host = item.get("target", "")
                            technologies = item.get("plugins", {})
                            if host:
                                _skip = {"IP", "RedirectLocation", "HTTPServer",
                                         "Script", "HttpOnly", "Cookies"}
                                tech_list = [
                                    t for t, d in technologies.items()
                                    if t not in _skip and isinstance(d, dict)
                                ]
                                if tech_list:
                                    # Use final redirect target as key (strip protocol)
                                    techs[host] = tech_list
                        except Exception:
                            pass
                except Exception:
                    pass  # skip timed-out batch, continue with next

            return {"techs": techs, "scanned_at": datetime.now().isoformat(timespec="seconds")}
        except Exception as e:
            return {"error": str(e), "results": []}

    def run_gowitness(self, cid: str, co: dict, hosts: list) -> dict:
        """Run gowitness v3 (scan file) for screenshot capture."""
        gowitness_bin = shutil.which("gowitness") or (
            str(BIN_DIR / "gowitness") if (BIN_DIR / "gowitness").is_file() else None
        )
        if not gowitness_bin:
            return {"error": "gowitness not found", "results": []}

        targets = [h["host"] for h in hosts if _is_responsive(h)]
        if not targets:
            return {"error": "No live hosts found", "results": []}

        output_dir = self.base / "scans" / cid / "screenshots"
        output_dir.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(targets))
            urls_file = tf.name

        try:
            _ct.trace([gowitness_bin, "scan", "file", "-f", urls_file,
                       "--screenshot-path", str(output_dir), "--threads", "5", "-q"])
            subprocess.run(
                [gowitness_bin, "scan", "file",
                 "-f", urls_file,
                 "--screenshot-path", str(output_dir),
                 "--threads", "5",
                 "-q"],
                capture_output=True, text=True, timeout=300,
            )
        except Exception:
            pass
        finally:
            Path(urls_file).unlink(missing_ok=True)

        # Build host metadata index for enrichment
        host_meta = {h["host"]: h for h in hosts if h.get("host")}

        screenshots = []
        for p in sorted(output_dir.glob("*.png")):
            host = p.stem.replace("_", ".", 2)
            meta = host_meta.get(host, {})
            screenshots.append({
                "host":        host,
                "screenshot":  f"screenshots/{p.name}",
                "status_code": meta.get("status_code"),
                "title":       meta.get("title", ""),
                "ip":          meta.get("ip", ""),
                "server":      meta.get("server", ""),
            })
        return {"screenshots": screenshots, "count": len(screenshots),
                "scanned_at": datetime.now().isoformat(timespec="seconds")}

    # ── Wappalyzer / httpx tech detection ───────────────────────────────────────

    def run_wappalyzer(self, cid: str, co: dict, hosts: list[dict] | None = None, options: dict | None = None) -> dict:
        httpx_bin = str(BIN_DIR / "httpx") if (BIN_DIR / "httpx").is_file() else shutil.which("httpx")
        if not httpx_bin:
            raise RuntimeError(
                "httpx not found in PATH — install: apt install httpx / go install"
            )

        options = options or {}
        hosts_data = hosts if hosts is not None else self._load_hosts(cid)
        domains    = co.get("domains", [])

        # Prefer live hosts (have ports) to maximize tech detection yield
        live    = [h["host"] for h in hosts_data if h.get("host") and h.get("ports")]
        passive = [h["host"] for h in hosts_data if h.get("host") and not h.get("ports")]
        targets = list(dict.fromkeys(domains + live[:150] + passive[:50]))
        if not targets:
            return {"error": "No hosts found — run a scan first", "techs": {}}

        proc = subprocess.run(
            [httpx_bin, "-tech-detect", "-silent", "-json",
             "-timeout", "8",
             "-threads", str(int(os.environ.get("ASM_HTTPX_THREADS", "25") or 25)),
             "-retries", "1",
             "-rate-limit", str(int(os.environ.get("ASM_HTTPX_RATE_LIMIT", "50") or 50))],
            input="\n".join(targets),
            capture_output=True, text=True, timeout=300,
        )

        tech_index: dict[str, list] = {}
        host_techs: dict[str, list] = {}
        errors: list[str] = []

        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row   = json.loads(line)
                url   = row.get("url", "")
                host  = re.sub(r"https?://([^/:]+).*", r"\1", url).lower().rstrip(".")
                techs = [t for t in (row.get("tech", []) or []) if t not in _SKIP_TECHS]
                if host and techs:
                    host_techs[host] = techs
                    for t in techs:
                        tech_index.setdefault(t, [])
                        if host not in tech_index[t]:
                            tech_index[t].append(host)
            except Exception as e:
                errors.append(str(e))

        if tech_index:
            try:
                data = self.db.load_asm_data()
                for co_data in data.get("companies", []):
                    if co_data.get("id") != cid:
                        continue
                    existing = co_data.get("tech_index", {})
                    for t, hs in tech_index.items():
                        existing.setdefault(t, [])
                        for h in hs:
                            if h not in existing[t]:
                                existing[t].append(h)
                    co_data["tech_index"] = existing
                    co_data["tech_summary"] = {
                        t: len(hs) for t, hs in
                        sorted(existing.items(), key=lambda x: -len(x[1]))[:20]
                    }
                    for hobj in co_data.get("hosts", []):
                        hn = hobj.get("host", "")
                        if hn in host_techs:
                            existing_techs = set(hobj.get("technologies", []))
                            existing_techs.update(host_techs[hn])
                            hobj["technologies"] = sorted(existing_techs)
                    break
                self.db.save_asm_data(data)
            except Exception as e:
                errors.append(f"ASM data update failed: {e}")

        return {
            "hosts_scanned":    len(targets),
            "hosts_with_tech":  len(host_techs),
            "tech_count":       len(tech_index),
            "tech_index":       tech_index,
            "errors":           errors,
            "scanned_at":       datetime.now().isoformat(timespec="seconds"),
        }

    def _call_run_wappalyzer(self, cid: str, co: dict, hosts: list[dict], options: dict) -> dict:
        """Call run_wappalyzer while preserving old monkeypatch-compatible arity."""
        try:
            params = inspect.signature(self.run_wappalyzer).parameters
            if len(params) <= 2:
                return self.run_wappalyzer(cid, co)
        except (TypeError, ValueError):
            pass
        return self.run_wappalyzer(cid, co, hosts, options)

    # ── Per-module API request handler ──────────────────────────────────────────

    def run_module_request(self, cid: str, module: str, co: dict, options: dict):
        """Launch one recon module in a background thread. Returns Flask response."""
        job_key = f"{cid}:{module}"
        if self.results.get(job_key, {}).get("status") == "running":
            return jsonify({"error": "Module already running"}), 409

        self.results[job_key] = {
            "status":     "running",
            "started_at": datetime.now().isoformat(timespec="seconds"),
        }

        # resolve which rate_phase this module belongs to
        mode = options.get("mode", _rl.DEFAULT_MODE)
        rate_phase = next(
            (p["rate_phase"] for p in PIPELINE_PHASES if module in p["modules"]),
            "passive",
        )
        limiter = _rl.make_limiter(rate_phase, mode)

        def _run():
            hosts = self._load_hosts(cid)
            self._run_context.cid = cid
            self._run_context.module = module
            _SUBPROCESS_CONTEXT.db = self.db
            _SUBPROCESS_CONTEXT.cid = cid
            _SUBPROCESS_CONTEXT.module = module
            if self._recon and hasattr(self._recon, "set_subprocess_context"):
                try:
                    self._recon.set_subprocess_context(self.db, cid, module)
                except Exception:
                    pass
            _ct.set_tracer(lambda cmd, _m=module: self._record_tool_log(cid, _m, cmd))
            if limiter:
                _rl.set_limiter(limiter)
            try:
                if module not in SELF_CONTAINED_MODULES and not self.recon_available:
                    raise RuntimeError("recon module not available")
                prev = self.results.get(job_key) or {}
                result = self._make_fn_map(cid, co, options, hosts)[module]()
                self.results[job_key] = {
                    "status":      "done",
                    "data":        result,
                    "started_at":  prev.get("started_at", ""),
                    "finished_at": datetime.now().isoformat(timespec="seconds"),
                }
            except Exception as e:
                prev = self.results.get(job_key) or {}
                self.results[job_key] = {
                    "status":      "error",
                    "error":       str(e),
                    "started_at":  prev.get("started_at", ""),
                    "finished_at": datetime.now().isoformat(timespec="seconds"),
                }
            finally:
                self._run_context.cid = ""
                self._run_context.module = ""
                _SUBPROCESS_CONTEXT.db = None
                _SUBPROCESS_CONTEXT.cid = ""
                _SUBPROCESS_CONTEXT.module = ""
                if self._recon and hasattr(self._recon, "set_subprocess_context"):
                    try:
                        self._recon.set_subprocess_context(None, "", "")
                    except Exception:
                        pass
                _ct.clear_tracer()
                _rl.clear_limiter()

        threading.Thread(target=_run, daemon=True).start()
        return jsonify({"ok": True, "module": module, "company_id": cid}), 202

    # ── Pipeline helpers ─────────────────────────────────────────────────────────

    # ── Cross-domain false positive validation ─────────────────────────────────

    # Compiled once: TLD patterns for cert-transparency noise detection
    _CROSS_DOMAIN_RE = re.compile(
        r'\.(com\.br|org\.br|net\.br|gov\.br|edu\.br|com|org|net|edu|gov|'
        r'io|co|ai|dev|app|info|biz|br|uk|de|jp|fr|cn|ru|it|es|nl|se|ch|pl|'
        r'be|at|no|dk|fi|pt|ie|cz|hu|ro|bg|sk|hr|si|lt|lv|ee|lu|mt|cy|gr)'
    )

    def _is_cross_domain_noise(self, subdomain: str, domains: list[str]) -> bool:
        """Returns True if subdomain is a cross-domain cert-transparency false positive.
        WHOIS cross-check: if the foreign domain has same owner → keep it."""
        for d in domains:
            if subdomain == d or subdomain.endswith(f".{d}"):
                if subdomain == d:
                    return False
                prefix = subdomain[:-len(f".{d}")]

                # Filter: prefix is an IP → noise
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', prefix):
                    return True

                # Filter: prefix has 3+ dots AND contains 3+ digits → noise
                if prefix.count('.') >= 3 and re.search(r'\d{3,}', prefix):
                    return True

                # Check if prefix contains a foreign TLD
                m = self._CROSS_DOMAIN_RE.search(prefix)
                if not m:
                    return False  # No TLD → legitimate subdomain

                # Extract the foreign domain: everything from the last
                # non-TLD segment through the TLD end
                # e.g. prefix="www.boletimsec.com.br" → foreign="boletimsec.com.br"
                tld_match = m.group(0)  # e.g. ".com.br"
                end_idx   = m.start() + len(tld_match)
                before    = prefix[:m.start()]  # "www.boletimsec"
                segs      = before.rstrip('.').split('.')
                foreign   = (segs[-1] if segs else '') + tld_match

                if not foreign or foreign == tld_match:
                    return False

                # ── WHOIS cross-check ──
                if self._same_owner_whois(d, foreign):
                    return False  # Same owner → keep

                return True  # Different owner or WHOIS failed → noise
        return False

    def _same_owner_whois(self, domain_a: str, domain_b: str) -> bool:
        """WHOIS owner check disabled — too slow for bulk subdomain filtering.
        Cross-domain noise that slips through will fail httpx probing anyway."""
        return False

    def _collect_new_subdomains(self, cid: str, domain: str, all_domains: list[str] | None = None) -> list[str]:
        subs: set = set()
        check_domains = all_domains or [domain]

        def _grab(module_key: str, *paths):
            data = (self.results.get(f"{cid}:{module_key}") or {}).get("data") or {}
            for path in paths:
                val = data
                for key in path.split("."):
                    val = val.get(key, {}) if isinstance(val, dict) else {}
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, str):
                            subs.add(item.strip().lower().lstrip("*."))
                        elif isinstance(item, dict):
                            h = (
                                item.get("host")
                                or item.get("domain")
                                or item.get("name")
                                or item.get("value")
                                or ""
                            )
                            if h:
                                subs.add(h.strip().lower().lstrip("*."))

        # ── Passive subdomain modules ─────────────────────────────────────────
        _grab("certs",          "ct_subdomains")
        _grab("dns_brute",      "findings")
        _grab("leaks",          "git_exposed")
        _grab("related",        "found")
        _grab("subfinder",      "subdomains")
        _grab("assetfinder",    "subdomains")
        _grab("theharvester",   "subdomains")
        _grab("zone_transfer",  "subdomains")
        _grab("amass",          "subdomains")
        _grab("riddler",        "subdomains")
        _grab("urlscan_io",     "subdomains")
        _grab("subdomains")
        _grab("rapiddns",       "subdomains")

        # ── Intel / OSINT sources ─────────────────────────────────────────────
        _grab("shodan",         "hosts")
        _grab("certstream",     "subdomains")

        # ── Wayback (historical URLs → extract hostnames) ─────────────────────
        wayback_data = (self.results.get(f"{cid}:wayback") or {}).get("data") or {}
        for url_str in (wayback_data.get("interesting") or []):
            if isinstance(url_str, dict):
                url_str = url_str.get("url", "")
            if isinstance(url_str, str) and url_str:
                try:
                    h = urlparse(url_str).hostname
                    if h:
                        subs.add(h.strip().lower().lstrip("*."))
                except Exception:
                    pass

        # ── URLFinder (URLs → extract hostnames) ──────────────────────────────
        urlfinder_data = (self.results.get(f"{cid}:urlfinder") or {}).get("data") or {}
        for item in (urlfinder_data.get("urls") or []):
            if isinstance(item, str):
                try:
                    h = urlparse(item).hostname
                    if h:
                        subs.add(h.strip().lower().lstrip("*."))
                except Exception:
                    pass

        # ── JS extraction (embedded URLs → extract hostnames) ─────────────────
        js_data = (self.results.get(f"{cid}:js") or {}).get("data") or {}
        for js_file in (js_data.get("js_files") or []):
            if not isinstance(js_file, dict):
                continue
            # From URLs found in JS content
            for u in (js_file.get("urls") or []):
                url_str = u.get("url") if isinstance(u, dict) else str(u)
                try:
                    h = urlparse(url_str).hostname
                    if h:
                        subs.add(h.strip().lower().lstrip("*."))
                except Exception:
                    pass
            # From endpoints
            for ep in (js_file.get("endpoints") or []):
                url_str = ep.get("url") or ep.get("endpoint") or (str(ep) if isinstance(ep, str) else "")
                try:
                    h = urlparse(url_str).hostname
                    if h:
                        subs.add(h.strip().lower().lstrip("*."))
                except Exception:
                    pass

        # ── JS endpoints module result ────────────────────────────────────────
        js_ep_data = (self.results.get(f"{cid}:js_endpoints") or {}).get("data") or {}
        for f in (js_ep_data.get("findings") or []):
            if isinstance(f, dict):
                val = f.get("value") or f.get("url") or ""
                try:
                    h = urlparse(val).hostname
                    if h:
                        subs.add(h.strip().lower().lstrip("*."))
                except Exception:
                    pass

        # ── API panels (nuclei findings with URLs) ────────────────────────────
        api_data = (self.results.get(f"{cid}:api_panels") or {}).get("data") or {}
        for f in (api_data.get("findings") or []):
            if isinstance(f, dict):
                val = f.get("url") or f.get("host") or ""
                if val:
                    try:
                        h = urlparse(val).hostname
                        if not h and not val.startswith("http"):
                            h = val.strip().lower().lstrip("*.")
                    except Exception:
                        if isinstance(val, str) and "." in val:
                            subs.add(val.strip().lower().lstrip("*."))
                    if h:
                        subs.add(h.strip().lower().lstrip("*."))

        # ── Scan ALL module results for any 'subdomains' or 'hosts' key ───────
        # Snapshot keys to avoid RuntimeError if another pipeline thread modifies self.results
        for (mod_key, wrapper) in list(self.results.items()):
            if not mod_key.startswith(f"{cid}:"):
                continue
            mod_name = mod_key.split(":", 1)[1]
            # Skip ones we already processed explicitly
            if mod_name in ("certs", "dns_brute", "leaks", "related", "subfinder",
                            "assetfinder", "theharvester", "zone_transfer", "amass",
                            "riddler", "urlscan_io", "rapiddns", "shodan", "certstream", "wayback", "urlfinder",
                            "js", "js_endpoints", "api_panels"):
                continue
            data = (wrapper.get("data") or {})
            if isinstance(data, dict):
                for key in ("subdomains", "hosts", "dns_names"):
                    arr = data.get(key, [])
                    if isinstance(arr, list):
                        for item in arr:
                            if isinstance(item, str):
                                subs.add(item.strip().lower().lstrip("*."))
                            elif isinstance(item, dict):
                                h = item.get("host") or item.get("domain") or item.get("name") or ""
                                if h:
                                    subs.add(h.strip().lower().lstrip("*."))

        # ── Validate subdomains ─────────────────────────────────────────────────
        try:
            from validators import filter_subdomain
            subs = {filter_subdomain(s, d) for s in subs for d in check_domains}
            subs.discard(None)
        except ImportError:
            valid = {
                s for s in subs
                if s and any(s.endswith(f".{d}") or s == d for d in check_domains)
            }
            subs = valid

        # ── Remove cross-domain cert-transparency false positives ──────────
        # e.g. boletimsec.com.br.hackersec.com — pertence ao boletimsec, nao hackersec
        filtered = {s for s in subs if not self._is_cross_domain_noise(s, check_domains)}
        return sorted(filtered)

    def _normalize_discovered_hosts(self, hosts: list[str], company_domains: list[str]) -> list[str]:
        """Normalize, scope-filter and deduplicate discovered host candidates."""
        normalized: list[str] = []
        seen: set[str] = set()
        try:
            from validators import filter_subdomain
        except ImportError:
            filter_subdomain = None

        for raw in hosts or []:
            host = ""
            if isinstance(raw, str):
                host = raw.strip().lower().lstrip("*.")
            elif isinstance(raw, dict):
                host = (
                    raw.get("host")
                    or raw.get("domain")
                    or raw.get("name")
                    or raw.get("value")
                    or raw.get("url")
                    or ""
                )
                host = str(host).strip().lower().lstrip("*.")
                if host.startswith("http://") or host.startswith("https://"):
                    try:
                        parsed = urlparse(host)
                        host = (parsed.hostname or "").strip().lower().lstrip("*.")
                    except Exception:
                        host = ""
            if not host or host in seen:
                continue

            if filter_subdomain and company_domains:
                try:
                    scoped = [filter_subdomain(host, d) for d in company_domains]
                    scoped = [s for s in scoped if s]
                    if not scoped:
                        continue
                    host = scoped[0]
                except Exception:
                    pass
            elif company_domains and not any(host == d or host.endswith(f".{d}") for d in company_domains):
                continue

            if company_domains and self._is_cross_domain_noise(host, company_domains):
                continue

            seen.add(host)
            normalized.append(host)
        return normalized

    def _upsert_discovered_hosts(
        self,
        cid: str,
        hosts: list[str],
        company_domains: list[str],
        source: str = "discovery",
    ) -> list[str]:
        """Persist newly discovered hosts before validation so they are never lost."""
        normalized = self._normalize_discovered_hosts(hosts, company_domains)
        if not normalized:
            return []

        try:
            data = self.db.load_asm_data()
        except Exception:
            return normalized

        now_ts = datetime.now().isoformat(timespec="seconds")
        changed = False
        for co in data.get("companies", []):
            if co.get("id") != cid:
                continue
            existing = {
                h.get("host"): h for h in co.get("hosts", [])
                if isinstance(h, dict) and h.get("host")
            }
            for host in normalized:
                if host in existing:
                    continue
                co.setdefault("hosts", []).append({
                    "host": host,
                    "status_code": None,
                    "content_length": None,
                    "title": "",
                    "server": "",
                    "ip": "",
                    "technologies": [],
                    "ports": [],
                    "waf": "",
                    "cdn": False,
                    "scope_distance": 0,
                    "source": source,
                    "discovered_at": now_ts,
                })
                changed = True
            if changed:
                co.setdefault("stats", {})
                co["stats"]["subdomains"] = len(co.get("hosts", []))
                co["stats"]["live_hosts"] = len([h for h in co.get("hosts", []) if _is_responsive(h)])
                co["generated"] = now_ts
            break

        if changed:
            try:
                self.db.save_asm_data(data)
            except Exception:
                pass

        return normalized

    def _probe_hosts_with_httpx(self, subdomains: list[str], cid: str, extra_headers: list[str] | None = None, _expand_redirects: bool = True) -> list[dict]:
        print(f"[DEBUG] _probe_hosts_with_httpx called with {len(subdomains)} subdomains for {cid}")
        httpx_bin = str(BIN_DIR / "httpx") if (BIN_DIR / "httpx").is_file() else shutil.which("httpx")
        if not httpx_bin or not subdomains:
            print(f"[DEBUG] httpx_bin={httpx_bin}, subdomains={len(subdomains) if subdomains else 0}")
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(subdomains))
            tf_path = tf.name

        # Scale timeout: 2s per subdomain, min 300s, max 3600s
        probe_timeout = max(300, min(3600, len(subdomains) * 2))
        try:
            httpx_threads = str(int(os.environ.get("ASM_HTTPX_THREADS", "25") or 25))
            httpx_rate = str(int(os.environ.get("ASM_HTTPX_RATE_LIMIT", "50") or 50))
            cmd = [httpx_bin, "-l", tf_path, "-silent", "-json",
                 "-status-code", "-title", "-server", "-tech-detect", "-content-length",
                 "-ports", "80,443,3000,5601,8080,8443,8888,9000,9090,9200",
                 "-follow-redirects", "-max-redirects", "3", "-location",
                 "-timeout", "8", "-threads", httpx_threads, "-rate-limit", httpx_rate]
            # Inject custom headers (e.g., User-Agent, Accept-Language for WAF bypass)
            if extra_headers:
                for h in extra_headers:
                    cmd.insert(1, "-H"); cmd.insert(2, h)
            result = subprocess.run(cmd,
                capture_output=True, text=True, timeout=probe_timeout,
            )
            Path(tf_path).unlink(missing_ok=True)
        except Exception as e:
            import traceback
            Path(tf_path).unlink(missing_ok=True)
            print(f"ERROR in _probe_hosts_with_httpx: {e}")
            traceback.print_exc()
            return []

        print(f"[DEBUG] httpx completed, stdout has {len(result.stdout.strip().splitlines())} lines")
        # Collect all ports per host (httpx emits one JSON line per port/scheme combo)
        host_data: dict[str, dict] = {}
        for line in result.stdout.strip().splitlines():
            try:
                item = json.loads(line)
                host = (
                    item.get("input", "")
                    .split(":")[0]
                    .replace("https://", "")
                    .replace("http://", "")
                )
                if not host:
                    continue
                port = "443" if item.get("scheme") == "https" else "80"
                a_records = item.get("a") or []
                ip = a_records[0] if a_records else ""
                if host not in host_data:
                    # Derive WAF/CDN status from httpx results
                    cdn_name = item.get("cdn_name", "")
                    waf_status = "Unknown"
                    if item.get("cdn") and cdn_name:
                        waf_status = f"CDN:{cdn_name}"
                    elif item.get("waf"):
                        waf_status = "WAF"
                    
                    final_url = item.get("final_url") or item.get("location") or ""
                    host_data[host] = {
                        "host":           host,
                        "ip":             ip,
                        "waf":            waf_status,
                        "technologies":   item.get("tech", []) or [],
                        "ports":          [],
                        "status_code":    item.get("status_code"),
                        "content_length": item.get("content_length"),
                        "title":          (item.get("title") or "")[:120],
                        "server":         item.get("webserver", ""),
                        "scope_distance": 0,
                        "cdn":            bool(item.get("cdn")),
                        "redirect_url":   str(final_url)[:200],
                    }
                if port not in host_data[host]["ports"]:
                    host_data[host]["ports"].append(port)
                # Prefer HTTPS IP if available
                if ip and not host_data[host]["ip"]:
                    host_data[host]["ip"] = ip
            except Exception:
                continue
        print(f"[DEBUG] _probe_hosts_with_httpx returning {len(host_data)} hosts")

        # ── WAF block detection: if >70% of hosts share the same IP and return 403 → blocked ──
        results_list = list(host_data.values())
        if len(results_list) >= 5:
            ip_counts: dict[str, int] = {}
            ip_403: dict[str, int] = {}
            for h in results_list:
                ip = h.get("ip", "")
                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                    if h.get("status_code") == 403:
                        ip_403[ip] = ip_403.get(ip, 0) + 1
            for ip, count in ip_counts.items():
                blocked_ratio = ip_403.get(ip, 0) / count if count > 0 else 0
                if count >= 5 and blocked_ratio > 0.7:
                    print(f"[WAF] _probe_hosts_with_httpx: {count} hosts on IP {ip} — {blocked_ratio*100:.0f}% 403 → WAF block suspected")
                    # Mark all hosts on this IP as WAF-blocked
                    for h in results_list:
                        if h.get("ip") == ip:
                            h["waf"] = "WAF Block"

        # ── In-scope redirect expansion ──────────────────────────────────────
        # When an in-scope host 3xx-redirects to a DIFFERENT domain that is also
        # owned by the company (in the scope list), follow it and probe the
        # target too. Redirects to third-party domains are ignored (scope-safe).
        if _expand_redirects:
            domains = self._company_domains(cid)
            if domains:
                already = {h["host"] for h in results_list}
                already |= {str(s).split("://")[-1].split("/")[0].split(":")[0].lower() for s in subdomains}
                targets: set[str] = set()
                for h in results_list:
                    rh = self._redirect_host(h.get("redirect_url"))
                    if rh and rh != h["host"] and rh not in already and self._host_in_scope(rh, domains):
                        targets.add(rh)
                if targets:
                    print(f"[redirect] {len(targets)} in-scope redirect target(s) to probe for {cid}")
                    extra = self._probe_hosts_with_httpx(sorted(targets), cid, extra_headers, _expand_redirects=False)
                    for e in extra:
                        e["via_redirect"] = True
                    results_list.extend(extra)
        return results_list

    @staticmethod
    def _redirect_host(final_url: str | None) -> str:
        """Extract the bare hostname from an httpx final_url / Location value."""
        if not final_url:
            return ""
        return str(final_url).split("://")[-1].split("/")[0].split(":")[0].strip().lower()

    def _host_in_scope(self, host: str, domains: list[str]) -> bool:
        """True if host equals or is a subdomain of any company scope domain."""
        h = (host or "").lower()
        return any(h == d or h.endswith("." + d) for d in (domains or []) if d)

    def _company_domains(self, cid: str) -> list[str]:
        """Full scope domain list for a company (used for redirect scope checks)."""
        try:
            data = self.db.load_asm_data()
            for co in data.get("companies", []):
                if co.get("id") == cid:
                    return [str(d).strip().lower() for d in (co.get("domains") or []) if str(d).strip()]
        except Exception:
            pass
        return []

    def _merge_hosts_into_asm_data(self, cid: str, new_hosts: list[dict]) -> int:
        try:
            data = self.db.load_asm_data()
            company_domains = []
            for co in data.get("companies", []):
                if co.get("id") == cid:
                    company_domains = co.get("domains", [])
                    existing_map = {
                        h["host"]: h for h in co.get("hosts", [])
                        if isinstance(h, dict) and h.get("host")
                    }
                    for h in new_hosts:
                        hostname = h["host"]
                        # ── Gate: skip cross-domain cert-transparency noise ──
                        if self._is_cross_domain_noise(hostname, company_domains):
                            continue
                        if hostname not in existing_map:
                            co.setdefault("hosts", []).append(h)
                            existing_map[hostname] = h
                        else:
                            # Update fields that may have been null on first probe
                            ex = existing_map[hostname]
                            if h.get("status_code") is not None and ex.get("status_code") is None:
                                ex["status_code"] = h["status_code"]
                            if h.get("title") and not ex.get("title"):
                                ex["title"] = h["title"]
                            if h.get("server") and not ex.get("server"):
                                ex["server"] = h["server"]
                            if h.get("ip") and not ex.get("ip"):
                                ex["ip"] = h["ip"]
                            if h.get("technologies"):
                                existing_techs = set(ex.get("technologies") or [])
                                for t in h["technologies"]:
                                    existing_techs.add(t)
                                ex["technologies"] = list(existing_techs)
                        target = existing_map[hostname]
                        for port in h.get("ports", []):
                            if port not in target.get("ports", []):
                                target.setdefault("ports", []).append(port)
                    co.setdefault("stats", {})
                    co["stats"]["live_hosts"] = len([item for item in co.get("hosts", []) if _is_responsive(item)])
                    co["stats"]["subdomains"] = len(co["hosts"])
                    co["generated"] = datetime.now().isoformat(timespec="seconds")
                    total = len(co["hosts"])
                    break
            else:
                # Company not found in asm_data_state — skip, do not auto-create
                return 0
            self.db.save_asm_data(data)
            return total
        except Exception as e:
            import traceback
            print(f"ERROR in _merge_hosts_into_asm_data: {e}")
            traceback.print_exc()
            return 0

    def _auto_cleanup_phase(self, cid: str, domain: str, _log) -> dict:
        """Fase 2 automática: remove cPanel junk e NXDOMAIN mortos."""
        hosts = self._load_hosts(cid)
        if not hosts:
            _log("  🧹 Fase 2 Cleanup: nenhum host para limpar")
            return {"removed": [], "remaining": 0}

        original_count = len(hosts)

        # Padrões de cPanel junk (aprendidos do hackersec.com scan)
        cpanel_patterns = [
            r'.*\.com\.br\.' + re.escape(domain),
            r'autodiscover\..*\.cpanel\..*',
            r'cpcalendars\..*\.cpanel\..*',
            r'cpcontacts\..*\.cpanel\..*',
            r'webdisk\..*\.cpanel\..*',
            r'.*\.webmail\.' + re.escape(domain),
            r'.*\.mail\.' + re.escape(domain) + r'\..*',
        ]

        removed = []
        filtered_hosts = []

        for h in hosts:
            host = h["host"]
            is_junk = False

            for pattern in cpanel_patterns:
                if re.match(pattern, host, re.IGNORECASE):
                    removed.append({"host": host, "reason": "cpanel_junk"})
                    is_junk = True
                    break

            if not is_junk:
                filtered_hosts.append(h)

        if removed:
            self._update_hosts(cid, filtered_hosts)

            for r in removed:
                try:
                    self.db.append_audit_log({
                        "ts": datetime.now().isoformat(timespec="seconds"),
                        "user": "system",
                        "action": "cleanup_auto",
                        "target": r["host"],
                        "details": f"Removed: {r['reason']}",
                    })
                except Exception:
                    pass

        removed_count = len(removed)
        remaining_count = len(filtered_hosts)

        if removed_count > 0:
            _log(f"  🧹 Fase 2 Cleanup: {removed_count} subdomínios removidos (cPanel junk), {remaining_count} restantes")
        else:
            _log(f"  🧹 Fase 2 Cleanup: nenhum subdomínio removido")

        return {"removed": removed, "remaining": remaining_count}

    def _update_hosts(self, cid: str, hosts: list[dict]) -> None:
        """Atualiza a lista de hosts de uma empresa no banco."""
        try:
            data = self.db.load_asm_data()
            for co in data.get("companies", []):
                if co.get("id") != cid:
                    continue
                co["hosts"] = hosts
                co.setdefault("stats", {})
                co["stats"]["live_hosts"] = len([h for h in hosts if _is_responsive(h)])
                co["stats"]["subdomains"] = len(hosts)
                co["generated"] = datetime.now().isoformat(timespec="seconds")
                break
            self.db.save_asm_data(data)
        except Exception as e:
            pass

    # ── Recursive enumeration ────────────────────────────────────────────────────

    def _recursive_enum(
        self,
        cid: str,
        co: dict,
        options: dict,
        new_subdomains: list[str],
        depth: int,
        _log,
    ) -> int:
        """For each new subdomain run dns_brute to find sub-subdomains (max 2 levels).
        Runs all subdomains at this depth in parallel to avoid serial wait."""
        if depth >= 2 or not new_subdomains:
            return 0

        from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed

        total_added = 0
        subs_to_recurse = new_subdomains[:20]

        def _enum_one(sub: str) -> tuple[str, list[str]]:
            fake_co = dict(co, domains=[sub])
            hosts   = self._load_hosts(cid)
            fn_map  = self._make_fn_map(cid, fake_co, options, hosts)

            _log(f"    ↳ [recurse d{depth+1}] Enumerando {sub}…")

            # dns_brute for sub-subdomains
            job_key = f"{cid}:dns_brute:{sub}"
            try:
                result = fn_map["dns_brute"]()
                self.results[job_key] = {
                    "status": "done",
                    "reason": "",
                    "data": result,
                    "metrics": _summarize_payload_metrics(result),
                    "artifacts": {},
                    "blocked": bool(isinstance(result, dict) and result.get("blocked", False)),
                    "finished_at": datetime.now().isoformat(timespec="seconds"),
                }
            except Exception as e:
                status, reason = _classify_result_status(None, str(e))
                self.results[job_key] = {
                    "status": status,
                    "reason": reason or str(e),
                    "error": str(e),
                    "data": None,
                    "metrics": {},
                    "artifacts": {},
                    "blocked": False,
                }
                return sub, []

            sub_subs = self._collect_new_subdomains(cid, sub)
            inventory = {
                h["host"]: h for h in self._load_hosts(cid)
                if isinstance(h, dict) and h.get("host")
            }
            to_probe = [
                s for s in sub_subs
                if s not in inventory or not _is_responsive(inventory.get(s, {}))
            ]
            if to_probe:
                self._upsert_discovered_hosts(
                    cid, to_probe, co.get("domains", [sub]), source=f"recurse:{depth+1}:{sub}"
                )
                live  = self._probe_hosts_with_httpx(to_probe, cid)
                self._merge_hosts_into_asm_data(cid, live)
                _log(f"    ↳ [recurse d{depth+1}] {sub}: {len(live)} sub-subdomínios vivos")
                # Only recurse on httpx-confirmed live hosts, not on DNS-found ones
                return sub, live
            else:
                _log(f"    ↳ [recurse d{depth+1}] {sub}: 0 sub-subdomínios vivos")
                return sub, []

        # Run all subdomains at this depth level in parallel
        with ThreadPoolExecutor(max_workers=min(4, len(subs_to_recurse))) as pool:
            futs = {pool.submit(_enum_one, sub): sub for sub in subs_to_recurse}
            for fut in _as_completed(futs):
                try:
                    sub, to_probe = fut.result()
                    if to_probe:
                        total_added += len(to_probe)
                        total_added += self._recursive_enum(
                            cid, co, options, to_probe, depth + 1, _log
                        )
                except Exception:
                    pass

        return total_added

    # ── Persist pipeline results to ASM database ─────────────────────────────────

    def _post_scan_analysis(self, cid: str, co: dict, _log=None):
        """Post-scan: save snapshot, compute diff, record timeline, generate alerts."""
        def log(msg):
            if _log: _log(msg)

        now_ts = datetime.now().isoformat(timespec="seconds")
        hosts = self._load_hosts(cid)

        # ── 1. Save current snapshot for diff comparison ──────────────────────
        try:
            current_snapshot = {
                "ts": now_ts,
                "hosts": hosts,
                "host_count": len(hosts),
                "modules": {
                    k.split(":", 1)[1]: {"status": v.get("status")}
                    for k, v in self.results.items()
                    if k.startswith(f"{cid}:")
                },
            }
            self.db.save_snapshot(cid, current_snapshot, slot="current")
            log("  📸 Snapshot saved")
        except Exception as e:
            log(f"  ⚠ Snapshot failed: {e}")

        # ── 2. Subdomain history ──────────────────────────────────────────────
        try:
            domain = co["domains"][0] if co.get("domains") else ""
            for h in hosts[:200]:
                hostname = h.get("host", "")
                if not hostname:
                    continue
                self.db.insert_subdomain_history(
                    cid, hostname, "resolved",
                    now_ts, now_ts, True,
                    source=h.get("source", "pipeline"),
                )
            if hosts:
                log(f"  📝 Subdomain history: {min(len(hosts), 200)} entries")
        except Exception as e:
            log(f"  ⚠ Subdomain history failed: {e}")

        # ── 3. Scan diff vs previous snapshot ─────────────────────────────────
        try:
            curr_snap = self.db.load_snapshot(cid, slot="current")
            prev_snap = self.db.load_snapshot(cid, slot="previous")
            if prev_snap and curr_snap:
                prev_hosts = set(h["host"] if isinstance(h, dict) else h for h in prev_snap.get("hosts", []))
                curr_hosts = set(h["host"] if isinstance(h, dict) else h for h in curr_snap.get("hosts", []))
                new_hosts = curr_hosts - prev_hosts
                removed_hosts = prev_hosts - curr_hosts
                changed = len(curr_hosts & prev_hosts)
                if new_hosts or removed_hosts:
                    log(f"  🔍 Diff: +{len(new_hosts)} new / -{len(removed_hosts)} removed / {changed} unchanged")
                    diff = {"new": list(new_hosts), "removed": list(removed_hosts), "changed": []}
                    try:
                        from alerting import AlertEngine
                        engine = AlertEngine(self.db, self.base, self.get_settings)
                        alerts = engine.process_scan_diff(cid, diff)
                        if alerts:
                            log(f"  🚨 Alerts: {len(alerts)} generated")
                            for a in alerts:
                                log(f"      [{a['severity']}] {a['title'][:100]}")
                    except ImportError:
                        pass
                    except Exception as e:
                        log(f"  ⚠ Alert engine failed: {e}")
        except Exception as e:
            log(f"  ⚠ Diff analysis failed: {e}")

    def _persist_pipeline_results(self, cid: str, _log=None, _options=None, _co=None):
        """Write all in-memory pipeline results back to the persistent ASM database."""
        def log(msg):
            if _log:
                _log(msg)

        try:
            data = self.db.load_asm_data()
        except Exception as e:
            log(f"  ⚠ Falha ao carregar dados ASM para persistência: {e}")
            return

        co_data = next((c for c in data.get("companies", []) if c.get("id") == cid), None)
        if co_data is None:
            # Company not registered — do not auto-create, abort persistence
            log(f"  ⚠ Empresa {cid} não encontrada na base — persistência ignorada")
            return

        primary_domain = (co_data.get("domains") or [""])[0]

        def _result(module: str) -> dict:
            return (self.results.get(f"{cid}:{module}") or {}).get("data") or {}

        # CVE findings
        cve_data = _result("cve")
        if cve_data.get("findings"):
            co_data["cve_findings"]    = cve_data["findings"]
            co_data["cve_summary"]     = {
                "total":      cve_data.get("total", 0),
                "critical":   cve_data.get("critical_count", 0),
                "high":       cve_data.get("high_count", 0),
                "medium":     cve_data.get("medium_count", 0),
                "low":        cve_data.get("low_count", 0),
                "kev":        cve_data.get("kev_count", 0),
                "epss_high":  cve_data.get("epss_high_count", 0),
            }
            co_data["tech_queried"]    = cve_data.get("tech_queried", [])
            co_data["tech_versions"]   = cve_data.get("tech_versions", {})
            log(f"  ↳ CVE: {cve_data.get('total', 0)} findings persistidos")

        # Supply chain findings
        sc_data = _result("supply_chain")
        if sc_data.get("findings"):
            co_data["supply_chain_findings"] = sc_data["findings"]
            co_data["supply_chain_summary"]   = {
                "total":    sc_data.get("total", 0),
                "critical": sc_data.get("critical", 0),
                "high":     sc_data.get("high", 0),
                "medium":   sc_data.get("medium", 0),
                "low":      sc_data.get("low", 0),
            }
            co_data["supply_chain_libs"]  = sc_data.get("libraries_scanned", [])
            log(f"  ↳ Supply Chain: {sc_data.get('total', 0)} CVEs in JS libs")

        # Shodan data — checkpoint uses "results" key
        shodan_data = _result("shodan")
        shodan_hosts = shodan_data.get("hosts") or shodan_data.get("results") or []
        if shodan_hosts:
            co_data["shodan_hosts"] = shodan_hosts
            log(f"  ↳ Shodan: {len(shodan_hosts)} hosts persistidos")

        # Breach data
        breach_data = _result("breach")
        if (breach_data.get("total_findings", 0) > 0
                or breach_data.get("trufflehog")
                or breach_data.get("hibp")
                or breach_data.get("leakix")
                or breach_data.get("dehashed")
                or breach_data.get("breaches")
                or breach_data.get("credentials")):
            co_data["breach_data"] = breach_data
            log(f"  ↳ Breach: {breach_data.get('total_findings', 0)} findings persistidos")

        # Phishing monitor findings (data saved, findings promoted below)
        phishing_data = _result("phishing")
        if phishing_data.get("findings"):
            co_data["phishing_data"] = phishing_data
            log(f"  ↳ Phishing: {len(phishing_data.get('findings',[]))} potenciais detectados, {phishing_data.get('total_threats',0)} ameaças")

        # DNS findings
        dns_data = _result("dns")
        if dns_data.get("records") or dns_data.get("mx") or dns_data.get("txt") or dns_data.get("A") or dns_data.get("MX") or dns_data.get("TXT"):
            co_data["dns_data"] = dns_data
            log(f"  ↳ DNS: registros persistidos")

        # Email security (SPF/DMARC/DKIM/MX from email module)
        email_data = _result("email")
        if email_data.get("spf") or email_data.get("dmarc") or email_data.get("mx"):
            co_data.setdefault("email_security", {}).update({
                k: v for k, v in email_data.items()
                if k in ("spf", "dmarc", "dkim", "mx", "bimi", "spoofability")
            })
            # Back-fill TXT records into dns_data so infra tab can render SPF/DMARC
            spf_record = (email_data.get("spf") or {}).get("record", "")
            dmarc_record = (email_data.get("dmarc") or {}).get("record", "")
            if spf_record or dmarc_record:
                co_data.setdefault("dns_data", {})
                txt_records = list(co_data["dns_data"].get("TXT") or [])
                existing_txt = " ".join(str(r) for r in txt_records)
                if spf_record and "v=spf" not in existing_txt:
                    txt_records.append(spf_record)
                if dmarc_record and "v=DMARC" not in existing_txt:
                    txt_records.append(dmarc_record)
                co_data["dns_data"]["TXT"] = txt_records
            log(f"  ↳ Email security: SPF/DMARC/DKIM persistidos")

        # Emails from theharvester + hunter.io
        harvester_data = _result("theharvester")
        harvester_emails = harvester_data.get("emails", [])
        if harvester_emails:
            existing_emails = set(co_data.get("emails", []))
            existing_emails.update(harvester_emails)
            co_data["emails"] = sorted(existing_emails)
            log(f"  ↳ Emails: {len(co_data['emails'])} emails persistidos (theHarvester)")

        hunterio_data = _result("hunterio")
        hunterio_findings = hunterio_data.get("findings", [])
        if hunterio_findings:
            existing_emails = set(co_data.get("emails", []))
            hunter_emails_raw = [f["value"] for f in hunterio_findings if f.get("type") == "email"]
            existing_emails.update(hunter_emails_raw)
            co_data["emails"] = sorted(existing_emails)
            co_data["email_details"] = [
                {"email": f["value"], "first_name": (f.get("metadata") or {}).get("first_name", ""),
                 "last_name": (f.get("metadata") or {}).get("last_name", ""),
                 "position": (f.get("metadata") or {}).get("position", ""),
                 "confidence": (f.get("metadata") or {}).get("confidence", 0)}
                for f in hunterio_findings if f.get("type") == "email"
            ]
            log(f"  ↳ Emails: {len(co_data['emails'])} emails persistidos (hunter.io + theHarvester)")

        # Certificate/CT log findings
        cert_data = _result("certs")
        if cert_data.get("ct_subdomains"):
            existing = set(co_data.get("ct_subdomains", []))
            existing.update(cert_data["ct_subdomains"])
            co_data["ct_subdomains"] = sorted(existing)
            log(f"  ↳ Certs: {len(co_data['ct_subdomains'])} subdomínios CT persistidos")

        # ── Enrich hosts with SSL cert expiry data ──────────────────────────────
        ssl_results = cert_data.get("ssl_results", [])
        if ssl_results:
            ssl_map = {}
            for s in ssl_results:
                host = s.get("host", "").lower()
                if host:
                    ssl_map[host] = s
            expiry_count = 0
            for h in co_data.get("hosts", []):
                hn = h.get("host", "").lower()
                if hn in ssl_map:
                    s = ssl_map[hn]
                    h["cert_info"] = {
                        "not_after": s.get("not_after", ""),
                        "days_left": s.get("days_left"),
                        "expired": s.get("expired", False),
                        "expiring_soon": s.get("expiring_soon", False),
                        "issuer": s.get("issuer", ""),
                    }
                    h["cert_expiry"] = s.get("not_after", "")[:10] if s.get("not_after") else ""
                    if s.get("expiring_soon") or s.get("expired"):
                        expiry_count += 1
            if ssl_results:
                log(f"  ↳ SSL: {len(ssl_results)} hosts enriquecidos, {expiry_count} com certificado expirado/expirando")

        # ASN / CIDR data
        asn_data = _result("asn")
        if asn_data.get("asn_groups"):
            co_data["asn_data"] = asn_data
            log(f"  ↳ ASN: {len(asn_data['asn_groups'])} grupos persistidos")

        asnmap_data = _result("asnmap")
        asnmap_findings = asnmap_data.get("findings", [])
        if asnmap_findings:
            cidrs = [f["value"] for f in asnmap_findings if f.get("type") == "asn_range"]
            asns  = [f["value"] for f in asnmap_findings if f.get("type") == "asn"]
            co_data["cidr_ranges"] = cidrs
            co_data["asn_numbers"] = asns
            log(f"  ↳ ASNmap: {len(cidrs)} CIDRs, {len(asns)} ASNs persistidos")
        elif asn_data.get("asn_groups"):
            # asnmap returned nothing (no PDCP key) — extract from ipinfo.io asn data
            cidrs = []
            asns  = []
            for g in asn_data["asn_groups"]:
                asn_num = g.get("asn", "")
                if asn_num and asn_num not in asns:
                    asns.append(asn_num)
                for prefix in g.get("prefixes", []):
                    if prefix and ":" not in prefix and prefix not in cidrs:  # IPv4 only
                        cidrs.append(prefix)
            if cidrs or asns:
                co_data["cidr_ranges"] = cidrs
                co_data["asn_numbers"] = asns
                log(f"  ↳ ASN (fallback ipinfo): {len(cidrs)} CIDRs, {len(asns)} ASNs persistidos")

        # Port scan findings
        port_data = _result("portscan")
        if port_data.get("open_ports") or port_data.get("results") or port_data.get("ips_scanned"):
            co_data["port_scan"] = port_data
            count = len(port_data.get("results") or port_data.get("open_ports") or [])
            log(f"  ↳ Portas: {count} resultados persistidos")

        # Vendor fingerprint findings
        vendor_data = _result("vendor_fp")
        vendor_findings = vendor_data.get("findings", [])
        if vendor_findings:
            co_data["vendor_fingerprints"] = vendor_findings
            co_data["vendors_found"] = vendor_data.get("vendors_found", [])
            # Enrich hosts with vendor info
            vendor_map = {}
            for vf in vendor_findings:
                h = vf.get("host", "")
                if h not in vendor_map:
                    vendor_map[h] = []
                vendor_map[h].append(vf.get("vendor", ""))
            for h in co_data.get("hosts", []):
                hn = h.get("host", "")
                if hn in vendor_map:
                    h["edge_appliances"] = vendor_map[hn]
            log(f"  ↳ Vendor FP: {len(vendor_findings)} fingerprints, {len(vendor_data.get('vendors_found',[]))} vendors detectados")

        # Secrets / JS recon — module is named "js_secrets"
        secrets_data = _result("js_secrets")
        if secrets_data.get("findings"):
            co_data["secrets_findings"] = secrets_data["findings"]
            log(f"  ↳ Secrets: {len(secrets_data['findings'])} achados persistidos")

        # JS discovery (katana + analysis + Playwright runtime capture)
        js_data = _result("js")
        if js_data.get("js_files") or js_data.get("endpoints_found") or js_data.get("runtime_network"):
            runtime_js_urls = list(js_data.get("runtime_js_urls") or [])
            if not runtime_js_urls:
                # Older checkpoints only kept runtime_js_count. Recover the
                # visible runtime JS URLs that also appeared as script/fetch calls
                # or browser-fetched JS files so the frontend can still show them.
                for call in js_data.get("runtime_network", []) or []:
                    u = call.get("url") if isinstance(call, dict) else str(call)
                    if isinstance(u, str) and (u.endswith(".js") or ".js?" in u or ".js#" in u):
                        runtime_js_urls.append(u)
                for jf in js_data.get("js_files", []) or []:
                    u = jf.get("url", "")
                    if jf.get("source") == "playwright" and u:
                        runtime_js_urls.append(u)
            runtime_js_urls = sorted(dict.fromkeys(runtime_js_urls))
            co_data["js_data"] = {
                "js_files":          js_data.get("js_files", []),
                "total_endpoints":   js_data.get("total_endpoints") or js_data.get("endpoints_found", 0),
                "total_secrets":     js_data.get("total_secrets") or js_data.get("secrets_found", 0),
                "js_analyzed":       js_data.get("js_analyzed", 0),
                "js_files_found":    js_data.get("js_files_found", 0),
                "critical_count":    js_data.get("critical_count", 0),
                "high_count":        js_data.get("high_count", 0),
                "medium_count":      js_data.get("medium_count", 0),
                # Playwright runtime network capture
                "runtime_network":     js_data.get("runtime_network", []),
                "runtime_network_map": js_data.get("runtime_network_map", {}),
                "runtime_js_urls":      runtime_js_urls,
                "runtime_js_count":    js_data.get("runtime_js_count", 0),
                "scanned_at":          js_data.get("scanned_at", ""),
            }
            log(f"  ↳ JS: {len(js_data.get('js_files',[]))} arquivos, {js_data.get('total_endpoints',0)} endpoints, "
                f"{len(js_data.get('runtime_network',[]))} runtime calls, {js_data.get('runtime_js_count',0)} runtime JS chunks")

        # Tech stack (wappalyzer — builds tech_index + tech_summary)
        wappalyzer_data = _result("wappalyzer")
        if wappalyzer_data.get("tech_index"):
            merged = dict(co_data.get("tech_index") or {})
            merged.update(wappalyzer_data["tech_index"])
            co_data["tech_index"] = merged
            log(f"  ↳ Tech stack: {len(merged)} tecnologias persistidas")
        # Always rebuild tech_summary from tech_index for frontend compatibility
        if co_data.get("tech_index"):
            co_data["tech_summary"] = {t: len(h) for t, h in co_data["tech_index"].items()}

        # WAF coverage (aggregate + per-host)
        waf_data = _result("waf")
        if waf_data.get("waf_counts"):
            co_data["waf_coverage"] = waf_data["waf_counts"]
            log(f"  ↳ WAF: {waf_data['waf_counts']} persistido")
        if waf_data.get("results"):
            host_waf_map = {}
            for r in waf_data["results"]:
                h = r.get("host", "")
                wafs = r.get("wafs", [])
                if h:
                    host_waf_map[h] = ", ".join(wafs) if wafs else ("Direct" if not r.get("protected") else "Unknown")
            for host in co_data.get("hosts", []):
                hn = host.get("host", "")
                if hn in host_waf_map:
                    host["waf"] = host_waf_map[hn]
                elif host.get("waf") == "Unknown":
                    host["waf"] = "Direct"

        # Wayback URL data
        wayback_data = _result("wayback")
        if wayback_data.get("interesting") or wayback_data.get("interesting_count"):
            co_data["wayback_data"] = {
                "interesting":       wayback_data.get("interesting", []),
                "interesting_count": wayback_data.get("interesting_count", 0),
            }
            log(f"  ↳ Wayback: {wayback_data.get('interesting_count',0)} URLs persistidas")

        # URLFinder data
        urlfinder_data = _result("urlfinder")
        urls = urlfinder_data.get("urls") or [f["value"] for f in urlfinder_data.get("findings", []) if f.get("value")]
        if urls:
            co_data["urlfinder_data"] = {"urls": urls[:5000]}
            log(f"  ↳ URLFinder: {len(urls)} URLs persistidas")

        # Headers data (stats for overview); back-fill host status_code from probe results
        headers_data = _result("headers")
        if headers_data.get("results"):
            co_data["headers_data"] = headers_data
            log(f"  ↳ Headers: {headers_data.get('total_hosts',0)} hosts analisados")
            host_status_map = {r["host"]: r["status"] for r in headers_data["results"] if r.get("host") and r.get("status")}
            patched = 0
            for h in co_data.get("hosts", []):
                if h.get("status_code") is None and h.get("host") in host_status_map:
                    h["status_code"] = host_status_map[h["host"]]
                    patched += 1
            if patched:
                log(f"  ↳ Patched {patched} host status_codes from headers scan")

        # API exposure
        api_data = _result("api_exposure")
        if api_data.get("exposed"):
            co_data["api_exposure"] = api_data["exposed"]
            log(f"  ↳ API exposure: {len(api_data['exposed'])} endpoints persistidos")

        # Browser crawl — Playwright crawler URLs, XHR/fetch and forms
        crawl_data = _result("browser_crawl")
        if crawl_data and (
            crawl_data.get("urls")
            or crawl_data.get("api_endpoints")
            or crawl_data.get("results")
            or crawl_data.get("form_count")
        ):
            co_data["browser_crawl_data"] = {
                "hosts_crawled": crawl_data.get("hosts_crawled", 0),
                "hosts_targeted": crawl_data.get("hosts_targeted", 0),
                "results": crawl_data.get("results", []),
                "urls": crawl_data.get("urls", []),
                "url_count": crawl_data.get("url_count", len(crawl_data.get("urls", []) or [])),
                "api_endpoints": crawl_data.get("api_endpoints", []),
                "api_endpoint_count": crawl_data.get("api_endpoint_count", len(crawl_data.get("api_endpoints", []) or [])),
                "forms": crawl_data.get("forms", []),
                "form_count": crawl_data.get("form_count", 0),
                "subdomains": crawl_data.get("subdomains", []),
                "scanned_at": crawl_data.get("scanned_at", ""),
            }
            log(
                f"  ↳ Browser Crawl: {crawl_data.get('url_count', 0)} URLs, "
                f"{crawl_data.get('api_endpoint_count', 0)} XHR/fetch, "
                f"{crawl_data.get('form_count', 0)} forms"
            )

        # Browser recon — deep JS analysis attached to hosts
        br_data = _result("browser_recon")
        if br_data and not br_data.get("error"):
            browser_results = br_data.get("results") if isinstance(br_data.get("results"), list) else []
            if browser_results or br_data.get("hosts_scanned"):
                co_data["browser_recon_data"] = {
                    "hosts_scanned": br_data.get("hosts_scanned", len(browser_results)),
                    "total_api_endpoints": br_data.get("total_api_endpoints", 0),
                    "total_secrets": br_data.get("total_secrets", 0),
                    "total_cookies": br_data.get("total_cookies", 0),
                    "insecure_cookies": br_data.get("insecure_cookies", 0),
                    "technologies": br_data.get("technologies", []),
                    "results": browser_results,
                    "scanned_at": br_data.get("scanned_at", ""),
                }
                by_host = {}
                for item in browser_results:
                    try:
                        host = __import__('urllib').parse.urlparse(item.get("url", "")).hostname or ""
                    except Exception:
                        host = ""
                    if host:
                        by_host[host.lower()] = item
                attached = 0
                for h in co_data.get("hosts", []):
                    item = by_host.get((h.get("host") or "").lower())
                    if not item:
                        continue
                    h["browser_recon"] = {
                        "js_analysis": item.get("js_analysis", {}),
                        "technologies": item.get("technologies", []),
                        "api_endpoints": item.get("api_endpoints", []),
                        "secrets_found": item.get("secrets_found", []),
                        "source_maps": item.get("source_maps", []),
                        "third_party_services": item.get("third_party_services", []),
                        "observations": item.get("observations", []),
                        "screenshot": item.get("screenshot", ""),
                        "cookies": item.get("cookies", []),
                        "status": item.get("status"),
                        "title": item.get("title", ""),
                    }
                    attached += 1
                log(f"  ↳ Browser Recon: {len(browser_results)} páginas persistidas, {attached} hosts enriquecidos")
            elif br_data.get("url"):
                hostname = __import__('urllib').parse.urlparse(br_data.get("url", "")).hostname or ""
                if hostname:
                    for h in co_data.get("hosts", []):
                        if h.get("host") == hostname:
                            h["browser_recon"] = {
                                "js_analysis": br_data.get("js_analysis", {}),
                                "technologies": br_data.get("technologies", []),
                                "api_endpoints": br_data.get("api_endpoints", []),
                                "secrets_found": br_data.get("secrets_found", []),
                                "source_maps": br_data.get("source_maps", []),
                                "third_party_services": br_data.get("third_party_services", []),
                                "observations": br_data.get("observations", []),
                                "screenshot": br_data.get("screenshot", ""),
                            }
                            log(f"  ↳ Browser Recon: JS deep analysis persistido para {hostname}")
                            break

        # Leaks (github)
        leaks_data = _result("leaks")
        if leaks_data.get("git_exposed") or leaks_data.get("leaks") or leaks_data.get("total_findings", 0) > 0 or leaks_data.get("github", {}).get("results"):
            co_data["leaks_data"] = leaks_data
            log(f"  ↳ Leaks: {leaks_data.get('total_findings', 0)} findings persistidos")

        # Screenshots metadata — gowitness uses "count", screenshot module uses "total".
        # Keep the largest available count because browser/screenshot/gowitness can
        # write to the same directory with different module-level totals.
        gw_data = _result("gowitness")
        screenshot_data = _result("screenshot") or _result("screenshots")
        shots_data = gw_data if gw_data.get("screenshots") else (screenshot_data or gw_data)
        shots_dir = self.base / "scans" / cid / "screenshots"
        disk_count = 0
        if shots_dir.exists():
            disk_count = len([f for f in shots_dir.iterdir() if f.suffix.lower() in (".png", ".jpg", ".jpeg")])
        shots_count = max(
            int(gw_data.get("count") or gw_data.get("total") or 0),
            int(screenshot_data.get("count") or screenshot_data.get("total") or 0),
            disk_count,
        )
        if shots_count:
            co_data["screenshots_count"] = shots_count

        # Link gowitness screenshots to host objects
        gw_screenshots = []
        for _sd in (gw_data, screenshot_data):
            if isinstance(_sd.get("screenshots"), list):
                gw_screenshots.extend(_sd.get("screenshots", []))
        if gw_screenshots:
            ss_map = {s.get("host","").lower(): s.get("screenshot","") for s in gw_screenshots if s.get("host")}
            for h in co_data.get("hosts", []):
                hn = h.get("host","").lower()
                if hn in ss_map and not h.get("screenshot"):
                    h["screenshot"] = ss_map[hn]
            log(f"  ↳ Screenshots linkados: {len(ss_map)} hosts com captura")

        # Fallback: link screenshots from disk when gowitness result is missing
        # (browser recon, playwright agent, or previous runs left files on disk)
        # Supports both flat file structure and gowitness v3 directory-per-host layout.
        log(f"  ↳ [persist] Ligando screenshots do disco...")
        try:
            shots_dir = self.base / "scans" / cid / "screenshots"
            if shots_dir.exists():
                disk_shots = {}
                for f in shots_dir.rglob("*"):
                    if not f.is_file() or f.suffix.lower() not in (".png", ".jpg", ".jpeg"):
                        continue
                    rel = f.relative_to(shots_dir)
                    parts = rel.parts
                    # gowitness v3: screenshot/<hostname>/<hash>.png
                    host = ""
                    if len(parts) >= 2:
                        host = parts[-2]  # parent dir = hostname
                    if not host or host in ("screenshot", "response"):
                        # Flat file: extract host from filename
                        name = f.stem
                        if name.startswith("browser_"):
                            host = name[8:].replace("___", "://").replace("_", ".")
                            host = host.split("://", 1)[-1] if "://" in host else host
                        elif name.startswith(("http---", "https---")):
                            host = re.sub(r"^https?---", "", name, flags=re.I)
                            host = re.sub(r"-\d+$", "", host)
                        else:
                            host = name.replace("-", ".")
                    host = host.lower().strip(".")
                    if host:
                        # Use relative path from screenshots dir for serving
                        serve_path = str(rel).replace("\\", "/")
                        disk_shots[host] = f"screenshots/{cid}/{serve_path}"
                linked = 0
                for h in co_data.get("hosts", []):
                    hn = h.get("host", "").lower()
                    if not h.get("screenshot") and hn in disk_shots:
                        h["screenshot"] = disk_shots[hn]
                        linked += 1
                if linked:
                    log(f"  ↳ Screenshots disco linkados: {linked}")
                if disk_shots and not gw_screenshots:
                    co_data["screenshots_count"] = len(disk_shots)
        except Exception as e:
            log(f"  ↳ Screenshots disco: erro ignorado ({e})")
        log(f"  ↳ [persist] Salvando no banco...")

        # ── Favicon hash / Shodan icon matching ───────────────────────────────────
        fav_data = _result("favicon_hunt")
        if fav_data.get("matches") or fav_data.get("findings"):
            co_data["favicon_data"] = fav_data
            log(f"  ↳ Favicon hunt: {len(fav_data.get('matches',[]))} Shodan matches")

        # ── Infra exposure (Kubernetes/Docker/etcd/Elasticsearch) ─────────────────
        infra_data = _result("infra_exposure")
        if infra_data.get("findings"):
            co_data["infra_data"] = infra_data
            log(f"  ↳ Infra exposure: {infra_data.get('vulnerable',0)} serviços expostos em {infra_data.get('total_ips_tested',0)} IPs")

        # ── Default credentials findings ──────────────────────────────────────────────
        dc_data = _result("default_creds")
        if dc_data.get("findings"):
            co_data["default_creds_data"] = dc_data
            log(f"  ↳ Default creds: {dc_data.get('total',0)} serviços vulneráveis")

        # ── Virtual hosts discovered ───────────────────────────────────────────────
        vhost_data = _result("vhost")
        if vhost_data.get("findings"):
            co_data["vhost_data"] = vhost_data
            log(f"  ↳ VHosts: {len(vhost_data['findings'])} virtual hosts descobertos")

        # ── CMS scan (wpscan / droopescan) ────────────────────────────────────────
        cms_data = _result("cms_scan")
        if cms_data.get("results") and not cms_data.get("skipped"):
            co_data["cms_data"] = cms_data
            log(f"  ↳ CMS scan: {len(cms_data.get('ran',[]))} scans concluídos")

        # ── Whatweb — merge into existing tech_index ───────────────────────────────
        whatweb_data = _result("whatweb")
        if whatweb_data.get("techs"):
            co_data.setdefault("whatweb_data", {}).update(whatweb_data["techs"])
            # Merge into tech_index so dashboard picks it up
            existing_idx = dict(co_data.get("tech_index") or {})
            for host, techs in whatweb_data["techs"].items():
                for t in techs:
                    existing_idx.setdefault(t, [])
                    if host not in existing_idx[t]:
                        existing_idx[t].append(host)
            co_data["tech_index"] = existing_idx
            co_data["tech_summary"] = {t: len(h) for t, h in existing_idx.items()}
            log(f"  ↳ Whatweb: {len(whatweb_data['techs'])} hosts enriquecidos")

        # ── Zone transfer attempts ─────────────────────────────────────────────────
        zt_data = _result("zone_transfer")
        if zt_data.get("attempts"):
            co_data["zone_transfer_data"] = zt_data
            ok = zt_data.get("successful_transfers", 0)
            log(f"  ↳ Zone Transfer: {len(zt_data['attempts'])} tentativas · {ok} bem-sucedidas · {zt_data.get('total_subdomains',0)} subdomínios")
            # Merge exposed subdomains into CT subdomain list
            if zt_data.get("subdomains"):
                existing_ct = set(co_data.get("ct_subdomains", []))
                existing_ct.update(zt_data["subdomains"])
                co_data["ct_subdomains"] = sorted(existing_ct)

        # ── Parameter mining (Arjun) ───────────────────────────────────────────────
        pm_data = _result("param_mine")
        if pm_data.get("results") or pm_data.get("parameters") or pm_data.get("findings"):
            co_data["param_mine_data"] = pm_data
            param_count = len(pm_data.get("parameters") or pm_data.get("findings") or pm_data.get("results") or [])
            log(f"  ↳ Param mine: {param_count} parâmetros descobertos")

        # ── Certstream — new certificate domains ───────────────────────────────────
        cs_data = _result("certstream")
        if cs_data.get("new_certs") or cs_data.get("subdomains"):
            co_data.setdefault("certstream_data", {})
            co_data["certstream_data"]["last_snapshot"] = cs_data
            # Merge new subdomains
            new_subs = [c.get("domain","") for c in (cs_data.get("new_certs") or [])]
            new_subs += cs_data.get("subdomains", [])
            new_subs = [s for s in new_subs if s]
            if new_subs:
                existing_ct = set(co_data.get("ct_subdomains", []))
                added = len(new_subs) - len(existing_ct & set(new_subs))
                existing_ct.update(new_subs)
                co_data["ct_subdomains"] = sorted(existing_ct)
                log(f"  ↳ Certstream: {len(new_subs)} certs capturados · {added} subdomínios novos")

        # ── GitHub repos ───────────────────────────────────────────────────────────
        gh_data = _result("github_repos")
        if gh_data.get("total_repos") or gh_data.get("findings"):
            co_data["github_repos_data"] = gh_data
            log(f"  ↳ GitHub: {gh_data.get('total_repos',0)} repos · "
                f"{len(gh_data.get('sensitive_files',[]))} arquivos sensíveis · "
                f"{len(gh_data.get('secrets_found',[]))} padrões de segredo")

        # ── DNSSEC ────────────────────────────────────────────────────────────────
        dnssec_data = _result("dnssec")
        if dnssec_data.get("results"):
            co_data["dnssec_data"] = dnssec_data
            issues = sum(1 for r in dnssec_data["results"] if r.get("issues"))
            log(f"  ↳ DNSSEC: {len(dnssec_data['results'])} domínios verificados · {issues} com problemas")

        # ── Related domains ────────────────────────────────────────────────────────
        related_data = _result("related")
        if related_data.get("found"):
            co_data["related_domains"] = related_data
            log(f"  ↳ Related domains: {related_data.get('count',0)} domínios relacionados encontrados")

        # ── WAF bypass test results ────────────────────────────────────────────────
        waf_bp_data = _result("waf_bypass")
        if waf_bp_data.get("findings"):
            co_data["waf_bypass_data"] = waf_bp_data
            log(f"  ↳ WAF bypass: {waf_bp_data.get('bypasses_found',0)} bypasses em {waf_bp_data.get('total_tested',0)} hosts")

        # ── SMTP probe results ─────────────────────────────────────────────────────
        smtp_data = _result("smtp_probe")
        if smtp_data.get("results") or smtp_data.get("findings"):
            co_data["smtp_data"] = smtp_data
            log(f"  ↳ SMTP: {smtp_data.get('smtp_hosts',0)} servidores SMTP · {len(smtp_data.get('findings',[]))} achados")

        # ── SNMP probe results ─────────────────────────────────────────────────────
        snmp_data = _result("snmp_probe")
        if snmp_data.get("findings"):
            co_data["snmp_data"] = snmp_data
            log(f"  ↳ SNMP: {snmp_data.get('vulnerable',0)} hosts com community 'public'")

        # General findings list (vulnerabilities, misconfigs, headers, CVEs, leaks)
        # Drop CVE/secret-type findings from prior run — re-added with updated metadata fields
        _prior = co_data.get("findings", [])
        all_findings: list[dict] = [f for f in _prior if f.get("type") not in ("cve", "secret")]
        existing_keys = {f.get("key") or f.get("title") or f.get("name") or "" for f in all_findings}

        # ── Normalize nuclei API panel findings ───────────────────────────────────
        try:
            from validators import filter_nuclei_info, dedup_findings
        except ImportError:
            filter_nuclei_info = lambda x: x
            dedup_findings = lambda x, _k="general": x

        nuclei_findings = _result("nuclei").get("findings", [])
        if nuclei_findings:
            nuclei_findings = filter_nuclei_info(nuclei_findings)
            for f in nuclei_findings:
                key = f.get("template") or f.get("name") or ""
                if key and key not in existing_keys:
                    all_findings.append(_normalize_finding(f, "nuclei"))
                    existing_keys.add(key)

        # ── Pull findings from headers, waf, takeover (normalize field names) ─────
        for mod in ("headers", "waf", "takeover"):
            for f in _result(mod).get("findings", []):
                key = f.get("key") or f.get("title") or f.get("header") or f.get("name") or ""
                if key and key not in existing_keys:
                    all_findings.append(_normalize_finding(f, mod))
                    existing_keys.add(key)

        # ── Also check takeover/waf results for per-host findings ──────────────────
        for mod in ("takeover", "waf"):
            for r in _result(mod).get("results", []):
                if r.get("takeover_possible") and r.get("cname_target"):
                    key = f"takeover-{r.get('host','')}-{r.get('cname','')}"
                    if key and key not in existing_keys:
                        all_findings.append({
                            "key":      key,
                            "type":     "takeover",
                            "title":    f"Subdomain Takeover: {r.get('host','')}",
                            "severity": r.get("severity", "critical"),
                            "category": "takeover",
                            "desc":     r.get("issue", ""),
                            "host":     r.get("host", ""),
                            "value":    r.get("cname", ""),
                            "module":   "baddns",
                        })
                        existing_keys.add(key)

        # Promote critical/high CVEs into findings
        for f in co_data.get("cve_findings", []):
            if f.get("severity") in ("critical", "high"):
                key = f.get("cve_id", "")
                if key and key not in existing_keys:
                    affected = f.get("affected_hosts", [])
                    host_str = affected[0] if len(affected) == 1 else (", ".join(affected[:3]) if affected else "")
                    title = f"{f.get('cve_id','')} — {f.get('product','')}".strip()
                    if f.get("detected_version"):
                        title += f" {f['detected_version']}"
                    all_findings.append({
                        "key":           key,
                        "type":          "cve",
                        "title":         title,
                        "severity":      f.get("severity", "high"),
                        "category":      "cve",
                        "desc":          f.get("desc", ""),
                        "host":          host_str,
                        "affected_hosts": affected,
                        "value":         f.get("cve_id", ""),
                        "url":           f.get("url", ""),
                        "score":         f.get("score", 0),
                        "epss":          f.get("epss", 0),
                        "kev":           f.get("kev", False),
                        "module":        "cve_scan",
                    })
                    existing_keys.add(key)

        # Headers misconfigs — cookie issues + missing critical headers promoted to findings
        _HEADER_SEV = {
            "Strict-Transport-Security": "medium",
            "Content-Security-Policy":   "medium",
            "X-Frame-Options":           "low",
            "X-Content-Type-Options":    "low",
        }
        for r in _result("headers").get("results", []):
            host = r.get("host", "")
            if not host:
                continue
            # Cookie security issues
            for ci in r.get("cookie_issues", []):
                sev = ci.get("severity", "medium")
                if sev not in ("high", "medium", "critical"):
                    continue
                cname = ci.get("cookie", "")
                issue = ci.get("issue", "")
                key = f"cookie-{host}-{cname}-{issue}"
                if key not in existing_keys:
                    all_findings.append({
                        "key":      key,
                        "type":     "header",
                        "title":    f"Cookie inseguro em {host}: {issue}",
                        "severity": sev,
                        "category": "headers",
                        "desc":     f"Cookie '{cname}' sem {issue}. Host: {host}",
                        "host":     host,
                        "value":    cname,
                        "module":   "headers",
                    })
                    existing_keys.add(key)
            # Missing critical security headers
            for hf in r.get("findings", []):
                if hf.get("present") or hf.get("severity") == "pass":
                    continue
                hname = hf.get("header", "")
                sev = _HEADER_SEV.get(hname)
                if not sev:
                    continue
                key = f"header-missing-{host}-{hname}"
                if key not in existing_keys:
                    all_findings.append({
                        "key":      key,
                        "type":     "header",
                        "title":    f"Header ausente em {host}: {hname}",
                        "severity": sev,
                        "category": "headers",
                        "desc":     hf.get("issue", f"Missing {hname}"),
                        "host":     host,
                        "value":    hname,
                        "module":   "headers",
                    })
                    existing_keys.add(key)

        # CORS misconfigurations
        for f in _result("cors_scan").get("findings", []):
            key = f"cors-{f.get('host','')}-{f.get('test','')}"
            if key not in existing_keys:
                all_findings.append({
                    "key": key, "type": "cors",
                    "title": f"CORS Misconfiguration: {f.get('host','')}",
                    "severity": f.get("severity", "high"), "category": "cors",
                    "desc": f"Origin: {f.get('origin_sent','')} → ACAO: {f.get('acao','')} ACAC: {f.get('acac','')}",
                    "host": f.get("host",""), "value": f.get("url",""), "url": f.get("url",""), "module": "cors_scan",
                })
                existing_keys.add(key)

        # GraphQL endpoints
        for f in _result("graphql").get("findings", []):
            key = f"graphql-{f.get('host','')}-{f.get('path','')}"
            if key not in existing_keys:
                # Use actual severity from recon (critical if introspection works, high if playground only)
                sev = f.get("severity") or ("critical" if f.get("introspection") else "high" if f.get("playground") else "medium")
                all_findings.append({
                    "key":      key,
                    "type":     "graphql",
                    "title":    f.get("title") or f"GraphQL Endpoint: {f.get('url','')}",
                    "severity": sev,
                    "category": "graphql",
                    "desc":     f.get("desc") or "GraphQL endpoint detected — introspection may be enabled",
                    "host":     f.get("host",""),
                    "value":    f.get("url",""),
                    "url":      f.get("url",""),
                    "module":   "graphql",
                    "metadata": {
                        "introspection": f.get("introspection", False),
                        "playground":    f.get("playground", False),
                        "schema_types":  f.get("schema_types", []),
                    },
                })
                existing_keys.add(key)

        # API panels / nuclei template matches
        for f in _result("api_panels").get("findings", []):
            key = f"apipanel-{f.get('host','')}-{f.get('template','')}"
            if key not in existing_keys:
                all_findings.append({
                    "key": key, "type": "nuclei",
                    "title": f.get("name","") or f.get("template",""),
                    "severity": f.get("severity","medium"), "category": "nuclei",
                    "desc": f"Template: {f.get('template','')}",
                    "host": f.get("host",""), "value": f.get("url",""), "url": f.get("url",""), "module": "api_panels",
                })
                existing_keys.add(key)

        # GitHub leaks
        for r in _result("leaks").get("github", {}).get("results", []):
            key = (r.get("url") or r.get("repo") or "")[:80]
            if key and key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     "leak",
                    "title":    f"GitHub Leak: {r.get('repo','')}",
                    "severity": r.get("severity", "high"),
                    "category": "leaks",
                    "desc":     f"File: {r.get('file','')}  Query: {r.get('query','')}",
                    "value":    r.get("url", ""),
                    "url":      r.get("url", ""),
                    "module":   "github_dork",
                })
                existing_keys.add(key)

        # Postman collections
        postman_data = _result("postman_collections")
        if postman_data.get("total", 0) > 0 or postman_data.get("collections") or postman_data.get("github_hits"):
            co_data["postman_data"] = postman_data
            log(f"  ↳ Postman: {len(postman_data.get('collections',[]))} collections, "
                f"{len(postman_data.get('github_hits',[]))} GitHub hits, "
                f"{len(postman_data.get('secrets',[]))} secrets")
        for pf in postman_data.get("findings", []):
            key = f"postman-{pf.get('type','')}-{pf.get('value','')[:60]}"
            if key and key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     pf.get("type", "postman_collection"),
                    "title":    pf.get("title", ""),
                    "severity": pf.get("severity", "medium"),
                    "category": pf.get("category", "leaks"),
                    "desc":     pf.get("desc", ""),
                    "host":     pf.get("host", primary_domain),
                    "value":    pf.get("value", ""),
                    "url":      pf.get("url", ""),
                    "module":   "postman_collections",
                    "metadata": pf.get("metadata", {}),
                })
                existing_keys.add(key)

        # Typosquat / brand domain exposure
        typo_data = _result("typosquat")
        if typo_data.get("registered"):
            co_data["typosquat_data"] = {
                "domain":           typo_data.get("domain", primary_domain),
                "total_checked":    typo_data.get("total_checked", 0),
                "registered_count": typo_data.get("registered_count", 0),
                "active_count":     typo_data.get("active_count", 0),
                "registered":       typo_data.get("registered", []),
                "scanned_at":       typo_data.get("scanned_at", ""),
            }
            broker       = [r for r in typo_data.get("registered", []) if r.get("status") == "broker_listed"]
            active        = [r for r in typo_data.get("registered", []) if r.get("status") == "active"]
            no_ip         = [r for r in typo_data.get("registered", []) if r.get("status") == "registered_no_ip"]
            company_owned = [r for r in typo_data.get("registered", []) if r.get("status") == "company_owned"]
            log(f"  ↳ Typosquat: {typo_data.get('registered_count',0)} registrados · "
                f"{len(broker)} brokers · {len(active)} ativos · {len(no_ip)} sem IP · "
                f"{len(company_owned)} próprios (filtrados)")
            # Promote to findings — skip company-owned domains
            for r in broker + active:
                if r.get("company_owned") or r.get("status") == "company_owned":
                    continue
                # Severity escalation matrix
                if r.get("risk") == "critical" or (
                    r.get("status") == "active" and (r.get("has_mx") or
                    r.get("ssl", {}).get("brand_in_cert"))
                ):
                    sev = "critical"
                elif r.get("status") == "broker_listed":
                    sev = "high"
                else:
                    sev = "medium"

                key = f"typosquat-{r['domain']}"
                if key not in existing_keys:
                    status_label = "à venda em broker" if r.get("status") == "broker_listed" else "ativo (terceiro)"
                    extras = []
                    if r.get("has_mx"):
                        extras.append("tem MX (pode enviar/receber e-mail)")
                    if r.get("ssl", {}).get("brand_in_cert"):
                        extras.append("certificado SSL com nome da marca (phishing kit completo)")
                    if r.get("whois_org"):
                        extras.append(f"registrante: {r['whois_org']}")
                    desc = (f"`{r['domain']}` está {status_label}. "
                            f"IP: {', '.join(r.get('ips', [])) or 'N/A'}. ")
                    if extras:
                        desc += " | ".join(extras) + ". "
                    desc += "Pode ser usado para phishing ou brand confusion."
                    all_findings.append({
                        "key":      key,
                        "type":     "brand_domain_exposure",
                        "title":    f"Domínio da marca não controlado: {r['domain']}",
                        "severity": sev,
                        "category": "brand_protection",
                        "desc":     desc,
                        "host":     r["domain"],
                        "value":    r["domain"],
                        "module":   "typosquat",
                        "metadata": {
                            "status":         r.get("status"),
                            "ips":            r.get("ips", []),
                            "redirect_to":    r.get("redirect_to", ""),
                            "has_mx":         r.get("has_mx", False),
                            "mx_records":     r.get("mx_records", []),
                            "ssl":            r.get("ssl", {}),
                            "whois_email":    r.get("email", ""),
                            "whois_org":      r.get("org", ""),
                        },
                    })
                    existing_keys.add(key)

        # Phishing findings (promoted from phishing monitor)
        phishing_data = co_data.get("phishing_data", {})
        for pf in phishing_data.get("findings", []):
            if pf.get("severity") in ("critical", "high", "medium"):
                key = f"phishing-{pf.get('url','')}"
                if key and key not in existing_keys:
                    all_findings.append({
                        "key":      key,
                        "type":     "phishing",
                        "title":    f"Potential Phishing: {pf.get('url','')}",
                        "severity": pf.get("severity", "high"),
                        "category": "phishing",
                        "desc":     f"Risk score: {pf.get('risk_score',0)}/100. Indicators: {', '.join(pf.get('indicators',[]))}. Title: {pf.get('title','')}",
                        "host":     pf.get("url", "").replace("https://", "").replace("http://", ""),
                        "value":    pf.get("url", ""),
                        "url":      pf.get("url", ""),
                        "module":   "phishing_monitor",
                    })
                    existing_keys.add(key)

        # ── JS Secrets → main findings ─────────────────────────────────────────────
        for sf in co_data.get("secrets_findings", []):
            sev = sf.get("severity", "high")
            if sev not in ("critical", "high", "medium"):
                continue
            key = f"secret-{sf.get('type','')}-{sf.get('value','')[:40]}-{sf.get('host','')}"
            if key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     "secret",
                    "title":    f"Secret exposto: {sf.get('type','unknown')} em {sf.get('host','')}",
                    "severity": sev,
                    "category": "secrets",
                    "desc":     sf.get("desc") or f"Tipo: {sf.get('type','')} · Arquivo: {sf.get('file','')} · Valor parcial: {str(sf.get('value',''))[:60]}",
                    "host":     sf.get("host", primary_domain),
                    "value":    str(sf.get("value", ""))[:120],
                    "url":      sf.get("file") or sf.get("url", ""),
                    "module":   "js_secrets",
                    "metadata": {
                        "type":        sf.get("type"),
                        "note":        sf.get("note", ""),
                        "secret_type": (sf.get("metadata") or {}).get("secret_type", sf.get("type", "")),
                        "source_url":  sf.get("file") or sf.get("url", ""),
                        "context":     (sf.get("metadata") or {}).get("context", ""),
                    },
                })
                existing_keys.add(key)

        # ── Infra exposure findings ────────────────────────────────────────────────
        for f in co_data.get("infra_data", {}).get("findings", []):
            key = f"infra-{f.get('host','')}-{f.get('port','')}"
            if key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     "infra_exposure",
                    "title":    f.get("title", f"Exposed {f.get('service','')}"),
                    "severity": f.get("severity", "critical"),
                    "category": f.get("category", "infrastructure"),
                    "desc":     f.get("desc", ""),
                    "host":     f.get("host", ""),
                    "value":    f.get("url", ""),
                    "url":      f.get("url", ""),
                    "module":   "infra_exposure",
                    "metadata": {"port": f.get("port"), "ip": f.get("ip"), "open_paths": f.get("open_paths", [])},
                })
                existing_keys.add(key)

        # ── Zone Transfer success → critical finding ───────────────────────────────
        for attempt in co_data.get("zone_transfer_data", {}).get("attempts", []):
            if not attempt.get("success"):
                continue
            key = f"zone-transfer-{attempt.get('domain','')}-{attempt.get('ns','')}"
            if key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     "zone_transfer",
                    "title":    f"Zone Transfer permitido: {attempt.get('domain','')} via {attempt.get('ns','')}",
                    "severity": "critical",
                    "category": "dns",
                    "desc":     (f"AXFR bem-sucedido no nameserver {attempt.get('ns','')} para {attempt.get('domain','')}. "
                                 f"{len(attempt.get('records',[]))} registros expostos. "
                                 f"Permite enumerar toda a zona DNS da empresa."),
                    "host":     attempt.get("domain", ""),
                    "value":    attempt.get("ns", ""),
                    "module":   "zone_transfer",
                    "metadata": {"records_count": len(attempt.get("records",[])), "ns": attempt.get("ns","")},
                })
                existing_keys.add(key)

        # ── VHost discoveries → medium findings ────────────────────────────────────
        for f in co_data.get("vhost_data", {}).get("findings", []):
            key = f"vhost-{f.get('host','')}-{f.get('vhost','')}"
            if key not in existing_keys:
                sev = "high" if any(w in (f.get("vhost","")).lower()
                                    for w in ("admin","staging","dev","test","internal","jenkins","gitlab")) \
                      else "medium"
                all_findings.append({
                    "key":      key,
                    "type":     "vhost",
                    "title":    f"Virtual Host descoberto: {f.get('vhost','')} em {f.get('host','')}",
                    "severity": sev,
                    "category": "discovery",
                    "desc":     (f"VHost `{f.get('vhost','')}` responde com status {f.get('status_code','')} "
                                 f"no IP {f.get('ip','')}. Pode ser ambiente não publicado."),
                    "host":     f.get("host", ""),
                    "value":    f.get("vhost", ""),
                    "module":   "vhost",
                    "metadata": {"ip": f.get("ip",""), "status_code": f.get("status_code",""), "size": f.get("size","")},
                })
                existing_keys.add(key)

        # ── Default credentials → findings ───────────────────────────────────────
        for f in co_data.get("default_creds_data", {}).get("findings", []):
            key = f"defcreds-{f.get('host','')}-{f.get('port','')}"
            if key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     "default_creds",
                    "title":    f.get("title",""),
                    "severity": f.get("severity","high"),
                    "category": "authentication",
                    "desc":     f.get("desc","") + (f" Credenciais: {f['credentials']}" if f.get("credentials") else ""),
                    "host":     f.get("host",""),
                    "value":    f.get("url",""),
                    "url":      f.get("url",""),
                    "module":   "default_creds",
                    "metadata": {"port": f.get("port"), "service": f.get("service"), "ip": f.get("ip")},
                })
                existing_keys.add(key)

        # ── GitHub repo findings ──────────────────────────────────────────────────
        for f in co_data.get("github_repos_data", {}).get("findings", []):
            key = f"github-{f.get('type','')}-{f.get('url','')[:60]}"
            if key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     f.get("type", "github_leak"),
                    "title":    f.get("title", ""),
                    "severity": f.get("severity", "high"),
                    "category": "leaks",
                    "desc":     f.get("desc", ""),
                    "host":     f.get("host", primary_domain),
                    "value":    f.get("url", ""),
                    "url":      f.get("url", ""),
                    "module":   "github_repos",
                })
                existing_keys.add(key)

        # ── DNSSEC findings ───────────────────────────────────────────────────────
        for f in co_data.get("dnssec_data", {}).get("findings", []):
            key = f"dnssec-{f.get('host','')}-{f.get('type','')}"
            if key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     f.get("type", "dnssec"),
                    "title":    f.get("title", ""),
                    "severity": f.get("severity", "medium"),
                    "category": "dns",
                    "desc":     f.get("desc", ""),
                    "host":     f.get("host", primary_domain),
                    "value":    f.get("value", ""),
                    "module":   "dnssec",
                })
                existing_keys.add(key)

        # ── Favicon match findings ─────────────────────────────────────────────────
        for m in co_data.get("favicon_data", {}).get("matches", []):
            severity = "high" if any(kw in (m.get("product","") or m.get("title","")).lower()
                                     for kw in ("vpn","admin","panel","citrix","juniper","fortinet","palo alto","checkpoint")) \
                       else "medium"
            key = f"favicon-{m.get('ip','')}-{m.get('hash','')}"
            if key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     "favicon_match",
                    "title":    f"Favicon Hash Match: {m.get('product') or m.get('title','')} at {m.get('ip','')}",
                    "severity": severity,
                    "category": "discovery",
                    "desc":     (f"Shodan favicon hash match: {m.get('product','?')} "
                                 f"on {m.get('ip','')}:{m.get('port','?')}. "
                                 f"Hash: {m.get('hash','')}"),
                    "host":     m.get("hostname") or m.get("ip",""),
                    "value":    m.get("ip",""),
                    "url":      f"http://{m.get('ip','')}:{m.get('port','')}",
                    "module":   "favicon_hunt",
                    "metadata": m,
                })
                existing_keys.add(key)

        # ── WAF bypass findings ────────────────────────────────────────────────────
        for f in co_data.get("waf_bypass_data", {}).get("findings", []):
            key = f"wafbypass-{f.get('host','')}"
            if key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     "waf_bypass",
                    "title":    f.get("title",""),
                    "severity": f.get("severity","high"),
                    "category": "waf_bypass",
                    "desc":     f.get("desc",""),
                    "host":     f.get("host",""),
                    "value":    f.get("url",""),
                    "url":      f.get("url",""),
                    "module":   "waf_bypass",
                    "metadata": f.get("metadata",{}),
                })
                existing_keys.add(key)

        # ── SMTP findings ──────────────────────────────────────────────────────────
        for f in co_data.get("smtp_data", {}).get("findings", []):
            key = f"smtp-{f.get('host','')}-{f.get('metadata',{}).get('port','')}"
            if key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     "smtp_exposure",
                    "title":    f.get("title",""),
                    "severity": f.get("severity","medium"),
                    "category": "services",
                    "desc":     f.get("desc",""),
                    "host":     f.get("host",""),
                    "value":    f.get("url",""),
                    "url":      f.get("url",""),
                    "module":   "smtp_probe",
                })
                existing_keys.add(key)

        # ── SNMP findings ──────────────────────────────────────────────────────────
        for f in co_data.get("snmp_data", {}).get("findings", []):
            key = f"snmp-{f.get('host','')}"
            if key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     "snmp_public",
                    "title":    f.get("title",""),
                    "severity": f.get("severity","high"),
                    "category": "services",
                    "desc":     f.get("desc",""),
                    "host":     f.get("host",""),
                    "value":    f.get("url",""),
                    "url":      f.get("url",""),
                    "module":   "snmp_probe",
                })
                existing_keys.add(key)

        # ── Host Header Injection findings ────────────────────────────────────────
        hhi_data = _result("host_header_injection")
        if hhi_data.get("findings"):
            co_data["hhi_data"] = hhi_data
            log(f"  ↳ Host Header Injection: {hhi_data.get('vulnerable',0)} hosts vulneráveis")
        for f in co_data.get("hhi_data", {}).get("findings", []):
            key = f"hhi-{f.get('host','')}-{f.get('metadata',{}).get('header','')}"
            if key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     "host_header_injection",
                    "title":    f.get("title",""),
                    "severity": f.get("severity","high"),
                    "category": "injection",
                    "desc":     f.get("desc",""),
                    "host":     f.get("host",""),
                    "value":    f.get("url",""),
                    "url":      f.get("url",""),
                    "module":   "host_header_injection",
                    "metadata": f.get("metadata",{}),
                })
                existing_keys.add(key)

        # ── Open Redirect findings ─────────────────────────────────────────────────
        or_data = _result("open_redirect")
        if or_data.get("findings"):
            co_data["open_redirect_data"] = or_data
            log(f"  ↳ Open Redirect: {or_data.get('vulnerable',0)} URLs vulneráveis")
        for f in co_data.get("open_redirect_data", {}).get("findings", []):
            key = f"openredir-{f.get('host','')}-{f.get('url','')[:60]}"
            if key not in existing_keys:
                _or_url = f.get("url", "")
                _pm = re.search(r'\?([^=&]+)=', _or_url)
                _param = _pm.group(1) if _pm else ""
                _title = f"Open Redirect (?{_param}): {f.get('host','')}" if _param else f.get("title", "")
                all_findings.append({
                    "key":      key,
                    "type":     "open_redirect",
                    "title":    _title,
                    "severity": f.get("severity","medium"),
                    "category": "injection",
                    "desc":     f.get("desc",""),
                    "host":     f.get("host",""),
                    "value":    f.get("url",""),
                    "url":      f.get("url",""),
                    "module":   "open_redirect",
                })
                existing_keys.add(key)

        # ── Tableau findings ──────────────────────────────────────────────────────────
        tab_data = _result("tableau")
        if tab_data.get("findings"):
            co_data["tableau_data"] = tab_data
            log(f"  ↳ Tableau: {len(tab_data.get('findings',[]))} exposures")
        for f in co_data.get("tableau_data", {}).get("findings", []):
            key = f"tableau-{f.get('host','')}-{f.get('url','')[-40:]}"
            if key not in existing_keys:
                all_findings.append({
                    "key":      key,
                    "type":     "tableau_exposure",
                    "title":    f.get("title", ""),
                    "severity": f.get("severity", "medium"),
                    "category": "exposure",
                    "desc":     f.get("desc", ""),
                    "host":     f.get("host", ""),
                    "value":    f.get("url", ""),
                    "url":      f.get("url", ""),
                    "module":   "tableau",
                })
                existing_keys.add(key)

        # ── Cross-module correlation — chain findings on same host ────────────────────
        host_findings: dict[str, list[dict]] = {}
        for f in all_findings:
            h = f.get("host","")
            if h:
                host_findings.setdefault(h, []).append(f)

        for hostname, hf in host_findings.items():
            sevs = {f.get("severity") for f in hf}
            cats = {f.get("category") for f in hf}

            # Pattern 1: secret + active port = critical chain
            has_secret = any(f.get("type") == "secret" for f in hf)
            has_dangerous_port = any(f.get("type") in ("default_creds","infra_exposure") for f in hf)
            if has_secret and has_dangerous_port and "critical" not in sevs:
                key = f"chain-secret-port-{hostname}"
                if key not in existing_keys:
                    secret_types = [f.get("metadata",{}).get("type","?") for f in hf if f.get("type")=="secret"]
                    all_findings.append({
                        "key":      key,
                        "type":     "attack_chain",
                        "title":    f"Attack Chain: Secret + Exposed Service em {hostname}",
                        "severity": "critical",
                        "category": "correlation",
                        "desc":     f"Host {hostname} tem simultaneamente: segredos expostos ({', '.join(set(secret_types))}) e serviços sem autenticação. Combinação permite acesso direto ao ambiente.",
                        "host":     hostname,
                        "module":   "correlation",
                    })
                    existing_keys.add(key)

            # Pattern 2: no WAF + critical finding = escalate note
            host_obj = next((h for h in co_data.get("hosts",[]) if h.get("host")==hostname), {})
            no_waf = not host_obj.get("waf") or host_obj.get("waf") == "Direct"
            has_critical = "critical" in sevs
            if no_waf and has_critical:
                key = f"chain-nowaf-critical-{hostname}"
                if key not in existing_keys:
                    all_findings.append({
                        "key":      key,
                        "type":     "attack_chain",
                        "title":    f"Sem WAF + Finding Crítico: {hostname}",
                        "severity": "critical",
                        "category": "correlation",
                        "desc":     f"Host {hostname} expõe finding crítico diretamente à internet (sem WAF). Exploração direta sem obstáculos.",
                        "host":     hostname,
                        "module":   "correlation",
                    })
                    existing_keys.add(key)

            # Pattern 3: 3+ high/critical findings on one host = concentrated surface
            critical_high = [f for f in hf if f.get("severity") in ("critical","high")]
            if len(critical_high) >= 3:
                key = f"chain-concentrated-{hostname}"
                if key not in existing_keys:
                    titles = [f.get("title","")[:50] for f in critical_high[:3]]
                    all_findings.append({
                        "key":      key,
                        "type":     "attack_chain",
                        "title":    f"Superfície concentrada: {len(critical_high)} findings críticos/altos em {hostname}",
                        "severity": "high",
                        "category": "correlation",
                        "desc":     f"Host {hostname} concentra {len(critical_high)} findings de alta severidade: {'; '.join(titles)}",
                        "host":     hostname,
                        "module":   "correlation",
                    })
                    existing_keys.add(key)

        # ── Normalize remaining legacy findings ────────────────────────────────
        all_findings = [_normalize_finding(f, f.get("module") or f.get("category") or "general") for f in all_findings]

        # ── Semantic deduplication — normalize equivalent findings ────────────────────
        def _semantic_key(f: dict) -> str:
            """Generate a semantic key for grouping equivalent findings."""
            import re as _re
            host = f.get("host","").lower().removeprefix("www.")
            ftype = f.get("type","")
            title = f.get("title","").lower()
            # Normalize version numbers out of title for CVE grouping
            title_norm = _re.sub(r'\b\d+\.\d+[\.\d]*\b', 'VER', title)
            title_norm = _re.sub(r'\s+', ' ', title_norm).strip()
            # Key: host + type + normalized title (first 80 chars)
            return f"{host}||{ftype}||{title_norm[:80]}"

        seen_semantic: dict[str, dict] = {}
        for f in all_findings:
            sk = _semantic_key(f)
            if sk not in seen_semantic:
                seen_semantic[sk] = f
            else:
                # Keep the higher severity finding
                existing = seen_semantic[sk]
                sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                if sev_order.get(f.get("severity","info"), 4) < sev_order.get(existing.get("severity","info"), 4):
                    seen_semantic[sk] = f
        all_findings = list(seen_semantic.values())

        # ── Deduplicate ────────────────────────────────────────────────────────
        all_findings = dedup_findings(all_findings, "general")

        if all_findings:
            co_data["findings"] = all_findings

        # ── Checkpoint delta — tag findings/hosts that are NEW since last scan ──────
        try:
            prev_snap = self.db.load_snapshot(cid, slot="previous")
            if prev_snap:
                prev_finding_keys = {f.get("key","") for f in prev_snap.get("findings", [])}
                prev_host_names   = {h.get("host","") for h in prev_snap.get("hosts", [])}
                prev_subdomain_set = set(prev_snap.get("ct_subdomains", []))

                new_findings  = [f for f in all_findings if f.get("key","") not in prev_finding_keys]
                new_hosts     = [h for h in co_data.get("hosts",[]) if h.get("host","") not in prev_host_names]
                new_subdomains = [s for s in co_data.get("ct_subdomains",[]) if s not in prev_subdomain_set]

                # Tag each new finding
                for f in new_findings:
                    f["is_new"] = True

                co_data["checkpoint_diff"] = {
                    "new_findings_count":   len(new_findings),
                    "new_hosts_count":      len(new_hosts),
                    "new_subdomains_count": len(new_subdomains),
                    "new_findings":         [f.get("key","") for f in new_findings[:50]],
                    "new_hosts":            [h.get("host","") for h in new_hosts[:50]],
                    "new_subdomains":       new_subdomains[:100],
                    "compared_to":          prev_snap.get("scanned_at", ""),
                }
                log(f"  ↳ Delta vs scan anterior: +{len(new_findings)} findings · +{len(new_hosts)} hosts · +{len(new_subdomains)} subdomínios")

            # Save current state as new "previous" snapshot for next run
            self.db.save_snapshot(cid, {
                "scanned_at":   datetime.now().isoformat(timespec="seconds"),
                "findings":     [{"key": f.get("key",""), "severity": f.get("severity","")} for f in all_findings],
                "hosts":        [{"host": h.get("host","")} for h in co_data.get("hosts",[])],
                "ct_subdomains": co_data.get("ct_subdomains", []),
            }, slot="previous")
        except Exception as e:
            log(f"  ⚠ Checkpoint delta falhou: {e}")

        # Fix js_data total_secrets count
        js_files = co_data.get("js_data", {}).get("js_files", [])
        if js_files and co_data.get("js_data", {}).get("total_secrets") is None:
            co_data["js_data"]["total_secrets"] = sum(len(f.get("secrets", [])) for f in js_files)

        # ── Cloud provider enrichment ──────────────────────────────────────────────
        try:
            from core.recon import detect_cloud_provider, classify_service
            cloud_counts = {}
            for h in co_data.get("hosts", []):
                ip = (h.get("ip") or "").split(",")[0].strip()
                if ip:
                    provider = detect_cloud_provider(ip)
                    if provider:
                        h["cloud_provider"] = provider
                        cloud_counts[provider] = cloud_counts.get(provider, 0) + 1
                # Enrich ports with service classification
                ports = h.get("ports", [])
                if ports and not h.get("port_details"):
                    h["port_details"] = [classify_service(int(p)) for p in ports if str(p).isdigit()]
            if cloud_counts:
                co_data["cloud_assets"] = cloud_counts
                log(f"  ↳ Cloud: {cloud_counts}")
        except Exception as e:
            log(f"  ⚠ Cloud enrichment failed: {e}")

        # Rebuild stats with all frontend-required fields
        def _count_sev(sev): return sum(1 for f in all_findings if f.get("severity") == sev)
        co_data.setdefault("stats", {}).update({
            "live_hosts":        len(co_data.get("hosts", [])),
            "subdomains":        len(co_data.get("hosts", [])),
            "findings_critical": _count_sev("critical"),
            "findings_high":     _count_sev("high"),
            "findings_medium":   _count_sev("medium"),
            "findings_info":     _count_sev("info"),
            "open_ports":        len(co_data.get("port_scan", {}).get("results", [])),
            "waf_protected":     sum(co_data.get("waf_coverage", {}).values()),
            "screenshots":       int(co_data.get("screenshots_count") or 0),
        })
        log(f"  ↳ Stats: {co_data['stats']['findings_critical']}c/{co_data['stats']['findings_high']}h/{co_data['stats']['findings_medium']}m findings, {co_data['stats']['open_ports']} ports")

        # Timestamp of last full pipeline run
        now_ts = datetime.now().isoformat(timespec="seconds")
        co_data["pipeline_ran_at"] = now_ts
        co_data["last_scan"] = now_ts

        # Modules that did not complete successfully, plus justified skips.
        not_done, skipped_modules = self._pipeline_execution_summary(cid, _options or {})
        co_data["not_done"] = not_done
        co_data["skipped_modules"] = skipped_modules

        try:
            self.db.save_asm_data(data)
            log(f"  ✓ Resultados do pipeline persistidos na base de dados")
        except Exception as e:
            log(f"  ⚠ Falha ao salvar dados ASM: {e}")

    # ── Full pipeline ────────────────────────────────────────────────────────────

    def _check_gate(self, cid: str, gate: str, domain: str = "", hosts: list[dict] | None = None) -> bool:
        hosts = hosts if hosts is not None else self._load_hosts(cid)

        def _is_live(h: dict) -> bool:
            return _is_responsive(h)


        # Gates booleanos existentes
        if gate == "has_live_hosts":
            return any(_is_live(h) for h in hosts)
        if gate == "has_open_ports":
            return any(h.get("ports") for h in hosts)

        # Gates numéricos
        if gate.startswith("min_hosts:"):
            threshold = int(gate.split(":")[1])
            live_count = len([h for h in hosts if _is_live(h)])
            return live_count >= threshold

        if gate.startswith("min_subdomains:") and domain:
            threshold = int(gate.split(":")[1])
            all_subs = set()
            for h in hosts:
                if domain in h.get("host", ""):
                    all_subs.add(h["host"])
            return len(all_subs) >= threshold

        # Gates contextuais
        if gate == "has_web_endpoints":
            for h in hosts:
                endpoints = h.get("endpoints") or []
                if endpoints:
                    interesting = [
                        e for e in endpoints
                        if any(kw in str(e).lower() for kw in ["login", "admin", "api", "panel", "dashboard"])
                    ]
                    if interesting:
                        return True
            return False

        if gate == "has_js_files":
            return any(
                h.get("js_files") or h.get("javascript")
                for h in hosts
            )

        # has_tech:keyword1,keyword2 — True if ANY keyword appears in ANY host's techs
        if gate.startswith("has_tech:"):
            keywords = [k.strip().lower() for k in gate.split(":", 1)[1].split(",")]
            all_techs = self._get_detected_techs(cid)
            return any(kw in tech for kw in keywords for tech in all_techs)

        return True

    def _detect_cloudflare_coverage(self, cid: str) -> float:
        """Retorna % de hosts protegidos por Cloudflare."""
        hosts = self._load_hosts(cid)
        if not hosts:
            return 0.0

        cloudflare_hosts = 0
        for h in hosts:
            waf = str(h.get("waf", "")).lower()
            techs = [str(t).lower() for t in h.get("technologies", [])]
            if "cloudflare" in waf or any("cloudflare" in t for t in techs):
                cloudflare_hosts += 1

        return (cloudflare_hosts / len(hosts)) * 100 if hosts else 0.0

    def run_pipeline(self, cid: str, co: dict, options: dict):
        """Execute full recon pipeline in ordered phases. Blocking — run in thread."""
        options      = self._resolve_pipeline_profile(options)
        domain       = co["domains"][0] if co.get("domains") else ""
        mode         = options.get("mode", _rl.DEFAULT_MODE)
        total_phases = len(PIPELINE_PHASES)
        cf_detected  = False

        # In queue mode, use the specific target domain for checkpoint isolation
        queue_target = options.get("queue_domain", "")

        # Load any previously completed modules so we can resume after a restart
        self._load_checkpoints(cid, target=queue_target)
        current_hosts = self._filter_hosts_for_options(self._load_hosts(cid), co, options)
        previous_state = self.pipeline_state.get(cid, {}) or self._load_pipeline_state(cid) or {}
        current_scope_hash = self._scan_scope_hash(co)
        previous_scope_hash = previous_state.get("scope_hash") or ""

        scoped_queue_run = bool(options.get("queue_domain"))
        if previous_scope_hash and previous_scope_hash != current_scope_hash and not scoped_queue_run:
            self._invalidate_checkpoint_modules(
                cid,
                [
                    "subfinder", "assetfinder", "theharvester", "amass",
                    "hackertarget", "alienvault_otx", "hunterio", "riddler", "urlscan_io",
                    "rapiddns", "github_subdomains", "dns", "email", "certs",
                    "asn", "asnmap", "related", "reverse_whois", "typosquat", "zone_transfer",
                    "shodan", "breach", "certstream", "phishing", "postman_collections",
                    "apk_recon", "dep_confusion", "cloud",
                    "dns_brute", "leaks", "headers", "waf", "wappalyzer", "whatweb", "vendor_fp",
                    "js", "js_endpoints", "js_secrets", "wayback", "urlfinder", "screenshot",
                    "gowitness", "favicon_hunt", "browser_crawl", "vhost", "param_mine",
                    "origin_discovery", "portscan", "cloudlist", "services", "cms_scan",
                    "takeover", "subjack", "cve", "cloud_enum", "cors_scan", "infra_exposure",
                    "default_creds", "database_enum_extra", "graphql", "browser_recon", "supply_chain", "github_repos",
                    "dnssec", "waf_bypass", "smtp_probe", "snmp_probe", "host_header_injection",
                    "open_redirect", "tableau", "api_panels",
                    "container_registry", "bulk_dataset", "service_version",
                    "udp_portscan", "api_discovery_extra", "screenshot_diff",
                ],
                reason="scope changed",
            )

        try:
            from core.checkpoints import run_checkpoint_scan as _run_checkpoint_scan
            # Smart-scan checkpoint fingerprints every known host (httpx GET) to
            # decide which browser/check phases need a re-scan. Large bug-bounty
            # queues already run per selected domain, so the smart diff is skipped
            # by default unless an operator explicitly enables it.
            if options.get("skip_smart_scan"):
                host_targets = []
            else:
                host_targets = [h.get("host") for h in current_hosts if isinstance(h, dict) and h.get("host")]
            if host_targets:
                checkpoint_result = _run_checkpoint_scan(
                    cid,
                    host_targets,
                    max_workers=min(12, max(4, len(host_targets))),
                )
                diff = checkpoint_result.get("diff")
                needs_rescan = list(getattr(diff, "needs_rescan", [])) if diff else []
                if needs_rescan:
                    self.pipeline_state.setdefault(cid, {})["smart_scan_diff"] = {
                        "summary": checkpoint_result.get("summary", ""),
                        "needs_rescan": needs_rescan[:200],
                        "new": list(getattr(diff, "new", []))[:200],
                        "changed": list(getattr(diff, "changed", []))[:200],
                        "removed": list(getattr(diff, "removed", []))[:200],
                        "first_run": bool(checkpoint_result.get("first_run")),
                    }
                    self._invalidate_checkpoint_modules(
                        cid,
                        [
                            "validation", "fingerprint", "js_discovery", "api_mapping",
                            "browser", "bug_checks", "ports_services", "nuclei",
                        ],
                        reason=checkpoint_result.get("summary", "host or app fingerprint changed"),
                    )
        except Exception as e:
            print(f"[checkpoint] {cid}: smart scan diff failed: {e}")

        def _log(msg: str):
            entry = {"ts": datetime.now().isoformat(timespec="seconds"), "msg": msg}
            self.pipeline_state[cid]["log"].append(entry)

        # Optional Mullvad integration: disabled by default.
        if _mullvad_enabled():
            try:
                import mullvad_rotator as _mr
                rotator = _mr.Rotator(
                    log_callback=_log,
                    ip_callback=lambda ip: self.pipeline_state[cid].update({"mullvad_ip": ip}),
                )
                if not hasattr(self, "_mullvad_rotators"):
                    self._mullvad_rotators = {}
                self._mullvad_rotators[cid] = rotator

                if not _mr.is_connected():
                    _log("⚠ Mullvad desconectado — tentando conectar...")
                    try:
                        subprocess.run(["mullvad", "connect"], capture_output=True, timeout=15)
                        import time as _t; _t.sleep(3)
                        ip_now = rotator.wait_connected(20)
                        self.pipeline_state[cid]["mullvad_ip"] = ip_now
                        _log(f"🌐 Mullvad conectado: {ip_now}")
                    except Exception:
                        _log("⚠ Não foi possível conectar ao Mullvad — scans continuarão sem VPN")
                else:
                    ip_now = _mr.current_ip()
                    if ip_now:
                        self.pipeline_state[cid]["mullvad_ip"] = ip_now
                    _log(_mr.status_line())
            except Exception:
                pass

        def _run_module(module: str, limiter=None):
            job_key = f"{cid}:{module}"

            # Check if pipeline was stopped
            if self.pipeline_state.get(cid, {}).get("status") == "stopped":
                return

            max_retries = 2
            for attempt in range(max_retries + 1):
                hosts = self._filter_hosts_for_options(self._load_hosts(cid), co, options)
                if self._module_checkpoint_is_valid(cid, module, co, hosts, options):
                    _log(f"  ⏩ {module} — checkpoint válido (smart scan)")
                    return

                self.results[job_key] = {
                    "status":     "running",
                    "started_at": datetime.now().isoformat(timespec="seconds"),
                }
                self._run_context.cid = cid
                self._run_context.module = module
                _SUBPROCESS_CONTEXT.db = self.db
                _SUBPROCESS_CONTEXT.cid = cid
                _SUBPROCESS_CONTEXT.module = module
                if self._recon and hasattr(self._recon, "set_subprocess_context"):
                    try:
                        self._recon.set_subprocess_context(self.db, cid, module)
                    except Exception:
                        pass
                _ct.set_tracer(lambda cmd, _m=module: self._record_tool_log(cid, _m, cmd))
                if limiter:
                    _rl.set_limiter(limiter)
                try:
                    result = self._make_fn_map(cid, co, options, hosts)[module]()
                    envelope = _normalize_module_envelope(module, result)
                    
                    # ── Check if pipeline was stopped during module execution ──
                    if self.pipeline_state.get(cid, {}).get("status") == "stopped":
                        _log(f"  ⏹ {module} interrompido — pipeline stopped")
                        now_ts = datetime.now()
                        finished_at = now_ts.isoformat(timespec="seconds")
                        started_at = (self.results.get(job_key) or {}).get("started_at", finished_at)
                        duration_s = round(
                            (now_ts - datetime.fromisoformat(started_at)).total_seconds(), 2
                        ) if started_at else 0.0
                        self.results[job_key] = {
                            "status": "stopped",
                            "reason": "pipeline stopped",
                            "data": envelope["data"],
                            "metrics": envelope["metrics"],
                            "artifacts": envelope["artifacts"],
                            "blocked": envelope["blocked"],
                            "duration": duration_s,
                            "started_at": started_at,
                            "finished_at": finished_at,
                        }
                        break

                    blocked = bool(envelope.get("blocked"))
                    if blocked and attempt < max_retries and self._check_blocked_and_rotate(cid, module, forced=True):
                        _log(f"  🔄 {module}: retry {attempt + 1}/{max_retries} após rotação")
                        continue

                    if blocked and envelope["status"] == "done":
                        envelope["status"] = "error"
                        envelope["reason"] = envelope["reason"] or "blocked"

                    now_ts = datetime.now()
                    finished_at = now_ts.isoformat(timespec="seconds")
                    started_at = (self.results.get(job_key) or {}).get("started_at", finished_at)
                    duration_s = round(
                        (now_ts - datetime.fromisoformat(started_at)).total_seconds(), 2
                    ) if started_at else 0.0

                    self.results[job_key] = {
                        "status":      envelope["status"],
                        "reason":      envelope["reason"],
                        "data":        envelope["data"],
                        "metrics":     envelope["metrics"],
                        "artifacts":   envelope["artifacts"],
                        "blocked":     envelope["blocked"],
                        "duration":    duration_s,
                        "fingerprint": self._module_checkpoint_fingerprint(cid, module, co, hosts, options),
                        "started_at":  started_at,
                        "finished_at": finished_at,
                    }

                    metrics_preview = ", ".join(
                        f"{k}={v}" for k, v in list((envelope["metrics"] or {}).items())[:4]
                    )
                    if envelope["status"] == "done":
                        summary = f"in={len(hosts)}"
                        if metrics_preview:
                            summary += f" | {metrics_preview}"
                        _log(f"  ✓ {module} concluído — {summary}")
                        self._save_checkpoint(cid, module, target=queue_target)
                    elif envelope["status"] == "skipped":
                        _log(f"  ⏭ {module} pulado — {envelope['reason'] or 'skipped'} | in={len(hosts)}")
                    elif envelope["status"] == "timeout":
                        _log(f"  ⏱ {module} timeout — {envelope['reason'] or 'timeout'} | in={len(hosts)}")
                    else:
                        _log(f"  ⚠ {module} falhou — {envelope['reason'] or 'error'} | in={len(hosts)}")
                except Exception as e:
                    # Check if exception indicates network blocking
                    err_str = str(e).lower()
                    blocked_errors = ["rate limit", "429", "too many requests", 
                                     "connection refused", "connection reset",
                                     "blocked", "timeout", "context deadline"]
                    is_block = any(x in err_str for x in blocked_errors)
                    if is_block and attempt < max_retries and self._check_blocked_and_rotate(cid, module, forced=True):
                        _log(f"  🔄 {module}: erro de rede detectado — retry {attempt + 1}/{max_retries}")
                        continue
                    status, reason = _classify_result_status(None, str(e))
                    now_ts = datetime.now()
                    finished_at = now_ts.isoformat(timespec="seconds")
                    started_at = (self.results.get(job_key) or {}).get("started_at", finished_at)
                    duration_s = round(
                        (now_ts - datetime.fromisoformat(started_at)).total_seconds(), 2
                    ) if started_at and started_at != finished_at else 0.0
                    self.results[job_key] = {
                        "status":      status,
                        "error":       str(e),
                        "reason":      reason or str(e),
                        "data":        None,
                        "metrics":     {},
                        "artifacts":   {},
                        "blocked":     False,
                        "duration":    duration_s,
                        "fingerprint": self._module_checkpoint_fingerprint(cid, module, co, hosts, options),
                        "started_at":  started_at,
                        "finished_at": finished_at,
                    }
                    if status == "timeout":
                        _log(f"  ⏱ {module} timeout — {reason or e} | in={len(hosts)}")
                    elif status == "skipped":
                        _log(f"  ⏭ {module} pulado — {reason or e} | in={len(hosts)}")
                    else:
                        _log(f"  ⚠ {module} falhou: {e} — seguindo com o próximo módulo")
                finally:
                    self._run_context.cid = ""
                    self._run_context.module = ""
                    _SUBPROCESS_CONTEXT.db = None
                    _SUBPROCESS_CONTEXT.cid = ""
                    _SUBPROCESS_CONTEXT.module = ""
                    if self._recon and hasattr(self._recon, "set_subprocess_context"):
                        try:
                            self._recon.set_subprocess_context(None, "", "")
                        except Exception:
                            pass
                    _ct.clear_tracer()
                    _rl.clear_limiter()
                break  # success or non-retryable error

        self.pipeline_state[cid]["status"] = "running"
        self.pipeline_state[cid]["scope_hash"] = current_scope_hash
        self.pipeline_state[cid]["host_fp_hash"] = self._host_fingerprint_hash(current_hosts)

        for phase_idx, phase in enumerate(PIPELINE_PHASES):
            # ── Check if pipeline was stopped ──
            if self.pipeline_state.get(cid, {}).get("status") == "stopped":
                _log("⏹ Pipeline stopped by user")
                break

            phase_id    = phase["id"]
            phase_label = phase["label"]
            modules     = phase["modules"]

            # ── Gate: skip phase if condition not met ─────────────────────────
            gate = phase.get("gate")
            phase_hosts = self._filter_hosts_for_options(self._load_hosts(cid), co, options)
            if gate and not self._check_gate(cid, gate, domain, phase_hosts):
                _log(f"⏭ {phase_label} — gate '{gate}' não satisfeito, pulando")
                for m in modules:
                    self.results[f"{cid}:{m}"] = {
                        "status": "skipped",
                        "reason": f"Gate not satisfied: {gate}",
                        "data": None,
                        "metrics": {},
                        "artifacts": {},
                        "blocked": False,
                    }
                continue

            # ── Internal phase: executa método direto (ex: cleanup) ────────────
            if phase.get("internal"):
                self.pipeline_state[cid].update({
                    "phase_idx":   phase_idx,
                    "phase_id":    phase_id,
                    "phase_label": phase_label,
                })
                _log(f"▶ Fase {phase_idx + 1}/{total_phases}: {phase_label}")

                if phase_id == "cleanup":
                    cleanup_result = self._auto_cleanup_phase(cid, domain, _log)
                    self.results[f"{cid}:cleanup"] = {
                        "status": "done",
                        "reason": "",
                        "data": cleanup_result,
                        "metrics": _summarize_payload_metrics(cleanup_result),
                        "artifacts": {},
                        "blocked": False,
                        "finished_at": datetime.now().isoformat(timespec="seconds"),
                    }

                _log(f"  ✓ {phase_label} concluída")
                self._save_pipeline_state(cid)
                continue

            # ── Rate limiter for this phase ────────────────────────────────────
            phase_limiter = _rl.make_limiter(phase.get("rate_phase", "passive"), mode)
            rate_info = (
                f"{phase_limiter.base_rate:.1f} req/s, jitter {phase_limiter.jitter}s"
                if phase_limiter else "ilimitado"
            )

            self.pipeline_state[cid].update({
                "phase_idx":   phase_idx,
                "phase_id":    phase_id,
                "phase_label": phase_label,
                "mode":        mode,
                "rate_info":   rate_info,
            })
            _log(f"▶ Fase {phase_idx + 1}/{total_phases}: {phase_label} — {len(modules)} módulos [{mode} · {rate_info}]")

            # ── IP rotation: rotate every ~3 phases to avoid fingerprinting ──
            if _mullvad_enabled() and modules and phase_idx > 0 and phase_idx % 3 == 0:
                try:
                    import mullvad_rotator as _mr
                    rotator = (getattr(self, "_mullvad_rotators", {}) or {}).get(cid)
                    if rotator and _mr.is_connected():
                        new_ip = rotator.rotate(wait=15)
                        if new_ip:
                            self.pipeline_state[cid]["mullvad_ip"] = new_ip
                            _log(f"  🔄 Scheduled IP rotation → {new_ip}")
                        else:
                            _log(f"  🚨 Mullvad rotation FAILED — IP não mudou, scans expostos ao alvo")
                            self.pipeline_state[cid].setdefault("mullvad_failures", []).append({
                                "phase": phase_label, "ts": datetime.now().isoformat(timespec="seconds"),
                                "reason": "rotate() returned None",
                            })
                    elif rotator:
                        _log(f"  🚨 Mullvad desconectado na fase {phase_label} — scans sem VPN")
                        self.pipeline_state[cid].setdefault("mullvad_failures", []).append({
                            "phase": phase_label, "ts": datetime.now().isoformat(timespec="seconds"),
                            "reason": "not connected",
                        })
                except Exception as _rot_e:
                    _log(f"  🚨 Mullvad rotation exception na fase {phase_label}: {_rot_e}")
                    self.pipeline_state[cid].setdefault("mullvad_failures", []).append({
                        "phase": phase_label, "ts": datetime.now().isoformat(timespec="seconds"),
                        "reason": str(_rot_e),
                    })

            if phase.get("parallel", True) and modules:
                workers = min(_MAX_PARALLEL_MODULES, len(modules))
                with ThreadPoolExecutor(max_workers=workers) as _pool:
                    futs = [_pool.submit(_run_module, m, phase_limiter) for m in modules]
                    for idx, f in enumerate(futs):
                        try:
                            f.result()
                        except Exception:
                            pass
                        if self.pipeline_state.get(cid, {}).get("status") == "stopped":
                            _log("  ⏹ Pipeline stopped — cancelando módulos restantes")
                            for remaining in futs[idx + 1:]:
                                try: remaining.cancel()
                                except: pass
                            break
            else:
                for m in modules:
                    _run_module(m, phase_limiter)
                    if self.pipeline_state.get(cid, {}).get("status") == "stopped":
                        _log("  ⏹ Pipeline stopped")
                        break

            errors = [
                m for m in modules
                if self.results.get(f"{cid}:{m}", {}).get("status") == "error"
            ]
            if errors:
                _log(f"  ⚠ Erros em: {', '.join(errors)}")
            _log(f"  ✓ {phase_label} concluída")

            # Save state so frontend sees progress immediately
            self.pipeline_state[cid]["phase_idx"] = phase_idx
            self.pipeline_state[cid]["phase_id"] = phase_id
            self._save_pipeline_state(cid)
            # Persist deferred to end of pipeline — avoids DB lock contention
            # between persist thread and pipeline gate checks

            # ── Cloudflare detection & mode adjustment (após Fase 4 profiling) ──
            if phase_id == "fingerprint" and not cf_detected:
                cf_coverage = self._detect_cloudflare_coverage(cid)
                if cf_coverage >= 80:
                    cf_detected = True
                    mode = "stealth"
                    _log(f"  🛡 Detectado {cf_coverage:.0f}% Cloudflare — modo stealth ativado")

            if phase.get("merge_hosts"):
                _log("  ↳ Coletando subdomínios descobertos…")
                all_co_domains = co.get("domains", [domain])
                new_subs = self._collect_new_subdomains(cid, domain, all_co_domains)
                _log(f"  ↳ _collect_new_subdomains retornou: {len(new_subs)} subdomínios")
                inventory_hosts = {
                    h["host"]: h for h in self._load_hosts(cid)
                    if isinstance(h, dict) and h.get("host")
                }
                subs_to_probe = [
                    s for s in new_subs
                    if s not in inventory_hosts or not _is_responsive(inventory_hosts.get(s, {}))
                ]
                _log(f"  ↳ Subdomínios para sondar (após filtrar já validados): {len(subs_to_probe)}")
                if subs_to_probe:
                    inserted = self._upsert_discovered_hosts(
                        cid, subs_to_probe, all_co_domains, source=f"phase:{phase_id}"
                    )
                    if inserted:
                        _log(f"  ↳ {len(inserted)} hosts descobertos persistidos antes da validação")
                    _log(f"  ↳ Sondando {len(subs_to_probe)} novos subdomínios com httpx…")
                    live  = self._probe_hosts_with_httpx(subs_to_probe, cid)
                    _log(f"  ↳ _probe_hosts_with_httpx retornou: {len(live)} hosts vivos")

                    # ── WAF block detection: if >10% of results are 403 (min 2) → bypass ──
                    if len(live) >= 3:
                        blocked_hosts = [h for h in live if h.get("status_code") == 403]
                        if len(blocked_hosts) >= 2 and len(blocked_hosts) > len(live) * 0.10:
                            _log(f"  🛡 WAF detectado: {len(blocked_hosts)}/{len(live)} hosts retornaram 403")
                            blocked_names = [h["host"] for h in blocked_hosts]
                            bypassed = False

                            # ── Step 1: try User-Agent rotation first (fast, no VPN change) ──
                            import core.recon as _recon_module
                            for ua_attempt in range(3):
                                new_ua = random.choice(_recon_module._UA_POOL)
                                new_lang = _recon_module._random_accept_language()
                                _log(f"  🎭 Tentando bypass UA ({ua_attempt+1}/3): {new_ua[:60]}...")
                                retry = self._probe_hosts_with_httpx(blocked_names, cid,
                                    extra_headers=[f"User-Agent: {new_ua}", f"Accept-Language: {new_lang}"])
                                still_403 = sum(1 for h in retry if h.get("status_code") == 403)
                                if still_403 < len(blocked_names) * 0.5:
                                    _log(f"  ✅ Bypass UA funcionou: {still_403}/{len(blocked_names)} ainda bloqueados")
                                    # Merge retry results
                                    live_map = {h["host"]: h for h in live}
                                    for h in retry:
                                        live_map[h["host"]] = h
                                    live = list(live_map.values())
                                    bypassed = True
                                    break
                                _log(f"  ⚠ UA {ua_attempt+1}: {still_403}/{len(blocked_names)} ainda bloqueados")
                            
                            # ── Step 2: if UA rotation didn't work, rotate Mullvad IP (up to 3 attempts) ──
                            if _mullvad_enabled() and not bypassed:
                                _log(f"  🔄 UA bypass failed — rotating Mullvad IP (up to 3 attempts)...")
                                try:
                                    import mullvad_rotator as _mr
                                    rotator = (getattr(self, "_mullvad_rotators", {}) or {}).get(cid)
                                    if rotator and _mr.is_connected():
                                        for ip_attempt in range(3):
                                            try:
                                                rotator.rotate(wait=15)
                                            except Exception as rot_err:
                                                _log(f"  ⚠ IP rotation attempt {ip_attempt+1} failed: {rot_err}")
                                                break
                                            new_ip = _mr.current_ip()
                                            self.pipeline_state[cid]["mullvad_ip"] = new_ip
                                            _log(f"  🔄 IP rotated → {new_ip} (attempt {ip_attempt+1}/3)")
                                            retry = self._probe_hosts_with_httpx(blocked_names, cid)
                                            still_403 = sum(1 for h in retry if h.get("status_code") == 403)
                                            _log(f"  ↳ After IP rotation: {still_403}/{len(blocked_names)} hosts still blocked")
                                            # Merge results regardless
                                            live_map = {h["host"]: h for h in live}
                                            for h in retry:
                                                live_map[h["host"]] = h
                                            live = list(live_map.values())
                                            if still_403 < len(blocked_names) * 0.5:
                                                _log(f"  ✅ IP rotation unblocked {len(blocked_names) - still_403}/{len(blocked_names)} hosts")
                                                bypassed = True
                                                break
                                            _log(f"  ⚠ IP rotation attempt {ip_attempt+1}: still {still_403}/{len(blocked_names)} blocked, retrying...")
                                        if not bypassed:
                                            _log(f"  ✗ WAF bypass exhausted — {len(blocked_names)} hosts remain partially blocked")
                                    else:
                                        _log(f"  ⚠ Mullvad not connected — IP bypass unavailable")
                                except Exception as e:
                                    _log(f"  ⚠ IP rotation error: {e}")

                    unresolved_count = len(subs_to_probe) - len(live)
                    if unresolved_count > 0:
                        _log(f"  ↳ {unresolved_count} hosts persistidos como pendentes (sem resposta httpx)")

                    total = self._merge_hosts_into_asm_data(cid, live)
                    _log(f"  ↳ _merge_hosts_into_asm_data retornou total: {total}")
                    self.pipeline_state[cid]["host_count"] = total
                    _log(f"  ↳ {len(live)} hosts vivos adicionados — pool total: {total}")

                    if phase.get("recursive") and subs_to_probe:
                        _log(f"  ↳ Protocolo recursivo: enumerando sub-subdomínios…")
                        added = self._recursive_enum(
                            cid, co, options, subs_to_probe, depth=0, _log=_log
                        )
                        if added:
                            new_total = len(self._load_hosts(cid))
                            self.pipeline_state[cid]["host_count"] = new_total
                            _log(f"  ↳ Recursão: +{added} hosts — pool total: {new_total}")
                else:
                    _log("  ↳ Nenhum novo subdomínio para sondar")

        not_done, skipped_modules = self._pipeline_execution_summary(cid, options)

        # Don't overwrite stopped status
        if self.pipeline_state.get(cid, {}).get("status") != "stopped":
            self.pipeline_state[cid].update({
                "status":          "done" if not not_done else "done_with_issues",
                "finished_at":     datetime.now().isoformat(timespec="seconds"),
                "not_done":        not_done,
                "skipped_modules": skipped_modules,
            })
        if not_done:
            preview = ", ".join(
                f"{e['module']} ({e['reason']})" if e.get("reason") else e["module"]
                for e in not_done[:8]
            )
            _log(f"  ⚠ {len(not_done)} módulo(s) não concluído(s): {preview}")
        if skipped_modules:
            preview = ", ".join(
                f"{e['module']} ({e['reason']})" for e in skipped_modules[:5]
            )
            _log(f"  ⏭ {len(skipped_modules)} módulo(s) pulado(s) com justificativa: {preview}")
        _log("✅ Pipeline completo" if not not_done else "⚠ Pipeline finalizada com pendências justificadas")
        self._persist_pipeline_results(cid, _log, _options=options, _co=co)
        self._save_pipeline_state(cid)

        # ── Save scan stats snapshot for historical trend charts ──────────────
        try:
            data = self.db.load_asm_data()
            co_data = next((c for c in data.get("companies", []) if c.get("id") == cid), {})
            stats = co_data.get("stats", {})
            stats["scanned_at"] = datetime.now().isoformat(timespec="seconds")
            self.db.add_scan_stat(cid, stats)
        except Exception as e:
            _log(f"  ⚠ Falha ao salvar histórico de stats: {e}")

        # ── Post-scan: snapshot, diff, timeline, alerts ───────────────────────
        try:
            self._post_scan_analysis(cid, co, _log)
        except Exception as e:
            _log(f"  ⚠ Post-scan analysis failed: {e}")

        # ── Technology change detection ────────────────────────────────────────
        try:
            self._detect_tech_changes(cid, co, _log)
        except Exception as e:
            _log(f"  ⚠ Tech change detection failed: {e}")

    def _detect_tech_changes(self, cid: str, co: dict, _log):
        """Compare current tech stack with previous scan and generate alerts for changes."""
        data = self.db.load_asm_data()
        co_data = next((c for c in data.get("companies", []) if c.get("id") == cid), {})
        current_tech = co_data.get("tech_summary", {})
        if not current_tech:
            return

        # Load previous tech from last snapshot
        prev = self.db.load_snapshot(cid, slot="previous")
        prev_tech = {}
        if prev:
            prev_hosts = prev.get("hosts", [])
            for h in prev_hosts:
                if isinstance(h, dict):
                    for t in h.get("technologies", []):
                        prev_tech[t] = prev_tech.get(t, 0) + 1

        if not prev_tech:
            _log("  📊 Tech baseline saved (first scan)")
            # Save current tech as baseline
            self.db.save_snapshot(cid, {"ts": datetime.now().isoformat(timespec="seconds"), "tech_summary": current_tech, "hosts": co_data.get("hosts", [])}, slot="tech_baseline")
            return

        added = {t: c for t, c in current_tech.items() if t not in prev_tech}
        removed = {t: c for t, c in prev_tech.items() if t not in current_tech}
        changed = {}
        for t in set(current_tech) & set(prev_tech):
            if abs(current_tech[t] - prev_tech[t]) >= max(3, prev_tech[t] * 0.3):
                changed[t] = {"from": prev_tech[t], "to": current_tech[t]}

        if added or removed or changed:
            _log(f"  🔔 Tech changes detected:")
            for t, c in added.items():
                _log(f"      ＋ {t}: {c} hosts (NEW)")
            for t, c in removed.items():
                _log(f"      － {t}: {c} hosts (REMOVED)")
            for t, delta in changed.items():
                _log(f"      ~ {t}: {delta['from']} → {delta['to']} hosts")

            # Fire alert for significant changes
            try:
                from alerting import AlertEngine
                engine = AlertEngine(self.db, self.base, self.get_settings)
                engine.process_scan_diff(cid, {"new": list(added.keys()), "removed": list(removed.keys()), "changed": list(changed.keys()), "type": "tech_change"})
            except Exception:
                pass

        # Save updated baseline
        self.db.save_snapshot(cid, {"ts": datetime.now().isoformat(timespec="seconds"), "tech_summary": current_tech, "hosts": co_data.get("hosts", [])}, slot="tech_baseline")

    # ── opensquat daily monitor ────────────────────────────────────────────────

    def setup_opensquat_cron(self, cid: str, keywords: list[str]) -> dict:
        """
        Install a system cron entry that runs the opensquat monitor daily at 06:00
        and pushes new domain findings into the ASM DB for the given company.
        Returns {"installed": True/False, "cron_line": str}.
        """
        import shutil, pwd, os
        script = str(self.base / "scripts" / "opensquat_daily.py")
        kw_file = str(self.base / "scripts" / f"opensquat_kw_{cid}.txt")

        # Write keyword file
        (self.base / "scripts").mkdir(parents=True, exist_ok=True)
        with open(kw_file, "w") as f:
            f.write("\n".join(keywords))

        # Write the standalone runner script
        runner_code = f'''#!/usr/bin/env python3
"""opensquat daily monitor — auto-generated for company {cid}"""
import sys, json
sys.path.insert(0, "{str(self.base)}")
from core.recon import run_opensquat_monitor
from core.database import ASMDatabase
from datetime import datetime

DB_PATH = "{str(self.base / "data" / "asm.db")}"
CID     = "{cid}"
KW_FILE = "{kw_file}"

with open(KW_FILE) as f:
    keywords = [l.strip() for l in f if l.strip()]

result = run_opensquat_monitor(keywords)
if not result.get("findings"):
    print(f"[{{datetime.now():%Y-%m-%d}}] opensquat: no new domains found")
    sys.exit(0)

db = ASMDatabase(db_path=DB_PATH)
data = db.load_asm_data()
co_data = next((c for c in data.get("companies", []) if c.get("id") == CID), None)
if not co_data:
    print(f"Company {{CID}} not found in DB", file=sys.stderr)
    sys.exit(1)

existing_keys = {{f.get("key","") for f in co_data.get("findings", [])}}
new_findings = []
for r in result["findings"]:
    if r.get("risk") in ("critical","high","medium"):
        key = f"opensquat-{{r['domain']}}"
        if key not in existing_keys:
            new_findings.append({{
                "key":      key,
                "type":     "brand_domain_exposure",
                "title":    f"Novo domínio detectado (CT log): {{r['domain']}}",
                "severity": r.get("risk","medium"),
                "category": "brand_protection",
                "desc":     f"Domínio recém-registrado detectado via CT log: {{r['domain']}}. "
                            f"Status: {{r.get('status','unknown')}}. IP: {{', '.join(r.get('ips',[]))}}.",
                "host":     r["domain"],
                "value":    r["domain"],
                "module":   "opensquat",
                "metadata": {{
                    "status":     r.get("status"),
                    "ips":        r.get("ips",[]),
                    "has_mx":     r.get("has_mx",False),
                    "scanned_at": result.get("scanned_at",""),
                }},
            }})

if new_findings:
    co_data.setdefault("findings", []).extend(new_findings)
    # Also append to opensquat_alerts history
    co_data.setdefault("opensquat_alerts", []).append({{
        "date":       result["scanned_at"],
        "new_count":  len(new_findings),
        "domains":    [f["value"] for f in new_findings],
    }})
    db.save_asm_data(data)
    print(f"[{{datetime.now():%Y-%m-%d}}] opensquat: {{len(new_findings)}} new findings saved for {{CID}}")
else:
    print(f"[{{datetime.now():%Y-%m-%d}}] opensquat: {{result['new_domains']}} domains found, all already known")
'''
        try:
            with open(script, "w") as f:
                f.write(runner_code)
            import os as _os
            _os.chmod(script, 0o755)
        except Exception as e:
            return {"installed": False, "error": str(e)}

        # Add crontab entry (run at 06:00 daily)
        python_bin = shutil.which("python3") or "python3"
        cron_line  = f"0 6 * * * {python_bin} {script} >> /tmp/opensquat_{cid}.log 2>&1"
        try:
            import subprocess as _sp
            existing = _sp.run(["crontab", "-l"],
                               capture_output=True, text=True).stdout
            if script not in existing:
                new_cron = existing.rstrip("\n") + "\n" + cron_line + "\n"
                proc = _sp.run(["crontab", "-"],
                               input=new_cron, capture_output=True, text=True)
                if proc.returncode != 0:
                    return {"installed": False, "error": proc.stderr, "cron_line": cron_line}
            return {"installed": True, "cron_line": cron_line, "script": script}
        except Exception as e:
            return {"installed": False, "error": str(e), "cron_line": cron_line}

    def ingest_opensquat_alerts(self, cid: str) -> list[dict]:
        """
        Run opensquat on-demand for a company and return new findings.
        Also persists them directly to the DB.
        """
        data = self.db.load_asm_data()
        co_data = next((c for c in data.get("companies", []) if c.get("id") == cid), None)
        if not co_data:
            return []
        domains = co_data.get("domains", [])
        keywords = list({d.split(".")[0] for d in domains})
        result = self._recon.run_opensquat_monitor(keywords)
        return result.get("findings", [])
