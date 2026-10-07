from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from .auth_analyzer import analyze_auth_surface
from .browser import BrowserRuntime
from .console_recon import classify
from .crawler import crawl
from .file_utils import ensure_dir
from .idor_mapper import compare_access, extract_candidates
from .masking import mask_cookie, mask_cookie_string, mask_storage_value, mask_text
from .models import SessionState
from .network import dedupe_endpoints
from .reporter import write_markdown
from .url_utils import in_scope
from .tech_detector import DetectorContext, TechnologyDetector, build_stack_profile


@dataclass
class PipelineConfig:
    url: str
    output: str = "reports/report.md"
    evidence_dir: str = "evidence"
    scope: list[str] = field(default_factory=list)
    max_pages: int = 50
    max_depth: int = 3
    headless: bool = True
    timeout: int = 20
    slow_mo: int = 0
    user_agent: str = ""
    allow_external: bool = False
    safe_mode: bool = True
    test_xss: bool = False
    test_race: bool = False
    test_access: bool = False
    trace: bool = False
    auth_state: str | None = None
    auth_state_b: str | None = None
    config_path: str | None = None


class PlaywrightPentestPipeline:
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.detector = TechnologyDetector.load_default()
        self.session = SessionState(
            scope=config.scope or [urlparse(config.url).hostname or ""],
            target=config.url,
            config=config.__dict__,
            evidence_dir=config.evidence_dir,
        )

    def _save_session_checkpoint(self, suffix: str = "partial") -> None:
        try:
            path = Path(self.config.evidence_dir) / f"session.{suffix}.json"
            self.session.save(path)
        except Exception:
            pass

    def _normalize_host_candidates(self, urls: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        scope = self.session.scope or []
        for raw in urls or []:
            url = str(raw or "").strip()
            if not url or url.startswith(("data:", "javascript:", "mailto:")):
                continue
            if "://" not in url:
                url = f"https://{url.lstrip('/')}"
            try:
                host = (urlparse(url).hostname or "").strip().lower().lstrip("*.")
            except Exception:
                host = ""
            if not host or host in seen:
                continue
            if scope and not self.config.allow_external and not in_scope(f"https://{host}", scope, allow_external=False):
                continue
            seen.add(host)
            out.append(host)
        return out

    def _probe_hosts_httpx(self, hosts: list[str]) -> list[dict]:
        if not hosts:
            return []
        try:
            import httpx
        except Exception:
            return [{"host": h, "status_code": None, "error": "httpx unavailable"} for h in hosts]

        timeout = max(5, int(self.config.timeout))
        headers = {"User-Agent": self.config.user_agent or "Mozilla/5.0 ASM-Playwright"}

        def _probe(host: str) -> dict:
            from utils.circuit_breaker import CircuitOpen, guard_host
            target_urls = [f"https://{host}", f"http://{host}"]
            last_err = ""
            try:
                br = guard_host(target_urls[0], name=host)
            except CircuitOpen:
                return {
                    "host": host,
                    "status_code": None,
                    "content_type": "",
                    "title": "",
                    "server": "",
                    "final_url": f"https://{host}",
                    "error": "circuit open",
                }
            with httpx.Client(
                timeout=timeout,
                verify=False,
                follow_redirects=True,
                headers=headers,
            ) as client:
                for target in target_urls:
                    for method in ("HEAD", "GET"):
                        try:
                            resp = client.request(method, target)
                            if resp.status_code >= 500:
                                br.failure()
                            else:
                                br.success()
                            if resp.status_code == 405 and method == "HEAD":
                                continue
                            ctype = resp.headers.get("content-type", "")
                            title = ""
                            if "text/html" in ctype.lower():
                                body = resp.text[:65536]
                                match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                                if match:
                                    title = re.sub(r"\s+", " ", match.group(1)).strip()[:160]
                            return {
                                "host": host,
                                "url": str(resp.url),
                                "scheme": resp.url.scheme,
                                "status_code": resp.status_code,
                                "content_type": ctype,
                                "title": title,
                                "server": resp.headers.get("server", ""),
                                "final_url": str(resp.url),
                                "error": "",
                            }
                        except Exception as exc:
                            br.failure()
                            last_err = str(exc)[:180]
                            continue
            return {
                "host": host,
                "status_code": None,
                "content_type": "",
                "title": "",
                "server": "",
                "final_url": f"https://{host}",
                "error": last_err or "no response",
            }

        results: list[dict] = []
        workers = min(4, max(1, len(hosts)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_probe, host): host for host in hosts}
            for fut in as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception as exc:
                    host = futs[fut]
                    results.append({
                        "host": host,
                        "status_code": None,
                        "content_type": "",
                        "title": "",
                        "server": "",
                        "final_url": f"https://{host}",
                        "error": str(exc)[:180],
                    })
        return results

    def _sync_host_inventory(self, urls: list[str], *, source: str) -> list[dict]:
        candidates = self._normalize_host_candidates(urls)
        if not candidates:
            return []

        existing: dict[str, dict] = {}
        for item in self.session.host_inventory:
            host = str(item.get("host", "")).strip().lower()
            if host:
                existing[host] = dict(item)

        now = self.session.started_at
        new_hosts: list[str] = []
        for host in candidates:
            rec = existing.get(host)
            if not rec:
                rec = {
                    "host": host,
                    "status": "pending",
                    "status_code": None,
                    "source": source,
                    "sources": [source],
                    "discovered_at": now,
                    "validated_at": "",
                    "title": "",
                    "server": "",
                    "content_type": "",
                    "final_url": "",
                    "error": "",
                }
                existing[host] = rec
                new_hosts.append(host)
            else:
                rec.setdefault("sources", [])
                if source not in rec["sources"]:
                    rec["sources"].append(source)
                if not rec.get("source"):
                    rec["source"] = source

        if new_hosts:
            self.session.discovered_hosts = sorted({*self.session.discovered_hosts, *new_hosts})
        self.session.host_inventory = sorted(existing.values(), key=lambda x: x.get("host", ""))
        self.session.pending_hosts = sorted(
            {item["host"] for item in self.session.host_inventory if item.get("status_code") is None}
        )
        self.session.validated_hosts = sorted(
            {item["host"] for item in self.session.host_inventory if item.get("status_code") is not None}
        )
        if new_hosts:
            self._save_session_checkpoint("partial")

        probe_hosts = [host for host in candidates if existing.get(host, {}).get("status_code") is None]
        validations = self._probe_hosts_httpx(probe_hosts)
        validated_now: list[str] = []
        pending_now: list[str] = []
        for item in validations:
            host = item.get("host", "")
            if not host:
                continue
            rec = existing.setdefault(host, {"host": host, "sources": [source], "discovered_at": now})
            rec.update(item)
            if item.get("status_code") is not None:
                rec["status"] = "validated"
                rec["validated_at"] = now
                validated_now.append(host)
            else:
                rec["status"] = "pending"
                pending_now.append(host)

        self.session.host_inventory = sorted(existing.values(), key=lambda x: x.get("host", ""))
        self.session.validated_hosts = sorted(
            {item["host"] for item in self.session.host_inventory if item.get("status_code") is not None}
        )
        self.session.pending_hosts = sorted(
            {item["host"] for item in self.session.host_inventory if item.get("status_code") is None}
        )
        if validated_now or pending_now:
            self._save_session_checkpoint("partial")
        return validations

    def run(self) -> SessionState:
        ensure_dir(self.config.evidence_dir)
        ensure_dir(Path(self.config.evidence_dir) / "pages")
        trace_dir = str(Path(self.config.evidence_dir) / "traces") if self.config.trace else None
        try:
            with BrowserRuntime(
                headless=self.config.headless,
                user_agent=self.config.user_agent,
                storage_state=self.config.auth_state,
                trace_dir=trace_dir,
                slow_mo=self.config.slow_mo,
                timeout=self.config.timeout,
            ) as runtime:
                response = runtime.goto(self.config.url)
                # Many targets are HTTP-only. If the HTTPS landing fails to
                # connect, retry over HTTP and continue the whole scan on that
                # scheme (crawl, host inventory and report all read config.url).
                if runtime.last_navigation_error and self.config.url.lower().startswith("https://"):
                    http_url = "http://" + self.config.url[len("https://"):]
                    http_resp = runtime.goto(http_url)
                    if http_resp is not None and not runtime.last_navigation_error:
                        self.config.url = http_url
                        self.session.target = http_url
                        response = http_resp
                        self.session.skipped_checks.append(
                            f"HTTPS landing failed; fell back to HTTP ({http_url})."
                        )
                if runtime.last_navigation_error:
                    # Don't abort the whole job on a slow/blocked landing page —
                    # record it and continue with whatever loaded (partial report).
                    self.session.skipped_checks.append(
                        f"Initial navigation issue ({runtime.last_navigation_error[:180]}); report may be partial."
                    )
                runtime.page.wait_for_timeout(750)
                runtime.harvest_agent_events()  # drena rotas SPA + fetch/XHR da landing page
                try:
                    html = runtime.page.content()
                except Exception:
                    html = ""
                headers = dict(response.headers) if response else {}
                cookies = runtime.context.cookies()
                initial_ctx = DetectorContext(
                    url=runtime.page.url,
                    html=html,
                    headers=headers,
                    cookies=cookies,
                    js_texts=list(runtime.js_bodies.values()),
                    paths=[runtime.page.url] + [e.url for e in runtime.network_events],
                    console=runtime.console_events,
                )
                self.session.response_headers = headers
                tech = self.detector.detect(initial_ctx)
                self.session.tech = tech
                self.session.stack_profile = build_stack_profile(tech, html=html, headers=headers, cookies=cookies)
                self._add_stack_notes()
                self._sync_host_inventory(
                    [runtime.page.url] + [e.url for e in runtime.network_events],
                    source="landing",
                )
                self._save_session_checkpoint("partial")
                snapshots = crawl(
                    runtime=runtime,
                    target_url=self.config.url,
                    scope=self.session.scope,
                    max_pages=self.config.max_pages,
                    max_depth=self.config.max_depth,
                    allow_external=self.config.allow_external,
                    evidence_dir=self.config.evidence_dir,
                )
                self.session.pages = snapshots
                self.session.routes = [
                    {
                        "url": page.url,
                        "depth": page.depth,
                        "title": page.title,
                        "status": page.status,
                        "links": len(page.links),
                        "forms": len(page.forms),
                        "scripts": len(page.scripts),
                    }
                    for page in snapshots
                ]
                self.session.endpoints = dedupe_endpoints(runtime.network_events)
                self.session.console = [classify(event) for event in runtime.console_events]
                # Browser-only captures (WebSocket/SSE/postMessage listeners).
                self.session.websockets = list(runtime.ws_messages)
                self.session.sse = list(runtime.sse_endpoints)
                # Detection above used raw cookies; the *persisted* copy must be masked.
                self.session.cookies = [mask_cookie(dict(c)) for c in cookies]
                raw_storage = runtime.snapshot_storage()
                # Token/JWT analysis runs on RAW storage+cookies (needs to decode), before masking.
                from .token_analyzer import analyze_tokens
                self.session.tokens = analyze_tokens(raw_storage, cookies)
                self.session.globals_secrets = [
                    {"key": g.get("key"), "sample": mask_text(str(g.get("sample", "")))}
                    for g in (raw_storage.get("globalsSecrets") or [])
                ]
                self.session.storage = self._mask_storage(raw_storage)
                self.session.inputs = [inp for page in snapshots for inp in page.inputs]
                self.session.auth = analyze_auth_surface(self.session.inputs, self.session.cookies, html=html)
                self._aggregate_js(runtime)
                self._run_passive_analysis(runtime, headers)
                self._sync_host_inventory(
                    [p.url for p in snapshots]
                    + [e.url for e in self.session.endpoints]
                    + [r.get("url", "") for r in self.session.routes]
                    + [j.file_url for j in self.session.js]
                    + [ep for j in self.session.js for ep in (j.endpoints or [])]
                    + [r for j in self.session.js for r in (j.routes or [])],
                    source="browser",
                )
                self._save_session_checkpoint("partial")
        except Exception as exc:
            self.session.skipped_checks.append(f"Browser pipeline partial failure: {str(exc)[:180]}")
            self._save_session_checkpoint("partial")
        # ── Active checks open their OWN browser(s); run them only after the main
        #    sync-Playwright context is closed (it cannot nest a second instance). ──
        self._run_idor_checks()
        self._run_xss_checks()
        self._run_dom_xss_checks()
        self._run_race_checks()
        self._run_session_analysis()
        self._run_client_trust_checks()
        self._promote_findings()
        self.session.save(Path(self.config.evidence_dir) / "session.json")
        write_markdown(self.session, self.config.output)
        return self.session

    def _aggregate_js(self, runtime: BrowserRuntime, max_source_maps: int = 30) -> None:
        from .js_analyzer import analyze_js
        from .source_map import fetch_source_map, summarize_source_map

        js_items = []
        fetched = 0
        for url, body in runtime.js_bodies.items():
            artifact = analyze_js(url, body)
            # Fase 7 — Source Map Analysis: try to resolve referenced .map files.
            if artifact.source_map_url and fetched < max_source_maps:
                fetched += 1
                summary = summarize_source_map(fetch_source_map(url, artifact.source_map_url))
                artifact.source_map_accessible = summary["accessible"]
                artifact.source_map_sources = summary["sources"][:100]
            js_items.append(artifact)
        self.session.js = js_items

    def _run_xss_checks(self) -> None:
        # Active test — only with safe-mode OFF and explicitly enabled.
        if self.config.safe_mode or not self.config.test_xss:
            if self.config.test_xss and self.config.safe_mode:
                self.session.skipped_checks.append("XSS testing requested but skipped: safe-mode is ON.")
            return
        from .xss_tester import run_xss_tests

        targets = [e.url for e in self.session.endpoints] + [p.url for p in self.session.pages]
        results = run_xss_tests(
            targets,
            headless=self.config.headless,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            auth_state=self.config.auth_state,
            evidence_dir=self.config.evidence_dir,
        )
        self.session.xss = results
        confirmed = sum(1 for r in results if r.status == "confirmed_xss")
        if confirmed:
            self.session.skipped_checks.append(f"XSS testing confirmed {confirmed} executing payload(s).")

    def _mask_storage(self, raw: dict) -> dict:
        out = {"cookies": mask_cookie_string(raw.get("cookies", "") or ""),
               "globals": list(raw.get("globals", []))[:200]}
        for store in ("localStorage", "sessionStorage"):
            out[store] = {k: mask_storage_value(v) for k, v in (raw.get(store) or {}).items()}
        return out

    def _run_passive_analysis(self, runtime, headers: dict) -> None:
        """Browser-only passive analyses (run in safe-mode): postMessage, CSP, GraphQL."""
        from .csp_analyzer import analyze_csp
        from .graphql_introspect import introspect
        from .postmessage_analyzer import analyze_postmessage

        self.session.postmessage = analyze_postmessage(runtime.msg_listeners)
        self.session.csp = analyze_csp(headers)
        urls = [e.url for e in self.session.endpoints] + [
            r for j in self.session.js for r in (j.endpoints or [])
        ]
        cookies = {c.get("name"): c.get("value") for c in (runtime.context.cookies() or []) if c.get("name")}
        try:
            self.session.graphql = introspect(urls, cookies=cookies, user_agent=self.config.user_agent)
        except Exception as exc:
            self.session.graphql = {"introspection_enabled": False, "error": str(exc)[:80]}

    def _run_dom_xss_checks(self) -> None:
        if self.config.safe_mode or not self.config.test_xss:
            return
        from .dom_xss import run_dom_xss

        urls = [self.config.url] + [p.url for p in self.session.pages]
        self.session.dom_xss = run_dom_xss(
            urls, headless=self.config.headless, timeout=self.config.timeout,
            user_agent=self.config.user_agent, auth_state=self.config.auth_state,
            evidence_dir=self.config.evidence_dir,
        )
        confirmed = sum(1 for r in self.session.dom_xss if r.get("status") == "confirmed_dom_xss")
        if confirmed:
            self.session.skipped_checks.append(f"DOM XSS confirmed on {confirmed} URL(s).")

    def _run_client_trust_checks(self) -> None:
        if self.config.safe_mode or not self.config.test_access:
            if self.config.test_access and self.config.safe_mode:
                self.session.skipped_checks.append("Access-control replay requested but skipped: safe-mode is ON.")
            return
        from .client_trust import run_client_trust

        self.session.client_trust = run_client_trust(
            self.config.url, self.session.endpoints, self.session.js,
            auth_state=self.config.auth_state, headless=self.config.headless,
            timeout=self.config.timeout, user_agent=self.config.user_agent,
        )
        broken = sum(1 for r in self.session.client_trust if r.get("verdict") == "accessible_without_auth")
        if broken:
            self.session.skipped_checks.append(f"Client-trust replay: {broken} privileged endpoint(s) reachable without auth.")

    def _run_race_checks(self) -> None:
        # Fase 17 — always MAP candidates; only PROBE when explicitly enabled.
        from .race_mapper import map_candidates, probe_candidates

        candidates = map_candidates(self.session.endpoints, self.session.inputs)
        if candidates and self.config.test_race and not self.config.safe_mode:
            probe_candidates(candidates, auth_state=self.config.auth_state,
                             user_agent=self.config.user_agent)
            inconsistent = sum(1 for c in candidates if c.probe_status == "inconsistent")
            if inconsistent:
                self.session.skipped_checks.append(
                    f"Race probe flagged {inconsistent} endpoint(s) with inconsistent parallel responses."
                )
        elif candidates and self.config.test_race and self.config.safe_mode:
            self.session.skipped_checks.append("Race probe requested but skipped: safe-mode is ON (candidates mapped only).")
        self.session.race = candidates

    def _run_session_analysis(self) -> None:
        # Fase 15 — active authed-vs-anon access comparison + logout test.
        from .auth_analyzer import find_logout_urls, run_session_analysis

        all_links = [ln for p in self.session.pages for ln in p.links]
        logout_urls = find_logout_urls(all_links, self.session.scope)
        self.session.auth.logout_urls = logout_urls
        if not self.config.auth_state:
            return
        access_urls = [p.url for p in self.session.pages] + [e.url for e in self.session.endpoints]
        result = run_session_analysis(
            access_urls, logout_urls,
            auth_state=self.config.auth_state, scope=self.session.scope,
            headless=self.config.headless, timeout=self.config.timeout,
            user_agent=self.config.user_agent,
        )
        self.session.auth.access_control = result["access_control"]
        self.session.auth.logout = result["logout"]
        self.session.auth.notes.extend(result["notes"])

    def _promote_findings(self) -> None:
        """Only execution-/access-confirmed results become reportable Findings."""
        from .models import Finding

        for r in self.session.xss:
            if r.status == "confirmed_xss":
                self.session.findings.append(Finding(
                    title=f"Reflected XSS in '{r.parameter}'",
                    severity="high", endpoint=r.url, parameter=r.parameter,
                    status="confirmed", cwe="CWE-79", evidence=r.evidence,
                    impact="Attacker-controlled script executes in the victim's browser session.",
                    reproduction_steps=[
                        f"Set parameter '{r.parameter}' to: {r.payload}",
                        f"Load the URL; alert() fires with marker {r.marker}.",
                    ],
                    recommendation="Context-aware output encoding; add a strict Content-Security-Policy.",
                ))
        for r in self.session.idor:
            if r.status == "confirmed_idor":
                self.session.findings.append(Finding(
                    title=f"IDOR / broken access control on '{r.parameter or r.url}'",
                    severity=r.severity if r.severity != "info" else "high",
                    endpoint=r.url, parameter=r.parameter, status="confirmed",
                    cwe=r.cwe or "CWE-639", evidence=r.evidence,
                    impact="One user can access another user's object/data.",
                    recommendation="Enforce per-object authorization server-side.",
                ))
        for r in self.session.dom_xss:
            if r.get("status") == "confirmed_dom_xss":
                self.session.findings.append(Finding(
                    title=f"DOM-based XSS via URL fragment ({r.get('sink')})",
                    severity="high", endpoint=r.get("url", ""), status="confirmed",
                    cwe="CWE-79", evidence=r.get("evidence", []),
                    impact="Attacker-controlled URL fragment executes script in the victim's browser.",
                    recommendation="Avoid writing untrusted URL data into DOM sinks; sanitize/encode.",
                ))
        for r in self.session.client_trust:
            if r.get("verdict") == "accessible_without_auth":
                self.session.findings.append(Finding(
                    title=f"Broken access control — privileged endpoint reachable without auth",
                    severity="high", endpoint=r.get("url", ""), status="confirmed",
                    cwe="CWE-602", impact="Server serves a privileged endpoint that the UI only gates client-side.",
                    reproduction_steps=[f"GET {r.get('url')} with no session → HTTP {r.get('anon_status')}"],
                    recommendation="Enforce authorization server-side, not just in the frontend.",
                ))

    def _add_stack_notes(self) -> None:
        profile = self.session.stack_profile
        if profile.get("skip_viewstate"):
            self.session.skipped_checks.append(
                "ViewState/EventValidation audit skipped: modern frontend detected and no legacy ASP.NET WebForms signals found."
            )
        if profile.get("run_api_focus"):
            self.session.skipped_checks.append("Focus shifted to JS/runtime/API surface because the target looks like a modern client-heavy app.")

    def _run_idor_checks(self) -> None:
        urls = [p.url for p in self.session.pages] + [e.url for e in self.session.endpoints]
        candidates = extract_candidates(urls)
        if not candidates:
            return
        results = compare_access(
            candidates,
            auth_state_a=self.config.auth_state,
            auth_state_b=self.config.auth_state_b,
            headless=self.config.headless,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            evidence_dir=self.config.evidence_dir,
        )
        self.session.idor = results
        if self.config.auth_state_b:
            positives = [r for r in results if r.status == "potential_idor"]
            if positives:
                self.session.skipped_checks.append(
                    f"IDOR review produced {len(positives)} potential candidate(s) from A/B session comparison."
                )


def load_session(path: str | Path) -> SessionState:
    return SessionState.load(path)


def render_report_from_session(session_path: str | Path, output: str | Path) -> Path:
    from .reporter import write_markdown

    session = load_session(session_path)
    return write_markdown(session, output)
