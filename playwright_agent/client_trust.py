"""Client-side trust / broken access control (the "everything trusts the front" test).

Two moves:
  1. Privilege flip (browser, read-only on the client): force common admin/role flags
     and feature flags true in memory, re-render, and harvest any newly-fired API calls
     that the UI normally gates — candidate privileged endpoints.
  2. Server-truth replay (httpx): request each privileged endpoint anonymously and with a
     low-privilege session, comparing — if the server serves it without proper auth, the
     gate was client-only (broken access control).

Read-only GET replays only; never destructive. Active → gate behind safe-mode OFF.
"""
from __future__ import annotations

from pathlib import Path
import re

from .race_mapper import _cookies_from_state

_PRIV_RE = re.compile(
    r"/(admin|administrator|internal|manage|management|config|settings|users?|roles?|"
    r"permission|privilege|debug|export|import|billing|invoice|audit|backup|sysadmin|console)\b",
    re.I,
)

_FLIP_SCRIPT = r"""() => {
  const truths = ['isAdmin','admin','is_admin','isSuperuser','superuser','isStaff','canEdit','canDelete','hasAccess','authorized'];
  const roleVals = ['admin','superadmin','ROLE_ADMIN','administrator'];
  const targets = [window, window.__USER__, window.user, window.currentUser, window.__INITIAL_STATE__,
                   window.__NUXT__, window.__NEXT_DATA__, window.store && window.store.getState && window.store.getState()];
  let flipped = 0;
  for (const o of targets) {
    if (!o || typeof o !== 'object') continue;
    for (const t of truths) { try { if (t in o) { o[t] = true; flipped++; } } catch(e){} }
    for (const k of ['role','roles','userRole']) { try { if (k in o) { o[k] = roleVals[0]; flipped++; } } catch(e){} }
    try { if (o.flags && typeof o.flags === 'object') { for (const f of Object.keys(o.flags)) { if (typeof o.flags[f] === 'boolean') { o.flags[f] = true; flipped++; } } } } catch(e){}
  }
  try { window.dispatchEvent(new Event('resize')); window.dispatchEvent(new HashChangeEvent('hashchange')); } catch(e){}
  return flipped;
}"""


def _privileged_urls(endpoints, js_artifacts, limit: int) -> list[str]:
    urls = set()
    for e in endpoints or []:
        u = getattr(e, "url", "")
        if u.startswith("http") and _PRIV_RE.search(u):
            urls.add(u.split("#")[0])
    for j in js_artifacts or []:
        for r in (getattr(j, "endpoints", []) or []):
            if r.startswith("http") and _PRIV_RE.search(r):
                urls.add(r.split("#")[0])
    return sorted(urls)[:limit]


def run_client_trust(
    target_url: str,
    endpoints,
    js_artifacts,
    *,
    auth_state: str | None = None,
    headless: bool = True,
    timeout: int = 15,
    user_agent: str = "",
    max_endpoints: int = 15,
) -> list[dict]:
    candidates = set(_privileged_urls(endpoints, js_artifacts, max_endpoints))

    # ── Move 1: privilege flip (best-effort) to surface client-gated API calls ──
    try:
        from .browser import BrowserRuntime
        with BrowserRuntime(headless=headless, timeout=timeout, user_agent=user_agent,
                            storage_state=auth_state) as rt:
            rt.goto(target_url)
            rt.page.wait_for_timeout(600)
            base = len(rt.network_events)
            try:
                rt.page.evaluate(_FLIP_SCRIPT)
                rt.page.wait_for_timeout(900)
            except Exception:
                pass
            rt.harvest_agent_events()
            for e in rt.network_events[base:]:
                if e.url.startswith("http") and _PRIV_RE.search(e.url):
                    candidates.add(e.url.split("#")[0])
    except Exception:
        pass

    cand = sorted(candidates)[:max_endpoints]
    if not cand:
        return []

    # ── Move 2: server-truth replay (anon vs low-priv) ──
    cookies = _cookies_from_state(auth_state)
    hdrs = {"User-Agent": user_agent} if user_agent else {}
    out: list[dict] = []
    for u in cand:
        a_s = b_s = None
        try:
            # Rate-limit guard: 0.8s between endpoint probes
            if out:
                import time as _time
                _time.sleep(0.8)
            from utils.circuit_breaker import guarded_httpx
            a_s = guarded_httpx(
                "GET", u, timeout=timeout, verify=False, follow_redirects=False, headers=hdrs,
            ).status_code
            if cookies:
                b_s = guarded_httpx(
                    "GET", u, timeout=timeout, verify=False, follow_redirects=False,
                    headers=hdrs, cookies=cookies,
                ).status_code
        except Exception as exc:
            out.append({"url": u, "verdict": "error", "detail": str(exc)[:80], "severity": "info"})
            continue
        if a_s == 200:
            verdict, sev = "accessible_without_auth", "high"
        elif b_s == 200 and a_s in (401, 403):
            verdict, sev = "server_enforced", "info"
        elif b_s == 200 and a_s in (301, 302):
            verdict, sev = "needs_manual_validation", "low"
        else:
            verdict, sev = "inaccessible", "info"
        out.append({"url": u, "anon_status": a_s, "authed_status": b_s,
                    "verdict": verdict, "severity": sev})
    return out
