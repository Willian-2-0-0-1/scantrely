"""Race-condition candidate mapper (Fase 17).

By default it ONLY maps candidates (no requests). With test_race enabled it runs a
*bounded* parallel probe (≤max_parallel) — and only against non-destructive GET
candidates — to surface response inconsistency. Destructive intent (delete/pay/buy/
checkout/transfer/cancel) is never auto-probed; those become manual leads only.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse
import json

from .models import RaceCandidate


# category -> (keywords, suggested manual test)
_CATEGORIES: dict[str, tuple[tuple[str, ...], str]] = {
    "coupon":      (("coupon", "promo", "voucher", "discount", "giftcard", "redeem"),
                    "Send N parallel apply requests; check if the coupon applies more than once."),
    "vote":        (("vote", "upvote", "like", "rating", "star", "favorite"),
                    "Fire N parallel votes; check if the counter exceeds 1 per user."),
    "cart":        (("cart", "basket", "addtocart", "add-to-cart", "add_item"),
                    "Add the same item in parallel; check for negative price/quantity races."),
    "comment":     (("comment", "review", "reply", "message", "post"),
                    "Submit in parallel; check for duplicate/inconsistent state."),
    "upload":      (("upload", "attach", "import"),
                    "Parallel uploads; check quota/limit bypass."),
    "points":      (("points", "balance", "credit", "wallet", "reward", "cashback"),
                    "Parallel redeem/transfer of points; check for double-spend."),
    "password":    (("reset", "forgot-password", "forgotpassword"),
                    "Parallel reset requests; check token reuse/limits."),
    "email_change":(("change-email", "changeemail", "update-email"),
                    "Parallel email-change requests; check confirmation race."),
    "mfa":         (("otp", "2fa", "totp", "mfa", "verify-code"),
                    "Parallel code submissions; check for brute/limit bypass."),
    "inventory":   (("stock", "inventory", "reserve", "claim", "booking"),
                    "Parallel reserve/claim; check overselling."),
    "payment":     (("payment", "pay", "charge", "subscribe", "purchase"),
                    "MANUAL ONLY — never auto-probe payment flows."),
}

_DESTRUCTIVE = ("delete", "remove", "pay", "buy", "checkout", "transfer", "cancel",
                "charge", "withdraw", "deactivate", "purchase")


def _classify(text: str) -> tuple[str, str] | None:
    t = (text or "").lower()
    for category, (keywords, suggestion) in _CATEGORIES.items():
        if any(k in t for k in keywords):
            return category, suggestion
    return None


def map_candidates(endpoints: list, inputs: list) -> list[RaceCandidate]:
    """Scan discovered endpoints and form actions for race-prone operations."""
    out: list[RaceCandidate] = []
    seen: set[tuple[str, str]] = set()

    def _add(url: str, method: str):
        hit = _classify(url)
        if not hit:
            return
        category, suggestion = hit
        path = urlparse(url).path or url
        key = (method.upper(), path, category)
        if key in seen:
            return
        seen.add(key)
        risky = any(d in url.lower() for d in _DESTRUCTIVE)
        out.append(RaceCandidate(
            url=url, method=method.upper(), category=category,
            reason=f"{category} operation in URL/action",
            risky_intent=risky, suggested_test=suggestion,
            notes=["destructive intent — map only" if risky else ""],
        ))

    for ep in endpoints or []:
        _add(getattr(ep, "url", ""), getattr(ep, "method", "GET") or "GET")
    for ip in inputs or []:
        action = getattr(ip, "action", "") or ""
        if action:
            _add(action, getattr(ip, "method", "GET") or "GET")
    return out


def _cookies_from_state(auth_state: str | None) -> dict:
    if not auth_state:
        return {}
    try:
        data = json.loads(Path(auth_state).read_text(encoding="utf-8"))
        return {c["name"]: c["value"] for c in data.get("cookies", []) if c.get("name")}
    except Exception:
        return {}


def probe_candidates(
    candidates: list[RaceCandidate],
    *,
    auth_state: str | None = None,
    user_agent: str = "",
    max_candidates: int = 6,
    max_parallel: int = 5,
    timeout: int = 15,
) -> None:
    """Bounded active probe: parallel GET replays of non-destructive candidates.

    Mutates candidates in place (probe_status/probe_detail). Skips non-GET and
    destructive candidates — those stay manual leads.
    """
    import httpx
    from utils.circuit_breaker import CircuitOpen, guard_host

    cookies = _cookies_from_state(auth_state)
    headers = {"User-Agent": user_agent} if user_agent else {}
    tested = 0
    for cand in candidates:
        if tested >= max_candidates:
            break
        if cand.risky_intent or cand.category == "payment":
            cand.probe_status = "skipped_destructive"
            continue
        if cand.method != "GET":
            cand.probe_status = "not_tested"
            cand.notes.append("non-GET: replay needs the original body — test manually")
            continue
        tested += 1
        try:
            br = guard_host(cand.url)
            with httpx.Client(timeout=timeout, follow_redirects=True, verify=False,
                              cookies=cookies, headers=headers) as client:
                def _fire(_):
                    r = client.get(cand.url)
                    return (r.status_code, len(r.content))
                with ThreadPoolExecutor(max_workers=max_parallel) as pool:
                    results = list(pool.map(_fire, range(max_parallel)))
            if any(status >= 500 for status, _ in results):
                br.failure()
            else:
                br.success()
        except CircuitOpen:
            cand.probe_status = "not_tested"
            cand.probe_detail = "circuit open"
            continue
        except Exception as exc:
            try:
                br.failure()
            except Exception:
                pass
            cand.probe_status = "not_tested"
            cand.probe_detail = f"probe error: {exc}"
            continue
        distinct = set(results)
        if len(distinct) > 1:
            cand.probe_status = "inconsistent"
            cand.probe_detail = f"{max_parallel} parallel requests returned differing responses: {sorted(distinct)}"
            cand.notes.append("inconsistent parallel responses — investigate race manually")
        else:
            cand.probe_status = "consistent"
            cand.probe_detail = f"{max_parallel} parallel requests were identical {distinct.pop()}"
