from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import re

from .browser import BrowserRuntime
from .file_utils import ensure_dir
from .models import IdorCandidate, IdorResult
from .url_utils import normalize_url


_SENSITIVE_KEYS = {
    "id", "user_id", "account_id", "profile_id", "order_id", "invoice_id", "file_id",
    "document_id", "tenant_id", "organization_id", "company_id", "customer_id",
    "ticket_id", "project_id", "task_id", "record_id", "item_id", "resource_id",
}
_UUID_RE = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_LONG_NUM_RE = re.compile(r"^\d{2,}$")


def extract_candidates(urls: list[str]) -> list[IdorCandidate]:
    out: list[IdorCandidate] = []
    seen = set()
    for raw in urls:
        url = normalize_url(raw)
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        for key, value in query.items():
            if key.lower() in _SENSITIVE_KEYS and value:
                candidate_url = _replace_query_param(url, key, value)
                key_id = ("query", candidate_url, key.lower())
                if key_id not in seen:
                    seen.add(key_id)
                    out.append(
                        IdorCandidate(
                            url=candidate_url,
                            endpoint=parsed.path or url,
                            parameter=key,
                            reason=f"query parameter '{key}' looks like an object reference",
                            kind="query",
                        )
                    )
        path_bits = [bit for bit in parsed.path.split("/") if bit]
        for idx, bit in enumerate(path_bits):
            if _looks_like_identifier(bit):
                new_path = "/".join(path_bits)
                key_id = ("path", parsed.scheme, parsed.netloc, new_path, idx)
                if key_id in seen:
                    continue
                seen.add(key_id)
                out.append(
                    IdorCandidate(
                        url=url,
                        endpoint=parsed.path or url,
                        parameter=bit,
                        reason=f"path segment '{bit}' looks like an object reference",
                        kind="path",
                    )
                )
    return out


def compare_access(
    candidates: list[IdorCandidate],
    *,
    auth_state_a: str | None = None,
    auth_state_b: str | None = None,
    headless: bool = True,
    timeout: int = 20,
    user_agent: str = "",
    evidence_dir: str | Path = "evidence",
    max_candidates: int = 12,
) -> list[IdorResult]:
    results: list[IdorResult] = []
    evidence_dir = ensure_dir(Path(evidence_dir) / "idor")
    selected = candidates[:max_candidates]
    if not selected:
        return results

    if not auth_state_b:
        for cand in selected:
            results.append(
                IdorResult(
                    url=cand.url,
                    parameter=cand.parameter,
                    candidate_kind=cand.kind,
                    status="not_tested",
                    severity="info",
                    notes=[cand.reason, "auth_state_b missing; comparison skipped"],
                    cwe="CWE-639",
                )
            )
        return results

    with BrowserRuntime(headless=headless, storage_state=auth_state_a, timeout=timeout, user_agent=user_agent) as a_rt:
        with BrowserRuntime(headless=headless, storage_state=auth_state_b, timeout=timeout, user_agent=user_agent) as b_rt:
            for idx, cand in enumerate(selected, 1):
                a = _probe(a_rt, cand.url)
                b = _probe(b_rt, cand.url)
                verdict, severity, notes = _compare(a, b, cand)
                evidence = [
                    str(evidence_dir / f"{idx:02d}-a.txt"),
                    str(evidence_dir / f"{idx:02d}-b.txt"),
                ]
                _write_probe(evidence_dir / f"{idx:02d}-a.txt", a)
                _write_probe(evidence_dir / f"{idx:02d}-b.txt", b)
                results.append(
                    IdorResult(
                        url=cand.url,
                        parameter=cand.parameter,
                        candidate_kind=cand.kind,
                        status=verdict,
                        severity=severity,
                        evidence=evidence,
                        a_status=a["status"],
                        b_status=b["status"],
                        a_length=a["length"],
                        b_length=b["length"],
                        notes=[cand.reason] + notes,
                        cwe="CWE-639",
                    )
                )
    return results


def _probe(runtime: BrowserRuntime, url: str) -> dict:
    try:
        response = runtime.goto(url)
        runtime.page.wait_for_timeout(500)
        html = runtime.page.content()
        title = runtime.page.title()
        return {
            "status": response.status if response else None,
            "length": len(html or ""),
            "title": title,
            "final_url": runtime.page.url,
            "html": html[:12000],
        }
    except Exception as exc:
        return {
            "status": None,
            "length": 0,
            "title": "",
            "final_url": url,
            "html": f"ERROR: {exc}",
        }


def _compare(a: dict, b: dict, cand: IdorCandidate) -> tuple[str, str, list[str]]:
    notes: list[str] = []
    if a["status"] in {401, 403} and b["status"] in {200, 302}:
        notes.append("Session B can access while A is denied")
        return "potential_idor", "medium", notes
    if b["status"] in {401, 403} and a["status"] in {200, 302}:
        notes.append("Session A can access while B is denied")
        return "potential_idor", "medium", notes
    if a["status"] == b["status"] and a["status"] in {200, 201, 202}:
        diff = abs(a["length"] - b["length"])
        baseline = max(a["length"], b["length"], 1)
        if diff / baseline > 0.25 and cand.kind in {"path", "query"}:
            notes.append(f"Response size differs by {diff} bytes between A and B")
            return "potential_idor", "low", notes
        notes.append("No access difference observed between sessions")
        return "access_denied", "info", notes
    notes.append(f"Status A={a['status']} B={b['status']}")
    return "needs_manual_validation", "info", notes


def _looks_like_identifier(value: str) -> bool:
    return bool(_LONG_NUM_RE.match(value) or _UUID_RE.match(value) or len(value) >= 24 and re.fullmatch(r"[A-Za-z0-9_-]+", value or ""))


def _replace_query_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    rebuilt = []
    for k, v in query:
        if k == key:
            rebuilt.append((k, value))
        else:
            rebuilt.append((k, v))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urlencode(rebuilt), ""))


def _write_probe(path: Path, data: dict) -> None:
    path.write_text(
        "\n".join(
            [
                f"status: {data['status']}",
                f"length: {data['length']}",
                f"title: {data['title']}",
                f"final_url: {data['final_url']}",
                "",
                data["html"],
            ]
        ),
        encoding="utf-8",
    )

