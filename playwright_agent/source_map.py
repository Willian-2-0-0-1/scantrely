from __future__ import annotations

import json
from urllib.parse import urljoin


def extract_source_map_url(js_text: str) -> str | None:
    marker = "sourceMappingURL="
    if marker not in js_text:
        return None
    tail = js_text.rsplit(marker, 1)[-1].strip()
    tail = tail.splitlines()[0].strip()
    tail = tail.replace("*/", "").strip()
    return tail or None


def fetch_source_map(js_url: str, source_map_url: str, timeout: int = 15) -> dict | None:
    if not source_map_url:
        return None
    full = urljoin(js_url, source_map_url)
    try:
        from utils.circuit_breaker import guarded_httpx
        resp = guarded_httpx(
            "GET", full, timeout=timeout, follow_redirects=True, verify=False,
        )
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def summarize_source_map(map_json: dict | None) -> dict:
    if not map_json:
        return {"accessible": False, "sources": [], "names": [], "source_root": ""}
    return {
        "accessible": True,
        "sources": list(map_json.get("sources", []) or [])[:200],
        "names": list(map_json.get("names", []) or [])[:200],
        "source_root": map_json.get("sourceRoot", ""),
    }

