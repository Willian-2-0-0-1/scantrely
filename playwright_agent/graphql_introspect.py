"""GraphQL introspection (read-only).

When a GraphQL endpoint is detected, send a standard introspection query to dump the
schema's query/mutation fields — a large hidden surface the UI never exposes.
"""
from __future__ import annotations

_INTROSPECT = {
    "query": "query{__schema{queryType{name} mutationType{name} "
             "types{name kind fields{name}}}}"
}


def _gql_endpoints(urls: list[str]) -> list[str]:
    seen, out = set(), []
    for u in urls or []:
        if "graphql" in (u or "").lower() and u.startswith("http"):
            base = u.split("?")[0]
            if base not in seen:
                seen.add(base)
                out.append(base)
    return out


def introspect(urls: list[str], *, cookies: dict | None = None, user_agent: str = "", timeout: int = 15) -> dict:
    endpoints = _gql_endpoints(urls)
    if not endpoints:
        return {"introspection_enabled": False, "endpoints": []}

    headers = {"Content-Type": "application/json"}
    if user_agent:
        headers["User-Agent"] = user_agent

    for url in endpoints[:3]:
        try:
            from utils.circuit_breaker import guarded_httpx
            r = guarded_httpx(
                "POST", url, json=_INTROSPECT, timeout=timeout, verify=False,
                cookies=cookies or {}, headers=headers,
            )
        except Exception:
            continue
        if r.status_code != 200:
            continue
        try:
            schema = (r.json().get("data") or {}).get("__schema")
        except Exception:
            schema = None
        if not schema:
            continue
        types = schema.get("types", []) or []
        qname = (schema.get("queryType") or {}).get("name")
        mname = (schema.get("mutationType") or {}).get("name")
        qtype = next((t for t in types if t.get("name") == qname), {})
        mtype = next((t for t in types if t.get("name") == mname), {})
        return {
            "introspection_enabled": True,
            "endpoint": url,
            "query_fields": [f["name"] for f in (qtype.get("fields") or [])][:80],
            "mutation_fields": [f["name"] for f in (mtype.get("fields") or [])][:80],
            "type_count": len([t for t in types if not str(t.get("name", "")).startswith("__")]),
            "severity": "medium",
            "note": "Introspection enabled — disable in production or restrict it.",
        }
    return {"introspection_enabled": False, "endpoints": endpoints}
