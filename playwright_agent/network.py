from __future__ import annotations

from urllib.parse import urlparse

from .masking import mask_headers, mask_text
from .models import Endpoint


SENSITIVE_PARAM_NAMES = {
    "id", "user_id", "account_id", "profile_id", "order_id", "invoice_id", "file_id",
    "document_id", "tenant_id", "organization_id", "company_id", "token", "jwt", "secret",
    "apikey", "api_key", "password", "passwd", "email", "role", "isadmin",
}


def normalize_endpoint_from_response(response, source_page: str = "") -> Endpoint:
    request = response.request
    post_data = getattr(request, "post_data", None) or ""
    query = dict(_query_params(response.url))
    return Endpoint(
        url=response.url,
        method=(request.method or "GET").upper(),
        status=response.status,
        request_headers=mask_headers(dict(request.headers)),
        response_headers=mask_headers(dict(response.headers)),
        parameters={
            "query_keys": sorted(query.keys()),
            "post_data": mask_text(post_data) if post_data else "",
            "sensitive_keys": sorted(k for k in query if k.lower() in SENSITIVE_PARAM_NAMES),
        },
        content_type=response.headers.get("content-type", ""),
        source_page=source_page,
    )


def normalize_failed_request(request, source_page: str = "") -> Endpoint:
    return Endpoint(
        url=request.url,
        method=(request.method or "GET").upper(),
        status=None,
        request_headers=mask_headers(dict(request.headers)),
        parameters={"failure": getattr(getattr(request, "failure", None), "error_text", "")},
        source_page=source_page,
        notes=["request_failed"],
    )


def dedupe_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    seen = set()
    out: list[Endpoint] = []
    for ep in endpoints:
        key = (ep.method, _normalize_for_key(ep.url))
        if key in seen:
            continue
        seen.add(key)
        out.append(ep)
    return out


def _normalize_for_key(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def _query_params(url: str) -> list[tuple[str, str]]:
    parsed = urlparse(url)
    out = []
    for chunk in parsed.query.split("&"):
        if not chunk:
            continue
        if "=" in chunk:
            k, v = chunk.split("=", 1)
        else:
            k, v = chunk, ""
        out.append((k, v))
    return out

