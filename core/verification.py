"""Verificação de evidência: nada de "crítico" só porque a URL parece perigosa ou o servidor respondeu 200.

Dois falsos positivos reais que motivaram este módulo:
  • `/.git/config` com HTTP 200 e corpo HTML (SPA/soft-404 respondendo 200 para qualquer caminho);
  • URL histórica do Wayback (`/.git/config`) classificada como crítica, mas o servidor hoje responde 403.
"""
from __future__ import annotations

import re

_HTML = re.compile(rb"^\s*(<!doctype\s+html|<html|<head|<body|<\?xml|<script)", re.I)
_HEX40 = re.compile(rb"^[0-9a-f]{40}\s*$", re.I)


def _b(body) -> bytes:
    if body is None:
        return b""
    return body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8", "ignore")


def is_html(body) -> bool:
    return bool(_HTML.match(_b(body)[:300]))


def looks_like_git(path: str, body) -> bool:
    """O corpo é mesmo um arquivo interno do git? (HTML nunca é)."""
    raw = _b(body)
    if not raw or is_html(raw):
        return False
    p = (path or "").lower()
    if p.endswith("/.git/config") or p.endswith(".git/config"):
        return b"[core]" in raw or b"repositoryformatversion" in raw or b"[remote " in raw
    if p.endswith("/.git/head") or p.endswith(".git/head"):
        return raw.lstrip().startswith(b"ref:") or bool(_HEX40.match(raw.strip()))
    if p.endswith(".git/index"):
        return raw.startswith(b"DIRC")
    return b"[core]" in raw or raw.lstrip().startswith(b"ref:")


_JSON_START = re.compile(rb"^\s*[\[{]")


def _json_has(raw: bytes, *keys: bytes) -> bool:
    return bool(_JSON_START.match(raw[:20])) and any(b'"' + k + b'"' in raw[:20000] for k in keys)


# (regex do caminho, verificação sobre o corpo). A primeira regra que casa decide.
# Cada verificação olha o CONTEÚDO esperado do arquivo/serviço — status 200 e tamanho não contam.
_CONTENT_RULES = [
    (re.compile(r"\.git/"), lambda p, r: looks_like_git(p, r)),
    (re.compile(r"(^|/)\.env(\.[\w.-]+)?$|/\.env\b"), lambda p, r: bool(re.search(rb"^[A-Z][A-Z0-9_]{2,}\s*=", r, re.M))),
    (re.compile(r"/\.svn/"), lambda p, r: b"svn:" in r or r[:2].isdigit()),
    (re.compile(r"\.sql(\.|$|\b)"), lambda p, r: bool(re.search(rb"CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE", r, re.I))),
    (re.compile(r"wp-config"), lambda p, r: b"DB_NAME" in r or b"DB_PASSWORD" in r),
    (re.compile(r"\.htaccess$"), lambda p, r: bool(re.search(rb"RewriteEngine|AuthType|Require |Options ", r))),
    (re.compile(r"id_rsa|\.pem$|\.key$"), lambda p, r: b"PRIVATE KEY" in r),
    (re.compile(r"\.ds_store$"), lambda p, r: r.startswith(b"\x00\x00\x00\x01Bud1")),
    (re.compile(r"phpinfo"), lambda p, r: b"PHP Version" in r),
    (re.compile(r"web\.config$"), lambda p, r: b"<configuration" in r.lower()),
    (re.compile(r"\.tfstate(\.backup)?$"), lambda p, r: _json_has(r, b"terraform_version", b"resources", b"serial")),
    (re.compile(r"docker-compose\.ya?ml$"), lambda p, r: bool(re.search(rb"^\s*services\s*:", r, re.M))),
    (re.compile(r"(composer|package)\.json$"), lambda p, r: _json_has(r, b"require", b"dependencies", b"name")),
    (re.compile(r"\.(zip)$"), lambda p, r: r.startswith(b"PK\x03\x04")),
    (re.compile(r"\.(tar\.gz|tgz|gz)$"), lambda p, r: r.startswith(b"\x1f\x8b")),
    (re.compile(r"\.(rar)$"), lambda p, r: r.startswith(b"Rar!")),
    (re.compile(r"\.(7z)$"), lambda p, r: r.startswith(b"7z\xbc\xaf")),
    (re.compile(r"/actuator(/|$)"), lambda p, r: _json_has(r, b"status", b"_links", b"propertySources", b"activeProfiles", b"beans")),
    (re.compile(r"(swagger|openapi|api-docs)[^/]*\.json$|/v[23]/api-docs$"), lambda p, r: _json_has(r, b"swagger", b"openapi", b"paths")),
    (re.compile(r"swagger-ui"), lambda p, r: b"swagger-ui" in r.lower() or b"swagger ui" in r.lower()),
    (re.compile(r"server-status$"), lambda p, r: b"Apache Server Status" in r or b"Server Version" in r),
    (re.compile(r"/trace\.axd$"), lambda p, r: b"Application Trace" in r),
    (re.compile(r"(^|/)\.dockerenv$|/\.aws/credentials$"), lambda p, r: b"aws_access_key_id" in r.lower()),
]
# HTML legítimo: estas rotas respondem em HTML de verdade, então HTML não as descarta.
_HTML_OK = re.compile(r"phpinfo|swagger-ui|server-status|trace\.axd|\.(php|html?)$")


def _content_rule(path: str):
    p = (path or "").lower()
    for rx, check in _CONTENT_RULES:
        if rx.search(p):
            return p, check
    return p, None


def has_content_rule(path: str) -> bool:
    """Existe verificação por conteúdo para este caminho? (Se sim, 200 sem o conteúdo não vale como achado.)"""
    return _content_rule(path)[1] is not None


def looks_like_sensitive_file(path: str, body) -> bool:
    """Confirma arquivos sensíveis conhecidos pelo conteúdo (não pelo status)."""
    raw = _b(body)
    p, check = _content_rule(path)
    if not raw or check is None:
        return False
    if is_html(raw) and not _HTML_OK.search(p):
        return False
    return bool(check(p, raw))


# Caminhos que, se confirmados, são de fato críticos — só estes valem a sondagem ao vivo.
HIGH_RISK_PATH = re.compile(
    r"(/\.git/|/\.svn/|/\.env\b|\.env$|wp-config|\.sql\b|\.htaccess|id_rsa|\.pem$|\.ds_store|phpinfo|backup|\.bak$|\.old$|\.zip$|\.tar\.gz$)", re.I)


def classify_live(path: str, status, body) -> dict:
    """Resultado da sondagem ao vivo de uma URL histórica."""
    try:
        code = int(status or 0)
    except (TypeError, ValueError):
        code = 0
    confirmed = code == 200 and looks_like_sensitive_file(path, body)
    return {"live_status": code, "verified": confirmed}
