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


def looks_like_sensitive_file(path: str, body) -> bool:
    """Confirma arquivos sensíveis conhecidos pelo conteúdo (não pelo status)."""
    raw = _b(body)
    if not raw or is_html(raw) and not path.lower().endswith((".php", ".html", ".htm")):
        return False
    p = path.lower()
    if ".git/" in p:
        return looks_like_git(p, raw)
    if p.endswith(".env") or "/.env" in p:
        return bool(re.search(rb"^[A-Z][A-Z0-9_]{2,}\s*=", raw, re.M))
    if "/.svn/" in p:
        return b"svn:" in raw or raw[:2].isdigit()
    if p.endswith(".sql") or ".sql" in p:
        return bool(re.search(rb"CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE", raw, re.I))
    if "wp-config" in p:
        return b"DB_NAME" in raw or b"DB_PASSWORD" in raw
    if p.endswith(".htaccess"):
        return bool(re.search(rb"RewriteEngine|AuthType|Require |Options ", raw))
    if "id_rsa" in p or p.endswith(".pem") or p.endswith(".key"):
        return b"PRIVATE KEY" in raw
    if p.endswith(".ds_store"):
        return raw.startswith(b"\x00\x00\x00\x01Bud1")
    if "phpinfo" in p:
        return b"PHP Version" in raw
    return False


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
