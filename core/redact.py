"""Máscara de segredos para tudo que sai do Scantrely em forma de relatório (HTML, PDF, CSV, SARIF).

O valor bruto continua no banco e no JSON de exportação (é o dado do analista, usado para reteste);
o relatório que circula por e-mail ou chamado mostra só o suficiente para reconhecer a chave:
`AKIA****…MPLE`. Funções puras e idempotentes.
"""
from __future__ import annotations

import re

# Formatos de credencial com prefixo conhecido ou estrutura inconfundível.
_TOKEN_RES = [re.compile(p) for p in (
    r"AKIA[0-9A-Z]{16}", r"ASIA[0-9A-Z]{16}",
    r"gh[pousr]_[A-Za-z0-9]{30,}", r"github_pat_[A-Za-z0-9_]{40,}",
    r"xox[abprs]-[A-Za-z0-9-]{10,}",
    r"[sr]k_live_[A-Za-z0-9]{16,}", r"sk-[A-Za-z0-9]{32,}",
    r"AIza[0-9A-Za-z_-]{35}",
    r"glpat-[A-Za-z0-9_-]{20,}",
    r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}",
    r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",   # JWT
)]
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)
# nome=valor / "nome": "valor" onde o nome indica segredo
_ASSIGN_RE = re.compile(
    r"""(?ix)
    (?P<k>["']?\b[\w.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization|auth[_-]?token)[\w.-]*["']?\s*[:=]\s*["']?)
    (?P<v>[^\s"'&,;<>]{6,})""")
_URL_CRED_RE = re.compile(r"(?P<p>[a-z][a-z0-9+.-]*://[^\s:/@]+:)(?P<v>[^\s@/]{3,})(?=@)", re.I)
_MASK = "****"


def mask_secret(value: str) -> str:
    """`AKIAIOSFODNN7EXAMPLE` → `AKIA****MPLE`. Valores curtos viram só `****`."""
    v = str(value or "")
    if len(v) <= 12:
        return _MASK
    return f"{v[:4]}{_MASK}{v[-4:]}"


def redact_text(text, extra: tuple = ()) -> str:
    """Troca credenciais reconhecíveis por versões mascaradas. `extra` = valores conhecidos (ex.: o `value` do achado)."""
    s = str(text or "")
    if not s:
        return s
    for v in extra:
        v = str(v or "")
        if len(v) >= 8 and v in s:
            s = s.replace(v, mask_secret(v))
    s = _PRIVATE_KEY_RE.sub("-----PRIVATE KEY REDACTED-----", s)
    for rx in _TOKEN_RES:
        s = rx.sub(lambda m: mask_secret(m.group(0)), s)
    s = _URL_CRED_RE.sub(lambda m: m.group("p") + _MASK, s)
    s = _ASSIGN_RE.sub(lambda m: m.group("k") + (m.group("v") if _MASK in m.group("v") else mask_secret(m.group("v"))), s)
    return s


_TEXT_FIELDS = ("title", "desc", "value", "url", "matched", "evidence", "request_raw", "response_raw", "snippet")


def redact_finding(f: dict) -> dict:
    """Cópia do achado com segredos mascarados nos campos de texto. O original não é alterado."""
    if not isinstance(f, dict):
        return f
    meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
    known = tuple(x for x in (f.get("value") if f.get("type") == "secret" else "", meta.get("secret_value"), meta.get("secret")) if x)
    out = dict(f)
    for k in _TEXT_FIELDS:
        if isinstance(out.get(k), str):
            out[k] = redact_text(out[k], known)
    if isinstance(meta.get("context"), str):
        out["metadata"] = {**meta, "context": redact_text(meta["context"], known)}
    return out


def redact_findings(findings) -> list:
    return [redact_finding(f) for f in findings or []]
