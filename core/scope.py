"""Exclusões de escopo por empresa ("fora do escopo" do programa).

Em bug bounty, testar um host fora do escopo é motivo de banimento: o que estiver aqui não entra em
nenhuma etapa ativa (sondagem HTTP, módulos ativos, takeover, vigilância, listas exportadas, Burp).

Formatos aceitos (um por item):
  status.example.com          só esse host
  *.legacy.example.com        os subdomínios de legacy.example.com (não o próprio)
  https://x.example.com/path  vira o host x.example.com (cola direto da página do programa)
"""
from __future__ import annotations

import re

_HOST_RE = re.compile(r"^(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$")


def normalize_exclusion(entry: str) -> str:
    """Item como o usuário colou → padrão normalizado; "" se não for um host válido."""
    s = str(entry or "").strip().lower()
    if not s or s.startswith("#"):
        return ""
    s = s.split("://", 1)[-1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    s = s.rsplit("@", 1)[-1]
    if ":" in s:
        s = s.split(":", 1)[0]
    s = s.strip(".")
    return s if _HOST_RE.match(s) else ""


def normalize_exclusions(entries) -> tuple[list[str], list[str]]:
    """(padrões válidos sem repetição, itens inválidos)."""
    if isinstance(entries, str):
        entries = re.split(r"[\s,;]+", entries)
    ok, bad = [], []
    for e in entries or []:
        if not str(e or "").strip() or str(e).strip().startswith("#"):
            continue
        n = normalize_exclusion(e)
        if n and n not in ok:
            ok.append(n)
        elif not n:
            bad.append(str(e).strip())
    return ok, bad


def is_excluded(host: str, patterns) -> bool:
    h = str(host or "").strip().lower().split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].strip(".")
    if not h:
        return False
    for p in patterns or []:
        if p.startswith("*."):
            if h.endswith(p[1:]):          # ".legacy.example.com"
                return True
        elif h == p:
            return True
    return False


def drop_excluded(items, patterns, key: str = "host") -> list:
    """Filtra lista de hosts (str) ou de dicts com `key`."""
    if not patterns:
        return list(items or [])
    out = []
    for it in items or []:
        host = it.get(key, "") if isinstance(it, dict) else it
        if not is_excluded(host, patterns):
            out.append(it)
    return out


# ── leitura do escopo colado da página do programa (H1, Bugcrowd, Intigriti, YesWeHack…) ──
_TOKEN_SPLIT = re.compile(r"[\s,;|()\[\]<>\"']+")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
_APP_ID_PREFIXES = ("com.", "br.", "org.", "net.", "io.", "me.")


def parse_scope_text(text: str, *, out_of_scope: bool = False) -> tuple[list[str], list[str]]:
    """Texto colado → (itens, ignorados).

    Dentro do escopo: "*.example.com" vira o domínio example.com; host/URL vira o host.
    Fora do escopo: mantém o curinga ("*.legacy.example.com") como padrão de exclusão.
    IP/CIDR, id de app (com.empresa.app) e texto solto ficam em "ignorados" para o usuário ver.
    """
    items, ignored = [], []
    for raw in _TOKEN_SPLIT.split(str(text or "")):
        tok = raw.strip().strip(".:-*•").lower() if not raw.strip().startswith("*.") else raw.strip().lower()
        if not tok or "." not in tok:
            continue
        if _IP_RE.match(tok):
            ignored.append(raw.strip())
            continue
        bare = tok.split("://", 1)[-1]
        if "://" not in tok and bare.startswith(_APP_ID_PREFIXES) and "/" not in bare:
            ignored.append(raw.strip())
            continue
        n = normalize_exclusion(tok)
        if not n:
            ignored.append(raw.strip())
            continue
        if not out_of_scope and n.startswith("*."):
            n = n[2:]
        if n not in items:
            items.append(n)
    return items, ignored
