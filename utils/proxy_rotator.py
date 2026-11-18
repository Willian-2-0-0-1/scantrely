"""Rotação de proxy residencial (Webshare e compatíveis) usada quando o motor HTTP
detecta bloqueio de WAF/CDN — ver core/reconlib/base.py (http_get) e core/pipeline.py
(_check_blocked_and_rotate).

O scan roda em IP direto por padrão (sem custo de proxy). Só quando uma sondagem bate
num bloqueio real é que o proxy configurado entra, e se o bloqueio persistir mesmo
pelo proxy, a sessão é rotacionada para sair por outra IP residencial.

Formato de autenticação do Webshare (apidocs.webshare.io/proxy-connection):
    http://{usuario}-{pais}-{sessao}:{senha}@p.webshare.io:80
Um número de sessão numérico no final do usuário fixa a IP de saída enquanto esse
número não muda — é assim que o Webshare implementa "sticky session". Rotacionar aqui
é só sortear um novo número e remontar a URL; não existe chamada de API para isso,
a próxima conexão com um número de sessão diferente já sai por outra IP residencial
do pool. Se o usuário não seguir esse formato (sem `-<número>` no final), a rotação
não tem o que trocar e devolve a mesma URL — ainda funciona como proxy fixo.
"""
from __future__ import annotations

import random
import re
from urllib.parse import urlsplit, urlunsplit

_SESSION_RE = re.compile(r"^(?P<base>.+)-(?P<session>\d+)$")


def is_enabled(settings: dict | None) -> bool:
    """A proxy está habilitada e configurada nas Configurações?"""
    s = settings or {}
    enabled = str(s.get("proxy_enabled", "")).strip().lower() in {"1", "true", "yes", "on"}
    return enabled and bool((s.get("proxy_url") or "").strip())


def base_url(settings: dict | None) -> str:
    """URL de proxy configurada (vazio se não configurada)."""
    return ((settings or {}).get("proxy_url") or "").strip()


def rotate(url: str) -> str:
    """Devolve a mesma URL com um novo número de sessão sorteado (= nova IP residencial
    no próximo connect). Sem padrão `usuario-...-<número>` no usuário, devolve a URL
    sem alteração (nada a rotacionar — ainda assim é tentada de novo, só não muda a IP)."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
        if not parts.username:
            return url
        m = _SESSION_RE.match(parts.username)
        if not m:
            return url
        new_user = f"{m.group('base')}-{random.randint(1, 999_999)}"
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        userinfo = new_user if not parts.password else f"{new_user}:{parts.password}"
        netloc = f"{userinfo}@{host}"
        return urlunsplit((parts.scheme or "http", netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        return url


def redact(url: str) -> str:
    """URL sem a senha — para log e UI."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
        if parts.password:
            host = parts.hostname or ""
            if parts.port:
                host = f"{host}:{parts.port}"
            netloc = f"{parts.username}:***@{host}"
            return urlunsplit((parts.scheme or "http", netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        pass
    return url


def test(url: str, timeout: float = 8.0) -> dict:
    """Faz uma requisição real através do proxy e devolve a IP de saída.
    Usado pelo botão 'Testar proxy' / endpoint de diagnóstico — não depende de
    curl_cffi, só de urllib (biblioteca padrão), então funciona mesmo sem dependências
    opcionais instaladas."""
    import urllib.error
    import urllib.request

    if not url:
        return {"ok": False, "error": "proxy não configurado"}
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": url, "https": url}))
        with opener.open("https://ipv4.webshare.io/", timeout=timeout) as r:
            ip = r.read(200).decode("utf-8", "ignore").strip()
        return {"ok": True, "ip": ip, "proxy": redact(url)}
    except urllib.error.URLError as e:
        return {"ok": False, "error": str(e.reason or e), "proxy": redact(url)}
    except Exception as e:
        return {"ok": False, "error": str(e), "proxy": redact(url)}
