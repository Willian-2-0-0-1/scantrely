"""Envia URLs pelo proxy do Burp para elas aparecerem no Site map (Repeater/Intruder/Scanner a partir dali).

É uma ação do usuário (botão "Enviar ao Burp"): faz um GET real em cada URL, passando pelo proxy.
As URLs vêm de core/tool_lists.py, já dentro do escopo e sem o "fora do escopo".
"""
from __future__ import annotations

import json
import logging
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

log = logging.getLogger("scantrely.burp")

DEFAULT_PROXY = "http://127.0.0.1:8080"
MAX_URLS = 500


def _opener(proxy: str):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # o Burp intercepta com o certificado dele
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
        urllib.request.HTTPSHandler(context=ctx),
    )


def proxy_reachable(proxy: str, timeout: float = 3.0) -> bool:
    import socket
    from urllib.parse import urlsplit
    p = urlsplit(proxy if "://" in proxy else "http://" + proxy)
    try:
        with socket.create_connection((p.hostname or "127.0.0.1", p.port or 8080), timeout=timeout):
            return True
    except OSError:
        return False


def is_burp(proxy: str, timeout: float = 5.0) -> bool:
    """O proxy é mesmo o Burp? Ele responde a http://burp/ com a própria página. Outra coisa na porta
    (nesta máquina, a 8080 é de um container Docker e o listener do Burp ficou parado) não conta."""
    try:
        with _opener(proxy).open("http://burp/", timeout=timeout) as r:
            return b"Burp Suite" in r.read(4096)
    except Exception:
        return False


def feed(urls: list[str], proxy: str = DEFAULT_PROXY, *, workers: int = 5, timeout: int = 15,
         opener=None) -> dict:
    urls = list(urls)[:MAX_URLS]
    op = opener or _opener(proxy)
    ok, failed = [], []

    def _one(url):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Scantrely to Burp)"})
            with op.open(req, timeout=timeout) as r:
                r.read(1024)
            ok.append(url)
        except urllib.error.HTTPError:
            ok.append(url)              # 4xx/5xx também entram no Site map
        except Exception as e:
            failed.append((url, type(e).__name__))

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        list(ex.map(_one, urls))
    return {"sent": len(urls), "ok": len(ok), "failed": len(failed), "errors": failed[:20]}


def feed_and_record(urls: list[str], proxy: str, out_path: Path, kind: str) -> dict:
    started = datetime.now()
    res = feed(urls, proxy)
    res.update({"kind": kind, "proxy": proxy, "started_at": started.isoformat(timespec="seconds"),
                "finished_at": datetime.now().isoformat(timespec="seconds")})
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    except Exception:
        log.debug("burp: resumo não gravado", exc_info=True)
    log.info("[burp] %s: %s/%s URLs entregues ao proxy %s", kind, res["ok"], res["sent"], proxy)
    return res
