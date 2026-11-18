"""Monitor contínuo de Certificate Transparency via CertStream.

Fica em segundo plano, ligado a um servidor CertStream (o seu `certstream-server-go`, o servidor
público da Calidog ou ambos), e avisa quando surge certificado para um nome novo sob um domínio em
escopo. Diferente do snapshot de 45 s do pipeline, aqui a escuta é ininterrupta.

Configuração (Configurações → Certificate Transparency, ou variável de ambiente):
  certstream_enabled          "1" liga o monitor (padrão: desligado)
  certstream_url              um ou mais ws:// / wss:// (vírgula/espaço); tentados em ordem
                              (ASM_CERTSTREAM_URL é usada se a configuração estiver vazia)
  certstream_public_fallback  "0" tira o servidor público da lista de reserva

Aceita os dois formatos: o de certificado (`data.leaf_cert.all_domains`, endpoints "/" e "/full-stream" do
certstream-server-go) e o só-domínios (`data` = lista de nomes, endpoint "/domains-only": menos tráfego).
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import threading
import time
from collections import OrderedDict, deque
from datetime import datetime

log = logging.getLogger("scantrely.certmonitor")

PUBLIC_URL = "wss://certstream.calidog.io/"
RECV_TIMEOUT_S = 45        # o servidor manda heartbeat/ping a cada ~15 s: 45 s mudo = conexão morta
POLL_S = 5                 # tempo máximo parado em recv() antes de descarregar alertas / checar parada
FLUSH_EVERY_S = 30         # agrupa o que chegou antes de alertar
SCOPE_REFRESH_S = 60
SETTINGS_POLL_S = 20
PRIMARY_RETRY_S = 600      # em servidor de reserva há tanto tempo: volta a tentar o primeiro
MAX_ALERTS_PER_FLUSH = 25
SEEN_MAX = 50_000
RECENT_MAX = 2_000
BACKOFF_MAX_S = 120


# ── configuração ─────────────────────────────────────────────────────────────

def parse_urls(*values) -> list[str]:
    out: list[str] = []
    for v in values:
        for u in re.split(r"[\s,;]+", str(v or "")):
            u = u.strip()
            if u.startswith(("ws://", "wss://")) and u not in out:
                out.append(u)
    return out


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on", "sim")


def resolve_urls(settings: dict | None = None) -> list[str]:
    """URLs na ordem de tentativa: as configuradas e, por último, o servidor público."""
    s = settings or {}
    urls = parse_urls(s.get("certstream_url"), os.environ.get("ASM_CERTSTREAM_URL"))
    fallback = str(s.get("certstream_public_fallback") or "").strip().lower() not in ("0", "false", "no", "off", "nao", "não")
    if PUBLIC_URL not in urls and (fallback or not urls):
        urls.append(PUBLIC_URL)
    return urls


def is_enabled(settings: dict | None) -> bool:
    return _truthy((settings or {}).get("certstream_enabled")) or _truthy(os.environ.get("ASM_CERTSTREAM"))


def _is_timeout(e: Exception) -> bool:
    return isinstance(e, TimeoutError) or type(e).__name__ == "WebSocketTimeoutException"


# ── mensagens ────────────────────────────────────────────────────────────────

def extract_names(msg) -> tuple[list[str], dict]:
    """(nomes do certificado, metadados) para os dois formatos do CertStream."""
    if not isinstance(msg, dict):
        return [], {}
    data = msg.get("data")
    if isinstance(data, dict) and isinstance(data.get("leaf_cert"), dict):      # "certificate_update"
        leaf = data.get("leaf_cert") or {}
        issuer = leaf.get("issuer") or {}
        names = leaf.get("all_domains") or []
        meta = {
            "issuer": (issuer.get("O") or issuer.get("CN") or "") if isinstance(issuer, dict) else "",
            "not_before": leaf.get("not_before"),
            "not_after": leaf.get("not_after"),
            "log": (data.get("source") or {}).get("name", "") if isinstance(data.get("source"), dict) else "",
        }
        return [n for n in names if isinstance(n, str)], meta
    if isinstance(data, list):                                                   # "dns_entries" (domains-only)
        return [n for n in data if isinstance(n, str)], {}
    return [], {}


class _Scope:
    """Índice domínio → empresas, para casar nome de certificado em O(rótulos)."""

    def __init__(self, companies: list[dict]):
        self.domains: dict[str, list[str]] = {}
        self.excluded: dict[str, list[str]] = {}
        self.names: dict[str, str] = {}
        for co in companies or []:
            cid = co.get("id")
            if not cid:
                continue
            self.names[cid] = co.get("name") or cid
            self.excluded[cid] = list(co.get("out_of_scope") or [])
            for d in co.get("domains") or []:
                d = str(d or "").strip().lower().strip(".")
                if d and "." in d:
                    self.domains.setdefault(d, [])
                    if cid not in self.domains[d]:
                        self.domains[d].append(cid)

    def match(self, host: str) -> list[tuple[str, str]]:
        """[(company_id, domínio em escopo)] para um host já normalizado."""
        parts = host.split(".")
        hits: list[tuple[str, str]] = []
        seen: set[str] = set()
        for i in range(len(parts) - 1):
            dom = ".".join(parts[i:])
            for cid in self.domains.get(dom, ()):
                if cid not in seen:
                    seen.add(cid)
                    hits.append((cid, dom))
        return hits


def _normalize(name: str) -> tuple[str, bool]:
    n = str(name or "").strip().lower().rstrip(".")
    wildcard = n.startswith("*.")
    n = n.lstrip("*.")
    if not n or " " in n or "." not in n or "/" in n:
        return "", wildcard
    return n, wildcard


# ── monitor ──────────────────────────────────────────────────────────────────

class CertStreamMonitor:
    def __init__(self, db, get_settings, base_dir=None, connect=None):
        self.db = db
        self.get_settings = get_settings
        self.base_dir = base_dir
        self._connect_fn = connect          # injetável nos testes
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._ws = None
        self._scope = _Scope([])
        self._scope_at = 0.0
        self._seen: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._pending: dict[tuple[str, str], dict] = {}
        self._recent: deque = deque(maxlen=RECENT_MAX)
        self._idx = 0
        self.stats = {
            "state": "stopped", "url": "", "connected_at": None, "last_message_at": None,
            "received": 0, "matched": 0, "alerts": 0, "reconnects": 0, "last_error": "",
        }

    # ── ciclo de vida ───────────────────────────────────────────────────────
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="certstream-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        ws = self._ws
        if ws is not None:
            try:
                ws.close()
            except Exception:
                log.debug("certstream: fechar conexão falhou", exc_info=True)
        if self._thread:
            self._thread.join(timeout=5)
        self.stats["state"] = "stopped"

    def status(self) -> dict:
        with self._lock:
            return {**self.stats, "domains": len(self._scope.domains), "recent": len(self._recent),
                    "pending": len(self._pending), "urls": resolve_urls(self._safe_settings())}

    def is_connected(self) -> bool:
        return self.stats["state"] == "connected"

    def recent_for(self, domains) -> list[dict]:
        """Certificados vistos (desde que o monitor subiu) sob os domínios dados — alimenta o módulo do pipeline."""
        ds = {str(d or "").strip().lower().strip(".") for d in domains or [] if d}
        with self._lock:
            return [dict(r) for r in self._recent if r["domain"] in ds]

    # ── laço principal ──────────────────────────────────────────────────────
    def _safe_settings(self) -> dict:
        try:
            return self.get_settings() or {}
        except Exception:
            log.debug("certstream: ler configurações falhou", exc_info=True)
            return {}

    def _run(self) -> None:
        backoff = 2.0
        while not self._stop.is_set():
            s = self._safe_settings()
            if not is_enabled(s):
                self.stats["state"] = "disabled"
                self._stop.wait(SETTINGS_POLL_S)
                continue
            urls = resolve_urls(s)
            url = urls[self._idx % len(urls)]
            self.stats["state"], self.stats["url"] = "connecting", url
            healthy = False
            try:
                healthy = self._session(url)
                backoff = 2.0
            except Exception as e:
                self.stats["last_error"] = f"{url}: {e}"[:300]
                log.info("certstream: %s", self.stats["last_error"])
            finally:
                self._ws = None
                self._flush()
                if not self._stop.is_set() and self.stats["state"] != "disabled":
                    self.stats["state"] = "reconnecting"
            if self._stop.is_set():
                break
            self.stats["reconnects"] += 1
            if not healthy:
                self._idx += 1                    # servidor não serviu: tenta o próximo
                if self._idx % len(urls) == 0:
                    backoff = min(backoff * 2, BACKOFF_MAX_S)
            self._stop.wait(backoff + random.uniform(0, backoff / 4))

    def _connect(self, url: str):
        if self._connect_fn:
            return self._connect_fn(url)
        import websocket                          # websocket-client
        return websocket.create_connection(url, timeout=10)

    def _session(self, url: str) -> bool:
        """Uma conexão. True se chegou mensagem (servidor saudável); levanta se não conectou/ficou mudo."""
        ws = self._connect(url)
        self._ws = ws
        try:
            ws.settimeout(POLL_S)             # acorda a cada POLL_S para descarregar alertas e checar parada
        except Exception:
            log.debug("certstream: settimeout indisponível", exc_info=True)
        got = False
        started = last_msg = last_flush = last_check = time.time()
        self.stats.update(state="connected", connected_at=datetime.now().isoformat(timespec="seconds"))
        log.info("certstream: conectado em %s", url)
        try:
            while not self._stop.is_set():
                raw = None
                try:
                    raw = ws.recv()
                except Exception as e:
                    if self._stop.is_set():
                        break
                    if not _is_timeout(e):
                        if got:
                            self.stats["last_error"] = f"{url}: {e}"[:300]
                            return True       # caiu depois de servir: reconecta no mesmo
                        raise
                    if time.time() - last_msg > RECV_TIMEOUT_S:
                        if got:
                            self.stats["last_error"] = f"{url}: sem mensagens há {RECV_TIMEOUT_S:.0f}s"
                            return True
                        raise ConnectionError(f"sem mensagens em {RECV_TIMEOUT_S:.0f}s")
                else:
                    if not raw:
                        if got:
                            return True
                        raise ConnectionError("conexão fechada sem mensagens")
                    got = True
                    last_msg = time.time()
                    self.stats["received"] += 1
                    self.stats["last_message_at"] = datetime.now().isoformat(timespec="seconds")
                    try:
                        self._handle(json.loads(raw))
                    except ValueError:
                        pass
                now = time.time()
                if now - last_flush >= FLUSH_EVERY_S:
                    self._flush()
                    last_flush = now
                if now - last_check >= SETTINGS_POLL_S:
                    last_check = now
                    s = self._safe_settings()
                    if not is_enabled(s):
                        self.stats["state"] = "disabled"
                        return True
                    urls = resolve_urls(s)
                    if url not in urls:
                        return True               # URL mudou na configuração
                    if self._idx % len(urls) != 0 and now - started > PRIMARY_RETRY_S:
                        self._idx = 0             # volta ao servidor preferido
                        return True
        finally:
            try:
                ws.close()
            except Exception:
                log.debug("certstream: close falhou", exc_info=True)
        return got

    # ── processamento ───────────────────────────────────────────────────────
    def _refresh_scope(self) -> None:
        if time.time() - self._scope_at < SCOPE_REFRESH_S and self._scope.domains:
            return
        try:
            scope = _Scope(self.db.load_companies())
        except Exception:
            log.debug("certstream: carregar escopo falhou", exc_info=True)
            return
        with self._lock:
            self._scope, self._scope_at = scope, time.time()

    def _handle(self, msg: dict) -> None:
        names, meta = extract_names(msg)
        if not names:
            return
        self._refresh_scope()
        scope = self._scope
        if not scope.domains:
            return
        from core.scope import is_excluded
        now = datetime.now().isoformat(timespec="seconds")
        for raw_name in names:
            host, wildcard = _normalize(raw_name)
            if not host:
                continue
            for cid, dom in scope.match(host):
                if is_excluded(host, scope.excluded.get(cid)):
                    continue
                item = {"company_id": cid, "domain": dom, "host": host, "wildcard": wildcard,
                        "cn": host, "issuer": meta.get("issuer", ""), "not_before": meta.get("not_before") or "",
                        "not_after": meta.get("not_after") or "", "log": meta.get("log", ""), "seen_at": now,
                        "source": "certstream"}
                with self._lock:
                    self._recent.append(item)
                    self.stats["matched"] += 1
                    key = (cid, host)
                    if key in self._seen:
                        self._seen.move_to_end(key)
                        continue
                    self._seen[key] = time.time()
                    if len(self._seen) > SEEN_MAX:
                        self._seen.popitem(last=False)
                    if host != dom:               # o apex já é conhecido
                        self._pending[key] = item

    def _flush(self) -> None:
        with self._lock:
            pending, self._pending = self._pending, {}
        if not pending:
            return
        try:
            data = self.db.load_asm_data()
        except Exception:
            log.debug("certstream: inventário indisponível", exc_info=True)
            data = {}
        inventory = {c.get("id"): {h.get("host") for h in c.get("hosts", []) if isinstance(h, dict)}
                     for c in data.get("companies", [])}
        by_co: dict[str, list[dict]] = {}
        for (cid, host), item in pending.items():
            if host in inventory.get(cid, ()):
                continue                          # já inventariado: certificado novo de host conhecido não é novidade
            by_co.setdefault(cid, []).append(item)
        now = datetime.now().isoformat(timespec="seconds")
        for cid, items in by_co.items():
            items.sort(key=lambda i: i["host"])
            for it in items[:MAX_ALERTS_PER_FLUSH]:
                sev = "low" if it["wildcard"] else "medium"
                desc = (f"Certificado emitido por {it['issuer'] or 'CA desconhecida'}"
                        + (" (curinga)" if it["wildcard"] else "")
                        + f" para um nome sob {it['domain']} que não está no inventário.")
                try:
                    self.db.create_alert(cid, "certstream_new_host", f"Novo certificado: {it['host']}", desc, sev, it)
                    self.db.insert_subdomain_history(cid, it["host"], "new", now, now, 0, source="certstream")
                    self.stats["alerts"] += 1
                except Exception:
                    log.debug("certstream: gravar alerta falhou", exc_info=True)
            if len(items) > MAX_ALERTS_PER_FLUSH:
                try:
                    self.db.create_alert(cid, "certstream_summary", f"{len(items)} nomes novos em certificados",
                                         "Muitos nomes novos de uma vez; veja o histórico de subdomínios.", "medium",
                                         {"count": len(items)})
                except Exception:
                    log.debug("certstream: alerta de resumo falhou", exc_info=True)
            try:
                from utils.notifications import notify
                notify(self.db, self.get_settings, self.base_dir, "surface_change",
                       {"company_name": self._scope.names.get(cid, cid), "company_id": cid,
                        "new_host": [i["host"] for i in items]})
            except Exception:
                log.debug("certstream: notificação falhou", exc_info=True)


# ── instância única (o servidor registra; o módulo do pipeline consulta) ─────

_MONITOR: CertStreamMonitor | None = None


def set_monitor(m: CertStreamMonitor | None) -> None:
    global _MONITOR
    _MONITOR = m


def get_monitor() -> CertStreamMonitor | None:
    return _MONITOR
