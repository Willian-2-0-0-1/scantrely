"""Vigilância contínua da superfície: enumeração passiva + sondagem leve + diff contra o inventário.

É o que roda a cada X horas (agenda com perfil "watch") ou no botão "Monitor Now". Não é o pipeline:
nada de módulo ativo, só subfinder (passivo) e uma sondagem HTTP em 80/443 com o filtro de curinga.
Cada mudança vira um alerta e os webhooks recebem um resumo (evento "surface_change").
"""
from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

log = logging.getLogger("scantrely.watch")

MISSES_TO_DEAD = 2       # vigilâncias seguidas sem resposta antes de dizer que o host caiu
MAX_ALERTS = 50          # acima disso, um alerta de resumo em vez de um por mudança
SEVERITY = {"new_host_live": "medium", "came_alive": "medium", "new_host": "low",
            "changed": "low", "went_dead": "info"}
# páginas de desafio anti-bot: o mesmo host alterna entre elas e a página real a cada requisição
_CHALLENGE_TITLES = ("just a moment", "attention required", "checking your browser", "ddos-guard",
                     "please wait", "verifying you are human")


def _severity(ch: dict) -> str:
    """Host novo/que voltou respondendo com erro (404, 403…) chama menos atenção que um com conteúdo."""
    sev = SEVERITY.get(ch["kind"], "info")
    if ch["kind"] in ("new_host_live", "came_alive") and (ch.get("status_code") or 0) >= 400:
        return "low"
    return sev


def _challenge(title) -> bool:
    t = str(title or "").strip().lower()
    return any(t.startswith(c) for c in _CHALLENGE_TITLES)


def _live(h: dict | None) -> bool:
    return bool(h) and h.get("status_code") is not None


def diff_surface(before: dict[str, dict], probed: dict[str, dict], passive_names: set[str],
                 probe_targets: set[str], wildcard: set[str] | None = None) -> list[dict]:
    """Mudanças entre o inventário (`before`) e esta vigilância.

    `probed`: hosts que responderam agora; `probe_targets`: o que foi sondado (um host do
    inventário que estava vivo, foi sondado e não respondeu vira "not_responding");
    `wildcard`: hosts que responderam igual ao curinga — sem informação, não contam como mortos.
    IP não é comparado: balanceador de nuvem e CDN trocam de IP o tempo todo.
    """
    changes: list[dict] = []
    for host in sorted((set(probed) | set(passive_names)) - set(before)):
        cur = probed.get(host)
        changes.append({"kind": "new_host_live" if cur else "new_host", "host": host,
                        "status_code": (cur or {}).get("status_code"), "title": (cur or {}).get("title", "")})
    for host in sorted(set(probed) & set(before)):
        old, cur = before[host], probed[host]
        if not _live(old):
            changes.append({"kind": "came_alive", "host": host,
                            "status_code": cur.get("status_code"), "title": cur.get("title", "")})
            continue
        diffs = {}
        if _challenge(old.get("title")) or _challenge(cur.get("title")):
            continue   # desafio anti-bot de um lado: status/título não dizem nada
        for field in ("status_code", "title"):
            if str(old.get(field) or "") != str(cur.get(field) or ""):
                diffs[field] = {"old": old.get(field), "new": cur.get(field)}
        added = sorted(set(cur.get("technologies") or []) - set(old.get("technologies") or []))
        if added:
            diffs["technologies"] = {"added": added}
        if diffs:
            changes.append({"kind": "changed", "host": host, "changes": diffs})
    for host in sorted((probe_targets & set(before)) - (wildcard or set())):
        if _live(before[host]) and host not in probed:
            changes.append({"kind": "not_responding", "host": host})
    return changes


def _apply(db, cid: str, probed: dict[str, dict], changes: list[dict], now: str) -> list[dict]:
    """Grava o estado atual no inventário. Devolve as mudanças confirmadas (not_responding só
    vira went_dead na MISSES_TO_DEAD-ésima vez seguida)."""
    data = db.load_asm_data()
    co = next((c for c in data.get("companies", []) if c.get("id") == cid), None)
    if co is None:
        return []
    hosts = {h["host"]: h for h in co.get("hosts", []) if isinstance(h, dict) and h.get("host")}
    confirmed = []
    for ch in changes:
        host = ch["host"]
        h = hosts.get(host)
        if ch["kind"] in ("new_host", "new_host_live"):
            h = {"host": host, "status_code": None, "title": "", "ip": "", "technologies": [], "ports": [],
                 "waf": "", "cdn": False, "scope_distance": 0, "source": "watch", "discovered_at": now}
            co.setdefault("hosts", []).append(h)
            hosts[host] = h
        if ch["kind"] == "not_responding":
            h["watch_misses"] = int(h.get("watch_misses") or 0) + 1
            if h["watch_misses"] < MISSES_TO_DEAD:
                continue
            h["status_code"] = None
            confirmed.append({**ch, "kind": "went_dead"})
            continue
        confirmed.append(ch)
    for host, cur in probed.items():
        h = hosts.get(host)
        if h is None:
            continue
        for field in ("status_code", "title", "ip", "server", "waf", "cdn", "content_length", "redirect_url"):
            if cur.get(field) not in (None, ""):
                h[field] = cur[field]
        h["technologies"] = sorted(set(h.get("technologies") or []) | set(cur.get("technologies") or []))
        h["ports"] = sorted(set(map(str, h.get("ports") or [])) | set(map(str, cur.get("ports") or [])))
        h["watch_misses"] = 0
        h["last_seen"] = now
    co["watched_at"] = now
    db.save_asm_data(data)
    return confirmed


def _describe(ch: dict) -> tuple[str, str]:
    host, kind = ch["host"], ch["kind"]
    if kind == "new_host_live":
        return f"Novo host respondendo: {host}", f"HTTP {ch.get('status_code')} — {ch.get('title') or 'sem título'}"
    if kind == "new_host":
        return f"Novo subdomínio: {host}", "Visto em fonte passiva; não respondeu em 80/443."
    if kind == "came_alive":
        return f"Host voltou a responder: {host}", f"HTTP {ch.get('status_code')} — {ch.get('title') or 'sem título'}"
    if kind == "went_dead":
        return f"Host parou de responder: {host}", f"Sem resposta em {MISSES_TO_DEAD} vigilâncias seguidas."
    parts = []
    for field, d in ch.get("changes", {}).items():
        if field == "technologies":
            parts.append("tecnologia nova: " + ", ".join(d["added"]))
        else:
            parts.append(f"{field}: {d['old']} → {d['new']}")
    return f"Mudança em {host}", "; ".join(parts)


def run_watch(runner, cid: str, co: dict, options: dict | None = None) -> dict:
    """Uma vigilância completa. `runner` é o ReconRunner (reaproveita subfinder, httpx e escopo)."""
    options = options or {}
    started = datetime.now()
    now = started.isoformat(timespec="seconds")
    domains = runner._active_scan_domains(co.get("domains") or []) or list(co.get("domains") or [])

    # 1) passivo
    passive: set[str] = set()

    def _sub(d):
        out = runner._run_tool("subfinder", d, cid=cid, module="watch")
        return {str(f.get("value") or f.get("host") or "").lower() for f in out.get("findings", []) if f.get("type") == "subdomain"}

    with ThreadPoolExecutor(max_workers=max(1, min(8, len(domains)))) as ex:
        for names in ex.map(_sub, domains[:20]):
            passive |= names
    passive = {n for n in passive if n and runner._host_in_scope(n, domains)}

    # 2) sondagem leve: nomes passivos + inventário, só 80/443, com o filtro de curinga
    before = {h["host"]: h for h in runner._load_hosts(cid) if isinstance(h, dict) and h.get("host")}
    targets = set(passive) | set(before)
    wildcard: set[str] = set()
    live = runner._probe_hosts_with_httpx(sorted(targets), cid, _expand_redirects=False, extra_ports=False,
                                          wildcard_out=wildcard)
    probed = {h["host"]: h for h in live if h.get("host") in targets}

    # 3) diff, gravação e avisos
    changes = _apply(runner.db, cid, probed, diff_surface(before, probed, passive, targets, wildcard), now)
    # domínio sem nenhum host no inventário (recém-adicionado ao escopo): é linha de base, não
    # mudança — grava tudo, mas um alerta só em vez de um por host
    baseline = [d for d in domains if not any(h == d or h.endswith("." + d) for h in before)]

    def _in(host, ds):
        return any(host == d or host.endswith("." + d) for d in ds)

    alertable = [ch for ch in changes if not _in(ch["host"], baseline)]
    by_kind: dict[str, list[str]] = {}
    for ch in changes:
        by_kind.setdefault(ch["kind"], []).append(ch["host"])
        if ch["kind"] in ("new_host", "new_host_live"):
            try:
                runner.db.insert_subdomain_history(cid, ch["host"], "new", now, now,
                                                   1 if ch["kind"] == "new_host_live" else 0, source="watch")
            except Exception:
                log.debug("watch: histórico falhou", exc_info=True)

    for d in baseline:
        hosts_d = [ch for ch in changes if _in(ch["host"], [d])]
        if hosts_d:
            live_d = sum(1 for ch in hosts_d if ch["kind"] == "new_host_live")
            runner.db.create_alert(cid, "surface_baseline", f"Linha de base de {d}: {len(hosts_d)} hosts",
                                   f"Primeira vigilância do domínio: {live_d} respondendo. Próximas vigilâncias "
                                   "avisam só o que mudar.", "info", {"domain": d, "hosts": len(hosts_d), "live": live_d})
    for ch in alertable[:MAX_ALERTS]:
        title, desc = _describe(ch)
        runner.db.create_alert(cid, f"surface_{ch['kind']}", title, desc, _severity(ch), ch)
    if len(alertable) > MAX_ALERTS:
        counts = {}
        for ch in alertable:
            counts[ch["kind"]] = counts.get(ch["kind"], 0) + 1
        runner.db.create_alert(cid, "surface_summary", f"{len(alertable)} mudanças na superfície",
                               ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())), "medium", {"counts": counts})
    if alertable:
        try:
            from utils.notifications import notify
            hosts_by_kind: dict[str, list[str]] = {}
            for ch in alertable:
                hosts_by_kind.setdefault(ch["kind"], []).append(ch["host"])
            notify(runner.db, runner.get_settings, runner.base, "surface_change",
                   {"company_name": co.get("name", cid), "company_id": cid, **dict(sorted(hosts_by_kind.items()))})
        except Exception:
            log.debug("watch: notificação falhou", exc_info=True)

    # linha de base não dispara scan ativo: o domínio inteiro é "novo"
    active_targets = sorted({ch["host"] for ch in alertable if ch["kind"] in ("new_host_live", "came_alive")})
    summary = {
        "company_id": cid, "started_at": now, "finished_at": datetime.now().isoformat(timespec="seconds"),
        "duration_s": round((datetime.now() - started).total_seconds(), 1),
        "passive_names": len(passive), "probed": len(targets), "live": len(probed),
        "counts": {k: len(v) for k, v in by_kind.items()}, "changes": changes[:200], "baseline_domains": baseline,
        "active_targets": active_targets,
    }
    try:
        path = Path(runner.base) / "scans" / cid / "watch_last.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    except Exception:
        log.debug("watch: resumo não gravado", exc_info=True)
    log.info("[watch] %s: %s nomes passivos, %s vivos, mudanças %s em %.0fs",
             cid, len(passive), len(probed), summary["counts"] or "nenhuma", summary["duration_s"])
    return summary
