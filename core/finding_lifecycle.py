"""Ciclo de vida dos achados entre scans: visto → não visto → resolvido.

Antes, todo achado de um scan anterior era carregado para sempre e os geradores pulavam chaves já existentes,
então nada saía da lista mesmo depois de corrigido. Agora, para módulos que rodaram neste scan com resultado:
  • o que o módulo voltou a reportar é regerado (dado fresco, `last_seen` = agora);
  • o que ele NÃO reportou fica `status="not_seen"` e some das contagens/prioridades;
  • após `RESOLVE_AFTER` scans seguidos sem aparecer vira `status="resolved"`.
Módulos que não rodaram (ou falharam) não mudam nada.
"""
from __future__ import annotations

from datetime import datetime

RESOLVE_AFTER = 3
INACTIVE = ("not_seen", "resolved")

# módulo do achado → chave do resultado do pipeline que o gera (só os que leem o resultado deste scan)
AUTHORITATIVE = {
    "headers": "headers", "cors_scan": "cors_scan", "open_redirect": "open_redirect", "default_creds": "default_creds",
    "infra_exposure": "infra_exposure", "host_header_injection": "host_header_injection", "graphql": "graphql",
    "smtp_probe": "smtp_probe", "snmp_probe": "snmp_probe", "zone_transfer": "zone_transfer", "tableau": "tableau",
    "postman_collections": "postman_collections", "dnssec": "dnssec", "email": "email",
}


def is_active(f: dict) -> bool:
    return f.get("status") not in INACTIVE


def split_prior(prior: list[dict], ran) -> tuple[list[dict], dict[str, dict]]:
    """Separa os achados antigos: (carregados como estão, a reavaliar). `ran(chave_do_resultado) -> bool`."""
    carry, reeval = [], {}
    for f in prior:
        key = AUTHORITATIVE.get(f.get("module") or "")
        if key and f.get("key") and ran(key):
            reeval[f["key"]] = f
        else:
            carry.append(f)
    return carry, reeval


def apply_lifecycle(fresh: list[dict], reeval: dict[str, dict], now: str | None = None) -> list[dict]:
    """Carimba os achados regerados e devolve também os não vistos (marcados)."""
    now = now or datetime.now().isoformat(timespec="seconds")
    out = []
    for f in fresh:
        old = reeval.get(f.get("key"))
        f = dict(f)
        f["first_seen"] = (old or {}).get("first_seen") or f.get("first_seen") or now
        f["last_seen"] = now
        f["miss_count"] = 0
        if f.get("status") in INACTIVE:
            f.pop("status")
        out.append(f)
    fresh_keys = {f.get("key") for f in out}
    for key, old in reeval.items():
        if key in fresh_keys:
            continue
        miss = int(old.get("miss_count") or 0) + 1
        g = dict(old)
        g["miss_count"] = miss
        g["status"] = "resolved" if miss >= RESOLVE_AFTER else "not_seen"
        g["last_seen"] = old.get("last_seen") or old.get("first_seen") or now
        out.append(g)
    return out
