"""Higiene dos achados: reduz ruído e corrige dados antes de chegarem à tela.

Funções puras e idempotentes — rodam a cada scan (pipeline) e também sobre
dados já gravados (``python -m core.finding_hygiene``).
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime

from core.verification import looks_like_git

INACTIVE_STATUSES = ("not_seen", "resolved")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Teto de severidade por tipo: evidência fraca (presença, heurística, padrão de URL) não pode ser crítica/alta.
# CORS é decisão explícita do usuário; os demais seguem a regra "sem prova de exploração, no máximo médio".
SEVERITY_CAPS = {
    "cors": "medium",               # nunca crítico (decisão do usuário)
    "header": "medium",             # cabeçalho/cookie ausente
    "vendor_fingerprint": "medium", # só a presença do produto; não prova a versão vulnerável
    "waf_bypass": "medium",         # heurística: tamanho da resposta mudou com X-Forwarded-For
    "staging_in_csp": "low",        # referência a staging na CSP
    "brand_domain_exposure": "high",
}
_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def cap_severity(ftype: str, severity: str) -> str:
    cap = SEVERITY_CAPS.get(ftype)
    if cap and _RANK.get(severity, 4) < _RANK[cap]:
        return cap
    return severity

_VHOST_WILDCARD_MIN = 3          # respostas idênticas em ≥3 vhosts do mesmo IP = padrão do WAF/CDN
_VHOST_ADMIN_WORDS = ("admin", "staging", "dev", "test", "internal", "jenkins", "gitlab")
_MOJIBAKE = re.compile(r"[ÃÂâð][^\x00-\x7f]{1,11}")
_AGG_TITLE = re.compile(r"^(Header ausente|Cookie inseguro) em (.+?): (.+)$")


# ── texto ──────────────────────────────────────────────────────────────────
def _cp1252(ch: str) -> bytes | None:
    try:
        return ch.encode("cp1252")
    except UnicodeEncodeError:
        return ch.encode("latin-1") if ord(ch) < 256 else None


def _unmojibake_run(run: str) -> str:
    for _ in range(3):
        raw = b""
        for ch in run:
            b = _cp1252(ch)
            if b is None:
                return run
            raw += b
        try:
            fixed = raw.decode("utf-8")
        except UnicodeDecodeError:
            return run
        if fixed == run:
            break
        run = fixed
        if not re.search("[ÃÂâ]", run):
            break
    return run


def repair_mojibake(text: str) -> str:
    """Desfaz UTF-8 lido como cp1252 (uma ou duas vezes), ex.: 'Ã¢â‚¬â€' → '—'."""
    if not isinstance(text, str) or not _MOJIBAKE.search(text):
        return text
    return _MOJIBAKE.sub(lambda m: _unmojibake_run(m.group(0)), text)


def repair_deep(obj):
    """repair_mojibake em todas as strings (valores e chaves) de uma estrutura JSON, in-place quando possível."""
    if isinstance(obj, str):
        return repair_mojibake(obj)
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            obj[i] = repair_deep(v)
        return obj
    if isinstance(obj, dict):
        for k in list(obj):
            v = repair_deep(obj[k])
            nk = repair_mojibake(k) if isinstance(k, str) else k
            if nk != k:
                del obj[k]
            obj[nk] = v
        return obj
    return obj


# ── VHost ──────────────────────────────────────────────────────────────────
def vhost_findings(vhost_data: dict) -> list[dict]:
    """Converte a saída crua do módulo vhost em achados, sem falsos positivos.

    Resposta idêntica (status+tamanho) em vários vhosts do mesmo IP é a página
    padrão do WAF/CDN — vira UM achado informativo em vez de dezenas de médios.
    """
    raw = [r for r in (vhost_data or {}).get("findings", []) if isinstance(r, dict) and r.get("vhost")]
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in raw:
        groups[(r.get("ip", ""), r.get("status", r.get("status_code", "")), r.get("length", r.get("size", "")))].append(r)

    out: list[dict] = []
    for (ip, status, length), items in groups.items():
        if len(items) >= _VHOST_WILDCARD_MIN:
            out.append({
                "key": f"vhost-wildcard-{ip}-{status}-{length}",
                "type": "vhost", "severity": "info", "category": "discovery", "module": "vhost",
                "title": f"{len(items)} vhosts respondem igual em {ip} (HTTP {status}, {length} bytes)",
                "desc": "Resposta idêntica para nomes diferentes: é a página padrão do WAF/CDN, "
                        "não indica ambiente real. Sem ação.",
                "host": ip, "value": ip, "metadata": {"ip": ip, "status_code": status, "size": length},
                "affected_hosts": sorted(r["vhost"] for r in items),
            })
            continue
        for r in items:
            name = r["vhost"]
            code = int(status) if str(status).isdigit() else 0
            sev = r.get("severity") if r.get("severity") in SEV_ORDER else "low"
            keyword = any(w in name.lower() for w in _VHOST_ADMIN_WORDS)
            if 200 <= code < 400:
                sev = "high" if keyword else "medium"
            out.append({
                "key": f"vhost-{ip}-{name}",
                "type": "vhost", "severity": sev, "category": "discovery", "module": "vhost",
                "title": f"Virtual Host descoberto: {name} (HTTP {status}) em {ip}",
                "desc": f"VHost `{name}` responde HTTP {status} ({length} bytes) no IP {ip} com resposta "
                        "diferente das demais. Pode ser ambiente não publicado.",
                "host": r.get("host") or name, "value": name,
                "metadata": {"ip": ip, "status_code": status, "size": length},
            })
    return out


# ── pipeline do conjunto ───────────────────────────────────────────────────
def _group_headers(findings: list[dict]) -> list[dict]:
    """Um achado por header/cookie (com a lista de hosts), não um por host."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    rest: list[dict] = []
    for f in findings:
        m = _AGG_TITLE.match(f.get("title", "")) if f.get("type") == "header" else None
        if m:
            groups[(m.group(1), m.group(3))].append(f)
        else:
            rest.append(f)
    for (prefix, what), items in groups.items():
        hosts = sorted({h for f in items for h in ([f["host"]] if f.get("host") and not f.get("affected_hosts") else [])
                        + list(f.get("affected_hosts") or [])})
        if len(hosts) <= 1:
            rest.extend(items)
            continue
        best = min(items, key=lambda f: SEV_ORDER.get(f.get("severity", "info"), 4))
        rest.append({
            **best,
            "key": f"headers-agg-{prefix}-{what}".lower().replace(" ", "-"),
            "title": f"{prefix} em {len(hosts)} hosts: {what}",
            "host": hosts[0], "affected_hosts": hosts,
        })
    return rest


def _false_positive_git(f: dict) -> bool:
    """`.git exposto` sem evidência de git no corpo (HTML de SPA/soft-200 ou só "HTTP 200")."""
    if f.get("type") != "git_exposed":
        return False
    path = f.get("value") or "/.git/config"
    evidence = f.get("desc") or ""
    return not looks_like_git(path, evidence)


def unversioned_cve_severity(severity: str, kev: bool = False) -> str:
    """CVE casada só pelo nome do produto (versão não detectada) é "possível", nunca crítica/alta."""
    if kev:
        return "medium"
    return severity if severity in ("low", "info") else "low"


def cap_unversioned_cves(co_data: dict) -> set[str]:
    """Rebaixa em `cve_findings` as CVEs sem versão detectada e devolve os ids afetados."""
    capped: set[str] = set()
    findings = co_data.get("cve_findings")
    if not isinstance(findings, list):
        return capped
    for c in findings:
        if isinstance(c, dict) and not c.get("detected_version") and c.get("severity") not in ("low", "info"):
            c.setdefault("severity_raw", c.get("severity"))
            c["severity"] = unversioned_cve_severity(c.get("severity"), bool(c.get("kev")))
            c["verified"] = False
            capped.add(c.get("cve_id"))
    summ = co_data.get("cve_summary")
    if isinstance(summ, dict) and capped:
        for k in ("critical", "high", "medium", "low"):
            summ[k] = sum(1 for c in findings if isinstance(c, dict) and c.get("severity") == k)
    return capped


def dismiss_false_positives(findings: list[dict], co_data: dict) -> list[dict]:
    """Tira da lista achados que não resistem à verificação e guarda o motivo em `auto_dismissed`."""
    keep, dismissed = [], co_data.setdefault("auto_dismissed", [])
    known = {d.get("key") for d in dismissed}
    for f in findings:
        if _false_positive_git(f):
            if f.get("key") not in known:
                dismissed.append({"key": f.get("key"), "title": f.get("title"), "host": f.get("host"), "type": f.get("type"),
                                  "reason": "Resposta HTML (SPA/soft-200), não é um repositório .git",
                                  "evidence": str(f.get("desc") or "")[:120], "dismissed_at": datetime.now().isoformat(timespec="seconds")})
            continue
        keep.append(f)
    leaks = co_data.get("leaks_data")
    if isinstance(leaks, dict) and isinstance(leaks.get("git_exposed"), list):
        leaks["git_exposed"] = [g for g in leaks["git_exposed"]
                                if isinstance(g, dict) and looks_like_git(g.get("path") or "/.git/config", g.get("snippet") or "")]
    return keep


def tidy_findings(findings: list[dict], co_data: dict) -> list[dict]:
    """Aplica todas as regras de higiene. Idempotente."""
    out: list[dict] = []
    unversioned = cap_unversioned_cves(co_data)
    for f in dismiss_false_positives(findings, co_data):
        f = dict(f)
        if f.get("type") == "cve" and f.get("value") in unversioned:
            f["severity"] = unversioned_cve_severity(f.get("severity"), bool(f.get("kev")))
            f["verified"] = False
        for k in ("title", "desc"):
            if k in f:
                f[k] = repair_mojibake(f[k])
        f["severity"] = cap_severity(f.get("type"), f.get("severity"))
        out.append(f)

    vd = co_data.get("vhost_data")
    if vd is not None:
        out = [f for f in out if f.get("type") != "vhost"] + vhost_findings(vd)

    return _group_headers(out)


def derive_attack_chains(findings: list[dict], co_data: dict) -> list[dict]:
    """Correlações por host do inventário (só achados ativos). Derivadas: recalculadas a cada scan."""
    inventory = chain_candidate_hosts(co_data)
    by_host: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        h = f.get("host", "")
        if h and h in inventory and f.get("type") not in ("brand_domain_exposure", "attack_chain") \
                and f.get("status") not in INACTIVE_STATUSES:
            by_host[h].append(f)
    hosts = {h.get("host"): h for h in co_data.get("hosts", [])}
    out: list[dict] = []

    def chain(key, title, severity, desc, host):
        out.append({"key": key, "type": "attack_chain", "title": title, "severity": severity, "category": "correlation",
                    "desc": desc, "host": host, "module": "correlation"})

    for host, hf in by_host.items():
        sevs = {f.get("severity") for f in hf}
        has_secret = any(f.get("type") == "secret" for f in hf)
        has_dangerous_port = any(f.get("type") in ("default_creds", "infra_exposure") for f in hf)
        if has_secret and has_dangerous_port and "critical" not in sevs:
            types = [(f.get("metadata") or {}).get("type", "?") for f in hf if f.get("type") == "secret"]
            chain(f"chain-secret-port-{host}", f"Attack Chain: Secret + Exposed Service em {host}", "critical",
                  f"Host {host} tem simultaneamente: segredos expostos ({', '.join(set(types))}) e serviços sem autenticação. "
                  "Combinação permite acesso direto ao ambiente.", host)
        waf = (hosts.get(host) or {}).get("waf")
        if (not waf or waf == "Direct") and "critical" in sevs:
            chain(f"chain-nowaf-critical-{host}", f"Sem WAF + Finding Crítico: {host}", "critical",
                  f"Host {host} expõe finding crítico diretamente à internet (sem WAF). Exploração direta sem obstáculos.", host)
        critical_high = [f for f in hf if f.get("severity") in ("critical", "high")]
        if len(critical_high) >= 3:
            titles = [f.get("title", "")[:50] for f in critical_high[:3]]
            chain(f"chain-concentrated-{host}", f"Superfície concentrada: {len(critical_high)} findings críticos/altos em {host}", "high",
                  f"Host {host} concentra {len(critical_high)} findings de alta severidade: {'; '.join(titles)}", host)
    return out


def chain_candidate_hosts(co_data: dict) -> set[str]:
    """Hosts do inventário — só nesses faz sentido correlacionar 'sem WAF'."""
    return {h.get("host") for h in co_data.get("hosts", []) if h.get("host")}


def count_by_severity(findings: list[dict]) -> dict[str, int]:
    return {f"findings_{s}": sum(1 for f in findings if f.get("severity") == s and f.get("status") not in ("not_seen", "resolved"))
            for s in ("critical", "high", "medium", "low", "info")}


# ── dados já gravados ──────────────────────────────────────────────────────
def tidy_stored(data: dict) -> dict:
    """Reaplica a higiene a todas as empresas de um asm_data. Retorna antes/depois."""
    report = {}
    repair_deep(data)   # acentuação corrompida em qualquer campo gravado (observações do browser recon etc.)
    for co in data.get("companies", []):
        before = list(co.get("findings") or [])
        if not before:
            continue
        # cadeias antigas ficam; as inválidas (host fora do inventário / typosquat) saem
        keep = [f for f in before if f.get("type") != "attack_chain"]
        after = tidy_findings(keep, co)
        after += derive_attack_chains(after, co)    # cadeias são derivadas: recalculadas sobre os achados já corrigidos
        co["findings"] = after
        co.setdefault("stats", {}).update(count_by_severity(after))
        report[co.get("id")] = (len(before), len(after))
    return report


if __name__ == "__main__":  # python -m core.finding_hygiene
    from pathlib import Path

    from core.database import ASMDatabase

    base = Path(__file__).resolve().parent.parent
    db = ASMDatabase(base / "data" / "asm.db", asm_data_file=base / "data" / "asm_data.js")
    data = db.load_asm_data()
    rep = tidy_stored(data)
    db.save_asm_data(data)
    for cid, (a, b) in rep.items():
        print(f"{cid}: {a} → {b} achados")
