"""Prioridades: transforma centenas de achados em uma lista curta de ações.

Cada ação diz o quê, onde, por que importa e como corrigir. Pura e sem I/O.
"""
from __future__ import annotations

import math
from collections import defaultdict

SEV_WEIGHT = {"critical": 100, "high": 60, "medium": 30, "low": 10, "info": 0}
SEV_LABEL = {"critical": "Crítico", "high": "Alto", "medium": "Médio", "low": "Baixo", "info": "Info"}

# tipo do achado → (ação, por que importa, como corrigir, aba de detalhe)
_PLAYBOOK: dict[str, tuple[str, str, str, str]] = {
    "git_exposed": ("Fechar repositório .git exposto",
                    "Qualquer pessoa baixa o código-fonte e o histórico, que costuma conter senhas e chaves.",
                    "Remover a pasta .git do servidor web (ou bloquear /.git) e rotacionar qualquer credencial que já esteve no repositório.",
                    "vulns"),
    "secret": ("Revogar segredos expostos",
               "Chaves e tokens públicos em JS/respostas podem ser usados por qualquer um.",
               "Revogar e gerar novas chaves; guardar no servidor, nunca no front-end; restringir a chave por domínio/IP.",
               "jsreverse"),
    "default_creds": ("Trocar credenciais padrão", "Login com usuário/senha de fábrica dá acesso direto ao serviço.",
                      "Trocar a senha, desativar a conta padrão e restringir o acesso por rede.", "vulns"),
    "infra_exposure": ("Fechar serviços de infraestrutura expostos", "Banco, painel ou serviço interno acessível pela internet.",
                       "Limitar por firewall/VPN ao que realmente precisa ser público.", "infra"),
    "zone_transfer": ("Bloquear transferência de zona DNS (AXFR)", "Entrega a lista completa de subdomínios internos.",
                      "Permitir AXFR só para os servidores secundários autorizados.", "vulns"),
    "cve": ("Atualizar software com CVE conhecida", "Vulnerabilidade pública, muitas vezes com exploit disponível.",
            "Aplicar o patch/versão corrigida indicada no achado; priorizar as marcadas como KEV.", "cve"),
    "cors": ("Corrigir CORS permissivo", "Outro site consegue ler respostas autenticadas da API em nome do usuário.",
             "Trocar a reflexão de origem por uma lista fixa de origens confiáveis; nunca combinar '*' com credenciais.", "vulns"),
    "waf_bypass": ("Esconder o IP de origem atrás do WAF", "O WAF pode ser contornado acessando o servidor direto.",
                   "Aceitar tráfego apenas dos IPs do WAF/CDN no firewall de origem.", "vulns"),
    "dangling_name": ("Remover registro DNS apontando para nada", "Risco de takeover: alguém registra o destino e passa a servir conteúdo no seu domínio.",
                      "Apagar o CNAME/A órfão ou recriar o recurso de destino.", "vulns"),
    "takeover": ("Corrigir possível subdomain takeover", "Subdomínio aponta para serviço de terceiros não reivindicado.",
                 "Reivindicar o recurso ou remover o registro DNS.", "vulns"),
    "open_redirect": ("Validar destinos de redirecionamento", "Usado em phishing com o domínio legítimo da empresa na URL.",
                      "Aceitar apenas caminhos relativos ou uma lista fixa de destinos.", "vulns"),
    "email_security": ("Configurar SPF/DKIM/DMARC", "Sem isso qualquer um envia e-mail se passando pelo domínio.",
                       "Publicar DMARC com p=quarantine/reject e alinhar SPF e DKIM.", "vulns"),
    "dnssec": ("Ativar DNSSEC", "Sem DNSSEC respostas DNS podem ser forjadas.", "Habilitar no registrador e publicar o DS.", "vulns"),
    "staging_host": ("Tirar ambiente de staging/dev da internet", "Costuma ter menos proteção e dados reais.",
                     "Restringir por VPN/IP ou autenticação.", "vulns"),
    "staging_in_csp": ("Remover staging da CSP", "Revela ambientes internos e permite carregar código deles.", "Limpar a CSP em produção.", "vulns"),
    "tls_alias_mismatch": ("Corrigir certificado que não cobre o nome", "Gera aviso no navegador e indica host mal configurado.",
                           "Emitir certificado que cubra o nome ou desativar o alias.", "vulns"),
    "cdn_s3_origin": ("Proteger bucket S3 de origem do CDN", "Bucket acessível direto contorna as regras do CDN.",
                      "Usar OAC/OAI e bloquear acesso público.", "vulns"),
    "supply_chain_origin": ("Revisar dependências expostas", "Pacote interno publicado/confundível pode ser sequestrado.",
                            "Reservar o nome no registro público e fixar fontes.", "supplychain"),
    "vendor_fingerprint": ("Atualizar/fechar appliance exposto", "Equipamento de fornecedor com painel acessível.",
                           "Restringir o painel e aplicar o último firmware.", "vulns"),
    "header": ("Ativar headers de segurança", "Reduz impacto de XSS, clickjacking e downgrade para HTTP.",
               "Configurar CSP, HSTS, X-Frame-Options e X-Content-Type-Options no servidor/CDN uma vez, para todos os hosts.", "vulns"),
    "brand_domain_exposure": ("Monitorar domínios parecidos com a marca", "Podem hospedar phishing contra clientes.",
                              "Registrar os mais perigosos, pedir takedown dos ativos com e-mail ou certificado da marca.", "typosquat"),
    "vhost": ("Revisar virtual hosts diferentes do padrão", "Respostas distintas podem ser ambientes não publicados.",
              "Confirmar se cada um deve estar acessível.", "vulns"),
}
_MAX_ACTIONS = 10
SEV_WEIGHT_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _hosts_of(f: dict) -> list[str]:
    hs = list(f.get("affected_hosts") or [])
    if f.get("host") and not hs:
        hs = [f["host"]]
    return hs


def build_priorities(co: dict, limit: int = _MAX_ACTIONS) -> dict:
    """Retorna {actions:[...], hidden:N, total:N}. Ordem: severidade, KEV, nº de hosts."""
    findings = [f for f in (co.get("findings") or []) if f.get("severity") in ("critical", "high", "medium", "low")]
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        ftype = f.get("type") or "other"
        # correlações derivadas ("sem WAF + crítico") repetem outro achado: não são ação própria
        if ftype == "attack_chain":
            continue
        groups[ftype].append(f)

    actions = []
    for ftype, items in groups.items():
        sev = min((f["severity"] for f in items), key=lambda v: SEV_WEIGHT_RANK[v])
        hosts = sorted({h for f in items for h in _hosts_of(f)})
        play = _PLAYBOOK.get(ftype)
        title, why, fix, tab = play or (items[0].get("title", ftype), items[0].get("desc", ""), "Ver detalhes no achado.", "vulns")
        kev = any(f.get("kev") for f in items)
        score = SEV_WEIGHT[sev] + (30 if kev else 0) + min(15, 5 * math.log2(len(hosts) + 1))
        # ruído conhecido: tipos informativos pesam menos que o resto da mesma severidade
        if ftype in ("brand_domain_exposure", "vhost", "header"):
            score -= 20
        actions.append({
            "type": ftype, "severity": sev, "severity_label": SEV_LABEL[sev], "title": title, "why": why, "fix": fix,
            "tab": tab, "count": len(items), "hosts": hosts[:6], "hosts_more": max(0, len(hosts) - 6),
            "kev": kev, "example": items[0].get("title", ""), "score": round(score, 1),
            "keys": [f.get("key") for f in items][:50],
        })
    actions.sort(key=lambda a: (-a["score"], a["title"]))
    shown = actions[:limit]
    for i, a in enumerate(shown, 1):
        a["rank"] = i
    return {"actions": shown, "hidden": max(0, len(actions) - limit), "total": len(actions),
            "findings_total": len(findings)}
