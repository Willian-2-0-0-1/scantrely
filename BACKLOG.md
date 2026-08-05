# Backlog — Scantrely ASM Platform

> Última atualização: 2026-06-16  
> Legenda de prioridade: 🔴 Alta · 🟡 Média · 🟢 Baixa

---

## 🐛 Bugs Confirmados

| # | Prioridade | Arquivo | Descrição |
|---|-----------|---------|-----------|
| B1 | 🔴 | `core/pipeline.py:2918–3053` | **DEBUG prints em produção** — 26 chamadas `print()` no pipeline, incluindo 6 marcadas com `[DEBUG]`. Em produção vazam para stdout do servidor. Trocar por `logging.getLogger()` com nível `DEBUG`. |
| B2 | 🔴 | `static/js/dashboard.js:10553` | **Alert rules criadas via `prompt()` nativo** — `addAlertRule()` usa `prompt()` do browser (bloqueado em alguns contextos, sem validação, UX ruim). Substituir por modal próprio. |
| B3 | 🔴 | `static/js/dashboard.js:2764` | **`hostsPageNav` não filtra por `technologies`** — `applyHostFilter` filtra por tecnologia mas a paginação (`hostsPageNav`) ignora esse campo. Ao mudar de página, hosts que não deveriam aparecer surgem. Adicionar `(h.technologies\|\|[]).join(",").toLowerCase().includes(q)` à paginação. |
| B4 | 🟡 | `static/js/dashboard.js:1697` | **Global search — findings não navegam para a vuln** — Resultados do tipo `Findings` levam para `group: 'operation'` (aba Operation), não para a aba de vulnerabilidades filtrada pelo título. Mudar `action` para `group: 'vulns'` com filtro pré-aplicado. |
| B5 | 🟡 | `static/js/dashboard.js:8263` | **SMTP/Jira/Linear sem UI de configuração** — Backend em `utils/alerting.py` suporta Jira (`jira_url`, `jira_token`, `jira_project`, `jira_user`), Linear (`linear_token`, `linear_team_id`) e SMTP (`smtp_host`, `smtp_port`, `smtp_user`, `smtp_pass`). Nenhum desses campos está no `SETTINGS_SCHEMA` — impossível configurar via UI. |
| B6 | 🟡 | `static/js/dashboard.js:8274` | **`WEBHOOK_EVENTS` limitado** — Só dois eventos configuráveis (`scan_complete`, `critical_finding`). Backend suporta mais (`new_host`, `new_port`, `cert_expiring`, `supply_chain_critical`, etc.) mas não há forma de selecioná-los ao criar um webhook. |
| B7 | 🟢 | `core/pipeline.py:279` | **Fase 4 (cleanup) sem módulos** — `PIPELINE_PHASES[3]` tem `modules: []` e `internal: true` mas nenhum código interno é associado à fase. A limpeza de dados acontece no código de transição de fase, o que é implícito e difícil de debugar. Documentar ou converter em fase interna explícita. |

---

## ✨ Melhorias

| # | Prioridade | Área | Descrição |
|---|-----------|------|-----------|
| M1 | 🔴 | `core/pipeline.py` | **Logging estruturado** — Substituir todos os `print()` por `logging.getLogger("pipeline")` com níveis corretos. Permite configurar verbosidade por variável de ambiente e redirecionar para arquivo sem poluir stdout. |
| M2 | 🔴 | `static/js/dashboard.js` | **Modal para Alert Rules** — Criar modal HTML para configurar nome, tipo (`new_host`, `cve_critical`, etc.), canais, threshold de severidade e empresa-alvo. Atualmente só `prompt()` nativo. |
| M3 | 🔴 | `static/js/dashboard.js` | **Adicionar SMTP / Jira / Linear ao SETTINGS_SCHEMA** — Criar grupos `Notificações por E-mail (SMTP)` e `Integração de Tickets (Jira / Linear)` no schema de configurações para que o usuário possa configurá-los pela UI. |
| M4 | 🟡 | `static/js/dashboard.js` | **Paginação na aba de Findings** — Com muitas vulnerabilidades (>100), a aba renderiza tudo de uma vez e fica lenta. Adicionar paginação de 25 por página similar ao que já existe em Hosts e Portas. |
| M5 | 🟡 | `static/js/dashboard.js` | **Relatório HTML mais completo** — `_buildReportHTML()` não inclui seções de Hosts, Portas, Supply Chain e Infra. Adicionar essas seções ao relatório exportável. |
| M6 | 🟡 | `core/pipeline.py` | **Progress por módulo no HUD** — O Pipeline HUD mostra o progresso por fase mas não por módulo dentro da fase. Emitir eventos SSE com `{phase, module, status}` para mostrar granularidade por módulo. |
| M7 | 🟡 | `routes/recon.py` | **Cancelamento de módulo individual** — Hoje só é possível cancelar o pipeline inteiro. Adicionar endpoint `DELETE /api/recon/<cid>/pipeline/<module>` para cancelar um módulo específico. |
| M8 | 🟡 | `static/js/dashboard.js` | **WEBHOOK_EVENTS expansível** — Incluir todos os tipos de evento suportados pelo backend na UI de criação de webhooks (`new_host`, `new_port`, `new_tech`, `status_change`, `cert_expiring`, etc.). |
| M9 | 🟢 | `static/js/dashboard.js` | **Global search navega para finding específico** — Ao clicar num resultado de `Findings` na busca global, aplicar filtro de título/severidade na aba de vulnerabilidades em vez de abrir a aba Operation genérica. |
| M10 | 🟢 | `static/js/dashboard.js` | **Toast notifications** — Substituir `alert()` (usado em ~12 lugares) por toasts não-bloqueantes no canto da tela. Evita interrupção de fluxo, especialmente em scans automáticos. |
| M11 | 🟢 | `core/pipeline.py` | **Retry automático para módulos que falham por rate limit** — Módulos que retornam `429` ou `rate limit` já detectam o bloqueio, mas apenas com Mullvad ativo fazem retry. Adicionar backoff com retry mesmo sem rotação de IP. |
| M12 | 🟢 | `utils/alerting.py` | **Severidade mínima configurável por regra de alerta** — Alert rules hoje disparam para qualquer severity. Permitir configurar threshold (`critical_only`, `high_and_above`, `medium_and_above`) por regra. |

---

## 🚀 Funcionalidades Futuras

| # | Prioridade | Área | Descrição |
|---|-----------|------|-----------|
| F1 | 🔴 | Auth | **2FA / TOTP** — O sistema tem JWT mas não tem segundo fator. Adicionar TOTP (Google Authenticator / Authy) para contas admin. Biblioteca: `pyotp`. |
| F2 | 🔴 | Dashboard | **Comparação histórica de scans (timeline diff)** — Mostrar gráfico de evolução: novos hosts, hosts removidos, novas vulnerabilidades, vulnerabilidades corrigidas por data. A infra de diff já existe (`renderDiffTab`), falta a visualização temporal agregada. |
| F3 | 🔴 | Pipeline | **Upload de templates Nuclei customizados** — Permitir que o usuário faça upload de templates `.yaml` próprios (armazenados em `data/custom-templates/<cid>/`). O pipeline os inclui automaticamente via `-t` na fase 11. |
| F4 | 🟡 | Export | **Exportar findings como SARIF** — SARIF (Static Analysis Results Interchange Format) é padrão do GitHub Security. Permite integrar findings diretamente no Code Scanning do repositório alvo. |
| F5 | 🟡 | Export | **Relatório PDF server-side** — O PDF atual é gerado via `window.print()` (client-side), dependente de pop-ups do browser. Gerar PDF server-side com `weasyprint` ou `playwright PDF` para melhor controle de layout e possibilidade de envio por e-mail. |
| F6 | 🟡 | Integração | **Exportar para DefectDojo** — DefectDojo é o padrão open-source de gestão de vulnerabilidades. Adicionar endpoint de push direto para a API do DefectDojo ao final de cada scan. |
| F7 | 🟡 | Dashboard | **Métricas históricas (gráficos)** — KPIs visuais: quantidade de hosts ao longo do tempo, findings por severidade por semana, novos subdomínios por scan. Usar Chart.js (já presente no projeto) ou lightweight canvas. |
| F8 | 🟡 | Dashboard | **Tema claro** — Todo o CSS usa variáveis `--bg`, `--text1`, etc., que já estão preparadas para theming. Implementar um segundo conjunto de variáveis para tema claro e um toggle na barra superior. |
| F9 | 🟡 | Notificações | **Notificações push no browser (Web Push API)** — Quando um scan critico terminar ou um finding de alta severidade for gerado, enviar push notification mesmo com a aba do browser fechada. |
| F10 | 🟡 | Pipeline | **Scan incremental (delta scan)** — Em vez de re-escanear tudo, executar apenas módulos de discovery + validação e comparar com o último snapshot. Útil para runs agendados diários que não precisam refazer fingerprint completo. |
| F11 | 🟢 | Auth | **Convidar usuários com escopo por empresa** — O RBAC já suporta `company_ids` no JWT. Adicionar UI para criar usuários com acesso restrito a empresas específicas (útil para time de segurança dividido por cliente). |
| F12 | 🟢 | Integrações | **Comando Slack/Discord para trigger de scan** — Bot que responde a `/scan <domínio>` no Slack ou Discord, inicia o pipeline e envia atualizações de progresso no canal. |
| F13 | 🟢 | API | **Documentação OpenAPI (Swagger)** — Gerar spec OpenAPI dos endpoints Flask automaticamente via `flask-openapi3` ou similar. Facilita integração com ferramentas externas e automações. |
| F14 | 🟢 | Pipeline | **Módulo de recon de aplicações mobile** — Buscar por apps iOS/Android vinculados ao domínio (App Store / Google Play search, links em JS, `assetlinks.json`, `apple-app-site-association`). |
| F15 | 🟢 | Dashboard | **Visualização de grafo de ativos** — Visualização em grafo (D3.js ou Vis.js) conectando domínios, IPs, ASNs e tecnologias. Ajuda a identificar clusters e dependências ocultas na superfície de ataque. |

---

## 🔧 Dívida Técnica

| # | Arquivo | Descrição |
|---|---------|-----------|
| T1 | `core/pipeline.py` | `_make_fn_map` e `PIPELINE_PHASES` precisam ser a única fonte de verdade. Atualmente um módulo pode estar no map mas não em nenhuma fase (código morto). Adicionar validação no startup que avisa módulos não atribuídos. |
| T2 | `static/js/dashboard.js` | Arquivo com 10.965 linhas. Dividir em módulos ES (`dashboard-core.js`, `dashboard-pipeline.js`, `dashboard-vulns.js`, etc.) com bundler (Vite ou esbuild) para melhorar manutenibilidade. |
| T3 | `routes/` | Quatro arquivos legados na raiz (`recon_routes.py`, `scan_routes.py`, `ops_routes.py`, `asset_routes.py`) coexistem com os novos em `routes/`. Remover os legados ou garantir que não estejam sendo importados. |
| T4 | `core/pipeline.py` | `except Exception: pass` em 146 locais. Logging mínimo (`logger.warning(...)`) nos blocos de exceção críticos para não suprimir erros silenciosamente. |
| T5 | `asm_data.json` | Arquivo JSON de dados na raiz do projeto (não rastreado pelo git). Mover definitivamente para `data/` e garantir que o `.gitignore` cubra ambos os caminhos. |

---

## ✅ Resolvidos Recentemente

| Commit | O que foi corrigido |
|--------|---------------------|
| `f169433` | Null guards em hosts/portas; mapeamento censys_api_id→censys_id; scan_mode para pipeline; censys_api_secret e wpscan_token no SETTINGS_SCHEMA |
| `7f2c3a7` | Filtros de vuln "low"; timing bug em goToVulnSeverity (pendingVulnFilter) |
| `b2f0501` | Módulos asn/asnmap/email/theharvester/hunterio sem fase atribuída; live_hosts contava todos os hosts |
| `7259b27` | httpx fallback — timeout e workers insuficientes |
| `d7cc384` | Botão cancelar todos os scans |
| `9aa14de` | Botão escanear todos os targets de todas as empresas |
| `6d67680` | Escopos sumindo ao salvar empresa (optimistic update) |
| `02c4554` | Remoção do Bugcrowd; credenciais HackerOne nas configurações |
