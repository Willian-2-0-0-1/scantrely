# Backlog — Scantrely ASM Platform

> Última atualização: 2026-10-07 (1.2.0)  
> Legenda de prioridade: 🔴 Alta · 🟡 Média · 🟢 Baixa

---

## 🐛 Bugs Confirmados

Nenhum bug confirmado aberto nesta lista. B1–B7 foram corrigidos em 2026-10-07 (ver Resolvidos).

---

## ✨ Melhorias

| # | Prioridade | Área | Descrição |
|---|-----------|------|-----------|
| M1 | ✅ | `core/pipeline.py` | **Logging estruturado** — Feito: `logging.getLogger("scantrely.pipeline")` + `ASM_LOG_LEVEL`. |
| M2 | ✅ | `static/js/dashboard.js` | **Modal para Alert Rules** — Feito: modal HTML (nome, tipo, canais). |
| M3 | ✅ | `static/js/dashboard.js` | **SMTP / Jira / Linear no SETTINGS_SCHEMA** — Feito, com persistência em `_SETTINGS_KEYS`. |
| M4 | ✅ | `static/js/dashboard.js` | **Paginação na aba de Findings** — Feito: 25 grupos por página, pager igual ao de Hosts. |
| M5 | ✅ | `static/js/dashboard.js` | **Relatório HTML mais completo** — Feito: hosts, portas, cloud storage e supply chain. |
| M6 | ✅ | `core/pipeline.py` | **Progress por módulo no HUD** — Feito: `_emit_module` + `module_events` no GET/SSE e chips por módulo na fase ativa. |
| M7 | ✅ | `routes/recon.py` | **Cancelamento de módulo individual** — Feito: `DELETE /api/recon/<cid>/pipeline/<module>` + `skip_modules`. |
| M8 | ✅ | `static/js/dashboard.js` | **WEBHOOK_EVENTS expansível** — Feito: eventos alinhados ao backend. |
| M9 | ✅ | `static/js/dashboard.js` | **Global search navega para finding específico** — Feito: `group: 'vulns'` com filtro de título/severidade. |
| M10 | ✅ | `static/js/dashboard.js` | **Toast notifications** — Feito: `alert()` → `showToast()`. `confirm()` permanece. |
| M11 | ✅ | `core/pipeline.py` | **Retry automático para rate limit** — Feito: `_backoff_retry` mesmo sem Mullvad. |
| M12 | ✅ | `utils/alerting.py` | **Severidade mínima por regra** — Feito: coluna `min_severity` + filtro em `_fire`. |

---

## 🚀 Funcionalidades Futuras

| # | Prioridade | Área | Descrição |
|---|-----------|------|-----------|
| F1 | ✅ | Auth | **2FA / TOTP** — Feito: `pyotp`, `/api/auth/2fa/setup|enable|disable`, campo no login. |
| F2 | ✅ | Dashboard | **Comparação histórica** — Feito: `renderDiffTab` inclui evolução via `/api/stats-history`. |
| F3 | ✅ | Pipeline | **Templates Nuclei custom** — Feito: upload em `data/custom-templates/<cid>/` e `-t` no nuclei. |
| F4 | ✅ | Export | **SARIF** — Feito: `GET /api/export/<cid>?format=sarif`. |
| F5 | ✅ | Export | **PDF server-side** — Feito: Playwright PDF em `format=pdf`. |
| F6 | ✅ | Integração | **DefectDojo** — Feito: `POST /api/export/<cid>/defectdojo`. |
| F7 | ✅ | Dashboard | **Métricas históricas** — Feito: `#ov-trends` + `loadTrendCharts`. |
| F8 | ✅ | Dashboard | **Tema claro** — Feito: `body.theme-light` + toggle na topbar. |
| F9 | ✅ | Notificações | **Web Push** — Feito: Notification API + `/api/push/subscribe` (VAPID opcional). |
| F10 | ✅ | Pipeline | **Scan incremental** — Feito: opção `incremental` usa checkpoint e pula fases caras sem diff. |
| F11 | ✅ | Auth | **Convite com escopo** — Feito: `/api/admins/invite` + accept público. |
| F12 | ✅ | Integrações | **Slash /scan** — Feito: `POST /api/integrations/slash` com `slash_token`. |
| F13 | ✅ | API | **OpenAPI** — Feito: `GET /api/openapi.json` e `/api/docs`. |
| F14 | ✅ | Pipeline | **Mobile recon** — Feito: `apk_recon` atribuído à fase intel (já existia o runner). |
| F15 | ✅ | Dashboard | **Grafo de ativos** — Feito: SVG em `asset-graph.js` (sem D3). |
| F16 | ✅ | Intel | **Surface intel sem VirusTotal** — DNS/CNAME/CDN/CT/CSP/CORS + grafo (visão VT). |

---

## 🔧 Dívida Técnica

| # | Arquivo | Descrição |
|---|---------|-----------|
| T1 | `core/pipeline.py` | ✅ `_warn_unassigned_modules()` no startup + `pipeline_assigned_modules()`. |
| T2 | `static/js/dashboard.js` | ✅ Módulos extras (`theme.js`, `asset-graph.js`, `extras.js`) sem bundler — split total de 11k linhas evitado de propósito. |
| T3 | `routes/` | ✅ Shims na raiz documentados como re-export; o servidor importa `routes.*`. |
| T4 | `core/pipeline.py` | ✅ `except Exception: pass` vira `_ignore(exc, where)` (log DEBUG). |
| T5 | `asm_data.json` | ✅ `.gitignore` cobre `asm_data.json` e `data/asm_data.json`. |

---

## ✅ Resolvidos Recentemente

| Commit | O que foi corrigido |
|--------|---------------------|
| local 2026-10-07 | 1.2.0 — Hermes breaker; S3 403 = sucesso; http_cache guarded; drain SIGTERM; X-Request-Id + pipeline trace_id; chaos `ASM_CHAOS_HOSTS`; load test `/health` |
| local 2026-10-07 | 1.1.13 — OAuth Google com timeout + breaker; bootstrap cloudlist (GitHub/ZIP) via `guarded_urlopen` |
| local 2026-10-07 | 1.1.12 — Playwright httpx (source map, GraphQL, race, client-trust, probe) e checkpoints via `guarded_httpx` |
| local 2026-10-07 | 1.1.11 — ApiTool/NVD/crt.sh/favicon/Hunter/HackerTarget/OTX via `_http_open`; CircuitOpen sem retry |
| local 2026-10-07 | 1.1.10 — `guarded_urlopen`; alertas/notificações, DefectDojo, HackerOne e dep_confusion no circuit breaker |
| local 2026-10-07 | 1.1.9 — recon GET JSON via `_http_get_json`; CORS via `http_get`; WhoisXML/open-redirect/S3/Tableau com `breaker_for` |
| local 2026-10-07 | 1.1.8 — circuit breaker por host; `/health` profundo; `retries=0` faz 1 tentativa; `release_safety_hold` no SQLite; restart consulta health |
| local 2026-10-07 | 1.1.7 — checkpoint não pula falha; timeout por módulo; stop cancela running; assetfinder/whatweb/theHarvester/certstream; Hunter.io skip sem chave |
| local 2026-10-07 | 1.1.6 — HUD após restart via module_status/events; gate skip emite evento; _run_tool sem RuntimeError; Gantt de scan done |
| local 2026-10-07 | 1.1.5 — logs da pipeline: shutil/has_kr/phishing, status error, 11 fases alinhadas BE/FE, screenshots jpeg, cloud_enum enum_tools |
| local 2026-10-07 | 1.1.3 — surface_intel (DNS/CDN/CSP/CORS/grafo sem VirusTotal) + origin_discovery na fase intel |
| local 2026-10-07 | 1.1.2 — backlog restante: M6–M12, T2–T4, F1–F15 (HUD por módulo, cancel module, toasts, backoff 429, min_severity, 2FA, SARIF/PDF, DefectDojo, tema, grafo, incremental, OpenAPI, slash, convite, apk_recon) |
| local 2026-10-07 | B1/M1 logging no pipeline; B2/M2 modal de alert rules; B3 filtro de tech na paginação de hosts; B4/M9 busca global → aba vulns; B5/M3 SMTP/Jira/Linear no SETTINGS_SCHEMA e `_SETTINGS_KEYS`; B6/M8 WEBHOOK_EVENTS; B7 fase cleanup explícita; M4 paginação de findings; M5 relatório HTML com hosts/portas/cloud/supply chain; T1 warning de módulos órfãos; install_tools (`((INSTALLED++))`, gitleaks, vendor persistente); restart_server usa venv |
| `f169433` | Null guards em hosts/portas; mapeamento censys_api_id→censys_id; scan_mode para pipeline; censys_api_secret e wpscan_token no SETTINGS_SCHEMA |
| `7f2c3a7` | Filtros de vuln "low"; timing bug em goToVulnSeverity (pendingVulnFilter) |
| `b2f0501` | Módulos asn/asnmap/email/theharvester/hunterio sem fase atribuída; live_hosts contava todos os hosts |
| `7259b27` | httpx fallback — timeout e workers insuficientes |
| `d7cc384` | Botão cancelar todos os scans |
| `9aa14de` | Botão escanear todos os targets de todas as empresas |
| `6d67680` | Escopos sumindo ao salvar empresa (optimistic update) |
| `02c4554` | Remoção do Bugcrowd; credenciais HackerOne nas configurações |
