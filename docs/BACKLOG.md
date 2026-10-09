# Backlog — Scantrely ASM Platform

> Última atualização: 2026-10-08 (1.3.11)  
> Legenda de prioridade: 🔴 Alta · 🟡 Média · 🟢 Baixa

---

## ▶ Próximos passos (pós 1.4.0)

| # | Prioridade | Descrição |
|---|-----------|-----------|
| P1 | 🔴 | Front das abas Vulnerabilidades/Hosts passar a usar `/findings` e `/hosts` paginados (hoje ainda baixam a empresa inteira em `/api/data/company/<id>`). |
| P4 | 🟡 | Dividir `static/js/dashboard.js` (~12 mil linhas) por aba; remover estilos inline. |
| P6 | 🟢 | Marcar achados "não vistos no último scan" como resolvidos em vez de mantê-los. |

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
| F15 | ✅ | Dashboard | **Grafo de ativos** — Feito: SVG em `asset-graph.js` (sem D3). 1.3.3: cluster/LOD, zoom, busca, formas, lista. |
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
| local 2026-10-08 | 1.3.11 — Grupo Vulnerabilidades (Confirmadas) em PT: título, loading, empty, filtros |
| local 2026-10-08 | 1.3.10 — Aba Recon/Screenshots em PT (título, loading, empty, filtros) |
| local 2026-10-08 | 1.3.9 — Badge Exposição = funcionários; Hosts = ativos; Pipeline em PT |
| local 2026-10-08 | 1.3.8 — Inventário de hosts no Hosts visível; clique no screenshot abre lightbox; alvos 44px |
| local 2026-10-08 | 1.3.7 — Screenshot 404: path sem company id vira `/screenshots/<cid>/<arquivo>` |
| local 2026-10-08 | 1.3.6 — URL relativa colapsa `..`; inventário JS sem MIME/webpack; secrets da aba Endpoints iguais ao JS Reverse |
| local 2026-10-08 | 1.3.5 — Clique em secret/endpoint/URL/host abre o local em que foi achado |
| local 2026-10-07 | 1.3.4 — Operação mostra persist browser/crawl/JS; empty só sem evidência; CTA Playwright |
| local 2026-10-07 | 1.3.3 — Grafo: cluster por apex, LOD, zoom/pan, busca, formas, vista lista |
| local 2026-10-07 | 1.3.2 — Sync backend/frontend: subnav das abas órfãs, infra lê persist, git/vendor viram findings, param_mine nos endpoints |
| local 2026-10-07 | 1.3.1 — JS scan: KPI array, JWT do módulo js, noise CDN por sufixo, source maps analisados, par client_id/secret |
| local 2026-10-07 | 1.3.0 — Exposição estilo Cavalier: parser Hudson Rock rico, persist hudsonrock-only, busca ao vivo, aba + workspace |
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


---

# Backlog de ferramentas


> Ferramentas adicionais para integrar ao pipeline ASM e aumentar a chance de achar vulnerabilidades.
> Prioridade: 🔴 crítica | 🟡 alta | 🟢 média

---

## SQL Injection & Database

| Ferramenta | Descrição | Prio |
|-----------|-----------|------|
| **sqlmap** | SQLi detection & exploitation automático | 🔴 |
| **NoSQLMap** | MongoDB/CouchDB injection | 🟡 |
| **nosqli** | NoSQL injection scanner | 🟡 |

---

## XSS & Client-Side

| Ferramenta | Descrição | Prio |
|-----------|-----------|------|
| **dalfox** | XSS scanner com DOM-based, stored, reflected | 🔴 |
| **XSStrike** | XSS detection com fuzzing inteligente | 🔴 |
| **kxss** | Fast XSS discovery via param reflection | 🟡 |
| **wuzz** | Interactive HTTP client (like Burp CLI) | 🟡 |

---

## SSRF / RCE / Injection

| Ferramenta | Descrição | Prio |
|-----------|-----------|------|
| **ssrf-sheriff** | SSRF detection via callback/OOB | 🔴 |
| **interactsh-client** | OOB (out-of-band) interaction catcher | 🔴 |
| **commix** | Command injection scanner | 🔴 |
| **tplmap** | SSTI (Server-Side Template Injection) | 🟡 |
| **crlfuzz** | CRLF injection scanner | 🟡 |
| **Oralyzer** | Open redirect scanner | 🟡 |

---

## API & GraphQL

| Ferramenta | Descrição | Prio |
|-----------|-----------|------|
| **graphw00f** | GraphQL fingerprint & security analysis | 🟡 |
| **clairvoyance** | GraphQL schema brute (introspection off) | 🟡 |
| **swagger-stalker** | OpenAPI/Swagger endpoint enumeration | 🟢 |
| **NoPac** | API security scanner | 🟢 |

---

## Auth & Session

| Ferramenta | Descrição | Prio |
|-----------|-----------|------|
| **jwt_tool** | JWT analysis, bruteforce, injection | 🔴 |
| **jwt-cracker** | JWT HMAC secret brute-force | 🟡 |
| **oauth2-tester** | OAuth 2.0 misconfig checker | 🟡 |

---

## Cloud & Infrastructure

| Ferramenta | Descrição | Prio |
|-----------|-----------|------|
| **ScoutSuite** | Multi-cloud security audit (AWS/GCP/Azure) | 🔴 |
| **prowler** | AWS security assessment | 🟡 |
| **cloudsplaining** | AWS IAM privilege escalation scanner | 🟡 |
| **trivy** | Container & dependency vuln scanner | 🟡 |

---

## Dependency & Supply Chain

| Ferramenta | Descrição | Prio |
|-----------|-----------|------|
| **npm-audit / yarn audit** | JS dependency vulns | 🟡 |
| **safety (Python)** | Python package vulns | 🟡 |
| **bundler-audit** | Ruby gem vulns | 🟢 |
| **osv-scanner** | Google OSV multi-ecosystem scanner | 🟡 |

---

## Web Fingerprint & Exploitation

| Ferramenta | Descrição | Prio |
|-----------|-----------|------|
| **nikto** | Web server scanner (CGI, misconfigs) | 🟡 |
| **testssl.sh** | TLS/SSL full security suite | 🟡 |
| **CMSeeK** | CMS detection + vuln scan (WP, Joomla, Drupal) | 🟡 |
| **wpscan** | Já registrado — verificar integração | 🟡 |

---

## Network & Service

| Ferramenta | Descrição | Prio |
|-----------|-----------|------|
| **rustscan** | Port scanner 3x mais rápido que nmap | 🟢 |
| **snmpcheck** | SNMP enumeration | 🟡 |
| **enum4linux** | SMB/RPC enumeration | 🟡 |
| **ldapsearch** | LDAP enumeration | 🟡 |

---

## Secrets & Leaks

| Ferramenta | Descrição | Prio |
|-----------|-----------|------|
| **gitleaks** | Git history secret scanner | 🔴 |
| **whispers** | Hardcoded credential finder | 🟡 |
| **S3Scanner** | Open S3 bucket finder + list | 🔴 |
| **git-dumper** | .git exposed downloader | 🟡 |

---

## Mobile & IoT

| Ferramenta | Descrição | Prio |
|-----------|-----------|------|
| **MobSF** | Mobile security framework (APK/IPA) | 🟡 |
| **frida** | Dynamic instrumentation (mobile runtime) | 🟡 |
| **r2frida** | Radare2 + Frida bridge | 🟢 |

---

## Resumo por Categoria de Vulnerabilidade

| Categoria | Ferramentas | Cobertura Atual |
|-----------|------------|-----------------|
| SQL Injection | sqlmap, NoSQLMap | ❌ Nenhuma |
| XSS | dalfox, XSStrike, kxss | ❌ Nenhuma |
| SSRF/OOB | ssrf-sheriff, interactsh | ❌ Nenhuma |
| Command Injection | commix | ❌ Nenhuma |
| JWT/Auth | jwt_tool | ❌ Nenhuma |
| Cloud Security | ScoutSuite, trivy | ⚠️ cloud_enum apenas |
| Secrets | gitleaks, S3Scanner | ⚠️ trufflehog apenas |
| GraphQL | graphw00f, clairvoyance | ⚠️ graphqlmap apenas |
| Web vulns | nuclei | ✅ Nuclei (limitado sem templates custom) |
| Port scan | naabu, nmap, masscan | ✅ Completo |
| Subdomain | subfinder, amass | ✅ Completo |
| JS Recon | katana, getJS | ✅ Completo |

---

## Próximos Passos Sugeridos

1. **Instalar sqlmap + dalfox** — maior impacto imediato (SQLi + XSS)
2. **Instalar gitleaks** — scan de secrets em repositórios expostos
3. **Instalar interactsh-client** — callback OOB para SSRF/blind injection
4. **Instalar S3Scanner** — buckets S3 abertos
5. **Instalar jwt_tool** — análise de tokens JWT nos JS bundles
6. **Integrar ScoutSuite** — auditoria completa de cloud se tiver acesso
