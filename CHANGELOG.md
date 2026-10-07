# Changelog

Todas as mudanças relevantes do projeto são documentadas aqui.

## [1.2.0] - 2026-10-07

### Robustez

- Hermes (`POST /api/ai/enrich-finding`) passa pelo circuit breaker do host. Circuito aberto devolve 503 `circuit open` sem ir à rede. 4xx conta como sucesso do breaker (o peer respondeu); 5xx/timeout abrem o circuito.
- PUT/DELETE S3: HTTP 403/4xx conta como sucesso do breaker (bucket recusou a escrita). Timeout/5xx continuam falha.
- `utils/http_cache.fetch` usa `guarded_urlopen`.
- Drain no SIGTERM: `GET /health` devolve 503 `draining`; `restart_server.sh` manda TERM, espera `ASM_DRAIN_TIMEOUT` (8s) e só então KILL. Porta única ainda tem um gap curto entre o bind antigo e o novo.
- Tracing: `X-Request-Id` / `X-Trace-Id` no Flask; `trace_id` no estado da pipeline e em `_emit_module`; logs com `rid=`/`tid=`.
- Chaos de testes: `ASM_CHAOS_HOSTS` força `CircuitOpen` naquele host, sem ir à rede. Não injeta falha no host live nem no Porto.
- Load test: `collect_health` em rajada concorrente (32 chamadas) no pytest.

## [1.1.13] - 2026-10-07

### Robustez

- OAuth Google (`exchange_google_code`) usa `guarded_urlopen` com timeout de 15s no token e no userinfo. Circuito aberto ou falha devolve `None` (antes o `urlopen` não tinha timeout).
- Bootstrap do `cloudlist` (GitHub releases + download do ZIP) passa pelo breaker. GitHub caído não prende `available()` da ferramenta.

## [1.1.12] - 2026-10-07

### Robustez

- `guarded_httpx` / `guard_host` no circuit breaker: Playwright (source map, GraphQL introspection, race mapper, client-trust, probe HTTP) e fingerprint de checkpoint herdam o circuito por host.
- Circuito aberto devolve `None`/skip sem ir à rede. 401/403 no client-trust continuam sucesso (o peer respondeu). Race mapper não abre N conexões em paralelo contra um host já aberto.

## [1.1.11] - 2026-10-07

### Robustez

- `BaseTool._http_open` envia os GETs do registry (NVD, crt.sh, favicon no host alvo, Shodan, Hunter.io, HackerTarget, AlienVault OTX) por `guarded_urlopen`. Circuito aberto no host alvo do favicon não abre o breaker da ferramenta inteira.
- `ApiTool.run` trata `CircuitOpen` sem retry (sai na hora). crt.sh HTML (rate-limit) continua contando como falha do circuito.

## [1.1.10] - 2026-10-07

### Robustez

- `guarded_urlopen` no circuit breaker: POST/GET com timeout herdam o circuito por host. 4xx conta como sucesso (o peer respondeu); 5xx/timeout abrem o circuito.
- Alertas (Slack, Discord, webhook, Jira, Linear) e notificações (`_post_json` / `_post_form`) falham rápido com circuito aberto, sem enfileirar timeout no dispatch.
- DefectDojo (`POST /api/export/<cid>/defectdojo`) devolve 503 `circuit: open`. Proxy HackerOne usa o breaker de `api.hackerone.com`.
- `dep_confusion` (npm/PyPI/RubyGems/GitHub) passa pelo mesmo helper; o script adiciona a raiz do projeto ao `sys.path` quando roda via subprocess.

## [1.1.9] - 2026-10-07

### Robustez

- GETs JSON da recon (NVD supply-chain/CVE, GitHub, HudsonRock, CISA KEV, FIRST EPSS) passam por `_http_get_json` → `http_get` (timeout + circuit breaker por host). Circuito aberto devolve `None` sem ir à rede.
- CORS usa `http_get(..., retries=0)` e ignora `status==0` (circuito aberto / host morto).
- POST WhoisXML reverse-whois, probe de open-redirect (sem seguir Location), PUT/DELETE S3 e Tableau (TLS `CERT_NONE`) mantêm o método original e consultam `breaker_for` antes de cada chamada. Timeout no open-redirect conta como falha do circuito.

## [1.1.8] - 2026-10-07

### Robustez

- Circuit breaker por host nas APIs de recon (`http_get`, urlscan/rapiddns, ApiTool, crt.sh, NVD). Depois de 5 falhas o destino abre e as próximas chamadas saem na hora, sem queimar o pool da discovery.
- `http_get(..., retries=0)` passa a fazer **uma** tentativa (antes o loop `range(0)` não chamava a rede).
- `GET /health` e `GET /api/health` (sem auth) checam SQLite, disco, `bin/`, watchdog, pipelines em voo, Playwright e circuitos abertos. 503 só se o banco ou o disco estiverem inutilizáveis.
- Watchdog: `ASMDatabase.release_safety_hold()` reenfileira jobs parados pelo SAFETY-WATCHDOG (o método era chamado e não existia). `safety_hold_jobs` bindava o `job_type` no campo `error`, então o hold no SQLite não pegava nenhum job.
- `restart_server.sh` consulta `/health` depois de subir o processo.

## [1.1.7] - 2026-10-07

### Corrigido

- Checkpoint deixa de tratar falha como sucesso: `whatweb not found`, NameError, binário ausente e chave de API faltando não são retomados no smart-scan (arquivo inválido é apagado).
- `_classify_result_status` usa a mensagem para reclassificar `done` falso (`not found`, `api key`, crash).
- Stop da pipeline marca módulos `running` como `cancelled` no HUD e grava `pipeline_state.json` na hora.
- Cada módulo tem timeout próprio (default 180s); certstream não faz mais 3 retries de 90s que travavam a discovery.
- Hunter.io / APIs com `requires_key` saem como `skipped` quando a chave não está configurada, em vez de `done` vazio.
- `whatweb` e o registry de tools resolvem binários em `bin/` do projeto.
- `urlscan_io` / `rapiddns` bloqueados deixam de ser gravados como `done`.

### Ferramentas

- `install_tools.sh` instala `assetfinder`, `whatweb` (clone WhatWeb), `theHarvester` (GitHub) e o pacote Python `certstream`.
- `certstream` casa o domínio da empresa (não o sufixo `.com.br`) e cai no crt.sh se o websocket falhar.

## [1.1.6] - 2026-10-07

### Corrigido

- `GET /api/recon/<cid>/pipeline` reconstrói o status de cada módulo a partir de `module_status` / `module_events` quando a memória (`recon_results`) está vazia após restart.
- Módulo que ficou `running` numa pipeline já `done` passa a `error` (`interrupted`) no HUD.
- Skip por gate (`has_live_hosts` etc.) emite evento e grava `module_status`, então o HUD não mostra `not_run`.
- `_run_tool` devolve envelope `error`/`skipped` em vez de levantar `RuntimeError` no erro da ferramenta.
- Gantt da pipeline não fica “active” para sempre num scan já concluído quando o catálogo ganhou módulos novos.

### Pipeline

- Cada run grava `phase_catalog` e o mapa compacto `module_status` em `pipeline_state.json`.
- HUD do terminal (BBOT overlay) usa as mesmas 11 fases do backend.

## [1.1.5] - 2026-10-07

### Corrigido

- `core/recon.py` importa `shutil`/`tempfile`/`base64` no módulo: `git_leaks`, `s3_scanner`, `jwt_analysis`, `xss_scan` e `portscan` deixam de falhar com `name 'shutil' is not defined`.
- `run_api_discovery_extra` não referencia mais `has_kr` fora do escopo.
- Exceções da pipeline (`NameError`, `KeyError`, traceback de ferramenta) classificam como `error` em vez de `done`.
- Módulo `phishing` ganhou runner (typosquat/lookalike passivo); HUD e persistência passam a enxergar o resultado.
- Módulo sem runner é pulado com `no runner` em vez de `KeyError`.
- Falhas de ferramenta (`ModuleNotFoundError` do `cloud_enum`, binário ausente) voltam como `skipped`/`error` estruturado, sem traceback no HUD.
- Screenshots gowitness (`.jpeg` `http---host-80`) e Playwright (`browser_https___…`) ligam no host certo.
- HUD da pipeline usa as 11 fases do backend (`js_discovery`, `ports_services`, `nuclei`) e mostra chips de erro.

### Pipeline

- Fases reorganizadas: amass/certstream na discovery; zone_transfer na validation; related/reverse_whois na intel; vhost no fingerprint; param_mine no api_mapping; smtp/snmp/udp no ports_services.
- `riddler` e `typosquat` ficam on-demand (`OPTIONAL_ON_DEMAND`); typosquat é coberto por `phishing`.
- `GET /api/recon/pipeline/phases` e `/api/recon/pipeline/profiles` devolvem o catálogo canônico.
- `install_tools.sh` copia `enum_tools` ao lado de `bin/cloud_enum`.

## [1.1.4] - 2026-10-07

### UI (ui-ux-pro-max)

- Design system persistido em `design-system/scantrely/MASTER.md` (Fira Sans + Fira Code, glassmorphism, densidade 9, motion 3).
- Tokens de cor/espaço aplicados no dashboard (superfícies `#0F172A`, CTA `#22C55E`, scan live `#38BDF8`).
- Ícones SVG outline (Phosphor-style) no lugar de emoji em nav, login, topbar, settings, grafo, pipeline, geradores e bug bounty.
- Skip link, anéis de foco visíveis, alvos 44px, `prefers-reduced-motion`, labels nos campos de login.
- Grafo de ativos com legenda clicável, filtros por tipo, rótulos com colisão, detalhe ao clicar e modos auto/todos/nenhum.
- Texto da UI recodificado (travessões e português íntegros nos placeholders e subtítulos).
- Home, agenda, fechar/salvar e geradores usam SVG + i18n PT-BR.

## [1.1.3] - 2026-10-07

### Adicionado

- Módulo `surface_intel` (fase discovery): visão equivalente ao VirusTotal Domain (A/CNAME/NS, CDN, staging, API, CSP terceiros, CORS `*`+credentials, grafo) **sem chave da VT**. Fontes: DNS + Certificate Transparency + HTTP.
- `origin_discovery` entra na fase intel (origem atrás de CDN).
- Grafo de ativos usa CNAME/CDN/NS e origens do CSP.

### Intel

- CloudFront anycast muda de IP por PoP; o identificador estável é o CNAME `*.cloudfront.net`.
- NS `awsdns-*` no hostname de catálogo é da distribuição CloudFront, não da zona `portoplus.com.br` (NS reais: `ns*.portoseguro.com.br`).
- `surface_intel` segue a cadeia CNAME (A/NS do alvo, como a aba Details do VirusTotal), atribui CORS/CSP/S3 ao alias em escopo, detecta listing S3, hostname default CloudFront público e origens de supply chain no CSP. CDNs genéricos (GA, jsDelivr, jQuery) ficam só no grafo.

## [1.1.2] - 2026-10-07

### Adicionado

- HUD de pipeline com eventos por módulo (`phase`/`module`/`status`) via SSE e chips com cancelamento individual (`DELETE /api/recon/<cid>/pipeline/<module>`).
- Retry com backoff em rate limit/429 mesmo sem Mullvad.
- Severidade mínima por regra de alerta (`info`, `medium_and_above`, `high_and_above`, `critical_only`).
- 2FA TOTP (`pyotp`) com setup/enable/disable e campo no login.
- Scan incremental (delta), templates Nuclei custom em `data/custom-templates/<cid>/`, e `apk_recon` na fase intel.
- Export SARIF e PDF server-side (Playwright); push para DefectDojo.
- Tema claro, grafo de ativos SVG, métricas históricas no overview, timeline de diff.
- Convite de usuários com escopo, slash `/scan`, OpenAPI em `/api/openapi.json`, Web Push (Notification API + subscribe).
- Módulos JS extras (`theme.js`, `asset-graph.js`, `extras.js`) sem bundler.

### Corrigido

- `alert()` nativo substituído por toasts no dashboard.
- `except Exception: pass` críticos no pipeline passam por `_ignore()` (log DEBUG).
- Shims `*_routes.py` documentados como re-export; testes continuam importando-os.

## [1.1.1] - 2026-10-07

### Corrigido

- Pipeline deixa de usar `print()` em produção; logs vão para `logging.getLogger("scantrely.pipeline")` (`ASM_LOG_LEVEL`).
- `addAlertRule()` usa modal próprio em vez de `prompt()` nativo.
- Paginação de hosts respeita o filtro de tecnologias.
- Busca global de findings abre a aba de vulnerabilidades com título/severidade.
- SMTP, Jira e Linear persistem em `_SETTINGS_KEYS` e aparecem em Configurações.
- Webhooks listam os eventos reais do backend (`new_host`, `cert_expiring`, etc.).
- Fase 4 (cleanup) lista o módulo interno no HUD.
- `install_tools.sh` não aborta mais em `set -e` no resumo; gitleaks, dnsgen, LinkFinder e SecretFinder instalam de forma persistente.
- `restart_server.sh` usa o Python do `.venv` e o Chromium em `$HOME/.asm-playwright`.

### Adicionado

- Paginação de 25 grupos na aba de findings.
- Relatório HTML com hosts, portas, cloud storage e supply chain.
- Validação de módulos órfãos no startup do pipeline.
- Toasts empilhados no dashboard.

## [1.1.0] - 2026-06-15

### Adicionado

- **Triagem de findings** — status persistido por finding (Aberto, Em progresso,
  Corrigido, Risco aceito), com filtro dedicado na aba de findings.
  Endpoints: `GET/POST /api/findings/<cid>/triage`.
- **CRUD completo de regras de alerta** — criação, edição (nome, tipo, canais),
  habilitar/desabilitar e exclusão de regras, com validação de tipos no backend.
  Endpoints: `GET/POST/PUT/DELETE /api/alert-rules/<cid>[/<rid>]`.
- **Busca global (Ctrl+K)** — modal de busca rápida em empresas, domínios,
  hosts, pessoas (e-mails) e findings, com navegação por teclado.
- **Exportação em PDF** — botão "Exportar PDF" que gera o relatório via
  impressão do navegador, complementando a exportação em HTML existente.
- **Pivot de e-mails/funcionários** — tabela na aba de Infraestrutura com
  contatos do Hunter.io (nome, cargo, confiança) e links de pivot para
  LinkedIn, HaveIBeenPwned e Google.
- **Cloud exposure mais profunda (S3 / Azure Blob / GCS)** —
  - Probe de ACL pública somente leitura para detectar buckets com permissão
    anônima de escrita/alteração de ACL.
  - Extração de amostra de objetos (`sample_objects`) para os três provedores.
  - Resultados persistidos em `co.cloud_buckets` e exibidos em um novo card
    "☁ Cloud Storage Buckets" (provedor, nível de acesso, objetos de amostra,
    arquivos sensíveis, alertas de ACL).

### Corrigido

- **Bug crítico em `_curl_check`** — o corpo da resposta HTTP era descartado
  (`-o /dev/null`), o que impedia silenciosamente a detecção de objetos
  listados e arquivos sensíveis em buckets S3/Azure/GCS. Agora o corpo é
  capturado corretamente.
- **Aba de Findings/Vulnerabilidades sempre vazia** — `_confirmedVulnFindings()`
  exigia que `status` contivesse `"confirmed"`, campo que nunca era definido
  pelo pipeline, deixando a aba permanentemente vazia mesmo com findings
  (incluindo secrets) computados nas estatísticas. Agora os findings aparecem
  por padrão, exceto os marcados explicitamente como falso-positivo, ignorado
  ou duplicado.
- **Secrets escondidos pelo filtro de ruído** — secrets do tipo `password`
  eram filtrados por engano (a descrição continha a palavra "password", que
  caía no filtro de ruído). Secrets agora são isentos desse filtro.
- **Título genérico em secrets** — findings de secret sempre mostravam
  "Secret exposto: secret em ..."; agora mostram o tipo real
  (`aws_key`, `password`, `stripe_key`, etc.).

---

## [1.0.0] - 2026-06-06

- Lançamento inicial — 14 fases, 79 módulos, +40 ferramentas nativas,
  Playwright headless, SQLite WAL, fila de jobs serial.
