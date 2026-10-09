# ASM Platform — Como Funciona

> Documento gerado em 2026-06-03 após limpeza do projeto.
> Plataforma de **Attack Surface Management / OSINT / recon** construída em **Flask + SQLite**,
> orquestrando 35+ ferramentas externas num pipeline de 11 fases.

---

## 1. Visão geral

A ASM Platform recebe uma **empresa-alvo** (com sua lista de domínios), executa um
**pipeline de reconhecimento** que descobre subdomínios, hosts vivos, tecnologias, portas,
serviços e vulnerabilidades, e expõe tudo numa **SPA (single-page app)** servida pelo próprio
backend Flask.

```
  Navegador (SPA)  ──HTTP/JSON──►  server.py (Flask)
                                      │
                          ┌───────────┼─────────────┐
                          ▼           ▼             ▼
                    Blueprints     JobScheduler   ASMDatabase
                    (routes/)      (core/jobs)    (core/database → asm.db)
                          │           │
                          └────►  ReconRunner (core/pipeline.py)
                                      │  executa 11 fases
                                      ▼
                            44 módulos run_* (core/recon.py)
                                      │  invocam binários em bin/
                                      ▼
                          subfinder, amass, httpx, nuclei, ffuf, ...
```

---

## 2. Como rodar

O servidor é iniciado pelo script de conveniência (mata processo antigo, religa, grava PID/log):

```bash
./restart_server.sh                 # sobe em http://127.0.0.1:5000
HOST=0.0.0.0 PORT=8080 ./restart_server.sh   # override via env
```

Ou diretamente:

```bash
python3 server.py --host 127.0.0.1 --port 5000
```

- **Log:** `logs/server.log`  •  **PID:** `logs/server.pid`
- **Primeiro acesso:** um admin padrão é criado automaticamente —
  **usuário `admin` / senha `admin`** (troque imediatamente).
- **Instalação das ferramentas externas:** `./install_tools.sh` (popula `bin/`).
- **Dependências Python:** `pip install -r requirements.txt`.

---

## 3. Estrutura do projeto (pós-limpeza)

```
asm/
├── server.py              # Entrypoint Flask: auth, sessões, registro de blueprints
├── restart_server.sh      # Sobe/reinicia o servidor (PID + log)
├── install_tools.sh       # Instala os 35+ binários em bin/
├── requirements.txt       # Dependências Python
│
├── core/                  # Núcleo de domínio
│   ├── database.py        # ASMDatabase — toda a camada SQLite (asm.db)
│   ├── pipeline.py        # ReconRunner + PIPELINE_PHASES (11 fases)
│   ├── recon.py           # 44 módulos run_* (a lógica de cada ferramenta)
│   ├── jobs.py            # JobScheduler — fila de jobs com prioridade/retry
│   ├── targets.py         # Seleção/normalização de domínios-alvo
│   ├── checkpoints.py     # Persistência de progresso do scan
│   ├── rbac.py            # Papéis e permissões
│   └── validators.py      # Validação de entrada
│
├── routes/                # Blueprints Flask (82 rotas no total)
│   ├── core.py            # Dashboard, empresas, dados base
│   ├── scans.py           # Disparo e acompanhamento de scans
│   ├── recon.py           # Endpoints de recon/pipeline
│   ├── assets.py          # Ativos descobertos (hosts, subdomínios)
│   ├── reporting.py       # Relatórios / exportações
│   └── ops.py             # Operação (status de ferramentas, saúde)
│
├── utils/                 # Infraestrutura transversal
│   ├── command_runner.py  # Execução de subprocessos (stdin=DEVNULL p/ evitar prompt /dev/tty)
│   ├── tools.py           # Registro/descritores das ferramentas externas
│   ├── tool_gate.py       # Limitador de concorrência entre ferramentas
│   ├── rate_limiter.py    # Rate limiting por fase
│   ├── alerting.py        # Regras de alerta
│   ├── http_cache.py      # Cache de respostas HTTP
│   ├── dep_confusion.py   # Checagem de dependency confusion (usa node/jsdom)
│   ├── mullvad_rotator.py # Rotação de saída VPN (Mullvad)
│   └── dns_tcp_proxy.py   # Proxy DNS-over-TCP
│
├── static/                # Frontend (SPA)
│   ├── index.html         # Shell da SPA (inclui tela de login)
│   └── js/                # api.js, asm.js, dashboard/*.js (UI principal, 17 arquivos em ordem)
│   └── css/dashboard.css
│
├── config/                # Estado em JSON (admins, empresas, settings, webhooks…)
├── data/                  # Runtime: asm.db (+ -wal/-shm), asm_data.js, snapshots/
├── scans/                 # Saída bruta por alvo (ex.: scans/portoseguro/)
├── logs/                  # server.log, audit.log, server.pid
├── bin/                   # 35+ binários das ferramentas (gitignored, ~775 MB)
├── wordlists/             # Wordlists de fuzzing/brute (~220 MB)
├── migrations/            # 001_initial.sql (schema base)
├── tests/                 # test_asm.py (suíte pytest)
└── node_modules/          # jsdom — usado por utils/dep_confusion.py
```

> **Shims de raiz** (`database.py`, `pipeline.py`, `validators.py`, `*_routes.py`):
> arquivos de uma linha que reexportam os módulos reais de `core/` e `routes/`.
> Mantidos por **compatibilidade com a suíte de testes** (`tests/test_asm.py` ainda
> importa pelos nomes antigos). `server.py` já usa os caminhos novos (`core.*`, `routes.*`).

---

## 4. Backend — `server.py`

- Cria o app Flask, instancia `ASMDatabase` (→ `data/asm.db`) e o `JobScheduler`.
- **Autenticação:** `POST /api/auth/login` devolve `{token}`; as APIs autenticadas usam o
  header **`X-Auth-Token`**. Sessões ficam em memória com **fallback no banco** (tabela `sessions`).
  Senhas com **PBKDF2-SHA256, 260.000 iterações** (compatível com OWASP).
- **RBAC:** dois papéis — `super_admin` (acesso total) e `analyst` (escopo por empresa).
- **Rate limit de login:** 10 falhas por IP → bloqueio de 15 min (compartilhado entre usuários do mesmo IP).
- **Registro de blueprints** (linhas ~643–746): `core`, `ops`, `reporting`, `assets`, `scans`, `recon`.
- Serve a SPA em `/` (por isso `/login` "não existe" como rota — é a própria SPA).
- **Health:** `GET /health` e `GET /api/health` (sem login) devolvem SQLite, disco, `bin/`, watchdog, pipelines e circuit breakers. HTTP 503 só se o banco ou o disco falharem.

### Endpoints principais (prefixo `/api`)
| Caminho | Função |
|---|---|
| `POST /api/auth/login`, `GET /api/auth/me` | Autenticação / sessão atual |
| `GET /api/companies` | Empresas no escopo do usuário |
| `GET /api/tools/status` | Estado das ferramentas externas |
| `POST /api/scans...` | Dispara/acompanha scans |
| `GET /asm_data.js` | Dump de dados do front (gerado do banco, não estático) |

---

## 5. O pipeline de recon (`core/pipeline.py`)

`ReconRunner` executa **`PIPELINE_PHASES`** — uma lista declarativa de **11 fases**. Cada fase tem:
`modules` (quais run_* rodar), `parallel` (concorrência), `rate_phase` (perfil de rate limit),
`gate` (pré-condição, ex.: `has_live_hosts`) e flags como `recursive`/`merge_hosts`.
O catálogo canônico também sai em `GET /api/recon/pipeline/phases` (HUD e API usam a mesma lista).
Cada execução grava `phase_catalog` + `module_status` em `scans/<cid>/pipeline_state.json`,
então o HUD reconstitui o status depois de um restart.

| # | Fase (`id`) | O que faz | Módulos (exemplos) |
|---|---|---|---|
| 1 | `discovery` | Discovery passivo de superfície | subfinder, assetfinder, amass, certs, certstream, surface_intel, otx, urlscan… |
| 2 | `validation` | DNS, zona, leaks (recursivo) | dns, dns_brute, zone_transfer, leaks, git_leaks, email |
| 3 | `intel` | Intel útil para bug bounty | shodan, cloud, phishing, related, reverse_whois, apk_recon, origin_discovery… |
| 4 | `cleanup` | Limpeza e priorização (interno) | cleanup |
| 5 | `fingerprint` | Fingerprint web | headers, waf, wappalyzer, vhost, screenshot, gowitness… |
| 6 | `js_discovery` | JS em hosts vivos | js |
| 7 | `api_mapping` | APIs, endpoints e secrets | js_endpoints, js_secrets, param_mine, graphql, jwt_analysis |
| 8 | `browser` | Evidência Playwright | browser_crawl, browser_recon |
| 9 | `bug_checks` | Checks leves de bug bounty | takeover, cors, open_redirect, cloud_enum, xss_scan… |
| 10 | `ports_services` | Portas e serviços | portscan, udp_portscan, smtp_probe, snmp_probe, cms_scan… |
| 11 | `nuclei` | Templates curados | cve, api_panels, screenshot_diff |

- **Gates** evitam trabalho inútil: fases ativas só rodam se houver hosts vivos / portas abertas.
- **`SELF_CONTAINED_MODULES`**: módulos que não dependem de descoberta prévia.
- **Isolamento de erro por módulo:** cada `run_*` captura suas próprias exceções — uma ferramenta
  que falha não derruba o pipeline inteiro.
- **Concorrência** controlada por `utils/tool_gate.py`; domínios são processados em lotes
  (ex.: Porto Seguro = 32 domínios em batches).

### Módulos adicionados (2026-06-03)
Dois módulos passivos novos em `core/recon.py`, ligados à **Fase 1 (`passive`)**:

- **`run_reverse_whois`** (ASM — atribuição de ativos): puxa o registrante via **RDAP**
  (grátis) e, com `whoisxml_key` configurada nas Settings, consulta a **WhoisXML Reverse
  WHOIS API** para listar os domínios *apex* irmãos da mesma organização.
  Os apexes irmãos são **apenas reportados** (`sibling_domains`/`found`) — de propósito
  **não** entram no pool ativo de hosts, para evitar varrer domínios de terceiros fora de escopo.
- **`run_github_subdomains`** (Bug Bounty): **GitHub code search** extraindo hostnames
  `*.<domínio>` de código público (CI, JS, infra). Distinto do search de *secrets* já
  existente. Os `subdomains` retornados são **mesclados automaticamente** na superfície
  pelo harvester do pipeline (`_collect_new_subdomains`) e sondados com httpx.
  Requer `github_token`; sem token degrada gracioso (code search exige auth).

- **`run_apk_recon`** (Bug Bounty/ASM — mobile) — Fase 1b (`intel`): descobre os
  **pacotes Android** da org via busca no **Google Play** (passivo) e, se houver APKs
  do analista em `scans/<empresa>/apks/` e **apkleaks** instalado, extrai URIs, endpoints
  e secrets — subdomínios `*.<alvo>` encontrados são mesclados na superfície. Sem
  apkleaks/APK degrada para só a lista de pacotes. Dependências adicionadas ao
  `install_tools.sh` (`apkleaks` via pip + `jadx` via apt).
- **`run_origin_discovery`** (Bug Bounty — WAF bypass) — Fase 6 (`enum_active`): para
  domínios atrás de **Cloudflare/CDN**, reúne IPs de origem candidatos de fontes passivas
  (registros **MX**, mecanismos **SPF `ip4:`/`include:`**, subdomínios comuns não-proxiados
  como `mail/direct/origin/cpanel`, e busca por **certificado no Shodan** se houver key),
  excluindo ranges de CDN. Cada candidato é **verificado** com requisição usando o header
  `Host` do alvo, comparando título/status com o baseline. Origens são **apenas reportadas**
  (nunca varridas automaticamente). Detecção de Cloudflare prioriza o header `cf-ray`/
  `server: cloudflare` (definitivo) sobre o range de IP.

Wiring: dispatch em `core/pipeline.py` (`_make_fn_map`), módulos adicionados às fases
`passive`/`intel`/`enum_active` em `PIPELINE_PHASES`, e a chave `whoisxml_key` exposta em
`routes/recon.py`. Detalhes por módulo:

- `reverse_whois` → fase `passive`, key `whoisxml_key`
- `github_subdomains` → fase `passive`, key `github_token`
- `apk_recon` → fase `intel`, APKs em `scans/<empresa>/apks/`
- `origin_discovery` → fase `enum_active`, key `shodan_key` (opcional)
- `browser_crawl` → fase `crawl`, opção `crawl_max_hosts` (default 150)

### Crawler com Playwright (`run_browser_crawl`) — Fase 5 `crawl`
Crawler headless que roda em **todos os subdomínios vivos** (não só nos "interessantes"
como o `browser_recon`). Para cada host renderiza a raiz e segue links internos do mesmo
host em **largura (BFS)** até `max_pages_per_host` (default 8), **executando JS** — então
captura rotas de SPA e URLs injetadas dinamicamente, que crawlers estáticos perdem. Por
página coleta: hyperlinks, **endpoints de API** (intercepta `xhr`/`fetch` no nível do
browser) e **forms**. Hostnames `*.<alvo>` achados nos links voltam em `subdomains` e são
mesclados na superfície pelo harvester do pipeline.

- **Playwright** é importado de um venv dedicado (`/home/kali/.asm-playwright`) via
  `_pw_import()` — o pacote do sistema no Kali é ignorado de propósito.
- **Limites de segurança** (config via `options`): `crawl_max_hosts` (default 150),
  `max_pages_per_host` (8), `workers` (3 browsers em paralelo), `timeout` (20s/página).
  Suba `crawl_max_hosts` para cobrir inventários maiores ao custo de tempo.
- Verificado: crawl real de `iana.org` seguiu 5 páginas, coletou 500 URLs e descobriu
  `whois.iana.org`/`www.iana.org` como subdomínios in-scope.

### Configuração de API keys (tela de Settings)
As chaves de API são geridas pela página **Settings** da SPA, definida de forma
declarativa em `SETTINGS_SCHEMA` (`static/js/dashboard/*.js`) — cada entrada renderiza,
carrega e salva automaticamente. O fluxo de persistência:

```
Settings (SPA)  ──POST /api/settings──►  api_save_settings (routes/core.py)
                                              │ filtra por _SETTINGS_KEYS (allowlist)
                                              ▼
                                         DB.set_settings → tabela settings / settings.json
```

- **Allowlist:** `_SETTINGS_KEYS` em `server.py` — uma chave só persiste/retorna se estiver
  nesse conjunto. Ao adicionar uma key nova é preciso incluí-la **tanto** no `SETTINGS_SCHEMA`
  (frontend) **quanto** no `_SETTINGS_KEYS` (backend).
- **`whoisxml_key`** foi adicionada (grupo *DNS & Subdomain*, tag `paid`) para habilitar o
  `reverse_whois`. Sem ela o módulo degrada para atribuição via RDAP apenas.
- Valores mascarados retornados pelo GET não sobrescrevem a key salva (o save ignora máscaras).

### Execução de ferramentas (`utils/command_runner.py`)
Toda ferramenta de `bin/` roda via subprocess com **`stdin=DEVNULL`** — isso impede prompts em
`/dev/tty` que travavam o pipeline em background (correção do bug do asnmap).

---

## 6. Camada de dados (`core/database.py` → `data/asm.db`)

SQLite único com WAL. Tabelas principais:

| Tabela | Conteúdo |
|---|---|
| `companies` | Empresas e suas listas de domínios |
| `asm_data_state` | Estado consolidado servido ao front (upsert + sync em disco) |
| `jobs` | Fila de jobs com **prioridade + lógica de retry** |
| `tool_runs` | Histórico de execução de cada ferramenta |
| `subdomain_history`, `scan_stats_history` | Histórico/diffs ao longo do tempo |
| `snapshots` | Snapshots por domínio (espelhados em `data/snapshots/*.json`) |
| `admins`, `sessions` | Usuários e sessões |
| `alerts`, `alert_rules`, `webhooks`, `schedules` | Alertas, regras, notificações e agendamentos |
| `audit_log` | Trilha de auditoria (também em `logs/audit.log`) |
| `whitelist_entries`, `settings`, `schema_meta` | Whitelist, configurações, versão de schema |

**Sincronização:** a cada save, `_sync_asm_data_file` reescreve `data/asm_data.js` e
`_sync_snapshots_dir` espelha os snapshots no filesystem — o front lê o estado do banco, não de arquivo estático.

---

## 7. Frontend (`static/`)

SPA servida diretamente pelo Flask. `index.html` carrega `static/js/dashboard/*.js` (UI principal),
`asm.js` e `api.js` (cliente HTTP). A tela de login faz parte da própria SPA. O grande
`asm_data.js` é gerado dinamicamente a partir do banco.

---

## 8. Limpeza realizada (2026-06-03)

Removidos como lixo desnecessário:

| Item | Motivo |
|---|---|
| `-` (arquivo) | Saída perdida do ffuf (`-o -` gravou num arquivo chamado "-") |
| `__pycache__/` (4 dirs) | Bytecode Python regenerável (gitignored) |
| `test_dump.py` | Script de debug pontual com caminho hardcoded inexistente |
| `test-results/` | Artefato residual do Playwright |
| `backups/asm.db.bak_20260525` (15 MB) | Backup manual antigo do banco |
| `data/recon.db` (90 KB) | Banco de **schema antigo**, órfão, sem referências no código |

**Mantidos de propósito:** `bin/` e `wordlists/` (essenciais às ferramentas), shims de raiz
(testes dependem deles), `logs/server.log` (runtime ativo) e os diretórios de runtime vazios
(`checkpoints/`, `static/img/`, etc.) que o servidor pode precisar para escrever.

---

## 9. Documentos relacionados

- `../README.md` — visão rápida / instalação.
- `ARQUITETURA.md` — arquitetura detalhada (referência longa).
- `FERRAMENTAS.md` — análise das ferramentas integradas.
