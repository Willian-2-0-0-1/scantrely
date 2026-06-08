# Scantrely — External Attack Surface Management

> Plataforma de Attack Surface Management (ASM) totalmente local. Orquestra 35+ ferramentas de recon em um pipeline de 14 fases com 50+ módulos. Subdomínios, portas, tecnologias, vulnerabilidades, secrets, cloud, mobile, JS recon e pentest automatizado com Playwright — tudo integrado.

![Pipeline](https://img.shields.io/badge/pipeline-14%20fases-blue)
![Módulos](https://img.shields.io/badge/modulos-50+-green)
![Python](https://img.shields.io/badge/python-3.10+-yellow)
![Playwright](https://img.shields.io/badge/playwright-headless-purple)
![Licença](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Funcionalidades

### Descoberta Passiva (Fase 1)
- **Subdomínios** via 10+ fontes: subfinder, assetfinder, amass, crt.sh, theHarvester, OTX, urlscan, GitHub code search, reverse WHOIS
- **ASN & IP** via bgp.he.net, ipinfo.io, asnmap — mapeamento completo de CIDR
- **DNS** — A, MX, TXT, CNAME, NS, SOA, SPF, DMARC, DKIM, DNSSEC, zone transfer
- **Domínios relacionados** — typosquatting, reverse WHOIS, domínios irmãos

### Intel & OSINT (Fase 1b)
- **Shodan** — hosts, portas, vulnerabilidades por IP
- **Breach data** — HIBP, Dehashed, LeakIX, IntelX
- **CertStream** — monitoramento em tempo real de CT logs
- **Mobile** — APK recon via Google Play + apkleaks (URIs, endpoints, secrets)
- **Phishing** — monitoramento de phishing, opensquat
- **Postman** — coleções públicas com endpoints/creds

### Supply Chain & Cloud (Fase 1c)
- **Dependency confusion** — npm, PyPI, RubyGems, NuGet, Packagist, Cargo, Hex
- **Cloud assets** — S3, Azure, GCP bucket discovery
- **Container registry** — scan de registries Docker/GCR/ECR

### Validação DNS (Fase 3)
- **Brute-force** via dnsgen + dnsx/massdns/shuffledns
- **Leaks** via trufflehog + GitHub code search
- **Git exposed** — detecção de .git exposto

### Perfil do Alvo (Fase 4)
- **WAF detection** — wafw00f + custom signatures (Cloudflare, Akamai, AWS, Imperva, etc.)
- **Tech stack** — wappalyzer, wappalyzergo, whatweb
- **Security headers** — CSP, HSTS, X-Frame-Options, cookies, CORS
- **Vendor fingerprint** — servidores, banners, redirects
- **Origin discovery** — bypass de CDN/Cloudflare (MX, SPF, certs Shodan)

### JavaScript Recon (Fases 4b-4c)
- **Descoberta** via katana, subjs, getJS, gau
- **Endpoints** via LinkFinder — paths, APIs, tokens em JS
- **Secrets** via SecretFinder (35 patterns + source maps)
- **Source maps** — reconstrução de código fonte via .map files

### Crawling & Screenshots (Fase 5)
- **Wayback URLs** via gau + Wayback CDX
- **urlfinder** — CommonCrawl + OTX + Wayback
- **Browser crawl** via Playwright headless (BFS, executa JS, captura SPA routes)
- **Screenshots** via gowitness
- **Favicon hunt** — fingerprint via mmh3 + Shodan

### Enumeração Ativa (Fase 6)
- **VHOST discovery** via ffuf (Host header fuzzing)
- **Parameter mining** via arjun + paramspider
- **Origin discovery** — bypass CDN/WAF

### Port Scan (Fase 7)
- **54 portas TCP** via naabu/nmap
- **25 portas UDP** via nmap
- **Cloudlist** — IPs de cloud providers (AWS/GCP/Azure)

### Serviços & CMS (Fase 7b)
- **Banner grabbing** em serviços comuns (HTTP, SSH, FTP, SMTP, MySQL, etc.)
- **CMS scan** — WordPress (wpscan), Drupal (droopescan), Joomla (joomscan)
- **Database probes** — MySQL, PostgreSQL, MSSQL, Oracle, MongoDB

### Vuln Scan (Fase 9)
- **Subdomain takeover** — CNAME/DNS check + subjack
- **CVE lookup** — NVD API por produto/versão detectados
- **CORS misconfig** — origin reflection, null origin
- **Default credentials** — serviços comuns
- **GraphQL** — introspection, field suggestion
- **Open redirect**, SMTP probe, SNMP probe, host header injection

### Nuclei (Fase 10)
- **Template-based scan** — API panels, tokens, exposures, misconfigs
- Templates específicos para cada tecnologia detectada

### Browser Pentest (Playwright Agent)
- **Spider BFS** com execução JS — captura SPA routes, APIs, forms
- **Análise de auth** — multi-role, token patterns, OAuth flows
- **CSP analyzer** — bypass vectors, unsafe-inline, wildcards
- **PostMessage** — listeners, origem wildcard, insecure handlers
- **DOM XSS** — sources/sinks, prototype pollution
- **IDOR mapper** — padrões de ID, role swapping
- **Input surface** — forms, WebSocket, file upload
- **Race mapper** — endpoints paralelizáveis, race conditions
- **GraphQL** — introspection, queries, mutations
- **Token analyzer** — JWT, API keys, session tokens

---

## Arquitetura

```
server.py (Flask)
  ├── routes/              API REST (7 blueprints, 80+ rotas)
  │   ├── core.py          Auth, admins, settings
  │   ├── recon.py         Pipeline, módulos individuais, SSE
  │   ├── assets.py        Empresas, ferramentas, checkpoints
  │   ├── scans.py         Histórico, screenshots, asm_data
  │   ├── ops.py           Agendamento, webhooks, whitelist, diff
  │   └── reporting.py     Risk score, export, findings
  ├── core/
  │   ├── pipeline.py      ReconRunner — motor de execução (14 fases)
  │   ├── recon.py         ~10K linhas — 50+ funções run_*
  │   ├── database.py      ASMDatabase — SQLite WAL mode
  │   ├── jobs.py          JobScheduler — fila FIFO com prioridade
  │   ├── targets.py       Seleção/normalização de domínios
  │   ├── checkpoints.py   Fingerprint de hosts + diff
  │   ├── rbac.py          Controle de acesso (super_admin/analyst)
  │   └── validators.py    Validação de entrada
  ├── utils/
  │   ├── tools.py         Registro de 24 ferramentas externas
  │   ├── tool_gate.py     Controle de concorrência por ferramenta
  │   ├── command_runner.py  Subprocess executor com timeout/stdin guard
  │   ├── rate_limiter.py  Rate limiting adaptativo por fase
  │   ├── dep_confusion.py Dependency confusion (npm/PyPI/RubyGems/etc.)
  │   ├── resource_profile.py  Auto-detecção CPU/RAM p/ VPS
  │   ├── mullvad_rotator.py   Rotação de VPN Mullvad
  │   ├── dns_tcp_proxy.py     Proxy DNS-over-TCP
  │   ├── http_cache.py        Cache de respostas HTTP
  │   └── alerting.py          Regras de alerta
  ├── playwright_agent/     Recon baseado em browser (Chromium headless)
  │   ├── agent.py          Entrypoint principal
  │   ├── crawler.py        Spider BFS com execução JS
  │   ├── js_analyzer.py    Secrets, endpoints, source maps
  │   ├── csp_analyzer.py   Análise de CSP
  │   ├── dom_xss.py        DOM XSS sources/sinks
  │   ├── idor_mapper.py    IDOR pattern detection
  │   └── ...               +12 módulos especializados
  ├── static/               Frontend SPA (vanilla JS + CSS)
  │   ├── index.html        Shell da aplicação
  │   └── js/               dashboard.js (10K linhas), api.js, asm.js
  ├── bin/                  35+ binários (Go, Python)
  ├── wordlists/            Wordlists de fuzzing/brute (~220 MB)
  └── config/               Estado em JSON (admins, empresas, settings)
```

---

## Perfis de Execução

| Perfil | Uso | Fases | Limite |
|--------|-----|-------|--------|
| `passive_bulk` | Varredura de milhares de domínios | Fase 1 | Seguro para fila grande |
| `active_light` | Validação de hosts vivos | Fases 4-6 | Máx 25 hosts |
| `active_heavy` | Testes pesados | Fases 7-10 | Máx 5 hosts |
| `full` | Pipeline completo | Todas as 14 fases | ~3-4h por domínio (~30K linhas de código) |

Threads, processos e rate limits se adaptam automaticamente ao hardware da máquina (CPU/RAM/swap) via `utils/resource_profile.py`.

---

## Instalação

```bash
# Clone
git clone https://github.com/Willian-2-0-0-1/scantrely.git
cd scantrely

# Dependências de sistema (Debian/Ubuntu/Kali)
sudo apt install -y nmap masscan chromium libnss3 libatk-bridge2.0-0 libgbm1 libasound2

# Dependências Python
pip install -r requirements.txt

# Instalar 35+ ferramentas externas (subfinder, nuclei, httpx, etc.)
bash install_tools.sh

# Instalar Playwright + Chromium (browser recon)
PLAYWRIGHT_BROWSERS_PATH="$HOME/.asm-playwright" python3 -m playwright install chromium

# Iniciar servidor
bash restart_server.sh
```

Acesse `http://localhost:5000` — login padrão: `admin` / `admin`

> **Troque a senha imediatamente** via Settings.

### Dependências Python (`requirements.txt`)

```
flask>=3.0, flask-limiter>=3.0, gunicorn>=21.0
httpx>=0.27, playwright>=1.45
jinja2>=3.1, pyyaml>=6.0
psycopg2-binary>=2.9 (opcional), celery>=5.3 (opcional), redis>=5.0 (opcional)
```

---

## Variáveis de Ambiente

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `ASM_JOB_WORKERS` | 1 | Jobs simultâneos |
| `ASM_GLOBAL_PROC_LIMIT` | 6 | Subprocessos máximo global |
| `ASM_DOMAIN_FANOUT_WORKERS` | 3 | Domínios em paralelo por módulo |
| `ASM_GATE_DEFAULT` | 3 | Concorrência padrão por ferramenta |
| `ASM_GATE_SUBFINDER` | 3 | Limite subfinder |
| `ASM_GATE_HTTPX` | 3 | Limite httpx |
| `ASM_GATE_NUCLEI` | 1 | Limite nuclei (pesado) |
| `ASM_GATE_NAABU` | 1 | Limite naabu (pesado) |
| `ASM_WATCHDOG_MAX_LOAD` | 4 | Pausa fila se load > N |
| `ASM_WATCHDOG_MIN_MEM_MB` | 1536 | Pausa fila se RAM livre < N MB |
| `ASM_WATCHDOG_MAX_RECON_PROCS` | 10 | Pausa fila se subprocessos > N |
| `ASM_ENABLE_SCHEDULED_SCANS` | 0 | Liga scans agendados automáticos |
| `ASM_AUTO_PROFILE` | 1 | Auto-detecção de recursos da VPS |

---

## API Keys Suportadas

| Serviço | Key | Módulos |
|---------|-----|---------|
| GitHub | `github_token` | leaks, github_subdomains |
| Shodan | `shodan_key` | shodan, origin_discovery, favicon |
| HIBP | `hibp_key` | breach |
| Dehashed | `dehashed_key` | breach |
| NVD (NIST) | `nvd_key` | cve |
| WhoisXML | `whoisxml_key` | reverse_whois |
| Chaos (PD) | `chaos_key` | subfinder |
| SecurityTrails | `securitytrails_key` | passive |
| Censys | `censys_api_id` + `censys_api_secret` | passive |
| VirusTotal | `virustotal_key` | various |
| LeakIX | `leakix_key` | breach |
| IntelX | `intelx_key` | breach |
| Netlas | `netlas_key` | passive |
| FOFA | `fofa_email` + `fofa_key` | passive |
| FullHunt | `fullhunt_key` | subfinder |
| BinaryEdge | `binaryedge_key` | subfinder |
| Hunter.io | `hunter_key` | theharvester |
| DNSDumpster | `dnsdumpster_token` | dns |

Todas as chaves são opcionais. Módulos sem key retornam dados parciais ou pulam sem erro.

---

## API REST

```bash
# Autenticação
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
# → {"token": "<hex>", "role": "super_admin"}

# Criar empresa
curl -X POST http://localhost:5000/api/companies \
  -H "X-Auth-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Example Inc","domains":["example.com"],"org":"Example"}'

# Iniciar pipeline
curl -X POST http://localhost:5000/api/recon/example-inc/pipeline \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d '{"profile":"full","mode":"balanced"}'

# Status do pipeline (SSE em tempo real)
curl http://localhost:5000/api/recon/example-inc/pipeline/stream \
  -H "X-Auth-Token: $TOKEN"

# Módulo individual
curl -X POST http://localhost:5000/api/recon/example-inc/subfinder \
  -H "X-Auth-Token: $TOKEN"

# Dados completos da empresa
curl http://localhost:5000/api/data \
  -H "X-Auth-Token: $TOKEN"

# Screenshots
curl http://localhost:5000/api/screenshots/example-inc \
  -H "X-Auth-Token: $TOKEN"

# Exportar relatório
curl "http://localhost:5000/api/export/example-inc?format=html" \
  -H "X-Auth-Token: $TOKEN"

# Limpar dados de scan
curl -X DELETE http://localhost:5000/api/recon/example-inc/data \
  -H "X-Auth-Token: $TOKEN"
```

---

## Pipeline de Recon (14 Fases)

| # | Fase | Módulos | Gate |
|---|------|---------|------|
| 1 | Passive Discovery | subfinder, assetfinder, amass, theharvester, crt.sh, github_subdomains, reverse_whois, related, typosquat, zone_transfer, dns, email, certs, asn, asnmap | — |
| 1b | Intel & OSINT | shodan, breach, certstream, phishing, postman, apk_recon | — |
| 1c | Supply Chain | dep_confusion, cloud, container_registry | — |
| 2 | Cleanup | (interno) | — |
| 3 | Validation | dns_brute, leaks | has_live_hosts |
| 4 | Profiling | headers, waf, wappalyzer, whatweb, vendor_fp | has_live_hosts |
| 4b | JS Discovery | js | has_live_hosts |
| 4c | JS Analysis | js_endpoints, js_secrets | has_live_hosts |
| 5 | Crawl | wayback, urlfinder, gowitness, favicon_hunt, browser_crawl | — |
| 6 | Active Enum | vhost, param_mine, origin_discovery | has_live_hosts |
| 7 | Port Scan | portscan, cloudlist | has_live_hosts |
| 7b | Services | services, cms_scan | has_open_ports |
| 9 | Vuln Scan | takeover, subjack, cve, cors_scan, default_creds, graphql, open_redirect, smtp, snmp, host_header_injection, infra_exposure | has_live_hosts |
| 10 | Nuclei | api_panels | has_live_hosts |

---

## Segurança

- **Autenticação**: Bearer token, PBKDF2-SHA256 (260K iterações), expiração 12h
- **RBAC**: `super_admin` (acesso total) e `analyst` (escopo por empresa)
- **Rate limit de login**: 10 falhas/IP → bloqueio 15 min
- **Timeout global**: todo subprocesso com timeout padrão de 300s
- **stdin guard**: `subprocess stdin=DEVNULL` — evita prompt em /dev/tty
- **SQLite busy_timeout**: 5000ms — elimina retry storms
- **Watchdog**: monitora load, RAM livre e processos — pausa fila automaticamente
- **ToolGate**: limite de concorrência por ferramenta (nuclei=1, naabu=1, httpx=3, etc.)
- **Rate limiter adaptativo**: reduz taxa em 50% ao detectar 403/429, recupera gradualmente
- **Checkpoints**: cada módulo salva progresso — pipeline pode ser retomado após crash
- **Auto-profile VPS**: limites ajustados automaticamente por CPU/RAM/swap
- **Modo stealth**: ativado automaticamente ao detectar Cloudflare/AWS WAF

---

## Licença

MIT — veja [LICENSE](LICENSE)
