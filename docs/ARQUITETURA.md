# ASM Platform — Architecture & Maintenance Guide

## Índice

1. [Visão Geral](#visão-geral)
2. [Estrutura de Arquivos](#estrutura-de-arquivos)
3. [Inicialização e Serviço](#inicialização-e-serviço)
4. [Autenticação](#autenticação)
5. [Banco de Dados (SQLite)](#banco-de-dados-sqlite)
6. [API — Blueprints e Rotas](#api--blueprints-e-rotas)
7. [Pipeline de Recon](#pipeline-de-recon)
8. [Módulos de Recon (recon.py)](#módulos-de-recon-reconpy)
9. [Rate Limiter Adaptativo](#rate-limiter-adaptativo)
10. [Sistema de Checkpoints](#sistema-de-checkpoints)
11. [Ferramentas Externas](#ferramentas-externas)
12. [Dashboard (dashboard.html)](#dashboard-dashboardhtml)
13. [Fluxo de Dados Ponta a Ponta](#fluxo-de-dados-ponta-a-ponta)
14. [Campos Críticos para o Frontend](#campos-críticos-para-o-frontend)
15. [Armadilhas Conhecidas](#armadilhas-conhecidas)
16. [Manutenção e Operação](#manutenção-e-operação)

---

## Visão Geral

Plataforma de **Attack Surface Management (ASM)** totalmente local. Orquestra 50+ ferramentas de recon em um pipeline de 13 fases e expõe os resultados em um dashboard SPA de aba única.

```
┌─────────────────────────────────────────────────────────┐
│  dashboard.html  (SPA — fetch /api/* com token de auth) │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP / SSE
┌──────────────────────▼──────────────────────────────────┐
│  server.py  (Flask — porta 5000)                        │
│  ├── core_routes.py    auth/admins/settings             │
│  ├── asset_routes.py   companies/tools/checkpoints      │
│  ├── scan_routes.py    history/screenshots/asm data     │
│  ├── recon_routes.py   módulos individuais + pipeline   │
│  ├── ops_routes.py     schedule/webhooks/whitelist/diff │
│  └── reporting_routes.py  risk/export/findings          │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│  pipeline.py  (ReconRunner)                             │
│  ├── Executa PIPELINE_PHASES em sequência               │
│  ├── Cada fase: módulos em threads paralelas            │
│  ├── Salva checkpoints JSON por módulo                  │
│  └── _persist_pipeline_results() → asm.db              │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│  recon.py  (funções de recon puras)                     │
│  rate_limiter.py  (AdaptiveRateLimiter por thread)      │
│  checkpoints.py   (fingerprint de hosts live)           │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│  asm.db  (SQLite — fonte de verdade)                    │
│  Espelhos: companies.json, settings.json, admins.json   │
└─────────────────────────────────────────────────────────┘
```

---

## Estrutura de Arquivos

```
/home/kali/recon/asm/
├── server.py              — entry point Flask, monta todos os blueprints
├── pipeline.py            — ReconRunner + PIPELINE_PHASES
├── recon.py               — ~3500 linhas com todas as funções de recon
├── database.py            — ASMDatabase (SQLite + migração de legado)
├── rate_limiter.py        — AdaptiveRateLimiter por thread
├── checkpoints.py         — fingerprint de hosts para detetar mudanças
├── tools.py               — registry de ferramentas externas
├── core_routes.py         — Blueprint: auth, admins, settings, presets
├── asset_routes.py        — Blueprint: companies, tools, checkpoints
├── scan_routes.py         — Blueprint: histórico, screenshots, asm data
├── recon_routes.py        — Blueprint: módulos de recon, pipeline SSE
├── ops_routes.py          — Blueprint: schedule, webhooks, whitelist, diff
├── reporting_routes.py    — Blueprint: risk, export HTML/JSON, findings
├── dashboard.html         — SPA frontend (HTML + JS + CSS embutidos)
├── asm.db                 — SQLite (fonte de verdade)
├── asm_data.js            — espelho JSON do asm.db (para compatibilidade)
├── companies.json         — espelho JSON de companies
├── settings.json          — espelho JSON de settings
├── admins.json            — espelho JSON de admins
├── schedules.json         — espelho JSON de schedules
├── webhooks.json          — espelho JSON de webhooks
├── whitelist.json         — espelho JSON de whitelist
├── audit.log              — espelho JSON de audit log
├── install_tools.sh       — instala todas as ferramentas externas
├── requirements.txt       — dependências Python
├── bin/                   — binários instalados pelo install_tools.sh
├── scans/                 — saídas brutas dos scans por empresa
│   └── {cid}/
│       ├── {scan_name}/   — saída BBOT (output.ndjson, scan.log, asm_run.log)
│       └── screenshots/   — imagens do gowitness
├── checkpoints/           — checkpoints de fingerprint de hosts
│   └── {cid}.json
└── snapshots/             — snapshots de dados ASM para diff
    └── {cid}/current.json
```

---

## Inicialização e Serviço

### Início manual

```bash
cd /home/kali/recon/asm
python3 server.py --host 127.0.0.1 --port 5000
```

### systemd (`/etc/systemd/system/asm.service`)

```ini
[Unit]
Description=ASM Platform

[Service]
WorkingDirectory=/home/kali/recon/asm
ExecStart=/usr/bin/python3 server.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
systemctl start asm
systemctl enable asm
systemctl status asm
journalctl -u asm -f
```

### Inicialização do banco

Em `server.py`, na inicialização:

```python
DB = ASMDatabase(DB_FILE, ...)
DB.initialize()          # cria tabelas se não existirem
DB.migrate_from_legacy() # importa JSON legados para o SQLite
```

`DB.initialize()` cria as tabelas:
`settings`, `admins`, `companies`, `asm_data`, `schedules`, `webhooks`,
`whitelist`, `audit_log`, `subdomain_history`, `snapshots`, `schema_version`.

### PATH de ferramentas

```python
_BIN_DIR  = BASE / "bin"          # instalacos pelo install_tools.sh
_VENV_BIN = BASE / ".venv" / "bin"
os.environ["PATH"] = f"{_BIN_DIR}:{_VENV_BIN}:{original_PATH}"
```

---

## Autenticação

Todas as rotas de API (exceto `GET /` e `POST /api/auth/login`) são protegidas pelo decorator `@require_auth`.

### Login

```
POST /api/auth/login
Body: {"username": "admin", "password": "admin"}
Response: {"token": "<hex>", "username": "admin", "role": "admin"}
```

O token é armazenado em `_sessions` (dict em memória, expira em 12h). Senhas são armazenadas com PBKDF2-HMAC-SHA256 (260.000 iterações).

### Uso do token no frontend

```javascript
// O dashboard armazena o token em localStorage["asmToken"]
function _authHeaders() {
    return {"X-Auth-Token": localStorage.getItem("asmToken") || ""};
}
// Toda chamada fetch deve incluir:
fetch("/api/...", {headers: _authHeaders()})
```

**Atenção**: qualquer `fetch()` sem `{headers: _authHeaders()}` vai receber 401 silenciosamente.

---

## Banco de Dados (SQLite)

Arquivo: `asm.db`. Classe: `ASMDatabase` em `database.py`.

### Tabelas principais

| Tabela | Conteúdo |
|---|---|
| `settings` | Chaves API e configurações globais (KV store) |
| `admins` | Usuários (username, salt, hash, role) |
| `companies` | Lista de empresas alvo com todos os dados de scan |
| `asm_data` | Blob JSON com todo o estado do dashboard (`{companies:[...]}`) |
| `schedules` | Agendamentos de pipeline por empresa |
| `webhooks` | Destinos de webhook para notificações |
| `whitelist` | IPs/CIDRs a ignorar nas varreduras |
| `audit_log` | Log de ações dos admins |
| `subdomain_history` | Histórico de subdomínios por empresa (timeline) |
| `snapshots` | Snapshots de dados ASM para calcular diff |
| `schema_version` | Versão atual do schema (para migrações futuras) |

### Estrutura de dados de uma empresa (`companies` / `asm_data`)

```json
{
  "id": "red-bull",
  "name": "Red Bull",
  "domains": ["redbull.com", "redbull.at"],
  "org": "Red Bull GmbH",

  "hosts": [
    {
      "host": "www.redbull.com",
      "ip": "1.2.3.4",
      "status_code": 200,
      "title": "Red Bull — Home",
      "server": "cloudflare",
      "waf": "Cloudflare",
      "technologies": ["Next.js", "React"],
      "ports": [80, 443]
    }
  ],

  "stats": {
    "live_hosts": 171,
    "subdomains": 171,
    "findings_critical": 3,
    "findings_high": 12,
    "findings_medium": 45,
    "findings_info": 89,
    "open_ports": 234,
    "waf_protected": 8
  },

  "findings": [
    {
      "key": "CVE-2023-XXXX",
      "title": "...",
      "severity": "critical|high|medium|low|info",
      "category": "cve|takeover|headers|leaks|...",
      "host": "...",
      "description": "..."
    }
  ],

  "port_scan": {
    "results": [{"ip": "1.2.3.4", "port": 443, "service": "https"}],
    "ips_scanned": 50,
    "scanned_at": "2025-01-01T00:00:00"
  },

  "waf_coverage": {"Cloudflare": 8, "AWS WAF": 2},
  "waf_results": {"results": [...]},
  "asns": [{"asn": "AS13335", "org": "Cloudflare"}],
  "asn_data": {"asns": [...], "cidr_ranges": [...]},
  "cidr_ranges": ["104.16.0.0/12"],
  "asn_numbers": ["AS13335"],

  "emails": ["admin@redbull.com"],
  "ct_subdomains": ["sub1.redbull.com", "sub2.redbull.com"],
  "cve_findings": [{"cve_id": "...", "severity": "...", "product": "..."}],
  "cve_summary": {"total": 10, "critical": 2, "high": 5},
  "shodan_hosts": [{"ip": "...", "ports": [...], "vulns": [...]}],
  "breach_data": {"emails": [...], "total": 100},

  "wayback_data": {"interesting": [...], "total_urls": 5000},
  "urlfinder_data": {"urls": ["https://..."]},
  "js_data": {"js_files": [...], "total_secrets": 3},
  "tech_index": {"Next.js": ["www.redbull.com", "app.redbull.com"]},
  "tech_summary": {"Next.js": 2, "Cloudflare": 8},
  "tech_queried": true,

  "dns_data": {"A": [...], "MX": [...], "TXT": [...], "records": [...]},
  "headers_data": {"results": [{"host": "...", "findings": [...]}]},
  "leaks_data": {"git_exposed": [...], "github": {"results": [...]}},
  "api_exposure": {"results": [...]},
  "secrets_findings": [...],
  "screenshots_count": 45,

  "pipeline_ran_at": "2025-01-01T12:00:00",
  "last_scan": "2025-01-01T12:00:00",
  "not_done": ["vhost", "param_mine"]
}
```

### Métodos principais de ASMDatabase

```python
db.load_asm_data()           # → {companies: [...]}
db.save_asm_data(data)       # salva + espelha para asm_data.js
db.load_companies()          # → lista de empresas (sem dados de scan pesados)
db.save_companies(companies)
db.get_settings(keys=None)   # → dict de settings
db.set_settings(values)
db.load_admins() / save_admins()
db.append_audit_log(entry)
db.insert_subdomain_history(cid, subdomain, ...)
db.get_subdomain_history(cid, limit=1000)
db.save_snapshot(cid, payload, slot="current")
db.load_snapshot(cid, slot="current")
db.get_asm_data_timestamp()  # → float mtime
```

---

## API — Blueprints e Rotas

### core_routes.py — Autenticação e Configuração

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/presets` | Presets de configuração padrão |
| POST | `/api/auth/login` | Login — retorna token |
| POST | `/api/auth/logout` | Invalida sessão |
| GET | `/api/auth/me` | Info do usuário autenticado |
| GET | `/api/admins` | Lista admins |
| POST | `/api/admins` | Cria admin |
| PUT | `/api/admins/<aid>` | Atualiza admin |
| DELETE | `/api/admins/<aid>` | Remove admin |
| GET | `/api/settings` | Lê settings (chaves API) |
| POST | `/api/settings` | Salva settings |

### asset_routes.py — Empresas e Ferramentas

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/companies` | Lista empresas |
| POST | `/api/companies` | Cria empresa |
| PUT | `/api/companies/<cid>` | Atualiza empresa |
| DELETE | `/api/companies/<cid>` | Remove empresa |
| GET | `/api/tools/status` | Status das ferramentas externas |
| POST | `/api/tools/run` | Instala ferramentas |
| GET | `/api/tools/result` | Resultado da instalação |
| POST | `/api/validate-domains` | Valida domínios da empresa |
| GET | `/api/checkpoints/<cid>` | Lista checkpoints de hosts |
| POST | `/api/checkpoints/<cid>/scan` | Roda fingerprint de hosts |
| GET | `/api/checkpoints/job/<scan_id>` | Status do job de fingerprint |
| POST | `/api/dnsdumpster/<cid>` | Compara com DNSDumpster |

### scan_routes.py — Histórico e Screenshots

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/data` | Retorna todo asm_data (empresas + scan data) |
| GET | `/api/data/ts` | Timestamp do último save |
| GET | `/api/data/<cid>/subhistory` | Histórico de subdomínios |
| GET | `/api/scan-history/<cid>` | Lista scans BBOT da empresa |
| DELETE | `/api/scan-history/<cid>/<scan_name>` | Remove scan específico |
| DELETE | `/api/scan-history/<cid>` | Remove todos os scans |
| GET | `/api/scan-history/<cid>/<scan_name>/log` | Linhas do log do scan |
| POST | `/api/scan-history/<cid>/<scan_name>/reparse` | Re-parseia saída BBOT |
| GET | `/api/screenshots/<cid>` | Lista screenshots com metadata |
| GET | `/screenshots/<cid>/<filename>` | Serve imagem de screenshot |

### recon_routes.py — Módulos e Pipeline

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/recon/modules` | Lista todos os módulos disponíveis |
| POST | `/api/recon/<cid>/<module>` | Executa módulo individual |
| POST | `/api/recon/<cid>/pipeline` | Inicia pipeline completo |
| GET | `/api/recon/<cid>/pipeline` | Status do pipeline (fases + módulos) |
| GET | `/api/recon/<cid>/pipeline/stream` | SSE stream de log do pipeline |
| GET | `/api/recon/<cid>/tool-logs` | Logs de ferramentas externas executadas |
| DELETE | `/api/recon/<cid>/tool-logs` | Limpa logs de ferramentas |
| GET/DELETE | `/api/recon/<cid>/<module>` | Resultado de módulo / delete de dados |
| GET | `/api/recon/<cid>` | Resumo de todos os módulos |

**Deleção de dados de scan**: `DELETE /api/recon/<cid>/data` remove todos os campos de scan da empresa no banco.

### ops_routes.py — Operações

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/schedule` | Lista todos os agendamentos |
| GET/POST/DELETE | `/api/schedule/<cid>` | Agendamento por empresa |
| GET/POST | `/api/webhooks` | Webhooks de notificação |
| POST | `/api/webhooks/test` | Testa webhook |
| GET | `/api/diff/<cid>` | Diff entre snapshot atual e anterior |
| GET/POST | `/api/whitelist/<cid>` | Whitelist de IPs/CIDRs |
| DELETE | `/api/whitelist/<cid>/<wid>` | Remove entrada da whitelist |
| GET | `/api/audit` | Log de auditoria |

### reporting_routes.py — Relatórios

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/risk/<cid>` | Score de risco calculado |
| GET | `/api/export/<cid>` | Exporta relatório (HTML ou JSON) |
| GET | `/api/findings/all` | Todos os findings de todas as empresas |

---

## Pipeline de Recon

### Fases do Pipeline (`PIPELINE_PHASES` em `pipeline.py`)

| Fase | ID | Label | Módulos | Paralelo | Gate |
|---|---|---|---|---|---|
| 1 | `passive` | Discovery Passivo | subfinder, assetfinder, theharvester, dns, email, certs, asn, asnmap, related, typosquat, zone_transfer | ✓ | — |
| 1b | `intel` | Intel & OSINT | shodan, breach, certstream | ✓ | — |
| 1c | `supply_chain` | Supply Chain & Cloud | dep_confusion, cloud | ✓ | — |
| 2 | `cleanup` | Cleanup Automático | (interno) | — | — |
| 3 | `validation` | Validação & DNS Brute | dns_brute, leaks | ✓ | has_live_hosts |
| 4 | `profiling` | Perfil do Alvo | headers, waf, wappalyzer, wappalyzergo, whatweb | ✓ | has_live_hosts |
| 4b | `js_tech` | JS & Tech Discovery | js, js_endpoints, js_secrets | ✓ | has_live_hosts |
| 5 | `crawl` | Crawl & Discovery | wayback, urlfinder, screenshot, gowitness, favicon_hunt | ✓ | — |
| 6 | `enum_active` | Enum Ativa | vhost, param_mine | ✓ | has_live_hosts |
| 7 | `portscan` | Port Scan | portscan, cloudlist | ✓ | has_live_hosts |
| 7b | `services` | Serviços & CMS | services, cms_scan | ✓ | has_open_ports |
| 9 | `vulnscan` | Vuln Scan | takeover, subjack, cve, cloud_enum | ✓ | has_live_hosts |
| 10 | `nuclei` | Nuclei Scan | api_panels | — | has_live_hosts |

### Gates de progressão

- `has_live_hosts`: fase só executa se `co_data["hosts"]` não estiver vazio
- `has_open_ports`: fase só executa se `co_data["port_scan"]["results"]` existir

### Checkpoint/Resume

Cada módulo salva seu resultado em `scans/{cid}/.checkpoints/{module}.json`. Se o processo morrer e for reiniciado, os módulos já completos são pulados.

```python
# Salva
checkpoint_dir = base_dir / "scans" / cid / ".checkpoints"
checkpoint_dir.mkdir(parents=True, exist_ok=True)
(checkpoint_dir / f"{module}.json").write_text(json.dumps(result))

# Carrega (no início do pipeline)
cp_file = checkpoint_dir / f"{module}.json"
if cp_file.exists():
    result = json.loads(cp_file.read_text())
    # pula execução do módulo
```

### `_persist_pipeline_results()` — a função central

Chamada ao final do pipeline (e opcionalmente após cada fase). Lê todos os checkpoints e constrói o estado completo da empresa no banco:

1. Lê todos os módulos do `scans/{cid}/.checkpoints/`
2. Faz merge de hosts com `_merge_hosts_into_asm_data()`
3. Constrói `findings` (takeover + CVE crítico/alto + headers misconfigs + leaks)
4. Reconstrói `tech_summary` de `tech_index`
5. Atualiza `stats` completo (live_hosts, subdomains, findings_*, open_ports, waf_protected)
6. Salva `last_scan` e `pipeline_ran_at`
7. Chama `db.save_asm_data()`

### `_probe_hosts_with_httpx()` — validação de hosts vivos

Usa `httpx` com saída JSON para testar quais subdomínios respondem HTTP/HTTPS.

**Atenção**: a saída JSON do httpx usa `status_code` (com underscore), não `status-code` (com hífen).

```python
# CORRETO:
"status_code": item.get("status_code"),
# ERRADO (bug histórico):
"status_code": item.get("status-code"),  # sempre None!
```

### `_merge_hosts_into_asm_data()` — merge de hosts

Atualiza hosts existentes em vez de duplicar. A lógica:

```python
existing_map = {h["host"]: h for h in co.get("hosts", [])}
for new_host in new_hosts:
    if new_host["host"] not in existing_map:
        co["hosts"].append(new_host)
    else:
        ex = existing_map[new_host["host"]]
        # Só preenche campos vazios, nunca sobrescreve dados existentes
        for field in ["status_code", "title", "server", "technologies", "ports"]:
            if not ex.get(field) and new_host.get(field):
                ex[field] = new_host[field]
```

---

## Módulos de Recon (recon.py)

### Mapa completo de módulos → funções

| Módulo | Função principal | Ferramentas externas | Chave de resultado |
|---|---|---|---|
| `subfinder` | `ReconRunner.run_subfinder()` | subfinder | hosts[] |
| `assetfinder` | `run_assetfinder()` | assetfinder | hosts[] |
| `theharvester` | `run_theharvester()` | theHarvester | emails, hosts[] |
| `dns` | `dns_records()` | dig, Python socket | dns_data |
| `email` | `run_email_recon()` | dig (SPF/DMARC/MX) | emails, dns_data |
| `certs` | `run_cert_recon()` | crt.sh API, certspotter | ct_subdomains |
| `asn` | `run_asn_recon()` | bgp.he.net, ipinfo | asns, asn_data, cidr_ranges |
| `asnmap` | inline | asnmap | asn_numbers |
| `related` | `run_related_domains()` | DNS resolve | related domains |
| `typosquat` | `run_typosquatting()` | DNS resolve | typo variants |
| `zone_transfer` | `run_zone_transfer()` | dig AXFR | zone data |
| `shodan` | `run_shodan()` | Shodan API | shodan_hosts |
| `breach` | `run_breach_check()` | HaveIBeenPwned, dehashed, leakix | breach_data |
| `certstream` | inline | certstream-python | live CT stream |
| `dep_confusion` | `dep_confusion.py` | pip, npm, Go module check | dep confusion |
| `cloud` | `run_cloud_assets()` | HTTP (S3/Azure/GCP) | cloud assets |
| `dns_brute` | `run_dns_bruteforce()` | massdns, dnsx, wordlist | hosts[] |
| `leaks` | `run_leaks_recon()` | trufflehog, GitHub API | leaks_data |
| `headers` | `run_headers_bulk()` | httpx, curl | headers_data |
| `waf` | `run_waf_detection()` | wafw00f, curl | waf_coverage, waf_results |
| `wappalyzer` | `run_wappalyzer()` | wappalyzer (Node) | tech_index, tech_summary |
| `wappalyzergo` | inline | wappalyzergo | tech_index |
| `whatweb` | `run_whatweb()` | WhatWeb | tech_index |
| `js` | `run_js_recon()` | httpx, Python regex | js_data |
| `js_endpoints` | inline | gau, waybackurls | js endpoints |
| `js_secrets` | inline | trufflehog, nuclei-js | secrets_findings |
| `wayback` | `run_wayback()` | gau, waybackurls, Wayback CDX | wayback_data |
| `urlfinder` | inline | urlfinder, gau | urlfinder_data |
| `screenshot` | `run_screenshots()` | gowitness, aquatone | screenshots_count |
| `gowitness` | `run_gowitness()` | gowitness | screenshots_count |
| `favicon_hunt` | inline | httpx (favicon hash) | favicon data |
| `vhost` | inline | ffuf, httpx (Host header) | vhost data |
| `param_mine` | inline | arjun, paramspider | param data |
| `portscan` | `run_port_scan()` | naabu, nmap | port_scan |
| `cloudlist` | inline | cloudlist | cloud IPs |
| `services` | `run_services_recon()` | netcat, curl | services |
| `cms_scan` | `run_cms_scan_smart()` | wpscan, droopescan, joomscan | CMS vulns |
| `takeover` | `run_takeover_check()` | Python (CNAME + DNS check) | findings[takeover] |
| `subjack` | inline | subjack | findings[takeover] |
| `cve` | inline | NVD API (por produto detectado) | cve_findings, cve_summary |
| `cloud_enum` | `run_cloud_assets()` | HTTP checks | cloud exposure |
| `api_panels` | `run_api_panels_smart()` | nuclei, httpx | findings[api] |

### Funções auxiliares importantes em recon.py

```python
http_get(url, timeout, retries, ...)     # HTTP com retry, UA rotation e rate limit
dns_records(domain)                       # registros DNS (A, MX, TXT, CNAME, NS)
run_zone_transfer(domains)               # tenta AXFR em todos os NS
email_spoofability(spf, dmarc)          # avalia risco de spoofing
get_ct_certs(domain, limit=500)          # certs de crt.sh + certspotter
get_ssl_info(host, port=443)             # info TLS/SSL do host
_probe_url(url, timeout)                 # testa se URL responde HTTP
run_services_recon(host)                 # detecta serviços em portas comuns
search_github(domain, token)             # busca leaks no GitHub
_check_takeover(host)                    # verifica CNAME para serviço abandonado
_detect_waf(host)                        # fingerprint de WAF por headers/body
run_breach_check(domain, ...)            # HIBP + dehashed + leakix + trufflehog
run_js_recon(domains, hosts)             # analisa JS em busca de endpoints/secrets
run_screenshots(hosts, domains, ...)     # gowitness screenshots
run_dns_bruteforce(domain, hosts)        # brute com massdns/dnsx
```

---

## Rate Limiter Adaptativo

Arquivo: `rate_limiter.py`. Classe: `AdaptiveRateLimiter`.

### Perfis por fase e modo

| Fase | Stealth (req/s) | Balanced | Fast |
|---|---|---|---|
| `passive` | ilimitado | ilimitado | ilimitado |
| `dns` | 1.0 | 5.0 | 50.0 |
| `http` | 0.5 | 3.0 | 10.0 |
| `tech` | 0.3 | 2.0 | 5.0 |
| `crawl` | 0.2 | 1.0 | 3.0 |
| `fuzz` | 0.05 | 1.0 | 10.0 |
| `portscan` | 0.5 | 10.0 | 100.0 |
| `vulnscan` | 0.3 | 2.0 | 10.0 |

### Adaptação automática

- **403/429/timeout** → corta a taxa em 50% (piso: `min_rate`)
- **20 respostas 2xx consecutivas** → restaura 10% em direção à taxa base

### Ativação do modo stealth

O pipeline detecta automaticamente Cloudflare/AWS WAF durante a Fase 4 e ativa o modo stealth para as fases seguintes, independente do modo escolhido pelo usuário.

### Uso por thread

```python
from rate_limiter import make_limiter, set_limiter, clear_limiter, wait, signal

lim = make_limiter("tech", "balanced")
set_limiter(lim)
try:
    wait()                  # bloqueia até permitido
    resp = requests.get(url)
    signal(resp.status_code)  # alimenta o adaptador
finally:
    clear_limiter()
```

---

## Sistema de Checkpoints

Arquivo: `checkpoints.py`. Usado pela feature de "scan incremental" — detecta quais hosts mudaram desde o último scan.

### Fluxo

```
fingerprint_hosts(urls)     → dict[url, HostFingerprint]
load_checkpoints(cid)       → dict[url, HostFingerprint]  (do disco)
diff(old, new)              → CheckpointDiff
save_checkpoints(cid, new)  → salva em checkpoints/{cid}.json
```

### HostFingerprint

Campos rastreados por host:
- `status_code`, `title`, `server`
- `content_hash` — SHA256 do body normalizado (sem tokens dinâmicos, CSRF nonces, timestamps)
- `js_hash` — SHA256 das URLs de JS ordenadas
- `headers_hash` — SHA256 dos security headers rastreados
- `content_length`, `redirect_url`, `js_urls`

### Padrões dinâmicos filtrados do body

`csrf_token`, `nonce`, timestamps ISO, unix timestamps, `_cache_buster`, ViewState.

### API REST

```
GET  /api/checkpoints/<cid>          → lista fingerprints + diff resumido
POST /api/checkpoints/<cid>/scan     → inicia novo scan de fingerprint (async)
GET  /api/checkpoints/job/<scan_id>  → status do job
```

---

## Ferramentas Externas

Instaladas em `bin/` pelo `install_tools.sh`. O PATH é ajustado no início do `server.py` para incluir `bin/` antes do PATH do sistema.

### Discovery / Enumeração

| Ferramenta | Uso |
|---|---|
| `subfinder` | Enumeração passiva de subdomínios (Certificate Transparency, APIs) |
| `assetfinder` | Subdomínios via várias fontes passivas |
| `theHarvester` | Emails, IPs, subdomínios via OSINT |
| `massdns` | Resolução DNS em massa (brute force) |
| `dnsx` | Resolução DNS + verificação de hosts vivos |
| `asnmap` | Mapeamento ASN → CIDRs |
| `cloudlist` | Lista IPs de provedores cloud (AWS/GCP/Azure/CF) |

### HTTP / Tech Detection

| Ferramenta | Uso |
|---|---|
| `httpx` | Probe HTTP bulk com saída JSON (`status_code`, `title`, `server`) |
| `wafw00f` | Fingerprint de WAF |
| `WhatWeb` | Detecção de tecnologias via HTTP |
| `wappalyzergo` | Detecção de stack (Go port do Wappalyzer) |

### Crawl / URLs

| Ferramenta | Uso |
|---|---|
| `gau` | URLs históricas (Wayback Machine + Common Crawl + OTX) |
| `waybackurls` | URLs do Wayback Machine |
| `urlfinder` | Extração de URLs de páginas e JS |
| `arjun` | Descoberta de parâmetros HTTP |
| `paramspider` | Mineração de parâmetros |

### Screenshots

| Ferramenta | Uso |
|---|---|
| `gowitness` | Screenshots de HTTP/HTTPS (saída: JPEG em `scans/{cid}/screenshots/`) |
| `aquatone` | Screenshots alternativos |

### Port Scan

| Ferramenta | Uso |
|---|---|
| `naabu` | Port scan rápido (Go) |
| `nmap` | Port scan detalhado com detecção de serviços |

### Vuln / Secrets

| Ferramenta | Uso |
|---|---|
| `nuclei` | Templates de vuln scan (api_panels, js-secrets) |
| `trufflehog` | Busca de secrets em repositórios Git |
| `subjack` | Verificação de subdomain takeover |
| `wpscan` | Scan específico para WordPress |
| `droopescan` | Scan para Drupal |
| `joomscan` | Scan para Joomla |
| `ffuf` | Fuzzing de vhosts e caminhos |

### Utilitários

| Ferramenta | Uso |
|---|---|
| `dig` | Consultas DNS (zone transfer, registros MX/TXT/NS) |
| `curl` | Requests HTTP com controle fino de headers |
| `openssl` | Inspecção de certificados TLS |

---

## Dashboard (dashboard.html)

SPA de página única. Todo o HTML, CSS e JS está em um único arquivo.

### Tabs principais

| Tab | ID | Conteúdo |
|---|---|---|
| Overview | `tab-overview` | Stats gerais, host table, gráficos |
| Findings | `tab-findings` | Lista de findings por severidade |
| CVE | `tab-cve` | CVEs por produto/host |
| Subdomains | `tab-subdomains` | Lista de subdomínios com status HTTP |
| Stack | `tab-stack` | Tecnologias detectadas |
| Ports | `tab-ports` | Resultados de port scan |
| Screenshots | `tab-screenshots` | Grid de screenshots |
| URLs / Wayback | `tab-urls` | URLs interessantes históricas |
| JS | `tab-js` | Arquivos JS analisados, secrets |
| Infra | `tab-infra` | ASN, CIDR, WAF/CDN, DNS, Leaks |
| Emails | `tab-emails` | Emails coletados |
| Breach | `tab-breach` | Dados de breach/HIBP |
| Scan History | `tab-history` | Scans BBOT anteriores |
| Pipeline | `tab-pipeline` | Status do pipeline com log SSE |

### Tab count badges

```html
<span id="tc-findings">0</span>
<span id="tc-cve">0</span>
<span id="tc-subdomains">0</span>
<span id="tc-stack">0</span>
<span id="tc-ports">0</span>
<span id="tc-screenshots">0</span>
<span id="tc-urls">0</span>
<span id="tc-js">0</span>
```

Populados por `updateTabCounts(co)` que lê:
- `tc-findings` ← `co.findings.length`
- `tc-cve` ← `co.cve_findings.length`
- `tc-subdomains` ← `co.hosts.length`
- `tc-stack` ← `Object.keys(co.tech_summary).length`
- `tc-ports` ← `co.stats.open_ports` (não `stats.live_hosts`!)
- `tc-screenshots` ← `co.screenshots_count`
- `tc-urls` ← `co.urlfinder_data.urls.length`
- `tc-js` ← `co.js_data.js_files.length`

### Funções JS principais

```javascript
_authHeaders()                     // → {X-Auth-Token: localStorage token}
reloadServerData()                 // GET /api/data + /api/companies
renderOverview(co)                 // aba overview — stats, host table, charts
renderFindingsTab(co)              // aba findings com filtros de severidade
renderCVETab(co)                   // aba CVE com agrupamento por produto
renderSubdomainsTab(co)            // tabela de hosts com status_code/WAF/tech
renderStackTab(co)                 // tech_summary em grid de cards
renderPortsTab(co)                 // port_scan.results em tabela
renderInfraTab(co)                 // ASN/CIDR/WAF/DNS/leaks — renderização dinâmica
loadScreenshots(cid)               // GET /api/screenshots/{cid} (requer auth header)
loadScanHistory(cid)               // GET /api/scan-history/{cid} (requer auth header)
startPipelineSSE(cid)              // abre SSE /api/recon/{cid}/pipeline/stream
updateTabCounts(co)                // atualiza badges numéricos das tabs
```

### Fluxo de renderização

```
page load
  → GET /api/auth/me  (verifica token salvo)
  → GET /api/data     (reloadServerData)
  → renderCompanyList()
  → selectCompany(cid)
    → renderOverview(co)
    → updateTabCounts(co)
    → renderActiveTab()
```

---

## Fluxo de Dados Ponta a Ponta

### 1. Criar empresa

```
POST /api/companies  {name, domains, org}
→ ASMDatabase.save_companies()
→ companies.json (espelho)
```

### 2. Iniciar pipeline

```
POST /api/recon/{cid}/pipeline  {mode: "balanced", shodan_key: "..."}
→ pipeline_state[cid] = {status: "running", ...}
→ threading.Thread(target=runner.run_pipeline, ...)
→ 202 Accepted
```

### 3. Pipeline em background

```
ReconRunner.run_pipeline(cid, company, options)
  Para cada PIPELINE_PHASES:
    Verifica gate (has_live_hosts / has_open_ports)
    Para cada módulo da fase (em threads paralelas):
      Verifica checkpoint existente
      Executa função de recon
      Salva checkpoint JSON em scans/{cid}/.checkpoints/{module}.json
      Atualiza pipeline_state[cid]["log"]
    Após fase: _probe_hosts_with_httpx() → merge hosts vivos
    Fase 4: detecta WAF → ativa stealth se CF/AWS WAF alto
  _persist_pipeline_results(cid)  → constrói estado final
  db.save_asm_data()
  pipeline_state[cid]["status"] = "done"
```

### 4. Frontend pollingm SSE

```
GET /api/recon/{cid}/pipeline/stream  (SSE)
  → yield cada linha do pipeline_state[cid]["log"]
  → quando status == "done": yield {done: true}

GET /api/recon/{cid}/pipeline  (polling)
  → {status, phase_idx, phase_label, host_count, phases:[...], log[-30:]}
```

### 5. Visualização

```
reloadServerData()
  → GET /api/data  → {companies: [{id, name, hosts, findings, stats, ...}]}
  → renderOverview(co)  lê co.stats, co.hosts, co.findings
  → renderSubdomainsTab(co)  lê co.hosts[].status_code / waf / technologies
  → renderInfraTab(co)  lê co.asn_data, co.waf_coverage, co.dns_data, co.leaks_data
```

---

## Campos Críticos para o Frontend

Estes campos **precisam existir** na empresa para o dashboard renderizar corretamente.

### Overview funcionar

```json
{
  "stats": {
    "live_hosts": 171,
    "subdomains": 171,
    "findings_critical": 3,
    "findings_high": 12,
    "findings_medium": 45,
    "findings_info": 89,
    "open_ports": 234,
    "waf_protected": 8
  }
}
```

### Host table mostrar status HTTP

```json
{
  "hosts": [
    {"host": "www.example.com", "status_code": 200, "title": "...", "waf": "Cloudflare"}
  ]
}
```

`status_code` vem de `httpx` (campo `status_code` com underscore, não `status-code` com hífen).

### Tab Ports mostrar dados

```json
{
  "port_scan": {
    "results": [{"ip": "1.2.3.4", "port": 443, "service": "https"}],
    "ips_scanned": 50
  }
}
```

Checkpoint do `portscan` usa a chave `results` (lista de objetos), não `open_ports`.

### Tab Stack mostrar tecnologias

```json
{
  "tech_summary": {"Next.js": 5, "Cloudflare": 8},
  "tech_index": {"Next.js": ["www.example.com", "app.example.com"]}
}
```

`tech_summary` deve ser sempre derivado de `tech_index` em `_persist_pipeline_results`.

### URLs tab mostrar dados

```json
{
  "urlfinder_data": {"urls": ["https://...", "..."]}
}
```

O checkpoint do urlfinder salva em `findings[].value`, não em `urls[]`. `_persist_pipeline_results` extrai e converte.

---

## Armadilhas Conhecidas

### 1. `status-code` vs `status_code` (httpx)

A saída JSON do `httpx` usa `status_code` (underscore). Qualquer `item.get("status-code")` retorna sempre `None`.

### 2. `port_scan` checkpoint usa `results`, não `open_ports`

```python
# ERRADO — sempre falso:
if port_data.get("open_ports"):
# CORRETO:
if port_data.get("open_ports") or port_data.get("results") or port_data.get("ips_scanned"):
```

### 3. `urlfinder_data` checkpoint usa `findings[].value`, não `urls[]`

```python
urls = urlfinder_data.get("urls") or [
    f["value"] for f in urlfinder_data.get("findings", []) if f.get("value")
]
```

### 4. `dns_data` checkpoint usa chaves maiúsculas (`A`, `MX`, `TXT`)

```python
# ERRADO — sempre falso:
if dns_data.get("records") or dns_data.get("mx"):
# CORRETO:
if dns_data.get("records") or dns_data.get("A") or dns_data.get("MX") or dns_data.get("TXT"):
```

### 5. `leaks_data` — `git_exposed` pode ser lista vazia

```python
# ERRADO:
if leaks_data.get("git_exposed") or leaks_data.get("leaks"):
# CORRETO:
if leaks_data.get("git_exposed") or leaks_data.get("leaks") \
   or leaks_data.get("total_findings", 0) > 0 \
   or leaks_data.get("github", {}).get("results"):
```

### 6. `tech_summary` precisa ser reconstruído

`tech_index` é salvo pelos módulos, mas `tech_summary` (o que o frontend lê) é derivado. Sempre reconstruir em `_persist_pipeline_results`:

```python
if co_data.get("tech_index"):
    co_data["tech_summary"] = {t: len(h) for t, h in co_data["tech_index"].items()}
```

### 7. `tc-ports` conta portas abertas, não hosts vivos

```javascript
// ERRADO:
document.getElementById("tc-ports").textContent = s.live_hosts || 0;
// CORRETO:
document.getElementById("tc-ports").textContent =
    s.open_ports || (co.hosts||[]).filter(h=>(h.ports||[]).length>0).length || 0;
```

### 8. Todos os `fetch()` precisam de auth headers

```javascript
// ERRADO (retorna 401 silencioso):
fetch(`/api/screenshots/${cid}`)
// CORRETO:
fetch(`/api/screenshots/${cid}`, {headers: _authHeaders()})
```

### 9. `_merge_hosts_into_asm_data` deve atualizar, não duplicar

A função deve verificar se o host já existe antes de append. Usar `existing_map = {h["host"]: h for h in hosts}`.

### 10. WAF por host precisa ser assignado manualmente

O `waf_coverage` guarda contagens agregadas. Para cada `host.waf` ser populado, é necessário iterar os resultados de `waf_results.results` e mapear host → WAF.

### 11. Subfinder/assetfinder/wayback devem iterar todos os `domains`

```python
# ERRADO — só usa o primeiro domínio:
domain = co["domains"][0]
result = run_subfinder(domain)
# CORRETO:
for domain in co["domains"]:
    result = run_subfinder(domain)
    # merge results
```

### 12. `asm_run.log` deve ser escrito incrementalmente

O log `scans/{cid}/{scan_name}/asm_run.log` deve ter linhas appendadas durante o scan, não escritas apenas ao final. O frontend pode ler o log em tempo real via `GET /api/scan-history/{cid}/{scan}/log`.

---

## Manutenção e Operação

### Verificar estado do banco

```bash
python3 - <<'EOF'
import json
import sqlite3
conn = sqlite3.connect("/home/kali/recon/asm/asm.db")
data = json.loads(conn.execute("SELECT value FROM asm_data WHERE key='main'").fetchone()[0])
for co in data.get("companies", []):
    print(co["name"], "—", len(co.get("hosts",[])), "hosts,",
          len(co.get("findings",[])), "findings,",
          co.get("stats",{}).get("open_ports",0), "ports")
conn.close()
EOF
```

### Ler checkpoint de um módulo

```bash
python3 -c "
import json
from pathlib import Path
cp = Path('scans/red-bull/.checkpoints/portscan.json')
if cp.exists():
    d = json.loads(cp.read_text())
    print(list(d.keys()))
    print('results:', len(d.get('results', d.get('open_ports', []))))
"
```

### Resetar pipeline de uma empresa

```
DELETE /api/recon/{cid}/data
```

Isso remove todos os campos de scan do banco e limpa `pipeline_state`. Os checkpoints JSON em disco são mantidos (podem ser usados para re-persist manual).

### Forçar re-persist dos checkpoints

```bash
python3 - <<'EOF'
import sys; sys.path.insert(0, "/home/kali/recon/asm")
from database import ASMDatabase
from pathlib import Path

db = ASMDatabase(Path("/home/kali/recon/asm/asm.db"))
db.initialize()

# Carregar pipeline e forçar persist
from pipeline import ReconRunner, PIPELINE_PHASES
import recon as recon_mod

runner = ReconRunner(
    db=db, base_dir=Path("/home/kali/recon/asm"),
    get_settings=db.get_settings,
    load_hosts_fn=lambda cid: [],
    recon_module=recon_mod,
    recon_available=True,
)
runner._persist_pipeline_results("red-bull")
print("Done")
EOF
```

### Adicionar nova chave de API

1. `POST /api/settings` com o novo par `{key: value}`
2. As chaves disponíveis estão em `settings.json`:
   `github_token`, `shodan_key`, `hibp_key`, `dehashed_key`, `nvd_key`,
   `virustotal_key`, `censys_api_id`, `censys_api_secret`, `chaos_key`,
   `binaryedge_key`, `fullhunt_key`, `hunter_key`, `intelx_key`,
   `leakix_key`, `netlas_key`, `securitytrails_key`, `fofa_email`, `fofa_key`,
   `dnsdumpster_token`

### Instalar novas ferramentas

```bash
cd /home/kali/recon/asm
bash install_tools.sh
# Verificar status via API:
# GET /api/tools/status
```

### Logs do servidor

```bash
# systemd:
journalctl -u asm -f

# direto:
tail -f /home/kali/recon/asm/server.log
```

### Backup do banco

```bash
sqlite3 /home/kali/recon/asm/asm.db ".backup /tmp/asm_backup_$(date +%Y%m%d).db"
```

### Migrar dados legados (JSON → SQLite)

Chamado automaticamente no boot via `DB.migrate_from_legacy()`. Pode ser forçado manualmente se necessário importando os arquivos JSON individualmente pelas rotas de API.

---

## Integrações de API Externas

| Serviço | Chave | Módulos que usam |
|---|---|---|
| GitHub | `github_token` | leaks, breach (trufflehog) |
| Shodan | `shodan_key` | shodan |
| HaveIBeenPwned | `hibp_key` | breach |
| dehashed | `dehashed_key` | breach |
| NVD (NIST) | `nvd_key` | cve |
| VirusTotal | `virustotal_key` | various |
| Censys | `censys_api_id` + `censys_api_secret` | passive |
| Chaos (ProjectDiscovery) | `chaos_key` | subfinder |
| BinaryEdge | `binaryedge_key` | subfinder |
| FullHunt | `fullhunt_key` | subfinder |
| Hunter.io | `hunter_key` | theharvester |
| IntelX | `intelx_key` | breach |
| LeakIX | `leakix_key` | breach |
| Netlas | `netlas_key` | passive |
| SecurityTrails | `securitytrails_key` | passive |
| FOFA | `fofa_email` + `fofa_key` | passive |
| DNSDumpster | `dnsdumpster_token` | dns |

Todas as chaves são opcionais. Módulos que precisam de API key e não a encontram simplesmente retornam dados parciais ou pulam sem erro fatal.
