<div align="center">

# Scantrely

**Attack Surface Management local, sem SaaS e sem enviar dados para fora.**

Descobre subdomínios, portas, tecnologias, vulnerabilidades, segredos expostos e vazamento de
credenciais de uma empresa — e entrega uma lista priorizada de **o que corrigir primeiro**.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/backend-Flask-black)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-412%20passing-brightgreen)](tests/)

</div>

---

## Índice

- [O que é](#o-que-é)
- [Funcionalidades](#funcionalidades)
- [Como usar](#como-usar)
- [Instalação](#instalação)
- [Arquitetura](#arquitetura)
- [Pipeline de recon](#pipeline-de-recon-11-fases)
- [API essencial](#api-essencial)
- [Testes](#testes)
- [Segurança e dados](#segurança-e-dados)
- [Documentação completa](#documentação-completa)

---

## O que é

Scantrely é uma plataforma de **ASM / recon / bug bounty** que roda inteiramente na sua máquina:
backend em **Flask**, dados em **SQLite**, front-end em uma **SPA** servida pelo próprio backend.
Ela orquestra mais de 50 ferramentas externas (subfinder, amass, httpx, nuclei, ffuf, Playwright…)
num pipeline de 11 fases, normaliza os achados, remove falso-positivo e devolve uma matriz de
ativos por empresa com priorização automática.

Não existe envio de telemetria, nem dependência de serviço de terceiros para funcionar — o que
sai são apenas as chamadas que as próprias ferramentas de recon fazem para a internet pública.

## Funcionalidades

| Área | O que faz |
|---|---|
| **Discovery passivo** | subfinder, amass, assetfinder, Certificate Transparency (snapshot + **monitor CertStream contínuo**), OTX, urlscan, RapidDNS, GitHub subdomains, Wayback, theHarvester, Hunter.io |
| **Validação & DNS** | resolução, brute-force de DNS, zone transfer, escopo por empresa (`out_of_scope`), leaks de `.git`, e-mails |
| **Intel para bug bounty** | Shodan, Postman collections públicas, buckets S3, registries de container, breach data, phishing/typosquat, reverse WHOIS, dependency confusion, ASN/ASNMap, recon de APK |
| **Fingerprint web** | detecção de borda (WAF/CDN) separada da aplicação, Wappalyzer, WhatWeb, versão de serviço, vhosts, screenshots (gowitness) |
| **JS & API recon** | extração de endpoints e segredos em bundles JS, GraphQL introspection, detecção de texto de interface vs. credencial real |
| **Browser pentest** | agente Playwright: crawler autenticado, mapeamento de IDOR, client trust, captura de tráfego |
| **Portas & serviços** | scan priorizado por porta/serviço com verificação de conteúdo (sem 200 vazio contando como achado) |
| **Vulnerabilidades** | nuclei com templates curados, CVE enriquecida com KEV/EPSS/exploit público conhecido, severidade ajustada pela prova disponível |
| **Higiene de achados** | colapso de vhosts idênticos, segredos mascarados em relatórios, falso-positivo de config de build/CVE de outro produto removidos automaticamente |
| **Gestão** | checkpoints incrementais, agendamento, webhooks, diff entre scans, exportação (CSV/SARIF/PDF/HTML), RBAC, 2FA |

## Como usar

1. Cadastre a empresa e os domínios no escopo.
2. Rode o scan (aba **Técnico → Pipeline**).
3. A empresa abre na **matriz de ativos**: um host por linha, uma coluna por assunto (achados
   por severidade, CVE, secrets, endpoints, portas, infra, tecnologia, captura). Filtre, ordene,
   ligue/desligue colunas e clique numa contagem para ver o detalhe do host.
4. **Prioridades** reúne até 10 ações ordenadas, cada uma com *o quê, onde, por quê e como
   corrigir*.

| Aba | Para quê |
|---|---|
| **Ativos** (tela inicial) | Matriz de hosts + domínios, endpoints, portas, infraestrutura, screenshots, grafo, typosquat |
| **Prioridades** | O que fazer agora |
| **Vulnerabilidades** | Todos os achados, CVEs, supply chain, segredos em JS |
| **Exposição** | Credenciais vazadas / infostealers |
| **Técnico** | Pipeline, logs, alertas, histórico, diferenças entre scans |

## Instalação

Requer **Python 3.10+**.

```bash
git clone https://github.com/Willian-2-0-0-1/scantrely.git && cd scantrely

pip install -r requirements.txt
bash install_tools.sh        # ferramentas externas: subfinder, nuclei, httpx, amass...
bash restart_server.sh       # sobe em http://127.0.0.1:5000
```

No primeiro start é criado o usuário `admin` com **senha aleatória, impressa uma única vez** no
console e em `logs/server.log` — ou defina `ASM_ADMIN_PASSWORD` antes de subir para fixar a sua.
Troque a senha em **Configurações** depois do primeiro login.

```bash
HOST=0.0.0.0 PORT=8080 bash restart_server.sh   # override de host/porta
```

### Monitor CertStream (opcional)

Além do snapshot pontual de Certificate Transparency, o Scantrely pode manter uma conexão
WebSocket contínua, capturando certificados novos em tempo real e cruzando com o escopo de cada
empresa automaticamente. Configurável em **Configurações → Certificate Transparency**:
URL do servidor CertStream (público ou auto-hospedado) e fallback para o servidor público.
Detalhes e exemplo de `docker run` para um servidor próprio em
[`docs/REFERENCIA.md`](docs/REFERENCIA.md#monitor-certstream-certificate-transparency).

## Arquitetura

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
                        60+ módulos run_* (core/reconlib/*.py)
                                       │  invocam binários em bin/
                                       ▼
                      subfinder · amass · httpx · nuclei · ffuf · playwright · ...
```

Mais detalhes de módulos, banco de dados e rotas em
[`docs/ARQUITETURA.md`](docs/ARQUITETURA.md).

## Pipeline de recon (11 fases)

| # | Fase | Exemplos de módulos |
|---|---|---|
| 1 | Discovery de superfície | subfinder, amass, certs, certstream, OSINT |
| 2 | Validação, DNS e escopo | dns, dns_brute, zone_transfer, leaks |
| 3 | Intel para bug bounty | shodan, s3_scanner, breach, apk_recon |
| 4 | Limpeza e priorização | cleanup (interno) |
| 5 | Fingerprint web | headers, waf, wappalyzer, screenshot |
| 6 | JS discovery | js |
| 7 | APIs, endpoints e secrets | js_endpoints, graphql |
| 8 | Evidência via browser | Playwright (crawler, IDOR, client trust) |
| 9 | Checks leves de bug bounty | — |
| 10 | Portas e serviços priorizados | — |
| 11 | Templates curados e evidência final | nuclei |

## API essencial

```
GET /api/data/company/<id>/priorities   ações ordenadas
GET /api/data/company/<id>/findings     achados paginados (?severity=&type=&host=&q=&page=)
GET /api/data/company/<id>/hosts        hosts paginados   (?q=&live=1&waf=none&page=)
```

Autenticação via header `X-Auth-Token` (ou cookie de sessão). Referência completa de rotas,
variáveis de ambiente e chaves de API em [`docs/REFERENCIA.md`](docs/REFERENCIA.md).

## Testes

```bash
python -m pytest -q
```

412 testes cobrindo pipeline, banco, módulos de recon, API e o monitor CertStream.

## Segurança e dados

- Tudo roda local: SQLite em `data/`, sem telemetria.
- Sem credencial padrão conhecida — senha de admin é aleatória por instalação.
- Segredos (API keys, tokens encontrados em scans) são mascarados em relatórios exportados;
  o valor bruto só existe no banco local, para reteste.
- Achados passam por `core/finding_hygiene.py` a cada scan (vhosts idênticos colapsados, headers
  agrupados, severidade reduzida quando falta prova, typosquat limitado a *high*). Para reaplicar
  em dados já gravados: `python -m core.finding_hygiene`.

## Documentação completa

| Documento | Conteúdo |
|---|---|
| [`docs/COMO_FUNCIONA.md`](docs/COMO_FUNCIONA.md) | Visão geral do fluxo |
| [`docs/ARQUITETURA.md`](docs/ARQUITETURA.md) | Módulos, pipeline, banco de dados |
| [`docs/REFERENCIA.md`](docs/REFERENCIA.md) | Funcionalidades, variáveis de ambiente, chaves de API, API REST |
| [`docs/PERFIS_EXECUCAO.md`](docs/PERFIS_EXECUCAO.md) | Perfis de execução (rápido/completo/stealth) |
| [`docs/FERRAMENTAS.md`](docs/FERRAMENTAS.md) | Ferramentas externas usadas e como instalá-las |
| [`docs/BACKLOG.md`](docs/BACKLOG.md) | Pendências (backlog único do projeto) |
| [`CHANGELOG.md`](CHANGELOG.md) | Histórico de mudanças |

---

<div align="center">

Projeto pessoal de pesquisa em segurança ofensiva — distribuído sob licença [MIT](LICENSE).

</div>
