# Scantrely

Plataforma local de **Attack Surface Management**: descobre subdomínios, portas, tecnologias, vulnerabilidades, segredos e exposição de credenciais de uma empresa e diz **o que corrigir primeiro**.

## Como usar

1. Cadastre a empresa e os domínios no escopo.
2. Rode o scan (aba **Técnico → Pipeline**).
3. Abra **Prioridades**: até 10 ações ordenadas, cada uma com *o quê, onde, por quê e como corrigir*.

| Aba | Para quê |
|---|---|
| **Prioridades** | O que fazer agora |
| **Ativos** | Hosts, domínios, portas, infraestrutura, screenshots, grafo, typosquat |
| **Vulnerabilidades** | Todos os achados, CVEs, supply chain, segredos em JS |
| **Exposição** | Credenciais vazadas / infostealers |
| **Técnico** | Pipeline, logs, alertas, histórico, diferenças entre scans |

## Instalar e rodar

```bash
git clone https://github.com/Willian-2-0-0-1/scantrely.git && cd scantrely
pip install -r requirements.txt
bash install_tools.sh        # ferramentas externas (subfinder, nuclei, httpx…)
bash restart_server.sh       # http://127.0.0.1:5000
```

Login padrão `admin` / `admin` — **troque a senha** em Configurações.

## Testes

```bash
python -m pytest -q
```

## Documentação

- [`docs/COMO_FUNCIONA.md`](docs/COMO_FUNCIONA.md) — visão geral do fluxo
- [`docs/ARQUITETURA.md`](docs/ARQUITETURA.md) — módulos, pipeline, banco
- [`docs/REFERENCIA.md`](docs/REFERENCIA.md) — funcionalidades, variáveis de ambiente, chaves de API, API REST
- [`docs/PERFIS_EXECUCAO.md`](docs/PERFIS_EXECUCAO.md) · [`docs/FERRAMENTAS.md`](docs/FERRAMENTAS.md)
- [`docs/BACKLOG.md`](docs/BACKLOG.md) — pendências (único backlog)
- [`CHANGELOG.md`](CHANGELOG.md)

## API essencial

```
GET /api/data/company/<id>/priorities   ações ordenadas
GET /api/data/company/<id>/findings     achados paginados (?severity=&type=&host=&q=&page=)
GET /api/data/company/<id>/hosts        hosts paginados   (?q=&live=1&waf=none&page=)
```
Autenticação: header `X-Auth-Token`. Lista completa em `docs/REFERENCIA.md`.

## Higiene dos dados

Os achados passam por `core/finding_hygiene.py` a cada scan (vhosts idênticos colapsados, headers agrupados, cadeias só sobre hosts do inventário, typosquat limitado a *high*). Para reaplicar em dados gravados: `python -m core.finding_hygiene`.
