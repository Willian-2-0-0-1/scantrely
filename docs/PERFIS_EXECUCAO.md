# Perfis de execucao da pipeline ASM

Este projeto agora separa a pipeline em perfis para rodar bug bounty automatizado sem derrubar a VPS.

## Regra principal

Nao rode ativo em massa.

Use descoberta passiva para muitos dominios e rode ativo apenas em lotes pequenos, escopados por dominio/host.

## Perfis

| Perfil | Uso | O que roda | Limites |
| --- | --- | --- | --- |
| `passive_bulk` | Varredura de muitos dominios | Descoberta passiva leve de subdominios | Seguro para fila grande |
| `active_light` | Validar poucos dominios/hosts vivos | Profiling, headers/WAF/tech, JS, crawl leve, enum ativo leve | Max. 25 hosts por job |
| `active_heavy` | Teste pesado em alvo pequeno | Port scan, services, nuclei/vulnscan | Max. 5 hosts por job |
| `full` | Pipeline completa manual | Todas as fases habilitadas | Use apenas em escopo pequeno |

## Auto-ajuste para VPS

O `restart_server.sh` executa `python3 -m utils.resource_profile` e define limites conforme CPU/RAM/swap:

| Variavel | Funcao |
| --- | --- |
| `ASM_JOB_WORKERS` | Quantas pipelines rodam em paralelo |
| `ASM_GLOBAL_PROC_LIMIT` | Teto global de subprocessos externos |
| `ASM_DOMAIN_FANOUT_WORKERS` | Quantos dominios cada modulo processa em paralelo |
| `ASM_GATE_*` | Limite por ferramenta (`httpx`, `subfinder`, `nuclei`, etc.) |
| `ASM_WATCHDOG_*` | Limites de seguranca para pausar jobs se a VPS pesar |
| `ASM_ENABLE_SCHEDULED_SCANS` | Liga scans agendados automaticos; padrao `0` |

Variaveis exportadas manualmente sempre vencem o auto-profile.

## Exemplos de API

Descoberta passiva em fila:

```json
{
  "profile": "passive_bulk",
  "queue_domains": true,
  "domains": ["example.com", "example.org"]
}
```

Ativo leve em poucos alvos:

```json
{
  "profile": "active_light",
  "queue_domains": false,
  "domains": ["api.example.com"]
}
```

Ativo pesado somente em alvo pequeno:

```json
{
  "profile": "active_heavy",
  "queue_domains": false,
  "domains": ["api.example.com"]
}
```

## Protecoes implementadas

- Jobs `running` antigos nao voltam para `pending` no boot por padrao.
- Fila grande pode ficar em `stopped` sem auto-disparar.
- Todo `subprocess.run/check_output` passa pelo gate global.
- `nuclei` via `Popen` fica segurando slot do gate ate terminar.
- Light mode bloqueia ferramentas pesadas por padrao.
- Smart checkpoint nao roda em `light`, evitando fingerprint de todos os hosts da empresa em cada job.
- Perfis ativos filtram hosts pelo dominio/host selecionado e nao varrem a empresa inteira por acidente.
- Scans agendados automaticos ficam desligados por padrao; ligue apenas com `ASM_ENABLE_SCHEDULED_SCANS=1`.
- Watchdog do scheduler segura jobs se load, memoria livre ou numero de processos passarem do limite.

## Procedimento recomendado

1. Rode `passive_bulk` para alimentar subdominios.
2. Revise/filtre hosts vivos e interessantes.
3. Rode `active_light` em lote pequeno.
4. Rode `active_heavy` somente em hosts com maior chance de resultado.
5. Se a VPS pesar, reduza `ASM_JOB_WORKERS` e `ASM_GLOBAL_PROC_LIMIT`.
