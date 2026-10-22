# Changelog

Todas as mudanças relevantes do projeto são documentadas aqui.

## [Não lançado] - 2026-10-15

### Do recon para o teste manual

- **Texto de interface não é senha** (`core/reconlib/jsrecon.py`, `core/asset_matrix.py`): `\xE9`/`é` do bundle decodificado (`_unescape_js`); valor de `password` com duas ou mais palavras naturais (qualquer língua, com acento) é falso positivo — "Olvidé mi contraseña" saía como segredo alto.
- **Config de build não é arquivo sensível** (`core/reconlib/github_org.py`, `core/finding_hygiene.py`): `tsconfig.json`, `ionic.config.json`, `webpack.config.js` e afins são públicos por natureza (`BUILD_CONFIG_RE`) e saem de `github_sensitive_file`, que agora também teto em médio — só o nome do arquivo, sem conteúdo verificado.
- **Segredo em comentário e mapa do css-loader** (`core/finding_hygiene.py`): token dentro de bloco de comentário (exemplo de documentação) teto em médio; `exports={password:"_183C…"}` do css-loader/webpack reconhecido como classe CSS pelo contexto, não só pelo valor.
- **CVE de outro produto** (`core/finding_hygiene.py`, `core/reconlib/cve.py`): o CPE do `python` fixa o fabricante (`python:python`) — com curinga vinham a extensão Python do VS Code e o Odoo ("when running with Python 3.6"); o que escapar, `dismiss_false_positives` descarta pela descrição.
- **Vhost já inventariado** (`core/finding_hygiene.py`): nome que já está no inventário DNS respondendo em IP compartilhado (CDN) não é "ambiente não publicado" — `vhost_findings` recebe os hosts conhecidos.
- **Fora do escopo por empresa** (`core/scope.py`, coluna `companies.out_of_scope_json`): `host.exemplo.com`, `*.x.exemplo.com` ou URL colada. Host excluído não entra em sondagem HTTP, módulos ativos, takeover, vigilância, listas nem Burp. Campo novo em "Editar escopo"; a API valida os itens.
- **Importar escopo do programa**: colar os blocos In scope / Out of scope (HackerOne, Bugcrowd, Intigriti…) e "Ler escopo" (`POST /api/scope/parse`, só lê): `*.x.com` vira domínio, URL vira host; IP, id de app e texto ficam como ignorados.
- **Listas para ferramentas** (`core/tool_lists.py`, `GET /api/data/company/<id>/lists/<hosts|urls|endpoints|params>`, menu Exportar): só o que está no escopo.
- **Enviar ao Burp** (`core/burp_feed.py`, `POST /api/data/company/<id>/burp`): GET de cada URL pelo proxy do Burp (`burp_proxy`, padrão `http://127.0.0.1:8080`), até 500 por envio; confere que o proxy é mesmo o Burp (`http://burp/`) antes de enviar.

### Identificação: quem respondeu e cobertura dos testes

- **Borda x aplicação** (`core/reconlib/edge.py`): `classify` separa resposta da aplicação, bloqueio de WAF/CDN e limitação de taxa. `cf-ray` e similares só identificam o fabricante; só marca de enforcement (`cf-mitigated`, `x-amzn-waf`…) ou texto de bloqueio em 403/406/419 vira "bloqueado". Baseline por host (caminho aleatório) descarta respostas iguais para tudo e hosts em que a borda barra até caminho inexistente.
- **Validação por conteúdo** (`core/verification.py`): tabela de regras (`.env`, `.git`, `.sql`, `tfstate`, `web.config`, backups por magic bytes, Actuator, Swagger, `server-status`…). 200 sem o conteúdo esperado não vira achado em `services` nem no `ffuf`.
- **Cobertura** (`edge_coverage`): `services`, `leaks` e `graphql` contam quantas sondagens chegaram na aplicação. Aparece no card "Test Coverage (WAF/CDN)" da aba Infra e na seção "Cobertura dos testes" do relatório HTML/PDF, com aviso quando menos da metade chegou.
- **WAF sobre o `classify`** (`core/reconlib/waf.py`): `_detect_waf` identifica o fabricante pela resposta normal e pela sondagem, e informa `probe_blocked` (a borda barrou a sondagem) separado de `protected` (há CDN/WAF na frente). `_is_waf_challenge_body` (CORS e takeover) agora recebe status e cabeçalhos: texto como "access denied" num 200 deixa de ser tratado como página da borda. Saíram as listas soltas `_WAF_SIGNATURES` e `_WAF_CHALLENGE_SIGNATURES`; Barracuda, Fortinet e Radware passaram para `edge.py`.
- **Severidade pela prova** (`core/finding_hygiene.py`): crítico/alto sem resposta/trecho guardado e com linguagem de hipótese ("poderia", "possível"…) cai para médio com "(potencial)" no título; a original fica em `severity_raw`. `evidence_grade` (`proven`/`partial`/`none`) nos achados críticos/altos.
- **Segredos mascarados nos relatórios** (`core/redact.py`): HTML, PDF, CSV de achados e SARIF mostram `AKIA****MPLE`; o JSON de exportação e o banco guardam o valor bruto para reteste.
- **Mais sondagens com prova de conteúdo** (`services`): `terraform.tfstate`, `docker-compose`, backups, `trace.axd`, Actuator `configprops`/`httptrace` e variações de Swagger/OpenAPI, todas só com o conteúdo esperado.
- **Correção:** `graphql` trocava status e corpo do `http_get` e nunca detectava nada; `ffuf` gravava o host errado nos achados.

### Estabilidade e desempenho

- **Servidor travava com o uso**: `with sqlite3.connect(...)` só faz commit/rollback, não fecha a conexão. `_connect` (banco e cache HTTP) agora fecha sempre. Com ~500 conexões abertas (`asm.db` + `asm.db-wal`) o processo batia no limite de 1024 descritores, o `accept` falhava em laço (100% de CPU) e nada mais era atendido. Depois: 4 descritores estáveis sob carga.
- **Scan fantasma**: estado "running"/"queued" sem nenhum job ativo há mais de 2 min (servidor reiniciado no meio do scan) passa a aparecer como interrompido — uma empresa aparecia "rodando" havia 6 dias.
- **Carga**: perfil `large` com 2 jobs em paralelo (era 3) e 1 gowitness (era 2, com 3 abas do Chrome em vez de 5); whatweb/wpscan (`ruby`) limitados a 1. Com 3 domínios juntos na fase de fingerprint a carga chegou a 14,85 e o watchdog pausou o scan.
- **Pausa do watchdog ≠ parado**: status novo `paused` (job e pipeline). Antes a pausa gravava `stopped`, o worker via `stopped` e cancelava o job — quem estava rodando na hora da pausa nunca voltava (só os da fila). Agora o run pausado salva o progresso e sai sem fechar a empresa, o job fica `paused` e volta à fila quando a máquina folga (inclusive depois de reiniciar o servidor). A tela mostra "Pausado · máquina carregada, retoma sozinho".
- Captura de navegador do módulo `js`: 3 navegadores simultâneos (eram 8, cada visita abre o seu; levavam o load acima de 20).
- **Um módulo de navegador por vez** (gate `playwright` = 1): `browser_crawl`, `browser_recon`, `screenshot` e a captura do `js` rodam dentro do processo (fora do gate de subprocesso) e abrem 3 navegadores cada; dois domínios na fase 8 juntos passaram de load 13 em 10s.
- Serviço de usuário `scantrely` (systemd) sobe o servidor no boot via `restart_server.sh`, com `LimitNOFILE=8192`.
- Abrir uma empresa: 21 → 16 requisições e ~350 → ~210 ms. GET idêntico em voo é compartilhado (`_sharedGetJSON`); prioridades guardadas por 60s — antes eram buscadas de novo a cada 4s pela sincronização do pipeline e o bloco piscava "Calculando prioridades…".
- Aba "Domínios e marca" quebrada em todas as empresas: o "Loading" ao abrir a empresa apagava os contêineres embutidos (infra/typosquat). Abas com estrutura própria (`data-keep-layout`) e embutidas não são mais apagadas, e a aba se refaz se preciso. `asm.js` passou a ter versão na URL (ficava preso no cache).

### Vigilância contínua

- **`core/watch.py`**: job `watch` (passivo com subfinder + checagem 80/443 com filtro de curinga + diff contra o inventário), ~40s para 350 hosts. Cada mudança vira alerta (host novo, voltou a responder, parou de responder após 2 vigilâncias seguidas, status/título/tecnologia nova; IP não conta) e os webhooks recebem `surface_change`. Primeira vigilância de um domínio recém-adicionado é linha de base: grava tudo e gera um alerta só.
- Sem alarme falso por curinga (hosts iguais ao curinga não contam como mortos; 3 canários por zona; página de erro idêntica em ≥ 5 hosts de zona com curinga é do curinga) nem por desafio anti-bot ("Just a moment…"). Medido: 3 vigilâncias seguidas sem mudança real → 0, 0 e 1 alerta.
- Vigilância consulta também Certificate Transparency (crt.sh/certspotter/Shodan CT) em paralelo com o subfinder, com prazo de 45s: subdomínio novo costuma aparecer ali minutos após a emissão do certificado.
- "Monitorar agora" enfileira a vigilância e mostra o resumo (antes disparava o pipeline completo; a rota `/api/monitor` antiga olhava 15 hosts e não gravava nada). `GET /api/monitor/<id>` devolve a última.
- Agenda: perfil `watch` (ou `watch_active`, que também roda o scan ativo só nos hosts que mudaram) sempre roda; o scan completo agendado continua dependendo de `ASM_ENABLE_SCHEDULED_SCANS=1`. O botão de agenda cria vigilância (sugestão: 6h).
- **Aba Alertas sempre vazia**: a rota chamava `db.get_alerts`, que não existia (o `hasattr` devolvia lista vazia). Criados `get_alerts`/`acknowledge_alert`; a rota de "Acknowledge" aceita id em texto (era `<int:aid>`, os ids são hex) e o botão passa o id entre aspas (dava erro de JavaScript); rotas de alerta respeitam o escopo do admin.
- Alertas por diff de scan nunca saíam: o import era `from alerting` (atalho da raiz removido) e o diff ia sem `"diff": "ok"` e com hosts como texto. Corrigido (`snapshot_diff`).

### Scan

- **DNS curinga**: o `dns_brute` resolve rótulos aleatórios em cada zona e descarta nomes que só apontam para o IP do curinga (`drop_wildcard_hits`). Num scan real, 473 de 525 hosts eram o curinga.
- **httpx**: sondagem com `-stream -o`; ao estourar o prazo, o resultado parcial é usado (antes, 16 min de sondagem viravam lista vazia).
- **gowitness**: uma URL por host com esquema e porta explícitos (`https://host:443` ou `http://host:80`); antes eram 4 capturas por host.
- `host_header_injection`, `open_redirect`, `waf_bypass`, `smtp_probe` e `infra_exposure` rodam em paralelo com prazo interno de 150s (`run_bounded`) e devolvem o parcial em vez de estourar os 180s do módulo; `vendor_fp` passou a respeitar o mesmo prazo.
- **Fila por domínio**: o primeiro domínio a terminar marcava o pipeline da empresa como concluído com outro ainda rodando; agora só o último fecha o status.
- **Fila por domínio, fim do scan**: histórico de stats, snapshot/diff/alertas, detecção de mudança de tecnologia e notificações (`scan_complete`, `critical_finding`) rodam uma vez, no último domínio. Antes rodavam a cada domínio: notificações duplicadas e o diff do segundo domínio comparava contra o snapshot pela metade do primeiro.
- **Log**: GET de polling da tela com sucesso (`/pipeline`, `/tool-logs`, `/live-output`, `/api/jobs`, `/api/data/ts`, `/health`) sai do `server.log` — eram 98% das linhas; erros e outros métodos ficam (`ASM_LOG_POLLING=1` volta ao antigo). `restart_server.sh` gira o log acima de 20 MB (`ASM_LOG_ROTATE_MB`) e guarda 3 cópias `.gz`.
- **Curinga por resposta HTTP**: a sondagem pede 2 nomes aleatórios por zona com curinga; host cujas respostas são todas páginas do curinga não conta como vivo (escopo e `www.` do escopo nunca saem).
- **httpx em duas etapas**: 80/443 em todos; as outras 8 portas só fora de CDN. A porta registrada é a real (antes 8080 virava 80).
- **Cancelamento cooperativo**: módulo que estoura o prazo tem `http_get`/subprocessos cancelados na próxima chamada, em vez de seguir disputando rede com os módulos seguintes.
- **subfinder** com `-all -es crtsh` (~9s estáveis por domínio; crt.sh oscilava até 2 min e já é consultado pelo módulo `certs`); arquivo temporário de chaves com permissão 600.
- AlienVault OTX passou a usar a chave das Configurações (antes ia vazia e tomava 429); sem chave é pulado na hora em vez de gastar 180s em retentativas.
- **Resolvedores do sistema** (`utils/resolvers.py`) para `dnsx`, `subjack` e `amass`: com VPN de firewall estrito (Mullvad) os resolvedores públicos que eles usavam são recusados e as três ferramentas não resolviam nada, em silêncio (o subjack terminava em 1–3s sem saída; o `dns_brute` caía no resolvedor Python).
- **Takeover sem teto de hosts**: `takeover` e `subjack` verificam todos os hosts do escopo, não só os 40 ativos (vivos primeiro) — CNAME pendurado está justamente nos que não respondem. Prazo interno com parcial.
- **param_mine (arjun)**: sem `--stable` (1 thread, 6–12s entre requisições), wordlist média em lotes de 500, 150s (antes 300s, acima do módulo), saída própria por execução (domínios em paralelo gravavam no mesmo arquivo) e alvo = primeiro host com 200 (antes o domínio raiz, em geral 403 de CDN). O parser só lia o formato antigo do arjun e nunca devolvia parâmetro.
- **api_discovery_extra**: hosts em paralelo com prazo; esquema descoberto uma vez por host; host sem resposta abandonado (antes até 2.100 requisições em série); kiterunner limitado a 120s.
- **services**: caminho aleatório como referência — host sem resposta custa 1 requisição (antes ~130) e respostas iguais à referência (SPA/WAF que respondem igual a tudo) não viram achado; prazo e parcial.
- **cors_scan**: hosts em paralelo com prazo; host abandonado após 2 falhas de rede.
- **infra_exposure exige assinatura do serviço** (`INFRA_SIGNATURES`: `gitVersion`/`NamespaceList`, `ServerVersion`, `etcdserver`, `cluster_name`…). Depois de corrigir a ordem status/corpo, qualquer resposta < 500 na porta virava achado: o Cloudflare responde na 8080 e geraram-se 9 "Kubernetes API exposta" críticos falsos (+4 cadeias derivadas). A higiene descarta os gravados sem assinatura (`auto_dismissed`).
- **Segredo "password" em JS**: nome de classe gerado por CSS Modules (`_forgetPassword_ejzvx_198`) não é senha — filtro na coleta e na higiene (3 "altos" falsos).
- **Domínio da marca à venda em corretora** (estacionado): informativo, não médio.
- **Vaga com prazo** (`ToolGate.try_slot`): o `js` desiste da captura de navegador se a vaga não vier a tempo, em vez de estourar o módulo esperando; gowitness com 180s (cabe com a espera nos 420s do módulo).
- Contador da fila por domínio vem dos jobs do mesmo disparo (`count_jobs_with_trace`), seja qual for o caminho que enfileirou.
- **amass limitado a 3 min** (`-timeout` é em minutos; com 20 segurava a fase 1 por 4–5 min por domínio e, sem chaves de API, quase nunca trouxe nada — timeout ou erro vazio em quase todas as execuções de 15/10). Módulo 240s.
- **git_leaks nunca detectava `.git` exposto**: testava `"ref:" in body` com o corpo em bytes (TypeError engolido em todo host). Agora exige conteúdo real de `.git/HEAD` (`ref: refs/…` ou sha de 40 caracteres — página de SPA não conta), hosts em paralelo com prazo, http só se o https não responder; devolve `exposed_git`.
- **whatweb**: prazo de 150s para o módulo inteiro (lotes até onde der, devolvendo o que já veio — antes 4 lotes de 60s em série estouravam e perdiam tudo), lotes de 20 com 10 threads e timeouts de conexão/leitura de 8/12s.
- **js**: prazo único de 330s (módulo: 360s). katana/subjs/getJS/gau rodam em paralelo com até 120s (antes em série: 300+150+90+3×60s); navegador com até 15 alvos (antes 30) e pulado se o prazo estiver no fim; o teto da análise dos arquivos passou a valer (o `with ThreadPoolExecutor` esperava todas as threads na saída).
- **Takeover crítico só com evidência**: CNAME pendurado vira crítico apenas se o nome é registrável por terceiros (Elastic Beanstalk, Azure, Heroku…); ELB/CloudFront órfãos viram informativo (higiene de DNS).
- Corrigidos: `infra_exposure` lia `(status, body)` invertido e nunca reportava Kubernetes/Docker/etcd expostos; `waf_bypass` tratava falha de rede (status 0) como bypass de severidade alta; `smtp_probe` reportava "STARTTLS ausente" quando o EHLO nem respondia.

## [1.4.0] - 2026-10-09

### Dados e organização

- **Higiene dos achados** (`core/finding_hygiene.py`): vhosts com resposta idêntica viram 1 achado informativo; headers/cookies agrupados por tipo; cadeias de ataque recalculadas a cada scan e só sobre hosts do inventário; typosquat limitado a *high*; achados de scans antigos não se acumulam. Porto: 567 → 130 achados, críticos 50 → 8.
- Corrigida a acentuação corrompida (dupla codificação UTF-8) em `core/recon.py` e nos textos gravados.
- **Prioridades**: `GET /api/data/company/<id>/priorities` (`core/priorities.py`) e nova visão geral "O que fazer agora".
- Abas da empresa de 10 para 5; cabeçalho com menus Exportar e ⋯.
- **API paginada**: `/api/data/company/<id>/findings` e `/hosts` sobre tabelas de índice (`finding_index`, `host_index`) derivadas do JSON.
- `/api/data/company/<id>` respeita o escopo do admin.
- ~200 `except Exception: pass` viraram `_log.debug(..., exc_info=True)` (ligue com `ASM_LOG_LEVEL=DEBUG`); shims da raiz removidos.
- `core/recon.py` dividido em `core/reconlib/*` (36 módulos); corrigidos NameError latentes em xss_scan e na checagem de CNAME do salesforce_recon.
- `static/js/dashboard.js` (12 mil linhas) dividido em `static/js/dashboard/NN-*.js` (17 arquivos, mesma ordem); render de todos os painéis conferido antes/depois. `priorities.js` não era servido pelo servidor (404): corrigido; rota `/js/<nome>.js` genérica.
- **Tela principal = matriz de ativos** (Ativos → Hosts, abre por padrão): uma linha por host e colunas Achados (por severidade), CVE, Secrets, Endpoints, Portas, Infra, Tech, Título, IP, Captura; Domínio opcional. Filtros por achados/“contém”/domínio, atalhos com contagem e menu “Colunas” (salvo no navegador). Ordenação por qualquer coluna (numéricas do maior para o menor).
- Gaveta do host com achados, CVE, secrets e endpoints; contagens da matriz abrem a seção certa; exportação CSV/JSON respeita os filtros e leva todas as colunas; cabeçalho e coluna URL fixos; layout compacto no celular.
- Corrigidos: `_downloadBlob` inexistente (botões CSV/JSON de hosts e achados não faziam nada), "NaN" no cartão de ferramenta da aba Portas, data velha no rodapé.
- Vulnerabilidades: seções e cartões sem dados não aparecem; KPIs de severidade deixaram de duplicar os cartões.
- **Falsos positivos tratados (`core/verification.py`)**: `.git exposto` só vale com conteúdo de git (HTML de SPA/soft-200 não conta; os 3 críticos da Porto eram isso e foram para `auto_dismissed`); URLs históricas do Wayback de alto risco são sondadas ao vivo (`live_status`/`verified`) e, sem confirmação, aparecem como INFO "histórico · não verificado" na aba Endpoints (ex.: `/.git/config` que hoje responde 403); CORS refletido em resposta 4xx/5xx é rebaixado um nível.
- **Tetos de severidade** (`SEVERITY_CAPS` em `core/finding_hygiene.py`): CORS nunca passa de médio (e baixo se a raiz responde 4xx/5xx); cabeçalho/cookie, fingerprint de fornecedor e bypass de WAF até médio; staging na CSP até baixo; CVE casada só pelo nome do produto (versão não detectada) é "possível" (baixo; KEV, médio). As cadeias de ataque são recalculadas sobre os achados já corrigidos. Porto: 0 críticos.
- **Achados "não vistos"**: `core/finding_lifecycle.py` — o que um módulo que rodou neste scan deixa de reportar vira `not_seen` (some das contagens, prioridades, matriz e lista; aparece no filtro "Não vistos") e `resolved` após 3 scans; módulos que não rodaram não mudam nada.
- Matriz de ativos (`/assets`, `/assets/export`) e lista de vulnerabilidades (`/finding-groups`) agora filtram, ordenam e paginam no servidor; `tests/test_asset_matrix_parity.py` compara o servidor com o código antigo do front (congelado em `tests/js/legacy`) no node.
- Corrigidos: `_classifyCache` nunca declarada, ordenação que jogava críticos para o fim (`||5`), `_IP_RE` indefinido em `utils/tools.py`, gaveta do host vazia para hosts só do histórico.
- Docs movidos para `docs/`, README curto e backlog único.

## [1.3.11] - 2026-10-08

### Vulnerabilidades confirmadas

- Painel padrão do grupo Vulnerabilidades (`#tab-vulns`) em PT: título, loading, empty, filtros, contagem, pager e seções CORS/GraphQL/Nuclei/takeover.
- Loading com `aria-busy` e `role="status"`.
- Cards de severidade (Crítica/Alta/Média/Baixa) usam o mesmo i18n.

## [1.3.10] - 2026-10-08

### Recon / Screenshots

- Título, subtítulo, loading, empty states, filtros e cabeçalhos da aba Recon em PT (`recon_*` no i18n).
- Loading com `aria-busy` e `role="status"`, sem tela em branco.
- Secrets do Postman ficam mascarados e só revelam no clique.

## [1.3.9] - 2026-10-08

### Contagens e Pipeline

- Badge da aba Exposição usa o KPI de funcionários (consulta de domínio) ou registros de stealer (e-mail), sem somar usuários.
- Badge do grupo Hosts = inventário ativo (`status_code` real), igual à tabela.
- Aba Pipeline em PT: título, botão Rodar/Parar (ícone SVG restaurado), HUD e painel Playwright.

## [1.3.8] - 2026-10-08

### Inventário de hosts

- O grupo Hosts abre o Inventário de ativos (`#tab-subdomains`) com o card `#playwright-host-inventory` (crawl persistido; sessão Playwright se existir).
- Clique na miniatura abre o lightbox; Escape fecha; setas navegam. Toque no celular abre a prévia (hover fica só no desktop).
- Ações de copiar/abrir/detalhe usam SVG de 44px com `aria-label` (sem emoji ⧉↗◉).

## [1.3.7] - 2026-10-08

### Screenshots

- URL de captura inclui o id da empresa (`/screenshots/porto/<arquivo>`). Persist sem cid (gowitness `screenshots/<file.jpeg>`) deixa de 404.
- Inventário e persist reescrevem path inválido; rota compatível atende o URL antigo sem cid.
- Miniaturas, drawer e sessão Playwright passam pelo mesmo helper.

## [1.3.6] - 2026-10-08

### Inventário JS

- Clique em path relativo (`../../foo`) abre a URL colapsada (`https://host/foo`), sem `..` na barra.
- MIME (`application/json`), máscaras de data (`dd/MM/yyyy`) e imports webpack (`../utils`) saem do inventário de endpoints.
- Aba Endpoints mostra os mesmos secrets do JS Reverse (FP filter + `secrets_findings`); o bloco `#endpoints-secrets` inclui a tabela com links de origem.

## [1.3.5] - 2026-10-08

### Clique na origem

- Secret, endpoint, URL e host abrem o local em que foram achados (`target=_blank`, `rel=noopener`).
- Tabela plana de endpoints: a URL é um link; o restante da linha ainda expande detalhes.
- Secrets: arquivo JS e host navegam; o valor mascarado continua só revelando.
- JS Reverse: host, path e fonte JS viram links; path relativo resolve contra o host.
- Findings: chips de host e URLs abrem o alvo em vez de copiar.
- Operação: crawl, cookies (página), observações, forms, terceiros com domínio, sessão Playwright.

## [1.3.4] - 2026-10-07

### Operação

- A aba Operação lê `browser_recon_data`, `browser_crawl_data` e `js_data` da pipeline. Sem job `playwright_recon` a evidência do browser já aparece.
- Empty state só quando não há persist nem job. CTA de 44px abre o modal Playwright Recon.
- Inventário de hosts no grupo Hosts usa o crawl persistido.

## [1.3.3] - 2026-10-07

### Grafo de ativos

- Clusters por apex (eTLD+1, `.com.br`, AWS DNS, CloudFront, Imperva) encolhem folhas; o grupo `+N hosts` expande no clique.
- Layout por gravidade de cluster (sem D3), não mais um anel por tipo.
- Zoom (roda, `+`/`−`, botões), pan, busca, tooltip com hostname integral.
- Forma + cor por tipo (círculo, quadrado, losango, triângulo, hexágono, cruz).
- Vista Lista como adjacência acessível. Chips e busca em 44px.

## [1.3.2] - 2026-10-07

### Backend ↔ frontend

- Abas órfãs (JS Reverse, Endpoints, Portas, CVE, Supply Chain, Typosquat, Alertas, Timeline, Diff, Suprimidos, Terminal) entram na barra via subnav dos grupos Hosts / Vulnerabilidades / Operação / Pipeline.
- Overview ganha atalhos para esses resultados.
- Infra deixa o dump estático de Porto Seguro e passa a ler `vendor_fingerprints`, `related_domains`, Shodan, favicon, zone transfer, CMS e certstream.
- `.git` exposto e fingerprints de appliance viram findings na aba Vulnerabilidades.
- Param mine entra no inventário unificado de endpoints.
- `#tab-terminal` passa a existir; o HUD da pipeline e o terminal verbose são sub-abas.

## [1.3.1] - 2026-10-07

### JS scan

- KPI JavaScript conta `js_files.length` (antes `Number(array)` virava NaN).
- Empty state aponta o módulo `js`, não `js_scan`.
- `jwt_analysis` lê JWTs já extraídos pelo módulo `js` e não baixa de novo os bundles.
- Hosts de CDN/analytics (Securiti, Clarity, Maps, GTM, Hotjar) são ignorados por sufixo; o flatten de endpoints/secrets segue a mesma regra.
- Source maps (`.js.map`) entram no persist e o `sourcesContent` é varrido por secrets/endpoints.
- Par `client_id` + `client_secret` no mesmo arquivo sobe para critical também no fetch direto.
- Chave Google de Maps/Firebase no cliente cai para medium.
- Padrões novos: `github_pat_`, Slack `xox*`, OpenAI `sk-proj-`, Anthropic `sk-ant-`, npm token.

## [1.3.0] - 2026-10-07

### Exposição (ideias do Cavalier, marca Scantrely)

- Parser Hudson Rock lê `stealerFamilies`, datas de último compromisso, força de senha, `thirdPartyDomains`, aplicações, URLs de funcionários/clientes (pula `*****`), antivírus e logo.
- Lookup por e-mail sanitizado: sem `malware_path`; logins e senhas seguem mascarados como a API pública já devolve.
- Persistência do módulo Breach grava hudsonrock mesmo sem LeakIX/HIBP/TruffleHog.
- `POST /api/intel/exposure` busca ao vivo. `GET/POST /api/recon/<cid>/exposure` lê e atualiza a empresa. Auth obrigatória. Circuit breaker do host Cavalier.
- Aba da empresa + página Workspace search-first, cards KPI, barras de família com rótulo (não só cor), split de senha, terceiros e tabelas de URL.

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
