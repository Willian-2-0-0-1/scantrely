# Changelog

Todas as mudanças relevantes do projeto são documentadas aqui.

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
