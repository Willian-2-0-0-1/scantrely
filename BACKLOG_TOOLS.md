# Backlog de Ferramentas — Ampliação de Superfície de Ataque

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
