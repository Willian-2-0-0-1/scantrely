// ════════════════════════════════════════════════════════════════════════
//  SETTINGS PAGE
// ════════════════════════════════════════════════════════════════════════
const SETTINGS_SCHEMA = [
  { group:"Threat Intelligence", ico:"radar", desc:"Active asset discovery & port/service data",
    fields:[
      {key:"shodan_key",          label:"Shodan API Key",          tag:"free",     hint:"shodan.io — free plan available",        signup:"https://account.shodan.io/"},
      {key:"censys_api_id",       label:"Censys API ID",           tag:"free",     hint:"censys.io — free researcher plan",       signup:"https://search.censys.io/account/api"},
      {key:"censys_api_secret",   label:"Censys API Secret",       tag:"free",     hint:"Paired with Censys API ID",              signup:"https://search.censys.io/account/api"},
      {key:"netlas_key",          label:"Netlas API Key",          tag:"free",     hint:"netlas.io — free tier available",        signup:"https://app.netlas.io/profile/"},
    ]
  },
  { group:"OSINT & Breach Data", ico:"bug", desc:"Credential leaks, breach intelligence, dark web",
    fields:[
      {key:"hibp_key",            label:"HaveIBeenPwned API Key",  tag:"paid",     hint:"haveibeenpwned.com — domain search requires paid", signup:"https://haveibeenpwned.com/API/Key"},
      {key:"dehashed_key",        label:"DeHashed API Key",        tag:"paid",     hint:"dehashed.com — email/credential search", signup:"https://www.dehashed.com/profile"},
      {key:"leakix_key",          label:"LeakIX API Key",          tag:"free",     hint:"leakix.net — free tier works without key", signup:"https://leakix.net/settings"},
      {key:"intelx_key",          label:"IntelligenceX API Key",   tag:"paid",     hint:"intelx.io — leak & darkweb OSINT",       signup:"https://intelx.io/account?tab=developer"},
    ]
  },
  { group:"DNS & Subdomain", ico:"globe", desc:"Passive subdomain enumeration & DNS intelligence",
    fields:[
      {key:"securitytrails_key",  label:"SecurityTrails API Key",  tag:"free",     hint:"securitytrails.com — 50 req/month free", signup:"https://securitytrails.com/app/account"},
      {key:"chaos_key",           label:"Chaos (ProjectDiscovery)",tag:"free",     hint:"chaos.projectdiscovery.io — free for researchers", signup:"https://chaos.projectdiscovery.io/"},
      {key:"whoisxml_key",        label:"WhoisXML API Key",        tag:"paid",     hint:"whoisxmlapi.com — reverse WHOIS (domínios irmãos da org)", signup:"https://user.whoisxmlapi.com/products"},
    ]
  },
  { group:"CVE & Vulnerability DB", ico:"explosion", desc:"CVE intelligence from NVD — cross-reference detected technologies with known vulnerabilities",
    fields:[
      {key:"nvd_key",             label:"NVD API Key",             tag:"free",     hint:"nvd.nist.gov — free, 50 req/30s with key vs 5 without", signup:"https://nvd.nist.gov/developers/request-an-api-key"},
    ]
  },
  { group:"Code & Secrets", ico:"key", desc:"GitHub secrets, code leaks, API keys in repos",
    fields:[
      {key:"github_token",        label:"GitHub Token",            tag:"free",     hint:"Personal access token — avoids rate limits", signup:"https://github.com/settings/tokens/new"},
      {key:"wpscan_token",        label:"WPScan API Token",        tag:"free",     hint:"wpscan.com — WordPress vulnerability scanner, free API token", signup:"https://wpscan.com/profile"},
    ]
  },
  { group:"Email & Identity", ico:"envelope", desc:"Email infrastructure and identity OSINT",
    fields:[
      {key:"hunter_key",          label:"Hunter.io API Key",       tag:"free",     hint:"hunter.io — email finder, 25 req/month free", signup:"https://hunter.io/api_keys"},
    ]
  },
  { group:"Search Engines", ico:"search", desc:"Specialized internet-wide search engines",
    fields:[
      {key:"virustotal_key",      label:"VirusTotal API Key",      tag:"free",     hint:"virustotal.com — free tier",             signup:"https://www.virustotal.com/gui/my-apikey"},
      {key:"fofa_email",          label:"FOFA Email",              tag:"paid",     hint:"fofa.info — Chinese internet search",    signup:"https://fofa.info/userInfo"},
      {key:"fofa_key",            label:"FOFA API Key",            tag:"paid",     hint:"Paired with FOFA Email",                 signup:"https://fofa.info/userInfo"},
    ]
  },
  { group:"AI / Hermes Agent", ico:"sparkle", desc:"Enriquecimento de findings (CVSS, CWE, mitigação e PoC) via Hermes Agent (Nous Research), self-hosted. Inicie o gateway com 'hermes gateway' e aponte para o host:porta dele — qualquer outro endpoint compatível com OpenAI chat/completions também funciona.",
    fields:[
      {key:"hermes_base_url",     label:"API Base URL",            tag:"optional", hint:"Padrão: http://127.0.0.1:8642/v1 (endereço do seu 'hermes gateway' local, endpoint OpenAI-compatible /chat/completions)"},
      {key:"hermes_api_key",      label:"API Server Key", tag:"optional",  hint:"Bearer token (API_SERVER_KEY) do gateway, se ele exigir autenticação. Deixe vazio se o gateway local não exigir chave."},
      {key:"hermes_model",        label:"Modelo",                  tag:"optional", hint:"Padrão: hermes-agent (nome cosmético — o gateway usa o modelo do profile configurado)"},
    ]
  },
  { group:"Bug Bounty Platforms", ico:"trophy", desc:"Credenciais para visualizar programas de Bug Bounty diretamente na plataforma",
    fields:[
      {key:"hackerone_username",  label:"HackerOne Username",      tag:"optional", hint:"Seu username do HackerOne (não o e-mail)", signup:"https://hackerone.com/settings/api_token_v2"},
      {key:"hackerone_token",     label:"HackerOne API Token",     tag:"optional", hint:"Token de API gerado em hackerone.com/settings/api_token_v2", signup:"https://hackerone.com/settings/api_token_v2"},
    ]
  },
  { group:"Notificações por E-mail (SMTP)", ico:"mail", desc:"Canal de e-mail usado pelas regras de alerta e pelo webhook tipo Email",
    fields:[
      {key:"smtp_host",    label:"SMTP Host",        tag:"optional", hint:"smtp.example.com"},
      {key:"smtp_port",    label:"SMTP Port",        tag:"optional", hint:"587"},
      {key:"smtp_user",    label:"SMTP User",        tag:"optional", hint:"alertas@empresa.com"},
      {key:"smtp_pass",    label:"SMTP Password",    tag:"optional", hint:"senha ou app password"},
      {key:"alert_email",  label:"Destinatário",     tag:"optional", hint:"security@empresa.com"},
    ]
  },
  { group:"Integração de Tickets (Jira / Linear)", ico:"ticket", desc:"Abre tickets automaticamente quando uma regra de alerta dispara",
    fields:[
      {key:"jira_url",        label:"Jira URL",          tag:"optional", hint:"https://empresa.atlassian.net"},
      {key:"jira_user",       label:"Jira User / e-mail", tag:"optional", hint:"user@empresa.com"},
      {key:"jira_token",      label:"Jira API Token",    tag:"optional", hint:"token de API do Atlassian"},
      {key:"jira_project",    label:"Jira Project Key",  tag:"optional", hint:"SEC"},
      {key:"linear_token",    label:"Linear API Token",  tag:"optional", hint:"lin_api_..."},
      {key:"linear_team_id",  label:"Linear Team ID",    tag:"optional", hint:"uuid do time no Linear"},
    ]
  },
  { group:"DefectDojo", ico:"clipboard", desc:"Push de findings para o DefectDojo no fim do scan",
    fields:[
      {key:"defectdojo_url",     label:"DefectDojo URL",     tag:"optional", hint:"https://defectdojo.empresa.com"},
      {key:"defectdojo_token",   label:"API Token",          tag:"optional", hint:"Token da API v2"},
      {key:"defectdojo_product", label:"Product name",       tag:"optional", hint:"Nome do produto no DefectDojo"},
    ]
  },
  { group:"Bots / Slash", ico:"chat", desc:"Token para /scan no Slack ou Discord",
    fields:[
      {key:"slash_token", label:"Slash token", tag:"optional", hint:"Bearer compartilhado em POST /api/integrations/slash"},
    ]
  },
];

// ── Runtime Config Schema (separate ⚡ Performance page) ──
const RUNTIME_SCHEMA = [
  { group:"Runtime Engine", ico:"cpu", desc:"Pipeline workers, rate limits, and scan defaults",
    fields:[
      {key:"asm_job_workers",        label:"Pipeline Workers",        tag:"runtime", hint:"1",
       tooltip:"Quantos jobs de pipeline rodam ao mesmo tempo. 1 = um domínio por vez (seguro). Aumente para acelerar scans em massa, mas cada worker extra consome mais CPU e RAM."},
      {key:"asm_global_proc_limit",  label:"Global Process Limit",    tag:"runtime", hint:"6",
       tooltip:"Teto máximo de subprocessos externos (nmap, nuclei, ffuf, etc) rodando simultaneamente. Se atingir esse limite, novas ferramentas esperam na fila. Reduza se a VPS travar."},
      {key:"asm_domain_fanout",      label:"Domain Fan-out Workers",  tag:"runtime", hint:"3",
       tooltip:"Quantos domínios cada módulo processa em paralelo. Ex: com 3, o subfinder escaneia 3 domínios ao mesmo tempo. Aumente para acelerar, mas cuidado com rate limit de APIs."},
      {key:"asm_gate_default",       label:"Default Tool Gate",       tag:"runtime", hint:"3",
       tooltip:"Limite de execuções simultâneas por ferramenta. Ex: com 3, no máximo 3 httpx rodam ao mesmo tempo. Ferramentas pesadas (nuclei, amass) têm limite individual menor (1)."},
    ]
  },
  { group:"Scan Defaults", ico:"target", desc:"Default scan profile and rate mode for new scans",
    fields:[
      {key:"asm_rate_mode",          label:"Default Rate Mode",       tag:"runtime", hint:"balanced",
       tooltip:"Velocidade padrão dos scans. stealth = lento e invisível (24/7). balanced = moderado. fast = rápido mas pode alertar WAFs e bloqueadores."},
      {key:"asm_scan_mode",          label:"Default Scan Mode",       tag:"runtime", hint:"bug_bounty",
       tooltip:"Pipeline padrão da ferramenta. bug_bounty executa descoberta, validação, priorização, JS/API, Playwright, checks leves, portas priorizadas e evidências."},
    ]
  },
  { group:"Watchdog", ico:"shield", desc:"Safety limits that pause the queue before the machine crashes",
    fields:[
      {key:"asm_watchdog_max_load",  label:"Max System Load",         tag:"runtime", hint:"4.0",
       tooltip:"Se a carga do sistema (load average) ultrapassar esse valor, o watchdog pausa a fila de jobs para evitar travamento da máquina. Ajuste conforme o número de CPUs."},
      {key:"asm_watchdog_min_mem_mb",label:"Min Free RAM (MB)",       tag:"runtime", hint:"1536",
       tooltip:"Se a memória RAM livre cair abaixo desse valor, o watchdog pausa a fila. Aumente se tiver mais RAM disponível, reduza se for uma VPS pequena."},
      {key:"asm_watchdog_max_procs", label:"Max Recon Processes",     tag:"runtime", hint:"10",
       tooltip:"Se o número de processos de recon (nmap, nuclei, subfinder, etc) ultrapassar esse valor, o watchdog pausa a fila. Evita fork bombs e travamentos."},
    ]
  },
];

let _settingsData = {};
let _playwrightDefaults = {};
let _toolsData = [];

// Runtime config defaults (mirrors restart_server.sh)
const _RUNTIME_DEFAULTS = {
  asm_job_workers: "1",
  asm_global_proc_limit: "6",
  asm_domain_fanout: "3",
  asm_gate_default: "3",
  asm_rate_mode: "balanced",
  asm_scan_mode: "bug_bounty",
  asm_watchdog_max_load: "4.0",
  asm_watchdog_min_mem_mb: "1536",
  asm_watchdog_max_procs: "10",
};

// Fill runtime defaults from env if available (injected at page load)
if (typeof ASM !== 'undefined' && ASM.runtimeConfig) {
  Object.assign(_RUNTIME_DEFAULTS, ASM.runtimeConfig);
}

const PLAYWRIGHT_SETTING_KEYS = [
  "playwright_safe_mode",
  "playwright_headless",
  "playwright_allow_external",
  "playwright_trace",
  "playwright_max_pages",
  "playwright_max_depth",
  "playwright_timeout",
  "playwright_slow_mo",
  "playwright_user_agent",
  "playwright_auth_state",
  "playwright_auth_state_b",
  "playwright_test_xss",
  "playwright_test_race",
  "playwright_test_access",
];

function _toolId(name) {
  return String(name || "").replace(/[^a-zA-Z0-9_-]/g, "_");
}

function _boolish(v, def = false) {
  if (v === undefined || v === null || v === "") return def;
  if (typeof v === "boolean") return v;
  const t = String(v).trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(t)) return true;
  if (["0", "false", "no", "n", "off"].includes(t)) return false;
  return def;
}

function _syncPlaywrightDefaults(raw) {
  const next = {};
  for (const key of PLAYWRIGHT_SETTING_KEYS) {
    if (raw && Object.prototype.hasOwnProperty.call(raw, key)) {
      next[key] = raw[key];
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(_playwrightDefaults, key)) {
      next[key] = _playwrightDefaults[key];
    }
  }
  _playwrightDefaults = next;
  return _playwrightDefaults;
}

function _currentPlaywrightDefaults() {
  const cfg = { ..._playwrightDefaults };
  let local = {};
  try { local = JSON.parse(localStorage.getItem("asm_settings") || "{}"); } catch(e) {}
  for (const key of PLAYWRIGHT_SETTING_KEYS) {
    if (cfg[key] === undefined || cfg[key] === null || cfg[key] === "") {
      if (local[key] !== undefined) cfg[key] = local[key];
    }
  }
  return cfg;
}

async function loadPlaywrightDefaults() {
  if (!SERVER_MODE) return _currentPlaywrightDefaults();
  try {
    const r = await fetch("/api/settings");
    if (r.ok) {
      const data = await r.json();
      _settingsData = data;
      _syncPlaywrightDefaults(data);
    }
  } catch(e) {}
  return _currentPlaywrightDefaults();
}

function renderSettingsGrid() {
  const grid = document.getElementById("settings-grid");
  if (!grid) return;
  grid.innerHTML = SETTINGS_SCHEMA.map(group => `
<div class="settings-group">
  <div class="sg-title">${group.ico ? icoHtml(group.ico,16) : (group.icon||"")} ${group.group}</div>
  <div class="sg-desc">${group.desc}</div>
  ${group.fields.map(f => {
    const val = _settingsData[f.key] || "";
    return `
  <div class="sg-field">
    <div class="sg-label">
      <span>${f.label}</span>
      <span class="sg-tag ${f.tag}">${f.tag}</span>
      ${f.signup ? `<a class="sg-getkey" href="${escAttr(f.signup)}" target="_blank" rel="noopener noreferrer" title="Obter chave em ${escAttr(new URL(f.signup).hostname)}">Obter chave</a>` : ""}
    </div>
    <div class="sg-input-wrap">
      <input type="password" class="sg-input${val? " has-value":""}"
             id="sg-${f.key}" value="${esc(val)}"
             placeholder="${esc(f.hint)}"
             oninput="document.getElementById('settings-save-status').textContent=(typeof window.t==='function'?window.t('settings_unsaved_mod'):'Unsaved changes');document.getElementById('settings-save-status').className='save-status'">
      <button class="sg-toggle" onclick="toggleSgVisibility('sg-${f.key}',this)" title="Show/hide">${icoHtml("eye",14)}</button>
    </div>
  </div>`;
  }).join("")}
</div>`).join("");
}

// ── Runtime Config (⚡ Performance page) ──

function renderRuntimeGrid() {
  const grid = document.getElementById("runtime-grid");
  if (!grid) return;
  grid.innerHTML = RUNTIME_SCHEMA.map(group => `
<div class="settings-group">
  <div class="sg-title">${group.ico ? icoHtml(group.ico,16) : (group.icon||"")} ${group.group}</div>
  <div class="sg-desc">${group.desc}</div>
  ${group.fields.map(f => {
    const val = _settingsData[f.key] || _RUNTIME_DEFAULTS[f.key] || "";
    const tip = f.tooltip ? f.tooltip.replace(/"/g, '&quot;').replace(/'/g, '&#39;') : "";
    return `
  <div class="sg-field">
    <div class="sg-label"${tip ? ` title="${tip}"` : ""}>
      <span>${f.label}</span>
      <span class="sg-tag ${f.tag}">${f.tag}</span>
    </div>
    <div class="sg-input-wrap">
      <input type="text" class="sg-input${val? " has-value":""}"
             id="rt-${f.key}" value="${esc(val)}"
             placeholder="${esc(f.hint)}"${tip ? ` title="${tip}"` : ""}
             oninput="document.getElementById('runtime-save-status').textContent=(typeof window.t==='function'?window.t('settings_unsaved_mod'):'Unsaved changes');document.getElementById('runtime-save-status').className='save-status'">
    </div>
  </div>`;
  }).join("")}
</div>`).join("");
}

async function loadRuntimeConfig() {
  if (!SERVER_MODE) { renderRuntimeGrid(); return; }
  try {
    const r = await fetch("/api/settings");
    if (r.ok) {
      _settingsData = await r.json();
    }
  } catch(e) {}
  renderRuntimeGrid();
  const _t = (k) => (typeof window.t === 'function' ? window.t(k) : k);
  document.getElementById("runtime-save-status").textContent = _t('config_loaded');
  document.getElementById("runtime-save-status").className = "save-status ok";
}

async function saveRuntimeConfig() {
  const data = {};
  RUNTIME_SCHEMA.forEach(g => g.fields.forEach(f => {
    const el = document.getElementById("rt-" + f.key);
    if (el && el.value.trim()) data[f.key] = el.value.trim();
  }));
  const st = document.getElementById("runtime-save-status");
  const _t = (k) => (typeof window.t === 'function' ? window.t(k) : k);
  try {
    const r = await fetch("/api/settings", {
      method: "POST", body: JSON.stringify(data),
      headers: _authHeaders(),
    });
    if (r.ok) {
      st.textContent = _t('config_saved_ok');
      st.className = "save-status ok";
    } else {
      const d = await r.json();
      throw new Error(d.error || _t('config_save_err'));
    }
  } catch(e) {
    st.textContent = "Error: " + e.message;
    st.className = "save-status";
  }
}

function toggleSgVisibility(id, btn) {
  const el = document.getElementById(id);
  el.type = el.type === "password" ? "text" : "password";
  btn.style.opacity = el.type === "text" ? "1" : "0.4";
}

async function loadSettings() {
  if (!SERVER_MODE) { renderSettingsGrid(); return; }
  try {
    const r = await fetch("/api/settings");
    if (r.ok) {
      _settingsData = await r.json();
      _syncPlaywrightDefaults(_settingsData);
    }
  } catch(e) {}
  renderSettingsGrid();
  const _t = (k) => (typeof window.t === 'function' ? window.t(k) : k);
  document.getElementById("settings-save-status").textContent = _t('settings_loaded');
  document.getElementById("settings-save-status").className = "save-status ok";
  loadWebhooks();
}

async function saveSettings() {
  const data = {};
  SETTINGS_SCHEMA.forEach(g => g.fields.forEach(f => {
    const el = document.getElementById("sg-"+f.key);
    if (el) data[f.key] = el.value.trim();
  }));
  _settingsData = data;
  const st = document.getElementById("settings-save-status");
  const _t = (k) => (typeof window.t === 'function' ? window.t(k) : k);
  if (!SERVER_MODE) { st.textContent = _t('settings_demo_mode'); st.className="save-status err"; return; }
  try {
    const r = await fetch("/api/settings", {method:"POST", body:JSON.stringify(data), headers: _authHeaders()});
    if (r.ok) { st.textContent = _t('settings_saved_ok'); st.className="save-status ok"; }
    else { st.textContent = _t('settings_save_err'); st.className="save-status err"; }
  } catch(e) { st.textContent = _t('settings_conn_err'); st.className="save-status err"; }
}

// ── Notifications / Webhooks (Telegram, Discord, Slack, WhatsApp, Signal, Email, CLI) ──

const WEBHOOK_TYPES = {
  telegram: { label: "Telegram", fields: [
      {key:"bot_token", label:"Bot Token", placeholder:"123456:ABC-DEF..."},
      {key:"chat_id",   label:"Chat ID",   placeholder:"-100123456789"},
    ]},
  discord: { label: "Discord", fields: [
      {key:"url", label:"Webhook URL", placeholder:"https://discord.com/api/webhooks/..."},
    ]},
  slack: { label: "Slack", fields: [
      {key:"url", label:"Webhook URL", placeholder:"https://hooks.slack.com/services/..."},
    ]},
  whatsapp: { label: "WhatsApp (Twilio)", fields: [
      {key:"account_sid", label:"Account SID"},
      {key:"auth_token",  label:"Auth Token"},
      {key:"from",        label:"From", placeholder:"whatsapp:+14155238886"},
      {key:"to",          label:"To",   placeholder:"whatsapp:+5511999999999"},
    ]},
  signal: { label: "Signal (signal-cli-rest-api)", fields: [
      {key:"url",        label:"API Base URL", placeholder:"http://localhost:8080"},
      {key:"number",     label:"Número remetente", placeholder:"+5511999999999"},
      {key:"recipients", label:"Destinatários (separados por vírgula)"},
    ]},
  email: { label: "Email (usa SMTP de Configurações)", fields: [
      {key:"to", label:"Destinatário", placeholder:"security@empresa.com"},
    ]},
  cli: { label: "CLI (feed local data/cli_notifications.jsonl)", fields: [] },
  generic: { label: "Webhook genérico (JSON POST)", fields: [
      {key:"url", label:"URL"},
    ]},
};

const WEBHOOK_EVENTS = [
  {key:"scan_complete",          label:"Scan finalizado"},
  {key:"scan_error",             label:"Erro no scan"},
  {key:"critical_finding",       label:"Finding crítico"},
  {key:"new_host",               label:"Novo host"},
  {key:"new_port",               label:"Nova porta"},
  {key:"new_tech",               label:"Nova tecnologia"},
  {key:"status_change",          label:"Mudança de status HTTP"},
  {key:"waf_change",             label:"Mudança de WAF"},
  {key:"cert_expiring",          label:"Certificado expirando"},
  {key:"cve_critical",           label:"CVE crítica"},
  {key:"supply_chain_critical",  label:"Supply chain crítica"},
];

let _webhooksData = [];

async function loadWebhooks() {
  if (!SERVER_MODE) { renderWebhooksPanel(); return; }
  try {
    const r = await fetch("/api/webhooks", {headers:_authHeaders()});
    if (r.ok) _webhooksData = await r.json();
  } catch(e) {}
  renderWebhooksPanel();
}

function renderWebhookFormFields() {
  const type = document.getElementById("wh-new-type")?.value || "generic";
  const def = WEBHOOK_TYPES[type] || WEBHOOK_TYPES.generic;
  const fields = document.getElementById("wh-new-fields");
  if (fields) {
    fields.innerHTML = def.fields.map(f => `
    <div class="sg-field">
      <div class="sg-label"><span>${f.label}</span></div>
      <input type="text" class="sg-input" id="wh-new-${f.key}" placeholder="${esc(f.placeholder||"")}">
    </div>`).join("") || `<div class="sg-desc">Nenhuma configuração adicional necessária.</div>`;
  }
  const events = document.getElementById("wh-new-events");
  if (events) {
    events.innerHTML = WEBHOOK_EVENTS.map(e => `
    <label style="display:inline-flex;align-items:center;gap:6px;margin-right:16px;">
      <input type="checkbox" class="wh-new-event" value="${e.key}" checked> ${e.label}
    </label>`).join("");
  }
}

function renderWebhooksPanel() {
  const typeSel = document.getElementById("wh-new-type");
  if (typeSel && !typeSel.options.length) {
    typeSel.innerHTML = Object.entries(WEBHOOK_TYPES).map(([k,v]) => `<option value="${k}">${esc(v.label)}</option>`).join("");
    renderWebhookFormFields();
  }

  const list = document.getElementById("webhooks-list");
  if (!list) return;
  if (!_webhooksData.length) {
    list.innerHTML = `<div class="sg-desc">Nenhum webhook configurado ainda.</div>`;
    return;
  }
  list.innerHTML = _webhooksData.map((hook, idx) => {
    const def = WEBHOOK_TYPES[hook.type] || WEBHOOK_TYPES.generic;
    const target = hook.chat_id || hook.to || hook.url || hook.number || "(sem destino)";
    const events = (hook.events || []).map(e => (WEBHOOK_EVENTS.find(x=>x.key===e)||{label:e}).label).join(", ") || "todos os eventos";
    return `
  <div class="sg-field" style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
    <div>
      <strong>${esc(def.label)}</strong> — <span style="color:var(--text3)">${esc(String(target))}</span>
      <div class="sg-desc" style="margin:2px 0 0;">Eventos: ${esc(events)}</div>
    </div>
    <div style="display:flex;gap:8px;">
      <button class="btn btn-secondary" onclick="testWebhook(${idx})"> Testar</button>
      <button class="btn btn-secondary" onclick="deleteWebhook(${idx})">${icoHtml("trash",14)} Remover</button>
    </div>
  </div>`;
  }).join("");
}

async function _saveWebhooks() {
  const st = document.getElementById("webhooks-save-status");
  try {
    const r = await fetch("/api/webhooks", {method:"POST", body:JSON.stringify(_webhooksData), headers:_authHeaders()});
  if (r.ok) { if (st) { st.textContent = " Salvo"; st.className = "save-status ok"; } }
    else { if (st) { st.textContent = "Erro ao salvar"; st.className = "save-status err"; } }
  } catch(e) { if (st) { st.textContent = "Erro de conexão"; st.className = "save-status err"; } }
}

function addWebhook() {
  const type = document.getElementById("wh-new-type")?.value || "generic";
  const def = WEBHOOK_TYPES[type] || WEBHOOK_TYPES.generic;
  const hook = {id: "wh_" + Math.random().toString(36).slice(2,10), type};
  def.fields.forEach(f => {
    const el = document.getElementById("wh-new-" + f.key);
    let val = el ? el.value.trim() : "";
    if (f.key === "recipients" && val) val = val.split(",").map(s=>s.trim()).filter(Boolean);
    if (val) hook[f.key] = val;
  });
  hook.events = Array.from(document.querySelectorAll(".wh-new-event:checked")).map(c => c.value);
  if (!hook.events.length) { showToast("Selecione ao menos um evento."); return; }
  _webhooksData.push(hook);
  renderWebhooksPanel();
  _saveWebhooks();
  def.fields.forEach(f => { const el = document.getElementById("wh-new-" + f.key); if (el) el.value = ""; });
}

function deleteWebhook(idx) {
  _webhooksData.splice(idx, 1);
  renderWebhooksPanel();
  _saveWebhooks();
}

async function testWebhook(idx) {
  const hook = _webhooksData[idx];
  try {
    const r = await fetch("/api/webhooks/test", {method:"POST", body:JSON.stringify({hook}), headers:_authHeaders()});
    if (r.ok) showToast("Teste enviado — verifique o canal configurado.");
    else showToast("Falha ao enviar teste.");
  } catch(e) { showToast("Erro de conexão: " + e.message); }
}

function _toolMatchesFilter(tool, categoryFilter, availFilter) {
  const category = String(tool.category || "");
  const available = !!tool.available;
  if (categoryFilter && category !== categoryFilter) return false;
  if (availFilter === "available" || availFilter === "enabled") return available;
  if (availFilter === "missing" || availFilter === "disabled") return !available;
  return true;
}

function _renderPlaywrightDefaultsCard() {
  const cfg = _currentPlaywrightDefaults();
  const rows = [
    {label:"Safe mode", key:"playwright_safe_mode", type:"checkbox", def:true},
    {label:"Headless", key:"playwright_headless", type:"checkbox", def:true},
    {label:"Allow external", key:"playwright_allow_external", type:"checkbox", def:false},
    {label:"Trace", key:"playwright_trace", type:"checkbox", def:false},
    {label:"Max pages", key:"playwright_max_pages", type:"number", def:50},
    {label:"Max depth", key:"playwright_max_depth", type:"number", def:3},
    {label:"Timeout (s)", key:"playwright_timeout", type:"number", def:20},
    {label:"Slow mo (ms)", key:"playwright_slow_mo", type:"number", def:0},
    {label:"User agent", key:"playwright_user_agent", type:"text", def:""},
    {label:"Auth state", key:"playwright_auth_state", type:"text", def:""},
    {label:"Auth state B", key:"playwright_auth_state_b", type:"text", def:""},
  ];
  const active = [
    ["Test XSS", "playwright_test_xss"],
    ["Test Race", "playwright_test_race"],
    ["Test Access", "playwright_test_access"],
  ];
  return `
    <div class="section-shell" style="margin-bottom:18px">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">Playwright Defaults</div>
          <div class="section-title">Browser phase defaults</div>
          <div class="section-sub">These settings are used by the bug bounty browser phase and prefill the manual Playwright run dialog.</div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <span id="tools-pw-save-status" class="save-status"></span>
          <button class="btn btn-secondary btn-sm" onclick="loadToolsStatus()">↺ Reload</button>
          <button class="btn btn-primary btn-sm" onclick="savePlaywrightDefaults()">Save Defaults</button>
        </div>
      </div>
      <div class="stats-row" style="margin-bottom:12px">
        ${rows.map(({label, key, type, def}) => {
          const value = cfg[key];
          const checked = type === "checkbox" ? (_boolish(value, def) ? "checked" : "") : "";
          const display = type === "checkbox"
            ? `<label class="toggle" style="margin-top:6px"><input type="checkbox" id="tools-${key}" ${checked}><span class="slider"></span></label>`
            : `<input class="fi" id="tools-${key}" type="${type}" value="${esc(value ?? def ?? "")}" style="width:100%;margin-top:6px">`;
          return `
            <div class="stat-card" style="min-width:180px;flex:1">
              <div class="stat-label">${esc(label)}</div>
              ${display}
            </div>`;
        }).join("")}
      </div>
      <div class="stats-row" style="margin-bottom:0;gap:10px">
        ${active.map(([label, key]) => {
          const checked = _boolish(cfg[key], false) ? "checked" : "";
          return `
            <div class="stat-card" style="min-width:180px;flex:1">
              <div class="stat-label">${esc(label)}</div>
              <label class="toggle" style="margin-top:6px"><input type="checkbox" id="tools-${key}" ${checked}><span class="slider"></span></label>
            </div>`;
        }).join("")}
      </div>
    </div>`;
}

function _renderToolCard(tool, defaultTarget) {
  const id = _toolId(tool.name);
  const available = !!tool.available;
  const gate = tool.gate || {};
  const gateLabel = gate ? `${Number(gate.active || 0)}/${Number(gate.limit || 1)}` : "";
  const statusLabel = available ? "Installed" : "Missing";
  const requires = tool.requires_key ? `<span class="chip">key: ${esc(tool.requires_key)}</span>` : "";
  const gateChip = gate ? `<span class="chip">gate ${esc(gateLabel)}</span>` : "";
  return `
    <div class="section-shell" style="padding:14px 14px 12px">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px">
        <div style="min-width:0">
          <div class="section-title" style="font-size:1rem;line-height:1.1">${esc(tool.name)}</div>
          <div class="section-sub" style="margin-top:4px">${esc(tool.description || "")}</div>
        </div>
        <span class="chip" style="background:${available ? "rgba(0,255,136,.12)" : "rgba(255,51,85,.12)"};color:${available ? "var(--green)" : "var(--red)"};border-color:${available ? "rgba(0,255,136,.2)" : "rgba(255,51,85,.2)"}">${statusLabel}</span>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin:10px 0 12px">
        <span class="chip">${esc(String(tool.category || ""))}</span>
        <span class="chip">${esc(String(tool.type || ""))}</span>
        <span class="chip">${esc(String(tool.version || ""))}</span>
        ${requires}
        ${gateChip}
      </div>
      <div style="display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center">
        <input class="fi" id="ti-${id}" value="${esc(defaultTarget || "")}" placeholder="Target domain or IP">
        <button class="btn btn-primary btn-sm" id="tb-${id}" ${available ? "" : "disabled"} onclick="runTool('${esc(tool.name)}')">Run</button>
      </div>
      <div style="margin-top:10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <code id="ic-${id}" style="font-size:.68rem;white-space:normal;word-break:break-word;flex:1;background:var(--bg1);padding:8px 10px;border:1px solid var(--border);border-radius:8px">${esc(tool.install_cmd || "—")}</code>
        <button class="btn btn-secondary btn-sm" onclick="copyInstall('${esc(tool.name)}')">Copy</button>
      </div>
      <div id="tr-${id}" class="tc-result" style="margin-top:10px"></div>
    </div>`;
}

function renderToolsCatalog() {
  const grid = document.getElementById("tools-grid");
  const stats = document.getElementById("tools-stats-strip");
  const pwCfg = document.getElementById("tools-playwright-config");
  if (!grid || !stats || !pwCfg) return;

  const categoryFilter = document.getElementById("tools-cat-filter")?.value || "";
  const availFilter = document.getElementById("tools-avail-filter")?.value || "";
  const defaultTarget = (allCompanies().find(c => c.id === state.currentId)?.domains || [])[0]
    || (allCompanies()[0]?.domains || [])[0]
    || "";
  const filtered = _toolsData.filter(tool => _toolMatchesFilter(tool, categoryFilter, availFilter));

  const total = _toolsData.length;
  const available = _toolsData.filter(t => t.available).length;
  const missing = total - available;
  const apiCount = _toolsData.filter(t => String(t.type || "") === "api").length;
  const cliCount = total - apiCount;

  stats.innerHTML = [
    ["Total", total, "var(--cyan)"],
    ["Installed", available, "var(--green)"],
    ["Missing", missing, "var(--red)"],
    ["API tools", apiCount, "var(--blue)"],
    ["CLI tools", cliCount, "var(--yellow)"],
  ].map(([label, value, color]) => `
    <div class="stat-card" style="min-width:130px;flex:1">
      <div class="stat-value" style="color:${color}">${value}</div>
      <div class="stat-label">${label}</div>
    </div>`).join("");

  pwCfg.innerHTML = _renderPlaywrightDefaultsCard();

  if (!filtered.length) {
    grid.innerHTML = `<div class="empty" style="grid-column:1/-1"><b>No tools match the current filters</b> Try another category or availability filter.</div>`;
    return;
  }
  grid.innerHTML = filtered.map(tool => _renderToolCard(tool, defaultTarget)).join("");
}

async function loadToolsStatus() {
  const grid = document.getElementById("tools-grid");
  const stats = document.getElementById("tools-stats-strip");
  const pwCfg = document.getElementById("tools-playwright-config");
  if (grid) grid.innerHTML = `<div class="skel skel-card"></div><div class="skel skel-card"></div>`;
  if (stats) stats.innerHTML = `<div class="skel skel-card"></div>`;
  if (pwCfg) pwCfg.innerHTML = `<div class="skel skel-card"></div>`;

  if (!SERVER_MODE) {
    _toolsData = [];
    renderToolsCatalog();
    return;
  }

  try {
    const [toolsResp, settingsResp] = await Promise.all([
      fetch("/api/tools/status", {headers:_authHeaders()}),
      fetch("/api/settings", {headers:_authHeaders()}),
    ]);
    if (settingsResp.ok) {
      const settings = await settingsResp.json();
      _settingsData = settings;
      _syncPlaywrightDefaults(settings);
    }
    if (!toolsResp.ok) throw await _apiErr(toolsResp);
    _toolsData = await toolsResp.json();
    renderToolsCatalog();
  } catch(e) {
    if (grid) grid.innerHTML = `<div class="empty" style="grid-column:1/-1"><b>Tools unavailable</b> ${esc(e.message)}</div>`;
    if (stats) stats.innerHTML = "";
    if (pwCfg) pwCfg.innerHTML = "";
  }
}

function filterTools() {
  renderToolsCatalog();
}

async function savePlaywrightDefaults() {
  if (!SERVER_MODE) return;
  const cfg = {
    playwright_safe_mode: document.getElementById("tools-playwright_safe_mode")?.checked ?? true,
    playwright_headless: document.getElementById("tools-playwright_headless")?.checked ?? true,
    playwright_allow_external: document.getElementById("tools-playwright_allow_external")?.checked ?? false,
    playwright_trace: document.getElementById("tools-playwright_trace")?.checked ?? false,
    playwright_max_pages: Number(document.getElementById("tools-playwright_max_pages")?.value || 50),
    playwright_max_depth: Number(document.getElementById("tools-playwright_max_depth")?.value || 3),
    playwright_timeout: Number(document.getElementById("tools-playwright_timeout")?.value || 20),
    playwright_slow_mo: Number(document.getElementById("tools-playwright_slow_mo")?.value || 0),
    playwright_user_agent: document.getElementById("tools-playwright_user_agent")?.value.trim() || "",
    playwright_auth_state: document.getElementById("tools-playwright_auth_state")?.value.trim() || "",
    playwright_auth_state_b: document.getElementById("tools-playwright_auth_state_b")?.value.trim() || "",
    playwright_test_xss: document.getElementById("tools-playwright_test_xss")?.checked ?? false,
    playwright_test_race: document.getElementById("tools-playwright_test_race")?.checked ?? false,
    playwright_test_access: document.getElementById("tools-playwright_test_access")?.checked ?? false,
  };
  try {
    const r = await fetch("/api/settings", {
      method:"POST",
      headers: {"Content-Type":"application/json", ..._authHeaders()},
      body: JSON.stringify(cfg),
    });
    if (!r.ok) throw await _apiErr(r);
    _settingsData = { ..._settingsData, ...cfg };
    _syncPlaywrightDefaults(cfg);
    try {
      const local = JSON.parse(localStorage.getItem("asm_settings") || "{}");
      localStorage.setItem("asm_settings", JSON.stringify({ ...local, ...cfg }));
    } catch(e) {}
    const status = document.getElementById("tools-pw-save-status");
    if (status) {
   status.textContent = " Playwright defaults saved";
      status.className = "save-status ok";
    }
  } catch(e) {
    const status = document.getElementById("tools-pw-save-status");
    if (status) {
      status.textContent = "Error saving Playwright defaults";
      status.className = "save-status err";
    }
    showToast("Error saving Playwright defaults: " + e.message);
  }
}
