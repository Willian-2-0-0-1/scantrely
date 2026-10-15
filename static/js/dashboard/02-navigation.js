function _syncSidebarActive() {
  document.querySelectorAll(".sidebar-nav .nav-item").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".nav-co").forEach(el => el.classList.remove("active"));
  const page = state.page || (state.currentId ? "company" : "companies");
  const pageNav = {
    companies: "nav-all",
    jobs: "nav-jobs",
    tools: "nav-tools",
    bbhelper:    "nav-bbhelper",
    exttools:    "nav-exttools",
    bbprograms:  "nav-bbprograms",
    generators:  "nav-generators",
    admins:      "nav-admins",
    runtime:     "nav-runtime",
    exposure:    "nav-exposure",
  };
  if (page === "company" && state.currentId) {
    document.querySelectorAll(".nav-co").forEach(el => {
      if (String(el.dataset.id || "") === String(state.currentId)) el.classList.add("active");
    });
    return;
  }
  const id = pageNav[page];
  if (id) document.getElementById(id)?.classList.add("active");
}

function _showCompaniesView() {
  state.page = "companies";
  state.currentId = null;
  stopLiveDataPolling();
  stopCompanyPipelineSync();
  closeMobileNav();
  document.body.classList.add("executive-home");
  document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));
  document.getElementById("view-all").classList.add("active");
  _syncSidebarActive();
  document.getElementById("crumb-sep").style.display = "none";
  document.getElementById("crumb-current").textContent = "";
  document.getElementById("topbar-pill").innerHTML = "";
  renderAllCompanies();
}

let _companyPipelineSyncInterval = null;

function stopCompanyPipelineSync() {
  if (_companyPipelineSyncInterval) {
    clearInterval(_companyPipelineSyncInterval);
    _companyPipelineSyncInterval = null;
  }
}

async function refreshCompanyPipelineState(companyId, { render = true } = {}) {
  if (!companyId || !SERVER_MODE) return null;
  try {
    const r = await fetch(`/api/recon/${companyId}/pipeline`, {headers: _authHeaders()});
    if (!r.ok) return null;
    const ps = await r.json();
    pipelineState[companyId] = ps;

    if (!reconState[companyId]) reconState[companyId] = {};
    (ps.phases || []).forEach(ph => (ph.modules || []).forEach(m => {
      if (m.status !== "not_run") reconState[companyId][m.module] = {status: m.status};
    }));

    if (render) {
      // renderPipelineStatus updates the live phase HUD in place. We must NOT
      // rebuild the whole recon tab here: renderReconTab() re-fetches the
      // Playwright session artifact on every poll, which spammed the server
      // with one artifact/session request every 4s (403 loop on done jobs).
      renderPipelineStatus(companyId);
      const co = allCompanies().find(c => c.id === companyId);
      if (co && state.currentId === companyId) {
        renderOverview(co);
        renderAllCompanies();
      }
    }
    return ps;
  } catch (e) {
    return null;
  }
}

function startCompanyPipelineSync(companyId) {
  stopCompanyPipelineSync();
  if (!companyId || !SERVER_MODE) return;
  refreshCompanyPipelineState(companyId, {render: true});
  _companyPipelineSyncInterval = setInterval(() => {
    refreshCompanyPipelineState(companyId, {render: true});
  }, 4000);
}

function _buildReportHTML(co) {
  const findings = co.findings || [];
  const hosts = co.hosts || [];
  const now = new Date().toLocaleString('pt-BR');

  const sevCounts = {
    critical: findings.filter(f=>f.severity==='critical').length,
    high:     findings.filter(f=>f.severity==='high').length,
    medium:   findings.filter(f=>f.severity==='medium').length,
    low:      findings.filter(f=>f.severity==='low').length,
    info:     findings.filter(f=>f.severity==='info').length,
  };

  const findingsHTML = ['critical','high','medium','low','info'].flatMap(sev =>
    findings.filter(f=>f.severity===sev).map(f => `
      <tr>
        <td><span style="background:${sev==='critical'?'#ef4444':sev==='high'?'#f97316':sev==='medium'?'#eab308':sev==='low'?'#3b82f6':'#6b7280'};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700">${sev.toUpperCase()}</span></td>
        <td style="font-weight:600">${esc(f.title||'')}</td>
        <td>${esc(f.host||'')}</td>
        <td>${esc(f.category||f.type||'')}</td>
        <td style="font-size:11px;max-width:300px;word-break:break-word">${esc(f.desc||'')}</td>
      </tr>`)
  ).join('');

  const hostsHTML = hosts.slice(0,200).map(h => `
    <tr>
      <td style="font-family:monospace">${esc(h.host||'')}</td>
      <td>${esc(h.ip||'')}</td>
      <td>${esc(h.status_code||'')}</td>
      <td>${esc(h.title||'')}</td>
      <td>${esc(h.waf||'Direct')}</td>
      <td style="font-size:11px">${esc((h.technologies||h.techs||[]).slice(0,5).join(', '))}</td>
    </tr>`).join('');

  const portRows = hosts.flatMap(h => (h.ports || []).map(p => ({
    host: h.host || '', ip: h.ip || '', port: p,
  }))).slice(0, 300);
  const portsHTML = portRows.length
    ? portRows.map(r => `<tr><td style="font-family:monospace">${esc(r.host)}</td><td>${esc(r.ip)}</td><td>${esc(String(r.port))}</td></tr>`).join('')
    : '<tr><td colspan="3">Nenhuma porta mapeada</td></tr>';

  const buckets = co.cloud_buckets || co.s3_buckets || [];
  const bucketsHTML = buckets.length
    ? buckets.slice(0, 80).map(b => {
        const name = b.name || b.bucket || b.url || '';
        const provider = b.provider || b.type || '';
        const access = b.access || b.acl || b.public || '';
        return `<tr><td>${esc(String(name))}</td><td>${esc(String(provider))}</td><td>${esc(String(access))}</td></tr>`;
      }).join('')
    : '<tr><td colspan="3">Nenhum bucket catalogado</td></tr>';

  const supply = findings.filter(f => {
    const cat = `${f.category || ''} ${f.type || ''}`.toLowerCase();
    return cat.includes('supply') || cat.includes('dep_confusion') || cat.includes('dependency');
  });
  const supplyHTML = supply.length
    ? supply.map(f => `<tr><td>${esc(f.severity||'')}</td><td>${esc(f.title||'')}</td><td>${esc(f.host||'')}</td></tr>`).join('')
    : '<tr><td colspan="3">Nenhum finding de supply chain</td></tr>';

  const attackChains = findings.filter(f=>f.type==='attack_chain');
  const attackHTML = attackChains.map(f=>`<li><strong>${esc(f.title||'')}</strong> — ${esc(f.desc||'')}</li>`).join('') || '<li>No attack chains identified</li>';

  const html = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>ASM Report — ${co.name||co.id} — ${now}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 0; background: #fff; color: #1a1a2e; }
  .cover { background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 100%); color: #fff; padding: 60px 80px; min-height: 200px; }
  .cover h1 { font-size: 2.4rem; margin: 0 0 8px; font-weight: 800; }
  .cover .sub { font-size: 1rem; color: rgba(255,255,255,0.6); margin: 0; }
  .cover .meta { margin-top: 40px; font-size: 0.85rem; color: rgba(255,255,255,0.5); }
  .section { padding: 40px 80px; border-bottom: 1px solid #e5e7eb; }
  h2 { font-size: 1.4rem; color: #0f172a; margin: 0 0 20px; padding-bottom: 8px; border-bottom: 2px solid #6366f1; display: inline-block; }
  .stat-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 24px; }
  .stat-card { border-radius: 8px; padding: 20px; text-align: center; }
  .stat-num { font-size: 2.2rem; font-weight: 800; }
  .stat-lbl { font-size: 0.75rem; text-transform: uppercase; letter-spacing: .05em; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 16px; }
  th { background: #f8fafc; text-align: left; padding: 10px 12px; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: #64748b; border-bottom: 2px solid #e2e8f0; }
  td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
  tr:hover td { background: #f8fafc; }
  .chain-list { list-style: none; padding: 0; }
  .chain-list li { padding: 12px 16px; margin: 8px 0; background: #fff7ed; border-left: 4px solid #f97316; border-radius: 4px; font-size: 13px; }
  .footer { padding: 20px 80px; font-size: 12px; color: #94a3b8; text-align: center; border-top: 1px solid #e5e7eb; }
  @media print { .section { break-inside: avoid; } }
</style>
</head>
<body>
<div class="cover">
  <h1>Attack Surface Management Report</h1>
  <p class="sub">Target: ${co.name||co.id||''} &nbsp;|&nbsp; Scope: ${(co.domains||[]).length > 10 ? (co.domains.slice(0,10).join(', ') + ', +' + (co.domains.length - 10) + ' more') : (co.domains||[]).join(', ')}</p>
  <div class="meta">Generated: ${now} &nbsp;|&nbsp; Classification: CONFIDENTIAL — AUTHORIZED PENTEST</div>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <div class="stat-grid">
    <div class="stat-card" style="background:#fef2f2"><div class="stat-num" style="color:#ef4444">${sevCounts.critical}</div><div class="stat-lbl" style="color:#ef4444">Critical</div></div>
    <div class="stat-card" style="background:#fff7ed"><div class="stat-num" style="color:#f97316">${sevCounts.high}</div><div class="stat-lbl" style="color:#f97316">High</div></div>
    <div class="stat-card" style="background:#fefce8"><div class="stat-num" style="color:#ca8a04">${sevCounts.medium}</div><div class="stat-lbl" style="color:#ca8a04">Medium</div></div>
    <div class="stat-card" style="background:#eff6ff"><div class="stat-num" style="color:#3b82f6">${sevCounts.low}</div><div class="stat-lbl" style="color:#3b82f6">Low</div></div>
    <div class="stat-card" style="background:#f0fdf4"><div class="stat-num" style="color:#16a34a">${hosts.length}</div><div class="stat-lbl" style="color:#16a34a">Live Hosts</div></div>
  </div>
  <p style="color:#475569;line-height:1.7">
    This report covers the external attack surface of <strong>${co.name||co.id}</strong>.
    The assessment identified <strong>${findings.length} security findings</strong> across
    <strong>${hosts.length} live hosts</strong> and <strong>${(co.ct_subdomains||[]).length} discovered hosts</strong>.
    ${sevCounts.critical > 0 ? `<strong style="color:#ef4444">${sevCounts.critical} critical findings require immediate attention.</strong>` : ''}
  </p>
</div>

<div class="section">
  <h2>Attack Chains</h2>
  <ul class="chain-list">${attackHTML}</ul>
</div>

<div class="section">
  <h2>Findings (${findings.length})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Host</th><th>Category</th><th>Description</th></tr></thead>
    <tbody>${findingsHTML}</tbody>
  </table>
</div>

<div class="section">
  <h2>Live Hosts (${hosts.length})</h2>
  <table>
    <thead><tr><th>Hostname</th><th>IP</th><th>Status</th><th>Title</th><th>WAF</th><th>Technologies</th></tr></thead>
    <tbody>${hostsHTML}</tbody>
  </table>
</div>

<div class="section">
  <h2>Open Ports (${portRows.length})</h2>
  <table>
    <thead><tr><th>Host</th><th>IP</th><th>Port</th></tr></thead>
    <tbody>${portsHTML}</tbody>
  </table>
</div>

<div class="section">
  <h2>Cloud Storage (${buckets.length})</h2>
  <table>
    <thead><tr><th>Bucket</th><th>Provider</th><th>Access</th></tr></thead>
    <tbody>${bucketsHTML}</tbody>
  </table>
</div>

<div class="section">
  <h2>Supply Chain (${supply.length})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Host</th></tr></thead>
    <tbody>${supplyHTML}</tbody>
  </table>
</div>

<div class="footer">
  ASM Platform — Authorized Security Assessment — ${now} — CONFIDENTIAL
</div>
</body>
</html>`;

  return html;
}

function exportHTMLReport(co) {
  if (!co) return;
  const html = _buildReportHTML(co);
  const blob = new Blob([html], {type: 'text/html'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `asm-report-${(co.id||'target').replace(/[^a-z0-9]/gi,'-')}-${new Date().toISOString().slice(0,10)}.html`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function exportPDFReport(co) {
  if (!co) return;
  const html = _buildReportHTML(co);
  const win = window.open('', '_blank');
  if (!win) { showToast('Pop-up bloqueado. Permita pop-ups para exportar em PDF.'); return; }
  win.document.open();
  win.document.write(html);
  win.document.close();
  win.onload = () => { win.focus(); win.print(); };
  // Fallback in case onload doesn't fire (already-loaded blank doc)
  setTimeout(() => { try { win.focus(); win.print(); } catch(e) {} }, 600);
}

function showToast(msg, kind) {
  let stack = document.getElementById("toast-stack");
  if (!stack) {
    stack = document.createElement("div");
    stack.id = "toast-stack";
    stack.className = "toast-stack";
    document.body.appendChild(stack);
  }
  const el = document.createElement("div");
  el.className = "toast" + (kind ? " " + kind : "");
  el.textContent = String(msg || "");
  stack.appendChild(el);
  setTimeout(() => { try { el.remove(); } catch(e) {} }, 4200);
}

function renderCompanyView(co) {
  const s = co.stats||{};
  const _doms = co.domains || [];
  const _MAXD = 6;
  const _domSummary = _doms.length
    ? _doms.slice(0, _MAXD).join("  ·  ") + (_doms.length > _MAXD ? `  ·  +${_doms.length - _MAXD} more` : "")
    : "No domains";
  document.getElementById("co-desc").textContent = _domSummary + "  ·  " + t("lbl_last_scan") + ": " + (co.last_scan||"N/A");
  document.getElementById("tc-findings").textContent =
    (s.findings_critical||0)+(s.findings_high||0)+(s.findings_medium||0)+(s.findings_info||0);
  document.getElementById("tc-cve").textContent = co.cve_summary?.total || 0;
  document.getElementById("tc-supplychain").textContent = co.supply_chain_summary?.total || 0;
  const tcJs = document.getElementById("tc-jsreverse");
  if (tcJs) {
    const jsCount = Number(co.js_data?.total_secrets || 0) || (Array.isArray(co.js_data?.js_files) ? co.js_data.js_files.length : 0);
    tcJs.textContent = jsCount || "";
  }
  document.getElementById("tc-domains").textContent = (co.domains||[]).length || 0;
  document.getElementById("tc-subdomains").textContent = (co.hosts||[]).filter(_isActiveHost).length || 0;
  document.getElementById("tc-ports").textContent = s.open_ports || (co.hosts||[]).filter(h=>(h.ports||[]).length>0).length || 0;
  const tcOperation = document.getElementById("tc-operation");
  if (tcOperation) {
    const persist = _opSummarize(co);
    tcOperation.textContent = persist.badge ? String(persist.badge) : "";
  }
  document.getElementById("tc-screenshots").textContent = "";
  const hrStored = (co.breach_data && co.breach_data.hudsonrock) || {};
  const expCount = (window.ASMExposure && typeof window.ASMExposure.count === "function")
    ? window.ASMExposure.count(hrStored)
    : Number(hrStored.employees || 0);
  const tcExp = document.getElementById("tc-exposure");
  if (tcExp) tcExp.textContent = expCount > 0 ? String(expCount) : "";
  // Async: load counts without blocking render
  if (SERVER_MODE) {
    fetch(`/api/screenshots/${co.id}`, {headers:_authHeaders()}).then(r=>r.ok?r.json():[]).then(d=>{
      const el = document.getElementById("tc-screenshots");
      if(el && d.length) el.textContent = d.length;
      _applyScreenshotInventory(co, d);
    }).catch(()=>{});
    fetch(`/api/data/${co.id}/subhistory`, {headers: _authHeaders()}).then(r=>r.json()).then(d=>{
      const el = document.getElementById("tc-subhistory");
      if(el && d.history) el.textContent = d.history.length;
    }).catch(()=>{});
  }

  // Count all endpoints (URLs + JS + API)
  let endpointsTotal = 0;
  if (co.wayback_data?.interesting_count) endpointsTotal += co.wayback_data.interesting_count;
  if (co.urlfinder_data?.urls) endpointsTotal += co.urlfinder_data.urls.length;
  if (co.js_data?.total_endpoints) endpointsTotal += co.js_data.total_endpoints;
  if (co.api_exposure?.total) endpointsTotal += co.api_exposure.total;
  document.getElementById("tc-endpoints").textContent = endpointsTotal;

  renderOverview(co);
  try { setTimeout(initThreatMaps, 50); setTimeout(initThreatMaps, 400); } catch(e) {}
  try { setTimeout(updateTabScrollBtns, 100); } catch(e) {}
  renderFindingsTab(co);
  renderCveTab(co);
  invalidateEndpointCache(co);
  renderDomainsTab(co);
  renderSubdomainsTab(co);
  renderInfraTab(co);
  renderTyposquatTab(co);
  syncCompanyTabsAccessibility(TAB_TO_GROUP[state.tab] || state.tab || "overview");
  updateGroupCounts();
  initGroupCountObserver();
}

function _applyScreenshotInventory(co, shots) {
  if (!co || !Array.isArray(shots) || !shots.length) return;
  const map = new Map();
  shots.forEach(item => {
    const url = String(item.url || "").trim();
    let host = "";
    try { host = new URL(url).hostname || ""; } catch(e) {}
    if (!host && item.filename) host = _screenshotFilenameHost(item.filename);
    host = _normalizeScopeDomain(host);
    if (!host || map.has(host)) return;
    map.set(host, `screenshots/${co.id}/${item.filename}`);
  });
  if (!map.size) return;
  co._screenshotsByHost = map;
  (co.hosts || []).forEach(h => {
    const host = _normalizeScopeDomain(h.host || "");
    if (!host || !map.has(host)) return;
    if (!h.screenshot || _shotMissingCid(co.id, h.screenshot)) {
      h.screenshot = map.get(host);
    }
  });
  if (state.currentId === co.id && (state.tab === "subdomains" || state.activeGroup === "hosts")) {
    renderSubdomainsTab(co);
  }
}

function _screenshotFilenameHost(filename) {
  let name = String(filename || "").replace(/\.(png|jpe?g|webp)$/i, "");
  if (name.startsWith("browser_")) {
    name = name.slice(8);
    if (name.includes("___")) name = name.split("___").slice(1).join("___");
    return name.replace(/_/g, ".");
  }
  const gw = /^(https?)---(.+)-(\d+)$/i.exec(name);
  if (gw) return gw[2];
  name = name.replace(/^https?---/i, "");
  name = name.replace(/-\d+$/i, "");
  return name;
}

async function selectCompany(id) {
  state.page = "company";
  state.currentId = id;
  state.tab = "overview";
  state.hostsPage = 1;
  state.portsPage = 1;
  closeMobileNav();
  document.body.classList.remove("executive-home");

  document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));
  if (_jobsPoll) { clearInterval(_jobsPoll); _jobsPoll = null; }
  document.getElementById("view-company").classList.add("active");
  _syncSidebarActive();

  let co = allCompanies().find(c=>c.id===id);
  if (!co) return;

  const rl = riskLevel(co);
  document.getElementById("crumb-sep").style.display = "";
  document.getElementById("crumb-current").textContent = co.name;
  document.getElementById("co-title").textContent = co.name;

  const pillColors = {critical:"red", high:"orange", medium:"orange", low:"green"};
  document.getElementById("topbar-pill").innerHTML = `
    <div class="topbar-pill ${pillColors[rl]||'green'}">
      <span class="pulse"></span>${riskLabel(rl)}
    </div>`;

  // Show scan + monitor buttons in server mode
  var scanBtn = document.getElementById("topbar-scan-btn");
  scanBtn.style.display = SERVER_MODE ? "" : "none";
  var monBtn = document.getElementById("monitor-now-btn");
  if (monBtn) monBtn.style.display = SERVER_MODE ? "" : "none";
  var schBtn = document.getElementById("enable-schedule-btn");
  if (schBtn) schBtn.style.display = SERVER_MODE ? "" : "none";
  if (schBtn && SERVER_MODE) loadScheduleStatus(id);

  // Reset active tab button
  // A tela principal da empresa é a matriz de ativos (Ativos → Hosts).
  state.tab = "subdomains";
  state.activeGroup = "hosts";
  state.hostPanel = "subdomains";
  if (!state.groupPanel) state.groupPanel = {};
  state.groupPanel.hosts = "subdomains";
  document.querySelectorAll(".tab-btn").forEach(b=>b.classList.toggle("active", b.dataset.group === "hosts"));
  document.querySelectorAll(".tab-content").forEach(t=>t.classList.toggle("active", t.id === "tab-subdomains"));
  renderGroupSubnav("hosts", "subdomains");
  syncCompanyTabsAccessibility("hosts");

  if (SERVER_MODE && co.summary_only) {
    renderCompanyLoading(id);
    try {
      co = await ensureCompanyLoaded(id);
    } catch (e) {
      document.getElementById("co-desc").textContent = `Error loading company details: ${e.message}`;
      return;
    }
  }
  renderCompanyView(co);
  switchGroup("hosts", document.querySelector('.tab-btn[data-group="hosts"]'), "subdomains");
  if (SERVER_MODE) startCompanyPipelineSync(id);
  if (SERVER_MODE) { loadTrendCharts(id); loadSuppressedFindings(id); }
  // Always poll for live data while viewing a company
  startLiveDataPolling(id);
  // Update URL hash for browser history
  if (typeof ASM !== 'undefined' && ASM.updateHash) ASM.updateHash('company/' + id + '/subdomains');
}

const TAB_GROUPS = {
  overview:    ['overview'],
  hosts:       ['subdomains', 'domains', 'graph'],
  vulns:       ['vulns', 'cve', 'supplychain'],
  exposure:    ['exposure'],
  operation:   ['operation', 'alerts', 'timeline', 'diff', 'suppressed', 'toollogs', 'pipeline', 'terminal']
};
const TAB_TO_GROUP = {};
(function() { for (const [g, tabs] of Object.entries(TAB_GROUPS)) tabs.forEach(t => TAB_TO_GROUP[t] = g); })();

const GROUP_PANEL_I18N = {
  overview: "subtab_overview",
  domains: "subtab_domains",
  subdomains: "subtab_hosts",
  endpoints: "subtab_endpoints",
  ports: "subtab_ports",
  typosquat: "subtab_typosquat",
  vulns: "subtab_vulns",
  cve: "subtab_cve",
  supplychain: "subtab_supplychain",
  jsreverse: "subtab_jsreverse",
  infra: "subtab_infra",
  screenshots: "subtab_screenshots",
  operation: "subtab_operation",
  alerts: "subtab_alerts",
  timeline: "subtab_timeline",
  diff: "subtab_diff",
  suppressed: "subtab_suppressed",
  toollogs: "subtab_logs",
  pipeline: "subtab_pipeline",
  terminal: "subtab_terminal",
  graph: "subtab_graph",
  exposure: "subtab_exposure",
};

function _panelLabel(name) {
  const key = GROUP_PANEL_I18N[name];
  if (key && typeof t === "function") {
    const translated = t(key);
    if (translated && translated !== key) return translated;
  }
  return name;
}

function renderGroupSubnav(groupName, panel) {
  const el = document.getElementById("co-subnav");
  if (!el) return;
  const tabs = TAB_GROUPS[groupName] || [];
  if (tabs.length <= 1) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.hidden = false;
  el.setAttribute("role", "tablist");
  el.setAttribute("aria-label", typeof t === "function" ? t("aria_company_sub") : "Subseção da empresa");
  el.innerHTML = tabs.map(tabName => {
    const active = tabName === panel;
    const src = document.getElementById("tc-" + tabName);
    const rawCount = src ? String(src.textContent || "").trim() : "";
    const count = rawCount && rawCount !== "0" ? rawCount : "";
    return `<button type="button" class="group-subnav-btn${active ? " active" : ""}" role="tab" aria-selected="${active ? "true" : "false"}" data-panel="${tabName}" onclick="switchGroupPanel('${groupName}','${tabName}')">${esc(_panelLabel(tabName))}${count ? ` <span class="tab-count">${esc(count)}</span>` : ""}</button>`;
  }).join("");
}

async function switchGroup(groupName, btn, panelName) {
  const groupTabs = TAB_GROUPS[groupName] || [groupName];
  const requested = panelName || (state.groupPanel && state.groupPanel[groupName]) || (groupName === "hosts" ? state.hostPanel : null);
  const panel = groupTabs.includes(requested) ? requested : groupTabs[0];
  if (!state.groupPanel) state.groupPanel = {};
  state.groupPanel[groupName] = panel;
  if (groupName === "hosts") state.hostPanel = panel;
  state.tab = panel;
  state.activeGroup = groupName;

  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  if (btn) btn.classList.add('active');
  const pane = document.getElementById('tab-' + panel);
  if (pane) pane.classList.add('active');

  renderGroupSubnav(groupName, panel);
  syncCompanyTabsAccessibility(groupName);

  const co = allCompanies().find(c => c.id === state.currentId);
  const name = panel;
  if (name === 'overview'     && co)              renderOverview(co);
  if (name === 'domains'      && co)              { renderDomainsTab(co); renderInfraTab(co); renderTyposquatTab(co); }
  if (name === 'subdomains'   && co)              renderSubdomainsTab(co);
  if (name === 'pipeline'     && state.currentId) await renderReconTab(state.currentId);
  if (name === 'cve'          && co)              renderCveTab(co);
  if (name === 'supplychain'  && co)              renderSupplyChainTab(co);
  if (name === 'vulns'        && co)              renderVulnsTab(co);
  if (name === 'findings'     && co)              renderFindingsTab(co);
  if (name === 'operation'    && co)              renderOperationTab(co);
  if (name === 'toollogs'     && state.currentId) {
    await loadToolLogs();
  }
  if (name === 'terminal'     && state.currentId) renderLiveTerminal(state.currentId);
  if (name === 'alerts'       && co)              renderAlertsTab(co);
  if (name === 'timeline'     && co)              renderTimelineTab(co);
  if (name === 'diff'         && co)              renderDiffTab(co);
  if (name === 'suppressed'   && state.currentId) loadSuppressedFindings(state.currentId);
  if (name === 'graph'        && co && typeof renderAssetGraph === 'function') renderAssetGraph(co);
  if (name === 'exposure'     && co && typeof renderExposureTab === 'function') renderExposureTab(co);

  if (typeof ASM !== 'undefined' && ASM.updateHash && state.currentId) {
    ASM.updateHash('company/' + state.currentId + '/' + panel);
  }
  if (btn) btn.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  updateTabScrollBtns();
}

// Painéis que foram absorvidos pela matriz de ativos (uma tabela, uma coluna por assunto) ou pelo painel de domínios.
// Quem ainda chama o nome antigo (atalhos, busca global, prioridades) cai no lugar certo, já com o filtro aplicado.
const TAB_REDIRECT = {
  endpoints:   {to: "subdomains", has: "endpoints"},
  ports:       {to: "subdomains", has: "riskport"},
  screenshots: {to: "subdomains", has: "shot"},
  jsreverse:   {to: "subdomains", has: "secrets"},
  infra:       {to: "domains"},
  typosquat:   {to: "domains"},
};

async function switchTab(name, btn) {
  const redirect = TAB_REDIRECT[name];
  if (redirect) {
    await switchTab(redirect.to, btn);
    if (redirect.has) {
      const sel = document.getElementById("sub-has");
      if (sel) { sel.value = redirect.has; _subApplyFilter(); }
    }
    return;
  }
  const groupName = TAB_TO_GROUP[name] || name;
  if (!state.groupPanel) state.groupPanel = {};
  if ((TAB_GROUPS[groupName] || []).includes(name)) state.groupPanel[groupName] = name;
  if (groupName === "hosts") state.hostPanel = name;
  const groupBtn = document.querySelector(`.tab-btn[data-group="${groupName}"]`) || btn;
  return switchGroup(groupName, groupBtn, name);
}

function switchGroupPanel(groupName, panel) {
  if (!state.groupPanel) state.groupPanel = {};
  state.groupPanel[groupName] = panel;
  if (groupName === "hosts") state.hostPanel = panel;
  const groupBtn = document.querySelector(`.tab-btn[data-group="${groupName}"]`);
  return switchGroup(groupName, groupBtn, panel);
}

// Jump straight from any critical/high/medium/info severity indicator to the
// filtered Vulnerabilities tab for the given company.
let _pendingVulnFilter = null; // {cid, sev, q} applied by renderVulnsTab after fetch completes

function _applyPendingVulnFilter(cid) {
  if (!_pendingVulnFilter || _pendingVulnFilter.cid !== cid) return false;
  const sevSel = document.getElementById("f-sev");
  const searchEl = document.getElementById("f-search");
  if (!sevSel && !searchEl) return false;
  if (sevSel && _pendingVulnFilter.sev != null) sevSel.value = _pendingVulnFilter.sev;
  if (searchEl && _pendingVulnFilter.q) searchEl.value = _pendingVulnFilter.q;
  _pendingVulnFilter = null;
  applyFindFilter(cid);
  return true;
}

async function goToVulnSeverity(cid, severity, ev) {
  if (ev) ev.stopPropagation();
  const mappedSev = (severity === "info") ? "" : severity;
  _pendingVulnFilter = { cid, sev: mappedSev, q: "" };
  if (state.currentId !== cid || state.page !== "company") {
    await selectCompany(cid);
  }
  const groupBtn = document.querySelector('.tab-btn[data-group="vulns"]');
  await switchGroup("vulns", groupBtn);
  setTimeout(() => {
    _applyPendingVulnFilter(cid);
    const list = document.getElementById("f-list") || document.getElementById("tab-vulns");
    if (list) list.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 60);
}

function switchHostsPanel(panel) {
  return switchGroupPanel("hosts", panel);
}

function scrollTabBar(dir) {
  const tb = document.getElementById('co-tabs');
  if (!tb) return;
  tb.scrollBy({ left: dir * 220, behavior: 'smooth' });
  setTimeout(updateTabScrollBtns, 280);
}

function updateTabScrollBtns() {
  const tb = document.getElementById('co-tabs');
  const lBtn = document.getElementById('tab-scroll-left');
  const rBtn = document.getElementById('tab-scroll-right');
  if (!tb || !lBtn || !rBtn) return;
  const atStart = tb.scrollLeft <= 2;
  const atEnd   = tb.scrollLeft >= tb.scrollWidth - tb.clientWidth - 2;
  lBtn.style.display = atStart ? 'none' : 'flex';
  rBtn.style.display = atEnd   ? 'none' : 'flex';
}

const _GC_DEFS = {
  hosts:      ['subdomains'],
  vulns:      ['vulns', 'cve', 'supplychain', 'jsreverse'],
  exposure:   ['exposure'],
};

function updateGroupCounts() {
  for (const [group, ids] of Object.entries(_GC_DEFS)) {
    const total = ids.reduce((s, id) => {
      const el = document.getElementById('tc-' + id);
      return s + (el ? parseInt(el.textContent) || 0 : 0);
    }, 0);
    const el = document.getElementById('gc-' + group);
    if (el) el.textContent = total > 0 ? total : '';
  }
  if (state.activeGroup) renderGroupSubnav(state.activeGroup, state.tab);
}

function initGroupCountObserver() {
  const hidden = document.getElementById('tc-hidden');
  if (!hidden || hidden._gcObserved) return;
  hidden._gcObserved = true;
  new MutationObserver(updateGroupCounts).observe(hidden, { subtree: true, characterData: true, childList: true });
}
