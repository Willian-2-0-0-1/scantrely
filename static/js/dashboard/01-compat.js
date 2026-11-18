// ════════════════════════════════════════════════════════════════════════
//  COMPATIBILITY LAYER — bridges old globals to ASM namespace
//  When js/asm.js is loaded before this file, ASM namespace is available.
//  When loaded standalone (legacy), fall back to local definitions.
// ════════════════════════════════════════════════════════════════════════
(function() {
  'use strict';
  // If ASM module loaded, set up aliases. Otherwise define locally.
  if (typeof window.ASM === 'undefined') {
    // Legacy mode — define essential values locally
    window.SERVER_MODE = window.location.protocol === 'http:' && window.location.hostname !== '';
    window._authHeaders = function() {
      var tok = null;
      try { tok = localStorage.getItem('asmToken'); } catch(e) {}
      return tok ? {'x-auth-token': tok} : {};
    };
  }
})();

function icoHtml(name, size) {
  if (typeof window.icon === "function") return window.icon(name, { size: size || 16, className: "ico" });
  return '<span data-ico="'+name+'" data-ico-size="'+(size||16)+'" aria-hidden="true"></span>';
}
function _setIconLabel(el, name, text) {
  if (!el) return;
  el.innerHTML = icoHtml(name, 14) + " " + (text || "");
}

function originHref(raw, host) {
  return (window.ASMOrigin && typeof ASMOrigin.originHref === "function") ? ASMOrigin.originHref(raw, host) : "";
}
function isJsPathNoise(path) {
  if (window.ASMOrigin && typeof ASMOrigin.isJsPathNoise === "function") return ASMOrigin.isJsPathNoise(path);
  var s = String(path || "");
  return s.indexOf("../") === 0 || s.indexOf("./") === 0;
}
function originLinkHtml(raw, label, opts) {
  if (window.ASMOrigin && typeof ASMOrigin.originLinkHtml === "function") return ASMOrigin.originLinkHtml(raw, label, opts);
  return esc(label != null ? label : (raw || ""));
}
function originHostChip(host, extraClass) {
  if (window.ASMOrigin && typeof ASMOrigin.originHostChip === "function") {
    return ASMOrigin.originHostChip(host, extraClass);
  }
  return originLinkHtml("", host, { host: host, className: extraClass || "fg-host-chip origin-link" });
}
function _originTitle(kind) {
  if (typeof t === "function") {
    if (kind === "host") return t("origin_open_host") || "Abrir host";
    if (kind === "js") return t("origin_open_js") || "Abrir arquivo JS";
    return t("origin_open") || "Abrir o local em que foi achado";
  }
  return kind === "host" ? "Abrir host" : (kind === "js" ? "Abrir arquivo JS" : "Abrir o local em que foi achado");
}

let _pendingFoundFilter = null; // {tab, q} applied after switchTab paints the owner surface

async function jumpToFound(tab, query, ev) {
  if (ev) { ev.preventDefault(); ev.stopPropagation(); }
  _pendingFoundFilter = { tab: tab, q: String(query || "") };
  await switchTab(tab);
  setTimeout(_applyPendingFoundFilter, 80);
}

function _applyPendingFoundFilter() {
  const p = _pendingFoundFilter;
  if (!p) return;
  if (p.tab === "jsreverse") {
    const el = document.getElementById("jsr-text-filter");
    const ep = document.getElementById("jsr-ep-text");
    if (!el && !ep) return;
    _pendingFoundFilter = null;
    if (el) el.value = p.q;
    if (ep) ep.value = p.q;
    if (typeof _jsrRender === "function") _jsrRender();
    if (typeof _jsrRenderEp === "function") _jsrRenderEp();
    const tbl = document.getElementById("jsr-secrets-table") || document.getElementById("tab-jsreverse");
    if (tbl) tbl.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  if (p.tab === "endpoints") {
    const el = document.getElementById("url-search");
    if (!el) return;
    _pendingFoundFilter = null;
    el.value = p.q;
    window._urlSearch = p.q;
    if (typeof filterUrlsTable === "function") filterUrlsTable();
    const wrap = document.getElementById("urls-table-wrap") || document.getElementById("tab-endpoints");
    if (wrap) wrap.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}



// ════════════════════════════════════════════════════════════════════════
//  GLOBAL COMPAT — maps dashboard globals to the ASM namespace
//  (Defined in js/asm.js — available when loaded via dashboard.html)
// ════════════════════════════════════════════════════════════════════════
const SERVER_MODE = window.SERVER_MODE; // from asm.js

let DATA = (typeof window.ASM !== 'undefined' && ASM.data) ? ASM.data
  : (SERVER_MODE ? { version: '1.0', generated: null, companies: [] }
    : ((typeof window.ASM_DATA !== 'undefined') ? window.ASM_DATA : { version: '1.0', generated: null, companies: [] }));

// Keep DATA in sync with ASM namespace
if (typeof window.ASM !== 'undefined') {
  if (!ASM.data) ASM.data = { version: '1.0', generated: null, companies: [] };
  if (!ASM.data.companies) ASM.data.companies = [];
  DATA = ASM.data;
}

function _replaceCompanyInData(company) {
  if (typeof ASM !== 'undefined' && ASM.replaceCompanyInData) {
    ASM.replaceCompanyInData(company);
    return;
  }
  if (!company || !company.id) return;
  const companies = DATA.companies || [];
  const idx = companies.findIndex(c => c.id === company.id);
  if (idx >= 0) companies[idx] = company;
  else companies.push(company);
}

// ── API error helper ─────────────────────────────────────────────────────────
async function _apiErr(r) {
  if (r.status === 401) {
    // Only redirect to login if we have no token at all (not just a server-side expiry)
    const hasToken = !!(authToken || (function(){ try { return localStorage.getItem('asmToken'); } catch(_){ return null; } })());
    if (!hasToken && typeof showLoginScreen === 'function') showLoginScreen();
    return new Error('Session expired — please sign in again');
  }
  try {
    const d = await r.clone().json();
    return new Error(d.error || d.message || `HTTP ${r.status}`);
  } catch(_) {
    return new Error(`HTTP ${r.status}`);
  }
}

// These are provided by js/api.js when available
if (typeof loadServerSummary === 'undefined') {
  window.loadServerSummary = async function() {
    if (!SERVER_MODE) return;
    const r = await fetch('/api/data/summary', { headers: _authHeaders() });
    if (!r.ok) throw await _apiErr(r);
    const d = await r.json();
    // Mutate in place so DATA stays in sync with ASM.data
    DATA.version = d.version || DATA.version;
    DATA.generated = d.generated || DATA.generated;
    DATA.companies = d.companies || [];
  };
}
if (typeof ensureCompanyLoaded === 'undefined') {
  window.ensureCompanyLoaded = async function(id, opts = {}) {
    if (!SERVER_MODE || !id) return allCompanies().find(c => c.id === id);
    const existing = allCompanies().find(c => c.id === id);
    if (existing && !existing.summary_only && !opts.force) return existing;
    const r = await fetch(`/api/data/company/${encodeURIComponent(id)}`, { headers: _authHeaders() });
    if (!r.ok) throw await _apiErr(r);
    const d = await r.json();
    _replaceCompanyInData(d);
    return d;
  };
}
if (typeof reloadServerData === 'undefined') {
  window.reloadServerData = async function() {
    if (!SERVER_MODE) return;
    try {
      await loadServerSummary();
      if (ASM && ASM.currentId) await ensureCompanyLoaded(ASM.currentId, { force: true });
      else if (state && state.currentId) await ensureCompanyLoaded(state.currentId, { force: true });
    } catch(e) {}
    try {
      const r2 = await fetch('/api/companies', { headers: _authHeaders() });
      if (!r2.ok) return;
      const cos = await r2.json();
      const dataIds = new Set((DATA.companies || []).map(c => c.id));
      for (const co of cos) {
        if (!dataIds.has(co.id)) {
          DATA.companies = DATA.companies || [];
          DATA.companies.push({ ...co,
            stats: { subdomains: 0, live_hosts: 0, open_ports: 0, waf_protected: 0,
              findings_critical: 0, findings_high: 0, findings_medium: 0, findings_low: 0, findings_info: 0 },
            waf_coverage: {}, tech_summary: {}, findings: [], hosts: [], buckets: [] });
        }
      }
    } catch(e) {}
  };
}

// State object — use ASM when available, fallback to local
const state = (typeof ASM !== 'undefined') ? ASM : {
  currentId: null, page: 'companies', tab: 'overview',
  hostsPage: 1, portsPage: 1,
  hostsFilter: { q: '', waf: '', status: '' },
  findFilter: { q: '', sev: '', cat: '' },
  portsFilter: { q: '', port: '' },
  hostsData: [], portsData: [], findData: [],
  mobileNavOpen: false,
};
if (!state.page) state.page = "companies";
if (!state.hostPanel) state.hostPanel = "subdomains";
if (!state.groupPanel) state.groupPanel = {};
if (!state.groupPanel.hosts) state.groupPanel.hosts = state.hostPanel;

let _jobsPoll = null;
let _jobCountPoll = null;  // always-on job count updater for nav badge
let _companyQueueSummaryCache = [];
let _companyQueueSummaryLoading = false;
let _companyQueueSummaryLoaded = false;

function _cardKPI({ cls = "", value = "0", label = "", note = "" }) {
  return `
    <div class="portfolio-kpi ${cls}">
      <div class="value">${esc(value)}</div>
      <div class="label">${esc(label)}</div>
      ${note ? `<div class="job-detail-copy" style="margin-top:8px">${esc(note)}</div>` : ""}
    </div>`;
}

function _jobKPICard(status, count) {
  const label = _jobStatusLabel(status);
  return `
    <div class="job-kpi ${_jobStatusClass(status)}">
      <div class="job-kpi-num">${Number(count || 0)}</div>
      <div class="job-kpi-label">${esc(label)}</div>
    </div>`;
}

function _companyScopeCount(co) {
  return Array.isArray(co?.domains) ? co.domains.filter(Boolean).length : 0;
}

function _companyScopeLabel(co) {
  const total = _companyScopeCount(co);
  return `${total.toLocaleString()} ${total === 1 ? "dominio" : "dominios"} no escopo`;
}

function _companyQueueCounts(co) {
  const scopeTotal = _companyScopeCount(co);
  const summary = _companyQueueSummaryCache.find(s => String(s.company_id || "") === String(co?.id || ""));
  if (!summary) return { complete: 0, finalized: 0, queued: scopeTotal };
  const counts = summary.counts || {};
  return {
    complete: Number(counts.complete || 0),
    finalized: Number(counts.done || 0),
    queued: Number(counts.pending || 0) + Number(counts.running || 0),
  };
}

function _companyQueueProgress(co) {
  const summary = _companyQueueSummaryCache.find(s => String(s.company_id || "") === String(co?.id || ""));
  if (!summary) return null;
  const c = summary.counts || {};
  const total = Number(summary.total || 0);
  const done = Number(c.done || 0);
  const running = Number(c.running || 0);
  const pending = Number(c.pending || 0);
  const stopped = Number(c.stopped || 0);
  const error = Number(c.error || 0);
  const cancelled = Number(c.cancelled || 0);
  const complete = Number(c.complete || 0);
  const active = running + pending;
  if (!total) return null;
  const completed = done + stopped + error + cancelled;
  const rawPct = Math.min(100, ((completed + (running ? 0.5 : 0)) / total) * 100);
  const pct = active ? Math.max(rawPct, 2) : rawPct;
  return {total, complete, done, running, pending, stopped, error, cancelled, active, pct};
}

function _ensureCompanyQueueSummary() {
  if (!SERVER_MODE || _companyQueueSummaryLoaded || _companyQueueSummaryLoading) return;
  _companyQueueSummaryLoading = true;
  fetch("/api/jobs/summary", {headers:_authHeaders()})
    .then(r => r.ok ? r.json() : [])
    .then(summary => {
      _companyQueueSummaryCache = Array.isArray(summary) ? summary : [];
      _companyQueueSummaryLoaded = true;
      if (state.page === "companies") renderAllCompanies();
    })
    .catch(() => { _companyQueueSummaryLoaded = true; })
    .finally(() => { _companyQueueSummaryLoading = false; });
}

function _playwrightCard(job, opts = {}) {
  const meta = opts.meta || _fmtJobTime(job.created_at);
  const company = esc(_companyNameForJob(job.company_id));
  const target = esc(job.target || opts.target_url || "—");
  const status = _jobStatusLabel(job.status);
  const badges = [
    job.status === "done" ? `<a class="playwright-item-badge done" href="${_jobArtifactUrl(job.id, 'report')}" target="_blank" rel="noopener">Report</a>` : "",
    job.status === "done" ? `<a class="playwright-item-badge done" href="${_jobArtifactUrl(job.id, 'session')}" target="_blank" rel="noopener">Session</a>` : "",
    `<button class="playwright-item-badge" style="cursor:pointer" onclick="openJobDetail(${_jsArg(job.id)})">Details</button>`,
  ].join("");
  return `
    <article class="playwright-item">
      <div class="playwright-item-head">
        <div>
          <div class="playwright-item-title">${company}</div>
          <div class="playwright-item-sub">${target}</div>
        </div>
        <span class="playwright-item-badge ${_jobStatusClass(job.status)}">${status}</span>
      </div>
      <div class="playwright-item-sub" style="margin-top:8px">${esc(meta)}</div>
      <div class="playwright-item-sub" id="pw-inventory-${escAttr(job.id)}" style="margin-top:8px">${opts.inventory || ""}</div>
      <div class="playwright-item-badges">${badges}</div>
    </article>`;
}

async function _hydratePlaywrightInventory(job) {
  if (!job || job.job_type !== "playwright_recon") return;
  const mount = document.getElementById(`pw-inventory-${job.id}`);
  if (!mount) return;
  mount.innerHTML = `<span style="color:var(--text3)">Loading host inventory…</span>`;
  try {
    const r = await fetch(_jobArtifactUrl(job.id, "session"), {headers:_authHeaders()});
    if (!r.ok) throw new Error("HTTP " + r.status);
    const session = await r.json();
    mount.innerHTML = _playwrightInventorySummary(session);
  } catch(e) {
    mount.innerHTML = `<span style="color:var(--text3)">Inventory unavailable</span>`;
  }
}

function _hydratePlaywrightInventoryBatch(jobs) {
  (jobs || []).filter(job => job.job_type === "playwright_recon").slice(0, 4).forEach(job => {
    _hydratePlaywrightInventory(job);
  });
}

function _severityCard(severity, count, cid) {
  const classes = { critical: "c", high: "h", medium: "m", low: "l", info: "i" };
  const labels = {
    critical: _opT("vuln_sev_critical", "Crítica"),
    high: _opT("vuln_sev_high", "Alta"),
    medium: _opT("vuln_sev_medium", "Média"),
    low: _opT("vuln_sev_low", "Baixa"),
    info: _opT("vuln_sev_info", "Info"),
  };
  const click = cid ? ` onclick="goToVulnSeverity(${_jsArg(cid)},'${severity}',event)" style="cursor:pointer" title="Ver vulnerabilidades ${labels[severity] || severity}"` : "";
  return `
    <div class="findings-mini ${classes[severity] || ""}"${click}>
      <div class="findings-mini-num">${Number(count || 0)}</div>
      <div class="findings-mini-lbl">${labels[severity] || severity || "Info"}</div>
    </div>`;
}

function _hostTableRow(h) {
  const techs = (h.technologies || []).map(t => `<span class="tech-c">${esc(t)}</span>`).join("");
  const ports = (h.ports || []).map(p => `<span class="port-c">${esc(p)}</span>`).join("");
  const title = (h.title || "").substring(0, 80);
  const shotSrc = _shotSrc(h.screenshot);
  const screenshot = shotSrc
    ? `<img src="${esc(shotSrc)}" alt="${esc("Screenshot de " + (h.host || ""))}" style="width:48px;height:30px;object-fit:cover;border-radius:4px;border:1px solid var(--border);cursor:pointer" onerror="this.style.display='none'" onmouseenter="ssPopoverShow(event,${_shotJs(shotSrc)},${_shotJs(h.host || "")})" onmouseleave="ssPopoverHide()">`
    : `<span style="color:var(--text3);font-size:.6rem">—</span>`;
  return `
    <tr>
      <td><a class="host-a" href="https://${esc(h.host)}" target="_blank">${esc(h.host)}</a></td>
      <td><span class="ip-t">${esc(h.ip)}</span></td>
      <td><span style="font-size:.7rem;color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block" title="${esc(title)}">${esc(title) || '—'}</span></td>
      <td><span class="waf-t ${wafClass(h.waf)}">${esc(h.waf)}</span></td>
      <td>${techs || `<span style="color:var(--text3);font-size:.65rem">—</span>`}</td>
      <td>${ports || `<span style="color:var(--text3);font-size:.65rem">—</span>`}</td>
      <td>${screenshot}</td>
    </tr>`;
}

function _infraCard(title, rows, attrs = "") {
  return `
    <div class="ic" ${attrs}>
      <div class="ic-title">${esc(title)}</div>
      ${(rows || []).join("")}
    </div>`;
}

function _infraRow(key, value, cls = "") {
  return `<div class="ic-row"><span class="ic-k">${esc(key)}</span><span class="ic-v ${cls}">${value}</span></div>`;
}

function _timelineRow(e) {
  const ports = Array.isArray(e.ports) ? e.ports.join(', ') : e.ports;
  return `
    <div class="timeline-item">
      <div class="timeline-dot new"></div>
      <div class="timeline-info">
        <div class="timeline-host">${esc(e.host)}</div>
        <div class="timeline-meta">
          <span>IP: ${esc(e.ip||'?')}</span>
          <span>Ports: ${esc(ports)}</span>
          <span>Status: ${esc(e.status_code||'?')}</span>
          ${e.waf ? `<span>WAF: ${esc(e.waf)}</span>` : ''}
        </div>
      </div>
      <div class="timeline-ts">${esc((e.scan_ts||'').slice(0,16))}</div>
    </div>`;
}

// ── Always-polling job count badge for the sidebar nav ──
function _startJobCountPoll() {
  if (_jobCountPoll) return;
  _updateJobCountBadge();
  _jobCountPoll = setInterval(_updateJobCountBadge, 8000);
}
function _updateJobCountBadgeFromList(jobs) {
  const badge = document.getElementById("nav-jobs-badge");
  const pwBadge = document.getElementById("nav-playwright-badge");
  const topPwBadge = document.getElementById("topbar-playwright-badge");
  if (!badge) return;
  const running = jobs.filter(j => j.status === "running").length;
  const pending = jobs.filter(j => j.status === "pending").length;
  const errors  = jobs.filter(j => j.status === "error").length;
  const playwrightActive = jobs.filter(j => j.job_type === "playwright_recon" && (j.status === "running" || j.status === "pending")).length;
  const total   = running + pending;
  if (total > 0) {
    badge.style.display = "inline-flex";
    badge.textContent = total;
    badge.className = "nav-badge pulse";
    setTimeout(() => { if (badge.classList.contains("pulse")) badge.classList.remove("pulse"); }, 700);
    if (errors > 0) badge.classList.add("has-errors");
  } else {
    badge.style.display = "none";
  }
  if (pwBadge) {
    if (playwrightActive > 0) {
      pwBadge.style.display = "inline-flex";
      pwBadge.textContent = String(playwrightActive);
      pwBadge.className = "nav-badge pulse";
      pwBadge.title = `${playwrightActive} Playwright job(s) active`;
      setTimeout(() => { if (pwBadge.classList.contains("pulse")) pwBadge.classList.remove("pulse"); }, 700);
    } else {
      pwBadge.style.display = "none";
    }
  }
  if (topPwBadge) {
    if (playwrightActive > 0) {
      topPwBadge.style.display = "inline-flex";
      topPwBadge.textContent = `${playwrightActive} Playwright`;
      topPwBadge.className = "topbar-pw-badge pulse";
      topPwBadge.onclick = () => openJobsQueue("playwright_recon");
      setTimeout(() => { if (topPwBadge.classList.contains("pulse")) topPwBadge.classList.remove("pulse"); }, 700);
    } else {
      topPwBadge.style.display = "none";
    }
  }
}

async function _updateJobCountBadge() {
  try {
    const r = await fetch("/api/jobs?limit=50", {headers: _authHeaders()});
    if (!r.ok) return;
    const jobs = await r.json();
    _updateJobCountBadgeFromList(jobs);
    _updateScanProgressPill(jobs);
  } catch(e) {}
}

// ── Global "scan in progress" pill — visible from any page so the user
// always knows a long-running pipeline is active before closing the app ──
let _scanProgressCid = null;
async function _updateScanProgressPill(jobs) {
  const el = document.getElementById("topbar-scan-progress");
  if (!el) return;
  const running = (jobs || []).find(j => j.job_type === "pipeline" && j.status === "running");
  if (!running) {
    el.style.display = "none";
    _scanProgressCid = null;
    return;
  }
  _scanProgressCid = running.company_id;
  const co = allCompanies().find(c => c.id === running.company_id);
  const coName = co ? co.name : running.company_id;
  try {
    const r = await fetch(`/api/recon/${encodeURIComponent(running.company_id)}/pipeline`, {headers: _authHeaders()});
    if (!r.ok) return;
    const d = await r.json();
    if (!["running", "queued", "paused"].includes(d.status)) { el.style.display = "none"; return; }
    const total = Array.isArray(d.phases) ? d.phases.length : 0;
    const idx = (d.phase_idx || 0) + 1;
    const pct = total ? Math.min(100, Math.round((idx / total) * 100)) : 0;
    el.innerHTML = `
      <span class="pulse"></span>
      <span class="tsp-label">${esc(coName)} — Fase ${idx}${total ? "/" + total : ""}: ${esc(d.phase_label || "")}</span>
      <span class="tsp-bar"><span style="width:${pct}%"></span></span>`;
    el.style.display = "flex";
  } catch(e) {}
}
function _goToScanProgress() {
  if (_scanProgressCid) selectCompany(_scanProgressCid);
}

let extraCompanies = (typeof ASM !== 'undefined' && ASM.extraCompanies) ? ASM.extraCompanies
  : (function(){ try { return JSON.parse(localStorage.getItem('asm_extra_companies') || '[]'); } catch(e) { return []; } })();

function allCompanies() {
  if (typeof ASM !== 'undefined' && ASM.allCompanies) return ASM.allCompanies();
  return [...(DATA.companies || []), ...(extraCompanies || [])];
}
