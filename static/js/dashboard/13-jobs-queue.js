async function loadJobs() {
  const tbody = document.getElementById("jobs-tbody");
  if (!tbody) return;
  const note = document.getElementById("jobs-note");
  const pager = document.getElementById("jobs-pager");
  const deleteFilterBtn = document.getElementById("jobs-delete-filter");
  // KPI cards + per-company cards are driven by the aggregate summary so they
  // always reflect true totals, independent of what the table is showing.
  loadJobCompanyCards();
  renderPlaywrightOverviewAll();

  try {
    // Drill-down mode: the table becomes the per-domain list for one company.
    if (_jobDrilldownCid) {
      if (pager) pager.style.display = "none";
      if (deleteFilterBtn) deleteFilterBtn.style.display = "none";
      const cid = _jobDrilldownCid;
      const q = `company_id=${encodeURIComponent(cid)}`;
      const arr = a => Array.isArray(a) ? a : [];
      let jobs;
      if (_jobDrillQuery) {
        // Search expands job options too, so it finds domains stored inside
        // single pipeline jobs, not only per-domain queue targets.
        const res = await fetch(`/api/jobs?${q}&limit=500`, {headers:_authHeaders()}).then(r=>r.json());
        if (_jobDrilldownCid !== cid) return;
        jobs = arr(res);
      } else {
        const all = await fetch(`/api/jobs?${q}&limit=500`, {headers:_authHeaders()}).then(r=>r.json());
        if (_jobDrilldownCid !== cid) return;   // toggled away mid-flight
        jobs = arr(all);
      }
      const domainRows = _jobDomainRows(jobs, cid, _jobDrillQuery);
      renderJobDomains(domainRows, {cid});
      const sum = (_jobSummaryCache.find(s => s.company_id === cid) || {}).counts || {};
      const waitT = (sum.running||0)+(sum.pending||0), doneT = sum.done||0, stoppedT = sum.stopped||0;
      const back = `<a href="#" onclick="exitJobDrilldown();return false" style="color:var(--teal)">voltar para a fila</a>`;
      if (note) note.innerHTML = _jobDrillQuery
        ? `${domainRows.length} dominio(s) encontrados por "${esc(_jobDrillQuery)}" em <b>${esc(_companyNameForJob(cid))}</b>. ${back}`
        : `Dominios de <b>${esc(_companyNameForJob(cid))}</b>: ${domainRows.length.toLocaleString()} dominio(s), ${waitT.toLocaleString()} aguardando, ${doneT.toLocaleString()} finalizados, ${stoppedT.toLocaleString()} parados. ${back}`;
      return;
    }

    // Default mode: show recent queue history. Status filters narrow it down
    // without flooding the browser because the API remains capped.
    const type = document.getElementById("jobs-type-filter")?.value || "";
    const statusEl = document.getElementById("jobs-status-filter");
    const status = statusEl ? statusEl.value : "running";
    if (deleteFilterBtn) {
      deleteFilterBtn.style.display = ["done", "error", "cancelled", "stopped"].includes(status) ? "inline-flex" : "none";
    }
    const offset = (_jobsPage - 1) * JOBS_PAGE_SIZE;
    const url = `/api/jobs?limit=${JOBS_PAGE_SIZE}&offset=${offset}&include_total=1`
      + (type ? "&job_type=" + encodeURIComponent(type) : "")
      + (status ? "&status=" + encodeURIComponent(status) : "");
    const r = await fetch(url, {headers:_authHeaders()});
    if (!r.ok) throw new Error("HTTP " + r.status);
    const payload = await r.json();
    const jobs = Array.isArray(payload) ? payload : (payload.jobs || []);
    _jobsTotal = Array.isArray(payload) ? jobs.length : Number(payload.total || 0);
    const maxPage = Math.max(1, Math.ceil(_jobsTotal / JOBS_PAGE_SIZE));
    if (_jobsPage > maxPage) {
      _jobsPage = maxPage;
      return loadJobs();
    }
    renderJobs(jobs, {drilldown: false});
    renderJobsPager(_jobsTotal, _jobsPage, JOBS_PAGE_SIZE);
    _updateJobCountBadgeFromList(jobs);
    if (note) note.textContent = status === "running"
      ? `${_jobsTotal.toLocaleString()} job(s) rodando agora. Exibindo 20 por pagina. Clique em uma empresa para ver dominios pendentes e finalizados.`
      : `${_jobsTotal.toLocaleString()} job(s) no historico${type ? " de " + _jobTypeLabel(type) : ""}. Exibindo 20 por pagina.`;
  } catch(e) {
    tbody.innerHTML = `<tr><td colspan="8" style="color:var(--red);text-align:center;padding:22px">Failed to load jobs: ${esc(e.message)}</td></tr>`;
    if (note) note.textContent = "Fila indisponivel.";
    if (pager) pager.style.display = "none";
  }
}

function exitJobDrilldown() {
  _jobDrilldownCid = null;
  _jobDrillQuery = "";
  const dd = document.getElementById("jobs-drilldown");
  if (dd) dd.innerHTML = "";
  renderJobCompanyCards(_jobSummaryCache);
  loadJobs();
}

function _jobOptionDomains(job, cid) {
  const opts = job && job.options ? job.options : {};
  const domains = [];
  const add = value => {
    const clean = String(value || "").trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
    if (clean && clean !== cid && !domains.includes(clean)) domains.push(clean);
  };
  if (Array.isArray(opts.domains)) opts.domains.forEach(add);
  if (Array.isArray(opts.scope)) opts.scope.forEach(add);
  add(opts.queue_domain);
  add(opts.target_url);
  add(job && job.target);
  return domains;
}

function _jobDomainRows(jobs, cid, query) {
  const q = String(query || "").trim().toLowerCase();
  const rows = new Map();
  const sorted = [...(Array.isArray(jobs) ? jobs : [])].sort((a, b) => {
    return String(b.created_at || "").localeCompare(String(a.created_at || ""));
  });
  sorted.forEach(job => {
    _jobOptionDomains(job, cid).forEach(domain => {
      if (q && !domain.toLowerCase().includes(q)) return;
      if (!rows.has(domain)) rows.set(domain, {
        domain,
        job_id: job.id,
        company_id: job.company_id,
        job_type: job.job_type,
        status: job.status,
        attempts: job.attempts,
        max_attempts: job.max_attempts,
        created_at: job.created_at,
        started_at: job.started_at,
        finished_at: job.finished_at,
        error: job.error,
      });
    });
  });
  return [...rows.values()].sort((a, b) => {
    const sa = a.status === "running" ? 0 : a.status === "pending" ? 1 : 2;
    const sb = b.status === "running" ? 0 : b.status === "pending" ? 1 : 2;
    return sa - sb || a.domain.localeCompare(b.domain);
  });
}

function renderJobDomains(rows, ctx) {
  const tbody = document.getElementById("jobs-tbody");
  if (!tbody) return;
  const cid = ctx && ctx.cid;

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="8"><div class="job-empty">Nenhum dominio encontrado para esta empresa.</div></td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(row => {
    const cls = _jobStatusClass(row.status);
    const err = row.error ? `<div class="job-error" title="${esc(row.error)}">${esc(row.error)}</div>` : "";
    const canOpenResults = row.status === "done" || row.status === "running" || row.status === "stopped";
    return `<tr>
      <td><span class="job-status ${cls}">${_jobStatusLabel(row.status)}</span></td>
      <td>
        <div class="job-company" style="font-family:var(--mono)">${esc(row.domain)}</div>
        <div class="job-id">${esc(row.job_id)}</div>
        ${err}
      </td>
      <td><span class="job-type">${esc(_jobTypeLabel(row.job_type))}</span></td>
      <td>${_fmtJobTime(row.created_at)}</td>
      <td>${_fmtJobTime(row.started_at)}</td>
      <td>${_fmtJobTime(row.finished_at)}</td>
      <td>${Number(row.attempts || 0)} / ${Number(row.max_attempts || 1)}</td>
      <td>
        <div class="job-actions">
          <button type="button" class="btn btn-secondary btn-icon" data-job-action="detail" data-job-id="${escAttr(row.job_id)}">Detalhes</button>
          ${canOpenResults ? `<button type="button" class="btn btn-secondary btn-icon" data-job-action="domain-results" data-cid="${escAttr(cid)}" data-target="${escAttr(row.domain)}">Resultados</button>` : ""}
        </div>
      </td>
    </tr>`;
  }).join("");
}

function renderJobs(jobs, ctx) {
  const tbody = document.getElementById("jobs-tbody");
  if (!tbody) return;
  const drilldown = !!(ctx && ctx.drilldown);
  const cid = ctx && ctx.cid;

  if (!jobs.length) {
    const msg = drilldown ? "Nenhum dominio encontrado para esta empresa." : "Nenhum job encontrado neste filtro.";
    tbody.innerHTML = `<tr><td colspan="8"><div class="job-empty">${msg}</div></td></tr>`;
    return;
  }

  tbody.innerHTML = jobs.map(job => {
    const cls = _jobStatusClass(job.status);
    const err = job.error ? `<div class="job-error" title="${esc(job.error)}">${esc(job.error)}</div>` : "";
    const canCancel = job.status === "pending";
    const canDelete = ["done", "error", "cancelled", "stopped"].includes(job.status);
    const canArtifacts = job.job_type === "playwright_recon" && job.status === "done";
    const isErrorOrStuck = job.status === "error" || (job.status === "running" && job.attempts > 1);
    const rowClass = isErrorOrStuck ? " class='job-row-err'" : "";
    const primary = _jobPrimaryTarget(job);
    const secondary = `<div class="job-id">${esc(_jobSecondaryLabel(job))}</div>`;
    const isDone = job.status === "done";
    const openBtn = drilldown
      ? (isDone
          ? `<button type="button" class="btn btn-secondary btn-icon" data-job-action="domain-results" data-cid="${escAttr(cid)}" data-target="${escAttr(job.target || "")}">Resultados</button>`
          : "")
      : (job.company_id ? `<button type="button" class="btn btn-secondary btn-icon" data-job-action="open-company-pipeline" data-cid="${escAttr(job.company_id)}">Abrir</button>` : "");
    return `<tr${rowClass}>
      <td><span class="job-status ${cls}">${_jobStatusLabel(job.status)}</span></td>
      <td>
        <div class="job-company job-target">${esc(primary)}</div>
        ${secondary}
        ${err}
      </td>
      <td><span class="job-type">${esc(_jobTypeLabel(job.job_type))}</span></td>
      <td>${_fmtJobTime(job.created_at)}</td>
      <td>${_fmtJobTime(job.started_at)}</td>
      <td>${_fmtJobTime(job.finished_at)}</td>
      <td>${Number(job.attempts || 0)} / ${Number(job.max_attempts || 1)}</td>
      <td>
        <div class="job-actions">
          <button type="button" class="btn btn-secondary btn-icon" data-job-action="detail" data-job-id="${escAttr(job.id)}">Detalhes</button>
          ${openBtn}
          ${canArtifacts ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'report')}" target="_blank" rel="noopener">Relatorio</a>` : ""}
          ${canArtifacts ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'session')}" target="_blank" rel="noopener">Sessao</a>` : ""}
          ${canCancel ? `<button type="button" class="btn btn-icon job-cancel" data-job-action="cancel" data-job-id="${escAttr(job.id)}">Cancelar</button>` : ""}
          ${canDelete ? `<button type="button" class="btn btn-icon job-delete" data-job-action="delete" data-job-id="${escAttr(job.id)}">Excluir</button>` : ""}
        </div>
      </td>
    </tr>`;
  }).join("");

  const firstUseful = jobs.find(job => job.job_type === "playwright_recon" && job.status === "done");
  if (firstUseful && !document.querySelector("#job-detail-panel .job-detail-title")) {
    openJobDetail(firstUseful.id);
  }
}

function renderJobsPager(total, page, pageSize) {
  const pager = document.getElementById("jobs-pager");
  const info = document.getElementById("jobs-pinfo");
  const btns = document.getElementById("jobs-pbtns");
  if (!pager || !info || !btns) return;
  const pages = Math.max(1, Math.ceil((total || 0) / pageSize));
  if (!total || pages <= 1) {
    pager.style.display = "none";
    return;
  }
  pager.style.display = "flex";
  const start = (page - 1) * pageSize + 1;
  const end = Math.min(total, page * pageSize);
  info.textContent = `${start.toLocaleString()}-${end.toLocaleString()} de ${total.toLocaleString()} jobs`;

  const nums = [];
  const add = p => { if (!nums.includes(p) && p >= 1 && p <= pages) nums.push(p); };
  add(1);
  for (let p = page - 2; p <= page + 2; p++) add(p);
  add(pages);
  nums.sort((a,b) => a-b);

  let last = 0;
  const html = [];
  html.push(`<button class="pb" ${page <= 1 ? "disabled" : ""} onclick="setJobsPage(${page - 1})">←</button>`);
  nums.forEach(p => {
    if (last && p - last > 1) html.push(`<span class="job-page-gap">…</span>`);
    html.push(`<button class="pb ${p === page ? "active" : ""}" onclick="setJobsPage(${p})">${p}</button>`);
    last = p;
  });
  html.push(`<button class="pb" ${page >= pages ? "disabled" : ""} onclick="setJobsPage(${page + 1})">→</button>`);
  btns.innerHTML = html.join("");
}

function setJobsPage(page) {
  _jobsPage = Math.max(1, Number(page) || 1);
  loadJobs();
}

// ── Per-company queue cards + per-domain drill-down ───────────────────────────
let _jobSummaryCache = [], _jobDrilldownCid = null;
let _jobDrillQuery = "", _jobDrillTimer = null;

// Persistent search bar for the drill-down (rendered once on entry so the 5s
// poll that refreshes the table body does not steal focus or reset the query).
function _renderJobDrillSearchBar(cid) {
  const host = document.getElementById("jobs-drilldown");
  if (!host) return;
  host.innerHTML = `
    <div class="jobs-drillbar">
      <input class="fi" id="job-drill-search" type="text" value="${escAttr(_jobDrillQuery)}"
             placeholder="Buscar dominio em ${esc(_companyNameForJob(cid))}..."
             oninput="_onJobDrillSearch()" autocomplete="off"
             aria-label="Buscar dominio nesta empresa">
      <button class="btn btn-secondary btn-icon" onclick="exitJobDrilldown()">Voltar</button>
    </div>`;
}

function _onJobDrillSearch() {
  const inp = document.getElementById("job-drill-search");
  _jobDrillQuery = inp ? inp.value.trim() : "";
  clearTimeout(_jobDrillTimer);
  _jobDrillTimer = setTimeout(() => { if (_jobDrilldownCid) loadJobs(); }, 280);
}

async function loadJobCompanyCards() {
  const host = document.getElementById("jobs-company-cards");
  if (!host) return;
  try {
    const r = await fetch("/api/jobs/summary", {headers:_authHeaders()});
    if (!r.ok) throw new Error("HTTP " + r.status);
    _jobSummaryCache = await r.json();
    renderJobCompanyCards(_jobSummaryCache);
  } catch(e) {
    host.innerHTML = `<div style="color:var(--text3);font-size:.7rem;padding:6px 0">Per-company summary unavailable.</div>`;
  }
}

function _renderJobKPIs(summary) {
  const el = document.getElementById("jobs-summary");
  if (!el) return;
  const totals = {running:0, pending:0, done:0, error:0, stopped:0, cancelled:0};
  (Array.isArray(summary) ? summary : []).forEach(s => {
    const c = s.counts || {};
    for (const k in totals) totals[k] += (c[k] || 0);
  });
  el.innerHTML = ["running", "pending", "done", "error", "stopped", "cancelled"].map(st => _jobKPICard(st, totals[st] || 0)).join("");
}

function renderJobCompanyCards(summary) {
  const host = document.getElementById("jobs-company-cards");
  if (!host) return;
  _renderJobKPIs(summary);
  if (!Array.isArray(summary) || !summary.length) {
    host.innerHTML = "";
    _jobDrilldownCid = null;
    _jobDrillQuery = "";
    const dd = document.getElementById("jobs-drilldown");
    if (dd) dd.innerHTML = "";
    return;
  }
  const cards = summary.filter(s => (s.total || 0) > 0);
  const chip = (n, label, cls) => n ? `<span class="job-chip ${cls}">${n.toLocaleString()} ${label}</span>` : "";
  host.innerHTML = `<div class="job-company-card-grid">` + cards.map(s => {
    const c = s.counts || {};
    const active = _jobDrilldownCid === s.company_id;
    const name = _companyNameForJob(s.company_id);
    return `
      <div class="job-company-card ${active ? "active" : ""}" data-job-company-id="${escAttr(s.company_id)}" role="button" tabindex="0">
        <div class="job-company-card-head">
          <div class="job-company-card-title">${esc(name)}</div>
          <div class="job-company-card-total">${(s.total||0).toLocaleString()} jobs</div>
        </div>
        <div class="job-company-card-chips">
          ${chip(c.running, "rodando", "running")}
          ${chip(c.pending, "pendente", "pending")}
          ${chip(c.done, "finalizado", "done")}
          ${chip(c.error, "erro", "error")}
          ${chip(c.cancelled, "cancelado", "cancelled")}
          ${chip(c.stopped, "parado", "stopped")}
        </div>
        <div class="job-company-card-cta">${active ? "Mostrando dominios na tabela" : "Ver dominios da fila"}</div>
      </div>`;
  }).join("") + `</div>`;
}

function toggleJobDrilldown(cid) {
  const entering = _jobDrilldownCid !== cid;
  _jobDrilldownCid = entering ? cid : null;
  _jobDrillQuery = "";
  const dd = document.getElementById("jobs-drilldown");
  if (entering) _renderJobDrillSearchBar(cid);
  else if (dd) dd.innerHTML = "";
  renderJobCompanyCards(_jobSummaryCache);   // update active state immediately
  loadJobs();                                // table switches into / out of drill-down mode
}

async function openDomainResults(cid, domain) {
  try { await selectCompany(cid); } catch(e) {}
  openSubdomainsFiltered(domain);
}

// Launch dialog: lets the operator set safe-mode, active tests (XSS/Race) and auth-state
// before running. Active tests are gated behind safe-mode OFF + an authorization confirm.
function openPlaywrightModal(cid) {
  const cfg = _currentPlaywrightDefaults();
  const co = allCompanies().find(c => c.id === cid);
  const target = (co?.domains || []).filter(Boolean)[0] || "";
  const safe = cfg.playwright_safe_mode !== false;
  closePlaywrightModal();
  const ov = document.createElement("div");
  ov.className = "modal-overlay show";
  ov.id = "modal-playwright";
  ov.innerHTML = `
    <div class="modal" style="width:470px">
      <div class="modal-title">${icoHtml("play",14)} Playwright Recon — ${esc(co?.name || cid)}</div>
      <div class="modal-hint" style="margin-bottom:12px">Target: https://${esc(String(target).replace(/^https?:\/\//, ""))}</div>
      <div style="display:flex;gap:10px">
        <div class="modal-field" style="flex:1"><label class="modal-label">Max pages</label>
          <input type="number" class="modal-input" id="pw-max-pages" value="${Number(cfg.playwright_max_pages || 50)}" min="1" max="2000"></div>
        <div class="modal-field" style="flex:1"><label class="modal-label">Max depth</label>
          <input type="number" class="modal-input" id="pw-max-depth" value="${Number(cfg.playwright_max_depth || 3)}" min="1" max="10"></div>
      </div>
      <div class="modal-field"><label class="modal-label">Auth state — storage_state JSON (habilita testes autenticados)</label>
        <input type="text" class="modal-input" id="pw-auth-state" value="${esc(cfg.playwright_auth_state || "")}" placeholder="/caminho/para/auth.json"></div>
      <div class="modal-field"><label class="modal-label">Auth state B — para IDOR A/B (opcional)</label>
        <input type="text" class="modal-input" id="pw-auth-state-b" value="${esc(cfg.playwright_auth_state_b || "")}" placeholder="/caminho/para/auth-b.json"></div>
      <label class="modal-label" style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:10px">
        <input type="checkbox" id="pw-safe-mode" ${safe ? "checked" : ""} onchange="_pwSafeToggle()"><span>Safe mode (sem testes ativos)</span></label>
      <div id="pw-active-box" style="border:1px solid var(--border);border-radius:8px;padding:10px;margin-bottom:10px;opacity:${safe ? 0.5 : 1}">
        <div class="modal-hint" id="pw-active-warn" style="margin-top:0;color:var(--orange);${safe ? "display:none" : ""}">${icoHtml("warning",14)} Active testing — use apenas em alvos autorizados.</div>
        <label class="modal-label" style="display:flex;align-items:center;gap:8px;cursor:pointer;margin:8px 0 0">
          <input type="checkbox" class="pw-active-chk" id="pw-test-xss" ${cfg.playwright_test_xss ? "checked" : ""} ${safe ? "disabled" : ""}><span>Test XSS (confirmado por execução real)</span></label>
        <label class="modal-label" style="display:flex;align-items:center;gap:8px;cursor:pointer;margin:8px 0 0">
          <input type="checkbox" class="pw-active-chk" id="pw-test-race" ${cfg.playwright_test_race ? "checked" : ""} ${safe ? "disabled" : ""}><span>Test Race (probe paralelo bounded, não-destrutivo)</span></label>
        <label class="modal-label" style="display:flex;align-items:center;gap:8px;cursor:pointer;margin:8px 0 0">
          <input type="checkbox" class="pw-active-chk" id="pw-test-access" ${cfg.playwright_test_access ? "checked" : ""} ${safe ? "disabled" : ""}><span>Test Access (broken access control — "confia no front")</span></label>
      </div>
      <label class="modal-label" style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:6px">
        <input type="checkbox" id="pw-allow-external" ${cfg.playwright_allow_external ? "checked" : ""}><span>Allow external (seguir fora do escopo)</span></label>
      <div class="modal-btns">
        <button class="btn btn-secondary" onclick="closePlaywrightModal()">Cancel</button>
        <button class="btn btn-primary" onclick="submitPlaywrightRecon('${cid}')">${icoHtml("play",14)} Run</button>
      </div>
    </div>`;
  ov.addEventListener("click", e => { if (e.target === ov) closePlaywrightModal(); });
  document.body.appendChild(ov);
}

function _pwSafeToggle() {
  const safe = document.getElementById("pw-safe-mode").checked;
  document.querySelectorAll(".pw-active-chk").forEach(c => { c.disabled = safe; if (safe) c.checked = false; });
  document.getElementById("pw-active-box").style.opacity = safe ? 0.5 : 1;
  const warn = document.getElementById("pw-active-warn");
  if (warn) warn.style.display = safe ? "none" : "";
}

function closePlaywrightModal() {
  const el = document.getElementById("modal-playwright");
  if (el) el.remove();
}

function submitPlaywrightRecon(cid) {
  const v = id => document.getElementById(id);
  const opts = {
    max_pages: Number(v("pw-max-pages").value) || 50,
    max_depth: Number(v("pw-max-depth").value) || 3,
    auth_state: v("pw-auth-state").value.trim(),
    auth_state_b: v("pw-auth-state-b").value.trim(),
    safe_mode: v("pw-safe-mode").checked,
    test_xss: v("pw-test-xss").checked,
    test_race: v("pw-test-race").checked,
    test_access: v("pw-test-access").checked,
    allow_external: v("pw-allow-external").checked,
  };
  if (!opts.safe_mode && (opts.test_xss || opts.test_race || opts.test_access)) {
    if (!confirm("Active testing (XSS/Race/Access) envia payloads/requests ao alvo. Confirme que você tem autorização para testar este alvo.")) return;
  }
  let cfg = {};
  try { cfg = JSON.parse(localStorage.getItem("asm_settings") || "{}"); } catch(e) {}
  Object.assign(cfg, {
    playwright_max_pages: opts.max_pages, playwright_max_depth: opts.max_depth,
    playwright_auth_state: opts.auth_state, playwright_auth_state_b: opts.auth_state_b,
    playwright_safe_mode: opts.safe_mode, playwright_test_xss: opts.test_xss,
    playwright_test_race: opts.test_race, playwright_test_access: opts.test_access,
    playwright_allow_external: opts.allow_external,
  });
  try { localStorage.setItem("asm_settings", JSON.stringify(cfg)); } catch(e) {}
  closePlaywrightModal();
  runPlaywrightRecon(cid, opts);
}

async function runPlaywrightRecon(cid, opts = null) {
  const btn = document.getElementById(`playwright-btn-${cid}`);
  if (btn) { btn.disabled = true; btn.textContent = "Starting…"; }
  const cfg = _currentPlaywrightDefaults();
  const o = opts || {};
  const pick = (k, def) => (o[k] !== undefined ? o[k] : (cfg["playwright_" + k] !== undefined ? cfg["playwright_" + k] : def));
  const safe_mode = o.safe_mode !== undefined ? !!o.safe_mode : (cfg.playwright_safe_mode !== false);
  try {
    const co = allCompanies().find(c => c.id === cid);
    const domains = Array.isArray(co?.domains) ? co.domains.filter(Boolean) : [];
    const target = domains.length ? `https://${String(domains[0]).replace(/^https?:\/\//, "")}` : "";
    const r = await fetch(`/api/recon/${cid}/playwright`, {
      method: "POST",
      headers: {"Content-Type":"application/json", ..._authHeaders()},
      body: JSON.stringify({
        target_url: target,
        scope: domains,
        max_pages: Number(pick("max_pages", 50)),
        max_depth: Number(pick("max_depth", 3)),
        timeout: Number(cfg.playwright_timeout || 20),
        slow_mo: Number(cfg.playwright_slow_mo || 0),
        user_agent: cfg.playwright_user_agent || "",
        allow_external: !!pick("allow_external", false),
        safe_mode: safe_mode,
        // Active tests are only sent when safe-mode is off (backend enforces this too).
        test_xss: !safe_mode && !!(o.test_xss ?? cfg.playwright_test_xss),
        test_race: !safe_mode && !!(o.test_race ?? cfg.playwright_test_race),
        test_access: !safe_mode && !!(o.test_access ?? cfg.playwright_test_access),
        trace: !!pick("trace", false),
        headless: o.headless !== undefined ? !!o.headless : (cfg.playwright_headless !== false),
        auth_state: (o.auth_state ?? cfg.playwright_auth_state) || "",
        auth_state_b: (o.auth_state_b ?? cfg.playwright_auth_state_b) || "",
      }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
    showPage("jobs");
    loadJobs();
  } catch(e) {
  if (btn) { btn.disabled = false; btn.textContent = " Playwright Recon"; }
    showToast("Erro ao iniciar Playwright Recon: " + e.message);
  }
}

async function cancelJob(jobId) {
  if (!confirm("Cancel this pending job?")) return;
  try {
    const r = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`, {method:"DELETE", headers:_authHeaders()});
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      showToast(data.error || "Could not cancel job");
      return;
    }
    loadJobs();
  } catch(e) {
    showToast("Connection error: " + e.message);
  }
}

async function deleteJob(jobId) {
  if (!confirm("Excluir este registro finalizado da fila?")) return;
  try {
    const r = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`, {method:"DELETE", headers:_authHeaders()});
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      showToast(data.error || "Could not delete job");
      return;
    }
    loadJobs();
  } catch(e) {
    showToast("Connection error: " + e.message);
  }
}

async function deleteJobsFilter() {
  const type = document.getElementById("jobs-type-filter")?.value || "";
  const status = document.getElementById("jobs-status-filter")?.value || "";
  const finalStatuses = ["done", "error", "cancelled", "stopped"];
  if (!finalStatuses.includes(status)) {
    showToast("Selecione um status finalizado para limpar: Concluido, Erro, Parado ou Cancelado.");
    return;
  }
  if (!confirm(`Excluir todos os registros com status "${_jobStatusLabel(status)}"${type ? " de " + _jobTypeLabel(type) : ""}? Jobs rodando e pendentes nao serao apagados.`)) return;
  const params = new URLSearchParams({status});
  if (type) params.set("job_type", type);
  try {
    const r = await fetch(`/api/jobs?${params.toString()}`, {method:"DELETE", headers:_authHeaders()});
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      showToast(data.error || "Could not delete jobs");
      return;
    }
    _jobsPage = 1;
    loadJobs();
  } catch(e) {
    showToast("Connection error: " + e.message);
  }
}

function initJobQueueHandlers() {
  if (window.__jobQueueHandlersReady) return;
  window.__jobQueueHandlersReady = true;

  document.addEventListener("click", event => {
    const btn = event.target && event.target.closest ? event.target.closest("[data-job-action]") : null;
    if (!btn) return;
    const action = btn.dataset.jobAction;
    if (!action) return;
    event.preventDefault();
    event.stopPropagation();

    if (action === "detail") {
      openJobDetail(btn.dataset.jobId || "");
    } else if (action === "open-company-pipeline") {
      openJobCompanyPipeline(btn.dataset.cid || "");
    } else if (action === "domain-results") {
      openDomainResults(btn.dataset.cid || "", btn.dataset.target || "");
    } else if (action === "cancel") {
      cancelJob(btn.dataset.jobId || "");
    } else if (action === "delete") {
      deleteJob(btn.dataset.jobId || "");
    }
  });

  document.addEventListener("click", event => {
    const card = event.target && event.target.closest ? event.target.closest("[data-job-company-id]") : null;
    if (!card) return;
    event.preventDefault();
    toggleJobDrilldown(card.dataset.jobCompanyId || "");
  });

  document.addEventListener("keydown", event => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const card = event.target && event.target.closest ? event.target.closest("[data-job-company-id]") : null;
    if (!card) return;
    event.preventDefault();
    toggleJobDrilldown(card.dataset.jobCompanyId || "");
  });

  document.addEventListener("change", event => {
    const id = event.target && event.target.id;
    if (id === "jobs-type-filter" || id === "jobs-status-filter") {
      _jobsPage = 1;
      loadJobs();
    }
  });

  document.addEventListener("click", event => {
    const btn = event.target && event.target.closest ? event.target.closest("#jobs-badge") : null;
    if (!btn) return;
    event.preventDefault();
    showPage("jobs");
    loadJobs();
  });
}

document.addEventListener("DOMContentLoaded", initJobQueueHandlers);
