// ════════════════════════════════════════════════════════════════════════
//  JOB QUEUE
// ════════════════════════════════════════════════════════════════════════
function _jobStatusLabel(status) {
  const labels = {pending:"Pendente", running:"Rodando", done:"Finalizado", error:"Erro", cancelled:"Cancelado", stopped:"Parado", paused:"Pausado (máquina carregada — retoma sozinho)"};
  return labels[status] || status || "unknown";
}

function _jobStatusClass(status) {
  if (status === "done") return "done";
  if (status === "running") return "running";
  if (status === "pending") return "pending";
  if (status === "error") return "error";
  if (status === "cancelled") return "cancelled";
  if (status === "stopped") return "stopped";
  if (status === "paused") return "pending";   // pausa do watchdog: volta à fila sozinha
  return "unknown";
}

function _fmtJobTime(value) {
  if (!value) return "—";
  try {
    const d = new Date(value);
    if (!Number.isNaN(d.getTime())) {
      return d.toLocaleString(undefined, {month:"short", day:"2-digit", hour:"2-digit", minute:"2-digit"});
    }
  } catch(e) {}
  return String(value).replace("T", " ").slice(0, 16);
}

function _companyNameForJob(cid) {
  const co = allCompanies().find(c => c.id === cid);
  return co ? co.name : (cid || "—");
}

function _jsArg(value) {
  return JSON.stringify(String(value || ""));
}

function _jobTypeLabel(type) {
  const map = {
    pipeline: "ASM Pipeline",
    playwright_recon: "Playwright Recon",
  };
  return map[type] || type || "job";
}

function _jobArtifactUrl(jobId, kind) {
  return `/api/jobs/${encodeURIComponent(jobId)}/artifact/${encodeURIComponent(kind)}`;
}

const JOBS_PAGE_SIZE = 20;
let _jobsPage = 1;
let _jobsTotal = 0;

function _jobPrimaryTarget(job) {
  const opts = job?.options || {};
  const pick = [
    job?.target,
    opts.queue_domain,
    opts.target_url,
    Array.isArray(opts.domains) ? opts.domains[0] : "",
    Array.isArray(opts.scope) ? opts.scope[0] : "",
  ].find(Boolean);
  const clean = String(pick || "").trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
  return clean || "—";
}

function _jobSecondaryLabel(job) {
  const company = _companyNameForJob(job?.company_id);
  return `${company} · ${job?.id || ""}`;
}

function _playwrightInventorySummary(session) {
  if (!session) return "";
  const discovered = Array.isArray(session.discovered_hosts) ? session.discovered_hosts.length : 0;
  const validated = Array.isArray(session.validated_hosts) ? session.validated_hosts.length : 0;
  const pending = Array.isArray(session.pending_hosts) ? session.pending_hosts.length : 0;
  const items = Array.isArray(session.host_inventory) ? session.host_inventory : [];
  const chips = items.slice(0, 8).map(item => {
    const st = item.status_code == null ? "pending" : "validated";
    const code = item.status_code == null ? "pending" : String(item.status_code);
    return `<code class="fg-host-chip fg-host-chip-full ${st}" title="${esc(item.source || "browser")}">${esc(item.host)} · ${esc(code)}</code>`;
  }).join("");
  return `
    <div class="job-detail-grid">
      <div><span class="job-detail-k">${esc(_opT("op_discovered", "Descobertos"))}</span><div class="job-detail-v">${discovered}</div></div>
      <div><span class="job-detail-k">${esc(_opT("op_validated", "Validados"))}</span><div class="job-detail-v">${validated}</div></div>
      <div><span class="job-detail-k">${esc(_opT("op_pending_hosts", "Pendentes"))}</span><div class="job-detail-v">${pending}</div></div>
      <div><span class="job-detail-k">${esc(_opT("op_inventory", "Inventário"))}</span><div class="job-detail-v">${items.length}</div></div>
    </div>
    ${chips ? `<div class="chip-row" style="margin-top:10px">${chips}</div>` : ""}
  `;
}

function openJobsQueue(jobType) {
  const typeEl = document.getElementById("jobs-type-filter");
  if (typeEl) typeEl.value = jobType || "";
  showPage("jobs");
  loadJobs();
}

async function openJobCompanyPipeline(cid) {
  if (!cid) return;
  await selectCompany(cid);
  await switchTab("pipeline");
}

function _jobDetailPanel() {
  return document.getElementById("job-detail-panel");
}

function _renderJobDetail(job, preview) {
  const panel = _jobDetailPanel();
  if (!panel) return;
  const isPlaywright = job.job_type === "playwright_recon";
  const artReport = isPlaywright && job.status === "done" ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'report')}" target="_blank" rel="noopener">Open Report</a>` : "";
  const artSession = isPlaywright && job.status === "done" ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'session')}" target="_blank" rel="noopener">Open Session</a>` : "";
  const opts = job.options || {};
  const previewHtml = preview ? `
    <div class="job-detail-grid">
      <div><span class="job-detail-k">Pages</span><div class="job-detail-v">${preview.pages || 0}</div></div>
      <div><span class="job-detail-k">Endpoints</span><div class="job-detail-v">${preview.endpoints || 0}</div></div>
      <div><span class="job-detail-k">JS Chunks</span><div class="job-detail-v">${preview.js || 0}</div></div>
      <div><span class="job-detail-k">Tech</span><div class="job-detail-v">${preview.tech || 0}</div></div>
    </div>
    ${preview.inventory ? _playwrightInventorySummary(preview.inventory) : ""}
    ${preview.note ? `<div class="job-detail-copy">${esc(preview.note)}</div>` : ""}
    ${preview.report ? `<pre class="job-detail-pre">${esc(preview.report)}</pre>` : ""}
  ` : `<div class="job-detail-copy">No Playwright session preview available yet.</div>`;

  panel.style.display = "block";
  panel.innerHTML = `
    <div class="job-detail-card">
      <div class="job-detail-head">
        <div>
          <div class="job-detail-title">${esc(_jobTypeLabel(job.job_type))}</div>
          <div class="job-detail-copy">${esc(job.id)} · ${esc(job.company_id || "—")} · ${esc(job.status || "—")}</div>
        </div>
        <div class="job-actions">${artReport}${artSession}</div>
      </div>
      <div class="job-detail-grid">
        <div><span class="job-detail-k">Target</span><div class="job-detail-v">${esc(job.target || opts.target_url || "—")}</div></div>
        <div><span class="job-detail-k">Created by</span><div class="job-detail-v">${esc(job.created_by || "—")}</div></div>
        <div><span class="job-detail-k">Attempts</span><div class="job-detail-v">${Number(job.attempts || 0)} / ${Number(job.max_attempts || 1)}</div></div>
        <div><span class="job-detail-k">Error</span><div class="job-detail-v">${esc(job.error || "—")}</div></div>
      </div>
      <div class="job-detail-copy">
        Output: <code>${esc(opts.output || "—")}</code><br>
        Evidence: <code>${esc(opts.evidence_dir || "—")}</code><br>
        Scope: <code>${esc(Array.isArray(opts.scope) ? opts.scope.join(", ") : (opts.scope || "—"))}</code>
      </div>
      ${previewHtml}
    </div>
  `;
}

async function openJobDetail(jobId) {
  const panel = _jobDetailPanel();
  if (!panel) return;
  panel.style.display = "block";
  panel.innerHTML = `<div class="job-detail-card"><div class="job-detail-title">Loading job detail...</div></div>`;
  panel.scrollIntoView({block:"start", behavior:"smooth"});
  try {
    const r = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`, {headers:_authHeaders()});
    if (!r.ok) throw new Error("HTTP " + r.status);
    const job = await r.json();
    let preview = null;
    if (job.job_type === "playwright_recon") {
      try {
        const sessionResp = await fetch(_jobArtifactUrl(jobId, "session"), {headers:_authHeaders()});
        if (sessionResp.ok) {
          const session = await sessionResp.json();
          const reportResp = await fetch(_jobArtifactUrl(jobId, "report"), {headers:_authHeaders()});
          let report = "";
          if (reportResp.ok) {
            const txt = await reportResp.text();
            report = txt.split("\n").slice(0, 18).join("\n");
          }
          preview = {
            pages: Array.isArray(session.pages) ? session.pages.length : 0,
            endpoints: Array.isArray(session.endpoints) ? session.endpoints.length : 0,
            js: Array.isArray(session.js) ? session.js.length : 0,
            tech: Array.isArray(session.tech) ? session.tech.length : 0,
            inventory: session,
            note: Array.isArray(session.skipped_checks) && session.skipped_checks.length ? session.skipped_checks[0] : "",
            report: report,
          };
        }
      } catch(e) {
        preview = { note: "Failed to load Playwright artifact preview: " + e.message };
      }
    }
    _renderJobDetail(job, preview);
    panel.scrollIntoView({block:"start", behavior:"smooth"});
  } catch(e) {
    panel.innerHTML = `<div class="job-detail-card"><div class="job-detail-title">Failed to load job detail</div><div class="job-detail-copy">${esc(e.message)}</div></div>`;
  }
}

async function renderCompanyPlaywrightPanel(cid) {
  const panel = document.getElementById("company-playwright-panel");
  if (!panel) return;
  const ready = (pipelineState[cid] && pipelineState[cid].status === "done");
  panel.innerHTML = `
    <div class="job-detail-card">
      <div class="job-detail-title">Playwright Recon</div>
      <div class="job-detail-copy">${esc(_opT("pipe_pw_loading", "Carregando o último job desta empresa…"))}</div>
    </div>
  `;
  try {
    const r = await fetch(`/api/jobs?company_id=${encodeURIComponent(cid)}&limit=20`, {headers:_authHeaders()});
    if (!r.ok) throw new Error("HTTP " + r.status);
    const jobs = await r.json();
    const job = jobs.find(j => j.job_type === "playwright_recon");
    if (!job) {
      panel.innerHTML = `
        <div class="job-detail-card">
          <div class="job-detail-title">Playwright Recon</div>
          <div class="job-detail-copy">${esc(ready ? _opT("pipe_pw_none", "Nenhum job Playwright Recon nesta empresa.") : _opT("pipe_pw_locked", "Liberado quando o scan da pipeline terminar."))}</div>
        </div>
      `;
      return;
    }
    const canArtifacts = job.status === "done";
    const opts = job.options || {};
    let inventoryHtml = "";
    try {
      const sessionResp = await fetch(_jobArtifactUrl(job.id, "session"), {headers:_authHeaders()});
      if (sessionResp.ok) {
        const session = await sessionResp.json();
        inventoryHtml = _playwrightInventorySummary(session);
      }
    } catch(e) {}
    panel.innerHTML = `
      <div class="job-detail-card">
        <div class="job-detail-head">
          <div>
            <div class="job-detail-title">Playwright Recon</div>
            <div class="job-detail-copy">${esc(job.id)} · ${esc(job.status || "—")} · ${esc(job.created_at || "—")}</div>
          </div>
          <div class="job-actions">
            <button type="button" class="btn btn-secondary btn-icon" onclick="openJobDetail(${_jsArg(job.id)})">${esc(_opT("op_details", "Detalhes"))}</button>
            ${canArtifacts ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'report')}" target="_blank" rel="noopener">${esc(_opT("op_report", "Relatório"))}</a>` : ""}
            ${canArtifacts ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'session')}" target="_blank" rel="noopener">${esc(_opT("op_session", "Sessão"))}</a>` : ""}
          </div>
        </div>
        <div class="job-detail-grid">
          <div><span class="job-detail-k">${esc(_opT("pipe_pw_target", "Alvo"))}</span><div class="job-detail-v">${esc(job.target || opts.target_url || "—")}</div></div>
          <div><span class="job-detail-k">${esc(_opT("pipe_pw_started", "Início"))}</span><div class="job-detail-v">${esc(_fmtJobTime(job.started_at))}</div></div>
          <div><span class="job-detail-k">${esc(_opT("pipe_pw_finished", "Fim"))}</span><div class="job-detail-v">${esc(_fmtJobTime(job.finished_at))}</div></div>
          <div><span class="job-detail-k">${esc(_opT("pipe_pw_attempts", "Tentativas"))}</span><div class="job-detail-v">${Number(job.attempts || 0)} / ${Number(job.max_attempts || 1)}</div></div>
        </div>
        <div class="job-detail-copy">
          ${esc(_opT("pipe_pw_output", "Saída"))}: <code>${esc(opts.output || "—")}</code><br>
          ${esc(_opT("pipe_pw_evidence", "Evidência"))}: <code>${esc(opts.evidence_dir || "—")}</code>
        </div>
        ${inventoryHtml}
      </div>
    `;
  } catch(e) {
    panel.innerHTML = `
      <div class="job-detail-card">
        <div class="job-detail-title">Playwright Recon</div>
        <div class="job-detail-copy">${esc(_opT("pipe_pw_fail", "Falha ao carregar jobs Playwright: {err}").replace("{err}", e.message || ""))}</div>
      </div>
    `;
  }
}

async function _fetchLatestPlaywrightBundle(cid) {
  const r = await fetch(`/api/jobs?company_id=${encodeURIComponent(cid)}&limit=20`, {headers:_authHeaders()});
  if (!r.ok) throw new Error("HTTP " + r.status);
  const jobs = await r.json();
  const job = (jobs || []).find(j => j.job_type === "playwright_recon");
  if (!job) return {job: null, session: null, report: ""};

  let session = null;
  let report = "";
  try {
    const sessionResp = await fetch(_jobArtifactUrl(job.id, "session"), {headers:_authHeaders()});
    if (sessionResp.ok) session = await sessionResp.json();
  } catch(e) {}
  try {
    const reportResp = await fetch(_jobArtifactUrl(job.id, "report"), {headers:_authHeaders()});
    if (reportResp.ok) {
      const txt = await reportResp.text();
      report = txt.split("\n").slice(0, 24).join("\n");
    }
  } catch(e) {}
  return {job, session, report};
}
