// ════════════════════════════════════════════════════════════════════════
//  ADMIN CRUD
// ════════════════════════════════════════════════════════════════════════
async function loadAdmins() {
  if (!SERVER_MODE) {
    document.getElementById("admins-tbody").innerHTML = `<tr><td colspan="6" style="color:var(--text3);text-align:center;padding:20px">Server mode required</td></tr>`;
    return;
  }
  try {
    const r = await fetch("/api/admins");
    if (!r.ok) return;
    const admins = await r.json();
    renderAdminsTable(admins);
  } catch(e) {}
}

function renderAdminsTable(admins) {
  const tbody = document.getElementById("admins-tbody");
  tbody.innerHTML = admins.map(a => {
    const scopeLabel = (a.scoped_companies && a.scoped_companies.length) ? `${a.scoped_companies.length} company(s)` : "All";
    return `
<tr>
  <td><b>${a.username}</b></td>
  <td style="color:var(--text2)">${a.email || "—"}</td>
  <td><span class="role-badge ${a.role}">${a.role.replace("_"," ")}</span></td>
  <td style="color:var(--text3);font-size:0.65rem">${scopeLabel}</td>
  <td style="color:var(--text3);font-size:0.65rem">${(a.created_at||"").slice(0,10)}</td>
  <td style="color:var(--text3);font-size:0.65rem">${(a.last_login||"—").slice(0,16).replace("T"," ")}</td>
  <td>
    <div class="admin-actions">
      ${a.role !== 'super_admin' ? `<button class="btn btn-secondary btn-icon" onclick="openAdminModal('${a.id}','${a.username}','${a.email||""}','${a.role}','${JSON.stringify(a.scoped_companies||[]).replace(/"/g,'&quot;')}')">Edit</button>` : ''}
      ${a.id !== authUser?.admin_id ? `<button class="btn btn-icon" style="background:var(--red-dim);color:#fb7185;border:1px solid rgba(244,63,94,0.2)" onclick="deleteAdmin('${a.id}','${a.username}')">Delete</button>` : `<span style="font-size:0.65rem;color:var(--text3);padding:4px 8px">you</span>`}
    </div>
  </td>
</tr>`;}).join("") || `<tr><td colspan="7" style="color:var(--text3);text-align:center;padding:20px">No admins found</td></tr>`;
}

function onAdminRoleChange() {
  const role = document.getElementById("admin-modal-role").value;
  const scopeField = document.getElementById("admin-scope-field");
  scopeField.style.display = (role === "super_admin") ? "none" : "";
}

function openAdminModal(id, username, email, role, scopedJson) {
  const isNew = !id;
  document.getElementById("admin-modal-title").textContent = isNew ? "Add Admin" : "Edit Admin";
  document.getElementById("admin-modal-id").value    = id || "";
  document.getElementById("admin-modal-user").value  = username || "";
  document.getElementById("admin-modal-user").disabled = !isNew;
  document.getElementById("admin-modal-email").value = email || "";
  document.getElementById("admin-modal-role").value  = role || "analyst";
  document.getElementById("admin-modal-pw-field").style.display   = isNew ? "" : "none";
  document.getElementById("admin-modal-pw-change-toggle").style.display = isNew ? "none" : "";
  document.getElementById("admin-modal-pw").value = "";
  document.getElementById("admin-change-pw-cb").checked = false;
  document.getElementById("admin-new-pw-wrap").style.display = "none";

  // Populate company scope checkboxes
  let scoped = [];
  try { if (scopedJson) scoped = JSON.parse(scopedJson); } catch(e) {}
  if (!Array.isArray(scoped)) scoped = [];
  const grid = document.getElementById("admin-scope-grid");
  grid.innerHTML = (allCompanies() || []).map(c => {
    const checked = scoped.includes(c.id) ? "checked" : "";
    return `<label style="display:flex;align-items:center;gap:6px;font-size:0.72rem;color:var(--text2);cursor:pointer;padding:2px 4px;border-radius:4px">
      <input type="checkbox" value="${esc(c.id)}" ${checked} class="admin-scope-cb">
      ${esc(c.name)}
    </label>`;
  }).join("") || '<span style="color:var(--text3);font-size:0.72rem">No companies yet</span>';

  onAdminRoleChange();
  document.getElementById("modal-admin").style.display = "flex";
}

function closeAdminModal() { document.getElementById("modal-admin").style.display = "none"; }

function toggleChangePw(checked) {
  document.getElementById("admin-new-pw-wrap").style.display = checked ? "" : "none";
}

async function saveAdmin() {
  const id    = document.getElementById("admin-modal-id").value;
  const isNew = !id;
  const role  = document.getElementById("admin-modal-role").value;
  const body  = {
    username: document.getElementById("admin-modal-user").value.trim(),
    email:    document.getElementById("admin-modal-email").value.trim(),
    role:     role,
  };

  // Collect scoped companies (only for analyst role)
  if (role !== "super_admin") {
    const cbs = document.querySelectorAll(".admin-scope-cb:checked");
    body.scoped_companies = Array.from(cbs).map(cb => cb.value);
  }

  if (isNew) {
    body.password = document.getElementById("admin-modal-pw").value;
    if (!body.username || !body.password) { showToast("Username and password are required"); return; }
  } else {
    if (document.getElementById("admin-change-pw-cb").checked) {
      body.password = document.getElementById("admin-modal-pw2").value;
      if (!body.password) { showToast("Enter new password"); return; }
    }
  }

  try {
    const url    = isNew ? "/api/admins" : `/api/admins/${id}`;
    const method = isNew ? "POST"        : "PUT";
    const r = await fetch(url, {method, body:JSON.stringify(body), headers: _authHeaders()});
    const d = await r.json();
    if (!r.ok) { showToast(d.error || "Error saving admin"); return; }
    closeAdminModal();
    loadAdmins();
  } catch(e) { showToast("Connection error"); }
}

async function deleteAdmin(id, username) {
  if (!confirm(`Delete admin "${username}"? This cannot be undone.`)) return;
  try {
    const r = await fetch(`/api/admins/${id}`, {method:"DELETE"});
    const d = await r.json();
    if (!r.ok) { showToast(d.error || "Error"); return; }
    loadAdmins();
  } catch(e) { showToast("Connection error"); }
}


const _phudModTimes = {};   // Track module start/end for Gantt
const _phudParticles = {};  // Track animation frames

const PIPELINE_PHASES_DEF = [
  {id:"discovery",      label:"DISCOVERY", ico:"radar",  color:"#00e5ff", mods:["subfinder","assetfinder","amass","certs","certstream","surface_intel","alienvault_otx","urlscan_io","rapiddns","hackertarget","github_subdomains","wayback","urlfinder","theharvester","hunterio"]},
  {id:"validation",     label:"VALIDAÇÃO", ico:"search",  color:"#818cf8", mods:["dns","dns_brute","zone_transfer","leaks","git_leaks","email"]},
  {id:"intel",          label:"INTEL", ico:"bolt",  color:"#fbbf24", mods:["shodan","postman_collections","cloud","container_registry","bulk_dataset","breach","phishing","related","reverse_whois","dep_confusion","s3_scanner","asn","asnmap","apk_recon","origin_discovery"]},
  {id:"cleanup",        label:"CLEANUP", ico:"broom",  color:"#94a3b8", mods:["cleanup"]},
  {id:"fingerprint",    label:"FINGERPRINT", ico:"fingerprint",  color:"#00e5ff", mods:["headers","waf","wappalyzer","whatweb","vendor_fp","service_version","favicon_hunt","vhost","screenshot","gowitness"]},
  {id:"js_discovery",   label:"JS", ico:"code",  color:"#38bdf8", mods:["js"]},
  {id:"api_mapping",    label:"JS/API", ico:"code",  color:"#4ade80", mods:["js_endpoints","js_secrets","param_mine","api_discovery_extra","graphql","jwt_analysis"]},
  {id:"browser",        label:"PLAYWRIGHT", ico:"monitor",  color:"#c084fc", mods:["browser_crawl","browser_recon"]},
  {id:"bug_checks",     label:"CHECKS", ico:"warning",  color:"#f43f5e", mods:["takeover","subjack","cors_scan","open_redirect","host_header_injection","infra_exposure","cloud_enum","default_creds","dnssec","waf_bypass","tableau","github_repos","supply_chain","xss_scan","salesforce_recon"]},
  {id:"ports_services", label:"SERVIÇOS", ico:"folder",  color:"#fb923c", mods:["portscan","udp_portscan","smtp_probe","snmp_probe","cloudlist","services","cms_scan","database_enum_extra"]},
  {id:"nuclei",         label:"EVIDÊNCIA", ico:"check",   color:"#4ade80", mods:["cve","api_panels","screenshot_diff"]},
];

const _MOD_TO_PHASE = {};
PIPELINE_PHASES_DEF.forEach(ph => ph.mods.forEach(m => (_MOD_TO_PHASE[m] = ph.id)));

function _phudPhaseList(ps) {
  if (ps && Array.isArray(ps.phases) && ps.phases.length) {
    return ps.phases.map(function (p) {
      const fallback = PIPELINE_PHASES_DEF.find(d => d.id === p.id) || {};
      const mods = (p.modules || []).map(m => (typeof m === "string" ? m : m.module)).filter(Boolean);
      const rawLabel = String(p.label || fallback.label || p.id);
      const label = rawLabel.replace(/^Fase\s+\d+\s*[—-]\s*/i, "").toUpperCase();
      return {
        id: p.id,
        label: label,
        ico: fallback.ico || "layers",
        color: fallback.color || "#38BDF8",
        mods: mods.length ? mods : (fallback.mods || []),
      };
    });
  }
  return PIPELINE_PHASES_DEF;
}

function _rebuildModToPhase(phases) {
  const map = {};
  (phases || []).forEach(ph => (ph.mods || []).forEach(m => { map[m] = ph.id; }));
  return map;
}

function _phudPhaseStatus(phId, modMap, phases) {
  const list = phases || PIPELINE_PHASES_DEF;
  const ph = list.find(p => p.id === phId);
  if (!ph) return "idle";
  const statuses = ph.mods.map(m => modMap[m] || "not_run");
  if (statuses.some(s => s === "running"))  return "active";
  if (statuses.every(s => s === "skipped" || s === "cancelled")) return "skipped";
  if (statuses.some(s => s === "error" || s === "timeout")) return "error";
  if (statuses.some(s => s === "done"))     return "done";
  return "idle";
}

function _phudPhaseToolLabel(ph, modMap) {
  const running = ph.mods.find(m => modMap[m] === "running");
  if (running) return running;
  const done = ph.mods.find(m => modMap[m] === "done");
  if (done) return done;
  const err = ph.mods.find(m => modMap[m] === "error");
  if (err) return err;
  const skip = ph.mods.find(m => modMap[m] === "skipped");
  if (skip) return skip;
  const seen = ph.mods.find(m => modMap[m] && modMap[m] !== "not_run");
  return seen || ph.id;
}

function _pipelineCardLiveInfo(cid) {
  const ps = pipelineState[cid];
  if (!ps || (ps.status !== "queued" && ps.status !== "running")) return null;

  const modMap = {};
  (ps.phases || []).forEach(ph => (ph.modules || []).forEach(m => {
    if (m.status && m.status !== "not_run") modMap[m.module] = m.status;
  }));
  const rs = reconState[cid] || {};
  Object.keys(rs).forEach(m => {
    if (rs[m] && rs[m].status) modMap[m] = rs[m].status;
  });

  const activeTool =
    Object.keys(modMap).find(m => modMap[m] === "running") ||
    (ps.status === "running" ? Object.keys(modMap).find(m => modMap[m] === "done") : "") ||
    Object.keys(modMap).find(m => modMap[m] === "error") ||
    Object.keys(modMap).find(m => modMap[m] === "skipped") ||
    "";

  const phases = _phudPhaseList(ps);
  const modToPhase = _rebuildModToPhase(phases);
  const phaseId = activeTool ? (modToPhase[activeTool] || _MOD_TO_PHASE[activeTool]) : "";
  const phase = phaseId ? phases.find(p => p.id === phaseId) : null;
  const phaseLabel = phase ? phase.label : (ps.phase_label || "");
  const label = ps.status === "queued"
    ? (activeTool ? `Queued · ${activeTool}${phaseLabel ? ` · ${phaseLabel}` : ""}` : "Queued · waiting for worker")
    : (activeTool ? `Running · ${activeTool}${phaseLabel ? ` · ${phaseLabel}` : ""}` : "Running · starting");

  return {
    status: ps.status,
    tool: activeTool,
    phase: phaseLabel,
    label,
    jobId: ps.job_id || "",
  };
}

function _phudStartParticles(cid) {
  const canvas = document.getElementById(`phud-canvas-${cid}`);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  function resize() { canvas.width = canvas.offsetWidth; canvas.height = canvas.offsetHeight; }
  resize();
  new ResizeObserver(resize).observe(canvas.parentElement);
  const pts = Array.from({length:45}, () => ({
    x:Math.random(), y:Math.random(),
    vx:(Math.random()-.5)*.0005, vy:(Math.random()-.5)*.0005,
    r:Math.random()*.8+.2, a:Math.random()*.3+.04,
  }));
  function draw() {
    ctx.clearRect(0,0,canvas.width,canvas.height);
    pts.forEach(p => {
      const x = p.x*canvas.width, y = p.y*canvas.height;
      ctx.beginPath(); ctx.arc(x,y,p.r,0,Math.PI*2);
      ctx.fillStyle = `rgba(0,180,255,${p.a})`; ctx.fill();
      p.x += p.vx; p.y += p.vy;
      if(p.x<0)p.x=1; if(p.x>1)p.x=0;
      if(p.y<0)p.y=1; if(p.y>1)p.y=0;
    });
    _phudParticles[cid] = requestAnimationFrame(draw);
  }
  if(_phudParticles[cid]) cancelAnimationFrame(_phudParticles[cid]);
  draw();
}

function _phudStopParticles(cid) {
  if(_phudParticles[cid]) { cancelAnimationFrame(_phudParticles[cid]); delete _phudParticles[cid]; }
}

function renderPipelineStatus(cid) {
  const el = document.getElementById(`pipeline-status-${cid}`);
  if (!el) return;
  const ps = pipelineState[cid];
  if (!ps) { el.innerHTML = ""; _phudStopParticles(cid); return; }

  // Build module map from pipeline state phases
  const modMap = {};
  (ps.phases||[]).forEach(ph => ph.modules.forEach(m => { modMap[m.module] = m.status; }));
  // Also fill from reconState (live updates)
  const rs = reconState[cid] || {};
  Object.keys(rs).forEach(m => { if(rs[m].status) modMap[m] = rs[m].status; });

  // Track module start/end times for Gantt
  if (!_phudModTimes[cid]) _phudModTimes[cid] = {};
  const mt = _phudModTimes[cid];
  const now = Date.now();
  if (!mt._scanStart) mt._scanStart = now;
  Object.keys(modMap).forEach(m => {
    const st = modMap[m];
    if (st === "running" && !mt[m]) mt[m] = {start: now, end: null};
    if ((st === "done" || st === "error" || st === "skipped") && mt[m] && !mt[m].end) mt[m].end = now;
    if (!mt[m] && (st === "done" || st === "error")) mt[m] = {start: mt._scanStart, end: now};
  });

  const isRunning = ps.status === "running";
  const isQueued  = ps.status === "queued";
  const isDone    = ps.status === "done";
  const modeIcon = {stealth:"scale",balanced:"scale",fast:"bolt"}[ps.mode||"stealth"] || "scale";
  const cfCoverage = ps.cloudflare_coverage || 0;
  const phaseList = _phudPhaseList(ps);

  // ── Phase node timeline ──────────────────────────────────────────────────
  const totalPhases  = phaseList.length;
  const activeIdx    = phaseList.findIndex(p => _phudPhaseStatus(p.id, modMap, phaseList) === "active");
  const donePhases   = phaseList.filter(p => _phudPhaseStatus(p.id, modMap, phaseList) === "done").length;
  const progress     = activeIdx >= 0 ? (activeIdx + .5) / totalPhases : donePhases / totalPhases;
  const glowRight    = Math.round((1 - progress) * 100);

  const nodesHtml = phaseList.map(ph => {
    const st = _phudPhaseStatus(ph.id, modMap, phaseList);
    const dot = st === "done" ? icoHtml("check",12) : (st === "error" ? icoHtml("warning",12) : (ph.ico ? icoHtml(ph.ico,12) : ph.icon));
    const toolLabel = _phudPhaseToolLabel(ph, modMap);
    return `<div class="phud-node ${st}" title="${ph.label} · ${toolLabel}">
      <div class="phud-node-dot">${dot}</div>
      <div class="phud-node-lbl">${esc(toolLabel)}</div>
    </div>`;
  }).join("");

  // ── Gantt: show only modules with timing data ──────────────────────────
  const scanDuration = now - (mt._scanStart || now);
  const totalMs = Math.max(scanDuration, 5000);

  let ganttHtml = "";
  const doneMods = Object.keys(modMap).filter(m => modMap[m] !== "not_run" && modMap[m] !== "idle");
  const runningMod = doneMods.find(m => modMap[m] === "running");
  const doneCount = doneMods.filter(m => modMap[m] === "done").length;
  const errCount  = doneMods.filter(m => modMap[m] === "error").length;

  // Phase group summary
  phaseList.forEach(ph => {
    const phMods = ph.mods.filter(m => modMap[m] && modMap[m] !== "not_run");
    const phDone = phMods.filter(m => modMap[m] === "done").length;
    const phErr = phMods.filter(m => modMap[m] === "error" || modMap[m] === "timeout").length;
    const phRunning = !isDone && phMods.find(m => modMap[m] === "running");
    const phSt = phRunning ? "active" : phErr ? "error" : ((isDone && phMods.length) || phDone >= ph.mods.length) ? "done" : phDone > 0 ? "active" : "idle";
    ganttHtml += `<div class="phud-phase-hdr ${phSt==='active'?'ph-active':phSt==='done'?'ph-done':phSt==='error'?'ph-error':''}" style="border-left:3px solid ${phSt==='error'?'#ef4444':ph.color};padding:4px 10px;margin-top:4px;border-radius:3px;background:${phSt==='active'?'rgba(255,255,255,0.04)':phSt==='error'?'rgba(239,68,68,0.08)':'transparent'}">
      <span style="font-weight:700;font-size:.68rem;color:var(--text)">${ph.ico ? icoHtml(ph.ico,12) : ph.icon} ${esc(ph.label)}</span>
      <span style="margin-left:8px;font-size:.58rem;color:var(--text3)">${phDone}/${ph.mods.length}${phErr ? " · " + phErr + " erro" : ""}</span>
    </div>`;
    if (phSt === "active" || phSt === "error") {
      ganttHtml += `<div class="phud-mod-chips">` + ph.mods.map(m => {
        const st = modMap[m] || "pending";
        const canCancel = isRunning && (st === "running" || st === "not_run" || st === "pending" || !modMap[m]);
        const x = canCancel ? `<button type="button" title="Cancelar módulo" onclick="cancelPipelineModule('${cid}','${m}')">×</button>` : "";
        return `<span class="phud-chip ${st}">${m}${x}</span>`;
      }).join("") + `</div>`;
    }
  });

  // Running module highlight
  if (runningMod) {
    ganttHtml += `<div style="padding:6px 10px;font-size:.64rem;color:#00e5ff;background:rgba(0,229,255,0.05);border-radius:4px;margin:2px 0">
      ${icoHtml("play",14)} ${runningMod} <span style="color:var(--text3);font-size:.58rem">rodando...</span>
    </div>`;
  }

  // Last 5 completed modules
  const recentMods = doneMods.filter(m => (modMap[m] === "done" || modMap[m] === "error" || modMap[m] === "timeout") && mt[m]).slice(-5);
  if (recentMods.length) {
    ganttHtml += `<div style="font-size:.58rem;color:var(--text3);padding:4px 10px">Últimos concluídos:</div>`;
    recentMods.forEach(m => {
      const t = mt[m] || {};
      const durMs = t.end && t.start ? t.end - t.start : 0;
      const durStr = durMs > 60000 ? `${Math.round(durMs/60000)}m` : durMs > 1000 ? `${Math.round(durMs/1000)}s` : "";
      const barColor = modMap[m] === "error" || modMap[m] === "timeout" ? "#ef4444" : "#22c55e";
      const startOff = t.start ? ((t.start - mt._scanStart) / totalMs * 100).toFixed(1) : "0";
      const endOff = t.end ? ((t.end - mt._scanStart) / totalMs * 100).toFixed(1) : startOff;
      const width = Math.max(parseFloat(endOff) - parseFloat(startOff), 1).toFixed(1);

      ganttHtml += `<div style="display:flex;align-items:center;gap:6px;padding:2px 10px">
        <div style="font-size:.6rem;color:var(--text2);width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:right" title="${m}">${m}</div>
        <div style="flex:1;height:8px;background:rgba(255,255,255,0.03);border-radius:4px;overflow:hidden">
          <div style="left:${startOff}%;width:${width}%;background:${barColor};height:100%;border-radius:4px;opacity:.8;position:relative"></div>
        </div>
        <div style="font-size:.55rem;color:var(--text3);width:28px">${durStr}</div>
      </div>`;
    });
  }

  // ── Last log line ────────────────────────────────────────────────────────
  const logLines = ps.log || [];
  const lastLog  = logLines.length ? logLines[logLines.length-1].msg : (isQueued ? _opT("pipe_queued", "Na fila…") : isRunning ? _opT("pipe_waiting", "Aguardando início…") : "");

  // ── Cleanup badge ────────────────────────────────────────────────────────
  const cleanupData = (ps.phases||[]).find(p => p.id === "cleanup");
  const cleanupBadge = cleanupData && cleanupData.data?.removed > 0
    ? `<span class="phud-badge done"> -${cleanupData.data.removed} junk</span>` : "";
  const cfBadge = cfCoverage >= 80
    ? `<span class="phud-badge done">${icoHtml("shield",14)} ${cfCoverage.toFixed(0)}% CF</span>` : "";
  const mullvadIp = ps.mullvad_ip || "";
  const mullvadBadge = mullvadIp
    ? `<span class="phud-badge idle" title="Mullvad VPN — IP atual">${icoHtml("globe",14)} ${mullvadIp}</span>` : "";

  // ── Mullvad failures ──────────────────────────────────────────────────────
  const mullvadFailuresHtml = (ps.mullvad_failures||[]).length ? `<div style="margin-top:6px;padding:6px;background:rgba(239,68,68,0.1);border-radius:4px;border:1px solid rgba(239,68,68,0.3)"><span style="color:var(--red);font-weight:600;font-size:.7rem">${icoHtml("warning",14)} Mullvad Rotation Failures (${ps.mullvad_failures.length})</span>${ps.mullvad_failures.slice(-3).map(f=>`<div style="color:var(--text3);font-size:.65rem;margin-top:2px">${esc(f.ts||'')} · ${esc(f.phase||'')} · ${esc(f.reason||'')}</div>`).join('')}</div>` : '';

  // ── Not done summary ─────────────────────────────────────────────────────
  const notDone = (ps.not_done||[]);
  const notDoneHtml = (isDone && notDone.length) ? `
    <div style="margin-top:10px;padding:8px 12px;background:rgba(251,146,60,0.08);border:1px solid rgba(251,146,60,0.2);border-radius:7px;font-size:.63rem;">
      <span style="color:var(--orange);font-weight:700;">${icoHtml("warning",14)} ${esc(_opT("pipe_not_done", "{n} módulo(s) não concluído(s):").replace("{n}", String(notDone.length)))}</span>
      <span style="color:var(--text3);margin-left:6px">${notDone.slice(0,6).map(n=>{
        const reason = (n.reason||"").trim();
        return reason && reason !== "not executed"
          ? `${n.module} (${reason})`
          : n.module;
      }).join(", ")}${notDone.length>6?"…":""}</span>
    </div>` : "";

  el.innerHTML = `
  <div class="phud-wrap" id="phud-wrap-${cid}">
    <div class="phud-inner">

      <div class="phud-header">
        <span class="phud-title">${icoHtml("layers",14)} Pipeline</span>
        <span class="phud-badge ${isRunning?"running":isQueued?"idle":isDone?"done":"idle"}">${isRunning?esc(_opT("pipe_status_running","RODANDO")):isQueued?esc(_opT("pipe_status_queued","NA FILA")):isDone?esc(_opT("pipe_status_done","CONCLUÍDO")):esc(_opT("pipe_status_idle","PARADO"))}</span>
        ${modeIcon ? `<span class="phud-badge idle">${icoHtml(modeIcon,12)} ${ps.mode||""}</span>` : ""}
        ${cfBadge}${cleanupBadge}${mullvadBadge}
        <div class="phud-meta">
          <span>${icoHtml("monitor",12)} ${ps.host_count||0} hosts</span>
          <span>${icoHtml("layers",12)} ${donePhases}/${totalPhases} grupos</span>
          ${ps.started_at ? `<span>${icoHtml("clock",12)} ${ps.started_at}</span>` : ""}
        </div>
      </div>

      <div class="phud-gantt" style="margin-top:8px;position:relative">
        ${ganttHtml || '<div style="padding:20px;color:var(--text3);text-align:center;font-size:.72rem">Aguardando início…</div>'}
      </div>

      ${notDoneHtml}
      ${mullvadFailuresHtml}

      <div class="phud-action" id="phud-action-${cid}">${lastLog ? icoHtml("play",14)+" "+lastLog : "…"}</div>
    </div>
  </div>`;

  // Start/stop particle animation
  if (isRunning) {
    _phudStartParticles(cid);
  } else {
    _phudStopParticles(cid);
  }
}

const RECON_MODULES = [
  {id:"email",     label:"Email Security",          desc:"SPF, DMARC, DKIM, MX analysis",                     eta:"~10s", ico:"envelope"},
  {id:"certs",     label:"Certificate Transparency",desc:"crt.sh CT logs + SSL/TLS probe",                   eta:"~20s", ico:"lock"},
  {id:"dns",       label:"Full DNS Records",         desc:"A, AAAA, MX, TXT, NS, SOA, CNAME, SRV, CAA",       eta:"~10s", ico:"globe"},
  {id:"surface_intel", label:"Surface Intel (DNS/CDN/CSP)", desc:"CNAME/CDN, staging, CSP terceiros, CORS *+creds — sem VirusTotal", eta:"~25s", ico:"web"},
  {id:"origin_discovery", label:"Origin behind CDN", desc:"IP de origem atrás de CloudFront/Cloudflare/Imperva", eta:"~1m", ico:"target"},
  {id:"headers",   label:"Security Headers",         desc:"HSTS, CSP, X-Frame-Options, cookies",              eta:"~30s", ico:"clipboard"},
  {id:"waf",       label:"WAF Detection",            desc:"Detect Imperva, Cloudflare, AWS WAF, Akamai…",     eta:"~1m", ico:"shield"},
  {id:"takeover",  label:"Subdomain Takeover",       desc:"CNAME → dead 3rd-party services",                  eta:"~2m", ico:"warning"},
  {id:"typosquat", label:"Typosquatting",            desc:"Look-alike domains targeting your brand",          eta:"~2m", ico:"target"},
  {id:"related",   label:"Related Domains",          desc:".net, .org, .com variations of your domains",      eta:"~30s", ico:"link"},
  {id:"cloud",     label:"Cloud Asset Discovery",    desc:"S3, Azure Blob, GCP buckets — public/private",     eta:"~3m", ico:"cloud"},
  {id:"wayback",   label:"Wayback / GAU Mining",     desc:"Historical URLs with .env, .git, admin paths",     eta:"~2m", ico:"archive"},
  {id:"breach",    label:"Breach Intelligence",      desc:"Hudson Rock Cavalier, LeakIX, HaveIBeenPwned, TruffleHog", eta:"~30s", ico:"lock"},
  {id:"shodan",    label:"Shodan Intelligence",      desc:"Open ports, CVEs and banners per IP",              eta:"~1m", ico:"radar"},
  {id:"portscan",  label:"Port Scan",                desc:"naabu/nmap — risky exposed services",              eta:"~5m", ico:"plug"},
  {id:"services",  label:"Exposed Paths",            desc:"/.git /.env /admin /swagger /actuator…",          eta:"~5m", ico:"folder"},
  {id:"leaks",     label:"GitHub Secrets",           desc:"Leaked API keys and .git directory exposure",      eta:"~2m", ico:"key"},
  {id:"asn",       label:"ASN / IP Blocks",          desc:"All IP ranges and ASNs attributed to the org",     eta:"~30s", ico:"map"},
  {id:"cve",        label:"CVE Lookup (NVD)",          desc:"Cross-reference detected technologies with NVD CVE database",   eta:"~2m", ico:"explosion"},
  {id:"vhost",      label:"Virtual Host Discovery",    desc:"Host header fuzzing — find hidden apps on same IPs",  eta:"~3m", ico:"house"},
  {id:"js",         label:"JavaScript Recon",          desc:"Katana crawl + extract endpoints, secrets, S3, IPs",  eta:"~5m", ico:"code"},
  {id:"screenshot", label:"Screenshots",               desc:"Visual inventory of all live web assets (gowitness)",  eta:"~3m", ico:"camera"},
  {id:"dns_brute",  label:"DNS Brute-force",           desc:"dnsgen permutations + dnsx — find hidden subdomains",  eta:"~5m", ico:"search"},
  {id:"api_panels", label:"API & Panel Exposure",      desc:"Spring Boot, Swagger, GraphQL, CORS, Smuggling (nuclei)", eta:"~5m", ico:"plug"},
  {id:"certstream",   label:"CertStream Monitor",        desc:"Real-time certificate transparency — new asset alerts", eta:"~2m", ico:"radar"},
  {id:"wappalyzer",   label:"Wappalyzer Tech Detection", desc:"httpx -tech-detect — Bootstrap, jQuery, PHP, CMS, frameworks across all subdomains", eta:"~2m", ico:"flask"},
  {id:"dep_confusion",label:"Dependency Confusion",      desc:"npm/PyPI/RubyGems — nomes de pacotes internos que podem ser squatados", eta:"~3m", ico:"package"},
  {id:"postman_collections", label:"Postman Collections", desc:"Exposed Postman collections on public API and GitHub — finds hardcoded tokens, API keys, base URLs", eta:"~1m", ico:"inbox"},
];

// deduplicate by id
const RECON_MODS_DEDUP = RECON_MODULES.filter((m,i,a)=>a.findIndex(x=>x.id===m.id)===i);

const reconState = {};  // cid -> {module -> {status, data}}
const pipelineState = {};  // cid -> pipeline status object
let _pipelinePolls = {};   // cid -> interval id
let _pipelineDonePhases = {};  // cid -> number of completed phases seen so far

function _isPipelineActive(cid) {
  const status = pipelineState[cid]?.status;
  return status === "queued" || status === "running";
}

function _syncPipelineActionButton(cid) {
  const btn = document.getElementById(`pipeline-btn-${cid}`);
  if (!btn) return;
  const active = _isPipelineActive(cid);
  const label = active ? _opT("pipe_stop", "Parar pipeline") : _opT("pipe_run", "Rodar pipeline");
  btn.disabled = false;
  btn.className = `btn btn-icon ${active ? "pipeline-stop-btn" : "btn-secondary"}`;
  btn.setAttribute("aria-label", label);
  _setIconLabel(btn, active ? "stop" : "play", label);
}

async function handlePipelineAction(cid) {
  if (_isPipelineActive(cid)) return stopPipeline(cid, {notify: false});
  return runPipeline(cid);
}

async function stopPipeline(cid, {notify = true} = {}) {
  if (!cid) return;
  const btn = document.getElementById(`pipeline-btn-${cid}`);
  if (btn) { btn.disabled = true; _setIconLabel(btn, "stop", _opT("pipe_stopping", "Parando…")); }
  try {
    const r = await fetch('/api/recon/' + encodeURIComponent(cid) + '/pipeline', {method:'DELETE', headers:_authHeaders()});
    if (!r.ok) throw await _apiErr(r);
    pipelineState[cid] = {
      ...(pipelineState[cid] || {}),
      status: "stopped",
      finished_at: new Date().toISOString(),
    };
    if (_pipelinePolls[cid]) {
      clearInterval(_pipelinePolls[cid]);
      delete _pipelinePolls[cid];
    }
    renderPipelineStatus(cid);
    _syncPipelineActionButton(cid);
    if (notify) showToast('Pipeline stopped');
  } catch(e) {
    _syncPipelineActionButton(cid);
    showToast('Failed: ' + e.message);
  }
}

async function scanAllCompanies() {
  const companies = allCompanies();
  if (!companies.length) { showToast('Nenhuma empresa cadastrada.'); return; }
  const active = companies.filter(c => {
    const s = (pipelineState[c.id] || {}).status;
    return s === 'running' || s === 'queued';
  });
  const toStart = companies.length - active.length;
  if (toStart === 0) { showToast('Todos os scans já estão em execução.'); return; }
  if (!confirm(`Iniciar scan em ${toStart} empresa(s)${active.length ? ` (${active.length} já em execução serão ignoradas)` : ''}?`)) return;
  const btn = document.getElementById('btn-scan-all');
  if (btn) { btn.disabled = true; btn.textContent = 'Iniciando...'; }
  let cfg = {};
  try { cfg = JSON.parse(localStorage.getItem('asm_settings') || '{}'); } catch(e) {}
  cfg.mode = selectedRateMode || cfg.mode || 'balanced';
  try {
    const r = await fetch('/api/recon/scan-all', {
      method: 'POST',
      headers: Object.assign({'Content-Type': 'application/json'}, _authHeaders()),
      body: JSON.stringify(cfg),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    (d.cids || []).forEach(cid => {
      pipelineState[cid] = Object.assign({}, pipelineState[cid] || {}, {
        status: 'queued',
        started_at: new Date().toISOString(),
      });
      _syncPipelineActionButton(cid);
      _startPipelinePoll(cid);
    });
    loadJobs();
    showToast(`${d.started || 0} scan(s) iniciado(s)${d.skipped ? `, ${d.skipped} ignorado(s)` : ''}.`);
  } catch(e) {
    showToast('Erro ao iniciar scans: ' + e.message);
  } finally {
  if (btn) { btn.disabled = false; btn.textContent = ' Escanear Todos'; }
  }
}

async function cancelAllScans() {
  const btn = document.getElementById('btn-cancel-all-scans');
  if (!confirm('Cancelar todos os scans em execução?')) return;
  if (btn) { btn.disabled = true; btn.textContent = 'Cancelando...'; }
  try {
    const r = await fetch('/api/recon/cancel-all', {method:'POST', headers:_authHeaders()});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    // Update local pipeline state for all stopped companies
    (d.cids || []).forEach(cid => {
      pipelineState[cid] = Object.assign({}, pipelineState[cid] || {}, {
        status: 'stopped',
        finished_at: new Date().toISOString(),
      });
      if (_pipelinePolls[cid]) {
        clearInterval(_pipelinePolls[cid]);
        delete _pipelinePolls[cid];
      }
      _syncPipelineActionButton(cid);
      if (typeof renderPipelineStatus === 'function') renderPipelineStatus(cid);
    });
    loadJobs();
    const total = (d.stopped || 0);
    showToast(total > 0 ? `${total} scan(s) cancelado(s).` : 'Nenhum scan ativo encontrado.');
  } catch(e) {
    showToast('Erro ao cancelar: ' + e.message);
  } finally {
  if (btn) { btn.disabled = false; btn.textContent = ' Cancelar Todos'; }
  }
}

async function runPipeline(cid) {
  const btn = document.getElementById(`pipeline-btn-${cid}`);
  if (btn) { btn.disabled = true; btn.textContent = "Starting…"; }
  let cfg = {};
  try { cfg = JSON.parse(localStorage.getItem("asm_settings")||"{}"); } catch(e) {}
  cfg.mode = selectedRateMode;
  try {
    const r = await fetch(`/api/recon/${cid}/pipeline`, {
      method: "POST",
      headers: {"Content-Type":"application/json", ..._authHeaders()},
      body: JSON.stringify(cfg),
    });
    let data = {};
    if (!r.ok) {
      const t = await r.text();
      if (r.status !== 409 || !t.includes("already running")) {
        throw new Error(t);
      }
    } else {
      data = await r.json().catch(() => ({}));
    }
    pipelineState[cid] = {
      ...(pipelineState[cid] || {}),
      status: data.status || "queued",
      job_id: data.job_id || "",
      phase_label: "",
      host_count: 0,
      phases: [],
      not_done: [],
      started_at: new Date().toLocaleTimeString(),
      log: data.job_id ? [{ts:new Date().toISOString(), msg:`Pipeline queued as job ${data.job_id}`}] : [],
    };
    renderPipelineStatus(cid);
    _syncPipelineActionButton(cid);
    _startPipelinePoll(cid);
  } catch(e) {
    _syncPipelineActionButton(cid);
    showToast("Erro ao iniciar pipeline: " + e.message);
  }
}

function _startPipelinePoll(cid) {
  if (_pipelinePolls[cid]) clearInterval(_pipelinePolls[cid]);
  _pipelineDonePhases[cid] = _pipelineDonePhases[cid] || 0;
  _pipelinePolls[cid] = setInterval(async () => {
    try {
      const r = await fetch(`/api/recon/${cid}/pipeline`, {headers: _authHeaders()});
      if (!r.ok) return;
      const ps = await r.json();
      pipelineState[cid] = ps;

      // sync module states from pipeline
      if (!reconState[cid]) reconState[cid] = {};
      (ps.phases||[]).forEach(ph => ph.modules.forEach(m => {
        if (m.status !== "not_run") reconState[cid][m.module] = {status: m.status};
      }));

      // Update the live phase HUD in place only. renderReconTab() is NOT called
      // per-tick because it re-fetches the Playwright session artifact every poll;
      // the recon tab (and its Playwright panel) is refreshed once on scan completion below.
      renderPipelineStatus(cid);
      _syncPipelineActionButton(cid);
      renderAllCompanies();

      // reload company data whenever a new phase completes (results are persisted per phase)
      const doneNow = (ps.phases||[]).filter(p => p.done).length;
      if (doneNow > (_pipelineDonePhases[cid] || 0)) {
        _pipelineDonePhases[cid] = doneNow;
        try {
          await ensureCompanyLoaded(cid, {force: true});
          const co = allCompanies().find(c => c.id === cid);
          if (co) {
            renderOverview(co);
  try { setTimeout(initThreatMaps, 50); setTimeout(initThreatMaps, 400); } catch(e) {}
            renderDomainsTab(co);
            renderSubdomainsTab(co);
            renderFindingsTab(co);
          }
        } catch(e) { /* ignore transient reload errors */ }
      }

      if (["done", "error", "stopped", "cancelled"].includes(ps.status)) {
        if (typeof notifyAsm === "function") notifyAsm("Scantrely", "Scan " + cid + " " + ps.status);
        clearInterval(_pipelinePolls[cid]);
        _pipelineDonePhases[cid] = 0;
        _syncPipelineActionButton(cid);
        await reloadServerData();
        const co = allCompanies().find(c => c.id === cid);
        if (co) { renderOverview(co); renderDomainsTab(co); renderSubdomainsTab(co); renderFindingsTab(co); }
        // Refresh the recon tab once now that the scan is done so the Playwright
        // panel unlocks/updates — this is the only place it re-renders post-scan.
        if (state.currentId === cid && (state.activeGroup === "operation" || state.tab === "pipeline")) {
          renderReconTab(cid);
        }
      }
    } catch(e) { /* ignore transient errors */ }
  }, 2500);
}
