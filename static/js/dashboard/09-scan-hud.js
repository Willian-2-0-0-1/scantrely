// ════════════════════════════════════════════════════════════════════════
//  SCAN
// ════════════════════════════════════════════════════════════════════════
let activeScanId  = null;
let scanEventSrc  = null;
let scanLineCount = 0;
let scanStartTime = null;
let selectedProfile = "bug_bounty";

// ── Module ETA tracker ───────────────────────────────────────────────────────
const MODULE_ETA_S = {
  // DNS core
  dnsresolve:45,  speculate:5,    cloudcheck:10,  dnsbrute:300,
  dnscommonsrv:20, dnsbimi:15,    dnstlsrpt:10,   dnscaa:10,
  baddns:30,      baddns_zone:20,
  // HTTP
  httpx:90,       sslcert:30,     securitytxt:15, azure_realm:15,
  // Subdomain sources
  subfinder:60,   assetfinder:20, anubisdb:30,    certspotter:30,
  crt:30,         crt_db:20,      digitorus:20,hackertarget:15, myssl:15,      rapiddns:15,    sitedossier:20,
  subdomaincenter:15, urlscan:30, virustotal:20,  chaos:15,
  leakix:15,      otx:15,         wayback:60,     shodan_dns:20,
  shodan_idb:30,  securitytrails:20, censys_dns:20, censys_ip:20,
  // Cloud / Buckets
  bucket_amazon:30, bucket_firebase:20, bucket_google:20,
  bucket_microsoft:20, bucket_digitalocean:20,
  azure_tenant:15, asn:20,
  // Code / Secrets
  git:60,         git_clone:60,   github_codesearch:30, github_usersearch:20,
  github_org:15,  github_workflows:15, trufflehog:120,
  // Vuln
  nuclei:600,     badsecrets:60,
};

let _scanModules  = [];
let _moduleActive = new Set();
let _moduleDone   = new Set();
let _prevRunning  = new Set();

// ── BBOT HUD ────────────────────────────────────────────────────────────
const BBOT_HUD_PHASES = [
  {id:"discovery", label:"DISCOVERY", ico:"radar", color:"#00e5ff",
   mods:["subfinder","assetfinder","amass","certs","certstream","surface_intel","alienvault_otx","urlscan_io","rapiddns","hackertarget","github_subdomains","wayback","urlfinder","theharvester","hunterio"]},
  {id:"validation", label:"VALIDAÇÃO", ico:"search", color:"#818cf8",
   mods:["dns","dns_brute","zone_transfer","leaks","git_leaks","email"]},
  {id:"intel", label:"INTEL", ico:"bolt", color:"#fbbf24",
   mods:["shodan","postman_collections","cloud","container_registry","bulk_dataset","breach","phishing","related","reverse_whois","dep_confusion","s3_scanner","asn","asnmap","apk_recon","origin_discovery"]},
  {id:"cleanup", label:"CLEANUP", ico:"broom", color:"#94a3b8",
   mods:["cleanup"]},
  {id:"fingerprint", label:"FINGERPRINT", ico:"fingerprint", color:"#00e5ff",
   mods:["headers","waf","wappalyzer","whatweb","vendor_fp","service_version","favicon_hunt","vhost","screenshot","gowitness"]},
  {id:"js_discovery", label:"JS", ico:"code", color:"#38bdf8",
   mods:["js"]},
  {id:"api_mapping", label:"JS/API", ico:"code", color:"#4ade80",
   mods:["js_endpoints","js_secrets","param_mine","api_discovery_extra","graphql","jwt_analysis"]},
  {id:"browser", label:"PLAYWRIGHT", ico:"monitor", color:"#c084fc",
   mods:["browser_crawl","browser_recon"]},
  {id:"bug_checks", label:"CHECKS", ico:"warning", color:"#f43f5e",
   mods:["takeover","subjack","cors_scan","open_redirect","host_header_injection","infra_exposure","cloud_enum","default_creds","dnssec","waf_bypass","tableau","github_repos","supply_chain","xss_scan","salesforce_recon"]},
  {id:"ports_services", label:"SERVIÇOS", ico:"folder", color:"#fb923c",
   mods:["portscan","udp_portscan","smtp_probe","snmp_probe","cloudlist","services","cms_scan","database_enum_extra"]},
  {id:"nuclei", label:"EVIDÊNCIA", ico:"check", color:"#4ade80",
   mods:["cve","api_panels","screenshot_diff"]},
];
const _MOD_PHASE = {};
BBOT_HUD_PHASES.forEach((p,i) => p.mods.forEach(m => (_MOD_PHASE[m] = i)));
let _modState = {};
let _hudLogLines = [];
let _particleAnim = null;

function _stripAnsi(s) { return s.replace(/\x1b\[[0-9;]*m/g, ''); }

function _detectModules(line) {
  const plain = _stripAnsi(line);

  // Setup soft-failed
  const fail = plain.match(/Setup soft-failed for (\w+):/);
  if (fail) { _modState[fail[1]] = 'skipped'; renderHUD(); return; }

  // API is ready
  const ready = plain.match(/\[SUCC\][^\n]*?(\w+):\s+(?:\[.*?m)?API is ready/);
  if (ready) { _modState[ready[1]] = 'ready'; renderHUD(); return; }

  // Scan completed — finalize all pending HUD phases
  if (/completed in .+ with status FINISHED/i.test(plain)) {
    _finalizeScanHUD();
    return;
  }

  // Modules running
  const runMatch = plain.match(/Modules running[^)]+\)\s+(.*)/);
  if (runMatch) {
    const cur = new Set();
    (runMatch[1].match(/(\w+)\(\d+:\d+:\d+\)/g) || []).forEach(p => {
      const name = p.match(/(\w+)\(/)[1];
      cur.add(name);
      _moduleActive.add(name);
      _modState[name] = 'running';
    });
    _prevRunning.forEach(m => {
      if (!cur.has(m)) { _moduleDone.add(m); _modState[m] = 'done'; }
    });
    _prevRunning = cur;
    _updateETA();
    renderHUD();
  }
}

// Mark all HUD phase modules that never appeared in "Modules running" as done.
// Called when scan finishes — catches modules that ran too fast to be logged.
function _finalizeScanHUD() {
  _prevRunning.forEach(m => { _moduleDone.add(m); _modState[m] = 'done'; });
  _prevRunning = new Set();
  BBOT_HUD_PHASES.forEach(phase => {
    phase.mods.forEach(m => {
      if (!_modState[m]) { _modState[m] = 'done'; _moduleDone.add(m); }
    });
  });
  _updateETA();
  renderHUD();
}

// ── Particle engine ──────────────────────────────────────────────────────
function _startParticles() {
  const canvas = document.getElementById('hud-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  function resize() { canvas.width = canvas.offsetWidth; canvas.height = canvas.offsetHeight; }
  resize();
  const obs = new ResizeObserver(resize);
  obs.observe(canvas.parentElement);
  const pts = Array.from({length:55}, () => ({
    x: Math.random(), y: Math.random(),
    vx: (Math.random()-.5)*.0004, vy: (Math.random()-.5)*.0004,
    r: Math.random()*.9+.2, a: Math.random()*.35+.05,
  }));
  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    pts.forEach(p => {
      const x = p.x * canvas.width, y = p.y * canvas.height;
      ctx.beginPath(); ctx.arc(x, y, p.r, 0, Math.PI*2);
      ctx.fillStyle = `rgba(0,180,255,${p.a})`; ctx.fill();
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = 1; if (p.x > 1) p.x = 0;
      if (p.y < 0) p.y = 1; if (p.y > 1) p.y = 0;
    });
    _particleAnim = requestAnimationFrame(draw);
  }
  if (_particleAnim) cancelAnimationFrame(_particleAnim);
  draw();
}
function _stopParticles() {
  if (_particleAnim) { cancelAnimationFrame(_particleAnim); _particleAnim = null; }
}

// ── HUD render ───────────────────────────────────────────────────────────
function _phaseStatus(idx) {
  const phase = BBOT_HUD_PHASES[idx];
  const all = [...phase.mods, ...Object.keys(_modState).filter(m => _MOD_PHASE[m]===idx && !phase.mods.includes(m))];
  if (all.some(m => _modState[m]==='running'))  return 'active';
  if (all.some(m => _modState[m]==='done'))      return 'done';
  return 'pending';
}

function _buildPanel(phase, idx, show) {
  if (!show) return `<div class="hud-panel ph-hidden"></div>`;
  const st = _phaseStatus(idx);
  const all = [...phase.mods, ...Object.keys(_modState).filter(m => _MOD_PHASE[m]===idx && !phase.mods.includes(m))];

  const running = all.filter(m => _modState[m]==='running');
  const done    = all.filter(m => _modState[m]==='done');
  const ready   = all.filter(m => _modState[m]==='ready');
  const skipped = all.filter(m => _modState[m]==='skipped');

  const totalActive = running.length + done.length + ready.length;
  const pct = totalActive ? Math.round(done.length / Math.max(totalActive, 1) * 100) : 0;

  // Show: running first, then recent done, then ready; max 7 per panel
  const toShow = [...running, ...done.slice(-4), ...ready.slice(0,2)].slice(0,7);
  const skipHtml = skipped.length
    ? `<div class="hud-panel-mod hud-mod-skipped"><div class="hud-panel-mod-dot"></div><span>${skipped.length} sem api key</span></div>`
    : '';
  const modHtml = toShow.map(m => {
    const s = _modState[m]||'pending';
    return `<div class="hud-panel-mod hud-mod-${s}"><div class="hud-panel-mod-dot"></div><span>${m.replace(/_/g,' ')}</span></div>`;
  }).join('');

  const statsHtml = (done.length || running.length || skipped.length)
    ? `<div style="font-size:.53rem;color:#1e3a4a;margin-top:3px;letter-spacing:.04em">${done.length} ok · ${running.length} active · ${skipped.length} skip</div>`
    : '';

  // Placeholder when no modules ran yet: distinguish "waiting" vs "all skipped"
  const allSkipped = !toShow.length && skipped.length > 0 && skipped.length === all.length;
  const placeholder = allSkipped
    ? `<div class="hud-panel-mod hud-mod-skipped"><div class="hud-panel-mod-dot"></div><span>sem chaves configuradas</span></div>`
    : `<div class="hud-panel-mod hud-mod-pending"><div class="hud-panel-mod-dot"></div><span>aguardando…</span></div>`;

  return `<div class="hud-panel ${st}">
    <div class="hud-panel-label" style="color:${phase.color}">${phase.label}</div>
    <div class="hud-panel-prog"><div class="hud-panel-prog-bar" style="width:${pct}%;background:${phase.color}"></div></div>
    ${modHtml || placeholder}
    ${skipHtml}${statsHtml}
  </div>`;
}

function renderHUD() {
  const topEl   = document.getElementById('hud-top');
  const botEl   = document.getElementById('hud-bot');
  const nodesEl = document.getElementById('hud-nodes');
  const glowEl  = document.getElementById('hud-tl-glow');
  if (!topEl||!botEl||!nodesEl) return;

  // Timeline glow (progress across phases)
  const donePhases = BBOT_HUD_PHASES.filter((_,i)=>_phaseStatus(i)==='done').length;
  const activePh   = BBOT_HUD_PHASES.findIndex((_,i)=>_phaseStatus(i)==='active');
  const progress   = activePh>=0 ? (activePh+.5)/BBOT_HUD_PHASES.length : donePhases/BBOT_HUD_PHASES.length;
  if (glowEl) glowEl.style.right = `${Math.round((1-progress)*100)}%`;

  // Nodes
  nodesEl.innerHTML = BBOT_HUD_PHASES.map((phase, idx) => {
    const st = _phaseStatus(idx);
    return `<div class="hud-node ${st}" style="--nc:${phase.color}" title="${phase.label}">
      <div class="hud-node-inner">${st==='done'?icoHtml("check",14):(phase.ico?icoHtml(phase.ico,14):phase.icon)}</div>
      <div class="hud-node-label">${phase.label}</div>
    </div>`;
  }).join('');

  // Panels alternating top/bottom
  topEl.innerHTML = BBOT_HUD_PHASES.map((p,i) => _buildPanel(p,i, i%2===0)).join('');
  botEl.innerHTML = BBOT_HUD_PHASES.map((p,i) => _buildPanel(p,i, i%2===1)).join('');
}

function _fmtSec(s) {
  if (s >= 3600) return `~${Math.ceil(s/3600)}h`;
  if (s >= 60)   return `~${Math.ceil(s/60)}m`;
  return `~${s}s`;
}

function _updateETA() {
  // Total = all modules ever seen (active + done)
  const allSeen = new Set([..._moduleActive, ..._moduleDone]);
  const total   = allSeen.size || 1;
  const done    = _moduleDone.size;
  const active  = _prevRunning.size;
  const remaining = Math.max(0, total - done);

  // Sum ETA for modules not yet done
  let remSec = 0;
  allSeen.forEach(m => { if (!_moduleDone.has(m)) remSec += (MODULE_ETA_S[m] || 45); });
  const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
  // Decay: each elapsed second removes proportional estimated time
  remSec = Math.max(0, remSec - Math.floor(elapsed * (done / Math.max(total, 1))));

  const el = document.getElementById('term-modules');
  const sb = document.getElementById('scanbar-modules');
  if (remaining > 0) {
    const etaStr = _fmtSec(remSec);
    const html = `<span style="color:var(--teal)">${done}/${total}</span> modules`
      + ` · <span style="color:var(--yellow)">${active} active</span>`
      + ` · <span style="color:var(--text3)">${remaining} remaining · ETA ${etaStr}</span>`;
    if (el) el.innerHTML = html;
    if (sb) sb.textContent = `${done}/${total} · ${active} active · ETA ${etaStr}`;
  } else {
    if (el) el.innerHTML = `<span style="color:var(--green)">${icoHtml("check",14)} ${done} modules completed</span>`;
  if (sb) sb.textContent = ` ${done} modules`;
  }
}

function selectProfile(val, el) {
  selectedProfile = val;
  document.querySelectorAll(".scan-profile").forEach(e=>e.classList.remove("selected"));
  el.classList.add("selected");
  document.getElementById("scan-flags-field").style.display = val==="custom" ? "block" : "none";
}

let selectedRateMode = "stealth";
function selectRateMode(val, el) {
  selectedRateMode = val;
  document.querySelectorAll(".rate-mode-btn").forEach(e=>e.classList.remove("selected"));
  el.classList.add("selected");
}

async function monitorNow(cid) {
  // Run a quick pipeline scan now (stealth mode)
  var btn = document.getElementById('monitor-now-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Starting...'; }
  try {
    var r = await fetch('/api/recon/' + cid + '/pipeline', {
      method:'POST',
      headers: {'Content-Type':'application/json', ..._authHeaders()},
      body: JSON.stringify({mode:'stealth'})
    });
    var data = await r.json();
    if (r.ok) {
      showToast('Pipeline started in stealth mode — check Pipeline HUD tab');
      showPage('company'); selectCompany(cid); switchTab('pipeline');
    } else {
      showToast('Error: ' + (data.error || 'Unknown'));
    }
  } catch(e) { showToast('Failed: ' + e.message); }
 if (btn) { btn.disabled = false; btn.textContent = ' Monitor Now'; }
}

async function enableSchedule(cid, enabled) {
  try {
    if (enabled) {
      var interval = prompt('Scan interval (hours):', '24');
      if (!interval) return;
    }
    var r = await fetch('/api/schedule/' + cid, {
      method:'POST',
      headers: {'Content-Type':'application/json', ..._authHeaders()},
      body: JSON.stringify({enabled: enabled, interval_hours: enabled ? parseInt(interval) : 24, profile: 'bug_bounty'})
    });
    if (r.ok) {
      showToast('Schedule ' + (enabled ? 'enabled — every ' + interval + 'h' : 'disabled'));
      loadScheduleStatus(cid);
    }
  } catch(e) { showToast('Failed: ' + e.message); }
}

async function loadScheduleStatus(cid) {
  var schBtn = document.getElementById("enable-schedule-btn");
  if (!schBtn) return;
  try {
    var r = await fetch('/api/schedule/' + cid, {headers:_authHeaders()});
    if (!r.ok) { _setIconLabel(schBtn, "clock", t("btn_schedule")); return; }
    var s = await r.json();
    if (s && s.enabled) {
      _setIconLabel(schBtn, "clock", (s.interval_hours||'?') + 'h on');
      schBtn.style.color = '#4ade80';
    } else {
      _setIconLabel(schBtn, "clock", t("btn_schedule_off"));
      schBtn.style.color = '';
    }
  } catch(e) { _setIconLabel(schBtn, "clock", t("btn_schedule")); }
}

async function toggleSchedule(cid) {
  var btn = document.getElementById("enable-schedule-btn");
  if (!btn) return;
  try {
    var r = await fetch('/api/schedule/' + cid, {headers:_authHeaders()});
    var s = r.ok ? await r.json() : {};
    if (s && s.enabled) {
      if (!confirm('Schedule is active (every ' + (s.interval_hours||'?') + 'h). Disable it?')) return;
      await fetch('/api/schedule/' + cid, {method:'POST', headers:{'Content-Type':'application/json', ..._authHeaders()}, body:JSON.stringify({enabled:false, interval_hours:s.interval_hours||24, profile:'bug_bounty'})});
      _setIconLabel(btn, "clock", t("btn_schedule_off")); btn.style.color = '';
    } else {
      var interval = prompt('Scan interval (hours):', '24');
      if (!interval) return;
      await fetch('/api/schedule/' + cid, {method:'POST', headers:{'Content-Type':'application/json', ..._authHeaders()}, body:JSON.stringify({enabled:true, interval_hours:parseInt(interval), profile:'bug_bounty'})});
      _setIconLabel(btn, "clock", interval + 'h on'); btn.style.color = '#4ade80';
    }
  } catch(e) { console.error(e); }
}

async function openScanModal(companyId) {
  if (!SERVER_MODE) {
    showToast("Start the server to run scans:\n\npython3 server.py\n\nThen open http://localhost:5000");
    return;
  }
  const co = allCompanies().find(c=>c.id===companyId);
  if (!co) return;
  document.getElementById("scan-modal-co").textContent = co.name;
  document.getElementById("scan-error").style.display = "none";
  document.getElementById("modal-scan").classList.add("show");
  _scanCompanyId = companyId;

  // Show targets with loading state while validating
  const targetsEl = document.getElementById("scan-targets-list");
  targetsEl.innerHTML = (co.domains||[]).map(d=>`<div>⏳ ${esc(d)}</div>`).join("");

  try {
    const r = await fetch("/api/validate-domains", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({domains: co.domains||[]})
    });
    const results = await r.json();
    targetsEl.innerHTML = results.map(item => {
      const icon = item.ok ? "" : "";
      const color = item.ok ? "var(--teal)" : "var(--red)";
      const detail = item.ok ? item.ip : item.error;
      return `<div style="color:${color}">${icon} ${esc(item.domain)} <span style="color:var(--text3);font-size:.68rem">${esc(detail)}</span></div>`;
    }).join("");
    // Warn if any domain fails
    const failed = results.filter(r=>!r.ok);
    if(failed.length){
      const errEl = document.getElementById("scan-error");
      errEl.textContent = `Warning: ${failed.length} domain(s) did not resolve. Scan may produce limited results.`;
      errEl.style.display = "block";
      errEl.style.background = "rgba(251,191,36,0.1)";
      errEl.style.color = "#fbbf24";
      errEl.style.borderColor = "rgba(251,191,36,0.2)";
    }
  } catch(e) {
    targetsEl.innerHTML = (co.domains||[]).map(d=>`<div>${esc(d)}</div>`).join("");
  }
}

let _scanCompanyId = null;
function closeScanModal() {
  document.getElementById("modal-scan").classList.remove("show");
  document.getElementById("scan-checkpoint-info").style.display = "none";
}

async function runCheckpointDiff() {
  const btn = document.getElementById("checkpoint-btn");
  const infoEl = document.getElementById("scan-checkpoint-info");
  const bodyEl = document.getElementById("scan-checkpoint-body");
  btn.disabled = true;
  btn.textContent = "Fingerprinting…";
  infoEl.style.display = "block";
  bodyEl.innerHTML = `<span style="color:var(--text3)">Fetching live hosts and computing hashes… this takes ~30s</span>`;

  try {
    // Start the checkpoint scan job
    const r = await fetch(`/api/checkpoints/${_scanCompanyId}/scan`, {method:"POST",
      headers: _authHeaders(), body:"{}"});
    if (!r.ok) throw await _apiErr(r);
    const { scan_id, total_hosts } = await r.json();
    bodyEl.innerHTML = `<span style="color:var(--text3)">Scanning ${total_hosts} hosts…</span>`;

    // Poll until done
    await new Promise((resolve, reject) => {
      const iv = setInterval(async () => {
        try {
          const pr = await fetch(`/api/checkpoints/job/${scan_id}`);
          const pd = await pr.json();
          const pct = total_hosts > 0 ? Math.round((pd.done||0)/total_hosts*100) : 0;
          bodyEl.innerHTML = `<span style="color:var(--text3)">Progress: ${pd.done||0}/${total_hosts} (${pct}%)</span>`;
          if (pd.status === "done") { clearInterval(iv); resolve(pd); }
          else if (pd.status === "error") { clearInterval(iv); reject(new Error(pd.error||"failed")); }
        } catch(e) { clearInterval(iv); reject(e); }
      }, 2000);
    }).then(pd => {
      const SEV = (n) => n > 0 ? `<span style="color:#fb923c;font-weight:600">${n}</span>` : `<span style="color:var(--text3)">${n}</span>`;
      let html = `<div style="margin-bottom:6px">${pd.summary}</div>`;
      if (pd.first_run) {
        html += `<div style="color:var(--teal)">${icoHtml("check",14)} First checkpoint saved — future scans will diff against this.</div>`;
      } else {
        if (pd.changed && pd.changed.length > 0) {
          html += `<div style="margin-bottom:4px;color:#fb923c;font-weight:600">Changed hosts (${pd.changed.length}) — recommend re-scan:</div>`;
          html += pd.changed.slice(0,15).map(url => {
            const fields = (pd.change_details||{})[url] || [];
            return `<div style="font-family:var(--mono);font-size:.7rem;padding:2px 0">
              <span style="color:var(--text)">${url}</span>
              <span style="color:var(--text3);margin-left:6px">[${fields.join(", ")}]</span></div>`;
          }).join("") + (pd.changed.length > 15 ? `<div style="color:var(--text3)">…and ${pd.changed.length-15} more</div>` : "");
        }
        if (pd.new && pd.new.length > 0) {
          html += `<div style="margin-top:6px;color:#4ade80;font-weight:600">New hosts (${pd.new.length}):</div>`;
          html += pd.new.slice(0,10).map(u=>`<div style="font-family:var(--mono);font-size:.7rem">${u}</div>`).join("");
        }
        if ((!pd.changed || !pd.changed.length) && (!pd.new || !pd.new.length)) {
          html += `<div style="color:#4ade80">${icoHtml("check",14)} No changes detected — no re-scan needed.</div>`;
        }
      }
      bodyEl.innerHTML = html;
    });
  } catch(e) {
    bodyEl.innerHTML = `<span style="color:#fb7185">Error: ${e.message}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "⧗ Check Changes";
  }
}

async function startScan() {
  const btn = document.getElementById("scan-start-btn");
  const errEl = document.getElementById("scan-error");
  errEl.style.display = "none";
  btn.disabled = true; btn.textContent = "Starting…";

  try {
    const r = await fetch(`/api/recon/${_scanCompanyId}/pipeline`, {
      method: "POST",
      headers: {"Content-Type":"application/json", ..._authHeaders()},
      body: JSON.stringify({
        mode: selectedRateMode,
        profile: selectedProfile,
        incremental: !!(document.getElementById("scan-incremental") && document.getElementById("scan-incremental").checked),
      }),
    });
    let data = {};
    if (!r.ok) {
      if (r.status === 401) throw await _apiErr(r);
      const t = await r.text();
      if (r.status !== 409 || !t.includes("already running")) {
        throw new Error(t);
      }
    } else {
      data = await r.json().catch(() => ({}));
    }

    if (typeof uploadNucleiTemplate === "function" && document.getElementById("nuclei-template-file")?.files?.length) {
      try { await uploadNucleiTemplate(_scanCompanyId); } catch (e) {}
    }
    closeScanModal();
    // Switch to the Recon tab for the company so the user sees the pipeline progress
    switchTab("pipeline", [...document.querySelectorAll(".tab-btn")].find(b=>b.textContent.includes("Pipeline")));
    pipelineState[_scanCompanyId] = {
      ...(pipelineState[_scanCompanyId] || {}),
      status: data.status || "queued",
      job_id: data.job_id || "",
      phase_label: "",
      host_count: 0,
      phases: [],
      not_done: [],
      started_at: new Date().toLocaleTimeString(),
      log: data.job_id ? [{ts:new Date().toISOString(), msg:`Pipeline queued as job ${data.job_id}`}] : [],
    };
    renderPipelineStatus(_scanCompanyId);
    _startPipelinePoll(_scanCompanyId);
    _ltActiveCid = _scanCompanyId; _ltEnsurePolling();  // start live terminal globally
  } catch(e) {
    errEl.textContent = "Erro ao iniciar pipeline: "+e.message;
    errEl.style.display = "block";
  } finally {
    btn.disabled = false; btn.innerHTML = `<svg viewBox="0 0 16 16" fill="currentColor" style="width:12px;height:12px;margin-right:4px"><path d="M3 2l10 6-10 6V2z"/></svg>Start Scan`;
  }
}

// ── Terminal ──────────────────────────────────────────────────────────────────
let _liveDataInterval = null;
let _lastDataTs = 0;

function stopLiveDataPolling() {
  if (_liveDataInterval) { clearInterval(_liveDataInterval); _liveDataInterval = null; }
  // Note: terminal polling (_ltPoll) is NOT stopped here — it runs globally
  // while any pipeline is active, regardless of which tab the user is viewing.
}

function startLiveDataPolling(companyId) {
  stopLiveDataPolling();
  _lastDataTs = 0;
  // Use 8s interval — fast enough to catch phase transitions without hammering
  _liveDataInterval = setInterval(async () => {
    try {
      const r = await fetch("/api/data/ts", {headers: _authHeaders()});
      if (!r.ok) return;
      const { ts } = await r.json();
      if (ts > _lastDataTs && _lastDataTs > 0) {
        await reloadServerData();
        if (state.currentId === companyId) {
          const co = allCompanies().find(c => c.id === companyId);
          if (co) renderCompanyView(co);
        }
        renderAllCompanies();
        renderSidebar();
        const liveEl = document.getElementById("term-live-badge");
        if (liveEl) { liveEl.style.opacity = "1"; setTimeout(() => liveEl.style.opacity = "0.4", 800); }
      }
      _lastDataTs = ts;
    } catch(e) {}
  }, 8000);
}

function openTerminal(scanId, scanName, companyId) {
  activeScanId  = scanId;
  scanLineCount = 0;
  scanStartTime = Date.now();
  _scanModules  = [];
  _moduleActive = new Set();
  _moduleDone   = new Set();
  _prevRunning  = new Set();
  _modState     = {};
  _hudLogLines  = [];
  const modEl = document.getElementById('term-modules');
  if (modEl) modEl.innerHTML = '';
  const sbEl = document.getElementById('scanbar-modules');
  if (sbEl) sbEl.textContent = '';

  document.getElementById("term-title").textContent = scanName;
  document.getElementById("term-body").innerHTML = "";
  const logEl = document.getElementById('hud-mini-log');
  if (logEl) logEl.innerHTML = '';
  document.getElementById("terminal-overlay").classList.add("show");
  document.getElementById("term-stop-btn").style.display = "";
  document.getElementById("scanbar-name").textContent = scanName;

  renderHUD();
  _startParticles();
  updateTermStatus("running");
  streamScanOutput(scanId, companyId);
  startLiveDataPolling(companyId);
}

function closeTerminal() {
  document.getElementById("terminal-overlay").classList.remove("show");
  document.getElementById("scan-bar").style.display = "none";
  if (scanEventSrc) { scanEventSrc.close(); scanEventSrc = null; }
  _stopParticles();
}

function minimizeTerminal() {
  document.getElementById("terminal-overlay").classList.remove("show");
  document.getElementById("scan-bar").style.display = "flex";
}

function maximizeTerminal() {
  document.getElementById("terminal-overlay").classList.add("show");
  document.getElementById("scan-bar").style.display = "none";
}

async function stopScan() {
  // Stop pipeline by company ID (current viewed company)
  var cid = state.currentId || _scanCompanyId;
  if (!cid) return;
  await stopPipeline(cid, {notify: true});
  var stopBtn = document.getElementById("stop-pipeline-btn");
  if (stopBtn) stopBtn.style.display = "none";
}

function updateTermStatus(status) {
  const labels = {running:"Scanning…", done:"Completed", error:"Error", stopped:"Stopped"};
  const el = document.getElementById("term-status");
  el.innerHTML = `<span class="scan-status ${status}"><span class="scan-dot"></span>${labels[status]||status}</span>`;

  const sb = document.getElementById("scanbar-status");
  sb.className = `scan-status ${status}`;
  sb.innerHTML = `<span class="scan-dot"></span>${labels[status]||status}`;

  if (status !== "running") {
    document.getElementById("term-stop-btn").style.display = "none";
    const lb = document.getElementById("term-live-badge");
    if (lb) lb.style.display = "none";
  }
}

function streamScanOutput(scanId, companyId) {
  if (scanEventSrc) scanEventSrc.close();
  const src = new EventSource(`/api/scan/${scanId}/stream`);
  scanEventSrc = src;

  src.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.done) {
      src.close(); scanEventSrc = null;
      stopLiveDataPolling();
      updateTermStatus(msg.status);
      _finalizeScanHUD();
      document.getElementById("term-stop-btn").style.display = "none";
      // Final reload after scan completes
      setTimeout(()=>reloadServerData().then(()=>{
        if (state.currentId === companyId) {
          const co = allCompanies().find(c=>c.id===companyId);
          if (co) renderCompanyView(co);
        }
        renderAllCompanies(); renderSidebar();
      }), 1500);
      return;
    }
    appendTermLine(msg.line);
    updateTermStatus(msg.status);
  };

  src.onerror = () => {
    src.close(); scanEventSrc = null;
    updateTermStatus("error");
  };
}

function appendTermLine(raw) {
  scanLineCount++;
  const plain = _stripAnsi(raw);

  // Hidden buffer for legacy references
  const body = document.getElementById("term-body");
  if (body) { const d = document.createElement("div"); d.textContent = plain; body.appendChild(d); }

  // Action bar: update on meaningful lines only
  const actionEl = document.getElementById('hud-action');
  if (actionEl && plain.trim()) {
    const isFind  = plain.includes('[FINDING]') || plain.includes('[VULNERABILITY]');
    const isOk    = plain.includes('[✓]') || plain.includes('[SUCC]');
    const isWarn  = plain.includes('[!]');
    const isRun   = plain.includes('Modules running');
    if (isFind || isOk || isWarn || isRun || plain.includes('[INFO]')) {
   actionEl.textContent = ' ' + plain.replace(/\[.*?\]\s*/g,'').slice(0,140);
      actionEl.className = 'hud-action-bar' + (isFind?'  al-find': isOk?' al-ok': isWarn?' al-active': ' al-run');
    }
  }

  document.getElementById("term-stats").textContent = `${scanLineCount} lines`;
  const elapsed = Math.floor((Date.now()-scanStartTime)/1000);
  document.getElementById("term-time").textContent = `${Math.floor(elapsed/60)}m ${elapsed%60}s elapsed`;

  _detectModules(raw);
}

// ── Scan Log Viewer ──────────────────────────────────────────────────────
let _logAllLines = [];

function _logLineClass(line) {
  if (line.includes('[SUCC]') || line.includes('[✓]'))        return 'll-succ';
  if (line.includes('[FINDING]') || line.includes('[VULNERABILITY]')) return 'll-find';
  if (line.includes('[!]') || line.includes('[WARN]'))        return 'll-warn';
  if (line.includes('[ERROR]'))                               return 'll-err';
  if (line.includes('[INFO]'))                                return 'll-info';
  if (!line.trim())                                           return 'll-dim';
  return '';
}

async function openScanLog(cid, scanName) {
  const overlay = document.getElementById('log-modal-overlay');
  const bodyEl  = document.getElementById('log-modal-body');
  const titleEl = document.getElementById('log-modal-title');
  const metaEl  = document.getElementById('log-modal-meta');
  const countEl = document.getElementById('log-modal-count');
  const searchEl= document.getElementById('log-modal-search');
  if (!overlay) return;
  titleEl.textContent = scanName;
  metaEl.textContent  = 'Loading…';
  bodyEl.innerHTML    = `<div style="color:var(--text3);padding:20px">Loading scan log…</div>`;
  searchEl.value      = '';
  overlay.classList.add('show');
  try {
    const r = await fetch(`/api/scan-history/${encodeURIComponent(cid)}/${encodeURIComponent(scanName)}/log`, {headers:_authHeaders()});
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    const data = await r.json();
    _logAllLines = data.lines;
    metaEl.textContent  = `${data.total.toLocaleString()} linhas`;
    countEl.textContent = `${data.lines.length} exibidas de ${data.total}`;
    _renderLogLines(_logAllLines, bodyEl);
  } catch(e) {
    bodyEl.innerHTML = `<div style="color:var(--red);padding:20px">Erro: ${esc(e.message)}</div>`;
  }
}

function _renderLogLines(lines, bodyEl) {
  const frag = document.createDocumentFragment();
  lines.forEach(raw => {
    const plain = _stripAnsi(raw);
    const d = document.createElement('div');
    d.className = 'log-line ' + _logLineClass(plain);
    d.textContent = plain;
    frag.appendChild(d);
  });
  bodyEl.innerHTML = '';
  bodyEl.appendChild(frag);
}

function filterLogLines(q) {
  const bodyEl  = document.getElementById('log-modal-body');
  const countEl = document.getElementById('log-modal-count');
  if (!bodyEl) return;
  const filtered = q ? _logAllLines.filter(l => _stripAnsi(l).toLowerCase().includes(q.toLowerCase())) : _logAllLines;
  countEl.textContent = `${filtered.length} de ${_logAllLines.length} linhas`;
  // Re-render with highlight
  const frag = document.createDocumentFragment();
  filtered.forEach(raw => {
    const plain = _stripAnsi(raw);
    const d = document.createElement('div');
    d.className = 'log-line ' + (q ? 'll-highlight' : _logLineClass(plain));
    d.textContent = plain;
    frag.appendChild(d);
  });
  bodyEl.innerHTML = '';
  bodyEl.appendChild(frag);
}

function scrollLogTo(pos) {
  const b = document.getElementById('log-modal-body');
  if (!b) return;
  b.scrollTop = pos === 'bottom' ? b.scrollHeight : 0;
}

function lineClass(line) {
  if (line.includes("[DNS_NAME]"))        return "dns";
  if (line.includes("[FINDING]"))         return "find";
  if (line.includes("[VULNERABILITY]"))   return "vuln";
  if (line.includes("[WAF]"))             return "waf";
  if (line.includes("[TECHNOLOGY]"))      return "tech";
  if (line.includes("[HTTP_RESPONSE]"))   return "http";
  if (line.includes("[STORAGE_BUCKET]"))  return "warn";
  if (line.includes("[✓]") || line.includes("[*]")) return "ok";
  if (line.includes("[!]"))               return "warn";
  if (line.includes("[ERROR]"))           return "err";
  return "default";
}
