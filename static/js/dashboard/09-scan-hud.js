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

function _stopParticles() {
  if (_particleAnim) { cancelAnimationFrame(_particleAnim); _particleAnim = null; }
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

