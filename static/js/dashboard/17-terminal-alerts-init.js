// ════════════════════════════════════════════════════════════════════════
//  LIVE TERMINAL TAB — real-time verbose tool output
// ════════════════════════════════════════════════════════════════════════
// Shows actual stdout/stderr from tools as they execute, grouped by module.
// Polls globally while a pipeline is running, renders only when tab is open.
let _ltPoll = null;
let _ltPaused = false;
let _ltActiveCid = null;
let _ltSince = 0;          // Unix timestamp for incremental live output fetching
let _ltCmdLog = [];        // command invocations from tool-logs
let _ltCmdLastTs = "";     // last seen command timestamp

// Grouped output: { module: [{ts, stream, line}, ...] }
let _ltModules = {};       // module -> array of output lines + commands

function _ltEnsurePolling() {
  const activeCid = Object.keys(pipelineState).find(cid => {
    const ps = pipelineState[cid];
    return ps && (ps.status === "running" || ps.status === "queued");
  });
  if (!activeCid) {
    if (_ltPoll) { clearInterval(_ltPoll); _ltPoll = null; _ltActiveCid = null; }
    return;
  }
  if (_ltActiveCid !== activeCid) {
    _ltActiveCid = activeCid;
    _ltSince = Date.now() / 1000;
    _ltCmdLog = [];
    _ltCmdLastTs = "";
    _ltModules = {};
  }
  if (_ltPoll) return;
  _ltPoll = setInterval(() => _fetchLT(), 1500);
  _fetchLT();
}

async function _fetchLT() {
  if (_ltPaused || !_ltActiveCid) return;
  let hasNew = false;
  // 1) Fetch new command invocations from tool-logs
  try {
    const r = await fetch("/api/recon/" + _ltActiveCid + "/tool-logs", {headers: _authHeaders()});
    if (r.ok) {
      const all = await r.json();
      for (let i = all.length - 1; i >= 0; i--) {
        if (all[i].ts <= _ltCmdLastTs) break;
        const l = all[i];
        _ltCmdLog.unshift(l);
        // Record command start in module output
        const mod = l.module || "?";
        if (!_ltModules[mod]) _ltModules[mod] = [];
        if (!_ltModules[mod].some(e => e._cmd === l.cmd)) {
          _ltModules[mod].push({ts: l.ts, stream: "cmd", line: "$ "+l.cmd, _cmd: l.cmd,
            status: l.status, exit_code: l.exit_code, duration: l.duration, run_id: l.run_id, tool: l.tool});
        }
        hasNew = true;
      }
      if (all.length > 0) _ltCmdLastTs = all[all.length-1].ts;
    }
  } catch(e) {}

  // 2) Fetch real-time stdout/stderr output
  try {
    const r = await fetch("/api/live-output/" + _ltActiveCid + "?since=" + _ltSince, {headers: _authHeaders()});
    if (r.ok) {
      const {lines, ts} = await r.json();
      if (ts) _ltSince = ts;
      for (const l of lines) {
        const mod = l.module || "?";
        if (!_ltModules[mod]) _ltModules[mod] = [];
        _ltModules[mod].push({ts: l.ts, stream: l.stream, line: l.line});
        hasNew = true;
      }
    }
  } catch(e) {}

  if (hasNew) {
    _renderLTTerminal();
    const badge = document.getElementById("lt-live-badge");
    if (badge) { badge.style.display = "inline-block"; setTimeout(() => badge.style.display = "none", 1500); }
  }
  const cnt = document.getElementById("lt-cnt");
  if (cnt) {
    const total = Object.values(_ltModules).reduce((s,arr) => s+arr.length, 0);
    cnt.textContent = total + " lines" + (_ltPaused ? " (paused)" : "");
  }
}

function _lineCount() {
  return Object.values(_ltModules).reduce((s,arr) => s+arr.length, 0);
}

function _renderLTTerminal() {
  const body = document.getElementById("lt-body");
  if (!body) return;
  const wasAtBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 50;

  // Sort modules by first timestamp
  const sortedMods = Object.entries(_ltModules).sort((a,b) => {
    const ta = a[1].length ? a[1][0].ts : "z";
    const tb = b[1].length ? b[1][0].ts : "z";
    return ta < tb ? -1 : ta > tb ? 1 : 0;
  });

  let html = "";
  for (const [mod, entries] of sortedMods) {
    // Module header
    const lastEntry = entries[entries.length-1];
    const isRunning = lastEntry && lastEntry.stream === "stdout" && lastEntry.status !== "done" && lastEntry.status !== "error";
    const headerCls = isRunning ? "lt-mod-running" : "lt-mod-done";

    // Collapse/expand toggle
    const modId = "ltmod-" + mod.replace(/[^a-z0-9]/gi, "_");
    html += `<div class="lt-module ${headerCls}" id="${modId}-wrap">
   <div class="lt-mod-hdr" onclick="document.getElementById('${modId}-body').classList.toggle('lt-collapsed'); this.querySelector('.lt-mod-arr').textContent = document.getElementById('${modId}-body').classList.contains('lt-collapsed') ? '' : '▼'">
        <span class="lt-mod-arr">▼</span>
        <span class="lt-mod-name">[${esc(mod)}]</span>
        <span class="lt-mod-tool">${lastEntry && lastEntry.tool ? esc(lastEntry.tool) : ""}</span>
        ${lastEntry && lastEntry.status ? `<span class="lt-status ${lastEntry.status==='error'?'err':lastEntry.status==='timeout'?'timeout':'ok'}">${esc(lastEntry.status)}</span>` : isRunning ? `<span class="lt-status ok">running</span>` : ""}
        ${lastEntry && lastEntry.duration != null ? `<span class="lt-mod-dur">${lastEntry.duration.toFixed(1)}s</span>` : ""}
        <span class="lt-mod-lines">${entries.length} lines</span>
      </div>
      <div class="lt-mod-body" id="${modId}-body">`;

    // Module body — stdout/stderr lines
    for (const e of entries.slice(-200)) {
      if (e.stream === "cmd") {
        html += `<div class="lt-line lt-cmd-line">
          <span class="ts">${(e.ts||"").slice(11,19)}</span>
          <span class="lt-prom">$</span>
          <span class="lt-cmd-full">${esc(e.line)}</span>
        </div>`;
      } else if (e.stream === "stdout") {
        html += `<div class="lt-line lt-stdout">${esc(e.line)}</div>`;
      } else if (e.stream === "stderr") {
        html += `<div class="lt-line lt-stderr">${esc(e.line)}</div>`;
      }
    }
    html += `</div></div>`;
  }

  body.innerHTML = html + (_ltPaused ? `<div class="lt-paused">⏸ Paused — ${_lineCount()} lines captured</div>` : "") +
    (_ltPaused ? "" : `<div style="height:1px" id="lt-anchor"></div>`);

  if (wasAtBottom) {
    const anchor = document.getElementById("lt-anchor");
    if (anchor) anchor.scrollIntoView({behavior: "smooth", block: "end"});
    else body.scrollTop = body.scrollHeight;
  }
}

function renderLiveTerminal(cid) {
  const el = document.getElementById("tab-terminal");
  if (!el) return;
  _ltActiveCid = cid;
  _ltEnsurePolling();
  el.innerHTML = `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">Live Terminal</div>
          <div class="section-title">Verbose tool output — stdout & stderr in real time</div>
          <div class="section-sub">Each module is a collapsible process. Green = stdout, Red = stderr. Click module headers to expand/collapse.</div>
        </div>
        <div class="section-actions">
          <span class="sec-cnt" id="lt-cnt">${_lineCount()} lines</span>
        </div>
      </div>
      <div class="lt-wrap">
        <div class="lt-hdr">
          <div class="lt-dots"><span class="r"></span><span class="y"></span><span class="g"></span></div>
          <span>scantrely@asm:~$ pipeline monitor — ${esc(cid)}</span>
          <span style="margin-left:auto;display:flex;gap:8px">
            <span id="lt-live-badge" style="display:none;color:#4ade80;font-weight:600">⬤ LIVE</span>
            <button id="lt-pause-btn" class="btn btn-secondary btn-icon" onclick="toggleLTPause()">${_ltPaused ? icoHtml("play",14)+' Resume' : icoHtml("pause",14)+' Pause'}</button>
            <button class="btn btn-secondary btn-icon" onclick="_ltModules={};_ltSince=Date.now()/1000;_renderLTTerminal()" aria-label="Clear terminal">↻ Clear</button>
          </span>
        </div>
        <div class="lt-body" id="lt-body"></div>
      </div>
    </div>`;
  _renderLTTerminal();
}

function startLTPoll(cid) { _ltActiveCid = cid; _ltEnsurePolling(); }
function stopLTPoll() { if (_ltPoll) { clearInterval(_ltPoll); _ltPoll = null; } }
function toggleLTPause() {
  _ltPaused = !_ltPaused;
  const btn = document.getElementById("lt-pause-btn");
 if (btn) btn.innerHTML = _ltPaused ? icoHtml("play",14)+" Resume" : icoHtml("pause",14)+" Pause";
}
async function fetchLT(cid) { _ltActiveCid = cid; return _fetchLT(); }


// ════════════════════════════════════════════════════════════════════════
//  ALERTS TAB
// ════════════════════════════════════════════════════════════════════════
async function renderAlertsTab(co) {
  const el = document.getElementById("tab-alerts");
  if (!el) return;
  el.innerHTML = `<div class="skel skel-card"></div><div class="skel skel-card"></div>`;

  try {
    const r = await fetch(`/api/alerts/${co.id}`, {headers:_authHeaders()});
    if (!r.ok) { el.innerHTML = `<div class="diff-empty">Alerts unavailable</div>`; return; }
    const alerts = await r.json();
    const alertList = alerts.alerts || alerts || [];
    var badge = document.getElementById("tc-alerts");
    if (badge) badge.textContent = alertList.length || "";

    const rulesR = await fetch(`/api/alert-rules/${co.id}`, {headers:_authHeaders()});
    const rules = rulesR.ok ? await rulesR.json() : [];

    let html = `<div class="section-hdr"><h3> Alert Rules</h3>
      <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px" onclick="addAlertRule('${esc(co.id)}')">＋ Add Rule</button></div>`;

    for (const rule of (rules.rules || rules || [])) {
      const chs = (rule.channels || []).map(c => `<span class="channel-badge ${c}">${c}</span>`).join(' ');
      html += `<div class="rule-row">
        <div><div class="rule-name">${esc(rule.name||rule.rule_type)}</div><div class="rule-type">${esc(rule.rule_type)} · ${chs || 'no channels'}</div></div>
        <div style="display:flex;align-items:center;gap:10px">
          <label class="toggle"><input type="checkbox" ${rule.enabled ? 'checked' : ''} data-rid="${esc(rule.id)}" onchange="toggleAlertRule('${esc(co.id)}','${esc(rule.id)}',this.checked)"><span class="slider"></span></label>
          <button class="rule-del" title="Remove rule" onclick="deleteAlertRule('${esc(co.id)}','${esc(rule.id)}')">${icoHtml("x",14)}</button>
        </div>
      </div>`;
    }
    if (!(rules.rules || rules || []).length) html += `<div class="diff-empty">No alert rules configured</div>`;

    html += `<div class="section-hdr" style="margin-top:24px"><h3>${icoHtml("clipboard",14)} Recent Alerts</h3><span class="section-count">${(alerts.alerts||alerts||[]).length}</span></div>`;
    html += `<div class="alert-list">`;
    for (const a of (alerts.alerts || alerts || []).slice(0, 50)) {
      html += `<div class="alert-item">
        <div class="alert-sev ${a.severity}"></div>
        <div class="alert-body">
          <div class="alert-title">${esc(a.title)}</div>
          <div class="alert-desc">${esc(a.description||'')}</div>
          <div class="alert-ts">${esc(a.created_at||a.ts||'')}</div>
        </div>
        ${!a.acknowledged ? `<button class="alert-ack" onclick="ackAlert('${esc(co.id)}',${a.id})">Acknowledge</button>` : `<span style="font-size:.68rem;color:var(--text3)">${icoHtml("check",14)} Acked</span>`}
      </div>`;
    }
    if (!(alerts.alerts || alerts || []).length) html += `<div class="diff-empty">No alerts yet — they appear after scan diffs</div>`;
    html += `</div>`;

    el.innerHTML = html;
  } catch(e) { el.innerHTML = `<div class="diff-empty">Error: ${esc(e.message)}</div>`; }
}

async function toggleAlertRule(cid, rid, enabled) {
  await fetch(`/api/alert-rules/${cid}/${rid}`, {method:'PUT', headers:{'Content-Type':'application/json', ..._authHeaders()}, body:JSON.stringify({enabled})});
}

function openAlertRuleModal(cid) {
  const overlay = document.getElementById("modal-alert-rule");
  if (!overlay) { showToast("Modal de regra de alerta ausente", "error"); return; }
  overlay.dataset.cid = cid;
  const name = document.getElementById("ar-name");
  if (name) name.value = "";
  const type = document.getElementById("ar-type");
  if (type) type.selectedIndex = 0;
  overlay.querySelectorAll("#ar-channels input[type=checkbox]").forEach((cb) => { cb.checked = cb.value === "slack"; });
  const err = document.getElementById("ar-error");
  if (err) { err.style.display = "none"; err.textContent = ""; }
  overlay.classList.add("show");
  if (name) name.focus();
}

function closeAlertRuleModal() {
  document.getElementById("modal-alert-rule")?.classList.remove("show");
}

function addAlertRule(cid) { openAlertRuleModal(cid); }

async function submitAlertRule() {
  const overlay = document.getElementById("modal-alert-rule");
  const cid = overlay?.dataset.cid;
  const name = (document.getElementById("ar-name")?.value || "").trim();
  const type = document.getElementById("ar-type")?.value || "";
  const channels = [...document.querySelectorAll("#ar-channels input[type=checkbox]:checked")].map(cb => cb.value);
  const err = document.getElementById("ar-error");
  const showErr = (msg) => {
    if (err) { err.textContent = msg; err.style.display = "block"; }
    else showToast(msg, "error");
  };
  if (!cid) { showErr("Empresa inválida"); return; }
  if (!name) { showErr("Informe o nome da regra"); return; }
  if (!type) { showErr("Selecione o tipo"); return; }
  if (!channels.length) { showErr("Selecione ao menos um canal"); return; }
  try {
    const r = await fetch(`/api/alert-rules/${cid}`, {
      method: "POST",
      headers: {"Content-Type": "application/json", ..._authHeaders()},
      body: JSON.stringify({name, rule_type: type, channels, min_severity: (document.getElementById("ar-min-sev")?.value || "info")}),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok || data.error) { showErr(data.error || "Erro ao criar regra"); return; }
    closeAlertRuleModal();
    showToast("Regra de alerta criada", "ok");
    const co = allCompanies().find(c => c.id === cid);
    if (co) renderAlertsTab(co);
  } catch (e) {
    showErr(e.message || String(e));
  }
}

async function deleteAlertRule(cid, rid) {
  if (!confirm('Remover esta regra de alerta?')) return;
  await fetch(`/api/alert-rules/${cid}/${rid}`, {method:'DELETE', headers:_authHeaders()});
  reloadServerData().then(() => renderCompanyView(allCompanies().find(c=>c.id===cid)));
}

async function ackAlert(cid, aid) {
  await fetch(`/api/alerts/${cid}/${aid}/ack`, {method:'POST', headers:_authHeaders()});
  reloadServerData().then(() => renderCompanyView(allCompanies().find(c=>c.id===cid)));
}

// ════════════════════════════════════════════════════════════════════════
//  ASSET TIMELINE TAB
// ════════════════════════════════════════════════════════════════════════
async function renderTimelineTab(co) {
  const el = document.getElementById("tab-timeline");
  if (!el) return;
  el.innerHTML = `<div class="skel skel-card"></div><div class="skel skel-card"></div>`;

  try {
    const r = await fetch(`/api/timeline/${co.id}?limit=100`, {headers:_authHeaders()});
    if (!r.ok) { el.innerHTML = `<div class="diff-empty">Timeline unavailable</div>`; return; }
    const entries = await r.json();

    const timelineList = entries.timeline || entries || [];
    var tbadge = document.getElementById("tc-timeline");
    if (tbadge) tbadge.textContent = timelineList.length || "";
    let html = `<div class="section-hdr"><h3> Asset Timeline</h3><span class="section-count">${timelineList.length} snapshots</span></div>`;
    html += `<div class="timeline-list">`;
    for (const e of timelineList.slice(0, 80)) html += _timelineRow(e);
    if (!(entries.timeline || entries || []).length) html += `<div class="diff-empty">No timeline data — run a scan first</div>`;
    html += `</div>`;
    el.innerHTML = html;
  } catch(e) { el.innerHTML = `<div class="diff-empty">Error: ${esc(e.message)}</div>`; }
}

// ════════════════════════════════════════════════════════════════════════
//  SCAN DIFF TAB
// ════════════════════════════════════════════════════════════════════════
async function renderDiffTab(co) {
  const el = document.getElementById("tab-diff");
  if (!el) return;
  el.innerHTML = `<div class="skel skel-card"></div><div class="skel skel-card"></div>`;

  try {
    const r = await fetch(`/api/diff/${co.id}`, {headers:_authHeaders()});
    if (!r.ok) { el.innerHTML = `<div class="diff-empty">Diff unavailable</div>`; return; }
    const diff = await r.json();

    if (diff.error) {
      el.innerHTML = `<div class="diff-empty">${esc(diff.error)}${diff.current_hosts ? ` (${diff.current_hosts} hosts in current scan)` : ''}</div>`;
      return;
    }

    // Handle both SQLite format (new_hosts/removed_hosts) and PostgreSQL format (new/removed/changed)
    const news = (diff.new || []).map(h => typeof h === 'string' ? {host:h} : h);
    const removed = (diff.removed || []).map(h => typeof h === 'string' ? {host:h} : h);
    const changed = diff.changed || [];
    // SQLite port_changes → adapt to changed format
    if (diff.port_changes && !changed.length) {
      for (const pc of diff.port_changes) {
        changed.push({host: pc.host, changes: {ports: {from: pc.removed||[], to: pc.added||[]}}});
      }
    }

    var dbadge = document.getElementById("tc-diff");
    if (dbadge) { var dc = news.length + removed.length + changed.length; dbadge.textContent = dc || ""; }
    let html = `<div class="section-hdr"><h3>${icoHtml("search",14)} Scan Diff</h3><span class="section-count">${diff.curr_ts ? esc(diff.curr_ts.slice(0,16)) : 'vs previous'}</span></div>`;

    html += `<div class="stats-row">
      <div class="stat-card"><div class="stat-value" style="color:var(--green)">+${news.length}</div><div class="stat-label">New Hosts</div></div>
      <div class="stat-card"><div class="stat-value" style="color:var(--red)">-${removed.length}</div><div class="stat-label">Removed</div></div>
      <div class="stat-card"><div class="stat-value" style="color:var(--yellow)">~${changed.length}</div><div class="stat-label">Changed</div></div>
    </div>`;

    if (news.length) {
      html += `<div class="diff-section"><h4 style="color:var(--green);font-size:.82rem;margin-bottom:8px">＋ New (${news.length})</h4>`;
      for (const h of news.slice(0, 30)) html += `<div class="diff-item"><div class="diff-host">${esc(h.host||'?')}</div>${h.ip ? `<div class="diff-field"><span class="df-label">IP:</span><span class="df-new">${esc(h.ip)}</span></div>`:''}</div>`;
      html += `</div>`;
    }

    if (removed.length) {
      html += `<div class="diff-section"><h4 style="color:var(--red);font-size:.82rem;margin-bottom:8px">− Removed (${removed.length})</h4>`;
      for (const h of removed.slice(0, 30)) html += `<div class="diff-item"><div class="diff-host" style="color:var(--red)">${esc(h.host||'?')}</div></div>`;
      html += `</div>`;
    }

    if (changed.length) {
      html += `<div class="diff-section"><h4 style="color:var(--yellow);font-size:.82rem;margin-bottom:8px">~ Changed (${changed.length})</h4>`;
      for (const item of changed.slice(0, 30)) {
        html += `<div class="diff-item"><div class="diff-host">${esc(item.host)}</div>`;
        for (const [field, vals] of Object.entries(item.changes||{})) {
          html += `<div class="diff-field"><span class="df-label">${esc(field)}:</span><span class="df-old">${esc(JSON.stringify(vals.from))}</span><span class="df-arr">→</span><span class="df-new">${esc(JSON.stringify(vals.to))}</span></div>`;
        }
        html += `</div>`;
      }
      html += `</div>`;
    }

    if (!news.length && !removed.length && !changed.length) html += `<div class="diff-empty">No changes detected between scans</div>`;
    html += `<div id="diff-trends" style="margin-top:16px"></div>`;
    el.innerHTML = html;
    try {
      const hr = await fetch(`/api/stats-history/${co.id}?limit=20`, {headers:_authHeaders()});
      if (hr.ok) {
        const stats = await hr.json();
        const box = document.getElementById("diff-trends");
        if (box && stats.length) {
          box.innerHTML = `<div class="section-hdr"><h3>Evolução histórica</h3></div>` +
            stats.slice(-12).map(s => `<div class="history-row"><span>${esc((s.scanned_at||"").slice(0,16))}</span>
              <span>${s.subdomains||0} hosts</span><span>${s.live_hosts||0} live</span>
              <span style="color:var(--red)">${s.findings_critical||0} crit</span>
              <span style="color:var(--orange)">${s.findings_high||0} high</span></div>`).join("");
        }
      }
    } catch (e) {}
  } catch(e) { el.innerHTML = `<div class="diff-empty">Error: ${esc(e.message)}</div>`; }
}

// ════════════════════════════════════════════════════════════════════════
//  FALSE POSITIVE MANAGER
// ════════════════════════════════════════════════════════════════════════

function openFPModal(host, title, cid) {
  window._fpHost  = host;
  window._fpTitle = title;
  window._fpCid   = cid || window._fpCurrentCid || "";
  document.getElementById("fp-host").textContent  = host || "(any host)";
  document.getElementById("fp-title").textContent = title;
  document.getElementById("fp-reason").value = "";
  document.getElementById("fp-error").style.display = "none";
  document.getElementById("modal-fp").classList.add("show");
}

function closeFPModal() {
  document.getElementById("modal-fp").classList.remove("show");
}

async function submitFP() {
  const cid    = window._fpCid;
  const reason = document.getElementById("fp-reason").value.trim();
  const errEl  = document.getElementById("fp-error");
  if (!reason) { errEl.textContent = "Reason is required."; errEl.style.display = "block"; return; }
  if (!cid)    { errEl.textContent = "Company not identified."; errEl.style.display = "block"; return; }
  try {
    const r = await fetch(`/api/whitelist/${cid}`, {
      method: "POST",
      headers: {..._authHeaders(), "Content-Type": "application/json"},
      body: JSON.stringify({host: window._fpHost, title: window._fpTitle, reason}),
    });
    if (!r.ok) throw await _apiErr(r);
    closeFPModal();
    // Remove finding card from current view
    const co = allCompanies().find(c => c.id === cid);
    if (co) renderFindingsTab(co);
    showToast("Finding marked as false positive.");
  } catch(e) {
    errEl.textContent = "Error: " + e.message;
    errEl.style.display = "block";
  }
}

async function loadSuppressedFindings(cid) {
  const tab = document.getElementById("tab-suppressed");
  if (!tab) return;
  tab.innerHTML = `<div class="skel skel-card"></div><div class="skel skel-card"></div>`;
  try {
    const r = await fetch(`/api/whitelist/${cid}`, {headers: _authHeaders()});
    if (!r.ok) { tab.innerHTML = `<div class="diff-empty">Could not load suppressed findings</div>`; return; }
    const entries = await r.json();
    if (!entries.length) {
      tab.innerHTML = `<div class="empty-state"><div class="empty-state-icon" data-ico="inbox" aria-hidden="true"></div><div class="empty-state-title">No suppressed findings</div><div class="empty-state-copy">Findings you mark as false-positive will appear here and can be restored at any time.</div></div>`;
      return;
    }
    const listHtml = entries.map(e => `
      <div style="display:flex;align-items:center;gap:10px;padding:10px 14px;border-bottom:1px solid var(--border);font-size:.73rem">
        <div style="flex:1;min-width:0">
          <div style="color:var(--text);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.title)}</div>
          <div style="color:var(--text3);margin-top:2px">${esc(e.host)} · ${esc(e.reason||'—')} · by ${esc(e.suppressed_by||'?')}</div>
        </div>
        <button class="btn btn-secondary" style="font-size:.62rem;padding:2px 8px;color:var(--red);flex-shrink:0"
          onclick="restoreFinding('${esc(cid)}','${esc(e.id)}',this)">Restore</button>
      </div>`).join("");
    tab.innerHTML = `
      <div class="section-shell">
        <div class="section-head"><div class="section-head-main">
          <div class="section-kicker">Suppressed Findings</div>
          <div class="section-title">${entries.length} suppressed</div>
          <div class="section-sub">Findings marked as false-positive or out-of-scope. Click Restore to bring them back into the active queue.</div>
        </div></div>
        <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden" id="fp-suppressed-list">${listHtml}</div>
      </div>`;
  } catch(e) {
    tab.innerHTML = `<div class="diff-empty">Error: ${esc(e.message)}</div>`;
  }
}

async function restoreFinding(cid, wid, btn) {
  btn.disabled = true;
  try {
    const r = await fetch(`/api/whitelist/${cid}/${wid}`, {method:"DELETE", headers:_authHeaders()});
    if (!r.ok) throw await _apiErr(r);
    await loadSuppressedFindings(cid);
    showToast("Finding restored.");
  } catch(e) {
    btn.disabled = false;
    showToast("Error: " + e.message);
  }
}

// showToast is defined once near the top (stacked toasts).

// ════════════════════════════════════════════════════════════════════════
//  HISTORICAL TREND CHARTS
// ════════════════════════════════════════════════════════════════════════

async function loadTrendCharts(cid) {
  const el = document.getElementById("ov-trends");
  if (!el) return;
  el.innerHTML = `<span style="color:var(--text3);font-size:.75rem">Loading trend data…</span>`;
  try {
    const r = await fetch(`/api/stats-history/${cid}?limit=20`, {headers: _authHeaders()});
    if (!r.ok) { el.innerHTML = ""; return; }
    const stats = await r.json();
    if (!stats.length) { el.innerHTML = `<span style="color:var(--text3);font-size:.75rem">No historical data yet. Run more scans to see trends.</span>`; return; }

    const labels = stats.map(s => s.scanned_at ? s.scanned_at.substring(0,10) : "?");
    const mkSparkline = (values, color, label) => {
      const max = Math.max(...values, 1);
      const w = 120, h = 40;
      const pts = values.map((v,i) => {
        const x = (i / Math.max(values.length-1,1)) * (w-4) + 2;
        const y = h - 2 - ((v / max) * (h-6));
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      }).join(" ");
      const lastVal = values[values.length-1];
      const firstVal = values[0];
      const trend = lastVal > firstVal ? "▲" : lastVal < firstVal ? "▼" : "—";
      const trendColor = label.includes("finding") ? (lastVal > firstVal ? "var(--red)" : "var(--teal)") : (lastVal > firstVal ? "var(--teal)" : "var(--text3)");
      return `<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:10px 14px;min-width:140px">
        <div style="font-size:.62rem;color:var(--text3);text-transform:uppercase;margin-bottom:4px">${label}</div>
        <div style="font-size:1.2rem;font-weight:700;color:var(--text1)">${lastVal} <span style="font-size:.7rem;color:${trendColor}">${trend}</span></div>
        <svg width="${w}" height="${h}" style="display:block;margin-top:4px" viewBox="0 0 ${w} ${h}">
          <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
          <circle cx="${((values.length-1)/Math.max(values.length-1,1))*(w-4)+2}" cy="${h-2-((values[values.length-1]/max)*(h-6))}" r="3" fill="${color}"/>
        </svg>
      </div>`;
    };

    el.innerHTML = `
      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-start;margin-top:8px">
        ${mkSparkline(stats.map(s=>s.subdomains||0),  "var(--teal)",   "Hosts")}
        ${mkSparkline(stats.map(s=>s.live_hosts||0),  "var(--blue)",   "Live Hosts")}
        ${mkSparkline(stats.map(s=>s.findings_critical||0), "var(--red)",  "Critical Findings")}
        ${mkSparkline(stats.map(s=>s.findings_high||0),     "var(--orange)","High Findings")}
        ${mkSparkline(stats.map(s=>s.open_ports||0),  "#a78bfa",       "Open Ports")}
      </div>`;
  } catch(e) {
    el.innerHTML = `<span style="color:var(--text3);font-size:.75rem">Trend data unavailable.</span>`;
  }
}

// ════════════════════════════════════════════════════════════════════════
//  BULK COMPANY IMPORT
// ════════════════════════════════════════════════════════════════════════
//  INIT
// ════════════════════════════════════════════════════════════════════════
async function initApp() {
  if (SERVER_MODE) {
    document.getElementById("footer-gen").textContent = "Server mode";
    await reloadServerData();
    await loadPlaywrightDefaults();
    _startJobCountPoll();
  } else {
    document.getElementById("footer-gen").textContent =
      typeof window.ASM_DATA !== "undefined" ? "Live data" : "Demo data";
  }
  const gen = DATA.generated
    ? new Date(DATA.generated).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"})
    : "—";
  document.getElementById("footer-date").textContent = gen;
  renderSidebar();
  showPage("companies");
  syncCompanyTabsAccessibility();
  // Apply persisted language translations after dynamic render
  if (typeof applyTranslations === 'function') {
    const savedLang = localStorage.getItem('lang') || (window.appConfig && window.appConfig.defaultLanguage) || 'en';
    applyTranslations(savedLang);
  }
  // Mark as initialized for hash routing
  if (typeof ASM !== 'undefined') ASM.initialized = true;
}

document.addEventListener("DOMContentLoaded", async () => {
  initGroupCountObserver();
  const ok = await checkAuth();
  if (ok) await initApp();
  // Close modals on overlay click
  document.getElementById("modal-add").addEventListener("click",    function(e){ if(e.target===this) closeAddCompany(); });
  document.getElementById("modal-scan").addEventListener("click",   function(e){ if(e.target===this) closeScanModal(); });
  document.getElementById("modal-admin").addEventListener("click",  function(e){ if(e.target===this) closeAdminModal(); });
  const alertModal = document.getElementById("modal-alert-rule");
  if (alertModal) alertModal.addEventListener("click", function(e){ if(e.target===this) closeAlertRuleModal(); });
});


window.addEventListener("resize", () => {
  if (window.innerWidth > 860) closeMobileNav();
  try { initThreatMaps(); } catch(e) {}
});

// ════════════════════════════════════════════════════════════════════════
//  HOST DETAIL DRAWER
// ════════════════════════════════════════════════════════════════════════

function openHostDrawer(hostname) {
  const overlay = document.getElementById('host-drawer-overlay');
  const drawer = document.getElementById('host-drawer');
  const titleEl = document.getElementById('hd-title');
  const statusEl = document.getElementById('hd-status');
  const bodyEl = document.getElementById('hd-body');
  if (!drawer) return;

  // Look up host from current company
  const co = allCompanies().find(c => c.id === state.currentId);
  const hosts = co ? (co.hosts || []) : (_sub_hosts || _co_ports || []);
  const h = hosts.find(x => x.host === hostname) || {};
  const sc = h.status_code;
  const statusCls = sc ? (sc < 300 ? 's2' : sc < 400 ? 's3' : sc < 500 ? 's4' : 's5') : 'na';
  const statusText = sc ? `${sc}` : 'n/a';
  const statusColor = sc ? (sc < 300 ? '#22c55e' : sc < 400 ? '#fbbf24' : sc < 500 ? '#fb923c' : '#f43f5e') : 'var(--text3)';

  titleEl.textContent = h.host || 'Unknown';
  statusEl.textContent = statusText;
  statusEl.style.background = `rgba(${sc<300?'34,197,94':sc<400?'251,191,36':sc<500?'251,146,60':'244,63,94'},0.1)`;
  statusEl.style.color = statusColor;
  statusEl.style.border = `1px solid ${statusColor}33`;

  const portDetails = h.port_details || [];
  const portMap = Object.fromEntries(portDetails.map(pd => [pd.port, pd]));
  const portsHtml = (h.ports || []).length
    ? `<div class="hd-section"><div class="hd-section-title">Open Ports</div><div class="hd-badge-row">${h.ports.map(p => {
        if (portMap[p]) return `<span class="port-c" style="font-size:.65rem" title="${esc(portMap[p].category||'')}">${p}:${esc(portMap[p].service||'')}</span>`;
        return `<span class="port-c" style="font-size:.65rem">${p}</span>`;
      }).join('')}</div></div>`
    : '<div class="hd-section"><div class="hd-section-title">Open Ports</div><div style="color:var(--text3);font-size:.68rem">None detected</div></div>';

  const techHtml = (h.technologies || []).length
    ? `<div class="hd-section"><div class="hd-section-title">Technology Stack</div><div class="hd-badge-row">${h.technologies.map(t => `<span class="sd-tech-badge">${esc(t)}</span>`).join('')}</div></div>`
    : '';

  const cnames = h.cnames || [];
  const cnameHtml = cnames.length
    ? `<div class="hd-section"><div class="hd-section-title">CNAME Chain</div>${cnames.map(c => `<div class="hd-row"><span class="hd-k">→</span><span class="hd-v hi">${esc(typeof c === 'string' ? c : c.cname || c)}</span></div>`).join('')}</div>`
    : '';

  const certHtml = h.cert_info
    ? `<div class="hd-section"><div class="hd-section-title">SSL Certificate</div>
      <div class="hd-row"><span class="hd-k">Issuer</span><span class="hd-v">${esc(h.cert_info.issuer || '—')}</span></div>
      <div class="hd-row"><span class="hd-k">Expires</span><span class="hd-v ${h.cert_info.expiring_soon?'warn':''}">${esc(h.cert_info.not_after || '—')}${h.cert_info.expiring_soon?' ${icoHtml("warning",14)}':''}</span></div>
    </div>`
    : '';

  const shotSrc = _shotSrc(h.screenshot);
  const shotHtml = shotSrc
    ? `<div class="hd-section"><div class="hd-section-title">Screenshot</div>
      <a href="${esc(shotSrc)}" target="_blank" rel="noopener" aria-label="${esc("Abrir screenshot de " + (h.host || ""))}">
        <img src="${esc(shotSrc)}" style="width:100%;max-width:400px;border-radius:8px;border:1px solid var(--border);cursor:pointer" onerror="this.style.display='none'" alt="${esc("Screenshot de " + (h.host || ""))}">
      </a></div>`
    : '';

  bodyEl.innerHTML = `
    <div class="hd-section">
      <div class="hd-section-title">Identity</div>
      <div class="hd-row"><span class="hd-k">Host</span><span class="hd-v hi">${h.host ? originHostChip(h.host, "origin-link") : "—"}</span></div>
      <div class="hd-row"><span class="hd-k">IP</span><span class="hd-v">${esc(h.ip||'—')}</span></div>
      <div class="hd-row"><span class="hd-k">Title</span><span class="hd-v">${esc(h.title||'No title')}</span></div>
      <div class="hd-row"><span class="hd-k">WAF/CDN</span><span class="hd-v">${esc(h.waf||'Direct')}</span></div>
      ${h.cloud_provider ? `<div class="hd-row"><span class="hd-k">Cloud</span><span class="hd-v hi">${icoHtml("cloud",14)} ${esc(h.cloud_provider)}</span></div>` : ''}
      ${h.asn ? `<div class="hd-row"><span class="hd-k">ASN</span><span class="hd-v">${esc(h.asn)}</span></div>` : ''}
    </div>
    ${shotHtml}
    ${portsHtml}
    ${cnameHtml}
    ${certHtml}
    ${techHtml}
  `;

  drawer.classList.add('open');
  overlay.classList.add('show');
  document.body.style.overflow = 'hidden';
}

function closeHostDrawer() {
  const overlay = document.getElementById('host-drawer-overlay');
  const drawer = document.getElementById('host-drawer');
  if (drawer) drawer.classList.remove('open');
  if (overlay) overlay.classList.remove('show');
  document.body.style.overflow = '';
}

// Legacy stub — settings now lives at showPage('settings')
function openSettings(){ showPage("settings"); }

Object.assign(window, {
  loadJobs,
  openJobsQueue,
  openJobDetail,
  openJobCompanyPipeline,
  cancelJob,
  toggleJobDrilldown,
  exitJobDrilldown,
  openDomainResults,
  _onJobDrillSearch,
});
