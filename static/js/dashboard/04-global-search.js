// ════════════════════════════════════════════════════════════════════════
//  GLOBAL SEARCH (Ctrl+K)
// ════════════════════════════════════════════════════════════════════════
let _gsearchActiveIdx = -1;
let _gsearchResults = [];

document.addEventListener('keydown', function(e) {
  try {
    const k = (e.key || '').toLowerCase();
    if ((e.ctrlKey || e.metaKey) && k === 'k') {
      e.preventDefault();
      openGlobalSearch();
      return;
    }
    if (k === 'escape') {
      const overlay = document.getElementById('modal-global-search');
      if (overlay && overlay.classList.contains('show')) closeGlobalSearch();
    }
  } catch(ex) {}
});

function openGlobalSearch() {
  const overlay = document.getElementById('modal-global-search');
  if (!overlay) return;
  overlay.classList.add('show');
  _gsearchActiveIdx = -1;
  const input = document.getElementById('gsearch-input');
  input.value = '';
  document.getElementById('gsearch-results').innerHTML = '';
  setTimeout(() => input.focus(), 30);
}

function closeGlobalSearch() {
  const overlay = document.getElementById('modal-global-search');
  if (overlay) overlay.classList.remove('show');
}

function onGlobalSearchInput() {
  const q = (document.getElementById('gsearch-input').value || '').trim();
  _gsearchActiveIdx = -1;
  if (q.length < 2) {
    document.getElementById('gsearch-results').innerHTML = q
      ? `<div class="gsearch-empty">Digite ao menos 2 caracteres...</div>`
      : '';
    _gsearchResults = [];
    return;
  }
  _gsearchResults = performGlobalSearch(q);
  renderGlobalSearchResults(_gsearchResults);
}

function performGlobalSearch(query) {
  const q = query.toLowerCase();
  const results = [];
  const MAX_PER_GROUP = 8;

  for (const co of allCompanies()) {
    if ((co.name || '').toLowerCase().includes(q) || (co.id || '').toLowerCase().includes(q)) {
      results.push({
        group: 'Empresas', ico: 'buildings', title: co.name || co.id,
        sub: co.id, action: { type: 'company', cid: co.id },
      });
    }

    for (const dom of (co.domains || [])) {
      if (results.filter(r => r.group === 'Domínios').length >= MAX_PER_GROUP) break;
      if ((dom || '').toLowerCase().includes(q)) {
        results.push({
          group: 'Domínios', ico: 'globe', title: dom, sub: co.name || co.id,
          action: { type: 'company', cid: co.id, group: 'hosts' },
        });
      }
    }

    for (const h of (co.hosts || [])) {
      if (results.filter(r => r.group === 'Hosts').length >= MAX_PER_GROUP) break;
      const hay = `${h.host || ''} ${h.ip || ''} ${h.title || ''}`.toLowerCase();
      if (hay.includes(q)) {
        results.push({
          group: 'Hosts', ico: 'monitor', title: h.host || h.ip || '',
          sub: `${co.name || co.id}${h.ip ? ' · ' + h.ip : ''}${h.status_code ? ' · HTTP ' + h.status_code : ''}`,
          action: { type: 'company', cid: co.id, group: 'hosts' },
        });
      }
    }

    for (const d of (co.email_details || []).length ? co.email_details : (co.emails || []).map(e => ({email: e}))) {
      if (results.filter(r => r.group === 'Pessoas').length >= MAX_PER_GROUP) break;
      const name = [d.first_name, d.last_name].filter(Boolean).join(' ');
      const hay = `${d.email || ''} ${name} ${d.position || ''}`.toLowerCase();
      if (hay.includes(q)) {
        results.push({
          group: 'Pessoas', ico: 'person', title: d.email || '', sub: `${name || co.name || co.id}${d.position ? ' · ' + d.position : ''}`,
          action: { type: 'company', cid: co.id, group: 'hosts', panel: 'infra' },
        });
      }
    }

    for (const f of (co.findings || [])) {
      if (results.filter(r => r.group === 'Findings').length >= MAX_PER_GROUP) break;
      const hay = `${f.title || ''} ${f.host || ''} ${f.desc || ''} ${f.category || f.type || ''}`.toLowerCase();
      if (hay.includes(q)) {
        results.push({
          group: 'Findings', ico: 'warning', title: f.title || '', tag: f.severity || '',
          sub: `${co.name || co.id}${f.host ? ' · ' + f.host : ''}`,
          action: { type: 'company', cid: co.id, group: 'vulns', q: f.title || '', sev: f.severity || '' },
        });
      }
    }
  }

  return results.slice(0, 60);
}

function renderGlobalSearchResults(results) {
  const el = document.getElementById('gsearch-results');
  if (!results.length) {
    el.innerHTML = `<div class="gsearch-empty">Nenhum resultado encontrado</div>`;
    return;
  }
  let html = '';
  let lastGroup = null;
  results.forEach((r, i) => {
    if (r.group !== lastGroup) {
      html += `<div class="gsearch-group-label">${esc(r.group)}</div>`;
      lastGroup = r.group;
    }
    html += `<div class="gsearch-item" data-idx="${i}" onclick="selectGlobalSearchResult(${i})">
      <div class="gsearch-item-icon">${typeof r.ico==="string"?icoHtml(r.ico,16):esc(r.icon||"")}</div>
      <div class="gsearch-item-main">
        <div class="gsearch-item-title">${esc(r.title)}</div>
        <div class="gsearch-item-sub">${esc(r.sub || '')}</div>
      </div>
      ${r.tag ? `<div class="gsearch-item-tag">${esc(r.tag)}</div>` : ''}
    </div>`;
  });
  el.innerHTML = html;
}

function onGlobalSearchKeydown(e) {
  const k = e.key;
  if (k === 'ArrowDown' || k === 'ArrowUp') {
    e.preventDefault();
    if (!_gsearchResults.length) return;
    if (k === 'ArrowDown') _gsearchActiveIdx = Math.min(_gsearchActiveIdx + 1, _gsearchResults.length - 1);
    else _gsearchActiveIdx = Math.max(_gsearchActiveIdx - 1, 0);
    document.querySelectorAll('#gsearch-results .gsearch-item').forEach((it, i) => {
      it.classList.toggle('active', i === _gsearchActiveIdx);
      if (i === _gsearchActiveIdx) it.scrollIntoView({ block: 'nearest' });
    });
  } else if (k === 'Enter') {
    e.preventDefault();
    const idx = _gsearchActiveIdx >= 0 ? _gsearchActiveIdx : 0;
    if (_gsearchResults[idx]) selectGlobalSearchResult(idx);
  }
}

async function selectGlobalSearchResult(idx) {
  const r = _gsearchResults[idx];
  if (!r) return;
  closeGlobalSearch();
  const action = r.action;
  if (action.type === 'company') {
    await selectCompany(action.cid);
    if (action.group === 'vulns') {
      _pendingVulnFilter = { cid: action.cid, sev: action.sev || '', q: action.q || '' };
      setTimeout(() => _applyPendingVulnFilter(action.cid), 80);
    }
    if (action.group) {
      const btn = document.querySelector(`.tab-btn[data-group="${action.group}"]`);
      if (btn) switchGroup(action.group, btn, action.panel);
    }
  }
}

function _renderRiskGauge(crit, high, med, info, total) {
  const r = 44, stroke = 5, circ = 2 * Math.PI * r;
  const score = total > 0 ? Math.round((crit * 4 + high * 3 + med * 2 + info) / (total * 4) * 100) : 0;
  const color = score >= 70 ? '#fb7185' : score >= 40 ? '#fb923c' : score >= 15 ? '#fbbf24' : '#4ade80';
  const dash = (score / 100) * circ;
  return `<svg width="120" height="120" viewBox="0 0 120 120" class="risk-gauge">
    <circle cx="60" cy="60" r="${r}" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="${stroke}"/>
    <circle cx="60" cy="60" r="${r}" fill="none" stroke="${color}" stroke-width="${stroke+2}"
      stroke-dasharray="${dash} ${circ - dash}" stroke-linecap="round"
      transform="rotate(-90 60 60)" style="filter:drop-shadow(0 0 8px ${color}44)"/>
    <text x="60" y="55" text-anchor="middle" fill="${color}" font-size="22" font-weight="800">${score}</text>
    <text x="60" y="73" text-anchor="middle" fill="var(--text3)" font-size="9" font-weight="600" letter-spacing="0.08em">RISK SCORE</text>
  </svg>`;
}

function renderOverview(co) {
  setTimeout(() => { if (typeof renderPriorities === "function") renderPriorities(co.id); }, 0);
  const s = co.stats || {};
  const hosts = co.hosts || [];

  const crit = s.findings_critical || 0;
  const high = s.findings_high || 0;
  const med  = s.findings_medium || 0;
  const info = s.findings_info || 0;
  const totalFindings = crit + high + med + info;
  const risk = riskLevel(co);
  const directHosts = hosts.length - (s.waf_protected || 0);

  const exposed = Math.max(0, (s.subdomains || hosts.length || 0) - (s.waf_protected || 0));
  document.getElementById("tab-overview").innerHTML = `
    <div id="ov-priorities" class="ov-priorities"></div>
    <div class="ov-kpis" aria-label="Resumo">
      <div class="ov-kpi"><b>${s.subdomains || hosts.length || 0}</b><span>ativos</span></div>
      <div class="ov-kpi"><b>${s.live_hosts || 0}</b><span>no ar</span></div>
      <div class="ov-kpi"><b>${s.open_ports || 0}</b><span>portas abertas</span></div>
      <div class="ov-kpi"><b>${exposed}</b><span>sem WAF</span></div>
      <button type="button" class="ov-kpi ov-kpi-sev" onclick="switchTab('vulns')" title="Ver achados"><b class="c-crit">${crit}</b><span>críticos</span></button>
      <button type="button" class="ov-kpi ov-kpi-sev" onclick="switchTab('vulns')" title="Ver achados"><b class="c-high">${high}</b><span>altos</span></button>
    </div>
    <div id="ov-trends" style="margin-top:16px"></div>
    ${typeof renderExposureTeaser === "function" ? renderExposureTeaser(co) : ""}`;
}

async function loadScanHistory(cid) {
  const el = document.getElementById("ov-history");
  if(!el) return;
  el.innerHTML = `<span style="color:var(--text3)">Loading…</span>`;
  try {
    const r = await fetch(`/api/scan-history/${cid}`, {headers:_authHeaders()});
    const history = await r.json();
    if(!history.length){ el.innerHTML = `<span style="color:var(--text3)">No past scans found.</span>`; return; }
    el.innerHTML = `<div class="history-list">` +
      history.map(s => {
        const dt = new Date(s.mtime*1000).toLocaleString();
        const dnsColor = s.dns_names > 0 ? "var(--teal)" : "var(--text3)";
        const fColor   = s.findings  > 0 ? "var(--orange)" : "var(--text3)";
        const safeId   = `sh-${cid}-${esc(s.name)}`.replace(/[^a-zA-Z0-9_-]/g,"_");
        return `<div id="${safeId}" class="history-row">
          <span class="history-name">${esc(s.name)}</span>
          <span class="history-stat">${esc(dt)}</span>
          <span class="history-stat" style="color:${dnsColor}"><strong>${s.dns_names}</strong> hosts</span>
          <span class="history-stat" style="color:${fColor}"><strong>${s.findings}</strong> findings</span>
          <span class="history-stat"><strong>${s.events}</strong> events · ${s.size_kb}KB</span>
          <div class="history-cta">
          ${s.has_asm_log ? `<button class="btn btn-secondary" style="font-size:.65rem;padding:2px 8px;color:var(--teal)" onclick="openScanLog('${cid}','${esc(s.name)}')">${icoHtml("clipboard",14)} Ver Log</button>` : ''}
          <button class="btn btn-secondary" style="font-size:.65rem;padding:2px 8px"
                  onclick="reparseHistory('${cid}','${esc(s.name)}',this)">Re-parse</button>
          <button class="btn btn-secondary" style="font-size:.65rem;padding:2px 8px;color:var(--red)"
                  onclick="deleteScanHistory('${cid}','${esc(s.name)}','${safeId}',this)">Delete</button>
          </div>
        </div>`;
      }).join("") + `</div>`;
  } catch(e) {
    el.innerHTML = `<span style="color:var(--red)">Error: ${e.message}</span>`;
  }
}

async function reparseHistory(cid, scanName, btn) {
  btn.disabled = true;
  btn.textContent = "Parsing…";
  try {
    const r = await fetch(`/api/scan-history/${cid}/${encodeURIComponent(scanName)}/reparse`, {method:"POST", headers:_authHeaders()});
    if(!r.ok) throw await _apiErr(r);
    await reloadServerData();
    const co = allCompanies().find(c=>c.id===cid);
    if(co){ renderOverview(co); renderFindingsTab(co); renderCveTab(co); renderSubdomainsTab(co); renderTyposquatTab(co); }
  btn.textContent = " Done";
    setTimeout(()=>{ btn.textContent="Re-parse"; btn.disabled=false; }, 2000);
  } catch(e) {
  btn.textContent = " Error";
    btn.title = e.message;
    setTimeout(()=>{ btn.textContent="Re-parse"; btn.disabled=false; }, 3000);
  }
}

async function clearReconData(cid) {
  if (!confirm(`Clear ALL data for "${cid}"?\nThe project will be reset like a fresh project: hosts, findings, URLs, JS, secrets, jobs, logs, checkpoints, screenshots, snapshots and scan history will be removed.\nThe project name/domains/tags are preserved.\nThis action cannot be undone.`)) return;
  const btn = document.getElementById("clear-data-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Clearing…"; }
  try {
    const r = await fetch(`/api/recon/${encodeURIComponent(cid)}/data`, {
      method: "DELETE", headers: _authHeaders(),
    });
    if (!r.ok) throw await _apiErr(r);
    // Also clear tool logs explicitly
    try { await fetch(`/api/recon/${cid}/tool-logs`, { method: "DELETE", headers: _authHeaders() }); } catch(e) {}
    // Force-reload the entire app state from server
    location.reload();
  } catch(e) {
    showToast("Error clearing data: " + e.message);
  if (btn) { btn.disabled = false; btn.textContent = " Clear Data"; }
  }
}

async function deleteScanHistory(cid, scanName, rowId, btn) {
  if (!confirm(`Delete scan "${scanName}"? This action cannot be undone.`)) return;
  btn.disabled = true;
  btn.textContent = "Deleting…";
  try {
    const r = await fetch(`/api/scan-history/${encodeURIComponent(cid)}/${encodeURIComponent(scanName)}`, {
      method: "DELETE", headers: _authHeaders(),
    });
    if (!r.ok) throw await _apiErr(r);
    const row = document.getElementById(rowId);
    if (row) row.remove();
    await reloadServerData();
    const co = allCompanies().find(c => c.id === cid);
    if (co) { renderOverview(co); renderFindingsTab(co); renderCveTab(co); renderSubdomainsTab(co); }
  } catch(e) {
    btn.disabled = false;
    btn.textContent = "Delete";
    showToast("Error: " + e.message);
  }
}

async function deleteAllScanHistory(cid) {
  if (!confirm(`Delete ALL scans for "${cid}"? This action cannot be undone.`)) return;
  const el = document.getElementById("ov-history");
  if (el) el.innerHTML = `<span style="color:var(--text3)">Deleting…</span>`;
  try {
    const r = await fetch(`/api/scan-history/${encodeURIComponent(cid)}`, {
      method: "DELETE", headers: _authHeaders(),
    });
    if (!r.ok) throw await _apiErr(r);
    const d = await r.json();
    if (el) el.innerHTML = `<span style="color:var(--text3)">${d.count} scan(s) deleted. Findings cleared.</span>`;
    await reloadServerData();
    const co = allCompanies().find(c => c.id === cid);
    if (co) { renderOverview(co); renderFindingsTab(co); renderCveTab(co); renderSubdomainsTab(co); }
  } catch(e) {
    if (el) el.innerHTML = `<span style="color:var(--red)">Error: ${e.message}</span>`;
  }
}
