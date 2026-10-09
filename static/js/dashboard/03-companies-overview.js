// ════════════════════════════════════════════════════════════════════════
//  SIDEBAR
// ════════════════════════════════════════════════════════════════════════
function renderSidebar() {
  const el = document.getElementById("company-nav-items");
  const companyViewActive = state.page === "company";
  el.innerHTML = allCompanies().map(co => {
    const rl = riskLevel(co);
    const s = co.stats||{};
    const domain = (co.domains||[])[0]||"";
    const sideEditBtn = SERVER_MODE
      ? `<span class="nc-edit" onclick="event.stopPropagation();openEditCompanyModal('${co.id}')" title="Edit">${icoHtml("pencil",14)}</span>`
      : "";
    return `<button class="nav-item nav-company nav-co${companyViewActive && state.currentId === co.id ? " active" : ""}" data-id="${co.id}" onclick="selectCompany('${co.id}')">
      <div class="nc-top">
        <span class="nav-icon" data-ico="hexagon" aria-hidden="true"></span>
        <span class="nc-name">${esc(co.name)}</span>
        <span class="nc-risk ${rl}">${(s.findings_critical||0)>0 ? "C:"+s.findings_critical : (s.findings_high||0)>0 ? "H:"+s.findings_high : rl.charAt(0).toUpperCase()+rl.slice(1)}</span>
        ${sideEditBtn}
      </div>
      <span class="nc-domain">${esc(domain)}</span>
    </button>`;
  }).join("");
  _syncSidebarActive();
}

// ════════════════════════════════════════════════════════════════════════
//  ALL COMPANIES VIEW
// ════════════════════════════════════════════════════════════════════════
function renderAllCompanies() {
  _ensureCompanyQueueSummary();
  const companies = allCompanies();
  const grid = document.getElementById("companies-grid");
  const empty = document.getElementById("all-empty");
  const overview = document.getElementById("portfolio-overview");

  const totalC = companies.reduce((a,c)=>a+(c.stats?.findings_critical||0),0);
  const totalH = companies.reduce((a,c)=>a+(c.stats?.findings_high||0),0);
  const totalM = companies.reduce((a,c)=>a+(c.stats?.findings_medium||0),0);
  const totalI = companies.reduce((a,c)=>a+(c.stats?.findings_info||0),0);
  const totalHosts = companies.reduce((a,c)=>a+(c.stats?.subdomains||0),0);
  const totalLive = companies.reduce((a,c)=>a+(c.stats?.live_hosts||0),0);
  const totalEndpoints = companies.reduce((a, c) => {
    const wayback = c.wayback_data?.interesting_count || 0;
    const urlfinder = Array.isArray(c.urlfinder_data?.urls) ? c.urlfinder_data.urls.length : 0;
    const js = c.js_data?.total_endpoints || 0;
    const api = c.api_exposure?.total || 0;
    return a + wayback + urlfinder + js + api;
  }, 0);
  const totalVulns = totalC + totalH + totalM + totalI;
  const topRisk = [...companies].sort((a,b)=> {
    const sa = a.stats || {};
    const sb = b.stats || {};
    const ra = (sa.findings_critical||0) * 100 + (sa.findings_high||0) * 20 + (sa.findings_medium||0) * 5 + (sa.findings_info||0);
    const rb = (sb.findings_critical||0) * 100 + (sb.findings_high||0) * 20 + (sb.findings_medium||0) * 5 + (sb.findings_info||0);
    return rb - ra;
  }).slice(0, 3);
  const topCompany = topRisk[0];
  const topTargetCount = topCompany
    ? ((topCompany.stats?.findings_critical||0) + (topCompany.stats?.findings_high||0) + (topCompany.stats?.findings_medium||0) + (topCompany.stats?.findings_info||0))
    : 0;
  const severityBreakdown = [
    { key: "critical", label: "Critical", count: totalC, color: "var(--red)" },
    { key: "high", label: "High", count: totalH, color: "var(--orange)" },
    { key: "medium", label: "Medium", count: totalM, color: "var(--yellow)" },
    { key: "info", label: "Info", count: totalI, color: "var(--blue)" },
  ];
  const severityTotal = severityBreakdown.reduce((a, s) => a + s.count, 0);
  let severityParts = [];
  let start = 0;
  for (const s of severityBreakdown) {
    const span = severityTotal > 0 ? (s.count / severityTotal) * 100 : 0;
    const end = start + span;
    severityParts.push(`${s.color} ${start.toFixed(2)}% ${end.toFixed(2)}%`);
    start = end;
  }
  if (!severityParts.length) severityParts = ["var(--border2) 0% 100%"];
  const findingFreq = new Map();
  const findingMeta = new Map();
  for (const co of companies) {
    for (const f of (co.findings || [])) {
      const title = (f.title || f.name || "").trim();
      if (!title) continue;
      findingFreq.set(title, (findingFreq.get(title) || 0) + 1);
      if (!findingMeta.has(title)) findingMeta.set(title, f);
    }
  }
  const commonFindings = [...findingFreq.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([title, count]) => ({ title, count, item: findingMeta.get(title) }));
  document.getElementById("all-desc").textContent =
    `${companies.length} ${t("lbl_companies")} · ${totalVulns.toLocaleString()} ${t("lbl_vulns")} · ${totalHosts.toLocaleString()} ${t("lbl_hosts")} · ${totalEndpoints.toLocaleString()} ${t("lbl_endpoints")}`;

  if (overview) {
    overview.innerHTML = `
      <div class="portfolio-hero">
        <div class="portfolio-hero-top">
          <div>
            <div class="rh-kicker">${t("portfolio_kicker")}</div>
            <div class="rh-title">${t("portfolio_title")}</div>
            <div class="rh-sub">${t("portfolio_sub")}</div>
          </div>
          <div class="portfolio-hero-actions">
            <button class="btn btn-secondary" onclick="showPage('jobs'); loadJobs();">${t("btn_open_queue")}</button>
            <button class="btn btn-primary" onclick="openAddCompany()">${t("add_company_button")}</button>
          </div>
        </div>
        <div class="portfolio-kpis">
          ${_cardKPI({ cls: "c", value: companies.length, label: "Targets", note: "Companies tracked" })}
          ${_cardKPI({ cls: "h", value: totalHosts, label: "Hosts", note: `${totalLive.toLocaleString()} live / HTTP reachable` })}
          ${_cardKPI({ cls: "m", value: totalEndpoints, label: "Endpoints", note: "URLs + JS + API signals" })}
          ${_cardKPI({ cls: "i", value: totalVulns, label: "Vulnerabilities", note: `${totalC.toLocaleString()} critical · ${totalH.toLocaleString()} high` })}
        </div>
        <div class="portfolio-dashboard">
          <section class="portfolio-panel portfolio-severity-panel">
            <div class="portfolio-panel-head">
              <div>
                <div class="portfolio-panel-kicker">Severity breakdown</div>
                <div class="portfolio-panel-title">Vulnerability distribution</div>
                <div class="portfolio-panel-sub">Portfolio-wide counts by severity.</div>
              </div>
            </div>
            <div class="severity-wrap">
              <div class="severity-donut" style="--severity-gradient:${escAttr(`conic-gradient(${severityParts.join(", ")})`)}">
                <div class="severity-donut-center">
                  <div class="severity-donut-total">${totalVulns.toLocaleString()}</div>
                  <div class="severity-donut-label">Total</div>
                </div>
              </div>
              <div class="severity-legend">
                ${severityBreakdown.map(s => `
                  <div class="severity-legend-row" ${topCompany && s.count > 0 ? `onclick="goToVulnSeverity(${_jsArg(topCompany.id)},'${s.key}',event)" style="cursor:pointer" title="Ver vulnerabilidades ${esc(s.label)} no alvo de maior risco"` : ""}>
                    <div class="severity-legend-key">
                      <span class="severity-swatch" style="background:${s.color}"></span>
                      ${esc(s.label)}
                    </div>
                    <div class="severity-legend-count">${s.count.toLocaleString()}</div>
                  </div>
                `).join("")}
              </div>
            </div>
          </section>
          <section class="portfolio-panel portfolio-target-panel">
            <div class="portfolio-panel-head">
              <div>
                <div class="portfolio-panel-kicker">Most vulnerable target</div>
                <div class="portfolio-panel-title">Highest concentration of findings</div>
                <div class="portfolio-panel-sub">Use this as the first pivot for deeper triage.</div>
              </div>
            </div>
            ${topCompany ? `
              <div class="portfolio-table">
                <div class="portfolio-table-row portfolio-table-head">
                  <span>Target</span>
                  <span>Risk</span>
                  <span>Findings</span>
                </div>
                <div class="portfolio-table-row">
                  <div class="portfolio-target-cell">
                    <a class="portfolio-row-host" href="#" onclick="selectCompany(${_jsArg(topCompany.id)});return false;">${esc(topCompany.name)}</a>
                    <div class="portfolio-row-meta">${(topCompany.domains||[]).slice(0,2).map(esc).join(" · ") || "No domains"} · last scan ${esc(topCompany.last_scan || "—")}</div>
                  </div>
                  <span class="portfolio-badge ${riskLevel(topCompany)}">${riskLabel(riskLevel(topCompany))}</span>
                  <span class="portfolio-count">${topTargetCount.toLocaleString()}</span>
                </div>
                ${topRisk.slice(1).map(co => {
                  const s = co.stats || {};
                  const count = (s.findings_critical||0)+(s.findings_high||0)+(s.findings_medium||0)+(s.findings_info||0);
                  const rl = riskLevel(co);
                  return `
                    <div class="portfolio-table-row">
                      <div class="portfolio-target-cell">
                        <a class="portfolio-row-host" href="#" onclick="selectCompany(${_jsArg(co.id)});return false;">${esc(co.name)}</a>
                        <div class="portfolio-row-meta">${(co.domains||[]).slice(0,2).map(esc).join(" · ") || "No domains"} · ${s.subdomains||0} hosts</div>
                      </div>
                      <span class="portfolio-badge ${rl}">${riskLabel(rl)}</span>
                      <span class="portfolio-count">${count.toLocaleString()}</span>
                    </div>`;
                }).join("")}
              </div>
            ` : `
              <div class="empty-state">
                <div class="empty-state-title">No targets yet</div>
                <div class="empty-state-copy">Add a company and run a scan to populate this view.</div>
              </div>`}
          </section>
          <section class="portfolio-panel portfolio-vuln-panel">
            <div class="portfolio-panel-head">
              <div>
                <div class="portfolio-panel-kicker">Most common vulnerabilities</div>
                <div class="portfolio-panel-title">Repeated findings across the portfolio</div>
                <div class="portfolio-panel-sub">These titles appear most often in the current dataset.</div>
              </div>
            </div>
            ${commonFindings.length ? `
              <div class="portfolio-vuln-list">
                ${commonFindings.map(item => {
                  const sev = item.item?.severity || "info";
                  return `
                    <div class="portfolio-vuln-item">
                      <div>
                        <div class="portfolio-vuln-title">${esc(item.title)}</div>
                        <div class="portfolio-vuln-meta">${esc(item.item?.category || "Finding")} · ${esc(item.item?.host || "Portfolio wide")}</div>
                      </div>
                      <div class="portfolio-vuln-count ${sev}">${item.count.toLocaleString()}</div>
                    </div>`;
                }).join("")}
              </div>
            ` : `
              <div class="empty-state">
                <div class="empty-state-title">No vulnerability history yet</div>
                <div class="empty-state-copy">Scan companies to populate repeated findings here.</div>
              </div>`}
          </section>
        </div>
      </div>`;
  }


  if (!companies.length) {
    grid.innerHTML = ""; empty.style.display = "block"; return;
  }
  empty.style.display = "none";
  grid.innerHTML = companies.map(co => {
    const rl = riskLevel(co);
    const s = co.stats||{};
    const hasData = (s.subdomains||0) > 0 || (co.findings||[]).length > 0;
    const liveInfo = _pipelineCardLiveInfo(co.id);
    const checkpointInfo = co.checkpoint_diff || null;
    const endpointsCount = (co.wayback_data?.interesting_count || 0)
      + (Array.isArray(co.urlfinder_data?.urls) ? co.urlfinder_data.urls.length : 0)
      + (co.js_data?.total_endpoints || 0)
      + (co.api_exposure?.total || 0);
    const findingsCount = (s.findings_critical||0)+(s.findings_high||0)+(s.findings_medium||0)+(s.findings_info||0);
    const trendFindings = checkpointInfo?.new_findings_count || 0;
    const trendHosts = checkpointInfo?.new_hosts_count || checkpointInfo?.new_subdomains_count || 0;
    const queueCounts = _companyQueueCounts(co);
    const queueProgress = _companyQueueProgress(co);
    const trendScore = Math.min(100, trendFindings * 18 + trendHosts * 8);
    const trendText = checkpointInfo
      ? (trendScore > 0
        ? `+${trendFindings} findings · +${trendHosts} hosts`
        : "Stable")
      : "No diff yet";
    const progressTitle = queueProgress && queueProgress.active
      ? "Processo da fila"
      : "Trend";
    const progressText = queueProgress && queueProgress.active
      ? `${queueProgress.complete.toLocaleString()} concluidos · ${queueProgress.done.toLocaleString()} finalizados · ${queueProgress.running.toLocaleString()} rodando · ${queueProgress.pending.toLocaleString()} na fila`
      : trendText;
    const progressPct = queueProgress && queueProgress.active ? queueProgress.pct : trendScore;
    const progressCls = queueProgress && queueProgress.active ? " running" : "";
    const scanBtn = SERVER_MODE
      ? `<button class="btn-scan btn-scan-sm" onclick="event.stopPropagation();openScanModal('${co.id}')"><svg viewBox="0 0 16 16" fill="currentColor" style="width:10px;height:10px"><path d="M3 2l10 6-10 6V2z"/></svg> Scan</button>`
      : "";
    const editBtn = SERVER_MODE
      ? `<button class="btn btn-secondary" style="font-size:.65rem;padding:3px 9px;opacity:.7" onclick="event.stopPropagation();openEditCompanyModal('${co.id}')" title="Edit company">${icoHtml("pencil",14)} Editar</button>`
      : "";
    return `<div class="company-card risk-${rl}" onclick="selectCompany('${co.id}')">
      <div class="cc-top">
        <div class="cc-left">
          <div class="cc-name">${esc(co.name)}</div>
          <div class="cc-domain">${esc(_companyScopeLabel(co))}</div>
        </div>
        <div style="display:flex;gap:6px;align-items:center">
          ${hasData ? `<span class="cc-risk-badge ${rl}">${riskLabel(rl)}</span>` : scanBtn}
          ${editBtn}
        </div>
      </div>
      ${hasData ? `
      <div class="cc-mini">
        <span>${co.last_scan || "—"}</span>
        <span>${(co.domains||[]).length} domains</span>
        <span>${s.live_hosts||0} live</span>
        <span>${endpointsCount} endpoints</span>
      </div>
      ${liveInfo ? `
      <div class="cc-live ${liveInfo.status}">
        <span class="cc-live-chip ${liveInfo.status}">${esc(liveInfo.status === "queued" ? "Queued" : "Running")}</span>
        <div class="cc-live-text">
          <span class="cc-live-tool">${esc(liveInfo.tool || "starting")}</span>
          ${liveInfo.phase ? `<span class="cc-live-phase">${esc(liveInfo.phase)}</span>` : ""}
        </div>
      </div>` : ""}
      <div class="cc-trend${progressCls}" title="${queueProgress && queueProgress.active ? `${queueProgress.total.toLocaleString()} jobs totais` : (checkpointInfo ? `Compared to ${esc(checkpointInfo.compared_to || 'previous scan')}` : 'No checkpoint history')}">
        <div class="cc-trend-head">
          <span>${esc(progressTitle)}</span>
          <b>${esc(progressText)}</b>
        </div>
        <div class="cc-trend-bar">
          <div class="cc-trend-fill" style="width:${progressPct}%"></div>
        </div>
      </div>
      <div class="cc-track">
        <div class="cc-track-item c" onclick="goToVulnSeverity(${_jsArg(co.id)},'critical',event)" title="Ver vulnerabilidades Critical" style="cursor:pointer"><span>Critical</span><b>${s.findings_critical||0}</b></div>
        <div class="cc-track-item h" onclick="goToVulnSeverity(${_jsArg(co.id)},'high',event)" title="Ver vulnerabilidades High" style="cursor:pointer"><span>High</span><b>${s.findings_high||0}</b></div>
        <div class="cc-track-item m" onclick="goToVulnSeverity(${_jsArg(co.id)},'medium',event)" title="Ver vulnerabilidades Medium" style="cursor:pointer"><span>Medium</span><b>${s.findings_medium||0}</b></div>
        <div class="cc-track-item i" onclick="goToVulnSeverity(${_jsArg(co.id)},'info',event)" title="Ver vulnerabilidades Info" style="cursor:pointer"><span>Info</span><b>${s.findings_info||0}</b></div>
        <div class="cc-track-item"><span>Hosts</span><b>${s.subdomains||0}</b></div>
        <div class="cc-track-item"><span>Live</span><b>${s.live_hosts||0}</b></div>
        <div class="cc-track-item"><span>WAF</span><b>${s.waf_protected||0}</b></div>
      </div>
      <div class="cc-meta">
        <div>${s.subdomains||0} hosts</div>
        <div>${findingsCount} findings</div>
        <div>${s.waf_protected||0} behind WAF</div>
      </div>` : `
      <div class="cc-empty">
        <div class="cc-empty-title">Sem scan concluido ainda</div>
        <div class="cc-empty-stats">
          <div class="cc-empty-stat done">
            <b>${queueCounts.complete.toLocaleString()}</b>
            <span>dominios concluidos</span>
          </div>
          <div class="cc-empty-stat queued">
            <b>${queueCounts.queued.toLocaleString()}</b>
            <span>dominios na fila</span>
          </div>
        </div>
      </div>`}
    </div>`;
  }).join("");
}

// ════════════════════════════════════════════════════════════════════════
//  OVERVIEW TAB — Red Team Executive Summary
// ════════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════
//  THREAT MAP — Hexagonal grid canvas
// ════════════════════════════════════════════════════════════════════════
let _hexAnimFrame = null;
function drawThreatMap(canvas, hosts) {
  try {
  if (!canvas || !canvas.parentElement) return;
  // Cancel any existing animation loop on this canvas
  if (canvas._animFrame) { cancelAnimationFrame(canvas._animFrame); canvas._animFrame = null; }
  const dpr = window.devicePixelRatio || 1;
  const parent = canvas.parentElement;
  const W = parent.offsetWidth  || parent.getBoundingClientRect().width  || 800;
  const H = parent.offsetHeight || parent.getBoundingClientRect().height || 260;
  canvas.width = Math.round(W * dpr);
  canvas.height = Math.round(H * dpr);
  // Let CSS width:100%;height:100% control display size — don't set style here
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  const hexR = 18, hexGap = 3;
  const hexW = Math.sqrt(3) * hexR;
  const hexH = 2 * hexR;
  const cols = Math.floor(W / (hexW + hexGap)) + 1;
  const rows = Math.floor(H / (hexH * 0.75 + hexGap)) + 1;

  // Build hex grid with random intensity
  const hexes = [];
  const t = Date.now() * 0.0003;
  for (let row = 0; row < rows; row++) {
    for (let col = 0; col < cols; col++) {
      const cx = col * (hexW + hexGap) + (row % 2 ? hexW/2 + hexGap/2 : 0);
      const cy = row * (hexH * 0.75 + hexGap);
      const noise = Math.sin(cx * 0.04 + t) * Math.cos(cy * 0.05 + t * 0.7);
      const intensity = Math.abs(noise);
      const hasHost = hosts && hosts.length > 0 && (Math.abs(Math.sin(cx * 0.1 + cy * 0.13)) > 0.5);
      hexes.push({ cx, cy, intensity, hasHost });
    }
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    const now = Date.now() * 0.0002;

    for (const h of hexes) {
      const pulse = h.intensity * (0.5 + 0.5 * Math.sin(now * 3 + h.cx * 0.02));
      let alpha = 0.04 + pulse * 0.06;
      let stroke = 'rgba(0,229,255,0.12)';
      let fill = `rgba(0,229,255,${alpha})`;

      if (h.hasHost) {
        alpha = 0.08 + pulse * 0.12;
        fill = `rgba(0,229,255,${alpha})`;
        stroke = 'rgba(0,229,255,0.2)';
      }

      // Draw hex
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const angle = Math.PI / 3 * i - Math.PI / 6;
        const x = h.cx + hexR * Math.cos(angle);
        const y = h.cy + hexR * Math.sin(angle);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.fillStyle = fill;
      ctx.fill();
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 0.5;
      ctx.stroke();
    }
  }

   function animate() {
     draw();
     canvas._animFrame = requestAnimationFrame(animate);
   }
   animate();
  } catch(e) { console.error('drawThreatMap:', e); }
 }

function initThreatMaps() {
  try {
    document.querySelectorAll('.threat-map canvas').forEach(canvas => {
      const parent = canvas.parentElement;
      if (!parent) return;
      // If parent has no size yet (hidden or not laid out), use ResizeObserver
      if (parent.offsetWidth === 0) {
        if (window._tmResizeObs) window._tmResizeObs.disconnect();
        window._tmResizeObs = new ResizeObserver(entries => {
          for (const e of entries) {
            if (e.contentRect.width > 0) {
              window._tmResizeObs.disconnect();
              drawThreatMap(canvas, []);
              break;
            }
          }
        });
        window._tmResizeObs.observe(parent);
      } else {
        drawThreatMap(canvas, []);
      }
    });
  } catch(e) { console.error('initThreatMaps:', e); }
}

// ════════════════════════════════════════════════════════════════════════
//  TENANCY PANEL
// ════════════════════════════════════════════════════════════════════════
function openTenancyPanel() {
  const el = document.getElementById('tenancy-overlay');
  if (!el) return;
  el.classList.add('show');
  _renderTenancyClients();
}

function closeTenancyPanel() {
  document.getElementById('tenancy-overlay')?.classList.remove('show');
}

function _renderTenancyClients() {
  const list = document.getElementById('tenancy-client-list');
  if (!list) return;
  const companies = allCompanies();
  const active = state.currentId;
  list.innerHTML = companies.map(co =>
    `<div class="tp-client-item ${co.id === active ? 'active' : ''}" onclick="selectTenancyClient('${co.id}')">
      ${esc(co.name)}${co.id === active ? ' ← ACTIVE' : ''}
    </div>`
  ).join('');
}

function selectTenancyClient(cid) {
  selectCompany(cid);
  closeTenancyPanel();
}

// Keyboard shortcut: Alt+T opens tenancy panel
document.addEventListener('keydown', function(e) {
  try {
    if (e.altKey && e.key === 't') {
      e.preventDefault();
      openTenancyPanel();
    }
    if (e.altKey && e.key >= '1' && e.key <= '9') {
      e.preventDefault();
      var idx = parseInt(e.key) - 1;
      var cos = (typeof allCompanies === 'function') ? allCompanies() : [];
      if (cos[idx] && typeof selectCompany === 'function') selectCompany(cos[idx].id);
    }
  } catch(ex) {}
});
