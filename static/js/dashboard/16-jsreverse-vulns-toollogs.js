function renderJsReverseTab(co) {
  var el = document.getElementById("tab-jsreverse");
  var jd = co.js_data || {};
  var jsFiles = jd.js_files || [];

  // Update badge
  var totalSecrets = jd.total_secrets || 0;
  var tc = document.getElementById("tc-jsreverse");
  if (tc) tc.textContent = totalSecrets || "";

  if (!jsFiles.length) {
    el.innerHTML = '<div class="empty-state"><div class="empty-state-icon" data-ico="inbox" aria-hidden="true"></div><div class="empty-state-title">No JS analysis data yet</div><div class="empty-state-copy">Run the pipeline with the js module enabled (JS Discovery). js_endpoints and js_secrets flatten those results.</div></div>';
    return;
  }

  // Collect all secrets and endpoints from all files
  var allSecrets = [];
  var allEndpoints = [];
  var droppedEp = 0;

  jsFiles.forEach(function(f) {
    var host = f.host || "";
    var url = f.url || "";
    var noisy = _jsHostIsNoise(host);
    (f.secrets || []).forEach(function(s) {
      if (_isFpJsSecret(s.type, s.value)) return;
      allSecrets.push({ severity: s.severity || "medium", type: s.type || "unknown", host: host, value: s.value || "", context: s.context || "", url: url, noise: noisy });
    });
    (f.endpoints || []).forEach(function(ep) {
      var path = typeof ep === "string" ? ep : (ep.path || ep.url || "");
      if (isJsPathNoise(path)) { droppedEp += 1; return; }
      allEndpoints.push({ host: host, path: path, kind: (typeof ep === "object" && ep.kind) || "path", url: url, noise: noisy, source: f.source || "" });
    });
  });

  var totalEndpoints = jd.total_endpoints || allEndpoints.length;

  // Unique secret types for filter
  var uniqueTypes = Array.from(new Set(allSecrets.map(function(s) { return s.type; }))).sort();

  // Summary strip
  var critCnt = jd.critical_count || allSecrets.filter(function(s){return s.severity==="critical";}).length;
  var highCnt = jd.high_count    || allSecrets.filter(function(s){return s.severity==="high";}).length;
  var medCnt  = jd.medium_count  || allSecrets.filter(function(s){return s.severity==="medium";}).length;

  var html = '<div class="section-shell" style="padding:20px">';
  html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">';
  html += '<div><div style="font-size:.75rem;color:var(--text3);text-transform:uppercase;letter-spacing:.08em">JS Reverse Engineering</div>';
  html += '<div style="font-size:1.3rem;font-weight:700;color:var(--text)">Secrets &amp; API Endpoints</div></div></div>';

  // Summary strip cards
  html += '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px">';
  function _statCard(label, val, color) {
    return '<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 20px;min-width:110px">' +
      '<div style="font-size:1.6rem;font-weight:800;color:' + color + '">' + val + '</div>' +
      '<div style="font-size:.68rem;color:var(--text3);margin-top:2px;text-transform:uppercase">' + label + '</div></div>';
  }
  html += _statCard("Critical", critCnt, "var(--red)");
  html += _statCard("High", highCnt, "var(--orange)");
  html += _statCard("Medium", medCnt, "var(--yellow)");
  html += _statCard("Total Secrets", allSecrets.length || totalSecrets, "var(--teal)");
  html += _statCard("Endpoints", allEndpoints.length || totalEndpoints, "var(--text2)");
  html += _statCard("JS files", (jd.js_analyzed || jsFiles.length) + (jd.js_files_found ? "/" + jd.js_files_found : ""), "var(--text)");
  if (jd.source_maps_count) html += _statCard("Source maps", jd.source_maps_count, "var(--teal)");
  html += '</div>';
  var maps = jd.source_maps || [];
  if (maps.length) {
    html += '<div style="margin:-8px 0 18px;font-size:.72rem;color:var(--text2)">Source maps públicos:';
    maps.slice(0, 8).forEach(function(m) {
      html += '<div style="font-family:monospace;margin-top:2px">' + originLinkHtml(m.url || "", m.url || "", { className: "origin-link", title: _originTitle("js") }) + (m.sources_count ? " · " + m.sources_count + " sources" : "") + "</div>";
    });
    html += "</div>";
  }

  // ── SECRETS SECTION ──────────────────────────────────────────────────────
  html += '<div style="margin-bottom:32px">';
  html += '<div style="font-size:.9rem;font-weight:700;color:var(--text);margin-bottom:10px;display:flex;align-items:center;justify-content:space-between">';
  html += '<span>Secrets Found (' + allSecrets.length + ')</span>';
  html += '<button onclick="_jsrExportSecretsCsv()" style="background:var(--card);border:1px solid var(--border);color:var(--text2);border-radius:5px;padding:3px 10px;font-size:.68rem;cursor:pointer">' + icoHtml("chevron-down",14) + ' CSV</button>';
  html += '</div>';

  // Filter bar
  html += '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center">';
  html += '<select id="jsr-sev-filter" onchange="_jsrRender()" style="background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 8px;font-size:.72rem">';
  html += '<option value="">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>';

  html += '<select id="jsr-type-filter" onchange="_jsrRender()" style="background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 8px;font-size:.72rem">';
  html += '<option value="">All Types</option>';
  uniqueTypes.forEach(function(t) { html += '<option value="' + esc(t) + '">' + esc(t) + '</option>'; });
  html += '</select>';

  html += '<input id="jsr-text-filter" oninput="_jsrRender()" placeholder="Search value / host..." style="background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 10px;font-size:.72rem;width:180px">';

  html += '<label style="display:flex;align-items:center;gap:5px;font-size:.72rem;color:var(--text2);cursor:pointer">';
  html += '<input type="checkbox" id="jsr-noise-filter" onchange="_jsrRender()" checked> Hide noise CDNs</label>';
  html += '</div>';

  // Secrets table
  html += '<div id="jsr-secrets-table"></div>';
  html += '</div>';

  // ── ENDPOINTS SECTION ────────────────────────────────────────────────────
  html += '<div>';
  html += '<div style="font-size:.9rem;font-weight:700;color:var(--text);margin-bottom:10px;display:flex;align-items:center;justify-content:space-between">';
  html += '<span>Discovered Endpoints (' + allEndpoints.length + (droppedEp ? ' · ' + droppedEp + ' omitidos' : '') + ')</span>';
  html += '<button onclick="_jsrExportEndpointsCsv()" style="background:var(--card);border:1px solid var(--border);color:var(--text2);border-radius:5px;padding:3px 10px;font-size:.68rem;cursor:pointer">' + icoHtml("chevron-down",14) + ' CSV</button>';
  html += '</div>';

  html += '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center">';
  html += '<input id="jsr-ep-text" oninput="_jsrRenderEp()" placeholder="Search path / host..." style="background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 10px;font-size:.72rem;width:200px">';
  html += '<label style="display:flex;align-items:center;gap:5px;font-size:.72rem;color:var(--text2);cursor:pointer">';
  html += '<input type="checkbox" id="jsr-api-only" onchange="_jsrRenderEp()"> API/Auth only</label>';
  html += '</div>';

  html += '<div id="jsr-endpoints-table"></div>';
  html += '</div>';

  // ── RUNTIME NETWORK MAP (Playwright) ────────────────────────────────────
  var runtimeNet = jd.runtime_network || [];
  var runtimeJsCnt = jd.runtime_js_count || 0;
  html += '<div style="margin-top:32px">';
  html += '<div style="font-size:.9rem;font-weight:700;color:var(--text);margin-bottom:6px;display:flex;align-items:center;gap:10px">';
  html += '<span>Runtime Network Map <span style="font-size:.72rem;font-weight:400;color:var(--text3)">(Playwright)</span></span>';
  if (runtimeJsCnt) html += '<span style="font-size:.68rem;color:var(--teal);font-weight:600">' + runtimeJsCnt + ' runtime JS chunks captured</span>';
  html += '</div>';

  if (!runtimeNet.length) {
    html += '<div style="color:var(--text3);font-size:.78rem;padding:10px 0">No runtime network calls captured — run pipeline to collect Playwright data.</div>';
  } else {
    var methods = Array.from(new Set(runtimeNet.map(function(c){return c.method;}))).sort();
    html += '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center">';
    html += '<input id="jsr-net-filter" oninput="_jsrRenderNet()" placeholder="Filter URL..." style="background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 10px;font-size:.72rem;width:220px">';
    html += '<select id="jsr-net-method" onchange="_jsrRenderNet()" style="background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 8px;font-size:.72rem"><option value="">All Methods</option>';
    methods.forEach(function(m){ html += '<option>' + esc(m) + '</option>'; });
    html += '</select>';
    html += '<button onclick="_jsrExportNetCsv()" style="background:var(--card);border:1px solid var(--border);color:var(--text2);border-radius:5px;padding:3px 10px;font-size:.68rem;cursor:pointer">' + icoHtml("chevron-down",14) + ' CSV</button>';
    html += '</div>';
    html += '<div id="jsr-net-table"></div>';
  }
  html += '</div>';

  html += '</div>'; // section-shell

  el.innerHTML = html;

  // Store data on window for filter handlers
  window._jsrAllSecrets   = allSecrets;
  window._jsrAllEndpoints = allEndpoints;
  window._jsrRuntimeNet   = runtimeNet;
  window._jsrNoiseHosts   = _JS_NOISE_HOSTS;
  window._jsrRevealSet    = new Set();
  window._jsrDroppedEp    = droppedEp;

  if (_pendingFoundFilter && _pendingFoundFilter.tab === "jsreverse") {
    var q = _pendingFoundFilter.q;
    _pendingFoundFilter = null;
    var sevEl = document.getElementById("jsr-text-filter");
    var epEl = document.getElementById("jsr-ep-text");
    if (sevEl) sevEl.value = q;
    if (epEl) epEl.value = q;
  }

  _jsrRender();
  _jsrRenderEp();
  if (runtimeNet.length) _jsrRenderNet();
}

function _sevBadge(s) {
  var c = {critical:'#fb7185',high:'#fb923c',medium:'#fbbf24',low:'#4ade80'}[s] || 'var(--text3)';
  return '<span style="background:' + c + '22;color:' + c + ';border:1px solid ' + c + '44;border-radius:4px;padding:1px 7px;font-size:.65rem;font-weight:700;text-transform:uppercase">' + esc(s || 'info') + '</span>';
}

function _jsrRender() {
  var sev    = (document.getElementById("jsr-sev-filter")  || {}).value || "";
  var typ    = (document.getElementById("jsr-type-filter") || {}).value || "";
  var txt    = ((document.getElementById("jsr-text-filter")|| {}).value || "").toLowerCase();
  var noise  = (document.getElementById("jsr-noise-filter")|| {}).checked;
  var tbl    = document.getElementById("jsr-secrets-table");
  if (!tbl) return;

  var rows = (window._jsrAllSecrets || []).filter(function(s) {
    if (sev  && s.severity !== sev) return false;
    if (typ  && s.type     !== typ) return false;
    if (noise && (s.noise || (window._jsrNoiseHosts||new Set()).has(s.host))) return false;
    if (txt  && !((s.value||"").toLowerCase().includes(txt) || (s.host||"").toLowerCase().includes(txt) || (s.type||"").toLowerCase().includes(txt))) return false;
    return true;
  });

  if (!rows.length) {
    tbl.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3);font-size:.8rem">No secrets match current filters.</div>';
    return;
  }

  var h = '<table style="width:100%;border-collapse:collapse;font-size:.72rem">';
  h += '<thead><tr style="border-bottom:1px solid var(--border)">';
  ['Severity','Type','Host','Value','Source URL'].forEach(function(col) {
    h += '<th style="text-align:left;padding:6px 10px;color:var(--text3);font-weight:600;font-size:.68rem;text-transform:uppercase">' + col + '</th>';
  });
  h += '</tr></thead><tbody>';

  rows.forEach(function(s, i) {
    var revealed = (window._jsrRevealSet || new Set()).has(i);
    var display  = revealed ? esc(s.value) : '••••••••';
    var btnLabel = revealed ? 'hide' : 'reveal';
    var shortUrl = s.url ? s.url.replace(/^https?:\/\//,'').substring(0,55) + (s.url.length > 55 ? '…' : '') : '';
    h += '<tr style="border-bottom:1px solid var(--border)22;hover:background:var(--card2)">';
    h += '<td style="padding:6px 10px">' + _sevBadge(s.severity) + '</td>';
    h += '<td style="padding:6px 10px;color:var(--text2);font-family:monospace">' + esc(s.type) + '</td>';
    h += '<td style="padding:6px 10px">' + (s.host ? originHostChip(s.host, "origin-link") : "—") + '</td>';
    h += '<td style="padding:6px 10px;font-family:monospace;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(s.value) + '">';
    h += '<span id="jsr-val-' + i + '">' + display + '</span> ';
    h += '<button onclick="_jsrToggleReveal(' + i + ')" style="background:none;border:none;color:var(--teal);cursor:pointer;font-size:.65rem;padding:0 4px">' + btnLabel + '</button></td>';
    h += '<td style="padding:6px 10px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">';
    if (s.url) h += originLinkHtml(s.url, shortUrl, { className: "origin-link", title: _originTitle("js") });
    h += '</td></tr>';
  });
  h += '</tbody></table>';
  tbl.innerHTML = h;
}

function _jsrToggleReveal(i) {
  if (!window._jsrRevealSet) window._jsrRevealSet = new Set();
  if (window._jsrRevealSet.has(i)) window._jsrRevealSet.delete(i);
  else window._jsrRevealSet.add(i);
  _jsrRender();
}

function _jsrRenderEp() {
  var txt     = ((document.getElementById("jsr-ep-text")  || {}).value || "").toLowerCase();
  var apiOnly = (document.getElementById("jsr-api-only")  || {}).checked;
  var tbl     = document.getElementById("jsr-endpoints-table");
  if (!tbl) return;

  var noise = (document.getElementById("jsr-noise-filter")||{}).checked;
  var rows = (window._jsrAllEndpoints || []).filter(function(ep) {
    if (noise && ep.noise) return false;
    if (apiOnly && !/(\/api\/|\/auth\/|\/oauth|\/login|\/graphql|\/v[0-9])/i.test(ep.path)) return false;
    if (txt && !((ep.path||"").toLowerCase().includes(txt) || (ep.host||"").toLowerCase().includes(txt))) return false;
    return true;
  });

  var maxRows = 500;
  var shown   = rows.slice(0, maxRows);

  if (!shown.length) {
    tbl.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3);font-size:.8rem">No endpoints match current filters.</div>';
    return;
  }

  var h = '<div style="font-size:.68rem;color:var(--text3);margin-bottom:6px">Showing ' + shown.length + (rows.length > maxRows ? ' of ' + rows.length : '') + ' endpoints</div>';
  h += '<table style="width:100%;border-collapse:collapse;font-size:.72rem">';
  h += '<thead><tr style="border-bottom:1px solid var(--border)">';
  ['Host','Path','Kind','Fonte JS'].forEach(function(col) {
    h += '<th style="text-align:left;padding:6px 10px;color:var(--text3);font-weight:600;font-size:.68rem;text-transform:uppercase">' + col + '</th>';
  });
  h += '</tr></thead><tbody>';

  shown.forEach(function(ep) {
    var pathHref = originHref(ep.path, ep.host);
    var pathLabel = ep.path || "";
    var jsShort = ep.url ? String(ep.url).replace(/^https?:\/\//, "").substring(0, 48) : "";
    h += '<tr style="border-bottom:1px solid var(--border)22">';
    h += '<td style="padding:6px 10px">' + (ep.host ? originHostChip(ep.host, "origin-link") : "—") + '</td>';
    h += '<td style="padding:6px 10px;font-family:monospace">';
    h += pathHref ? originLinkHtml(ep.path, pathLabel, { host: ep.host, className: "origin-link origin-mono", title: _originTitle() }) : esc(pathLabel);
    h += '</td>';
    h += '<td style="padding:6px 10px;color:var(--text3)">' + esc(ep.kind) + '</td>';
    h += '<td style="padding:6px 10px">';
    if (ep.url) h += originLinkHtml(ep.url, jsShort, { className: "origin-link", title: _originTitle("js") });
    h += '</td></tr>';
  });
  h += '</tbody></table>';
  tbl.innerHTML = h;
}

function _jsrExportSecretsCsv() {
  var rows = window._jsrAllSecrets || [];
  var lines = ["severity,type,host,value,url"];
  rows.forEach(function(s) {
    lines.push([s.severity, s.type, s.host, '"' + (s.value||"").replace(/"/g,'""') + '"', s.url].join(","));
  });
  _downloadCsv("js_secrets.csv", lines.join("\n"));
}

function _jsrExportEndpointsCsv() {
  var rows = window._jsrAllEndpoints || [];
  var lines = ["host,path,kind"];
  rows.forEach(function(ep) {
    lines.push([ep.host, '"' + (ep.path||"").replace(/"/g,'""') + '"', ep.kind].join(","));
  });
  _downloadCsv("js_endpoints.csv", lines.join("\n"));
}

function _jsrRenderNet() {
  var txt    = ((document.getElementById("jsr-net-filter") || {}).value || "").toLowerCase();
  var method = ((document.getElementById("jsr-net-method") || {}).value || "");
  var tbl    = document.getElementById("jsr-net-table");
  if (!tbl) return;

  var rows = (window._jsrRuntimeNet || []).filter(function(c) {
    if (method && c.method !== method) return false;
    if (txt && !(c.url||"").toLowerCase().includes(txt)) return false;
    return true;
  });

  var maxRows = 400;
  var shown   = rows.slice(0, maxRows);

  if (!shown.length) {
    tbl.innerHTML = '<div style="padding:14px 0;color:var(--text3);font-size:.78rem">No calls match filter.</div>';
    return;
  }

  var h = '<div style="font-size:.68rem;color:var(--text3);margin-bottom:6px">Showing ' + shown.length + (rows.length > maxRows ? ' of ' + rows.length : '') + ' calls</div>';
  h += '<table style="width:100%;border-collapse:collapse;font-size:.71rem">';
  h += '<thead><tr style="border-bottom:1px solid var(--border)">';
  ['Method','Type','URL'].forEach(function(col) {
    h += '<th style="text-align:left;padding:5px 10px;color:var(--text3);font-weight:600;font-size:.67rem;text-transform:uppercase">' + col + '</th>';
  });
  h += '</tr></thead><tbody>';

  var methodColor = {GET:'var(--teal)',POST:'var(--orange)',PUT:'var(--yellow)',DELETE:'var(--red)',PATCH:'#a78bfa'};
  shown.forEach(function(c) {
    var mc = methodColor[c.method] || 'var(--text2)';
    var shortUrl = (c.url||'').replace(/^https?:\/\//,'');
    h += '<tr style="border-bottom:1px solid var(--border)22">';
    h += '<td style="padding:5px 10px;font-weight:700;color:' + mc + ';font-family:monospace;white-space:nowrap">' + esc(c.method) + '</td>';
    h += '<td style="padding:5px 10px;color:var(--text3);white-space:nowrap">' + esc(c.type||'') + '</td>';
    h += '<td style="padding:5px 10px;font-family:monospace;word-break:break-all">';
    h += originLinkHtml(c.url || "", shortUrl, { className: "origin-link origin-mono", title: _originTitle() });
    h += '</td></tr>';
  });
  h += '</tbody></table>';
  tbl.innerHTML = h;
}

function _jsrExportNetCsv() {
  var rows = window._jsrRuntimeNet || [];
  var lines = ["method,type,url"];
  rows.forEach(function(c) {
    lines.push([c.method, c.type, '"' + (c.url||"").replace(/"/g,'""') + '"'].join(","));
  });
  _downloadCsv("js_runtime_network.csv", lines.join("\n"));
}

function _downloadCsv(filename, content) {
  var blob = new Blob([content], {type: "text/csv"});
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}


async function renderVulnsTab(co) {
  const el = document.getElementById("tab-vulns");
  if (!el) return;

  el.setAttribute("aria-busy", "true");
  el.innerHTML = `<div class="vuln-loading" role="status" style="padding:40px;text-align:center;color:var(--text3);min-height:120px">
    <div class="pulse" style="width:12px;height:12px;background:var(--teal);border-radius:50%;margin:0 auto 12px"></div>
    ${esc(_opT("vuln_loading", "Carregando vulnerabilidades…"))}</div>`;

  let data;
  try {
    const resp = await fetch(`/api/vulns/${encodeURIComponent(co.id)}`, {headers:_authHeaders()});
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    data = await resp.json();
  } catch(e) {
    el.innerHTML = `<div class="empty-state"><div class="empty-state-icon" data-ico="inbox" aria-hidden="true"></div><div class="empty-state-title">${esc(_opT("vuln_fail", "Falha ao carregar vulnerabilidades"))}</div><div class="empty-state-copy">${esc(String(e))}</div></div>`;
    el.removeAttribute("aria-busy");
    return;
  }

  const cors     = data.cors || [];
  const graphql  = data.graphql || [];
  const nuclei   = data.nuclei || [];
  const takeover = data.takeover || [];
  const summary   = data.summary || {};
  // Achados confirmados: contagens e categorias vêm do servidor; a lista é paginada em applyFindFilter.
  let fg0 = {confirmed_total: 0, severity: {}, categories: []};
  try { fg0 = await fetchFindingGroups(co.id, {page: 1, per_page: 1}); } catch (e) {}
  const findings = {length: fg0.confirmed_total};
  const apiTotal  = Number(summary.total || (cors.length + graphql.length + nuclei.length + takeover.length));

  const tcv = document.getElementById("tc-vulns");
  if (tcv) tcv.textContent = String(apiTotal + findings.length);

  try {
    const triageR = await fetch(`/api/findings/${encodeURIComponent(co.id)}/triage`, {headers:_authHeaders()});
    if (triageR.ok) {
      const triageData = await triageR.json();
      if (!window._triageMap) window._triageMap = {};
      window._triageMap[co.id] = triageData.triage || {};
    }
  } catch(e) {}

  const cats = fg0.categories || [];
  const summaryCards = {
    critical: fg0.severity.critical || 0,
    high:     fg0.severity.high || 0,
    medium:   fg0.severity.medium || 0,
    low:      fg0.severity.low || 0,
  };

  const cidJs = _jsArg(co.id);
  let html = `<div class="section-shell" style="padding:18px">
    <div class="section-head">
      <div class="section-head-main">
        <div class="section-kicker">${esc(_opT("vuln_kicker", "Vulnerabilidades confirmadas"))}</div>
        <div class="section-title">${esc(_opT("vuln_title", "Só findings de vulnerabilidade confirmados"))}</div>
        <div class="section-sub">${esc(_opT("vuln_sub", "Ruído de recon, intel de marca, phishing e outras pistas que não são vulnerabilidade ficam de fora."))}</div>
      </div>
    </div>`;

  // Só o que tem dado: a quebra por severidade já aparece nos cartões logo abaixo.
  const _kpis = [
    [esc(_opT("vuln_kpi_confirmed", "Confirmadas")), findings.length, "var(--green)"],
    ["CORS", cors.length, "var(--red)"],
    ["GraphQL", graphql.length, "var(--teal)"],
    ["Nuclei", nuclei.length, "var(--orange)"],
    ["Takeover", takeover.length, "var(--yellow)"],
  ].filter(([, n], i) => i === 0 || n > 0);
  html += `<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px">${_kpis.map(k => _vStatCard(...k)).join("")}</div>`;

  if (findings.length) {
    html += `<div class="findings-summary">
      ${_severityCard("critical", summaryCards.critical, co.id)}
      ${_severityCard("high", summaryCards.high, co.id)}
      ${_severityCard("medium", summaryCards.medium, co.id)}
      ${_severityCard("low", summaryCards.low, co.id)}
    </div>`;
    html += `<div class="filter-bar">
      <input type="text" class="fi grow" id="f-search" placeholder="${escAttr(_opT("vuln_search", "Buscar vulns confirmadas, hosts, descrições…"))}" oninput='applyFindFilter(${cidJs})'>
      <select class="fi" id="f-sev" onchange='applyFindFilter(${cidJs})'>
        <option value="">${esc(_opT("vuln_all_sev", "Todas as severidades"))}</option><option value="critical">${esc(_opT("vuln_kpi_critical", "Críticas"))}</option><option value="high">${esc(_opT("vuln_kpi_high", "Altas"))}</option><option value="medium">${esc(_opT("vuln_kpi_medium", "Médias"))}</option><option value="low">${esc(_opT("vuln_kpi_low", "Baixas"))}</option>
      </select>
      <select class="fi" id="f-cat" onchange='applyFindFilter(${cidJs})'><option value="">${esc(_opT("vuln_all_cat", "Todas as categorias"))}</option>${cats.map(c=>`<option value="${esc(c)}">${esc(c)}</option>`).join("")}</select>
      <select class="fi" id="f-triage" onchange='applyFindFilter(${cidJs})'>
        <option value="">Todos os status</option>
        ${Object.entries(FINDING_TRIAGE_LABELS).map(([val,lbl])=>`<option value="${val}">${lbl}</option>`).join("")}
      </select>
      <span style="font-size:.68rem;color:var(--text3);padding:6px 4px" id="f-cnt"></span>
      <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px;margin-left:auto" onclick='exportFindings(${cidJs},"csv")' title="Export CSV">${icoHtml("chevron-down",14)} CSV</button>
      <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px" onclick='exportFindings(${cidJs},"json")' title="Export JSON">${icoHtml("chevron-down",14)} JSON</button>
    </div>
    <div class="findings-list" id="f-list"></div>
    <div class="pager" id="f-pager" style="display:none">
      <span class="pager-info" id="f-pinfo"></span>
      <div class="pager-btns">
        <button class="pb" id="f-prev" onclick="findsPageNav(-1)">${esc(_opT("vuln_prev", "← Anterior"))}</button>
        <span id="f-pnums"></span>
        <button class="pb" id="f-next" onclick="findsPageNav(1)">${esc(_opT("vuln_next", "Próxima →"))}</button>
      </div>
    </div>
    <div class="empty-state" id="f-empty" style="display:none"><div class="empty-state-icon" data-ico="inbox" aria-hidden="true"></div><div class="empty-state-title">${esc(_opT("vuln_empty_filter_t", "Nenhuma vuln confirmada bate com os filtros"))}</div><div class="empty-state-copy">${esc(_opT("vuln_empty_filter_c", "Amplie a busca ou limpe os filtros de severidade e categoria."))}</div></div>`;
  } else {
    html += `<div class="empty-state"><div class="empty-state-icon" data-ico="inbox" aria-hidden="true"></div><div class="empty-state-title">${esc(_opT("vuln_empty_t", "Nenhuma vulnerabilidade confirmada ainda"))}</div><div class="empty-state-copy">${esc(_opT("vuln_empty_c", "Rode a pipeline de bug bounty para preencher esta vista."))}</div></div>`;
  }

  html += `<div style="margin-top:18px">`;

  const _sectionHdr = (title, count) => !count ? "" : `<div style="font-size:.9rem;font-weight:700;color:var(--text);margin:24px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--border)">${esc(title)} <span style="color:var(--text3);font-weight:400">(${count})</span></div>`;
  const _emptySection = () => "";   // seção sem dados não aparece

  html += _sectionHdr(_opT("vuln_cors_title", "CORS mal configurado"), cors.length);
  if (!cors.length) {
    html += _emptySection(_opT("vuln_cors_empty", "Nenhum CORS mal configurado encontrado."));
  } else {
    html += `<div style="display:grid;gap:10px">` + cors.map(f => {
      const acac = f.acac === true || f.acac === "true" || f.acac === 1;
      return `<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          ${_sevBadge(f.severity || "high")}
          <span style="font-weight:700;color:var(--teal)">${esc(f.host || "")}</span>
          <span style="font-size:.72rem;color:var(--text3)">${esc(f.test || "")}</span>
        </div>
        <div style="font-size:.72rem;color:var(--text2);margin-bottom:6px">
          <span style="color:var(--text3)">ACAO: </span><code style="color:var(--text)">${esc(f.acao || "")}</code>
          ${acac ? `<span style="background:#fb718522;color:#fb7185;border:1px solid #fb718544;border-radius:4px;padding:1px 7px;font-size:.65rem;font-weight:700;margin-left:6px">${icoHtml("warning",14)} ${esc(_opT("vuln_credentials", "Credenciais"))}</span>` : ""}
        </div>
        <div style="font-size:.7rem;color:var(--text3)">${esc(_opT("vuln_origin_sent", "Origin enviada:"))} <code>${esc(f.origin_sent || "")}</code></div>
        ${f.url ? `<div style="margin-top:6px"><a href="${esc(f.url)}" target="_blank" rel="noopener" style="color:var(--teal);font-size:.7rem;text-decoration:none">${esc(f.url.substring(0,80))}</a></div>` : ""}
      </div>`;
    }).join("") + `</div>`;
  }

  html += _sectionHdr(_opT("vuln_gql_title", "Endpoints GraphQL"), graphql.length);
  html += graphql.length ? `<div style="display:grid;gap:10px">${graphql.map(f => `
    <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        ${_sevBadge(f.severity || "high")}
        <span style="font-weight:700;color:var(--teal)">${esc(f.host || "")}</span>
        <span style="font-size:.72rem;color:var(--text3)">${esc(f.url || "")}</span>
      </div>
      <div style="font-size:.72rem;color:var(--text2)">${esc(f.desc || f.title || "")}</div>
    </div>`).join("")}</div>` : _emptySection(_opT("vuln_gql_empty", "Nenhum endpoint GraphQL detectado."));

  html += _sectionHdr(_opT("vuln_nuclei_title", "Findings do Nuclei"), nuclei.length);
  html += nuclei.length ? `<div style="display:grid;gap:10px">${nuclei.map(f => `
    <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        ${_sevBadge(f.severity || "high")}
        <span style="font-weight:700;color:var(--teal)">${esc(f.host || "")}</span>
        <span style="font-size:.72rem;color:var(--text3)">${esc(f.template || f.name || "")}</span>
      </div>
      <div style="font-size:.72rem;color:var(--text2)">${esc(f.desc || "")}</div>
    </div>`).join("")}</div>` : _emptySection(_opT("vuln_nuclei_empty", "Nenhum finding do Nuclei detectado."));

  html += _sectionHdr(_opT("vuln_takeover_title", "Candidatos a takeover"), takeover.length);
  html += takeover.length ? `<div style="display:grid;gap:10px">${takeover.map(f => `
    <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        ${_sevBadge(f.severity || "high")}
        <span style="font-weight:700;color:var(--teal)">${esc(f.host || "")}</span>
      </div>
      <div style="font-size:.72rem;color:var(--text2)">${esc(f.desc || "")}</div>
    </div>`).join("")}</div>` : _emptySection(_opT("vuln_takeover_empty", "Nenhum candidato a takeover detectado."));

  html += `</div></div>`;
  el.innerHTML = html;
  el.removeAttribute("aria-busy");
  _finds_page = 1;
  if (!_applyPendingVulnFilter(co.id) && findings.length) applyFindFilter(co.id);
}

function exportHosts(fmt) {
  // Exporta o que está na tela: respeita os filtros ativos da matriz de ativos.
  const hosts = typeof _subFiltered === "function" && _sub_hosts && _sub_hosts.length ? _subFiltered() : (_sub_hosts || _co_hosts || []);
  const rows = typeof _assetExportRows === "function" ? _assetExportRows(hosts) : hosts.map(h => ({host: h.host, ip: h.ip, waf: h.waf}));
  const cid = state.currentId || "export";
  const ts = new Date().toISOString().slice(0,10);
  if (fmt === "json") {
    _downloadBlob(JSON.stringify(rows, null, 2), `${cid}_ativos_${ts}.json`, "application/json");
  } else {
    const cols = rows.length ? Object.keys(rows[0]) : ["host"];
    const q = v => `"${String(v ?? "").replace(/"/g, '""')}"`;
    _downloadBlob(cols.join(",") + "\n" + rows.map(r => cols.map(c => q(r[c])).join(",")).join("\n"), `${cid}_ativos_${ts}.csv`, "text/csv");
  }
}

function copyInstall(name){
  const el = document.getElementById("ic-" + name);
  if(!el) return;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(el.textContent).then(()=>{
      const btn = el.nextElementSibling;
   if(btn){ btn.textContent = ""; setTimeout(()=>btn.textContent="⎘", 1500); }
    });
  } else {
    _fallbackCopy(el.textContent);
    const btn = el.nextElementSibling;
  if(btn){ btn.textContent = ""; setTimeout(()=>btn.textContent="⎘", 1500); }
  }
}

async function runTool(name){
  const input = document.getElementById("ti-" + name);
  const btn   = document.getElementById("tb-" + name);
  const res   = document.getElementById("tr-" + name);
  const target = (input?.value||"").trim();
  if(!target){ input?.focus(); return; }

  btn.disabled = true;
  btn.textContent = "Running…";
  res.className = "tc-result show";
  res.innerHTML = `<div style="color:var(--text3)">Running ${name} against ${target}…</div>`;

  try {
    const r = await fetch("/api/tools/run", {
      method:"POST",
      headers: _authHeaders(),
      body: JSON.stringify({tool: name, target})
    });
    if(!r.ok) throw await _apiErr(r);

    // Poll for result
    const pollIv = setInterval(async ()=>{
      const pr = await fetch(`/api/tools/result?tool=${encodeURIComponent(name)}&target=${encodeURIComponent(target)}`);
      const pd = await pr.json();
      if(pd.status === "done" || pd.status === "error"){
        clearInterval(pollIv);
        btn.disabled = false;
        btn.textContent = "Run";
        if(pd.error){
          res.innerHTML = `<div style="color:var(--red)">Error: ${pd.error}</div>`;
        } else {
          const findings = pd.findings || [];
          if(!findings.length){
            res.innerHTML = `<div style="color:var(--text3)">No findings (${pd.duration?.toFixed(1)||"?"}s)</div>`;
          } else {
            const SEV_COLOR = {critical:"#fb7185",high:"#fb923c",medium:"#fbbf24",low:"#4ade80",info:"#60a5fa"};
            res.innerHTML = `<div style="color:var(--text3);margin-bottom:4px">${findings.length} findings · ${pd.duration?.toFixed(1)||"?"}s</div>` +
              findings.slice(0,50).map(f=>{
                const c = SEV_COLOR[f.severity]||"var(--text2)";
                return `<div class="f-line"><span style="color:${c};font-weight:600">[${esc(f.type)}]</span> ${esc(f.value)}${f.port?" :"+esc(String(f.port)):""}</div>`;
              }).join("") +
              (findings.length > 50 ? `<div style="color:var(--text3)">… and ${findings.length-50} more</div>` : "");
          }
        }
      }
    }, 1500);

  } catch(e){
    btn.disabled = false;
    btn.textContent = "Run";
    res.innerHTML = `<div style="color:var(--red)">Error: ${e.message}</div>`;
  }
}

function viewReconResult(cid, moduleId){
  const s = reconState[cid]?.[moduleId];
  if(!s||!s.data) return;
  const data = s.data.data||s.data;
  const pre = document.createElement("pre");
  pre.style.cssText="position:fixed;top:5vh;left:5vw;width:90vw;height:90vh;background:#0b0e18;color:#e2e8f0;border:1px solid #1e2d45;border-radius:10px;padding:20px;overflow:auto;z-index:9999;font-size:12px;line-height:1.5";
  pre.textContent = JSON.stringify(data, null, 2);
  const close = document.createElement("button");
 close.textContent=" Close";
  close.style.cssText="position:fixed;top:calc(5vh + 10px);right:calc(5vw + 16px);z-index:10000;background:#f43f5e;color:#fff;border:none;border-radius:6px;padding:5px 12px;cursor:pointer;font-size:13px";
  close.onclick=()=>{document.body.removeChild(pre);document.body.removeChild(close);};
  document.body.appendChild(pre);
  document.body.appendChild(close);
}

// ── Tool Logs tab ─────────────────────────────────���──────────────────────────
let _tlData = [];
let _tlFilter = "";
let _tlStatusFilter = "";
let _tlToolFilter = "";
let _tlPage = 1;
const _tlOpenGroups = new Set();
const _tlVirtualRuns = new Map();
const TLP = 40;

async function loadToolLogs() {
  const cid = state.currentId;
  if (!cid) return;
  const el = document.getElementById("tab-toollogs");
  el.innerHTML = `<div style="color:var(--text3);font-size:0.8rem;padding:20px 0">Loading logs…</div>`;
  try {
    const r = await fetch(`/api/recon/${cid}/tool-logs`, {headers: _authHeaders()});
    if (!r.ok) throw await _apiErr(r);
    _tlData = await r.json();
    document.getElementById("tc-toollogs").textContent = _tlData.length || "";
    renderToolLogs(el);
  } catch(e) {
    el.innerHTML = `<div style="color:var(--red);font-size:0.8rem;padding:20px 0">Error: ${e.message}</div>`;
  }
}

function renderToolLogs(el) {
  if (!el) return;
  _tlVirtualRuns.clear();
  const q = (_tlFilter || "").toLowerCase();
  const tools = [...new Set(_tlData.map(r => _tlExactName(r)).filter(Boolean))].sort();
  const filtered = _tlData.filter(r => {
    const hay = [r.module, r.tool, r.binary, r.display_name, r.cmd, r.status, r.exit_code, r.ts].join(" ").toLowerCase();
    const st = _tlNormalizedStatus(r);
    return (!q || hay.includes(q)) &&
      (!_tlStatusFilter || st === _tlStatusFilter) &&
      (!_tlToolFilter || _tlExactName(r) === _tlToolFilter);
  });

  const doneCount = _tlData.filter(r => _tlNormalizedStatus(r) === "done").length;
  const runningCount = _tlData.filter(r => _tlNormalizedStatus(r) === "running").length;
  const skippedCount = _tlData.filter(r => _tlNormalizedStatus(r) === "skipped").length;
  const errCount = _tlData.filter(r => _tlNormalizedStatus(r) === "error").length;
  const timeoutCount = _tlData.filter(r => _tlNormalizedStatus(r) === "timeout").length;
  const totalDur = _tlData.reduce((s, r) => s + (Number(r.duration) || 0), 0);

  const groupsMap = new Map();
  filtered.forEach(r => {
    const key = _tlGroupKey(r);
    if (!groupsMap.has(key)) {
      groupsMap.set(key, {
        key,
        module: r.module || "unknown",
        tool: _tlExactName(r),
        binary: r.binary || r.script || "",
        runs: [],
      });
    }
    groupsMap.get(key).runs.push(r);
  });
  const groups = [...groupsMap.values()].map(g => {
    g.runs.sort((a, b) => String(b.ts || "").localeCompare(String(a.ts || "")));
    g.done = g.runs.filter(r => _tlNormalizedStatus(r) === "done").length;
    g.error = g.runs.filter(r => _tlNormalizedStatus(r) === "error").length;
    g.timeout = g.runs.filter(r => _tlNormalizedStatus(r) === "timeout").length;
    g.skipped = g.runs.filter(r => _tlNormalizedStatus(r) === "skipped").length;
    g.running = g.runs.filter(r => _tlNormalizedStatus(r) === "running").length;
    g.duration = g.runs.reduce((s, r) => s + (Number(r.duration) || 0), 0);
    g.latest = g.runs[0] || {};
    return g;
  }).sort((a, b) => {
    const scoreA = (a.error * 1000) + (a.timeout * 500) + (a.running * 250) + (a.skipped * 50);
    const scoreB = (b.error * 1000) + (b.timeout * 500) + (b.running * 250) + (b.skipped * 50);
    return (scoreB - scoreA) || String(b.latest.ts || "").localeCompare(String(a.latest.ts || ""));
  });

  const totPg = Math.max(1, Math.ceil(groups.length / TLP));
  _tlPage = Math.max(1, Math.min(_tlPage, totPg));
  const start = (_tlPage - 1) * TLP;
  const pageGroups = groups.slice(start, start + TLP);
  const groupCards = pageGroups.map(_tlGroupCard).join("");

  const errBadge = errCount > 0
    ? `<span class="tl-err-badge" title="${errCount} tool error(s)">${errCount} error${errCount>1?'s':''}</span>` : "";
  const warnBadge = timeoutCount > 0
    ? `<span class="tl-warn-badge">${timeoutCount} timeout${timeoutCount>1?'s':''}</span>` : "";
  const pNums = _tlPager(totPg);

  el.innerHTML = `
    <div class="section-shell">
    <div class="section-head">
      <div class="section-head-main">
        <div class="section-kicker">Execution Logs ${errBadge}${warnBadge}</div>
        <div class="section-title">Ferramentas executadas neste projeto</div>
        <div class="section-sub">Agrupado pelo nome exato do executável/script que rodou. Clique em <code>dig</code>, <code>subfinder</code>, <code>httpx</code> etc. para ver comandos; clique em uma execução para abrir stdout/stderr completo.</div>
      </div>
      <div class="section-actions"><span class="sec-cnt">${groups.length} grupos · ${filtered.length} runs</span></div>
    </div>
    <div class="jobs-summary tl-summary">
      ${_tlKpi("Total", _tlData.length, "Runs registrados")}
      ${_tlKpi("Passou", doneCount, "Status done", "ok")}
      ${_tlKpi("Erro", errCount, "Exit/code failure", errCount ? "error" : "")}
      ${_tlKpi("Pulado", skippedCount, "Com justificativa")}
      ${_tlKpi("Rodando", runningCount, "Ainda sem finish", runningCount ? "running" : "")}
      ${_tlKpi("Tempo", _fmtDuration(totalDur), "Soma das execuções")}
    </div>
    <div class="tl-bar">
      <input class="tl-input grow" placeholder="Buscar por módulo, ferramenta, comando, status..." oninput="_tlFilter=this.value;_tlPage=1;renderToolLogs(document.getElementById('tab-toollogs'))" value="${esc(_tlFilter)}">
      <select class="fi" onchange="_tlStatusFilter=this.value;_tlPage=1;renderToolLogs(document.getElementById('tab-toollogs'))">
        <option value="" ${!_tlStatusFilter ? "selected" : ""}>Todos status</option>
        <option value="done" ${_tlStatusFilter==="done" ? "selected" : ""}>Passou</option>
        <option value="error" ${_tlStatusFilter==="error" ? "selected" : ""}>Erro</option>
        <option value="timeout" ${_tlStatusFilter==="timeout" ? "selected" : ""}>Timeout</option>
        <option value="skipped" ${_tlStatusFilter==="skipped" ? "selected" : ""}>Pulado</option>
        <option value="running" ${_tlStatusFilter==="running" ? "selected" : ""}>Rodando</option>
      </select>
      <select class="fi" onchange="_tlToolFilter=this.value;_tlPage=1;renderToolLogs(document.getElementById('tab-toollogs'))">
        <option value="" ${!_tlToolFilter ? "selected" : ""}>Todas ferramentas/scripts</option>
        ${tools.map(t => `<option value="${escAttr(t)}" ${_tlToolFilter===t ? "selected" : ""}>${esc(t)}</option>`).join("")}
      </select>
      <button class="tl-refresh" onclick="loadToolLogs()">Refresh</button>
      <button class="tl-clear" onclick="clearToolLogs()">Clear</button>
      ${errCount > 0 ? `<button class="tl-filter-err" onclick="_tlStatusFilter='error';_tlPage=1;renderToolLogs(document.getElementById('tab-toollogs'))">Errors only</button>` : ""}
      <span class="tl-count">${groups.length} grupos / ${filtered.length} execuções</span>
    </div>
    <div class="tl-groups">
      ${groupCards || '<div class="empty"><b>Nenhuma ferramenta registrada</b>Nenhum comando foi capturado ainda para este projeto.</div>'}
      <div class="pager">
        <span class="pager-info">${groups.length ? `${start+1}-${Math.min(start+TLP, groups.length)} of ${groups.length} grupos` : "0 of 0"}</span>
        <div class="pager-btns">
          <button class="pb" onclick="tlPageNav(-1)" ${_tlPage<=1 ? "disabled" : ""}>Prev</button>
          <span>${pNums}</span>
          <button class="pb" onclick="tlPageNav(1)" ${_tlPage>=totPg ? "disabled" : ""}>Next</button>
        </div>
      </div>
    </div>
    </div>`;
}

function _tlGroupKey(r) {
  return _tlExactName(r);
}

function _tlExactName(r) {
  return r.display_name || _baseName(r.binary || r.script || "") || r.tool || "?";
}

function _baseName(path) {
  const value = String(path || "").replace(/\\/g, "/");
  return value.split("/").filter(Boolean).pop() || "";
}

function _tlGroupDomId(key) {
  return "tlgrp-" + btoa(unescape(encodeURIComponent(key))).replace(/[^a-zA-Z0-9]/g, "");
}

function _tlGroupCard(group) {
  const key = group.key;
  const open = _tlOpenGroups.has(key);
  const latestStatus = _tlNormalizedStatus(group.latest || {});
  const healthClass = group.error ? "error" : group.timeout ? "warn" : group.running ? "running" : group.skipped ? "skipped" : "ok";
  const statusBadge = group.error
    ? `<span class="tl-badge-err">${group.error} erro${group.error>1?"s":""}</span>`
    : group.timeout
    ? `<span class="tl-badge-warn">${group.timeout} timeout${group.timeout>1?"s":""}</span>`
    : group.running
    ? `<span class="tl-badge-run">${group.running} rodando</span>`
    : group.skipped
    ? `<span class="tl-badge-dim">${group.skipped} pulado${group.skipped>1?"s":""}</span>`
    : `<span class="tl-badge-ok">passou</span>`;
  const latest = group.latest || {};
  const runsHtml = open ? _tlGroupRuns(group.runs) : "";
  return `
    <div class="tl-group-card ${healthClass}">
      <button type="button" class="tl-group-head" onclick="_tlToggleGroup('${escAttr(key)}')">
        <div class="tl-group-main">
          <div class="tl-group-title">
            <span class="tl-group-tool">${esc(group.tool)}</span>
          </div>
          <div class="tl-group-sub">
            <span class="tl-group-module">${esc(group.module)}</span>
            ${group.binary ? `<span class="tl-group-path">${esc(group.binary)}</span>` : ""}
            <span>${esc(latest.cmd || "sem comando")}</span>
          </div>
        </div>
        <div class="tl-group-metrics">
          ${statusBadge}
          <span class="tl-pill">${group.runs.length} execuções</span>
          <span class="tl-pill">${_fmtDuration(group.duration)}</span>
          <span class="tl-pill">${esc(_fmtToolTs(latest.ts))}</span>
          <span class="tl-caret">${open ? "−" : "+"}</span>
        </div>
      </button>
      <div class="tl-group-body" id="${_tlGroupDomId(key)}" style="display:${open ? "block" : "none"}">
        ${runsHtml}
      </div>
    </div>`;
}

function _tlGroupRuns(runs) {
  const rows = runs.map(r => {
    const st = _tlNormalizedStatus(r);
    const runId = r.run_id != null ? String(r.run_id) : "";
    let clickable = "";
    if (runId) {
      clickable = ` onclick="event.stopPropagation();openToolLogModal('${esc(runId)}')"`;
    } else {
      const virtualId = "v" + (_tlVirtualRuns.size + 1);
      _tlVirtualRuns.set(virtualId, r);
      clickable = ` onclick="event.stopPropagation();openToolLogVirtual('${virtualId}')"`;
    }
    const outBits = [
      r.stdout_tail ? `<span class="tl-io tl-stdout-dot">stdout</span>` : "",
      r.stderr_tail ? `<span class="tl-io tl-stderr-dot">stderr</span>` : "",
    ].filter(Boolean).join(" ");
    return `<tr class="tl-clickable"${clickable}>
      <td class="tl-ts">${esc(_fmtToolTs(r.ts))}</td>
      <td class="tl-tool">${esc(_tlExactName(r))}</td>
      <td><span class="${_tlStatusClass(st)}">${esc(st)}</span></td>
      <td class="tl-exit">${r.exit_code != null ? esc(r.exit_code) : "—"}</td>
      <td class="tl-dur">${_fmtDuration(r.duration)}</td>
      <td class="tl-cmd"><div class="tl-cmd-main">${esc(r.cmd || "—")}</div>${outBits ? `<div class="tl-io-row">${outBits}</div>` : ""}</td>
    </tr>`;
  }).join("");
  return `
    <div class="tl-wrap">
      <table class="tl-table tl-runs-table">
        <thead><tr><th>Quando</th><th>Ferramenta/script</th><th>Status</th><th>Exit</th><th>Duração</th><th>Comando / output</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function _tlToggleGroup(key) {
  if (_tlOpenGroups.has(key)) _tlOpenGroups.delete(key);
  else _tlOpenGroups.add(key);
  renderToolLogs(document.getElementById("tab-toollogs"));
}

function _tlNormalizedStatus(r) {
  if (r.status === "timeout") return "timeout";
  if (r.status === "running") return "running";
  if (r.status === "skipped" || r.status === "not_run") return "skipped";
  if (r.status === "error" || (r.exit_code != null && Number(r.exit_code) !== 0)) return "error";
  if (r.status === "done" || Number(r.exit_code) === 0) return "done";
  return r.status || "unknown";
}

function _tlStatusClass(st) {
  if (st === "error") return "tl-badge-err";
  if (st === "timeout") return "tl-badge-warn";
  if (st === "done") return "tl-badge-ok";
  if (st === "running") return "tl-badge-run";
  if (st === "skipped") return "tl-badge-dim";
  return "tl-badge-dim";
}

function _fmtDuration(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n >= 3600) return (n / 3600).toFixed(1) + "h";
  if (n >= 60) return (n / 60).toFixed(1) + "m";
  return n.toFixed(1) + "s";
}

function _fmtToolTs(value) {
  if (!value) return "—";
  return String(value).replace("T", " ").slice(0, 19);
}

function _tlKpi(label, value, sub, mood) {
  const cls = mood ? ` ${mood}` : "";
  return `<div class="job-kpi tl-kpi${cls}">
    <div class="job-kpi-label">${esc(label)}</div>
    <div class="job-kpi-value">${esc(value)}</div>
    <div class="job-kpi-sub">${esc(sub || "")}</div>
  </div>`;
}

function _tlPager(totPg) {
  let out = "";
  for (let i = Math.max(1, _tlPage - 2); i <= Math.min(totPg, _tlPage + 2); i++) {
    out += `<button class="pb${i === _tlPage ? " active" : ""}" onclick="tlGoPage(${i})">${i}</button>`;
  }
  return out;
}

function tlPageNav(delta) {
  _tlPage += delta;
  renderToolLogs(document.getElementById("tab-toollogs"));
}

function tlGoPage(page) {
  _tlPage = page;
  renderToolLogs(document.getElementById("tab-toollogs"));
}

async function clearToolLogs() {
  const cid = state.currentId;
  if (!cid) return;
  await fetch(`/api/recon/${cid}/tool-logs`, {method:"DELETE", headers: _authHeaders()});
  _tlData = [];
  _tlFilter = "";
   document.getElementById("tc-toollogs").textContent = "";
   renderToolLogs(document.getElementById("tab-toollogs"));
 }

// ── Tool Execution Detail Modal ───────────────────────────────────────────
function _renderToolLogDetail(d) {
  const titleEl = document.getElementById("tool-err-title");
  const bodyEl  = document.getElementById("tool-err-body");
  const status = _tlNormalizedStatus(d);
  const statusBadge = `<span class="${_tlStatusClass(status)}">${esc(status)}</span>`;
  const exitBadge = d.exit_code !== null && d.exit_code !== undefined
    ? (d.exit_code === 0 ? `<span class="tl-badge-ok">exit ${d.exit_code}</span>` : `<span class="tl-badge-err">exit ${d.exit_code}</span>`)
    : `<span class="tl-badge-dim">exit —</span>`;
  const durStr = _fmtDuration(d.duration);
  const stderrBlock = d.stderr_tail
    ? `<div style="margin-top:10px"><div class="tl-modal-label err">STDERR / erro</div><pre class="tool-err-pre">${esc(d.stderr_tail)}</pre></div>`
    : `<div style="margin-top:8px;color:var(--text3);font-size:.68rem">No stderr/error output captured.</div>`;
  const stdoutText = d.stdout_tail
    || (d.kind === "module"
      ? "Módulo interno não retornou payload detalhado."
      : "Comando executou e não escreveu nada em stdout. Isso é normal para consultas sem resultado, por exemplo dig CAA/SRV/CNAME sem registro.");
  const stdoutBlock = `<div style="margin-top:10px"><div class="tl-modal-label ok">STDOUT / output</div><pre class="tool-err-pre">${esc(stdoutText)}</pre></div>`;
  const exactName = _tlExactName(d);
  const exactPath = d.binary || d.script || (Array.isArray(d.argv) ? d.argv[0] : "");
  const commandLabel = d.kind === "module" ? "Module execution" : "Command";

  titleEl.textContent = exactName;
  bodyEl.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px">
      <div><span style="color:var(--text3);font-size:.68rem">Ferramenta / script / módulo</span><div style="margin-top:2px;color:var(--yellow);font-family:var(--mono);font-weight:700">${esc(exactName)}</div></div>
      <div><span style="color:var(--text3);font-size:.68rem">Módulo</span><div style="margin-top:2px;color:var(--teal);font-family:var(--mono)">${esc(d.module || "?")}</div></div>
      <div style="grid-column:1/-1"><span style="color:var(--text3);font-size:.68rem">Caminho exato</span><div style="margin-top:2px;color:var(--text);font-family:var(--mono);font-size:.68rem;word-break:break-all">${esc(exactPath || (d.kind === "module" ? "internal pipeline module" : "?"))}</div></div>
      <div><span style="color:var(--text3);font-size:.68rem">Status</span><div style="margin-top:2px">${statusBadge}</div></div>
      <div><span style="color:var(--text3);font-size:.68rem">Exit Code</span><div style="margin-top:2px">${exitBadge}</div></div>
      <div><span style="color:var(--text3);font-size:.68rem">Duration</span><div style="margin-top:2px;color:var(--text);font-family:var(--mono)">${durStr}</div></div>
      <div><span style="color:var(--text3);font-size:.68rem">Started</span><div style="margin-top:2px;color:var(--text);font-family:var(--mono);font-size:.68rem">${esc(d.ts || "?")}</div></div>
      <div style="grid-column:1/-1"><span style="color:var(--text3);font-size:.68rem">Finished</span><div style="margin-top:2px;color:var(--text);font-family:var(--mono);font-size:.68rem">${esc(d.finished_at || "?")}</div></div>
    </div>
    <div style="margin-bottom:8px">
      <div style="color:var(--text3);font-size:.68rem;margin-bottom:3px">${commandLabel}</div>
      <pre class="tool-err-pre" style="background:rgba(0,0,0,0.3);border-color:rgba(255,255,255,0.1)">${esc(d.cmd || "?")}</pre>
    </div>
    ${stderrBlock}
    ${stdoutBlock}
  `;
}

async function openToolLogModal(runId) {
  const cid = state.currentId;
  if (!cid || !runId) return;
  const overlay = document.getElementById("modal-tool-err");
  const titleEl = document.getElementById("tool-err-title");
  const bodyEl  = document.getElementById("tool-err-body");
  if (!overlay) return;

  titleEl.textContent = "Loading execution log...";
  bodyEl.innerHTML = `<div style="color:var(--text3);padding:20px">Fetching tool run #${runId}...</div>`;
  overlay.classList.add("show");

  try {
    const r = await fetch(`/api/recon/${cid}/tool-logs/${runId}`, {headers: _authHeaders()});
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json();
    _renderToolLogDetail(d);
  } catch(e) {
    titleEl.textContent = "Error loading execution log";
    bodyEl.innerHTML = `<div style="color:var(--red);padding:12px">Failed to load tool run details: ${esc(e.message)}</div>`;
  }
}

function openToolLogVirtual(virtualId) {
  const d = _tlVirtualRuns.get(virtualId);
  if (!d) return;
  const overlay = document.getElementById("modal-tool-err");
  if (!overlay) return;
  overlay.classList.add("show");
  _renderToolLogDetail(d);
}

async function openToolErrModal(runId) {
  return openToolLogModal(runId);
}

function closeToolErrModal() {
  document.getElementById("modal-tool-err").classList.remove("show");
}
