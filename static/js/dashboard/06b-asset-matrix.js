// ════════════════════════════════════════════════════════════════════════
//  MATRIZ DE ATIVOS — tela principal: um host por linha, uma coluna por assunto
//  (achados, CVE, secrets, endpoints, portas, infra, tech, captura) + filtros e colunas ajustáveis.
//  As funções de render de 06-hosts-ports-subdomains.js chamam este módulo em tempo de execução.
// ════════════════════════════════════════════════════════════════════════

const _SEV_KEYS = ["critical", "high", "medium", "low"];
const _SEV_PT = {critical: "críticos", high: "altos", medium: "médios", low: "baixos"};

function _hostFromAny(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  if (/^https?:\/\//i.test(raw)) {
    try { return _normalizeScopeDomain(new URL(raw).hostname); } catch (e) { return ""; }
  }
  return /^[a-z0-9._-]+\.[a-z]{2,}$/i.test(raw.split("/")[0]) ? _normalizeScopeDomain(raw) : "";
}

// Agregados por host: achados por severidade, CVEs, secrets e endpoints. Cacheado por empresa.
function _assetAgg(co) {
  const stamp = [(co.findings || []).length, (co.cve_findings || []).length, _epDataStamp(co)].join(":");
  if (co._assetAgg && co._assetAggStamp === stamp) return co._assetAgg;
  const map = new Map();
  const slot = host => {
    if (!host) return null;
    let a = map.get(host);
    if (!a) { a = {sev: {critical: 0, high: 0, medium: 0, low: 0}, findings: 0, cve: 0, secrets: 0, endpoints: 0, score: 0}; map.set(host, a); }
    return a;
  };
  (co.findings || []).forEach(f => {
    const sev = String(f.severity || "info").toLowerCase();
    const hosts = new Set();
    (Array.isArray(f.affected_hosts) ? f.affected_hosts : []).forEach(h => hosts.add(_hostFromAny(h)));
    hosts.add(_hostFromAny(f.host));
    hosts.add(_hostFromAny(f.domain));
    hosts.add(_hostFromAny(f.url));
    hosts.forEach(h => {
      const a = slot(h);
      if (!a) return;
      if (_SEV_KEYS.includes(sev)) { a.sev[sev]++; a.findings++; }
      if (f.type === "cve") a.cve++;
    });
  });
  try { buildUnifiedEndpoints(co); } catch (e) { /* sem dados de endpoints ainda */ }
  (co._unifiedEndpoints || []).forEach(ep => {
    const a = slot(_hostFromAny(ep.host) || _hostFromAny(ep.url));
    if (a) a.endpoints++;
  });
  (co._unifiedSecrets || []).forEach(s => {
    const a = slot(_hostFromAny(s.host) || _hostFromAny(s.url));
    if (a) a.secrets++;
  });
  map.forEach(a => { a.score = a.sev.critical * 1000 + a.sev.high * 100 + a.sev.medium * 10 + a.sev.low; });
  co._assetAgg = map;
  co._assetAggStamp = stamp;
  return map;
}

const _EMPTY_AGG = {sev: {critical: 0, high: 0, medium: 0, low: 0}, findings: 0, cve: 0, secrets: 0, endpoints: 0, score: 0};
const _aggOf = h => h._agg || _EMPTY_AGG;
const _dash = '<span class="ai-dash">—</span>';

function _countCell(n, cls) {
  return n > 0 ? `<span class="am-count ${cls}">${n}</span>` : _dash;
}

function _findingsCell(h) {
  const a = _aggOf(h);
  const chips = _SEV_KEYS.filter(s => a.sev[s] > 0)
    .map(s => `<span class="am-sev am-${s}" title="${a.sev[s]} ${_SEV_PT[s]}">${a.sev[s]}</span>`).join("");
  return chips ? `<div class="am-sev-row">${chips}</div>` : _dash;
}

function _urlOf(h) {
  const scheme = (h.status_code || (h.ports || []).includes("443") || !(h.ports || []).includes("80")) ? "https" : "http";
  return `${scheme}://${h.host}/`;
}

// Definição das colunas: key, rótulo, se aparece por padrão, valor de ordenação e célula.
const _ASSET_COLS = [
  {key: "url", label: "URL", always: true, val: h => h.host, td: (h, ctx) => {
    const url = _urlOf(h);
    const copyLbl = typeof t === "function" ? t("ai_copy_url") : "Copiar URL";
    const openLbl = typeof t === "function" ? t("ai_open_url") : "Abrir URL";
    return `<td class="ai-url-cell">
      <button type="button" class="ai-mini" title="${esc(copyLbl)}" aria-label="${esc(copyLbl)}" onclick="event.stopPropagation();copyToClipboard('${escAttr(url)}')">${icoHtml("clipboard",16)}</button>
      <a class="ai-mini" href="${escAttr(url)}" target="_blank" rel="noopener" title="${esc(openLbl)}" aria-label="${esc(openLbl)}" onclick="event.stopPropagation()">${icoHtml("link",16)}</a>
      <a class="ai-url" href="${escAttr(url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${esc(url)}</a>
    </td>`;
  }},
  {key: "status", label: "Status", on: true, val: h => Number(h.status_code || 0), td: h => {
    const sc = h.status_code;
    const cls = sc ? (sc < 300 ? "s2" : sc < 400 ? "s3" : sc < 500 ? "s4" : "s5") : "na";
    return `<td><span class="ai-status ${cls}">${sc}</span></td>`;
  }},
  {key: "domain", label: "Domínio", val: h => h._domain || "", td: h => `<td class="ai-ip">${h._domain ? esc(h._domain) : _dash}</td>`},
  {key: "findings", label: "Achados", on: true, val: h => _aggOf(h).score, td: h => `<td>${_findingsCell(h)}</td>`},
  {key: "cve", label: "CVE", on: true, val: h => _aggOf(h).cve, td: h => `<td class="am-num">${_countCell(_aggOf(h).cve, "am-cve")}</td>`},
  {key: "secrets", label: "Secrets", on: true, val: h => _aggOf(h).secrets, td: h => `<td class="am-num">${_countCell(_aggOf(h).secrets, "am-secret")}</td>`},
  {key: "endpoints", label: "Endpoints", on: true, val: h => _aggOf(h).endpoints, td: h => `<td class="am-num">${_countCell(_aggOf(h).endpoints, "am-ep")}</td>`},
  {key: "ports", label: "Portas", on: true, val: h => _hostOpenPorts(h).length, td: (h, ctx) => `<td class="ai-cl">${_fmtHostPorts(h, ctx.running)}</td>`},
  {key: "infra", label: "Infra", on: true, val: h => String(h.waf || "Direct"), td: h => {
    const chips = _hostInfraSignals(h).map(s => _infraChip(s.label, s.cls, s.title)).join("");
    return `<td><div class="ai-tech-row">${chips || _dash}</div></td>`;
  }},
  {key: "tech", label: "Tech", on: true, val: h => (h.technologies || []).length, td: h => {
    const infra = new Set(_hostInfraSignals(h).map(s => s.label.toLowerCase()));
    const techs = _hostTechLabels(h).filter(x => !infra.has(x.toLowerCase()));
    const shown = techs.slice(0, 3).map(_techChip).join("");
    const more = techs.length > 3 ? `<span class="ai-tech ai-tech-more">+${techs.length - 3}</span>` : "";
    return `<td><div class="ai-tech-row">${shown || more ? shown + more : _dash}</div></td>`;
  }},
  {key: "title", label: "Título", on: true, val: h => h.title || "", td: (h, ctx) =>
    `<td class="ai-title" title="${escAttr(h.title || "")}">${h.title ? esc(h.title) : (ctx.running ? _assetPendingCell() : _dash)}</td>`},
  {key: "ip", label: "IP", on: true, val: h => h.ip || "", td: (h, ctx) =>
    `<td class="ai-ip">${h.ip ? esc(h.ip) : (ctx.running ? _assetPendingCell() : _dash)}</td>`},
  {key: "shot", label: "Captura", on: true, noSort: true, th: 'style="width:88px"', td: (h, ctx) => {
    const shotSrc = _shotSrc(h.screenshot);
    const shotLbl = typeof t === "function" ? t("ai_open_shot") : "Abrir screenshot";
    const cell = shotSrc
      ? `<button type="button" class="ai-shot-btn" aria-label="${esc(shotLbl + " · " + (h.host || ""))}" onmouseenter="ssPopoverShow(event,${_shotJs(shotSrc)},${_shotJs(h.host || "")})" onmouseleave="ssPopoverHide()" onclick="event.stopPropagation();ssLightboxOpen(${_shotJs(shotSrc)},${_shotJs(h.host || _urlOf(h))})"><img src="${esc(shotSrc)}" alt="${esc("Screenshot de " + (h.host || ""))}" onerror="this.closest('.ai-shot-btn').style.display='none'"></button>`
      : (ctx.running ? _assetPendingCell() : _dash);
    return `<td class="ai-shot">${cell}</td>`;
  }},
  {key: "actions", label: "Ações", always: true, noSort: true, thClass: "ai-actions-h", td: h => {
    const viewLbl = typeof t === "function" ? t("ai_view_host") : "Ver detalhes";
    return `<td class="ai-actions"><button type="button" class="ai-eye" title="${esc(viewLbl)}" aria-label="${esc(viewLbl)}" onclick="event.stopPropagation();openHostDrawer('${escAttr(h.host)}')">${icoHtml("eye",16)}</button></td>`;
  }},
];
const _ASSET_COL = Object.fromEntries(_ASSET_COLS.map(c => [c.key, c]));

// Colunas visíveis (persistidas no navegador).
function _assetVisibleCols() {
  let saved = null;
  try { saved = JSON.parse(localStorage.getItem("asm_asset_cols") || "null"); } catch (e) {}
  return _ASSET_COLS.filter(c => c.always || (saved ? saved.includes(c.key) : c.on));
}
function assetToggleCol(key, on) {
  const cur = new Set(_assetVisibleCols().map(c => c.key));
  on ? cur.add(key) : cur.delete(key);
  try { localStorage.setItem("asm_asset_cols", JSON.stringify([...cur])); } catch (e) {}
  _subRerender();
}
function _subRerender() {
  const head = document.getElementById("sub-thead");
  if (head) head.innerHTML = _assetTheadHtml();
  const menu = document.getElementById("sub-colmenu");
  if (menu) menu.innerHTML = _assetColMenuHtml();
  _subRenderTable(_subFiltered());
}

function _assetTheadHtml() {
  return `<tr>${_assetVisibleCols().map(c => {
    const sort = c.noSort ? "" : ` onclick="_subSort('${c.key}')"`;
    const arrow = c.noSort ? "" : (_sub_sort === c.key ? (_sub_asc ? " ▲" : " ▼") : " ⇅");
    return `<th${sort} ${c.th || ""}${c.thClass ? ` class="${c.thClass}"` : ""}>${esc(c.label)}${arrow}</th>`;
  }).join("")}</tr>`;
}

function _assetColMenuHtml() {
  const vis = new Set(_assetVisibleCols().map(c => c.key));
  return _ASSET_COLS.filter(c => !c.always).map(c =>
    `<label class="am-colopt"><input type="checkbox" ${vis.has(c.key) ? "checked" : ""} onchange="assetToggleCol('${c.key}', this.checked)"> ${esc(c.label)}</label>`).join("");
}

// Filtros extras + atalhos (chips) ---------------------------------------------------------
const _FIND_FILTERS = {
  any:      h => _aggOf(h).findings > 0,
  critical: h => _aggOf(h).sev.critical > 0,
  high:     h => _aggOf(h).sev.critical + _aggOf(h).sev.high > 0,
  medium:   h => _aggOf(h).sev.critical + _aggOf(h).sev.high + _aggOf(h).sev.medium > 0,
  none:     h => _aggOf(h).findings === 0,
};
const _HAS_FILTERS = {
  secrets:   h => _aggOf(h).secrets > 0,
  cve:       h => _aggOf(h).cve > 0,
  endpoints: h => _aggOf(h).endpoints > 0,
  riskport:  h => _hostOpenPorts(h).some(p => _isHighRiskPort(p.port, p.service)),
  nowaf:     h => !h.waf || /^direct$/i.test(String(h.waf)),
  shot:      h => !!h.screenshot,
};

function _assetQuickChips(hosts) {
  const defs = [
    ["find", "critical", "Críticos", _FIND_FILTERS.critical],
    ["find", "high", "Alto ou crítico", _FIND_FILTERS.high],
    ["has", "secrets", "Com secrets", _HAS_FILTERS.secrets],
    ["has", "cve", "Com CVE", _HAS_FILTERS.cve],
    ["has", "riskport", "Porta sensível", _HAS_FILTERS.riskport],
    ["has", "nowaf", "Sem WAF", _HAS_FILTERS.nowaf],
  ];
  const cur = {find: document.getElementById("sub-find")?.value || "", has: document.getElementById("sub-has")?.value || ""};
  const chips = defs.map(([kind, val, label, fn]) => {
    const n = hosts.filter(fn).length;
    return `<button type="button" class="am-chip${cur[kind] === val ? " active" : ""}" onclick="assetQuickFilter('${kind}','${val}')" ${n ? "" : "disabled"}>${esc(label)} <b>${n}</b></button>`;
  }).join("");
  const any = cur.find || cur.has || document.getElementById("sub-dom")?.value;
  return chips + (any ? `<button type="button" class="am-chip am-clear" onclick="assetQuickFilter('clear')">Limpar filtros</button>` : "");
}

function assetQuickFilter(kind, val) {
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  if (kind === "clear") { ["sub-find", "sub-has", "sub-dom", "sub-status", "sub-tech", "sub-port", "sub-risk", "sub-waf"].forEach(id => set(id, "")); set("sub-search", ""); }
  else {
    const id = kind === "find" ? "sub-find" : "sub-has";
    const el = document.getElementById(id);
    set(id, el && el.value === val ? "" : val);   // clicar de novo desliga
  }
  _subApplyFilter();
}

function _assetExtraFilterHtml(hosts) {
  const doms = [...new Set(hosts.map(h => h._domain).filter(Boolean))].sort();
  return `
    <select class="ai-drop" id="sub-find" onchange="_subApplyFilter()" aria-label="Achados">
      <option value="">Achados</option>
      <option value="any">Com achados</option>
      <option value="critical">Críticos</option>
      <option value="high">Alto ou crítico</option>
      <option value="medium">Médio ou pior</option>
      <option value="none">Sem achados</option>
    </select>
    <select class="ai-drop" id="sub-has" onchange="_subApplyFilter()" aria-label="Contém">
      <option value="">Contém</option>
      <option value="secrets">Secrets</option>
      <option value="cve">CVE</option>
      <option value="endpoints">Endpoints</option>
      <option value="riskport">Porta sensível</option>
      <option value="nowaf">Sem WAF/CDN</option>
      <option value="shot">Com captura</option>
    </select>
    ${doms.length > 1 ? `<select class="ai-drop" id="sub-dom" onchange="_subApplyFilter()" aria-label="Domínio">
      <option value="">Domínio</option>${doms.map(d => `<option value="${escAttr(d)}">${esc(d)}</option>`).join("")}
    </select>` : ""}`;
}
