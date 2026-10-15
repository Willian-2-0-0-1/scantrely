// ════════════════════════════════════════════════════════════════════════
//  HOSTS TAB
// ════════════════════════════════════════════════════════════════════════
let _co_hosts = [], _hosts_page = 1, _hosts_sort = "host", _hosts_asc = true;
const HPP = 30;

function _paintCrawlHostInventory(mount, crawl) {
  if (!mount) return;
  if (!crawl.length) {
    mount.innerHTML = "";
    return;
  }
  const chips = crawl.slice(0, 24).map(r => {
    const pages = r.pages == null ? "—" : String(r.pages);
    return `<code class="fg-host-chip fg-host-chip-full" title="${esc(r.url || "")}">${esc(r.host || "")} · ${esc(pages)}</code>`;
  }).join("");
  mount.innerHTML = `
    <div class="job-detail-card">
      <div class="job-detail-title">${esc(_opT("op_hosts_title", "Inventário de hosts"))}</div>
      <div class="job-detail-copy">${esc(_opT("op_hosts_copy", "Hosts visitados pela pipeline (browser_crawl). Enfileire o Playwright Recon para a sessão de pentest."))}</div>
      <div class="chip-row" style="margin-top:10px">${chips}</div>
    </div>
  `;
}

async function renderPlaywrightHostInventoryTab(co) {
  const mount = document.getElementById("playwright-host-inventory");
  if (!mount || !co?.id) return;
  const persist = _opSummarize(co);
  const crawl = persist.crawl || [];
  _paintCrawlHostInventory(mount, crawl);
  try {
    const r = await fetch(`/api/jobs?company_id=${encodeURIComponent(co.id)}&limit=20`, {headers:_authHeaders()});
    if (!r.ok) throw new Error("HTTP " + r.status);
    const jobs = await r.json();
    const job = (jobs || []).find(j => j.job_type === "playwright_recon");
    if (!job) return;
    const sessionResp = await fetch(_jobArtifactUrl(job.id, "session"), {headers:_authHeaders()});
    if (!sessionResp.ok) return;
    const session = await sessionResp.json();
    mount.innerHTML = `
      <div class="job-detail-card">
        <div class="job-detail-head">
          <div>
            <div class="job-detail-title">${esc(_opT("op_hosts_title", "Inventário de hosts"))}</div>
            <div class="job-detail-copy">${esc(job.id)} · ${esc(job.status || "—")} · ${esc(job.created_at || "—")}</div>
          </div>
          <div class="job-actions">
            <button type="button" class="btn btn-secondary btn-icon" onclick="openJobDetail(${_jsArg(job.id)})">${esc(_opT("op_details", "Detalhes"))}</button>
            ${job.status === "done" ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'session')}" target="_blank" rel="noopener">${esc(_opT("op_session", "Sessão"))}</a>` : ""}
          </div>
        </div>
        ${_playwrightInventorySummary(session)}
      </div>
    `;
  } catch (e) {
    if (!crawl.length) mount.innerHTML = "";
  }
}

function _hostTechHay(h) {
  const techs = h.technologies || h.techs || [];
  return (Array.isArray(techs) ? techs : [techs]).join(",").toLowerCase();
}

function _filteredHosts() {
  const q  = (document.getElementById("h-search")?.value || "").toLowerCase();
  const wf = document.getElementById("h-waf")?.value || "";
  const st = document.getElementById("h-status")?.value || "";
  return _co_hosts.filter(h => {
    const hay = `${h.host || ""} ${h.ip || ""} ${_hostTechHay(h)}`.toLowerCase();
    const ms = !q || hay.includes(q);
    const ports = h.ports || [];
    return ms && (!wf || (h.waf || "").includes(wf)) &&
      (!st || (st === "active" && ports.length > 0) || (st === "inactive" && ports.length === 0));
  });
}

function hostsPageNav(d) {
  const filtered = _filteredHosts();
  const totPg = Math.ceil(filtered.length / HPP) || 1;
  _hosts_page = Math.max(1, Math.min(totPg, _hosts_page + d));
  renderHostsTable(filtered);
}

function hostsGoPage(p) { _hosts_page=p; hostsPageNav(0); }

function renderHostsTable(filtered) {
  const tot=filtered.length, totPg=Math.ceil(tot/HPP);
  const st=(_hosts_page-1)*HPP, pg=filtered.slice(st,st+HPP);
  const cnt=document.getElementById("h-cnt"); if(cnt) cnt.textContent=tot+" hosts";
  const pi=document.getElementById("h-pinfo"); if(pi) pi.textContent=`${st+1}–${Math.min(st+HPP,tot)} of ${tot}`;
  const pr=document.getElementById("h-prev"); if(pr) pr.disabled=_hosts_page<=1;
  const nx=document.getElementById("h-next"); if(nx) nx.disabled=_hosts_page>=totPg;
  let pn="";
  for(let i=Math.max(1,_hosts_page-2);i<=Math.min(totPg,_hosts_page+2);i++)
    pn+=`<button class="pb${i===_hosts_page?" active":""}" onclick="hostsGoPage(${i})">${i}</button>`;
  const pne=document.getElementById("h-pnums"); if(pne) pne.innerHTML=pn;
  const tb=document.getElementById("h-tbody"); if(!tb) return;
  tb.innerHTML = pg.map(h=>_hostTableRow(h)).join("");
}

// ════════════════════════════════════════════════════════════════════════
//  PORTS TAB
// ════════════════════════════════════════════════════════════════════════
let _co_ports = [], _ports_page = 1;
const PPP = 25;

function portsPageNav(d) {
  const q=document.getElementById("p-search")?.value.toLowerCase()||"";
  const pt=document.getElementById("p-port")?.value||"";
  const filtered=_co_ports.filter(h=>(!q||(h.host||"").includes(q)||(h.ip||"").includes(q))&&(!pt||(h.ports||[]).includes(pt)));
  const totPg=Math.ceil(filtered.length/PPP);
  _ports_page=Math.max(1,Math.min(totPg,_ports_page+d));
  renderPortsTable(filtered);
}

function portsGoPage(p){_ports_page=p;portsPageNav(0);}

function renderPortsTable(filtered) {
  const tot=filtered.length, totPg=Math.ceil(tot/PPP);
  const st=(_ports_page-1)*PPP, pg=filtered.slice(st,st+PPP);
  const cnt=document.getElementById("p-cnt"); if(cnt) cnt.textContent=tot+" hosts";
  const pi=document.getElementById("p-pinfo"); if(pi) pi.textContent=`${st+1}–${Math.min(st+PPP,tot)} of ${tot}`;
  let pn="";
  for(let i=Math.max(1,_ports_page-2);i<=Math.min(totPg,_ports_page+2);i++)
    pn+=`<button class="pb${i===_ports_page?" active":""}" onclick="portsGoPage(${i})">${i}</button>`;
  const pne=document.getElementById("p-pnums"); if(pne) pne.innerHTML=pn;
  const tb=document.getElementById("p-tbody"); if(!tb) return;
  tb.innerHTML=pg.map(h=>{
    const portDetails = h.port_details || [];
    const portMap = Object.fromEntries(portDetails.map(pd => [pd.port, pd]));
    const cloudLabel = h.cloud_provider ? ` <span class="waf-t" style="background:rgba(96,165,250,0.1);color:#60a5fa;border:1px solid rgba(96,165,250,0.2)">${icoHtml("cloud",14)} ${esc(h.cloud_provider)}</span>` : '';
    return `
    <tr class="clickable-host" onclick="openHostDrawer('${escAttr(h.host)}')">
      <td>
        <div class="host-cell">
          <a class="host-main" href="https://${h.host}" target="_blank">${esc(h.host)}</a>
          <span class="host-sub">${(h.title && esc(h.title)) || "Primary exposed host"}</span>
        </div>
      </td>
      <td><span class="ip-t">${esc(h.ip)}</span></td>
      <td><span class="waf-t ${wafClass(h.waf)}">${esc(h.waf)}</span>${cloudLabel}</td>
      <td><div class="badge-row">${(h.ports||[]).map(p=>{
        if (portMap[p]) return `<span class="port-c" title="${esc(portMap[p].category||'')}">${esc(p)}:${esc(portMap[p].service||'')}</span>`;
        return `<span class="port-c">${esc(p)}</span>`;
      }).join("")}</div></td>
      <td><span class="muted-kpi">${(h.ports||[]).length}</span></td>
      <td><button class="url-copy-btn" onclick="copyToClipboard('${escAttr(h.host)}');event.stopPropagation()" title="Copy hostname" style="font-size:.6rem;padding:2px 5px">${icoHtml("clipboard",14)}</button></td>
    </tr>`;
  }).join("");
}

// ════════════════════════════════════════════════════════════════════════
//  SUBDOMAINS TAB
// ════════════════════════════════════════════════════════════════════════
const ADMIN_PORT_LABELS = {
  "21":"FTP","22":"SSH","23":"Telnet","25":"SMTP","3306":"MySQL","5432":"PG",
  "6379":"Redis","27017":"Mongo","9200":"ES","2082":"cPanel","2083":"cPanel SSL",
  "2086":"WHM","2087":"WHM SSL","2095":"Webmail","2096":"Webmail SSL",
  "8080":"HTTP Alt","8443":"HTTPS Alt","8880":"HTTP Alt",
};
const WEB_PORTS = new Set(["80", "443", "8000", "8008", "8080", "8081", "8088", "8443", "8880"]);
const HIGH_RISK_PORT_LABELS = {
  "21":"FTP — plaintext file transfer",
  "22":"SSH",
  "23":"Telnet — plaintext shell",
  "25":"SMTP",
  "110":"POP3 — plaintext email",
  "143":"IMAP — plaintext email",
  "3306":"MySQL",
  "5432":"PostgreSQL",
  "6379":"Redis",
  "27017":"MongoDB",
  "9200":"Elasticsearch",
  "2082":"cPanel",
  "2083":"cPanel SSL",
  "2086":"WHM",
  "2087":"WHM SSL",
  "2095":"Webmail",
  "2096":"Webmail SSL",
};

let _sub_hosts = [], _sub_page = 1;

// Domains tab: cap how many domain cards render at once. Companies can have
// tens of thousands of scope domains; rendering one card each froze the UI.
const DOM_CARD_LIMIT = 50;
let _domBuckets = [], _domQuery = "";

function _normalizeScopeDomain(raw) {
  return String(raw || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/^\*\./, "")
    .replace(/\.$/, "")
    .toLowerCase();
}

function _buildSubdomainInventory(co, rows = []) {
  const merged = new Map();
  const techByHost = new Map();
  Object.entries(co.tech_index || {}).forEach(([tech, hosts]) => {
    (hosts || []).forEach(h => {
      const host = _normalizeScopeDomain(h);
      if (!host) return;
      if (!techByHost.has(host)) techByHost.set(host, new Set());
      techByHost.get(host).add(tech);
    });
  });

  const addHost = (item, source = "") => {
    if (!item) return;
    const host = _normalizeScopeDomain(item.host || item.subdomain || item.domain || "");
    if (!host) return;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return;
    const existing = merged.get(host) || {
      host,
      ip: item.ip || "",
      status_code: item.status_code,
      content_length: item.content_length,
      ports: Array.isArray(item.ports) ? item.ports.slice() : [],
      port_details: Array.isArray(item.port_details) ? item.port_details.slice() : [],
      waf: item.waf || "Direct",
      cloud_provider: item.cloud_provider || "",
      cert_info: item.cert_info || null,
      technologies: Array.isArray(item.technologies) ? item.technologies.slice() : [],
      title: item.title || "",
      screenshot: item.screenshot || (co._screenshotsByHost && co._screenshotsByHost.get(host)) || "",
      risk: item.risk || item.risk_level || item.severity || "",
      sources: [],
    };
    if (!existing.ip && item.ip) existing.ip = item.ip;
    if (existing.status_code == null && item.status_code != null) existing.status_code = item.status_code;
    if (existing.content_length == null && item.content_length != null) existing.content_length = item.content_length;
    if (Array.isArray(item.ports)) {
      item.ports.forEach(p => { if (!existing.ports.includes(p)) existing.ports.push(p); });
    }
    if (Array.isArray(item.port_details)) {
      existing.port_details = existing.port_details || [];
      item.port_details.forEach(p => {
        const port = String(p.port || p || "");
        if (port && !existing.port_details.some(x => String(x.port || x || "") === port)) existing.port_details.push(p);
      });
    }
    if (Array.isArray(item.technologies)) {
      item.technologies.forEach(t => { if (!existing.technologies.includes(t)) existing.technologies.push(t); });
    }
    const techSet = techByHost.get(host);
    if (techSet) {
      techSet.forEach(t => { if (!existing.technologies.includes(t)) existing.technologies.push(t); });
    }
    if (!existing.title && item.title) existing.title = item.title;
    if (!existing.risk && (item.risk || item.risk_level || item.severity)) existing.risk = item.risk || item.risk_level || item.severity;
    if (!existing.waf && item.waf) existing.waf = item.waf;
    if (!existing.cloud_provider && item.cloud_provider) existing.cloud_provider = item.cloud_provider;
    if (!existing.cert_info && item.cert_info) existing.cert_info = item.cert_info;
    if (!existing.screenshot && item.screenshot) existing.screenshot = item.screenshot;
    if (!existing.screenshot && co._screenshotsByHost && co._screenshotsByHost.has(host)) {
      existing.screenshot = co._screenshotsByHost.get(host);
    }
    if (source && !existing.sources.includes(source)) existing.sources.push(source);
    merged.set(host, existing);
  };

  (co.hosts || []).forEach(h => addHost(h, h.status_code != null ? "validated" : "host"));
  (co.ct_subdomains || []).forEach(s => addHost(typeof s === "string" ? {host: s} : s, "ct"));
  (rows || []).forEach(s => addHost({host: s.subdomain, status_code: s.is_alive ? 200 : null}, s.source || "history"));

  return Array.from(merged.values()).sort((a, b) => a.host.localeCompare(b.host));
}

function _matchDomainForHost(host, domains, domainSet) {
  const h = _normalizeScopeDomain(host);
  if (!h) return "";
  // Fast path: O(labels) suffix lookup against a Set instead of scanning/sorting
  // every scope domain per host (companies can have tens of thousands of domains).
  if (domainSet) {
    if (domainSet.has(h)) return h;
    const parts = h.split(".");
    for (let i = 1; i < parts.length; i++) {     // most specific (longest) suffix first
      const cand = parts.slice(i).join(".");
      if (domainSet.has(cand)) return cand;
    }
    return "";
  }
  const ordered = [...domains].sort((a, b) => b.length - a.length);
  for (const domain of ordered) {
    if (h === domain || h.endsWith("." + domain)) return domain;
  }
  return "";
}

function _loadSubdomainHistory(co) {
  if (!co) return Promise.resolve([]);
  if (Array.isArray(co.subdomain_history)) return Promise.resolve(co.subdomain_history);
  if (co._subhistoryPromise) return co._subhistoryPromise;
  co._subhistoryPromise = fetch(`/api/data/${co.id}/subhistory`, {headers: _authHeaders()})
    .then(r => r.ok ? r.json() : Promise.reject(r))
    .then(data => Array.isArray(data.history) ? data.history : [])
    .catch(() => []);
  return co._subhistoryPromise;
}

function _isActiveHost(h) {
  const sc = Number(h && h.status_code);
  return Number.isFinite(sc) && sc > 0;
}

function _isHighRiskPort(port, service = "") {
  const p = String(port || "").trim();
  if (!p || WEB_PORTS.has(p)) return false;
  if (HIGH_RISK_PORT_LABELS[p]) return true;
  return /ssh|ftp|telnet|mysql|postgres|redis|mongo|elastic|imap|pop3|smtp|cpanel|whm|webmail/i.test(String(service || ""));
}

function _portServiceLabel(port, service = "") {
  const p = String(port || "").trim();
  if (HIGH_RISK_PORT_LABELS[p]) return HIGH_RISK_PORT_LABELS[p];
  if (service) return service;
  if (ADMIN_PORT_LABELS[p]) return ADMIN_PORT_LABELS[p];
  if (p === "80") return "HTTP";
  if (p === "443") return "HTTPS";
  return "";
}

function _hostOpenPorts(h) {
  const raw = Array.isArray(h?.ports) ? h.ports : [];
  const details = Array.isArray(h?.port_details) ? h.port_details : [];
  const byPort = new Map();
  raw.forEach(p => {
    const port = String(p || "").trim();
    if (port) byPort.set(port, {port, service: _portServiceLabel(port)});
  });
  details.forEach(item => {
    const port = String(item?.port || item || "").trim();
    if (!port) return;
    byPort.set(port, {
      port,
      service: _portServiceLabel(port, item?.service || item?.name || ""),
      category: item?.category || "",
    });
  });
  return [...byPort.values()].sort((a, b) => Number(a.port) - Number(b.port));
}

function _assetPendingCell(label = "Running") {
  return `<span class="ai-pending" title="Coleta em andamento">${esc(label)}</span>`;
}

function _isAssetCollectionRunning() {
  return !!(state.currentId && typeof _isPipelineActive === "function" && _isPipelineActive(state.currentId));
}

function _fmtHostPorts(h, pending = false) {
  const ports = _hostOpenPorts(h);
  if (!ports.length) return pending ? _assetPendingCell() : `<span class="ai-dash">—</span>`;
  const shown = ports.slice(0, 4).map(p => {
    const label = p.service ? `${p.port}:${p.service}` : p.port;
    const risky = _isHighRiskPort(p.port, p.service);
    const title = p.category || p.service || "";
    return `<span class="ai-port ${risky ? "risk" : ""}" title="${escAttr(title)}">${esc(label)}</span>`;
  }).join("");
  const overflow = ports.length > 4 ? `<span class="ai-port more">+${ports.length - 4}</span>` : "";
  return `<div class="ai-port-row">${shown}${overflow}</div>`;
}



function _renderSubInventoryShell(co, resp, el) {
  // resp = resposta de /assets: {items, total, facets}. Filtros, ordenação e página são do servidor.
  const facets = resp.facets || {total: 0, status: {}, chips: {}, tech: [], ports: [], domains: []};
  _sub_hosts = resp.items || [];
  _sub_page = resp.page || 1;
  const tc = document.getElementById("tc-subdomains");
  if (tc) tc.textContent = facets.total || 0;

  if(!facets.total) {
    el.innerHTML = `<div id="playwright-host-inventory" class="ai-pw-inventory"></div>
      <div class="empty-state"><div class="empty-state-icon" data-ico="inbox" aria-hidden="true"></div><div class="empty-state-title">Nenhum host ativo encontrado</div><div class="empty-state-copy">A tabela de Hosts mostra somente dominios/subdominios com status HTTP real. Rode um scan para validar os ativos.</div></div>`;
    renderPlaywrightHostInventoryTab(co);
    if (typeof hydrateIcons === "function") hydrateIcons(el);
    return;
  }

    const checkpointInfo = co.checkpoint_diff || null;
    const newSubs = Array.isArray(checkpointInfo?.new_subdomains) ? checkpointInfo.new_subdomains : [];
    const newSubsHtml = newSubs.length
      ? newSubs.slice(0, 12).map(s => `<code class="fg-host-chip fg-host-chip-full" title="New since ${esc(checkpointInfo?.compared_to || 'previous scan')}">${esc(s)}</code>`).join("")
      : "";
    const hostSelector = "";

    const statBadges = _assetStatusBadges(facets.status);
    const techOptions = (facets.tech || [])
      .map(([name, n]) => `<option value="${escAttr(name)}">${esc(name)} (${n})</option>`).join("");
    const portOptions = (facets.ports || [])
      .map(([port, n]) => `<option value="${escAttr(port)}">${esc(port)}${ADMIN_PORT_LABELS[port] ? " · " + esc(ADMIN_PORT_LABELS[port]) : ""} (${n})</option>`).join("");
    const newHostsBanner = (checkpointInfo && checkpointInfo.new_subdomains_count > 0) ? `
      <div class="ai-newbanner">
        <span class="ai-newbanner-t">${icoHtml("bolt",14)} ${checkpointInfo.new_subdomains_count} new since last scan</span>
        <span class="ai-newbanner-s">compared to ${(checkpointInfo.compared_to||'').slice(0,19)}</span>
        ${newSubsHtml ? `<div class="ai-newbanner-chips">${newSubsHtml}</div>` : ""}
      </div>` : "";

    el.innerHTML = `
    ${hostSelector}
    <div class="ai-shell">
      <div class="ai-head">
        <div class="ai-head-l">
          <div class="ai-title">${esc(typeof t === "function" ? t("ai_title") : "Inventário de ativos")}</div>
          <div class="ai-sub"><span id="sub-cnt">${resp.total}</span> ${esc(typeof t === "function" ? t("ai_sub") : "ativos validados · sem n/a")}</div>
        </div>
        <div class="ai-head-r">
          ${statBadges}
          <button type="button" class="ai-refresh" onclick="switchHostsPanel('subdomains')" title="${esc(typeof t === "function" ? t("ai_refresh") : "Atualizar")}" aria-label="${esc(typeof t === "function" ? t("ai_refresh") : "Atualizar")}">${icoHtml("reload",14)} ${esc(typeof t === "function" ? t("ai_refresh") : "Atualizar")}</button>
          <details class="co-menu am-cols">
            <summary class="ai-icon-btn">Colunas ▾</summary>
            <div class="co-menu-list" id="sub-colmenu">${_assetColMenuHtml()}</div>
          </details>
          <button type="button" class="ai-icon-btn" onclick="exportHosts('csv')" title="Export CSV" aria-label="Export CSV">CSV</button>
          <button type="button" class="ai-icon-btn" onclick="exportHosts('json')" title="Export JSON" aria-label="Export JSON">JSON</button>
        </div>
      </div>
      ${newHostsBanner}
      <div class="ai-filter">
        <div class="ai-search">
          <span class="ai-search-ic" aria-hidden="true">${icoHtml("search",16)}</span>
          <label class="sr-only" for="sub-search">${esc(typeof t === "function" ? t("ai_search") : "Buscar host")}</label>
          <input id="sub-search" placeholder="${esc(typeof t === "function" ? t("ai_search_ph") : "Buscar dominio, subdominio, titulo, IP ou porta...")}" oninput="_subApplyFilter(1,false)">
        </div>
        <select class="ai-drop" id="sub-status" onchange="_subApplyFilter()" aria-label="Status HTTP">
          <option value="">Status HTTP</option>
          <option value="2">2xx — OK</option>
          <option value="3">3xx — Redirect</option>
          <option value="4">4xx — Bloqueado/cliente</option>
          <option value="5">5xx — Erro/risco</option>
        </select>
        <select class="ai-drop" id="sub-tech" onchange="_subApplyFilter()" aria-label="Tech / Infra">
          <option value="">Tech / Infra</option>
          ${techOptions}
        </select>
        <select class="ai-drop" id="sub-port" onchange="_subApplyFilter()" aria-label="${esc(typeof t === "function" ? t("ai_ports") : "Portas abertas")}">
          <option value="">${esc(typeof t === "function" ? t("ai_ports") : "Portas abertas")}</option>
          ${portOptions}
        </select>
        <select class="ai-drop" id="sub-risk" onchange="_subApplyFilter()" aria-label="${esc(typeof t === "function" ? t("ai_risk") : "Risco")}">
          <option value="">${esc(typeof t === "function" ? t("ai_risk") : "Risco")}</option>
          <option value="risk">${esc(typeof t === "function" ? t("ai_risk_yes") : "Com risco")}</option>
          <option value="clean">${esc(typeof t === "function" ? t("ai_risk_no") : "Sem risco")}</option>
        </select>
        <select class="ai-drop" id="sub-waf" onchange="_subApplyFilter()" aria-label="WAF / CDN">
          <option value="">WAF / CDN</option>
          <option value="Cloudflare">Cloudflare</option>
          <option value="Imperva">Imperva</option>
          <option value="AWS">AWS</option>
          <option value="Direct">Direct (no WAF)</option>
        </select>
        ${_assetExtraFilterHtml(facets)}
      </div>
      <div class="am-chips" id="sub-chips"></div>
      <div class="ai-table-wrap">
        <table class="ai-table">
          <thead id="sub-thead">${_assetTheadHtml()}</thead>
          <tbody id="sub-tbody"></tbody>
        </table>
        <div class="pager">
          <span class="pager-info" id="sub-pinfo"></span>
          <div class="pager-btns">
            <button type="button" class="pb" id="sub-prev" onclick="_subPageNav(-1)">${esc(typeof t === "function" ? t("ss_prev") : "Anterior")}</button>
            <span id="sub-pnums"></span>
            <button type="button" class="pb" id="sub-next" onclick="_subPageNav(1)">${esc(typeof t === "function" ? t("ss_next") : "Próximo")}</button>
            <select class="ai-drop" id="sub-perpage" onchange="_subSetPerPage(this.value)" aria-label="Linhas por página" style="padding:6px 8px">
              ${[25, 50, 100, 200].map(n => `<option value="${n}">${n} / pág.</option>`).join("")}
            </select>
          </div>
        </div>
      </div>
    </div>
    <div id="playwright-host-inventory" class="ai-pw-inventory"></div>`;
  _subPaint(resp);
  renderPlaywrightHostInventoryTab(co);
  if (typeof hydrateIcons === "function") hydrateIcons(el);
}

// Asset status-code summary badges (Osmedeus-style)
function _assetStatusBadges(st) {
  const chip = (g, cls) => st && st[g] ? `<span class="ai-statchip ${cls}">${g}xx: ${st[g]}</span>` : "";
  return chip(2, "s2") + chip(3, "s3") + chip(4, "s4") + chip(5, "s5");
}

// Colored tech chip with a stable hue per technology name
function _techChip(t) {
  const palette = ["#60a5fa", "#34d399", "#f59e0b", "#a78bfa", "#f472b6", "#22d3ee", "#fb7185", "#4ade80", "#facc15"];
  let hash = 0;
  for (let i = 0; i < t.length; i++) hash = (hash * 31 + t.charCodeAt(i)) >>> 0;
  const c = palette[hash % palette.length];
  return `<span class="ai-tech" style="color:${c};border-color:${c}33;background:${c}14">${esc(t)}</span>`;
}

function _infraChip(label, cls, title = "") {
  return `<span class="ai-tech ai-tech-infra ${cls}" title="${escAttr(title || label)}">${esc(label)}</span>`;
}

function _cloudLabel(value) {
  const v = String(value || "").trim();
  if (!v) return "";
  if (/gcp|google/i.test(v)) return "Cloud GCP";
  if (/aws|amazon/i.test(v)) return "Cloud AWS";
  if (/azure|microsoft/i.test(v)) return "Cloud Azure";
  if (/cloudflare/i.test(v)) return "Cloudflare";
  return `Cloud ${v}`;
}

function _hostInfraSignals(h) {
  const signals = [];
  const waf = String(h?.waf || "Direct").trim();
  const cloud = _cloudLabel(h?.cloud_provider || "");
  const add = (label, cls, title = "") => {
    if (!label || signals.some(s => s.label.toLowerCase() === label.toLowerCase())) return;
    signals.push({label, cls, title});
  };

  if (!waf || /^direct$/i.test(waf)) add("Sem WAF", "direct", "Direct: sem WAF/CDN identificado");
  else if (/direct/i.test(waf)) add("Sem WAF", "direct", waf);
  else if (/unknown waf/i.test(waf)) add("WAF desconhecido", "unknown", waf);
  else if (/cloudflare/i.test(waf)) add("CDN Cloudflare", "cloud", waf);
  else if (/cloudfront|aws/i.test(waf)) add("CDN AWS", "cloud", waf);
  else if (/gcp|google/i.test(waf)) add("Cloud GCP", "cloud", waf);
  else if (/imperva|incapsula/i.test(waf)) add("WAF Imperva", "waf", waf);
  else if (/akamai/i.test(waf)) add("CDN Akamai", "cloud", waf);
  else add(`WAF ${waf}`, "waf", waf);

  if (cloud) add(cloud, "cloud", h.cloud_provider || cloud);
  const techText = (h?.technologies || []).join(" ");
  if (/cloudflare/i.test(techText)) add("CDN Cloudflare", "cloud", "Detected in technologies");
  if (/gcp|google cloud/i.test(techText)) add("Cloud GCP", "cloud", "Detected in technologies");
  if (/aws|amazon|cloudfront/i.test(techText)) add("Cloud AWS", "cloud", "Detected in technologies");
  if (/azure|microsoft/i.test(techText)) add("Cloud Azure", "cloud", "Detected in technologies");
  return signals;
}

function _hostTechLabels(h) {
  const labels = _hostInfraSignals(h).map(s => s.label);
  (h?.technologies || []).forEach(t => {
    const label = String(t || "").trim();
    const low = label.toLowerCase();
    if (labels.includes("CDN Cloudflare") && low === "cloudflare") return;
    if (labels.includes("Cloud AWS") && /^(aws|amazon|amazon cloudfront|aws cloudfront)$/i.test(label)) return;
    if (labels.includes("Cloud GCP") && /^(gcp|google cloud)$/i.test(label)) return;
    if (labels.includes("Cloud Azure") && /^(azure|microsoft azure)$/i.test(label)) return;
    if (label && !labels.some(x => x.toLowerCase() === label.toLowerCase())) labels.push(label);
  });
  return labels;
}

async function renderSubdomainsTab(co) {
  const el = document.getElementById("tab-subdomains");
  if (!el) return;
  el.setAttribute("aria-busy", "true");
  el.innerHTML = `<div class="vuln-loading" role="status" style="padding:40px;text-align:center;color:var(--text3)">Carregando ativos…</div>`;
  let resp;
  try {
    resp = await _subQuery({page: 1, sort: "url", dir: "asc", per_page: _sub_per_page});
  } catch (e) {
    el.innerHTML = `<div class="empty-state"><div class="empty-state-title">Falha ao carregar os ativos</div><div class="empty-state-copy">${esc(e.message || e)}</div></div>`;
    el.removeAttribute("aria-busy");
    return;
  }
  if (state.currentId !== co.id) return;
  _sub_sort = "url"; _sub_asc = true;
  _renderSubInventoryShell(co, resp, el);
  el.removeAttribute("aria-busy");
}

function openSubdomainsFiltered(term) {
  switchHostsPanel('subdomains');
  setTimeout(() => {
    const s = document.getElementById('sub-search');
    if (s) {
      s.value = term || '';
      _subApplyFilter();
    }
  }, 100);
}

function renderDomainsTab(co, historyRows = null) {
  const el = document.getElementById("dom-main");
  if (!el) return;
  const rawDomains = Array.isArray(co.domains) ? co.domains.map(_normalizeScopeDomain).filter(Boolean) : [];
  if (!rawDomains.length) {
    el.innerHTML = `<div class="empty-state"><div class="empty-state-icon" data-ico="inbox" aria-hidden="true"></div><div class="empty-state-title">No domains configured</div><div class="empty-state-copy">Add at least one target domain to see domain-level work and generated subdomains here.</div></div>`;
    const tc = document.getElementById("tc-domains");
    if (tc) tc.textContent = "";
    return;
  }
  const rows = Array.isArray(historyRows)
    ? historyRows
    : Array.isArray(co.subdomain_history)
      ? co.subdomain_history
      : null;
  if (rows === null) {
    el.innerHTML = `<div class="empty-state"><div class="empty-state-icon" data-ico="inbox" aria-hidden="true"></div><div class="empty-state-title">Loading domain inventory…</div><div class="empty-state-copy">Merging domains, hosts and subdomain history.</div></div>`;
    _loadSubdomainHistory(co).then(history => {
      if (state.currentId !== co.id) return;
      co.subdomain_history = history;
      renderDomainsTab(co, history);
    });
    return;
  }

  const inventory = _buildSubdomainInventory(co, rows);
  const checkpointInfo = co.checkpoint_diff || null;
  const newSet = new Set((checkpointInfo?.new_subdomains || []).map(_normalizeScopeDomain).filter(Boolean));
  const buckets = new Map(rawDomains.map(d => [d, {domain: d, hosts: [], live: [], techs: new Set(), newHosts: []}]));
  const other = {domain: "Other / shared", hosts: [], live: [], techs: new Set(), newHosts: []};
  const domainSet = new Set(rawDomains);

  inventory.forEach(h => {
    const matched = _matchDomainForHost(h.host, rawDomains, domainSet);
    const bucket = matched ? buckets.get(matched) : other;
    bucket.hosts.push(h);
    if ((h.status_code && h.status_code < 400) || (h.ports || []).length > 0) bucket.live.push(h);
    if (newSet.has(h.host)) bucket.newHosts.push(h);
    (h.technologies || []).forEach(t => bucket.techs.add(t));
  });

  const domainBuckets = [...buckets.values()].sort((a, b) =>
    (b.hosts.length - a.hosts.length) || a.domain.localeCompare(b.domain));
  if (other.hosts.length) domainBuckets.push(other);
  _domBuckets = domainBuckets;
  _domQuery = "";

  const tc = document.getElementById("tc-domains");
  if (tc) tc.textContent = rawDomains.length || 0;

  const totalHosts = inventory.length;
  const totalLive = inventory.filter(h => (h.status_code && h.status_code < 400) || (h.ports || []).length > 0).length;
  const totalNew = checkpointInfo?.new_subdomains_count || 0;
  const totalDomains = rawDomains.length;
  const totalKnownTech = inventory.reduce((acc, h) => acc + ((h.technologies || []).length > 0 ? 1 : 0), 0);
  const hostSelector = "";

  el.innerHTML = `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">Domains</div>
          <div class="section-title">Domain work and generated hosts</div>
          <div class="section-sub">Each domain is shown with the hosts it generated, live hosts, technology signals and change since the previous scan.</div>
        </div>
      </div>
      ${hostSelector}
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">
        <div class="stat-card" style="min-width:120px"><div class="stat-value">${totalDomains}</div><div class="stat-label">Domains</div></div>
        <div class="stat-card" style="min-width:120px"><div class="stat-value">${totalHosts}</div><div class="stat-label">Hosts</div></div>
        <div class="stat-card" style="min-width:120px"><div class="stat-value">${totalLive}</div><div class="stat-label">Live / HTTP</div></div>
        <div class="stat-card" style="min-width:120px"><div class="stat-value">${totalNew}</div><div class="stat-label">New</div></div>
      </div>
      ${checkpointInfo && totalNew > 0 ? `
      <div style="margin:12px 0;padding:10px 14px;background:#16a34a18;border:1px solid #4ade8044;border-radius:8px">
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          <div style="font-size:.72rem;font-weight:700;color:#4ade80">${icoHtml("bolt",14)} Domain changes since last scan</div>
          <div style="font-size:.72rem;color:var(--text2)">${totalNew} new hosts · compared to ${(checkpointInfo.compared_to||'').slice(0,19)}</div>
        </div>
      </div>` : ""}
      <div class="table-shell">
        <div class="table-topline">
          <div class="table-title">Domain inventory</div>
          <div class="table-note">Click a host chip to inspect the full host record.</div>
        </div>
        <div style="margin-bottom:10px">
          <input id="dom-search" type="text" placeholder="Filter ${totalDomains.toLocaleString()} domains…"
                 oninput="_domFilterCards()"
                 style="width:100%;max-width:360px;padding:6px 10px;font-size:.72rem;font-family:var(--mono);background:rgba(255,255,255,0.03);border:1px solid var(--border2);border-radius:8px;color:var(--text1)">
          <div id="dom-cards-meta" style="margin-top:6px;font-size:.66rem;color:var(--text3)"></div>
        </div>
        <div id="dom-cards" style="display:flex;flex-direction:column;gap:12px"></div>
      </div>
    </div>`;
  _renderDomCards();
}

// Build a single domain card. Kept separate so search re-renders are cheap.
function _domCardHTML(bucket) {
  const techs = [...bucket.techs].sort().slice(0, 10);
  const hosts = bucket.hosts.slice().sort((a, b) => a.host.localeCompare(b.host));
  const liveCount = bucket.live.length;
  const newCount = bucket.newHosts.length;
  const sample = hosts.slice(0, 8);
  return `
    <div style="padding:14px 16px;border:1px solid var(--border2);border-radius:12px;background:rgba(255,255,255,0.02)">
      <div style="display:flex;gap:10px;align-items:flex-start;justify-content:space-between;flex-wrap:wrap">
        <div>
          <div style="font-size:.92rem;font-weight:700;color:var(--text1);font-family:var(--mono)">${esc(bucket.domain)}</div>
          <div style="margin-top:4px;font-size:.72rem;color:var(--text3)">${hosts.length} hosts · ${liveCount} live / HTTP · ${newCount} new</div>
        </div>
        <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px" onclick="openSubdomainsFiltered('${escAttr(bucket.domain)}')">Open Hosts</button>
      </div>
      <div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:6px">
        ${techs.length ? techs.map(t => `<span class="sd-tech-badge">${esc(t)}</span>`).join("") : `<span style="color:var(--text3);font-size:.65rem">No fingerprint</span>`}
      </div>
      <div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:6px">
        ${sample.length ? sample.map(h => `<code class="fg-host-chip fg-host-chip-full" onclick="openSubdomainsFiltered('${escAttr(h.host)}')" title="Open in Hosts">${esc(h.host)}</code>`).join("") : `<span style="color:var(--text3);font-size:.65rem">No hosts mapped yet</span>`}
      </div>
    </div>`;
}

// Render at most DOM_CARD_LIMIT cards from _domBuckets, filtered by _domQuery.
function _renderDomCards() {
  const host = document.getElementById("dom-cards");
  if (!host) return;
  const q = _domQuery.trim().toLowerCase();
  const filtered = q ? _domBuckets.filter(b => b.domain.toLowerCase().includes(q)) : _domBuckets;
  const shown = filtered.slice(0, DOM_CARD_LIMIT);
  host.innerHTML = shown.map(_domCardHTML).join("") ||
    `<div style="color:var(--text3);font-size:.7rem;padding:8px 0">No domains match “${esc(_domQuery)}”.</div>`;
  const meta = document.getElementById("dom-cards-meta");
  if (meta) {
    meta.textContent = filtered.length > shown.length
      ? `Showing ${shown.length} of ${filtered.length.toLocaleString()} domains${q ? " (filtered)" : ""} — refine the filter to narrow down.`
      : `Showing ${shown.length} domain${shown.length === 1 ? "" : "s"}${q ? " (filtered)" : ""}.`;
  }
}

function _domFilterCards() {
  const inp = document.getElementById("dom-search");
  _domQuery = inp ? inp.value : "";
  _renderDomCards();
}

let _sub_sort = "url", _sub_asc = true, _sub_per_page = 50, _sub_facets = null;
let _subReq = 0, _subTimer = null;

// Todos os filtros/ordenação/página vêm do servidor (/api/data/company/<id>/assets).
function _subParams(extra = {}) {
  const v = id => document.getElementById(id)?.value || "";
  const qs = new URLSearchParams();
  const set = (k, val) => { if (val !== "" && val != null) qs.set(k, val); };
  set("q", v("sub-search")); set("status", v("sub-status")); set("tech", v("sub-tech")); set("port", v("sub-port"));
  set("risk", v("sub-risk")); set("waf", v("sub-waf")); set("find", v("sub-find")); set("has", v("sub-has")); set("domain", v("sub-dom"));
  Object.entries(extra).forEach(([k, val]) => set(k, val));
  return qs;
}

async function _subQuery(extra) {
  const resp = await _sharedGetJSON(`/api/data/company/${encodeURIComponent(state.currentId)}/assets?${_subParams(extra)}`);
  // captura: o servidor não conhece os screenshots capturados pelo navegador/Playwright
  const co = allCompanies().find(c => c.id === state.currentId);
  const shots = co && co._screenshotsByHost;
  (resp.items || []).forEach(h => { if (!h.screenshot && shots && shots.has(h.host)) h.screenshot = shots.get(h.host); });
  return resp;
}

function _subSort(key){
  if (_sub_sort === key) _sub_asc = !_sub_asc;
  else {
    _sub_sort = key;
    const probe = _sub_hosts.length && _ASSET_COL[key] ? _ASSET_COL[key].val(_sub_hosts[0]) : "";
    _sub_asc = typeof probe !== "number";   // colunas numéricas começam do maior para o menor
  }
  _subApplyFilter();
}

// page=null => volta à primeira página (mudou um filtro); busca com atraso curto para não disparar a cada tecla
function _subApplyFilter(page = 1, immediate = true) {
  clearTimeout(_subTimer);
  const run = async () => {
    const req = ++_subReq;
    let resp;
    try { resp = await _subQuery({page, sort: _sub_sort, dir: _sub_asc ? "asc" : "desc", per_page: _sub_per_page}); }
    catch (e) { const pi = document.getElementById("sub-pinfo"); if (pi) pi.textContent = String(e.message || e); return; }
    if (req !== _subReq) return;   // resposta velha
    _subPaint(resp);
  };
  if (immediate) run(); else _subTimer = setTimeout(run, 220);
}
function _subPageNav(d){ _subApplyFilter(Math.max(1, _sub_page + d)); }
function _subGoPage(p){ _subApplyFilter(p); }
function _subSetPerPage(n){ _sub_per_page = Number(n) || 50; _subApplyFilter(1); }

function _subPaint(resp) {
  _sub_hosts = resp.items || [];
  _sub_page = resp.page || 1;
  _sub_facets = resp.facets || _sub_facets;
  _sub_hosts.forEach(h => { h._agg = h._agg || null; });
  const c = document.getElementById("sub-cnt"); if (c) c.textContent = resp.total;
  const head = document.getElementById("sub-thead"); if (head) head.innerHTML = _assetTheadHtml();
  const chips = document.getElementById("sub-chips"); if (chips) chips.innerHTML = _assetQuickChips(_sub_facets);
  const tot = resp.total, totPg = resp.pages, per = resp.per_page;
  const st = (resp.page - 1) * per;
  const pi = document.getElementById("sub-pinfo"); if (pi) pi.textContent = tot ? `${st + 1}–${Math.min(st + per, tot)} de ${tot}` : "0 de 0";
  const pr = document.getElementById("sub-prev"); if (pr) pr.disabled = resp.page <= 1;
  const nx = document.getElementById("sub-next"); if (nx) nx.disabled = resp.page >= totPg;
  let pn = "";
  for (let i = Math.max(1, resp.page - 2); i <= Math.min(totPg, resp.page + 2); i++)
    pn += `<button class="pb${i === resp.page ? " active" : ""}" onclick="_subGoPage(${i})">${i}</button>`;
  const pne = document.getElementById("sub-pnums"); if (pne) pne.innerHTML = pn;
  const pp = document.getElementById("sub-perpage"); if (pp) pp.value = String(per);
  _subRenderTable(_sub_hosts);
}

function _subRenderTable(rows) {
  const tb = document.getElementById("sub-tbody"); if (!tb) return;
  const ctx = {running: _isAssetCollectionRunning()};
  const cols = _assetVisibleCols();
  if (!rows.length) {
    tb.innerHTML = `<tr><td colspan="${cols.length}" class="recon-empty-row" style="padding:28px;text-align:center;color:var(--text3)">Nenhum ativo bate com os filtros.</td></tr>`;
    return;
  }
  tb.innerHTML = rows.map(h => `<tr class="ai-row" onclick="openHostDrawer('${escAttr(h.host)}')">${cols.map(c => c.td(h, ctx)).join("")}</tr>`).join("");
}

