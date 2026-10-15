function _opT(key, fallback) {
  if (typeof window.t === "function") {
    const v = window.t(key);
    if (v && v !== key) return v;
  }
  return fallback || key;
}

function _opSummarize(co) {
  if (window.ASMOperation && typeof window.ASMOperation.summarize === "function") {
    return window.ASMOperation.summarize(co);
  }
  return {
    has: false, pages: [], crawl: [], apis: [], cookies: [], observations: [],
    third: [], missingHeaders: [], forms: [], urls: [], runtimeJs: [],
    runtimeNetwork: [], jsFiles: [], hostsScanned: 0, hostsCrawled: 0,
    urlCount: 0, apiCount: 0, formCount: 0, cookieCount: 0, insecureCookies: 0,
    shots: 0, scannedAt: "", badge: 0
  };
}

function _opSetBadge(persist) {
  const el = document.getElementById("tc-operation");
  if (!el) return;
  const n = persist && persist.badge;
  el.textContent = n ? String(n) : "";
}

function _opShotUrl(cid, raw) {
  if (window.ASMOperation && typeof window.ASMOperation.screenshotServeUrl === "function") {
    return window.ASMOperation.screenshotServeUrl(cid, raw);
  }
  return "";
}

function _shotSrc(raw, cid) {
  cid = cid || (typeof state !== "undefined" && state.currentId) || "";
  return _opShotUrl(cid, raw);
}

function _shotMissingCid(cid, raw) {
  var s = String(raw || "").replace(/\\/g, "/");
  cid = String(cid || "").trim();
  if (!s || !cid) return true;
  return s.indexOf("screenshots/" + cid + "/") === -1;
}

function _shotJs(src) {
  return JSON.stringify(src || "").replace(/"/g, "&quot;");
}

function _opClip(s, n) {
  s = String(s || "");
  n = n || 140;
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function _opHydrate(el) {
  if (el && typeof window.hydrateIcons === "function") window.hydrateIcons(el);
}

function _opCta(cid) {
  return `<button type="button" class="btn btn-primary" id="playwright-btn-${escAttr(cid)}" onclick='openPlaywrightModal(${_jsArg(cid)})'>${icoHtml("play",14)} ${_opT("op_cta_playwright", "Enfileirar Playwright Recon")}</button>`;
}

// Seção sem dados não aparece: o marcador faz o CSS esconder o cartão inteiro (ver .op-empty-marker).
const _OP_EMPTY = `<span class="op-empty-marker" hidden></span>`;

function _opTable(headers, rowsHtml, emptyMsg) {
  if (!rowsHtml) return _OP_EMPTY;
  const cols = headers.length;
  return `<div class="table-shell"><div class="tl-wrap"><table class="jobs-table compact-table">
    <thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join("")}</tr></thead>
    <tbody>${rowsHtml || `<tr><td colspan="${cols}" class="recon-empty-row">${esc(emptyMsg)}</td></tr>`}</tbody>
  </table></div></div>`;
}

function _opCapNote(shown, total) {
  if (!total || shown >= total) return "";
  return `<div class="job-detail-copy">${esc(_opT("op_showing", "Mostrando {n} de {total}").replace("{n}", String(shown)).replace("{total}", String(total)))}</div>`;
}

function _renderOperationPersistCards(co, persist) {
  const cid = co.id || "";
  const pages = persist.pages || [];
  const crawl = persist.crawl || [];
  const apis = persist.apis || [];
  const cookies = persist.cookies || [];
  const observations = persist.observations || [];
  const third = persist.third || [];
  const forms = persist.forms || [];
  const runtimeJs = persist.runtimeJs || [];
  const network = persist.runtimeNetwork || [];
  const pageCap = pages.slice(0, 30);
  const apiCap = apis.slice(0, 40);
  const cookieCap = cookies.slice(0, 30);
  const obsCap = observations.slice(0, 20);
  const formCap = forms.slice(0, 12);
  const jsCap = runtimeJs.slice(0, 20);
  const netCap = network.slice(0, 30);

  const pageRows = pageCap.map(p => {
    const shot = _opShotUrl(cid, p.screenshot);
    const miss = Array.isArray(p.security_headers?.missing) ? p.security_headers.missing.join(", ") : "";
    const shotCell = shot
      ? `<a href="${escAttr(shot)}" target="_blank" rel="noopener"><img class="op-shot" src="${escAttr(shot)}" alt="" onerror="this.style.display='none'"> ${_opT("op_open", "Abrir")}</a>`
      : "—";
    return `<tr>
      <td class="recon-mono">${originLinkHtml(p.url || "", p.url || "", { title: _originTitle() })}</td>
      <td>${esc(String(p.status ?? "—"))}</td>
      <td>${esc(p.title || "")}</td>
      <td class="recon-mono">${esc(_opClip(miss, 80))}</td>
      <td>${shotCell}</td>
    </tr>`;
  }).join("");

  const crawlRows = crawl.map(r => `<tr>
    <td class="recon-mono">${r.host ? originHostChip(r.host, "origin-link") : "—"}</td>
    <td class="recon-mono">${originLinkHtml(r.url || "", r.url || "", { host: r.host, title: _originTitle() })}</td>
    <td>${esc(String(r.pages ?? 0))}</td>
    <td>${esc(String(Array.isArray(r.urls) ? r.urls.length : 0))}</td>
    <td>${esc(String(Array.isArray(r.api_endpoints) ? r.api_endpoints.length : 0))}</td>
    <td>${esc(String(Array.isArray(r.forms) ? r.forms.length : 0))}</td>
  </tr>`).join("");

  const apiRows = apiCap.map(e => `<tr>
    <td>${esc(e.method || "GET")}</td>
    <td class="recon-mono">${originLinkHtml(e.url || "", e.url || "", { title: _originTitle() })}</td>
    <td>${esc(e.type || "")}</td>
  </tr>`).join("");

  const cookieRows = cookieCap.map(c => `<tr>
    <td class="recon-mono">${esc(c.name || "")}</td>
    <td class="recon-mono">${c.domain ? originHostChip(String(c.domain).replace(/^\./, ""), "origin-link") : "—"}</td>
    <td>${c.httpOnly ? _opT("op_yes", "sim") : _opT("op_no", "não")}</td>
    <td>${c.secure ? _opT("op_yes", "sim") : _opT("op_no", "não")}</td>
    <td class="recon-mono">${originLinkHtml(c.page || "", c.page || "", { title: _originTitle() })}</td>
  </tr>`).join("");

  const obsRows = obsCap.map(o => `<tr>
    <td class="recon-mono">${originLinkHtml(o.url || "", o.url || "", { title: _originTitle() })}</td>
    <td>${esc(_opClip(o.text, 180))}</td>
  </tr>`).join("");

  const thirdChips = third.slice(0, 24).map(s => {
    const href = originHref(s);
    return href
      ? originLinkHtml(s, s, { className: "op-chip origin-link", title: _originTitle() })
      : `<span class="op-chip">${esc(s)}</span>`;
  }).join("");
  const formRows = formCap.map(f => `<tr>
    <td>${esc((f && f.method) || "")}</td>
    <td class="recon-mono">${originLinkHtml((f && f.action) || "", (f && f.action) || "", { title: _originTitle() })}</td>
    <td class="recon-mono">${esc(Array.isArray(f && f.inputs) ? f.inputs.join(", ") : "")}</td>
  </tr>`).join("");

  const jsRows = jsCap.map(u => {
    const url = typeof u === "string" ? u : (u && u.url) || "";
    return `<tr><td class="recon-mono">${originLinkHtml(url, url, { title: _originTitle("js") })}</td></tr>`;
  }).join("");

  const netRows = netCap.map(n => `<tr>
    <td>${esc(n.method || "GET")}</td>
    <td>${esc(n.type || "")}</td>
    <td class="recon-mono">${originLinkHtml(n.url || "", n.url || "", { title: _originTitle() })}</td>
  </tr>`).join("");

  return `
    <div class="recon-kpi-grid">
      ${_reconKpi(pages.length, _opT("op_pages", "Páginas"), `${persist.hostsScanned || 0} hosts`, "teal")}
      ${_reconKpi(persist.urlCount, _opT("op_crawl_urls", "URLs crawl"), `${persist.hostsCrawled || 0} hosts`, "blue")}
      ${_reconKpi(persist.apiCount, _opT("op_apis", "APIs"), `${persist.formCount || 0} forms`, "purple")}
      ${_reconKpi(persist.insecureCookies, _opT("op_insecure", "Cookies inseguros"), `${persist.cookieCount || 0} cookies`, "orange")}
      ${_reconKpi(runtimeJs.length, _opT("op_runtime_js", "JS runtime"), `${(persist.jsFiles || []).length} bundles`, "green")}
      ${_reconKpi(persist.shots, _opT("op_shots", "Screenshots"), persist.scannedAt ? String(persist.scannedAt).slice(0, 19) : "", "red")}
    </div>

    <div class="job-detail-card" style="margin-top:16px;margin-bottom:14px">
      <div class="job-detail-title">${esc(_opT("op_pages_title", "Páginas do browser"))}</div>
      ${_opTable(
        [_opT("op_col_url", "URL"), _opT("op_col_status", "Status"), _opT("op_col_title", "Título"), _opT("op_col_header", "Headers ausentes"), _opT("op_col_shot", "Screenshot")],
        pageRows,
        _opT("op_none_pages", "Nenhuma página persistida.")
      )}
      ${_opCapNote(pageCap.length, pages.length)}
    </div>

    <div class="job-detail-card" style="margin-bottom:14px">
      <div class="job-detail-title">${esc(_opT("op_crawl_title", "Crawl por host"))}</div>
      ${_opTable(
        [_opT("op_col_host", "Host"), _opT("op_col_url", "URL"), _opT("op_col_pages", "Páginas"), _opT("op_col_urls", "URLs"), _opT("op_col_apis", "APIs"), _opT("op_col_forms", "Forms")],
        crawlRows,
        _opT("op_none_crawl", "Nenhum host crawleado.")
      )}
    </div>

    <div class="job-detail-card" style="margin-bottom:14px">
      <div class="job-detail-title">${esc(_opT("op_api_title", "Endpoints de API"))}</div>
      ${_opTable(
        [_opT("op_col_method", "Método"), _opT("op_col_url", "URL"), _opT("op_col_type", "Tipo")],
        apiRows,
        _opT("op_none_api", "Nenhuma API capturada.")
      )}
      ${_opCapNote(apiCap.length, apis.length)}
    </div>

    <div class="recon-two-col">
      <div class="job-detail-card">
        <div class="job-detail-title">${esc(_opT("op_cookie_title", "Cookies (nome e flags)"))}</div>
        ${_opTable(
          [_opT("op_col_name", "Nome"), _opT("op_col_domain", "Domínio"), "HttpOnly", "Secure", _opT("op_col_url", "Página")],
          cookieRows,
          _opT("op_none_cookie", "Nenhum cookie persistido.")
        )}
        ${_opCapNote(cookieCap.length, cookies.length)}
      </div>
      <div class="job-detail-card">
        <div class="job-detail-title">${esc(_opT("op_obs_title", "Observações"))}</div>
        ${_opTable(
          [_opT("op_col_url", "URL"), _opT("op_col_obs", "Observação")],
          obsRows,
          _opT("op_none_obs", "Nenhuma observação.")
        )}
      </div>
    </div>

    <div class="job-detail-card" style="margin-top:14px;margin-bottom:14px">
      <div class="job-detail-title">${esc(_opT("op_third_title", "Serviços de terceiros"))}</div>
      ${thirdChips ? `<div class="op-chip-row">${thirdChips}</div>` : _OP_EMPTY}
    </div>

    <div class="job-detail-card" style="margin-bottom:14px">
      <div class="job-detail-title">${esc(_opT("op_form_title", "Formulários"))}</div>
      ${_opTable(
        [_opT("op_col_method", "Método"), _opT("op_col_action", "Action"), _opT("op_col_inputs", "Campos")],
        formRows,
        _opT("op_none_form", "Nenhum formulário capturado.")
      )}
    </div>

    <div class="recon-two-col">
      <div class="job-detail-card">
        <div class="job-detail-title">${esc(_opT("op_js_title", "JavaScript em runtime"))}</div>
        ${_opTable([_opT("op_col_bundle", "Bundle")], jsRows, _opT("op_none_js", "Nenhum JS de runtime."))}
        ${_opCapNote(jsCap.length, runtimeJs.length)}
      </div>
      <div class="job-detail-card">
        <div class="job-detail-title">${esc(_opT("op_net_title", "Rede em runtime"))}</div>
        ${_opTable(
          [_opT("op_col_method", "Método"), _opT("op_col_type", "Tipo"), _opT("op_col_url", "URL")],
          netRows,
          _opT("op_none_net", "Nenhuma chamada de rede.")
        )}
        ${_opCapNote(netCap.length, network.length)}
      </div>
    </div>
  `;
}

function _renderPlaywrightSessionHtml(job, session, report) {
  if (!job) return "";
  const pages = Array.isArray(session?.pages) ? session.pages : [];
  const endpoints = Array.isArray(session?.endpoints) ? session.endpoints : [];
  const js = Array.isArray(session?.js) ? session.js : [];
  const tech = Array.isArray(session?.tech) ? session.tech : [];
  const consoleEvents = Array.isArray(session?.console) ? session.console : [];
  const auth = session?.auth || {};
  const confirmed = Array.isArray(session?.findings) ? session.findings.filter(f => String(f.status || "").includes("confirmed")) : [];
  const idor = Array.isArray(session?.idor) ? session.idor : [];
  const xss = Array.isArray(session?.xss) ? session.xss : [];
  const race = Array.isArray(session?.race) ? session.race : [];
  const inventory = session ? _playwrightInventorySummary(session) : "";
  const storageKeys = session?.storage ? Object.keys(session.storage) : [];
  const tokenCount = Array.isArray(session?.tokens) ? session.tokens.length : 0;
  const finished = _fmtJobTime(job.finished_at);
  const started = _fmtJobTime(job.started_at);
  const canArtifacts = job.status === "done";
  const cidJs = _jsArg(job.id);
  const pageRows = pages.slice(0, 30).map(p => `
      <tr>
        <td class="recon-mono">${originLinkHtml(p.url || "", p.url || "", { title: _originTitle() })}</td>
        <td>${esc(String(p.depth ?? ""))}</td>
        <td>${esc(String(p.status ?? ""))}</td>
        <td>${esc(p.title || "")}</td>
        <td>${p.screenshot_path ? `<a href="${esc(_shotSrc(p.screenshot_path))}" target="_blank" rel="noopener">${esc(_opT("op_open", "Abrir"))}</a>` : "—"}</td>
      </tr>`).join("");
  const endpointRows = endpoints.slice(0, 40).map(e => `
      <tr>
        <td>${esc(e.method || "GET")}</td>
        <td class="recon-mono">${originLinkHtml(e.url || "", e.url || "", { title: _originTitle() })}</td>
        <td>${esc(String(e.status ?? "—"))}</td>
        <td>${esc(e.content_type || "")}</td>
        <td>${e.auth_required === true ? _opT("op_yes", "sim") : e.auth_required === false ? _opT("op_no", "não") : "—"}</td>
      </tr>`).join("");
  const jsRows = js.slice(0, 30).map(j => `
      <tr>
        <td class="recon-mono">${originLinkHtml(j.file_url || "", j.file_url || "", { title: _originTitle("js") })}</td>
        <td>${esc(String(j.size || 0))}</td>
        <td>${j.source_map_accessible ? _opT("op_yes", "sim") : (j.source_map_url ? "ref" : _opT("op_no", "não"))}</td>
        <td>${esc(String((j.endpoints || []).length))}</td>
        <td>${esc(String((j.routes || []).length))}</td>
      </tr>`).join("");
  const techRows = tech.slice(0, 30).map(t => `
      <tr>
        <td>${esc(t.name || "")}</td>
        <td>${esc(t.category || "")}</td>
        <td>${esc(t.confidence || "")}</td>
        <td>${esc(t.source || "")}</td>
      </tr>`).join("");
  const consoleRows = consoleEvents.slice(0, 40).map(c => `
      <tr>
        <td>${esc(c.type || "")}</td>
        <td class="recon-mono">${esc(c.message || "")}</td>
        <td>${esc(c.classification || "")}</td>
        <td class="recon-mono">${originLinkHtml(c.page_url || "", c.page_url || "", { title: _originTitle() })}</td>
      </tr>`).join("");
  const authForms = Array.isArray(auth.login_forms) ? auth.login_forms : [];
  const authRows = authForms.slice(0, 10).map(f => `
      <tr>
        <td class="recon-mono">${originLinkHtml(f.action || "", f.action || "", { title: _originTitle() })}</td>
        <td>${esc(f.method || "")}</td>
        <td>${esc(f.password_field || "")}</td>
        <td>${esc(f.csrf_field || "")}</td>
      </tr>`).join("");
  const findingsRows = confirmed.slice(0, 20).map(f => `
      <tr>
        <td>${esc(f.title || "")}</td>
        <td>${esc(f.severity || "")}</td>
        <td class="recon-mono">${originLinkHtml(f.endpoint || f.url || "", f.endpoint || f.url || "", { title: _originTitle() })}</td>
        <td>${esc(f.status || "")}</td>
      </tr>`).join("");
  const idorRows = idor.slice(0, 20).map(i => `
      <tr>
        <td class="recon-mono">${originLinkHtml(i.url || "", i.url || "", { title: _originTitle() })}</td>
        <td>${esc(i.parameter || "")}</td>
        <td>${esc(i.status || "")}</td>
        <td>${esc((i.notes || []).join("; "))}</td>
      </tr>`).join("");
  const xssRows = xss.slice(0, 20).map(x => `
      <tr>
        <td class="recon-mono">${originLinkHtml(x.url || "", x.url || "", { title: _originTitle() })}</td>
        <td>${esc(x.parameter || "")}</td>
        <td>${esc(x.context || "")}</td>
        <td>${esc(x.status || "")}</td>
      </tr>`).join("");
  const raceRows = race.slice(0, 20).map(r => `
      <tr>
        <td class="recon-mono">${originLinkHtml(r.url || "", r.url || "", { title: _originTitle() })}</td>
        <td>${esc(r.category || "")}</td>
        <td>${esc(r.probe_status || "")}</td>
        <td>${esc(r.reason || "")}</td>
      </tr>`).join("");

  if (!session) {
    return `
      <div class="op-banner">
        <div>
          <div class="job-detail-title">${esc(_opT("op_pw_title", "Sessão Playwright"))}</div>
          <div class="job-detail-copy">${esc(job.id)} · ${esc(_jobStatusLabel(job.status))} · ${esc(_opT("op_pw_pending", "Sessão ainda não disponível. A evidência da pipeline permanece acima."))}</div>
        </div>
        <div class="section-actions">
          <button type="button" class="btn btn-secondary" onclick='openJobDetail(${cidJs})'>${esc(_opT("op_cta_details", "Detalhes"))}</button>
        </div>
      </div>`;
  }

  return `
    <div class="section-head recon-inner-head">
      <div class="section-head-main">
        <div class="section-kicker">${esc(_opT("op_pw_title", "Sessão Playwright"))}</div>
        <div class="section-title">${esc(job.company_id || "—")} · ${esc(_jobStatusLabel(job.status))}</div>
        <div class="section-sub">${esc(job.id)} · ${esc(started)} · ${esc(finished)}</div>
      </div>
      <div class="section-actions">
        <button type="button" class="btn btn-secondary" onclick='openJobDetail(${cidJs})'>${esc(_opT("op_cta_details", "Detalhes"))}</button>
        ${canArtifacts ? `<a class="btn btn-secondary" href="${_jobArtifactUrl(job.id, "report")}" target="_blank" rel="noopener">${esc(_opT("op_report", "Relatório"))}</a>` : ""}
        ${canArtifacts ? `<a class="btn btn-secondary" href="${_jobArtifactUrl(job.id, "session")}" target="_blank" rel="noopener">${esc(_opT("op_session", "Sessão"))}</a>` : ""}
      </div>
    </div>
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px">
      ${_jobKPICard("pages", pages.length)}
      ${_jobKPICard("endpoints", endpoints.length)}
      ${_jobKPICard("js", js.length)}
      ${_jobKPICard("tech", tech.length)}
      ${_jobKPICard("confirmed", confirmed.length)}
      ${_jobKPICard("console", consoleEvents.length)}
    </div>
    <div class="job-detail-card" style="margin-bottom:14px">
      <div class="job-detail-title">${esc(_opT("op_hosts_title", "Inventário de hosts"))}</div>
      ${inventory || `<div class="job-detail-copy">${esc(_opT("op_hosts_empty", "Nenhum host capturado nesta sessão."))}</div>`}
    </div>
    <div class="job-detail-card" style="margin-bottom:14px">
      <div class="job-detail-title">${esc(_opT("op_pages_title", "Páginas do browser"))}</div>
      ${_opTable(["URL", "Depth", "Status", _opT("op_col_title", "Título"), "Screenshot"], pageRows, _opT("op_none_pages", "Nenhuma página persistida."))}
    </div>
    <div class="job-detail-card" style="margin-bottom:14px">
      <div class="job-detail-title">${esc(_opT("op_api_title", "Endpoints de API"))}</div>
      ${_opTable(["Method", "URL", "Status", "Content-Type", "Auth"], endpointRows, _opT("op_none_api", "Nenhuma API capturada."))}
    </div>
    <div class="job-detail-card" style="margin-bottom:14px">
      <div class="job-detail-title">JavaScript</div>
      ${_opTable(["Bundle", "Size", "Source Map", "Endpoints", "Routes"], jsRows, _opT("op_none_js", "Nenhum JS de runtime."))}
    </div>
    <div class="job-detail-card" style="margin-bottom:14px">
      <div class="job-detail-title">Technologies</div>
      ${_opTable(["Name", "Category", "Confidence", "Source"], techRows, _opT("op_none_tech", "Nenhuma tecnologia detectada."))}
    </div>
    <div class="job-detail-card" style="margin-bottom:14px">
      <div class="job-detail-title">Console</div>
      ${_opTable(["Type", "Message", "Classification", "Page"], consoleRows, _opT("op_none_console", "Nenhum evento de console."))}
    </div>
    <div class="job-detail-card" style="margin-bottom:14px">
      <div class="job-detail-title">Authentication</div>
      <div class="job-detail-copy">
        Login forms: <strong>${authForms.length}</strong> · CSRF: <strong>${(auth.csrf_fields || []).length || 0}</strong> · Cookies: <strong>${(auth.cookies || []).length || 0}</strong>
      </div>
      ${authForms.length ? _opTable(["Action", "Method", "Password Field", "CSRF"], authRows, "") : `<div class="job-detail-copy">${esc(_opT("op_none_form", "Nenhum formulário capturado."))}</div>`}
    </div>
    <div class="job-detail-card" style="margin-bottom:14px">
      <div class="job-detail-title">${esc(_opT("op_confirmed", "Findings confirmados"))}</div>
      ${confirmed.length ? _opTable(["Title", "Severity", "Endpoint", "Status"], findingsRows, "") : `<div class="job-detail-copy">${esc(_opT("op_none_findings", "Nenhum finding confirmado no Playwright."))}</div>`}
    </div>
    <div class="job-detail-card" style="margin-bottom:14px">
      <div class="job-detail-title">IDOR / XSS / Race</div>
      <div class="job-detail-copy">Storage keys: <strong>${storageKeys.length}</strong> · Tokens: <strong>${tokenCount}</strong> · WebSockets: <strong>${(session?.websockets || []).length || 0}</strong></div>
      <div style="margin-top:10px;display:grid;gap:12px">
        ${idor.length ? _opTable(["IDOR URL", "Param", "Status", "Notes"], idorRows, "") : `<div class="job-detail-copy">${esc(_opT("op_none_idor", "Nenhum candidato IDOR."))}</div>`}
        ${xss.length ? _opTable(["XSS URL", "Param", "Context", "Status"], xssRows, "") : `<div class="job-detail-copy">${esc(_opT("op_none_xss", "Nenhum check XSS."))}</div>`}
        ${race.length ? _opTable(["Race URL", "Category", "Status", "Reason"], raceRows, "") : `<div class="job-detail-copy">${esc(_opT("op_none_race", "Nenhum probe de race."))}</div>`}
      </div>
    </div>
    <div class="job-detail-card">
      <div class="job-detail-title">${esc(_opT("op_report", "Relatório"))}</div>
      ${report ? `<pre class="job-detail-pre">${esc(report)}</pre>` : `<div class="job-detail-copy">${esc(_opT("op_none_report", "Sem prévia de relatório."))}</div>`}
    </div>
  `;
}

function _renderOperationShell(co, persist, bundle) {
  const job = bundle && bundle.job;
  const session = bundle && bundle.session;
  const report = (bundle && bundle.report) || "";
  const cid = co.id || "";
  const trueEmpty = !persist.has && !job;
  if (trueEmpty) {
    const err = bundle && bundle.error;
    return `
      <div class="empty-state">
        <div class="empty-state-icon" data-ico="monitor" aria-hidden="true"></div>
        <div class="empty-state-title">${esc(err ? _opT("op_load_fail", "Falha ao carregar a operação") : _opT("op_empty_title", "Nenhuma evidência de browser ainda"))}</div>
        <div class="empty-state-copy">${esc(err || _opT("op_empty_copy", "Rode a pipeline para popular browser, crawl e JS. Depois enfileire o Playwright Recon para a sessão de pentest."))}</div>
        <div class="op-empty-cta">${_opCta(cid)}</div>
      </div>`;
  }
  return `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">${esc(_opT("op_kicker", "Operação"))}</div>
          <div class="section-title">${esc(_opT("op_title", "Superfície devolvida pelo browser"))}</div>
          <div class="section-sub">${esc(_opT("op_sub", "Resultados da pipeline (browser_recon, crawl e JS). O Playwright Recon extra entra abaixo quando houver job."))}</div>
        </div>
        <div class="section-actions">${_opCta(cid)}</div>
      </div>
      ${persist.has ? _renderOperationPersistCards(co, persist) : ""}
      ${job ? _renderPlaywrightSessionHtml(job, session, report) : ""}
    </div>
  `;
}

async function renderOperationTab(co) {
  const el = document.getElementById("tab-operation");
  if (!el) return;
  const persist = _opSummarize(co);
  _opSetBadge(persist);
  el.innerHTML = _renderOperationShell(co, persist, { job: null, session: null, report: "" });
  _opHydrate(el);
  let bundle = { job: null, session: null, report: "" };
  try {
    bundle = await _fetchLatestPlaywrightBundle(co.id);
  } catch (e) {
    bundle = { job: null, session: null, report: "", error: e.message };
  }
  if (!el.isConnected) return;
  if (document.getElementById("tc-operation") && bundle.session) {
    const pages = Array.isArray(bundle.session.pages) ? bundle.session.pages.length : 0;
    const endpoints = Array.isArray(bundle.session.endpoints) ? bundle.session.endpoints.length : 0;
    const js = Array.isArray(bundle.session.js) ? bundle.session.js.length : 0;
    const n = pages || endpoints || js || persist.badge;
    document.getElementById("tc-operation").textContent = n ? String(n) : "";
  }
  el.innerHTML = _renderOperationShell(co, persist, bundle);
  _opHydrate(el);
}

async function renderReconTab(cid) {
  const el = document.getElementById("tab-pipeline");
  if (!el) return;
  const activePipeline = _isPipelineActive(cid);
  const runLbl = _opT("pipe_run", "Rodar pipeline");
  const stopLbl = _opT("pipe_stop", "Parar pipeline");
  el.innerHTML = `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">${esc(_opT("tab_pipeline", "Pipeline"))}</div>
          <div class="section-title">${esc(_opT("pipe_title", "Execução do scan e status das fases"))}</div>
          <div class="section-sub">${esc(_opT("pipe_sub", "Acompanhe o runner e o último painel Playwright Recon aqui."))}</div>
        </div>
        <div class="section-actions">
          <button type="button" id="pipeline-btn-${escAttr(cid)}" class="btn ${activePipeline ? "btn-icon pipeline-stop-btn" : "btn-secondary btn-icon"}" aria-label="${esc(activePipeline ? stopLbl : runLbl)}" onclick="handlePipelineAction('${escAttr(cid)}')">${activePipeline ? icoHtml("stop",14)+" "+esc(stopLbl) : icoHtml("play",14)+" "+esc(runLbl)}</button>
        </div>
      </div>
      <div id="pipeline-status-${escAttr(cid)}" style="margin-top:12px"></div>
      <div id="company-playwright-panel" style="margin-top:14px"></div>
    </div>
  `;
  renderPipelineStatus(cid);
  _syncPipelineActionButton(cid);
  await renderCompanyPlaywrightPanel(cid);
}

// ── Screenshot lightbox ──────────────────────────────────────────────────────
let _ssShots = [], _ssIdx = 0;

function _ssIsOpen() {
  const lb = document.getElementById('ss-lightbox');
  return !!(lb && lb.classList.contains('open'));
}

function _ssOnKey(e) {
  if (!_ssIsOpen()) return;
  if (e.key === 'Escape') {
    e.preventDefault();
    window.ssLightboxClose();
    return;
  }
  if (e.key === 'ArrowLeft') {
    e.preventDefault();
    window.ssLightboxNav(-1);
    return;
  }
  if (e.key === 'ArrowRight') {
    e.preventDefault();
    window.ssLightboxNav(1);
  }
}

window.ssLightboxOpen = function(shotUrl, pageUrl, shots, idx) {
  _ssShots = shots || [{shotUrl, pageUrl}];
  _ssIdx   = idx   || 0;
  if (typeof window.ssPopoverHide === 'function') window.ssPopoverHide();
  _ssShow();
  const lb = document.getElementById('ss-lightbox');
  if (lb) { lb.classList.add('open'); lb.focus(); }
  document.removeEventListener('keydown', _ssOnKey);
  document.addEventListener('keydown', _ssOnKey);
};

window.ssLightboxClose = function() {
  const lb = document.getElementById('ss-lightbox');
  if (lb) lb.classList.remove('open');
  document.removeEventListener('keydown', _ssOnKey);
};

window.ssLightboxNav = function(dir) {
  if (!_ssShots.length) return;
  _ssIdx = (_ssIdx + dir + _ssShots.length) % _ssShots.length;
  _ssShow();
};

// ── Screenshot hover preview popover ──────────────────────────────────

let _ssPopover = null;

window.ssPopoverShow = function(e, shotUrl, pageUrl) {
  if (window.matchMedia && window.matchMedia('(hover: none)').matches) return;
  if (!_ssPopover) {
    _ssPopover = document.createElement('div');
    _ssPopover.className = 'ss-popover';
    _ssPopover.innerHTML = '<img src="" alt=""><div class="ss-popover-url"></div>';
    document.body.appendChild(_ssPopover);
  }
  const img = _ssPopover.querySelector('img');
  const lbl = _ssPopover.querySelector('.ss-popover-url');
  img.src = shotUrl;
  lbl.textContent = (pageUrl || '').length > 90 ? (pageUrl || '').substring(0, 90) + '…' : (pageUrl || '');
  // Position to the right of the thumbnail, clamped to viewport
  const rect = e.target.getBoundingClientRect();
  const pwW = _ssPopover.offsetWidth || 400;
  let left = rect.right + 12;
  let top  = rect.top - 40;
  if (left + pwW > window.innerWidth - 20) left = rect.left - pwW - 12;
  if (left < 10) left = 10;
  if (top < 10) top = 10;
  if (top + 300 > window.innerHeight) top = window.innerHeight - 320;
  _ssPopover.style.left = left + 'px';
  _ssPopover.style.top  = top + 'px';
  _ssPopover.classList.add('show');
};

window.ssPopoverHide = function() {
  if (_ssPopover) _ssPopover.classList.remove('show');
};

function _reconKpi(value, label, note, cls) {
  return `<div class="recon-kpi ${cls || ""}">
    <div class="recon-kpi-value">${esc(value ?? 0)}</div>
    <div class="recon-kpi-label">${esc(label)}</div>
    ${note ? `<div class="recon-kpi-note">${esc(note)}</div>` : ""}
  </div>`;
}

function _ssShow() {
  const s = _ssShots[_ssIdx] || {};
  const img = document.getElementById('ss-lightbox-img');
  const lbl = document.getElementById('ss-lightbox-url');
  const nav = document.getElementById('ss-lightbox-nav');
  if (img) {
    img.src = s.shotUrl || '';
    img.alt = s.pageUrl ? ('Screenshot de ' + s.pageUrl) : 'Screenshot';
  }
  if (lbl) lbl.textContent = s.pageUrl || '';
  if (nav) nav.style.display = _ssShots.length > 1 ? 'flex' : 'none';
}

async function renderPlaywrightOverviewAll() {
  const el = document.getElementById("playwright-overview-all");
  if (!el) return;
  el.innerHTML = `
    <div class="playwright-item">
      <div class="playwright-item-head">
        <div>
          <div class="playwright-item-title">Playwright Recon</div>
          <div class="playwright-item-sub">Loading latest global jobs...</div>
        </div>
      </div>
    </div>
  `;
  try {
    const r = await fetch("/api/jobs?limit=20", {headers:_authHeaders()});
    if (!r.ok) throw new Error("HTTP " + r.status);
    const jobs = await r.json();
    const pwJobs = (jobs || []).filter(job => job.job_type === "playwright_recon");
    if (!pwJobs.length) {
      el.innerHTML = `
        <div class="playwright-item">
          <div class="playwright-item-head">
            <div>
              <div class="playwright-item-title">Playwright Recon</div>
              <div class="playwright-item-sub">No Playwright jobs have been queued yet.</div>
            </div>
          </div>
        </div>
      `;
      return;
    }
    const done = pwJobs.filter(j => j.status === "done").length;
    const running = pwJobs.filter(j => j.status === "running").length;
    const pending = pwJobs.filter(j => j.status === "pending").length;
    el.innerHTML = `
      <div class="playwright-item" style="grid-column:1/-1">
        <div class="playwright-item-head">
          <div>
            <div class="playwright-item-title">Playwright Recon Overview</div>
            <div class="playwright-item-sub">${pwJobs.length} recent job(s) · ${done} done · ${running} running · ${pending} pending</div>
          </div>
          <div class="job-actions">
            <button class="btn btn-secondary btn-icon" onclick="showPage('jobs'); loadJobs();">Open Queue</button>
          </div>
        </div>
      </div>
      ${pwJobs.slice(0, 3).map(job => _playwrightCard(job)).join("")}
    `;
    _hydratePlaywrightInventoryBatch(pwJobs);
  } catch(e) {
    el.innerHTML = `
      <div class="playwright-item">
        <div class="playwright-item-head">
          <div>
            <div class="playwright-item-title">Playwright Recon</div>
            <div class="playwright-item-sub">Failed to load overview: ${esc(e.message)}</div>
          </div>
        </div>
      </div>
    `;
  }
}
