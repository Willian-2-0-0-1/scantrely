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

function _opTable(headers, rowsHtml, emptyMsg) {
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
      ${thirdChips ? `<div class="op-chip-row">${thirdChips}</div>` : `<div class="job-detail-copy">${esc(_opT("op_none_third", "Nenhum terceiro listado."))}</div>`}
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

function _reconSevColor(sev) {
  return ({critical:"#fb7185", high:"#fb923c", medium:"#fbbf24", low:"#4ade80", info:"#94a3b8"}[String(sev || "info").toLowerCase()] || "#94a3b8");
}

function _reconKpi(value, label, note, cls) {
  return `<div class="recon-kpi ${cls || ""}">
    <div class="recon-kpi-value">${esc(value ?? 0)}</div>
    <div class="recon-kpi-label">${esc(label)}</div>
    ${note ? `<div class="recon-kpi-note">${esc(note)}</div>` : ""}
  </div>`;
}

function _reconModuleCard(item) {
  const active = Number(item.count || 0) > 0 || item.status === "done";
  return `<div class="recon-module ${active ? "done" : "idle"}">
    <div class="recon-module-top">
      <span class="recon-module-name">${esc(item.name)}</span>
      <span class="recon-module-count">${esc(item.count ?? 0)}</span>
    </div>
    <div class="recon-module-desc">${esc(item.desc || "")}</div>
  </div>`;
}

function _renderReconEvidencePanel(co, shots, staticEndpoints, staticSecrets, session) {
  co = co || {};
  const hosts = Array.isArray(co.hosts) ? co.hosts : [];
  const findings = Array.isArray(co.findings) ? co.findings : [];
  const cves = Array.isArray(co.cve_findings) ? co.cve_findings : [];
  const headerResults = Array.isArray(co.headers_data?.results) ? co.headers_data.results : [];
  const browserData = co.browser_recon_data || {};
  const browserCrawl = co.browser_crawl_data || {};
  const runtimeNetwork = Array.isArray(co.js_data?.runtime_network) ? co.js_data.runtime_network : [];
  const runtimeJsUrls = Array.isArray(co.js_data?.runtime_js_urls) ? co.js_data.runtime_js_urls : [];
  const browserResults = Array.isArray(browserData.results) ? browserData.results : [];
  const pwPages = Array.isArray(session?.pages) ? session.pages : [];
  const pwEndpoints = Array.isArray(session?.endpoints) ? session.endpoints : [];
  const pwTokens = Array.isArray(session?.tokens) ? session.tokens : [];
  const techCount = co.tech_summary ? Object.keys(co.tech_summary).length : 0;
  const endpointTotal = (staticEndpoints || []).length + pwEndpoints.length + Number(browserData.total_api_endpoints || 0);
  const secretTotal = (staticSecrets || []).length + pwTokens.length + Number(browserData.total_secrets || 0);
  const screenshotTotal = Array.isArray(shots) ? shots.length : Number(co.screenshots_count || 0);
  const missingHeaders = headerResults.reduce((acc, r) => acc + (Array.isArray(r.findings) ? r.findings.filter(f => !f.present && f.severity !== "pass").length : 0), 0);
  const cookieIssues = Number(co.headers_data?.cookie_issues || 0) + Number(browserData.insecure_cookies || 0);

  const modules = [
    {name:_opT("recon_mod_sub","Subdomínios"), count: hosts.length || (co.ct_subdomains || []).length, desc:_opT("recon_mod_sub_d","Escopo descoberto e normalizado")},
    {name:_opT("recon_mod_urls","URLs"), count: endpointTotal, desc:_opT("recon_mod_urls_d","Wayback, URLFinder, JS e browser")},
    {name:_opT("recon_mod_shots","Screenshots"), count: screenshotTotal, desc:_opT("recon_mod_shots_d","Evidências visuais em disco/API")},
    {name:_opT("recon_mod_hdr","Headers"), count: headerResults.length, desc:_opT("recon_mod_hdr_d","{g} gaps · {c} issues de cookie").replace("{g}", String(missingHeaders)).replace("{c}", String(cookieIssues))},
    {name:_opT("recon_mod_br","Browser"), count: browserResults.length || pwPages.length, desc:_opT("recon_mod_br_d","{n} cookies inseguros").replace("{n}", String(browserData.insecure_cookies || 0))},
    {name:_opT("recon_mod_crawl","Crawl do browser"), count: Number(browserCrawl.url_count || 0) + Number(browserCrawl.api_endpoint_count || 0), desc:_opT("recon_mod_crawl_d","{h} hosts · {f} forms").replace("{h}", String(browserCrawl.hosts_crawled || 0)).replace("{f}", String(browserCrawl.form_count || 0))},
    {name:_opT("recon_mod_rjs","JS runtime"), count: runtimeJsUrls.length || Number(co.js_data?.runtime_js_count || 0), desc:_opT("recon_mod_rjs_d","{n} chamadas de rede · chunks/scripts").replace("{n}", String(runtimeNetwork.length))},
    {name:_opT("recon_mod_js","JavaScript"), count: Array.isArray(co.js_data?.js_files) ? co.js_data.js_files.length : Number(co.js_data?.js_analyzed || co.js_data?.js_files_found || 0), desc:_opT("recon_mod_js_d","{e} endpoints · {s} secrets").replace("{e}", String(co.js_data?.total_endpoints || 0)).replace("{s}", String(co.js_data?.total_secrets || 0))},
    {name:_opT("recon_mod_cve","CVEs"), count: cves.length, desc:_opT("recon_mod_cve_d","{c} críticas · {h} altas").replace("{c}", String(co.cve_summary?.critical || 0)).replace("{h}", String(co.cve_summary?.high || 0))},
    {name:_opT("recon_mod_dns","DNSSEC"), count: Array.isArray(co.dnssec_data?.findings) ? co.dnssec_data.findings.length : 0, desc:_opT("recon_mod_dns_d","Problemas DNSSEC detectados")},
    {name:_opT("recon_mod_gh","GitHub"), count: Number(co.github_repos_data?.total_repos || 0), desc:_opT("recon_mod_gh_d","Repositórios e exposições")},
    {name:_opT("recon_mod_cloud","Cloud"), count: co.cloud_assets ? Object.keys(co.cloud_assets).length : 0, desc:_opT("recon_mod_cloud_d","Providers inferidos por IP")},
    {name:_opT("recon_mod_tech","Tech"), count: techCount, desc:_opT("recon_mod_tech_d","Tecnologias fingerprintadas")}
  ];

  const sevRank = {critical:0, high:1, medium:2, low:3, info:4};
  const topFindings = [...findings]
    .sort((a,b) => (sevRank[a.severity] ?? 4) - (sevRank[b.severity] ?? 4))
    .slice(0, 8);
  const topFindingRows = topFindings.map(f => `<tr>
    <td><span class="recon-sev" style="color:${_reconSevColor(f.severity)}">${esc(String(f.severity || "info").toUpperCase())}</span></td>
    <td>${esc(f.title || f.type || "Finding")}</td>
    <td class="recon-mono">${esc(f.host || f.value || "")}</td>
    <td>${esc(f.module || f.category || "")}</td>
  </tr>`).join("") || `<tr><td colspan="4" class="recon-empty-row">${esc(_opT("recon_find_empty","Nenhum finding consolidado."))}</td></tr>`;

  const hostRows = hosts.slice(0, 10).map(h => `<tr>
    <td class="recon-mono">${esc(h.host || "")}</td>
    <td>${h.status_code ? `<span class="status-code">${esc(h.status_code)}</span>` : "—"}</td>
    <td>${esc(h.title || h.server || "")}</td>
    <td>${(h.screenshot || h.browser_recon?.screenshot) ? icoHtml("check",14) : "—"}</td>
  </tr>`).join("") || `<tr><td colspan="4" class="recon-empty-row">${esc(_opT("recon_hosts_empty","Nenhum host carregado."))}</td></tr>`;

  const browserRows = browserResults.slice(0, 8).map(r => `<tr>
    <td class="recon-mono"><a href="${escAttr(r.url || "")}" target="_blank" rel="noopener">${esc(r.url || "")}</a></td>
    <td>${esc(r.status ?? "—")}</td>
    <td>${esc(r.title || "")}</td>
    <td>${Array.isArray(r.observations) ? r.observations.length : 0}</td>
  </tr>`).join("") || `<tr><td colspan="4" class="recon-empty-row">${esc(_opT("recon_br_empty","Browser recon sem páginas persistidas."))}</td></tr>`;

  return `
    <div class="recon-kpi-grid">
      ${_reconKpi(hosts.length, _opT("recon_kpi_hosts","Hosts"), _opT("recon_kpi_ct","{n} CT/subdomínios").replace("{n}", String(co.ct_subdomains?.length || 0)), "teal")}
      ${_reconKpi(findings.length, _opT("recon_kpi_findings","Findings"), _opT("recon_kpi_crit","{c} críticas · {h} altas").replace("{c}", String(co.stats?.findings_critical || 0)).replace("{h}", String(co.stats?.findings_high || 0)), "red")}
      ${_reconKpi(endpointTotal, _opT("recon_kpi_urls","URLs/Endpoints"), _opT("recon_kpi_static_pw","{s} estáticos · {p} PW").replace("{s}", String(staticEndpoints.length)).replace("{p}", String(pwEndpoints.length)), "blue")}
      ${_reconKpi(secretTotal, _opT("recon_kpi_secrets","Secrets"), _opT("recon_kpi_js","{n} JS/estáticos").replace("{n}", String(staticSecrets.length)), "orange")}
      ${_reconKpi(screenshotTotal, _opT("recon_kpi_shots","Screenshots"), _opT("recon_kpi_shots_sub","capturas disponíveis"), "green")}
      ${_reconKpi(browserResults.length || pwPages.length, _opT("recon_kpi_browser","Browser"), _opT("recon_kpi_insecure","{n} cookies inseguros").replace("{n}", String(browserData.insecure_cookies || 0)), "purple")}
    </div>

    <div class="section-head recon-inner-head">
      <div class="section-head-main">
        <div class="section-kicker">${esc(_opT("recon_cov_kicker","Cobertura"))}</div>
        <div class="section-title">${esc(_opT("recon_cov_title","Resultados por módulo"))}</div>
        <div class="section-sub">${esc(_opT("recon_cov_sub","Resumo operacional do que a pipeline já consolidou para o alvo."))}</div>
      </div>
    </div>
    <div class="recon-module-grid">${modules.map(_reconModuleCard).join("")}</div>

    <div class="recon-two-col">
      <div>
        <div class="recon-panel-title">${esc(_opT("recon_find_title","Findings prioritários"))}</div>
        <div class="table-shell"><div class="tl-wrap"><table class="jobs-table compact-table">
          <thead><tr><th>Sev</th><th>Finding</th><th>${esc(_opT("recon_col_host_val","Host/Valor"))}</th><th>${esc(_opT("recon_col_module","Módulo"))}</th></tr></thead>
          <tbody>${topFindingRows}</tbody>
        </table></div></div>
      </div>
      <div>
        <div class="recon-panel-title">${esc(_opT("recon_hosts_title","Hosts em evidência"))}</div>
        <div class="table-shell"><div class="tl-wrap"><table class="jobs-table compact-table">
          <thead><tr><th>Host</th><th>Status</th><th>${esc(_opT("recon_col_title_srv","Título/Server"))}</th><th>Shot</th></tr></thead>
          <tbody>${hostRows}</tbody>
        </table></div></div>
      </div>
    </div>

    <div class="recon-two-col">
      <div>
        <div class="recon-panel-title">${esc(_opT("recon_br_title","Browser recon"))}</div>
        <div class="table-shell"><div class="tl-wrap"><table class="jobs-table compact-table">
          <thead><tr><th>URL</th><th>Status</th><th>${esc(_opT("recon_col_title","Título"))}</th><th>${esc(_opT("recon_col_obs","Obs"))}</th></tr></thead>
          <tbody>${browserRows}</tbody>
        </table></div></div>
      </div>
    </div>
  `;
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

async function loadScreenshots(cid, co) {
  const el = document.getElementById("tab-screenshots");
  if (!el) return;
  el.setAttribute("aria-busy", "true");
  el.innerHTML = `<div class="recon-loading" role="status" style="padding:24px;color:var(--text3);font-size:.8rem;min-height:120px">${esc(_opT("recon_loading", "Carregando evidências de recon…"))}</div>`;

  const [shotsRes, bundleRes] = await Promise.allSettled([
    fetch(`/api/screenshots/${encodeURIComponent(cid)}`, {headers:_authHeaders()}).then(r=>r.ok?r.json():[]).catch(()=>[]),
    _fetchLatestPlaywrightBundle(cid).catch(()=>({job:null,session:null}))
  ]);

  const shots   = shotsRes.status  === 'fulfilled' ? (shotsRes.value  || []) : [];
  const bundle  = bundleRes.status === 'fulfilled' ? bundleRes.value        : {job:null,session:null};
  const session = bundle.session;

  if (co) buildUnifiedEndpoints(co);
  const staticEndpoints = co?._unifiedEndpoints || [];
  const staticSecrets   = co?._unifiedSecrets   || [];

  const browserData    = co?.browser_recon_data || {};
  const browserResults = Array.isArray(browserData.results) ? browserData.results : [];
  const pwPages     = Array.isArray(session?.pages)           ? session.pages           : [];
  const pwEndpoints = Array.isArray(session?.endpoints)       ? session.endpoints       : [];
  const pwTokens    = Array.isArray(session?.tokens)          ? session.tokens          : [];
  const pwGlobals   = Array.isArray(session?.globals_secrets) ? session.globals_secrets : [];
  const pwFindings  = Array.isArray(session?.findings)        ? session.findings        : [];
  const crawledMap = new Map();
  browserResults.forEach(r => {
    const url = r.url || "";
    if (url && !crawledMap.has(url)) crawledMap.set(url, {
      url,
      status_code: r.status,
      title: r.title || "",
      server: "browser_recon",
      _src: "browser",
    });
  });
  pwPages.forEach(p => {
    const url = p.url || p.final_url || "";
    if (url && !crawledMap.has(url)) crawledMap.set(url, {...p, url, _src: "playwright"});
  });
  const crawledPages = [...crawledMap.values()];

  const countEl = document.getElementById("tc-screenshots");
  if (countEl) countEl.textContent = String(shots.length || 0);

  // ── section builder helpers ──────────────────────────────────────────────
  function _secHead(kicker, title, sub, count) {
    return `
      <div class="section-head" style="margin-top:28px;padding-top:20px;border-top:1px solid var(--border)">
        <div class="section-head-main">
          <div class="section-kicker">${kicker}</div>
          <div class="section-title">${esc(title)}</div>
          <div class="section-sub">${esc(sub)}</div>
        </div>
        ${count != null ? `<div class="section-actions"><span class="sec-cnt">${esc(_opT("recon_items", "{n} itens").replace("{n}", String(count)))}</span></div>` : ''}
      </div>`;
  }

  function _emptyRow(msg) {
    return `<tr><td colspan="99" style="padding:18px;color:var(--text3);text-align:center;font-size:.75rem">${msg}</td></tr>`;
  }

  // ── SCREENSHOTS ──────────────────────────────────────────────────────────
  let html = `<div class="section-shell">
    <div class="section-head">
      <div class="section-head-main">
        <div class="section-kicker">Recon</div>
        <div class="section-title">${esc(_opT("recon_title", "Evidências de recon e pistas da superfície de ataque"))}</div>
        <div class="section-sub">${esc(_opT("recon_sub", "Hosts, findings, URLs, evidência do browser, screenshots e cobertura de módulos do último pipeline de bug bounty."))}</div>
      </div>
    </div>
    ${_renderReconEvidencePanel(co, shots, staticEndpoints, staticSecrets, session)}`;

  // ── CRAWLED URLS (playwright pages) ─────────────────────────────────────
  html += _secHead(icoHtml("globe",14), _opT("recon_crawled_title", "URLs crawleadas ({n})").replace("{n}", String(crawledPages.length)), _opT("recon_crawled_sub", "Páginas visitadas pela fase de browser recon da pipeline ou por um job Playwright."), null);
  if (crawledPages.length) {
    const pageRows = crawledPages.map(p => {
      const url = p.url || p.final_url || '';
      return `<tr>
        <td style="font-family:var(--mono);font-size:.72rem;word-break:break-all">
          <a href="${esc(url)}" target="_blank" rel="noopener" style="color:var(--teal);text-decoration:none">${esc(url)}</a>
        </td>
        <td style="text-align:center">${p.status_code ?? '—'}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.7rem">${esc(p.title||'')}</td>
        <td style="color:var(--text3);font-size:.68rem">${esc(p._src || p.server || '')}</td>
      </tr>`;
    }).join('');
    html += `<div class="table-shell"><div class="tl-wrap"><table class="jobs-table">
      <thead><tr><th>URL</th><th>Status</th><th>${esc(_opT("recon_col_title","Título"))}</th><th>${esc(_opT("recon_col_source","Fonte"))}</th></tr></thead>
      <tbody>${pageRows}</tbody></table></div></div>`;
  } else {
    html += `<div style="padding:12px 0;color:var(--text3);font-size:.78rem">${esc(_opT("recon_crawled_empty", "Nenhuma página crawleada ainda. Rode a fase de browser na pipeline de bug bounty."))}</div>`;
  }

  // ── ENDPOINTS ────────────────────────────────────────────────────────────
  // Merge static (wayback/JS) + playwright endpoints, deduplicate by URL
  const epMap = new Map();
  staticEndpoints.forEach(e => epMap.set(e.url, {...e, _src:e.source || 'static'}));
  pwEndpoints.forEach(e => {
    const url = e.url || '';
    if (!epMap.has(url)) epMap.set(url, {url, method: e.method||'GET', type:'browser', _src:'playwright'});
  });
  browserResults.forEach(r => (r.api_endpoints || []).forEach(e => {
    const url = typeof e === "string" ? e : (e.url || e.endpoint || e.path || "");
    if (!url || epMap.has(url)) return;
    epMap.set(url, {url, method: e.method || "GET", type: "browser", _src: "browser"});
  }));
  const mergedEp = [...epMap.values()];

  // Filter out static resources and dedup
  const epFiltered = mergedEp.filter(e => {
    const t = (e.type||'').toLowerCase();
    if (t === 'static_resource' || t === 'static resource') return false;
    return true;
  });

  html += _secHead("", _opT("recon_ep_title", "Endpoints ({n})").replace("{n}", String(epFiltered.length)), _opT("recon_ep_sub", "Caminhos e rotas de API da análise JS e do crawl do browser. Clique a URL para abrir o local em que foi achada."), null);
  if (epFiltered.length) {
    html += `<div style="display:flex;gap:6px;flex-wrap:wrap;padding:8px 0;align-items:center">
      <input id="ep-filter" placeholder="${escAttr(_opT("recon_ep_filter", "Filtrar endpoints…"))}" style="background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 10px;font-size:.7rem;width:200px" oninput="document.querySelectorAll('.ep-row').forEach(r=>{const t=r.textContent.toLowerCase();r.style.display=t.includes(this.value.toLowerCase())?'':'none'})">
    </div>`;

    const SEV = {critical:'#fb7185',high:'#fb923c',medium:'#fbbf24',low:'#4ade80',info:'#94a3b8'};
    const epRows = epFiltered.slice(0, 500).map(e => {
      const mc = _methodColor ? _methodColor(e.method||'GET') : '#60a5fa';
      return `<tr class="ep-row">
        <td style="width:60px">
          <span style="font-family:var(--mono);font-size:.64rem;font-weight:700;color:${mc}">${esc(e.method||'GET')}</span>
        </td>
        <td class="recon-mono">${originLinkHtml(e.url || "", e.url || "", { title: _originTitle() })}</td>
        <td style="font-size:.62rem;color:var(--teal);font-family:var(--mono)">${esc(e._src || e.source || '')}</td>
        <td style="font-size:.66rem;color:var(--text3)">${esc(e.type||'')}</td>
        <td style="font-size:.66rem;color:${e.severity?SEV[e.severity]||'#94a3b8':'var(--text3)'}">${e.severity?e.severity.toUpperCase():''}</td>
      </tr>`;
    }).join('');
    const overflow = epFiltered.length > 500 ? `<tr><td colspan="5" style="padding:8px 12px;color:var(--text3);font-size:.7rem">${esc(_opT("recon_ep_more", "{n} endpoints a mais — use o filtro ou exporte CSV.").replace("{n}", String(epFiltered.length - 500)))}</td></tr>` : '';
    html += `<div class="table-shell"><div class="tl-wrap" style="max-height:360px;overflow-y:auto"><table class="jobs-table">
      <thead><tr><th>Method</th><th>URL</th><th>Source</th><th>Type</th><th>Risk</th></tr></thead>
      <tbody>${epRows}${overflow}</tbody></table></div></div>`;
  } else {
    html += `<div style="padding:12px 0;color:var(--text3);font-size:.78rem">${esc(_opT("recon_ep_empty", "Nenhum endpoint descoberto ainda. Rode wayback, urlfinder, js ou Playwright Recon."))}</div>`;
  }

  // ── SECRETS & HARDCODED KEYS ─────────────────────────────────────────────
  // Merge: static secrets + playwright tokens + playwright globals
  const secArr = [];
  staticSecrets.forEach(s => secArr.push({type:s.type||'secret', value:s.value||'', file:s.file||'', host:s.host||'', severity:s.severity||'medium', _src:'static'}));
  pwTokens.forEach(t => secArr.push({type:t.type||'token', value:t.value||JSON.stringify(t), file:'', host:t.host||'', severity:'high', _src:'playwright'}));
  pwGlobals.forEach(g => secArr.push({type:'global', value:g.sample||g.key||'', file:g.key||'', host:'', severity:'medium', _src:'playwright'}));
  browserResults.forEach(r => (r.secrets_found || []).forEach(s => {
    secArr.push({type:s.type || "browser_secret", value:s.value || s.secret || JSON.stringify(s), file:r.url || "", host:"", severity:s.severity || "high", _src:"browser"});
  }));

  html += _secHead(icoHtml("key",14), _opT("recon_sec_title", "Secrets e chaves hardcoded ({n})").replace("{n}", String(secArr.length)), _opT("recon_sec_sub", "Credenciais, tokens e chaves de API extraídos de bundles JS e globais do browser. Clique o arquivo ou o host para abrir o local. O valor mascarado revela no clique."), null);
  if (secArr.length) {
    html += `<div style="display:flex;gap:6px;flex-wrap:wrap;padding:8px 0;align-items:center">
      <input id="sec-filter" placeholder="${escAttr(_opT("recon_sec_filter", "Filtrar secrets…"))}" style="background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 10px;font-size:.7rem;width:200px" oninput="document.querySelectorAll('.sec-row').forEach(r=>{const t=r.textContent.toLowerCase();r.style.display=t.includes(this.value.toLowerCase())?'':'none'})">
    </div>`;
    const SEVC = {critical:'#fb7185',high:'#fb923c',medium:'#fbbf24',low:'#4ade80'};
    function maskVal(v) {
      const s = String(v||'');
      if (s.length <= 6) return '••••••';
      return s.slice(0,3) + '••••••' + s.slice(-3);
    }
    const secRows = secArr.map((s, i) => {
      const clr = SEVC[s.severity] || '#94a3b8';
      const src = s._src === 'playwright' ? `<span style="font-size:.56rem;color:var(--teal);opacity:.7;margin-left:3px">PW</span>` : '';
      const fileHref = originHref(s.file, s.host);
      const fileCell = s.file
        ? (fileHref
            ? originLinkHtml(s.file, s.file, { host: s.host, className: "origin-link origin-mono", title: _originTitle("js") })
            : `<button type="button" class="origin-jump" onclick="jumpToFound('jsreverse', ${_jsArg(s.file)})">${esc(s.file)}</button>`)
        : '<span style="font-size:.67rem;color:var(--text3)">—</span>';
      return `<tr class="sec-row">
        <td><span style="font-size:.68rem;background:rgba(251,146,60,.1);color:#fb923c;border:1px solid rgba(251,146,60,.2);border-radius:4px;padding:1px 6px">${esc(s.type)}</span>${src}</td>
        <td><code class="secret-value" style="cursor:pointer;font-size:.7rem;font-family:var(--mono);color:var(--text2)"
          onclick="var m=this.getAttribute('data-masked'),v=this.getAttribute('data-value');if(this.textContent===m){this.textContent=v;this.style.color='var(--teal)';this.style.cursor='pointer'}else{this.textContent=m;this.style.color='var(--text2)';this.style.cursor='pointer'}" data-masked="${esc(maskVal(s.value))}" data-value="${esc(String(s.value||''))}">${esc(maskVal(s.value))}</code></td>
        <td style="max-width:260px">${fileCell}</td>
        <td>${s.host ? originHostChip(s.host, "origin-link") : '<span style="font-size:.67rem;color:var(--text3)">—</span>'}</td>
        <td><span style="font-size:.62rem;font-weight:700;color:${clr}">${s.severity.toUpperCase()}</span></td>
      </tr>`;
    }).join('');
    html += `<div class="table-shell"><div class="tl-wrap" style="max-height:320px;overflow-y:auto"><table class="jobs-table">
      <thead><tr><th>${esc(_opT("recon_col_type","Tipo"))}</th><th>${esc(_opT("recon_sec_value","Valor (clique para revelar)"))}</th><th>${esc(_opT("recon_col_file","Arquivo"))}</th><th>Host</th><th>Risk</th></tr></thead>
      <tbody>${secRows}</tbody></table></div></div>`;
  } else {
    html += `<div style="padding:12px 0;color:var(--text3);font-size:.78rem">${esc(_opT("recon_sec_empty", "Nenhum secret ou chave hardcoded encontrado. Rode js, trufflehog ou Playwright Recon."))}</div>`;
  }

  // ── POSTMAN COLLECTIONS ─────────────────────────────────────────────────
  const postmanData = co?.postman_data;
  const pmCollections = postmanData?.collections || [];
  const pmGithubHits  = postmanData?.github_hits || [];
  const pmSecrets     = postmanData?.secrets || [];
  const pmHasData     = pmCollections.length + pmGithubHits.length + pmSecrets.length > 0;
  const pmTotal       = postmanData?.total || pmCollections.length + pmGithubHits.length;

  html += _secHead("", _opT("recon_pm_title", "Coleções Postman ({n})").replace("{n}", String(pmTotal)), _opT("recon_pm_sub", "Coleções públicas do Postman e arquivos postman no GitHub que citam o alvo. Clique as URLs para abrir."), null);
  if (pmHasData) {
    // Collections
    if (pmCollections.length) {
      html += `<div style="padding:4px 0 12px;font-size:.7rem;color:var(--text3)"><strong>${esc(_opT("recon_pm_public", "Coleções públicas ({n})").replace("{n}", String(pmCollections.length)))}</strong></div>`;
      const pmcRows = pmCollections.slice(0, 20).map(c => `<tr>
        <td style="font-size:.72rem"><a href="${esc(c.url||'')}" target="_blank" style="color:var(--teal);text-decoration:none" onmouseover="this.style.textDecoration='underline'" onmouseout="this.style.textDecoration='none'">${esc(c.name||c.id||'?')}</a></td>
        <td style="font-size:.67rem;color:var(--text3)">${esc(c.owner||'')}</td>
        <td style="font-size:.64rem;color:var(--teal)">${esc(c.id||'')}</td>
      </tr>`).join('');
      html += `<div class="table-shell"><div class="tl-wrap" style="max-height:240px;overflow-y:auto"><table class="jobs-table">
        <thead><tr><th>${esc(_opT("recon_col_collection","Coleção"))}</th><th>${esc(_opT("recon_col_owner","Dono"))}</th><th>ID</th></tr></thead>
        <tbody>${pmcRows}</tbody></table></div></div>`;
    }
    // GitHub hits
    if (pmGithubHits.length) {
      html += `<div style="padding:8px 0 4px;font-size:.7rem;color:var(--text3)"><strong>${esc(_opT("recon_pm_github", "Arquivos no GitHub ({n})").replace("{n}", String(pmGithubHits.length)))}</strong></div>`;
      const pmgRows = pmGithubHits.slice(0, 15).map(g => `<tr>
        <td style="font-size:.7rem"><a href="${esc(g.url||'')}" target="_blank" style="color:var(--teal);text-decoration:none" onmouseover="this.style.textDecoration='underline'" onmouseout="this.style.textDecoration='none'">${esc(g.repo||'')}/${esc(g.file||'')}</a></td>
        <td style="font-size:.67rem;color:var(--text3)">${esc(g.repo||'')}</td>
      </tr>`).join('');
      html += `<div class="table-shell"><div class="tl-wrap" style="max-height:200px;overflow-y:auto"><table class="jobs-table">
        <thead><tr><th>${esc(_opT("recon_col_file","Arquivo"))}</th><th>${esc(_opT("recon_col_repo","Repositório"))}</th></tr></thead>
        <tbody>${pmgRows}</tbody></table></div></div>`;
    }
    // Secrets from Postman files
    if (pmSecrets.length) {
      html += `<div style="padding:8px 0 4px;font-size:.7rem;color:var(--text3)"><strong>${esc(_opT("recon_pm_secrets", "Secrets extraídos ({n})").replace("{n}", String(pmSecrets.length)))}</strong></div>`;
      const pmsRows = pmSecrets.slice(0, 15).map(s => {
        const raw = String(s.value || '');
        const masked = raw.length <= 6 ? '••••••' : raw.slice(0, 3) + '••••••' + raw.slice(-3);
        return `<tr>
        <td style="font-size:.7rem"><code style="font-family:var(--mono);font-size:.66rem;color:var(--text2)">${esc(s.type||'secret')}</code></td>
        <td><code class="secret-value" style="cursor:pointer;font-size:.67rem;font-family:var(--mono);color:var(--text2)"
          onclick="var m=this.getAttribute('data-masked'),v=this.getAttribute('data-value');if(this.textContent===m){this.textContent=v;this.style.color='var(--teal)'}else{this.textContent=m;this.style.color='var(--text2)'}" data-masked="${esc(masked)}" data-value="${esc(raw)}">${esc(masked)}</code></td>
        <td style="font-size:.64rem;color:var(--teal)">${esc(s.repo||'')}</td>
      </tr>`;
      }).join('');
      html += `<div class="table-shell"><div class="tl-wrap" style="max-height:200px;overflow-y:auto"><table class="jobs-table">
        <thead><tr><th>${esc(_opT("recon_col_type","Tipo"))}</th><th>${esc(_opT("recon_col_value","Valor"))}</th><th>Repo</th></tr></thead>
        <tbody>${pmsRows}</tbody></table></div></div>`;
    }
  } else {
    html += `<div style="padding:12px 0;color:var(--text3);font-size:.78rem">${esc(_opT("recon_pm_empty", "Nenhuma coleção Postman encontrada. Rode o módulo postman_collections para descobrir coleções de API expostas."))}</div>`;
  }

  // ── VULNERABILITY FINDINGS (host header, redirect, CORS, CRLF, XSS, etc) ───
  const vulnModules = ['host_header_injection', 'open_redirect', 'cors_scan', 'xss_scan',
                       'crlf_injection', 'smtp_probe', 'snmp_probe', 'infra_exposure',
                       'default_creds', 'salesforce_recon', 'git_leaks'];
  const vulnFindings = (co?.findings || []).filter(f => vulnModules.includes(f.module));

  if (vulnFindings.length) {
    const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
    vulnFindings.sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));

    // Filter chips
    const vulnModulesUniq = [...new Set(vulnFindings.map(f => f.module))].sort();
    const vulnFilterId = 'vuln-filter';
    html += _secHead(icoHtml("target",14), _opT("recon_vuln_title", "Findings de vulnerabilidade ({n})").replace("{n}", String(vulnFindings.length)), _opT("recon_vuln_sub", "Host header injection, open redirects, CORS mal configurado, XSS, CRLF, credenciais padrão e outros checks ativos."), null);
    html += `<div style="display:flex;gap:6px;flex-wrap:wrap;padding:8px 0;align-items:center">
      <input id="${vulnFilterId}" placeholder="${escAttr(_opT("recon_vuln_filter", "Filtrar findings…"))}" style="background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 10px;font-size:.7rem;width:180px" oninput="document.querySelectorAll('.vuln-row').forEach(r=>{const t=r.textContent.toLowerCase();r.style.display=t.includes(this.value.toLowerCase())?'':'none'})">
    </div>`;

    const vulnRows = vulnFindings.slice(0, 100).map(f => {
      const clr = f.severity === 'critical' ? '#fb7185' : f.severity === 'high' ? '#fb923c' : f.severity === 'medium' ? '#fbbf24' : f.severity === 'low' ? '#4ade80' : '#94a3b8';
      const moduleLabel = f.module ? f.module.replace(/_/g, ' ') : '';
      const loc = f.url || "";
      const locLabel = (loc || f.value || "").slice(0, 50);
      return `<tr class="vuln-row">
        <td><span style="font-size:.62rem;font-weight:700;color:${clr}">${(f.severity||'').toUpperCase()}</span></td>
        <td style="font-size:.72rem"><span style="color:var(--teal);font-size:.6rem;opacity:.7">${esc(moduleLabel)}</span> ${esc(f.title||f.type||'')}</td>
        <td>${f.host ? originHostChip(f.host, "origin-link") : '<span style="font-size:.67rem;color:var(--text3)">—</span>'}</td>
        <td class="recon-mono">${originHref(loc, f.host) ? originLinkHtml(loc, locLabel, { host: f.host, title: _originTitle() }) : esc(locLabel)}</td>
      </tr>`;
    }).join('');

    html += `<div class="table-shell"><div class="tl-wrap" style="max-height:400px;overflow-y:auto"><table class="jobs-table">
      <thead><tr><th>Sev</th><th>Finding</th><th>Host</th><th>URL</th></tr></thead>
      <tbody>${vulnRows}</tbody></table></div></div>`;
  }

  // ── Playwright findings summary (if any) ─────────────────────────────────
  if (pwFindings.length) {
    html += _secHead(icoHtml("bolt",14), _opT("recon_pw_title", "Findings do Playwright ({n})").replace("{n}", String(pwFindings.length)), _opT("recon_pw_sub", "Issues apontados pelo agente de browser automatizado."), null);
    const fRows = pwFindings.map(f => `<tr>
      <td style="font-size:.7rem;font-weight:600;color:${f.severity==='critical'?'#fb7185':f.severity==='high'?'#fb923c':'#fbbf24'}">${esc(f.severity||'').toUpperCase()}</td>
      <td style="font-size:.75rem">${esc(f.title||f.type||'')}</td>
      <td class="recon-mono">${originHref(f.url, "") ? originLinkHtml(f.url, f.url, { title: _originTitle() }) : esc(f.url||f.evidence||'')}</td>
    </tr>`).join('');
    html += `<div class="table-shell"><div class="tl-wrap"><table class="jobs-table">
      <thead><tr><th>Sev</th><th>Finding</th><th>${esc(_opT("recon_col_evidence","URL / Evidência"))}</th></tr></thead>
      <tbody>${fRows}</tbody></table></div></div>`;
  }

  html += `</div>`;
  el.innerHTML = html;
  el.removeAttribute("aria-busy");
}

function renderPlaywrightOverview(jobs) {
  const el = document.getElementById("playwright-overview");
  if (!el) return;
  const pwJobs = (jobs || []).filter(job => job.job_type === "playwright_recon");
  if (!pwJobs.length) {
    el.innerHTML = `
      <div class="playwright-item">
        <div class="playwright-item-head">
          <div>
            <div class="playwright-item-title">Playwright Recon</div>
            <div class="playwright-item-sub">No Playwright jobs in the current queue view.</div>
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
          <div class="playwright-item-sub">${pwJobs.length} job(s) total · ${done} done · ${running} running · ${pending} pending</div>
        </div>
      </div>
      <div class="playwright-item-badges">
        <span class="playwright-item-badge done">Done ${done}</span>
        <span class="playwright-item-badge running">Running ${running}</span>
        <span class="playwright-item-badge pending">Pending ${pending}</span>
      </div>
    </div>
    ${pwJobs.slice(0, 4).map(job => _playwrightCard(job, {
      meta: `${_fmtJobTime(job.created_at)} · ${(Array.isArray(job.options?.scope) ? job.options.scope.join(", ") : (job.options?.scope || "no scope"))}`
    })).join("")}
  `;
  _hydratePlaywrightInventoryBatch(pwJobs);
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
