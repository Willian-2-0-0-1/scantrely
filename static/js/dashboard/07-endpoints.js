// ════════════════════════════════════════════════════════════════════════
//  URL CLASSIFICATION ENGINE (red-team focused)
// ════════════════════════════════════════════════════════════════════════
const URL_PATTERNS = [
  { type: 'Admin Panel',    severity: 'critical', score: 100, patterns: [/\/admin(\/|$)/i, /\/wp-admin/i, /\/administrator/i, /\/manage(\/|$)/i, /\bdashboard\b/i, /\/panel(\/|$)/i, /\/cpanel/i, /\/phpmyadmin/i, /\/pma\//i, /\/jenkins/i, /\/console/i] },
  { type: 'API Endpoint',   severity: 'high',     score: 75,  patterns: [/\/api\//i, /\/graphql/i, /\/rest\//i, /\/v[12]\//i, /\/oauth/i, /\bswagger\b/i, /\/openapi/i, /\/endpoint/i, /\/webhook/i, /\/callback/i] },
  { type: 'Dev / Stage Env',severity: 'high',     score: 70,  patterns: [/\/dev\//i, /\/staging\//i, /\/stage\//i, /\btest\//i, /\/hml\//i, /\/sandbox/i, /\/uat\//i, /\/qa\//i, /\/homolog/i] },
  { type: 'Config / Secrets',severity:'critical', score: 100, patterns: [/\.env$/i, /\/\.git\//i, /\/\.svn\//i, /\bconfig\b/i, /wp-config/i, /\.htaccess/i, /docker-compose/i, /\.npmrc/i, /\.pypirc/i, /credentials/i] },
  { type: 'Backup File',    severity: 'high',     score: 85,  patterns: [/\.bak$/i, /\.backup$/i, /\.sql$/i, /\.tar\.gz$/i, /\.zip$/i, /\/backup\//i, /\.old$/i, /\.orig$/i] },
  { type: 'Login / Auth',   severity: 'high',     score: 80,  patterns: [/\/login/i, /\/signin/i, /\/auth\b/i, /\/sso\//i, /\/oauth2/i, /\/saml/i, /\/token/i, /\/password/i, /\/reset-password/i] },
  { type: 'File Upload',    severity: 'medium',   score: 60,  patterns: [/\/upload/i, /\/file\//i, /\/attachment/i, /\/media\//i, /\/assets\//i, /\/static\//i] },
  { type: 'Internal Path',  severity: 'high',     score: 90,  patterns: [/\/internal/i, /\/private/i, /\/intranet/i, /\b10\.\d+\./, /\b172\.(1[6-9]|2\d|3[01])\./, /\b192\.168\./, /\/metadata/i, /instance-profile/i] },
  { type: 'Log File',       severity: 'medium',   score: 65,  patterns: [/\.log$/i, /\/logs\//i, /debug\.log/i, /error\.log/i, /access\.log/i] },
  { type: 'XML / JSON Data',severity:'low',       score: 30,  patterns: [/\.xml$/i, /data\.json/i, /package\.json/i, /composer\.json/i, /sitemap/i] },
  { type: 'WebSocket',      severity: 'medium',   score: 55,  patterns: [/^wss?:\/\//i, /\/ws\b/i, /\/socket/i, /\/realtime/i] },
  { type: 'Generic HTTP',   severity: 'info',     score: 20,  patterns: [/\.php$/i, /\.asp/i, /\.aspx$/i, /\.jsp$/i, /\.do$/i, /\.action$/i, /\.cfm$/i] },
];

function classifyUrl(url) {
  const u = String(url || '').toLowerCase();
  for (const group of URL_PATTERNS) {
    for (const re of group.patterns) {
      if (re.test(u)) return { type: group.type, severity: group.severity, score: group.score };
    }
  }
  // Fallback with dynamic scoring
  if (/\.(php|asp|aspx|jsp|do|action|cfm|cgi|pl|py|rb)$/i.test(u)) return { type: 'Generic HTTP', severity: 'info', score: 20 };
  if (u.includes('?')) return { type: 'Dynamic Route', severity: 'info', score: 25 };
  return { type: 'Static Resource', severity: 'info', score: 5 };
}

let _classifyCache = null;   // antes nunca era declarada: só funcionava se invalidateEndpointCache() rodasse primeiro
function _classifyUrlMemo(url) {
  const k = String(url || '').toLowerCase();
  if (!_classifyCache) _classifyCache = {};
  if (_classifyCache[k]) return _classifyCache[k];
  return (_classifyCache[k] = classifyUrl(url));
}

// ════════════════════════════════════════════════════════════════════════
//  UNIFIED ENDPOINTS TAB — URLs + JS endpoints + secrets merged (v2)
// ════════════════════════════════════════════════════════════════════════

const _FP_PWD_RE = /(%filtered%|wrong.?password|forgot.?password|invalid.?password|missing.?password|need.?password|change.?password|reset.?password|show.?password|confirm.?password|enter.?password|password.?hint|password.?set|create.?password|redefine.?password|new.?password|old.?password|repeat.?password)/i;
const _FP_LABEL_RE = /^[A-Z][A-Z0-9_\-]{3,}$|^[a-z][a-z0-9_]{4,}[a-z0-9]$/;
const _JS_NOISE_HOSTS = new Set(["aadcdn.msauth.net","aadcdn.msftauth.net","ok1static.oktacdn.com","use.fontawesome.com","cdn-prod.securiti.ai","scripts.clarity.ms"]);
const _JS_NOISE_SFX = [".securiti.ai",".clarity.ms",".hotjar.com",".googleapis.com",".gstatic.com",".googletagmanager.com",".google-analytics.com",".recaptcha.net"];

function _isFpJsSecret(type, value) {
  var v = value || "";
  if (type === "password") {
    var inner = v.replace(/^(?:password|passwd|pwd)\s*[=:]\s*['"]/i, "").replace(/['"]$/, "");
    if (_FP_PWD_RE.test(inner)) return true;
    if (/^[A-Z][A-Z0-9_\-.]+$/.test(inner) || /^[a-z][a-z\-.]+$/.test(inner)) return true;
    if (/^['"']?passwords?['"']?$/i.test(inner)) return true;
    if (/[\[\]{}&|?]|\.substring\(|\+[a-z]+\./.test(inner)) return true;
    if (/^[A-Za-z][A-Za-z ]+$/.test(inner)) return true;
    return false;
  }
  if (type === "access_token" || type === "secret_key") {
    var inner2 = v.replace(/^[\w\-]+\s*[=:]\s*['"]/i, "").replace(/['"]$/, "");
    return _FP_LABEL_RE.test(inner2);
  }
  if (type === "api_key") {
    var inner3 = v.replace(/^[\w\-]+\s*[=:]\s*['"]/i, "").replace(/['"]$/, "");
    return _FP_LABEL_RE.test(inner3);
  }
  if (type === "internal_ip") {
    var m = v.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)/);
    if (!m) return true;
    return [m[1], m[2], m[3], m[4]].some(function(o){ return parseInt(o, 10) > 255; });
  }
  return false;
}

function _jsHostIsNoise(host) {
  var h = (host || "").toLowerCase();
  if (_JS_NOISE_HOSTS.has(h)) return true;
  return _JS_NOISE_SFX.some(function(sfx){ return h.endsWith(sfx); });
}

function _epDataStamp(co) {
  var jd = co && co.js_data ? co.js_data : {};
  var files = Array.isArray(jd.js_files) ? jd.js_files.length : 0;
  var sf = Array.isArray(co && co.secrets_findings) ? co.secrets_findings.length : 0;
  var wb = (co && co.wayback_data && co.wayback_data.interesting_count) || 0;
  return [files, jd.total_secrets || 0, jd.total_endpoints || 0, sf, wb].join(":");
}

function invalidateEndpointCache(co) {
  if (co) {
    delete co._unifiedEndpoints;
    delete co._unifiedSecrets;
    delete co._unifiedSources;
    delete co._epStats;
    delete co._epStamp;
  }
  _classifyCache = null;
}

function buildUnifiedEndpoints(co) {
  const stamp = _epDataStamp(co);
  if (co._unifiedEndpoints && co._unifiedSources && co._epStamp === stamp) return;

  const allEndpoints = [];
  const allSecrets = [];
  const sources = [];
  const addEndpoint = (rawUrl, method, source, meta = {}) => {
    if (!rawUrl || typeof rawUrl !== 'string') return;
    if (source === 'js' && isJsPathNoise(rawUrl)) return;
    const cls = _classifyUrlMemo(rawUrl);
    allEndpoints.push({
      url: rawUrl,
      method: String(method || 'GET').toUpperCase(),
      host: meta.host || '',
      path: meta.path || '',
      source,
      type: meta.type || cls.type,
      severity: meta.severity || cls.severity,
      status: meta.status ?? null,
      jsFile: meta.jsFile || '',
    });
  };

  // Wayback
  if (co.wayback_data?.interesting) {
    co.wayback_data.interesting.forEach(u => {
      const rawUrl = typeof u === 'string' ? u : (u.url || '');
      addEndpoint(rawUrl, 'GET', 'wayback', {
        host: typeof u === 'object' ? (u.host || '') : '',
        path: typeof u === 'object' ? (u.path || '') : '',
        status: typeof u === 'object' ? u.status : null,
      });
    });
    sources.push({ name: 'Wayback', count: co.wayback_data.interesting_count || 0, key: 'wayback' });
  }

  // URLFinder
  if (co.urlfinder_data?.urls) {
    co.urlfinder_data.urls.forEach(u => {
      const rawUrl = typeof u === 'string' ? u : (u.url || u.path || '');
      addEndpoint(rawUrl, 'GET', 'urlfinder', {
        host: typeof u === 'object' ? (u.host || '') : '',
        path: typeof u === 'object' ? (u.path || '') : '',
      });
    });
    sources.push({ name: 'URLFinder', count: co.urlfinder_data.urls.length, key: 'urlfinder' });
  }

  // Param mine (ffuf parameters / paths)
  if (co.param_mine_data) {
    const pmItems = co.param_mine_data.findings || co.param_mine_data.parameters || co.param_mine_data.results || [];
    let pmCount = 0;
    pmItems.forEach(item => {
      const rawUrl = typeof item === 'string' ? item : (item.url || item.path || '');
      if (!rawUrl) return;
      addEndpoint(rawUrl, 'GET', 'param_mine', {
        host: typeof item === 'object' ? (item.host || '') : '',
        path: typeof item === 'object' ? (item.path || '') : '',
        status: typeof item === 'object' ? item.status : null,
        type: 'Parameter',
        severity: 'info',
      });
      pmCount += 1;
    });
    if (pmCount) sources.push({ name: 'Param mine', count: pmCount, key: 'param_mine' });
  }

  // Playwright browser crawler URLs + XHR/fetch
  if (co.browser_crawl_data) {
    (co.browser_crawl_data.urls || []).forEach(u => {
      addEndpoint(typeof u === 'string' ? u : (u.url || ''), 'GET', 'browser_crawl', {
        type: 'Browser crawled URL',
        host: typeof u === 'object' ? (u.host || '') : '',
      });
    });
    (co.browser_crawl_data.api_endpoints || []).forEach(e => {
      const rawUrl = typeof e === 'string' ? e : (e.url || '');
      addEndpoint(rawUrl, typeof e === 'object' ? (e.method || 'GET') : 'GET', 'browser_crawl_xhr', {
        type: 'Browser XHR/fetch',
        severity: 'medium',
      });
    });
    (co.browser_crawl_data.results || []).forEach(r => {
      (r.urls || []).forEach(u => addEndpoint(u, 'GET', 'browser_crawl', {
        type: 'Browser crawled URL',
        host: r.host || '',
      }));
      (r.api_endpoints || []).forEach(e => addEndpoint(e.url || '', e.method || 'GET', 'browser_crawl_xhr', {
        type: 'Browser XHR/fetch',
        severity: 'medium',
        host: r.host || '',
      }));
    });
    sources.push({ name: 'Browser Crawl', count: (co.browser_crawl_data.url_count || 0) + (co.browser_crawl_data.api_endpoint_count || 0), key: 'browser_crawl' });
  }

  // JS Endpoints + Secrets
  if (co.js_data?.js_files) {
    co.js_data.js_files.forEach(js => {
      (js.endpoints || []).forEach(ep => {
        const eUrl = typeof ep === 'string' ? ep : (ep.url || ep.endpoint || ep.path || '');
        if (!eUrl) return;
        const method = (typeof ep === 'object' ? (ep.method || 'GET') : 'GET').toUpperCase();
        addEndpoint(eUrl, method, 'js', {
          host: js.host || '',
          path: typeof ep === 'object' ? (ep.path || '') : '',
          severity: typeof ep === 'object' ? ep.severity : '',
          jsFile: js.file || js.url || '',
        });
      });
      (js.secrets || []).forEach(s => {
        const val = typeof s === 'string' ? s : (s.value || s.secret || '');
        const stype = typeof s === 'object' ? (s.type || 'Unknown') : 'Unknown';
        if (!val || _isFpJsSecret(stype, val) || _jsHostIsNoise(js.host || '')) return;
        allSecrets.push({
          type: stype,
          value: val,
          file: js.file || js.url || '',
          host: js.host || '',
          url: js.url || js.file || '',
          severity: (typeof s === 'object' && s.severity) || 'high'
        });
      });
    });
    sources.push({ name: 'JS Extraction', count: co.js_data.total_endpoints || 0, key: 'js' });
  }

  (co.secrets_findings || []).forEach(sf => {
    if (!sf || typeof sf !== 'object') return;
    const meta = sf.metadata || {};
    const val = sf.value || '';
    const stype = meta.secret_type || (sf.type !== 'secret' ? sf.type : '') || 'secret';
    if (!val || _isFpJsSecret(stype, val) || _jsHostIsNoise(sf.host || '')) return;
    allSecrets.push({
      type: stype,
      value: val,
      file: meta.source_url || '',
      host: sf.host || '',
      url: meta.source_url || '',
      severity: sf.severity || 'high'
    });
  });

  // Runtime network captured while Playwright rendered JS-heavy pages.
  if (co.js_data?.runtime_network) {
    co.js_data.runtime_network.forEach(e => {
      const rawUrl = typeof e === 'string' ? e : (e.url || '');
      addEndpoint(rawUrl, typeof e === 'object' ? (e.method || 'GET') : 'GET', 'playwright_runtime', {
        type: typeof e === 'object' ? (e.type || 'Runtime network') : 'Runtime network',
        severity: 'medium',
      });
    });
    sources.push({ name: 'Playwright Runtime', count: co.js_data.runtime_network.length, key: 'playwright_runtime' });
  }

  // Runtime JS chunks/scripts captured by Playwright while rendering pages.
  if (co.js_data?.runtime_js_urls) {
    co.js_data.runtime_js_urls.forEach(u => {
      addEndpoint(typeof u === 'string' ? u : (u.url || ''), 'GET', 'playwright_runtime_js', {
        type: 'Runtime JS chunk',
        severity: 'medium',
      });
    });
    sources.push({ name: 'Runtime JS Chunks', count: co.js_data.runtime_js_urls.length, key: 'playwright_runtime_js' });
  }

  // API Panels
  if (co.api_exposure?.findings) {
    co.api_exposure.findings.forEach(f => {
      const rawUrl = f.url || '';
      if (rawUrl) {
        const cls = _classifyUrlMemo(rawUrl);
        allEndpoints.push({ url: rawUrl, method: f.method || '—', host: f.host || '', path: f.path || rawUrl, source: 'nuclei', type: 'API Panel', severity: f.severity || cls.severity });
      }
    });
    sources.push({ name: 'API Panels', count: co.api_exposure.total || 0, key: 'nuclei' });
  }

  // Deduplicate & sort
  const seen = new Set();
  const unique = allEndpoints.filter(ep => {
    if (!ep.url || typeof ep.url !== 'string') return false;
    const k = ep.method + '|' + ep.url;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  unique.sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity] || String(a.url || '').localeCompare(String(b.url || '')));

  // Compute stats
  const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: unique.length };
  const byType = {};
  const actualMethods = { GET: 0, POST: 0, PUT: 0, DELETE: 0, PATCH: 0 };
  unique.forEach(ep => {
    stats[ep.severity] = (stats[ep.severity] || 0) + 1;
    byType[ep.type] = (byType[ep.type] || 0) + 1;
    const m = ep.method.toUpperCase();
    if (actualMethods.hasOwnProperty(m)) actualMethods[m]++;
  });

  const seenSec = new Set();
  const uniqueSecrets = allSecrets.filter(s => {
    const k = String(s.type || '') + '|' + String(s.value || '') + '|' + String(s.file || s.url || '') + '|' + String(s.host || '');
    if (seenSec.has(k)) return false;
    seenSec.add(k);
    return true;
  });

  co._unifiedEndpoints = unique;
  co._unifiedSecrets = uniqueSecrets;
  co._unifiedSources = sources;
  co._epStats = { stats, byType, actualMethods };
  co._epStamp = stamp;
}

const SEV_CFG = {
  critical: { color: '#fb7185', bg: 'rgba(244,63,94,0.12)', border: 'rgba(244,63,94,0.25)', label: 'Critical', labelShort: 'CRIT' },
  high:     { color: '#fb923c', bg: 'rgba(251,146,60,0.12)', border: 'rgba(251,146,60,0.25)', label: 'High',     labelShort: 'HIGH' },
  medium:   { color: '#fbbf24', bg: 'rgba(251,191,36,0.1)',  border: 'rgba(251,191,36,0.25)',  label: 'Medium',   labelShort: 'MED' },
  low:      { color: '#4ade80', bg: 'rgba(34,197,94,0.1)',   border: 'rgba(34,197,94,0.2)',    label: 'Low',      labelShort: 'LOW' },
  info:     { color: '#60a5fa', bg: 'rgba(96,165,250,0.08)', border: 'rgba(96,165,250,0.2)',   label: 'Info',     labelShort: 'INFO' },
};

function renderEndpointsTab(co) {
  const el = document.getElementById("tab-endpoints");
  if (!el) return;

  // Show skeleton while building
  el.innerHTML = `<div class="section-shell">
    <div class="skel skel-text" style="width:30%"></div>
    <div class="skel skel-text" style="width:60%"></div>
    <div class="skel skel-card" style="height:120px;margin-top:12px"></div>
  </div>`;

  // Use requestAnimationFrame to let skeleton paint before heavy work
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      _renderEndpointsTabInner(co, el);
    });
  });
}

function _renderEndpointsTabInner(co, el) {
  buildUnifiedEndpoints(co);
  const unique = co._unifiedEndpoints;
  const allSecrets = co._unifiedSecrets;
  const sources = co._unifiedSources;
  const { stats, byType, actualMethods } = co._epStats;

  window._urlData = unique;
  window._allSecrets = allSecrets;
  window._urlPage = 1;
  window._urlActiveSev = '';
  window._urlActiveMethod = '';
  window._urlGrouped = false;
  if (_pendingFoundFilter && _pendingFoundFilter.tab === "endpoints") {
    window._urlSearch = _pendingFoundFilter.q;
    _pendingFoundFilter = null;
  }

  const hasFilters = window._urlActiveSev || window._urlActiveMethod;

  el.innerHTML = `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">Endpoint Inventory</div>
          <div class="section-title">URLs + JS routes + API panels — unified</div>
          <div class="section-sub">${esc(typeof t === "function" ? (t("ep_sub_origin") || "Clique a URL, o host ou o arquivo JS para abrir o local em que foi achado. A linha expande os detalhes.") : "Clique a URL, o host ou o arquivo JS para abrir o local em que foi achado. A linha expande os detalhes.")}</div>
        </div>
        <div class="section-actions">
          ${hasFilters ? `<button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px" onclick="clearUrlFilters()">${icoHtml("x",14)} Clear Filters</button>` : ''}
          <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px" onclick="copyUrlsToClipboard()">${icoHtml("clipboard",14)} Copy Visible</button>
          <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px" onclick="exportEndpointsCSV()">${icoHtml("chevron-down",14)} CSV</button>
        </div>
      </div>

      ${unique.length === 0 && allSecrets.length === 0 ? `
        <div class="empty-state"><div class="empty-state-icon" data-ico="inbox" aria-hidden="true"></div><div class="empty-state-title">No endpoints collected</div><div class="empty-state-copy">Run wayback, urlfinder, js and api_panels modules.</div></div>
      ` : `
        <!-- Stat strip: totals + methods + secrets (all clickable) -->
        <div class="url-stat-strip">
          <div class="url-stat${!window._urlActiveSev && !window._urlActiveMethod ? ' active' : ''}" onclick="filterUrlsBy('','')">
            <div class="url-stat-num" style="color:var(--teal)">${unique.length}</div>
            <div class="url-stat-lbl">ENDPOINTS</div>
          </div>
          ${['critical','high','medium','low','info'].map(sev => {
            const n = stats[sev] || 0;
            if (!n) return '';
            const c = SEV_CFG[sev];
            return `<div class="url-stat" data-filter="${sev}" onclick="filterUrlsBy('${sev}','')">
              <div class="url-stat-num" style="color:${c.color}">${n}</div>
              <div class="url-stat-lbl">${c.label}</div>
            </div>`;
          }).join('')}
          <div style="grid-column:span 2;border-top:1px solid var(--border);margin:2px 0"></div>
          ${Object.entries(actualMethods).filter(([,c])=>c>0).sort(([a],[b])=>['GET','POST','PUT','DELETE','PATCH'].indexOf(a)-['GET','POST','PUT','DELETE','PATCH'].indexOf(b)).map(([m,c]) => `
            <div class="url-stat" data-filter-method="${m}" onclick="filterUrlsBy('','${m}')">
              <div class="url-stat-num" style="color:${_methodColor(m)}">${c}</div>
              <div class="url-stat-lbl">${m}</div>
            </div>
          `).join('')}
          ${allSecrets.length > 0 ? `
            <div class="url-stat" role="button" tabindex="0" onclick="document.getElementById('endpoints-secrets')?.scrollIntoView({behavior:'smooth',block:'start'})">
              <div class="url-stat-num" style="color:var(--orange)">${allSecrets.length}</div>
              <div class="url-stat-lbl">SECRETS</div>
            </div>
          ` : ''}
        </div>

        <!-- Source chips -->
        <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center">
          ${sources.map(s => `<span class="source-chip"><span style="color:var(--text3)">${s.name}:</span> <b>${s.count}</b></span>`).join('')}
        </div>
        <div style="font-size:.68rem;color:var(--text3);margin:-4px 0 12px">${esc(typeof t === "function" ? (t("ep_js_noise") || "Imports de módulo, MIME e máscaras de data ficam de fora do inventário.") : "Imports de módulo, MIME e máscaras de data ficam de fora do inventário.")}</div>

        <!-- Filter bar -->
        <div class="filter-bar" style="margin-bottom:10px">
          <input type="text" id="url-search" class="fi grow" placeholder="Search URL, host, path…" oninput="filterUrlsTable()" value="${esc(window._urlSearch || '')}">
          <select id="url-type-filter" class="fi" onchange="filterUrlsTable()">
            <option value="">All types</option>
            ${Object.keys(byType).sort().map(t => `<option value="${esc(t)}"${window._urlTypeFilter === t ? ' selected' : ''}>${esc(t)} (${byType[t]})</option>`).join('')}
          </select>
          <select id="url-source-filter" class="fi" onchange="filterUrlsTable()">
            <option value="">All sources</option>
            ${sources.map(s => `<option value="${s.name}"${window._urlSourceFilter === s.name ? ' selected' : ''}>${s.name}</option>`).join('')}
          </select>
          <select id="url-method-filter" class="fi" onchange="filterUrlsTable()">
            <option value="">All methods</option>
            ${['GET','POST','PUT','DELETE','PATCH'].filter(m=>actualMethods[m]>0).map(m => `<option value="${m}"${window._urlMethodFilter === m ? ' selected' : ''}>${m} (${actualMethods[m]})</option>`).join('')}
          </select>
          <button class="btn btn-secondary" style="font-size:.64rem;padding:4px 10px;white-space:nowrap" onclick="toggleUrlGrouping()" id="url-group-btn">
             ${window._urlGrouped ? 'Flat List' : 'Group by Path'}
          </button>
          <span style="font-size:.68rem;color:var(--text3);padding:6px 4px" id="url-cnt">${unique.length} endpoints</span>
        </div>

        <!-- Endpoints Table / Grouped View -->
        <div id="urls-table-wrap"></div>
        <div class="pager" style="margin-top:8px">
          <span class="pager-info" id="url-pinfo"></span>
          <div class="pager-btns" id="url-pbtns"></div>
        </div>

        <!-- Secrets section -->
        ${allSecrets.length > 0 ? `
          <div id="endpoints-secrets" class="endpoints-secrets">
          <div class="section-head" style="margin-top:24px">
            <div class="section-head-main">
              <div class="section-kicker">${icoHtml("key",14)} Embedded Secrets</div>
              <div class="section-title">Credentials, tokens and keys from JS</div>
              <div class="section-sub">${esc(typeof t === "function" ? (t("ep_secrets_sub") || "Clique o arquivo ou o host para abrir o local em que o secret foi achado. O valor mascarado revela no clique.") : "Clique o arquivo ou o host para abrir o local em que o secret foi achado. O valor mascarado revela no clique.")}</div>
            </div>
          </div>
          <div class="url-table-wrap">
            <table class="url-table">
              <thead><tr>
                <th style="width:14%">Type</th>
                <th style="width:34%">Value (click to reveal)</th>
                <th style="width:28%">File</th>
                <th style="width:14%">Host</th>
                <th style="width:10%">Risk</th>
              </tr></thead>
              <tbody>
                ${allSecrets.map(s => {
                  const masked = maskSecret(s.value);
                  const sevColor = s.severity === 'critical' ? '#fb7185' : s.severity === 'high' ? '#fb923c' : '#fbbf24';
                  const fileSrc = s.file || s.url || '';
                  const fileHref = originHref(fileSrc, s.host);
                  const fileLabel = fileSrc.replace(/^https?:\/\//, '').substring(0, 72) || fileSrc;
                  const fileCell = fileHref
                    ? originLinkHtml(fileSrc, fileLabel, { host: s.host, className: "origin-link origin-mono", title: _originTitle("js") })
                    : `<button type="button" class="origin-jump" onclick="jumpToFound('jsreverse', ${_jsArg(fileSrc || s.host || s.type)})">${esc(fileSrc || "JS Reverse")}</button>`;
    return `<tr>
                    <td><span class="url-type-badge" style="background:rgba(251,146,60,0.1);color:#fb923c;border:1px solid rgba(251,146,60,0.2)">${esc(s.type)}</span></td>
                    <td><code class="secret-value" title="Click to reveal" onclick="this.textContent='${esc(s.value).replace(/'/g,"\\'")}';this.classList.add('revealed')">${esc(masked)}</code></td>
                    <td>${fileCell}</td>
                    <td>${s.host ? originHostChip(s.host, "fg-host-chip origin-link") : '<span style="font-size:.68rem;color:var(--text3)">—</span>'}</td>
                    <td><span class="url-risk-badge" style="background:rgba(251,146,60,0.1);color:${sevColor}">${s.severity.toUpperCase()}</span></td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table>
          </div>
          </div>
        ` : ''}
      `}
    </div>`;

  filterUrlsTable();
}

// ── Clear filters ──────────────────────────────────────────────────────────

function clearUrlFilters() {
  window._urlActiveSev = '';
  window._urlActiveMethod = '';
  window._urlPage = 1;
  window._urlSearch = '';
  window._urlTypeFilter = '';
  window._urlSourceFilter = '';
  window._urlMethodFilter = '';
  const co = allCompanies().find(c => c.id === state.currentId);
  if (co) renderEndpointsTab(co);
}

function toggleUrlGrouping() {
  window._urlGrouped = !window._urlGrouped;
  window._urlPage = 1;
  const btn = document.getElementById('url-group-btn');
  if (btn) btn.textContent = window._urlGrouped ? ' Flat List' : ' Group by Path';
  filterUrlsTable();
}

// ── Endpoint table filtering and helpers ─────────────────────────────────────

function filterUrlsBy(sev, method) {
  window._urlActiveSev = sev || '';
  window._urlActiveMethod = method || '';
  window._urlPage = 1;
  $$('.url-stat').forEach(el => {
    const filterSev = el.dataset.filter;
    const filterMethod = el.dataset.filterMethod;
    if (filterSev) el.classList.toggle('active', filterSev === sev && !method);
    else if (filterMethod) el.classList.toggle('active', filterMethod === method);
    else el.classList.toggle('active', !sev && !method);
  });
  filterUrlsTable();
}

function filterUrlsTable() {
  if (!window._urlData) return;
  const search = (document.getElementById('url-search')?.value || '').toLowerCase();
  window._urlSearch = search;
  const typeFilter = document.getElementById('url-type-filter')?.value || '';
  window._urlTypeFilter = typeFilter;
  const sourceFilter = document.getElementById('url-source-filter')?.value || '';
  window._urlSourceFilter = sourceFilter;
  const methodFilter = document.getElementById('url-method-filter')?.value || '';
  window._urlMethodFilter = methodFilter;
  const activeSev = window._urlActiveSev || '';
  const activeMethod = window._urlActiveMethod || '';

  let filtered = window._urlData.filter(u => {
    if (search && !`${u.url} ${u.host} ${u.path} ${u.type} ${u.method}`.toLowerCase().includes(search)) return false;
    if (typeFilter && u.type !== typeFilter) return false;
    if (sourceFilter) {
      const srcMap = { 'Wayback': 'wayback', 'URLFinder': 'urlfinder', 'JS Extraction': 'js', 'API Panels': 'nuclei' };
      if ((srcMap[sourceFilter] || sourceFilter.toLowerCase()) !== u.source) return false;
    }
    if (methodFilter && u.method.toUpperCase() !== methodFilter.toUpperCase()) return false;
    if (activeSev && u.severity !== activeSev) return false;
    if (activeMethod && u.method.toUpperCase() !== activeMethod.toUpperCase()) return false;
    return true;
  });

  // Update count badge
  const cnt = document.getElementById('url-cnt');
  const activeLabel = [activeSev, activeMethod].filter(Boolean).join(' + ');
  if (cnt) cnt.textContent = `${filtered.length} endpoint${filtered.length !== 1 ? 's' : ''}${activeLabel ? ' (' + activeLabel + ')' : ''}`;

  if (window._urlGrouped) {
    _renderGroupedView(filtered);
  } else {
    _renderFlatTable(filtered);
  }
}

// ── Flat table view (with expandable rows) ──────────────────────────────────

function _renderFlatTable(filtered) {
  const wrap = document.getElementById('urls-table-wrap');
  if (!wrap) return;

  const perPage = 50;
  const total = filtered.length;
  const totalPages = Math.ceil(total / perPage) || 1;
  window._urlPage = Math.max(1, Math.min(window._urlPage, totalPages));
  const start = (window._urlPage - 1) * perPage;
  const page = filtered.slice(start, start + perPage);

  const pinfo = document.getElementById('url-pinfo');
  if (pinfo) pinfo.textContent = total ? `${start + 1}\u2013${Math.min(start + perPage, total)} of ${total}` : '0 results';

  if (!total) {
    wrap.innerHTML = '<div class="url-table-wrap"><table class="url-table"><tbody><tr><td colspan="7" style="text-align:center;padding:28px;color:var(--text3)">No endpoints match filters</td></tr></tbody></table></div>';
    const pbtns = document.getElementById('url-pbtns');
    if (pbtns) pbtns.innerHTML = '';
    return;
  }

  const methodColors = { GET: '#4ade80', POST: '#fb923c', PUT: '#60a5fa', DELETE: '#fb7185', PATCH: '#a78bfa' };

  wrap.innerHTML = `<div class="url-table-wrap">
    <table class="url-table">
      <thead><tr>
        <th style="width:6%">Method</th>
        <th style="width:42%">URL</th>
        <th style="width:13%">Type</th>
        <th style="width:13%">Host</th>
        <th style="width:9%">Source</th>
        <th style="width:9%">Risk</th>
        <th style="width:8%">Copy</th>
      </tr></thead>
      <tbody id="urls-tbody">
        ${page.map((ep, i) => {
          const sc = SEV_CFG[ep.severity] || SEV_CFG.info;
          const mc = methodColors[ep.method] || 'var(--text3)';
          const idx = start + i;
          const displayUrl = ep.url.length > 80 ? ep.url.substring(0, 77) + '\u2026' : ep.url;
          const hasQuery = ep.url.includes('?');
          return `<tr class="ep-row" onclick="toggleEpRow(this,'${idx}')" title="${esc(_originTitle())}">
            <td><span class="js-method-badge" style="background:${mc}12;color:${mc};border:1px solid ${mc}25;font-weight:700">${esc(ep.method)}</span>${ep.auth && ep.auth !== 'unknown' && ep.auth !== 'none_detected' ? `<span class="method-badge" style="background:var(--border);color:var(--teal);font-size:.58rem;padding:1px 5px;border-radius:3px;margin-left:3px" title="Auth: ${esc(ep.auth)}">${ep.auth === 'bearer' ? icoHtml("key",14)+'JWT' : ep.auth === 'api_key_header' ? icoHtml("key",14)+'API' : ep.auth === 'basic' ? icoHtml("lock",14)+'Basic' : ep.auth === 'oauth2' ? icoHtml("key",14)+'OAuth2' : ep.auth === 'cookie_session' ? icoHtml("tag",14)+'Session' : esc(ep.auth)}</span>` : ep.auth === 'none_detected' ? `<span class="method-badge" style="background:rgba(239,68,68,0.15);color:var(--red);font-size:.58rem;padding:1px 5px;border-radius:3px;margin-left:3px" title="No auth detected">${icoHtml("warning",14)} NOAUTH</span>` : ''}</td>
            <td>
              <div class="url-cell">
                ${originLinkHtml(ep.url, displayUrl, { host: ep.host, className: "url-cell-link ep-url-main origin-link", title: _originTitle() })}
                ${hasQuery ? '<span class="ep-expand-hint">\u25B6 Expand</span>' : ''}
              </div>
            </td>
            <td><span class="url-type-badge" style="background:${sc.bg};color:${sc.color};border:1px solid ${sc.color}22">${esc(ep.type)}</span></td>
            <td>${ep.host ? originHostChip(ep.host, "url-cell-host origin-link") : '<span class="url-cell-host">\u2014</span>'}</td>
            <td><span class="source-chip" style="font-size:.6rem">${esc(ep.source)}</span></td>
            <td><span class="url-risk-badge" style="background:${sc.bg};color:${sc.color};font-weight:700">${sc.labelShort}</span></td>
            <td><button class="url-copy-btn" onclick="copyToClipboard('${escAttr(ep.url).replace(/'/g,"\\'")}');event.stopPropagation()" title="${esc(typeof t === "function" ? (t("origin_copy") || "Copiar") : "Copiar")}">${icoHtml("clipboard",14)}</button></td>
          </tr>
          <tr class="ep-detail ep-detail-${idx}" style="display:none">
            <td colspan="7">
              <div class="ep-detail-box">
                <div class="ep-detail-row"><span class="ep-detail-k">Full URL</span>${originLinkHtml(ep.url, ep.url, { host: ep.host, className: "ep-detail-url origin-link", title: _originTitle() })}</div>
                <div class="ep-detail-row"><span class="ep-detail-k">Path</span><code class="ep-detail-code">${esc(ep.path || '/')}</code></div>
                ${hasQuery ? `<div class="ep-detail-row"><span class="ep-detail-k">Query Params</span><code class="ep-detail-code">${esc(_extractQuery(ep.url))}</code></div>` : ''}
                <div class="ep-detail-row"><span class="ep-detail-k">Host</span>${ep.host ? originHostChip(ep.host, "origin-link") : '<span style="color:var(--text2)">\u2014</span>'}</div>
                <div class="ep-detail-row"><span class="ep-detail-k">Source</span><span class="source-chip" style="font-size:.62rem">${esc(ep.source)}</span></div>
                ${ep.status ? `<div class="ep-detail-row"><span class="ep-detail-k">Status</span><span style="color:var(--text2);font-family:var(--mono)">${ep.status}</span></div>` : ''}
                ${ep.jsFile ? `<div class="ep-detail-row"><span class="ep-detail-k">JS File</span>${originLinkHtml(ep.jsFile, ep.jsFile, { host: ep.host, className: "origin-link origin-mono", title: _originTitle("js") })}</div>` : ''}
                <div class="ep-detail-actions">
                  <button class="btn btn-secondary" style="font-size:.62rem;padding:3px 8px" onclick="copyToClipboard('${escAttr(ep.url).replace(/'/g,"\\'")}')">${icoHtml("clipboard",14)} Copy URL</button>
                  ${originHref(ep.url, ep.host) ? `<a href="${esc(originHref(ep.url, ep.host))}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary" style="font-size:.62rem;padding:3px 8px;text-decoration:none">${icoHtml("link",14)} Abrir</a>` : ""}
                  ${ep.jsFile ? `<button type="button" class="btn btn-secondary" style="font-size:.62rem;padding:3px 8px" onclick="jumpToFound('jsreverse', ${_jsArg(ep.jsFile)})">JS Reverse</button>` : ""}
                </div>
              </div>
            </td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>
  </div>`;

  // Pagination
  const pbtns = document.getElementById('url-pbtns');
  if (pbtns && totalPages > 1) {
    let btns = '';
    for (let i = Math.max(1, window._urlPage - 2); i <= Math.min(totalPages, window._urlPage + 2); i++)
      btns += `<button class="pb${i === window._urlPage ? ' active' : ''}" onclick="window._urlPage=${i};filterUrlsTable()">${i}</button>`;
    if (window._urlPage > 1) btns = `<button class="pb" onclick="window._urlPage--;filterUrlsTable()">\u2190</button>` + btns;
    if (window._urlPage < totalPages) btns += `<button class="pb" onclick="window._urlPage++;filterUrlsTable()">\u2192</button>`;
    pbtns.innerHTML = btns;
  } else if (pbtns) { pbtns.innerHTML = ''; }
}

// ── Grouped view (by path pattern) ──────────────────────────────────────────

function _renderGroupedView(filtered) {
  const wrap = document.getElementById('urls-table-wrap');
  if (!wrap) return;

  // Group by path prefix: /api/v1/users/123 -> /api/v1/users/*
  const groups = new Map();
  filtered.forEach(ep => {
    const pattern = _pathPattern(ep.path || ep.url || '');
    if (!groups.has(pattern)) groups.set(pattern, []);
    groups.get(pattern).push(ep);
  });

  // Sort groups by count desc, then alpha
  const sorted = [...groups.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));

  const total = sorted.length;
  const perPage = 30;
  const totalPages = Math.ceil(total / perPage) || 1;
  window._urlPage = Math.max(1, Math.min(window._urlPage, totalPages));
  const start = (window._urlPage - 1) * perPage;
  const page = sorted.slice(start, start + perPage);

  const pinfo = document.getElementById('url-pinfo');
  if (pinfo) pinfo.textContent = total ? `${start + 1}\u2013${Math.min(start + perPage, total)} of ${total} path groups` : '0 results';

  if (!total) {
    wrap.innerHTML = '<div class="url-table-wrap"><table class="url-table"><tbody><tr><td colspan="1" style="text-align:center;padding:28px;color:var(--text3)">No endpoints match filters</td></tr></tbody></table></div>';
    const pbtns = document.getElementById('url-pbtns');
    if (pbtns) pbtns.innerHTML = '';
    return;
  }

  wrap.innerHTML = page.map(([pattern, eps]) => {
    const sevs = {};
    const methods = new Set();
    eps.forEach(ep => {
      sevs[ep.severity] = (sevs[ep.severity] || 0) + 1;
      methods.add(ep.method);
    });
    const topSev = Object.keys(sevs).sort((a,b) => ({critical:0,high:1,medium:2,low:3,info:4}[a]||4)-({critical:0,high:1,medium:2,low:3,info:4}[b]||4))[0] || 'info';
    const sc = SEV_CFG[topSev] || SEV_CFG.info;

    return `<div class="ep-group">
      <div class="ep-group-hdr" onclick="this.parentElement.classList.toggle('open')">
        <span class="ep-group-chevron">\u25B6</span>
        <span class="ep-group-pattern">${esc(pattern)}</span>
        <span class="source-chip" style="font-size:.6rem;margin-left:8px">${eps.length} endpoint${eps.length>1?'s':''}</span>
        <span class="url-risk-badge" style="background:${sc.bg};color:${sc.color};font-weight:700;margin-left:auto">${sc.labelShort}</span>
        <span style="font-size:.62rem;color:var(--text3);margin-left:8px">${[...methods].join(', ')}</span>
      </div>
      <div class="ep-group-body">
        ${eps.slice(0, 12).map(ep => {
          const displayUrl = ep.url.length > 100 ? ep.url.substring(0, 97) + '\u2026' : ep.url;
          return `<div class="ep-group-item">
            <span class="js-method-badge" style="font-size:.58rem;padding:1px 5px;background:${(_methodColor(ep.method))}12;color:${_methodColor(ep.method)};border:1px solid ${_methodColor(ep.method)}25">${esc(ep.method)}</span>${ep.auth && ep.auth !== 'unknown' && ep.auth !== 'none_detected' ? `<span class="method-badge" style="background:var(--border);color:var(--teal);font-size:.58rem;padding:1px 5px;border-radius:3px;margin-left:3px" title="Auth: ${esc(ep.auth)}">${ep.auth === 'bearer' ? icoHtml("key",14)+'JWT' : ep.auth === 'api_key_header' ? icoHtml("key",14)+'API' : ep.auth === 'basic' ? icoHtml("lock",14)+'Basic' : ep.auth === 'oauth2' ? icoHtml("key",14)+'OAuth2' : ep.auth === 'cookie_session' ? icoHtml("tag",14)+'Session' : esc(ep.auth)}</span>` : ep.auth === 'none_detected' ? `<span class="method-badge" style="background:rgba(239,68,68,0.15);color:var(--red);font-size:.58rem;padding:1px 5px;border-radius:3px;margin-left:3px" title="No auth detected">${icoHtml("warning",14)} NOAUTH</span>` : ''}
            ${originLinkHtml(ep.url, displayUrl, { host: ep.host, className: "url-cell-link origin-link", title: _originTitle() })}
            <button class="url-copy-btn" style="margin-left:auto" onclick="copyToClipboard('${escAttr(ep.url).replace(/'/g,"\\'")}');event.stopPropagation()" title="${esc(typeof t === "function" ? (t("origin_copy") || "Copiar") : "Copiar")}">${icoHtml("clipboard",14)}</button>
          </div>`;
        }).join('')}
        ${eps.length > 12 ? `<div style="padding:4px 10px;font-size:.62rem;color:var(--text3)">+ ${eps.length - 12} more endpoints in this group</div>` : ''}
      </div>
    </div>`;
  }).join('');

  // Pagination
  const pbtns = document.getElementById('url-pbtns');
  if (pbtns && totalPages > 1) {
    let btns = '';
    for (let i = Math.max(1, window._urlPage - 2); i <= Math.min(totalPages, window._urlPage + 2); i++)
      btns += `<button class="pb${i === window._urlPage ? ' active' : ''}" onclick="window._urlPage=${i};filterUrlsTable()">${i}</button>`;
    if (window._urlPage > 1) btns = `<button class="pb" onclick="window._urlPage--;filterUrlsTable()">\u2190</button>` + btns;
    if (window._urlPage < totalPages) btns += `<button class="pb" onclick="window._urlPage++;filterUrlsTable()">\u2192</button>`;
    pbtns.innerHTML = btns;
  } else if (pbtns) { pbtns.innerHTML = ''; }
}

function _pathPattern(pathOrUrl) {
  let p = String(pathOrUrl || '');
  // Strip scheme + host
  const m = p.match(/https?:\/\/[^\/]+(\/.*)/i);
  if (m) p = m[1];
  if (!p) p = '/';
  // Normalize numeric/hex IDs to *
  let pattern = p.replace(/\/\d+(?=[\/?#]|$)/g, '/*')
                .replace(/\/[0-9a-f]{24,}(?=[\/?#]|$)/gi, '/*')
                .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=[\/?#]|$)/gi, '/*')
                .replace(/\/[^\/]*\.(html?|php|asp|aspx|jsp)(?=[?#]|$)/i, '/*.$1');
  // Remove query string
  const qi = pattern.indexOf('?');
  if (qi !== -1) pattern = pattern.substring(0, qi);
  return pattern || '/';
}

function _extractQuery(url) {
  const qi = url.indexOf('?');
  if (qi === -1) return '';
  try {
    const params = new URL(url).searchParams;
    const keys = [];
    params.forEach((v, k) => keys.push(k + (v ? '=' + v.substring(0, 80) : '')));
    return keys.join('&').substring(0, 300) || url.substring(qi + 1).substring(0, 300);
  } catch (e) {
    return url.substring(qi + 1).substring(0, 300);
  }
}

function toggleEpRow(tr, idx) {
  const detail = tr.parentElement.querySelector('.ep-detail-' + idx);
  if (!detail) return;
  if (detail.style.display === 'none' || !detail.style.display) {
    // Close all others
    tr.parentElement.querySelectorAll('.ep-detail').forEach(d => d.style.display = 'none');
    tr.parentElement.querySelectorAll('.ep-row').forEach(r => r.classList.remove('expanded'));
    detail.style.display = '';
    tr.classList.add('expanded');
    const hint = tr.querySelector('.ep-expand-hint');
    if (hint) hint.textContent = '\u25BC Collapse';
  } else {
    detail.style.display = 'none';
    tr.classList.remove('expanded');
    const hint = tr.querySelector('.ep-expand-hint');
    if (hint) hint.textContent = '\u25B6 Expand';
  }
}

// ── Clipboard helpers ──────────────────────────────────────────────────────

function copyToClipboard(text) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).catch(() => _fallbackCopy(text));
  } else {
    _fallbackCopy(text);
  }
}
function _fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
}

function copyUrlsToClipboard() {
  if (!window._urlData) return;
  const filtered = getFilteredUrls();
  copyToClipboard(filtered.map(u => u.url).join('\n'));
}

function getFilteredUrls() {
  if (!window._urlData) return [];
  const search = (document.getElementById('url-search')?.value || '').toLowerCase();
  const typeFilter = document.getElementById('url-type-filter')?.value || '';
  const methodFilter = document.getElementById('url-method-filter')?.value || '';
  const sourceFilter = document.getElementById('url-source-filter')?.value || '';
  const activeSev = window._urlActiveSev || '';
  const activeMethod = window._urlActiveMethod || '';
  return window._urlData.filter(u => {
    if (search && !`${u.url} ${u.host} ${u.path} ${u.type} ${u.method}`.toLowerCase().includes(search)) return false;
    if (typeFilter && u.type !== typeFilter) return false;
    if (sourceFilter) {
      const srcMap = { 'Wayback': 'wayback', 'URLFinder': 'urlfinder', 'JS Extraction': 'js', 'API Panels': 'nuclei' };
      if ((srcMap[sourceFilter] || sourceFilter.toLowerCase()) !== u.source) return false;
    }
    if (methodFilter && u.method.toUpperCase() !== methodFilter.toUpperCase()) return false;
    if (activeSev && u.severity !== activeSev) return false;
    if (activeMethod && u.method.toUpperCase() !== activeMethod.toUpperCase()) return false;
    return true;
  });
}

// ── JS endpoint classification helpers ───────────────────────────────────────
function classifyEndpoint(url, method) {
  const u = String(url || '').toLowerCase();
  if (/\/(auth|login|signin|oauth|sso|token|session)/.test(u)) return 'Auth';
  if (/\/(admin|manage|dashboard|panel|console|control)/.test(u)) return 'Admin';
  if (/\b(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(u)) return 'Internal IP';
  if (/\/(api|graphql|rest|webhook|callback|endpoint)\//.test(u)) return 'API';
  if (/(\.php|\.asp|\.aspx|\.jsp|\.do|\.action|\.cfm)/.test(u)) return 'Dynamic';
  if (/\/(upload|file|media|asset|static|dist|build)\//.test(u)) return 'Static';
  if (/^wss?:\/\//.test(u)) return 'WebSocket';
  if (/(config|setup|install|debug|health|status|ping|info)/.test(u)) return 'Config';
  const m = String(method || 'GET').toUpperCase();
  if (m === 'POST' || m === 'PUT' || m === 'DELETE' || m === 'PATCH') return 'Mutation';
  return 'Route';
}

function _methodColor(m) {
  return { GET: '#4ade80', POST: '#fb923c', PUT: '#60a5fa', DELETE: '#fb7185', PATCH: '#a78bfa' }[m] || 'var(--text2)';
}

function maskSecret(val) {
  const s = String(val || '');
  if (s.length <= 8) return '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
  return s.substring(0, 4) + '\u2022\u2022\u2022\u2022' + s.substring(s.length - 4);
}

function exportEndpointsCSV() {
  if (!window._urlData) return;
  const rows = [['Method', 'URL', 'Type', 'Host', 'Path', 'Source', 'Severity']];
  window._urlData.forEach(ep => rows.push([ep.method, ep.url, ep.type, ep.host, ep.path || '', ep.source, ep.severity]));
  const csv = rows.map(r => r.map(v => '"' + String(v).replace(/"/g, "'") + '"').join(',')).join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'endpoints_inventory.csv';
  a.click();
}

// ═══════════════════════════════════════════════════════════════════════
// BRAND DOMAINS TAB
// ═══════════════════════════════════════════════════════════════════════
function renderTyposquatTab(co) {
  const el = document.getElementById("tab-typosquat");
  if (!el) return;

  const td = co.typosquat_data || {};
  const registered = td.registered || [];

  // Partition by status
  const critical      = registered.filter(r => r.risk === 'critical');
  const broker        = registered.filter(r => r.status === 'broker_listed' && r.risk !== 'critical');
  const active        = registered.filter(r => r.status === 'active' && r.risk !== 'critical');
  const noip          = registered.filter(r => r.status === 'registered_no_ip');
  const parked        = registered.filter(r => r.status === 'parked');
  const companyOwned  = registered.filter(r => r.status === 'company_owned');
  const opensquat     = (co.opensquat_alerts || []);

  // Update group badge
  const gc = document.getElementById('gc-brandgroup');
  if (gc) {
    const atRisk = critical.length + broker.length + active.length;
    gc.textContent = atRisk > 0 ? atRisk : '';
    gc.style.background = critical.length > 0 ? 'var(--purple)' : atRisk > 0 ? 'var(--red)' : '';
  }

  const RISK_COLOR = {
    critical: 'var(--purple)', high: 'var(--red)',
    medium: 'var(--orange)',   low:  'var(--text3)'
  };
  const STATUS_LABEL = {
    broker_listed:         { label: 'À VENDA',       color: 'var(--red)',    ico: 'tag' },
    active:                { label: 'ATIVO',          color: 'var(--orange)', ico: 'warning' },
    registered_no_ip:      { label: 'REGISTRADO',     color: 'var(--yellow)', ico: 'clipboard' },
    parked:                { label: 'PARKED',          color: 'var(--text3)', ico: 'inbox' },
    registered_unreachable:{ label: 'SEM RESPOSTA',   color: 'var(--text3)', ico: 'question' },
    company_owned:         { label: 'PRÓPRIO',         color: 'var(--green)', ico: 'check-circle' },
  };

  const renderRow = r => {
    const st  = STATUS_LABEL[r.status] || { label: r.status || '?', color: 'var(--text3)' };
    const rc  = RISK_COLOR[r.risk] || 'var(--text3)';
    const ips = (r.ips || []).join(', ') || '—';

    // Extra intel badges
    const badges = [];
    if (r.has_mx)
      badges.push(`<span style="background:#b91c1c22;color:#f87171;border:1px solid #f8717144;border-radius:3px;padding:1px 5px;font-size:.6rem;font-weight:700"> MX</span>`);
    if ((r.ssl || {}).brand_in_cert)
      badges.push(`<span style="background:#7c3aed22;color:#a78bfa;border:1px solid #a78bfa44;border-radius:3px;padding:1px 5px;font-size:.6rem;font-weight:700">${icoHtml("lock",14)} SSL+BRAND</span>`);
    if ((r.ssl || {}).cn && !(r.ssl || {}).brand_in_cert)
      badges.push(`<span style="background:#1e3a5f22;color:#60a5fa;border:1px solid #60a5fa33;border-radius:3px;padding:1px 5px;font-size:.6rem">${icoHtml("lock",14)} SSL</span>`);
    if (r.mx_records && r.mx_records.length)
      badges.push(`<span style="font-size:.6rem;color:var(--text3)" title="${escAttr(r.mx_records.join(', '))}">${r.mx_records[0]}</span>`);

    const badgeHtml  = badges.length ? `<div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:3px">${badges.join('')}</div>` : '';
    const redirect   = r.redirect_to ? `<div style="font-size:.63rem;color:var(--text3);margin-top:2px">↳ ${esc(r.redirect_to)}</div>` : '';
    const whoisInfo  = (r.org || r.email)
      ? `<div style="font-size:.61rem;color:var(--text3);margin-top:2px">Reg: ${esc(r.org || r.email || '')}</div>` : '';
    const sslDetail  = (r.ssl || {}).cn
      ? `<div style="font-size:.61rem;color:var(--text3);margin-top:1px">CN: ${esc(r.ssl.cn)}</div>` : '';

    const riskLabel  = r.risk === 'critical'
      ? `<span style="color:var(--purple);font-size:.65rem;font-weight:800">CRÍTICO</span>`
      : `<span style="color:${rc};font-size:.65rem;font-weight:700;text-transform:uppercase">${r.risk||'—'}</span>`;

    return `<div class="typo-row" style="display:grid;grid-template-columns:1fr auto auto auto;gap:6px 14px;align-items:start;padding:9px 12px;border-bottom:1px solid var(--border2);font-size:.74rem">
      <div>
        <a href="https://${escAttr(r.domain)}" target="_blank" rel="noopener"
           style="color:var(--teal);font-family:monospace;font-weight:600">${esc(r.domain)}</a>
        ${redirect}
        ${ips !== '—' ? `<div style="font-size:.63rem;color:var(--text3);margin-top:1px">${esc(ips)}</div>` : ''}
        ${whoisInfo}${sslDetail}${badgeHtml}
      </div>
      <div style="white-space:nowrap;padding-top:2px;color:${st.color};font-size:.65rem;font-weight:700">${st.ico ? icoHtml(st.ico,14)+' ' : (st.icon||'')} ${st.label}</div>
      <div style="padding-top:2px">${riskLabel}</div>
      <div style="padding-top:2px"><a href="https://who.is/whois/${escAttr(r.domain)}" target="_blank" rel="noopener"
              style="font-size:.63rem;color:var(--text3);text-decoration:none">WHOIS ↗</a></div>
    </div>`;
  };

  const section = (title, icon, color, items, emptyMsg, collapse=false) => {
    if (!items.length && collapse) return '';
    if (!items.length) return `<div style="padding:10px 14px;color:var(--text3);font-size:.72rem">${emptyMsg}</div>`;
    return `<div class="section-shell" style="margin-bottom:14px">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker" style="color:${color}">${icon} ${title}</div>
          <div class="section-title">${items.length} domínio${items.length>1?'s':''}</div>
        </div>
      </div>
      ${items.map(renderRow).join('')}
    </div>`;
  };

  // opensquat recent alerts
  const opensquatHtml = opensquat.length ? `
    <div class="section-shell" style="margin-bottom:14px">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker" style="color:var(--teal)">${icoHtml("radar",14)} CT Log — Novos Registros (opensquat)</div>
          <div class="section-title">${opensquat.length} alerta${opensquat.length>1?'s':''} histórico${opensquat.length>1?'s':''}</div>
        </div>
      </div>
      ${opensquat.slice(-5).reverse().map(a=>`
        <div style="padding:7px 12px;border-bottom:1px solid var(--border2);font-size:.72rem;display:flex;gap:12px;align-items:center">
          <span style="color:var(--text3);font-size:.64rem;white-space:nowrap">${(a.date||'').slice(0,10)}</span>
          <span style="color:var(--orange);font-weight:700">+${a.new_count} domínios</span>
          <span style="color:var(--text3);font-size:.65rem">${(a.domains||[]).slice(0,4).join(', ')}${a.domains.length>4?' …':''}</span>
        </div>`).join('')}
    </div>` : '';

  const scanMeta = td.scanned_at
    ? `<span style="color:var(--text3);font-size:.68rem">Verificados: ${td.total_checked||0} · Registrados: ${td.registered_count||0} · Scan: ${(td.scanned_at||'').slice(0,10)||'?'}</span>`
    : `<span style="color:var(--text3);font-size:.68rem">Sem dados — rode o pipeline primeiro.</span>`;

  el.innerHTML = `
    <div style="padding:18px 20px;max-width:1100px;margin:0 auto">
      <div style="display:flex;align-items:baseline;gap:14px;margin-bottom:18px;flex-wrap:wrap">
        <div>
          <div style="font-size:1.1rem;font-weight:700;color:var(--text1)">Brand Domain Exposure</div>
          <div style="font-size:.74rem;color:var(--text3);margin-top:3px">Domínios que deveriam ser da empresa mas não são — risco de phishing e brand confusion.</div>
        </div>
        <div style="margin-left:auto">${scanMeta}</div>
      </div>

      <!-- Stat row -->
      <div style="display:flex;gap:10px;margin-bottom:18px;flex-wrap:wrap">
        ${[
          ['Crítico (MX+SSL)', critical.length, 'var(--purple)'],
          ['À Venda',          broker.length,   'var(--red)'],
          ['Ativos',           active.length,   'var(--orange)'],
          ['Registrados',      noip.length,     'var(--yellow)'],
          ['Parked',           parked.length,   'var(--text3)'],
          ['Próprios',         companyOwned.length,'var(--green)'],
        ].map(([label,count,color])=>`
          <div class="stat-card" style="min-width:100px;text-align:center">
            <div class="stat-value" style="color:${color}">${count}</div>
            <div class="stat-label">${label}</div>
          </div>`).join('')}
      </div>

      ${!registered.length ? `
        <div class="empty-state" style="padding:40px">
          <div class="empty-state-copy">Nenhum domínio de marca encontrado ainda.<br>
          Rode o módulo Typosquat no pipeline.</div>
        </div>` : `
        ${section('CRÍTICO — Phishing Kit Completo (MX e/ou SSL+Brand)', "", 'var(--purple)', critical, '', true)}
        ${section('À Venda em Broker',   "", 'var(--red)',    broker,       '(nenhum)')}
        ${section('Ativo — Terceiro',    icoHtml("warning",14), 'var(--orange)', active,       '(nenhum)')}
        ${section('Registrado sem IP',   icoHtml("clipboard",14), 'var(--yellow)', noip,         '(nenhum)')}
        ${section('Parked',              "", 'var(--text3)',  parked,       '', true)}
        ${section('Próprios da Empresa', "", 'var(--green)',  companyOwned, '', true)}
      `}

      ${opensquatHtml}

      <div style="margin-top:16px;padding:12px 14px;background:var(--bg3);border-radius:6px;font-size:.71rem;color:var(--text3)">
        <strong style="color:var(--text2)">O que fazer:</strong>
        <strong style="color:var(--purple)">Crítico</strong> = domínio ativo com MX (pode enviar e-mail como a marca) e/ou certificado SSL com nome da marca — remediar imediatamente (takedown ou registro).
        <strong style="color:var(--red)">À Venda</strong> = comprar antes do atacante.
        <strong style="color:var(--orange)">Ativo</strong> = monitorar e solicitar takedown via registrar.
        CT Log via opensquat detecta novos registros diariamente (cron 06:00).
      </div>
    </div>`;
}
