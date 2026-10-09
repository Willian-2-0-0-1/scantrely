// ════════════════════════════════════════════════════════════════════════
//  HELPERS (esc/wafColor/wafClass now in js/asm.js when loaded)
// ════════════════════════════════════════════════════════════════════════
if (typeof esc === 'undefined') {
  function esc(s) { return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
}

if (typeof wafColor === 'undefined') {
  function wafColor(w) {
    if(w.includes("Imperva")) return "#a78bfa";
    if(w.includes("Cloudflare")) return "#fb923c";
    if(w.includes("AWS")) return "#fbbf24";
    if(w.includes("Google")) return "#22c55e";
    if(w.includes("Akamai")) return "#60a5fa";
    return "#f43f5e";
  }
}

if (typeof wafClass === 'undefined') {
  function wafClass(w) {
  if(w.includes("Imperva")) return "waf-Imperva";
  if(w.includes("Cloudflare")) return "waf-Cloudflare";
  if(w.includes("AWS")) return "waf-AWS";
  if(w.includes("Google")) return "waf-Google";
  if(w.includes("Firewalled")) return "waf-Firewalled";
  if(w.includes("Akamai")) return "waf-Akamai";
  return "waf-Direct";
}
} // end if wafClass undefined

// ════════════════════════════════════════════════════════════════════════
//  AUTH
// ════════════════════════════════════════════════════════════════════════
let authToken = "";
try { authToken = localStorage.getItem("asmToken") || localStorage.getItem("asm_token") || ""; } catch(e) {}
let authUser  = null;

window._authHeaders = function _authHeaders() {
  var tok = authToken || "";
  try { tok = tok || localStorage.getItem("asmToken") || localStorage.getItem("asm_token") || ""; } catch(e) {}
  var headers = tok ? {"X-Auth-Token": tok} : {};
  headers["Content-Type"] = "application/json";
  return headers;
};

async function checkAuth() {
  if (!SERVER_MODE) return true;  // demo mode — no auth
  try {
    const r = await fetch("/api/auth/me", {headers: _authHeaders()});
    if (r.status === 401) { showLoginScreen(); return false; }
    authUser = await r.json();
    hideLoginScreen();
    document.getElementById("nu-name").textContent = authUser.username;
    document.getElementById("nu-role").textContent = authUser.role.replace("_"," ");
    if (authUser.role === "super_admin") {
      document.getElementById("nav-admin-section").style.display = "";
      document.getElementById("nav-admins").style.display = "";
    }
    return true;
  } catch(e) { return true; }
}

function showLoginScreen() {
  document.getElementById("login-screen").style.display = "flex";
}
function hideLoginScreen() {
  document.getElementById("login-screen").style.display = "none";
}

async function doLogin() {
  console.log("doLogin called");
  const btn  = document.getElementById("login-btn");
  const user = document.getElementById("login-user").value.trim();
  const pass = document.getElementById("login-pass").value;
  const totpEl = document.getElementById("login-totp");
  const totp = totpEl ? totpEl.value.trim() : "";
  const err  = document.getElementById("login-err");
  err.style.display = "none";
  if (!user || !pass) { err.textContent = "Enter username and password"; err.style.display = "block"; return; }
  btn.textContent = "Signing in…"; btn.disabled = true;
  try {
    const r = await fetch("/api/auth/login", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({username:user, password:pass, totp_code: totp}),
    });
    const d = await r.json();
    if (!r.ok && d.need_2fa) {
      const field = document.getElementById("login-totp-field");
      if (field) field.style.display = "";
      err.textContent = d.error || "Two-factor code required";
      err.style.display = "block";
      if (totpEl) totpEl.focus();
      return;
    }
    if (!r.ok) { err.textContent = d.error || "Login failed"; err.style.display="block"; return; }
    authToken = d.token;
    try { localStorage.setItem("asmToken", authToken); } catch(e) {}
    try { localStorage.setItem("asm_token", authToken); } catch(e) {}
    await checkAuth();
    await initApp();
  } catch(e) {
    console.error("Login error:", e);
    err.textContent = "Connection error"; err.style.display = "block";
  } finally {
    btn.textContent = "Sign In"; btn.disabled = false;
  }
}

async function doLogout() {
  try { await fetch("/api/auth/logout", {method:"POST", headers:_authHeaders()}); } catch(e){}
  authToken = ""; authUser = null;
  try { localStorage.removeItem("asmToken"); } catch(e) {}
  try { localStorage.removeItem("asm_token"); } catch(e) {}
  showLoginScreen();
}

// Patch fetch to always include auth header
const _origFetch = window.fetch;
window.fetch = function(url, opts={}) {
  if (typeof url === "string" && url.startsWith("/api/") && !url.includes("/auth/login")) {
    opts.headers = {...(opts.headers||{}), ..._authHeaders()};
  }
  return _origFetch(url, opts);
};

// ════════════════════════════════════════════════════════════════════════
//  PAGE ROUTING
// ════════════════════════════════════════════════════════════════════════
function showPage(page) {
  state.page = page || "companies";
  closeMobileNav();
  if (page !== "company") stopCompanyPipelineSync();
  document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(b=>b.classList.remove("active"));
  document.getElementById("crumb-sep").style.display = "none";
  document.getElementById("crumb-current").textContent = "";
  document.getElementById("topbar-scan-btn").style.display = "none";
  ["monitor-now-btn", "enable-schedule-btn"].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.style.display = "none";
  });
  document.getElementById("topbar-pill").innerHTML = "";
  document.querySelectorAll(".nav-co").forEach(el => el.classList.remove("active"));
  var stopBtn = document.getElementById("stop-pipeline-btn");
  if (stopBtn) stopBtn.style.display = "none";
  // Only stop the jobs table poll (nav badge poll always runs)
  if (_jobsPoll) { clearInterval(_jobsPoll); _jobsPoll = null; }

  const _t = (k) => (typeof window.t === 'function' ? window.t(k) : k);
  const _crumb = (k) => {
    document.getElementById("crumb-sep").style.display = "";
    document.getElementById("crumb-current").textContent = _t(k);
  };
  const _i18n = () => { if (typeof window.applyI18n === 'function') window.applyI18n(); };

  if (page === "companies") {
    _showCompaniesView();
    _i18n();
    if (typeof ASM !== 'undefined' && ASM.updateHash) ASM.updateHash('companies');
    return;
  } else if (page === "jobs") {
    state.page = "jobs";
    state.currentId = null;
    stopLiveDataPolling();
    document.body.classList.remove("executive-home");
    document.getElementById("view-jobs").classList.add("active");
    _syncSidebarActive();
    _crumb('crumb_jobs');
    loadJobs();
    _jobsPoll = setInterval(loadJobs, 5000);
    _i18n();
    if (typeof ASM !== 'undefined' && ASM.updateHash) ASM.updateHash('jobs');
  } else if (page === "tools") {
    state.page = "tools";
    state.currentId = null;
    stopLiveDataPolling();
    document.body.classList.remove("executive-home");
    document.getElementById("view-tools").classList.add("active");
    _syncSidebarActive();
    _crumb('crumb_tools');
    loadToolsStatus();
    _i18n();
    if (typeof ASM !== 'undefined' && ASM.updateHash) ASM.updateHash('tools');
  } else if (page === "settings") {
    state.page = "settings";
    state.currentId = null;
    stopLiveDataPolling();
    document.body.classList.remove("executive-home");
    document.getElementById("view-settings").classList.add("active");
    document.getElementById("nav-all").closest("nav").querySelectorAll(".nav-item").forEach(b=>{
      if(b.getAttribute("onclick")==="showPage('settings')") b.classList.add("active");
    });
    _crumb('crumb_settings');
    loadSettings();
    _i18n();
    if (typeof ASM !== 'undefined' && ASM.updateHash) ASM.updateHash('settings');
  } else if (page === "runtime") {
    state.page = "runtime";
    state.currentId = null;
    stopLiveDataPolling();
    document.body.classList.remove("executive-home");
    document.getElementById("view-runtime").classList.add("active");
    _syncSidebarActive();
    _crumb('crumb_runtime');
    loadRuntimeConfig();
    _i18n();
    if (typeof ASM !== 'undefined' && ASM.updateHash) ASM.updateHash('runtime');
  } else if (page === "admins") {
    state.page = "admins";
    state.currentId = null;
    stopLiveDataPolling();
    document.body.classList.remove("executive-home");
    document.getElementById("view-admins").classList.add("active");
    _syncSidebarActive();
    _crumb('crumb_admins');
    loadAdmins();
    _i18n();
    if (typeof ASM !== 'undefined' && ASM.updateHash) ASM.updateHash('admins');
  } else if (page === "bbhelper") {
    state.page = "bbhelper";
    state.currentId = null;
    stopLiveDataPolling();
    document.body.classList.remove("executive-home");
    document.getElementById("view-bbhelper").classList.add("active");
    _syncSidebarActive();
    _crumb('crumb_bbhelper');
    if (typeof showBBHelperPage === 'function') showBBHelperPage();
    if (typeof ASM !== 'undefined' && ASM.updateHash) ASM.updateHash('bbhelper');
  } else if (page === "exttools") {
    state.page = "exttools";
    state.currentId = null;
    stopLiveDataPolling();
    document.body.classList.remove("executive-home");
    document.getElementById("view-exttools").classList.add("active");
    _syncSidebarActive();
    _crumb('crumb_exttools');
    if (typeof showExtToolsPage === 'function') showExtToolsPage();
    if (typeof ASM !== 'undefined' && ASM.updateHash) ASM.updateHash('exttools');
  } else if (page === "bbprograms") {
    state.page = "bbprograms";
    state.currentId = null;
    stopLiveDataPolling();
    document.body.classList.remove("executive-home");
    document.getElementById("view-bbprograms").classList.add("active");
    _syncSidebarActive();
    _crumb('crumb_bbprograms');
    if (typeof showBBProgramsPage === 'function') showBBProgramsPage();
    _i18n();
    if (typeof ASM !== 'undefined' && ASM.updateHash) ASM.updateHash('bbprograms');
  } else if (page === "generators") {
    state.page = "generators";
    state.currentId = null;
    stopLiveDataPolling();
    document.body.classList.remove("executive-home");
    document.getElementById("view-generators").classList.add("active");
    _syncSidebarActive();
    _crumb('crumb_generators');
    if (typeof showGeneratorsPage === 'function') showGeneratorsPage();
    _i18n();
    if (typeof ASM !== 'undefined' && ASM.updateHash) ASM.updateHash('generators');
  } else if (page === "exposure") {
    state.page = "exposure";
    state.currentId = null;
    stopLiveDataPolling();
    document.body.classList.remove("executive-home");
    document.getElementById("view-exposure").classList.add("active");
    _syncSidebarActive();
    _crumb('crumb_exposure');
    if (typeof showExposurePage === 'function') showExposurePage();
    _i18n();
    if (typeof ASM !== 'undefined' && ASM.updateHash) ASM.updateHash('exposure');
  }
}
