/* bugbounty.js — Bug Bounty Helper + External Tools tabs.
 * Inspired by https://dorks.faisalahmed.me/
 * Click a module → opens Google (or the relevant service) for the typed domain.
 */

// ─────────────────────────── helpers ────────────────────────────
function _bbhEnc(q) { return encodeURIComponent(q); }
function _bbhGoogle(q) { return "https://www.google.com/search?q=" + _bbhEnc(q); }

// ─────────────────────────── category meta ───────────────────────
const BBH_CATEGORIES = [
  {id:"",         label:"All Modules",         key:"bbh_cat_all"},
  {id:"dorks",    label:"Google Dorks",         key:"bbh_cat_dorks"},
  {id:"recon",    label:"Recon & Subdomains",   key:"bbh_cat_recon"},
  {id:"archives", label:"Archives & History",   key:"bbh_cat_archives"},
  {id:"intel",    label:"OSINT & Intelligence", key:"bbh_cat_intel"},
  {id:"files",    label:"Specific Files",       key:"bbh_cat_files"},
];

// tag → css class suffix used for coloring
const BBH_TAG_STYLE = {
  dorks:    {bg:"rgba(99,102,241,.18)", color:"#a5b4fc", border:"rgba(99,102,241,.35)"},
  intel:    {bg:"rgba(20,184,166,.15)", color:"#2dd4bf", border:"rgba(20,184,166,.3)"},
  recon:    {bg:"rgba(34,197,94,.13)",  color:"#4ade80", border:"rgba(34,197,94,.28)"},
  files:    {bg:"rgba(251,191,36,.13)", color:"#fbbf24", border:"rgba(251,191,36,.28)"},
  archives: {bg:"rgba(249,115,22,.13)", color:"#fb923c", border:"rgba(249,115,22,.28)"},
};
const BBH_TAG_LABEL = {dorks:"DORKS", intel:"INTEL", recon:"RECON", files:"FILES", archives:"ARCHIVES"};

// ─────────────────────────── dork modules ────────────────────────
const DORK_MODULES = [
  // Google Dorks ───────────────────────────────────────────────────
  {id:"dir_listing",     label:"Directory Listing",    cat:"dorks", icon:"📂",
   url:d=>_bbhGoogle(`site:${d} intitle:"index of"`)},
  {id:"exposed_configs", label:"Exposed Configs",       cat:"dorks", icon:"⚙️",
   url:d=>_bbhGoogle(`site:${d} ext:xml | ext:conf | ext:cnf | ext:cfg | ext:ini | ext:env | ext:yml | ext:yaml | ext:json`)},
  {id:"db_files",        label:"DB Files",              cat:"dorks", icon:"🗄️",
   url:d=>_bbhGoogle(`site:${d} ext:sql | ext:dbf | ext:mdb | ext:db | ext:sqlite`)},
  {id:"log_files",       label:"Log Files",             cat:"dorks", icon:"📋",
   url:d=>_bbhGoogle(`site:${d} ext:log`)},
  {id:"backup_files",    label:"Backup Files",          cat:"dorks", icon:"💾",
   url:d=>_bbhGoogle(`site:${d} ext:bak | ext:backup | ext:old | ext:swp | ext:tar | ext:zip | ext:7z`)},
  {id:"login_pages",     label:"Login Pages",           cat:"dorks", icon:"🔐",
   url:d=>_bbhGoogle(`site:${d} inurl:login | inurl:signin | inurl:logon | intitle:login`)},
  {id:"sql_errors",      label:"SQL Errors",            cat:"dorks", icon:"💥",
   url:d=>_bbhGoogle(`site:${d} intext:"sql syntax near" | intext:"Warning: mysql_" | intext:"ORA-01756"`)},
  {id:"public_docs",     label:"Public Documents",      cat:"dorks", icon:"📄",
   url:d=>_bbhGoogle(`site:${d} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:csv`)},
  {id:"phpinfo",         label:"phpinfo()",             cat:"dorks", icon:"🐘",
   url:d=>_bbhGoogle(`site:${d} intitle:"phpinfo()" "PHP Version"`)},
  {id:"shells",          label:"Shells / Backdoors",    cat:"dorks", icon:"🐚",
   url:d=>_bbhGoogle(`site:${d} intitle:"shell" | inurl:shell.php | inurl:c99 | inurl:webshell`)},
  {id:"open_redirects",  label:"Open Redirects",        cat:"dorks", icon:"↩️",
   url:d=>_bbhGoogle(`site:${d} inurl:redirect= | inurl:url= | inurl:return= | inurl:next= | inurl:goto=`)},
  {id:"struts_rce",      label:"Struts RCE",            cat:"dorks", icon:"⚡",
   url:d=>_bbhGoogle(`site:${d} ext:action | ext:do inurl:struts`)},
  {id:"wp_files",        label:"WordPress Files",       cat:"dorks", icon:"🔵",
   url:d=>_bbhGoogle(`site:${d} inurl:wp-content | inurl:wp-includes | inurl:wp-admin`)},
  {id:"git_exposed",     label:"Git Exposed",           cat:"dorks", icon:"🐙",
   url:d=>_bbhGoogle(`site:${d} inurl:.git intitle:"index of"`)},
  {id:"gitlab_config",   label:"GitLab Config",         cat:"dorks", icon:"🦊",
   url:d=>_bbhGoogle(`site:${d} inurl:.gitlab-ci.yml | inurl:.gitlab`)},
  {id:"env_files",       label:"ENV Files",             cat:"dorks", icon:"🔑",
   url:d=>_bbhGoogle(`site:${d} ext:env "DB_PASSWORD" | "API_KEY" | "SECRET_KEY"`)},
  {id:"htaccess",        label:"Htaccess / Info",       cat:"dorks", icon:"🔒",
   url:d=>_bbhGoogle(`site:${d} ext:htaccess | ext:htpasswd | intitle:"index of" ".htaccess"`)},
  {id:"install_setup",   label:"Install / Setup",       cat:"dorks", icon:"🛠️",
   url:d=>_bbhGoogle(`site:${d} inurl:install | inurl:setup intitle:install`)},
  // OSINT & Intelligence ───────────────────────────────────────────
  {id:"pastebin",        label:"Pastebin Dumps",        cat:"intel", icon:"📝",
   url:d=>_bbhGoogle(`site:pastebin.com "${d}"`)},
  {id:"linkedin",        label:"LinkedIn Employees",    cat:"intel", icon:"💼",
   url:d=>_bbhGoogle(`site:linkedin.com/in "${d}"`)},
  {id:"github_src",      label:"GitHub Source",         cat:"intel", icon:"🐱",
   url:d=>_bbhGoogle(`site:github.com "${d}"`)},
  {id:"threatcrowd",     label:"ThreatCrowd",           cat:"intel", icon:"🕸️",
   url:d=>`https://www.threatcrowd.org/domain/${d}/`},
  {id:"openbugbounty",   label:"OpenBugBounty",         cat:"intel", icon:"🔓",
   url:d=>`https://www.openbugbounty.org/search/?search=${_bbhEnc(d)}`},
  {id:"reddit",          label:"Reddit Mentions",       cat:"intel", icon:"👽",
   url:d=>_bbhGoogle(`site:reddit.com "${d}"`)},
  {id:"censys_ipv4",     label:"Censys (IPv4)",         cat:"intel", icon:"🌐",
   url:d=>`https://search.censys.io/search?resource=hosts&q=${_bbhEnc(d)}`},
  {id:"censys_domains",  label:"Censys (Domains)",      cat:"intel", icon:"🌐",
   url:d=>`https://search.censys.io/search?resource=hosts&q=${_bbhEnc('services.tls.certificates.leaf_data.subject.common_name: '+d)}`},
  {id:"censys_certs",    label:"Censys (Certs)",        cat:"intel", icon:"🌐",
   url:d=>`https://search.censys.io/certificates?q=${_bbhEnc(d)}`},
  {id:"shodan",          label:"Shodan Search",         cat:"intel", icon:"🔭",
   url:d=>`https://www.shodan.io/search?query=${_bbhEnc('hostname:'+d)}`},
  {id:"virustotal",      label:"VirusTotal",            cat:"intel", icon:"🛡️",
   url:d=>`https://www.virustotal.com/gui/domain/${d}`},
  {id:"urlscan",         label:"Urlscan.io",            cat:"intel", icon:"🔍",
   url:d=>`https://urlscan.io/search/#${_bbhEnc(d)}`},
  {id:"wappalyzer",      label:"Wappalyzer",            cat:"intel", icon:"🧩",
   url:d=>`https://www.wappalyzer.com/lookup/${d}/`},
  {id:"builtwith",       label:"BuiltWith",             cat:"intel", icon:"🏗️",
   url:d=>`https://builtwith.com/${d}`},
  {id:"censys_platform", label:"Censys Platform",       cat:"intel", icon:"🌐",
   url:d=>`https://platform.censys.io/search?q=${_bbhEnc(d)}`},
  {id:"publicwww",       label:"PublicWWW",             cat:"intel", icon:"🔍",
   url:d=>`https://publicwww.com/websites/${_bbhEnc(d)}/`},
  {id:"zoomeye",         label:"ZoomEye",               cat:"intel", icon:"👁️",
   url:d=>`https://www.zoomeye.org/searchResult?q=${_bbhEnc(d)}`},
  {id:"jina",            label:"Jina AI",               cat:"intel", icon:"🤖",
   url:d=>`https://r.jina.ai/https://${d}`},
  // Recon & Subdomains ─────────────────────────────────────────────
  {id:"find_subs",       label:"Find Subdomains",       cat:"recon", icon:"🔎",
   url:d=>_bbhGoogle(`site:*.${d} -www`)},
  {id:"deep_subs",       label:"Deep Subdomains",       cat:"recon", icon:"🕳️",
   url:d=>_bbhGoogle(`site:*.${d} -site:www.${d}`)},
  {id:"crtsh",           label:"Crt.sh (Certificates)", cat:"recon", icon:"📜",
   url:d=>`https://crt.sh/?q=%25.${_bbhEnc(d)}`},
  {id:"sec_headers",     label:"Security Headers",      cat:"recon", icon:"🪖",
   url:d=>`https://securityheaders.com/?q=${_bbhEnc(d)}`},
  {id:"ssllabs",         label:"SSL Labs",              cat:"recon", icon:"🔐",
   url:d=>`https://www.ssllabs.com/ssltest/analyze.html?d=${_bbhEnc(d)}`},
  // Specific Files ─────────────────────────────────────────────────
  {id:"wayback_swf",     label:"Wayback SWF",           cat:"files", icon:"📼",
   url:d=>`https://web.archive.org/web/*/${d}/*.swf`},
  {id:"wayback_mime",    label:"Wayback MIME SWF",      cat:"files", icon:"📼",
   url:d=>`https://web.archive.org/cdx/search/cdx?url=*.${d}/*&output=text&fl=original&collapse=urlkey&filter=mimetype:application/x-shockwave-flash`},
  {id:"crossdomain",     label:"Crossdomain.xml",       cat:"files", icon:"🌍",
   url:d=>`https://${d}/crossdomain.xml`},
  {id:"swf_google",      label:"SWF (Google)",          cat:"files", icon:"📼",
   url:d=>_bbhGoogle(`site:${d} ext:swf`)},
  {id:"swf_yandex",      label:"SWF (Yandex)",          cat:"files", icon:"📼",
   url:d=>`https://yandex.com/search/?text=${_bbhEnc('site:'+d+' ext:swf')}`},
  // Archives & History ─────────────────────────────────────────────
  {id:"wayback_domain",  label:"Wayback Domain",        cat:"archives", icon:"🕰️",
   url:d=>`https://web.archive.org/web/*/${d}`},
  {id:"wayback_full",    label:"Wayback Full",          cat:"archives", icon:"🕰️",
   url:d=>`https://web.archive.org/web/*/${d}/*`},
  {id:"wayback_wp",      label:"Wayback WP",            cat:"archives", icon:"🕰️",
   url:d=>`https://web.archive.org/web/*/${d}/wp-content/*`},
];

// ─────────────────────────── external tools ──────────────────────
// These open directly — domain is optional (passed to services that accept it).
const EXT_TOOLS = [
  {id:"dnsbin",        label:"DNSBin",                  desc:"Request Interceptor",    icon:"📡",
   url:()=>"http://dnsbin.zhack.ca/"},
  {id:"hunterio",      label:"Hunter.io",               desc:"Email Finder",           icon:"📧",
   url:d=>d ? `https://hunter.io/search/${_bbhEnc(d)}` : "https://hunter.io/"},
  {id:"interactsh",    label:"Interactsh",              desc:"OOB / SSRF testing",     icon:"🌐",
   url:()=>"https://app.interactsh.com/"},
  {id:"dnsdumpster",   label:"DNS Dumpster",            desc:"DNS Recon & Research",   icon:"🗑️",
   url:d=>d ? `https://dnsdumpster.com/?q=${_bbhEnc(d)}` : "https://dnsdumpster.com/"},
  {id:"hackertarget",  label:"HackerTarget DNS",        desc:"DNS Lookup",             icon:"🎯",
   url:d=>d ? `https://hackertarget.com/dns-lookup/?q=${_bbhEnc(d)}` : "https://hackertarget.com/dns-lookup/"},
  {id:"cyberchef",     label:"CyberChef",               desc:"Encode / Decode / Crypto", icon:"🍳",
   url:()=>"https://gchq.github.io/CyberChef/"},
  {id:"regex101",      label:"Regex101",                desc:"RegEx Tester",           icon:"🔣",
   url:()=>"https://regex101.com/"},
  {id:"jwtio",         label:"JWT.io",                  desc:"JWT Debugger",           icon:"🔑",
   url:()=>"https://jwt.io/"},
  {id:"breachdir",     label:"Breach Directory",        desc:"Password / Hash Lookup", icon:"🔓",
   url:()=>"https://breachdirectory.org/"},
  {id:"ipconverter",   label:"IP Converter",            desc:"IP ↔ Integer converter", icon:"🔢",
   url:()=>"https://www.browserling.com/tools/ip-to-dec"},
  {id:"iptolong",      label:"IP to Long",              desc:"IP to 32-bit integer",   icon:"🔢",
   url:()=>"https://www.browserling.com/tools/ip-to-dec"},
  {id:"domainhistory", label:"Domain History",          desc:"WHOIS / IP History",     icon:"🕓",
   url:d=>d ? `https://viewdns.info/iphistory/?domain=${_bbhEnc(d)}` : "https://viewdns.info/iphistory/"},
  {id:"srccodesearch", label:"Source Code Search",      desc:"Search code repositories", icon:"💻",
   url:d=>d ? `https://searchcode.com/?q=${_bbhEnc(d)}` : "https://searchcode.com/"},
  {id:"fbcert",        label:"FB Cert Transparency",   desc:"Certificate Search",      icon:"🛡️",
   url:d=>d ? `https://developers.facebook.com/tools/ct/search/?q=${_bbhEnc(d)}` : "https://developers.facebook.com/tools/ct/"},
];

// ─────────────────────────── state ───────────────────────────────
let _bbhActiveCat = "";

function _bbhDomain() {
  const inp = document.getElementById("bbh-domain");
  return inp ? inp.value.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "") : "";
}

function bbhOnDomainInput() {
  const d = _bbhDomain();
  try { localStorage.setItem("bbh_domain", d); } catch(e) {}
  // Re-render ext-tools with the new domain (updates optional domain in links)
  if (document.getElementById("view-exttools") &&
      document.getElementById("view-exttools").classList.contains("active")) {
    _renderExtGrid();
  }
}

// ─────────────────────────── tag badge HTML ───────────────────────
function _bbhTagBadge(cat) {
  const s = BBH_TAG_STYLE[cat] || {};
  const lbl = BBH_TAG_LABEL[cat] || cat.toUpperCase();
  return `<span style="font-size:.58rem;font-weight:700;letter-spacing:.07em;padding:2px 7px;border-radius:8px;
    background:${s.bg||'rgba(255,255,255,.07)'};color:${s.color||'var(--text3)'};
    border:1px solid ${s.border||'var(--border)'};font-family:var(--mono);white-space:nowrap">${lbl}</span>`;
}

// ─────────────────────────── Bug Bounty Helper ────────────────────
function bbhSetCategory(cat) {
  _bbhActiveCat = cat;
  document.querySelectorAll("#bbh-cat-tabs .bbh-tab-btn").forEach(b => {
    b.classList.toggle("active", b.getAttribute("data-cat") === cat);
  });
  _renderBBHGrid();
}

function _renderBBHCategoryTabs() {
  const wrap = document.getElementById("bbh-cat-tabs");
  if (!wrap) return;
  wrap.innerHTML = BBH_CATEGORIES.map(c => {
    const label = (typeof window.t === 'function') ? window.t(c.key) : c.label;
    const active = c.id === _bbhActiveCat ? " active" : "";
    return `<button type="button" class="tab-btn bbh-tab-btn${active}" data-cat="${c.id}"
      onclick="bbhSetCategory('${c.id}')">${label}</button>`;
  }).join("");
}

function _renderBBHGrid() {
  const grid = document.getElementById("bbh-grid");
  if (!grid) return;
  const mods = _bbhActiveCat
    ? DORK_MODULES.filter(m => m.cat === _bbhActiveCat)
    : DORK_MODULES;

  grid.innerHTML = mods.map(m => `
    <div class="bbh-module-card" onclick="_bbhOpenModule('${m.id}')" role="button" tabindex="0"
         onkeydown="if(event.key==='Enter'||event.key===' ')_bbhOpenModule('${m.id}')">
      <div style="display:flex;align-items:center;gap:10px;min-width:0">
        <span class="bbh-icon">${m.icon}</span>
        <span class="bbh-module-label">${m.label}</span>
      </div>
      ${_bbhTagBadge(m.cat)}
    </div>`).join("");
}

function _bbhOpenModule(id) {
  const mod = DORK_MODULES.find(m => m.id === id);
  if (!mod) return;
  const d = _bbhDomain();
  if (!d) {
    // Flash the domain input instead of alert
    const inp = document.getElementById("bbh-domain");
    if (inp) {
      inp.style.borderColor = "var(--red)";
      inp.focus();
      setTimeout(() => { inp.style.borderColor = ""; }, 1200);
    }
    return;
  }
  window.open(mod.url(d), "_blank", "noopener,noreferrer");
}

// ─────────────────────────── External Tools ───────────────────────
function _renderExtGrid() {
  const grid = document.getElementById("ext-grid");
  if (!grid) return;
  const d = _bbhDomain();
  grid.innerHTML = EXT_TOOLS.map(tool => {
    const href = tool.url(d);
    return `<a class="bbh-ext-card" href="${href}" target="_blank" rel="noopener noreferrer">
      <span class="bbh-icon">${tool.icon}</span>
      <div style="min-width:0">
        <div class="bbh-module-label">${tool.label}</div>
        <div class="bbh-ext-desc">${tool.desc}</div>
      </div>
      <span style="margin-left:auto;font-size:.75rem;color:var(--text3);flex-shrink:0">↗</span>
    </a>`;
  }).join("");
}

// ─────────────────────────── page entry points ────────────────────
function showBBHelperPage() {
  // Auto-load domain from ?d= or restore last used
  let domain = "";
  try {
    const params = new URLSearchParams(window.location.search);
    domain = (params.get("d") || "").trim();
  } catch(e) {}
  if (!domain) { try { domain = localStorage.getItem("bbh_domain") || ""; } catch(e) {} }
  const inp = document.getElementById("bbh-domain");
  if (inp && domain) { inp.value = domain; try { localStorage.setItem("bbh_domain", domain); } catch(e) {} }
  _renderBBHCategoryTabs();
  _renderBBHGrid();
  if (typeof window.applyI18n === 'function') window.applyI18n();
}

function showExtToolsPage() {
  _renderExtGrid();
  if (typeof window.applyI18n === 'function') window.applyI18n();
}
