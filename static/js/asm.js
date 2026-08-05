// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  ASM Platform — Core module                                             ║
// ║  Load order: asm.js → api.js → dashboard.js                             ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
(function () {
  'use strict';

  // ── HTML escaping ───────────────────────────────────────────────────────────
  window.esc = function (s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  };

  // ── URL-safe attribute escape (does NOT encode & in query strings) ──────
  window.escAttr = function (s) {
    if (s == null) return '';
    return String(s).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  };

  // ── Text preview (truncate) ────────────────────────────────────────────────
  window.textPreview = function (text, max) {
    max = max || 180;
    var clean = String(text || '').replace(/\s+/g, ' ').trim();
    if (!clean) return '';
    return clean.length > max ? clean.slice(0, max - 1) + '…' : clean;
  };

  // ── Risk assessment ────────────────────────────────────────────────────────
  window.riskLevel = function (co) {
    var s = co.stats || {};
    if ((s.findings_critical || 0) > 0) return 'critical';
    if ((s.findings_high || 0) > 2) return 'high';
    if ((s.findings_medium || 0) > 4) return 'medium';
    return 'low';
  };

  window.riskLabel = function (lvl) {
    return { critical: 'Critical Risk', high: 'High Risk', medium: 'Medium Risk', low: 'Low Risk' }[lvl] || 'Unknown';
  };

  // ── Severity CSS / labels ──────────────────────────────────────────────────
  window.sevCls = function (s) {
    return { critical: 'sev-c', high: 'sev-h', medium: 'sev-m', low: 'sev-l', info: 'sev-i' }[s] || 'sev-i';
  };

  window.sevLbl = function (s) {
    return { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' }[s] || 'INFO';
  };

  // ── WAF helpers ────────────────────────────────────────────────────────────
  window.wafColor = function (k) {
    var m = { Imperva: '#a78bfa', 'AWS CloudFront': '#fb923c', Cloudflare: '#f59e0b',
      'Google Cloud': '#4ade80', Google: '#4ade80', Direct: '#64748b',
      'Direct (Firewalled)': '#64748b' };
    return m[k] || '#60a5fa';
  };

  window.wafClass = function (w) {
    return 'waf-' + (w || 'Direct').replace(/[^a-zA-Z0-9]/g, '');
  };

  // ── DOM shortcuts ──────────────────────────────────────────────────────────
  window.$ = function (sel, ctx) { return (ctx || document).querySelector(sel); };
  window.$$ = function (sel, ctx) { return Array.from((ctx || document).querySelectorAll(sel)); };

  // ── Modal helpers ──────────────────────────────────────────────────────────
  window.showModal = function (id) { var el = document.getElementById(id); if (el) el.classList.add('show'); };
  window.hideModal = function (id) { var el = document.getElementById(id); if (el) el.classList.remove('show'); };

  // ── Server mode detection ──────────────────────────────────────────────────
  window.SERVER_MODE = window.location.protocol === 'http:' && window.location.hostname !== '';

  // ── Auth headers ───────────────────────────────────────────────────────────
  window._authHeaders = function () {
    var tok = localStorage.getItem('asmToken');
    return tok ? { 'x-auth-token': tok } : {};
  };

  // ════════════════════════════════════════════════════════════════════════════
  //  APPLICATION STATE (single source of truth)
  // ════════════════════════════════════════════════════════════════════════════
  var ASM = window.ASM = {

    // ── Demo data (used when backend not available) ──────────────────────
    DEMO_DATA: null,

    // ── Runtime state ────────────────────────────────────────────────────
    currentId: null,          // company id, null = "All Companies"
    tab: 'overview',          // active tab within company view
    route: 'companies',       // current page/view

    // ── Data store ───────────────────────────────────────────────────────
    data: null,               // { version, generated, companies: [...] }
    extraCompanies: JSON.parse(localStorage.getItem('asm_extra_companies') || '[]'),

    // ── Auth ─────────────────────────────────────────────────────────────
    authUser: null,
    authRole: null,

    // ── Scan state ───────────────────────────────────────────────────────
    activeScanId: null,
    scanEventSrc: null,

    // ── Pipeline state (per company) ─────────────────────────────────────
    pipelineState: {},

    // ── Live data polling ────────────────────────────────────────────────
    livePollInterval: null,

    // ── Mobile nav ───────────────────────────────────────────────────────
    mobileNavOpen: false,

    // ── Initialized flag ─────────────────────────────────────────────────
    initialized: false,

    // ── Helpers ──────────────────────────────────────────────────────────
    allCompanies: function () {
      return [].concat(this.data ? (this.data.companies || []) : [], this.extraCompanies || []);
    },

    replaceCompanyInData: function (company) {
      if (!company || !company.id) return;
      var companies = (this.data && this.data.companies) || [];
      var idx = companies.findIndex(function (c) { return c.id === company.id; });
      if (idx >= 0) companies[idx] = company;
      else companies.push(company);
    }
  };

  // ── Lazy-init data from globals ────────────────────────────────────────────
  function _initData() {
    if (SERVER_MODE) {
      ASM.data = { version: '1.0', generated: null, companies: [] };
    } else if (typeof window.ASM_DATA !== 'undefined') {
      ASM.data = window.ASM_DATA;
    } else if (ASM.DEMO_DATA) {
      ASM.data = ASM.DEMO_DATA;
    } else {
      ASM.data = { version: '1.0', generated: null, companies: [] };
    }
  }

  // Init data immediately (before other scripts load)
  _initData();

  // Auto-init events on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      setupGlobalEvents();
    });
  } else {
    setupGlobalEvents();
  }

  // ════════════════════════════════════════════════════════════════════════════
  //  GLOBAL EVENT DELEGATION
  // ════════════════════════════════════════════════════════════════════════════

  // ── Mobile nav ──────────────────────────────────────────────────────────────
  window.openMobileNav = function () {
    ASM.mobileNavOpen = true;
    document.body.classList.add('nav-open');
    var btn = document.getElementById('mobile-nav-toggle');
    if (btn) btn.setAttribute('aria-expanded', 'true');
  };

  window.closeMobileNav = function () {
    ASM.mobileNavOpen = false;
    document.body.classList.remove('nav-open');
    var btn = document.getElementById('mobile-nav-toggle');
    if (btn) btn.setAttribute('aria-expanded', 'false');
  };

  window.toggleMobileNav = function () {
    if (ASM.mobileNavOpen) closeMobileNav();
    else openMobileNav();
  };

  // ── Tab accessibility ───────────────────────────────────────────────────
  window.syncCompanyTabsAccessibility = function (activeName) {
    activeName = activeName || ASM.tab || 'overview';
    $$('#co-tabs .tab-btn').forEach(function (btn) {
      var group = btn.getAttribute('data-group') || '';
      var selected = group === activeName;
      btn.setAttribute('role', 'tab');
      btn.setAttribute('aria-selected', selected ? 'true' : 'false');
      btn.setAttribute('tabindex', selected ? '0' : '-1');
    });
    $$('#view-company .tab-content').forEach(function (panel) {
      panel.setAttribute('role', 'tabpanel');
      panel.setAttribute('tabindex', '0');
    });
  };

  window.renderCompanyLoading = function (id) {
    if (typeof window.allCompanies !== 'function') return;
    var co = window.allCompanies().find(function (c) { return c.id === id; });
    if (!co) return;
    var titleEl = document.getElementById('co-title');
    var descEl = document.getElementById('co-desc');
    if (titleEl) titleEl.textContent = co.name;
    if (descEl) descEl.textContent = 'Loading company details…';
    $$('#view-company .tab-content').forEach(function (panel) {
      panel.innerHTML = '<div class="empty"><b>Loading</b>Fetching the latest company data.</div>';
    });
  };

  // ── Hash-based routing ──────────────────────────────────────────────────
  function _getHashParts() {
    var h = window.location.hash.replace(/^#\/?/, '');
    return h ? h.split('/') : [];
  }

  function _handleHashRoute() {
    if (!ASM.initialized) return; // Wait for initApp() to finish
    var parts = _getHashParts();
    if (!parts.length || parts[0] === 'companies') {
      if (typeof showPage === 'function') showPage('companies');
    } else if (parts[0] === 'company' && parts[1]) {
      var cid = parts[1];
      var tab = parts[2] || 'overview';
      if (ASM.currentId !== cid) {
        if (typeof selectCompany === 'function') selectCompany(cid);
      }
      if (ASM.tab !== tab && typeof switchTab === 'function') {
        var btn = document.querySelector('.tab-btn[onclick*="' + tab + '"]');
        switchTab(tab, btn);
      }
    } else if (parts[0] === 'settings') {
      if (typeof showPage === 'function') showPage('settings');
    } else if (parts[0] === 'tools') {
      if (typeof showPage === 'function') showPage('tools');
    } else if (parts[0] === 'admins') {
      if (typeof showPage === 'function') showPage('admins');
    } else if (parts[0] === 'runtime') {
      if (typeof showPage === 'function') showPage('runtime');
    } else if (parts[0] === 'bbhelper') {
      if (typeof showPage === 'function') showPage('bbhelper');
    } else if (parts[0] === 'exttools') {
      if (typeof showPage === 'function') showPage('exttools');
    } else if (parts[0] === 'bbprograms') {
      if (typeof showPage === 'function') showPage('bbprograms');
    } else if (parts[0] === 'generators') {
      if (typeof showPage === 'function') showPage('generators');
    }
  }

  // Expose for external use
  ASM.updateHash = function (route) {
    var old = window.location.hash;
    if (route === null) {
      window.location.hash = '#/companies';
    } else if (old !== '#' + route) {
      window.location.hash = '#' + route;
    }
  };

  function setupGlobalEvents() {
    // Close modals on overlay click
    document.addEventListener('click', function (e) {
      if (e.target.classList.contains('modal-overlay') && e.target.classList.contains('show')) {
        e.target.classList.remove('show');
      }
    });

  // ── Close modals on Escape ──────────────────────────────────────────────────
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        $$('.modal-overlay.show').forEach(function (m) { m.classList.remove('show'); });
      }
    });

    // ── Hash-based routing ─────────────────────────────────────────────────
    window.addEventListener('hashchange', function () {
      _handleHashRoute();
    });
    // Initial route on load
    _handleHashRoute();

    // ── Handle data-action attributes (delegate for onclick-free buttons) ──
    document.addEventListener('click', function (e) {
      var el = e.target.closest('[data-action]');
      if (!el) return;
      var action = el.getAttribute('data-action');
      var fn = window[action];
      if (typeof fn === 'function') {
        fn(e, el);
        e.preventDefault();
      }
    });

    // Delegate findings card toggle
    document.addEventListener('click', function (e) {
      var fc = e.target.closest('.fc');
      if (!fc) return;
      if (e.target.closest('a')) return;
      if (e.target.closest('.fc-detail a')) { e.stopPropagation(); return; }
      fc.classList.toggle('open');
      var detail = fc.querySelector('.fc-detail');
      if (detail) detail.classList.toggle('show');
    });

    // Delegate tab switching
    document.addEventListener('click', function (e) {
      var btn = e.target.closest('.tab-btn');
      if (!btn) return;
      var match = (btn.getAttribute('onclick') || '').match(/switchTab\('([^']+)'/);
      if (match && typeof window.switchTab === 'function') {
        window.switchTab(match[1], btn);
      }
    });

    // Delegate scan profile selection
    document.addEventListener('click', function (e) {
      var prof = e.target.closest('.scan-profile');
      if (prof && typeof window.selectProfile === 'function') {
        window.selectProfile(prof.querySelector('input[type=radio]').value, prof);
      }
    });

    // Delegate rate mode selection
    document.addEventListener('click', function (e) {
      var btn = e.target.closest('.rate-mode-btn');
      if (btn && typeof window.selectRateMode === 'function') {
        var radio = btn.querySelector('input[type=radio]');
        if (radio) window.selectRateMode(radio.value, btn);
      }
    });

    // Screenshot lightbox close
    document.addEventListener('click', function (e) {
      var lb = document.getElementById('ss-lightbox');
      if (lb && lb.classList.contains('open') && e.target === lb) {
        if (typeof window.ssLightboxClose === 'function') window.ssLightboxClose();
        else lb.classList.remove('open');
      }
    });
  }

})();
