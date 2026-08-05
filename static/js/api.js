// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  ASM Platform — API layer                                                ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
(function () {
  'use strict';

  var ASM = window.ASM;

  // ── Generic request ────────────────────────────────────────────────────────
  function apiReq(url, opts) {
    opts = opts || {};
    opts.headers = Object.assign({}, _authHeaders(), opts.headers || {});
    return fetch(url, opts);
  }

  // ── Companies ──────────────────────────────────────────────────────────────
  ASM.api = {

    /** Load summary for all companies (lightweight) */
    loadServerSummary: async function () {
      if (!SERVER_MODE) return;
      var r = await fetch('/api/data/summary', { headers: _authHeaders() });
      if (!r.ok) throw new Error(await r.text());
      var d = await r.json();
      // Mutate in place so ASM.data stays the same reference
      ASM.data.version = d.version || ASM.data.version;
      ASM.data.generated = d.generated || ASM.data.generated;
      ASM.data.companies = d.companies || [];
    },

    /** Load full data for a company (on demand) */
    ensureCompanyLoaded: async function (id, opts) {
      opts = opts || {};
      if (!SERVER_MODE || !id) return ASM.allCompanies().find(function (c) { return c.id === id; });
      var existing = ASM.allCompanies().find(function (c) { return c.id === id; });
      if (existing && !existing.summary_only && !opts.force) return existing;
      var r = await fetch('/api/data/company/' + encodeURIComponent(id), { headers: _authHeaders() });
      if (!r.ok) throw new Error(await r.text());
      var d = await r.json();
      ASM.replaceCompanyInData(d);
      return d;
    },

    /** Reload all server data and merge new companies */
    reloadServerData: async function () {
      if (!SERVER_MODE) return;
      try {
        await ASM.api.loadServerSummary();
        if (ASM.currentId) await ASM.api.ensureCompanyLoaded(ASM.currentId, { force: true });
      } catch (e) { /* silent */ }
      try {
        var r = await fetch('/api/companies', { headers: _authHeaders() });
        if (!r.ok) return;
        var cos = await r.json();
        var dataIds = new Set((ASM.data.companies || []).map(function (c) { return c.id; }));
        cos.forEach(function (co) {
          if (!dataIds.has(co.id)) {
            ASM.data.companies = ASM.data.companies || [];
            ASM.data.companies.push(Object.assign({}, co, {
              stats: { subdomains: 0, live_hosts: 0, open_ports: 0, waf_protected: 0,
                findings_critical: 0, findings_high: 0, findings_medium: 0,
                findings_low: 0, findings_info: 0 },
              waf_coverage: {}, tech_summary: {}, findings: [], hosts: [], buckets: []
            }));
          }
        });
      } catch (e) { /* silent */ }
    },

    /** Create a new company */
    createCompany: async function (name, domains) {
      var r = await fetch('/api/companies', {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, _authHeaders()),
        body: JSON.stringify({ name: name, domains: domains })
      });
      var co = await r.json();
      if (!r.ok) throw new Error(co.error || 'Error creating company');
      return co;
    },

    /** Update a company */
    updateCompany: async function (id, name, domains) {
      var r = await fetch('/api/companies/' + id, {
        method: 'PUT',
        headers: Object.assign({ 'Content-Type': 'application/json' }, _authHeaders()),
        body: JSON.stringify({ name: name, domains: domains })
      });
      if (!r.ok) { var d = await r.json(); throw new Error(d.error || 'Server error'); }
    },

    /** Get screenshots for a company */
    getScreenshots: async function (cid) {
      var r = await fetch('/api/screenshots/' + cid, { headers: _authHeaders() });
      return r.ok ? r.json() : [];
    },

    /** Get subdomain history for a company */
    getSubHistory: async function (cid) {
      var r = await fetch('/api/data/' + cid + '/subhistory', { headers: _authHeaders() });
      return r.json();
    },

    /** Get scan history */
    getScanHistory: async function (cid) {
      var r = await fetch('/api/scan-history/' + cid, { headers: _authHeaders() });
      return r.json();
    },

    /** Delete scan history entry */
    deleteScanHistory: async function (cid, scanName) {
      var r = await fetch('/api/scan-history/' + encodeURIComponent(cid) + '/' + encodeURIComponent(scanName), {
        method: 'DELETE', headers: _authHeaders()
      });
      if (!r.ok) throw new Error(await r.text());
    },

    /** Re-parse scan history */
    reparseHistory: async function (cid, scanName) {
      var r = await fetch(
        '/api/scan-history/' + cid + '/' + encodeURIComponent(scanName) + '/reparse',
        { method: 'POST', headers: _authHeaders() }
      );
      if (!r.ok) throw new Error(await r.text());
    },

    /** Clear all recon data for a company */
    clearReconData: async function (cid) {
      var r = await fetch('/api/recon/' + encodeURIComponent(cid) + '/data', {
        method: 'DELETE', headers: _authHeaders()
      });
      if (!r.ok) throw new Error(await r.text());
    },

    /** DNSDumpster comparison (stub — diff is fetched directly via /api/diff/:cid) */
    dnsDumpsterCompare: null,

    /** Validate domains */
    validateDomains: async function (domains) {
      var r = await fetch('/api/validate-domains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domains: domains })
      });
      return r.json();
    },

    /** Start pipeline scan */
    startPipeline: async function (cid, rateMode) {
      var r = await fetch('/api/recon/' + cid + '/pipeline', {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, _authHeaders()),
        body: JSON.stringify({ mode: rateMode })
      });
      if (!r.ok) {
        var t = await r.text();
        if (r.status !== 409 || !t.includes('already running')) throw new Error(t);
      }
    },

    /** Stop scan */
    stopScan: async function (cid) {
      var r = await fetch('/api/recon/' + cid + '/pipeline/cancel', {
        method: 'POST', headers: _authHeaders()
      });
      if (!r.ok) throw new Error(await r.text());
      return r.json();
    },

    /** Load settings */
    loadSettings: async function () {
      var r = await fetch('/api/settings', { headers: _authHeaders() });
      if (!r.ok) throw new Error(await r.text());
      return r.json();
    },

    /** Save settings */
    saveSettings: async function (settings) {
      var r = await fetch('/api/settings', {
        method: 'PUT',
        headers: Object.assign({ 'Content-Type': 'application/json' }, _authHeaders()),
        body: JSON.stringify(settings)
      });
      if (!r.ok) throw new Error(await r.text());
      return r.json();
    },

    /** Get tool logs */
    getToolLogs: async function (cid) {
      var r = await fetch('/api/tool-logs/' + cid, { headers: _authHeaders() });
      if (r.ok) return r.json();
      return { logs: [] };
    },

    /** Clear tool logs */
    clearToolLogs: async function (cid) {
      var r = await fetch('/api/tool-logs/' + cid, {
        method: 'DELETE', headers: _authHeaders()
      });
      if (!r.ok) throw new Error(await r.text());
    },

    /** Export findings */
    exportFindings: function (cid, format) {
      var co = ASM.allCompanies().find(function (c) { return c.id === cid; });
      if (!co) return;
      var findings = co.findings || [];
      if (format === 'csv') {
        var rows = [['ID', 'Severity', 'Category', 'Title', 'Host', 'URL', 'Description']];
        findings.forEach(function (f) {
          rows.push([f.id, f.severity, f.category, f.title, f.host || '', f.url || '',
            (f.desc || '').replace(/"/g, "'")]);
        });
        var csv = rows.map(function (r) { return r.map(function (v) { return '"' + v + '"'; }).join(','); }).join('\n');
        downloadBlob(csv, cid + '_findings.csv', 'text/csv');
      } else {
        downloadBlob(JSON.stringify(findings, null, 2), cid + '_findings.json', 'application/json');
      }
    },

    /** Run individual tool */
    runTool: async function (cid, toolName, args) {
      var r = await fetch('/api/recon/' + cid + '/tool/' + toolName, {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, _authHeaders()),
        body: JSON.stringify({ args: args || '' })
      });
      if (!r.ok) throw new Error(await r.text());
      return r.json();
    },

  };

  // ── Helper: trigger file download ──────────────────────────────────────────
  function downloadBlob(content, filename, type) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([content], { type: type }));
    a.download = filename;
    a.click();
  }

  // ── Legacy aliases for backward compatibility ──────────────────────────────
  window.loadServerSummary  = function () { return ASM.api.loadServerSummary(); };
  window.ensureCompanyLoaded = function (id, opts) { return ASM.api.ensureCompanyLoaded(id, opts); };
  window.reloadServerData   = function () { return ASM.api.reloadServerData(); };

})();
