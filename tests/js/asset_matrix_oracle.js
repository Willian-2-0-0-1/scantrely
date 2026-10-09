// Oráculo de paridade: roda o código REAL do front (matriz de ativos) no node e imprime o resultado por host.
// Uso: node asset_matrix_oracle.js < {"co": {...}, "history": [...]}
const fs = require("fs"), vm = require("vm"), path = require("path");
const root = path.resolve(__dirname, "..", "..", "static", "js");
const ctx = {console, URL, Set, Map, Math, JSON, Object, Array, String, Number, RegExp, Date, parseInt, parseFloat, isFinite};
ctx.window = ctx; ctx.globalThis = ctx;
ctx.document = {getElementById: () => null, querySelector: () => null, querySelectorAll: () => [], addEventListener() {}};
ctx.localStorage = {getItem: () => null, setItem() {}};
ctx.state = {currentId: "x"};
ctx.esc = s => String(s == null ? "" : s); ctx.escAttr = ctx.esc; ctx.t = undefined;
ctx.icoHtml = () => ""; ctx._shotSrc = () => ""; ctx._shotJs = () => ""; ctx.SERVER_MODE = false;
vm.createContext(ctx);
const load = f => vm.runInContext(fs.readFileSync(f, "utf8").replace(/^﻿/, ""), ctx, {filename: f});
load(path.join(root, "origin-link.js"));
ctx.isJsPathNoise = p => ctx.ASMOrigin.isJsPathNoise(p);
for (const f of ["06-hosts-ports-subdomains.js", "07-endpoints.js", "06b-asset-matrix.js"]) {   // código legado congelado
  try { load(path.join(__dirname, "legacy", f)); } catch (e) { console.error("load", f, e.message); process.exit(2); }
}
const {co, history} = JSON.parse(fs.readFileSync(0, "utf8"));
const inv = vm.runInContext("(co, h) => _buildSubdomainInventory(co, h)", ctx)(co, history || []).filter(h => vm.runInContext("_isActiveHost", ctx)(h));
const out = vm.runInContext(`(co, inv) => {
  buildUnifiedEndpoints(co);   // sem try: falha de paridade tem de aparecer
  const riskMap = _findingHosts(co); const agg = _assetAgg(co);
  const domSet = new Set((co.domains || []).map(_normalizeScopeDomain));
  return inv.map(h => ({
    host: h.host, status: h.status_code, domain: _matchDomainForHost(h.host, co.domains || [], domSet),
    risk: _hostRiskInfo(h, riskMap), tech: _hostTechLabels(h), ports: _hostOpenPorts(h).map(p => p.port + ":" + p.service),
    infra: _hostInfraSignals(h).map(s => s.label), techs: (h.technologies || []), waf: h.waf, ip: h.ip,
    agg: (agg.get(h.host) || null),
  }));
}`, ctx)(co, inv);
console.log(JSON.stringify(out));
