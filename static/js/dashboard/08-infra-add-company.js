// ════════════════════════════════════════════════════════════════════════
//  INFRA TAB (auto-generated from parser + static for Porto Seguro demo)
// ════════════════════════════════════════════════════════════════════════
function renderInfraTab(co) {
  const el = document.getElementById("tab-infra");
  const shell = (cards) => `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">Infrastructure</div>
          <div class="section-title">Resolved infrastructure, providers and edge services</div>
          <div class="section-sub">Infrastructure cards aggregate ASN, network, provider and service clues gathered during the scan.</div>
        </div>
      </div>
      <div class="infra-grid">${cards}</div>
    </div>`;

  if (co.infra && co.infra.length) {
    el.innerHTML = shell(co.infra.map(card =>
      _infraCard(card.title, (card.rows || []).map(r => _infraRow(r.key, esc(r.val), r.cls || "")))
    ).join("")) + _emailPivotSection(co);
    return;
  }

  const cidrs = co.cidr_ranges || [];
  const dns   = co.dns_data   || {};
  const waf   = co.waf_coverage || {};
  const hosts = co.hosts || [];
  const cloudAssets = co.cloud_assets || {};
  const cloudBucketFindings = (co.cloud_buckets && co.cloud_buckets.findings) || [];
  const cloudHosts = hosts.filter(h => h.cloud_provider).reduce((acc, h) => {
    const p = h.cloud_provider;
    if (!acc[p]) acc[p] = [];
    acc[p].push(h.host);
    return acc;
  }, {});
  const vendorsFound = co.vendors_found || [];
  const vendorFp = co.vendor_fingerprints || [];
  const relatedFound = (co.related_domains && (co.related_domains.found || co.related_domains.domains)) || [];
  const shodanHosts = co.shodan_hosts || [];
  const favMatches = (co.favicon_data && co.favicon_data.matches) || [];
  const zoneAttempts = (co.zone_transfer_data && co.zone_transfer_data.attempts) || [];
  const cmsRan = (co.cms_data && co.cms_data.ran) || [];
  const certstreamSnap = (co.certstream_data && co.certstream_data.last_snapshot) || {};
  const infraFindings = (co.infra_data && co.infra_data.findings) || [];
  const hasAny = cidrs.length ||
    (co.asn_numbers || []).length ||
    Object.keys(dns).length ||
    Object.keys(waf).length ||
    Object.keys(cloudAssets).length ||
    Object.keys(cloudHosts).length ||
    cloudBucketFindings.length ||
    vendorsFound.length || vendorFp.length ||
    relatedFound.length ||
    shodanHosts.length ||
    favMatches.length ||
    zoneAttempts.length ||
    cmsRan.length ||
    (certstreamSnap.subdomains || []).length ||
    infraFindings.length;

  if (!hasAny) {
    el.innerHTML = `<div class="empty-state"><div class="empty-state-icon" data-ico="inbox" aria-hidden="true"></div><div class="empty-state-title">No infrastructure data yet</div><div class="empty-state-copy">Run a pipeline scan to populate ASN, DNS, WAF and leak-related infrastructure details.</div></div>` + _emailPivotSection(co);
    return;
  }

  let cards = '';

  // ASN / CIDR card
  if (cidrs.length || co.asn_numbers?.length) {
    const asnNums = (co.asn_numbers || []).join(', ') || '—';
    const cidrRows = [
      _infraRow("ASN(s)", esc(asnNums)),
      _infraRow("CIDRs", `${cidrs.length} ranges`),
      ...cidrs.slice(0, 12).map(c => _infraRow("CIDR", esc(c), "hi")),
    ];
    cards += _infraCard("IP Ranges / ASN", cidrRows);
  }

  if (Object.keys(waf).length) {
    const wafRows = Object.entries(waf).map(([k,v]) => _infraRow(k, `${v} hosts`));
    const unprotected = hosts.length - Object.values(waf).reduce((a,b)=>a+b,0);
    cards += _infraCard("WAF / CDN Coverage", [
      ...wafRows,
      ...(unprotected > 0 ? [_infraRow("No WAF", `${unprotected} hosts exposed`, "warn")] : []),
    ]);
  }

  if (Object.keys(cloudAssets).length || Object.keys(cloudHosts).length) {
    const cloudRows = [
      ...Object.entries(cloudAssets).map(([k,v]) => _infraRow(k, `${v} hosts`, "hi")),
      ...Object.entries(cloudHosts).map(([k,v]) => _infraRow(k, `${v.length} hosts`, "hi")),
    ];
    cards += _infraCard("Cloud Providers", cloudRows);
  }

  const cloudBuckets = (co.cloud_buckets && co.cloud_buckets.findings) || [];
  if (cloudBuckets.length) {
    cards += _cloudBucketsCard(cloudBuckets);
  }

  if (Object.keys(dns).length) {
    const mx = (dns.MX||[]).map(r=>r.value||r).join(', ') || '—';
    const ns = (dns.NS||[]).slice(0,4).map(r=>r.value||r).join(', ') || '—';
    const spf = (dns.TXT||[]).find(r=>(r.value||r).startsWith('v=spf'));
    const dmarc = (dns.TXT||[]).find(r=>(r.value||r).startsWith('v=DMARC'));
    cards += `<div class="ic"><div class="ic-title">${icoHtml("search",14)} DNS Records</div>
      <div class="ic-row"><span class="ic-k">MX</span><span class="ic-v">${esc(mx)}</span></div>
      <div class="ic-row"><span class="ic-k">NS</span><span class="ic-v">${esc(ns)}</span></div>
      <div class="ic-row"><span class="ic-k">SPF</span><span class="ic-v ${spf?'':'warn'}">${spf ? esc((spf.value||spf).slice(0,80)) : 'Missing'}</span></div>
      <div class="ic-row"><span class="ic-k">DMARC</span><span class="ic-v ${dmarc?'':'warn'}">${dmarc ? esc((dmarc.value||dmarc).slice(0,80)) : 'Missing'}</span></div>
      <div class="ic-row"><span class="ic-k">TXT records</span><span class="ic-v">${(dns.TXT||[]).length}</span></div>
    </div>`;
  }

  if (vendorsFound.length || vendorFp.length) {
    const rows = [
      _infraRow("Vendors", esc((vendorsFound.length ? vendorsFound : [...new Set(vendorFp.map(v => v.vendor).filter(Boolean))]).join(", ") || "—"), "hi"),
      ...vendorFp.slice(0, 10).map(v => _infraRow(v.vendor || "appliance", esc((v.host || "") + (v.url ? " · " + v.url : "")), v.severity === "critical" || v.severity === "high" ? "warn" : "hi")),
    ];
    cards += _infraCard("Edge appliances", rows);
  }

  if (relatedFound.length) {
    cards += _infraCard("Domínios relacionados", relatedFound.slice(0, 12).map(r => {
      const d = typeof r === "string" ? r : (r.domain || "");
      const extra = typeof r === "object" ? [r.status, (r.ips || []).slice(0, 2).join(", ")].filter(Boolean).join(" · ") : "";
      return _infraRow(d, esc(extra || "resolvido"), "hi");
    }));
  }

  if (shodanHosts.length) {
    cards += _infraCard("Shodan", [
      _infraRow("Hosts", String(shodanHosts.length), "hi"),
      ...shodanHosts.slice(0, 8).map(h => {
        const host = typeof h === "string" ? h : (h.host || h.ip || h.ip_str || "");
        const ports = typeof h === "object" ? (h.ports || []).slice(0, 6).join(", ") : "";
        return _infraRow(host, esc(ports || "visto"), "hi");
      }),
    ]);
  }

  if (favMatches.length) {
    cards += _infraCard("Favicon hash", favMatches.slice(0, 8).map(m =>
      _infraRow(m.product || m.title || m.hash || "match", esc([m.ip, m.port, m.hostname].filter(Boolean).join(" · ")), "hi")
    ));
  }

  if (zoneAttempts.length) {
    const ok = zoneAttempts.filter(a => a.success).length;
    cards += _infraCard("Zone transfer", [
      _infraRow("Tentativas", String(zoneAttempts.length)),
      _infraRow("AXFR ok", String(ok), ok ? "warn" : ""),
    ]);
  }

  if (cmsRan.length) {
    cards += _infraCard("CMS scan", [
      _infraRow("Rodou", esc(cmsRan.join(", ")), "hi"),
    ]);
  }

  const csSubs = certstreamSnap.subdomains || [];
  if (csSubs.length) {
    cards += _infraCard("Certstream", [
      _infraRow("Subdomínios", String(csSubs.length), "hi"),
      ...csSubs.slice(0, 8).map(s => _infraRow("CT", esc(s))),
    ]);
  }

  if (infraFindings.length) {
    cards += _infraCard("Exposição de infra", infraFindings.slice(0, 8).map(f =>
      _infraRow(f.service || f.host || "serviço", esc(f.title || f.url || f.host || ""), "warn")
    ));
  }

  el.innerHTML = shell(cards) + _emailPivotSection(co);
}

function _cloudBucketsCard(findings) {
  const ACCESS_LABELS = {
    public_write_acl: "ACL pública (escrita)",
    public_read_sensitive: "Leitura pública (sensível)",
    public_list_sensitive: "Listagem pública (sensível)",
    public_read: "Leitura pública",
    public_list: "Listagem pública",
    exists_redirect: "Existe (redirect)",
    exists_private: "Existe (privado)",
  };
  const rows = findings.map(f => {
    const accessLabel = ACCESS_LABELS[f.access] || f.access || "—";
    const sevCls = f.severity === "critical" ? "warn" : (f.severity === "low" ? "" : "");
    const objCount = f.object_count != null ? f.object_count : 0;
    let extra = '';
    if ((f.sample_objects || []).length) {
      extra += `<div class="ic-row"><span class="ic-k"></span><span class="ic-v" style="font-family:var(--mono);font-size:.7rem;opacity:.8">Objetos: ${(f.sample_objects||[]).slice(0,8).map(o=>esc(o)).join(', ')}${f.sample_objects.length>8?'…':''}</span></div>`;
    }
    if ((f.sensitive_files || []).length) {
      extra += `<div class="ic-row"><span class="ic-k"></span><span class="ic-v warn" style="font-family:var(--mono);font-size:.7rem">${icoHtml("warning",14)} Arquivos sensíveis: ${(f.sensitive_files||[]).slice(0,5).map(o=>esc(o)).join(', ')}</span></div>`;
    }
    if (f.acl && (f.acl.public_write_perms||[]).length) {
      extra += `<div class="ic-row"><span class="ic-k"></span><span class="ic-v warn">${icoHtml("warning",14)} ACL anônima: ${esc((f.acl.public_write_perms||[]).join('/'))}</span></div>`;
    }
    return `<div class="ic-row"><span class="ic-k">${esc(f.provider || '')}</span><span class="ic-v ${sevCls}">${esc(f.name || '')} · ${esc(accessLabel)}${objCount ? ' · ' + objCount + ' objetos' : ''}</span></div>${extra}`;
  }).join("");
  return _infraCard("Cloud Storage Buckets", [rows]);
}

function _emailPivotSection(co) {
  const details = co.email_details || [];
  const emails = co.emails || [];
  if (!emails.length) return '';

  const rows = (details.length ? details : emails.map(e => ({email: e}))).map(d => {
    const email = d.email || '';
    const name = [d.first_name, d.last_name].filter(Boolean).join(' ');
    const liUrl = `https://www.linkedin.com/search/results/people/?keywords=${encodeURIComponent(name || email)}`;
    const hibpUrl = `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`;
    const googleUrl = `https://www.google.com/search?q=${encodeURIComponent('"' + email + '"')}`;
    return `<tr>
      <td style="font-family:var(--mono);font-size:.74rem">${esc(email)}</td>
      <td>${esc(name || '—')}</td>
      <td>${esc(d.position || '—')}</td>
      <td>${d.confidence != null ? esc(String(d.confidence)) + '%' : '—'}</td>
      <td class="pivot-links">
        <a href="${escAttr(liUrl)}" target="_blank" rel="noopener noreferrer">LinkedIn</a>
        <a href="${escAttr(hibpUrl)}" target="_blank" rel="noopener noreferrer">HIBP</a>
        <a href="${escAttr(googleUrl)}" target="_blank" rel="noopener noreferrer">Google</a>
      </td>
    </tr>`;
  }).join('');

  return `<div class="section-shell" style="margin-top:18px">
    <div class="section-head">
      <div class="section-head-main">
        <div class="section-kicker">OSINT</div>
        <div class="section-title">Pivot de E-mails / Funcionários (${emails.length})</div>
        <div class="section-sub">E-mails e colaboradores descobertos via Hunter.io / theHarvester — use os links para pivotar em redes sociais e bases de vazamentos.</div>
      </div>
    </div>
    <div style="overflow-x:auto"><table class="people-table">
      <thead><tr><th>E-mail</th><th>Nome</th><th>Cargo</th><th>Confiança</th><th>Pivot</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
  </div>`;
}

// ════════════════════════════════════════════════════════════════════════
//  FINDINGS RENDER (sevCls/sevLbl now in js/asm.js)
// ════════════════════════════════════════════════════════════════════════
if (typeof sevCls === 'undefined') {
  function sevCls(s){ return {critical:"sev-c",high:"sev-h",medium:"sev-m",low:"sev-l",info:"sev-i"}[s]||"sev-i"; }
}
if (typeof sevLbl === 'undefined') {
  function sevLbl(s){ return {critical:"CRITICAL",high:"HIGH",medium:"MEDIUM",low:"LOW",info:"INFO"}[s]||"INFO"; }
}

function _hashId(title, host, sev) {
  let h = 0;
  const s = title + '|' + host + '|' + sev;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h) + s.charCodeAt(i);
    h |= 0;
  }
  return 'f' + Math.abs(h).toString(16).padStart(8, '0');
}

// ════════════════════════════════════════════════════════════════════════
//  ADD COMPANY
// ════════════════════════════════════════════════════════════════════════
function openAddCompany() { document.getElementById("modal-add").classList.add("show"); }
function closeAddCompany(){ document.getElementById("modal-add").classList.remove("show"); }

let _editCoId = null;
function openEditCompanyModal(cid) {
  const co = allCompanies().find(c=>c.id===cid);
  if(!co) return;
  _editCoId = cid;
  document.getElementById("edit-co-title").textContent  = co.name;
  document.getElementById("edit-co-name").value         = co.name;
  document.getElementById("edit-co-domains").value      = (co.domains||[]).join("\n");
  document.getElementById("edit-co-oos").value          = (co.out_of_scope||[]).join("\n");
  ["scope-in", "scope-out"].forEach(id => { const el = document.getElementById(id); if (el) el.value = ""; });
  document.getElementById("edit-co-error").style.display = "none";
  document.getElementById("modal-edit-co").classList.add("show");
  // a lista do painel pode não trazer out_of_scope: busca o cadastro atual
  if (SERVER_MODE) fetch("/api/companies", {headers: _authHeaders()}).then(r => r.ok ? r.json() : [])
    .then(list => { const c = (list.companies || list || []).find(x => x.id === cid);
                    if (c && _editCoId === cid) document.getElementById("edit-co-oos").value = (c.out_of_scope || []).join("\n"); })
    .catch(() => {});
}

function _lines(id) {
  return document.getElementById(id).value.split("\n").map(d => d.trim().toLowerCase()).filter(Boolean);
}

// Escopo colado da página do programa → preenche Domínios e Fora do escopo (não grava; revisar e salvar).
async function parseScopeIntoForm() {
  const msg = document.getElementById("scope-import-msg");
  try {
    const r = await fetch("/api/scope/parse", {method: "POST", headers: _authHeaders(),
      body: JSON.stringify({in_scope: document.getElementById("scope-in").value, out_of_scope: document.getElementById("scope-out").value})});
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || "HTTP " + r.status);
    const merge = (id, extra) => { const cur = _lines(id); extra.forEach(x => { if (!cur.includes(x)) cur.push(x); }); document.getElementById(id).value = cur.join("\n"); };
    merge("edit-co-domains", d.domains || []);
    merge("edit-co-oos", d.out_of_scope || []);
    msg.textContent = `${(d.domains||[]).length} no escopo, ${(d.out_of_scope||[]).length} fora` +
      ((d.ignored||[]).length ? ` · ignorados (IP, app, texto): ${d.ignored.slice(0, 6).join(", ")}${d.ignored.length > 6 ? "…" : ""}` : "") +
      " — revise e clique em Save Changes.";
  } catch (e) { msg.textContent = "Falha ao ler o escopo: " + (e.message || e); }
}

async function exportToolList(kind) {
  const cid = state.currentId;
  try {
    const r = await fetch(`/api/data/company/${encodeURIComponent(cid)}/lists/${kind}`, {headers: _authHeaders()});
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
    const txt = await r.text();
    if (!txt.trim()) { showToast("Lista vazia"); return; }
    _downloadBlob(txt, `${cid}-${kind}.txt`, "text/plain");
  } catch (e) { showToast("Falha ao exportar: " + (e.message || e)); }
}

async function sendToBurp(kind) {
  const cid = state.currentId;
  try {
    const r = await fetch(`/api/data/company/${encodeURIComponent(cid)}/burp`, {method: "POST", headers: _authHeaders(), body: JSON.stringify({kind})});
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(`Enviando ${d.queued} URL(s) ao Burp (${d.proxy})` + (d.total > d.queued ? ` — limite de ${d.queued} de ${d.total}` : ""));
  } catch (e) { showToast(String(e.message || e)); }
}

async function saveEditCompany() {
  const name    = document.getElementById("edit-co-name").value.trim();
  const domains = _lines("edit-co-domains");
  const out_of_scope = _lines("edit-co-oos");
  const errEl   = document.getElementById("edit-co-error");
  if(!name || !domains.length){
    errEl.textContent = "Name and at least one domain are required.";
    errEl.style.display = "block"; return;
  }
  if(!SERVER_MODE){ errEl.textContent = "Edit only available in server mode."; errEl.style.display="block"; return; }
  try {
    const r = await fetch(`/api/companies/${_editCoId}`, {
      method: "PUT",
      headers: _authHeaders(),
      body: JSON.stringify({name, domains, out_of_scope})
    });
    if(!r.ok){ const d=await r.json(); throw new Error(d.error||"Server error"); }
    document.getElementById("modal-edit-co").classList.remove("show");
    const co = allCompanies().find(c=>c.id===_editCoId);
    if(co) { co.name = name; co.domains = domains; co.out_of_scope = out_of_scope; }
    const updated = allCompanies().find(c=>c.id===_editCoId);
    if(updated) renderCompanyView(updated);
    renderSidebar();
    reloadServerData().catch(() => {});
  } catch(e) {
    errEl.textContent = e.message;
    errEl.style.display = "block";
  }
}

async function deleteCompany() {
  if (!_editCoId) { showToast("No company selected for deletion."); return; }
  const co = allCompanies().find(c => c.id === _editCoId);
  const name = co ? co.name : _editCoId;
  if (!confirm(`Delete "${name}" and all its data? This cannot be undone.`)) return;
  if (!SERVER_MODE) { showToast("Delete only available in server mode."); return; }
  const cidToDelete = _editCoId;
  const btn = document.querySelector("#modal-edit-co .btn-secondary");
  const errEl = document.getElementById("edit-co-error");
  try {
    if (btn) { btn.disabled = true; btn.textContent = "Deleting..."; }
    const r = await fetch(`/api/companies/${cidToDelete}`, {
      method: "DELETE",
      headers: _authHeaders(),
    });
    if (!r.ok) { const d = await r.json(); throw new Error(d.error || "Server error"); }
    document.getElementById("modal-edit-co").classList.remove("show");
    // Remove from local DATA immediately — reloadServerData only adds, never removes
    if (DATA.companies) {
      DATA.companies = DATA.companies.filter(c => c.id !== cidToDelete);
    }
    if (typeof ASM !== 'undefined' && ASM.data && ASM.data.companies) {
      ASM.data.companies = ASM.data.companies.filter(c => c.id !== cidToDelete);
    }
    extraCompanies = extraCompanies.filter(c => c.id !== cidToDelete);
    if (state.currentId === cidToDelete) state.currentId = null;
    showPage("all");
    renderSidebar();
    renderAllCompanies();
  } catch(e) {
    errEl.textContent = e.message;
    errEl.style.display = "block";
    if (btn) { btn.disabled = false; btn.textContent = "Delete"; }
  }
}

async function saveNewCompany() {
  const name    = document.getElementById("modal-name").value.trim();
  const domains = document.getElementById("modal-domains").value.trim().split("\n").map(d=>d.trim()).filter(Boolean);
  if (!name) return;

  if (SERVER_MODE) {
    const r = await fetch("/api/companies", { method:"POST", headers: _authHeaders(),
      body: JSON.stringify({name, domains}) });
    const co = await r.json();
    if (!r.ok) { showToast(co.error||"Error"); return; }
    await reloadServerData();
  } else {
    const id = name.toLowerCase().replace(/[^a-z0-9]/g,"-");
    const co = { id, name, domains, color:"#00c9a7", tags:[],
      stats:{ subdomains:0,live_hosts:0,open_ports:0,waf_protected:0,
        findings_critical:0,findings_high:0,findings_medium:0,findings_low:0,findings_info:0 },
      waf_coverage:{}, tech_summary:{}, findings:[], hosts:[], buckets:[] };
    extraCompanies.push(co);
    try { localStorage.setItem("asm_extra_companies", JSON.stringify(extraCompanies)); } catch(e) {}
  }

  closeAddCompany();
  document.getElementById("modal-name").value = "";
  document.getElementById("modal-domains").value = "";
  renderSidebar();
  renderAllCompanies();
}
