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

function renderFC(f) {
  // ── Normalize legacy field names ─────────────────────────────────────
  if (!f.desc && f.description) f.desc = f.description;
  if (!f.title && f.name) f.title = f.name;
  if (!f.id) f.id = _hashId(f.title || '', f.host || '', f.severity || '');

  // Extract confidence from description, e.g. "Confidence: [PROBABLE]"
  const confMatch = (f.desc||"").match(/Confidence:\s*\[([^\]]+)\]/i);
  const conf = confMatch ? confMatch[1] : "";
  // Clean description — strip trailing truncation artifacts
  const descClean = (f.desc||"").replace(/\s+$/, "");

  // Module badge color
  const modColor = {
    baddns:"var(--orange)", baddns_direct:"var(--orange)", baddns_zone:"var(--orange)",
    baddns_mx:"var(--orange)", baddns_txt:"var(--orange)",
    nuclei:"var(--red)", secretsdb:"var(--red)",
    httpx:"var(--blue)", wappalyzer:"var(--blue)",
    bucket_finder:"var(--purple)", bucket_amazon:"var(--purple)",
    headers:"var(--blue)", cve_scan:"var(--red)", github_dork:"var(--red)",
  };
  const mc = modColor[f.module] || "var(--text3)";

  // Tags — skip noisy internal bbot tags
  const skipTags = new Set(["affiliate","target","in-scope","out-of-scope"]);
  const tags = (f.tags||[]).filter(t=>!skipTags.has(t) && !t.startsWith("scope-") && !t.startsWith("distance-"));

  // Type-specific detail blocks
  const typeExtra = (() => {
    if (f.type === "cve") {
      const score    = f.score != null ? f.score : null;
      const epssVal  = f.epss  != null ? f.epss  : null;
      const kevFlag  = !!f.kev;
      const affected = (f.affected_hosts || []);
      const scoreC   = score >= 9 ? "#f43f5e" : score >= 7 ? "#fb923c" : score >= 4 ? "#fbbf24" : "var(--text2)";
      const epssC    = epssVal >= 0.5 ? "#f43f5e" : epssVal >= 0.1 ? "#fb923c" : "var(--teal)";
      return `<div style="display:flex;gap:10px;flex-wrap:wrap;margin:8px 0 4px;font-size:.72rem">
        ${score != null ? `<span style="background:var(--sidebar);border:1px solid var(--border);border-radius:4px;padding:2px 8px">
          CVSS <b style="color:${scoreC}">${score.toFixed(1)}</b></span>` : ""}
        ${epssVal != null ? `<span style="background:var(--sidebar);border:1px solid var(--border);border-radius:4px;padding:2px 8px">
          EPSS <b style="color:${epssC}">${(epssVal*100).toFixed(2)}%</b></span>` : ""}
        ${kevFlag ? `<span style="background:#dc262622;border:1px solid #dc262655;border-radius:4px;padding:2px 8px;color:#f43f5e;font-weight:700">${icoHtml("warning",14)} KEV</span>` : ""}
      </div>
      ${affected.length > 1 ? `<div style="font-size:.7rem;color:var(--text3);margin:4px 0">Affected: ${affected.map(h=>`<span style="font-family:monospace;color:var(--text2)">${esc(h)}</span>`).join(", ")}</div>` : ""}`;
    }
    if (f.type === "secret") {
      const val      = f.value || "";
      const sType    = (f.metadata && f.metadata.secret_type) ? f.metadata.secret_type : (f.metadata && f.metadata.type) ? f.metadata.type : "";
      const srcUrl   = (f.metadata && f.metadata.source_url) ? f.metadata.source_url : f.url || "";
      const ctx      = (f.metadata && f.metadata.context) ? f.metadata.context : "";
      return `${val ? `<div style="margin:8px 0 4px">
        <div style="font-size:.68rem;color:var(--text3);margin-bottom:3px">${sType ? esc(sType) : "secret"}</div>
        <div style="font-family:monospace;font-size:.75rem;background:var(--sidebar);border:1px solid var(--border);border-radius:4px;padding:6px 10px;word-break:break-all;color:#f43f5e">${esc(val)}</div>
      </div>` : ""}
      ${srcUrl ? `<div style="font-size:.7rem;margin-top:4px"><a class="fc-url-link" href="${esc(srcUrl)}" target="_blank" rel="noopener" onclick="event.stopPropagation()"> ${esc(srcUrl)}</a></div>` : ""}
      ${ctx ? `<div style="font-size:.68rem;color:var(--text3);margin-top:4px;font-family:monospace;white-space:pre-wrap;word-break:break-all">${esc(ctx.slice(0,300))}</div>` : ""}`;
    }
    if (f.type === "header") {
      const cookieName = f.value || "";
      const issCookie  = f.key && f.key.startsWith("cookie-");
      const issHeader  = f.key && f.key.startsWith("header-missing-");
      const headerName = issHeader ? (f.key.split("-").slice(2).join("-")) : "";
      const label = issCookie ? `Cookie: <b style="color:#f43f5e">${esc(cookieName)}</b>`
                  : issHeader ? `Header ausente: <b style="color:#fb923c">${esc(headerName)}</b>`
                  : esc(cookieName || "");
      return label ? `<div style="font-size:.71rem;margin:6px 0 3px;background:var(--sidebar);border:1px solid var(--border);border-radius:4px;padding:5px 9px">${label}</div>` : "";
    }
    if (f.type === "cors") {
      const m = (f.desc||"").match(/Origin:\s*(\S+)\s*→\s*ACAO:\s*([^\s]+)/);
      if (m) {
        const origin = m[1], acao = m[2];
        const acoColor = acao === '*' ? '#f43f5e' : '#fb923c';
        return `<div style="font-size:.71rem;margin:6px 0 3px;display:flex;gap:10px;flex-wrap:wrap">
          <span style="background:var(--sidebar);border:1px solid var(--border);border-radius:4px;padding:4px 8px">Origin: <b style="color:#fb923c">${esc(origin)}</b></span>
          <span style="background:var(--sidebar);border:1px solid var(--border);border-radius:4px;padding:4px 8px">ACAO: <b style="color:${acoColor}">${esc(acao)}</b></span>
        </div>`;
      }
      return "";
    }
    if (f.type === "brand_domain_exposure") {
      const status = (f.metadata && f.metadata.status) || "";
      const ips    = (f.metadata && f.metadata.ips) ? f.metadata.ips.slice(0,3) : [];
      return `<div style="font-size:.71rem;margin:6px 0 3px;display:flex;gap:8px;flex-wrap:wrap">
        ${status ? `<span style="background:var(--sidebar);border:1px solid var(--border);border-radius:4px;padding:3px 8px">Status: <b style="color:${status==='active'?'#f43f5e':'var(--text2)'}">${esc(status)}</b></span>` : ''}
        ${ips.length ? `<span style="background:var(--sidebar);border:1px solid var(--border);border-radius:4px;padding:3px 8px;font-family:monospace;font-size:.67rem">${ips.map(esc).join(' · ')}</span>` : ''}
      </div>`;
    }
    if (f.type === "postman_github" || f.type === "postman_secret") {
      const repo    = (f.metadata && f.metadata.repo) || "";
      const kind    = (f.metadata && f.metadata.kind) || "";
      const fileUrl = f.value && f.value.startsWith("http") ? f.value : (f.url || "");
      return `<div style="font-size:.71rem;margin:6px 0 3px">
        ${repo ? `<div style="background:var(--sidebar);border:1px solid var(--border);border-radius:4px;padding:4px 9px;margin-bottom:4px">${icoHtml("package",14)} <b style="color:var(--accent)">${esc(repo)}</b>${kind ? ` · <span style="color:var(--text3)">${esc(kind)}</span>` : ''}</div>` : ''}
        ${fileUrl ? `<a class="fc-url-link" href="${esc(fileUrl)}" target="_blank" rel="noopener" onclick="event.stopPropagation()" style="font-size:.68rem"> ${esc(fileUrl.slice(0,90))}${fileUrl.length>90?'…':''}</a>` : ''}
      </div>`;
    }
    if (f.type === "attack_chain") {
      const m = (f.title||"").match(/(\d+)\s+finding/);
      const count = m ? parseInt(m[1]) : null;
      return count ? `<div style="font-size:.71rem;margin:6px 0 3px;background:rgba(244,63,94,0.07);border:1px solid rgba(244,63,94,0.25);border-radius:4px;padding:5px 9px;color:#f43f5e">
         ${count} findings de alta severidade concentrados neste host
      </div>` : "";
    }
    return "";
  })();

  const detailHtml = `
    <div class="fc-desc-full">${esc(descClean)}</div>
    ${typeExtra}
    <div class="fc-meta-row">
      ${f.host ? `<span class="fc-meta-kv"><span class="k">host</span><span class="v">${esc(f.host)}</span></span>` : ""}
      ${f.module ? `<span class="fc-meta-kv"><span class="k">module</span><span class="v" style="color:${mc}">${esc(f.module)}</span></span>` : ""}
      ${conf ? `<span class="fc-meta-kv"><span class="k">confidence</span><span class="v">${esc(conf)}</span></span>` : ""}
      ${f.category ? `<span class="fc-meta-kv"><span class="k">category</span><span class="v">${esc(f.category)}</span></span>` : ""}
    </div>
    ${f.url && f.type !== "secret" ? `<div style="margin-bottom:6px"><a class="fc-url-link" href="${esc(f.url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()"> ${esc(f.url)}</a></div>` : ""}
    ${f.detail ? `<div style="margin-bottom:7px;font-size:.73rem;color:var(--text2);white-space:pre-wrap;word-break:break-word;background:var(--sidebar);border:1px solid var(--border);border-radius:5px;padding:9px 10px;">${esc(f.detail)}</div>` : ""}
    ${tags.length ? `<div class="fc-meta-row">${tags.map(t=>`<span class="fc-tag">${esc(t)}</span>`).join("")}</div>` : ""}`;

  const newBadge = f.is_new
    ? `<span style="background:#16a34a22;color:#4ade80;border:1px solid #4ade8055;border-radius:3px;padding:1px 6px;font-size:.6rem;font-weight:800;margin-left:6px">NOVO</span>`
    : "";

  return `<div class="fc" id="fc-${f.id}" onclick="toggleFC(${f.id})">
    <div><span class="sev ${sevCls(f.severity)}">${sevLbl(f.severity)}</span></div>
    <div class="fc-main">
      <div class="fc-topline">
        <div>
          <div class="fc-title">${esc(f.title)}${newBadge}</div>
          <div class="fc-host-row">
            ${f.host ? `<div class="fc-host">${esc(f.host)}</div>` : ""}
            <div class="fc-cat">${esc(f.category)}</div>
          </div>
        </div>
        <button class="btn btn-secondary fp-btn" style="font-size:.62rem;padding:2px 8px;margin-left:auto;flex-shrink:0;color:var(--text3)"
          onclick="event.stopPropagation();openFPModal(${JSON.stringify(esc(f.host||''))},${JSON.stringify(esc(f.title||''))},${JSON.stringify(esc(window._fpCurrentCid||''))})"
          title="Mark as False Positive"> FP</button>
        <button class="btn btn-secondary" style="font-size:.62rem;padding:2px 6px;flex-shrink:0;color:var(--text3);background:transparent;border:1px solid var(--border)"
          onclick="event.stopPropagation();copyToClipboard('${escAttr(f.title||'')}: ${escAttr(f.host||'')}')" title="Copy finding"></button>
      </div>
      <div class="fc-summary">${esc(textPreview(descClean, 220) || "No description available.")}</div>
      <div class="fc-detail" id="fd-${f.id}">${detailHtml}</div>
    </div>
    <div class="chevron">▼</div>
  </div>`;
}

function toggleFC(id) {
  const c=document.getElementById("fc-"+id), d=document.getElementById("fd-"+id);
  if(!d) return;
  c.classList.toggle("open"); d.classList.toggle("show");
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
  document.getElementById("edit-co-error").style.display = "none";
  document.getElementById("modal-edit-co").classList.add("show");
}

async function saveEditCompany() {
  const name    = document.getElementById("edit-co-name").value.trim();
  const domains = document.getElementById("edit-co-domains").value.trim()
                    .split("\n").map(d=>d.trim().toLowerCase()).filter(Boolean);
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
      body: JSON.stringify({name, domains})
    });
    if(!r.ok){ const d=await r.json(); throw new Error(d.error||"Server error"); }
    document.getElementById("modal-edit-co").classList.remove("show");
    const co = allCompanies().find(c=>c.id===_editCoId);
    if(co) { co.name = name; co.domains = domains; }
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
