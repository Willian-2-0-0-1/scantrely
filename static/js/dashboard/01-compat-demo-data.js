// ════════════════════════════════════════════════════════════════════════
//  COMPATIBILITY LAYER — bridges old globals to ASM namespace
//  When js/asm.js is loaded before this file, ASM namespace is available.
//  When loaded standalone (legacy), fall back to local definitions.
// ════════════════════════════════════════════════════════════════════════
(function() {
  'use strict';
  // If ASM module loaded, set up aliases. Otherwise define locally.
  if (typeof window.ASM === 'undefined') {
    // Legacy mode — define essential values locally
    window.SERVER_MODE = window.location.protocol === 'http:' && window.location.hostname !== '';
    window._authHeaders = function() {
      var tok = null;
      try { tok = localStorage.getItem('asmToken'); } catch(e) {}
      return tok ? {'x-auth-token': tok} : {};
    };
  }
})();

function icoHtml(name, size) {
  if (typeof window.icon === "function") return window.icon(name, { size: size || 16, className: "ico" });
  return '<span data-ico="'+name+'" data-ico-size="'+(size||16)+'" aria-hidden="true"></span>';
}
function _setIconLabel(el, name, text) {
  if (!el) return;
  el.innerHTML = icoHtml(name, 14) + " " + (text || "");
}

function originHref(raw, host) {
  return (window.ASMOrigin && typeof ASMOrigin.originHref === "function") ? ASMOrigin.originHref(raw, host) : "";
}
function isJsPathNoise(path) {
  if (window.ASMOrigin && typeof ASMOrigin.isJsPathNoise === "function") return ASMOrigin.isJsPathNoise(path);
  var s = String(path || "");
  return s.indexOf("../") === 0 || s.indexOf("./") === 0;
}
function originLinkHtml(raw, label, opts) {
  if (window.ASMOrigin && typeof ASMOrigin.originLinkHtml === "function") return ASMOrigin.originLinkHtml(raw, label, opts);
  return esc(label != null ? label : (raw || ""));
}
function originHostChip(host, extraClass) {
  if (window.ASMOrigin && typeof ASMOrigin.originHostChip === "function") {
    return ASMOrigin.originHostChip(host, extraClass);
  }
  return originLinkHtml("", host, { host: host, className: extraClass || "fg-host-chip origin-link" });
}
function _originTitle(kind) {
  if (typeof t === "function") {
    if (kind === "host") return t("origin_open_host") || "Abrir host";
    if (kind === "js") return t("origin_open_js") || "Abrir arquivo JS";
    return t("origin_open") || "Abrir o local em que foi achado";
  }
  return kind === "host" ? "Abrir host" : (kind === "js" ? "Abrir arquivo JS" : "Abrir o local em que foi achado");
}

let _pendingFoundFilter = null; // {tab, q} applied after switchTab paints the owner surface

async function jumpToFound(tab, query, ev) {
  if (ev) { ev.preventDefault(); ev.stopPropagation(); }
  _pendingFoundFilter = { tab: tab, q: String(query || "") };
  await switchTab(tab);
  setTimeout(_applyPendingFoundFilter, 80);
}

function _applyPendingFoundFilter() {
  const p = _pendingFoundFilter;
  if (!p) return;
  if (p.tab === "jsreverse") {
    const el = document.getElementById("jsr-text-filter");
    const ep = document.getElementById("jsr-ep-text");
    if (!el && !ep) return;
    _pendingFoundFilter = null;
    if (el) el.value = p.q;
    if (ep) ep.value = p.q;
    if (typeof _jsrRender === "function") _jsrRender();
    if (typeof _jsrRenderEp === "function") _jsrRenderEp();
    const tbl = document.getElementById("jsr-secrets-table") || document.getElementById("tab-jsreverse");
    if (tbl) tbl.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  if (p.tab === "endpoints") {
    const el = document.getElementById("url-search");
    if (!el) return;
    _pendingFoundFilter = null;
    el.value = p.q;
    window._urlSearch = p.q;
    if (typeof filterUrlsTable === "function") filterUrlsTable();
    const wrap = document.getElementById("urls-table-wrap") || document.getElementById("tab-endpoints");
    if (wrap) wrap.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}



// ════════════════════════════════════════════════════════════════════════
//  DEMO DATA (Porto Seguro) — used when asm_data.js is not present
// ════════════════════════════════════════════════════════════════════════
const DEMO_DATA = {
  version: "1.0",
  generated: "2026-04-20T12:00:00",
  companies: [
    {
      id: "portoseguro",
      name: "Porto Seguro",
      color: "#00c9a7",
      domains: ["portoseguro.com.br"],
      tags: ["insurance","fintech","brazil"],
      last_scan: "2026-04-20",
      stats: {
        subdomains: 450, live_hosts: 201, open_ports: 1296, waf_protected: 128,
        findings_critical: 3, findings_high: 6, findings_medium: 12, findings_low: 0, findings_info: 9
      },
      waf_coverage: { "Imperva":128, "AWS CloudFront":41, "Cloudflare":16, "Direct":56, "Direct (Firewalled)":110, "Google Cloud":8 },
      tech_summary: { "Imperva Incapsula":14, "Apache HTTP":4, "nginx":4, "Varnish Cache":3, "Citrix NetScaler":3, "Envoy Proxy":2, "Cloudflare":5, "amazon_elb":6 },
      buckets: [
        { name:"productionresultssa14", url:"https://productionresultssa14.blob.core.windows.net/", accessible:false },
        { name:"productionresultssa6",  url:"https://productionresultssa6.blob.core.windows.net/",  accessible:false }
      ],
      findings: [
        { id:1, severity:"critical", category:"Credentials", title:"admin:admin Hardcoded em JS de Produção", host:"loja.portoseguro.com.br", url:"https://loja.portoseguro.com.br",
          desc:"A classe <code>QuoteService</code> no bundle Angular contém credenciais Basic Auth hardcoded: <code>BasicAuth YWRtaW46YWRtaW4=</code> (admin:admin). Enviado em requests ao endpoint <code>/stage/proponente-api/v1/</code>.",
          detail:`<pre>this.token = "BasicAuth YWRtaW46YWRtaW4=", this.className = "QuoteService"\n// Arquivo: /etc/clientlibs/porto-store/clientlibs/clientlib-angular.lc-*.js\n// Decodificado: admin:admin</pre><b>Endpoints afetados:</b><br>• https://47zimjues7.execute-api.us-west-2.amazonaws.com/stage/proponente-api/v1/<br>• https://bxn9o4w0pd.execute-api.ca-central-1.amazonaws.com/` },
        { id:2, severity:"critical", category:"CVE / Vuln", title:"Tableau Server 2023.1.7 — 6 CVEs Conhecidas", host:"tableau.portoseguro.com.br", url:"https://tableau.portoseguro.com.br",
          desc:"Tableau Server versão <code>2023.1.7</code> em produção com 6 CVEs confirmados. Versão corrigida: <code>2023.3.19</code>.",
          detail:`<b>CVEs:</b><br>• CVE-2023-44487 — HTTP/2 Rapid Reset (CVSS 7.5)<br>• CVE-2023-25953 — Stored XSS<br>• CVE-2023-25954 — Info Disclosure<br><b>IP direto:</b> 131.161.97.72 &nbsp; <b>Portas:</b> 80, 443, 8080, 8443, 9000` },
        { id:3, severity:"critical", category:"Cloud", title:"MISP Threat Intelligence Platform Exposto", host:"misp.portoseguro.com.br", url:"https://misp.portoseguro.com.br",
          desc:"Plataforma MISP acessível via internet. Contém IOCs, indicadores de malware e inteligência de ameaças interna.",
          detail:`<b>Host:</b> misp.portoseguro.com.br → 131.161.97.x<br><b>Impacto:</b> Exposição de toda inteligência de ameaças interna e IOCs.<br><b>Fix:</b> Restringir via VPN/IP allowlist.` },
        { id:4, severity:"high", category:"IAM / Identity", title:"SailPoint IdentityNow Portal Exposto", host:"portaldeacessos.portoseguro.com.br", url:"https://portaldeacessos.portoseguro.com.br",
          desc:"Portal de Identity Governance (SailPoint) acessível via internet. Gerencia acesso de todos colaboradores.",
          detail:`<b>Tenant:</b> portoseguro.login.sailpoint.com<br><b>API:</b> portoseguro.api.identitynow.com<br><b>Disclosure:</b> Formato de matrícula <code>f0123456</code> revelado na página de login.` },
        { id:5, severity:"high", category:"CORS", title:"CORS Exploitable — Origin Refletido + Credentials", host:"abx.loja.portoseguro.com.br", url:"https://abx.loja.portoseguro.com.br",
          desc:"Servidor reflete qualquer cabeçalho Origin com <code>Access-Control-Allow-Credentials: true</code>.",
          detail:`<b>Request:</b> Origin: https://evil.com<br><b>Response:</b><br><pre>Access-Control-Allow-Origin: https://evil.com\nAccess-Control-Allow-Credentials: true</pre>` },
        { id:6, severity:"high", category:"Info Disclosure", title:"Hostname Interno Vazado em Header CSP", host:"dev.saude.portoseguro.com.br", url:"https://dev.saude.portoseguro.com.br",
          desc:"Header <code>Content-Security-Policy</code> expõe hostname de servidor interno na diretiva <code>frame-src</code>.",
          detail:`<b>CSP frame-src:</b><br><pre>https://nt50388.portoseguro.brasil/</pre>Hostname Windows NT interno. TLD ".brasil" = domínio AD interno.` },
        { id:7, severity:"high", category:"IAM / Identity", title:"Formato de Matrícula de Funcionários Exposto", host:"portaldeacessos.portoseguro.com.br", url:"https://portaldeacessos.portoseguro.com.br",
          desc:"Página de login SailPoint revela o formato das matrículas: <code>f0123456</code> (f + 7 dígitos).",
          detail:`<b>Texto:</b> "Lembrando de substituir f0123456 pela sua matricula"<br><b>Formato:</b> <code>f[0-9]{7}</code><br><b>Risco:</b> Permite gerar listas para password spray.` },
        { id:8, severity:"high", category:"Credentials", title:"AWS API Gateway URLs Hardcoded em JS", host:"loja.portoseguro.com.br", url:"https://loja.portoseguro.com.br",
          desc:"Dois AWS API Gateway endpoints hardcoded no bundle JS, usados com credenciais admin:admin.",
          detail:`<b>GW1:</b> <code>bxn9o4w0pd.execute-api.ca-central-1.amazonaws.com</code><br><b>GW2:</b> <code>47zimjues7.execute-api.us-west-2.amazonaws.com</code><br><b>Auth:</b> BasicAuth admin:admin` },
        { id:9, severity:"high", category:"CVE / Vuln", title:"OAuth Token Endpoint Potencialmente Spray-ável", host:"login.windows.net", url:"https://login.windows.net",
          desc:"Endpoint OAuth2 Azure AD identificado como potencialmente vulnerável a password spraying.",
          detail:`<b>Endpoint:</b> https://login.windows.net/ed7958eb-216a-4854-a42e-3c7127272021/oauth2/token<br><b>Tenant:</b> ed7958eb-216a-4854-a42e-3c7127272021` },
        { id:10, severity:"medium", category:"Dev/Stage", title:"APIs de Saúde DEV/HML Acessíveis (CORS Wildcard)", host:"dev.api.saude.portoseguro.com.br", url:"", desc:"APIs do Portal do Prestador em DEV/HML com CORS <code>Access-Control-Allow-Origin: *</code>.", detail:"<b>DEV:</b> https://dev.api.saude.portoseguro.com.br/prestador/v1/<br><b>HML:</b> https://hml.api.saude.portoseguro.com.br/prestador/v1/" },
        { id:11, severity:"medium", category:"Dev/Stage", title:"Ambientes Stage/Dev de Autenticação Expostos", host:"loja-stage-auth.portoseguro.com.br", url:"", desc:"Cognito User Pools HML e DEV do Adobe Experience Manager acessíveis via internet.", detail:"<b>Stage:</b> loja-stage-auth → aem-hml.auth.ca-central-1.amazoncognito.com<br><b>Dev:</b> loja-dev-auth → AWS Cognito DEV" },
        { id:12, severity:"medium", category:"Dev/Stage", title:"Portal do Prestador (Saúde) DEV/HML Exposto", host:"dev.saude.portoseguro.com.br", url:"", desc:"Portal de saúde DEV/HML acessível via internet (S3+CloudFront). Dados LGPD.", detail:"<b>HML:</b> hml.saude.portoseguro.com.br<br><b>DEV:</b> dev.saude.portoseguro.com.br" },
        { id:13, severity:"medium", category:"Cloud", title:"Orquestrador de Pagamentos Exposto", host:"portal.meiosdepagamento.portoseguro.com.br", url:"", desc:"Sistema de orquestração de pagamentos acessível via internet (S3+CloudFront+Azure AD).", detail:"<b>Azure App:</b> f7803731-7830-4239-a811-fee25df9883a<br><b>Tenant:</b> ed7958eb-216a-4854-a42e-3c7127272021" },
        { id:14, severity:"medium", category:"Cloud", title:"PortoStore Backoffice Exposto", host:"psstore.portoseguro.com.br", url:"", desc:"Backoffice da Porto Store (Angular + S3+CloudFront) acessível externamente.", detail:"<b>URL:</b> https://psstore.portoseguro.com.br" },
        { id:15, severity:"medium", category:"Dev/Stage", title:"APIs Stage/Dev da Loja Acessíveis", host:"loja-stage-api.portoseguro.com.br", url:"", desc:"Endpoints de API stage/dev da loja online acessíveis externamente via AWS CloudFront.", detail:"<b>Stage:</b> loja-stage-api.portoseguro.com.br<br><b>Dev:</b> loja-dev-api.portoseguro.com.br" },
        { id:16, severity:"medium", category:"IAM / Identity", title:"Cognito User Pools AEM Identificados", host:"loja-auth.portoseguro.com.br", url:"", desc:"User Pools AWS Cognito para autenticação AEM em PRD/HML/DEV identificados.", detail:"<b>PRD:</b> aem-prd.auth.ca-central-1.amazoncognito.com<br><b>HML:</b> aem-hml.auth.ca-central-1.amazoncognito.com" },
        { id:17, severity:"medium", category:"DNS", title:"Subdomain CNAME para Domínio Não Controlado", host:"campanhas.portoseguro.com.br", url:"", desc:"CNAME para <code>campanhasportoseguro.com.br</code> hospedado em DNS parking (Hostinger).", detail:"<b>NS:</b> ns1.dns-parking.com / ns2.dns-parking.com<br><b>IPs:</b> 77.37.42.244, 147.79.105.154" },
        { id:18, severity:"medium", category:"Info Disclosure", title:"Azure AD Client IDs Expostos em JS", host:"portal.meiosdepagamento.portoseguro.com.br", url:"", desc:"IDs de aplicações Azure AD expostos nos bundles JS públicos.", detail:"<b>Pagamentos:</b> f7803731-7830-4239-a811-fee25df9883a<br><b>SailPoint:</b> e488b780-0d92-4e92-8ea4-8b24849c0800" },
        { id:19, severity:"medium", category:"Cloud", title:"MuleSoft Anypoint Flex Gateway Identificado", host:"api.bap-hml.portoseguro.com.br", url:"", desc:"API Gateway MuleSoft em ambiente HML identificado e acessível.", detail:"<b>HML:</b> api.bap-hml.portoseguro.com.br<br><b>mTLS:</b> api.bap-mtls-hml.portoseguro.com.br" },
        { id:20, severity:"medium", category:"Info Disclosure", title:"Topologia de Rede Interna via DNS", host:"nac11dc00-tlf.portoseguro.com.br", url:"", desc:"DNS público com IPs privados (172.x.x.x) revelando topologia interna.", detail:"<b>NAC:</b> nac11dc00-tlf → 172.28.1.172<br><b>ALM:</b> portoalm → 172.27.73.27<br><b>VLANs:</b> visitantes1-4 → 172.26-27.x" },
        { id:21, severity:"info", category:"Cloud", title:"Axway Amplify API Marketplace Identificado", host:"developers.portoseguro.com.br", url:"", desc:"Marketplace de APIs Axway com 3 domínios para parceiros.", detail:"developers.portoseguro.com.br<br>porto-developers.portoseguro.com.br<br>seguros-developers.portoseguro.com.br" },
        { id:22, severity:"info", category:"Cloud", title:"PortoBank Cross-Domain API Gateways", host:"api-gw.portobank-crossdomain.prd.portoseguro.com.br", url:"", desc:"API Gateways cross-domain do PortoBank (PRD/HML) com variantes mTLS.", detail:"" },
        { id:23, severity:"info", category:"Cloud", title:"Session Border Controller (SBC) Identificado", host:"sbc.portoseguro.com.br", url:"wss://sbc.portoseguro.com.br", desc:"SBC VoIP/WebRTC identificado via URI wss://. Atrás de firewall.", detail:"<b>CNAME:</b> sbc.lb.portoseguro.com.br → 131.161.97.102" },
        { id:24, severity:"info", category:"Cloud", title:"Tenant Sydle (BPM) Identificado", host:"portoseguro.sydle.one", url:"https://portoseguro.sydle.one", desc:"Tenant Sydle BPM/automação hospedado no Cloudflare (403 requer auth).", detail:"" },
        { id:25, severity:"info", category:"DNS", title:"DNSSEC NSEC Zone Walking em Afiliados", host:"mtl.mailcloud.com.br", url:"", desc:"Zone walking DNSSEC habilitado em domínios de parceiros.", detail:"• mtl.mailcloud.com.br<br>• app.securiti.ai" },
        { id:26, severity:"info", category:"CVE / Vuln", title:"Shodan CVEs em Servidores de E-mail Afiliados", host:"mtl.mailcloud.com.br", url:"", desc:"CVEs em servidores de email/infra de terceiros usados pelo Porto Seguro.", detail:"<b>mtl.mailcloud.com.br:</b> CVE-2025-23419, CVE-2022-41742, CVE-2023-44487" },
        { id:27, severity:"info", category:"Info Disclosure", title:"Varnish Cache Plus na Loja", host:"loja.portoseguro.com.br", url:"", desc:"Loja usa Varnish Cache Plus (versão enterprise).", detail:"" },
        { id:28, severity:"info", category:"Cloud", title:"Dois Gateways Citrix NetScaler Identificados", host:"ho.portoseguro.com.br", url:"", desc:"Dois Citrix NetScaler ADC para acesso remoto/VDI de funcionários.", detail:"<b>GW1:</b> ho.portoseguro.com.br<br><b>GW2:</b> ho.ctx.portoseguro.com.br" },
        { id:29, severity:"info", category:"Cloud", title:"Banking Sandbox APIs Expostas", host:"apibank-sandbox.portoseguro.com.br", url:"", desc:"Endpoints sandbox do PortoBank disponíveis externamente.", detail:"apibank-sandbox.portoseguro.com.br → 54.94.225.105" },
        { id:30, severity:"info", category:"Info Disclosure", title:"Estrutura AEM CMS Revelada em 404", host:"loja-stage.portoseguro.com.br", url:"", desc:"Resposta 404 do AEM revela estrutura interna de paths.", detail:`<pre>404 Resource at '/content/porto-seguro/lojaonlineportoseguro/Home.html' not found</pre>` }
      ],
      hosts: [
        {host:"abx.loja.portoseguro.com.br",ip:"95.131.136.1",waf:"Direct",technologies:["nginx"],ports:["80","443"]},
        {host:"agendavip.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:[],ports:["80","443"]},
        {host:"aluguel.portoseguro.com.br",ip:"34.149.87.214",waf:"Google Cloud",technologies:["cloud_platform"],ports:["80","443"]},
        {host:"antecipacaoportobank.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:[],ports:["80","443"]},
        {host:"apibank-sandbox.portoseguro.com.br",ip:"54.94.225.105",waf:"AWS CloudFront",technologies:[],ports:["443"]},
        {host:"api.bap-hml.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:["anypoint_flex_gateway"],ports:["80","443"]},
        {host:"api.bap-mtls-hml.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:[],ports:["80","443"]},
        {host:"api.checkout.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:[],ports:["80","443"]},
        {host:"apicorporativops.portoseguro.com.br",ip:"192.225.159.76",waf:"Direct",technologies:["apache_http_server"],ports:["443","8080"]},
        {host:"api-gw.portobank-crossdomain.hml.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:[],ports:["80","443"]},
        {host:"api-gw.portobank-crossdomain.prd.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:[],ports:["80","443"]},
        {host:"api.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:[],ports:["80","443"]},
        {host:"bank-hml.portoseguro.com.br",ip:"108.158.168.188",waf:"AWS CloudFront",technologies:["amazon_cloudfront"],ports:["80","443"]},
        {host:"b.comunicados.portoseguro.com.br",ip:"104.18.16.230",waf:"Cloudflare",technologies:[],ports:["80","443","8080","8443"]},
        {host:"b.consorcio.portoseguro.com.br",ip:"104.18.17.230",waf:"Cloudflare",technologies:[],ports:["80","443","8080","8443"]},
        {host:"campanhas.portoseguro.com.br",ip:"77.37.42.244",waf:"Direct",technologies:[],ports:["80","443"]},
        {host:"checkout.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:[],ports:["80","443"]},
        {host:"clickplayrfc.el.portoseguro.com.br",ip:"104.26.0.210",waf:"Cloudflare",technologies:["cloudflare"],ports:["80","443","8080","8443"]},
        {host:"cpe-prd.portoseguro.com.br",ip:"3.166.152.54",waf:"AWS CloudFront",technologies:["amazon_cloudfront","amazon_elb"],ports:["80","443"]},
        {host:"dev.api.saude.portoseguro.com.br",ip:"15.157.223.2",waf:"AWS CloudFront",technologies:["amazon_elb"],ports:["443"]},
        {host:"developers.portoseguro.com.br",ip:"3.86.171.76",waf:"AWS CloudFront",technologies:["envoy","bootstrap"],ports:["80","443"]},
        {host:"dev.saude.portoseguro.com.br",ip:"3.174.83.116",waf:"AWS CloudFront",technologies:["amazon_cloudfront"],ports:["80","443"]},
        {host:"hml.api.saude.portoseguro.com.br",ip:"16.52.231.210",waf:"AWS CloudFront",technologies:["amazon_elb"],ports:["443"]},
        {host:"hml.saude.portoseguro.com.br",ip:"3.162.247.56",waf:"AWS CloudFront",technologies:["amazon_cloudfront"],ports:["80","443"]},
        {host:"ho.ctx.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:["apache","citrix_netscaler","jquery"],ports:["80","443"]},
        {host:"ho.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:["apache","citrix_netscaler","jquery"],ports:["80","443"]},
        {host:"loja-auth.portoseguro.com.br",ip:"18.155.21.66",waf:"AWS CloudFront",technologies:["amazon_cloudfront"],ports:["80","443"]},
        {host:"loja-dev-api.portoseguro.com.br",ip:"3.98.229.2",waf:"AWS CloudFront",technologies:[],ports:["443"]},
        {host:"loja.portoseguro.com.br",ip:"151.101.131.10",waf:"AWS CloudFront",technologies:["varnish_cache","varnish_cache_plus"],ports:["80","443"]},
        {host:"loja-stage-api.portoseguro.com.br",ip:"3.98.7.115",waf:"AWS CloudFront",technologies:[],ports:["443"]},
        {host:"loja-stage-auth.portoseguro.com.br",ip:"13.227.107.32",waf:"AWS CloudFront",technologies:["amazon_cloudfront"],ports:["80","443"]},
        {host:"loja-stage.portoseguro.com.br",ip:"151.101.67.10",waf:"AWS CloudFront",technologies:["varnish_cache"],ports:["80","443"]},
        {host:"misp.portoseguro.com.br",ip:"131.161.97.x",waf:"Direct (Firewalled)",technologies:[],ports:[]},
        {host:"parceirosgcp.portoseguro.com.br",ip:"35.215.247.198",waf:"Google Cloud",technologies:[],ports:["80","443"]},
        {host:"portaldeacessos.portoseguro.com.br",ip:"172.66.1.161",waf:"Cloudflare",technologies:["cloudflare"],ports:["80","443","8080","8443"]},
        {host:"portal.meiosdepagamento.portoseguro.com.br",ip:"18.67.130.35",waf:"AWS CloudFront",technologies:["amazon_cloudfront"],ports:["80","443"]},
        {host:"portoapicloud-mtls.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:["imperva_incapsula"],ports:["80","443"]},
        {host:"psstore.portoseguro.com.br",ip:"3.164.28.66",waf:"AWS CloudFront",technologies:[],ports:["80","443"]},
        {host:"queropagar.portoseguro.com.br",ip:"216.239.34.21",waf:"Google Cloud",technologies:["google_cloud"],ports:["80","443"]},
        {host:"relatorio.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:[],ports:["80","443","8080"]},
        {host:"relaytrk.apoliceauto.portoseguro.com.br",ip:"161.47.47.234",waf:"Direct",technologies:["asp.net"],ports:["80","443"]},
        {host:"salvados.portoseguro.com.br",ip:"45.60.4.187",waf:"Direct",technologies:["imperva_incapsula"],ports:["80","443","3000","5000","8080","8443"]},
        {host:"sbc.portoseguro.com.br",ip:"131.161.97.102",waf:"Direct (Firewalled)",technologies:[],ports:[]},
        {host:"tableau.portoseguro.com.br",ip:"45.223.45.75",waf:"Imperva",technologies:["imperva_incapsula"],ports:["80","443","8080","8443","9000"]},
        {host:"wwws.portoseguro.com.br",ip:"45.60.4.187",waf:"Direct",technologies:["imperva_incapsula"],ports:["80","443","3000","5000","8080","8443"]}
      ]
    }
  ]
};

// ════════════════════════════════════════════════════════════════════════
//  GLOBAL COMPAT — maps dashboard globals to the ASM namespace
//  (Defined in js/asm.js — available when loaded via dashboard.html)
// ════════════════════════════════════════════════════════════════════════
const SERVER_MODE = window.SERVER_MODE; // from asm.js

let DATA = (typeof window.ASM !== 'undefined' && ASM.data) ? ASM.data
  : (SERVER_MODE ? { version: '1.0', generated: null, companies: [] }
    : ((typeof window.ASM_DATA !== 'undefined') ? window.ASM_DATA : DEMO_DATA));

// Keep DATA in sync with ASM namespace
if (typeof window.ASM !== 'undefined') {
  if (!ASM.data || !ASM.data.companies || !ASM.data.companies.length) {
    // If ASM.data is empty/default, use our DEMO_DATA
    ASM.data = DEMO_DATA;
    DATA = ASM.data;
  } else {
    if (!ASM.data.companies) ASM.data.companies = [];
    DATA = ASM.data;
  }
  ASM.DEMO_DATA = DEMO_DATA;
}

function _replaceCompanyInData(company) {
  if (typeof ASM !== 'undefined' && ASM.replaceCompanyInData) {
    ASM.replaceCompanyInData(company);
    return;
  }
  if (!company || !company.id) return;
  const companies = DATA.companies || [];
  const idx = companies.findIndex(c => c.id === company.id);
  if (idx >= 0) companies[idx] = company;
  else companies.push(company);
}

// ── API error helper ─────────────────────────────────────────────────────────
async function _apiErr(r) {
  if (r.status === 401) {
    // Only redirect to login if we have no token at all (not just a server-side expiry)
    const hasToken = !!(authToken || (function(){ try { return localStorage.getItem('asmToken'); } catch(_){ return null; } })());
    if (!hasToken && typeof showLoginScreen === 'function') showLoginScreen();
    return new Error('Session expired — please sign in again');
  }
  try {
    const d = await r.clone().json();
    return new Error(d.error || d.message || `HTTP ${r.status}`);
  } catch(_) {
    return new Error(`HTTP ${r.status}`);
  }
}

// These are provided by js/api.js when available
if (typeof loadServerSummary === 'undefined') {
  window.loadServerSummary = async function() {
    if (!SERVER_MODE) return;
    const r = await fetch('/api/data/summary', { headers: _authHeaders() });
    if (!r.ok) throw await _apiErr(r);
    const d = await r.json();
    // Mutate in place so DATA stays in sync with ASM.data
    DATA.version = d.version || DATA.version;
    DATA.generated = d.generated || DATA.generated;
    DATA.companies = d.companies || [];
  };
}
if (typeof ensureCompanyLoaded === 'undefined') {
  window.ensureCompanyLoaded = async function(id, opts = {}) {
    if (!SERVER_MODE || !id) return allCompanies().find(c => c.id === id);
    const existing = allCompanies().find(c => c.id === id);
    if (existing && !existing.summary_only && !opts.force) return existing;
    const r = await fetch(`/api/data/company/${encodeURIComponent(id)}`, { headers: _authHeaders() });
    if (!r.ok) throw await _apiErr(r);
    const d = await r.json();
    _replaceCompanyInData(d);
    return d;
  };
}
if (typeof reloadServerData === 'undefined') {
  window.reloadServerData = async function() {
    if (!SERVER_MODE) return;
    try {
      await loadServerSummary();
      if (ASM && ASM.currentId) await ensureCompanyLoaded(ASM.currentId, { force: true });
      else if (state && state.currentId) await ensureCompanyLoaded(state.currentId, { force: true });
    } catch(e) {}
    try {
      const r2 = await fetch('/api/companies', { headers: _authHeaders() });
      if (!r2.ok) return;
      const cos = await r2.json();
      const dataIds = new Set((DATA.companies || []).map(c => c.id));
      for (const co of cos) {
        if (!dataIds.has(co.id)) {
          DATA.companies = DATA.companies || [];
          DATA.companies.push({ ...co,
            stats: { subdomains: 0, live_hosts: 0, open_ports: 0, waf_protected: 0,
              findings_critical: 0, findings_high: 0, findings_medium: 0, findings_low: 0, findings_info: 0 },
            waf_coverage: {}, tech_summary: {}, findings: [], hosts: [], buckets: [] });
        }
      }
    } catch(e) {}
  };
}

// State object — use ASM when available, fallback to local
const state = (typeof ASM !== 'undefined') ? ASM : {
  currentId: null, page: 'companies', tab: 'overview',
  hostsPage: 1, portsPage: 1,
  hostsFilter: { q: '', waf: '', status: '' },
  findFilter: { q: '', sev: '', cat: '' },
  portsFilter: { q: '', port: '' },
  hostsData: [], portsData: [], findData: [],
  mobileNavOpen: false,
};
if (!state.page) state.page = "companies";
if (!state.hostPanel) state.hostPanel = "subdomains";
if (!state.groupPanel) state.groupPanel = {};
if (!state.groupPanel.hosts) state.groupPanel.hosts = state.hostPanel;

let _jobsPoll = null;
let _jobCountPoll = null;  // always-on job count updater for nav badge
let _companyQueueSummaryCache = [];
let _companyQueueSummaryLoading = false;
let _companyQueueSummaryLoaded = false;

function _cardKPI({ cls = "", value = "0", label = "", note = "" }) {
  return `
    <div class="portfolio-kpi ${cls}">
      <div class="value">${esc(value)}</div>
      <div class="label">${esc(label)}</div>
      ${note ? `<div class="job-detail-copy" style="margin-top:8px">${esc(note)}</div>` : ""}
    </div>`;
}

function _jobKPICard(status, count) {
  const label = _jobStatusLabel(status);
  return `
    <div class="job-kpi ${_jobStatusClass(status)}">
      <div class="job-kpi-num">${Number(count || 0)}</div>
      <div class="job-kpi-label">${esc(label)}</div>
    </div>`;
}

function _companyScopeCount(co) {
  return Array.isArray(co?.domains) ? co.domains.filter(Boolean).length : 0;
}

function _companyScopeLabel(co) {
  const total = _companyScopeCount(co);
  return `${total.toLocaleString()} ${total === 1 ? "dominio" : "dominios"} no escopo`;
}

function _companyQueueCounts(co) {
  const scopeTotal = _companyScopeCount(co);
  const summary = _companyQueueSummaryCache.find(s => String(s.company_id || "") === String(co?.id || ""));
  if (!summary) return { complete: 0, finalized: 0, queued: scopeTotal };
  const counts = summary.counts || {};
  return {
    complete: Number(counts.complete || 0),
    finalized: Number(counts.done || 0),
    queued: Number(counts.pending || 0) + Number(counts.running || 0),
  };
}

function _companyQueueProgress(co) {
  const summary = _companyQueueSummaryCache.find(s => String(s.company_id || "") === String(co?.id || ""));
  if (!summary) return null;
  const c = summary.counts || {};
  const total = Number(summary.total || 0);
  const done = Number(c.done || 0);
  const running = Number(c.running || 0);
  const pending = Number(c.pending || 0);
  const stopped = Number(c.stopped || 0);
  const error = Number(c.error || 0);
  const cancelled = Number(c.cancelled || 0);
  const complete = Number(c.complete || 0);
  const active = running + pending;
  if (!total) return null;
  const completed = done + stopped + error + cancelled;
  const rawPct = Math.min(100, ((completed + (running ? 0.5 : 0)) / total) * 100);
  const pct = active ? Math.max(rawPct, 2) : rawPct;
  return {total, complete, done, running, pending, stopped, error, cancelled, active, pct};
}

function _ensureCompanyQueueSummary() {
  if (!SERVER_MODE || _companyQueueSummaryLoaded || _companyQueueSummaryLoading) return;
  _companyQueueSummaryLoading = true;
  fetch("/api/jobs/summary", {headers:_authHeaders()})
    .then(r => r.ok ? r.json() : [])
    .then(summary => {
      _companyQueueSummaryCache = Array.isArray(summary) ? summary : [];
      _companyQueueSummaryLoaded = true;
      if (state.page === "companies") renderAllCompanies();
    })
    .catch(() => { _companyQueueSummaryLoaded = true; })
    .finally(() => { _companyQueueSummaryLoading = false; });
}

function _playwrightCard(job, opts = {}) {
  const meta = opts.meta || _fmtJobTime(job.created_at);
  const company = esc(_companyNameForJob(job.company_id));
  const target = esc(job.target || opts.target_url || "—");
  const status = _jobStatusLabel(job.status);
  const badges = [
    job.status === "done" ? `<a class="playwright-item-badge done" href="${_jobArtifactUrl(job.id, 'report')}" target="_blank" rel="noopener">Report</a>` : "",
    job.status === "done" ? `<a class="playwright-item-badge done" href="${_jobArtifactUrl(job.id, 'session')}" target="_blank" rel="noopener">Session</a>` : "",
    `<button class="playwright-item-badge" style="cursor:pointer" onclick="openJobDetail(${_jsArg(job.id)})">Details</button>`,
  ].join("");
  return `
    <article class="playwright-item">
      <div class="playwright-item-head">
        <div>
          <div class="playwright-item-title">${company}</div>
          <div class="playwright-item-sub">${target}</div>
        </div>
        <span class="playwright-item-badge ${_jobStatusClass(job.status)}">${status}</span>
      </div>
      <div class="playwright-item-sub" style="margin-top:8px">${esc(meta)}</div>
      <div class="playwright-item-sub" id="pw-inventory-${escAttr(job.id)}" style="margin-top:8px">${opts.inventory || ""}</div>
      <div class="playwright-item-badges">${badges}</div>
    </article>`;
}

async function _hydratePlaywrightInventory(job) {
  if (!job || job.job_type !== "playwright_recon") return;
  const mount = document.getElementById(`pw-inventory-${job.id}`);
  if (!mount) return;
  mount.innerHTML = `<span style="color:var(--text3)">Loading host inventory…</span>`;
  try {
    const r = await fetch(_jobArtifactUrl(job.id, "session"), {headers:_authHeaders()});
    if (!r.ok) throw new Error("HTTP " + r.status);
    const session = await r.json();
    mount.innerHTML = _playwrightInventorySummary(session);
  } catch(e) {
    mount.innerHTML = `<span style="color:var(--text3)">Inventory unavailable</span>`;
  }
}

function _hydratePlaywrightInventoryBatch(jobs) {
  (jobs || []).filter(job => job.job_type === "playwright_recon").slice(0, 4).forEach(job => {
    _hydratePlaywrightInventory(job);
  });
}

function _severityCard(severity, count, cid) {
  const classes = { critical: "c", high: "h", medium: "m", low: "l", info: "i" };
  const labels = {
    critical: _opT("vuln_sev_critical", "Crítica"),
    high: _opT("vuln_sev_high", "Alta"),
    medium: _opT("vuln_sev_medium", "Média"),
    low: _opT("vuln_sev_low", "Baixa"),
    info: _opT("vuln_sev_info", "Info"),
  };
  const click = cid ? ` onclick="goToVulnSeverity(${_jsArg(cid)},'${severity}',event)" style="cursor:pointer" title="Ver vulnerabilidades ${labels[severity] || severity}"` : "";
  return `
    <div class="findings-mini ${classes[severity] || ""}"${click}>
      <div class="findings-mini-num">${Number(count || 0)}</div>
      <div class="findings-mini-lbl">${labels[severity] || severity || "Info"}</div>
    </div>`;
}

function _hostTableRow(h) {
  const techs = (h.technologies || []).map(t => `<span class="tech-c">${esc(t)}</span>`).join("");
  const ports = (h.ports || []).map(p => `<span class="port-c">${esc(p)}</span>`).join("");
  const title = (h.title || "").substring(0, 80);
  const shotSrc = _shotSrc(h.screenshot);
  const screenshot = shotSrc
    ? `<img src="${esc(shotSrc)}" alt="${esc("Screenshot de " + (h.host || ""))}" style="width:48px;height:30px;object-fit:cover;border-radius:4px;border:1px solid var(--border);cursor:pointer" onerror="this.style.display='none'" onmouseenter="ssPopoverShow(event,${_shotJs(shotSrc)},${_shotJs(h.host || "")})" onmouseleave="ssPopoverHide()">`
    : `<span style="color:var(--text3);font-size:.6rem">—</span>`;
  return `
    <tr>
      <td><a class="host-a" href="https://${esc(h.host)}" target="_blank">${esc(h.host)}</a></td>
      <td><span class="ip-t">${esc(h.ip)}</span></td>
      <td><span style="font-size:.7rem;color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block" title="${esc(title)}">${esc(title) || '—'}</span></td>
      <td><span class="waf-t ${wafClass(h.waf)}">${esc(h.waf)}</span></td>
      <td>${techs || `<span style="color:var(--text3);font-size:.65rem">—</span>`}</td>
      <td>${ports || `<span style="color:var(--text3);font-size:.65rem">—</span>`}</td>
      <td>${screenshot}</td>
    </tr>`;
}

function _infraCard(title, rows, attrs = "") {
  return `
    <div class="ic" ${attrs}>
      <div class="ic-title">${esc(title)}</div>
      ${(rows || []).join("")}
    </div>`;
}

function _infraRow(key, value, cls = "") {
  return `<div class="ic-row"><span class="ic-k">${esc(key)}</span><span class="ic-v ${cls}">${value}</span></div>`;
}

function _timelineRow(e) {
  const ports = Array.isArray(e.ports) ? e.ports.join(', ') : e.ports;
  return `
    <div class="timeline-item">
      <div class="timeline-dot new"></div>
      <div class="timeline-info">
        <div class="timeline-host">${esc(e.host)}</div>
        <div class="timeline-meta">
          <span>IP: ${esc(e.ip||'?')}</span>
          <span>Ports: ${esc(ports)}</span>
          <span>Status: ${esc(e.status_code||'?')}</span>
          ${e.waf ? `<span>WAF: ${esc(e.waf)}</span>` : ''}
        </div>
      </div>
      <div class="timeline-ts">${esc((e.scan_ts||'').slice(0,16))}</div>
    </div>`;
}

// ── Always-polling job count badge for the sidebar nav ──
function _startJobCountPoll() {
  if (_jobCountPoll) return;
  _updateJobCountBadge();
  _jobCountPoll = setInterval(_updateJobCountBadge, 8000);
}
function _updateJobCountBadgeFromList(jobs) {
  const badge = document.getElementById("nav-jobs-badge");
  const pwBadge = document.getElementById("nav-playwright-badge");
  const topPwBadge = document.getElementById("topbar-playwright-badge");
  if (!badge) return;
  const running = jobs.filter(j => j.status === "running").length;
  const pending = jobs.filter(j => j.status === "pending").length;
  const errors  = jobs.filter(j => j.status === "error").length;
  const playwrightActive = jobs.filter(j => j.job_type === "playwright_recon" && (j.status === "running" || j.status === "pending")).length;
  const total   = running + pending;
  if (total > 0) {
    badge.style.display = "inline-flex";
    badge.textContent = total;
    badge.className = "nav-badge pulse";
    setTimeout(() => { if (badge.classList.contains("pulse")) badge.classList.remove("pulse"); }, 700);
    if (errors > 0) badge.classList.add("has-errors");
  } else {
    badge.style.display = "none";
  }
  if (pwBadge) {
    if (playwrightActive > 0) {
      pwBadge.style.display = "inline-flex";
      pwBadge.textContent = String(playwrightActive);
      pwBadge.className = "nav-badge pulse";
      pwBadge.title = `${playwrightActive} Playwright job(s) active`;
      setTimeout(() => { if (pwBadge.classList.contains("pulse")) pwBadge.classList.remove("pulse"); }, 700);
    } else {
      pwBadge.style.display = "none";
    }
  }
  if (topPwBadge) {
    if (playwrightActive > 0) {
      topPwBadge.style.display = "inline-flex";
      topPwBadge.textContent = `${playwrightActive} Playwright`;
      topPwBadge.className = "topbar-pw-badge pulse";
      topPwBadge.onclick = () => openJobsQueue("playwright_recon");
      setTimeout(() => { if (topPwBadge.classList.contains("pulse")) topPwBadge.classList.remove("pulse"); }, 700);
    } else {
      topPwBadge.style.display = "none";
    }
  }
}

async function _updateJobCountBadge() {
  try {
    const r = await fetch("/api/jobs?limit=50", {headers: _authHeaders()});
    if (!r.ok) return;
    const jobs = await r.json();
    _updateJobCountBadgeFromList(jobs);
    _updateScanProgressPill(jobs);
  } catch(e) {}
}

// ── Global "scan in progress" pill — visible from any page so the user
// always knows a long-running pipeline is active before closing the app ──
let _scanProgressCid = null;
async function _updateScanProgressPill(jobs) {
  const el = document.getElementById("topbar-scan-progress");
  if (!el) return;
  const running = (jobs || []).find(j => j.job_type === "pipeline" && j.status === "running");
  if (!running) {
    el.style.display = "none";
    _scanProgressCid = null;
    return;
  }
  _scanProgressCid = running.company_id;
  const co = allCompanies().find(c => c.id === running.company_id);
  const coName = co ? co.name : running.company_id;
  try {
    const r = await fetch(`/api/recon/${encodeURIComponent(running.company_id)}/pipeline`, {headers: _authHeaders()});
    if (!r.ok) return;
    const d = await r.json();
    if (d.status !== "running" && d.status !== "queued") { el.style.display = "none"; return; }
    const total = Array.isArray(d.phases) ? d.phases.length : 0;
    const idx = (d.phase_idx || 0) + 1;
    const pct = total ? Math.min(100, Math.round((idx / total) * 100)) : 0;
    el.innerHTML = `
      <span class="pulse"></span>
      <span class="tsp-label">${esc(coName)} — Fase ${idx}${total ? "/" + total : ""}: ${esc(d.phase_label || "")}</span>
      <span class="tsp-bar"><span style="width:${pct}%"></span></span>`;
    el.style.display = "flex";
  } catch(e) {}
}
function _goToScanProgress() {
  if (_scanProgressCid) selectCompany(_scanProgressCid);
}

let extraCompanies = (typeof ASM !== 'undefined' && ASM.extraCompanies) ? ASM.extraCompanies
  : (function(){ try { return JSON.parse(localStorage.getItem('asm_extra_companies') || '[]'); } catch(e) { return []; } })();

function allCompanies() {
  if (typeof ASM !== 'undefined' && ASM.allCompanies) return ASM.allCompanies();
  return [...(DATA.companies || []), ...(extraCompanies || [])];
}
