// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  COMPATIBILITY LAYER â€” bridges old globals to ASM namespace
//  When js/asm.js is loaded before this file, ASM namespace is available.
//  When loaded standalone (legacy), fall back to local definitions.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
(function() {
  'use strict';
  // If ASM module loaded, set up aliases. Otherwise define locally.
  if (typeof window.ASM === 'undefined') {
    // Legacy mode â€” define essential values locally
    window.SERVER_MODE = window.location.protocol === 'http:' && window.location.hostname !== '';
    window._authHeaders = function() {
      var tok = null;
      try { tok = localStorage.getItem('asmToken'); } catch(e) {}
      return tok ? {'x-auth-token': tok} : {};
    };
  }
})();

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  DEMO DATA (Porto Seguro) â€” used when asm_data.js is not present
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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
        { id:1, severity:"critical", category:"Credentials", title:"admin:admin Hardcoded em JS de ProduÃ§Ã£o", host:"loja.portoseguro.com.br", url:"https://loja.portoseguro.com.br",
          desc:"A classe <code>QuoteService</code> no bundle Angular contÃ©m credenciais Basic Auth hardcoded: <code>BasicAuth YWRtaW46YWRtaW4=</code> (admin:admin). Enviado em requests ao endpoint <code>/stage/proponente-api/v1/</code>.",
          detail:`<pre>this.token = "BasicAuth YWRtaW46YWRtaW4=", this.className = "QuoteService"\n// Arquivo: /etc/clientlibs/porto-store/clientlibs/clientlib-angular.lc-*.js\n// Decodificado: admin:admin</pre><b>Endpoints afetados:</b><br>â€¢ https://47zimjues7.execute-api.us-west-2.amazonaws.com/stage/proponente-api/v1/<br>â€¢ https://bxn9o4w0pd.execute-api.ca-central-1.amazonaws.com/` },
        { id:2, severity:"critical", category:"CVE / Vuln", title:"Tableau Server 2023.1.7 â€” 6 CVEs Conhecidas", host:"tableau.portoseguro.com.br", url:"https://tableau.portoseguro.com.br",
          desc:"Tableau Server versÃ£o <code>2023.1.7</code> em produÃ§Ã£o com 6 CVEs confirmados. VersÃ£o corrigida: <code>2023.3.19</code>.",
          detail:`<b>CVEs:</b><br>â€¢ CVE-2023-44487 â€” HTTP/2 Rapid Reset (CVSS 7.5)<br>â€¢ CVE-2023-25953 â€” Stored XSS<br>â€¢ CVE-2023-25954 â€” Info Disclosure<br><b>IP direto:</b> 131.161.97.72 &nbsp; <b>Portas:</b> 80, 443, 8080, 8443, 9000` },
        { id:3, severity:"critical", category:"Cloud", title:"MISP Threat Intelligence Platform Exposto", host:"misp.portoseguro.com.br", url:"https://misp.portoseguro.com.br",
          desc:"Plataforma MISP acessÃ­vel via internet. ContÃ©m IOCs, indicadores de malware e inteligÃªncia de ameaÃ§as interna.",
          detail:`<b>Host:</b> misp.portoseguro.com.br â†’ 131.161.97.x<br><b>Impacto:</b> ExposiÃ§Ã£o de toda inteligÃªncia de ameaÃ§as interna e IOCs.<br><b>Fix:</b> Restringir via VPN/IP allowlist.` },
        { id:4, severity:"high", category:"IAM / Identity", title:"SailPoint IdentityNow Portal Exposto", host:"portaldeacessos.portoseguro.com.br", url:"https://portaldeacessos.portoseguro.com.br",
          desc:"Portal de Identity Governance (SailPoint) acessÃ­vel via internet. Gerencia acesso de todos colaboradores.",
          detail:`<b>Tenant:</b> portoseguro.login.sailpoint.com<br><b>API:</b> portoseguro.api.identitynow.com<br><b>Disclosure:</b> Formato de matrÃ­cula <code>f0123456</code> revelado na pÃ¡gina de login.` },
        { id:5, severity:"high", category:"CORS", title:"CORS Exploitable â€” Origin Refletido + Credentials", host:"abx.loja.portoseguro.com.br", url:"https://abx.loja.portoseguro.com.br",
          desc:"Servidor reflete qualquer cabeÃ§alho Origin com <code>Access-Control-Allow-Credentials: true</code>.",
          detail:`<b>Request:</b> Origin: https://evil.com<br><b>Response:</b><br><pre>Access-Control-Allow-Origin: https://evil.com\nAccess-Control-Allow-Credentials: true</pre>` },
        { id:6, severity:"high", category:"Info Disclosure", title:"Hostname Interno Vazado em Header CSP", host:"dev.saude.portoseguro.com.br", url:"https://dev.saude.portoseguro.com.br",
          desc:"Header <code>Content-Security-Policy</code> expÃµe hostname de servidor interno na diretiva <code>frame-src</code>.",
          detail:`<b>CSP frame-src:</b><br><pre>https://nt50388.portoseguro.brasil/</pre>Hostname Windows NT interno. TLD ".brasil" = domÃ­nio AD interno.` },
        { id:7, severity:"high", category:"IAM / Identity", title:"Formato de MatrÃ­cula de FuncionÃ¡rios Exposto", host:"portaldeacessos.portoseguro.com.br", url:"https://portaldeacessos.portoseguro.com.br",
          desc:"PÃ¡gina de login SailPoint revela o formato das matrÃ­culas: <code>f0123456</code> (f + 7 dÃ­gitos).",
          detail:`<b>Texto:</b> "Lembrando de substituir f0123456 pela sua matricula"<br><b>Formato:</b> <code>f[0-9]{7}</code><br><b>Risco:</b> Permite gerar listas para password spray.` },
        { id:8, severity:"high", category:"Credentials", title:"AWS API Gateway URLs Hardcoded em JS", host:"loja.portoseguro.com.br", url:"https://loja.portoseguro.com.br",
          desc:"Dois AWS API Gateway endpoints hardcoded no bundle JS, usados com credenciais admin:admin.",
          detail:`<b>GW1:</b> <code>bxn9o4w0pd.execute-api.ca-central-1.amazonaws.com</code><br><b>GW2:</b> <code>47zimjues7.execute-api.us-west-2.amazonaws.com</code><br><b>Auth:</b> BasicAuth admin:admin` },
        { id:9, severity:"high", category:"CVE / Vuln", title:"OAuth Token Endpoint Potencialmente Spray-Ã¡vel", host:"login.windows.net", url:"https://login.windows.net",
          desc:"Endpoint OAuth2 Azure AD identificado como potencialmente vulnerÃ¡vel a password spraying.",
          detail:`<b>Endpoint:</b> https://login.windows.net/ed7958eb-216a-4854-a42e-3c7127272021/oauth2/token<br><b>Tenant:</b> ed7958eb-216a-4854-a42e-3c7127272021` },
        { id:10, severity:"medium", category:"Dev/Stage", title:"APIs de SaÃºde DEV/HML AcessÃ­veis (CORS Wildcard)", host:"dev.api.saude.portoseguro.com.br", url:"", desc:"APIs do Portal do Prestador em DEV/HML com CORS <code>Access-Control-Allow-Origin: *</code>.", detail:"<b>DEV:</b> https://dev.api.saude.portoseguro.com.br/prestador/v1/<br><b>HML:</b> https://hml.api.saude.portoseguro.com.br/prestador/v1/" },
        { id:11, severity:"medium", category:"Dev/Stage", title:"Ambientes Stage/Dev de AutenticaÃ§Ã£o Expostos", host:"loja-stage-auth.portoseguro.com.br", url:"", desc:"Cognito User Pools HML e DEV do Adobe Experience Manager acessÃ­veis via internet.", detail:"<b>Stage:</b> loja-stage-auth â†’ aem-hml.auth.ca-central-1.amazoncognito.com<br><b>Dev:</b> loja-dev-auth â†’ AWS Cognito DEV" },
        { id:12, severity:"medium", category:"Dev/Stage", title:"Portal do Prestador (SaÃºde) DEV/HML Exposto", host:"dev.saude.portoseguro.com.br", url:"", desc:"Portal de saÃºde DEV/HML acessÃ­vel via internet (S3+CloudFront). Dados LGPD.", detail:"<b>HML:</b> hml.saude.portoseguro.com.br<br><b>DEV:</b> dev.saude.portoseguro.com.br" },
        { id:13, severity:"medium", category:"Cloud", title:"Orquestrador de Pagamentos Exposto", host:"portal.meiosdepagamento.portoseguro.com.br", url:"", desc:"Sistema de orquestraÃ§Ã£o de pagamentos acessÃ­vel via internet (S3+CloudFront+Azure AD).", detail:"<b>Azure App:</b> f7803731-7830-4239-a811-fee25df9883a<br><b>Tenant:</b> ed7958eb-216a-4854-a42e-3c7127272021" },
        { id:14, severity:"medium", category:"Cloud", title:"PortoStore Backoffice Exposto", host:"psstore.portoseguro.com.br", url:"", desc:"Backoffice da Porto Store (Angular + S3+CloudFront) acessÃ­vel externamente.", detail:"<b>URL:</b> https://psstore.portoseguro.com.br" },
        { id:15, severity:"medium", category:"Dev/Stage", title:"APIs Stage/Dev da Loja AcessÃ­veis", host:"loja-stage-api.portoseguro.com.br", url:"", desc:"Endpoints de API stage/dev da loja online acessÃ­veis externamente via AWS CloudFront.", detail:"<b>Stage:</b> loja-stage-api.portoseguro.com.br<br><b>Dev:</b> loja-dev-api.portoseguro.com.br" },
        { id:16, severity:"medium", category:"IAM / Identity", title:"Cognito User Pools AEM Identificados", host:"loja-auth.portoseguro.com.br", url:"", desc:"User Pools AWS Cognito para autenticaÃ§Ã£o AEM em PRD/HML/DEV identificados.", detail:"<b>PRD:</b> aem-prd.auth.ca-central-1.amazoncognito.com<br><b>HML:</b> aem-hml.auth.ca-central-1.amazoncognito.com" },
        { id:17, severity:"medium", category:"DNS", title:"Subdomain CNAME para DomÃ­nio NÃ£o Controlado", host:"campanhas.portoseguro.com.br", url:"", desc:"CNAME para <code>campanhasportoseguro.com.br</code> hospedado em DNS parking (Hostinger).", detail:"<b>NS:</b> ns1.dns-parking.com / ns2.dns-parking.com<br><b>IPs:</b> 77.37.42.244, 147.79.105.154" },
        { id:18, severity:"medium", category:"Info Disclosure", title:"Azure AD Client IDs Expostos em JS", host:"portal.meiosdepagamento.portoseguro.com.br", url:"", desc:"IDs de aplicaÃ§Ãµes Azure AD expostos nos bundles JS pÃºblicos.", detail:"<b>Pagamentos:</b> f7803731-7830-4239-a811-fee25df9883a<br><b>SailPoint:</b> e488b780-0d92-4e92-8ea4-8b24849c0800" },
        { id:19, severity:"medium", category:"Cloud", title:"MuleSoft Anypoint Flex Gateway Identificado", host:"api.bap-hml.portoseguro.com.br", url:"", desc:"API Gateway MuleSoft em ambiente HML identificado e acessÃ­vel.", detail:"<b>HML:</b> api.bap-hml.portoseguro.com.br<br><b>mTLS:</b> api.bap-mtls-hml.portoseguro.com.br" },
        { id:20, severity:"medium", category:"Info Disclosure", title:"Topologia de Rede Interna via DNS", host:"nac11dc00-tlf.portoseguro.com.br", url:"", desc:"DNS pÃºblico com IPs privados (172.x.x.x) revelando topologia interna.", detail:"<b>NAC:</b> nac11dc00-tlf â†’ 172.28.1.172<br><b>ALM:</b> portoalm â†’ 172.27.73.27<br><b>VLANs:</b> visitantes1-4 â†’ 172.26-27.x" },
        { id:21, severity:"info", category:"Cloud", title:"Axway Amplify API Marketplace Identificado", host:"developers.portoseguro.com.br", url:"", desc:"Marketplace de APIs Axway com 3 domÃ­nios para parceiros.", detail:"developers.portoseguro.com.br<br>porto-developers.portoseguro.com.br<br>seguros-developers.portoseguro.com.br" },
        { id:22, severity:"info", category:"Cloud", title:"PortoBank Cross-Domain API Gateways", host:"api-gw.portobank-crossdomain.prd.portoseguro.com.br", url:"", desc:"API Gateways cross-domain do PortoBank (PRD/HML) com variantes mTLS.", detail:"" },
        { id:23, severity:"info", category:"Cloud", title:"Session Border Controller (SBC) Identificado", host:"sbc.portoseguro.com.br", url:"wss://sbc.portoseguro.com.br", desc:"SBC VoIP/WebRTC identificado via URI wss://. AtrÃ¡s de firewall.", detail:"<b>CNAME:</b> sbc.lb.portoseguro.com.br â†’ 131.161.97.102" },
        { id:24, severity:"info", category:"Cloud", title:"Tenant Sydle (BPM) Identificado", host:"portoseguro.sydle.one", url:"https://portoseguro.sydle.one", desc:"Tenant Sydle BPM/automaÃ§Ã£o hospedado no Cloudflare (403 requer auth).", detail:"" },
        { id:25, severity:"info", category:"DNS", title:"DNSSEC NSEC Zone Walking em Afiliados", host:"mtl.mailcloud.com.br", url:"", desc:"Zone walking DNSSEC habilitado em domÃ­nios de parceiros.", detail:"â€¢ mtl.mailcloud.com.br<br>â€¢ app.securiti.ai" },
        { id:26, severity:"info", category:"CVE / Vuln", title:"Shodan CVEs em Servidores de E-mail Afiliados", host:"mtl.mailcloud.com.br", url:"", desc:"CVEs em servidores de email/infra de terceiros usados pelo Porto Seguro.", detail:"<b>mtl.mailcloud.com.br:</b> CVE-2025-23419, CVE-2022-41742, CVE-2023-44487" },
        { id:27, severity:"info", category:"Info Disclosure", title:"Varnish Cache Plus na Loja", host:"loja.portoseguro.com.br", url:"", desc:"Loja usa Varnish Cache Plus (versÃ£o enterprise).", detail:"" },
        { id:28, severity:"info", category:"Cloud", title:"Dois Gateways Citrix NetScaler Identificados", host:"ho.portoseguro.com.br", url:"", desc:"Dois Citrix NetScaler ADC para acesso remoto/VDI de funcionÃ¡rios.", detail:"<b>GW1:</b> ho.portoseguro.com.br<br><b>GW2:</b> ho.ctx.portoseguro.com.br" },
        { id:29, severity:"info", category:"Cloud", title:"Banking Sandbox APIs Expostas", host:"apibank-sandbox.portoseguro.com.br", url:"", desc:"Endpoints sandbox do PortoBank disponÃ­veis externamente.", detail:"apibank-sandbox.portoseguro.com.br â†’ 54.94.225.105" },
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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  GLOBAL COMPAT â€” maps dashboard globals to the ASM namespace
//  (Defined in js/asm.js â€” available when loaded via dashboard.html)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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

// â”€â”€ API error helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function _apiErr(r) {
  if (r.status === 401) {
    // Only redirect to login if we have no token at all (not just a server-side expiry)
    const hasToken = !!(authToken || (function(){ try { return localStorage.getItem('asmToken'); } catch(_){ return null; } })());
    if (!hasToken && typeof showLoginScreen === 'function') showLoginScreen();
    return new Error('Session expired â€” please sign in again');
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

// State object â€” use ASM when available, fallback to local
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
if (!state.hostPanel) state.hostPanel = "domains";

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
  const target = esc(job.target || opts.target_url || "â€”");
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
  mount.innerHTML = `<span style="color:var(--text3)">Loading host inventoryâ€¦</span>`;
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
  const labels = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
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
  const screenshot = h.screenshot
    ? `<img src="${esc('/' + h.screenshot)}" style="width:48px;height:30px;object-fit:cover;border-radius:4px;border:1px solid var(--border);cursor:pointer" onerror="this.style.display='none'" onmouseenter="ssPopoverShow(event,${JSON.stringify('/' + h.screenshot).replace(/"/g,'&quot;')},${JSON.stringify(h.host || '').replace(/"/g,'&quot;')})" onmouseleave="ssPopoverHide()">`
    : `<span style="color:var(--text3);font-size:.6rem">â€”</span>`;
  return `
    <tr>
      <td><a class="host-a" href="https://${esc(h.host)}" target="_blank">${esc(h.host)}</a></td>
      <td><span class="ip-t">${esc(h.ip)}</span></td>
      <td><span style="font-size:.7rem;color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block" title="${esc(title)}">${esc(title) || 'â€”'}</span></td>
      <td><span class="waf-t ${wafClass(h.waf)}">${esc(h.waf)}</span></td>
      <td>${techs || `<span style="color:var(--text3);font-size:.65rem">â€”</span>`}</td>
      <td>${ports || `<span style="color:var(--text3);font-size:.65rem">â€”</span>`}</td>
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

function _portSummaryCard(label, value, accent = "") {
  return `
    <div class="job-kpi ${accent}">
      <div class="job-kpi-num">${Number(value || 0)}</div>
      <div class="job-kpi-label">${esc(label)}</div>
    </div>`;
}

function _filteredHighRiskPorts(rows) {
  const seen = new Set();
  return (rows || []).filter(row => {
    const port = String(row.port || "").trim();
    if (!_isHighRiskPort(port, row.service || "")) return false;
    const key = `${row.ip || ""}:${port}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).map(row => ({
    ...row,
    service: _portServiceLabel(row.port, row.service || ""),
  }));
}

function _portRiskRow(h) {
  return `
    <div style="display:flex;gap:12px;align-items:center;padding:6px 10px;border-bottom:1px solid rgba(244,63,94,0.12)">
      <span style="font-family:var(--mono);font-size:.71rem;color:var(--text2);min-width:120px">${esc(h.ip||'')}</span>
      <span style="font-family:var(--mono);font-size:.71rem;font-weight:700;color:#f43f5e;min-width:45px">:${h.port}</span>
      <span style="font-size:.68rem;color:var(--text3)">${esc(h.service||'')}</span>
      <span class="sev ${h.severity==='critical'?'sev-c':'sev-h'}" style="margin-left:auto;font-size:.59rem">${(h.severity||'high').toUpperCase()}</span>
    </div>`;
}

function _toolsStat(value, label, color = "var(--text)") {
  return `<div class="tools-stat"><span class="tools-stat-num" style="color:${color}">${esc(value)}</span><div class="tools-stat-lbl">${esc(label)}</div></div>`;
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

// â”€â”€ Always-polling job count badge for the sidebar nav â”€â”€
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

// â”€â”€ Global "scan in progress" pill â€” visible from any page so the user
// always knows a long-running pipeline is active before closing the app â”€â”€
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
      <span class="tsp-label">${esc(coName)} â€” Fase ${idx}${total ? "/" + total : ""}: ${esc(d.phase_label || "")}</span>
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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  NAVIGATION
//  NAVIGATION
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function showAll() { showPage("companies"); }

function _syncSidebarActive() {
  document.querySelectorAll(".sidebar-nav .nav-item").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".nav-co").forEach(el => el.classList.remove("active"));
  const page = state.page || (state.currentId ? "company" : "companies");
  const pageNav = {
    companies: "nav-all",
    jobs: "nav-jobs",
    tools: "nav-tools",
    bbhelper:    "nav-bbhelper",
    exttools:    "nav-exttools",
    bbprograms:  "nav-bbprograms",
    generators:  "nav-generators",
    admins:      "nav-admins",
    runtime:     "nav-runtime",
  };
  if (page === "company" && state.currentId) {
    document.querySelectorAll(".nav-co").forEach(el => {
      if (String(el.dataset.id || "") === String(state.currentId)) el.classList.add("active");
    });
    return;
  }
  const id = pageNav[page];
  if (id) document.getElementById(id)?.classList.add("active");
}

function _showCompaniesView() {
  state.page = "companies";
  state.currentId = null;
  stopLiveDataPolling();
  stopCompanyPipelineSync();
  closeMobileNav();
  document.body.classList.add("executive-home");
  document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));
  document.getElementById("view-all").classList.add("active");
  _syncSidebarActive();
  document.getElementById("crumb-sep").style.display = "none";
  document.getElementById("crumb-current").textContent = "";
  document.getElementById("topbar-pill").innerHTML = "";
  renderAllCompanies();
}

let _companyPipelineSyncInterval = null;

function stopCompanyPipelineSync() {
  if (_companyPipelineSyncInterval) {
    clearInterval(_companyPipelineSyncInterval);
    _companyPipelineSyncInterval = null;
  }
}

async function refreshCompanyPipelineState(companyId, { render = true } = {}) {
  if (!companyId || !SERVER_MODE) return null;
  try {
    const r = await fetch(`/api/recon/${companyId}/pipeline`, {headers: _authHeaders()});
    if (!r.ok) return null;
    const ps = await r.json();
    pipelineState[companyId] = ps;

    if (!reconState[companyId]) reconState[companyId] = {};
    (ps.phases || []).forEach(ph => (ph.modules || []).forEach(m => {
      if (m.status !== "not_run") reconState[companyId][m.module] = {status: m.status};
    }));

    if (render) {
      // renderPipelineStatus updates the live phase HUD in place. We must NOT
      // rebuild the whole recon tab here: renderReconTab() re-fetches the
      // Playwright session artifact on every poll, which spammed the server
      // with one artifact/session request every 4s (403 loop on done jobs).
      renderPipelineStatus(companyId);
      const co = allCompanies().find(c => c.id === companyId);
      if (co && state.currentId === companyId) {
        renderOverview(co);
        renderAllCompanies();
      }
    }
    return ps;
  } catch (e) {
    return null;
  }
}

function startCompanyPipelineSync(companyId) {
  stopCompanyPipelineSync();
  if (!companyId || !SERVER_MODE) return;
  refreshCompanyPipelineState(companyId, {render: true});
  _companyPipelineSyncInterval = setInterval(() => {
    refreshCompanyPipelineState(companyId, {render: true});
  }, 4000);
}

function _buildReportHTML(co) {
  const findings = co.findings || [];
  const hosts = co.hosts || [];
  const now = new Date().toLocaleString('pt-BR');

  const sevCounts = {
    critical: findings.filter(f=>f.severity==='critical').length,
    high:     findings.filter(f=>f.severity==='high').length,
    medium:   findings.filter(f=>f.severity==='medium').length,
    low:      findings.filter(f=>f.severity==='low').length,
    info:     findings.filter(f=>f.severity==='info').length,
  };

  const findingsHTML = ['critical','high','medium','low','info'].flatMap(sev =>
    findings.filter(f=>f.severity===sev).map(f => `
      <tr>
        <td><span style="background:${sev==='critical'?'#ef4444':sev==='high'?'#f97316':sev==='medium'?'#eab308':sev==='low'?'#3b82f6':'#6b7280'};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700">${sev.toUpperCase()}</span></td>
        <td style="font-weight:600">${esc(f.title||'')}</td>
        <td>${esc(f.host||'')}</td>
        <td>${esc(f.category||f.type||'')}</td>
        <td style="font-size:11px;max-width:300px;word-break:break-word">${esc(f.desc||'')}</td>
      </tr>`)
  ).join('');

  const hostsHTML = hosts.slice(0,200).map(h => `
    <tr>
      <td style="font-family:monospace">${esc(h.host||'')}</td>
      <td>${esc(h.ip||'')}</td>
      <td>${esc(h.status_code||'')}</td>
      <td>${esc(h.title||'')}</td>
      <td>${esc(h.waf||'Direct')}</td>
      <td style="font-size:11px">${esc((h.techs||[]).slice(0,5).join(', '))}</td>
    </tr>`).join('');

  const attackChains = findings.filter(f=>f.type==='attack_chain');
  const attackHTML = attackChains.map(f=>`<li><strong>${esc(f.title||'')}</strong> â€” ${esc(f.desc||'')}</li>`).join('') || '<li>No attack chains identified</li>';

  const html = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>ASM Report â€” ${co.name||co.id} â€” ${now}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 0; background: #fff; color: #1a1a2e; }
  .cover { background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 100%); color: #fff; padding: 60px 80px; min-height: 200px; }
  .cover h1 { font-size: 2.4rem; margin: 0 0 8px; font-weight: 800; }
  .cover .sub { font-size: 1rem; color: rgba(255,255,255,0.6); margin: 0; }
  .cover .meta { margin-top: 40px; font-size: 0.85rem; color: rgba(255,255,255,0.5); }
  .section { padding: 40px 80px; border-bottom: 1px solid #e5e7eb; }
  h2 { font-size: 1.4rem; color: #0f172a; margin: 0 0 20px; padding-bottom: 8px; border-bottom: 2px solid #6366f1; display: inline-block; }
  .stat-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 24px; }
  .stat-card { border-radius: 8px; padding: 20px; text-align: center; }
  .stat-num { font-size: 2.2rem; font-weight: 800; }
  .stat-lbl { font-size: 0.75rem; text-transform: uppercase; letter-spacing: .05em; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 16px; }
  th { background: #f8fafc; text-align: left; padding: 10px 12px; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: #64748b; border-bottom: 2px solid #e2e8f0; }
  td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
  tr:hover td { background: #f8fafc; }
  .chain-list { list-style: none; padding: 0; }
  .chain-list li { padding: 12px 16px; margin: 8px 0; background: #fff7ed; border-left: 4px solid #f97316; border-radius: 4px; font-size: 13px; }
  .footer { padding: 20px 80px; font-size: 12px; color: #94a3b8; text-align: center; border-top: 1px solid #e5e7eb; }
  @media print { .section { break-inside: avoid; } }
</style>
</head>
<body>
<div class="cover">
  <h1>Attack Surface Management Report</h1>
  <p class="sub">Target: ${co.name||co.id||''} &nbsp;|&nbsp; Scope: ${(co.domains||[]).length > 10 ? (co.domains.slice(0,10).join(', ') + ', +' + (co.domains.length - 10) + ' more') : (co.domains||[]).join(', ')}</p>
  <div class="meta">Generated: ${now} &nbsp;|&nbsp; Classification: CONFIDENTIAL â€” AUTHORIZED PENTEST</div>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <div class="stat-grid">
    <div class="stat-card" style="background:#fef2f2"><div class="stat-num" style="color:#ef4444">${sevCounts.critical}</div><div class="stat-lbl" style="color:#ef4444">Critical</div></div>
    <div class="stat-card" style="background:#fff7ed"><div class="stat-num" style="color:#f97316">${sevCounts.high}</div><div class="stat-lbl" style="color:#f97316">High</div></div>
    <div class="stat-card" style="background:#fefce8"><div class="stat-num" style="color:#ca8a04">${sevCounts.medium}</div><div class="stat-lbl" style="color:#ca8a04">Medium</div></div>
    <div class="stat-card" style="background:#eff6ff"><div class="stat-num" style="color:#3b82f6">${sevCounts.low}</div><div class="stat-lbl" style="color:#3b82f6">Low</div></div>
    <div class="stat-card" style="background:#f0fdf4"><div class="stat-num" style="color:#16a34a">${hosts.length}</div><div class="stat-lbl" style="color:#16a34a">Live Hosts</div></div>
  </div>
  <p style="color:#475569;line-height:1.7">
    This report covers the external attack surface of <strong>${co.name||co.id}</strong>.
    The assessment identified <strong>${findings.length} security findings</strong> across
    <strong>${hosts.length} live hosts</strong> and <strong>${(co.ct_subdomains||[]).length} discovered hosts</strong>.
    ${sevCounts.critical > 0 ? `<strong style="color:#ef4444">${sevCounts.critical} critical findings require immediate attention.</strong>` : ''}
  </p>
</div>

<div class="section">
  <h2>Attack Chains</h2>
  <ul class="chain-list">${attackHTML}</ul>
</div>

<div class="section">
  <h2>Findings (${findings.length})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Host</th><th>Category</th><th>Description</th></tr></thead>
    <tbody>${findingsHTML}</tbody>
  </table>
</div>

<div class="section">
  <h2>Live Hosts (${hosts.length})</h2>
  <table>
    <thead><tr><th>Hostname</th><th>IP</th><th>Status</th><th>Title</th><th>WAF</th><th>Technologies</th></tr></thead>
    <tbody>${hostsHTML}</tbody>
  </table>
</div>

<div class="footer">
  ASM Platform â€” Authorized Security Assessment â€” ${now} â€” CONFIDENTIAL
</div>
</body>
</html>`;

  return html;
}

function exportHTMLReport(co) {
  if (!co) return;
  const html = _buildReportHTML(co);
  const blob = new Blob([html], {type: 'text/html'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `asm-report-${(co.id||'target').replace(/[^a-z0-9]/gi,'-')}-${new Date().toISOString().slice(0,10)}.html`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function exportPDFReport(co) {
  if (!co) return;
  const html = _buildReportHTML(co);
  const win = window.open('', '_blank');
  if (!win) { alert('Pop-up bloqueado. Permita pop-ups para exportar em PDF.'); return; }
  win.document.open();
  win.document.write(html);
  win.document.close();
  win.onload = () => { win.focus(); win.print(); };
  // Fallback in case onload doesn't fire (already-loaded blank doc)
  setTimeout(() => { try { win.focus(); win.print(); } catch(e) {} }, 600);
}

function renderCompanyView(co) {
  const s = co.stats||{};
  const _doms = co.domains || [];
  const _MAXD = 6;
  const _domSummary = _doms.length
    ? _doms.slice(0, _MAXD).join("  Â·  ") + (_doms.length > _MAXD ? `  Â·  +${_doms.length - _MAXD} more` : "")
    : "No domains";
  document.getElementById("co-desc").textContent = _domSummary + "  Â·  Last scan: " + (co.last_scan||"N/A");
  document.getElementById("tc-findings").textContent =
    (s.findings_critical||0)+(s.findings_high||0)+(s.findings_medium||0)+(s.findings_info||0);
  document.getElementById("tc-cve").textContent = co.cve_summary?.total || 0;
  document.getElementById("tc-supplychain").textContent = co.supply_chain_summary?.total || 0;
  document.getElementById("tc-domains").textContent = (co.domains||[]).length || 0;
  document.getElementById("tc-subdomains").textContent = s.subdomains||0;
  document.getElementById("tc-ports").textContent = s.open_ports || (co.hosts||[]).filter(h=>(h.ports||[]).length>0).length || 0;
  const tcOperation = document.getElementById("tc-operation");
  if (tcOperation) tcOperation.textContent = "";
  document.getElementById("tc-screenshots").textContent = "";
  // Async: load counts without blocking render
  if (SERVER_MODE) {
    fetch(`/api/screenshots/${co.id}`, {headers:_authHeaders()}).then(r=>r.ok?r.json():[]).then(d=>{
      const el = document.getElementById("tc-screenshots");
      if(el && d.length) el.textContent = d.length;
      _applyScreenshotInventory(co, d);
    }).catch(()=>{});
    fetch(`/api/data/${co.id}/subhistory`, {headers: _authHeaders()}).then(r=>r.json()).then(d=>{
      const el = document.getElementById("tc-subhistory");
      if(el && d.history) el.textContent = d.history.length;
    }).catch(()=>{});
  }

  // Count all endpoints (URLs + JS + API)
  let endpointsTotal = 0;
  if (co.wayback_data?.interesting_count) endpointsTotal += co.wayback_data.interesting_count;
  if (co.urlfinder_data?.urls) endpointsTotal += co.urlfinder_data.urls.length;
  if (co.js_data?.total_endpoints) endpointsTotal += co.js_data.total_endpoints;
  if (co.api_exposure?.total) endpointsTotal += co.api_exposure.total;
  document.getElementById("tc-endpoints").textContent = endpointsTotal;

  renderOverview(co);
  try { setTimeout(initThreatMaps, 50); setTimeout(initThreatMaps, 400); } catch(e) {}
  try { setTimeout(updateTabScrollBtns, 100); } catch(e) {}
  renderFindingsTab(co);
  renderCveTab(co);
  invalidateEndpointCache(co);
  renderEndpointsTab(co);
  renderDomainsTab(co);
  renderSubdomainsTab(co);
  renderInfraTab(co);
  renderTyposquatTab(co);
  syncCompanyTabsAccessibility(TAB_TO_GROUP[state.tab] || state.tab || "overview");
  updateGroupCounts();
  initGroupCountObserver();
}

function _applyScreenshotInventory(co, shots) {
  if (!co || !Array.isArray(shots) || !shots.length) return;
  const map = new Map();
  shots.forEach(item => {
    const url = String(item.url || "").trim();
    let host = "";
    try { host = new URL(url).hostname || ""; } catch(e) {}
    if (!host && item.filename) host = _screenshotFilenameHost(item.filename);
    host = _normalizeScopeDomain(host);
    if (!host || map.has(host)) return;
    map.set(host, `screenshots/${co.id}/${item.filename}`);
  });
  if (!map.size) return;
  co._screenshotsByHost = map;
  (co.hosts || []).forEach(h => {
    const host = _normalizeScopeDomain(h.host || "");
    if (host && !h.screenshot && map.has(host)) h.screenshot = map.get(host);
  });
  if (state.currentId === co.id && (state.tab === "subdomains" || state.activeGroup === "hosts")) {
    renderSubdomainsTab(co);
  }
}

function _screenshotFilenameHost(filename) {
  let name = String(filename || "").replace(/\.(png|jpe?g|webp)$/i, "");
  if (name.startsWith("browser_")) {
    name = name.slice(8).replace("___", "://");
    name = name.includes("://") ? name.split("://", 2)[1] : name;
    return name.replace(/_/g, ".");
  }
  name = name.replace(/^(https?|http)---/i, "");
  name = name.replace(/-\d+$/i, "");
  return name;
}

async function selectCompany(id) {
  state.page = "company";
  state.currentId = id;
  state.tab = "overview";
  state.hostsPage = 1;
  state.portsPage = 1;
  closeMobileNav();
  document.body.classList.remove("executive-home");

  document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));
  if (_jobsPoll) { clearInterval(_jobsPoll); _jobsPoll = null; }
  document.getElementById("view-company").classList.add("active");
  _syncSidebarActive();

  let co = allCompanies().find(c=>c.id===id);
  if (!co) return;

  const rl = riskLevel(co);
  document.getElementById("crumb-sep").style.display = "";
  document.getElementById("crumb-current").textContent = co.name;
  document.getElementById("co-title").textContent = co.name;

  const pillColors = {critical:"red", high:"orange", medium:"orange", low:"green"};
  document.getElementById("topbar-pill").innerHTML = `
    <div class="topbar-pill ${pillColors[rl]||'green'}">
      <span class="pulse"></span>${riskLabel(rl)}
    </div>`;

  // Show scan + monitor buttons in server mode
  var scanBtn = document.getElementById("topbar-scan-btn");
  scanBtn.style.display = SERVER_MODE ? "" : "none";
  var monBtn = document.getElementById("monitor-now-btn");
  if (monBtn) monBtn.style.display = SERVER_MODE ? "" : "none";
  var schBtn = document.getElementById("enable-schedule-btn");
  if (schBtn) schBtn.style.display = SERVER_MODE ? "" : "none";
  if (schBtn && SERVER_MODE) loadScheduleStatus(id);

  // Reset active tab button
  document.querySelectorAll(".tab-btn").forEach((b,i)=>b.classList.toggle("active",i===0));
  document.querySelectorAll(".tab-content").forEach((t,i)=>t.classList.toggle("active",i===0));
  syncCompanyTabsAccessibility("overview");

  if (SERVER_MODE && co.summary_only) {
    renderCompanyLoading(id);
    try {
      co = await ensureCompanyLoaded(id);
    } catch (e) {
      document.getElementById("co-desc").textContent = `Error loading company details: ${e.message}`;
      return;
    }
  }
  renderCompanyView(co);
  if (SERVER_MODE) startCompanyPipelineSync(id);
  if (SERVER_MODE) { loadTrendCharts(id); loadSuppressedFindings(id); }
  // Always poll for live data while viewing a company
  startLiveDataPolling(id);
  // Update URL hash for browser history
  if (typeof ASM !== 'undefined' && ASM.updateHash) ASM.updateHash('company/' + id + '/overview');
}

const TAB_GROUPS = {
  overview:    ['overview'],
  hosts:       ['domains', 'subdomains'],
  screenshots: ['screenshots'],
  operation:   ['operation'],
  infragroup:  ['infra'],
  vulns:       ['vulns'],
  logs:        ['toollogs'],
  pipeline:    ['pipeline', 'terminal']
};
const TAB_TO_GROUP = {};
(function() { for (const [g, tabs] of Object.entries(TAB_GROUPS)) tabs.forEach(t => TAB_TO_GROUP[t] = g); })();

async function switchGroup(groupName, btn) {
  const tabs = groupName === "hosts"
    ? [state.hostPanel || "domains"]
    : (TAB_GROUPS[groupName] || [groupName]);
  state.tab = tabs[0];
  state.activeGroup = groupName;

  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  if (btn) btn.classList.add('active');
  tabs.forEach(t => { const el = document.getElementById('tab-' + t); if (el) el.classList.add('active'); });

  syncCompanyTabsAccessibility(groupName);

  const co = allCompanies().find(c => c.id === state.currentId);
  for (const name of tabs) {
    if (name === 'domains'      && co)              renderDomainsTab(co);
    if (name === 'subdomains'   && co)              renderSubdomainsTab(co);
    if (name === 'endpoints'    && co)              renderEndpointsTab(co);
    if (name === 'pipeline'     && state.currentId) await renderReconTab(state.currentId);
    if (name === 'supplychain'  && co)              renderSupplyChainTab(co);
    if (name === 'jsreverse'    && co)              renderJsReverseTab(co);
    if (name === 'vulns'        && co)              renderVulnsTab(co);
    if (name === 'operation'    && co)              renderOperationTab(co);
    if (name === 'infra'        && co)              renderInfraTab(co);
    if (name === 'screenshots'  && state.currentId) loadScreenshots(state.currentId, co);
    if (name === 'toollogs'     && state.currentId) {
      await loadToolLogs();
    }
    if (name === 'terminal'     && state.currentId) renderLiveTerminal(state.currentId);
    if (name === 'alerts'       && co)              renderAlertsTab(co);
    if (name === 'timeline'     && co)              renderTimelineTab(co);
    if (name === 'diff'         && co)              renderDiffTab(co);
  }

  if (typeof ASM !== 'undefined' && ASM.updateHash && state.currentId) {
    ASM.updateHash('company/' + state.currentId + '/' + tabs[0]);
  }
  if (btn) btn.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  updateTabScrollBtns();
}

async function switchTab(name, btn) {
  if (name === "domains" || name === "subdomains") {
    state.hostPanel = name;
    const groupBtn = document.querySelector('.tab-btn[data-group="hosts"]') || btn;
    return switchGroup("hosts", groupBtn);
  }
  const groupName = TAB_TO_GROUP[name] || name;
  const groupBtn = document.querySelector(`.tab-btn[data-group="${groupName}"]`) || btn;
  return switchGroup(groupName, groupBtn);
}

// Jump straight from any critical/high/medium/info severity indicator to the
// filtered Vulnerabilities tab for the given company.
let _pendingVulnFilter = null; // {cid, sev} applied by renderVulnsTab after fetch completes

async function goToVulnSeverity(cid, severity, ev) {
  if (ev) ev.stopPropagation();
  const mappedSev = (severity === "info") ? "" : severity;
  _pendingVulnFilter = { cid, sev: mappedSev };
  if (state.currentId !== cid || state.page !== "company") {
    await selectCompany(cid);
  }
  const groupBtn = document.querySelector('.tab-btn[data-group="vulns"]');
  await switchGroup("vulns", groupBtn);
  // Fast path: if page already rendered, f-sev exists now
  setTimeout(() => {
    const sevSel = document.getElementById("f-sev");
    if (sevSel && _pendingVulnFilter && _pendingVulnFilter.cid === cid) {
      sevSel.value = mappedSev;
      _pendingVulnFilter = null;
      applyFindFilter(cid);
    }
    const list = document.getElementById("f-list") || document.getElementById("tab-vulns");
    if (list) list.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 60);
}

function switchHostsPanel(panel) {
  if (panel !== "domains" && panel !== "subdomains") return;
  state.hostPanel = panel;
  const groupBtn = document.querySelector('.tab-btn[data-group="hosts"]');
  switchGroup("hosts", groupBtn);
}

function scrollTabBar(dir) {
  const tb = document.getElementById('co-tabs');
  if (!tb) return;
  tb.scrollBy({ left: dir * 220, behavior: 'smooth' });
  setTimeout(updateTabScrollBtns, 280);
}

function updateTabScrollBtns() {
  const tb = document.getElementById('co-tabs');
  const lBtn = document.getElementById('tab-scroll-left');
  const rBtn = document.getElementById('tab-scroll-right');
  if (!tb || !lBtn || !rBtn) return;
  const atStart = tb.scrollLeft <= 2;
  const atEnd   = tb.scrollLeft >= tb.scrollWidth - tb.clientWidth - 2;
  lBtn.style.display = atStart ? 'none' : 'flex';
  rBtn.style.display = atEnd   ? 'none' : 'flex';
}

const _GC_DEFS = {
  hosts:      ['domains', 'subdomains'],
  screenshots:['screenshots'],
  operation:  ['operation'],
  logs:       ['toollogs'],
};

function updateGroupCounts() {
  for (const [group, ids] of Object.entries(_GC_DEFS)) {
    const total = ids.reduce((s, id) => {
      const el = document.getElementById('tc-' + id);
      return s + (el ? parseInt(el.textContent) || 0 : 0);
    }, 0);
    const el = document.getElementById('gc-' + group);
    if (el) el.textContent = total > 0 ? total : '';
  }
}

function initGroupCountObserver() {
  const hidden = document.getElementById('tc-hidden');
  if (!hidden || hidden._gcObserved) return;
  hidden._gcObserved = true;
  new MutationObserver(updateGroupCounts).observe(hidden, { subtree: true, characterData: true, childList: true });
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  SIDEBAR
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function renderSidebar() {
  const el = document.getElementById("company-nav-items");
  const companyViewActive = state.page === "company";
  el.innerHTML = allCompanies().map(co => {
    const rl = riskLevel(co);
    const s = co.stats||{};
    const domain = (co.domains||[])[0]||"";
    const sideEditBtn = SERVER_MODE
      ? `<span class="nc-edit" onclick="event.stopPropagation();openEditCompanyModal('${co.id}')" title="Edit">âœ</span>`
      : "";
    return `<button class="nav-item nav-company nav-co${companyViewActive && state.currentId === co.id ? " active" : ""}" data-id="${co.id}" onclick="selectCompany('${co.id}')">
      <div class="nc-top">
        <span class="nav-icon">â—Ž</span>
        <span class="nc-name">${esc(co.name)}</span>
        <span class="nc-risk ${rl}">${(s.findings_critical||0)>0 ? "C:"+s.findings_critical : (s.findings_high||0)>0 ? "H:"+s.findings_high : rl.charAt(0).toUpperCase()+rl.slice(1)}</span>
        ${sideEditBtn}
      </div>
      <span class="nc-domain">${esc(domain)}</span>
    </button>`;
  }).join("");
  _syncSidebarActive();
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  ALL COMPANIES VIEW
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function renderAllCompanies() {
  _ensureCompanyQueueSummary();
  const companies = allCompanies();
  const grid = document.getElementById("companies-grid");
  const empty = document.getElementById("all-empty");
  const overview = document.getElementById("portfolio-overview");

  const totalC = companies.reduce((a,c)=>a+(c.stats?.findings_critical||0),0);
  const totalH = companies.reduce((a,c)=>a+(c.stats?.findings_high||0),0);
  const totalM = companies.reduce((a,c)=>a+(c.stats?.findings_medium||0),0);
  const totalI = companies.reduce((a,c)=>a+(c.stats?.findings_info||0),0);
  const totalHosts = companies.reduce((a,c)=>a+(c.stats?.subdomains||0),0);
  const totalLive = companies.reduce((a,c)=>a+(c.stats?.live_hosts||0),0);
  const totalEndpoints = companies.reduce((a, c) => {
    const wayback = c.wayback_data?.interesting_count || 0;
    const urlfinder = Array.isArray(c.urlfinder_data?.urls) ? c.urlfinder_data.urls.length : 0;
    const js = c.js_data?.total_endpoints || 0;
    const api = c.api_exposure?.total || 0;
    return a + wayback + urlfinder + js + api;
  }, 0);
  const totalVulns = totalC + totalH + totalM + totalI;
  const topRisk = [...companies].sort((a,b)=> {
    const sa = a.stats || {};
    const sb = b.stats || {};
    const ra = (sa.findings_critical||0) * 100 + (sa.findings_high||0) * 20 + (sa.findings_medium||0) * 5 + (sa.findings_info||0);
    const rb = (sb.findings_critical||0) * 100 + (sb.findings_high||0) * 20 + (sb.findings_medium||0) * 5 + (sb.findings_info||0);
    return rb - ra;
  }).slice(0, 3);
  const topCompany = topRisk[0];
  const topTargetCount = topCompany
    ? ((topCompany.stats?.findings_critical||0) + (topCompany.stats?.findings_high||0) + (topCompany.stats?.findings_medium||0) + (topCompany.stats?.findings_info||0))
    : 0;
  const severityBreakdown = [
    { key: "critical", label: "Critical", count: totalC, color: "var(--red)" },
    { key: "high", label: "High", count: totalH, color: "var(--orange)" },
    { key: "medium", label: "Medium", count: totalM, color: "var(--yellow)" },
    { key: "info", label: "Info", count: totalI, color: "var(--blue)" },
  ];
  const severityTotal = severityBreakdown.reduce((a, s) => a + s.count, 0);
  let severityParts = [];
  let start = 0;
  for (const s of severityBreakdown) {
    const span = severityTotal > 0 ? (s.count / severityTotal) * 100 : 0;
    const end = start + span;
    severityParts.push(`${s.color} ${start.toFixed(2)}% ${end.toFixed(2)}%`);
    start = end;
  }
  if (!severityParts.length) severityParts = ["var(--border2) 0% 100%"];
  const findingFreq = new Map();
  const findingMeta = new Map();
  for (const co of companies) {
    for (const f of (co.findings || [])) {
      const title = (f.title || f.name || "").trim();
      if (!title) continue;
      findingFreq.set(title, (findingFreq.get(title) || 0) + 1);
      if (!findingMeta.has(title)) findingMeta.set(title, f);
    }
  }
  const commonFindings = [...findingFreq.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([title, count]) => ({ title, count, item: findingMeta.get(title) }));
  document.getElementById("all-desc").textContent =
    `${companies.length} companies Â· ${totalVulns.toLocaleString()} vulnerabilities Â· ${totalHosts.toLocaleString()} hosts Â· ${totalEndpoints.toLocaleString()} endpoints`;

  if (overview) {
    overview.innerHTML = `
      <div class="portfolio-hero">
        <div class="portfolio-hero-top">
          <div>
            <div class="rh-kicker">Portfolio Overview</div>
            <div class="rh-title">Attack surface at a glance</div>
            <div class="rh-sub">Executive view for all companies, with severity distribution, top risk targets and repeated findings across the portfolio.</div>
          </div>
          <div class="portfolio-hero-actions">
            <button class="btn btn-secondary" onclick="showPage('jobs'); loadJobs();">Open Queue</button>
            <button class="btn btn-primary" onclick="openAddCompany()">Add Company</button>
          </div>
        </div>
        <div class="portfolio-kpis">
          ${_cardKPI({ cls: "c", value: companies.length, label: "Targets", note: "Companies tracked" })}
          ${_cardKPI({ cls: "h", value: totalHosts, label: "Hosts", note: `${totalLive.toLocaleString()} live / HTTP reachable` })}
          ${_cardKPI({ cls: "m", value: totalEndpoints, label: "Endpoints", note: "URLs + JS + API signals" })}
          ${_cardKPI({ cls: "i", value: totalVulns, label: "Vulnerabilities", note: `${totalC.toLocaleString()} critical Â· ${totalH.toLocaleString()} high` })}
        </div>
        <div class="portfolio-dashboard">
          <section class="portfolio-panel portfolio-severity-panel">
            <div class="portfolio-panel-head">
              <div>
                <div class="portfolio-panel-kicker">Severity breakdown</div>
                <div class="portfolio-panel-title">Vulnerability distribution</div>
                <div class="portfolio-panel-sub">Portfolio-wide counts by severity.</div>
              </div>
            </div>
            <div class="severity-wrap">
              <div class="severity-donut" style="--severity-gradient:${escAttr(`conic-gradient(${severityParts.join(", ")})`)}">
                <div class="severity-donut-center">
                  <div class="severity-donut-total">${totalVulns.toLocaleString()}</div>
                  <div class="severity-donut-label">Total</div>
                </div>
              </div>
              <div class="severity-legend">
                ${severityBreakdown.map(s => `
                  <div class="severity-legend-row" ${topCompany && s.count > 0 ? `onclick="goToVulnSeverity(${_jsArg(topCompany.id)},'${s.key}',event)" style="cursor:pointer" title="Ver vulnerabilidades ${esc(s.label)} no alvo de maior risco"` : ""}>
                    <div class="severity-legend-key">
                      <span class="severity-swatch" style="background:${s.color}"></span>
                      ${esc(s.label)}
                    </div>
                    <div class="severity-legend-count">${s.count.toLocaleString()}</div>
                  </div>
                `).join("")}
              </div>
            </div>
          </section>
          <section class="portfolio-panel portfolio-target-panel">
            <div class="portfolio-panel-head">
              <div>
                <div class="portfolio-panel-kicker">Most vulnerable target</div>
                <div class="portfolio-panel-title">Highest concentration of findings</div>
                <div class="portfolio-panel-sub">Use this as the first pivot for deeper triage.</div>
              </div>
            </div>
            ${topCompany ? `
              <div class="portfolio-table">
                <div class="portfolio-table-row portfolio-table-head">
                  <span>Target</span>
                  <span>Risk</span>
                  <span>Findings</span>
                </div>
                <div class="portfolio-table-row">
                  <div class="portfolio-target-cell">
                    <a class="portfolio-row-host" href="#" onclick="selectCompany(${_jsArg(topCompany.id)});return false;">${esc(topCompany.name)}</a>
                    <div class="portfolio-row-meta">${(topCompany.domains||[]).slice(0,2).map(esc).join(" Â· ") || "No domains"} Â· last scan ${esc(topCompany.last_scan || "â€”")}</div>
                  </div>
                  <span class="portfolio-badge ${riskLevel(topCompany)}">${riskLabel(riskLevel(topCompany))}</span>
                  <span class="portfolio-count">${topTargetCount.toLocaleString()}</span>
                </div>
                ${topRisk.slice(1).map(co => {
                  const s = co.stats || {};
                  const count = (s.findings_critical||0)+(s.findings_high||0)+(s.findings_medium||0)+(s.findings_info||0);
                  const rl = riskLevel(co);
                  return `
                    <div class="portfolio-table-row">
                      <div class="portfolio-target-cell">
                        <a class="portfolio-row-host" href="#" onclick="selectCompany(${_jsArg(co.id)});return false;">${esc(co.name)}</a>
                        <div class="portfolio-row-meta">${(co.domains||[]).slice(0,2).map(esc).join(" Â· ") || "No domains"} Â· ${s.subdomains||0} hosts</div>
                      </div>
                      <span class="portfolio-badge ${rl}">${riskLabel(rl)}</span>
                      <span class="portfolio-count">${count.toLocaleString()}</span>
                    </div>`;
                }).join("")}
              </div>
            ` : `
              <div class="empty-state">
                <div class="empty-state-title">No targets yet</div>
                <div class="empty-state-copy">Add a company and run a scan to populate this view.</div>
              </div>`}
          </section>
          <section class="portfolio-panel portfolio-vuln-panel">
            <div class="portfolio-panel-head">
              <div>
                <div class="portfolio-panel-kicker">Most common vulnerabilities</div>
                <div class="portfolio-panel-title">Repeated findings across the portfolio</div>
                <div class="portfolio-panel-sub">These titles appear most often in the current dataset.</div>
              </div>
            </div>
            ${commonFindings.length ? `
              <div class="portfolio-vuln-list">
                ${commonFindings.map(item => {
                  const sev = item.item?.severity || "info";
                  return `
                    <div class="portfolio-vuln-item">
                      <div>
                        <div class="portfolio-vuln-title">${esc(item.title)}</div>
                        <div class="portfolio-vuln-meta">${esc(item.item?.category || "Finding")} Â· ${esc(item.item?.host || "Portfolio wide")}</div>
                      </div>
                      <div class="portfolio-vuln-count ${sev}">${item.count.toLocaleString()}</div>
                    </div>`;
                }).join("")}
              </div>
            ` : `
              <div class="empty-state">
                <div class="empty-state-title">No vulnerability history yet</div>
                <div class="empty-state-copy">Scan companies to populate repeated findings here.</div>
              </div>`}
          </section>
        </div>
      </div>`;
  }


  if (!companies.length) {
    grid.innerHTML = ""; empty.style.display = "block"; return;
  }
  empty.style.display = "none";
  grid.innerHTML = companies.map(co => {
    const rl = riskLevel(co);
    const s = co.stats||{};
    const hasData = (s.subdomains||0) > 0 || (co.findings||[]).length > 0;
    const liveInfo = _pipelineCardLiveInfo(co.id);
    const checkpointInfo = co.checkpoint_diff || null;
    const endpointsCount = (co.wayback_data?.interesting_count || 0)
      + (Array.isArray(co.urlfinder_data?.urls) ? co.urlfinder_data.urls.length : 0)
      + (co.js_data?.total_endpoints || 0)
      + (co.api_exposure?.total || 0);
    const findingsCount = (s.findings_critical||0)+(s.findings_high||0)+(s.findings_medium||0)+(s.findings_info||0);
    const trendFindings = checkpointInfo?.new_findings_count || 0;
    const trendHosts = checkpointInfo?.new_hosts_count || checkpointInfo?.new_subdomains_count || 0;
    const queueCounts = _companyQueueCounts(co);
    const queueProgress = _companyQueueProgress(co);
    const trendScore = Math.min(100, trendFindings * 18 + trendHosts * 8);
    const trendText = checkpointInfo
      ? (trendScore > 0
        ? `+${trendFindings} findings Â· +${trendHosts} hosts`
        : "Stable")
      : "No diff yet";
    const progressTitle = queueProgress && queueProgress.active
      ? "Processo da fila"
      : "Trend";
    const progressText = queueProgress && queueProgress.active
      ? `${queueProgress.complete.toLocaleString()} concluidos Â· ${queueProgress.done.toLocaleString()} finalizados Â· ${queueProgress.running.toLocaleString()} rodando Â· ${queueProgress.pending.toLocaleString()} na fila`
      : trendText;
    const progressPct = queueProgress && queueProgress.active ? queueProgress.pct : trendScore;
    const progressCls = queueProgress && queueProgress.active ? " running" : "";
    const scanBtn = SERVER_MODE
      ? `<button class="btn-scan btn-scan-sm" onclick="event.stopPropagation();openScanModal('${co.id}')"><svg viewBox="0 0 16 16" fill="currentColor" style="width:10px;height:10px"><path d="M3 2l10 6-10 6V2z"/></svg> Scan</button>`
      : "";
    const editBtn = SERVER_MODE
      ? `<button class="btn btn-secondary" style="font-size:.65rem;padding:3px 9px;opacity:.7" onclick="event.stopPropagation();openEditCompanyModal('${co.id}')" title="Edit company">âœ Edit</button>`
      : "";
    return `<div class="company-card risk-${rl}" onclick="selectCompany('${co.id}')">
      <div class="cc-top">
        <div class="cc-left">
          <div class="cc-name">${esc(co.name)}</div>
          <div class="cc-domain">${esc(_companyScopeLabel(co))}</div>
        </div>
        <div style="display:flex;gap:6px;align-items:center">
          ${hasData ? `<span class="cc-risk-badge ${rl}">${riskLabel(rl)}</span>` : scanBtn}
          ${editBtn}
        </div>
      </div>
      ${hasData ? `
      <div class="cc-mini">
        <span>${co.last_scan || "â€”"}</span>
        <span>${(co.domains||[]).length} domains</span>
        <span>${s.live_hosts||0} live</span>
        <span>${endpointsCount} endpoints</span>
      </div>
      ${liveInfo ? `
      <div class="cc-live ${liveInfo.status}">
        <span class="cc-live-chip ${liveInfo.status}">${esc(liveInfo.status === "queued" ? "Queued" : "Running")}</span>
        <div class="cc-live-text">
          <span class="cc-live-tool">${esc(liveInfo.tool || "starting")}</span>
          ${liveInfo.phase ? `<span class="cc-live-phase">${esc(liveInfo.phase)}</span>` : ""}
        </div>
      </div>` : ""}
      <div class="cc-trend${progressCls}" title="${queueProgress && queueProgress.active ? `${queueProgress.total.toLocaleString()} jobs totais` : (checkpointInfo ? `Compared to ${esc(checkpointInfo.compared_to || 'previous scan')}` : 'No checkpoint history')}">
        <div class="cc-trend-head">
          <span>${esc(progressTitle)}</span>
          <b>${esc(progressText)}</b>
        </div>
        <div class="cc-trend-bar">
          <div class="cc-trend-fill" style="width:${progressPct}%"></div>
        </div>
      </div>
      <div class="cc-track">
        <div class="cc-track-item c" onclick="goToVulnSeverity(${_jsArg(co.id)},'critical',event)" title="Ver vulnerabilidades Critical" style="cursor:pointer"><span>Critical</span><b>${s.findings_critical||0}</b></div>
        <div class="cc-track-item h" onclick="goToVulnSeverity(${_jsArg(co.id)},'high',event)" title="Ver vulnerabilidades High" style="cursor:pointer"><span>High</span><b>${s.findings_high||0}</b></div>
        <div class="cc-track-item m" onclick="goToVulnSeverity(${_jsArg(co.id)},'medium',event)" title="Ver vulnerabilidades Medium" style="cursor:pointer"><span>Medium</span><b>${s.findings_medium||0}</b></div>
        <div class="cc-track-item i" onclick="goToVulnSeverity(${_jsArg(co.id)},'info',event)" title="Ver vulnerabilidades Info" style="cursor:pointer"><span>Info</span><b>${s.findings_info||0}</b></div>
        <div class="cc-track-item"><span>Hosts</span><b>${s.subdomains||0}</b></div>
        <div class="cc-track-item"><span>Live</span><b>${s.live_hosts||0}</b></div>
        <div class="cc-track-item"><span>WAF</span><b>${s.waf_protected||0}</b></div>
      </div>
      <div class="cc-meta">
        <div>${s.subdomains||0} hosts</div>
        <div>${findingsCount} findings</div>
        <div>${s.waf_protected||0} behind WAF</div>
      </div>` : `
      <div class="cc-empty">
        <div class="cc-empty-title">Sem scan concluido ainda</div>
        <div class="cc-empty-stats">
          <div class="cc-empty-stat done">
            <b>${queueCounts.complete.toLocaleString()}</b>
            <span>dominios concluidos</span>
          </div>
          <div class="cc-empty-stat queued">
            <b>${queueCounts.queued.toLocaleString()}</b>
            <span>dominios na fila</span>
          </div>
        </div>
      </div>`}
    </div>`;
  }).join("");
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  OVERVIEW TAB â€” Red Team Executive Summary
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  THREAT MAP â€” Hexagonal grid canvas
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
let _hexAnimFrame = null;
function drawThreatMap(canvas, hosts) {
  try {
  if (!canvas || !canvas.parentElement) return;
  // Cancel any existing animation loop on this canvas
  if (canvas._animFrame) { cancelAnimationFrame(canvas._animFrame); canvas._animFrame = null; }
  const dpr = window.devicePixelRatio || 1;
  const parent = canvas.parentElement;
  const W = parent.offsetWidth  || parent.getBoundingClientRect().width  || 800;
  const H = parent.offsetHeight || parent.getBoundingClientRect().height || 260;
  canvas.width = Math.round(W * dpr);
  canvas.height = Math.round(H * dpr);
  // Let CSS width:100%;height:100% control display size â€” don't set style here
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  const hexR = 18, hexGap = 3;
  const hexW = Math.sqrt(3) * hexR;
  const hexH = 2 * hexR;
  const cols = Math.floor(W / (hexW + hexGap)) + 1;
  const rows = Math.floor(H / (hexH * 0.75 + hexGap)) + 1;

  // Build hex grid with random intensity
  const hexes = [];
  const t = Date.now() * 0.0003;
  for (let row = 0; row < rows; row++) {
    for (let col = 0; col < cols; col++) {
      const cx = col * (hexW + hexGap) + (row % 2 ? hexW/2 + hexGap/2 : 0);
      const cy = row * (hexH * 0.75 + hexGap);
      const noise = Math.sin(cx * 0.04 + t) * Math.cos(cy * 0.05 + t * 0.7);
      const intensity = Math.abs(noise);
      const hasHost = hosts && hosts.length > 0 && (Math.abs(Math.sin(cx * 0.1 + cy * 0.13)) > 0.5);
      hexes.push({ cx, cy, intensity, hasHost });
    }
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    const now = Date.now() * 0.0002;

    for (const h of hexes) {
      const pulse = h.intensity * (0.5 + 0.5 * Math.sin(now * 3 + h.cx * 0.02));
      let alpha = 0.04 + pulse * 0.06;
      let stroke = 'rgba(0,229,255,0.12)';
      let fill = `rgba(0,229,255,${alpha})`;

      if (h.hasHost) {
        alpha = 0.08 + pulse * 0.12;
        fill = `rgba(0,229,255,${alpha})`;
        stroke = 'rgba(0,229,255,0.2)';
      }

      // Draw hex
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const angle = Math.PI / 3 * i - Math.PI / 6;
        const x = h.cx + hexR * Math.cos(angle);
        const y = h.cy + hexR * Math.sin(angle);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.fillStyle = fill;
      ctx.fill();
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 0.5;
      ctx.stroke();
    }
  }

   function animate() {
     draw();
     canvas._animFrame = requestAnimationFrame(animate);
   }
   animate();
  } catch(e) { console.error('drawThreatMap:', e); }
 }

function initThreatMaps() {
  try {
    document.querySelectorAll('.threat-map canvas').forEach(canvas => {
      const parent = canvas.parentElement;
      if (!parent) return;
      // If parent has no size yet (hidden or not laid out), use ResizeObserver
      if (parent.offsetWidth === 0) {
        if (window._tmResizeObs) window._tmResizeObs.disconnect();
        window._tmResizeObs = new ResizeObserver(entries => {
          for (const e of entries) {
            if (e.contentRect.width > 0) {
              window._tmResizeObs.disconnect();
              drawThreatMap(canvas, []);
              break;
            }
          }
        });
        window._tmResizeObs.observe(parent);
      } else {
        drawThreatMap(canvas, []);
      }
    });
  } catch(e) { console.error('initThreatMaps:', e); }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  TENANCY PANEL
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function openTenancyPanel() {
  const el = document.getElementById('tenancy-overlay');
  if (!el) return;
  el.classList.add('show');
  _renderTenancyClients();
}

function closeTenancyPanel() {
  document.getElementById('tenancy-overlay')?.classList.remove('show');
}

function _renderTenancyClients() {
  const list = document.getElementById('tenancy-client-list');
  if (!list) return;
  const companies = allCompanies();
  const active = state.currentId;
  list.innerHTML = companies.map(co =>
    `<div class="tp-client-item ${co.id === active ? 'active' : ''}" onclick="selectTenancyClient('${co.id}')">
      ${esc(co.name)}${co.id === active ? ' â† ACTIVE' : ''}
    </div>`
  ).join('');
}

function selectTenancyClient(cid) {
  selectCompany(cid);
  closeTenancyPanel();
}

// Keyboard shortcut: Alt+T opens tenancy panel
document.addEventListener('keydown', function(e) {
  try {
    if (e.altKey && e.key === 't') {
      e.preventDefault();
      openTenancyPanel();
    }
    if (e.altKey && e.key >= '1' && e.key <= '9') {
      e.preventDefault();
      var idx = parseInt(e.key) - 1;
      var cos = (typeof allCompanies === 'function') ? allCompanies() : [];
      if (cos[idx] && typeof selectCompany === 'function') selectCompany(cos[idx].id);
    }
  } catch(ex) {}
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  GLOBAL SEARCH (Ctrl+K)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
let _gsearchActiveIdx = -1;
let _gsearchResults = [];

document.addEventListener('keydown', function(e) {
  try {
    const k = (e.key || '').toLowerCase();
    if ((e.ctrlKey || e.metaKey) && k === 'k') {
      e.preventDefault();
      openGlobalSearch();
      return;
    }
    if (k === 'escape') {
      const overlay = document.getElementById('modal-global-search');
      if (overlay && overlay.classList.contains('show')) closeGlobalSearch();
    }
  } catch(ex) {}
});

function openGlobalSearch() {
  const overlay = document.getElementById('modal-global-search');
  if (!overlay) return;
  overlay.classList.add('show');
  _gsearchActiveIdx = -1;
  const input = document.getElementById('gsearch-input');
  input.value = '';
  document.getElementById('gsearch-results').innerHTML = '';
  setTimeout(() => input.focus(), 30);
}

function closeGlobalSearch() {
  const overlay = document.getElementById('modal-global-search');
  if (overlay) overlay.classList.remove('show');
}

function onGlobalSearchInput() {
  const q = (document.getElementById('gsearch-input').value || '').trim();
  _gsearchActiveIdx = -1;
  if (q.length < 2) {
    document.getElementById('gsearch-results').innerHTML = q
      ? `<div class="gsearch-empty">Digite ao menos 2 caracteres...</div>`
      : '';
    _gsearchResults = [];
    return;
  }
  _gsearchResults = performGlobalSearch(q);
  renderGlobalSearchResults(_gsearchResults);
}

function performGlobalSearch(query) {
  const q = query.toLowerCase();
  const results = [];
  const MAX_PER_GROUP = 8;

  for (const co of allCompanies()) {
    if ((co.name || '').toLowerCase().includes(q) || (co.id || '').toLowerCase().includes(q)) {
      results.push({
        group: 'Empresas', icon: 'ðŸ¢', title: co.name || co.id,
        sub: co.id, action: { type: 'company', cid: co.id },
      });
    }

    for (const dom of (co.domains || [])) {
      if (results.filter(r => r.group === 'DomÃ­nios').length >= MAX_PER_GROUP) break;
      if ((dom || '').toLowerCase().includes(q)) {
        results.push({
          group: 'DomÃ­nios', icon: 'ðŸŒ', title: dom, sub: co.name || co.id,
          action: { type: 'company', cid: co.id, group: 'hosts' },
        });
      }
    }

    for (const h of (co.hosts || [])) {
      if (results.filter(r => r.group === 'Hosts').length >= MAX_PER_GROUP) break;
      const hay = `${h.host || ''} ${h.ip || ''} ${h.title || ''}`.toLowerCase();
      if (hay.includes(q)) {
        results.push({
          group: 'Hosts', icon: 'ðŸ–¥', title: h.host || h.ip || '',
          sub: `${co.name || co.id}${h.ip ? ' Â· ' + h.ip : ''}${h.status_code ? ' Â· HTTP ' + h.status_code : ''}`,
          action: { type: 'company', cid: co.id, group: 'hosts' },
        });
      }
    }

    for (const d of (co.email_details || []).length ? co.email_details : (co.emails || []).map(e => ({email: e}))) {
      if (results.filter(r => r.group === 'Pessoas').length >= MAX_PER_GROUP) break;
      const name = [d.first_name, d.last_name].filter(Boolean).join(' ');
      const hay = `${d.email || ''} ${name} ${d.position || ''}`.toLowerCase();
      if (hay.includes(q)) {
        results.push({
          group: 'Pessoas', icon: 'ðŸ‘¤', title: d.email || '', sub: `${name || co.name || co.id}${d.position ? ' Â· ' + d.position : ''}`,
          action: { type: 'company', cid: co.id, group: 'infragroup' },
        });
      }
    }

    for (const f of (co.findings || [])) {
      if (results.filter(r => r.group === 'Findings').length >= MAX_PER_GROUP) break;
      const hay = `${f.title || ''} ${f.host || ''} ${f.desc || ''} ${f.category || f.type || ''}`.toLowerCase();
      if (hay.includes(q)) {
        results.push({
          group: 'Findings', icon: 'âš ', title: f.title || '', tag: f.severity || '',
          sub: `${co.name || co.id}${f.host ? ' Â· ' + f.host : ''}`,
          action: { type: 'company', cid: co.id, group: 'operation' },
        });
      }
    }
  }

  return results.slice(0, 60);
}

function renderGlobalSearchResults(results) {
  const el = document.getElementById('gsearch-results');
  if (!results.length) {
    el.innerHTML = `<div class="gsearch-empty">Nenhum resultado encontrado</div>`;
    return;
  }
  let html = '';
  let lastGroup = null;
  results.forEach((r, i) => {
    if (r.group !== lastGroup) {
      html += `<div class="gsearch-group-label">${esc(r.group)}</div>`;
      lastGroup = r.group;
    }
    html += `<div class="gsearch-item" data-idx="${i}" onclick="selectGlobalSearchResult(${i})">
      <div class="gsearch-item-icon">${r.icon}</div>
      <div class="gsearch-item-main">
        <div class="gsearch-item-title">${esc(r.title)}</div>
        <div class="gsearch-item-sub">${esc(r.sub || '')}</div>
      </div>
      ${r.tag ? `<div class="gsearch-item-tag">${esc(r.tag)}</div>` : ''}
    </div>`;
  });
  el.innerHTML = html;
}

function onGlobalSearchKeydown(e) {
  const k = e.key;
  if (k === 'ArrowDown' || k === 'ArrowUp') {
    e.preventDefault();
    if (!_gsearchResults.length) return;
    if (k === 'ArrowDown') _gsearchActiveIdx = Math.min(_gsearchActiveIdx + 1, _gsearchResults.length - 1);
    else _gsearchActiveIdx = Math.max(_gsearchActiveIdx - 1, 0);
    document.querySelectorAll('#gsearch-results .gsearch-item').forEach((it, i) => {
      it.classList.toggle('active', i === _gsearchActiveIdx);
      if (i === _gsearchActiveIdx) it.scrollIntoView({ block: 'nearest' });
    });
  } else if (k === 'Enter') {
    e.preventDefault();
    const idx = _gsearchActiveIdx >= 0 ? _gsearchActiveIdx : 0;
    if (_gsearchResults[idx]) selectGlobalSearchResult(idx);
  }
}

async function selectGlobalSearchResult(idx) {
  const r = _gsearchResults[idx];
  if (!r) return;
  closeGlobalSearch();
  const action = r.action;
  if (action.type === 'company') {
    await selectCompany(action.cid);
    if (action.group) {
      const btn = document.querySelector(`.tab-btn[data-group="${action.group}"]`);
      if (btn) switchGroup(action.group, btn);
    }
  }
}

function _renderRiskGauge(crit, high, med, info, total) {
  const r = 44, stroke = 5, circ = 2 * Math.PI * r;
  const score = total > 0 ? Math.round((crit * 4 + high * 3 + med * 2 + info) / (total * 4) * 100) : 0;
  const color = score >= 70 ? '#fb7185' : score >= 40 ? '#fb923c' : score >= 15 ? '#fbbf24' : '#4ade80';
  const dash = (score / 100) * circ;
  return `<svg width="120" height="120" viewBox="0 0 120 120" class="risk-gauge">
    <circle cx="60" cy="60" r="${r}" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="${stroke}"/>
    <circle cx="60" cy="60" r="${r}" fill="none" stroke="${color}" stroke-width="${stroke+2}"
      stroke-dasharray="${dash} ${circ - dash}" stroke-linecap="round"
      transform="rotate(-90 60 60)" style="filter:drop-shadow(0 0 8px ${color}44)"/>
    <text x="60" y="55" text-anchor="middle" fill="${color}" font-size="22" font-weight="800">${score}</text>
    <text x="60" y="73" text-anchor="middle" fill="var(--text3)" font-size="9" font-weight="600" letter-spacing="0.08em">RISK SCORE</text>
  </svg>`;
}

function renderOverview(co) {
  const s = co.stats || {};
  const hosts = co.hosts || [];

  const crit = s.findings_critical || 0;
  const high = s.findings_high || 0;
  const med  = s.findings_medium || 0;
  const info = s.findings_info || 0;
  const totalFindings = crit + high + med + info;
  const risk = riskLevel(co);
  const directHosts = hosts.length - (s.waf_protected || 0);

  document.getElementById("tab-overview").innerHTML = `
    <div class="overview-hero overview-hero-clean">
      <div class="ov-hero-left">
        ${_renderRiskGauge(crit, high, med, info, totalFindings)}
        <div class="ov-hero-sub">${riskLabel(risk)} Â· ${co.domains?.[0] || co.name}</div>
      </div>
      <div class="ov-hero-right">
        <div class="ov-hero-metrics">
          <div class="ov-metric"><span class="ov-metric-num">${s.subdomains || hosts.length || 0}</span><span class="ov-metric-lbl">assets</span></div>
          <div class="ov-metric"><span class="ov-metric-num">${s.live_hosts || 0}</span><span class="ov-metric-lbl">live hosts</span></div>
          <div class="ov-metric"><span class="ov-metric-num">${s.open_ports || 0}</span><span class="ov-metric-lbl">open ports</span></div>
          <div class="ov-metric"><span class="ov-metric-num">${s.waf_protected || 0}</span><span class="ov-metric-lbl">behind WAF</span></div>
          <div class="ov-metric"><span class="ov-metric-num">${directHosts}</span><span class="ov-metric-lbl" style="color:${directHosts > 0 ? 'var(--red)' : 'var(--text3)'}">direct</span></div>
        </div>
        <div class="ov-sev-pills">
          <span class="ov-sev-pill crit">${crit}<span>critical</span></span>
          <span class="ov-sev-pill high">${high}<span>high</span></span>
          <span class="ov-sev-pill med">${med}<span>medium</span></span>
          <span class="ov-sev-pill info">${info}<span>info</span></span>
        </div>
      </div>
    </div>`;
}

async function loadScanHistory(cid) {
  const el = document.getElementById("ov-history");
  if(!el) return;
  el.innerHTML = `<span style="color:var(--text3)">Loadingâ€¦</span>`;
  try {
    const r = await fetch(`/api/scan-history/${cid}`, {headers:_authHeaders()});
    const history = await r.json();
    if(!history.length){ el.innerHTML = `<span style="color:var(--text3)">No past scans found.</span>`; return; }
    el.innerHTML = `<div class="history-list">` +
      history.map(s => {
        const dt = new Date(s.mtime*1000).toLocaleString();
        const dnsColor = s.dns_names > 0 ? "var(--teal)" : "var(--text3)";
        const fColor   = s.findings  > 0 ? "var(--orange)" : "var(--text3)";
        const safeId   = `sh-${cid}-${esc(s.name)}`.replace(/[^a-zA-Z0-9_-]/g,"_");
        return `<div id="${safeId}" class="history-row">
          <span class="history-name">${esc(s.name)}</span>
          <span class="history-stat">${esc(dt)}</span>
          <span class="history-stat" style="color:${dnsColor}"><strong>${s.dns_names}</strong> hosts</span>
          <span class="history-stat" style="color:${fColor}"><strong>${s.findings}</strong> findings</span>
          <span class="history-stat"><strong>${s.events}</strong> events Â· ${s.size_kb}KB</span>
          <div class="history-cta">
          ${s.has_asm_log ? `<button class="btn btn-secondary" style="font-size:.65rem;padding:2px 8px;color:var(--teal)" onclick="openScanLog('${cid}','${esc(s.name)}')">ðŸ“‹ Ver Log</button>` : ''}
          <button class="btn btn-secondary" style="font-size:.65rem;padding:2px 8px"
                  onclick="reparseHistory('${cid}','${esc(s.name)}',this)">Re-parse</button>
          <button class="btn btn-secondary" style="font-size:.65rem;padding:2px 8px;color:var(--red)"
                  onclick="deleteScanHistory('${cid}','${esc(s.name)}','${safeId}',this)">Delete</button>
          </div>
        </div>`;
      }).join("") + `</div>`;
  } catch(e) {
    el.innerHTML = `<span style="color:var(--red)">Error: ${e.message}</span>`;
  }
}

async function reparseHistory(cid, scanName, btn) {
  btn.disabled = true;
  btn.textContent = "Parsingâ€¦";
  try {
    const r = await fetch(`/api/scan-history/${cid}/${encodeURIComponent(scanName)}/reparse`, {method:"POST", headers:_authHeaders()});
    if(!r.ok) throw await _apiErr(r);
    await reloadServerData();
    const co = allCompanies().find(c=>c.id===cid);
    if(co){ renderOverview(co); renderFindingsTab(co); renderCveTab(co); renderSubdomainsTab(co); renderTyposquatTab(co); }
    btn.textContent = "âœ“ Done";
    setTimeout(()=>{ btn.textContent="Re-parse"; btn.disabled=false; }, 2000);
  } catch(e) {
    btn.textContent = "âœ— Error";
    btn.title = e.message;
    setTimeout(()=>{ btn.textContent="Re-parse"; btn.disabled=false; }, 3000);
  }
}

async function clearReconData(cid) {
  if (!confirm(`Clear ALL data for "${cid}"?\nThe project will be reset like a fresh project: hosts, findings, URLs, JS, secrets, jobs, logs, checkpoints, screenshots, snapshots and scan history will be removed.\nThe project name/domains/tags are preserved.\nThis action cannot be undone.`)) return;
  const btn = document.getElementById("clear-data-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Clearingâ€¦"; }
  try {
    const r = await fetch(`/api/recon/${encodeURIComponent(cid)}/data`, {
      method: "DELETE", headers: _authHeaders(),
    });
    if (!r.ok) throw await _apiErr(r);
    // Also clear tool logs explicitly
    try { await fetch(`/api/recon/${cid}/tool-logs`, { method: "DELETE", headers: _authHeaders() }); } catch(e) {}
    // Force-reload the entire app state from server
    location.reload();
  } catch(e) {
    alert("Error clearing data: " + e.message);
    if (btn) { btn.disabled = false; btn.textContent = "ðŸ—‘ Clear Data"; }
  }
}

async function deleteScanHistory(cid, scanName, rowId, btn) {
  if (!confirm(`Delete scan "${scanName}"? This action cannot be undone.`)) return;
  btn.disabled = true;
  btn.textContent = "Deletingâ€¦";
  try {
    const r = await fetch(`/api/scan-history/${encodeURIComponent(cid)}/${encodeURIComponent(scanName)}`, {
      method: "DELETE", headers: _authHeaders(),
    });
    if (!r.ok) throw await _apiErr(r);
    const row = document.getElementById(rowId);
    if (row) row.remove();
    await reloadServerData();
    const co = allCompanies().find(c => c.id === cid);
    if (co) { renderOverview(co); renderFindingsTab(co); renderCveTab(co); renderSubdomainsTab(co); }
  } catch(e) {
    btn.disabled = false;
    btn.textContent = "Delete";
    alert("Error: " + e.message);
  }
}

async function deleteAllScanHistory(cid) {
  if (!confirm(`Delete ALL scans for "${cid}"? This action cannot be undone.`)) return;
  const el = document.getElementById("ov-history");
  if (el) el.innerHTML = `<span style="color:var(--text3)">Deletingâ€¦</span>`;
  try {
    const r = await fetch(`/api/scan-history/${encodeURIComponent(cid)}`, {
      method: "DELETE", headers: _authHeaders(),
    });
    if (!r.ok) throw await _apiErr(r);
    const d = await r.json();
    if (el) el.innerHTML = `<span style="color:var(--text3)">${d.count} scan(s) deleted. Findings cleared.</span>`;
    await reloadServerData();
    const co = allCompanies().find(c => c.id === cid);
    if (co) { renderOverview(co); renderFindingsTab(co); renderCveTab(co); renderSubdomainsTab(co); }
  } catch(e) {
    if (el) el.innerHTML = `<span style="color:var(--red)">Error: ${e.message}</span>`;
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  FINDINGS / VULNS TAB
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function _confirmedVulnFindings(findings) {
  const noise = /phish|typosquat|intel|osint|leak|brand|whois|monitor|newsletter|marketing|scan noise/i;
  return (findings || []).filter(f => {
    const status = String(f.status || "").toLowerCase();
    if (status.includes("false") || status.includes("ignor") || status.includes("dismiss") || status.includes("duplicate") || status.includes("invalid")) return false;
    // Secrets are always real findings â€” never hide them behind the noise filter
    if (f.type === "secret" || f.category === "secrets") return true;
    const text = [
      f.title,
      f.name,
      f.category,
      f.type,
      f.module,
      f.desc,
      f.description,
      f.impact,
      f.endpoint,
    ].join(" ").toLowerCase();
    if (noise.test(text)) return false;
    return true;
  });
}

function _vStatCard(label, val, color) {
  return '<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 18px;min-width:110px">' +
    '<div style="font-size:1.45rem;font-weight:800;color:' + color + '">' + val + '</div>' +
    '<div style="font-size:.68rem;color:var(--text3);margin-top:2px;text-transform:uppercase">' + label + '</div></div>';
}

function renderFindingsTab(co) {
  return renderVulnsTab(co);
}

// â”€â”€ Vulnerability intelligence: CWE / CVSS estimates / mitigation guidance â”€â”€
const VULN_INTEL_RULES = [
  { id:'sqli', re:/sql\s*injection|sqli/i, cwe:'CWE-89', cvss:9.8, vector:'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    mitigation:[
      'Use parameterized queries / prepared statements for all database access â€” never concatenate user input into SQL.',
      'Apply the principle of least privilege to the database account used by the application.',
      'Add input validation and an allow-list for expected formats (e.g. numeric IDs).',
      'Deploy WAF rules as defense-in-depth, but do not rely on them as the primary fix.'
    ]},
  { id:'xss', re:/cross-site scripting|\bxss\b|reflected_xss|confirmed_xss|dom_xss|tainted_sink/i, cwe:'CWE-79', cvss:6.1, vector:'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    mitigation:[
      'Apply context-aware output encoding for all user-controlled data rendered in HTML, JS or attributes.',
      'Adopt a strict Content-Security-Policy (script-src without unsafe-inline / unsafe-eval).',
      'Use templating that auto-escapes output by default and avoid innerHTML / dangerouslySetInnerHTML with raw input.',
      'Set HttpOnly and SameSite=Strict/Lax on session cookies to limit impact of injected scripts.'
    ]},
  { id:'idor', re:/idor|insecure direct object reference|potential_idor|broken access control/i, cwe:'CWE-639', cvss:6.5, vector:'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    mitigation:[
      'Enforce server-side authorization (ownership/tenant validation) on every object reference, not just authentication.',
      'Avoid predictable/sequential identifiers â€” use UUIDs or an indirect reference map.',
      'Centralize access-control logic in a middleware/policy layer instead of per-endpoint checks.',
      'Add automated tests that attempt cross-tenant/cross-user access for every resource endpoint.'
    ]},
  { id:'open_redirect', re:/open redirect/i, cwe:'CWE-601', cvss:4.7, vector:'AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
    mitigation:[
      'Avoid passing full URLs in redirect parameters â€” use an allow-list of internal paths or indirect IDs.',
      'If external redirects are required, validate the destination against a strict domain allow-list.',
      'Show an interstitial warning page before redirecting to a different host.'
    ]},
  { id:'cors', re:/cors|cross-origin resource sharing/i, cwe:'CWE-942', cvss:7.5, vector:'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    mitigation:[
      'Never reflect the Origin header with Access-Control-Allow-Credentials: true.',
      'Use a strict allow-list of trusted origins instead of a wildcard or reflected origin.',
      'Separate APIs that require credentials from those intended to be public.'
    ]},
  { id:'takeover', re:/takeover|subdomain takeover|dangling/i, cwe:'CWE-350', cvss:7.5, vector:'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
    mitigation:[
      'Remove the dangling DNS record (CNAME/A) pointing at the deprovisioned service.',
      'Re-claim the resource on the third-party provider if the subdomain is still needed.',
      'Add monitoring that alerts when a CNAME target stops resolving or returns an "unclaimed" page.'
    ]},
  { id:'secret', re:/secret|api[\s_-]?key|credential|token leak|aws_key|private key/i, cwe:'CWE-798', cvss:9.1, vector:'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    mitigation:[
      'Revoke and rotate the exposed credential immediately.',
      'Purge the secret from source control history (git filter-repo / BFG) â€” rotation alone is not enough on a public repo.',
      'Move secrets to a dedicated secrets manager and load via environment at runtime.',
      'Add pre-commit/CI secret scanning (gitleaks, trufflehog) to prevent recurrence.'
    ]},
  { id:'graphql', re:/graphql/i, cwe:'CWE-200', cvss:5.3, vector:'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    mitigation:[
      'Disable GraphQL introspection in production.',
      'Apply query depth/complexity limiting and rate limiting.',
      'Ensure field-level authorization is enforced, not just at the query root.'
    ]},
  { id:'ssrf', re:/ssrf|server-side request forgery/i, cwe:'CWE-918', cvss:8.6, vector:'AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N',
    mitigation:[
      'Validate and allow-list outbound destinations; block requests to internal/link-local/metadata ranges (169.254.169.254, RFC1918).',
      'Use a dedicated egress proxy with strict allow-lists for server-side fetch functionality.',
      'Disable unused URL schemes (file://, gopher://, dict://) in HTTP client libraries.'
    ]},
  { id:'ssti', re:/ssti|template injection/i, cwe:'CWE-1336', cvss:9.0, vector:'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    mitigation:[
      'Never render user input directly as a template string; use logic-less or sandboxed templates.',
      'Apply strict input validation/escaping before passing data to the template engine.',
      'Run the template renderer with the least privilege needed.'
    ]},
  { id:'headers', re:/missing.*header|x-frame-options|hsts|security headers|clickjack/i, cwe:'CWE-1021', cvss:4.3, vector:'AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
    mitigation:[
      'Add X-Frame-Options: DENY (or CSP frame-ancestors), Strict-Transport-Security and X-Content-Type-Options: nosniff.',
      'Adopt a baseline security-headers policy and verify it with automated checks.'
    ]},
  { id:'default_creds', re:/default credential|default password/i, cwe:'CWE-1392', cvss:9.8, vector:'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    mitigation:[
      'Force a password change on first login and disable/rename default accounts.',
      'Restrict admin panels to internal networks/VPN where possible.'
    ]},
  { id:'info_disclosure', re:/directory listing|information disclosure|exposed|stack trace|debug/i, cwe:'CWE-200', cvss:5.3, vector:'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    mitigation:[
      'Disable directory listing and verbose error/debug output in production.',
      'Review what is served from publicly accessible paths and remove sensitive files.'
    ]},
  { id:'xxe', re:/xxe|xml external entity/i, cwe:'CWE-611', cvss:7.5, vector:'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    mitigation:[
      'Disable DTD processing and external entity resolution in the XML parser.',
      'Prefer less complex data formats (JSON) where possible.'
    ]},
];

const VULN_INTEL_DEFAULT_MITIGATION = [
  'Review the finding manually to confirm exploitability and business impact.',
  'Apply input validation, output encoding and least-privilege access controls relevant to the affected component.',
  'Re-test after remediation to confirm the issue is resolved.'
];

function _cvssSeverityLabel(score) {
  if (score == null) return 'N/A';
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score > 0) return 'Low';
  return 'None';
}

function _vulnIntel(f) {
  const text = [f.title, f.category, f.type, f.name, f.desc, f.description].filter(Boolean).join(' ');
  const rule = VULN_INTEL_RULES.find(r => r.re.test(text));
  if (rule) return rule;
  const sevCvss = {critical:9.0, high:7.5, medium:5.3, low:3.1, info:0.0}[f.severity];
  return {
    id: 'generic',
    cwe: 'CWE-200',
    cvss: sevCvss != null ? sevCvss : 5.0,
    vector: null,
    mitigation: VULN_INTEL_DEFAULT_MITIGATION,
  };
}

function _buildPocPreview(f, intel) {
  const title = f.title || f.name || 'Security Finding';
  const host = f.host || '';
  const url = f.url || f.endpoint || '';
  const desc = f.desc || f.description || '';
  const cvssLine = intel.cvss != null
    ? `${intel.cvss.toFixed(1)} (${_cvssSeverityLabel(intel.cvss)})` + (intel.vector ? ` â€” CVSS:3.1/${intel.vector}` : '')
    : 'N/A';
  return `## Summary
${title} was identified on ${host || url}.

## Vulnerability Details
- **Affected asset:** ${url || host}
- **Category:** ${f.category || f.type || 'N/A'}
- **CWE:** ${intel.cwe}
- **CVSS:** ${cvssLine}
- **Severity:** ${(f.severity || 'info').toUpperCase()}

## Description
${desc || '[Describe the issue and how it was discovered]'}

## Steps to Reproduce
1. Navigate to ${url || host}
2. [Describe the exact request/action that triggers the issue]
3. Observe the resulting behavior described above

## Impact
[Describe what an attacker could achieve â€” data exposure, account takeover, lateral movement, etc.]

## Recommended Mitigation
${intel.mitigation.map(m => '- ' + m).join('\n')}
`;
}

function _normalizeFindingTitle(title, host) {
  if (!title) return "?";
  let t = title;
  if (host && t.includes(host)) t = t.replace(host, "<HOST>");
  t = t.replace(/\b\d+\.\d+\.\d+\.\d+\b/g, "<IP>");
  t = t.replace(/:\d{2,5}\b/g, ":<PORT>");
  return t;
}

const FINDING_TRIAGE_LABELS = {
  open: "Aberto", in_progress: "Em progresso", fixed: "Corrigido", accepted_risk: "Risco aceito",
};

function applyFindFilter(cid) {
  const co = allCompanies().find(c=>c.id===cid); if(!co) return;
  const q       = document.getElementById("f-search")?.value.toLowerCase()||"";
  const sev     = document.getElementById("f-sev")?.value||"";
  const cat     = document.getElementById("f-cat")?.value||"";
  const triageFilter = document.getElementById("f-triage")?.value||"";
  const triageMap = (window._triageMap && window._triageMap[cid]) || {};
  const filtered = _confirmedVulnFindings(co.findings||[]).filter(f=>{
    const ms = !q||[f.title,f.host,f.desc||f.description,f.category].join(" ").toLowerCase().includes(q);
    return ms && (!sev||f.severity===sev) && (!cat||f.category===cat);
  });

  // Group by normalized title
  const groups = new Map();
  filtered.forEach(f => {
    const key = _normalizeFindingTitle(f.title||"", f.host||"");
    if (!groups.has(key)) groups.set(key, {findings:[]});
    groups.get(key).findings.push(f);
  });

  // Apply triage status filter at group level
  let entries = [...groups.entries()];
  if (triageFilter) {
    entries = entries.filter(([normTitle]) => {
      const triageKey = _hashId(normTitle, "", "");
      const status = (triageMap[triageKey] && triageMap[triageKey].status) || "open";
      return status === triageFilter;
    });
  }

  const list  = document.getElementById("f-list");
  const empty = document.getElementById("f-empty");
  const cnt   = document.getElementById("f-cnt");
  const filteredCount = entries.reduce((n,[,g])=>n+g.findings.length, 0);
  if(cnt) cnt.textContent = filteredCount+" findings Â· "+entries.length+" unique issues";
  if(!entries.length){ list.innerHTML=""; empty.style.display="block"; return; }
  empty.style.display="none";

  // Sort groups: most hosts first, then by highest severity
  const sevRank = {critical:0, high:1, medium:2, low:3, info:4};
  const sortedGroups = entries.sort((a,b) => {
    const maxSevA = Math.min(...a[1].findings.map(f=>sevRank[f.severity]||4));
    const maxSevB = Math.min(...b[1].findings.map(f=>sevRank[f.severity]||4));
    if (maxSevA !== maxSevB) return maxSevA - maxSevB;
    return b[1].findings.length - a[1].findings.length;
  });

  list.innerHTML = sortedGroups.map(([normTitle, group]) => {
    const f0 = group.findings[0];
    const hosts = [...new Set(group.findings.map(f=>f.host||"").filter(Boolean))];
    const count = group.findings.length;
    const isMulti = count > 1;
    const sevs = [...new Set(group.findings.map(f=>f.severity||"info"))];
    const topSev = sevs.includes("critical") ? "critical" : sevs.includes("high") ? "high" : sevs.includes("medium") ? "medium" : sevs.includes("low") ? "low" : "info";
    const sevColors = {critical:"#f43f5e", high:"#fb923c", medium:"#fbbf24", low:"var(--blue)", info:"var(--text3)"};

    // Host list preview
    const hostPreview = hosts.length <= 5
      ? hosts.map(h=>`<code class="fg-host-chip">${esc(h)}</code>`).join(" ")
      : hosts.slice(0,5).map(h=>`<code class="fg-host-chip">${esc(h)}</code>`).join(" ") + ` <span style="color:var(--text3);font-size:.68rem">+${hosts.length-5} more</span>`;

    const allHostsId = `fg-hosts-${_hashId(normTitle, "", "")}`;
    const triageKey = _hashId(normTitle, "", "");
    const triageStatus = (triageMap[triageKey] && triageMap[triageKey].status) || "open";

    const intel = _vulnIntel(f0);
    if (!window._findingIntelMap) window._findingIntelMap = {};
    window._findingIntelMap[allHostsId] = { f: f0, intel };
    const cvssLabel = intel.cvss != null ? `${intel.cvss.toFixed(1)} ${_cvssSeverityLabel(intel.cvss)}` : "N/A";

    return `<div class="fg-row" onclick="toggleFindGroupHosts('${allHostsId}')" style="cursor:pointer">
      <div class="fg-sev" style="background:${sevColors[topSev]}"></div>
      <div class="fg-main">
        <div class="fg-title-row">
          <span class="fg-title">${esc(f0.title||normTitle)}</span>
          ${isMulti ? `<span class="fg-badge" style="background:${sevColors[topSev]}22;color:${sevColors[topSev]};border:1px solid ${sevColors[topSev]}44">${count} hosts</span>` : ""}
          <span style="color:var(--text3);font-size:.68rem;margin-left:4px">${esc(f0.category||"")}</span>
          <span style="background:var(--card);border:1px solid var(--border);border-radius:4px;padding:1px 7px;font-size:.62rem;color:var(--text3);margin-left:4px" title="Estimated CWE">${esc(intel.cwe)}</span>
          <span style="background:var(--card);border:1px solid var(--border);border-radius:4px;padding:1px 7px;font-size:.62rem;color:var(--text3)" title="Estimated CVSS 3.1">CVSS ${cvssLabel}</span>
          <select class="fi fg-triage-select fg-triage-${triageStatus}" onclick="event.stopPropagation()" onchange="event.stopPropagation();setFindingTriage('${esc(cid)}','${triageKey}',this.value)">
            ${Object.entries(FINDING_TRIAGE_LABELS).map(([val,lbl])=>`<option value="${val}" ${triageStatus===val?'selected':''}>${lbl}</option>`).join("")}
          </select>
        </div>
        <div class="fg-hosts-preview">${hostPreview}</div>
        <div class="fg-hosts-full" id="${allHostsId}" style="display:none;margin-top:8px;padding:10px 12px;background:rgba(0,0,0,0.2);border:1px solid var(--border2);border-radius:8px">
          <div style="color:var(--text3);font-size:.65rem;font-weight:600;margin-bottom:6px">ðŸ“‹ All affected hosts (${hosts.length}):</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px">
            ${hosts.map(h=>`<code class="fg-host-chip fg-host-chip-full" onclick="event.stopPropagation();navigator.clipboard.writeText('${esc(h)}');this.style.background='var(--teal-dim)';setTimeout(()=>this.style.background='',1500)" title="Click to copy">${esc(h)}</code>`).join("")}
          </div>
          <div style="margin-top:8px;font-size:.65rem;color:var(--text3)">
            Click any host to copy Â· ${esc(f0.desc||"").slice(0,200)}${(f0.desc||"").length>200?"â€¦":""}
          </div>
          ${_renderHttpEvidence(group.findings)}
          <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border2)">
            <div style="font-size:.65rem;font-weight:700;color:var(--text2);text-transform:uppercase;margin-bottom:6px">ðŸ›¡ Mitigation recommendations</div>
            <ul style="margin:0 0 8px 18px;padding:0;font-size:.72rem;color:var(--text2);line-height:1.5">
              ${intel.mitigation.map(m=>`<li>${esc(m)}</li>`).join("")}
            </ul>
            <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
              <button class="btn btn-secondary" style="font-size:.65rem;padding:4px 10px" onclick="event.stopPropagation();_copyPocPreview('${allHostsId}')">ðŸ“‹ Copy PoC (HackerOne/Bugcrowd)</button>
              <button class="btn btn-secondary" style="font-size:.65rem;padding:4px 10px" onclick="event.stopPropagation();_enrichFindingWithHermes('${esc(cid)}','${allHostsId}')" id="${allHostsId}-aibtn">âœ¨ Enrich with Hermes AI</button>
              <span style="font-size:.62rem;color:var(--text3)">CWE: ${esc(intel.cwe)} Â· CVSS 3.1: ${esc(cvssLabel)}${intel.vector ? ' ('+esc(intel.vector)+')' : ''} â€” estimates, confirm before reporting</span>
            </div>
            <div id="${allHostsId}-ai" style="display:none;margin-top:8px;padding:10px;background:var(--card);border:1px solid var(--border);border-radius:6px;font-size:.72rem;color:var(--text2);white-space:pre-wrap"></div>
          </div>
        </div>
      </div>
      <div class="fg-arrow" id="${allHostsId}-arr">â–¾</div>
    </div>`;
  }).join("");
}

async function setFindingTriage(cid, findingKey, status) {
  if (!window._triageMap) window._triageMap = {};
  if (!window._triageMap[cid]) window._triageMap[cid] = {};
  window._triageMap[cid][findingKey] = { status };
  try {
    await fetch(`/api/findings/${encodeURIComponent(cid)}/triage`, {
      method: 'POST',
      headers: {'Content-Type':'application/json', ..._authHeaders()},
      body: JSON.stringify({ finding_key: findingKey, status }),
    });
  } catch(e) {}
  applyFindFilter(cid);
}

function _copyPocPreview(allHostsId) {
  const entry = (window._findingIntelMap || {})[allHostsId];
  if (!entry) return;
  const text = _buildPocPreview(entry.f, entry.intel);
  navigator.clipboard.writeText(text).then(() => {
    showToast && showToast("PoC preview copiado para a Ã¡rea de transferÃªncia");
  }).catch(() => {
    showToast && showToast("NÃ£o foi possÃ­vel copiar automaticamente");
  });
}

async function _enrichFindingWithHermes(cid, allHostsId) {
  const entry = (window._findingIntelMap || {})[allHostsId];
  if (!entry) return;
  const btn = document.getElementById(`${allHostsId}-aibtn`);
  const out = document.getElementById(`${allHostsId}-ai`);
  if (!out) return;
  out.style.display = "block";
  out.textContent = "Consultando Hermes AI...";
  if (btn) btn.disabled = true;
  try {
    const resp = await fetch(`/api/ai/enrich-finding`, {
      method: 'POST',
      headers: {'Content-Type':'application/json', ..._authHeaders()},
      body: JSON.stringify({
        company_id: cid,
        finding: {
          title: entry.f.title, host: entry.f.host, url: entry.f.url || entry.f.endpoint,
          category: entry.f.category, type: entry.f.type, severity: entry.f.severity,
          desc: entry.f.desc || entry.f.description,
          cwe: entry.intel.cwe, cvss: entry.intel.cvss, vector: entry.intel.vector,
        },
      }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
    out.textContent = data.text || "Sem resposta.";
  } catch(e) {
    out.textContent = "Falha ao consultar Hermes AI: " + String(e.message || e) +
      "\n\nConfigure sua chave de API do Hermes/OpenRouter em ConfiguraÃ§Ãµes â†’ Threat Intelligence.";
  } finally {
    if (btn) btn.disabled = false;
  }
}

function toggleFindGroupHosts(elId) {
  const el = document.getElementById(elId);
  const arrow = document.getElementById(elId+"-arr");
  if (!el) return;
  const isHidden = el.style.display === "none";
  el.style.display = isHidden ? "block" : "none";
  if (arrow) arrow.textContent = isHidden ? "â–´" : "â–¾";
}

// â”€â”€ HTTP Evidence panel â€” Burp Suite style â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const _httpCopyTexts = {};

function _copyHttpPanel(id) {
  const text = _httpCopyTexts[id] || "";
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById("hcopy-" + id);
    if (!btn) return;
    btn.textContent = "âœ“ Copied";
    btn.classList.add("copied");
    setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 1800);
  }).catch(() => {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.cssText = "position:fixed;opacity:0;top:0;left:0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
  });
}

function _httpHighlight(rawText, matched) {
  if (!rawText) return "";
  // 1. Escape HTML entities first
  let t = rawText
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  // 2. Highlight HTTP request line: METHOD path HTTP/x.x
  t = t.replace(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)(\s)/m,
    '<span class="http-method">$1</span>$2');
  // 3. Highlight HTTP/x.x version token
  t = t.replace(/(HTTP\/[12](?:\.[01])?)/g, '<span class="http-ver">$1</span>');
  // 4. Colour status code by class
  t = t.replace(/\b([2][0-9]{2})\b/, '<span class="http-status-2">$1</span>');
  t = t.replace(/\b([3][0-9]{2})\b/, '<span class="http-status-3">$1</span>');
  t = t.replace(/\b([4][0-9]{2})\b/, '<span class="http-status-4">$1</span>');
  t = t.replace(/\b([5][0-9]{2})\b/, '<span class="http-status-5">$1</span>');
  // 5. Highlight header names: "Name:" at start of line
  t = t.replace(/^([A-Za-z][A-Za-z0-9_\-]+):/gm,
    '<span class="http-hdr-name">$1</span>:');
  // 6. Highlight matched value (injected/reflected payload)
  if (matched) {
    const safe = matched.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    t = t.replace(new RegExp(safe, 'gi'), '<span class="http-match">$&</span>');
  }
  return t;
}

function _renderHttpEvidence(findings) {
  const instances = (findings || [])
    .filter(f => f.request_raw || f.response_raw)
    .slice(0, 5);
  if (!instances.length) return "";

  const blocks = instances.map((f, i) => {
    const reqHtml  = _httpHighlight(f.request_raw  || "", f.matched || "");
    const respHtml = _httpHighlight(f.response_raw || "", f.matched || "");
    const hostTag  = instances.length > 1
      ? `<code style="font-size:.62rem;background:rgba(255,255,255,.07);padding:1px 6px;border-radius:4px;margin-left:6px;color:var(--text2)">${esc(f.host||"")}</code>` : "";
    const uid = Date.now().toString(36) + i;
    const reqId  = "req-"  + uid;
    const respId = "resp-" + uid;
    _httpCopyTexts[reqId]  = f.request_raw  || "";
    _httpCopyTexts[respId] = f.response_raw || "";
    return `
      <div style="margin-bottom:${i < instances.length-1 ? '10' : '0'}px">
        ${hostTag ? `<div style="font-size:.62rem;color:var(--text3);margin-bottom:4px">Instance ${i+1}${hostTag}</div>` : ""}
        <div class="http-panels">
          <div class="http-panel">
            <div class="http-panel-tab">
              <span>Request</span>
              <button id="hcopy-${reqId}" class="http-copy-btn" onclick="_copyHttpPanel('${reqId}')">Copy</button>
            </div>
            <pre class="http-pre">${reqHtml || '<span style="color:#484f58">â€”</span>'}</pre>
          </div>
          <div class="http-panel">
            <div class="http-panel-tab">
              <span>Response</span>
              <button id="hcopy-${respId}" class="http-copy-btn" onclick="_copyHttpPanel('${respId}')">Copy</button>
            </div>
            <pre class="http-pre">${respHtml || '<span style="color:#484f58">â€”</span>'}</pre>
          </div>
        </div>
      </div>`;
  }).join("");

  return `
    <div class="http-evidence">
      <div class="http-evidence-hdr">ðŸ“¡ HTTP Evidence</div>
      ${blocks}
    </div>`;
}

function _hashId() { return [...arguments].join("|").split("").reduce((a,c)=>((a<<5)-a)+c.charCodeAt(0)|0,0).toString(36); }

function exportFindings(cid, fmt) {
  const co = allCompanies().find(c=>c.id===cid);
  if(!co) return;
  const findings = _confirmedVulnFindings(co.findings||[]);
  const ts = new Date().toISOString().slice(0,10);
  if(fmt === "json") {
    _downloadBlob(JSON.stringify(findings, null, 2), `${cid}_findings_${ts}.json`, "application/json");
  } else {
    const header = "severity,name,host,url,category,module,description\n";
    const rows = findings.map(f => [
      f.severity||"", f.title||f.name||"", f.host||"", f.url||"", f.category||"", f.module||"",
      (f.desc||f.description||"").replace(/"/g,"'").replace(/\n/g," ")
    ].map(v=>`"${v}"`).join(",")).join("\n");
    _downloadBlob(header + rows, `${cid}_findings_${ts}.csv`, "text/csv");
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  CVE TAB
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
let _cveFilter = "", _cveSevFilter = "", _cveProductFilter = "";

var _cveKevOnly = false;

function renderCveTab(co) {
  window._coForCve = co;
  const el = document.getElementById("tab-cve");
  const findings = (co.cve_findings || []).filter(f => f.cve_id && f.severity !== "info");
  const summary  = co.cve_summary  || {};

  if (!findings.length) {
    el.innerHTML = `
      <div class="empty-state"><div class="empty-state-icon">ðŸ’¥</div><div class="empty-state-title">No CVE data yet</div><div class="empty-state-copy">Run the pipeline. The CVE module uses NVD CPE virtualMatchString queries for precise product:version matching, then enriches results with EPSS exploit probability and CISA KEV flags.</div></div>`;
    return;
  }

  const products  = [...new Set(findings.map(f => f.product).filter(Boolean))].sort();
  const kevCount  = summary.kev       || findings.filter(f => f.kev).length;
  const epssHigh  = summary.epss_high || findings.filter(f => (f.epss||0) >= 0.1).length;

  const summaryBar = `
    <div style="display:flex;gap:10px;flex-wrap:wrap;padding:14px 0 10px;align-items:center">
      ${_cardKPI({ cls: "c", value: summary.critical||0, label: "Critical" })}
      ${_cardKPI({ cls: "h", value: summary.high||0, label: "High" })}
      ${_cardKPI({ cls: "m", value: summary.medium||0, label: "Medium" })}
      ${_cardKPI({ value: summary.low||0, label: "Low" })}
      ${_cardKPI({ value: kevCount, label: "KEV", note: "Listed in CISA KEV" })}
      ${_cardKPI({ value: epssHigh, label: "EPSSâ‰¥10%", note: "Exploit probability threshold" })}
      ${_cardKPI({ value: findings.length, label: "Total" })}
      <div style="margin-left:auto;font-size:.68rem;color:var(--text3);max-width:320px;line-height:1.5;background:rgba(96,165,250,0.06);border:1px solid rgba(96,165,250,0.15);border-radius:8px;padding:8px 12px">
        <b style="color:var(--blue)">Precision matching</b><br>
        CPE <code>virtualMatchString</code> queries return only CVEs where the exact product:version is in affected configurations â€” not keyword mentions.
        Results enriched with <b style="color:#a855f7">EPSS</b> (exploit probability) and <b style="color:#f43f5e">CISA KEV</b> (active exploitation) flags.
      </div>
    </div>`;

  el.innerHTML = `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">CVEs</div>
          <div class="section-title">Known vulnerabilities matched against detected technologies</div>
          <div class="section-sub">CPE-precise matching. KEV and EPSS enriched. Sorted by active exploitation risk.</div>
        </div>
      </div>
      ${summaryBar}
      <div class="filter-bar">
      <input type="text" class="fi grow" id="cve-search" placeholder="Search CVE ID, product, host, description..."
             oninput="_cveFilter=this.value;applyCveFilter()">
      <select class="fi" id="cve-sev" onchange="_cveSevFilter=this.value;applyCveFilter()">
        <option value="">All severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <select class="fi" id="cve-product" onchange="_cveProductFilter=this.value;applyCveFilter()">
        <option value="">All products</option>
        ${products.map(p=>`<option value="${esc(p)}">${esc(p)}</option>`).join("")}
      </select>
      <label style="display:flex;align-items:center;gap:5px;font-size:.7rem;color:var(--text2);white-space:nowrap;cursor:pointer">
        <input type="checkbox" id="cve-kev-only" onchange="_cveKevOnly=this.checked;applyCveFilter()"> KEV only
      </label>
      <span style="font-size:.68rem;color:var(--text3);padding:6px 4px" id="cve-cnt"></span>
      <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px;margin-left:auto"
              onclick="exportCveCsv()" title="Export CSV">â¬‡ CSV</button>
      </div>
      <div class="table-shell">
        <div class="table-topline">
          <div class="table-title">Matched CVEs</div>
          <div class="table-note">Sorted by active exploitation risk: CISA KEV first, then EPSS Ã— CVSS descending.</div>
        </div>
      <table id="cve-table">
        <thead><tr>
          <th style="width:100px">Severity</th>
          <th style="width:150px">CVE ID</th>
          <th style="width:190px">Product / Version</th>
          <th style="width:60px;text-align:center">CVSS</th>
          <th style="width:70px;text-align:center" title="EPSS: probability this CVE will be exploited in the next 30 days (FIRST.org)">EPSS</th>
          <th>Description</th>
          <th style="width:180px">Detected On</th>
          <th style="width:90px">Published</th>
        </tr></thead>
        <tbody id="cve-tbody"></tbody>
      </table>
      </div>
    </div>`;

  applyCveFilter();
}

function _cveSevColor(sev) {
  switch((sev||"").toLowerCase()) {
    case "critical": return "#fb7185";
    case "high":     return "#fb923c";
    case "medium":   return "#fbbf24";
    case "low":      return "#4ade80";
    default:         return "var(--text3)";
  }
}

function applyCveFilter() {
  const co = window._coForCve; if (!co) return;
  const q    = (_cveFilter||"").toLowerCase();
  const sev  = _cveSevFilter||"";
  const prod = _cveProductFilter||"";
  const kevOnly = !!_cveKevOnly;
  const findings = (co.cve_findings||[]).filter(f => {
    if (!f.cve_id || f.severity === "info") return false;
    if (kevOnly && !f.kev) return false;
    const hostsStr = (f.affected_hosts||[]).join(" ");
    const ms = !q || [f.cve_id,f.product,f.desc,hostsStr].join(" ").toLowerCase().includes(q);
    const ss = !sev  || (f.severity||"").toLowerCase() === sev;
    const ps = !prod || f.product === prod;
    return ms && ss && ps;
  });
  const cnt = document.getElementById("cve-cnt");
  if (cnt) cnt.textContent = findings.length + " CVEs";
  const tbody = document.getElementById("cve-tbody");
  if (!tbody) return;
  tbody.innerHTML = findings.map(f => {
    const sevColor  = _cveSevColor(f.severity);
    const sevLabel  = (f.severity||"medium").toLowerCase();
    const score     = f.score != null ? f.score.toFixed(1) : "â€”";
    const desc      = (f.desc||"").length > 120 ? esc(f.desc.slice(0,120))+"â€¦" : esc(f.desc||"");
    const pub       = f.published ? f.published.slice(0,10) : "â€”";
    const detVer    = f.detected_version
      ? `<span style="font-size:.65rem;color:var(--teal);font-family:monospace;display:block">${esc(f.detected_version)}</span>`
      : `<span style="font-size:.62rem;color:var(--text3);display:block">no version detected</span>`;
    const kevBadge  = f.kev
      ? `<span style="display:inline-block;font-size:.55rem;font-weight:700;letter-spacing:.04em;background:rgba(244,63,94,0.18);color:#f43f5e;border:1px solid rgba(244,63,94,0.4);border-radius:3px;padding:1px 5px;margin-left:4px;vertical-align:middle">EXPLOITED</span>`
      : "";
    const cveLink   = f.url
      ? `<a href="${esc(f.url)}" target="_blank" rel="noopener"
            style="color:var(--teal);font-family:monospace;font-size:.8rem;white-space:nowrap">${esc(f.cve_id)}</a>${kevBadge}`
      : `<span style="font-family:monospace;font-size:.8rem">${esc(f.cve_id||"")}</span>${kevBadge}`;
    const epssVal   = (f.epss != null && f.epss > 0)
      ? f.epss
      : null;
    const epssColor = epssVal === null ? "var(--text3)"
      : epssVal >= 0.5 ? "#f43f5e"
      : epssVal >= 0.1 ? "#fb923c"
      : epssVal >= 0.01 ? "#fbbf24"
      : "var(--text3)";
    const epssHtml  = epssVal !== null
      ? `<span style="font-family:monospace;font-size:.78rem;font-weight:600;color:${epssColor}">${(epssVal*100).toFixed(1)}%</span>`
      : `<span style="font-size:.68rem;color:var(--text3)">â€”</span>`;
    const affHosts  = (f.affected_hosts||[]);
    const hostsHtml = affHosts.length
      ? affHosts.slice(0,3).map(h=>`<span style="display:block;font-size:.62rem;color:var(--text2);font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:170px" title="${esc(h)}">${esc(h)}</span>`).join("")
        + (affHosts.length > 3 ? `<span style="font-size:.6rem;color:var(--text3)">+${affHosts.length-3} more</span>` : "")
      : `<span style="font-size:.62rem;color:var(--text3)">â€”</span>`;
    return `<tr${f.kev ? ' style="background:rgba(244,63,94,0.04)"' : ''}>
      <td><span class="cc-risk-badge ${sevLabel}">${esc(sevLabel)}</span></td>
      <td>${cveLink}</td>
      <td style="font-size:.78rem;color:var(--text2)">${esc(f.product||"")}${detVer}</td>
      <td style="text-align:center;font-weight:700;font-size:.85rem;color:${sevColor}">${score}</td>
      <td style="text-align:center">${epssHtml}</td>
      <td style="font-size:.73rem;color:var(--text3);max-width:340px">${desc}</td>
      <td>${hostsHtml}</td>
      <td style="font-size:.72rem;color:var(--text3)">${pub}</td>
    </tr>`;
  }).join("");
  if (!findings.length) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text3)">No CVEs match the current filters.</td></tr>`;
  }
}

function exportCveCsv() {
  const co = window._coForCve; if (!co) return;
  const rows = [["CVE ID","Product","Detected Version","Severity","CVSS Score","EPSS %","CISA KEV","Affected Hosts","Published","Description","URL"]];
  (co.cve_findings||[]).filter(f=>f.cve_id && f.severity!=="info").forEach(f => {
    rows.push([
      f.cve_id||"", f.product||"", f.detected_version||"", f.severity||"",
      f.score!=null?f.score:"",
      f.epss!=null?(f.epss*100).toFixed(2)+"":"",
      f.kev?"YES":"",
      (f.affected_hosts||[]).join("; "),
      f.published||"", (f.desc||"").replace(/"/g,"'"), f.url||""
    ]);
  });
  const csv = rows.map(r=>r.map(v=>`"${v}"`).join(",")).join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv],{type:"text/csv"}));
  a.download = `${co.id}_cves.csv`;
  a.click();
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  SUPPLY CHAIN TAB â€” JS library CVEs
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

function renderSupplyChainTab(co) {
  const el = document.getElementById("tab-supplychain");
  const findings = (co.supply_chain_findings || []).filter(f => f.cve_id);
  const summary  = co.supply_chain_summary || {};

  if (!findings.length) {
    el.innerHTML = `
      <div class="empty-state"><div class="empty-state-icon">ðŸ“¦</div><div class="empty-state-title">No supply chain CVEs yet</div><div class="empty-state-copy">Run the pipeline. The Supply Chain module scans JS libraries detected by whatweb/wappalyzer across all hosts and cross-references each library@version against the NVD database.</div></div>`;
    return;
  }

  // Count unique libraries
  const libsMap = {};
  findings.forEach(f => {
    const key = f.library || 'unknown';
    if (!libsMap[key]) libsMap[key] = { name: key, version: f.version || '?', count: 0, critical: 0 };
    libsMap[key].count++;
    if (f.severity === 'critical') libsMap[key].critical++;
  });
  const libsList = Object.values(libsMap).sort((a,b) => b.count - a.count);

  const summaryBar = `
    <div style="display:flex;gap:10px;flex-wrap:wrap;padding:14px 0 10px;align-items:center">
      ${_severityCard("critical", summary.critical||0)}
      ${_severityCard("high", summary.high||0)}
      ${_severityCard("medium", summary.medium||0)}
      ${_severityCard("info", summary.low||0)}
      <div style="margin-left:auto;font-size:.68rem;color:var(--text3);max-width:340px;line-height:1.5;background:rgba(96,165,250,0.06);border:1px solid rgba(96,165,250,0.15);border-radius:8px;padding:8px 12px">
        <b style="color:var(--blue)">How it works</b><br>
        JS libraries detected via Wappalyzer/WhatWeb across all hosts.
        Each library@version is queried against the NVD database.
        Only client-side (JS/frontend) libraries are scanned â€” server frameworks excluded.
      </div>
    </div>`;

  // Detected JS libraries panel (raw, from supply_chain_libs)
  const rawLibs = co.supply_chain_libs || [];
  const rawLibsPanel = rawLibs.length ? `
    <div style="margin-bottom:16px">
      <div style="font-size:.68rem;color:var(--text3);margin-bottom:7px;text-transform:uppercase;letter-spacing:.06em">Bibliotecas JS detectadas (${rawLibs.length})</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        ${rawLibs.map(l => {
          const at = l.lastIndexOf('@');
          const name = at > 0 ? l.slice(0, at) : l;
          const ver  = at > 0 ? l.slice(at+1) : '';
          return `<span style="background:var(--card);border:1px solid var(--border);border-radius:5px;padding:3px 9px;font-size:.7rem;font-family:var(--mono)"><b style="color:var(--text)">${esc(name)}</b>${ver?`<span style="color:var(--text3)">@${esc(ver)}</span>`:''}</span>`;
        }).join('')}
      </div>
    </div>` : '';

  // Libraries panel (CVE-linked)
  const libsPanel = `
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">
      ${libsList.map(l => `
        <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px 12px;display:flex;align-items:center;gap:8px;font-size:.72rem">
          <b style="color:var(--text)">${esc(l.name)}</b>
          <span style="color:var(--text3)">${esc(l.version)}</span>
          <span style="background:var(--bg);padding:2px 6px;border-radius:4px;color:var(--text2)">${l.count} CVEs</span>
          ${l.critical > 0 ? '<span style="color:#ef4444;font-weight:700">' + l.critical + ' crit</span>' : ''}
        </div>
      `).join("")}
    </div>`;

  // Table of CVEs
  const sevColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6' };
  const rows = findings.map(f => `
    <tr>
      <td style="white-space:nowrap"><a href="${esc(f.url||'#')}" target="_blank" rel="noopener" style="color:${sevColors[f.severity]||'#6b7280'};font-weight:600;font-size:.75rem">${esc(f.cve_id||'')}</a></td>
      <td><span style="font-size:.7rem;font-weight:600;color:var(--text)">${esc(f.library||'')}</span> <span style="font-size:.65rem;color:var(--text3)">${esc(f.version||'')}</span></td>
      <td style="text-align:center"><span style="display:inline-block;padding:2px 8px;border-radius:12px;font-size:.65rem;font-weight:700;background:rgba(${f.severity==='critical'?'244,63,94':f.severity==='high'?'251,146,60':f.severity==='medium'?'251,191,36':'59,130,246'},0.12);color:${sevColors[f.severity]||'#6b7280'}">${(f.score||'').toString()}</span></td>
      <td style="font-size:.68rem;color:var(--text2);max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc((f.desc||'').substring(0,150))}</td>
      <td style="font-size:.65rem;color:var(--text3)">${esc(f.published||'')}</td>
      <td style="font-size:.65rem;color:var(--text3)">${esc((f.affected_hosts||[]).slice(0,3).join(', '))}</td>
    </tr>`).join("");

  el.innerHTML = `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">Supply Chain</div>
          <div class="section-title">Client-side JS library vulnerabilities from the NVD</div>
          <div class="section-sub">These CVEs affect JavaScript/frontend libraries detected on your assets. Each finding is linked to the library version running on specific hosts.</div>
        </div>
      </div>
      ${summaryBar}
      ${rawLibsPanel}
      ${libsPanel}
      <div class="tbl-wrap">
        <table class="tbl tbd-striped">
          <thead>
            <tr>
              <th style="width:140px">CVE</th>
              <th style="width:170px">Library</th>
              <th style="width:60px;text-align:center">Score</th>
              <th>Description</th>
              <th style="width:80px">Published</th>
              <th style="width:160px">Hosts</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  HOSTS TAB
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
let _co_hosts = [], _hosts_page = 1, _hosts_sort = "host", _hosts_asc = true;
const HPP = 30;

function renderHostsTab(co) {
  document.getElementById("tab-hosts").innerHTML = `
    <div id="playwright-host-inventory" style="margin-bottom:12px"></div>
    <div class="filter-bar">
      <input type="text" class="fi grow" id="h-search" placeholder="Search host, IP, technology..." oninput="applyHostFilter()">
      <select class="fi" id="h-waf" onchange="applyHostFilter()">
        <option value="">All WAF/CDN</option>
        <option value="Imperva">Imperva</option>
        <option value="Cloudflare">Cloudflare</option>
        <option value="AWS">AWS CloudFront</option>
        <option value="Google">Google Cloud</option>
        <option value="Direct">Direct (no WAF)</option>
        <option value="Firewalled">Direct (Firewall)</option>
      </select>
      <select class="fi" id="h-status" onchange="applyHostFilter()">
        <option value="">All hosts</option>
        <option value="active">With open ports</option>
        <option value="inactive">No ports mapped</option>
      </select>
      <span style="font-size:.68rem;color:var(--text3);padding:6px 4px;" id="h-cnt"></span>
      <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px;margin-left:auto"
              onclick="exportHosts('csv')" title="Export CSV">â¬‡ CSV</button>
      <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px"
              onclick="exportHosts('json')" title="Export JSON">â¬‡ JSON</button>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead><tr>
          <th onclick="sortHosts('host')">Host â†•</th>
          <th onclick="sortHosts('ip')">IP Address â†•</th>
          <th>Title</th>
          <th>WAF / CDN</th>
          <th>Technologies</th>
          <th>Open Ports</th>
          <th style="width:66px">Shot</th>
        </tr></thead>
        <tbody id="h-tbody"></tbody>
      </table>
      <div class="pager">
        <span class="pager-info" id="h-pinfo"></span>
        <div class="pager-btns">
          <button class="pb" id="h-prev" onclick="hostsPageNav(-1)">â† Prev</button>
          <span id="h-pnums"></span>
          <button class="pb" id="h-next" onclick="hostsPageNav(1)">Next â†’</button>
        </div>
      </div>
    </div>`;
  _co_hosts = [...(co.hosts||[])];
  _hosts_page = 1;
  applyHostFilter();
  renderPlaywrightHostInventoryTab(co);
}

async function renderPlaywrightHostInventoryTab(co) {
  const mount = document.getElementById("playwright-host-inventory");
  if (!mount || !co?.id) return;
  mount.innerHTML = `
    <div class="job-detail-card">
      <div class="job-detail-title">Playwright Host Inventory</div>
      <div class="job-detail-copy">Loading browser-discovered hosts...</div>
    </div>
  `;
  try {
    const r = await fetch(`/api/jobs?company_id=${encodeURIComponent(co.id)}&limit=20`, {headers:_authHeaders()});
    if (!r.ok) throw new Error("HTTP " + r.status);
    const jobs = await r.json();
    const job = (jobs || []).find(j => j.job_type === "playwright_recon");
    if (!job) {
      mount.innerHTML = `
        <div class="job-detail-card">
          <div class="job-detail-title">Playwright Host Inventory</div>
          <div class="job-detail-copy">No Playwright run found for this company yet.</div>
        </div>
      `;
      return;
    }
    const sessionResp = await fetch(_jobArtifactUrl(job.id, "session"), {headers:_authHeaders()});
    if (!sessionResp.ok) {
      mount.innerHTML = `
        <div class="job-detail-card">
          <div class="job-detail-title">Playwright Host Inventory</div>
          <div class="job-detail-copy">Host inventory not available yet.</div>
        </div>
      `;
      return;
    }
    const session = await sessionResp.json();
    mount.innerHTML = `
      <div class="job-detail-card">
        <div class="job-detail-head">
          <div>
            <div class="job-detail-title">Playwright Host Inventory</div>
            <div class="job-detail-copy">${esc(job.id)} Â· ${esc(job.status || "â€”")} Â· ${esc(job.created_at || "â€”")}</div>
          </div>
          <div class="job-actions">
            <button class="btn btn-secondary btn-icon" onclick="openJobDetail(${_jsArg(job.id)})">Details</button>
            ${job.status === "done" ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'session')}" target="_blank" rel="noopener">Session</a>` : ""}
          </div>
        </div>
        ${_playwrightInventorySummary(session)}
      </div>
    `;
  } catch(e) {
    mount.innerHTML = `
      <div class="job-detail-card">
        <div class="job-detail-title">Playwright Host Inventory</div>
        <div class="job-detail-copy">Failed to load host inventory: ${esc(e.message)}</div>
      </div>
    `;
  }
}

function applyHostFilter() {
  const q  = document.getElementById("h-search")?.value.toLowerCase()||"";
  const wf = document.getElementById("h-waf")?.value||"";
  const st = document.getElementById("h-status")?.value||"";
  const filtered = _co_hosts.filter(h=>{
    const ms = !q || (h.host||"").includes(q)||(h.ip||"").includes(q)||(h.technologies||[]).join(",").toLowerCase().includes(q);
    return ms && (!wf||(h.waf||"").includes(wf)) &&
      (!st||(st==="active"&&(h.ports||[]).length>0)||(st==="inactive"&&(h.ports||[]).length===0));
  });
  _hosts_page = 1;
  renderHostsTable(filtered);
}

function sortHosts(key) {
  if(_hosts_sort===key) _hosts_asc=!_hosts_asc; else {_hosts_sort=key;_hosts_asc=true;}
  _co_hosts.sort((a,b)=>{ const av=(a[key]||"").toLowerCase(),bv=(b[key]||"").toLowerCase(); return _hosts_asc?av.localeCompare(bv):bv.localeCompare(av); });
  applyHostFilter();
}

function hostsPageNav(d) {
  const q=document.getElementById("h-search")?.value.toLowerCase()||"";
  const wf=document.getElementById("h-waf")?.value||"";
  const st=document.getElementById("h-status")?.value||"";
  const filtered=_co_hosts.filter(h=>{
    const ms=!q||(h.host||"").includes(q)||(h.ip||"").includes(q);
    return ms&&(!wf||(h.waf||"").includes(wf))&&(!st||(st==="active"&&(h.ports||[]).length>0)||(st==="inactive"&&(h.ports||[]).length===0));
  });
  const totPg=Math.ceil(filtered.length/HPP);
  _hosts_page=Math.max(1,Math.min(totPg,_hosts_page+d));
  renderHostsTable(filtered);
}

function hostsGoPage(p) { _hosts_page=p; hostsPageNav(0); }

function renderHostsTable(filtered) {
  const tot=filtered.length, totPg=Math.ceil(tot/HPP);
  const st=(_hosts_page-1)*HPP, pg=filtered.slice(st,st+HPP);
  const cnt=document.getElementById("h-cnt"); if(cnt) cnt.textContent=tot+" hosts";
  const pi=document.getElementById("h-pinfo"); if(pi) pi.textContent=`${st+1}â€“${Math.min(st+HPP,tot)} of ${tot}`;
  const pr=document.getElementById("h-prev"); if(pr) pr.disabled=_hosts_page<=1;
  const nx=document.getElementById("h-next"); if(nx) nx.disabled=_hosts_page>=totPg;
  let pn="";
  for(let i=Math.max(1,_hosts_page-2);i<=Math.min(totPg,_hosts_page+2);i++)
    pn+=`<button class="pb${i===_hosts_page?" active":""}" onclick="hostsGoPage(${i})">${i}</button>`;
  const pne=document.getElementById("h-pnums"); if(pne) pne.innerHTML=pn;
  const tb=document.getElementById("h-tbody"); if(!tb) return;
  tb.innerHTML = pg.map(h=>_hostTableRow(h)).join("");
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  PORTS TAB
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
let _co_ports = [], _ports_page = 1;
const PPP = 25;

function renderPortsTab(co) {
  const ps = co.port_scan || {};
  const highRiskRows = _filteredHighRiskPorts(ps.high_risk || []);
  const scanSummary = (ps.tool || ps.ips_scanned) ? (() => {
    const tool      = ps.tool || "nmap";
    const scanned   = ps.ips_scanned || 0;
    const skipped   = ps.waf_ips_skipped || 0;
    const highRisk  = highRiskRows.length;
    const scanDate  = ps.scanned_at ? ps.scanned_at.replace("T"," ").slice(0,16) : "";
    return `
      <div class="jobs-summary" style="margin-bottom:12px">
        ${_portSummaryCard("Tool", tool)}
        ${_portSummaryCard("IPs scanned", scanned)}
        ${skipped ? _portSummaryCard("WAF IPs skipped", skipped, "") : ""}
        ${highRisk ? _portSummaryCard("High-risk ports", highRisk, "error") : ""}
        ${scanDate ? `<div class="job-kpi" style="grid-column:1/-1"><div class="job-kpi-label">Scanned</div><div class="job-detail-v" style="margin-top:4px">${esc(scanDate)}</div></div>` : ""}
      </div>`;
  })() : "";

  const highRiskPanel = highRiskRows.length ? (() => {
    const rows = highRiskRows.map(h => _portRiskRow(h)).join('');
    return `<div style="background:rgba(244,63,94,0.05);border:1px solid rgba(244,63,94,0.25);border-radius:7px;margin-bottom:12px;overflow:hidden">
      <div style="padding:8px 12px;font-size:.72rem;font-weight:700;color:#f43f5e;border-bottom:1px solid rgba(244,63,94,0.2)">âš  Portas de Alto Risco (${highRiskRows.length})</div>
      ${rows}
    </div>`;
  })() : "";

  document.getElementById("tab-ports").innerHTML = `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">Ports</div>
          <div class="section-title">Open service exposure by host</div>
          <div class="section-sub">Use this view to spot concentration of exposed services and quickly pivot by host, IP or common ports.</div>
        </div>
      </div>
      ${scanSummary}
      ${highRiskPanel}
      <div class="filter-bar">
      <input type="text" class="fi grow" id="p-search" placeholder="Search host or IP..." oninput="applyPortFilter()">
      <select class="fi" id="p-port" onchange="applyPortFilter()">
        <option value="">All ports</option>
        <option value="80">80 (HTTP)</option>
        <option value="443">443 (HTTPS)</option>
        <option value="8080">8080</option>
        <option value="8443">8443</option>
        <option value="3000">3000</option>
        <option value="5000">5000</option>
        <option value="9000">9000</option>
      </select>
      <span style="font-size:.68rem;color:var(--text3);padding:6px 4px;" id="p-cnt"></span>
      </div>
      <div class="table-shell">
        <div class="table-topline">
          <div class="table-title">Hosts with exposed ports</div>
          <div class="table-note">Sorted visually by host row; count column highlights concentration.</div>
        </div>
      <table>
        <thead><tr><th>Host</th><th>IP Address</th><th>WAF / CDN</th><th>Open Ports</th><th>#</th><th style="width:40px"></th></tr></thead>
        <tbody id="p-tbody"></tbody>
      </table>
      <div class="pager">
        <span class="pager-info" id="p-pinfo"></span>
        <div class="pager-btns">
          <button class="pb" onclick="portsPageNav(-1)">â† Prev</button>
          <span id="p-pnums"></span>
          <button class="pb" onclick="portsPageNav(1)">Next â†’</button>
        </div>
      </div>
      </div>
    </div>`;
  _co_ports = (co.hosts||[]).filter(h=>(h.ports||[]).length>0);
  _ports_page = 1;
  applyPortFilter();
}

function applyPortFilter() {
  const q  = document.getElementById("p-search")?.value.toLowerCase()||"";
  const pt = document.getElementById("p-port")?.value||"";
  const filtered = _co_ports.filter(h=>{
    return (!q||(h.host||"").includes(q)||(h.ip||"").includes(q)) && (!pt||(h.ports||[]).includes(pt));
  });
  _ports_page = 1;
  renderPortsTable(filtered);
}

function portsPageNav(d) {
  const q=document.getElementById("p-search")?.value.toLowerCase()||"";
  const pt=document.getElementById("p-port")?.value||"";
  const filtered=_co_ports.filter(h=>(!q||(h.host||"").includes(q)||(h.ip||"").includes(q))&&(!pt||(h.ports||[]).includes(pt)));
  const totPg=Math.ceil(filtered.length/PPP);
  _ports_page=Math.max(1,Math.min(totPg,_ports_page+d));
  renderPortsTable(filtered);
}

function portsGoPage(p){_ports_page=p;portsPageNav(0);}

function renderPortsTable(filtered) {
  const tot=filtered.length, totPg=Math.ceil(tot/PPP);
  const st=(_ports_page-1)*PPP, pg=filtered.slice(st,st+PPP);
  const cnt=document.getElementById("p-cnt"); if(cnt) cnt.textContent=tot+" hosts";
  const pi=document.getElementById("p-pinfo"); if(pi) pi.textContent=`${st+1}â€“${Math.min(st+PPP,tot)} of ${tot}`;
  let pn="";
  for(let i=Math.max(1,_ports_page-2);i<=Math.min(totPg,_ports_page+2);i++)
    pn+=`<button class="pb${i===_ports_page?" active":""}" onclick="portsGoPage(${i})">${i}</button>`;
  const pne=document.getElementById("p-pnums"); if(pne) pne.innerHTML=pn;
  const tb=document.getElementById("p-tbody"); if(!tb) return;
  tb.innerHTML=pg.map(h=>{
    const portDetails = h.port_details || [];
    const portMap = Object.fromEntries(portDetails.map(pd => [pd.port, pd]));
    const cloudLabel = h.cloud_provider ? ` <span class="waf-t" style="background:rgba(96,165,250,0.1);color:#60a5fa;border:1px solid rgba(96,165,250,0.2)">â˜ ${esc(h.cloud_provider)}</span>` : '';
    return `
    <tr class="clickable-host" onclick="openHostDrawer('${escAttr(h.host)}')">
      <td>
        <div class="host-cell">
          <a class="host-main" href="https://${h.host}" target="_blank">${esc(h.host)}</a>
          <span class="host-sub">${(h.title && esc(h.title)) || "Primary exposed host"}</span>
        </div>
      </td>
      <td><span class="ip-t">${esc(h.ip)}</span></td>
      <td><span class="waf-t ${wafClass(h.waf)}">${esc(h.waf)}</span>${cloudLabel}</td>
      <td><div class="badge-row">${(h.ports||[]).map(p=>{
        if (portMap[p]) return `<span class="port-c" title="${esc(portMap[p].category||'')}">${esc(p)}:${esc(portMap[p].service||'')}</span>`;
        return `<span class="port-c">${esc(p)}</span>`;
      }).join("")}</div></td>
      <td><span class="muted-kpi">${(h.ports||[]).length}</span></td>
      <td><button class="url-copy-btn" onclick="copyToClipboard('${escAttr(h.host)}');event.stopPropagation()" title="Copy hostname" style="font-size:.6rem;padding:2px 5px">ðŸ“‹</button></td>
    </tr>`;
  }).join("");
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  SUBDOMAINS TAB
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const ADMIN_PORT_LABELS = {
  "21":"FTP","22":"SSH","23":"Telnet","25":"SMTP","3306":"MySQL","5432":"PG",
  "6379":"Redis","27017":"Mongo","9200":"ES","2082":"cPanel","2083":"cPanel SSL",
  "2086":"WHM","2087":"WHM SSL","2095":"Webmail","2096":"Webmail SSL",
  "8080":"HTTP Alt","8443":"HTTPS Alt","8880":"HTTP Alt",
};
const WEB_PORTS = new Set(["80", "443", "8000", "8008", "8080", "8081", "8088", "8443", "8880"]);
const HIGH_RISK_PORT_LABELS = {
  "21":"FTP â€” plaintext file transfer",
  "22":"SSH",
  "23":"Telnet â€” plaintext shell",
  "25":"SMTP",
  "110":"POP3 â€” plaintext email",
  "143":"IMAP â€” plaintext email",
  "3306":"MySQL",
  "5432":"PostgreSQL",
  "6379":"Redis",
  "27017":"MongoDB",
  "9200":"Elasticsearch",
  "2082":"cPanel",
  "2083":"cPanel SSL",
  "2086":"WHM",
  "2087":"WHM SSL",
  "2095":"Webmail",
  "2096":"Webmail SSL",
};

let _sub_hosts = [], _sub_page = 1;
const SUB_PER_PAGE = 50;

// Domains tab: cap how many domain cards render at once. Companies can have
// tens of thousands of scope domains; rendering one card each froze the UI.
const DOM_CARD_LIMIT = 50;
let _domBuckets = [], _domQuery = "";

function _normalizeScopeDomain(raw) {
  return String(raw || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/^\*\./, "")
    .replace(/\.$/, "")
    .toLowerCase();
}

function _buildSubdomainInventory(co, rows = []) {
  const merged = new Map();
  const techByHost = new Map();
  Object.entries(co.tech_index || {}).forEach(([tech, hosts]) => {
    (hosts || []).forEach(h => {
      const host = _normalizeScopeDomain(h);
      if (!host) return;
      if (!techByHost.has(host)) techByHost.set(host, new Set());
      techByHost.get(host).add(tech);
    });
  });

  const addHost = (item, source = "") => {
    if (!item) return;
    const host = _normalizeScopeDomain(item.host || item.subdomain || item.domain || "");
    if (!host) return;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return;
    const existing = merged.get(host) || {
      host,
      ip: item.ip || "",
      status_code: item.status_code,
      content_length: item.content_length,
      ports: Array.isArray(item.ports) ? item.ports.slice() : [],
      port_details: Array.isArray(item.port_details) ? item.port_details.slice() : [],
      waf: item.waf || "Direct",
      cloud_provider: item.cloud_provider || "",
      cert_info: item.cert_info || null,
      technologies: Array.isArray(item.technologies) ? item.technologies.slice() : [],
      title: item.title || "",
      screenshot: item.screenshot || (co._screenshotsByHost && co._screenshotsByHost.get(host)) || "",
      risk: item.risk || item.risk_level || item.severity || "",
      sources: [],
    };
    if (!existing.ip && item.ip) existing.ip = item.ip;
    if (existing.status_code == null && item.status_code != null) existing.status_code = item.status_code;
    if (existing.content_length == null && item.content_length != null) existing.content_length = item.content_length;
    if (Array.isArray(item.ports)) {
      item.ports.forEach(p => { if (!existing.ports.includes(p)) existing.ports.push(p); });
    }
    if (Array.isArray(item.port_details)) {
      existing.port_details = existing.port_details || [];
      item.port_details.forEach(p => {
        const port = String(p.port || p || "");
        if (port && !existing.port_details.some(x => String(x.port || x || "") === port)) existing.port_details.push(p);
      });
    }
    if (Array.isArray(item.technologies)) {
      item.technologies.forEach(t => { if (!existing.technologies.includes(t)) existing.technologies.push(t); });
    }
    const techSet = techByHost.get(host);
    if (techSet) {
      techSet.forEach(t => { if (!existing.technologies.includes(t)) existing.technologies.push(t); });
    }
    if (!existing.title && item.title) existing.title = item.title;
    if (!existing.risk && (item.risk || item.risk_level || item.severity)) existing.risk = item.risk || item.risk_level || item.severity;
    if (!existing.waf && item.waf) existing.waf = item.waf;
    if (!existing.cloud_provider && item.cloud_provider) existing.cloud_provider = item.cloud_provider;
    if (!existing.cert_info && item.cert_info) existing.cert_info = item.cert_info;
    if (!existing.screenshot && item.screenshot) existing.screenshot = item.screenshot;
    if (!existing.screenshot && co._screenshotsByHost && co._screenshotsByHost.has(host)) {
      existing.screenshot = co._screenshotsByHost.get(host);
    }
    if (source && !existing.sources.includes(source)) existing.sources.push(source);
    merged.set(host, existing);
  };

  (co.hosts || []).forEach(h => addHost(h, h.status_code != null ? "validated" : "host"));
  (co.ct_subdomains || []).forEach(s => addHost(typeof s === "string" ? {host: s} : s, "ct"));
  (rows || []).forEach(s => addHost({host: s.subdomain, status_code: s.is_alive ? 200 : null}, s.source || "history"));

  return Array.from(merged.values()).sort((a, b) => a.host.localeCompare(b.host));
}

function _matchDomainForHost(host, domains, domainSet) {
  const h = _normalizeScopeDomain(host);
  if (!h) return "";
  // Fast path: O(labels) suffix lookup against a Set instead of scanning/sorting
  // every scope domain per host (companies can have tens of thousands of domains).
  if (domainSet) {
    if (domainSet.has(h)) return h;
    const parts = h.split(".");
    for (let i = 1; i < parts.length; i++) {     // most specific (longest) suffix first
      const cand = parts.slice(i).join(".");
      if (domainSet.has(cand)) return cand;
    }
    return "";
  }
  const ordered = [...domains].sort((a, b) => b.length - a.length);
  for (const domain of ordered) {
    if (h === domain || h.endsWith("." + domain)) return domain;
  }
  return "";
}

function _loadSubdomainHistory(co) {
  if (!co) return Promise.resolve([]);
  if (Array.isArray(co.subdomain_history)) return Promise.resolve(co.subdomain_history);
  if (co._subhistoryPromise) return co._subhistoryPromise;
  co._subhistoryPromise = fetch(`/api/data/${co.id}/subhistory`, {headers: _authHeaders()})
    .then(r => r.ok ? r.json() : Promise.reject(r))
    .then(data => Array.isArray(data.history) ? data.history : [])
    .catch(() => []);
  return co._subhistoryPromise;
}

function _isActiveHost(h) {
  const sc = Number(h && h.status_code);
  return Number.isFinite(sc) && sc > 0;
}

function _isHighRiskPort(port, service = "") {
  const p = String(port || "").trim();
  if (!p || WEB_PORTS.has(p)) return false;
  if (HIGH_RISK_PORT_LABELS[p]) return true;
  return /ssh|ftp|telnet|mysql|postgres|redis|mongo|elastic|imap|pop3|smtp|cpanel|whm|webmail/i.test(String(service || ""));
}

function _portServiceLabel(port, service = "") {
  const p = String(port || "").trim();
  if (HIGH_RISK_PORT_LABELS[p]) return HIGH_RISK_PORT_LABELS[p];
  if (service) return service;
  if (ADMIN_PORT_LABELS[p]) return ADMIN_PORT_LABELS[p];
  if (p === "80") return "HTTP";
  if (p === "443") return "HTTPS";
  return "";
}

function _hostOpenPorts(h) {
  const raw = Array.isArray(h?.ports) ? h.ports : [];
  const details = Array.isArray(h?.port_details) ? h.port_details : [];
  const byPort = new Map();
  raw.forEach(p => {
    const port = String(p || "").trim();
    if (port) byPort.set(port, {port, service: _portServiceLabel(port)});
  });
  details.forEach(item => {
    const port = String(item?.port || item || "").trim();
    if (!port) return;
    byPort.set(port, {
      port,
      service: _portServiceLabel(port, item?.service || item?.name || ""),
      category: item?.category || "",
    });
  });
  return [...byPort.values()].sort((a, b) => Number(a.port) - Number(b.port));
}

function _assetPendingCell(label = "Running") {
  return `<span class="ai-pending" title="Coleta em andamento">${esc(label)}</span>`;
}

function _isAssetCollectionRunning() {
  return !!(state.currentId && typeof _isPipelineActive === "function" && _isPipelineActive(state.currentId));
}

function _fmtHostPorts(h, pending = false) {
  const ports = _hostOpenPorts(h);
  if (!ports.length) return pending ? _assetPendingCell() : `<span class="ai-dash">â€”</span>`;
  const shown = ports.slice(0, 4).map(p => {
    const label = p.service ? `${p.port}:${p.service}` : p.port;
    const risky = _isHighRiskPort(p.port, p.service);
    const title = p.category || p.service || "";
    return `<span class="ai-port ${risky ? "risk" : ""}" title="${escAttr(title)}">${esc(label)}</span>`;
  }).join("");
  const overflow = ports.length > 4 ? `<span class="ai-port more">+${ports.length - 4}</span>` : "";
  return `<div class="ai-port-row">${shown}${overflow}</div>`;
}

function _findingHosts(co) {
  const map = new Map();
  const sevRank = {critical: 4, high: 3, medium: 2, low: 1, info: 0};
  const add = (host, finding) => {
    const h = _normalizeScopeDomain(host);
    if (!h) return;
    const sev = String(finding.severity || "info").toLowerCase();
    const prev = map.get(h);
    if (!prev || (sevRank[sev] || 0) > (sevRank[prev.severity] || 0)) {
      map.set(h, {severity: sev, title: finding.title || finding.category || "Finding"});
    }
  };
  (co?.findings || []).forEach(f => {
    add(f.host, f);
    add(f.domain, f);
    try {
      if (f.url) add(new URL(f.url).hostname, f);
    } catch(e) {}
  });
  return map;
}

function _hostRiskInfo(h, riskMap) {
  const direct = String(h?.risk || h?.risk_level || h?.severity || "").toLowerCase();
  if (["critical", "high", "medium"].includes(direct)) return {risk: true, severity: direct, label: direct};
  const finding = riskMap && riskMap.get(h.host);
  if (finding && ["critical", "high", "medium"].includes(finding.severity)) {
    return {risk: true, severity: finding.severity, label: finding.title || finding.severity};
  }
  const sc = Number(h?.status_code || 0);
  if (sc >= 500) return {risk: true, severity: "high", label: "5xx"};
  const sensitivePort = _hostOpenPorts(h).find(p => _isHighRiskPort(p.port, p.service));
  if (sensitivePort) return {risk: true, severity: "high", label: _portServiceLabel(sensitivePort.port, sensitivePort.service) || `Port ${sensitivePort.port}`};
  return {risk: false, severity: "", label: ""};
}

function _renderSubInventoryShell(co, inventory, el) {
  const activeInventory = (inventory || []).filter(_isActiveHost);
  const riskMap = _findingHosts(co);
  activeInventory.forEach(h => { h._risk = _hostRiskInfo(h, riskMap); });
  _sub_hosts = activeInventory;
  _sub_page = 1;
  const tc = document.getElementById("tc-subdomains");
  if (tc) tc.textContent = _sub_hosts.length || 0;

  if(!_sub_hosts.length) {
    el.innerHTML = `<div class="empty-state"><div class="empty-state-icon">â—Ž</div><div class="empty-state-title">Nenhum host ativo encontrado</div><div class="empty-state-copy">A tabela de Hosts mostra somente dominios/subdominios com status HTTP real. Rode um scan para validar os ativos.</div></div>`;
    return;
  }

    const checkpointInfo = co.checkpoint_diff || null;
    const newSubs = Array.isArray(checkpointInfo?.new_subdomains) ? checkpointInfo.new_subdomains : [];
    const newSubsHtml = newSubs.length
      ? newSubs.slice(0, 12).map(s => `<code class="fg-host-chip fg-host-chip-full" title="New since ${esc(checkpointInfo?.compared_to || 'previous scan')}">${esc(s)}</code>`).join("")
      : "";
    const hostSelector = `
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:14px;flex-wrap:wrap">
        <button class="btn ${state.hostPanel === 'domains' ? 'btn-primary' : 'btn-secondary'}" style="font-size:.68rem;padding:4px 10px" onclick="switchHostsPanel('domains')">Domains</button>
        <button class="btn ${state.hostPanel === 'subdomains' ? 'btn-primary' : 'btn-secondary'}" style="font-size:.68rem;padding:4px 10px" onclick="switchHostsPanel('subdomains')">Hosts</button>
        <span style="font-size:.68rem;color:var(--text3)">Current view: ${state.hostPanel === 'subdomains' ? 'Hosts' : 'Domains'}</span>
      </div>`;

    const statBadges = _assetStatusSummary(activeInventory);
    const techCounts = {};
    activeInventory.forEach(h => _hostTechLabels(h).forEach(t => { techCounts[t] = (techCounts[t] || 0) + 1; }));
    const techOptions = Object.keys(techCounts).sort((a, b) => techCounts[b] - techCounts[a]).slice(0, 40)
      .map(t => `<option value="${escAttr(t)}">${esc(t)} (${techCounts[t]})</option>`).join("");
    const portCounts = {};
    activeInventory.forEach(h => _hostOpenPorts(h).forEach(p => { portCounts[p.port] = (portCounts[p.port] || 0) + 1; }));
    const portOptions = Object.keys(portCounts).sort((a,b)=>Number(a)-Number(b))
      .map(p => `<option value="${escAttr(p)}">${esc(p)}${ADMIN_PORT_LABELS[p] ? " Â· " + esc(ADMIN_PORT_LABELS[p]) : ""} (${portCounts[p]})</option>`).join("");
    const newHostsBanner = (checkpointInfo && checkpointInfo.new_subdomains_count > 0) ? `
      <div class="ai-newbanner">
        <span class="ai-newbanner-t">âš¡ ${checkpointInfo.new_subdomains_count} new since last scan</span>
        <span class="ai-newbanner-s">compared to ${(checkpointInfo.compared_to||'').slice(0,19)}</span>
        ${newSubsHtml ? `<div class="ai-newbanner-chips">${newSubsHtml}</div>` : ""}
      </div>` : "";

    el.innerHTML = `
    ${hostSelector}
    <div class="ai-shell">
      <div class="ai-head">
        <div class="ai-head-l">
          <div class="ai-title">Assets Inventory</div>
          <div class="ai-sub"><span id="sub-cnt">${activeInventory.length}</span> ativos validados Â· sem n/a</div>
        </div>
        <div class="ai-head-r">
          ${statBadges}
          <button class="ai-refresh" onclick="switchHostsPanel('subdomains')" title="Refresh"><span style="font-size:.85rem">âŸ³</span> Refresh</button>
          <button class="ai-icon-btn" onclick="exportHosts('csv')" title="Export CSV">CSV</button>
          <button class="ai-icon-btn" onclick="exportHosts('json')" title="Export JSON">JSON</button>
        </div>
      </div>
      ${newHostsBanner}
      <div class="ai-filter">
        <div class="ai-search">
          <span class="ai-search-ic">âŒ•</span>
          <input id="sub-search" placeholder="Buscar dominio, subdominio, titulo, IP ou porta..." oninput="_subApplyFilter()">
        </div>
        <select class="ai-drop" id="sub-status" onchange="_subApplyFilter()">
          <option value=""># Status HTTP</option>
          <option value="2">2xx â€” OK</option>
          <option value="3">3xx â€” Redirect</option>
          <option value="4">4xx â€” Bloqueado/cliente</option>
          <option value="5">5xx â€” Erro/risco</option>
        </select>
        <select class="ai-drop" id="sub-tech" onchange="_subApplyFilter()">
          <option value="">âŠž Tech / Infra</option>
          ${techOptions}
        </select>
        <select class="ai-drop" id="sub-port" onchange="_subApplyFilter()">
          <option value="">â›“ Portas abertas</option>
          ${portOptions}
        </select>
        <select class="ai-drop" id="sub-risk" onchange="_subApplyFilter()">
          <option value="">â—‡ Risco</option>
          <option value="risk">Com risco</option>
          <option value="clean">Sem risco</option>
        </select>
        <select class="ai-drop" id="sub-waf" onchange="_subApplyFilter()">
          <option value="">â›› More Â· WAF/CDN</option>
          <option value="Cloudflare">Cloudflare</option>
          <option value="Imperva">Imperva</option>
          <option value="AWS">AWS</option>
          <option value="Direct">Direct (no WAF)</option>
        </select>
      </div>
      <div class="ai-table-wrap">
        <table class="ai-table">
          <thead><tr>
            <th onclick="_subSort('host')">URL â‡…</th>
            <th onclick="_subSort('status_code')">Status â‡…</th>
            <th onclick="_subSort('ports')">Portas â‡…</th>
            <th onclick="_subSort('title')">Title â‡…</th>
            <th onclick="_subSort('ip')">Host IP â‡…</th>
            <th>Tech</th>
            <th style="width:50px">Shot</th>
            <th class="ai-actions-h">Actions</th>
          </tr></thead>
          <tbody id="sub-tbody"></tbody>
        </table>
        <div class="pager">
          <span class="pager-info" id="sub-pinfo"></span>
          <div class="pager-btns">
            <button class="pb" id="sub-prev" onclick="_subPageNav(-1)">â† Prev</button>
            <span id="sub-pnums"></span>
            <button class="pb" id="sub-next" onclick="_subPageNav(1)">Next â†’</button>
          </div>
        </div>
      </div>
    </div>`;
  _subApplyFilter();
}

// Asset status-code summary badges (Osmedeus-style)
function _assetStatusSummary(hosts) {
  const b = {2: 0, 3: 0, 4: 0, 5: 0};
  (hosts || []).forEach(h => { const s = h.status_code; if (s) { const g = Math.floor(s / 100); if (b[g] != null) b[g]++; } });
  const chip = (g, cls) => b[g] ? `<span class="ai-statchip ${cls}">${g}xx: ${b[g]}</span>` : "";
  return chip(2, "s2") + chip(3, "s3") + chip(4, "s4") + chip(5, "s5");
}

// Colored tech chip with a stable hue per technology name
function _techChip(t) {
  const palette = ["#60a5fa", "#34d399", "#f59e0b", "#a78bfa", "#f472b6", "#22d3ee", "#fb7185", "#4ade80", "#facc15"];
  let hash = 0;
  for (let i = 0; i < t.length; i++) hash = (hash * 31 + t.charCodeAt(i)) >>> 0;
  const c = palette[hash % palette.length];
  return `<span class="ai-tech" style="color:${c};border-color:${c}33;background:${c}14">${esc(t)}</span>`;
}

function _infraChip(label, cls, title = "") {
  return `<span class="ai-tech ai-tech-infra ${cls}" title="${escAttr(title || label)}">${esc(label)}</span>`;
}

function _cloudLabel(value) {
  const v = String(value || "").trim();
  if (!v) return "";
  if (/gcp|google/i.test(v)) return "Cloud GCP";
  if (/aws|amazon/i.test(v)) return "Cloud AWS";
  if (/azure|microsoft/i.test(v)) return "Cloud Azure";
  if (/cloudflare/i.test(v)) return "Cloudflare";
  return `Cloud ${v}`;
}

function _hostInfraSignals(h) {
  const signals = [];
  const waf = String(h?.waf || "Direct").trim();
  const cloud = _cloudLabel(h?.cloud_provider || "");
  const add = (label, cls, title = "") => {
    if (!label || signals.some(s => s.label.toLowerCase() === label.toLowerCase())) return;
    signals.push({label, cls, title});
  };

  if (!waf || /^direct$/i.test(waf)) add("Sem WAF", "direct", "Direct: sem WAF/CDN identificado");
  else if (/direct/i.test(waf)) add("Sem WAF", "direct", waf);
  else if (/unknown waf/i.test(waf)) add("WAF desconhecido", "unknown", waf);
  else if (/cloudflare/i.test(waf)) add("CDN Cloudflare", "cloud", waf);
  else if (/cloudfront|aws/i.test(waf)) add("CDN AWS", "cloud", waf);
  else if (/gcp|google/i.test(waf)) add("Cloud GCP", "cloud", waf);
  else if (/imperva|incapsula/i.test(waf)) add("WAF Imperva", "waf", waf);
  else if (/akamai/i.test(waf)) add("CDN Akamai", "cloud", waf);
  else add(`WAF ${waf}`, "waf", waf);

  if (cloud) add(cloud, "cloud", h.cloud_provider || cloud);
  const techText = (h?.technologies || []).join(" ");
  if (/cloudflare/i.test(techText)) add("CDN Cloudflare", "cloud", "Detected in technologies");
  if (/gcp|google cloud/i.test(techText)) add("Cloud GCP", "cloud", "Detected in technologies");
  if (/aws|amazon|cloudfront/i.test(techText)) add("Cloud AWS", "cloud", "Detected in technologies");
  if (/azure|microsoft/i.test(techText)) add("Cloud Azure", "cloud", "Detected in technologies");
  return signals;
}

function _hostTechLabels(h) {
  const labels = _hostInfraSignals(h).map(s => s.label);
  (h?.technologies || []).forEach(t => {
    const label = String(t || "").trim();
    const low = label.toLowerCase();
    if (labels.includes("CDN Cloudflare") && low === "cloudflare") return;
    if (labels.includes("Cloud AWS") && /^(aws|amazon|amazon cloudfront|aws cloudfront)$/i.test(label)) return;
    if (labels.includes("Cloud GCP") && /^(gcp|google cloud)$/i.test(label)) return;
    if (labels.includes("Cloud Azure") && /^(azure|microsoft azure)$/i.test(label)) return;
    if (label && !labels.some(x => x.toLowerCase() === label.toLowerCase())) labels.push(label);
  });
  return labels;
}

function _hostTechCell(h) {
  const signals = _hostInfraSignals(h);
  const infra = signals.map(s => _infraChip(s.label, s.cls, s.title)).join("");
  const infraLabels = new Set(signals.map(s => s.label.toLowerCase()));
  const techs = (h?.technologies || [])
    .map(t => String(t || "").trim())
    .filter(Boolean)
    .filter(t => !(infraLabels.has("cdn cloudflare") && t.toLowerCase() === "cloudflare"))
    .filter(t => !(infraLabels.has("cloud aws") && /^(aws|amazon|amazon cloudfront|aws cloudfront)$/i.test(t)))
    .filter(t => !(infraLabels.has("cloud gcp") && /^(gcp|google cloud)$/i.test(t)))
    .filter(t => !(infraLabels.has("cloud azure") && /^(azure|microsoft azure)$/i.test(t)))
    .filter(t => !infraLabels.has(t.toLowerCase()));
  const remainingSlots = Math.max(0, 4 - signals.length);
  const shownTech = techs.slice(0, remainingSlots).map(_techChip).join("");
  const overflow = techs.length > remainingSlots ? `<span class="ai-tech ai-tech-more">+${techs.length - remainingSlots}</span>` : "";
  return infra || shownTech || overflow ? `${infra}${shownTech}${overflow}` : '<span class="ai-dash">â€”</span>';
}

function _fmtCL(n) {
  if (n == null || n === "") return "â€”";
  const v = Number(n);
  if (!isFinite(v)) return "â€”";
  return v.toLocaleString("en-US");
}

function renderSubdomainsTab(co, historyRows = null) {
  const el = document.getElementById("tab-subdomains");
  if (!el) return;
  const rows = Array.isArray(historyRows)
    ? historyRows
    : Array.isArray(co.subdomain_history)
      ? co.subdomain_history
      : null;
  if (rows === null) {
    _renderSubInventoryShell(co, _buildSubdomainInventory(co, []), el);
    _loadSubdomainHistory(co).then(history => {
      if (state.currentId !== co.id) return;
      co.subdomain_history = history;
      _renderSubInventoryShell(co, _buildSubdomainInventory(co, history), el);
    });
    return;
  }
  _renderSubInventoryShell(co, _buildSubdomainInventory(co, rows), el);
}

function openSubdomainsFiltered(term) {
  switchHostsPanel('subdomains');
  setTimeout(() => {
    const s = document.getElementById('sub-search');
    if (s) {
      s.value = term || '';
      _subApplyFilter();
    }
  }, 100);
}

function renderDomainsTab(co, historyRows = null) {
  const el = document.getElementById("tab-domains");
  if (!el) return;
  const rawDomains = Array.isArray(co.domains) ? co.domains.map(_normalizeScopeDomain).filter(Boolean) : [];
  if (!rawDomains.length) {
    el.innerHTML = `<div class="empty-state"><div class="empty-state-icon">ðŸŒ</div><div class="empty-state-title">No domains configured</div><div class="empty-state-copy">Add at least one target domain to see domain-level work and generated subdomains here.</div></div>`;
    const tc = document.getElementById("tc-domains");
    if (tc) tc.textContent = "";
    return;
  }
  const rows = Array.isArray(historyRows)
    ? historyRows
    : Array.isArray(co.subdomain_history)
      ? co.subdomain_history
      : null;
  if (rows === null) {
    el.innerHTML = `<div class="empty-state"><div class="empty-state-icon">ðŸŒ</div><div class="empty-state-title">Loading domain inventoryâ€¦</div><div class="empty-state-copy">Merging domains, hosts and subdomain history.</div></div>`;
    _loadSubdomainHistory(co).then(history => {
      if (state.currentId !== co.id) return;
      co.subdomain_history = history;
      renderDomainsTab(co, history);
    });
    return;
  }

  const inventory = _buildSubdomainInventory(co, rows);
  const checkpointInfo = co.checkpoint_diff || null;
  const newSet = new Set((checkpointInfo?.new_subdomains || []).map(_normalizeScopeDomain).filter(Boolean));
  const buckets = new Map(rawDomains.map(d => [d, {domain: d, hosts: [], live: [], techs: new Set(), newHosts: []}]));
  const other = {domain: "Other / shared", hosts: [], live: [], techs: new Set(), newHosts: []};
  const domainSet = new Set(rawDomains);

  inventory.forEach(h => {
    const matched = _matchDomainForHost(h.host, rawDomains, domainSet);
    const bucket = matched ? buckets.get(matched) : other;
    bucket.hosts.push(h);
    if ((h.status_code && h.status_code < 400) || (h.ports || []).length > 0) bucket.live.push(h);
    if (newSet.has(h.host)) bucket.newHosts.push(h);
    (h.technologies || []).forEach(t => bucket.techs.add(t));
  });

  const domainBuckets = [...buckets.values()].sort((a, b) =>
    (b.hosts.length - a.hosts.length) || a.domain.localeCompare(b.domain));
  if (other.hosts.length) domainBuckets.push(other);
  _domBuckets = domainBuckets;
  _domQuery = "";

  const tc = document.getElementById("tc-domains");
  if (tc) tc.textContent = rawDomains.length || 0;

  const totalHosts = inventory.length;
  const totalLive = inventory.filter(h => (h.status_code && h.status_code < 400) || (h.ports || []).length > 0).length;
  const totalNew = checkpointInfo?.new_subdomains_count || 0;
  const totalDomains = rawDomains.length;
  const totalKnownTech = inventory.reduce((acc, h) => acc + ((h.technologies || []).length > 0 ? 1 : 0), 0);
  const hostSelector = `
    <div style="display:flex;gap:8px;align-items:center;margin-bottom:14px;flex-wrap:wrap">
      <button class="btn ${state.hostPanel === 'domains' ? 'btn-primary' : 'btn-secondary'}" style="font-size:.68rem;padding:4px 10px" onclick="switchHostsPanel('domains')">Domains</button>
      <button class="btn ${state.hostPanel === 'subdomains' ? 'btn-primary' : 'btn-secondary'}" style="font-size:.68rem;padding:4px 10px" onclick="switchHostsPanel('subdomains')">Hosts</button>
      <span style="font-size:.68rem;color:var(--text3)">Current view: ${state.hostPanel === 'subdomains' ? 'Subdomains' : 'Domains'}</span>
    </div>`;

  el.innerHTML = `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">Domains</div>
          <div class="section-title">Domain work and generated hosts</div>
          <div class="section-sub">Each domain is shown with the hosts it generated, live hosts, technology signals and change since the previous scan.</div>
        </div>
      </div>
      ${hostSelector}
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">
        <div class="stat-card" style="min-width:120px"><div class="stat-value">${totalDomains}</div><div class="stat-label">Domains</div></div>
        <div class="stat-card" style="min-width:120px"><div class="stat-value">${totalHosts}</div><div class="stat-label">Hosts</div></div>
        <div class="stat-card" style="min-width:120px"><div class="stat-value">${totalLive}</div><div class="stat-label">Live / HTTP</div></div>
        <div class="stat-card" style="min-width:120px"><div class="stat-value">${totalNew}</div><div class="stat-label">New</div></div>
      </div>
      ${checkpointInfo && totalNew > 0 ? `
      <div style="margin:12px 0;padding:10px 14px;background:#16a34a18;border:1px solid #4ade8044;border-radius:8px">
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          <div style="font-size:.72rem;font-weight:700;color:#4ade80">âš¡ Domain changes since last scan</div>
          <div style="font-size:.72rem;color:var(--text2)">${totalNew} new hosts Â· compared to ${(checkpointInfo.compared_to||'').slice(0,19)}</div>
        </div>
      </div>` : ""}
      <div class="table-shell">
        <div class="table-topline">
          <div class="table-title">Domain inventory</div>
          <div class="table-note">Click a host chip to inspect the full host record.</div>
        </div>
        <div style="margin-bottom:10px">
          <input id="dom-search" type="text" placeholder="Filter ${totalDomains.toLocaleString()} domainsâ€¦"
                 oninput="_domFilterCards()"
                 style="width:100%;max-width:360px;padding:6px 10px;font-size:.72rem;font-family:var(--mono);background:rgba(255,255,255,0.03);border:1px solid var(--border2);border-radius:8px;color:var(--text1)">
          <div id="dom-cards-meta" style="margin-top:6px;font-size:.66rem;color:var(--text3)"></div>
        </div>
        <div id="dom-cards" style="display:flex;flex-direction:column;gap:12px"></div>
      </div>
    </div>`;
  _renderDomCards();
}

// Build a single domain card. Kept separate so search re-renders are cheap.
function _domCardHTML(bucket) {
  const techs = [...bucket.techs].sort().slice(0, 10);
  const hosts = bucket.hosts.slice().sort((a, b) => a.host.localeCompare(b.host));
  const liveCount = bucket.live.length;
  const newCount = bucket.newHosts.length;
  const sample = hosts.slice(0, 8);
  return `
    <div style="padding:14px 16px;border:1px solid var(--border2);border-radius:12px;background:rgba(255,255,255,0.02)">
      <div style="display:flex;gap:10px;align-items:flex-start;justify-content:space-between;flex-wrap:wrap">
        <div>
          <div style="font-size:.92rem;font-weight:700;color:var(--text1);font-family:var(--mono)">${esc(bucket.domain)}</div>
          <div style="margin-top:4px;font-size:.72rem;color:var(--text3)">${hosts.length} hosts Â· ${liveCount} live / HTTP Â· ${newCount} new</div>
        </div>
        <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px" onclick="openSubdomainsFiltered('${escAttr(bucket.domain)}')">Open Hosts</button>
      </div>
      <div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:6px">
        ${techs.length ? techs.map(t => `<span class="sd-tech-badge">${esc(t)}</span>`).join("") : `<span style="color:var(--text3);font-size:.65rem">No fingerprint</span>`}
      </div>
      <div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:6px">
        ${sample.length ? sample.map(h => `<code class="fg-host-chip fg-host-chip-full" onclick="openSubdomainsFiltered('${escAttr(h.host)}')" title="Open in Hosts">${esc(h.host)}</code>`).join("") : `<span style="color:var(--text3);font-size:.65rem">No hosts mapped yet</span>`}
      </div>
    </div>`;
}

// Render at most DOM_CARD_LIMIT cards from _domBuckets, filtered by _domQuery.
function _renderDomCards() {
  const host = document.getElementById("dom-cards");
  if (!host) return;
  const q = _domQuery.trim().toLowerCase();
  const filtered = q ? _domBuckets.filter(b => b.domain.toLowerCase().includes(q)) : _domBuckets;
  const shown = filtered.slice(0, DOM_CARD_LIMIT);
  host.innerHTML = shown.map(_domCardHTML).join("") ||
    `<div style="color:var(--text3);font-size:.7rem;padding:8px 0">No domains match â€œ${esc(_domQuery)}â€.</div>`;
  const meta = document.getElementById("dom-cards-meta");
  if (meta) {
    meta.textContent = filtered.length > shown.length
      ? `Showing ${shown.length} of ${filtered.length.toLocaleString()} domains${q ? " (filtered)" : ""} â€” refine the filter to narrow down.`
      : `Showing ${shown.length} domain${shown.length === 1 ? "" : "s"}${q ? " (filtered)" : ""}.`;
  }
}

function _domFilterCards() {
  const inp = document.getElementById("dom-search");
  _domQuery = inp ? inp.value : "";
  _renderDomCards();
}

let _sub_sort = "host", _sub_asc = true;
function _subSort(key){ if(_sub_sort===key) _sub_asc=!_sub_asc; else{_sub_sort=key;_sub_asc=true;} _subApplyFilter(); }
function _subPageNav(d){ _sub_page+=d; _subRenderTable(_subFiltered()); }

function _subFiltered(){
  const q  = document.getElementById("sub-search")?.value.toLowerCase()||"";
  const st = document.getElementById("sub-status")?.value||"";
  const tc = document.getElementById("sub-tech")?.value||"";
  const pt = document.getElementById("sub-port")?.value||"";
  const rk = document.getElementById("sub-risk")?.value||"";
  const wf = document.getElementById("sub-waf")?.value||"";
  const NUMERIC = {status_code:1, ports:1};
  return _sub_hosts.filter(h=>{
    const techLabels = _hostTechLabels(h);
    const mq = !q || h.host.toLowerCase().includes(q) || (h.ip||"").includes(q)
              || (h.title||"").toLowerCase().includes(q)
              || techLabels.join(",").toLowerCase().includes(q)
              || _hostOpenPorts(h).some(p => String(p.port).includes(q) || String(p.service || "").toLowerCase().includes(q));
    let ms = true;
    if (st) ms = h.status_code && Math.floor(h.status_code/100) === Number(st);
    const mt = !tc || techLabels.includes(tc);
    const mp = !pt || _hostOpenPorts(h).some(p => String(p.port) === String(pt));
    const mr = !rk || (rk === "risk" ? !!h._risk?.risk : !h._risk?.risk);
    const mw = !wf || (h.waf||"Direct").includes(wf);
    return mq && ms && mt && mp && mr && mw;
  }).sort((a,b)=>{
    if (NUMERIC[_sub_sort]) {
      const av = _sub_sort === "ports" ? _hostOpenPorts(a).length : Number(a[_sub_sort]||0);
      const bv = _sub_sort === "ports" ? _hostOpenPorts(b).length : Number(b[_sub_sort]||0);
      return _sub_asc ? av-bv : bv-av;
    }
    const av=String(a[_sub_sort]||""), bv=String(b[_sub_sort]||"");
    return _sub_asc ? av.localeCompare(bv) : bv.localeCompare(av);
  });
}

function _subApplyFilter(){
  _sub_page = 1;
  const filtered = _subFiltered();
  const c = document.getElementById("sub-cnt"); if (c) c.textContent = filtered.length;
  _subRenderTable(filtered);
}

function _subRenderTable(filtered){
  const tot=filtered.length, totPg=Math.ceil(tot/SUB_PER_PAGE);
  _sub_page = Math.max(1, Math.min(_sub_page, totPg||1));
  const st=(_sub_page-1)*SUB_PER_PAGE, pg=filtered.slice(st, st+SUB_PER_PAGE);
  const pi=document.getElementById("sub-pinfo"); if(pi) pi.textContent=`${st+1}â€“${Math.min(st+SUB_PER_PAGE,tot)} of ${tot}`;
  const pr=document.getElementById("sub-prev"); if(pr) pr.disabled=_sub_page<=1;
  const nx=document.getElementById("sub-next"); if(nx) nx.disabled=_sub_page>=totPg;
  let pn="";
  for(let i=Math.max(1,_sub_page-2);i<=Math.min(totPg,_sub_page+2);i++)
    pn+=`<button class="pb${i===_sub_page?" active":""}" onclick="_sub_page=${i};_subRenderTable(_subFiltered())">${i}</button>`;
  const pne=document.getElementById("sub-pnums"); if(pne) pne.innerHTML=pn;
  const tb=document.getElementById("sub-tbody"); if(!tb) return;
  const collectionRunning = _isAssetCollectionRunning();
  tb.innerHTML = pg.map(h => {
    const scheme = (h.status_code || (h.ports||[]).includes('443') || !(h.ports||[]).includes('80')) ? 'https' : 'http';
    const url   = `${scheme}://${h.host}/`;
    const sc    = h.status_code;
    const scCls = sc ? (sc<300?'s2':sc<400?'s3':sc<500?'s4':'s5') : 'na';
    const scHtml= `<span class="ai-status ${scCls}">${sc}</span>`;
    const techCell = _hostTechCell(h);
    const title = h.title ? esc(h.title) : (collectionRunning ? _assetPendingCell() : '<span class="ai-dash">â€”</span>');
    const ipCell = h.ip ? esc(h.ip) : (collectionRunning ? _assetPendingCell() : '<span class="ai-dash">â€”</span>');
    const shotCell = h.screenshot
      ? `<img src="${esc('/' + h.screenshot)}" style="width:42px;height:26px;object-fit:cover;border-radius:3px;border:1px solid var(--border);cursor:pointer;vertical-align:middle" onerror="this.style.display='none'" onmouseenter="ssPopoverShow(event,${JSON.stringify('/' + h.screenshot).replace(/"/g,'&quot;')},${JSON.stringify(h.host || '').replace(/"/g,'&quot;')})" onmouseleave="ssPopoverHide()" onclick="event.stopPropagation()">`
      : (collectionRunning ? _assetPendingCell() : '<span class="ai-dash">â€”</span>');
    return `<tr class="ai-row" onclick="openHostDrawer('${escAttr(h.host)}')">
      <td class="ai-url-cell">
        <button class="ai-mini" title="Copy URL" onclick="event.stopPropagation();copyToClipboard('${escAttr(url)}')">â§‰</button>
        <a class="ai-mini" href="${escAttr(url)}" target="_blank" rel="noopener" title="Open" onclick="event.stopPropagation()">â†—</a>
        <a class="ai-url" href="${escAttr(url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${esc(url)}</a>
      </td>
      <td>${scHtml}</td>
      <td class="ai-cl">${_fmtHostPorts(h, collectionRunning)}</td>
      <td class="ai-title" title="${escAttr(h.title||'')}">${title}</td>
      <td class="ai-ip">${ipCell}</td>
      <td><div class="ai-tech-row">${techCell}</div></td>
      <td class="ai-shot">${shotCell}</td>
      <td class="ai-actions"><button class="ai-eye" title="View details" onclick="event.stopPropagation();openHostDrawer('${escAttr(h.host)}')">â—‰</button></td>
    </tr>`;
  }).join('');
}

function renderSubHistoryTab(co) {
  const el = document.getElementById("tab-subhistory");
  if (!el) return;

  fetch(`/api/data/${co.id}/subhistory`, {headers: _authHeaders()})
    .then(r => r.json())
    .then(data => {
      renderHistoryContent(el, data.history || [], co.id);
    })
    .catch(() => {
      el.innerHTML = `
        <div style="padding:60px 20px;text-align:center;color:var(--text3)">
          <div style="font-size:2rem;margin-bottom:12px">ðŸ“œ</div>
          <div style="font-size:.9rem;color:var(--text2);margin-bottom:6px">Subdomain history</div>
          <div style="font-size:.75rem">Run the pipeline to start tracking subdomain changes.</div>
        </div>`;
    });
}

function renderHistoryContent(el, history, cid) {
  if (!history || history.length === 0) {
    el.innerHTML = `
      <div style="padding:60px 20px;text-align:center;color:var(--text3)">
        <div style="font-size:2rem;margin-bottom:12px">ðŸ“œ</div>
        <div style="font-size:.9rem;color:var(--text2);margin-bottom:6px">No history yet</div>
        <div style="font-size:.75rem">History will be populated after each pipeline scan.</div>
      </div>`;
    return;
  }

  const added = history.filter(h => h.event === "added");
  const removed = history.filter(h => h.event === "removed");
  const seen = history.filter(h => h.event === "seen");

  el.innerHTML = `
    <div style="padding:24px 0 8px">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
        <div style="font-size:1rem;font-weight:700">ðŸ“œ Subdomain Timeline</div>
        <div style="font-size:0.75rem;color:var(--text3)">${history.length} eventos</div>
      </div>

      <div class="stat-strip" style="margin-bottom:18px">
        <div class="stat-box" style="border-left:3px solid var(--green)">
          <div class="stat-num" style="color:var(--green)">${added.length}</div>
          <div class="stat-lbl">Adicionados</div>
        </div>
        <div class="stat-box" style="border-left:3px solid var(--red)">
          <div class="stat-num" style="color:var(--red)">${removed.length}</div>
          <div class="stat-lbl">Removidos</div>
        </div>
        <div class="stat-box" style="border-left:3px solid var(--blue)">
          <div class="stat-num" style="color:var(--blue)">${seen.length}</div>
          <div class="stat-lbl">Vistos</div>
        </div>
      </div>

      <div class="sec-hdr">
        <span class="sec-title">Eventos Recentes</span>
        <span class="sec-cnt">${Math.min(history.length, 100)}</span>
      </div>

      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Subdomain</th>
              <th>Evento</th>
              <th>Status</th>
              <th>Fonte</th>
              <th>First Seen</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            ${history.slice(0, 100).map(h => {
              const eventStyle = {
                added: "color:var(--green)",
                removed: "color:var(--red)",
                seen: "color:var(--blue)"
              }[h.event] || "";
              const eventLabel = {
                added: "âž• Adicionado",
                removed: "âž– Removido",
                seen: "ðŸ‘ï¸ Visto"
              }[h.event] || h.event;
              return `
                <tr>
                  <td><span class="host-a">${h.subdomain}</span></td>
                  <td><span style="${eventStyle};font-weight:600;font-size:.7rem">${eventLabel}</span></td>
                  <td>${h.is_alive ? '<span style="color:var(--green);font-size:.68rem">â— Vivo</span>' : '<span style="color:var(--text3);font-size:.68rem">â—‹ Morto</span>'}</td>
                  <td><span style="font-size:.7rem;color:var(--text2)">${h.source || "â€”"}</span></td>
                  <td><span style="font-size:.7rem;color:var(--text3)">${h.first_seen?.split("T")[0] || "â€”"}</span></td>
                  <td><span style="font-size:.7rem;color:var(--text3)">${h.last_seen?.split("T")[0] || "â€”"}</span></td>
                </tr>`;
            }).join("")}
          </tbody>
        </table>
      </div>
    </div>`;
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  URL CLASSIFICATION ENGINE (red-team focused)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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

function _classifyUrlMemo(url) {
  const k = String(url || '').toLowerCase();
  if (!_classifyCache) _classifyCache = {};
  if (_classifyCache[k]) return _classifyCache[k];
  return (_classifyCache[k] = classifyUrl(url));
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  UNIFIED ENDPOINTS TAB â€” URLs + JS endpoints + secrets merged (v2)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

function invalidateEndpointCache(co) {
  if (co) {
    delete co._unifiedEndpoints;
    delete co._unifiedSecrets;
    delete co._unifiedSources;
    delete co._epStats;
  }
  _classifyCache = null;
}

function buildUnifiedEndpoints(co) {
  if (co._unifiedEndpoints && co._unifiedSources) return;

  const allEndpoints = [];
  const allSecrets = [];
  const sources = [];
  const addEndpoint = (rawUrl, method, source, meta = {}) => {
    if (!rawUrl || typeof rawUrl !== 'string') return;
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
        allSecrets.push({ type: s.type || 'Unknown', value: s.secret || s.value || s, file: js.file || js.url || '', host: js.host || '', severity: s.severity || 'high' });
      });
    });
    sources.push({ name: 'JS Extraction', count: co.js_data.total_endpoints || 0, key: 'js' });
  }

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
        allEndpoints.push({ url: rawUrl, method: f.method || 'â€”', host: f.host || '', path: f.path || rawUrl, source: 'nuclei', type: 'API Panel', severity: f.severity || cls.severity });
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

  co._unifiedEndpoints = unique;
  co._unifiedSecrets = allSecrets;
  co._unifiedSources = sources;
  co._epStats = { stats, byType, actualMethods };
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

  const hasFilters = window._urlActiveSev || window._urlActiveMethod;

  el.innerHTML = `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">Endpoint Inventory</div>
          <div class="section-title">URLs + JS routes + API panels â€” unified</div>
          <div class="section-sub">Auto-classified by type and risk. Click severity or method stats to filter. Rows expand on click for full details.</div>
        </div>
        <div class="section-actions">
          ${hasFilters ? `<button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px" onclick="clearUrlFilters()">âœ• Clear Filters</button>` : ''}
          <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px" onclick="copyUrlsToClipboard()">ðŸ“‹ Copy Visible</button>
          <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px" onclick="exportEndpointsCSV()">â¬‡ CSV</button>
        </div>
      </div>

      ${unique.length === 0 && allSecrets.length === 0 ? `
        <div class="empty-state"><div class="empty-state-icon">ðŸ”—</div><div class="empty-state-title">No endpoints collected</div><div class="empty-state-copy">Run wayback, urlfinder, js_endpoints and api_panels modules.</div></div>
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
            <div class="url-stat">
              <div class="url-stat-num" style="color:var(--orange)">${allSecrets.length}</div>
              <div class="url-stat-lbl">SECRETS</div>
            </div>
          ` : ''}
        </div>

        <!-- Source chips -->
        <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center">
          ${sources.map(s => `<span class="source-chip"><span style="color:var(--text3)">${s.name}:</span> <b>${s.count}</b></span>`).join('')}
        </div>

        <!-- Filter bar -->
        <div class="filter-bar" style="margin-bottom:10px">
          <input type="text" id="url-search" class="fi grow" placeholder="Search URL, host, pathâ€¦" oninput="filterUrlsTable()" value="${esc(window._urlSearch || '')}">
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
            ðŸ“‚ ${window._urlGrouped ? 'Flat List' : 'Group by Path'}
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
          <div class="section-head" style="margin-top:24px">
            <div class="section-head-main">
              <div class="section-kicker">ðŸ”‘ Embedded Secrets</div>
              <div class="section-title">Credentials, tokens and keys from JS</div>
              <div class="section-sub">Extracted from JavaScript bundles. Click masked values to reveal.</div>
            </div>
          </div>
          <div class="url-table-wrap">
            <table class="url-table">
              <thead><tr>
                <th style="width:15%">Type</th>
                <th style="width:42%">Value (click to reveal)</th>
                <th style="width:25%">File</th>
                <th style="width:10%">Host</th>
                <th style="width:8%">Risk</th>
              </tr></thead>
              <tbody>
                ${allSecrets.map(s => {
                  const masked = maskSecret(s.value);
                  const sevColor = s.severity === 'critical' ? '#fb7185' : s.severity === 'high' ? '#fb923c' : '#fbbf24';
    return `<tr>
                    <td><span class="url-type-badge" style="background:rgba(251,146,60,0.1);color:#fb923c;border:1px solid rgba(251,146,60,0.2)">${esc(s.type)}</span></td>
                    <td><code class="secret-value" title="Click to reveal" onclick="this.textContent='${esc(s.value).replace(/'/g,"\\'")}';this.classList.add('revealed')">${esc(masked)}</code></td>
                    <td><span style="font-size:.68rem;font-family:var(--mono);color:var(--text2)">${esc(s.file)}</span></td>
                    <td><span style="font-size:.68rem;color:var(--text3)">${esc(s.host || 'â€”')}</span></td>
                    <td><span class="url-risk-badge" style="background:rgba(251,146,60,0.1);color:${sevColor}">${s.severity.toUpperCase()}</span></td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table>
          </div>
        ` : ''}
      `}
    </div>`;

  filterUrlsTable();
}

// â”€â”€ Clear filters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
  if (btn) btn.textContent = window._urlGrouped ? 'ðŸ“‚ Flat List' : 'ðŸ“‚ Group by Path';
  filterUrlsTable();
}

// â”€â”€ Endpoint table filtering and helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ Flat table view (with expandable rows) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
          return `<tr class="ep-row" onclick="toggleEpRow(this,'${idx}')" title="Click to expand details">
            <td><span class="js-method-badge" style="background:${mc}12;color:${mc};border:1px solid ${mc}25;font-weight:700">${esc(ep.method)}</span>${ep.auth && ep.auth !== 'unknown' && ep.auth !== 'none_detected' ? `<span class="method-badge" style="background:var(--border);color:var(--teal);font-size:.58rem;padding:1px 5px;border-radius:3px;margin-left:3px" title="Auth: ${esc(ep.auth)}">${ep.auth === 'bearer' ? 'ðŸ”‘JWT' : ep.auth === 'api_key_header' ? 'ðŸ”‘API' : ep.auth === 'basic' ? 'ðŸ”’Basic' : ep.auth === 'oauth2' ? 'ðŸ”‘OAuth2' : ep.auth === 'cookie_session' ? 'ðŸªSession' : esc(ep.auth)}</span>` : ep.auth === 'none_detected' ? `<span class="method-badge" style="background:rgba(239,68,68,0.15);color:var(--red);font-size:.58rem;padding:1px 5px;border-radius:3px;margin-left:3px" title="No auth detected">âš  NOAUTH</span>` : ''}</td>
            <td>
              <div class="url-cell">
                <span class="url-cell-link ep-url-main">${esc(displayUrl)}</span>
                ${hasQuery ? '<span class="ep-expand-hint">\u25B6 Expand</span>' : ''}
              </div>
            </td>
            <td><span class="url-type-badge" style="background:${sc.bg};color:${sc.color};border:1px solid ${sc.color}22">${esc(ep.type)}</span></td>
            <td><span class="url-cell-host">${esc(ep.host || '\u2014')}</span></td>
            <td><span class="source-chip" style="font-size:.6rem">${esc(ep.source)}</span></td>
            <td><span class="url-risk-badge" style="background:${sc.bg};color:${sc.color};font-weight:700">${sc.labelShort}</span></td>
            <td><button class="url-copy-btn" onclick="copyToClipboard('${escAttr(ep.url).replace(/'/g,"\\'")}');event.stopPropagation()" title="Copy URL">\uD83D\uDCCB</button></td>
          </tr>
          <tr class="ep-detail ep-detail-${idx}" style="display:none">
            <td colspan="7">
              <div class="ep-detail-box">
                <div class="ep-detail-row"><span class="ep-detail-k">Full URL</span><a href="${escAttr(ep.url)}" target="_blank" rel="noopener" class="ep-detail-url">${esc(ep.url)}</a></div>
                <div class="ep-detail-row"><span class="ep-detail-k">Path</span><code class="ep-detail-code">${esc(ep.path || '/')}</code></div>
                ${hasQuery ? `<div class="ep-detail-row"><span class="ep-detail-k">Query Params</span><code class="ep-detail-code">${esc(_extractQuery(ep.url))}</code></div>` : ''}
                <div class="ep-detail-row"><span class="ep-detail-k">Host</span><span style="color:var(--text2)">${esc(ep.host || '\u2014')}</span></div>
                <div class="ep-detail-row"><span class="ep-detail-k">Source</span><span class="source-chip" style="font-size:.62rem">${esc(ep.source)}</span></div>
                ${ep.status ? `<div class="ep-detail-row"><span class="ep-detail-k">Status</span><span style="color:var(--text2);font-family:var(--mono)">${ep.status}</span></div>` : ''}
                ${ep.jsFile ? `<div class="ep-detail-row"><span class="ep-detail-k">JS File</span><span style="color:var(--text2);font-family:var(--mono)">${esc(ep.jsFile)}</span></div>` : ''}
                <div class="ep-detail-actions">
                  <button class="btn btn-secondary" style="font-size:.62rem;padding:3px 8px" onclick="copyToClipboard('${escAttr(ep.url).replace(/'/g,"\\'")}')">\uD83D\uDCCB Copy URL</button>
                  <a href="${escAttr(ep.url)}" target="_blank" rel="noopener" class="btn btn-secondary" style="font-size:.62rem;padding:3px 8px;text-decoration:none">\u2197 Open</a>
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

// â”€â”€ Grouped view (by path pattern) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
            <span class="js-method-badge" style="font-size:.58rem;padding:1px 5px;background:${(_methodColor(ep.method))}12;color:${_methodColor(ep.method)};border:1px solid ${_methodColor(ep.method)}25">${esc(ep.method)}</span>${ep.auth && ep.auth !== 'unknown' && ep.auth !== 'none_detected' ? `<span class="method-badge" style="background:var(--border);color:var(--teal);font-size:.58rem;padding:1px 5px;border-radius:3px;margin-left:3px" title="Auth: ${esc(ep.auth)}">${ep.auth === 'bearer' ? 'ðŸ”‘JWT' : ep.auth === 'api_key_header' ? 'ðŸ”‘API' : ep.auth === 'basic' ? 'ðŸ”’Basic' : ep.auth === 'oauth2' ? 'ðŸ”‘OAuth2' : ep.auth === 'cookie_session' ? 'ðŸªSession' : esc(ep.auth)}</span>` : ep.auth === 'none_detected' ? `<span class="method-badge" style="background:rgba(239,68,68,0.15);color:var(--red);font-size:.58rem;padding:1px 5px;border-radius:3px;margin-left:3px" title="No auth detected">âš  NOAUTH</span>` : ''}
            <a href="${escAttr(ep.url)}" target="_blank" rel="noopener" class="url-cell-link" style="font-size:.68rem" title="${esc(ep.url)}">${esc(displayUrl)}</a>
            <button class="url-copy-btn" style="margin-left:auto" onclick="copyToClipboard('${escAttr(ep.url).replace(/'/g,"\\'")}');event.stopPropagation()">\uD83D\uDCCB</button>
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

// â”€â”€ Clipboard helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ JS endpoint classification helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// BRAND DOMAINS TAB
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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
    broker_listed:         { label: 'Ã€ VENDA',       color: 'var(--red)',    icon: 'ðŸ·ï¸' },
    active:                { label: 'ATIVO',          color: 'var(--orange)', icon: 'âš ï¸' },
    registered_no_ip:      { label: 'REGISTRADO',     color: 'var(--yellow)', icon: 'ðŸ“‹' },
    parked:                { label: 'PARKED',          color: 'var(--text3)', icon: 'ðŸ…¿ï¸' },
    registered_unreachable:{ label: 'SEM RESPOSTA',   color: 'var(--text3)', icon: 'â“' },
    company_owned:         { label: 'PRÃ“PRIO',         color: 'var(--green)', icon: 'âœ…' },
  };

  const renderRow = r => {
    const st  = STATUS_LABEL[r.status] || { label: r.status || '?', color: 'var(--text3)', icon: 'â“' };
    const rc  = RISK_COLOR[r.risk] || 'var(--text3)';
    const ips = (r.ips || []).join(', ') || 'â€”';

    // Extra intel badges
    const badges = [];
    if (r.has_mx)
      badges.push(`<span style="background:#b91c1c22;color:#f87171;border:1px solid #f8717144;border-radius:3px;padding:1px 5px;font-size:.6rem;font-weight:700">ðŸ“§ MX</span>`);
    if ((r.ssl || {}).brand_in_cert)
      badges.push(`<span style="background:#7c3aed22;color:#a78bfa;border:1px solid #a78bfa44;border-radius:3px;padding:1px 5px;font-size:.6rem;font-weight:700">ðŸ”’ SSL+BRAND</span>`);
    if ((r.ssl || {}).cn && !(r.ssl || {}).brand_in_cert)
      badges.push(`<span style="background:#1e3a5f22;color:#60a5fa;border:1px solid #60a5fa33;border-radius:3px;padding:1px 5px;font-size:.6rem">ðŸ”’ SSL</span>`);
    if (r.mx_records && r.mx_records.length)
      badges.push(`<span style="font-size:.6rem;color:var(--text3)" title="${escAttr(r.mx_records.join(', '))}">${r.mx_records[0]}</span>`);

    const badgeHtml  = badges.length ? `<div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:3px">${badges.join('')}</div>` : '';
    const redirect   = r.redirect_to ? `<div style="font-size:.63rem;color:var(--text3);margin-top:2px">â†³ ${esc(r.redirect_to)}</div>` : '';
    const whoisInfo  = (r.org || r.email)
      ? `<div style="font-size:.61rem;color:var(--text3);margin-top:2px">Reg: ${esc(r.org || r.email || '')}</div>` : '';
    const sslDetail  = (r.ssl || {}).cn
      ? `<div style="font-size:.61rem;color:var(--text3);margin-top:1px">CN: ${esc(r.ssl.cn)}</div>` : '';

    const riskLabel  = r.risk === 'critical'
      ? `<span style="color:var(--purple);font-size:.65rem;font-weight:800">CRÃTICO</span>`
      : `<span style="color:${rc};font-size:.65rem;font-weight:700;text-transform:uppercase">${r.risk||'â€”'}</span>`;

    return `<div class="typo-row" style="display:grid;grid-template-columns:1fr auto auto auto;gap:6px 14px;align-items:start;padding:9px 12px;border-bottom:1px solid var(--border2);font-size:.74rem">
      <div>
        <a href="https://${escAttr(r.domain)}" target="_blank" rel="noopener"
           style="color:var(--teal);font-family:monospace;font-weight:600">${esc(r.domain)}</a>
        ${redirect}
        ${ips !== 'â€”' ? `<div style="font-size:.63rem;color:var(--text3);margin-top:1px">${esc(ips)}</div>` : ''}
        ${whoisInfo}${sslDetail}${badgeHtml}
      </div>
      <div style="white-space:nowrap;padding-top:2px;color:${st.color};font-size:.65rem;font-weight:700">${st.icon} ${st.label}</div>
      <div style="padding-top:2px">${riskLabel}</div>
      <div style="padding-top:2px"><a href="https://who.is/whois/${escAttr(r.domain)}" target="_blank" rel="noopener"
              style="font-size:.63rem;color:var(--text3);text-decoration:none">WHOIS â†—</a></div>
    </div>`;
  };

  const section = (title, icon, color, items, emptyMsg, collapse=false) => {
    if (!items.length && collapse) return '';
    if (!items.length) return `<div style="padding:10px 14px;color:var(--text3);font-size:.72rem">${emptyMsg}</div>`;
    return `<div class="section-shell" style="margin-bottom:14px">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker" style="color:${color}">${icon} ${title}</div>
          <div class="section-title">${items.length} domÃ­nio${items.length>1?'s':''}</div>
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
          <div class="section-kicker" style="color:var(--teal)">ðŸ“¡ CT Log â€” Novos Registros (opensquat)</div>
          <div class="section-title">${opensquat.length} alerta${opensquat.length>1?'s':''} histÃ³rico${opensquat.length>1?'s':''}</div>
        </div>
      </div>
      ${opensquat.slice(-5).reverse().map(a=>`
        <div style="padding:7px 12px;border-bottom:1px solid var(--border2);font-size:.72rem;display:flex;gap:12px;align-items:center">
          <span style="color:var(--text3);font-size:.64rem;white-space:nowrap">${(a.date||'').slice(0,10)}</span>
          <span style="color:var(--orange);font-weight:700">+${a.new_count} domÃ­nios</span>
          <span style="color:var(--text3);font-size:.65rem">${(a.domains||[]).slice(0,4).join(', ')}${a.domains.length>4?' â€¦':''}</span>
        </div>`).join('')}
    </div>` : '';

  const scanMeta = td.scanned_at
    ? `<span style="color:var(--text3);font-size:.68rem">Verificados: ${td.total_checked||0} Â· Registrados: ${td.registered_count||0} Â· Scan: ${(td.scanned_at||'').slice(0,10)||'?'}</span>`
    : `<span style="color:var(--text3);font-size:.68rem">Sem dados â€” rode o pipeline primeiro.</span>`;

  el.innerHTML = `
    <div style="padding:18px 20px;max-width:1100px;margin:0 auto">
      <div style="display:flex;align-items:baseline;gap:14px;margin-bottom:18px;flex-wrap:wrap">
        <div>
          <div style="font-size:1.1rem;font-weight:700;color:var(--text1)">Brand Domain Exposure</div>
          <div style="font-size:.74rem;color:var(--text3);margin-top:3px">DomÃ­nios que deveriam ser da empresa mas nÃ£o sÃ£o â€” risco de phishing e brand confusion.</div>
        </div>
        <div style="margin-left:auto">${scanMeta}</div>
      </div>

      <!-- Stat row -->
      <div style="display:flex;gap:10px;margin-bottom:18px;flex-wrap:wrap">
        ${[
          ['CrÃ­tico (MX+SSL)', critical.length, 'var(--purple)'],
          ['Ã€ Venda',          broker.length,   'var(--red)'],
          ['Ativos',           active.length,   'var(--orange)'],
          ['Registrados',      noip.length,     'var(--yellow)'],
          ['Parked',           parked.length,   'var(--text3)'],
          ['PrÃ³prios',         companyOwned.length,'var(--green)'],
        ].map(([label,count,color])=>`
          <div class="stat-card" style="min-width:100px;text-align:center">
            <div class="stat-value" style="color:${color}">${count}</div>
            <div class="stat-label">${label}</div>
          </div>`).join('')}
      </div>

      ${!registered.length ? `
        <div class="empty-state" style="padding:40px">
          <div class="empty-state-copy">Nenhum domÃ­nio de marca encontrado ainda.<br>
          Rode o mÃ³dulo Typosquat no pipeline.</div>
        </div>` : `
        ${section('CRÃTICO â€” Phishing Kit Completo (MX e/ou SSL+Brand)', 'ðŸš¨', 'var(--purple)', critical, '', true)}
        ${section('Ã€ Venda em Broker',   'ðŸ·ï¸', 'var(--red)',    broker,       '(nenhum)')}
        ${section('Ativo â€” Terceiro',    'âš ï¸', 'var(--orange)', active,       '(nenhum)')}
        ${section('Registrado sem IP',   'ðŸ“‹', 'var(--yellow)', noip,         '(nenhum)')}
        ${section('Parked',              'ðŸ…¿ï¸', 'var(--text3)',  parked,       '', true)}
        ${section('PrÃ³prios da Empresa', 'âœ…', 'var(--green)',  companyOwned, '', true)}
      `}

      ${opensquatHtml}

      <div style="margin-top:16px;padding:12px 14px;background:var(--bg3);border-radius:6px;font-size:.71rem;color:var(--text3)">
        <strong style="color:var(--text2)">O que fazer:</strong>
        <strong style="color:var(--purple)">CrÃ­tico</strong> = domÃ­nio ativo com MX (pode enviar e-mail como a marca) e/ou certificado SSL com nome da marca â€” remediar imediatamente (takedown ou registro).
        <strong style="color:var(--red)">Ã€ Venda</strong> = comprar antes do atacante.
        <strong style="color:var(--orange)">Ativo</strong> = monitorar e solicitar takedown via registrar.
        CT Log via opensquat detecta novos registros diariamente (cron 06:00).
      </div>
    </div>`;
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  INFRA TAB (auto-generated from parser + static for Porto Seguro demo)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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

  if (co.id === "portoseguro") {
    el.innerHTML = shell(`
      ${_infraCard("â˜ Azure AD / Microsoft Identity", [
        _infraRow("Tenant ID", "ed7958eb-216a-4854-a42e-3c7127272021", "hi"),
        _infraRow("Tenant Domain", "portoseguro.com.br"),
        _infraRow("Namespace", "Managed (Azure AD)"),
        _infraRow("App: Pagamentos", "f7803731-7830-4239-a811-fee25df9883a", "hi"),
        _infraRow("App: SailPoint", "e488b780-0d92-4e92-8ea4-8b24849c0800", "hi"),
        _infraRow("OAuth Token URL", "login.windows.net/ed7958eb.../oauth2/token", ""),
      ])}
      ${_infraCard("ðŸ” IAM / Identity Platforms", [
        _infraRow("SailPoint Tenant", "portoseguro.login.sailpoint.com", "hi"),
        _infraRow("SailPoint API", "portoseguro.api.identitynow.com"),
        _infraRow("Portal Externo", "portaldeacessos.portoseguro.com.br"),
        _infraRow("Formato usuÃ¡rio", "f0123456 (f + 7 dÃ­gitos)", "hi"),
        _infraRow("Cognito PRD", "aem-prd.auth.ca-central-1.amazoncognito.com"),
        _infraRow("Cognito HML", "aem-hml.auth.ca-central-1.amazoncognito.com"),
        _infraRow("Citrix Gateway 1", "ho.portoseguro.com.br"),
        _infraRow("Citrix Gateway 2", "ho.ctx.portoseguro.com.br"),
      ])}
      ${_infraCard("ðŸ”Œ API Gateways", [
        _infraRow("Sensedia PRD", "api-portoseg.sensedia.com", "hi"),
        _infraRow("Sensedia HML", "apihlg-portoseg.sensedia.com"),
        _infraRow("Sensedia DEV", "apidev-portoseg.sensedia.com"),
        _infraRow("MuleSoft HML", "api.bap-hml.portoseguro.com.br"),
        _infraRow("AWS GW 1", "bxn9o4w0pd.execute-api.ca-central-1.amazonaws.com", "hi"),
        _infraRow("AWS GW 2", "47zimjues7.execute-api.us-west-2.amazonaws.com", "hi"),
      ])}
      ${_infraCard("ðŸŒ WAF / CDN", [
        _infraRow("Imperva IP 1", "45.223.45.75 (128 hosts)", "hi"),
        _infraRow("Imperva IP 2", "45.223.41.75 (2 hosts)"),
        _infraRow("Cloudflare", "~16 hosts"),
        _infraRow("AWS CloudFront", "~41 hosts"),
        _infraRow("Diretos (sem WAF)", "~56 hosts expostos", "warn"),
      ])}
      ${_infraCard("ðŸ¢ Internal Applications", [
        _infraRow("MISP", "misp.portoseguro.com.br (131.161.97.x)", "warn"),
        _infraRow("Tableau", "tableau.portoseguro.com.br (2023.1.7)", "warn"),
        _infraRow("Orquestrador Pgmt", "portal.meiosdepagamento.portoseguro.com.br"),
        _infraRow("Backoffice Loja", "psstore.portoseguro.com.br"),
        _infraRow("Portal Prestador DEV", "dev.saude.portoseguro.com.br", "hi"),
        _infraRow("API Marketplace", "developers.portoseguro.com.br (Axway)"),
      ])}
      ${_infraCard("ðŸ—º Internal Network (DNS Leak)", [
        _infraRow("Range principal", "131.161.96.x / 131.161.97.x", "hi"),
        _infraRow("NAC Server 1", "nac11dc00-tlf â†’ 172.28.1.172"),
        _infraRow("NAC Server 2", "nac12db02-tlf â†’ 172.28.1.173"),
        _infraRow("ALM Server", "portoalm â†’ 172.27.73.27"),
        _infraRow("Hostname CSP leak", "nt50388.portoseguro.brasil", "warn"),
        _infraRow("SBC (VoIP)", "sbc.portoseguro.com.br â†’ 131.161.97.102"),
      ])}
    `);
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
  const hasAny = cidrs.length ||
    (co.asn_numbers || []).length ||
    Object.keys(dns).length ||
    Object.keys(waf).length ||
    Object.keys(cloudAssets).length ||
    Object.keys(cloudHosts).length ||
    cloudBucketFindings.length;

  if (!hasAny) {
    el.innerHTML = `<div class="empty-state"><div class="empty-state-icon">ðŸ§±</div><div class="empty-state-title">No infrastructure data yet</div><div class="empty-state-copy">Run a pipeline scan to populate ASN, DNS, WAF and leak-related infrastructure details.</div></div>` + _emailPivotSection(co);
    return;
  }

  let cards = '';

  // ASN / CIDR card
  if (cidrs.length || co.asn_numbers?.length) {
    const asnNums = (co.asn_numbers || []).join(', ') || 'â€”';
    const cidrRows = [
      _infraRow("ASN(s)", esc(asnNums)),
      _infraRow("CIDRs", `${cidrs.length} ranges`),
      ...cidrs.slice(0, 12).map(c => _infraRow("CIDR", esc(c), "hi")),
    ];
    cards += _infraCard("ðŸŒ IP Ranges / ASN", cidrRows);
  }

  if (Object.keys(waf).length) {
    const wafRows = Object.entries(waf).map(([k,v]) => _infraRow(k, `${v} hosts`));
    const unprotected = hosts.length - Object.values(waf).reduce((a,b)=>a+b,0);
    cards += _infraCard("ðŸ›¡ WAF / CDN Coverage", [
      ...wafRows,
      ...(unprotected > 0 ? [_infraRow("No WAF", `${unprotected} hosts exposed`, "warn")] : []),
    ]);
  }

  if (Object.keys(cloudAssets).length || Object.keys(cloudHosts).length) {
    const cloudRows = [
      ...Object.entries(cloudAssets).map(([k,v]) => _infraRow(k, `${v} hosts`, "hi")),
      ...Object.entries(cloudHosts).map(([k,v]) => _infraRow(k, `${v.length} hosts`, "hi")),
    ];
    cards += _infraCard("â˜ Cloud Providers", cloudRows);
  }

  const cloudBuckets = (co.cloud_buckets && co.cloud_buckets.findings) || [];
  if (cloudBuckets.length) {
    cards += _cloudBucketsCard(cloudBuckets);
  }

  if (Object.keys(dns).length) {
    const mx = (dns.MX||[]).map(r=>r.value||r).join(', ') || 'â€”';
    const ns = (dns.NS||[]).slice(0,4).map(r=>r.value||r).join(', ') || 'â€”';
    const spf = (dns.TXT||[]).find(r=>(r.value||r).startsWith('v=spf'));
    const dmarc = (dns.TXT||[]).find(r=>(r.value||r).startsWith('v=DMARC'));
    cards += `<div class="ic"><div class="ic-title">ðŸ”Ž DNS Records</div>
      <div class="ic-row"><span class="ic-k">MX</span><span class="ic-v">${esc(mx)}</span></div>
      <div class="ic-row"><span class="ic-k">NS</span><span class="ic-v">${esc(ns)}</span></div>
      <div class="ic-row"><span class="ic-k">SPF</span><span class="ic-v ${spf?'':'warn'}">${spf ? esc((spf.value||spf).slice(0,80)) : 'Missing'}</span></div>
      <div class="ic-row"><span class="ic-k">DMARC</span><span class="ic-v ${dmarc?'':'warn'}">${dmarc ? esc((dmarc.value||dmarc).slice(0,80)) : 'Missing'}</span></div>
      <div class="ic-row"><span class="ic-k">TXT records</span><span class="ic-v">${(dns.TXT||[]).length}</span></div>
    </div>`;
  }

  el.innerHTML = shell(cards) + _emailPivotSection(co);
}

function _cloudBucketsCard(findings) {
  const ACCESS_LABELS = {
    public_write_acl: "ACL pÃºblica (escrita)",
    public_read_sensitive: "Leitura pÃºblica (sensÃ­vel)",
    public_list_sensitive: "Listagem pÃºblica (sensÃ­vel)",
    public_read: "Leitura pÃºblica",
    public_list: "Listagem pÃºblica",
    exists_redirect: "Existe (redirect)",
    exists_private: "Existe (privado)",
  };
  const rows = findings.map(f => {
    const accessLabel = ACCESS_LABELS[f.access] || f.access || "â€”";
    const sevCls = f.severity === "critical" ? "warn" : (f.severity === "low" ? "" : "");
    const objCount = f.object_count != null ? f.object_count : 0;
    let extra = '';
    if ((f.sample_objects || []).length) {
      extra += `<div class="ic-row"><span class="ic-k"></span><span class="ic-v" style="font-family:var(--mono);font-size:.7rem;opacity:.8">Objetos: ${(f.sample_objects||[]).slice(0,8).map(o=>esc(o)).join(', ')}${f.sample_objects.length>8?'â€¦':''}</span></div>`;
    }
    if ((f.sensitive_files || []).length) {
      extra += `<div class="ic-row"><span class="ic-k"></span><span class="ic-v warn" style="font-family:var(--mono);font-size:.7rem">âš  Arquivos sensÃ­veis: ${(f.sensitive_files||[]).slice(0,5).map(o=>esc(o)).join(', ')}</span></div>`;
    }
    if (f.acl && (f.acl.public_write_perms||[]).length) {
      extra += `<div class="ic-row"><span class="ic-k"></span><span class="ic-v warn">âš  ACL anÃ´nima: ${esc((f.acl.public_write_perms||[]).join('/'))}</span></div>`;
    }
    return `<div class="ic-row"><span class="ic-k">${esc(f.provider || '')}</span><span class="ic-v ${sevCls}">${esc(f.name || '')} Â· ${esc(accessLabel)}${objCount ? ' Â· ' + objCount + ' objetos' : ''}</span></div>${extra}`;
  }).join("");
  return _infraCard("â˜ Cloud Storage Buckets", [rows]);
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
      <td>${esc(name || 'â€”')}</td>
      <td>${esc(d.position || 'â€”')}</td>
      <td>${d.confidence != null ? esc(String(d.confidence)) + '%' : 'â€”'}</td>
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
        <div class="section-title">Pivot de E-mails / FuncionÃ¡rios (${emails.length})</div>
        <div class="section-sub">E-mails e colaboradores descobertos via Hunter.io / theHarvester â€” use os links para pivotar em redes sociais e bases de vazamentos.</div>
      </div>
    </div>
    <div style="overflow-x:auto"><table class="people-table">
      <thead><tr><th>E-mail</th><th>Nome</th><th>Cargo</th><th>ConfianÃ§a</th><th>Pivot</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
  </div>`;
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  FINDINGS RENDER (sevCls/sevLbl now in js/asm.js)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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
  // â”€â”€ Normalize legacy field names â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (!f.desc && f.description) f.desc = f.description;
  if (!f.title && f.name) f.title = f.name;
  if (!f.id) f.id = _hashId(f.title || '', f.host || '', f.severity || '');

  // Extract confidence from description, e.g. "Confidence: [PROBABLE]"
  const confMatch = (f.desc||"").match(/Confidence:\s*\[([^\]]+)\]/i);
  const conf = confMatch ? confMatch[1] : "";
  // Clean description â€” strip trailing truncation artifacts
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

  // Tags â€” skip noisy internal bbot tags
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
        ${kevFlag ? `<span style="background:#dc262622;border:1px solid #dc262655;border-radius:4px;padding:2px 8px;color:#f43f5e;font-weight:700">âš  KEV</span>` : ""}
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
      ${srcUrl ? `<div style="font-size:.7rem;margin-top:4px"><a class="fc-url-link" href="${esc(srcUrl)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">ðŸ“„ ${esc(srcUrl)}</a></div>` : ""}
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
      const m = (f.desc||"").match(/Origin:\s*(\S+)\s*â†’\s*ACAO:\s*([^\s]+)/);
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
        ${ips.length ? `<span style="background:var(--sidebar);border:1px solid var(--border);border-radius:4px;padding:3px 8px;font-family:monospace;font-size:.67rem">${ips.map(esc).join(' Â· ')}</span>` : ''}
      </div>`;
    }
    if (f.type === "postman_github" || f.type === "postman_secret") {
      const repo    = (f.metadata && f.metadata.repo) || "";
      const kind    = (f.metadata && f.metadata.kind) || "";
      const fileUrl = f.value && f.value.startsWith("http") ? f.value : (f.url || "");
      return `<div style="font-size:.71rem;margin:6px 0 3px">
        ${repo ? `<div style="background:var(--sidebar);border:1px solid var(--border);border-radius:4px;padding:4px 9px;margin-bottom:4px">ðŸ“¦ <b style="color:var(--accent)">${esc(repo)}</b>${kind ? ` Â· <span style="color:var(--text3)">${esc(kind)}</span>` : ''}</div>` : ''}
        ${fileUrl ? `<a class="fc-url-link" href="${esc(fileUrl)}" target="_blank" rel="noopener" onclick="event.stopPropagation()" style="font-size:.68rem">ðŸ”— ${esc(fileUrl.slice(0,90))}${fileUrl.length>90?'â€¦':''}</a>` : ''}
      </div>`;
    }
    if (f.type === "attack_chain") {
      const m = (f.title||"").match(/(\d+)\s+finding/);
      const count = m ? parseInt(m[1]) : null;
      return count ? `<div style="font-size:.71rem;margin:6px 0 3px;background:rgba(244,63,94,0.07);border:1px solid rgba(244,63,94,0.25);border-radius:4px;padding:5px 9px;color:#f43f5e">
        â›“ ${count} findings de alta severidade concentrados neste host
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
    ${f.url && f.type !== "secret" ? `<div style="margin-bottom:6px"><a class="fc-url-link" href="${esc(f.url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">ðŸ”— ${esc(f.url)}</a></div>` : ""}
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
          title="Mark as False Positive">âœ• FP</button>
        <button class="btn btn-secondary" style="font-size:.62rem;padding:2px 6px;flex-shrink:0;color:var(--text3);background:transparent;border:1px solid var(--border)"
          onclick="event.stopPropagation();copyToClipboard('${escAttr(f.title||'')}: ${escAttr(f.host||'')}')" title="Copy finding">ðŸ“‹</button>
      </div>
      <div class="fc-summary">${esc(textPreview(descClean, 220) || "No description available.")}</div>
      <div class="fc-detail" id="fd-${f.id}">${detailHtml}</div>
    </div>
    <div class="chevron">â–¼</div>
  </div>`;
}

function toggleFC(id) {
  const c=document.getElementById("fc-"+id), d=document.getElementById("fd-"+id);
  if(!d) return;
  c.classList.toggle("open"); d.classList.toggle("show");
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  ADD COMPANY
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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
  if (!_editCoId) { alert("No company selected for deletion."); return; }
  const co = allCompanies().find(c => c.id === _editCoId);
  const name = co ? co.name : _editCoId;
  if (!confirm(`Delete "${name}" and all its data? This cannot be undone.`)) return;
  if (!SERVER_MODE) { alert("Delete only available in server mode."); return; }
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
    // Remove from local DATA immediately â€” reloadServerData only adds, never removes
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
    if (!r.ok) { alert(co.error||"Error"); return; }
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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  SCAN
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
let activeScanId  = null;
let scanEventSrc  = null;
let scanLineCount = 0;
let scanStartTime = null;
let selectedProfile = "bug_bounty";

// â”€â”€ Module ETA tracker â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const MODULE_ETA_S = {
  // DNS core
  dnsresolve:45,  speculate:5,    cloudcheck:10,  dnsbrute:300,
  dnscommonsrv:20, dnsbimi:15,    dnstlsrpt:10,   dnscaa:10,
  baddns:30,      baddns_zone:20,
  // HTTP
  httpx:90,       sslcert:30,     securitytxt:15, azure_realm:15,
  // Subdomain sources
  subfinder:60,   assetfinder:20, anubisdb:30,    certspotter:30,
  crt:30,         crt_db:20,      digitorus:20,hackertarget:15, myssl:15,      rapiddns:15,    sitedossier:20,
  subdomaincenter:15, urlscan:30, virustotal:20,  chaos:15,
  leakix:15,      otx:15,         wayback:60,     shodan_dns:20,
  shodan_idb:30,  securitytrails:20, censys_dns:20, censys_ip:20,
  // Cloud / Buckets
  bucket_amazon:30, bucket_firebase:20, bucket_google:20,
  bucket_microsoft:20, bucket_digitalocean:20,
  azure_tenant:15, asn:20,
  // Code / Secrets
  git:60,         git_clone:60,   github_codesearch:30, github_usersearch:20,
  github_org:15,  github_workflows:15, trufflehog:120,
  // Vuln
  nuclei:600,     badsecrets:60,
};

let _scanModules  = [];
let _moduleActive = new Set();
let _moduleDone   = new Set();
let _prevRunning  = new Set();

// â”€â”€ BBOT HUD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const BBOT_HUD_PHASES = [
  {id:"discovery", label:"DISCOVERY", icon:"â—‰", color:"#00e5ff",
   mods:["subfinder","assetfinder","certs","alienvault_otx","urlscan_io","rapiddns","hackertarget","github_subdomains","wayback","urlfinder"]},
  {id:"validation", label:"VALIDATE", icon:"âŒ", color:"#818cf8",
   mods:["dns","dns_brute","leaks"]},
  {id:"intel", label:"INTEL", icon:"âš¡", color:"#fbbf24",
   mods:["shodan","postman_collections","cloud","container_registry","bulk_dataset","breach","dep_confusion"]},
  {id:"web", label:"WEB/JS", icon:"â¬¡", color:"#4ade80",
   mods:["headers","waf","wappalyzer","whatweb","vendor_fp","service_version","favicon_hunt","js","js_endpoints","js_secrets","api_discovery_extra","graphql"]},
  {id:"browser", label:"BROWSER", icon:"â–£", color:"#c084fc",
   mods:["browser_crawl","browser_recon","screenshot","gowitness"]},
  {id:"checks", label:"CHECKS", icon:"âš ", color:"#f43f5e",
   mods:["takeover","subjack","cors_scan","open_redirect","host_header_injection","infra_exposure","cloud_enum","default_creds","dnssec","waf_bypass","tableau","github_repos","supply_chain","portscan","services","cms_scan","cve","api_panels"]},
];
const _MOD_PHASE = {};
BBOT_HUD_PHASES.forEach((p,i) => p.mods.forEach(m => (_MOD_PHASE[m] = i)));
let _modState = {};
let _hudLogLines = [];
let _particleAnim = null;

function _stripAnsi(s) { return s.replace(/\x1b\[[0-9;]*m/g, ''); }

function _detectModules(line) {
  const plain = _stripAnsi(line);

  // Setup soft-failed
  const fail = plain.match(/Setup soft-failed for (\w+):/);
  if (fail) { _modState[fail[1]] = 'skipped'; renderHUD(); return; }

  // API is ready
  const ready = plain.match(/\[SUCC\][^\n]*?(\w+):\s+(?:\[.*?m)?API is ready/);
  if (ready) { _modState[ready[1]] = 'ready'; renderHUD(); return; }

  // Scan completed â€” finalize all pending HUD phases
  if (/completed in .+ with status FINISHED/i.test(plain)) {
    _finalizeScanHUD();
    return;
  }

  // Modules running
  const runMatch = plain.match(/Modules running[^)]+\)\s+(.*)/);
  if (runMatch) {
    const cur = new Set();
    (runMatch[1].match(/(\w+)\(\d+:\d+:\d+\)/g) || []).forEach(p => {
      const name = p.match(/(\w+)\(/)[1];
      cur.add(name);
      _moduleActive.add(name);
      _modState[name] = 'running';
    });
    _prevRunning.forEach(m => {
      if (!cur.has(m)) { _moduleDone.add(m); _modState[m] = 'done'; }
    });
    _prevRunning = cur;
    _updateETA();
    renderHUD();
  }
}

// Mark all HUD phase modules that never appeared in "Modules running" as done.
// Called when scan finishes â€” catches modules that ran too fast to be logged.
function _finalizeScanHUD() {
  _prevRunning.forEach(m => { _moduleDone.add(m); _modState[m] = 'done'; });
  _prevRunning = new Set();
  BBOT_HUD_PHASES.forEach(phase => {
    phase.mods.forEach(m => {
      if (!_modState[m]) { _modState[m] = 'done'; _moduleDone.add(m); }
    });
  });
  _updateETA();
  renderHUD();
}

// â”€â”€ Particle engine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function _startParticles() {
  const canvas = document.getElementById('hud-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  function resize() { canvas.width = canvas.offsetWidth; canvas.height = canvas.offsetHeight; }
  resize();
  const obs = new ResizeObserver(resize);
  obs.observe(canvas.parentElement);
  const pts = Array.from({length:55}, () => ({
    x: Math.random(), y: Math.random(),
    vx: (Math.random()-.5)*.0004, vy: (Math.random()-.5)*.0004,
    r: Math.random()*.9+.2, a: Math.random()*.35+.05,
  }));
  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    pts.forEach(p => {
      const x = p.x * canvas.width, y = p.y * canvas.height;
      ctx.beginPath(); ctx.arc(x, y, p.r, 0, Math.PI*2);
      ctx.fillStyle = `rgba(0,180,255,${p.a})`; ctx.fill();
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = 1; if (p.x > 1) p.x = 0;
      if (p.y < 0) p.y = 1; if (p.y > 1) p.y = 0;
    });
    _particleAnim = requestAnimationFrame(draw);
  }
  if (_particleAnim) cancelAnimationFrame(_particleAnim);
  draw();
}
function _stopParticles() {
  if (_particleAnim) { cancelAnimationFrame(_particleAnim); _particleAnim = null; }
}

// â”€â”€ HUD render â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function _phaseStatus(idx) {
  const phase = BBOT_HUD_PHASES[idx];
  const all = [...phase.mods, ...Object.keys(_modState).filter(m => _MOD_PHASE[m]===idx && !phase.mods.includes(m))];
  if (all.some(m => _modState[m]==='running'))  return 'active';
  if (all.some(m => _modState[m]==='done'))      return 'done';
  return 'pending';
}

function _buildPanel(phase, idx, show) {
  if (!show) return `<div class="hud-panel ph-hidden"></div>`;
  const st = _phaseStatus(idx);
  const all = [...phase.mods, ...Object.keys(_modState).filter(m => _MOD_PHASE[m]===idx && !phase.mods.includes(m))];

  const running = all.filter(m => _modState[m]==='running');
  const done    = all.filter(m => _modState[m]==='done');
  const ready   = all.filter(m => _modState[m]==='ready');
  const skipped = all.filter(m => _modState[m]==='skipped');

  const totalActive = running.length + done.length + ready.length;
  const pct = totalActive ? Math.round(done.length / Math.max(totalActive, 1) * 100) : 0;

  // Show: running first, then recent done, then ready; max 7 per panel
  const toShow = [...running, ...done.slice(-4), ...ready.slice(0,2)].slice(0,7);
  const skipHtml = skipped.length
    ? `<div class="hud-panel-mod hud-mod-skipped"><div class="hud-panel-mod-dot"></div><span>${skipped.length} sem api key</span></div>`
    : '';
  const modHtml = toShow.map(m => {
    const s = _modState[m]||'pending';
    return `<div class="hud-panel-mod hud-mod-${s}"><div class="hud-panel-mod-dot"></div><span>${m.replace(/_/g,' ')}</span></div>`;
  }).join('');

  const statsHtml = (done.length || running.length || skipped.length)
    ? `<div style="font-size:.53rem;color:#1e3a4a;margin-top:3px;letter-spacing:.04em">${done.length} ok Â· ${running.length} active Â· ${skipped.length} skip</div>`
    : '';

  // Placeholder when no modules ran yet: distinguish "waiting" vs "all skipped"
  const allSkipped = !toShow.length && skipped.length > 0 && skipped.length === all.length;
  const placeholder = allSkipped
    ? `<div class="hud-panel-mod hud-mod-skipped"><div class="hud-panel-mod-dot"></div><span>sem chaves configuradas</span></div>`
    : `<div class="hud-panel-mod hud-mod-pending"><div class="hud-panel-mod-dot"></div><span>aguardandoâ€¦</span></div>`;

  return `<div class="hud-panel ${st}">
    <div class="hud-panel-label" style="color:${phase.color}">${phase.label}</div>
    <div class="hud-panel-prog"><div class="hud-panel-prog-bar" style="width:${pct}%;background:${phase.color}"></div></div>
    ${modHtml || placeholder}
    ${skipHtml}${statsHtml}
  </div>`;
}

function renderHUD() {
  const topEl   = document.getElementById('hud-top');
  const botEl   = document.getElementById('hud-bot');
  const nodesEl = document.getElementById('hud-nodes');
  const glowEl  = document.getElementById('hud-tl-glow');
  if (!topEl||!botEl||!nodesEl) return;

  // Timeline glow (progress across phases)
  const donePhases = BBOT_HUD_PHASES.filter((_,i)=>_phaseStatus(i)==='done').length;
  const activePh   = BBOT_HUD_PHASES.findIndex((_,i)=>_phaseStatus(i)==='active');
  const progress   = activePh>=0 ? (activePh+.5)/BBOT_HUD_PHASES.length : donePhases/BBOT_HUD_PHASES.length;
  if (glowEl) glowEl.style.right = `${Math.round((1-progress)*100)}%`;

  // Nodes
  nodesEl.innerHTML = BBOT_HUD_PHASES.map((phase, idx) => {
    const st = _phaseStatus(idx);
    return `<div class="hud-node ${st}" style="--nc:${phase.color}" title="${phase.label}">
      <div class="hud-node-inner">${st==='done'?'âœ“':phase.icon}</div>
      <div class="hud-node-label">${phase.label}</div>
    </div>`;
  }).join('');

  // Panels alternating top/bottom
  topEl.innerHTML = BBOT_HUD_PHASES.map((p,i) => _buildPanel(p,i, i%2===0)).join('');
  botEl.innerHTML = BBOT_HUD_PHASES.map((p,i) => _buildPanel(p,i, i%2===1)).join('');
}

function _fmtSec(s) {
  if (s >= 3600) return `~${Math.ceil(s/3600)}h`;
  if (s >= 60)   return `~${Math.ceil(s/60)}m`;
  return `~${s}s`;
}

function _updateETA() {
  // Total = all modules ever seen (active + done)
  const allSeen = new Set([..._moduleActive, ..._moduleDone]);
  const total   = allSeen.size || 1;
  const done    = _moduleDone.size;
  const active  = _prevRunning.size;
  const remaining = Math.max(0, total - done);

  // Sum ETA for modules not yet done
  let remSec = 0;
  allSeen.forEach(m => { if (!_moduleDone.has(m)) remSec += (MODULE_ETA_S[m] || 45); });
  const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
  // Decay: each elapsed second removes proportional estimated time
  remSec = Math.max(0, remSec - Math.floor(elapsed * (done / Math.max(total, 1))));

  const el = document.getElementById('term-modules');
  const sb = document.getElementById('scanbar-modules');
  if (remaining > 0) {
    const etaStr = _fmtSec(remSec);
    const html = `<span style="color:var(--teal)">${done}/${total}</span> modules`
      + ` Â· <span style="color:var(--yellow)">${active} active</span>`
      + ` Â· <span style="color:var(--text3)">${remaining} remaining Â· ETA ${etaStr}</span>`;
    if (el) el.innerHTML = html;
    if (sb) sb.textContent = `${done}/${total} Â· ${active} active Â· ETA ${etaStr}`;
  } else {
    if (el) el.innerHTML = `<span style="color:var(--green)">âœ“ ${done} modules completed</span>`;
    if (sb) sb.textContent = `âœ“ ${done} modules`;
  }
}

function selectProfile(val, el) {
  selectedProfile = val;
  document.querySelectorAll(".scan-profile").forEach(e=>e.classList.remove("selected"));
  el.classList.add("selected");
  document.getElementById("scan-flags-field").style.display = val==="custom" ? "block" : "none";
}

let selectedRateMode = "stealth";
function selectRateMode(val, el) {
  selectedRateMode = val;
  document.querySelectorAll(".rate-mode-btn").forEach(e=>e.classList.remove("selected"));
  el.classList.add("selected");
}

async function monitorNow(cid) {
  // Run a quick pipeline scan now (stealth mode)
  var btn = document.getElementById('monitor-now-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'â³ Starting...'; }
  try {
    var r = await fetch('/api/recon/' + cid + '/pipeline', {
      method:'POST',
      headers: {'Content-Type':'application/json', ..._authHeaders()},
      body: JSON.stringify({mode:'stealth'})
    });
    var data = await r.json();
    if (r.ok) {
      alert('Pipeline started in stealth mode â€” check Pipeline HUD tab');
      showPage('company'); selectCompany(cid); switchTab('pipeline');
    } else {
      alert('Error: ' + (data.error || 'Unknown'));
    }
  } catch(e) { alert('Failed: ' + e.message); }
  if (btn) { btn.disabled = false; btn.textContent = 'ðŸ” Monitor Now'; }
}

async function enableSchedule(cid, enabled) {
  try {
    if (enabled) {
      var interval = prompt('Scan interval (hours):', '24');
      if (!interval) return;
    }
    var r = await fetch('/api/schedule/' + cid, {
      method:'POST',
      headers: {'Content-Type':'application/json', ..._authHeaders()},
      body: JSON.stringify({enabled: enabled, interval_hours: enabled ? parseInt(interval) : 24, profile: 'bug_bounty'})
    });
    if (r.ok) {
      alert('Schedule ' + (enabled ? 'enabled â€” every ' + interval + 'h' : 'disabled'));
      loadScheduleStatus(cid);
    }
  } catch(e) { alert('Failed: ' + e.message); }
}

async function loadScheduleStatus(cid) {
  var schBtn = document.getElementById("enable-schedule-btn");
  if (!schBtn) return;
  try {
    var r = await fetch('/api/schedule/' + cid, {headers:_authHeaders()});
    if (!r.ok) { schBtn.textContent = 'â± Schedule'; return; }
    var s = await r.json();
    if (s && s.enabled) {
      schBtn.textContent = 'â± ' + (s.interval_hours||'?') + 'h On';
      schBtn.style.color = '#4ade80';
    } else {
      schBtn.textContent = 'â± Schedule Off';
      schBtn.style.color = '';
    }
  } catch(e) { schBtn.textContent = 'â± Schedule'; }
}

async function toggleSchedule(cid) {
  var btn = document.getElementById("enable-schedule-btn");
  if (!btn) return;
  try {
    var r = await fetch('/api/schedule/' + cid, {headers:_authHeaders()});
    var s = r.ok ? await r.json() : {};
    if (s && s.enabled) {
      if (!confirm('Schedule is active (every ' + (s.interval_hours||'?') + 'h). Disable it?')) return;
      await fetch('/api/schedule/' + cid, {method:'POST', headers:{'Content-Type':'application/json', ..._authHeaders()}, body:JSON.stringify({enabled:false, interval_hours:s.interval_hours||24, profile:'bug_bounty'})});
      btn.textContent = 'â± Schedule Off'; btn.style.color = '';
    } else {
      var interval = prompt('Scan interval (hours):', '24');
      if (!interval) return;
      await fetch('/api/schedule/' + cid, {method:'POST', headers:{'Content-Type':'application/json', ..._authHeaders()}, body:JSON.stringify({enabled:true, interval_hours:parseInt(interval), profile:'bug_bounty'})});
      btn.textContent = 'â± ' + interval + 'h On'; btn.style.color = '#4ade80';
    }
  } catch(e) { console.error(e); }
}

async function openScanModal(companyId) {
  if (!SERVER_MODE) {
    alert("Start the server to run scans:\n\npython3 server.py\n\nThen open http://localhost:5000");
    return;
  }
  const co = allCompanies().find(c=>c.id===companyId);
  if (!co) return;
  document.getElementById("scan-modal-co").textContent = co.name;
  document.getElementById("scan-error").style.display = "none";
  document.getElementById("modal-scan").classList.add("show");
  _scanCompanyId = companyId;

  // Show targets with loading state while validating
  const targetsEl = document.getElementById("scan-targets-list");
  targetsEl.innerHTML = (co.domains||[]).map(d=>`<div>â³ ${esc(d)}</div>`).join("");

  try {
    const r = await fetch("/api/validate-domains", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({domains: co.domains||[]})
    });
    const results = await r.json();
    targetsEl.innerHTML = results.map(item => {
      const icon = item.ok ? "âœ“" : "âœ—";
      const color = item.ok ? "var(--teal)" : "var(--red)";
      const detail = item.ok ? item.ip : item.error;
      return `<div style="color:${color}">${icon} ${esc(item.domain)} <span style="color:var(--text3);font-size:.68rem">${esc(detail)}</span></div>`;
    }).join("");
    // Warn if any domain fails
    const failed = results.filter(r=>!r.ok);
    if(failed.length){
      const errEl = document.getElementById("scan-error");
      errEl.textContent = `Warning: ${failed.length} domain(s) did not resolve. Scan may produce limited results.`;
      errEl.style.display = "block";
      errEl.style.background = "rgba(251,191,36,0.1)";
      errEl.style.color = "#fbbf24";
      errEl.style.borderColor = "rgba(251,191,36,0.2)";
    }
  } catch(e) {
    targetsEl.innerHTML = (co.domains||[]).map(d=>`<div>${esc(d)}</div>`).join("");
  }
}

let _scanCompanyId = null;
function closeScanModal() {
  document.getElementById("modal-scan").classList.remove("show");
  document.getElementById("scan-checkpoint-info").style.display = "none";
}

async function runCheckpointDiff() {
  const btn = document.getElementById("checkpoint-btn");
  const infoEl = document.getElementById("scan-checkpoint-info");
  const bodyEl = document.getElementById("scan-checkpoint-body");
  btn.disabled = true;
  btn.textContent = "Fingerprintingâ€¦";
  infoEl.style.display = "block";
  bodyEl.innerHTML = `<span style="color:var(--text3)">Fetching live hosts and computing hashesâ€¦ this takes ~30s</span>`;

  try {
    // Start the checkpoint scan job
    const r = await fetch(`/api/checkpoints/${_scanCompanyId}/scan`, {method:"POST",
      headers: _authHeaders(), body:"{}"});
    if (!r.ok) throw await _apiErr(r);
    const { scan_id, total_hosts } = await r.json();
    bodyEl.innerHTML = `<span style="color:var(--text3)">Scanning ${total_hosts} hostsâ€¦</span>`;

    // Poll until done
    await new Promise((resolve, reject) => {
      const iv = setInterval(async () => {
        try {
          const pr = await fetch(`/api/checkpoints/job/${scan_id}`);
          const pd = await pr.json();
          const pct = total_hosts > 0 ? Math.round((pd.done||0)/total_hosts*100) : 0;
          bodyEl.innerHTML = `<span style="color:var(--text3)">Progress: ${pd.done||0}/${total_hosts} (${pct}%)</span>`;
          if (pd.status === "done") { clearInterval(iv); resolve(pd); }
          else if (pd.status === "error") { clearInterval(iv); reject(new Error(pd.error||"failed")); }
        } catch(e) { clearInterval(iv); reject(e); }
      }, 2000);
    }).then(pd => {
      const SEV = (n) => n > 0 ? `<span style="color:#fb923c;font-weight:600">${n}</span>` : `<span style="color:var(--text3)">${n}</span>`;
      let html = `<div style="margin-bottom:6px">${pd.summary}</div>`;
      if (pd.first_run) {
        html += `<div style="color:var(--teal)">âœ“ First checkpoint saved â€” future scans will diff against this.</div>`;
      } else {
        if (pd.changed && pd.changed.length > 0) {
          html += `<div style="margin-bottom:4px;color:#fb923c;font-weight:600">Changed hosts (${pd.changed.length}) â€” recommend re-scan:</div>`;
          html += pd.changed.slice(0,15).map(url => {
            const fields = (pd.change_details||{})[url] || [];
            return `<div style="font-family:var(--mono);font-size:.7rem;padding:2px 0">
              <span style="color:var(--text)">${url}</span>
              <span style="color:var(--text3);margin-left:6px">[${fields.join(", ")}]</span></div>`;
          }).join("") + (pd.changed.length > 15 ? `<div style="color:var(--text3)">â€¦and ${pd.changed.length-15} more</div>` : "");
        }
        if (pd.new && pd.new.length > 0) {
          html += `<div style="margin-top:6px;color:#4ade80;font-weight:600">New hosts (${pd.new.length}):</div>`;
          html += pd.new.slice(0,10).map(u=>`<div style="font-family:var(--mono);font-size:.7rem">${u}</div>`).join("");
        }
        if ((!pd.changed || !pd.changed.length) && (!pd.new || !pd.new.length)) {
          html += `<div style="color:#4ade80">âœ“ No changes detected â€” no re-scan needed.</div>`;
        }
      }
      bodyEl.innerHTML = html;
    });
  } catch(e) {
    bodyEl.innerHTML = `<span style="color:#fb7185">Error: ${e.message}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "â§— Check Changes";
  }
}

async function startScan() {
  const btn = document.getElementById("scan-start-btn");
  const errEl = document.getElementById("scan-error");
  errEl.style.display = "none";
  btn.disabled = true; btn.textContent = "Startingâ€¦";

  try {
    const r = await fetch(`/api/recon/${_scanCompanyId}/pipeline`, {
      method: "POST",
      headers: {"Content-Type":"application/json", ..._authHeaders()},
      body: JSON.stringify({ mode: selectedRateMode, profile: selectedProfile }),
    });
    let data = {};
    if (!r.ok) {
      if (r.status === 401) throw await _apiErr(r);
      const t = await r.text();
      if (r.status !== 409 || !t.includes("already running")) {
        throw new Error(t);
      }
    } else {
      data = await r.json().catch(() => ({}));
    }

    closeScanModal();
    // Switch to the Recon tab for the company so the user sees the pipeline progress
    switchTab("pipeline", [...document.querySelectorAll(".tab-btn")].find(b=>b.textContent.includes("Pipeline")));
    pipelineState[_scanCompanyId] = {
      ...(pipelineState[_scanCompanyId] || {}),
      status: data.status || "queued",
      job_id: data.job_id || "",
      phase_label: "",
      host_count: 0,
      phases: [],
      not_done: [],
      started_at: new Date().toLocaleTimeString(),
      log: data.job_id ? [{ts:new Date().toISOString(), msg:`Pipeline queued as job ${data.job_id}`}] : [],
    };
    renderPipelineStatus(_scanCompanyId);
    _startPipelinePoll(_scanCompanyId);
    _ltActiveCid = _scanCompanyId; _ltEnsurePolling();  // start live terminal globally
  } catch(e) {
    errEl.textContent = "Erro ao iniciar pipeline: "+e.message;
    errEl.style.display = "block";
  } finally {
    btn.disabled = false; btn.innerHTML = `<svg viewBox="0 0 16 16" fill="currentColor" style="width:12px;height:12px;margin-right:4px"><path d="M3 2l10 6-10 6V2z"/></svg>Start Scan`;
  }
}

// â”€â”€ Terminal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
let _liveDataInterval = null;
let _lastDataTs = 0;

function stopLiveDataPolling() {
  if (_liveDataInterval) { clearInterval(_liveDataInterval); _liveDataInterval = null; }
  // Note: terminal polling (_ltPoll) is NOT stopped here â€” it runs globally
  // while any pipeline is active, regardless of which tab the user is viewing.
}

function startLiveDataPolling(companyId) {
  stopLiveDataPolling();
  _lastDataTs = 0;
  // Use 8s interval â€” fast enough to catch phase transitions without hammering
  _liveDataInterval = setInterval(async () => {
    try {
      const r = await fetch("/api/data/ts", {headers: _authHeaders()});
      if (!r.ok) return;
      const { ts } = await r.json();
      if (ts > _lastDataTs && _lastDataTs > 0) {
        await reloadServerData();
        if (state.currentId === companyId) {
          const co = allCompanies().find(c => c.id === companyId);
          if (co) renderCompanyView(co);
        }
        renderAllCompanies();
        renderSidebar();
        const liveEl = document.getElementById("term-live-badge");
        if (liveEl) { liveEl.style.opacity = "1"; setTimeout(() => liveEl.style.opacity = "0.4", 800); }
      }
      _lastDataTs = ts;
    } catch(e) {}
  }, 8000);
}

function openTerminal(scanId, scanName, companyId) {
  activeScanId  = scanId;
  scanLineCount = 0;
  scanStartTime = Date.now();
  _scanModules  = [];
  _moduleActive = new Set();
  _moduleDone   = new Set();
  _prevRunning  = new Set();
  _modState     = {};
  _hudLogLines  = [];
  const modEl = document.getElementById('term-modules');
  if (modEl) modEl.innerHTML = '';
  const sbEl = document.getElementById('scanbar-modules');
  if (sbEl) sbEl.textContent = '';

  document.getElementById("term-title").textContent = scanName;
  document.getElementById("term-body").innerHTML = "";
  const logEl = document.getElementById('hud-mini-log');
  if (logEl) logEl.innerHTML = '';
  document.getElementById("terminal-overlay").classList.add("show");
  document.getElementById("term-stop-btn").style.display = "";
  document.getElementById("scanbar-name").textContent = scanName;

  renderHUD();
  _startParticles();
  updateTermStatus("running");
  streamScanOutput(scanId, companyId);
  startLiveDataPolling(companyId);
}

function closeTerminal() {
  document.getElementById("terminal-overlay").classList.remove("show");
  document.getElementById("scan-bar").style.display = "none";
  if (scanEventSrc) { scanEventSrc.close(); scanEventSrc = null; }
  _stopParticles();
}

function minimizeTerminal() {
  document.getElementById("terminal-overlay").classList.remove("show");
  document.getElementById("scan-bar").style.display = "flex";
}

function maximizeTerminal() {
  document.getElementById("terminal-overlay").classList.add("show");
  document.getElementById("scan-bar").style.display = "none";
}

async function stopScan() {
  // Stop pipeline by company ID (current viewed company)
  var cid = state.currentId || _scanCompanyId;
  if (!cid) return;
  await stopPipeline(cid, {notify: true});
  var stopBtn = document.getElementById("stop-pipeline-btn");
  if (stopBtn) stopBtn.style.display = "none";
}

function updateTermStatus(status) {
  const labels = {running:"Scanningâ€¦", done:"Completed", error:"Error", stopped:"Stopped"};
  const el = document.getElementById("term-status");
  el.innerHTML = `<span class="scan-status ${status}"><span class="scan-dot"></span>${labels[status]||status}</span>`;

  const sb = document.getElementById("scanbar-status");
  sb.className = `scan-status ${status}`;
  sb.innerHTML = `<span class="scan-dot"></span>${labels[status]||status}`;

  if (status !== "running") {
    document.getElementById("term-stop-btn").style.display = "none";
    const lb = document.getElementById("term-live-badge");
    if (lb) lb.style.display = "none";
  }
}

function streamScanOutput(scanId, companyId) {
  if (scanEventSrc) scanEventSrc.close();
  const src = new EventSource(`/api/scan/${scanId}/stream`);
  scanEventSrc = src;

  src.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.done) {
      src.close(); scanEventSrc = null;
      stopLiveDataPolling();
      updateTermStatus(msg.status);
      _finalizeScanHUD();
      document.getElementById("term-stop-btn").style.display = "none";
      // Final reload after scan completes
      setTimeout(()=>reloadServerData().then(()=>{
        if (state.currentId === companyId) {
          const co = allCompanies().find(c=>c.id===companyId);
          if (co) renderCompanyView(co);
        }
        renderAllCompanies(); renderSidebar();
      }), 1500);
      return;
    }
    appendTermLine(msg.line);
    updateTermStatus(msg.status);
  };

  src.onerror = () => {
    src.close(); scanEventSrc = null;
    updateTermStatus("error");
  };
}

function appendTermLine(raw) {
  scanLineCount++;
  const plain = _stripAnsi(raw);

  // Hidden buffer for legacy references
  const body = document.getElementById("term-body");
  if (body) { const d = document.createElement("div"); d.textContent = plain; body.appendChild(d); }

  // Action bar: update on meaningful lines only
  const actionEl = document.getElementById('hud-action');
  if (actionEl && plain.trim()) {
    const isFind  = plain.includes('[FINDING]') || plain.includes('[VULNERABILITY]');
    const isOk    = plain.includes('[âœ“]') || plain.includes('[SUCC]');
    const isWarn  = plain.includes('[!]');
    const isRun   = plain.includes('Modules running');
    if (isFind || isOk || isWarn || isRun || plain.includes('[INFO]')) {
      actionEl.textContent = 'â–¶ ' + plain.replace(/\[.*?\]\s*/g,'').slice(0,140);
      actionEl.className = 'hud-action-bar' + (isFind?'  al-find': isOk?' al-ok': isWarn?' al-active': ' al-run');
    }
  }

  document.getElementById("term-stats").textContent = `${scanLineCount} lines`;
  const elapsed = Math.floor((Date.now()-scanStartTime)/1000);
  document.getElementById("term-time").textContent = `${Math.floor(elapsed/60)}m ${elapsed%60}s elapsed`;

  _detectModules(raw);
}

// â”€â”€ Scan Log Viewer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
let _logAllLines = [];

function _logLineClass(line) {
  if (line.includes('[SUCC]') || line.includes('[âœ“]'))        return 'll-succ';
  if (line.includes('[FINDING]') || line.includes('[VULNERABILITY]')) return 'll-find';
  if (line.includes('[!]') || line.includes('[WARN]'))        return 'll-warn';
  if (line.includes('[ERROR]'))                               return 'll-err';
  if (line.includes('[INFO]'))                                return 'll-info';
  if (!line.trim())                                           return 'll-dim';
  return '';
}

async function openScanLog(cid, scanName) {
  const overlay = document.getElementById('log-modal-overlay');
  const bodyEl  = document.getElementById('log-modal-body');
  const titleEl = document.getElementById('log-modal-title');
  const metaEl  = document.getElementById('log-modal-meta');
  const countEl = document.getElementById('log-modal-count');
  const searchEl= document.getElementById('log-modal-search');
  if (!overlay) return;
  titleEl.textContent = scanName;
  metaEl.textContent  = 'Loadingâ€¦';
  bodyEl.innerHTML    = `<div style="color:var(--text3);padding:20px">Loading scan logâ€¦</div>`;
  searchEl.value      = '';
  overlay.classList.add('show');
  try {
    const r = await fetch(`/api/scan-history/${encodeURIComponent(cid)}/${encodeURIComponent(scanName)}/log`, {headers:_authHeaders()});
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    const data = await r.json();
    _logAllLines = data.lines;
    metaEl.textContent  = `${data.total.toLocaleString()} linhas`;
    countEl.textContent = `${data.lines.length} exibidas de ${data.total}`;
    _renderLogLines(_logAllLines, bodyEl);
  } catch(e) {
    bodyEl.innerHTML = `<div style="color:var(--red);padding:20px">Erro: ${esc(e.message)}</div>`;
  }
}

function _renderLogLines(lines, bodyEl) {
  const frag = document.createDocumentFragment();
  lines.forEach(raw => {
    const plain = _stripAnsi(raw);
    const d = document.createElement('div');
    d.className = 'log-line ' + _logLineClass(plain);
    d.textContent = plain;
    frag.appendChild(d);
  });
  bodyEl.innerHTML = '';
  bodyEl.appendChild(frag);
}

function filterLogLines(q) {
  const bodyEl  = document.getElementById('log-modal-body');
  const countEl = document.getElementById('log-modal-count');
  if (!bodyEl) return;
  const filtered = q ? _logAllLines.filter(l => _stripAnsi(l).toLowerCase().includes(q.toLowerCase())) : _logAllLines;
  countEl.textContent = `${filtered.length} de ${_logAllLines.length} linhas`;
  // Re-render with highlight
  const frag = document.createDocumentFragment();
  filtered.forEach(raw => {
    const plain = _stripAnsi(raw);
    const d = document.createElement('div');
    d.className = 'log-line ' + (q ? 'll-highlight' : _logLineClass(plain));
    d.textContent = plain;
    frag.appendChild(d);
  });
  bodyEl.innerHTML = '';
  bodyEl.appendChild(frag);
}

function scrollLogTo(pos) {
  const b = document.getElementById('log-modal-body');
  if (!b) return;
  b.scrollTop = pos === 'bottom' ? b.scrollHeight : 0;
}

function lineClass(line) {
  if (line.includes("[DNS_NAME]"))        return "dns";
  if (line.includes("[FINDING]"))         return "find";
  if (line.includes("[VULNERABILITY]"))   return "vuln";
  if (line.includes("[WAF]"))             return "waf";
  if (line.includes("[TECHNOLOGY]"))      return "tech";
  if (line.includes("[HTTP_RESPONSE]"))   return "http";
  if (line.includes("[STORAGE_BUCKET]"))  return "warn";
  if (line.includes("[âœ“]") || line.includes("[*]")) return "ok";
  if (line.includes("[!]"))               return "warn";
  if (line.includes("[ERROR]"))           return "err";
  return "default";
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  HELPERS (esc/wafColor/wafClass now in js/asm.js when loaded)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  AUTH
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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
  if (!SERVER_MODE) return true;  // demo mode â€” no auth
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
  const err  = document.getElementById("login-err");
  err.style.display = "none";
  if (!user || !pass) { err.textContent = "Enter username and password"; err.style.display = "block"; return; }
  btn.textContent = "Signing inâ€¦"; btn.disabled = true;
  try {
    const r = await fetch("/api/auth/login", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({username:user, password:pass}),
    });
    const d = await r.json();
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

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  PAGE ROUTING
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function showPage(page) {
  state.page = page || "companies";
  closeMobileNav();
  if (page !== "company") stopCompanyPipelineSync();
  document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(b=>b.classList.remove("active"));
  document.getElementById("crumb-sep").style.display = "none";
  document.getElementById("crumb-current").textContent = "";
  document.getElementById("topbar-scan-btn").style.display = "none";
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
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  JOB QUEUE
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function _jobStatusLabel(status) {
  const labels = {pending:"Pendente", running:"Rodando", done:"Finalizado", error:"Erro", cancelled:"Cancelado", stopped:"Parado"};
  return labels[status] || status || "unknown";
}

function _jobStatusClass(status) {
  if (status === "done") return "done";
  if (status === "running") return "running";
  if (status === "pending") return "pending";
  if (status === "error") return "error";
  if (status === "cancelled") return "cancelled";
  if (status === "stopped") return "stopped";
  return "unknown";
}

function _fmtJobTime(value) {
  if (!value) return "â€”";
  try {
    const d = new Date(value);
    if (!Number.isNaN(d.getTime())) {
      return d.toLocaleString(undefined, {month:"short", day:"2-digit", hour:"2-digit", minute:"2-digit"});
    }
  } catch(e) {}
  return String(value).replace("T", " ").slice(0, 16);
}

function _companyNameForJob(cid) {
  const co = allCompanies().find(c => c.id === cid);
  return co ? co.name : (cid || "â€”");
}

function _jsArg(value) {
  return JSON.stringify(String(value || ""));
}

function _jobTypeLabel(type) {
  const map = {
    pipeline: "ASM Pipeline",
    playwright_recon: "Playwright Recon",
  };
  return map[type] || type || "job";
}

function _jobArtifactUrl(jobId, kind) {
  return `/api/jobs/${encodeURIComponent(jobId)}/artifact/${encodeURIComponent(kind)}`;
}

const JOBS_PAGE_SIZE = 20;
let _jobsPage = 1;
let _jobsTotal = 0;

function _jobPrimaryTarget(job) {
  const opts = job?.options || {};
  const pick = [
    job?.target,
    opts.queue_domain,
    opts.target_url,
    Array.isArray(opts.domains) ? opts.domains[0] : "",
    Array.isArray(opts.scope) ? opts.scope[0] : "",
  ].find(Boolean);
  const clean = String(pick || "").trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
  return clean || "â€”";
}

function _jobSecondaryLabel(job) {
  const company = _companyNameForJob(job?.company_id);
  return `${company} Â· ${job?.id || ""}`;
}

function _playwrightInventorySummary(session) {
  if (!session) return "";
  const discovered = Array.isArray(session.discovered_hosts) ? session.discovered_hosts.length : 0;
  const validated = Array.isArray(session.validated_hosts) ? session.validated_hosts.length : 0;
  const pending = Array.isArray(session.pending_hosts) ? session.pending_hosts.length : 0;
  const items = Array.isArray(session.host_inventory) ? session.host_inventory : [];
  const chips = items.slice(0, 8).map(item => {
    const st = item.status_code == null ? "pending" : "validated";
    const code = item.status_code == null ? "pending" : String(item.status_code);
    return `<code class="fg-host-chip fg-host-chip-full ${st}" title="${esc(item.source || "browser")}">${esc(item.host)} Â· ${esc(code)}</code>`;
  }).join("");
  return `
    <div class="job-detail-grid">
      <div><span class="job-detail-k">Discovered</span><div class="job-detail-v">${discovered}</div></div>
      <div><span class="job-detail-k">Validated</span><div class="job-detail-v">${validated}</div></div>
      <div><span class="job-detail-k">Pending</span><div class="job-detail-v">${pending}</div></div>
      <div><span class="job-detail-k">Inventory</span><div class="job-detail-v">${items.length}</div></div>
    </div>
    ${chips ? `<div class="chip-row" style="margin-top:10px">${chips}</div>` : ""}
  `;
}

function openJobsQueue(jobType) {
  const typeEl = document.getElementById("jobs-type-filter");
  if (typeEl) typeEl.value = jobType || "";
  showPage("jobs");
  loadJobs();
}

async function openJobCompanyPipeline(cid) {
  if (!cid) return;
  await selectCompany(cid);
  await switchTab("pipeline");
}

function _jobDetailPanel() {
  return document.getElementById("job-detail-panel");
}

function _renderJobDetailEmpty(message) {
  const panel = _jobDetailPanel();
  if (!panel) return;
  panel.style.display = "block";
  panel.innerHTML = `
    <div class="job-detail-card">
      <div class="job-detail-title">Job Detail</div>
      <div class="job-detail-copy">${esc(message || "Select a job to inspect.")}</div>
    </div>
  `;
}

function _renderJobDetail(job, preview) {
  const panel = _jobDetailPanel();
  if (!panel) return;
  const isPlaywright = job.job_type === "playwright_recon";
  const artReport = isPlaywright && job.status === "done" ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'report')}" target="_blank" rel="noopener">Open Report</a>` : "";
  const artSession = isPlaywright && job.status === "done" ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'session')}" target="_blank" rel="noopener">Open Session</a>` : "";
  const opts = job.options || {};
  const previewHtml = preview ? `
    <div class="job-detail-grid">
      <div><span class="job-detail-k">Pages</span><div class="job-detail-v">${preview.pages || 0}</div></div>
      <div><span class="job-detail-k">Endpoints</span><div class="job-detail-v">${preview.endpoints || 0}</div></div>
      <div><span class="job-detail-k">JS Chunks</span><div class="job-detail-v">${preview.js || 0}</div></div>
      <div><span class="job-detail-k">Tech</span><div class="job-detail-v">${preview.tech || 0}</div></div>
    </div>
    ${preview.inventory ? _playwrightInventorySummary(preview.inventory) : ""}
    ${preview.note ? `<div class="job-detail-copy">${esc(preview.note)}</div>` : ""}
    ${preview.report ? `<pre class="job-detail-pre">${esc(preview.report)}</pre>` : ""}
  ` : `<div class="job-detail-copy">No Playwright session preview available yet.</div>`;

  panel.style.display = "block";
  panel.innerHTML = `
    <div class="job-detail-card">
      <div class="job-detail-head">
        <div>
          <div class="job-detail-title">${esc(_jobTypeLabel(job.job_type))}</div>
          <div class="job-detail-copy">${esc(job.id)} Â· ${esc(job.company_id || "â€”")} Â· ${esc(job.status || "â€”")}</div>
        </div>
        <div class="job-actions">${artReport}${artSession}</div>
      </div>
      <div class="job-detail-grid">
        <div><span class="job-detail-k">Target</span><div class="job-detail-v">${esc(job.target || opts.target_url || "â€”")}</div></div>
        <div><span class="job-detail-k">Created by</span><div class="job-detail-v">${esc(job.created_by || "â€”")}</div></div>
        <div><span class="job-detail-k">Attempts</span><div class="job-detail-v">${Number(job.attempts || 0)} / ${Number(job.max_attempts || 1)}</div></div>
        <div><span class="job-detail-k">Error</span><div class="job-detail-v">${esc(job.error || "â€”")}</div></div>
      </div>
      <div class="job-detail-copy">
        Output: <code>${esc(opts.output || "â€”")}</code><br>
        Evidence: <code>${esc(opts.evidence_dir || "â€”")}</code><br>
        Scope: <code>${esc(Array.isArray(opts.scope) ? opts.scope.join(", ") : (opts.scope || "â€”"))}</code>
      </div>
      ${previewHtml}
    </div>
  `;
}

async function openJobDetail(jobId) {
  const panel = _jobDetailPanel();
  if (!panel) return;
  panel.style.display = "block";
  panel.innerHTML = `<div class="job-detail-card"><div class="job-detail-title">Loading job detail...</div></div>`;
  panel.scrollIntoView({block:"start", behavior:"smooth"});
  try {
    const r = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`, {headers:_authHeaders()});
    if (!r.ok) throw new Error("HTTP " + r.status);
    const job = await r.json();
    let preview = null;
    if (job.job_type === "playwright_recon") {
      try {
        const sessionResp = await fetch(_jobArtifactUrl(jobId, "session"), {headers:_authHeaders()});
        if (sessionResp.ok) {
          const session = await sessionResp.json();
          const reportResp = await fetch(_jobArtifactUrl(jobId, "report"), {headers:_authHeaders()});
          let report = "";
          if (reportResp.ok) {
            const txt = await reportResp.text();
            report = txt.split("\n").slice(0, 18).join("\n");
          }
          preview = {
            pages: Array.isArray(session.pages) ? session.pages.length : 0,
            endpoints: Array.isArray(session.endpoints) ? session.endpoints.length : 0,
            js: Array.isArray(session.js) ? session.js.length : 0,
            tech: Array.isArray(session.tech) ? session.tech.length : 0,
            inventory: session,
            note: Array.isArray(session.skipped_checks) && session.skipped_checks.length ? session.skipped_checks[0] : "",
            report: report,
          };
        }
      } catch(e) {
        preview = { note: "Failed to load Playwright artifact preview: " + e.message };
      }
    }
    _renderJobDetail(job, preview);
    panel.scrollIntoView({block:"start", behavior:"smooth"});
  } catch(e) {
    panel.innerHTML = `<div class="job-detail-card"><div class="job-detail-title">Failed to load job detail</div><div class="job-detail-copy">${esc(e.message)}</div></div>`;
  }
}

async function renderCompanyPlaywrightPanel(cid) {
  const panel = document.getElementById("company-playwright-panel");
  if (!panel) return;
  const ready = (pipelineState[cid] && pipelineState[cid].status === "done");
  panel.innerHTML = `
    <div class="job-detail-card">
      <div class="job-detail-title">Playwright Recon</div>
      <div class="job-detail-copy">Loading latest job for this company...</div>
    </div>
  `;
  try {
    const r = await fetch(`/api/jobs?company_id=${encodeURIComponent(cid)}&limit=20`, {headers:_authHeaders()});
    if (!r.ok) throw new Error("HTTP " + r.status);
    const jobs = await r.json();
    const job = jobs.find(j => j.job_type === "playwright_recon");
    if (!job) {
      panel.innerHTML = `
        <div class="job-detail-card">
          <div class="job-detail-title">Playwright Recon</div>
          <div class="job-detail-copy">${ready ? "No Playwright Recon jobs found for this company yet." : "Locked until the bug bounty pipeline scan finishes."}</div>
        </div>
      `;
      return;
    }
    const canArtifacts = job.status === "done";
    const opts = job.options || {};
    let inventoryHtml = "";
    try {
      const sessionResp = await fetch(_jobArtifactUrl(job.id, "session"), {headers:_authHeaders()});
      if (sessionResp.ok) {
        const session = await sessionResp.json();
        inventoryHtml = _playwrightInventorySummary(session);
      }
    } catch(e) {}
    panel.innerHTML = `
      <div class="job-detail-card">
        <div class="job-detail-head">
          <div>
            <div class="job-detail-title">Playwright Recon</div>
            <div class="job-detail-copy">${esc(job.id)} Â· ${esc(job.status || "â€”")} Â· ${esc(job.created_at || "â€”")}</div>
          </div>
          <div class="job-actions">
            <button class="btn btn-secondary btn-icon" onclick="openJobDetail(${_jsArg(job.id)})">Details</button>
            ${canArtifacts ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'report')}" target="_blank" rel="noopener">Report</a>` : ""}
            ${canArtifacts ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'session')}" target="_blank" rel="noopener">Session</a>` : ""}
          </div>
        </div>
        <div class="job-detail-grid">
          <div><span class="job-detail-k">Target</span><div class="job-detail-v">${esc(job.target || opts.target_url || "â€”")}</div></div>
          <div><span class="job-detail-k">Started</span><div class="job-detail-v">${esc(_fmtJobTime(job.started_at))}</div></div>
          <div><span class="job-detail-k">Finished</span><div class="job-detail-v">${esc(_fmtJobTime(job.finished_at))}</div></div>
          <div><span class="job-detail-k">Attempts</span><div class="job-detail-v">${Number(job.attempts || 0)} / ${Number(job.max_attempts || 1)}</div></div>
        </div>
        <div class="job-detail-copy">
          Output: <code>${esc(opts.output || "â€”")}</code><br>
          Evidence: <code>${esc(opts.evidence_dir || "â€”")}</code>
        </div>
        ${inventoryHtml}
      </div>
    `;
  } catch(e) {
    panel.innerHTML = `
      <div class="job-detail-card">
        <div class="job-detail-title">Playwright Recon</div>
        <div class="job-detail-copy">Failed to load Playwright jobs: ${esc(e.message)}</div>
      </div>
    `;
  }
}

async function _fetchLatestPlaywrightBundle(cid) {
  const r = await fetch(`/api/jobs?company_id=${encodeURIComponent(cid)}&limit=20`, {headers:_authHeaders()});
  if (!r.ok) throw new Error("HTTP " + r.status);
  const jobs = await r.json();
  const job = (jobs || []).find(j => j.job_type === "playwright_recon");
  if (!job) return {job: null, session: null, report: ""};

  let session = null;
  let report = "";
  try {
    const sessionResp = await fetch(_jobArtifactUrl(job.id, "session"), {headers:_authHeaders()});
    if (sessionResp.ok) session = await sessionResp.json();
  } catch(e) {}
  try {
    const reportResp = await fetch(_jobArtifactUrl(job.id, "report"), {headers:_authHeaders()});
    if (reportResp.ok) {
      const txt = await reportResp.text();
      report = txt.split("\n").slice(0, 24).join("\n");
    }
  } catch(e) {}
  return {job, session, report};
}

async function renderOperationTab(co) {
  const el = document.getElementById("tab-operation");
  if (!el) return;
  el.innerHTML = `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">Playwright Operation</div>
          <div class="section-title">Browser-returned surface, session state and runtime evidence</div>
          <div class="section-sub">This view shows everything the Playwright pass returned for the selected company.</div>
        </div>
      </div>
    </div>
  `;

  try {
    const bundle = await _fetchLatestPlaywrightBundle(co.id);
    const job = bundle.job;
    const session = bundle.session;
    if (!job) {
      el.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">âˆ…</div>
          <div class="empty-state-title">No Playwright run found</div>
          <div class="empty-state-copy">Run the bug bounty pipeline first, then queue Playwright Recon to populate this view.</div>
        </div>`;
      return;
    }

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
    const report = bundle.report || "";
    const storageKeys = session?.storage ? Object.keys(session.storage) : [];
    const tokenCount = Array.isArray(session?.tokens) ? session.tokens.length : 0;

    const finished = _fmtJobTime(job.finished_at);
    const started = _fmtJobTime(job.started_at);
    const canArtifacts = job.status === "done";
    const cidJs = _jsArg(job.id);

    if (document.getElementById("tc-operation")) {
      document.getElementById("tc-operation").textContent = String(pages.length || endpoints.length || js.length || 0);
    }

    const pageRows = pages.slice(0, 30).map(p => `
      <tr>
        <td style="font-family:var(--mono);font-size:.72rem;word-break:break-all">${esc(p.url || "")}</td>
        <td>${esc(String(p.depth ?? ""))}</td>
        <td>${esc(String(p.status ?? ""))}</td>
        <td>${esc(p.title || "")}</td>
        <td>${p.screenshot_path ? `<a href="${esc('/' + p.screenshot_path)}" target="_blank" rel="noopener">Open</a>` : "â€”"}</td>
      </tr>`).join("");

    const endpointRows = endpoints.slice(0, 40).map(e => `
      <tr>
        <td>${esc(e.method || "GET")}</td>
        <td style="font-family:var(--mono);font-size:.72rem;word-break:break-all">${esc(e.url || "")}</td>
        <td>${esc(String(e.status ?? "â€”"))}</td>
        <td>${esc(e.content_type || "")}</td>
        <td>${e.auth_required === true ? "yes" : e.auth_required === false ? "no" : "â€”"}</td>
      </tr>`).join("");

    const jsRows = js.slice(0, 30).map(j => `
      <tr>
        <td style="font-family:var(--mono);font-size:.72rem;word-break:break-all">${esc(j.file_url || "")}</td>
        <td>${esc(String(j.size || 0))}</td>
        <td>${j.source_map_accessible ? "yes" : (j.source_map_url ? "ref" : "no")}</td>
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
        <td style="font-family:var(--mono);font-size:.72rem;word-break:break-all">${esc(c.message || "")}</td>
        <td>${esc(c.classification || "")}</td>
        <td>${esc(c.page_url || "")}</td>
      </tr>`).join("");

    const authForms = Array.isArray(auth.login_forms) ? auth.login_forms : [];
    const authRows = authForms.slice(0, 10).map(f => `
      <tr>
        <td>${esc(f.action || "")}</td>
        <td>${esc(f.method || "")}</td>
        <td>${esc(f.password_field || "")}</td>
        <td>${esc(f.csrf_field || "")}</td>
      </tr>`).join("");

    const findingsRows = confirmed.slice(0, 20).map(f => `
      <tr>
        <td>${esc(f.title || "")}</td>
        <td>${esc(f.severity || "")}</td>
        <td style="font-family:var(--mono);font-size:.72rem;word-break:break-all">${esc(f.endpoint || f.url || "")}</td>
        <td>${esc(f.status || "")}</td>
      </tr>`).join("");

    const idorRows = idor.slice(0, 20).map(i => `
      <tr>
        <td style="font-family:var(--mono);font-size:.72rem;word-break:break-all">${esc(i.url || "")}</td>
        <td>${esc(i.parameter || "")}</td>
        <td>${esc(i.status || "")}</td>
        <td>${esc((i.notes || []).join("; "))}</td>
      </tr>`).join("");

    const xssRows = xss.slice(0, 20).map(x => `
      <tr>
        <td style="font-family:var(--mono);font-size:.72rem;word-break:break-all">${esc(x.url || "")}</td>
        <td>${esc(x.parameter || "")}</td>
        <td>${esc(x.context || "")}</td>
        <td>${esc(x.status || "")}</td>
      </tr>`).join("");

    const raceRows = race.slice(0, 20).map(r => `
      <tr>
        <td style="font-family:var(--mono);font-size:.72rem;word-break:break-all">${esc(r.url || "")}</td>
        <td>${esc(r.category || "")}</td>
        <td>${esc(r.probe_status || "")}</td>
        <td>${esc(r.reason || "")}</td>
      </tr>`).join("");

    el.innerHTML = `
      <div class="section-shell">
        <div class="section-head">
          <div class="section-head-main">
            <div class="section-kicker">Playwright Operation</div>
            <div class="section-title">${esc(job.company_id || "â€”")} Â· ${esc(_jobStatusLabel(job.status))}</div>
            <div class="section-sub">${esc(job.id)} Â· started ${esc(started)} Â· finished ${esc(finished)}</div>
          </div>
          <div class="section-actions">
            <div class="job-actions">
              <button class="btn btn-secondary btn-icon" onclick='openJobDetail(${cidJs})'>Details</button>
              ${canArtifacts ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'report')}" target="_blank" rel="noopener">Report</a>` : ""}
              ${canArtifacts ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'session')}" target="_blank" rel="noopener">Session</a>` : ""}
            </div>
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
          <div class="job-detail-title">Host inventory</div>
          ${inventory || '<div class="job-detail-copy">No host inventory captured yet.</div>'}
        </div>

        <div class="job-detail-card" style="margin-bottom:14px">
          <div class="job-detail-title">Captured pages</div>
          <div class="table-shell"><div class="tl-wrap"><table class="jobs-table">
            <thead><tr><th>URL</th><th>Depth</th><th>Status</th><th>Title</th><th>Screenshot</th></tr></thead>
            <tbody>${pageRows || '<tr><td colspan="5" style="color:var(--text3);padding:18px">No pages captured.</td></tr>'}</tbody>
          </table></div></div>
        </div>

        <div class="job-detail-card" style="margin-bottom:14px">
          <div class="job-detail-title">Endpoints</div>
          <div class="table-shell"><div class="tl-wrap"><table class="jobs-table">
            <thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Content-Type</th><th>Auth</th></tr></thead>
            <tbody>${endpointRows || '<tr><td colspan="5" style="color:var(--text3);padding:18px">No endpoints captured.</td></tr>'}</tbody>
          </table></div></div>
        </div>

        <div class="job-detail-card" style="margin-bottom:14px">
          <div class="job-detail-title">JavaScript</div>
          <div class="table-shell"><div class="tl-wrap"><table class="jobs-table">
            <thead><tr><th>Bundle</th><th>Size</th><th>Source Map</th><th>Endpoints</th><th>Routes</th></tr></thead>
            <tbody>${jsRows || '<tr><td colspan="5" style="color:var(--text3);padding:18px">No JS captured.</td></tr>'}</tbody>
          </table></div></div>
        </div>

        <div class="job-detail-card" style="margin-bottom:14px">
          <div class="job-detail-title">Technologies</div>
          <div class="table-shell"><div class="tl-wrap"><table class="jobs-table">
            <thead><tr><th>Name</th><th>Category</th><th>Confidence</th><th>Source</th></tr></thead>
            <tbody>${techRows || '<tr><td colspan="4" style="color:var(--text3);padding:18px">No tech detected.</td></tr>'}</tbody>
          </table></div></div>
        </div>

        <div class="job-detail-card" style="margin-bottom:14px">
          <div class="job-detail-title">Console</div>
          <div class="table-shell"><div class="tl-wrap"><table class="jobs-table">
            <thead><tr><th>Type</th><th>Message</th><th>Classification</th><th>Page</th></tr></thead>
            <tbody>${consoleRows || '<tr><td colspan="4" style="color:var(--text3);padding:18px">No console events captured.</td></tr>'}</tbody>
          </table></div></div>
        </div>

        <div class="job-detail-card" style="margin-bottom:14px">
          <div class="job-detail-title">Authentication</div>
          <div class="job-detail-copy">
            Login forms: <strong>${authForms.length}</strong> Â· CSRF fields: <strong>${(auth.csrf_fields || []).length || 0}</strong> Â· Cookies: <strong>${(auth.cookies || []).length || 0}</strong> Â· Session mechanisms: <strong>${(auth.session_mechanisms || []).length || 0}</strong>
          </div>
          ${authForms.length ? `<div class="table-shell" style="margin-top:10px"><div class="tl-wrap"><table class="jobs-table">
            <thead><tr><th>Action</th><th>Method</th><th>Password Field</th><th>CSRF</th></tr></thead>
            <tbody>${authRows}</tbody>
          </table></div></div>` : '<div class="job-detail-copy">No login form detected.</div>'}
        </div>

        <div class="job-detail-card" style="margin-bottom:14px">
          <div class="job-detail-title">Confirmed Findings</div>
          ${confirmed.length ? `<div class="table-shell"><div class="tl-wrap"><table class="jobs-table">
            <thead><tr><th>Title</th><th>Severity</th><th>Endpoint</th><th>Status</th></tr></thead>
            <tbody>${findingsRows}</tbody>
          </table></div></div>` : '<div class="job-detail-copy">No confirmed findings returned by Playwright.</div>'}
        </div>

        <div class="job-detail-card" style="margin-bottom:14px">
          <div class="job-detail-title">IDOR / XSS / Race</div>
          <div class="job-detail-copy">Storage keys: <strong>${storageKeys.length}</strong> Â· Tokens: <strong>${tokenCount}</strong> Â· WebSockets: <strong>${(session?.websockets || []).length || 0}</strong> Â· SSE: <strong>${(session?.sse || []).length || 0}</strong></div>
          <div style="margin-top:10px;display:grid;gap:12px">
            ${idor.length ? `<div class="table-shell"><div class="tl-wrap"><table class="jobs-table">
              <thead><tr><th>IDOR URL</th><th>Param</th><th>Status</th><th>Notes</th></tr></thead>
              <tbody>${idorRows}</tbody>
            </table></div></div>` : '<div class="job-detail-copy">No IDOR candidates returned.</div>'}
            ${xss.length ? `<div class="table-shell"><div class="tl-wrap"><table class="jobs-table">
              <thead><tr><th>XSS URL</th><th>Param</th><th>Context</th><th>Status</th></tr></thead>
              <tbody>${xssRows}</tbody>
            </table></div></div>` : '<div class="job-detail-copy">No XSS checks returned.</div>'}
            ${race.length ? `<div class="table-shell"><div class="tl-wrap"><table class="jobs-table">
              <thead><tr><th>Race URL</th><th>Category</th><th>Status</th><th>Reason</th></tr></thead>
              <tbody>${raceRows}</tbody>
            </table></div></div>` : '<div class="job-detail-copy">No race probes returned.</div>'}
          </div>
        </div>

        <div class="job-detail-card">
          <div class="job-detail-title">Report Preview</div>
          ${report ? `<pre class="job-detail-pre">${esc(report)}</pre>` : '<div class="job-detail-copy">No report preview available.</div>'}
        </div>
      </div>
    `;
  } catch(e) {
    el.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">âš </div>
        <div class="empty-state-title">Failed to load Playwright operation</div>
        <div class="empty-state-copy">${esc(e.message)}</div>
      </div>`;
  }
}

async function renderReconTab(cid) {
  const el = document.getElementById("tab-pipeline");
  if (!el) return;
  const activePipeline = _isPipelineActive(cid);
  el.innerHTML = `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">Pipeline</div>
          <div class="section-title">Scan execution and live phase status</div>
          <div class="section-sub">Monitor the scan runner and the latest Playwright recon panel here.</div>
        </div>
        <div class="section-actions">
          <button id="pipeline-btn-${escAttr(cid)}" class="btn ${activePipeline ? "btn-icon pipeline-stop-btn" : "btn-secondary btn-icon"}" onclick="handlePipelineAction('${escAttr(cid)}')">${activePipeline ? "â–  Stop Pipeline" : "â–¶ Run Pipeline"}</button>
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

// â”€â”€ Screenshot lightbox â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
let _ssShots = [], _ssIdx = 0;

window.ssLightboxOpen = function(shotUrl, pageUrl, shots, idx) {
  _ssShots = shots || [{shotUrl, pageUrl}];
  _ssIdx   = idx   || 0;
  _ssShow();
  const lb = document.getElementById('ss-lightbox');
  if (lb) { lb.classList.add('open'); lb.focus(); }
};

window.ssLightboxClose = function() {
  const lb = document.getElementById('ss-lightbox');
  if (lb) lb.classList.remove('open');
};

window.ssLightboxNav = function(dir) {
  if (!_ssShots.length) return;
  _ssIdx = (_ssIdx + dir + _ssShots.length) % _ssShots.length;
  _ssShow();
};

// â”€â”€ Screenshot hover preview popover â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

let _ssPopover = null;

window.ssPopoverShow = function(e, shotUrl, pageUrl) {
  if (!_ssPopover) {
    _ssPopover = document.createElement('div');
    _ssPopover.className = 'ss-popover';
    _ssPopover.innerHTML = '<img src="" alt=""><div class="ss-popover-url"></div>';
    document.body.appendChild(_ssPopover);
  }
  const img = _ssPopover.querySelector('img');
  const lbl = _ssPopover.querySelector('.ss-popover-url');
  img.src = shotUrl;
  lbl.textContent = (pageUrl || '').length > 90 ? (pageUrl || '').substring(0, 90) + 'â€¦' : (pageUrl || '');
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
    {name:"Subdomains", count: hosts.length || (co.ct_subdomains || []).length, desc:"Escopo descoberto e normalizado"},
    {name:"URLs", count: endpointTotal, desc:"Wayback, URLFinder, JS e browser"},
    {name:"Screenshots", count: screenshotTotal, desc:"Evidencias visuais em disco/API"},
    {name:"Headers", count: headerResults.length, desc:`${missingHeaders} gaps Â· ${cookieIssues} cookie issues`},
    {name:"Browser", count: browserResults.length || pwPages.length, desc:`${browserData.insecure_cookies || 0} cookies inseguros`},
    {name:"Browser Crawl", count: Number(browserCrawl.url_count || 0) + Number(browserCrawl.api_endpoint_count || 0), desc:`${browserCrawl.hosts_crawled || 0} hosts Â· ${browserCrawl.form_count || 0} forms`},
    {name:"Runtime JS", count: runtimeJsUrls.length || Number(co.js_data?.runtime_js_count || 0), desc:`${runtimeNetwork.length} network calls Â· chunks/scripts`},
    {name:"JavaScript", count: Number(co.js_data?.js_files || 0), desc:`${co.js_data?.total_endpoints || 0} endpoints Â· ${co.js_data?.total_secrets || 0} secrets`},
    {name:"CVEs", count: cves.length, desc:`${co.cve_summary?.critical || 0} critical Â· ${co.cve_summary?.high || 0} high`},
    {name:"DNSSEC", count: Array.isArray(co.dnssec_data?.findings) ? co.dnssec_data.findings.length : 0, desc:"Problemas DNSSEC detectados"},
    {name:"GitHub", count: Number(co.github_repos_data?.total_repos || 0), desc:"Repositorios e exposicoes"},
    {name:"Cloud", count: co.cloud_assets ? Object.keys(co.cloud_assets).length : 0, desc:"Providers inferidos por IP"},
    {name:"Tech", count: techCount, desc:"Tecnologias fingerprints"}
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
  </tr>`).join("") || `<tr><td colspan="4" class="recon-empty-row">Nenhum finding consolidado.</td></tr>`;

  const hostRows = hosts.slice(0, 10).map(h => `<tr>
    <td class="recon-mono">${esc(h.host || "")}</td>
    <td>${h.status_code ? `<span class="status-code">${esc(h.status_code)}</span>` : "â€”"}</td>
    <td>${esc(h.title || h.server || "")}</td>
    <td>${(h.screenshot || h.browser_recon?.screenshot) ? "âœ“" : "â€”"}</td>
  </tr>`).join("") || `<tr><td colspan="4" class="recon-empty-row">Nenhum host carregado.</td></tr>`;

  const browserRows = browserResults.slice(0, 8).map(r => `<tr>
    <td class="recon-mono"><a href="${escAttr(r.url || "")}" target="_blank" rel="noopener">${esc(r.url || "")}</a></td>
    <td>${esc(r.status ?? "â€”")}</td>
    <td>${esc(r.title || "")}</td>
    <td>${Array.isArray(r.observations) ? r.observations.length : 0}</td>
  </tr>`).join("") || `<tr><td colspan="4" class="recon-empty-row">Browser recon sem paginas persistidas.</td></tr>`;

  return `
    <div class="recon-kpi-grid">
      ${_reconKpi(hosts.length, "Hosts", `${co.ct_subdomains?.length || 0} CT/subdomains`, "teal")}
      ${_reconKpi(findings.length, "Findings", `${co.stats?.findings_critical || 0} critical Â· ${co.stats?.findings_high || 0} high`, "red")}
      ${_reconKpi(endpointTotal, "URLs/Endpoints", `${staticEndpoints.length} static Â· ${pwEndpoints.length} PW`, "blue")}
      ${_reconKpi(secretTotal, "Secrets", `${staticSecrets.length} JS/static`, "orange")}
      ${_reconKpi(screenshotTotal, "Screenshots", "capturas disponiveis", "green")}
      ${_reconKpi(browserResults.length || pwPages.length, "Browser", `${browserData.insecure_cookies || 0} insecure cookies`, "purple")}
    </div>

    <div class="section-head recon-inner-head">
      <div class="section-head-main">
        <div class="section-kicker">Coverage</div>
        <div class="section-title">Resultados por modulo</div>
        <div class="section-sub">Resumo operacional do que a pipeline ja consolidou para o alvo.</div>
      </div>
    </div>
    <div class="recon-module-grid">${modules.map(_reconModuleCard).join("")}</div>

    <div class="recon-two-col">
      <div>
        <div class="recon-panel-title">Findings prioritarios</div>
        <div class="table-shell"><div class="tl-wrap"><table class="jobs-table compact-table">
          <thead><tr><th>Sev</th><th>Finding</th><th>Host/Valor</th><th>Modulo</th></tr></thead>
          <tbody>${topFindingRows}</tbody>
        </table></div></div>
      </div>
      <div>
        <div class="recon-panel-title">Hosts em evidencia</div>
        <div class="table-shell"><div class="tl-wrap"><table class="jobs-table compact-table">
          <thead><tr><th>Host</th><th>Status</th><th>Titulo/Server</th><th>Shot</th></tr></thead>
          <tbody>${hostRows}</tbody>
        </table></div></div>
      </div>
    </div>

    <div class="recon-two-col">
      <div>
        <div class="recon-panel-title">Browser recon</div>
        <div class="table-shell"><div class="tl-wrap"><table class="jobs-table compact-table">
          <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Obs</th></tr></thead>
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
  if (img) img.src = s.shotUrl || '';
  if (lbl) lbl.textContent = s.pageUrl || '';
  if (nav) nav.style.display = _ssShots.length > 1 ? 'flex' : 'none';
}

async function loadScreenshots(cid, co) {
  const el = document.getElementById("tab-screenshots");
  if (!el) return;
  el.innerHTML = `<div style="padding:24px;color:var(--text3);font-size:.8rem">Loading recon dataâ€¦</div>`;

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

  // â”€â”€ section builder helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  function _secHead(kicker, title, sub, count) {
    return `
      <div class="section-head" style="margin-top:28px;padding-top:20px;border-top:1px solid var(--border)">
        <div class="section-head-main">
          <div class="section-kicker">${kicker}</div>
          <div class="section-title">${esc(title)}</div>
          <div class="section-sub">${esc(sub)}</div>
        </div>
        ${count != null ? `<div class="section-actions"><span class="sec-cnt">${count} items</span></div>` : ''}
      </div>`;
  }

  function _emptyRow(msg) {
    return `<tr><td colspan="99" style="padding:18px;color:var(--text3);text-align:center;font-size:.75rem">${msg}</td></tr>`;
  }

  // â”€â”€ SCREENSHOTS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  let html = `<div class="section-shell">
    <div class="section-head">
      <div class="section-head-main">
        <div class="section-kicker">Recon</div>
        <div class="section-title">Recon evidence and attack surface leads</div>
        <div class="section-sub">Hosts, findings, URLs, browser evidence, screenshots and module coverage from the latest bug bounty pipeline.</div>
      </div>
    </div>
    ${_renderReconEvidencePanel(co, shots, staticEndpoints, staticSecrets, session)}`;

  // â”€â”€ CRAWLED URLS (playwright pages) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  html += _secHead('ðŸŒ', `Crawled URLs (${crawledPages.length})`, 'Pages visited by the integrated browser recon phase or by a Playwright job.', null);
  if (crawledPages.length) {
    const pageRows = crawledPages.map(p => {
      const url = p.url || p.final_url || '';
      return `<tr>
        <td style="font-family:var(--mono);font-size:.72rem;word-break:break-all">
          <a href="${esc(url)}" target="_blank" rel="noopener" style="color:var(--teal);text-decoration:none">${esc(url)}</a>
        </td>
        <td style="text-align:center">${p.status_code ?? 'â€”'}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.7rem">${esc(p.title||'')}</td>
        <td style="color:var(--text3);font-size:.68rem">${esc(p._src || p.server || '')}</td>
      </tr>`;
    }).join('');
    html += `<div class="table-shell"><div class="tl-wrap"><table class="jobs-table">
      <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Source</th></tr></thead>
      <tbody>${pageRows}</tbody></table></div></div>`;
  } else {
    html += `<div style="padding:12px 0;color:var(--text3);font-size:.78rem">No crawled pages yet. Run the browser phase in the bug bounty pipeline.</div>`;
  }

  // â”€â”€ ENDPOINTS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

  html += _secHead('ðŸ”—', `Endpoints (${epFiltered.length})`, 'API paths and routes from JS analysis and browser crawl. Click row to copy URL.', null);
  if (epFiltered.length) {
    html += `<div style="display:flex;gap:6px;flex-wrap:wrap;padding:8px 0;align-items:center">
      <input id="ep-filter" placeholder="Filter endpoints..." style="background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 10px;font-size:.7rem;width:200px" oninput="document.querySelectorAll('.ep-row').forEach(r=>{const t=r.textContent.toLowerCase();r.style.display=t.includes(this.value.toLowerCase())?'':'none'})">
    </div>`;

    const SEV = {critical:'#fb7185',high:'#fb923c',medium:'#fbbf24',low:'#4ade80',info:'#94a3b8'};
    const epRows = epFiltered.slice(0, 500).map(e => {
      const mc = _methodColor ? _methodColor(e.method||'GET') : '#60a5fa';
      const copyUrl = esc(e.url);
      return `<tr class="ep-row" style="cursor:pointer" onclick="navigator.clipboard.writeText(this.getAttribute('data-copy')).then(()=>{this.style.background='rgba(0,201,167,.08)';setTimeout(()=>this.style.background='',600)})" data-copy="${copyUrl}" title="Click to copy URL">
        <td style="width:60px">
          <span style="font-family:var(--mono);font-size:.64rem;font-weight:700;color:${mc}">${esc(e.method||'GET')}</span>
        </td>
        <td style="font-family:var(--mono);font-size:.7rem;word-break:break-all;color:var(--text1)">${esc(e.url)} ðŸ“‹</td>
        <td style="font-size:.62rem;color:var(--teal);font-family:var(--mono)">${esc(e._src || e.source || '')}</td>
        <td style="font-size:.66rem;color:var(--text3)">${esc(e.type||'')}</td>
        <td style="font-size:.66rem;color:${e.severity?SEV[e.severity]||'#94a3b8':'var(--text3)'}">${e.severity?e.severity.toUpperCase():''}</td>
      </tr>`;
    }).join('');
    const overflow = epFiltered.length > 500 ? `<tr><td colspan="5" style="padding:8px 12px;color:var(--text3);font-size:.7rem">${epFiltered.length - 500} more endpoints â€” use filter or export CSV.</td></tr>` : '';
    html += `<div class="table-shell"><div class="tl-wrap" style="max-height:360px;overflow-y:auto"><table class="jobs-table">
      <thead><tr><th>Method</th><th>URL (click to copy)</th><th>Source</th><th>Type</th><th>Risk</th></tr></thead>
      <tbody>${epRows}${overflow}</tbody></table></div></div>`;
  } else {
    html += `<div style="padding:12px 0;color:var(--text3);font-size:.78rem">No endpoints discovered yet. Run wayback, urlfinder, js_endpoints or Playwright Recon.</div>`;
  }

  // â”€â”€ SECRETS & HARDCODED KEYS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // Merge: static secrets + playwright tokens + playwright globals
  const secArr = [];
  staticSecrets.forEach(s => secArr.push({type:s.type||'secret', value:s.value||'', file:s.file||'', host:s.host||'', severity:s.severity||'medium', _src:'static'}));
  pwTokens.forEach(t => secArr.push({type:t.type||'token', value:t.value||JSON.stringify(t), file:'', host:t.host||'', severity:'high', _src:'playwright'}));
  pwGlobals.forEach(g => secArr.push({type:'global', value:g.sample||g.key||'', file:g.key||'', host:'', severity:'medium', _src:'playwright'}));
  browserResults.forEach(r => (r.secrets_found || []).forEach(s => {
    secArr.push({type:s.type || "browser_secret", value:s.value || s.secret || JSON.stringify(s), file:r.url || "", host:"", severity:s.severity || "high", _src:"browser"});
  }));

  html += _secHead('ðŸ”‘', `Secrets & Hardcoded Keys (${secArr.length})`, 'Credentials, tokens and API keys extracted from JS bundles and browser globals. Click value to reveal. Click file path to copy.', null);
  if (secArr.length) {
    html += `<div style="display:flex;gap:6px;flex-wrap:wrap;padding:8px 0;align-items:center">
      <input id="sec-filter" placeholder="Filter secrets..." style="background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 10px;font-size:.7rem;width:200px" oninput="document.querySelectorAll('.sec-row').forEach(r=>{const t=r.textContent.toLowerCase();r.style.display=t.includes(this.value.toLowerCase())?'':'none'})">
    </div>`;
    const SEVC = {critical:'#fb7185',high:'#fb923c',medium:'#fbbf24',low:'#4ade80'};
    function maskVal(v) {
      const s = String(v||'');
      if (s.length <= 6) return 'â€¢â€¢â€¢â€¢â€¢â€¢';
      return s.slice(0,3) + 'â€¢â€¢â€¢â€¢â€¢â€¢' + s.slice(-3);
    }
    const secRows = secArr.map((s, i) => {
      const clr = SEVC[s.severity] || '#94a3b8';
      const src = s._src === 'playwright' ? `<span style="font-size:.56rem;color:var(--teal);opacity:.7;margin-left:3px">PW</span>` : '';
      const filePath = esc(s.file||'');
      const fileCell = s.file
        ? `<span title="${filePath}&#10;Click to copy path" onclick="event.stopPropagation();navigator.clipboard.writeText(this.getAttribute('data-path')).then(()=>{this.style.color='var(--teal)';setTimeout(()=>this.style.color='',1200)});return false" data-path="${filePath}" style="cursor:pointer;border-bottom:1px dashed var(--text3);font-size:.67rem;font-family:var(--mono);word-break:break-all">${filePath}</span>`
        : '<span style="font-size:.67rem;color:var(--text3)">â€”</span>';
      return `<tr class="sec-row">
        <td><span style="font-size:.68rem;background:rgba(251,146,60,.1);color:#fb923c;border:1px solid rgba(251,146,60,.2);border-radius:4px;padding:1px 6px">${esc(s.type)}</span>${src}</td>
        <td><code class="secret-value" style="cursor:pointer;font-size:.7rem;font-family:var(--mono);color:var(--text2)"
          onclick="var m=this.getAttribute('data-masked'),v=this.getAttribute('data-value');if(this.textContent===m){this.textContent=v;this.style.color='var(--teal)';this.style.cursor='pointer'}else{this.textContent=m;this.style.color='var(--text2)';this.style.cursor='pointer'}" data-masked="${esc(maskVal(s.value))}" data-value="${esc(String(s.value||''))}">${esc(maskVal(s.value))}</code></td>
        <td style="max-width:260px">${fileCell}</td>
        <td style="font-size:.67rem;color:var(--text3)">${esc(s.host||'â€”')}</td>
        <td><span style="font-size:.62rem;font-weight:700;color:${clr}">${s.severity.toUpperCase()}</span></td>
      </tr>`;
    }).join('');
    html += `<div class="table-shell"><div class="tl-wrap" style="max-height:320px;overflow-y:auto"><table class="jobs-table">
      <thead><tr><th>Type</th><th>Value (click to reveal)</th><th>File (click to copy path)</th><th>Host</th><th>Risk</th></tr></thead>
      <tbody>${secRows}</tbody></table></div></div>`;
  } else {
    html += `<div style="padding:12px 0;color:var(--text3);font-size:.78rem">No secrets or hardcoded keys found. Run js_secrets, trufflehog or Playwright Recon.</div>`;
  }

  // â”€â”€ POSTMAN COLLECTIONS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const postmanData = co?.postman_data;
  const pmCollections = postmanData?.collections || [];
  const pmGithubHits  = postmanData?.github_hits || [];
  const pmSecrets     = postmanData?.secrets || [];
  const pmHasData     = pmCollections.length + pmGithubHits.length + pmSecrets.length > 0;
  const pmTotal       = postmanData?.total || pmCollections.length + pmGithubHits.length;

  html += _secHead('ðŸ“®', `Postman Collections (${pmTotal})`, 'Public Postman collections and GitHub-committed postman files referencing the target. Click URLs to open.', null);
  if (pmHasData) {
    // Collections
    if (pmCollections.length) {
      html += `<div style="padding:4px 0 12px;font-size:.7rem;color:var(--text3)"><strong>Public Collections (${pmCollections.length})</strong></div>`;
      const pmcRows = pmCollections.slice(0, 20).map(c => `<tr>
        <td style="font-size:.72rem"><a href="${esc(c.url||'')}" target="_blank" style="color:var(--teal);text-decoration:none" onmouseover="this.style.textDecoration='underline'" onmouseout="this.style.textDecoration='none'">${esc(c.name||c.id||'?')}</a></td>
        <td style="font-size:.67rem;color:var(--text3)">${esc(c.owner||'')}</td>
        <td style="font-size:.64rem;color:var(--teal)">${esc(c.id||'')}</td>
      </tr>`).join('');
      html += `<div class="table-shell"><div class="tl-wrap" style="max-height:240px;overflow-y:auto"><table class="jobs-table">
        <thead><tr><th>Collection</th><th>Owner</th><th>ID</th></tr></thead>
        <tbody>${pmcRows}</tbody></table></div></div>`;
    }
    // GitHub hits
    if (pmGithubHits.length) {
      html += `<div style="padding:8px 0 4px;font-size:.7rem;color:var(--text3)"><strong>GitHub Files (${pmGithubHits.length})</strong></div>`;
      const pmgRows = pmGithubHits.slice(0, 15).map(g => `<tr>
        <td style="font-size:.7rem"><a href="${esc(g.url||'')}" target="_blank" style="color:var(--teal);text-decoration:none" onmouseover="this.style.textDecoration='underline'" onmouseout="this.style.textDecoration='none'">${esc(g.repo||'')}/${esc(g.file||'')}</a></td>
        <td style="font-size:.67rem;color:var(--text3)">${esc(g.repo||'')}</td>
      </tr>`).join('');
      html += `<div class="table-shell"><div class="tl-wrap" style="max-height:200px;overflow-y:auto"><table class="jobs-table">
        <thead><tr><th>File</th><th>Repository</th></tr></thead>
        <tbody>${pmgRows}</tbody></table></div></div>`;
    }
    // Secrets from Postman files
    if (pmSecrets.length) {
      html += `<div style="padding:8px 0 4px;font-size:.7rem;color:var(--text3)"><strong>Extracted Secrets (${pmSecrets.length})</strong></div>`;
      const pmsRows = pmSecrets.slice(0, 15).map(s => `<tr>
        <td style="font-size:.7rem"><code style="font-family:var(--mono);font-size:.66rem;color:var(--text2)">${esc(s.type||'secret')}</code></td>
        <td style="font-size:.67rem;color:var(--text3);font-family:var(--mono);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(s.value||'')}">${esc((s.value||'').slice(0,40))}...</td>
        <td style="font-size:.64rem;color:var(--teal)">${esc(s.repo||'')}</td>
      </tr>`).join('');
      html += `<div class="table-shell"><div class="tl-wrap" style="max-height:200px;overflow-y:auto"><table class="jobs-table">
        <thead><tr><th>Type</th><th>Value</th><th>Repo</th></tr></thead>
        <tbody>${pmsRows}</tbody></table></div></div>`;
    }
  } else {
    html += `<div style="padding:12px 0;color:var(--text3);font-size:.78rem">No Postman collections found. Run postman_collections module to discover exposed API collections.</div>`;
  }

  // â”€â”€ VULNERABILITY FINDINGS (host header, redirect, CORS, CRLF, XSS, etc) â”€â”€â”€
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
    html += _secHead('ðŸŽ¯', `Vulnerability Findings (${vulnFindings.length})`, 'Host header injection, open redirects, CORS misconfigs, XSS, CRLF, default creds, and other active checks.', null);
    html += `<div style="display:flex;gap:6px;flex-wrap:wrap;padding:8px 0;align-items:center">
      <input id="${vulnFilterId}" placeholder="Filter findings..." style="background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 10px;font-size:.7rem;width:180px" oninput="document.querySelectorAll('.vuln-row').forEach(r=>{const t=r.textContent.toLowerCase();r.style.display=t.includes(this.value.toLowerCase())?'':'none'})">
    </div>`;

    const vulnRows = vulnFindings.slice(0, 100).map(f => {
      const clr = f.severity === 'critical' ? '#fb7185' : f.severity === 'high' ? '#fb923c' : f.severity === 'medium' ? '#fbbf24' : f.severity === 'low' ? '#4ade80' : '#94a3b8';
      const moduleLabel = f.module ? f.module.replace(/_/g, ' ') : '';
      const copyVal = esc(f.url||f.value||'');
      return `<tr class="vuln-row" style="cursor:pointer" onclick="navigator.clipboard.writeText(this.getAttribute('data-copy')).then(()=>{this.style.background='rgba(0,201,167,.08)';setTimeout(()=>this.style.background='',600)})" data-copy="${copyVal}" title="Click to copy: ${copyVal}">
        <td><span style="font-size:.62rem;font-weight:700;color:${clr}">${(f.severity||'').toUpperCase()}</span></td>
        <td style="font-size:.72rem"><span style="color:var(--teal);font-size:.6rem;opacity:.7">${esc(moduleLabel)}</span> ${esc(f.title||f.type||'')}</td>
        <td style="font-size:.67rem;color:var(--text3);font-family:var(--mono);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.host||'')}">${esc((f.host||'â€”').slice(0,35))}</td>
        <td style="font-size:.64rem;color:var(--teal);font-family:var(--mono);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${copyVal}">${esc((f.url||f.value||'').slice(0,50))} ðŸ“‹</td>
      </tr>`;
    }).join('');

    html += `<div class="table-shell"><div class="tl-wrap" style="max-height:400px;overflow-y:auto"><table class="jobs-table">
      <thead><tr><th>Sev</th><th>Finding</th><th>Host</th><th>URL / Value (click to copy)</th></tr></thead>
      <tbody>${vulnRows}</tbody></table></div></div>`;
  }

  // â”€â”€ Playwright findings summary (if any) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (pwFindings.length) {
    html += _secHead('âš¡', `Playwright Findings (${pwFindings.length})`, 'Issues flagged by the automated browser agent.', null);
    const fRows = pwFindings.map(f => `<tr>
      <td style="font-size:.7rem;font-weight:600;color:${f.severity==='critical'?'#fb7185':f.severity==='high'?'#fb923c':'#fbbf24'}">${esc(f.severity||'').toUpperCase()}</td>
      <td style="font-size:.75rem">${esc(f.title||f.type||'')}</td>
      <td style="font-size:.68rem;color:var(--text3);font-family:var(--mono);word-break:break-all">${esc(f.url||f.evidence||'')}</td>
    </tr>`).join('');
    html += `<div class="table-shell"><div class="tl-wrap"><table class="jobs-table">
      <thead><tr><th>Sev</th><th>Finding</th><th>URL / Evidence</th></tr></thead>
      <tbody>${fRows}</tbody></table></div></div>`;
  }

  html += `</div>`;
  el.innerHTML = html;
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
          <div class="playwright-item-sub">${pwJobs.length} job(s) total Â· ${done} done Â· ${running} running Â· ${pending} pending</div>
        </div>
      </div>
      <div class="playwright-item-badges">
        <span class="playwright-item-badge done">Done ${done}</span>
        <span class="playwright-item-badge running">Running ${running}</span>
        <span class="playwright-item-badge pending">Pending ${pending}</span>
      </div>
    </div>
    ${pwJobs.slice(0, 4).map(job => _playwrightCard(job, {
      meta: `${_fmtJobTime(job.created_at)} Â· ${(Array.isArray(job.options?.scope) ? job.options.scope.join(", ") : (job.options?.scope || "no scope"))}`
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
            <div class="playwright-item-sub">${pwJobs.length} recent job(s) Â· ${done} done Â· ${running} running Â· ${pending} pending</div>
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

async function loadJobs() {
  const tbody = document.getElementById("jobs-tbody");
  if (!tbody) return;
  const note = document.getElementById("jobs-note");
  const pager = document.getElementById("jobs-pager");
  const deleteFilterBtn = document.getElementById("jobs-delete-filter");
  // KPI cards + per-company cards are driven by the aggregate summary so they
  // always reflect true totals, independent of what the table is showing.
  loadJobCompanyCards();
  renderPlaywrightOverviewAll();

  try {
    // Drill-down mode: the table becomes the per-domain list for one company.
    if (_jobDrilldownCid) {
      if (pager) pager.style.display = "none";
      if (deleteFilterBtn) deleteFilterBtn.style.display = "none";
      const cid = _jobDrilldownCid;
      const q = `company_id=${encodeURIComponent(cid)}`;
      const arr = a => Array.isArray(a) ? a : [];
      let jobs;
      if (_jobDrillQuery) {
        // Search expands job options too, so it finds domains stored inside
        // single pipeline jobs, not only per-domain queue targets.
        const res = await fetch(`/api/jobs?${q}&limit=500`, {headers:_authHeaders()}).then(r=>r.json());
        if (_jobDrilldownCid !== cid) return;
        jobs = arr(res);
      } else {
        const all = await fetch(`/api/jobs?${q}&limit=500`, {headers:_authHeaders()}).then(r=>r.json());
        if (_jobDrilldownCid !== cid) return;   // toggled away mid-flight
        jobs = arr(all);
      }
      const domainRows = _jobDomainRows(jobs, cid, _jobDrillQuery);
      renderJobDomains(domainRows, {cid});
      const sum = (_jobSummaryCache.find(s => s.company_id === cid) || {}).counts || {};
      const waitT = (sum.running||0)+(sum.pending||0), doneT = sum.done||0, stoppedT = sum.stopped||0;
      const back = `<a href="#" onclick="exitJobDrilldown();return false" style="color:var(--teal)">voltar para a fila</a>`;
      if (note) note.innerHTML = _jobDrillQuery
        ? `${domainRows.length} dominio(s) encontrados por "${esc(_jobDrillQuery)}" em <b>${esc(_companyNameForJob(cid))}</b>. ${back}`
        : `Dominios de <b>${esc(_companyNameForJob(cid))}</b>: ${domainRows.length.toLocaleString()} dominio(s), ${waitT.toLocaleString()} aguardando, ${doneT.toLocaleString()} finalizados, ${stoppedT.toLocaleString()} parados. ${back}`;
      return;
    }

    // Default mode: show recent queue history. Status filters narrow it down
    // without flooding the browser because the API remains capped.
    const type = document.getElementById("jobs-type-filter")?.value || "";
    const statusEl = document.getElementById("jobs-status-filter");
    const status = statusEl ? statusEl.value : "running";
    if (deleteFilterBtn) {
      deleteFilterBtn.style.display = ["done", "error", "cancelled", "stopped"].includes(status) ? "inline-flex" : "none";
    }
    const offset = (_jobsPage - 1) * JOBS_PAGE_SIZE;
    const url = `/api/jobs?limit=${JOBS_PAGE_SIZE}&offset=${offset}&include_total=1`
      + (type ? "&job_type=" + encodeURIComponent(type) : "")
      + (status ? "&status=" + encodeURIComponent(status) : "");
    const r = await fetch(url, {headers:_authHeaders()});
    if (!r.ok) throw new Error("HTTP " + r.status);
    const payload = await r.json();
    const jobs = Array.isArray(payload) ? payload : (payload.jobs || []);
    _jobsTotal = Array.isArray(payload) ? jobs.length : Number(payload.total || 0);
    const maxPage = Math.max(1, Math.ceil(_jobsTotal / JOBS_PAGE_SIZE));
    if (_jobsPage > maxPage) {
      _jobsPage = maxPage;
      return loadJobs();
    }
    renderJobs(jobs, {drilldown: false});
    renderJobsPager(_jobsTotal, _jobsPage, JOBS_PAGE_SIZE);
    _updateJobCountBadgeFromList(jobs);
    if (note) note.textContent = status === "running"
      ? `${_jobsTotal.toLocaleString()} job(s) rodando agora. Exibindo 20 por pagina. Clique em uma empresa para ver dominios pendentes e finalizados.`
      : `${_jobsTotal.toLocaleString()} job(s) no historico${type ? " de " + _jobTypeLabel(type) : ""}. Exibindo 20 por pagina.`;
  } catch(e) {
    tbody.innerHTML = `<tr><td colspan="8" style="color:var(--red);text-align:center;padding:22px">Failed to load jobs: ${esc(e.message)}</td></tr>`;
    if (note) note.textContent = "Fila indisponivel.";
    if (pager) pager.style.display = "none";
  }
}

function exitJobDrilldown() {
  _jobDrilldownCid = null;
  _jobDrillQuery = "";
  const dd = document.getElementById("jobs-drilldown");
  if (dd) dd.innerHTML = "";
  renderJobCompanyCards(_jobSummaryCache);
  loadJobs();
}

function _jobOptionDomains(job, cid) {
  const opts = job && job.options ? job.options : {};
  const domains = [];
  const add = value => {
    const clean = String(value || "").trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
    if (clean && clean !== cid && !domains.includes(clean)) domains.push(clean);
  };
  if (Array.isArray(opts.domains)) opts.domains.forEach(add);
  if (Array.isArray(opts.scope)) opts.scope.forEach(add);
  add(opts.queue_domain);
  add(opts.target_url);
  add(job && job.target);
  return domains;
}

function _jobDomainRows(jobs, cid, query) {
  const q = String(query || "").trim().toLowerCase();
  const rows = new Map();
  const sorted = [...(Array.isArray(jobs) ? jobs : [])].sort((a, b) => {
    return String(b.created_at || "").localeCompare(String(a.created_at || ""));
  });
  sorted.forEach(job => {
    _jobOptionDomains(job, cid).forEach(domain => {
      if (q && !domain.toLowerCase().includes(q)) return;
      if (!rows.has(domain)) rows.set(domain, {
        domain,
        job_id: job.id,
        company_id: job.company_id,
        job_type: job.job_type,
        status: job.status,
        attempts: job.attempts,
        max_attempts: job.max_attempts,
        created_at: job.created_at,
        started_at: job.started_at,
        finished_at: job.finished_at,
        error: job.error,
      });
    });
  });
  return [...rows.values()].sort((a, b) => {
    const sa = a.status === "running" ? 0 : a.status === "pending" ? 1 : 2;
    const sb = b.status === "running" ? 0 : b.status === "pending" ? 1 : 2;
    return sa - sb || a.domain.localeCompare(b.domain);
  });
}

function renderJobDomains(rows, ctx) {
  const tbody = document.getElementById("jobs-tbody");
  if (!tbody) return;
  const cid = ctx && ctx.cid;

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="8"><div class="job-empty">Nenhum dominio encontrado para esta empresa.</div></td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(row => {
    const cls = _jobStatusClass(row.status);
    const err = row.error ? `<div class="job-error" title="${esc(row.error)}">${esc(row.error)}</div>` : "";
    const canOpenResults = row.status === "done" || row.status === "running" || row.status === "stopped";
    return `<tr>
      <td><span class="job-status ${cls}">${_jobStatusLabel(row.status)}</span></td>
      <td>
        <div class="job-company" style="font-family:var(--mono)">${esc(row.domain)}</div>
        <div class="job-id">${esc(row.job_id)}</div>
        ${err}
      </td>
      <td><span class="job-type">${esc(_jobTypeLabel(row.job_type))}</span></td>
      <td>${_fmtJobTime(row.created_at)}</td>
      <td>${_fmtJobTime(row.started_at)}</td>
      <td>${_fmtJobTime(row.finished_at)}</td>
      <td>${Number(row.attempts || 0)} / ${Number(row.max_attempts || 1)}</td>
      <td>
        <div class="job-actions">
          <button type="button" class="btn btn-secondary btn-icon" data-job-action="detail" data-job-id="${escAttr(row.job_id)}">Detalhes</button>
          ${canOpenResults ? `<button type="button" class="btn btn-secondary btn-icon" data-job-action="domain-results" data-cid="${escAttr(cid)}" data-target="${escAttr(row.domain)}">Resultados</button>` : ""}
        </div>
      </td>
    </tr>`;
  }).join("");
}

function renderJobs(jobs, ctx) {
  const tbody = document.getElementById("jobs-tbody");
  if (!tbody) return;
  const drilldown = !!(ctx && ctx.drilldown);
  const cid = ctx && ctx.cid;

  if (!jobs.length) {
    const msg = drilldown ? "Nenhum dominio encontrado para esta empresa." : "Nenhum job encontrado neste filtro.";
    tbody.innerHTML = `<tr><td colspan="8"><div class="job-empty">${msg}</div></td></tr>`;
    return;
  }

  tbody.innerHTML = jobs.map(job => {
    const cls = _jobStatusClass(job.status);
    const err = job.error ? `<div class="job-error" title="${esc(job.error)}">${esc(job.error)}</div>` : "";
    const canCancel = job.status === "pending";
    const canDelete = ["done", "error", "cancelled", "stopped"].includes(job.status);
    const canArtifacts = job.job_type === "playwright_recon" && job.status === "done";
    const isErrorOrStuck = job.status === "error" || (job.status === "running" && job.attempts > 1);
    const rowClass = isErrorOrStuck ? " class='job-row-err'" : "";
    const primary = _jobPrimaryTarget(job);
    const secondary = `<div class="job-id">${esc(_jobSecondaryLabel(job))}</div>`;
    const isDone = job.status === "done";
    const openBtn = drilldown
      ? (isDone
          ? `<button type="button" class="btn btn-secondary btn-icon" data-job-action="domain-results" data-cid="${escAttr(cid)}" data-target="${escAttr(job.target || "")}">Resultados</button>`
          : "")
      : (job.company_id ? `<button type="button" class="btn btn-secondary btn-icon" data-job-action="open-company-pipeline" data-cid="${escAttr(job.company_id)}">Abrir</button>` : "");
    return `<tr${rowClass}>
      <td><span class="job-status ${cls}">${_jobStatusLabel(job.status)}</span></td>
      <td>
        <div class="job-company job-target">${esc(primary)}</div>
        ${secondary}
        ${err}
      </td>
      <td><span class="job-type">${esc(_jobTypeLabel(job.job_type))}</span></td>
      <td>${_fmtJobTime(job.created_at)}</td>
      <td>${_fmtJobTime(job.started_at)}</td>
      <td>${_fmtJobTime(job.finished_at)}</td>
      <td>${Number(job.attempts || 0)} / ${Number(job.max_attempts || 1)}</td>
      <td>
        <div class="job-actions">
          <button type="button" class="btn btn-secondary btn-icon" data-job-action="detail" data-job-id="${escAttr(job.id)}">Detalhes</button>
          ${openBtn}
          ${canArtifacts ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'report')}" target="_blank" rel="noopener">Relatorio</a>` : ""}
          ${canArtifacts ? `<a class="btn btn-secondary btn-icon" href="${_jobArtifactUrl(job.id, 'session')}" target="_blank" rel="noopener">Sessao</a>` : ""}
          ${canCancel ? `<button type="button" class="btn btn-icon job-cancel" data-job-action="cancel" data-job-id="${escAttr(job.id)}">Cancelar</button>` : ""}
          ${canDelete ? `<button type="button" class="btn btn-icon job-delete" data-job-action="delete" data-job-id="${escAttr(job.id)}">Excluir</button>` : ""}
        </div>
      </td>
    </tr>`;
  }).join("");

  const firstUseful = jobs.find(job => job.job_type === "playwright_recon" && job.status === "done");
  if (firstUseful && !document.querySelector("#job-detail-panel .job-detail-title")) {
    openJobDetail(firstUseful.id);
  }
}

function renderJobsPager(total, page, pageSize) {
  const pager = document.getElementById("jobs-pager");
  const info = document.getElementById("jobs-pinfo");
  const btns = document.getElementById("jobs-pbtns");
  if (!pager || !info || !btns) return;
  const pages = Math.max(1, Math.ceil((total || 0) / pageSize));
  if (!total || pages <= 1) {
    pager.style.display = "none";
    return;
  }
  pager.style.display = "flex";
  const start = (page - 1) * pageSize + 1;
  const end = Math.min(total, page * pageSize);
  info.textContent = `${start.toLocaleString()}-${end.toLocaleString()} de ${total.toLocaleString()} jobs`;

  const nums = [];
  const add = p => { if (!nums.includes(p) && p >= 1 && p <= pages) nums.push(p); };
  add(1);
  for (let p = page - 2; p <= page + 2; p++) add(p);
  add(pages);
  nums.sort((a,b) => a-b);

  let last = 0;
  const html = [];
  html.push(`<button class="pb" ${page <= 1 ? "disabled" : ""} onclick="setJobsPage(${page - 1})">â†</button>`);
  nums.forEach(p => {
    if (last && p - last > 1) html.push(`<span class="job-page-gap">â€¦</span>`);
    html.push(`<button class="pb ${p === page ? "active" : ""}" onclick="setJobsPage(${p})">${p}</button>`);
    last = p;
  });
  html.push(`<button class="pb" ${page >= pages ? "disabled" : ""} onclick="setJobsPage(${page + 1})">â†’</button>`);
  btns.innerHTML = html.join("");
}

function setJobsPage(page) {
  _jobsPage = Math.max(1, Number(page) || 1);
  loadJobs();
}

// â”€â”€ Per-company queue cards + per-domain drill-down â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
let _jobSummaryCache = [], _jobDrilldownCid = null;
let _jobDrillQuery = "", _jobDrillTimer = null;

// Persistent search bar for the drill-down (rendered once on entry so the 5s
// poll that refreshes the table body does not steal focus or reset the query).
function _renderJobDrillSearchBar(cid) {
  const host = document.getElementById("jobs-drilldown");
  if (!host) return;
  host.innerHTML = `
    <div class="jobs-drillbar">
      <input class="fi" id="job-drill-search" type="text" value="${escAttr(_jobDrillQuery)}"
             placeholder="Buscar dominio em ${esc(_companyNameForJob(cid))}..."
             oninput="_onJobDrillSearch()" autocomplete="off"
             aria-label="Buscar dominio nesta empresa">
      <button class="btn btn-secondary btn-icon" onclick="exitJobDrilldown()">Voltar</button>
    </div>`;
}

function _onJobDrillSearch() {
  const inp = document.getElementById("job-drill-search");
  _jobDrillQuery = inp ? inp.value.trim() : "";
  clearTimeout(_jobDrillTimer);
  _jobDrillTimer = setTimeout(() => { if (_jobDrilldownCid) loadJobs(); }, 280);
}

async function loadJobCompanyCards() {
  const host = document.getElementById("jobs-company-cards");
  if (!host) return;
  try {
    const r = await fetch("/api/jobs/summary", {headers:_authHeaders()});
    if (!r.ok) throw new Error("HTTP " + r.status);
    _jobSummaryCache = await r.json();
    renderJobCompanyCards(_jobSummaryCache);
  } catch(e) {
    host.innerHTML = `<div style="color:var(--text3);font-size:.7rem;padding:6px 0">Per-company summary unavailable.</div>`;
  }
}

function _renderJobKPIs(summary) {
  const el = document.getElementById("jobs-summary");
  if (!el) return;
  const totals = {running:0, pending:0, done:0, error:0, stopped:0, cancelled:0};
  (Array.isArray(summary) ? summary : []).forEach(s => {
    const c = s.counts || {};
    for (const k in totals) totals[k] += (c[k] || 0);
  });
  el.innerHTML = ["running", "pending", "done", "error", "stopped", "cancelled"].map(st => _jobKPICard(st, totals[st] || 0)).join("");
}

function renderJobCompanyCards(summary) {
  const host = document.getElementById("jobs-company-cards");
  if (!host) return;
  _renderJobKPIs(summary);
  if (!Array.isArray(summary) || !summary.length) {
    host.innerHTML = "";
    _jobDrilldownCid = null;
    _jobDrillQuery = "";
    const dd = document.getElementById("jobs-drilldown");
    if (dd) dd.innerHTML = "";
    return;
  }
  const cards = summary.filter(s => (s.total || 0) > 0);
  const chip = (n, label, cls) => n ? `<span class="job-chip ${cls}">${n.toLocaleString()} ${label}</span>` : "";
  host.innerHTML = `<div class="job-company-card-grid">` + cards.map(s => {
    const c = s.counts || {};
    const active = _jobDrilldownCid === s.company_id;
    const name = _companyNameForJob(s.company_id);
    return `
      <div class="job-company-card ${active ? "active" : ""}" data-job-company-id="${escAttr(s.company_id)}" role="button" tabindex="0">
        <div class="job-company-card-head">
          <div class="job-company-card-title">${esc(name)}</div>
          <div class="job-company-card-total">${(s.total||0).toLocaleString()} jobs</div>
        </div>
        <div class="job-company-card-chips">
          ${chip(c.running, "rodando", "running")}
          ${chip(c.pending, "pendente", "pending")}
          ${chip(c.done, "finalizado", "done")}
          ${chip(c.error, "erro", "error")}
          ${chip(c.cancelled, "cancelado", "cancelled")}
          ${chip(c.stopped, "parado", "stopped")}
        </div>
        <div class="job-company-card-cta">${active ? "Mostrando dominios na tabela" : "Ver dominios da fila"}</div>
      </div>`;
  }).join("") + `</div>`;
}

function toggleJobDrilldown(cid) {
  const entering = _jobDrilldownCid !== cid;
  _jobDrilldownCid = entering ? cid : null;
  _jobDrillQuery = "";
  const dd = document.getElementById("jobs-drilldown");
  if (entering) _renderJobDrillSearchBar(cid);
  else if (dd) dd.innerHTML = "";
  renderJobCompanyCards(_jobSummaryCache);   // update active state immediately
  loadJobs();                                // table switches into / out of drill-down mode
}

async function openDomainResults(cid, domain) {
  try { await selectCompany(cid); } catch(e) {}
  openSubdomainsFiltered(domain);
}

// Launch dialog: lets the operator set safe-mode, active tests (XSS/Race) and auth-state
// before running. Active tests are gated behind safe-mode OFF + an authorization confirm.
function openPlaywrightModal(cid) {
  const cfg = _currentPlaywrightDefaults();
  const co = allCompanies().find(c => c.id === cid);
  const target = (co?.domains || []).filter(Boolean)[0] || "";
  const safe = cfg.playwright_safe_mode !== false;
  closePlaywrightModal();
  const ov = document.createElement("div");
  ov.className = "modal-overlay show";
  ov.id = "modal-playwright";
  ov.innerHTML = `
    <div class="modal" style="width:470px">
      <div class="modal-title">â–¶ Playwright Recon â€” ${esc(co?.name || cid)}</div>
      <div class="modal-hint" style="margin-bottom:12px">Target: https://${esc(String(target).replace(/^https?:\/\//, ""))}</div>
      <div style="display:flex;gap:10px">
        <div class="modal-field" style="flex:1"><label class="modal-label">Max pages</label>
          <input type="number" class="modal-input" id="pw-max-pages" value="${Number(cfg.playwright_max_pages || 50)}" min="1" max="2000"></div>
        <div class="modal-field" style="flex:1"><label class="modal-label">Max depth</label>
          <input type="number" class="modal-input" id="pw-max-depth" value="${Number(cfg.playwright_max_depth || 3)}" min="1" max="10"></div>
      </div>
      <div class="modal-field"><label class="modal-label">Auth state â€” storage_state JSON (habilita testes autenticados)</label>
        <input type="text" class="modal-input" id="pw-auth-state" value="${esc(cfg.playwright_auth_state || "")}" placeholder="/caminho/para/auth.json"></div>
      <div class="modal-field"><label class="modal-label">Auth state B â€” para IDOR A/B (opcional)</label>
        <input type="text" class="modal-input" id="pw-auth-state-b" value="${esc(cfg.playwright_auth_state_b || "")}" placeholder="/caminho/para/auth-b.json"></div>
      <label class="modal-label" style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:10px">
        <input type="checkbox" id="pw-safe-mode" ${safe ? "checked" : ""} onchange="_pwSafeToggle()"><span>Safe mode (sem testes ativos)</span></label>
      <div id="pw-active-box" style="border:1px solid var(--border);border-radius:8px;padding:10px;margin-bottom:10px;opacity:${safe ? 0.5 : 1}">
        <div class="modal-hint" id="pw-active-warn" style="margin-top:0;color:var(--orange);${safe ? "display:none" : ""}">âš  Active testing â€” use apenas em alvos autorizados.</div>
        <label class="modal-label" style="display:flex;align-items:center;gap:8px;cursor:pointer;margin:8px 0 0">
          <input type="checkbox" class="pw-active-chk" id="pw-test-xss" ${cfg.playwright_test_xss ? "checked" : ""} ${safe ? "disabled" : ""}><span>Test XSS (confirmado por execuÃ§Ã£o real)</span></label>
        <label class="modal-label" style="display:flex;align-items:center;gap:8px;cursor:pointer;margin:8px 0 0">
          <input type="checkbox" class="pw-active-chk" id="pw-test-race" ${cfg.playwright_test_race ? "checked" : ""} ${safe ? "disabled" : ""}><span>Test Race (probe paralelo bounded, nÃ£o-destrutivo)</span></label>
        <label class="modal-label" style="display:flex;align-items:center;gap:8px;cursor:pointer;margin:8px 0 0">
          <input type="checkbox" class="pw-active-chk" id="pw-test-access" ${cfg.playwright_test_access ? "checked" : ""} ${safe ? "disabled" : ""}><span>Test Access (broken access control â€” "confia no front")</span></label>
      </div>
      <label class="modal-label" style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:6px">
        <input type="checkbox" id="pw-allow-external" ${cfg.playwright_allow_external ? "checked" : ""}><span>Allow external (seguir fora do escopo)</span></label>
      <div class="modal-btns">
        <button class="btn btn-secondary" onclick="closePlaywrightModal()">Cancel</button>
        <button class="btn btn-primary" onclick="submitPlaywrightRecon('${cid}')">â–¶ Run</button>
      </div>
    </div>`;
  ov.addEventListener("click", e => { if (e.target === ov) closePlaywrightModal(); });
  document.body.appendChild(ov);
}

function _pwSafeToggle() {
  const safe = document.getElementById("pw-safe-mode").checked;
  document.querySelectorAll(".pw-active-chk").forEach(c => { c.disabled = safe; if (safe) c.checked = false; });
  document.getElementById("pw-active-box").style.opacity = safe ? 0.5 : 1;
  const warn = document.getElementById("pw-active-warn");
  if (warn) warn.style.display = safe ? "none" : "";
}

function closePlaywrightModal() {
  const el = document.getElementById("modal-playwright");
  if (el) el.remove();
}

function submitPlaywrightRecon(cid) {
  const v = id => document.getElementById(id);
  const opts = {
    max_pages: Number(v("pw-max-pages").value) || 50,
    max_depth: Number(v("pw-max-depth").value) || 3,
    auth_state: v("pw-auth-state").value.trim(),
    auth_state_b: v("pw-auth-state-b").value.trim(),
    safe_mode: v("pw-safe-mode").checked,
    test_xss: v("pw-test-xss").checked,
    test_race: v("pw-test-race").checked,
    test_access: v("pw-test-access").checked,
    allow_external: v("pw-allow-external").checked,
  };
  if (!opts.safe_mode && (opts.test_xss || opts.test_race || opts.test_access)) {
    if (!confirm("Active testing (XSS/Race/Access) envia payloads/requests ao alvo. Confirme que vocÃª tem autorizaÃ§Ã£o para testar este alvo.")) return;
  }
  let cfg = {};
  try { cfg = JSON.parse(localStorage.getItem("asm_settings") || "{}"); } catch(e) {}
  Object.assign(cfg, {
    playwright_max_pages: opts.max_pages, playwright_max_depth: opts.max_depth,
    playwright_auth_state: opts.auth_state, playwright_auth_state_b: opts.auth_state_b,
    playwright_safe_mode: opts.safe_mode, playwright_test_xss: opts.test_xss,
    playwright_test_race: opts.test_race, playwright_test_access: opts.test_access,
    playwright_allow_external: opts.allow_external,
  });
  try { localStorage.setItem("asm_settings", JSON.stringify(cfg)); } catch(e) {}
  closePlaywrightModal();
  runPlaywrightRecon(cid, opts);
}

async function runPlaywrightRecon(cid, opts = null) {
  const btn = document.getElementById(`playwright-btn-${cid}`);
  if (btn) { btn.disabled = true; btn.textContent = "Startingâ€¦"; }
  const cfg = _currentPlaywrightDefaults();
  const o = opts || {};
  const pick = (k, def) => (o[k] !== undefined ? o[k] : (cfg["playwright_" + k] !== undefined ? cfg["playwright_" + k] : def));
  const safe_mode = o.safe_mode !== undefined ? !!o.safe_mode : (cfg.playwright_safe_mode !== false);
  try {
    const co = allCompanies().find(c => c.id === cid);
    const domains = Array.isArray(co?.domains) ? co.domains.filter(Boolean) : [];
    const target = domains.length ? `https://${String(domains[0]).replace(/^https?:\/\//, "")}` : "";
    const r = await fetch(`/api/recon/${cid}/playwright`, {
      method: "POST",
      headers: {"Content-Type":"application/json", ..._authHeaders()},
      body: JSON.stringify({
        target_url: target,
        scope: domains,
        max_pages: Number(pick("max_pages", 50)),
        max_depth: Number(pick("max_depth", 3)),
        timeout: Number(cfg.playwright_timeout || 20),
        slow_mo: Number(cfg.playwright_slow_mo || 0),
        user_agent: cfg.playwright_user_agent || "",
        allow_external: !!pick("allow_external", false),
        safe_mode: safe_mode,
        // Active tests are only sent when safe-mode is off (backend enforces this too).
        test_xss: !safe_mode && !!(o.test_xss ?? cfg.playwright_test_xss),
        test_race: !safe_mode && !!(o.test_race ?? cfg.playwright_test_race),
        test_access: !safe_mode && !!(o.test_access ?? cfg.playwright_test_access),
        trace: !!pick("trace", false),
        headless: o.headless !== undefined ? !!o.headless : (cfg.playwright_headless !== false),
        auth_state: (o.auth_state ?? cfg.playwright_auth_state) || "",
        auth_state_b: (o.auth_state_b ?? cfg.playwright_auth_state_b) || "",
      }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
    showPage("jobs");
    loadJobs();
  } catch(e) {
    if (btn) { btn.disabled = false; btn.textContent = "â–¶ Playwright Recon"; }
    alert("Erro ao iniciar Playwright Recon: " + e.message);
  }
}

async function cancelJob(jobId) {
  if (!confirm("Cancel this pending job?")) return;
  try {
    const r = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`, {method:"DELETE", headers:_authHeaders()});
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      alert(data.error || "Could not cancel job");
      return;
    }
    loadJobs();
  } catch(e) {
    alert("Connection error: " + e.message);
  }
}

async function deleteJob(jobId) {
  if (!confirm("Excluir este registro finalizado da fila?")) return;
  try {
    const r = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`, {method:"DELETE", headers:_authHeaders()});
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      alert(data.error || "Could not delete job");
      return;
    }
    loadJobs();
  } catch(e) {
    alert("Connection error: " + e.message);
  }
}

async function deleteJobsFilter() {
  const type = document.getElementById("jobs-type-filter")?.value || "";
  const status = document.getElementById("jobs-status-filter")?.value || "";
  const finalStatuses = ["done", "error", "cancelled", "stopped"];
  if (!finalStatuses.includes(status)) {
    alert("Selecione um status finalizado para limpar: Concluido, Erro, Parado ou Cancelado.");
    return;
  }
  if (!confirm(`Excluir todos os registros com status "${_jobStatusLabel(status)}"${type ? " de " + _jobTypeLabel(type) : ""}? Jobs rodando e pendentes nao serao apagados.`)) return;
  const params = new URLSearchParams({status});
  if (type) params.set("job_type", type);
  try {
    const r = await fetch(`/api/jobs?${params.toString()}`, {method:"DELETE", headers:_authHeaders()});
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      alert(data.error || "Could not delete jobs");
      return;
    }
    _jobsPage = 1;
    loadJobs();
  } catch(e) {
    alert("Connection error: " + e.message);
  }
}

function initJobQueueHandlers() {
  if (window.__jobQueueHandlersReady) return;
  window.__jobQueueHandlersReady = true;

  document.addEventListener("click", event => {
    const btn = event.target && event.target.closest ? event.target.closest("[data-job-action]") : null;
    if (!btn) return;
    const action = btn.dataset.jobAction;
    if (!action) return;
    event.preventDefault();
    event.stopPropagation();

    if (action === "detail") {
      openJobDetail(btn.dataset.jobId || "");
    } else if (action === "open-company-pipeline") {
      openJobCompanyPipeline(btn.dataset.cid || "");
    } else if (action === "domain-results") {
      openDomainResults(btn.dataset.cid || "", btn.dataset.target || "");
    } else if (action === "cancel") {
      cancelJob(btn.dataset.jobId || "");
    } else if (action === "delete") {
      deleteJob(btn.dataset.jobId || "");
    }
  });

  document.addEventListener("click", event => {
    const card = event.target && event.target.closest ? event.target.closest("[data-job-company-id]") : null;
    if (!card) return;
    event.preventDefault();
    toggleJobDrilldown(card.dataset.jobCompanyId || "");
  });

  document.addEventListener("keydown", event => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const card = event.target && event.target.closest ? event.target.closest("[data-job-company-id]") : null;
    if (!card) return;
    event.preventDefault();
    toggleJobDrilldown(card.dataset.jobCompanyId || "");
  });

  document.addEventListener("change", event => {
    const id = event.target && event.target.id;
    if (id === "jobs-type-filter" || id === "jobs-status-filter") {
      _jobsPage = 1;
      loadJobs();
    }
  });

  document.addEventListener("click", event => {
    const btn = event.target && event.target.closest ? event.target.closest("#jobs-badge") : null;
    if (!btn) return;
    event.preventDefault();
    showPage("jobs");
    loadJobs();
  });
}

document.addEventListener("DOMContentLoaded", initJobQueueHandlers);

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  SETTINGS PAGE
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const SETTINGS_SCHEMA = [
  { group:"Threat Intelligence", icon:"ðŸ“¡", desc:"Active asset discovery & port/service data",
    fields:[
      {key:"shodan_key",          label:"Shodan API Key",          tag:"free",     hint:"shodan.io â€” free plan available",        signup:"https://account.shodan.io/"},
      {key:"censys_api_id",       label:"Censys API ID",           tag:"free",     hint:"censys.io â€” free researcher plan",       signup:"https://search.censys.io/account/api"},
      {key:"censys_api_secret",   label:"Censys API Secret",       tag:"free",     hint:"Paired with Censys API ID",              signup:"https://search.censys.io/account/api"},
      {key:"netlas_key",          label:"Netlas API Key",          tag:"free",     hint:"netlas.io â€” free tier available",        signup:"https://app.netlas.io/profile/"},
    ]
  },
  { group:"OSINT & Breach Data", icon:"ðŸ’€", desc:"Credential leaks, breach intelligence, dark web",
    fields:[
      {key:"hibp_key",            label:"HaveIBeenPwned API Key",  tag:"paid",     hint:"haveibeenpwned.com â€” domain search requires paid", signup:"https://haveibeenpwned.com/API/Key"},
      {key:"dehashed_key",        label:"DeHashed API Key",        tag:"paid",     hint:"dehashed.com â€” email/credential search", signup:"https://www.dehashed.com/profile"},
      {key:"leakix_key",          label:"LeakIX API Key",          tag:"free",     hint:"leakix.net â€” free tier works without key", signup:"https://leakix.net/settings"},
      {key:"intelx_key",          label:"IntelligenceX API Key",   tag:"paid",     hint:"intelx.io â€” leak & darkweb OSINT",       signup:"https://intelx.io/account?tab=developer"},
    ]
  },
  { group:"DNS & Subdomain", icon:"ðŸŒ", desc:"Passive subdomain enumeration & DNS intelligence",
    fields:[
      {key:"securitytrails_key",  label:"SecurityTrails API Key",  tag:"free",     hint:"securitytrails.com â€” 50 req/month free", signup:"https://securitytrails.com/app/account"},
      {key:"chaos_key",           label:"Chaos (ProjectDiscovery)",tag:"free",     hint:"chaos.projectdiscovery.io â€” free for researchers", signup:"https://chaos.projectdiscovery.io/"},
      {key:"whoisxml_key",        label:"WhoisXML API Key",        tag:"paid",     hint:"whoisxmlapi.com â€” reverse WHOIS (domÃ­nios irmÃ£os da org)", signup:"https://user.whoisxmlapi.com/products"},
    ]
  },
  { group:"CVE & Vulnerability DB", icon:"ðŸ’¥", desc:"CVE intelligence from NVD â€” cross-reference detected technologies with known vulnerabilities",
    fields:[
      {key:"nvd_key",             label:"NVD API Key",             tag:"free",     hint:"nvd.nist.gov â€” free, 50 req/30s with key vs 5 without", signup:"https://nvd.nist.gov/developers/request-an-api-key"},
    ]
  },
  { group:"Code & Secrets", icon:"ðŸ”‘", desc:"GitHub secrets, code leaks, API keys in repos",
    fields:[
      {key:"github_token",        label:"GitHub Token",            tag:"free",     hint:"Personal access token â€” avoids rate limits", signup:"https://github.com/settings/tokens/new"},
      {key:"wpscan_token",        label:"WPScan API Token",        tag:"free",     hint:"wpscan.com â€” WordPress vulnerability scanner, free API token", signup:"https://wpscan.com/profile"},
    ]
  },
  { group:"Email & Identity", icon:"âœ‰", desc:"Email infrastructure and identity OSINT",
    fields:[
      {key:"hunter_key",          label:"Hunter.io API Key",       tag:"free",     hint:"hunter.io â€” email finder, 25 req/month free", signup:"https://hunter.io/api_keys"},
    ]
  },
  { group:"Search Engines", icon:"ðŸ”", desc:"Specialized internet-wide search engines",
    fields:[
      {key:"virustotal_key",      label:"VirusTotal API Key",      tag:"free",     hint:"virustotal.com â€” free tier",             signup:"https://www.virustotal.com/gui/my-apikey"},
      {key:"fofa_email",          label:"FOFA Email",              tag:"paid",     hint:"fofa.info â€” Chinese internet search",    signup:"https://fofa.info/userInfo"},
      {key:"fofa_key",            label:"FOFA API Key",            tag:"paid",     hint:"Paired with FOFA Email",                 signup:"https://fofa.info/userInfo"},
    ]
  },
  { group:"AI / Hermes Agent", icon:"âœ¨", desc:"Enriquecimento de findings (CVSS, CWE, mitigaÃ§Ã£o e PoC) via Hermes Agent (Nous Research), self-hosted. Inicie o gateway com 'hermes gateway' e aponte para o host:porta dele â€” qualquer outro endpoint compatÃ­vel com OpenAI chat/completions tambÃ©m funciona.",
    fields:[
      {key:"hermes_base_url",     label:"API Base URL",            tag:"optional", hint:"PadrÃ£o: http://127.0.0.1:8642/v1 (endereÃ§o do seu 'hermes gateway' local, endpoint OpenAI-compatible /chat/completions)"},
      {key:"hermes_api_key",      label:"API Server Key", tag:"optional",  hint:"Bearer token (API_SERVER_KEY) do gateway, se ele exigir autenticaÃ§Ã£o. Deixe vazio se o gateway local nÃ£o exigir chave."},
      {key:"hermes_model",        label:"Modelo",                  tag:"optional", hint:"PadrÃ£o: hermes-agent (nome cosmÃ©tico â€” o gateway usa o modelo do profile configurado)"},
    ]
  },
  { group:"Bug Bounty Platforms", icon:"ðŸ†", desc:"Credenciais para visualizar programas de Bug Bounty diretamente na plataforma",
    fields:[
      {key:"hackerone_username",  label:"HackerOne Username",      tag:"optional", hint:"Seu username do HackerOne (nÃ£o o e-mail)", signup:"https://hackerone.com/settings/api_token_v2"},
      {key:"hackerone_token",     label:"HackerOne API Token",     tag:"optional", hint:"Token de API gerado em hackerone.com/settings/api_token_v2", signup:"https://hackerone.com/settings/api_token_v2"},
    ]
  },
];

// â”€â”€ Runtime Config Schema (separate âš¡ Performance page) â”€â”€
const RUNTIME_SCHEMA = [
  { group:"Runtime Engine", icon:"âš™", desc:"Pipeline workers, rate limits, and scan defaults",
    fields:[
      {key:"asm_job_workers",        label:"Pipeline Workers",        tag:"runtime", hint:"1",
       tooltip:"Quantos jobs de pipeline rodam ao mesmo tempo. 1 = um domÃ­nio por vez (seguro). Aumente para acelerar scans em massa, mas cada worker extra consome mais CPU e RAM."},
      {key:"asm_global_proc_limit",  label:"Global Process Limit",    tag:"runtime", hint:"6",
       tooltip:"Teto mÃ¡ximo de subprocessos externos (nmap, nuclei, ffuf, etc) rodando simultaneamente. Se atingir esse limite, novas ferramentas esperam na fila. Reduza se a VPS travar."},
      {key:"asm_domain_fanout",      label:"Domain Fan-out Workers",  tag:"runtime", hint:"3",
       tooltip:"Quantos domÃ­nios cada mÃ³dulo processa em paralelo. Ex: com 3, o subfinder escaneia 3 domÃ­nios ao mesmo tempo. Aumente para acelerar, mas cuidado com rate limit de APIs."},
      {key:"asm_gate_default",       label:"Default Tool Gate",       tag:"runtime", hint:"3",
       tooltip:"Limite de execuÃ§Ãµes simultÃ¢neas por ferramenta. Ex: com 3, no mÃ¡ximo 3 httpx rodam ao mesmo tempo. Ferramentas pesadas (nuclei, amass) tÃªm limite individual menor (1)."},
    ]
  },
  { group:"Scan Defaults", icon:"ðŸŽ¯", desc:"Default scan profile and rate mode for new scans",
    fields:[
      {key:"asm_rate_mode",          label:"Default Rate Mode",       tag:"runtime", hint:"balanced",
       tooltip:"Velocidade padrÃ£o dos scans. stealth = lento e invisÃ­vel (24/7). balanced = moderado. fast = rÃ¡pido mas pode alertar WAFs e bloqueadores."},
      {key:"asm_scan_mode",          label:"Default Scan Mode",       tag:"runtime", hint:"bug_bounty",
       tooltip:"Pipeline padrÃ£o da ferramenta. bug_bounty executa descoberta, validaÃ§Ã£o, priorizaÃ§Ã£o, JS/API, Playwright, checks leves, portas priorizadas e evidÃªncias."},
    ]
  },
  { group:"Watchdog", icon:"ðŸ›¡", desc:"Safety limits that pause the queue before the machine crashes",
    fields:[
      {key:"asm_watchdog_max_load",  label:"Max System Load",         tag:"runtime", hint:"4.0",
       tooltip:"Se a carga do sistema (load average) ultrapassar esse valor, o watchdog pausa a fila de jobs para evitar travamento da mÃ¡quina. Ajuste conforme o nÃºmero de CPUs."},
      {key:"asm_watchdog_min_mem_mb",label:"Min Free RAM (MB)",       tag:"runtime", hint:"1536",
       tooltip:"Se a memÃ³ria RAM livre cair abaixo desse valor, o watchdog pausa a fila. Aumente se tiver mais RAM disponÃ­vel, reduza se for uma VPS pequena."},
      {key:"asm_watchdog_max_procs", label:"Max Recon Processes",     tag:"runtime", hint:"10",
       tooltip:"Se o nÃºmero de processos de recon (nmap, nuclei, subfinder, etc) ultrapassar esse valor, o watchdog pausa a fila. Evita fork bombs e travamentos."},
    ]
  },
];

let _settingsData = {};
let _playwrightDefaults = {};
let _toolsData = [];

// Runtime config defaults (mirrors restart_server.sh)
const _RUNTIME_DEFAULTS = {
  asm_job_workers: "1",
  asm_global_proc_limit: "6",
  asm_domain_fanout: "3",
  asm_gate_default: "3",
  asm_rate_mode: "balanced",
  asm_scan_mode: "bug_bounty",
  asm_watchdog_max_load: "4.0",
  asm_watchdog_min_mem_mb: "1536",
  asm_watchdog_max_procs: "10",
};

// Fill runtime defaults from env if available (injected at page load)
if (typeof ASM !== 'undefined' && ASM.runtimeConfig) {
  Object.assign(_RUNTIME_DEFAULTS, ASM.runtimeConfig);
}

const PLAYWRIGHT_SETTING_KEYS = [
  "playwright_safe_mode",
  "playwright_headless",
  "playwright_allow_external",
  "playwright_trace",
  "playwright_max_pages",
  "playwright_max_depth",
  "playwright_timeout",
  "playwright_slow_mo",
  "playwright_user_agent",
  "playwright_auth_state",
  "playwright_auth_state_b",
  "playwright_test_xss",
  "playwright_test_race",
  "playwright_test_access",
];

function _toolId(name) {
  return String(name || "").replace(/[^a-zA-Z0-9_-]/g, "_");
}

function _boolish(v, def = false) {
  if (v === undefined || v === null || v === "") return def;
  if (typeof v === "boolean") return v;
  const t = String(v).trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(t)) return true;
  if (["0", "false", "no", "n", "off"].includes(t)) return false;
  return def;
}

function _intish(v, def) {
  const n = Number(v);
  return Number.isFinite(n) ? n : def;
}

function _syncPlaywrightDefaults(raw) {
  const next = {};
  for (const key of PLAYWRIGHT_SETTING_KEYS) {
    if (raw && Object.prototype.hasOwnProperty.call(raw, key)) {
      next[key] = raw[key];
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(_playwrightDefaults, key)) {
      next[key] = _playwrightDefaults[key];
    }
  }
  _playwrightDefaults = next;
  return _playwrightDefaults;
}

function _currentPlaywrightDefaults() {
  const cfg = { ..._playwrightDefaults };
  let local = {};
  try { local = JSON.parse(localStorage.getItem("asm_settings") || "{}"); } catch(e) {}
  for (const key of PLAYWRIGHT_SETTING_KEYS) {
    if (cfg[key] === undefined || cfg[key] === null || cfg[key] === "") {
      if (local[key] !== undefined) cfg[key] = local[key];
    }
  }
  return cfg;
}

async function loadPlaywrightDefaults() {
  if (!SERVER_MODE) return _currentPlaywrightDefaults();
  try {
    const r = await fetch("/api/settings");
    if (r.ok) {
      const data = await r.json();
      _settingsData = data;
      _syncPlaywrightDefaults(data);
    }
  } catch(e) {}
  return _currentPlaywrightDefaults();
}

function renderSettingsGrid() {
  const grid = document.getElementById("settings-grid");
  if (!grid) return;
  grid.innerHTML = SETTINGS_SCHEMA.map(group => `
<div class="settings-group">
  <div class="sg-title">${group.icon} ${group.group}</div>
  <div class="sg-desc">${group.desc}</div>
  ${group.fields.map(f => {
    const val = _settingsData[f.key] || "";
    return `
  <div class="sg-field">
    <div class="sg-label">
      <span>${f.label}</span>
      <span class="sg-tag ${f.tag}">${f.tag}</span>
      ${f.signup ? `<a class="sg-getkey" href="${escAttr(f.signup)}" target="_blank" rel="noopener noreferrer" title="Obter chave em ${escAttr(new URL(f.signup).hostname)}">ðŸ”— Obter chave</a>` : ""}
    </div>
    <div class="sg-input-wrap">
      <input type="password" class="sg-input${val? " has-value":""}"
             id="sg-${f.key}" value="${esc(val)}"
             placeholder="${esc(f.hint)}"
             oninput="document.getElementById('settings-save-status').textContent=(typeof window.t==='function'?window.t('settings_unsaved_mod'):'Unsaved changes');document.getElementById('settings-save-status').className='save-status'">
      <button class="sg-toggle" onclick="toggleSgVisibility('sg-${f.key}',this)" title="Show/hide">ðŸ‘</button>
    </div>
  </div>`;
  }).join("")}
</div>`).join("");
}

// â”€â”€ Runtime Config (âš¡ Performance page) â”€â”€

function renderRuntimeGrid() {
  const grid = document.getElementById("runtime-grid");
  if (!grid) return;
  grid.innerHTML = RUNTIME_SCHEMA.map(group => `
<div class="settings-group">
  <div class="sg-title">${group.icon} ${group.group}</div>
  <div class="sg-desc">${group.desc}</div>
  ${group.fields.map(f => {
    const val = _settingsData[f.key] || _RUNTIME_DEFAULTS[f.key] || "";
    const tip = f.tooltip ? f.tooltip.replace(/"/g, '&quot;').replace(/'/g, '&#39;') : "";
    return `
  <div class="sg-field">
    <div class="sg-label"${tip ? ` title="${tip}"` : ""}>
      <span>${f.label}</span>
      <span class="sg-tag ${f.tag}">${f.tag}</span>
    </div>
    <div class="sg-input-wrap">
      <input type="text" class="sg-input${val? " has-value":""}"
             id="rt-${f.key}" value="${esc(val)}"
             placeholder="${esc(f.hint)}"${tip ? ` title="${tip}"` : ""}
             oninput="document.getElementById('runtime-save-status').textContent=(typeof window.t==='function'?window.t('settings_unsaved_mod'):'Unsaved changes');document.getElementById('runtime-save-status').className='save-status'">
    </div>
  </div>`;
  }).join("")}
</div>`).join("");
}

async function loadRuntimeConfig() {
  if (!SERVER_MODE) { renderRuntimeGrid(); return; }
  try {
    const r = await fetch("/api/settings");
    if (r.ok) {
      _settingsData = await r.json();
    }
  } catch(e) {}
  renderRuntimeGrid();
  const _t = (k) => (typeof window.t === 'function' ? window.t(k) : k);
  document.getElementById("runtime-save-status").textContent = _t('config_loaded');
  document.getElementById("runtime-save-status").className = "save-status ok";
}

async function saveRuntimeConfig() {
  const data = {};
  RUNTIME_SCHEMA.forEach(g => g.fields.forEach(f => {
    const el = document.getElementById("rt-" + f.key);
    if (el && el.value.trim()) data[f.key] = el.value.trim();
  }));
  const st = document.getElementById("runtime-save-status");
  const _t = (k) => (typeof window.t === 'function' ? window.t(k) : k);
  try {
    const r = await fetch("/api/settings", {
      method: "POST", body: JSON.stringify(data),
      headers: _authHeaders(),
    });
    if (r.ok) {
      st.textContent = _t('config_saved_ok');
      st.className = "save-status ok";
    } else {
      const d = await r.json();
      throw new Error(d.error || _t('config_save_err'));
    }
  } catch(e) {
    st.textContent = "Error: " + e.message;
    st.className = "save-status";
  }
}

function toggleSgVisibility(id, btn) {
  const el = document.getElementById(id);
  el.type = el.type === "password" ? "text" : "password";
  btn.style.opacity = el.type === "text" ? "1" : "0.4";
}

async function loadSettings() {
  if (!SERVER_MODE) { renderSettingsGrid(); return; }
  try {
    const r = await fetch("/api/settings");
    if (r.ok) {
      _settingsData = await r.json();
      _syncPlaywrightDefaults(_settingsData);
    }
  } catch(e) {}
  renderSettingsGrid();
  const _t = (k) => (typeof window.t === 'function' ? window.t(k) : k);
  document.getElementById("settings-save-status").textContent = _t('settings_loaded');
  document.getElementById("settings-save-status").className = "save-status ok";
  loadWebhooks();
}

async function saveSettings() {
  const data = {};
  SETTINGS_SCHEMA.forEach(g => g.fields.forEach(f => {
    const el = document.getElementById("sg-"+f.key);
    if (el) data[f.key] = el.value.trim();
  }));
  _settingsData = data;
  const st = document.getElementById("settings-save-status");
  const _t = (k) => (typeof window.t === 'function' ? window.t(k) : k);
  if (!SERVER_MODE) { st.textContent = _t('settings_demo_mode'); st.className="save-status err"; return; }
  try {
    const r = await fetch("/api/settings", {method:"POST", body:JSON.stringify(data), headers: _authHeaders()});
    if (r.ok) { st.textContent = _t('settings_saved_ok'); st.className="save-status ok"; }
    else { st.textContent = _t('settings_save_err'); st.className="save-status err"; }
  } catch(e) { st.textContent = _t('settings_conn_err'); st.className="save-status err"; }
}

// â”€â”€ Notifications / Webhooks (Telegram, Discord, Slack, WhatsApp, Signal, Email, CLI) â”€â”€

const WEBHOOK_TYPES = {
  telegram: { label: "Telegram", fields: [
      {key:"bot_token", label:"Bot Token", placeholder:"123456:ABC-DEF..."},
      {key:"chat_id",   label:"Chat ID",   placeholder:"-100123456789"},
    ]},
  discord: { label: "Discord", fields: [
      {key:"url", label:"Webhook URL", placeholder:"https://discord.com/api/webhooks/..."},
    ]},
  slack: { label: "Slack", fields: [
      {key:"url", label:"Webhook URL", placeholder:"https://hooks.slack.com/services/..."},
    ]},
  whatsapp: { label: "WhatsApp (Twilio)", fields: [
      {key:"account_sid", label:"Account SID"},
      {key:"auth_token",  label:"Auth Token"},
      {key:"from",        label:"From", placeholder:"whatsapp:+14155238886"},
      {key:"to",          label:"To",   placeholder:"whatsapp:+5511999999999"},
    ]},
  signal: { label: "Signal (signal-cli-rest-api)", fields: [
      {key:"url",        label:"API Base URL", placeholder:"http://localhost:8080"},
      {key:"number",     label:"NÃºmero remetente", placeholder:"+5511999999999"},
      {key:"recipients", label:"DestinatÃ¡rios (separados por vÃ­rgula)"},
    ]},
  email: { label: "Email (usa SMTP de ConfiguraÃ§Ãµes)", fields: [
      {key:"to", label:"DestinatÃ¡rio", placeholder:"security@empresa.com"},
    ]},
  cli: { label: "CLI (feed local data/cli_notifications.jsonl)", fields: [] },
  generic: { label: "Webhook genÃ©rico (JSON POST)", fields: [
      {key:"url", label:"URL"},
    ]},
};

const WEBHOOK_EVENTS = [
  {key:"scan_complete",    label:"Scan finalizado"},
  {key:"critical_finding", label:"Finding crÃ­tico"},
];

let _webhooksData = [];

async function loadWebhooks() {
  if (!SERVER_MODE) { renderWebhooksPanel(); return; }
  try {
    const r = await fetch("/api/webhooks", {headers:_authHeaders()});
    if (r.ok) _webhooksData = await r.json();
  } catch(e) {}
  renderWebhooksPanel();
}

function renderWebhookFormFields() {
  const type = document.getElementById("wh-new-type")?.value || "generic";
  const def = WEBHOOK_TYPES[type] || WEBHOOK_TYPES.generic;
  const fields = document.getElementById("wh-new-fields");
  if (fields) {
    fields.innerHTML = def.fields.map(f => `
    <div class="sg-field">
      <div class="sg-label"><span>${f.label}</span></div>
      <input type="text" class="sg-input" id="wh-new-${f.key}" placeholder="${esc(f.placeholder||"")}">
    </div>`).join("") || `<div class="sg-desc">Nenhuma configuraÃ§Ã£o adicional necessÃ¡ria.</div>`;
  }
  const events = document.getElementById("wh-new-events");
  if (events) {
    events.innerHTML = WEBHOOK_EVENTS.map(e => `
    <label style="display:inline-flex;align-items:center;gap:6px;margin-right:16px;">
      <input type="checkbox" class="wh-new-event" value="${e.key}" checked> ${e.label}
    </label>`).join("");
  }
}

function renderWebhooksPanel() {
  const typeSel = document.getElementById("wh-new-type");
  if (typeSel && !typeSel.options.length) {
    typeSel.innerHTML = Object.entries(WEBHOOK_TYPES).map(([k,v]) => `<option value="${k}">${esc(v.label)}</option>`).join("");
    renderWebhookFormFields();
  }

  const list = document.getElementById("webhooks-list");
  if (!list) return;
  if (!_webhooksData.length) {
    list.innerHTML = `<div class="sg-desc">Nenhum webhook configurado ainda.</div>`;
    return;
  }
  list.innerHTML = _webhooksData.map((hook, idx) => {
    const def = WEBHOOK_TYPES[hook.type] || WEBHOOK_TYPES.generic;
    const target = hook.chat_id || hook.to || hook.url || hook.number || "(sem destino)";
    const events = (hook.events || []).map(e => (WEBHOOK_EVENTS.find(x=>x.key===e)||{label:e}).label).join(", ") || "todos os eventos";
    return `
  <div class="sg-field" style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
    <div>
      <strong>${esc(def.label)}</strong> â€” <span style="color:var(--text3)">${esc(String(target))}</span>
      <div class="sg-desc" style="margin:2px 0 0;">Eventos: ${esc(events)}</div>
    </div>
    <div style="display:flex;gap:8px;">
      <button class="btn btn-secondary" onclick="testWebhook(${idx})">ðŸ”” Testar</button>
      <button class="btn btn-secondary" onclick="deleteWebhook(${idx})">ðŸ—‘ Remover</button>
    </div>
  </div>`;
  }).join("");
}

async function _saveWebhooks() {
  const st = document.getElementById("webhooks-save-status");
  try {
    const r = await fetch("/api/webhooks", {method:"POST", body:JSON.stringify(_webhooksData), headers:_authHeaders()});
    if (r.ok) { if (st) { st.textContent = "âœ“ Salvo"; st.className = "save-status ok"; } }
    else { if (st) { st.textContent = "Erro ao salvar"; st.className = "save-status err"; } }
  } catch(e) { if (st) { st.textContent = "Erro de conexÃ£o"; st.className = "save-status err"; } }
}

function addWebhook() {
  const type = document.getElementById("wh-new-type")?.value || "generic";
  const def = WEBHOOK_TYPES[type] || WEBHOOK_TYPES.generic;
  const hook = {id: "wh_" + Math.random().toString(36).slice(2,10), type};
  def.fields.forEach(f => {
    const el = document.getElementById("wh-new-" + f.key);
    let val = el ? el.value.trim() : "";
    if (f.key === "recipients" && val) val = val.split(",").map(s=>s.trim()).filter(Boolean);
    if (val) hook[f.key] = val;
  });
  hook.events = Array.from(document.querySelectorAll(".wh-new-event:checked")).map(c => c.value);
  if (!hook.events.length) { alert("Selecione ao menos um evento."); return; }
  _webhooksData.push(hook);
  renderWebhooksPanel();
  _saveWebhooks();
  def.fields.forEach(f => { const el = document.getElementById("wh-new-" + f.key); if (el) el.value = ""; });
}

function deleteWebhook(idx) {
  _webhooksData.splice(idx, 1);
  renderWebhooksPanel();
  _saveWebhooks();
}

async function testWebhook(idx) {
  const hook = _webhooksData[idx];
  try {
    const r = await fetch("/api/webhooks/test", {method:"POST", body:JSON.stringify({hook}), headers:_authHeaders()});
    if (r.ok) alert("Teste enviado â€” verifique o canal configurado.");
    else alert("Falha ao enviar teste.");
  } catch(e) { alert("Erro de conexÃ£o: " + e.message); }
}

function _toolMatchesFilter(tool, categoryFilter, availFilter) {
  const category = String(tool.category || "");
  const available = !!tool.available;
  if (categoryFilter && category !== categoryFilter) return false;
  if (availFilter === "available" || availFilter === "enabled") return available;
  if (availFilter === "missing" || availFilter === "disabled") return !available;
  return true;
}

function _renderPlaywrightDefaultsCard() {
  const cfg = _currentPlaywrightDefaults();
  const rows = [
    {label:"Safe mode", key:"playwright_safe_mode", type:"checkbox", def:true},
    {label:"Headless", key:"playwright_headless", type:"checkbox", def:true},
    {label:"Allow external", key:"playwright_allow_external", type:"checkbox", def:false},
    {label:"Trace", key:"playwright_trace", type:"checkbox", def:false},
    {label:"Max pages", key:"playwright_max_pages", type:"number", def:50},
    {label:"Max depth", key:"playwright_max_depth", type:"number", def:3},
    {label:"Timeout (s)", key:"playwright_timeout", type:"number", def:20},
    {label:"Slow mo (ms)", key:"playwright_slow_mo", type:"number", def:0},
    {label:"User agent", key:"playwright_user_agent", type:"text", def:""},
    {label:"Auth state", key:"playwright_auth_state", type:"text", def:""},
    {label:"Auth state B", key:"playwright_auth_state_b", type:"text", def:""},
  ];
  const active = [
    ["Test XSS", "playwright_test_xss"],
    ["Test Race", "playwright_test_race"],
    ["Test Access", "playwright_test_access"],
  ];
  return `
    <div class="section-shell" style="margin-bottom:18px">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">Playwright Defaults</div>
          <div class="section-title">Browser phase defaults</div>
          <div class="section-sub">These settings are used by the bug bounty browser phase and prefill the manual Playwright run dialog.</div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <span id="tools-pw-save-status" class="save-status"></span>
          <button class="btn btn-secondary btn-sm" onclick="loadToolsStatus()">â†º Reload</button>
          <button class="btn btn-primary btn-sm" onclick="savePlaywrightDefaults()">Save Defaults</button>
        </div>
      </div>
      <div class="stats-row" style="margin-bottom:12px">
        ${rows.map(({label, key, type, def}) => {
          const value = cfg[key];
          const checked = type === "checkbox" ? (_boolish(value, def) ? "checked" : "") : "";
          const display = type === "checkbox"
            ? `<label class="toggle" style="margin-top:6px"><input type="checkbox" id="tools-${key}" ${checked}><span class="slider"></span></label>`
            : `<input class="fi" id="tools-${key}" type="${type}" value="${esc(value ?? def ?? "")}" style="width:100%;margin-top:6px">`;
          return `
            <div class="stat-card" style="min-width:180px;flex:1">
              <div class="stat-label">${esc(label)}</div>
              ${display}
            </div>`;
        }).join("")}
      </div>
      <div class="stats-row" style="margin-bottom:0;gap:10px">
        ${active.map(([label, key]) => {
          const checked = _boolish(cfg[key], false) ? "checked" : "";
          return `
            <div class="stat-card" style="min-width:180px;flex:1">
              <div class="stat-label">${esc(label)}</div>
              <label class="toggle" style="margin-top:6px"><input type="checkbox" id="tools-${key}" ${checked}><span class="slider"></span></label>
            </div>`;
        }).join("")}
      </div>
    </div>`;
}

function _renderToolCard(tool, defaultTarget) {
  const id = _toolId(tool.name);
  const available = !!tool.available;
  const gate = tool.gate || {};
  const gateLabel = gate ? `${Number(gate.active || 0)}/${Number(gate.limit || 1)}` : "";
  const statusLabel = available ? "Installed" : "Missing";
  const requires = tool.requires_key ? `<span class="chip">key: ${esc(tool.requires_key)}</span>` : "";
  const gateChip = gate ? `<span class="chip">gate ${esc(gateLabel)}</span>` : "";
  return `
    <div class="section-shell" style="padding:14px 14px 12px">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px">
        <div style="min-width:0">
          <div class="section-title" style="font-size:1rem;line-height:1.1">${esc(tool.name)}</div>
          <div class="section-sub" style="margin-top:4px">${esc(tool.description || "")}</div>
        </div>
        <span class="chip" style="background:${available ? "rgba(0,255,136,.12)" : "rgba(255,51,85,.12)"};color:${available ? "var(--green)" : "var(--red)"};border-color:${available ? "rgba(0,255,136,.2)" : "rgba(255,51,85,.2)"}">${statusLabel}</span>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin:10px 0 12px">
        <span class="chip">${esc(String(tool.category || ""))}</span>
        <span class="chip">${esc(String(tool.type || ""))}</span>
        <span class="chip">${esc(String(tool.version || ""))}</span>
        ${requires}
        ${gateChip}
      </div>
      <div style="display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center">
        <input class="fi" id="ti-${id}" value="${esc(defaultTarget || "")}" placeholder="Target domain or IP">
        <button class="btn btn-primary btn-sm" id="tb-${id}" ${available ? "" : "disabled"} onclick="runTool('${esc(tool.name)}')">Run</button>
      </div>
      <div style="margin-top:10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <code id="ic-${id}" style="font-size:.68rem;white-space:normal;word-break:break-word;flex:1;background:var(--bg1);padding:8px 10px;border:1px solid var(--border);border-radius:8px">${esc(tool.install_cmd || "â€”")}</code>
        <button class="btn btn-secondary btn-sm" onclick="copyInstall('${esc(tool.name)}')">Copy</button>
      </div>
      <div id="tr-${id}" class="tc-result" style="margin-top:10px"></div>
    </div>`;
}

function renderToolsCatalog() {
  const grid = document.getElementById("tools-grid");
  const stats = document.getElementById("tools-stats-strip");
  const pwCfg = document.getElementById("tools-playwright-config");
  if (!grid || !stats || !pwCfg) return;

  const categoryFilter = document.getElementById("tools-cat-filter")?.value || "";
  const availFilter = document.getElementById("tools-avail-filter")?.value || "";
  const defaultTarget = (allCompanies().find(c => c.id === state.currentId)?.domains || [])[0]
    || (allCompanies()[0]?.domains || [])[0]
    || "";
  const filtered = _toolsData.filter(tool => _toolMatchesFilter(tool, categoryFilter, availFilter));

  const total = _toolsData.length;
  const available = _toolsData.filter(t => t.available).length;
  const missing = total - available;
  const apiCount = _toolsData.filter(t => String(t.type || "") === "api").length;
  const cliCount = total - apiCount;

  stats.innerHTML = [
    ["Total", total, "var(--cyan)"],
    ["Installed", available, "var(--green)"],
    ["Missing", missing, "var(--red)"],
    ["API tools", apiCount, "var(--blue)"],
    ["CLI tools", cliCount, "var(--yellow)"],
  ].map(([label, value, color]) => `
    <div class="stat-card" style="min-width:130px;flex:1">
      <div class="stat-value" style="color:${color}">${value}</div>
      <div class="stat-label">${label}</div>
    </div>`).join("");

  pwCfg.innerHTML = _renderPlaywrightDefaultsCard();

  if (!filtered.length) {
    grid.innerHTML = `<div class="empty" style="grid-column:1/-1"><b>No tools match the current filters</b> Try another category or availability filter.</div>`;
    return;
  }
  grid.innerHTML = filtered.map(tool => _renderToolCard(tool, defaultTarget)).join("");
}

async function loadToolsStatus() {
  const grid = document.getElementById("tools-grid");
  const stats = document.getElementById("tools-stats-strip");
  const pwCfg = document.getElementById("tools-playwright-config");
  if (grid) grid.innerHTML = `<div class="skel skel-card"></div><div class="skel skel-card"></div>`;
  if (stats) stats.innerHTML = `<div class="skel skel-card"></div>`;
  if (pwCfg) pwCfg.innerHTML = `<div class="skel skel-card"></div>`;

  if (!SERVER_MODE) {
    _toolsData = [];
    renderToolsCatalog();
    return;
  }

  try {
    const [toolsResp, settingsResp] = await Promise.all([
      fetch("/api/tools/status", {headers:_authHeaders()}),
      fetch("/api/settings", {headers:_authHeaders()}),
    ]);
    if (settingsResp.ok) {
      const settings = await settingsResp.json();
      _settingsData = settings;
      _syncPlaywrightDefaults(settings);
    }
    if (!toolsResp.ok) throw await _apiErr(toolsResp);
    _toolsData = await toolsResp.json();
    renderToolsCatalog();
  } catch(e) {
    if (grid) grid.innerHTML = `<div class="empty" style="grid-column:1/-1"><b>Tools unavailable</b> ${esc(e.message)}</div>`;
    if (stats) stats.innerHTML = "";
    if (pwCfg) pwCfg.innerHTML = "";
  }
}

function filterTools() {
  renderToolsCatalog();
}

async function savePlaywrightDefaults() {
  if (!SERVER_MODE) return;
  const cfg = {
    playwright_safe_mode: document.getElementById("tools-playwright_safe_mode")?.checked ?? true,
    playwright_headless: document.getElementById("tools-playwright_headless")?.checked ?? true,
    playwright_allow_external: document.getElementById("tools-playwright_allow_external")?.checked ?? false,
    playwright_trace: document.getElementById("tools-playwright_trace")?.checked ?? false,
    playwright_max_pages: Number(document.getElementById("tools-playwright_max_pages")?.value || 50),
    playwright_max_depth: Number(document.getElementById("tools-playwright_max_depth")?.value || 3),
    playwright_timeout: Number(document.getElementById("tools-playwright_timeout")?.value || 20),
    playwright_slow_mo: Number(document.getElementById("tools-playwright_slow_mo")?.value || 0),
    playwright_user_agent: document.getElementById("tools-playwright_user_agent")?.value.trim() || "",
    playwright_auth_state: document.getElementById("tools-playwright_auth_state")?.value.trim() || "",
    playwright_auth_state_b: document.getElementById("tools-playwright_auth_state_b")?.value.trim() || "",
    playwright_test_xss: document.getElementById("tools-playwright_test_xss")?.checked ?? false,
    playwright_test_race: document.getElementById("tools-playwright_test_race")?.checked ?? false,
    playwright_test_access: document.getElementById("tools-playwright_test_access")?.checked ?? false,
  };
  try {
    const r = await fetch("/api/settings", {
      method:"POST",
      headers: {"Content-Type":"application/json", ..._authHeaders()},
      body: JSON.stringify(cfg),
    });
    if (!r.ok) throw await _apiErr(r);
    _settingsData = { ..._settingsData, ...cfg };
    _syncPlaywrightDefaults(cfg);
    try {
      const local = JSON.parse(localStorage.getItem("asm_settings") || "{}");
      localStorage.setItem("asm_settings", JSON.stringify({ ...local, ...cfg }));
    } catch(e) {}
    const status = document.getElementById("tools-pw-save-status");
    if (status) {
      status.textContent = "âœ“ Playwright defaults saved";
      status.className = "save-status ok";
    }
  } catch(e) {
    const status = document.getElementById("tools-pw-save-status");
    if (status) {
      status.textContent = "Error saving Playwright defaults";
      status.className = "save-status err";
    }
    alert("Error saving Playwright defaults: " + e.message);
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  ADMIN CRUD
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function loadAdmins() {
  if (!SERVER_MODE) {
    document.getElementById("admins-tbody").innerHTML = `<tr><td colspan="6" style="color:var(--text3);text-align:center;padding:20px">Server mode required</td></tr>`;
    return;
  }
  try {
    const r = await fetch("/api/admins");
    if (!r.ok) return;
    const admins = await r.json();
    renderAdminsTable(admins);
  } catch(e) {}
}

function renderAdminsTable(admins) {
  const tbody = document.getElementById("admins-tbody");
  tbody.innerHTML = admins.map(a => {
    const scopeLabel = (a.scoped_companies && a.scoped_companies.length) ? `${a.scoped_companies.length} company(s)` : "All";
    return `
<tr>
  <td><b>${a.username}</b></td>
  <td style="color:var(--text2)">${a.email || "â€”"}</td>
  <td><span class="role-badge ${a.role}">${a.role.replace("_"," ")}</span></td>
  <td style="color:var(--text3);font-size:0.65rem">${scopeLabel}</td>
  <td style="color:var(--text3);font-size:0.65rem">${(a.created_at||"").slice(0,10)}</td>
  <td style="color:var(--text3);font-size:0.65rem">${(a.last_login||"â€”").slice(0,16).replace("T"," ")}</td>
  <td>
    <div class="admin-actions">
      ${a.role !== 'super_admin' ? `<button class="btn btn-secondary btn-icon" onclick="openAdminModal('${a.id}','${a.username}','${a.email||""}','${a.role}','${JSON.stringify(a.scoped_companies||[]).replace(/"/g,'&quot;')}')">Edit</button>` : ''}
      ${a.id !== authUser?.admin_id ? `<button class="btn btn-icon" style="background:var(--red-dim);color:#fb7185;border:1px solid rgba(244,63,94,0.2)" onclick="deleteAdmin('${a.id}','${a.username}')">Delete</button>` : `<span style="font-size:0.65rem;color:var(--text3);padding:4px 8px">you</span>`}
    </div>
  </td>
</tr>`;}).join("") || `<tr><td colspan="7" style="color:var(--text3);text-align:center;padding:20px">No admins found</td></tr>`;
}

function onAdminRoleChange() {
  const role = document.getElementById("admin-modal-role").value;
  const scopeField = document.getElementById("admin-scope-field");
  scopeField.style.display = (role === "super_admin") ? "none" : "";
}

function openAdminModal(id, username, email, role, scopedJson) {
  const isNew = !id;
  document.getElementById("admin-modal-title").textContent = isNew ? "Add Admin" : "Edit Admin";
  document.getElementById("admin-modal-id").value    = id || "";
  document.getElementById("admin-modal-user").value  = username || "";
  document.getElementById("admin-modal-user").disabled = !isNew;
  document.getElementById("admin-modal-email").value = email || "";
  document.getElementById("admin-modal-role").value  = role || "analyst";
  document.getElementById("admin-modal-pw-field").style.display   = isNew ? "" : "none";
  document.getElementById("admin-modal-pw-change-toggle").style.display = isNew ? "none" : "";
  document.getElementById("admin-modal-pw").value = "";
  document.getElementById("admin-change-pw-cb").checked = false;
  document.getElementById("admin-new-pw-wrap").style.display = "none";

  // Populate company scope checkboxes
  let scoped = [];
  try { if (scopedJson) scoped = JSON.parse(scopedJson); } catch(e) {}
  if (!Array.isArray(scoped)) scoped = [];
  const grid = document.getElementById("admin-scope-grid");
  grid.innerHTML = (allCompanies() || []).map(c => {
    const checked = scoped.includes(c.id) ? "checked" : "";
    return `<label style="display:flex;align-items:center;gap:6px;font-size:0.72rem;color:var(--text2);cursor:pointer;padding:2px 4px;border-radius:4px">
      <input type="checkbox" value="${esc(c.id)}" ${checked} class="admin-scope-cb">
      ${esc(c.name)}
    </label>`;
  }).join("") || '<span style="color:var(--text3);font-size:0.72rem">No companies yet</span>';

  onAdminRoleChange();
  document.getElementById("modal-admin").style.display = "flex";
}

function closeAdminModal() { document.getElementById("modal-admin").style.display = "none"; }

function toggleChangePw(checked) {
  document.getElementById("admin-new-pw-wrap").style.display = checked ? "" : "none";
}

async function saveAdmin() {
  const id    = document.getElementById("admin-modal-id").value;
  const isNew = !id;
  const role  = document.getElementById("admin-modal-role").value;
  const body  = {
    username: document.getElementById("admin-modal-user").value.trim(),
    email:    document.getElementById("admin-modal-email").value.trim(),
    role:     role,
  };

  // Collect scoped companies (only for analyst role)
  if (role !== "super_admin") {
    const cbs = document.querySelectorAll(".admin-scope-cb:checked");
    body.scoped_companies = Array.from(cbs).map(cb => cb.value);
  }

  if (isNew) {
    body.password = document.getElementById("admin-modal-pw").value;
    if (!body.username || !body.password) { alert("Username and password are required"); return; }
  } else {
    if (document.getElementById("admin-change-pw-cb").checked) {
      body.password = document.getElementById("admin-modal-pw2").value;
      if (!body.password) { alert("Enter new password"); return; }
    }
  }

  try {
    const url    = isNew ? "/api/admins" : `/api/admins/${id}`;
    const method = isNew ? "POST"        : "PUT";
    const r = await fetch(url, {method, body:JSON.stringify(body), headers: _authHeaders()});
    const d = await r.json();
    if (!r.ok) { alert(d.error || "Error saving admin"); return; }
    closeAdminModal();
    loadAdmins();
  } catch(e) { alert("Connection error"); }
}

async function deleteAdmin(id, username) {
  if (!confirm(`Delete admin "${username}"? This cannot be undone.`)) return;
  try {
    const r = await fetch(`/api/admins/${id}`, {method:"DELETE"});
    const d = await r.json();
    if (!r.ok) { alert(d.error || "Error"); return; }
    loadAdmins();
  } catch(e) { alert("Connection error"); }
}


const _phudModTimes = {};   // Track module start/end for Gantt
const _phudParticles = {};  // Track animation frames

const PIPELINE_PHASES_DEF = [
  {id:"discovery",    label:"DISCOVERY",       icon:"ðŸ›°",  color:"#00e5ff", mods:["subfinder","assetfinder","certs","alienvault_otx","urlscan_io","rapiddns","hackertarget","github_subdomains","wayback","urlfinder","theharvester","hunterio"]},
  {id:"validation",   label:"VALIDAÃ‡ÃƒO",       icon:"ðŸ”",  color:"#818cf8", mods:["dns","dns_brute","leaks","email"]},
  {id:"intel",        label:"INTEL",           icon:"âš¡",  color:"#fbbf24", mods:["shodan","postman_collections","cloud","container_registry","bulk_dataset","breach","dep_confusion","asn","asnmap"]},
  {id:"fingerprint",  label:"FINGERPRINT",     icon:"ðŸ”¬",  color:"#00e5ff", mods:["headers","waf","wappalyzer","whatweb","vendor_fp","service_version","favicon_hunt","screenshot","gowitness"]},
  {id:"api_mapping",  label:"JS/API",          icon:"â¬¡",  color:"#4ade80", mods:["js","js_endpoints","js_secrets","api_discovery_extra","graphql"]},
  {id:"browser",      label:"PLAYWRIGHT",      icon:"â–£",  color:"#c084fc", mods:["browser_crawl","browser_recon"]},
  {id:"bug_checks",   label:"CHECKS",          icon:"âš ",  color:"#f43f5e", mods:["takeover","subjack","cors_scan","open_redirect","host_header_injection","infra_exposure","cloud_enum","default_creds","dnssec","waf_bypass","tableau","github_repos","supply_chain"]},
  {id:"services",     label:"SERVIÃ‡OS",        icon:"ðŸ”Œ",  color:"#fb923c", mods:["portscan","cloudlist","services","cms_scan","database_enum_extra"]},
  {id:"evidence",     label:"EVIDÃŠNCIA",       icon:"âœ“",   color:"#4ade80", mods:["cve","api_panels","screenshot_diff"]},
];

const _MOD_TO_PHASE = {};
PIPELINE_PHASES_DEF.forEach(ph => ph.mods.forEach(m => (_MOD_TO_PHASE[m] = ph.id)));

function _phudPhaseStatus(phId, modMap) {
  const ph = PIPELINE_PHASES_DEF.find(p => p.id === phId);
  if (!ph) return "idle";
  const statuses = ph.mods.map(m => modMap[m] || "not_run");
  if (statuses.some(s => s === "running"))  return "active";
  if (statuses.every(s => s === "skipped")) return "skipped";
  if (statuses.some(s => s === "done"))     return "done";
  if (statuses.some(s => s === "error"))    return "error";
  return "idle";
}

function _phudPhaseToolLabel(ph, modMap) {
  const running = ph.mods.find(m => modMap[m] === "running");
  if (running) return running;
  const done = ph.mods.find(m => modMap[m] === "done");
  if (done) return done;
  const err = ph.mods.find(m => modMap[m] === "error");
  if (err) return err;
  const skip = ph.mods.find(m => modMap[m] === "skipped");
  if (skip) return skip;
  const seen = ph.mods.find(m => modMap[m] && modMap[m] !== "not_run");
  return seen || ph.id;
}

function _pipelineCardLiveInfo(cid) {
  const ps = pipelineState[cid];
  if (!ps || (ps.status !== "queued" && ps.status !== "running")) return null;

  const modMap = {};
  (ps.phases || []).forEach(ph => (ph.modules || []).forEach(m => {
    if (m.status && m.status !== "not_run") modMap[m.module] = m.status;
  }));
  const rs = reconState[cid] || {};
  Object.keys(rs).forEach(m => {
    if (rs[m] && rs[m].status) modMap[m] = rs[m].status;
  });

  const activeTool =
    Object.keys(modMap).find(m => modMap[m] === "running") ||
    (ps.status === "running" ? Object.keys(modMap).find(m => modMap[m] === "done") : "") ||
    Object.keys(modMap).find(m => modMap[m] === "error") ||
    Object.keys(modMap).find(m => modMap[m] === "skipped") ||
    "";

  const phaseId = activeTool ? _MOD_TO_PHASE[activeTool] : "";
  const phase = phaseId ? PIPELINE_PHASES_DEF.find(p => p.id === phaseId) : null;
  const phaseLabel = phase ? phase.label : (ps.phase_label || "");
  const label = ps.status === "queued"
    ? (activeTool ? `Queued Â· ${activeTool}${phaseLabel ? ` Â· ${phaseLabel}` : ""}` : "Queued Â· waiting for worker")
    : (activeTool ? `Running Â· ${activeTool}${phaseLabel ? ` Â· ${phaseLabel}` : ""}` : "Running Â· starting");

  return {
    status: ps.status,
    tool: activeTool,
    phase: phaseLabel,
    label,
    jobId: ps.job_id || "",
  };
}

function _phudStartParticles(cid) {
  const canvas = document.getElementById(`phud-canvas-${cid}`);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  function resize() { canvas.width = canvas.offsetWidth; canvas.height = canvas.offsetHeight; }
  resize();
  new ResizeObserver(resize).observe(canvas.parentElement);
  const pts = Array.from({length:45}, () => ({
    x:Math.random(), y:Math.random(),
    vx:(Math.random()-.5)*.0005, vy:(Math.random()-.5)*.0005,
    r:Math.random()*.8+.2, a:Math.random()*.3+.04,
  }));
  function draw() {
    ctx.clearRect(0,0,canvas.width,canvas.height);
    pts.forEach(p => {
      const x = p.x*canvas.width, y = p.y*canvas.height;
      ctx.beginPath(); ctx.arc(x,y,p.r,0,Math.PI*2);
      ctx.fillStyle = `rgba(0,180,255,${p.a})`; ctx.fill();
      p.x += p.vx; p.y += p.vy;
      if(p.x<0)p.x=1; if(p.x>1)p.x=0;
      if(p.y<0)p.y=1; if(p.y>1)p.y=0;
    });
    _phudParticles[cid] = requestAnimationFrame(draw);
  }
  if(_phudParticles[cid]) cancelAnimationFrame(_phudParticles[cid]);
  draw();
}

function _phudStopParticles(cid) {
  if(_phudParticles[cid]) { cancelAnimationFrame(_phudParticles[cid]); delete _phudParticles[cid]; }
}

function renderPipelineStatus(cid) {
  const el = document.getElementById(`pipeline-status-${cid}`);
  if (!el) return;
  const ps = pipelineState[cid];
  if (!ps) { el.innerHTML = ""; _phudStopParticles(cid); return; }

  // Build module map from pipeline state phases
  const modMap = {};
  (ps.phases||[]).forEach(ph => ph.modules.forEach(m => { modMap[m.module] = m.status; }));
  // Also fill from reconState (live updates)
  const rs = reconState[cid] || {};
  Object.keys(rs).forEach(m => { if(rs[m].status) modMap[m] = rs[m].status; });

  // Track module start/end times for Gantt
  if (!_phudModTimes[cid]) _phudModTimes[cid] = {};
  const mt = _phudModTimes[cid];
  const now = Date.now();
  if (!mt._scanStart) mt._scanStart = now;
  Object.keys(modMap).forEach(m => {
    const st = modMap[m];
    if (st === "running" && !mt[m]) mt[m] = {start: now, end: null};
    if ((st === "done" || st === "error" || st === "skipped") && mt[m] && !mt[m].end) mt[m].end = now;
    if (!mt[m] && (st === "done" || st === "error")) mt[m] = {start: mt._scanStart, end: now};
  });

  const isRunning = ps.status === "running";
  const isQueued  = ps.status === "queued";
  const isDone    = ps.status === "done";
  const modeIcon  = {stealth:"ðŸ§Š",balanced:"âš–ï¸",fast:"ðŸš€"}[ps.mode||"stealth"] || "ðŸ§Š";
  const cfCoverage = ps.cloudflare_coverage || 0;

  // â”€â”€ Phase node timeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const totalPhases  = PIPELINE_PHASES_DEF.length;
  const activeIdx    = PIPELINE_PHASES_DEF.findIndex(p => _phudPhaseStatus(p.id, modMap) === "active");
  const donePhases   = PIPELINE_PHASES_DEF.filter(p => _phudPhaseStatus(p.id, modMap) === "done").length;
  const progress     = activeIdx >= 0 ? (activeIdx + .5) / totalPhases : donePhases / totalPhases;
  const glowRight    = Math.round((1 - progress) * 100);

  const nodesHtml = PIPELINE_PHASES_DEF.map(ph => {
    const st = _phudPhaseStatus(ph.id, modMap);
    const dot = st === "done" ? "âœ“" : ph.icon;
    const toolLabel = _phudPhaseToolLabel(ph, modMap);
    return `<div class="phud-node ${st}" title="${ph.label} Â· ${toolLabel}">
      <div class="phud-node-dot">${dot}</div>
      <div class="phud-node-lbl">${esc(toolLabel)}</div>
    </div>`;
  }).join("");

  // â”€â”€ Gantt: show only modules with timing data â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const scanDuration = now - (mt._scanStart || now);
  const totalMs = Math.max(scanDuration, 5000);

  let ganttHtml = "";
  const doneMods = Object.keys(modMap).filter(m => modMap[m] !== "not_run" && modMap[m] !== "idle");
  const runningMod = doneMods.find(m => modMap[m] === "running");
  const doneCount = doneMods.filter(m => modMap[m] === "done").length;
  const errCount  = doneMods.filter(m => modMap[m] === "error").length;

  // Phase group summary
  PIPELINE_PHASES_DEF.forEach(ph => {
    const phMods = ph.mods.filter(m => modMap[m] && modMap[m] !== "not_run");
    const phDone = phMods.filter(m => modMap[m] === "done").length;
    const phRunning = phMods.find(m => modMap[m] === "running");
    const phSt = phRunning ? "active" : phDone >= ph.mods.length ? "done" : phDone > 0 ? "active" : "idle";
    ganttHtml += `<div class="phud-phase-hdr ${phSt==='active'?'ph-active':phSt==='done'?'ph-done':''}" style="border-left:3px solid ${ph.color};padding:4px 10px;margin-top:4px;border-radius:3px;background:${phSt==='active'?'rgba(255,255,255,0.04)':'transparent'}">
      <span style="font-weight:700;font-size:.68rem;color:var(--text)">${ph.icon} ${esc(ph.label)}</span>
      <span style="margin-left:8px;font-size:.58rem;color:var(--text3)">${phDone}/${ph.mods.length}</span>
    </div>`;
  });

  // Running module highlight
  if (runningMod) {
    ganttHtml += `<div style="padding:6px 10px;font-size:.64rem;color:#00e5ff;background:rgba(0,229,255,0.05);border-radius:4px;margin:2px 0">
      â–¶ ${runningMod} <span style="color:var(--text3);font-size:.58rem">rodando...</span>
    </div>`;
  }

  // Last 5 completed modules
  const recentMods = doneMods.filter(m => modMap[m] === "done" && mt[m]).slice(-5);
  if (recentMods.length) {
    ganttHtml += `<div style="font-size:.58rem;color:var(--text3);padding:4px 10px">Ãšltimos concluÃ­dos:</div>`;
    recentMods.forEach(m => {
      const t = mt[m] || {};
      const durMs = t.end && t.start ? t.end - t.start : 0;
      const durStr = durMs > 60000 ? `${Math.round(durMs/60000)}m` : durMs > 1000 ? `${Math.round(durMs/1000)}s` : "";
      const barColor = "#22c55e";
      const startOff = t.start ? ((t.start - mt._scanStart) / totalMs * 100).toFixed(1) : "0";
      const endOff = t.end ? ((t.end - mt._scanStart) / totalMs * 100).toFixed(1) : startOff;
      const width = Math.max(parseFloat(endOff) - parseFloat(startOff), 1).toFixed(1);

      ganttHtml += `<div style="display:flex;align-items:center;gap:6px;padding:2px 10px">
        <div style="font-size:.6rem;color:var(--text2);width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:right" title="${m}">${m}</div>
        <div style="flex:1;height:8px;background:rgba(255,255,255,0.03);border-radius:4px;overflow:hidden">
          <div style="left:${startOff}%;width:${width}%;background:${barColor};height:100%;border-radius:4px;opacity:.8;position:relative"></div>
        </div>
        <div style="font-size:.55rem;color:var(--text3);width:28px">${durStr}</div>
      </div>`;
    });
  }

  // â”€â”€ Last log line â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const logLines = ps.log || [];
  const lastLog  = logLines.length ? logLines[logLines.length-1].msg : (isQueued ? "Waiting in queueâ€¦" : isRunning ? "Waiting for startâ€¦" : "");

  // â”€â”€ Cleanup badge â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const cleanupData = (ps.phases||[]).find(p => p.id === "cleanup");
  const cleanupBadge = cleanupData && cleanupData.data?.removed > 0
    ? `<span class="phud-badge done">ðŸ§¹ -${cleanupData.data.removed} junk</span>` : "";
  const cfBadge = cfCoverage >= 80
    ? `<span class="phud-badge done">ðŸ›¡ ${cfCoverage.toFixed(0)}% CF</span>` : "";
  const mullvadIp = ps.mullvad_ip || "";
  const mullvadBadge = mullvadIp
    ? `<span class="phud-badge idle" title="Mullvad VPN â€” IP atual">ðŸŒ ${mullvadIp}</span>` : "";

  // â”€â”€ Mullvad failures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const mullvadFailuresHtml = (ps.mullvad_failures||[]).length ? `<div style="margin-top:6px;padding:6px;background:rgba(239,68,68,0.1);border-radius:4px;border:1px solid rgba(239,68,68,0.3)"><span style="color:var(--red);font-weight:600;font-size:.7rem">âš  Mullvad Rotation Failures (${ps.mullvad_failures.length})</span>${ps.mullvad_failures.slice(-3).map(f=>`<div style="color:var(--text3);font-size:.65rem;margin-top:2px">${esc(f.ts||'')} Â· ${esc(f.phase||'')} Â· ${esc(f.reason||'')}</div>`).join('')}</div>` : '';

  // â”€â”€ Not done summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const notDone = (ps.not_done||[]);
  const notDoneHtml = (isDone && notDone.length) ? `
    <div style="margin-top:10px;padding:8px 12px;background:rgba(251,146,60,0.08);border:1px solid rgba(251,146,60,0.2);border-radius:7px;font-size:.63rem;">
      <span style="color:var(--orange);font-weight:700;">âš  ${notDone.length} module(s) not completed:</span>
      <span style="color:var(--text3);margin-left:6px">${notDone.slice(0,6).map(n=>{
        const reason = (n.reason||"").trim();
        return reason && reason !== "not executed"
          ? `${n.module} (${reason})`
          : n.module;
      }).join(", ")}${notDone.length>6?"â€¦":""}</span>
    </div>` : "";

  el.innerHTML = `
  <div class="phud-wrap" id="phud-wrap-${cid}">
    <div class="phud-inner">

      <div class="phud-header">
        <span class="phud-title">ðŸ›° Pipeline</span>
        <span class="phud-badge ${isRunning?"running":isQueued?"idle":isDone?"done":"idle"}">${isRunning?"â— RUNNING":isQueued?"â–£ QUEUED":isDone?"âœ“ DONE":"IDLE"}</span>
        ${modeIcon ? `<span class="phud-badge idle">${modeIcon} ${ps.mode||""}</span>` : ""}
        ${cfBadge}${cleanupBadge}${mullvadBadge}
        <div class="phud-meta">
          <span>ðŸ–¥ ${ps.host_count||0} hosts</span>
          <span>ðŸ“Š ${donePhases}/${totalPhases} grupos</span>
          ${ps.started_at ? `<span>ðŸ• ${ps.started_at}</span>` : ""}
        </div>
      </div>

      <div class="phud-gantt" style="margin-top:8px;position:relative">
        ${ganttHtml || '<div style="padding:20px;color:var(--text3);text-align:center;font-size:.72rem">Aguardando inÃ­cioâ€¦</div>'}
      </div>

      ${notDoneHtml}
      ${mullvadFailuresHtml}

      <div class="phud-action" id="phud-action-${cid}">${lastLog ? "â–¶ "+lastLog : "â€¦"}</div>
    </div>
  </div>`;

  // Start/stop particle animation
  if (isRunning) {
    _phudStartParticles(cid);
  } else {
    _phudStopParticles(cid);
  }
}

function renderCleanupResults(data) {
  if (!data || !data.removed || data.removed.length === 0) return "";
  const removed = data.removed.slice(0, 10);
  const more = data.removed.length - 10;
  return `
    <div style="margin-top:12px;padding:10px 14px;background:rgba(34,197,94,0.06);border:1px solid rgba(34,197,94,0.15);border-radius:7px">
      <div style="font-size:.7rem;font-weight:600;color:var(--green);margin-bottom:6px">ðŸ§¹ Subdomains removed (${data.removed.length})</div>
      <div style="display:flex;flex-direction:column;gap:3px">
        ${removed.map(r => `<div style="font-size:.67rem;color:var(--text2);display:flex;gap:8px;padding:1px 0">
          <span style="color:var(--text3);min-width:90px;font-family:var(--mono);overflow:hidden;text-overflow:ellipsis">${esc(r.host)}</span>
          <span style="color:var(--orange)">${esc(r.reason)}</span>
        </div>`).join("")}
        ${more > 0 ? `<div style="font-size:.65rem;color:var(--text3);padding-top:2px">â€¦ and ${more} more</div>` : ""}
      </div>
      <div style="font-size:.67rem;color:var(--text3);margin-top:6px">${data.remaining} valid subdomains remaining</div>
    </div>`;
}

const RECON_MODULES = [
  {id:"email",     label:"Email Security",          desc:"SPF, DMARC, DKIM, MX analysis",                     eta:"~10s",  icon:"âœ‰"},
  {id:"certs",     label:"Certificate Transparency",desc:"crt.sh CT logs + SSL/TLS probe",                   eta:"~20s",  icon:"ðŸ”’"},
  {id:"dns",       label:"Full DNS Records",         desc:"A, AAAA, MX, TXT, NS, SOA, CNAME, SRV, CAA",       eta:"~10s",  icon:"ðŸŒ"},
  {id:"headers",   label:"Security Headers",         desc:"HSTS, CSP, X-Frame-Options, cookies",              eta:"~30s",  icon:"ðŸ“‹"},
  {id:"waf",       label:"WAF Detection",            desc:"Detect Imperva, Cloudflare, AWS WAF, Akamaiâ€¦",     eta:"~1m",   icon:"ðŸ›¡"},
  {id:"takeover",  label:"Subdomain Takeover",       desc:"CNAME â†’ dead 3rd-party services",                  eta:"~2m",   icon:"âš "},
  {id:"typosquat", label:"Typosquatting",            desc:"Look-alike domains targeting your brand",          eta:"~2m",   icon:"ðŸŽ£"},
  {id:"related",   label:"Related Domains",          desc:".net, .org, .com variations of your domains",      eta:"~30s",  icon:"ðŸ”—"},
  {id:"cloud",     label:"Cloud Asset Discovery",    desc:"S3, Azure Blob, GCP buckets â€” public/private",     eta:"~3m",   icon:"â˜"},
  {id:"wayback",   label:"Wayback / GAU Mining",     desc:"Historical URLs with .env, .git, admin paths",     eta:"~2m",   icon:"âª"},
  {id:"breach",    label:"Breach Intelligence",      desc:"LeakIX, HaveIBeenPwned, TruffleHog secrets",       eta:"~30s",  icon:"ðŸ’€"},
  {id:"shodan",    label:"Shodan Intelligence",      desc:"Open ports, CVEs and banners per IP",              eta:"~1m",   icon:"ðŸ“¡"},
  {id:"portscan",  label:"Port Scan",                desc:"naabu/nmap â€” risky exposed services",              eta:"~5m",   icon:"ðŸ”Œ"},
  {id:"services",  label:"Exposed Paths",            desc:"/.git /.env /admin /swagger /actuatorâ€¦",          eta:"~5m",   icon:"ðŸ—‚"},
  {id:"leaks",     label:"GitHub Secrets",           desc:"Leaked API keys and .git directory exposure",      eta:"~2m",   icon:"ðŸ”‘"},
  {id:"asn",       label:"ASN / IP Blocks",          desc:"All IP ranges and ASNs attributed to the org",     eta:"~30s",  icon:"ðŸ—º"},
  {id:"cve",        label:"CVE Lookup (NVD)",          desc:"Cross-reference detected technologies with NVD CVE database",   eta:"~2m",   icon:"ðŸ’¥"},
  {id:"vhost",      label:"Virtual Host Discovery",    desc:"Host header fuzzing â€” find hidden apps on same IPs",  eta:"~3m",   icon:"ðŸ "},
  {id:"js",         label:"JavaScript Recon",          desc:"Katana crawl + extract endpoints, secrets, S3, IPs",  eta:"~5m",   icon:"ðŸ“œ"},
  {id:"screenshot", label:"Screenshots",               desc:"Visual inventory of all live web assets (gowitness)",  eta:"~3m",   icon:"ðŸ“¸"},
  {id:"dns_brute",  label:"DNS Brute-force",           desc:"dnsgen permutations + dnsx â€” find hidden subdomains",  eta:"~5m",   icon:"ðŸ”¡"},
  {id:"api_panels", label:"API & Panel Exposure",      desc:"Spring Boot, Swagger, GraphQL, CORS, Smuggling (nuclei)", eta:"~5m", icon:"ðŸ”Œ"},
  {id:"certstream",   label:"CertStream Monitor",        desc:"Real-time certificate transparency â€” new asset alerts", eta:"~2m",  icon:"ðŸ“¡"},
  {id:"wappalyzer",   label:"Wappalyzer Tech Detection", desc:"httpx -tech-detect â€” Bootstrap, jQuery, PHP, CMS, frameworks across all subdomains", eta:"~2m", icon:"ðŸ”¬"},
  {id:"dep_confusion",label:"Dependency Confusion",      desc:"npm/PyPI/RubyGems â€” nomes de pacotes internos que podem ser squatados", eta:"~3m",  icon:"ðŸ“¦"},
  {id:"postman_collections", label:"Postman Collections", desc:"Exposed Postman collections on public API and GitHub â€” finds hardcoded tokens, API keys, base URLs", eta:"~1m", icon:"ðŸ“®"},
];

// deduplicate by id
const RECON_MODS_DEDUP = RECON_MODULES.filter((m,i,a)=>a.findIndex(x=>x.id===m.id)===i);

const reconState = {};  // cid -> {module -> {status, data}}
const pipelineState = {};  // cid -> pipeline status object
let _pipelinePolls = {};   // cid -> interval id
let _pipelineDonePhases = {};  // cid -> number of completed phases seen so far

function _isPipelineActive(cid) {
  const status = pipelineState[cid]?.status;
  return status === "queued" || status === "running";
}

function _syncPipelineActionButton(cid) {
  const btn = document.getElementById(`pipeline-btn-${cid}`);
  if (!btn) return;
  const active = _isPipelineActive(cid);
  btn.disabled = false;
  btn.className = `btn btn-icon ${active ? "pipeline-stop-btn" : "btn-secondary"}`;
  btn.textContent = active ? "â–  Stop Pipeline" : "â–¶ Run Pipeline";
}

async function handlePipelineAction(cid) {
  if (_isPipelineActive(cid)) return stopPipeline(cid, {notify: false});
  return runPipeline(cid);
}

async function stopPipeline(cid, {notify = true} = {}) {
  if (!cid) return;
  const btn = document.getElementById(`pipeline-btn-${cid}`);
  if (btn) { btn.disabled = true; btn.textContent = "Stopping..."; }
  try {
    const r = await fetch('/api/recon/' + encodeURIComponent(cid) + '/pipeline', {method:'DELETE', headers:_authHeaders()});
    if (!r.ok) throw await _apiErr(r);
    pipelineState[cid] = {
      ...(pipelineState[cid] || {}),
      status: "stopped",
      finished_at: new Date().toISOString(),
    };
    if (_pipelinePolls[cid]) {
      clearInterval(_pipelinePolls[cid]);
      delete _pipelinePolls[cid];
    }
    renderPipelineStatus(cid);
    _syncPipelineActionButton(cid);
    if (notify) alert('Pipeline stopped');
  } catch(e) {
    _syncPipelineActionButton(cid);
    alert('Failed: ' + e.message);
  }
}

async function scanAllCompanies() {
  const companies = allCompanies();
  if (!companies.length) { alert('Nenhuma empresa cadastrada.'); return; }
  const active = companies.filter(c => {
    const s = (pipelineState[c.id] || {}).status;
    return s === 'running' || s === 'queued';
  });
  const toStart = companies.length - active.length;
  if (toStart === 0) { alert('Todos os scans jÃ¡ estÃ£o em execuÃ§Ã£o.'); return; }
  if (!confirm(`Iniciar scan em ${toStart} empresa(s)${active.length ? ` (${active.length} jÃ¡ em execuÃ§Ã£o serÃ£o ignoradas)` : ''}?`)) return;
  const btn = document.getElementById('btn-scan-all');
  if (btn) { btn.disabled = true; btn.textContent = 'Iniciando...'; }
  let cfg = {};
  try { cfg = JSON.parse(localStorage.getItem('asm_settings') || '{}'); } catch(e) {}
  cfg.mode = selectedRateMode || cfg.mode || 'balanced';
  try {
    const r = await fetch('/api/recon/scan-all', {
      method: 'POST',
      headers: Object.assign({'Content-Type': 'application/json'}, _authHeaders()),
      body: JSON.stringify(cfg),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    (d.cids || []).forEach(cid => {
      pipelineState[cid] = Object.assign({}, pipelineState[cid] || {}, {
        status: 'queued',
        started_at: new Date().toISOString(),
      });
      _syncPipelineActionButton(cid);
      _startPipelinePoll(cid);
    });
    loadJobs();
    alert(`${d.started || 0} scan(s) iniciado(s)${d.skipped ? `, ${d.skipped} ignorado(s)` : ''}.`);
  } catch(e) {
    alert('Erro ao iniciar scans: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'â–¶ Escanear Todos'; }
  }
}

async function cancelAllScans() {
  const btn = document.getElementById('btn-cancel-all-scans');
  if (!confirm('Cancelar todos os scans em execuÃ§Ã£o?')) return;
  if (btn) { btn.disabled = true; btn.textContent = 'Cancelando...'; }
  try {
    const r = await fetch('/api/recon/cancel-all', {method:'POST', headers:_authHeaders()});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    // Update local pipeline state for all stopped companies
    (d.cids || []).forEach(cid => {
      pipelineState[cid] = Object.assign({}, pipelineState[cid] || {}, {
        status: 'stopped',
        finished_at: new Date().toISOString(),
      });
      if (_pipelinePolls[cid]) {
        clearInterval(_pipelinePolls[cid]);
        delete _pipelinePolls[cid];
      }
      _syncPipelineActionButton(cid);
      if (typeof renderPipelineStatus === 'function') renderPipelineStatus(cid);
    });
    loadJobs();
    const total = (d.stopped || 0);
    alert(total > 0 ? `${total} scan(s) cancelado(s).` : 'Nenhum scan ativo encontrado.');
  } catch(e) {
    alert('Erro ao cancelar: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'â–  Cancelar Todos'; }
  }
}

async function runPipeline(cid) {
  const btn = document.getElementById(`pipeline-btn-${cid}`);
  if (btn) { btn.disabled = true; btn.textContent = "Startingâ€¦"; }
  let cfg = {};
  try { cfg = JSON.parse(localStorage.getItem("asm_settings")||"{}"); } catch(e) {}
  cfg.mode = selectedRateMode;
  try {
    const r = await fetch(`/api/recon/${cid}/pipeline`, {
      method: "POST",
      headers: {"Content-Type":"application/json", ..._authHeaders()},
      body: JSON.stringify(cfg),
    });
    let data = {};
    if (!r.ok) {
      const t = await r.text();
      if (r.status !== 409 || !t.includes("already running")) {
        throw new Error(t);
      }
    } else {
      data = await r.json().catch(() => ({}));
    }
    pipelineState[cid] = {
      ...(pipelineState[cid] || {}),
      status: data.status || "queued",
      job_id: data.job_id || "",
      phase_label: "",
      host_count: 0,
      phases: [],
      not_done: [],
      started_at: new Date().toLocaleTimeString(),
      log: data.job_id ? [{ts:new Date().toISOString(), msg:`Pipeline queued as job ${data.job_id}`}] : [],
    };
    renderPipelineStatus(cid);
    _syncPipelineActionButton(cid);
    _startPipelinePoll(cid);
  } catch(e) {
    _syncPipelineActionButton(cid);
    alert("Erro ao iniciar pipeline: " + e.message);
  }
}

function _startPipelinePoll(cid) {
  if (_pipelinePolls[cid]) clearInterval(_pipelinePolls[cid]);
  _pipelineDonePhases[cid] = _pipelineDonePhases[cid] || 0;
  _pipelinePolls[cid] = setInterval(async () => {
    try {
      const r = await fetch(`/api/recon/${cid}/pipeline`, {headers: _authHeaders()});
      if (!r.ok) return;
      const ps = await r.json();
      pipelineState[cid] = ps;

      // sync module states from pipeline
      if (!reconState[cid]) reconState[cid] = {};
      (ps.phases||[]).forEach(ph => ph.modules.forEach(m => {
        if (m.status !== "not_run") reconState[cid][m.module] = {status: m.status};
      }));

      // Update the live phase HUD in place only. renderReconTab() is NOT called
      // per-tick because it re-fetches the Playwright session artifact every poll;
      // the recon tab (and its Playwright panel) is refreshed once on scan completion below.
      renderPipelineStatus(cid);
      _syncPipelineActionButton(cid);
      renderAllCompanies();

      // reload company data whenever a new phase completes (results are persisted per phase)
      const doneNow = (ps.phases||[]).filter(p => p.done).length;
      if (doneNow > (_pipelineDonePhases[cid] || 0)) {
        _pipelineDonePhases[cid] = doneNow;
        try {
          await ensureCompanyLoaded(cid, {force: true});
          const co = allCompanies().find(c => c.id === cid);
          if (co) {
            renderOverview(co);
  try { setTimeout(initThreatMaps, 50); setTimeout(initThreatMaps, 400); } catch(e) {}
            renderDomainsTab(co);
            renderSubdomainsTab(co);
            renderFindingsTab(co);
          }
        } catch(e) { /* ignore transient reload errors */ }
      }

      if (["done", "error", "stopped", "cancelled"].includes(ps.status)) {
        clearInterval(_pipelinePolls[cid]);
        _pipelineDonePhases[cid] = 0;
        _syncPipelineActionButton(cid);
        await reloadServerData();
        const co = allCompanies().find(c => c.id === cid);
        if (co) { renderOverview(co); renderDomainsTab(co); renderSubdomainsTab(co); renderFindingsTab(co); }
        // Refresh the recon tab once now that the scan is done so the Playwright
        // panel unlocks/updates â€” this is the only place it re-renders post-scan.
        if (state.currentId === cid && (state.activeGroup === "pipeline" || state.tab === "pipeline")) {
          renderReconTab(cid);
        }
      }
    } catch(e) { /* ignore transient errors */ }
  }, 2500);
}


function renderJsReverseTab(co) {
  var el = document.getElementById("tab-jsreverse");
  var jd = co.js_data || {};
  var jsFiles = jd.js_files || [];

  // Update badge
  var totalSecrets = jd.total_secrets || 0;
  var tc = document.getElementById("tc-jsreverse");
  if (tc) tc.textContent = totalSecrets || "";

  if (!jsFiles.length) {
    el.innerHTML = '<div class="empty-state"><div class="empty-state-icon">ðŸ”¬</div><div class="empty-state-title">No JS analysis data yet</div><div class="empty-state-copy">Run the pipeline with the js_scan module enabled.</div></div>';
    return;
  }

  // FP filter â€” mirrors recon.py _is_fp_secret logic, applied retroactively to stored data
  var _FP_PWD_RE = /(%filtered%|wrong.?password|forgot.?password|invalid.?password|missing.?password|need.?password|change.?password|reset.?password|show.?password|confirm.?password|enter.?password|password.?hint|password.?set|create.?password|redefine.?password|new.?password|old.?password|repeat.?password)/i;
  var _FP_LABEL_RE = /^[A-Z][A-Z0-9_\-]{3,}$|^[a-z][a-z0-9_]{4,}[a-z0-9]$/;
  function _jsFP(type, value) {
    var v = value || "";
    if (type === "password") {
      // Strip key name to get inner value
      var inner = v.replace(/^(?:password|passwd|pwd)\s*[=:]\s*['"]/i, "").replace(/['"]$/, "");
      if (_FP_PWD_RE.test(inner)) return true;
      if (/^[A-Z][A-Z0-9_\-.]+$/.test(inner) || /^[a-z][a-z\-.]+$/.test(inner)) return true;
      if (/^['"']?passwords?['"']?$/i.test(inner)) return true;
      // JS code fragments: WebRTC pwd: parsing, template strings, +var. concatenation
      if (/[\[\]{}&|?]|\.substring\(|\+[a-z]+\./.test(inner)) return true;
      // Sentence-like phrases: only letters and spaces
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
      // Validate each octet â‰¤ 255
      var m = v.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)/);
      if (!m) return true;
      return [m[1],m[2],m[3],m[4]].some(function(o){ return parseInt(o,10) > 255; });
    }
    return false;
  }

  // Collect all secrets and endpoints from all files
  var allSecrets = [];
  var allEndpoints = [];
  var noiseHosts = new Set(["aadcdn.msauth.net","aadcdn.msftauth.net","ok1static.oktacdn.com","use.fontawesome.com"]);

  jsFiles.forEach(function(f) {
    var host = f.host || "";
    var url = f.url || "";
    (f.secrets || []).forEach(function(s) {
      if (_jsFP(s.type, s.value)) return;
      allSecrets.push({ severity: s.severity || "medium", type: s.type || "unknown", host: host, value: s.value || "", context: s.context || "", url: url });
    });
    (f.endpoints || []).forEach(function(ep) {
      allEndpoints.push({ host: host, path: ep.path || ep.url || "", kind: ep.kind || "path", url: url });
    });
  });

  var totalEndpoints = jd.total_endpoints || allEndpoints.length;

  // Unique secret types for filter
  var uniqueTypes = Array.from(new Set(allSecrets.map(function(s) { return s.type; }))).sort();

  // Summary strip
  var critCnt = jd.critical_count || allSecrets.filter(function(s){return s.severity==="critical";}).length;
  var highCnt = jd.high_count    || allSecrets.filter(function(s){return s.severity==="high";}).length;
  var medCnt  = jd.medium_count  || allSecrets.filter(function(s){return s.severity==="medium";}).length;

  var html = '<div class="section-shell" style="padding:20px">';
  html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">';
  html += '<div><div style="font-size:.75rem;color:var(--text3);text-transform:uppercase;letter-spacing:.08em">JS Reverse Engineering</div>';
  html += '<div style="font-size:1.3rem;font-weight:700;color:var(--text)">Secrets &amp; API Endpoints</div></div></div>';

  // Summary strip cards
  html += '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px">';
  function _statCard(label, val, color) {
    return '<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 20px;min-width:110px">' +
      '<div style="font-size:1.6rem;font-weight:800;color:' + color + '">' + val + '</div>' +
      '<div style="font-size:.68rem;color:var(--text3);margin-top:2px;text-transform:uppercase">' + label + '</div></div>';
  }
  html += _statCard("Critical", critCnt, "var(--red)");
  html += _statCard("High", highCnt, "var(--orange)");
  html += _statCard("Medium", medCnt, "var(--yellow)");
  html += _statCard("Total Secrets", totalSecrets, "var(--teal)");
  html += _statCard("Endpoints", totalEndpoints, "var(--text2)");
  html += '</div>';

  // â”€â”€ SECRETS SECTION â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  html += '<div style="margin-bottom:32px">';
  html += '<div style="font-size:.9rem;font-weight:700;color:var(--text);margin-bottom:10px;display:flex;align-items:center;justify-content:space-between">';
  html += '<span>Secrets Found (' + allSecrets.length + ')</span>';
  html += '<button onclick="_jsrExportSecretsCsv()" style="background:var(--card);border:1px solid var(--border);color:var(--text2);border-radius:5px;padding:3px 10px;font-size:.68rem;cursor:pointer">â¬‡ CSV</button>';
  html += '</div>';

  // Filter bar
  html += '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center">';
  html += '<select id="jsr-sev-filter" onchange="_jsrRender()" style="background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 8px;font-size:.72rem">';
  html += '<option value="">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>';

  html += '<select id="jsr-type-filter" onchange="_jsrRender()" style="background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 8px;font-size:.72rem">';
  html += '<option value="">All Types</option>';
  uniqueTypes.forEach(function(t) { html += '<option value="' + esc(t) + '">' + esc(t) + '</option>'; });
  html += '</select>';

  html += '<input id="jsr-text-filter" oninput="_jsrRender()" placeholder="Search value / host..." style="background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 10px;font-size:.72rem;width:180px">';

  html += '<label style="display:flex;align-items:center;gap:5px;font-size:.72rem;color:var(--text2);cursor:pointer">';
  html += '<input type="checkbox" id="jsr-noise-filter" onchange="_jsrRender()" checked> Hide noise CDNs</label>';
  html += '</div>';

  // Secrets table
  html += '<div id="jsr-secrets-table"></div>';
  html += '</div>';

  // â”€â”€ ENDPOINTS SECTION â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  html += '<div>';
  html += '<div style="font-size:.9rem;font-weight:700;color:var(--text);margin-bottom:10px;display:flex;align-items:center;justify-content:space-between">';
  html += '<span>Discovered Endpoints</span>';
  html += '<button onclick="_jsrExportEndpointsCsv()" style="background:var(--card);border:1px solid var(--border);color:var(--text2);border-radius:5px;padding:3px 10px;font-size:.68rem;cursor:pointer">â¬‡ CSV</button>';
  html += '</div>';

  html += '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center">';
  html += '<input id="jsr-ep-text" oninput="_jsrRenderEp()" placeholder="Search path / host..." style="background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 10px;font-size:.72rem;width:200px">';
  html += '<label style="display:flex;align-items:center;gap:5px;font-size:.72rem;color:var(--text2);cursor:pointer">';
  html += '<input type="checkbox" id="jsr-api-only" onchange="_jsrRenderEp()"> API/Auth only</label>';
  html += '</div>';

  html += '<div id="jsr-endpoints-table"></div>';
  html += '</div>';

  // â”€â”€ RUNTIME NETWORK MAP (Playwright) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  var runtimeNet = jd.runtime_network || [];
  var runtimeJsCnt = jd.runtime_js_count || 0;
  html += '<div style="margin-top:32px">';
  html += '<div style="font-size:.9rem;font-weight:700;color:var(--text);margin-bottom:6px;display:flex;align-items:center;gap:10px">';
  html += '<span>Runtime Network Map <span style="font-size:.72rem;font-weight:400;color:var(--text3)">(Playwright)</span></span>';
  if (runtimeJsCnt) html += '<span style="font-size:.68rem;color:var(--teal);font-weight:600">' + runtimeJsCnt + ' runtime JS chunks captured</span>';
  html += '</div>';

  if (!runtimeNet.length) {
    html += '<div style="color:var(--text3);font-size:.78rem;padding:10px 0">No runtime network calls captured â€” run pipeline to collect Playwright data.</div>';
  } else {
    var methods = Array.from(new Set(runtimeNet.map(function(c){return c.method;}))).sort();
    html += '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center">';
    html += '<input id="jsr-net-filter" oninput="_jsrRenderNet()" placeholder="Filter URL..." style="background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 10px;font-size:.72rem;width:220px">';
    html += '<select id="jsr-net-method" onchange="_jsrRenderNet()" style="background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 8px;font-size:.72rem"><option value="">All Methods</option>';
    methods.forEach(function(m){ html += '<option>' + esc(m) + '</option>'; });
    html += '</select>';
    html += '<button onclick="_jsrExportNetCsv()" style="background:var(--card);border:1px solid var(--border);color:var(--text2);border-radius:5px;padding:3px 10px;font-size:.68rem;cursor:pointer">â¬‡ CSV</button>';
    html += '</div>';
    html += '<div id="jsr-net-table"></div>';
  }
  html += '</div>';

  html += '</div>'; // section-shell

  el.innerHTML = html;

  // Store data on window for filter handlers
  window._jsrAllSecrets   = allSecrets;
  window._jsrAllEndpoints = allEndpoints;
  window._jsrRuntimeNet   = runtimeNet;
  window._jsrNoiseHosts   = noiseHosts;
  window._jsrRevealSet    = new Set();

  _jsrRender();
  _jsrRenderEp();
  if (runtimeNet.length) _jsrRenderNet();
}

function _sevBadge(s) {
  var c = {critical:'#fb7185',high:'#fb923c',medium:'#fbbf24',low:'#4ade80'}[s] || 'var(--text3)';
  return '<span style="background:' + c + '22;color:' + c + ';border:1px solid ' + c + '44;border-radius:4px;padding:1px 7px;font-size:.65rem;font-weight:700;text-transform:uppercase">' + esc(s || 'info') + '</span>';
}

function _jsrRender() {
  var sev    = (document.getElementById("jsr-sev-filter")  || {}).value || "";
  var typ    = (document.getElementById("jsr-type-filter") || {}).value || "";
  var txt    = ((document.getElementById("jsr-text-filter")|| {}).value || "").toLowerCase();
  var noise  = (document.getElementById("jsr-noise-filter")|| {}).checked;
  var tbl    = document.getElementById("jsr-secrets-table");
  if (!tbl) return;

  var rows = (window._jsrAllSecrets || []).filter(function(s) {
    if (sev  && s.severity !== sev) return false;
    if (typ  && s.type     !== typ) return false;
    if (noise && (window._jsrNoiseHosts||new Set()).has(s.host)) return false;
    if (txt  && !((s.value||"").toLowerCase().includes(txt) || (s.host||"").toLowerCase().includes(txt) || (s.type||"").toLowerCase().includes(txt))) return false;
    return true;
  });

  if (!rows.length) {
    tbl.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3);font-size:.8rem">No secrets match current filters.</div>';
    return;
  }

  var h = '<table style="width:100%;border-collapse:collapse;font-size:.72rem">';
  h += '<thead><tr style="border-bottom:1px solid var(--border)">';
  ['Severity','Type','Host','Value','Source URL'].forEach(function(col) {
    h += '<th style="text-align:left;padding:6px 10px;color:var(--text3);font-weight:600;font-size:.68rem;text-transform:uppercase">' + col + '</th>';
  });
  h += '</tr></thead><tbody>';

  rows.forEach(function(s, i) {
    var revealed = (window._jsrRevealSet || new Set()).has(i);
    var display  = revealed ? esc(s.value) : 'â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢';
    var btnLabel = revealed ? 'hide' : 'reveal';
    var shortUrl = s.url ? s.url.replace(/^https?:\/\//,'').substring(0,55) + (s.url.length > 55 ? 'â€¦' : '') : '';
    h += '<tr style="border-bottom:1px solid var(--border)22;hover:background:var(--card2)">';
    h += '<td style="padding:6px 10px">' + _sevBadge(s.severity) + '</td>';
    h += '<td style="padding:6px 10px;color:var(--text2);font-family:monospace">' + esc(s.type) + '</td>';
    h += '<td style="padding:6px 10px;color:var(--teal)">' + esc(s.host) + '</td>';
    h += '<td style="padding:6px 10px;font-family:monospace;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(s.value) + '">';
    h += '<span id="jsr-val-' + i + '">' + display + '</span> ';
    h += '<button onclick="_jsrToggleReveal(' + i + ')" style="background:none;border:none;color:var(--teal);cursor:pointer;font-size:.65rem;padding:0 4px">' + btnLabel + '</button></td>';
    h += '<td style="padding:6px 10px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">';
    if (s.url) h += '<a href="' + esc(s.url) + '" target="_blank" rel="noopener" style="color:var(--text3);text-decoration:none" title="' + esc(s.url) + '">' + esc(shortUrl) + '</a>';
    h += '</td></tr>';
  });
  h += '</tbody></table>';
  tbl.innerHTML = h;
}

function _jsrToggleReveal(i) {
  if (!window._jsrRevealSet) window._jsrRevealSet = new Set();
  if (window._jsrRevealSet.has(i)) window._jsrRevealSet.delete(i);
  else window._jsrRevealSet.add(i);
  _jsrRender();
}

function _jsrRenderEp() {
  var txt     = ((document.getElementById("jsr-ep-text")  || {}).value || "").toLowerCase();
  var apiOnly = (document.getElementById("jsr-api-only")  || {}).checked;
  var tbl     = document.getElementById("jsr-endpoints-table");
  if (!tbl) return;

  var rows = (window._jsrAllEndpoints || []).filter(function(ep) {
    if (apiOnly && !/(\/api\/|\/auth\/|\/oauth|\/login|\/graphql|\/v[0-9])/i.test(ep.path)) return false;
    if (txt && !((ep.path||"").toLowerCase().includes(txt) || (ep.host||"").toLowerCase().includes(txt))) return false;
    return true;
  });

  var maxRows = 500;
  var shown   = rows.slice(0, maxRows);

  if (!shown.length) {
    tbl.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3);font-size:.8rem">No endpoints match current filters.</div>';
    return;
  }

  var h = '<div style="font-size:.68rem;color:var(--text3);margin-bottom:6px">Showing ' + shown.length + (rows.length > maxRows ? ' of ' + rows.length : '') + ' endpoints</div>';
  h += '<table style="width:100%;border-collapse:collapse;font-size:.72rem">';
  h += '<thead><tr style="border-bottom:1px solid var(--border)">';
  ['Host','Path','Kind'].forEach(function(col) {
    h += '<th style="text-align:left;padding:6px 10px;color:var(--text3);font-weight:600;font-size:.68rem;text-transform:uppercase">' + col + '</th>';
  });
  h += '</tr></thead><tbody>';

  shown.forEach(function(ep) {
    h += '<tr style="border-bottom:1px solid var(--border)22">';
    h += '<td style="padding:6px 10px;color:var(--teal)">' + esc(ep.host) + '</td>';
    h += '<td style="padding:6px 10px;font-family:monospace;color:var(--text)">' + esc(ep.path) + '</td>';
    h += '<td style="padding:6px 10px;color:var(--text3)">' + esc(ep.kind) + '</td>';
    h += '</tr>';
  });
  h += '</tbody></table>';
  tbl.innerHTML = h;
}

function _jsrExportSecretsCsv() {
  var rows = window._jsrAllSecrets || [];
  var lines = ["severity,type,host,value,url"];
  rows.forEach(function(s) {
    lines.push([s.severity, s.type, s.host, '"' + (s.value||"").replace(/"/g,'""') + '"', s.url].join(","));
  });
  _downloadCsv("js_secrets.csv", lines.join("\n"));
}

function _jsrExportEndpointsCsv() {
  var rows = window._jsrAllEndpoints || [];
  var lines = ["host,path,kind"];
  rows.forEach(function(ep) {
    lines.push([ep.host, '"' + (ep.path||"").replace(/"/g,'""') + '"', ep.kind].join(","));
  });
  _downloadCsv("js_endpoints.csv", lines.join("\n"));
}

function _jsrRenderNet() {
  var txt    = ((document.getElementById("jsr-net-filter") || {}).value || "").toLowerCase();
  var method = ((document.getElementById("jsr-net-method") || {}).value || "");
  var tbl    = document.getElementById("jsr-net-table");
  if (!tbl) return;

  var rows = (window._jsrRuntimeNet || []).filter(function(c) {
    if (method && c.method !== method) return false;
    if (txt && !(c.url||"").toLowerCase().includes(txt)) return false;
    return true;
  });

  var maxRows = 400;
  var shown   = rows.slice(0, maxRows);

  if (!shown.length) {
    tbl.innerHTML = '<div style="padding:14px 0;color:var(--text3);font-size:.78rem">No calls match filter.</div>';
    return;
  }

  var h = '<div style="font-size:.68rem;color:var(--text3);margin-bottom:6px">Showing ' + shown.length + (rows.length > maxRows ? ' of ' + rows.length : '') + ' calls</div>';
  h += '<table style="width:100%;border-collapse:collapse;font-size:.71rem">';
  h += '<thead><tr style="border-bottom:1px solid var(--border)">';
  ['Method','Type','URL'].forEach(function(col) {
    h += '<th style="text-align:left;padding:5px 10px;color:var(--text3);font-weight:600;font-size:.67rem;text-transform:uppercase">' + col + '</th>';
  });
  h += '</tr></thead><tbody>';

  var methodColor = {GET:'var(--teal)',POST:'var(--orange)',PUT:'var(--yellow)',DELETE:'var(--red)',PATCH:'#a78bfa'};
  shown.forEach(function(c) {
    var mc = methodColor[c.method] || 'var(--text2)';
    var shortUrl = (c.url||'').replace(/^https?:\/\//,'');
    h += '<tr style="border-bottom:1px solid var(--border)22">';
    h += '<td style="padding:5px 10px;font-weight:700;color:' + mc + ';font-family:monospace;white-space:nowrap">' + esc(c.method) + '</td>';
    h += '<td style="padding:5px 10px;color:var(--text3);white-space:nowrap">' + esc(c.type||'') + '</td>';
    h += '<td style="padding:5px 10px;font-family:monospace;color:var(--text2);word-break:break-all">';
    h += '<a href="' + esc(c.url||'') + '" target="_blank" rel="noopener" style="color:inherit;text-decoration:none" title="' + esc(c.url||'') + '">' + esc(shortUrl) + '</a>';
    h += '</td></tr>';
  });
  h += '</tbody></table>';
  tbl.innerHTML = h;
}

function _jsrExportNetCsv() {
  var rows = window._jsrRuntimeNet || [];
  var lines = ["method,type,url"];
  rows.forEach(function(c) {
    lines.push([c.method, c.type, '"' + (c.url||"").replace(/"/g,'""') + '"'].join(","));
  });
  _downloadCsv("js_runtime_network.csv", lines.join("\n"));
}

function _downloadCsv(filename, content) {
  var blob = new Blob([content], {type: "text/csv"});
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}


async function renderVulnsTab(co) {
  const el = document.getElementById("tab-vulns");
  if (!el) return;

  el.innerHTML = `<div style="padding:40px;text-align:center;color:var(--text3)">
    <div class="pulse" style="width:12px;height:12px;background:var(--teal);border-radius:50%;margin:0 auto 12px"></div>
    Loading vulnerability data...</div>`;

  let data;
  try {
    const resp = await fetch(`/api/vulns/${encodeURIComponent(co.id)}`, {headers:_authHeaders()});
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    data = await resp.json();
  } catch(e) {
    el.innerHTML = `<div class="empty-state"><div class="empty-state-icon">âš </div><div class="empty-state-title">Failed to load vuln data</div><div class="empty-state-copy">${esc(String(e))}</div></div>`;
    return;
  }

  const cors     = data.cors || [];
  const graphql  = data.graphql || [];
  const nuclei   = data.nuclei || [];
  const takeover = data.takeover || [];
  const summary   = data.summary || {};
  const findings  = _confirmedVulnFindings(co.findings || []);
  const apiTotal  = Number(summary.total || (cors.length + graphql.length + nuclei.length + takeover.length));

  const tcv = document.getElementById("tc-vulns");
  if (tcv) tcv.textContent = String(apiTotal + findings.length);

  try {
    const triageR = await fetch(`/api/findings/${encodeURIComponent(co.id)}/triage`, {headers:_authHeaders()});
    if (triageR.ok) {
      const triageData = await triageR.json();
      if (!window._triageMap) window._triageMap = {};
      window._triageMap[co.id] = triageData.triage || {};
    }
  } catch(e) {}

  const cats = [...new Set(findings.map(f => f.category).filter(Boolean))].sort();
  const summaryCards = {
    critical: findings.filter(f => f.severity === "critical").length,
    high:     findings.filter(f => f.severity === "high").length,
    medium:   findings.filter(f => f.severity === "medium").length,
    low:      findings.filter(f => f.severity === "low").length,
  };

  const cidJs = _jsArg(co.id);
  let html = `<div class="section-shell" style="padding:18px">
    <div class="section-head">
      <div class="section-head-main">
        <div class="section-kicker">Confirmed Vulnerabilities</div>
        <div class="section-title">Confirmed vulnerability findings only</div>
        <div class="section-sub">Recon noise, brand intelligence, phishing and other non-vulnerability leads are filtered out.</div>
      </div>
    </div>`;

  html += `<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px">
    ${_vStatCard("Confirmed", findings.length, "var(--green)")}
    ${_vStatCard("Critical", summaryCards.critical, "var(--red)")}
    ${_vStatCard("High", summaryCards.high, "var(--orange)")}
    ${_vStatCard("Medium", summaryCards.medium, "var(--yellow)")}
    ${_vStatCard("Low", summaryCards.low, "var(--blue)")}
    ${_vStatCard("CORS", cors.length, "var(--red)")}
    ${_vStatCard("GraphQL", graphql.length, "var(--teal)")}
    ${_vStatCard("Nuclei", nuclei.length, "var(--orange)")}
    ${_vStatCard("Takeover", takeover.length, "var(--yellow)")}
  </div>`;

  if (findings.length) {
    html += `<div class="findings-summary">
      ${_severityCard("critical", summaryCards.critical, co.id)}
      ${_severityCard("high", summaryCards.high, co.id)}
      ${_severityCard("medium", summaryCards.medium, co.id)}
      ${_severityCard("low", summaryCards.low, co.id)}
    </div>`;
    html += `<div class="filter-bar">
      <input type="text" class="fi grow" id="f-search" placeholder="Search confirmed vulns, hosts, descriptions..." oninput='applyFindFilter(${cidJs})'>
      <select class="fi" id="f-sev" onchange='applyFindFilter(${cidJs})'>
        <option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
      </select>
      <select class="fi" id="f-cat" onchange='applyFindFilter(${cidJs})'><option value="">All categories</option>${cats.map(c=>`<option value="${esc(c)}">${esc(c)}</option>`).join("")}</select>
      <select class="fi" id="f-triage" onchange='applyFindFilter(${cidJs})'>
        <option value="">Todos os status</option>
        ${Object.entries(FINDING_TRIAGE_LABELS).map(([val,lbl])=>`<option value="${val}">${lbl}</option>`).join("")}
      </select>
      <span style="font-size:.68rem;color:var(--text3);padding:6px 4px" id="f-cnt"></span>
      <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px;margin-left:auto" onclick='exportFindings(${cidJs},"csv")' title="Export CSV">â¬‡ CSV</button>
      <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px" onclick='exportFindings(${cidJs},"json")' title="Export JSON">â¬‡ JSON</button>
    </div>
    <div class="findings-list" id="f-list"></div>
    <div class="empty-state" id="f-empty" style="display:none"><div class="empty-state-icon">âˆ…</div><div class="empty-state-title">No confirmed vulns match the current filters</div><div class="empty-state-copy">Try widening the search terms or clearing severity/category filters.</div></div>`;
  } else {
    html += `<div class="empty-state"><div class="empty-state-icon">âˆ…</div><div class="empty-state-title">No confirmed vulnerabilities yet</div><div class="empty-state-copy">Run the bug bounty pipeline to populate this view.</div></div>`;
  }

  html += `<div style="margin-top:18px">`;

  const _sectionHdr = (title, count) => `<div style="font-size:.9rem;font-weight:700;color:var(--text);margin:24px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--border)">${esc(title)} <span style="color:var(--text3);font-weight:400">(${count})</span></div>`;
  const _emptySection = msg => `<div style="padding:12px 16px;color:var(--text3);font-size:.8rem;background:var(--card);border:1px solid var(--border);border-radius:8px">${esc(msg)}</div>`;

  html += _sectionHdr("CORS Misconfigurations", cors.length);
  if (!cors.length) {
    html += _emptySection("No CORS misconfigurations found.");
  } else {
    html += `<div style="display:grid;gap:10px">` + cors.map(f => {
      const acac = f.acac === true || f.acac === "true" || f.acac === 1;
      return `<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          ${_sevBadge(f.severity || "high")}
          <span style="font-weight:700;color:var(--teal)">${esc(f.host || "")}</span>
          <span style="font-size:.72rem;color:var(--text3)">${esc(f.test || "")}</span>
        </div>
        <div style="font-size:.72rem;color:var(--text2);margin-bottom:6px">
          <span style="color:var(--text3)">ACAO: </span><code style="color:var(--text)">${esc(f.acao || "")}</code>
          ${acac ? `<span style="background:#fb718522;color:#fb7185;border:1px solid #fb718544;border-radius:4px;padding:1px 7px;font-size:.65rem;font-weight:700;margin-left:6px">âš  Credentials</span>` : ""}
        </div>
        <div style="font-size:.7rem;color:var(--text3)">Origin sent: <code>${esc(f.origin_sent || "")}</code></div>
        ${f.url ? `<div style="margin-top:6px"><a href="${esc(f.url)}" target="_blank" rel="noopener" style="color:var(--teal);font-size:.7rem;text-decoration:none">${esc(f.url.substring(0,80))}</a></div>` : ""}
      </div>`;
    }).join("") + `</div>`;
  }

  html += _sectionHdr("GraphQL Endpoints", graphql.length);
  html += graphql.length ? `<div style="display:grid;gap:10px">${graphql.map(f => `
    <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        ${_sevBadge(f.severity || "high")}
        <span style="font-weight:700;color:var(--teal)">${esc(f.host || "")}</span>
        <span style="font-size:.72rem;color:var(--text3)">${esc(f.url || "")}</span>
      </div>
      <div style="font-size:.72rem;color:var(--text2)">${esc(f.desc || f.title || "")}</div>
    </div>`).join("")}</div>` : _emptySection("No GraphQL endpoints detected.");

  html += _sectionHdr("Nuclei Findings", nuclei.length);
  html += nuclei.length ? `<div style="display:grid;gap:10px">${nuclei.map(f => `
    <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        ${_sevBadge(f.severity || "high")}
        <span style="font-weight:700;color:var(--teal)">${esc(f.host || "")}</span>
        <span style="font-size:.72rem;color:var(--text3)">${esc(f.template || f.name || "")}</span>
      </div>
      <div style="font-size:.72rem;color:var(--text2)">${esc(f.desc || "")}</div>
    </div>`).join("")}</div>` : _emptySection("No nuclei findings detected.");

  html += _sectionHdr("Takeover Candidates", takeover.length);
  html += takeover.length ? `<div style="display:grid;gap:10px">${takeover.map(f => `
    <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        ${_sevBadge(f.severity || "high")}
        <span style="font-weight:700;color:var(--teal)">${esc(f.host || "")}</span>
      </div>
      <div style="font-size:.72rem;color:var(--text2)">${esc(f.desc || "")}</div>
    </div>`).join("")}</div>` : _emptySection("No takeover candidates detected.");

  html += `</div></div>`;
  el.innerHTML = html;
  // Apply any pending severity filter (set by goToVulnSeverity before fetch resolved)
  if (_pendingVulnFilter && _pendingVulnFilter.cid === co.id) {
    const sevSel = document.getElementById("f-sev");
    if (sevSel) sevSel.value = _pendingVulnFilter.sev;
    _pendingVulnFilter = null;
  }
  if (findings.length) applyFindFilter(co.id);
}

function exportHosts(fmt) {
  const hosts = _sub_hosts || _co_hosts || [];
  const cid = state.currentId || "export";
  const ts = new Date().toISOString().slice(0,10);
  if(fmt === "json") {
    _downloadBlob(JSON.stringify(hosts, null, 2), `${cid}_hosts_${ts}.json`, "application/json");
  } else {
    const header = "host,ip,waf,technologies,ports\n";
    const rows = hosts.map(h => [
      h.host||"", h.ip||"", h.waf||"",
      (h.technologies||[]).join("|"),
      (h.ports||[]).join("|")
    ].map(v=>`"${v}"`).join(",")).join("\n");
    _downloadBlob(header + rows, `${cid}_hosts_${ts}.csv`, "text/csv");
  }
}

function copyInstall(name){
  const el = document.getElementById("ic-" + name);
  if(!el) return;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(el.textContent).then(()=>{
      const btn = el.nextElementSibling;
      if(btn){ btn.textContent = "âœ“"; setTimeout(()=>btn.textContent="âŽ˜", 1500); }
    });
  } else {
    _fallbackCopy(el.textContent);
    const btn = el.nextElementSibling;
    if(btn){ btn.textContent = "âœ“"; setTimeout(()=>btn.textContent="âŽ˜", 1500); }
  }
}

async function runTool(name){
  const input = document.getElementById("ti-" + name);
  const btn   = document.getElementById("tb-" + name);
  const res   = document.getElementById("tr-" + name);
  const target = (input?.value||"").trim();
  if(!target){ input?.focus(); return; }

  btn.disabled = true;
  btn.textContent = "Runningâ€¦";
  res.className = "tc-result show";
  res.innerHTML = `<div style="color:var(--text3)">Running ${name} against ${target}â€¦</div>`;

  try {
    const r = await fetch("/api/tools/run", {
      method:"POST",
      headers: _authHeaders(),
      body: JSON.stringify({tool: name, target})
    });
    if(!r.ok) throw await _apiErr(r);

    // Poll for result
    const pollIv = setInterval(async ()=>{
      const pr = await fetch(`/api/tools/result?tool=${encodeURIComponent(name)}&target=${encodeURIComponent(target)}`);
      const pd = await pr.json();
      if(pd.status === "done" || pd.status === "error"){
        clearInterval(pollIv);
        btn.disabled = false;
        btn.textContent = "Run";
        if(pd.error){
          res.innerHTML = `<div style="color:var(--red)">Error: ${pd.error}</div>`;
        } else {
          const findings = pd.findings || [];
          if(!findings.length){
            res.innerHTML = `<div style="color:var(--text3)">No findings (${pd.duration?.toFixed(1)||"?"}s)</div>`;
          } else {
            const SEV_COLOR = {critical:"#fb7185",high:"#fb923c",medium:"#fbbf24",low:"#4ade80",info:"#60a5fa"};
            res.innerHTML = `<div style="color:var(--text3);margin-bottom:4px">${findings.length} findings Â· ${pd.duration?.toFixed(1)||"?"}s</div>` +
              findings.slice(0,50).map(f=>{
                const c = SEV_COLOR[f.severity]||"var(--text2)";
                return `<div class="f-line"><span style="color:${c};font-weight:600">[${esc(f.type)}]</span> ${esc(f.value)}${f.port?" :"+esc(String(f.port)):""}</div>`;
              }).join("") +
              (findings.length > 50 ? `<div style="color:var(--text3)">â€¦ and ${findings.length-50} more</div>` : "");
          }
        }
      }
    }, 1500);

  } catch(e){
    btn.disabled = false;
    btn.textContent = "Run";
    res.innerHTML = `<div style="color:var(--red)">Error: ${e.message}</div>`;
  }
}

function viewReconResult(cid, moduleId){
  const s = reconState[cid]?.[moduleId];
  if(!s||!s.data) return;
  const data = s.data.data||s.data;
  const pre = document.createElement("pre");
  pre.style.cssText="position:fixed;top:5vh;left:5vw;width:90vw;height:90vh;background:#0b0e18;color:#e2e8f0;border:1px solid #1e2d45;border-radius:10px;padding:20px;overflow:auto;z-index:9999;font-size:12px;line-height:1.5";
  pre.textContent = JSON.stringify(data, null, 2);
  const close = document.createElement("button");
  close.textContent="âœ• Close";
  close.style.cssText="position:fixed;top:calc(5vh + 10px);right:calc(5vw + 16px);z-index:10000;background:#f43f5e;color:#fff;border:none;border-radius:6px;padding:5px 12px;cursor:pointer;font-size:13px";
  close.onclick=()=>{document.body.removeChild(pre);document.body.removeChild(close);};
  document.body.appendChild(pre);
  document.body.appendChild(close);
}

// â”€â”€ Tool Logs tab â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ï¿½ï¿½ï¿½â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
let _tlData = [];
let _tlFilter = "";
let _tlStatusFilter = "";
let _tlToolFilter = "";
let _tlPage = 1;
const _tlOpenGroups = new Set();
const _tlVirtualRuns = new Map();
const TLP = 40;

async function loadToolLogs() {
  const cid = state.currentId;
  if (!cid) return;
  const el = document.getElementById("tab-toollogs");
  el.innerHTML = `<div style="color:var(--text3);font-size:0.8rem;padding:20px 0">Loading logsâ€¦</div>`;
  try {
    const r = await fetch(`/api/recon/${cid}/tool-logs`, {headers: _authHeaders()});
    if (!r.ok) throw await _apiErr(r);
    _tlData = await r.json();
    document.getElementById("tc-toollogs").textContent = _tlData.length || "";
    renderToolLogs(el);
  } catch(e) {
    el.innerHTML = `<div style="color:var(--red);font-size:0.8rem;padding:20px 0">Error: ${e.message}</div>`;
  }
}

function renderToolLogs(el) {
  if (!el) return;
  _tlVirtualRuns.clear();
  const q = (_tlFilter || "").toLowerCase();
  const tools = [...new Set(_tlData.map(r => _tlExactName(r)).filter(Boolean))].sort();
  const filtered = _tlData.filter(r => {
    const hay = [r.module, r.tool, r.binary, r.display_name, r.cmd, r.status, r.exit_code, r.ts].join(" ").toLowerCase();
    const st = _tlNormalizedStatus(r);
    return (!q || hay.includes(q)) &&
      (!_tlStatusFilter || st === _tlStatusFilter) &&
      (!_tlToolFilter || _tlExactName(r) === _tlToolFilter);
  });

  const doneCount = _tlData.filter(r => _tlNormalizedStatus(r) === "done").length;
  const runningCount = _tlData.filter(r => _tlNormalizedStatus(r) === "running").length;
  const skippedCount = _tlData.filter(r => _tlNormalizedStatus(r) === "skipped").length;
  const errCount = _tlData.filter(r => _tlNormalizedStatus(r) === "error").length;
  const timeoutCount = _tlData.filter(r => _tlNormalizedStatus(r) === "timeout").length;
  const totalDur = _tlData.reduce((s, r) => s + (Number(r.duration) || 0), 0);

  const groupsMap = new Map();
  filtered.forEach(r => {
    const key = _tlGroupKey(r);
    if (!groupsMap.has(key)) {
      groupsMap.set(key, {
        key,
        module: r.module || "unknown",
        tool: _tlExactName(r),
        binary: r.binary || r.script || "",
        runs: [],
      });
    }
    groupsMap.get(key).runs.push(r);
  });
  const groups = [...groupsMap.values()].map(g => {
    g.runs.sort((a, b) => String(b.ts || "").localeCompare(String(a.ts || "")));
    g.done = g.runs.filter(r => _tlNormalizedStatus(r) === "done").length;
    g.error = g.runs.filter(r => _tlNormalizedStatus(r) === "error").length;
    g.timeout = g.runs.filter(r => _tlNormalizedStatus(r) === "timeout").length;
    g.skipped = g.runs.filter(r => _tlNormalizedStatus(r) === "skipped").length;
    g.running = g.runs.filter(r => _tlNormalizedStatus(r) === "running").length;
    g.duration = g.runs.reduce((s, r) => s + (Number(r.duration) || 0), 0);
    g.latest = g.runs[0] || {};
    return g;
  }).sort((a, b) => {
    const scoreA = (a.error * 1000) + (a.timeout * 500) + (a.running * 250) + (a.skipped * 50);
    const scoreB = (b.error * 1000) + (b.timeout * 500) + (b.running * 250) + (b.skipped * 50);
    return (scoreB - scoreA) || String(b.latest.ts || "").localeCompare(String(a.latest.ts || ""));
  });

  const totPg = Math.max(1, Math.ceil(groups.length / TLP));
  _tlPage = Math.max(1, Math.min(_tlPage, totPg));
  const start = (_tlPage - 1) * TLP;
  const pageGroups = groups.slice(start, start + TLP);
  const groupCards = pageGroups.map(_tlGroupCard).join("");

  const errBadge = errCount > 0
    ? `<span class="tl-err-badge" title="${errCount} tool error(s)">${errCount} error${errCount>1?'s':''}</span>` : "";
  const warnBadge = timeoutCount > 0
    ? `<span class="tl-warn-badge">${timeoutCount} timeout${timeoutCount>1?'s':''}</span>` : "";
  const pNums = _tlPager(totPg);

  el.innerHTML = `
    <div class="section-shell">
    <div class="section-head">
      <div class="section-head-main">
        <div class="section-kicker">Execution Logs ${errBadge}${warnBadge}</div>
        <div class="section-title">Ferramentas executadas neste projeto</div>
        <div class="section-sub">Agrupado pelo nome exato do executÃ¡vel/script que rodou. Clique em <code>dig</code>, <code>subfinder</code>, <code>httpx</code> etc. para ver comandos; clique em uma execuÃ§Ã£o para abrir stdout/stderr completo.</div>
      </div>
      <div class="section-actions"><span class="sec-cnt">${groups.length} grupos Â· ${filtered.length} runs</span></div>
    </div>
    <div class="jobs-summary tl-summary">
      ${_tlKpi("Total", _tlData.length, "Runs registrados")}
      ${_tlKpi("Passou", doneCount, "Status done", "ok")}
      ${_tlKpi("Erro", errCount, "Exit/code failure", errCount ? "error" : "")}
      ${_tlKpi("Pulado", skippedCount, "Com justificativa")}
      ${_tlKpi("Rodando", runningCount, "Ainda sem finish", runningCount ? "running" : "")}
      ${_tlKpi("Tempo", _fmtDuration(totalDur), "Soma das execuÃ§Ãµes")}
    </div>
    <div class="tl-bar">
      <input class="tl-input grow" placeholder="Buscar por mÃ³dulo, ferramenta, comando, status..." oninput="_tlFilter=this.value;_tlPage=1;renderToolLogs(document.getElementById('tab-toollogs'))" value="${esc(_tlFilter)}">
      <select class="fi" onchange="_tlStatusFilter=this.value;_tlPage=1;renderToolLogs(document.getElementById('tab-toollogs'))">
        <option value="" ${!_tlStatusFilter ? "selected" : ""}>Todos status</option>
        <option value="done" ${_tlStatusFilter==="done" ? "selected" : ""}>Passou</option>
        <option value="error" ${_tlStatusFilter==="error" ? "selected" : ""}>Erro</option>
        <option value="timeout" ${_tlStatusFilter==="timeout" ? "selected" : ""}>Timeout</option>
        <option value="skipped" ${_tlStatusFilter==="skipped" ? "selected" : ""}>Pulado</option>
        <option value="running" ${_tlStatusFilter==="running" ? "selected" : ""}>Rodando</option>
      </select>
      <select class="fi" onchange="_tlToolFilter=this.value;_tlPage=1;renderToolLogs(document.getElementById('tab-toollogs'))">
        <option value="" ${!_tlToolFilter ? "selected" : ""}>Todas ferramentas/scripts</option>
        ${tools.map(t => `<option value="${escAttr(t)}" ${_tlToolFilter===t ? "selected" : ""}>${esc(t)}</option>`).join("")}
      </select>
      <button class="tl-refresh" onclick="loadToolLogs()">Refresh</button>
      <button class="tl-clear" onclick="clearToolLogs()">Clear</button>
      ${errCount > 0 ? `<button class="tl-filter-err" onclick="_tlStatusFilter='error';_tlPage=1;renderToolLogs(document.getElementById('tab-toollogs'))">Errors only</button>` : ""}
      <span class="tl-count">${groups.length} grupos / ${filtered.length} execuÃ§Ãµes</span>
    </div>
    <div class="tl-groups">
      ${groupCards || '<div class="empty"><b>Nenhuma ferramenta registrada</b>Nenhum comando foi capturado ainda para este projeto.</div>'}
      <div class="pager">
        <span class="pager-info">${groups.length ? `${start+1}-${Math.min(start+TLP, groups.length)} of ${groups.length} grupos` : "0 of 0"}</span>
        <div class="pager-btns">
          <button class="pb" onclick="tlPageNav(-1)" ${_tlPage<=1 ? "disabled" : ""}>Prev</button>
          <span>${pNums}</span>
          <button class="pb" onclick="tlPageNav(1)" ${_tlPage>=totPg ? "disabled" : ""}>Next</button>
        </div>
      </div>
    </div>
    </div>`;
}

function _tlGroupKey(r) {
  return _tlExactName(r);
}

function _tlExactName(r) {
  return r.display_name || _baseName(r.binary || r.script || "") || r.tool || "?";
}

function _baseName(path) {
  const value = String(path || "").replace(/\\/g, "/");
  return value.split("/").filter(Boolean).pop() || "";
}

function _tlGroupDomId(key) {
  return "tlgrp-" + btoa(unescape(encodeURIComponent(key))).replace(/[^a-zA-Z0-9]/g, "");
}

function _tlGroupCard(group) {
  const key = group.key;
  const open = _tlOpenGroups.has(key);
  const latestStatus = _tlNormalizedStatus(group.latest || {});
  const healthClass = group.error ? "error" : group.timeout ? "warn" : group.running ? "running" : group.skipped ? "skipped" : "ok";
  const statusBadge = group.error
    ? `<span class="tl-badge-err">${group.error} erro${group.error>1?"s":""}</span>`
    : group.timeout
    ? `<span class="tl-badge-warn">${group.timeout} timeout${group.timeout>1?"s":""}</span>`
    : group.running
    ? `<span class="tl-badge-run">${group.running} rodando</span>`
    : group.skipped
    ? `<span class="tl-badge-dim">${group.skipped} pulado${group.skipped>1?"s":""}</span>`
    : `<span class="tl-badge-ok">passou</span>`;
  const latest = group.latest || {};
  const runsHtml = open ? _tlGroupRuns(group.runs) : "";
  return `
    <div class="tl-group-card ${healthClass}">
      <button type="button" class="tl-group-head" onclick="_tlToggleGroup('${escAttr(key)}')">
        <div class="tl-group-main">
          <div class="tl-group-title">
            <span class="tl-group-tool">${esc(group.tool)}</span>
          </div>
          <div class="tl-group-sub">
            <span class="tl-group-module">${esc(group.module)}</span>
            ${group.binary ? `<span class="tl-group-path">${esc(group.binary)}</span>` : ""}
            <span>${esc(latest.cmd || "sem comando")}</span>
          </div>
        </div>
        <div class="tl-group-metrics">
          ${statusBadge}
          <span class="tl-pill">${group.runs.length} execuÃ§Ãµes</span>
          <span class="tl-pill">${_fmtDuration(group.duration)}</span>
          <span class="tl-pill">${esc(_fmtToolTs(latest.ts))}</span>
          <span class="tl-caret">${open ? "âˆ’" : "+"}</span>
        </div>
      </button>
      <div class="tl-group-body" id="${_tlGroupDomId(key)}" style="display:${open ? "block" : "none"}">
        ${runsHtml}
      </div>
    </div>`;
}

function _tlGroupRuns(runs) {
  const rows = runs.map(r => {
    const st = _tlNormalizedStatus(r);
    const runId = r.run_id != null ? String(r.run_id) : "";
    let clickable = "";
    if (runId) {
      clickable = ` onclick="event.stopPropagation();openToolLogModal('${esc(runId)}')"`;
    } else {
      const virtualId = "v" + (_tlVirtualRuns.size + 1);
      _tlVirtualRuns.set(virtualId, r);
      clickable = ` onclick="event.stopPropagation();openToolLogVirtual('${virtualId}')"`;
    }
    const outBits = [
      r.stdout_tail ? `<span class="tl-io tl-stdout-dot">stdout</span>` : "",
      r.stderr_tail ? `<span class="tl-io tl-stderr-dot">stderr</span>` : "",
    ].filter(Boolean).join(" ");
    return `<tr class="tl-clickable"${clickable}>
      <td class="tl-ts">${esc(_fmtToolTs(r.ts))}</td>
      <td class="tl-tool">${esc(_tlExactName(r))}</td>
      <td><span class="${_tlStatusClass(st)}">${esc(st)}</span></td>
      <td class="tl-exit">${r.exit_code != null ? esc(r.exit_code) : "â€”"}</td>
      <td class="tl-dur">${_fmtDuration(r.duration)}</td>
      <td class="tl-cmd"><div class="tl-cmd-main">${esc(r.cmd || "â€”")}</div>${outBits ? `<div class="tl-io-row">${outBits}</div>` : ""}</td>
    </tr>`;
  }).join("");
  return `
    <div class="tl-wrap">
      <table class="tl-table tl-runs-table">
        <thead><tr><th>Quando</th><th>Ferramenta/script</th><th>Status</th><th>Exit</th><th>DuraÃ§Ã£o</th><th>Comando / output</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function _tlToggleGroup(key) {
  if (_tlOpenGroups.has(key)) _tlOpenGroups.delete(key);
  else _tlOpenGroups.add(key);
  renderToolLogs(document.getElementById("tab-toollogs"));
}

function _tlNormalizedStatus(r) {
  if (r.status === "timeout") return "timeout";
  if (r.status === "running") return "running";
  if (r.status === "skipped" || r.status === "not_run") return "skipped";
  if (r.status === "error" || (r.exit_code != null && Number(r.exit_code) !== 0)) return "error";
  if (r.status === "done" || Number(r.exit_code) === 0) return "done";
  return r.status || "unknown";
}

function _tlStatusClass(st) {
  if (st === "error") return "tl-badge-err";
  if (st === "timeout") return "tl-badge-warn";
  if (st === "done") return "tl-badge-ok";
  if (st === "running") return "tl-badge-run";
  if (st === "skipped") return "tl-badge-dim";
  return "tl-badge-dim";
}

function _fmtDuration(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return "â€”";
  if (n >= 3600) return (n / 3600).toFixed(1) + "h";
  if (n >= 60) return (n / 60).toFixed(1) + "m";
  return n.toFixed(1) + "s";
}

function _fmtToolTs(value) {
  if (!value) return "â€”";
  return String(value).replace("T", " ").slice(0, 19);
}

function _tlKpi(label, value, sub, mood) {
  const cls = mood ? ` ${mood}` : "";
  return `<div class="job-kpi tl-kpi${cls}">
    <div class="job-kpi-label">${esc(label)}</div>
    <div class="job-kpi-value">${esc(value)}</div>
    <div class="job-kpi-sub">${esc(sub || "")}</div>
  </div>`;
}

function _tlPager(totPg) {
  let out = "";
  for (let i = Math.max(1, _tlPage - 2); i <= Math.min(totPg, _tlPage + 2); i++) {
    out += `<button class="pb${i === _tlPage ? " active" : ""}" onclick="tlGoPage(${i})">${i}</button>`;
  }
  return out;
}

function tlPageNav(delta) {
  _tlPage += delta;
  renderToolLogs(document.getElementById("tab-toollogs"));
}

function tlGoPage(page) {
  _tlPage = page;
  renderToolLogs(document.getElementById("tab-toollogs"));
}

async function clearToolLogs() {
  const cid = state.currentId;
  if (!cid) return;
  await fetch(`/api/recon/${cid}/tool-logs`, {method:"DELETE", headers: _authHeaders()});
  _tlData = [];
  _tlFilter = "";
   document.getElementById("tc-toollogs").textContent = "";
   renderToolLogs(document.getElementById("tab-toollogs"));
 }

// â”€â”€ Tool Execution Detail Modal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function _renderToolLogDetail(d) {
  const titleEl = document.getElementById("tool-err-title");
  const bodyEl  = document.getElementById("tool-err-body");
  const status = _tlNormalizedStatus(d);
  const statusBadge = `<span class="${_tlStatusClass(status)}">${esc(status)}</span>`;
  const exitBadge = d.exit_code !== null && d.exit_code !== undefined
    ? (d.exit_code === 0 ? `<span class="tl-badge-ok">exit ${d.exit_code}</span>` : `<span class="tl-badge-err">exit ${d.exit_code}</span>`)
    : `<span class="tl-badge-dim">exit â€”</span>`;
  const durStr = _fmtDuration(d.duration);
  const stderrBlock = d.stderr_tail
    ? `<div style="margin-top:10px"><div class="tl-modal-label err">STDERR / erro</div><pre class="tool-err-pre">${esc(d.stderr_tail)}</pre></div>`
    : `<div style="margin-top:8px;color:var(--text3);font-size:.68rem">No stderr/error output captured.</div>`;
  const stdoutText = d.stdout_tail
    || (d.kind === "module"
      ? "MÃ³dulo interno nÃ£o retornou payload detalhado."
      : "Comando executou e nÃ£o escreveu nada em stdout. Isso Ã© normal para consultas sem resultado, por exemplo dig CAA/SRV/CNAME sem registro.");
  const stdoutBlock = `<div style="margin-top:10px"><div class="tl-modal-label ok">STDOUT / output</div><pre class="tool-err-pre">${esc(stdoutText)}</pre></div>`;
  const exactName = _tlExactName(d);
  const exactPath = d.binary || d.script || (Array.isArray(d.argv) ? d.argv[0] : "");
  const commandLabel = d.kind === "module" ? "Module execution" : "Command";

  titleEl.textContent = exactName;
  bodyEl.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px">
      <div><span style="color:var(--text3);font-size:.68rem">Ferramenta / script / mÃ³dulo</span><div style="margin-top:2px;color:var(--yellow);font-family:var(--mono);font-weight:700">${esc(exactName)}</div></div>
      <div><span style="color:var(--text3);font-size:.68rem">MÃ³dulo</span><div style="margin-top:2px;color:var(--teal);font-family:var(--mono)">${esc(d.module || "?")}</div></div>
      <div style="grid-column:1/-1"><span style="color:var(--text3);font-size:.68rem">Caminho exato</span><div style="margin-top:2px;color:var(--text);font-family:var(--mono);font-size:.68rem;word-break:break-all">${esc(exactPath || (d.kind === "module" ? "internal pipeline module" : "?"))}</div></div>
      <div><span style="color:var(--text3);font-size:.68rem">Status</span><div style="margin-top:2px">${statusBadge}</div></div>
      <div><span style="color:var(--text3);font-size:.68rem">Exit Code</span><div style="margin-top:2px">${exitBadge}</div></div>
      <div><span style="color:var(--text3);font-size:.68rem">Duration</span><div style="margin-top:2px;color:var(--text);font-family:var(--mono)">${durStr}</div></div>
      <div><span style="color:var(--text3);font-size:.68rem">Started</span><div style="margin-top:2px;color:var(--text);font-family:var(--mono);font-size:.68rem">${esc(d.ts || "?")}</div></div>
      <div style="grid-column:1/-1"><span style="color:var(--text3);font-size:.68rem">Finished</span><div style="margin-top:2px;color:var(--text);font-family:var(--mono);font-size:.68rem">${esc(d.finished_at || "?")}</div></div>
    </div>
    <div style="margin-bottom:8px">
      <div style="color:var(--text3);font-size:.68rem;margin-bottom:3px">${commandLabel}</div>
      <pre class="tool-err-pre" style="background:rgba(0,0,0,0.3);border-color:rgba(255,255,255,0.1)">${esc(d.cmd || "?")}</pre>
    </div>
    ${stderrBlock}
    ${stdoutBlock}
  `;
}

async function openToolLogModal(runId) {
  const cid = state.currentId;
  if (!cid || !runId) return;
  const overlay = document.getElementById("modal-tool-err");
  const titleEl = document.getElementById("tool-err-title");
  const bodyEl  = document.getElementById("tool-err-body");
  if (!overlay) return;

  titleEl.textContent = "Loading execution log...";
  bodyEl.innerHTML = `<div style="color:var(--text3);padding:20px">Fetching tool run #${runId}...</div>`;
  overlay.classList.add("show");

  try {
    const r = await fetch(`/api/recon/${cid}/tool-logs/${runId}`, {headers: _authHeaders()});
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json();
    _renderToolLogDetail(d);
  } catch(e) {
    titleEl.textContent = "Error loading execution log";
    bodyEl.innerHTML = `<div style="color:var(--red);padding:12px">Failed to load tool run details: ${esc(e.message)}</div>`;
  }
}

function openToolLogVirtual(virtualId) {
  const d = _tlVirtualRuns.get(virtualId);
  if (!d) return;
  const overlay = document.getElementById("modal-tool-err");
  if (!overlay) return;
  overlay.classList.add("show");
  _renderToolLogDetail(d);
}

async function openToolErrModal(runId) {
  return openToolLogModal(runId);
}

function closeToolErrModal() {
  document.getElementById("modal-tool-err").classList.remove("show");
}


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  LIVE TERMINAL TAB â€” real-time verbose tool output
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Shows actual stdout/stderr from tools as they execute, grouped by module.
// Polls globally while a pipeline is running, renders only when tab is open.
let _ltPoll = null;
let _ltPaused = false;
let _ltActiveCid = null;
let _ltSince = 0;          // Unix timestamp for incremental live output fetching
let _ltCmdLog = [];        // command invocations from tool-logs
let _ltCmdLastTs = "";     // last seen command timestamp

// Grouped output: { module: [{ts, stream, line}, ...] }
let _ltModules = {};       // module -> array of output lines + commands

function _ltEnsurePolling() {
  const activeCid = Object.keys(pipelineState).find(cid => {
    const ps = pipelineState[cid];
    return ps && (ps.status === "running" || ps.status === "queued");
  });
  if (!activeCid) {
    if (_ltPoll) { clearInterval(_ltPoll); _ltPoll = null; _ltActiveCid = null; }
    return;
  }
  if (_ltActiveCid !== activeCid) {
    _ltActiveCid = activeCid;
    _ltSince = Date.now() / 1000;
    _ltCmdLog = [];
    _ltCmdLastTs = "";
    _ltModules = {};
  }
  if (_ltPoll) return;
  _ltPoll = setInterval(() => _fetchLT(), 1500);
  _fetchLT();
}

async function _fetchLT() {
  if (_ltPaused || !_ltActiveCid) return;
  let hasNew = false;
  // 1) Fetch new command invocations from tool-logs
  try {
    const r = await fetch("/api/recon/" + _ltActiveCid + "/tool-logs", {headers: _authHeaders()});
    if (r.ok) {
      const all = await r.json();
      for (let i = all.length - 1; i >= 0; i--) {
        if (all[i].ts <= _ltCmdLastTs) break;
        const l = all[i];
        _ltCmdLog.unshift(l);
        // Record command start in module output
        const mod = l.module || "?";
        if (!_ltModules[mod]) _ltModules[mod] = [];
        if (!_ltModules[mod].some(e => e._cmd === l.cmd)) {
          _ltModules[mod].push({ts: l.ts, stream: "cmd", line: "$ "+l.cmd, _cmd: l.cmd,
            status: l.status, exit_code: l.exit_code, duration: l.duration, run_id: l.run_id, tool: l.tool});
        }
        hasNew = true;
      }
      if (all.length > 0) _ltCmdLastTs = all[all.length-1].ts;
    }
  } catch(e) {}

  // 2) Fetch real-time stdout/stderr output
  try {
    const r = await fetch("/api/live-output/" + _ltActiveCid + "?since=" + _ltSince, {headers: _authHeaders()});
    if (r.ok) {
      const {lines, ts} = await r.json();
      if (ts) _ltSince = ts;
      for (const l of lines) {
        const mod = l.module || "?";
        if (!_ltModules[mod]) _ltModules[mod] = [];
        _ltModules[mod].push({ts: l.ts, stream: l.stream, line: l.line});
        hasNew = true;
      }
    }
  } catch(e) {}

  if (hasNew) {
    _renderLTTerminal();
    const badge = document.getElementById("lt-live-badge");
    if (badge) { badge.style.display = "inline-block"; setTimeout(() => badge.style.display = "none", 1500); }
  }
  const cnt = document.getElementById("lt-cnt");
  if (cnt) {
    const total = Object.values(_ltModules).reduce((s,arr) => s+arr.length, 0);
    cnt.textContent = total + " lines" + (_ltPaused ? " (paused)" : "");
  }
}

function _lineCount() {
  return Object.values(_ltModules).reduce((s,arr) => s+arr.length, 0);
}

function _renderLTTerminal() {
  const body = document.getElementById("lt-body");
  if (!body) return;
  const wasAtBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 50;

  // Sort modules by first timestamp
  const sortedMods = Object.entries(_ltModules).sort((a,b) => {
    const ta = a[1].length ? a[1][0].ts : "z";
    const tb = b[1].length ? b[1][0].ts : "z";
    return ta < tb ? -1 : ta > tb ? 1 : 0;
  });

  let html = "";
  for (const [mod, entries] of sortedMods) {
    // Module header
    const lastEntry = entries[entries.length-1];
    const isRunning = lastEntry && lastEntry.stream === "stdout" && lastEntry.status !== "done" && lastEntry.status !== "error";
    const headerCls = isRunning ? "lt-mod-running" : "lt-mod-done";

    // Collapse/expand toggle
    const modId = "ltmod-" + mod.replace(/[^a-z0-9]/gi, "_");
    html += `<div class="lt-module ${headerCls}" id="${modId}-wrap">
      <div class="lt-mod-hdr" onclick="document.getElementById('${modId}-body').classList.toggle('lt-collapsed'); this.querySelector('.lt-mod-arr').textContent = document.getElementById('${modId}-body').classList.contains('lt-collapsed') ? 'â–¶' : 'â–¼'">
        <span class="lt-mod-arr">â–¼</span>
        <span class="lt-mod-name">[${esc(mod)}]</span>
        <span class="lt-mod-tool">${lastEntry && lastEntry.tool ? esc(lastEntry.tool) : ""}</span>
        ${lastEntry && lastEntry.status ? `<span class="lt-status ${lastEntry.status==='error'?'err':lastEntry.status==='timeout'?'timeout':'ok'}">${esc(lastEntry.status)}</span>` : isRunning ? `<span class="lt-status ok">running</span>` : ""}
        ${lastEntry && lastEntry.duration != null ? `<span class="lt-mod-dur">${lastEntry.duration.toFixed(1)}s</span>` : ""}
        <span class="lt-mod-lines">${entries.length} lines</span>
      </div>
      <div class="lt-mod-body" id="${modId}-body">`;

    // Module body â€” stdout/stderr lines
    for (const e of entries.slice(-200)) {
      if (e.stream === "cmd") {
        html += `<div class="lt-line lt-cmd-line">
          <span class="ts">${(e.ts||"").slice(11,19)}</span>
          <span class="lt-prom">$</span>
          <span class="lt-cmd-full">${esc(e.line)}</span>
        </div>`;
      } else if (e.stream === "stdout") {
        html += `<div class="lt-line lt-stdout">${esc(e.line)}</div>`;
      } else if (e.stream === "stderr") {
        html += `<div class="lt-line lt-stderr">${esc(e.line)}</div>`;
      }
    }
    html += `</div></div>`;
  }

  body.innerHTML = html + (_ltPaused ? `<div class="lt-paused">â¸ Paused â€” ${_lineCount()} lines captured</div>` : "") +
    (_ltPaused ? "" : `<div style="height:1px" id="lt-anchor"></div>`);

  if (wasAtBottom) {
    const anchor = document.getElementById("lt-anchor");
    if (anchor) anchor.scrollIntoView({behavior: "smooth", block: "end"});
    else body.scrollTop = body.scrollHeight;
  }
}

function renderLiveTerminal(cid) {
  const el = document.getElementById("tab-terminal");
  if (!el) return;
  _ltActiveCid = cid;
  _ltEnsurePolling();
  el.innerHTML = `
    <div class="section-shell">
      <div class="section-head">
        <div class="section-head-main">
          <div class="section-kicker">Live Terminal</div>
          <div class="section-title">Verbose tool output â€” stdout & stderr in real time</div>
          <div class="section-sub">Each module is a collapsible process. Green = stdout, Red = stderr. Click module headers to expand/collapse.</div>
        </div>
        <div class="section-actions">
          <span class="sec-cnt" id="lt-cnt">${_lineCount()} lines</span>
        </div>
      </div>
      <div class="lt-wrap">
        <div class="lt-hdr">
          <div class="lt-dots"><span class="r"></span><span class="y"></span><span class="g"></span></div>
          <span>scantrely@asm:~$ pipeline monitor â€” ${esc(cid)}</span>
          <span style="margin-left:auto;display:flex;gap:8px">
            <span id="lt-live-badge" style="display:none;color:#4ade80;font-weight:600">â¬¤ LIVE</span>
            <button id="lt-pause-btn" class="btn btn-secondary btn-icon" onclick="toggleLTPause()">${_ltPaused ? 'â–¶ Resume' : 'â¸ Pause'}</button>
            <button class="btn btn-secondary btn-icon" onclick="_ltModules={};_ltSince=Date.now()/1000;_renderLTTerminal()" aria-label="Clear terminal">â†» Clear</button>
          </span>
        </div>
        <div class="lt-body" id="lt-body"></div>
      </div>
    </div>`;
  _renderLTTerminal();
}

function startLTPoll(cid) { _ltActiveCid = cid; _ltEnsurePolling(); }
function stopLTPoll() { if (_ltPoll) { clearInterval(_ltPoll); _ltPoll = null; } }
function toggleLTPause() {
  _ltPaused = !_ltPaused;
  const btn = document.getElementById("lt-pause-btn");
  if (btn) btn.textContent = _ltPaused ? "â–¶ Resume" : "â¸ Pause";
}
async function fetchLT(cid) { _ltActiveCid = cid; return _fetchLT(); }


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  ALERTS TAB
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function renderAlertsTab(co) {
  const el = document.getElementById("tab-alerts");
  if (!el) return;
  el.innerHTML = `<div class="skel skel-card"></div><div class="skel skel-card"></div>`;

  try {
    const r = await fetch(`/api/alerts/${co.id}`, {headers:_authHeaders()});
    if (!r.ok) { el.innerHTML = `<div class="diff-empty">Alerts unavailable</div>`; return; }
    const alerts = await r.json();
    const alertList = alerts.alerts || alerts || [];
    var badge = document.getElementById("tc-alerts");
    if (badge) badge.textContent = alertList.length || "";

    const rulesR = await fetch(`/api/alert-rules/${co.id}`, {headers:_authHeaders()});
    const rules = rulesR.ok ? await rulesR.json() : [];

    let html = `<div class="section-hdr"><h3>ðŸš¨ Alert Rules</h3>
      <button class="btn btn-secondary" style="font-size:.68rem;padding:4px 10px" onclick="addAlertRule('${esc(co.id)}')">ï¼‹ Add Rule</button></div>`;

    for (const rule of (rules.rules || rules || [])) {
      const chs = (rule.channels || []).map(c => `<span class="channel-badge ${c}">${c}</span>`).join(' ');
      html += `<div class="rule-row">
        <div><div class="rule-name">${esc(rule.name||rule.rule_type)}</div><div class="rule-type">${esc(rule.rule_type)} Â· ${chs || 'no channels'}</div></div>
        <div style="display:flex;align-items:center;gap:10px">
          <label class="toggle"><input type="checkbox" ${rule.enabled ? 'checked' : ''} data-rid="${esc(rule.id)}" onchange="toggleAlertRule('${esc(co.id)}','${esc(rule.id)}',this.checked)"><span class="slider"></span></label>
          <button class="rule-del" title="Remove rule" onclick="deleteAlertRule('${esc(co.id)}','${esc(rule.id)}')">âœ•</button>
        </div>
      </div>`;
    }
    if (!(rules.rules || rules || []).length) html += `<div class="diff-empty">No alert rules configured</div>`;

    html += `<div class="section-hdr" style="margin-top:24px"><h3>ðŸ“‹ Recent Alerts</h3><span class="section-count">${(alerts.alerts||alerts||[]).length}</span></div>`;
    html += `<div class="alert-list">`;
    for (const a of (alerts.alerts || alerts || []).slice(0, 50)) {
      html += `<div class="alert-item">
        <div class="alert-sev ${a.severity}"></div>
        <div class="alert-body">
          <div class="alert-title">${esc(a.title)}</div>
          <div class="alert-desc">${esc(a.description||'')}</div>
          <div class="alert-ts">${esc(a.created_at||a.ts||'')}</div>
        </div>
        ${!a.acknowledged ? `<button class="alert-ack" onclick="ackAlert('${esc(co.id)}',${a.id})">Acknowledge</button>` : `<span style="font-size:.68rem;color:var(--text3)">âœ“ Acked</span>`}
      </div>`;
    }
    if (!(alerts.alerts || alerts || []).length) html += `<div class="diff-empty">No alerts yet â€” they appear after scan diffs</div>`;
    html += `</div>`;

    el.innerHTML = html;
  } catch(e) { el.innerHTML = `<div class="diff-empty">Error: ${esc(e.message)}</div>`; }
}

async function toggleAlertRule(cid, rid, enabled) {
  await fetch(`/api/alert-rules/${cid}/${rid}`, {method:'PUT', headers:{'Content-Type':'application/json', ..._authHeaders()}, body:JSON.stringify({enabled})});
}

async function addAlertRule(cid) {
  const name = prompt("Rule name (e.g. 'New Hosts'):");
  if (!name) return;
  const type = prompt("Rule type: new_host, new_port, new_tech, status_change, waf_change, cert_expiring, cve_critical, supply_chain_critical");
  if (!type) return;
  const channels = prompt("Channels (comma-separated): slack, discord, email, webhook, jira, linear","slack");
  const r = await fetch(`/api/alert-rules/${cid}`, {method:'POST', headers:{'Content-Type':'application/json', ..._authHeaders()}, body:JSON.stringify({name, rule_type:type, channels:(channels||'').split(',').map(c=>c.trim()).filter(Boolean)})});
  const data = await r.json().catch(()=>({}));
  if (!r.ok || data.error) { alert(data.error || 'Erro ao criar regra'); return; }
  reloadServerData().then(() => renderCompanyView(allCompanies().find(c=>c.id===cid)));
}

async function deleteAlertRule(cid, rid) {
  if (!confirm('Remover esta regra de alerta?')) return;
  await fetch(`/api/alert-rules/${cid}/${rid}`, {method:'DELETE', headers:_authHeaders()});
  reloadServerData().then(() => renderCompanyView(allCompanies().find(c=>c.id===cid)));
}

async function ackAlert(cid, aid) {
  await fetch(`/api/alerts/${cid}/${aid}/ack`, {method:'POST', headers:_authHeaders()});
  reloadServerData().then(() => renderCompanyView(allCompanies().find(c=>c.id===cid)));
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  ASSET TIMELINE TAB
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function renderTimelineTab(co) {
  const el = document.getElementById("tab-timeline");
  if (!el) return;
  el.innerHTML = `<div class="skel skel-card"></div><div class="skel skel-card"></div>`;

  try {
    const r = await fetch(`/api/timeline/${co.id}?limit=100`, {headers:_authHeaders()});
    if (!r.ok) { el.innerHTML = `<div class="diff-empty">Timeline unavailable</div>`; return; }
    const entries = await r.json();

    const timelineList = entries.timeline || entries || [];
    var tbadge = document.getElementById("tc-timeline");
    if (tbadge) tbadge.textContent = timelineList.length || "";
    let html = `<div class="section-hdr"><h3>ðŸ“Š Asset Timeline</h3><span class="section-count">${timelineList.length} snapshots</span></div>`;
    html += `<div class="timeline-list">`;
    for (const e of timelineList.slice(0, 80)) html += _timelineRow(e);
    if (!(entries.timeline || entries || []).length) html += `<div class="diff-empty">No timeline data â€” run a scan first</div>`;
    html += `</div>`;
    el.innerHTML = html;
  } catch(e) { el.innerHTML = `<div class="diff-empty">Error: ${esc(e.message)}</div>`; }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  SCAN DIFF TAB
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function renderDiffTab(co) {
  const el = document.getElementById("tab-diff");
  if (!el) return;
  el.innerHTML = `<div class="skel skel-card"></div><div class="skel skel-card"></div>`;

  try {
    const r = await fetch(`/api/diff/${co.id}`, {headers:_authHeaders()});
    if (!r.ok) { el.innerHTML = `<div class="diff-empty">Diff unavailable</div>`; return; }
    const diff = await r.json();

    if (diff.error) {
      el.innerHTML = `<div class="diff-empty">${esc(diff.error)}${diff.current_hosts ? ` (${diff.current_hosts} hosts in current scan)` : ''}</div>`;
      return;
    }

    // Handle both SQLite format (new_hosts/removed_hosts) and PostgreSQL format (new/removed/changed)
    const news = (diff.new || []).map(h => typeof h === 'string' ? {host:h} : h);
    const removed = (diff.removed || []).map(h => typeof h === 'string' ? {host:h} : h);
    const changed = diff.changed || [];
    // SQLite port_changes â†’ adapt to changed format
    if (diff.port_changes && !changed.length) {
      for (const pc of diff.port_changes) {
        changed.push({host: pc.host, changes: {ports: {from: pc.removed||[], to: pc.added||[]}}});
      }
    }

    var dbadge = document.getElementById("tc-diff");
    if (dbadge) { var dc = news.length + removed.length + changed.length; dbadge.textContent = dc || ""; }
    let html = `<div class="section-hdr"><h3>ðŸ” Scan Diff</h3><span class="section-count">${diff.curr_ts ? esc(diff.curr_ts.slice(0,16)) : 'vs previous'}</span></div>`;

    html += `<div class="stats-row">
      <div class="stat-card"><div class="stat-value" style="color:var(--green)">+${news.length}</div><div class="stat-label">New Hosts</div></div>
      <div class="stat-card"><div class="stat-value" style="color:var(--red)">-${removed.length}</div><div class="stat-label">Removed</div></div>
      <div class="stat-card"><div class="stat-value" style="color:var(--yellow)">~${changed.length}</div><div class="stat-label">Changed</div></div>
    </div>`;

    if (news.length) {
      html += `<div class="diff-section"><h4 style="color:var(--green);font-size:.82rem;margin-bottom:8px">ï¼‹ New (${news.length})</h4>`;
      for (const h of news.slice(0, 30)) html += `<div class="diff-item"><div class="diff-host">${esc(h.host||'?')}</div>${h.ip ? `<div class="diff-field"><span class="df-label">IP:</span><span class="df-new">${esc(h.ip)}</span></div>`:''}</div>`;
      html += `</div>`;
    }

    if (removed.length) {
      html += `<div class="diff-section"><h4 style="color:var(--red);font-size:.82rem;margin-bottom:8px">âˆ’ Removed (${removed.length})</h4>`;
      for (const h of removed.slice(0, 30)) html += `<div class="diff-item"><div class="diff-host" style="color:var(--red)">${esc(h.host||'?')}</div></div>`;
      html += `</div>`;
    }

    if (changed.length) {
      html += `<div class="diff-section"><h4 style="color:var(--yellow);font-size:.82rem;margin-bottom:8px">~ Changed (${changed.length})</h4>`;
      for (const item of changed.slice(0, 30)) {
        html += `<div class="diff-item"><div class="diff-host">${esc(item.host)}</div>`;
        for (const [field, vals] of Object.entries(item.changes||{})) {
          html += `<div class="diff-field"><span class="df-label">${esc(field)}:</span><span class="df-old">${esc(JSON.stringify(vals.from))}</span><span class="df-arr">â†’</span><span class="df-new">${esc(JSON.stringify(vals.to))}</span></div>`;
        }
        html += `</div>`;
      }
      html += `</div>`;
    }

    if (!news.length && !removed.length && !changed.length) html += `<div class="diff-empty">No changes detected between scans</div>`;
    el.innerHTML = html;
  } catch(e) { el.innerHTML = `<div class="diff-empty">Error: ${esc(e.message)}</div>`; }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  FALSE POSITIVE MANAGER
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

function openFPModal(host, title, cid) {
  window._fpHost  = host;
  window._fpTitle = title;
  window._fpCid   = cid || window._fpCurrentCid || "";
  document.getElementById("fp-host").textContent  = host || "(any host)";
  document.getElementById("fp-title").textContent = title;
  document.getElementById("fp-reason").value = "";
  document.getElementById("fp-error").style.display = "none";
  document.getElementById("modal-fp").classList.add("show");
}

function closeFPModal() {
  document.getElementById("modal-fp").classList.remove("show");
}

async function submitFP() {
  const cid    = window._fpCid;
  const reason = document.getElementById("fp-reason").value.trim();
  const errEl  = document.getElementById("fp-error");
  if (!reason) { errEl.textContent = "Reason is required."; errEl.style.display = "block"; return; }
  if (!cid)    { errEl.textContent = "Company not identified."; errEl.style.display = "block"; return; }
  try {
    const r = await fetch(`/api/whitelist/${cid}`, {
      method: "POST",
      headers: {..._authHeaders(), "Content-Type": "application/json"},
      body: JSON.stringify({host: window._fpHost, title: window._fpTitle, reason}),
    });
    if (!r.ok) throw await _apiErr(r);
    closeFPModal();
    // Remove finding card from current view
    const co = allCompanies().find(c => c.id === cid);
    if (co) renderFindingsTab(co);
    showToast("Finding marked as false positive.");
  } catch(e) {
    errEl.textContent = "Error: " + e.message;
    errEl.style.display = "block";
  }
}

async function loadSuppressedFindings(cid) {
  const tab = document.getElementById("tab-suppressed");
  if (!tab) return;
  tab.innerHTML = `<div class="skel skel-card"></div><div class="skel skel-card"></div>`;
  try {
    const r = await fetch(`/api/whitelist/${cid}`, {headers: _authHeaders()});
    if (!r.ok) { tab.innerHTML = `<div class="diff-empty">Could not load suppressed findings</div>`; return; }
    const entries = await r.json();
    if (!entries.length) {
      tab.innerHTML = `<div class="empty-state"><div class="empty-state-icon">âœ“</div><div class="empty-state-title">No suppressed findings</div><div class="empty-state-copy">Findings you mark as false-positive will appear here and can be restored at any time.</div></div>`;
      return;
    }
    const listHtml = entries.map(e => `
      <div style="display:flex;align-items:center;gap:10px;padding:10px 14px;border-bottom:1px solid var(--border);font-size:.73rem">
        <div style="flex:1;min-width:0">
          <div style="color:var(--text);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.title)}</div>
          <div style="color:var(--text3);margin-top:2px">${esc(e.host)} Â· ${esc(e.reason||'â€”')} Â· by ${esc(e.suppressed_by||'?')}</div>
        </div>
        <button class="btn btn-secondary" style="font-size:.62rem;padding:2px 8px;color:var(--red);flex-shrink:0"
          onclick="restoreFinding('${esc(cid)}','${esc(e.id)}',this)">Restore</button>
      </div>`).join("");
    tab.innerHTML = `
      <div class="section-shell">
        <div class="section-head"><div class="section-head-main">
          <div class="section-kicker">Suppressed Findings</div>
          <div class="section-title">${entries.length} suppressed</div>
          <div class="section-sub">Findings marked as false-positive or out-of-scope. Click Restore to bring them back into the active queue.</div>
        </div></div>
        <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden" id="fp-suppressed-list">${listHtml}</div>
      </div>`;
  } catch(e) {
    tab.innerHTML = `<div class="diff-empty">Error: ${esc(e.message)}</div>`;
  }
}

async function restoreFinding(cid, wid, btn) {
  btn.disabled = true;
  try {
    const r = await fetch(`/api/whitelist/${cid}/${wid}`, {method:"DELETE", headers:_authHeaders()});
    if (!r.ok) throw await _apiErr(r);
    await loadSuppressedFindings(cid);
    showToast("Finding restored.");
  } catch(e) {
    btn.disabled = false;
    alert("Error: " + e.message);
  }
}

function showToast(msg) {
  let t = document.getElementById("asm-toast");
  if (!t) {
    t = document.createElement("div");
    t.id = "asm-toast";
    t.style.cssText = "position:fixed;bottom:24px;right:24px;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:10px 18px;font-size:.8rem;color:var(--text1);z-index:9999;box-shadow:0 4px 20px rgba(0,0,0,.4);transition:opacity .3s";
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.opacity = "1";
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.style.opacity = "0"; }, 3000);
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  HISTORICAL TREND CHARTS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

async function loadTrendCharts(cid) {
  const el = document.getElementById("ov-trends");
  if (!el) return;
  el.innerHTML = `<span style="color:var(--text3);font-size:.75rem">Loading trend dataâ€¦</span>`;
  try {
    const r = await fetch(`/api/stats-history/${cid}?limit=20`, {headers: _authHeaders()});
    if (!r.ok) { el.innerHTML = ""; return; }
    const stats = await r.json();
    if (!stats.length) { el.innerHTML = `<span style="color:var(--text3);font-size:.75rem">No historical data yet. Run more scans to see trends.</span>`; return; }

    const labels = stats.map(s => s.scanned_at ? s.scanned_at.substring(0,10) : "?");
    const mkSparkline = (values, color, label) => {
      const max = Math.max(...values, 1);
      const w = 120, h = 40;
      const pts = values.map((v,i) => {
        const x = (i / Math.max(values.length-1,1)) * (w-4) + 2;
        const y = h - 2 - ((v / max) * (h-6));
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      }).join(" ");
      const lastVal = values[values.length-1];
      const firstVal = values[0];
      const trend = lastVal > firstVal ? "â–²" : lastVal < firstVal ? "â–¼" : "â€”";
      const trendColor = label.includes("finding") ? (lastVal > firstVal ? "var(--red)" : "var(--teal)") : (lastVal > firstVal ? "var(--teal)" : "var(--text3)");
      return `<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:10px 14px;min-width:140px">
        <div style="font-size:.62rem;color:var(--text3);text-transform:uppercase;margin-bottom:4px">${label}</div>
        <div style="font-size:1.2rem;font-weight:700;color:var(--text1)">${lastVal} <span style="font-size:.7rem;color:${trendColor}">${trend}</span></div>
        <svg width="${w}" height="${h}" style="display:block;margin-top:4px" viewBox="0 0 ${w} ${h}">
          <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
          <circle cx="${((values.length-1)/Math.max(values.length-1,1))*(w-4)+2}" cy="${h-2-((values[values.length-1]/max)*(h-6))}" r="3" fill="${color}"/>
        </svg>
      </div>`;
    };

    el.innerHTML = `
      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-start;margin-top:8px">
        ${mkSparkline(stats.map(s=>s.subdomains||0),  "var(--teal)",   "Hosts")}
        ${mkSparkline(stats.map(s=>s.live_hosts||0),  "var(--blue)",   "Live Hosts")}
        ${mkSparkline(stats.map(s=>s.findings_critical||0), "var(--red)",  "Critical Findings")}
        ${mkSparkline(stats.map(s=>s.findings_high||0),     "var(--orange)","High Findings")}
        ${mkSparkline(stats.map(s=>s.open_ports||0),  "#a78bfa",       "Open Ports")}
      </div>`;
  } catch(e) {
    el.innerHTML = `<span style="color:var(--text3);font-size:.75rem">Trend data unavailable.</span>`;
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  BULK COMPANY IMPORT
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  INIT
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function initApp() {
  if (SERVER_MODE) {
    document.getElementById("footer-gen").textContent = "Server mode";
    await reloadServerData();
    await loadPlaywrightDefaults();
    _startJobCountPoll();
  } else {
    document.getElementById("footer-gen").textContent =
      typeof window.ASM_DATA !== "undefined" ? "Live data" : "Demo data";
  }
  const gen = DATA.generated
    ? new Date(DATA.generated).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"})
    : "â€”";
  document.getElementById("footer-date").textContent = gen;
  renderSidebar();
  showPage("companies");
  syncCompanyTabsAccessibility();
  // Apply persisted language translations after dynamic render
  if (typeof applyTranslations === 'function') {
    const savedLang = localStorage.getItem('lang') || (window.appConfig && window.appConfig.defaultLanguage) || 'en';
    applyTranslations(savedLang);
  }
  // Mark as initialized for hash routing
  if (typeof ASM !== 'undefined') ASM.initialized = true;
}

document.addEventListener("DOMContentLoaded", async () => {
  initGroupCountObserver();
  const ok = await checkAuth();
  if (ok) await initApp();
  // Close modals on overlay click
  document.getElementById("modal-add").addEventListener("click",    function(e){ if(e.target===this) closeAddCompany(); });
  document.getElementById("modal-scan").addEventListener("click",   function(e){ if(e.target===this) closeScanModal(); });
  document.getElementById("modal-admin").addEventListener("click",  function(e){ if(e.target===this) closeAdminModal(); });
});


window.addEventListener("resize", () => {
  if (window.innerWidth > 860) closeMobileNav();
  try { initThreatMaps(); } catch(e) {}
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  HOST DETAIL DRAWER
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

function openHostDrawer(hostname) {
  const overlay = document.getElementById('host-drawer-overlay');
  const drawer = document.getElementById('host-drawer');
  const titleEl = document.getElementById('hd-title');
  const statusEl = document.getElementById('hd-status');
  const bodyEl = document.getElementById('hd-body');
  if (!drawer) return;

  // Look up host from current company
  const co = allCompanies().find(c => c.id === state.currentId);
  const hosts = co ? (co.hosts || []) : (_sub_hosts || _co_ports || []);
  const h = hosts.find(x => x.host === hostname) || {};
  const sc = h.status_code;
  const statusCls = sc ? (sc < 300 ? 's2' : sc < 400 ? 's3' : sc < 500 ? 's4' : 's5') : 'na';
  const statusText = sc ? `${sc}` : 'n/a';
  const statusColor = sc ? (sc < 300 ? '#22c55e' : sc < 400 ? '#fbbf24' : sc < 500 ? '#fb923c' : '#f43f5e') : 'var(--text3)';

  titleEl.textContent = h.host || 'Unknown';
  statusEl.textContent = statusText;
  statusEl.style.background = `rgba(${sc<300?'34,197,94':sc<400?'251,191,36':sc<500?'251,146,60':'244,63,94'},0.1)`;
  statusEl.style.color = statusColor;
  statusEl.style.border = `1px solid ${statusColor}33`;

  const portDetails = h.port_details || [];
  const portMap = Object.fromEntries(portDetails.map(pd => [pd.port, pd]));
  const portsHtml = (h.ports || []).length
    ? `<div class="hd-section"><div class="hd-section-title">Open Ports</div><div class="hd-badge-row">${h.ports.map(p => {
        if (portMap[p]) return `<span class="port-c" style="font-size:.65rem" title="${esc(portMap[p].category||'')}">${p}:${esc(portMap[p].service||'')}</span>`;
        return `<span class="port-c" style="font-size:.65rem">${p}</span>`;
      }).join('')}</div></div>`
    : '<div class="hd-section"><div class="hd-section-title">Open Ports</div><div style="color:var(--text3);font-size:.68rem">None detected</div></div>';

  const techHtml = (h.technologies || []).length
    ? `<div class="hd-section"><div class="hd-section-title">Technology Stack</div><div class="hd-badge-row">${h.technologies.map(t => `<span class="sd-tech-badge">${esc(t)}</span>`).join('')}</div></div>`
    : '';

  const cnames = h.cnames || [];
  const cnameHtml = cnames.length
    ? `<div class="hd-section"><div class="hd-section-title">CNAME Chain</div>${cnames.map(c => `<div class="hd-row"><span class="hd-k">â†’</span><span class="hd-v hi">${esc(typeof c === 'string' ? c : c.cname || c)}</span></div>`).join('')}</div>`
    : '';

  const certHtml = h.cert_info
    ? `<div class="hd-section"><div class="hd-section-title">SSL Certificate</div>
      <div class="hd-row"><span class="hd-k">Issuer</span><span class="hd-v">${esc(h.cert_info.issuer || 'â€”')}</span></div>
      <div class="hd-row"><span class="hd-k">Expires</span><span class="hd-v ${h.cert_info.expiring_soon?'warn':''}">${esc(h.cert_info.not_after || 'â€”')}${h.cert_info.expiring_soon?' âš ':''}</span></div>
    </div>`
    : '';

  bodyEl.innerHTML = `
    <div class="hd-section">
      <div class="hd-section-title">Identity</div>
      <div class="hd-row"><span class="hd-k">Host</span><span class="hd-v hi">${esc(h.host||'â€”')}</span></div>
      <div class="hd-row"><span class="hd-k">IP</span><span class="hd-v">${esc(h.ip||'â€”')}</span></div>
      <div class="hd-row"><span class="hd-k">Title</span><span class="hd-v">${esc(h.title||'No title')}</span></div>
      <div class="hd-row"><span class="hd-k">WAF/CDN</span><span class="hd-v">${esc(h.waf||'Direct')}</span></div>
      ${h.cloud_provider ? `<div class="hd-row"><span class="hd-k">Cloud</span><span class="hd-v hi">â˜ ${esc(h.cloud_provider)}</span></div>` : ''}
      ${h.asn ? `<div class="hd-row"><span class="hd-k">ASN</span><span class="hd-v">${esc(h.asn)}</span></div>` : ''}
    </div>
    ${h.screenshot ? `<div class="hd-section"><div class="hd-section-title">Screenshot</div>
      <a href="${esc('/' + h.screenshot)}" target="_blank" rel="noopener">
        <img src="${esc('/' + h.screenshot)}" style="width:100%;max-width:400px;border-radius:8px;border:1px solid var(--border);cursor:pointer" onerror="this.style.display='none'" alt="Screenshot of ${esc(h.host)}">
      </a></div>` : ''}
    ${portsHtml}
    ${cnameHtml}
    ${certHtml}
    ${techHtml}
  `;

  drawer.classList.add('open');
  overlay.classList.add('show');
  document.body.style.overflow = 'hidden';
}

function closeHostDrawer() {
  const overlay = document.getElementById('host-drawer-overlay');
  const drawer = document.getElementById('host-drawer');
  if (drawer) drawer.classList.remove('open');
  if (overlay) overlay.classList.remove('show');
  document.body.style.overflow = '';
}

// Legacy stub â€” settings now lives at showPage('settings')
function openSettings(){ showPage("settings"); }

Object.assign(window, {
  loadJobs,
  openJobsQueue,
  openJobDetail,
  openJobCompanyPipeline,
  cancelJob,
  toggleJobDrilldown,
  exitJobDrilldown,
  openDomainResults,
  _onJobDrillSearch,
});
