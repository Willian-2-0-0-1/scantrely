"""Browser Crawler — Playwright multi-page crawl across ALL subdomains — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
import os
import re
import socket
import time
from core.reconlib.base import UA, _log, _subp, http_get, run_bounded, subprocess

# ── Browser Deep Recon via Playwright ──
# Uses the playwright venv at /home/kali/.asm-playwright (upstream pip, not Kali pkg).
# Falls back gracefully if unavailable.

def _pw_import():
    """Import playwright from the dedicated venv, bypassing the broken Kali system package."""
    import sys
    from pathlib import Path as _P
    venv_lib = _P("/home/kali/.asm-playwright/lib")
    site_pkg = next(venv_lib.glob("python3.*/site-packages"), None) if venv_lib.exists() else None
    if site_pkg and str(site_pkg) not in sys.path:
        sys.path.insert(0, str(site_pkg))
    from playwright.sync_api import sync_playwright, TimeoutError as PwTimeout
    return sync_playwright, PwTimeout



def run_browser_recon(target_url: str, screenshot_dir: str = "/tmp", timeout: int = 25) -> dict:
    """Launch headless Chromium via Playwright, navigate, extract recon intel.

    Returns:
      {
        "url": str,
        "status": int,
        "title": str,
        "technologies": [str],
        "api_endpoints": [{"method":str,"url":str,"type":str}],
        "secrets_found": [{"source":str,"key":str,"value_hint":str}],
        "source_maps": [str],
        "exposed_paths": [{"path":str,"status":int}],
        "cors_config": {"allow_origin":str,"allow_credentials":bool,...},
        "security_headers": {"missing":[str],"present":{str:str}},
        "third_party_services": [str],
        "developer_notes": [str],
        "screenshot": str,
        "observations": [str],
        "js_analysis": {...},
        "error": str|None,
      }
    """
    import re, os

    result = {
        "url": target_url,
        "status": 0,
        "title": "",
        "technologies": [],
        "api_endpoints": [],
        "secrets_found": [],
        "source_maps": [],
        "exposed_paths": [],
        "cors_config": {},
        "security_headers": {"missing": [], "present": {}},
        "third_party_services": [],
        "developer_notes": [],
        "screenshot": "",
        "observations": [],
        "cookies": [],
        "error": None,
    }

    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    result["url"] = target_url

    try:
        sync_playwright, PwTimeout = _pw_import()
    except Exception as e:
        result["error"] = f"playwright unavailable: {e}"
        return result

    timeout_ms = timeout * 1000
    api_endpoints = []
    nav_headers: dict = {}

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox", "--disable-dev-shm-usage",
                "--ignore-certificate-errors", "--disable-web-security",
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars", "--window-size=1366,768",
            ],
        )
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        )
        page = context.new_page()

        # ── Network interception — captures ALL requests at browser level ──
        def _on_request(req):
            u = req.url
            rt = req.resource_type
            if rt in ("xhr", "fetch") or any(
                x in u for x in ["/api/", "/graphql", "/v1/", "/v2/", "/rest/", ".json"]
            ):
                api_endpoints.append({"method": req.method, "url": u, "type": rt})

        def _on_response(resp):
            nonlocal nav_headers
            try:
                if resp.url.rstrip("/") == target_url.rstrip("/") and not nav_headers:
                    nav_headers = dict(resp.headers)
                    result["status"] = resp.status
            except Exception:
                _log.debug('recon.py:9058 erro ignorado', exc_info=True)

        page.on("request", _on_request)
        page.on("response", _on_response)

        try:
            from playwright_agent.browser import goto_resilient
            _, nav_error, _, _ = goto_resilient(page, target_url, base_timeout=timeout)
            if nav_error:
                result["observations"].append(f"navigation_warning: {nav_error[:160]}")
        except Exception as e:
            result["error"] = str(e)
            browser.close()
            return result

        result["api_endpoints"] = api_endpoints[:200]

        # Helper: evaluate JS and return parsed value or ""
        def _eval(expr: str):
            try:
                val = page.evaluate(expr)
                return val if val is not None else ""
            except Exception:
                return ""

        # ── Title ──
        try:
            result["title"] = page.title() or ""
        except Exception:
            _log.debug('recon.py:9087 erro ignorado', exc_info=True)

        # ── 1. Source maps ──
        try:
            js_urls = _eval(
                "Array.from(document.querySelectorAll('script[src]')).map(s=>s.src)"
            )
            if isinstance(js_urls, list):
                for u in js_urls:
                    if isinstance(u, str) and u.endswith(".map"):
                        result["source_maps"].append(u)
        except Exception:
            _log.debug('recon.py:9099 erro ignorado', exc_info=True)

        # ── 2. Inline secrets ──
        secret_patterns = [
            ("apiKey",      r'(?:api_key|apiKey|apikey|API_KEY)\s*[:=]\s*["\']([^"\'&]{8,80})["\']'),
            ("token",       r'(?:token|access_token|auth_token|bearer)\s*[:=]\s*["\']([^"\'&]{12,200})["\']'),
            ("firebase",    r'(?:firebase|FIREBASE)\s*[:=]\s*["\']([^"\'&]{8,120})["\']'),
            ("aws_key",     r'(?:AWS_ACCESS_KEY|AWSAccessKeyId)\s*[:=]\s*["\']([A-Z0-9]{16,40})["\']'),
            ("google_maps", r'(?:google_maps_key|GOOGLE_MAPS_KEY|mapsApiKey)\s*[:=]\s*["\']([A-Za-z0-9_-]{20,60})["\']'),
        ]
        try:
            blocks = _eval(
                "Array.from(document.querySelectorAll('script:not([src])')).map(s=>s.textContent)"
            )
            if isinstance(blocks, list):
                for block in blocks:
                    if not isinstance(block, str):
                        continue
                    for label, pat in secret_patterns:
                        for m in re.finditer(pat, block, re.IGNORECASE):
                            val = m.group(1) if m.lastindex else ""
                            result["secrets_found"].append({
                                "source": "inline-script",
                                "key": label,
                                "value_hint": val[:8] + "..." if len(val) > 8 else val,
                            })
        except Exception:
            _log.debug('recon.py:9126 erro ignorado', exc_info=True)

        # ── 3. Third-party services ──
        known_services = {
            "google-analytics.com": "Google Analytics", "googletagmanager.com": "Google Tag Manager",
            "googleapis.com": "Google APIs",            "firebaseio.com": "Firebase",
            "stripe.com": "Stripe",                      "jsdelivr.net": "jsDelivr CDN",
            "cdnjs.cloudflare.com": "Cloudflare CDN",   "unpkg.com": "unpkg CDN",
            "amazonaws.com": "AWS",                      "azure.com": "Azure",
            "cloudfront.net": "AWS CloudFront",          "recaptcha.net": "reCAPTCHA",
            "hcaptcha.com": "hCaptcha",                  "hotjar.com": "Hotjar",
            "intercom.io": "Intercom",                   "zendesk.com": "Zendesk",
            "segment.io": "Segment",                     "sentry.io": "Sentry",
            "datadoghq.com": "DataDog",                  "newrelic.com": "New Relic",
        }
        try:
            ext_urls = _eval(
                "Array.from(document.querySelectorAll('script[src],link[href],iframe[src],img[src]'))"
                ".map(e=>e.src||e.href||'').filter(u=>u&&!u.includes(location.hostname))"
            )
            if isinstance(ext_urls, list):
                domains: set = set()
                for u in ext_urls:
                    m = re.search(r'//([^/]+)', u)
                    if m:
                        domains.add(m.group(1))
                for d in sorted(domains):
                    label = next((v for k, v in known_services.items() if k in d), d)
                    result["third_party_services"].append(label)
        except Exception:
            _log.debug('recon.py:9156 erro ignorado', exc_info=True)

        # ── 4. Technology detection ──
        tech_sigs = {
            "react": "React", "vue": "Vue.js", "angular": "Angular", "jquery": "jQuery",
            "bootstrap": "Bootstrap", "tailwind": "Tailwind CSS", "next": "Next.js",
            "nuxt": "Nuxt.js", "gatsby": "Gatsby", "wordpress": "WordPress",
            "drupal": "Drupal", "laravel": "Laravel", "django": "Django",
            "flask": "Flask", "express": "Express.js", "fastapi": "FastAPI",
            "swagger": "Swagger", "redoc": "ReDoc", "graphql": "GraphQL",
            "alpinejs": "Alpine.js", "svelte": "Svelte", "preact": "Preact",
            "socket.io": "Socket.IO", "axios": "Axios",
        }
        try:
            meta_tags = _eval(
                "Array.from(document.querySelectorAll('meta[name=generator]')).map(m=>m.content||'')"
            )
            if isinstance(meta_tags, list):
                result["technologies"].extend(t for t in meta_tags if t)
            script_srcs = _eval(
                "Array.from(document.querySelectorAll('script[src]')).map(s=>s.src)"
            )
            if isinstance(script_srcs, list):
                for src in script_srcs:
                    sl = src.lower()
                    for sig, name in tech_sigs.items():
                        if sig in sl and name not in result["technologies"]:
                            result["technologies"].append(name)
        except Exception:
            _log.debug('recon.py:9185 erro ignorado', exc_info=True)

        # ── 5. JS Deep Analysis ──
        js_deep = result.setdefault("js_analysis", {
            "webpack_modules": 0, "webpack_chunks": [],
            "storage_keys": {"localStorage": [], "sessionStorage": []},
            "global_variables": [], "framework_routes": [],
            "service_workers": [], "inline_event_handlers": 0,
        })

        try:
            wp = _eval(
                "(function(){try{"
                "var wp=window.webpackChunk||window.__webpack_require__||null;"
                "var mods=0,chunks=[];"
                "if(wp){if(wp.m)mods=Object.keys(wp.m).length;"
                "if(wp.c)chunks=Object.keys(wp.c).filter(k=>typeof wp.c[k]==='object');}"
                "return {modules:mods,chunks:chunks.slice(0,20)}"
                "}catch(e){return {modules:0,chunks:[]}}})()"
            )
            if isinstance(wp, dict):
                js_deep["webpack_modules"] = wp.get("modules", 0)
                js_deep["webpack_chunks"] = wp.get("chunks", [])
        except Exception:
            _log.debug('recon.py:9209 erro ignorado', exc_info=True)

        try:
            comps = _eval(
                "(function(){try{"
                "var comps=[];"
                "var root=document.getElementById('root')||document.getElementById('__next')||document.getElementById('app');"
                "if(root){var fk=Object.keys(root).find(k=>k.startsWith('__reactFiber')||k.startsWith('__reactInternalInstance'));"
                "if(fk){function w(n,d){if(!n||d>30)return;"
                "var name=(n.type||{}).name||(n.type||{}).displayName||(n.elementType||{}).name||'';"
                "if(name)comps.push(name);if(n.child)w(n.child,d+1);if(n.sibling)w(n.sibling,d+1);}"
                "w(root[fk],0);}}"
                "return [...new Set(comps)].slice(0,50)"
                "}catch(e){return []}})()"
            )
            if isinstance(comps, list) and comps:
                js_deep["framework_routes"] = comps
        except Exception:
            _log.debug('recon.py:9227 erro ignorado', exc_info=True)

        try:
            vue = _eval(
                "(function(){try{"
                "var all=document.querySelectorAll('*');"
                "for(var i=0;i<Math.min(all.length,500);i++){"
                "var el=all[i];var v=el.__vue__||el.__vue_app__||el._vnode;"
                "if(v){return [(v.$options||{}).name||el.tagName.toLowerCase()];}}"
                "var a=document.querySelector('[data-v-]')||document.querySelector('[data-v-app]');"
                "return a?['VueApp detected']:[]"
                "}catch(e){return []}})()"
            )
            if isinstance(vue, list) and vue:
                js_deep["framework_routes"].extend(vue)
        except Exception:
            _log.debug('recon.py:9243 erro ignorado', exc_info=True)

        try:
            storage = _eval(
                "(function(){try{"
                "var ls=[],ss=[];"
                "for(var i=0;i<localStorage.length;i++)ls.push(localStorage.key(i));"
                "for(var i=0;i<sessionStorage.length;i++)ss.push(sessionStorage.key(i));"
                "return {ls:ls.slice(0,50),ss:ss.slice(0,50)}"
                "}catch(e){return {ls:[],ss:[]}}})()"
            )
            if isinstance(storage, dict):
                js_deep["storage_keys"]["localStorage"] = storage.get("ls", [])
                js_deep["storage_keys"]["sessionStorage"] = storage.get("ss", [])
        except Exception:
            _log.debug('recon.py:9258 erro ignorado', exc_info=True)

        try:
            globs = _eval(
                "(function(){try{"
                "var std=new Set('Infinity NaN undefined Array ArrayBuffer Boolean DataView Date Error Function Generator Int8Array Int16Array Int32Array Intl JSON Map Math Number Object Promise Proxy RangeError ReferenceError Reflect RegExp Set SharedArrayBuffer String Symbol SyntaxError TypeError Uint8Array Uint16Array Uint32Array WeakMap WeakSet decodeURI encodeURI eval isFinite isNaN parseFloat parseInt globalThis queueMicrotask TextDecoder TextEncoder DOMException AbortController'.split(' '));"
                "var g=[];"
                "for(var k of Object.getOwnPropertyNames(window)){"
                "if(!std.has(k)&&!k.startsWith('webkit')&&!k.startsWith('__')&&k[0]!==k[0].toLowerCase()&&k!=='Window'){"
                "try{var v=window[k];if(typeof v==='function'||typeof v==='object')g.push(k);}catch(e){}}}"
                "return g.slice(0,80)"
                "}catch(e){return []}})()"
            )
            if isinstance(globs, list):
                js_deep["global_variables"] = globs
        except Exception:
            _log.debug('recon.py:9274 erro ignorado', exc_info=True)

        try:
            sws = _eval(
                "(async()=>{try{"
                "if(!navigator.serviceWorker)return [];"
                "var r=await navigator.serviceWorker.getRegistrations();"
                "return r.map(x=>({scope:x.scope,active:!!x.active,scriptURL:x.active?x.active.scriptURL:''}))"
                "}catch(e){return []}})()"
            )
            if isinstance(sws, list):
                js_deep["service_workers"] = sws
        except Exception:
            _log.debug('recon.py:9287 erro ignorado', exc_info=True)

        try:
            eh_count = _eval(
                "(function(){var c=0,all=document.querySelectorAll('*');"
                "for(var i=0;i<Math.min(all.length,500);i++){"
                "var a=all[i].getAttributeNames?all[i].getAttributeNames():[];"
                "for(var j=0;j<a.length;j++)if(/^on[a-z]+$/i.test(a[j])&&all[i].getAttribute(a[j]))c++;}"
                "return c})()"
            )
            if isinstance(eh_count, int):
                js_deep["inline_event_handlers"] = eh_count
        except Exception:
            _log.debug('recon.py:9300 erro ignorado', exc_info=True)

        # Observations from JS analysis
        if js_deep["webpack_modules"] > 0:
            result["observations"].append(f"Webpack: {js_deep['webpack_modules']} modules, {len(js_deep['webpack_chunks'])} chunks — source exposure possible")
        if js_deep["framework_routes"]:
            result["observations"].append(f"Framework components: {', '.join(js_deep['framework_routes'][:8])}")
        if js_deep["storage_keys"]["localStorage"]:
            ls = js_deep["storage_keys"]["localStorage"]
            result["observations"].append(f"localStorage: {len(ls)} keys — {', '.join(ls[:5])}")
        if js_deep["storage_keys"]["sessionStorage"]:
            result["observations"].append(f"sessionStorage: {len(js_deep['storage_keys']['sessionStorage'])} keys — possible auth tokens")
        if js_deep["service_workers"]:
            result["observations"].append(f"Service Workers: {', '.join(s['scope'] for s in js_deep['service_workers'][:3])}")
        if js_deep["global_variables"]:
            result["observations"].append(f"Custom globals: {', '.join(js_deep['global_variables'][:6])}")
        if js_deep["inline_event_handlers"] > 5:
            result["observations"].append(f"Inline event handlers: {js_deep['inline_event_handlers']} — possible DOM XSS surface")

        # ── 6. Security headers — read from nav_headers captured at response time ──
        sec_headers = [
            "content-security-policy", "x-frame-options",
            "x-content-type-options", "strict-transport-security",
        ]
        for h in sec_headers:
            if nav_headers.get(h):
                result["security_headers"]["present"][h] = nav_headers[h]
            else:
                result["security_headers"]["missing"].append(h)
        acao = nav_headers.get("access-control-allow-origin", "")
        if acao:
            result["cors_config"]["allow_origin"] = acao
            result["cors_config"]["allow_credentials"] = (
                nav_headers.get("access-control-allow-credentials", "").lower() == "true"
            )
            if acao == "*":
                result["observations"].append("CORS wildcard (*) — overly permissive")
            if result["cors_config"].get("allow_credentials") and acao == "*":
                result["observations"].append("DANGER: CORS * + credentials=true — credential theft possible")

        # ── 7. Developer comments / TODOs ──
        try:
            comments = _eval(
                "Array.from(document.querySelectorAll('*'))"
                ".flatMap(e=>Array.from(e.childNodes).filter(n=>n.nodeType===8).map(c=>c.textContent))"
            )
            if isinstance(comments, list):
                kws = {"todo", "fixme", "hack", "debug", "password", "secret", "key",
                       "token", "backdoor", "disabled", "staging", "sandbox"}
                for c in comments:
                    if isinstance(c, str) and any(kw in c.lower() for kw in kws):
                        result["developer_notes"].append(c.strip()[:200])
        except Exception:
            _log.debug('recon.py:9353 erro ignorado', exc_info=True)

        # ── 8. Login forms ──
        try:
            forms = _eval(
                "Array.from(document.querySelectorAll('form')).map(f=>({"
                "action:f.action||'',"
                "inputs:Array.from(f.querySelectorAll('input')).map(i=>({type:i.type,name:i.name})),"
                "hasPassword:!!f.querySelector('input[type=password]')}))"
            )
            if isinstance(forms, list):
                for f in forms:
                    if isinstance(f, dict) and f.get("hasPassword"):
                        result["observations"].append(
                            f"Login form at {f.get('action','(page)')} — {len(f.get('inputs',[]))} inputs"
                        )
        except Exception:
            _log.debug('recon.py:9370 erro ignorado', exc_info=True)

        # ── 9. Cookies ──
        try:
            cookies = context.cookies()
            result["cookies"] = [
                {
                    "name":      c["name"],
                    "domain":    c.get("domain", ""),
                    "httpOnly":  c.get("httpOnly", False),
                    "secure":    c.get("secure", False),
                    "sameSite":  c.get("sameSite", ""),
                    "path":      c.get("path", "/"),
                    "session":   not bool(c.get("expires", -1) > 0),
                }
                for c in cookies
            ]
            insecure = [c for c in result["cookies"] if not c["httpOnly"] or not c["secure"]]
            if insecure:
                result["observations"].append(
                    f"{len(insecure)} cookies with insecure flags — "
                    f"{sum(1 for c in insecure if not c['httpOnly'])} missing HttpOnly, "
                    f"{sum(1 for c in insecure if not c['secure'])} missing Secure"
                )
        except Exception:
            result["cookies"] = []

        # ── 10. Screenshot ──
        try:
            safe = re.sub(r'[^a-zA-Z0-9]', '_', target_url)[:60]
            fname = f"browser_{safe}.png"
            fpath = os.path.join(screenshot_dir, fname)
            page.screenshot(path=fpath, full_page=False)
            result["screenshot"] = fpath
        except Exception:
            _log.debug('recon.py:9405 erro ignorado', exc_info=True)

        # ── Security header observations ──
        if "content-security-policy" in result["security_headers"]["missing"]:
            result["observations"].append("Missing CSP — XSS risk")
        if "strict-transport-security" in result["security_headers"]["missing"]:
            result["observations"].append("Missing HSTS — no TLS enforcement")
        if "x-frame-options" in result["security_headers"]["missing"]:
            result["observations"].append("Missing X-Frame-Options — clickjacking possible")
        if result["source_maps"]:
            result["observations"].append(f"Source maps exposed ({len(result['source_maps'])}) — source code recoverable")
        if len(result["api_endpoints"]) > 5:
            result["observations"].append(f"{len(result['api_endpoints'])} API endpoints captured — check for unauth access")
        if result["secrets_found"]:
            result["observations"].append(f"{len(result['secrets_found'])} potential secrets in inline JS — rotate immediately")

        browser.close()

    return result



# ── Browser Crawler — Playwright multi-page crawl across ALL subdomains ──

def run_browser_crawl(hosts, domains, max_hosts: int = 150,
                      max_pages_per_host: int = 8, timeout: int = 20,
                      workers: int = 3) -> dict:
    """
    Playwright crawler over ALL live subdomains. For each live host it renders the
    root page and follows same-host internal links (breadth-first) up to
    max_pages_per_host, executing JS so SPA routes and dynamically-injected URLs are
    captured (vs. static crawlers). Per page it collects hyperlinks, network API
    endpoints (xhr/fetch) and forms. In-scope `*.<domain>` hostnames found in links
    are returned under `subdomains` and merged into the host pool by the pipeline.

    Bounded by max_hosts / max_pages_per_host for safety; raise them for fuller
    coverage at the cost of runtime.
    """
    if isinstance(domains, str):
        domains = [domains]
    domains = [str(d).lower().strip().strip(".") for d in domains if d]
    now = datetime.now().isoformat(timespec="seconds")
    from urllib.parse import urlparse as _up

    # ── Build target URLs from live hosts (dedup by host) ──
    LIVE = {200, 301, 302, 401, 403}
    seen_hosts, targets = set(), []
    for h in hosts or []:
        host = (h.get("host") or "").strip().lower()
        if not host or host in seen_hosts:
            continue
        if h.get("status_code", 0) not in LIVE and not h.get("ip"):
            continue
        seen_hosts.add(host)
        targets.append(h.get("url") or f"https://{host}")
        if len(targets) >= max_hosts:
            break

    if not targets:
        return {"hosts_crawled": 0, "hosts_targeted": 0, "results": [], "urls": [],
                "subdomains": [], "api_endpoints": [], "url_count": 0, "count": 0,
                "note": "nenhum host vivo para crawl", "scanned_at": now}

    try:
        sync_playwright, PwTimeout = _pw_import()
    except Exception as e:
        return {"hosts_crawled": 0, "hosts_targeted": len(targets), "results": [],
                "urls": [], "subdomains": [], "error": f"playwright unavailable: {e}",
                "scanned_at": now}

    sub_res = [re.compile(r"([a-z0-9](?:[a-z0-9\-]{0,62}\.)+" + re.escape(d) + r")", re.I)
               for d in domains]
    args = ["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors",
            "--disable-blink-features=AutomationControlled", "--window-size=1366,768"]

    def _crawl_one(base_url):
        if not base_url.startswith("http"):
            base_url = "https://" + base_url
        base_host = _up(base_url).netloc.split(":")[0].lower()
        out = {"url": base_url, "host": base_host, "pages": 0,
               "urls": set(), "api_endpoints": [], "forms": [], "error": None}
        api_seen = set()
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, args=args)
                ctx  = browser.new_context(ignore_https_errors=True, user_agent=UA)
                page = ctx.new_page()

                def _on_request(req):
                    u = req.url
                    if (req.resource_type in ("xhr", "fetch")
                            or any(x in u for x in ("/api/", "/graphql", "/v1/", "/v2/", "/rest/", ".json"))):
                        key = (req.method, u)
                        if key not in api_seen and len(out["api_endpoints"]) < 300:
                            api_seen.add(key)
                            out["api_endpoints"].append({"method": req.method, "url": u})
                page.on("request", _on_request)

                queue, visited = [base_url], set()
                while queue and len(visited) < max_pages_per_host:
                    url = queue.pop(0)
                    if url in visited:
                        continue
                    visited.add(url)
                    try:
                        from playwright_agent.browser import goto_resilient
                        _, nav_error, _, _ = goto_resilient(page, url, base_timeout=timeout)
                        if nav_error and "timeout" not in nav_error.lower():
                            continue
                        page.wait_for_timeout(800)   # deixa XHR disparar
                    except Exception:
                        continue
                    try:
                        links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)") or []
                    except Exception:
                        links = []
                    try:
                        forms = page.evaluate(
                            "() => [...document.forms].map(f => ({action: f.action, "
                            "method: (f.method||'get'), "
                            "inputs: [...f.elements].map(e=>e.name).filter(Boolean)}))"
                        ) or []
                        for fr in forms:
                            if fr.get("action") and fr not in out["forms"] and len(out["forms"]) < 100:
                                out["forms"].append(fr)
                    except Exception:
                        _log.debug('recon.py:9530 erro ignorado', exc_info=True)
                    for ln in links:
                        if not isinstance(ln, str) or not ln.startswith("http"):
                            continue
                        out["urls"].add(ln)
                        h = _up(ln).netloc.split(":")[0].lower()
                        if h == base_host:
                            clean = ln.split("#")[0]
                            if clean not in visited and len(queue) < max_pages_per_host * 3:
                                queue.append(clean)
                    out["pages"] = len(visited)
                browser.close()
        except Exception as e:
            out["error"] = str(e)
        out["urls"] = sorted(out["urls"])[:500]
        return out

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for r in pool.map(_crawl_one, targets):
            results.append(r)

    # ── Aggregate ──
    all_urls, all_api, subdomains = set(), [], set()
    total_forms = 0
    for r in results:
        for u in r.get("urls", []):
            all_urls.add(u)
            host = _up(u).netloc.split(":")[0].lower()
            for rx in sub_res:
                for m in rx.findall(host):
                    subdomains.add(m.lower().strip("."))
        all_api.extend(r.get("api_endpoints", []))
        total_forms += len(r.get("forms", []))

    return {
        "hosts_crawled":  len([r for r in results if not r.get("error")]),
        "hosts_targeted": len(targets),
        "results":        results,
        "urls":           sorted(all_urls)[:5000],
        "url_count":      len(all_urls),
        "api_endpoints":  all_api[:1000],
        "api_endpoint_count": len(all_api),
        "form_count":     total_forms,
        "subdomains":     sorted(subdomains),
        "count":          len(all_urls),
        "scanned_at":     now,
    }



# â•â•Â──
# GAP 3  — Container Registry Scanning (Docker Hub, GHCR, ECR Public, Quay)
# â•â•Â──

_CONTAINER_REGISTRIES = [
    {"name": "Docker Hub",      "api": "https://hub.docker.com/v2/repositories/{org}/",      "key_header": None},
    {"name": "GitHub Container", "api": "https://ghcr.io/v2/{org}/",                          "key_header": None},
    {"name": "Quay.io",         "api": "https://quay.io/api/v1/repository?namespace={org}",   "key_header": None},
    {"name": "ECR Public",      "api": "https://public.ecr.aws/v2/{org}/",                     "key_header": None},
]


_CONTAINER_KEYWORDS = [
    "api", "app", "web", "backend", "frontend", "worker", "service", "proxy",
    "cron", "scheduler", "migrate", "seed", "build", "deploy", "release",
    "admin", "dashboard", "monitor", "log", "metrics", "alerts", "nginx",
    "envoy", "haproxy", "traefik", "caddy",
]



def _derive_org_names_from_domain(domain: str) -> list:
    names = set()
    base = domain.lower().split(".")[0] if "." in domain else domain.lower()
    names.add(base)
    names.add(base.replace("-", ""))
    names.add(base.replace("_", ""))
    base2 = domain.replace(".", "-")
    if base2 != domain:
        names.add(base2)
    for part in domain.split(".")[:-1]:
        if len(part) > 2:
            names.add(part)
    return sorted(names, key=len)



def _check_container_registry(registry: dict, org: str, token: str = "") -> list:
    findings = []
    api_url = registry["api"].format(org=org)
    headers = {"Accept": "application/json", "User-Agent": UA}
    if registry["key_header"] and token:
        headers[registry["key_header"]] = token

    try:
        sc, raw, _ = http_get(api_url, timeout=8, retries=1, extra_headers=headers)
        if sc == 200:
            data = json.loads(raw.decode("utf-8", "ignore"))
            images = []
            if isinstance(data, dict):
                images = data.get("results", data.get("repositories", data.get("images", [])))
            elif isinstance(data, list):
                images = data
            for img in images:
                name = img.get("name", img.get("repository_name", img.get("slug", str(img))))
                desc = img.get("description", img.get("short_description", ""))
                updated = img.get("last_updated", img.get("updated_at", ""))
                pulls = img.get("pull_count", img.get("download_count", "?"))
                findings.append({
                    "type": "container_image",
                    "image": str(name),
                    "registry": registry["name"],
                    "org": org,
                    "description": str(desc)[:200],
                    "updated": str(updated),
                    "pulls": str(pulls),
                    "url": api_url.rstrip("/") + "/" + str(name),
                    "severity": "medium",
                })
    except Exception:
        _log.debug('recon.py:9647 erro ignorado', exc_info=True)
    return findings



def _brute_container_orgs(registry: dict, org_names: list, token: str = "") -> list:
    findings = []
    for org in org_names[:6]:
        findings.extend(_check_container_registry(registry, org, token))
        time.sleep(0.3)
    return findings



def run_container_registry_scan(domains, company_name: str = "",
                                 docker_token: str = "") -> dict:
    org_names = set()
    for d in domains if isinstance(domains, list) else [domains]:
        org_names.update(_derive_org_names_from_domain(d))
    if company_name:
        base = re.sub(r"[^a-z0-9]", "", company_name.lower())
        if base:
            org_names.add(base)
            org_names.add(base.replace(" ", ""))
    org_names = sorted(org_names, key=len)[:10]
    all_findings = []
    scanned = {}
    for reg in _CONTAINER_REGISTRIES:
        try:
            f = _brute_container_orgs(reg, org_names, docker_token)
            all_findings.extend(f)
            scanned[reg["name"]] = len(f)
        except Exception:
            scanned[reg["name"]] = 0
    critical = [f for f in all_findings if "critical" in f.get("severity", "")]
    return {
        "findings": all_findings,
        "total": len(all_findings),
        "critical_count": len(critical),
        "orgs_checked": org_names,
        "registries_scanned": scanned,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



# â•â•Â──
# GAP 9  — Internet-Wide Scan Dataset Ingestion (Censys bulk, Shodan bulk)
# â•â•Â──

def run_bulk_dataset_scan(hosts: list, domains: list,
                           shodan_key: str = "", censys_id: str = "",
                           censys_secret: str = "") -> dict:
    bulk_findings = []
    domain_names = [d for d in (domains or []) if d]

    # ── Shodan InternetDB (free, no key required) ──
    for h in hosts[:50]:
        ip = h.get("ip", "")
        if not ip:
            continue
        try:
            sc, raw, _ = http_get(
                f"https://internetdb.shodan.io/{ip}",
                timeout=5, retries=1,
            )
            if sc == 200:
                data = json.loads(raw.decode("utf-8", "ignore"))
                hostnames_found = data.get("hostnames", [])
                ports_found = data.get("ports", [])
                vulns_found = data.get("vulns", [])
                cpes_found = data.get("cpes", [])
                if ports_found or vulns_found:
                    bulk_findings.append({
                        "type": "shodan_internetdb",
                        "ip": ip,
                        "host": h.get("host", ip),
                        "ports": ports_found,
                        "vulns": vulns_found,
                        "cpes": cpes_found,
                        "hostnames": hostnames_found[:10],
                        "severity": "medium" if vulns_found else "info",
                        "source": "shodan_internetdb",
                    })
        except Exception:
            _log.debug('recon.py:9729 erro ignorado', exc_info=True)

    # ── Censys Search API (requires id/secret) ──
    if censys_id and censys_secret:
        import base64
        auth = base64.b64encode(f"{censys_id}:{censys_secret}".encode()).decode()
        for domain in domain_names[:3]:
            try:
                sc, raw, _ = http_get(
                    f"https://search.censys.io/api/v2/certificates/search"
                    f"?q=parsed.names:{domain}&per_page=20",
                    timeout=10, retries=1,
                    extra_headers={
                        "Authorization": f"Basic {auth}",
                        "Accept": "application/json",
                        "User-Agent": UA,
                    },
                )
                if sc == 200:
                    data = json.loads(raw.decode("utf-8", "ignore"))
                    for hit in data.get("result", {}).get("hits", []):
                        names = hit.get("parsed", {}).get("names", [])
                        for name in names[:5]:
                            if domain in name:
                                bulk_findings.append({
                                    "type": "censys_cert",
                                    "domain": domain,
                                    "subdomain": name,
                                    "fingerprint": hit.get("fingerprint_sha256", "")[:16],
                                    "validity": hit.get("parsed", {}).get("validity_period"),
                                    "severity": "info",
                                    "source": "censys_bulk",
                                })
            except Exception:
                _log.debug('recon.py:9763 erro ignorado', exc_info=True)

    return {
        "findings": bulk_findings,
        "total": len(bulk_findings),
        "hosts_checked": min(len(hosts), 50),
        "has_shodan": bool(shodan_key),
        "has_censys": bool(censys_id and censys_secret),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



# â•â•Â──
# GAP 11 — Database Enumeration: MySQL, PostgreSQL, MSSQL, Oracle active probes
# â•â•Â──

def _check_mysql(ip, port=3306):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return None
        # MySQL sends a greeting packet on connect
        data = s.recv(128)
        s.close()
        if len(data) >= 4:
            # MySQL greeting packet: payload length at offset 0-2, seq=0
            payload_len = data[0] | (data[1] << 8) | (data[2] << 16)
            if payload_len > 0 and len(data) > 4:
                # Extract server version (null-terminated string after protocol version)
                proto_ver = data[4]
                if proto_ver == 10:  # MySQL protocol v10
                    desc = "".join(chr(b) for b in data[5:payload_len + 4] if 32 <= b < 127).split("\x00")
                    version = desc[0] if desc else ""
                    auth_detail = "no auth (got greeting)"
                    sev = "high"
                    return {"auth": False, "detail": f"MySQL {version} — {auth_detail}", "severity": sev, "version": version}
    except Exception:
        _log.debug('recon.py:9802 erro ignorado', exc_info=True)
    return None



def _check_postgresql(ip, port=5432):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return None
        # PostgreSQL StartupMessage — send SSLRequest first
        # SSLRequest: length 8, protocol 80877103
        ssl_req = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
        s.send(ssl_req)
        resp = s.recv(1)
        s.close()
        if resp == b'S':
            return {"auth": "unknown", "detail": "PostgreSQL SSL supported — no auth probe", "severity": "medium"}
        elif resp == b'N':
            return {"auth": "unknown", "detail": "PostgreSQL SSL refused — no auth probe", "severity": "medium"}
        elif len(resp) > 0:
            return {"auth": "unknown", "detail": "PostgreSQL responded — no auth probe", "severity": "medium"}
    except Exception:
        _log.debug('recon.py:9826 erro ignorado', exc_info=True)
    return None



def _check_mssql(ip, port=1433):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return None
        # TDS Pre-Login — send empty prelogin packet
        prelogin = (
            b'\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b'
            b'\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01'
            b'\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00'
            b'\xf3\x0b\x00\x00'
        )
        s.send(prelogin)
        data = s.recv(256)
        s.close()
        if len(data) > 8:
            return {"auth": "unknown", "detail": "MSSQL TDS responded — no auth probe", "severity": "medium"}
    except Exception:
        _log.debug('recon.py:9850 erro ignorado', exc_info=True)
    return None



def _check_oracle(ip, port=1521):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return None
        # TNS Connect packet to get service name + version
        connect_data = (
            b'\x00\x3a\x00\x00\x01\x00\x00\x00\x01\x38\x01\x2c\x00\x00\x08\x00'
            b'\x7f\xff\xc6\x0e\x00\x00\x01\x00\x00\x00\x00\x3a\x00\x00\x08\x00'
            b'\x41\x41\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x28\x44\x45\x53\x43\x52\x49\x50'
            b'\x54\x49\x4f\x4e\x3d\x28\x43\x4f\x4e\x4e\x45\x43\x54\x5f\x44\x41'
            b'\x54\x41\x3d\x28\x43\x49\x44\x3d\x28\x50\x52\x4f\x47\x52\x41\x4d'
            b'\x3d\x41\x53\x4d\x29\x29\x29'
        )
        s.send(connect_data)
        data = s.recv(256)
        s.close()
        if len(data) > 4 and data[4] in (0x02, 0x03, 0x04):
            # Extract version string from TNS response
            raw = data.decode("latin-1", "ignore")
            body = raw[8:] if len(raw) > 8 else raw
            return {"auth": "unknown", "detail": f"Oracle TNS responded — version probe: {body[:80]}", "severity": "medium"}
    except Exception:
        _log.debug('recon.py:9880 erro ignorado', exc_info=True)
    return None



_DB_PROBES_EXTRA = [
    (3306, "MySQL",       "mysql",          _check_mysql),
    (5432, "PostgreSQL",  "postgresql",     _check_postgresql),
    (1433, "MSSQL",       "mssql",          _check_mssql),
    (1521, "Oracle",      "oracle",         _check_oracle),
]



def run_database_enum_extra(hosts: list) -> dict:
    """Active probe for MySQL, PostgreSQL, MSSQL, Oracle — complements run_default_creds."""
    findings = []
    tested = set()
    for h in hosts[:60]:
        if not isinstance(h, dict):
            continue
        ip = h.get("ip", "")
        if not ip or ip in tested:
            continue
        hostname = h.get("host", ip)
        host_ports = set(str(p) for p in (h.get("ports") or []))
        for port, name, _, check_fn in _DB_PROBES_EXTRA:
            if host_ports and str(port) not in host_ports:
                continue
            try:
                result = check_fn(ip, port)
            except Exception:
                result = None
            if result:
                findings.append({
                    "host": hostname, "ip": ip, "port": port, "service": name,
                    "severity": result.get("severity", "high"),
                    "title": f"Database reachable: {name} on {hostname}:{port}",
                    "desc": result.get("detail", ""),
                    "url": f"tcp://{ip}:{port}",
                    "type": "database_enum",
                })
                tested.add(ip)
    return {
        "findings": findings, "total": len(findings),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



# â•â•Â──
# GAP 13 — Service Version Detection (banner grabbing on open TCP ports)
# â•â•Â──

_SERVICE_PROBES = {
    21:   ("FTP",    b""),
    22:   ("SSH",    b""),
    23:   ("Telnet", b""),
    25:   ("SMTP",   b"EHLO asm.local\r\n"),
    110:  ("POP3",   b"CAPA\r\n"),
    143:  ("IMAP",   b"A001 CAPABILITY\r\n"),
    389:  ("LDAP",   b"0\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"),
    445:  ("SMB",    b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"),
    636:  ("LDAPS",  b""),
    3389: ("RDP",    b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"),
    5900: ("VNC",    b"RFB 003.008\n"),
    8080: ("HTTP",   b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
    8443: ("HTTP",   b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
}


_BANNER_RULES = [
    (re.compile(r"SSH-([\d.]+)[-_](\w+)", re.I), "SSH"),
    (re.compile(r"([\d.]+)\s+.*?FTP", re.I), "FTP"),
    (re.compile(r"(\d+)\s+.*?SMTP", re.I), "SMTP"),
    (re.compile(r"\+OK\s+(.*?)(POP3|ready)", re.I), "POP3"),
    (re.compile(r"\*\s+OK\s+.*?IMAP.*?([\d.]+)", re.I), "IMAP"),
    (re.compile(r"(?:Postfix|Sendmail|Exim|Exchange|ESMTP)\s*([\d.]+)?", re.I), "MTA"),
    (re.compile(r"(?:nginx|Apache|IIS|lighttpd|Caddy|Tomcat|Jetty)[/\s]*([\d.]+)?", re.I), "WebServer"),
    (re.compile(r"(?:Debian|Ubuntu|CentOS|RHEL|Fedora|Amazon Linux)", re.I), "OS"),
    (re.compile(r"RFB\s+([\d.]+)", re.I), "VNC"),
    (re.compile(r"(?:Microsoft\s*)?(?:Windows\s*(?:NT|Server|200\d|201\d|202\d)\s*[\d.]*)", re.I), "Windows"),
]



def _banner_grab(ip: str, port: int, probe: bytes, timeout: float = 3.0) -> str:
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return ""
        if probe:
            s.send(probe)
        time.sleep(0.3)
        data = b""
        while True:
            try:
                chunk = s.recv(512)
                if not chunk:
                    break
                data += chunk
                if len(data) >= 1024:
                    break
            except socket.timeout:
                break
        s.close()
        return data.decode("utf-8", "ignore").replace("\r\n", " ").replace("\n", " ").strip()[:300]
    except Exception:
        return ""



def _parse_banner(banner: str) -> list:
    matches = []
    for rx, svc in _BANNER_RULES:
        m = rx.search(banner)
        if m:
            ver = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
            matches.append(f"{svc}{' ' + ver if ver else ''}")
    return matches[:5]



def run_service_version_detect(hosts: list) -> dict:
    findings = []
    tested = set()
    for h in hosts[:100]:
        if not isinstance(h, dict):
            continue
        ip = h.get("ip", "")
        if not ip or ip in tested:
            continue
        hostname = h.get("host", ip)
        host_ports = h.get("ports", [])
        for port in (host_ports if host_ports else sorted(_SERVICE_PROBES.keys())):
            port_int = int(port) if not isinstance(port, int) else port
            probe_info = _SERVICE_PROBES.get(port_int)
            if not probe_info:
                continue
            svc_name, probe_bytes = probe_info
            banner = _banner_grab(ip, port_int, probe_bytes)
            if banner:
                versions = _parse_banner(banner)
                findings.append({
                    "host": hostname, "ip": ip, "port": port_int,
                    "service": svc_name, "banner": banner,
                    "versions": versions,
                    "title": f"{svc_name} banner on {hostname}:{port_int}",
                    "severity": "info",
                    "type": "service_version",
                })
                tested.add(ip)
    return {
        "findings": findings, "total": len(findings),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



# â•â•Â──
# GAP 14 — UDP Port Scanning
# â•â•Â──

_UDP_SCAN_PORTS = (
    "53,67,68,69,111,123,137,138,161,162,500,514,520,1194,1701,"
    "1812,1813,1900,2049,4500,5060,5353,5683,11211"
)


_UDP_PORT_NAMES = {
    53: "DNS", 67: "DHCPv4-server", 68: "DHCPv4-client", 69: "TFTP",
    111: "RPC/portmapper", 123: "NTP", 137: "NetBIOS-ns", 138: "NetBIOS-dgm",
    161: "SNMP", 162: "SNMP-trap", 500: "IKE/IPsec", 514: "Syslog",
    520: "RIP", 1194: "OpenVPN", 1701: "L2TP", 1812: "RADIUS", 1813: "RADIUS-acct",
    1900: "UPnP/SSDP", 2049: "NFS", 4500: "IPsec-NAT-T", 5060: "SIP",
    5353: "mDNS", 5683: "CoAP", 11211: "Memcached",
}



def run_udp_port_scan(hosts: list) -> dict:
    """Scan top UDP ports using nmap -sU (fast). Falls back to unicornscan if present."""
    unique_ips = sorted(set(
        h.get("ip", "") for h in (hosts or [])
        if isinstance(h, dict) and h.get("ip")
    ))
    if not unique_ips:
        return {"error": "no IPs to scan", "findings": [], "total": 0}

    # Check for nmap (preferred, has UDP support)
    has_nmap = subprocess.run(
        ["which", "nmap"], capture_output=True, text=True
    ).returncode == 0

    results = []
    tool_used = "none"

    if has_nmap:
        try:
            import tempfile
            ip_list = "\n".join(unique_ips[:20])
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write(ip_list)
                hosts_file = tf.name
            try:
                proc = _subp(
                    ["nmap", "-sU", "-iL", hosts_file, "-p", _UDP_SCAN_PORTS,
                     "--open", "-T4", "--host-timeout", "60s", "-oG", "-"],
                    capture_output=True, text=True, timeout=300,
                )
                tool_used = "nmap"
                current_ip = ""
                for line in proc.stdout.splitlines():
                    if line.startswith("Host:") and "Ports:" in line:
                        parts = line.split()
                        current_ip = parts[1] if len(parts) > 1 else ""
                        port_section = line.split("Ports:")[1].strip()
                        for entry in port_section.split(","):
                            entry = entry.strip()
                            if "open" not in entry:
                                continue
                            try:
                                port = int(entry.split("/")[0])
                                svc = _UDP_PORT_NAMES.get(port, "")
                                sev = "critical" if port in (161, 111, 2049, 500, 4500) else \
                                      "high" if svc else "info"
                                results.append({
                                    "ip": current_ip, "port": port,
                                    "service": svc, "severity": sev,
                                    "type": "udp_port",
                                })
                            except Exception:
                                _log.debug('recon.py:10105 erro ignorado', exc_info=True)
            finally:
                os.unlink(hosts_file)
        except Exception as e:
            return {"error": f"nmap UDP failed: {e}", "findings": [], "total": 0}

    # Fallback: lightweight UDP ping per port using raw socket
    if not has_nmap:
        tool_used = "raw-socket"
        for ip in unique_ips[:10]:
            for port in sorted(_UDP_PORT_NAMES.keys()):
                try:
                    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
                    s = socket.socket(family, socket.SOCK_DGRAM)
                    s.settimeout(1.0)
                    s.sendto(b"\x00", (ip, port))
                    try:
                        data, addr = s.recvfrom(64)
                        svc = _UDP_PORT_NAMES.get(port, "")
                        results.append({
                            "ip": ip, "port": port, "service": svc or "udp",
                            "severity": "high" if svc else "info",
                            "type": "udp_port",
                        })
                    except socket.timeout:
                        pass
                    s.close()
                except Exception:
                    continue

    high_risk = [r for r in results if r["severity"] in ("critical", "high")]
    return {
        "tool": tool_used,
        "ips_scanned": len(unique_ips[:20]) if has_nmap else len(unique_ips[:10]),
        "results": results,
        "high_risk": high_risk,
        "total": len(results),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



# â•â•Â──
# GAP 15 — API Discovery (kiterunner-based, with fallback to swagger/openapi probes)
# â•â•Â──

_API_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api/swagger.json", "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/openapi.json", "/api/openapi.json", "/api-docs", "/api-docs.json",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api-spec.json", "/api/spec", "/api/schema",
    "/redoc", "/reference", "/docs/api", "/api/docs",
    "/.well-known/ai-plugin.json",
]



def _probe_swagger_endpoint(host: str, path: str, timeout: int = 5,
                            schemes: tuple = ("https://", "http://")) -> dict | None:
    for scheme in schemes:
        url = f"{scheme}{host}{path}"
        try:
            sc, raw, _ = http_get(url, timeout=timeout, retries=0)
            if sc == 200:
                try:
                    data = json.loads(raw.decode("utf-8", "ignore"))
                    if isinstance(data, dict):
                        swagger_ver = data.get("swagger", data.get("openapi", ""))
                        title = data.get("info", {}).get("title", "")
                        endpoints_count = len(data.get("paths", {}))
                        return {
                            "url": url, "swagger_version": swagger_ver,
                            "title": title, "endpoints_count": endpoints_count,
                            "severity": "medium",
                        }
                except Exception:
                    if b"swagger" in (raw or b"")[:200].lower() or b"openapi" in (raw or b"")[:200].lower():
                        return {"url": url, "swagger_version": "detected", "title": "",
                                "endpoints_count": 0, "severity": "low"}
        except Exception:
            continue
    return None



def _run_kiterunner_on_hosts(hosts: list, workers: int = 5) -> list:
    """Run kiterunner if installed; fall back to swagger/openapi probes."""
    import shutil as _shutil
    has_kr = _shutil.which("kiterunner") is not None

    findings = []
    if has_kr:
        import tempfile
        target_hosts = []
        for h in hosts[:30]:
            host = h.get("host", h.get("ip", ""))
            if host:
                target_hosts.append(host)
        if target_hosts:
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                    tf.write("\n".join(target_hosts))
                    target_file = tf.name
                try:
                    proc = _subp(
                        ["kiterunner", "scan", "-f", target_file,
                         "-x", "10", "-j", "--fail-status-codes", "400-499"],
                        capture_output=True, text=True, timeout=120,   # abaixo dos 180s do módulo
                    )
                    for line in proc.stdout.strip().splitlines():
                        try:
                            item = json.loads(line)
                            findings.append({
                                "type": "kiterunner",
                                "host": item.get("host", ""),
                                "method": item.get("method", ""),
                                "path": item.get("url", item.get("path", "")),
                                "status": item.get("status_code", 0),
                                "length": item.get("content_length", 0),
                                "severity": "info",
                                "source": "kiterunner",
                            })
                        except Exception:
                            _log.debug('recon.py:10225 erro ignorado', exc_info=True)
                finally:
                    os.unlink(target_file)
            except Exception:
                _log.debug('recon.py:10229 erro ignorado', exc_info=True)

    # Always also run swagger/openapi probes (lightweight)
    # Antes: até 50 hosts × 21 caminhos × 2 esquemas em série (2.100 requisições) — estourava.
    # Agora: hosts em paralelo com prazo; o esquema que responde no 1º caminho vale para os outros.
    targets = list(dict.fromkeys(h.get("host", h.get("ip", "")) for h in hosts[:50] if h.get("host") or h.get("ip")))

    def _probe_host(host):
        scheme = ""
        for sch in ("https://", "http://"):
            sc, _, _ = http_get(f"{sch}{host}{_API_PATHS[0]}", timeout=4, retries=0)
            if sc:
                scheme = sch
                break
        if not scheme:
            return   # não responde em nenhum esquema: os outros 20 caminhos também cairiam no timeout
        for path in _API_PATHS:
            result = _probe_swagger_endpoint(host, path, timeout=4, schemes=(scheme,))
            if result:
                findings.append({
                    "type": "swagger_endpoint",
                    "host": host, "path": path,
                    "url": result["url"],
                    "swagger_version": result.get("swagger_version", ""),
                    "title": result.get("title", ""),
                    "endpoints_count": result.get("endpoints_count", 0),
                    "severity": result.get("severity", "low"),
                    "source": "swagger_probe",
                })
                return  # found one spec per host is enough

    run_bounded(_probe_host, targets, workers=10, label="api_disc")
    return list(findings)



def run_api_discovery_extra(hosts: list, domains: list) -> dict:
    findings = _run_kiterunner_on_hosts(hosts)
    used_kr = any(f.get("source") == "kiterunner" for f in findings)
    return {
        "findings": findings,
        "total": len(findings),
        "hosts_probed": len(set(h.get("host", "") for h in hosts[:50] if h.get("host"))),
        "sources_used": ["swagger_probe"] + (["kiterunner"] if used_kr else []),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    }



# â•â•Â──
# GAP 16 — Screenshot Visual Diffing Between Historical Versions
# â•â•Â──

def _image_similarity(path_a: str, path_b: str) -> float | None:
    """Compare two images using pixel hashing. Returns similarity 0.0-1.0 or None."""
    try:
        from PIL import Image
        import hashlib
        a = Image.open(path_a).convert("L").resize((64, 64))
        b = Image.open(path_b).convert("L").resize((64, 64))
        # dHash: compare adjacent pixel columns
        def _dhash(img):
            pixels = list(img.getdata())
            diff = 0
            for row in range(64):
                for col in range(63):
                    idx = row * 64 + col
                    if pixels[idx] < pixels[idx + 1]:
                        diff |= (1 << (row * 64 + col))
            return diff
        h1 = _dhash(a)
        h2 = _dhash(b)
        # Hamming distance
        xor = h1 ^ h2
        dist = xor.bit_count() if hasattr(int, "bit_count") else bin(xor).count("1")
        return 1.0 - (dist / (64 * 63))
    except Exception:
        return None



def run_screenshot_diff(hosts: list, output_dir: str,
                         previous_dir: str | None = None) -> dict:
    """Compare current screenshots against previous run. Detects visual changes."""
    findings = []
    checks = 0
    now = datetime.now().isoformat(timespec="seconds")

    if not previous_dir or not os.path.isdir(previous_dir):
        return {
            "findings": [], "total": 0,
            "note": "no previous screenshot directory for comparison",
            "scanned_at": now,
        }

    if not os.path.isdir(output_dir):
        return {
            "findings": [], "total": 0,
            "note": "current screenshot directory not found",
            "scanned_at": now,
        }

    try:
        current_files = {f for f in os.listdir(output_dir) if f.endswith(".png")}
        previous_files = {f for f in os.listdir(previous_dir) if f.endswith(".png")}
    except Exception:
        return {"findings": [], "total": 0, "error": "cannot list screenshot dirs", "scanned_at": now}

    for fname in current_files:
        if fname not in previous_files:
            findings.append({
                "type": "screenshot_diff",
                "host": re.sub(r"https?_?|_?\.png", "", fname).replace("_", ".")[:120],
                "change": "new_host",
                "detail": "new screenshot — host not in previous run",
                "severity": "info",
                "file": fname,
            })
            continue

        curr_path = os.path.join(output_dir, fname)
        prev_path = os.path.join(previous_dir, fname)
        checks += 1
        similarity = _image_similarity(curr_path, prev_path)
        if similarity is not None and similarity < 0.85:
            pct = round((1 - similarity) * 100, 1)
            findings.append({
                "type": "screenshot_diff",
                "host": re.sub(r"https?_?|_?\.png", "", fname).replace("_", ".")[:120],
                "change": f"visual_change_{pct}pct",
                "detail": f"page changed {pct}% visually since last scan",
                "severity": "medium" if similarity < 0.60 else "low",
                "file": fname,
                "similarity": round(similarity, 3),
            })

    # Also detect hosts that disappeared since last run
    for fname in previous_files - current_files:
        findings.append({
            "type": "screenshot_diff",
            "host": re.sub(r"https?_?|_?\.png", "", fname).replace("_", ".")[:120],
            "change": "host_gone",
            "detail": "host had screenshot previously but not in current run",
            "severity": "info",
            "file": fname,
        })

    return {
        "findings": findings,
        "total": len(findings),
        "comparisons_done": checks,
        "current_screenshots": len(current_files),
        "previous_screenshots": len(previous_files),
        "scanned_at": now,
    }
