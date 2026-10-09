/* operation-persist.js — flatten pipeline browser/crawl/JS persist for Operação.
 * window.ASMOperation.summarize(co) / screenshotServeUrl(cid, path)
 */
(function () {
  "use strict";

  function screenshotServeUrl(cid, raw) {
    var s = String(raw || "").trim();
    if (!s) return "";
    if (/^https?:\/\//i.test(s)) return s;
    s = s.replace(/\\/g, "/");
    var rest = "";
    var m = s.match(/(?:^|\/)screenshots\/(.+)$/i);
    if (m) {
      rest = m[1];
    } else if (s.charAt(0) === "/" || /^[a-zA-Z]:\//.test(s) || s.indexOf("/scans/") !== -1) {
      rest = s.split("/").filter(Boolean).pop() || "";
    } else {
      rest = s.replace(/^\/+/, "");
    }
    rest = rest.replace(/^screenshots\//i, "");
    cid = String(cid || "").trim();
    if (cid) {
      if (rest === cid) rest = "";
      else if (rest.indexOf(cid + "/") === 0) rest = rest.slice(cid.length + 1);
    }
    rest = rest.replace(/^\/+/, "");
    if (!rest || !cid) return "";
    var encoded = rest.split("/").filter(Boolean).map(function (seg) {
      return encodeURIComponent(seg);
    }).join("/");
    return "/screenshots/" + encodeURIComponent(cid) + "/" + encoded;
  }

  function asList(v) {
    return Array.isArray(v) ? v : [];
  }

  function addApi(map, item) {
    if (item == null) return;
    var url = typeof item === "string" ? item : String(item.url || item.path || "");
    if (!url) return;
    var method = "GET";
    var kind = "";
    if (typeof item === "object") {
      method = String(item.method || "GET").toUpperCase();
      kind = String(item.type || item.kind || "");
    }
    var key = method + " " + url;
    if (map.has(key)) return;
    map.set(key, { method: method, url: url, type: kind });
  }

  function isNoiseThird(s) {
    var t = String(s || "").trim();
    if (!t || t.length < 3) return true;
    if (t.indexOf(".") === -1 && /^[A-Za-z0-9_-]{8,}$/.test(t)) return true;
    return false;
  }

  function isNoiseObs(s) {
    var t = String(s || "");
    if (!t) return true;
    if (t.indexOf("Custom globals:") === 0) return true;
    return false;
  }

  function summarize(co) {
    co = co || {};
    var br = co.browser_recon_data || {};
    var bc = co.browser_crawl_data || {};
    var js = co.js_data || {};
    var pages = asList(br.results);
    var crawl = asList(bc.results);
    var apiMap = new Map();
    pages.forEach(function (p) {
      asList(p && p.api_endpoints).forEach(function (a) { addApi(apiMap, a); });
    });
    asList(bc.api_endpoints).forEach(function (a) { addApi(apiMap, a); });
    crawl.forEach(function (r) {
      asList(r && r.api_endpoints).forEach(function (a) { addApi(apiMap, a); });
    });
    asList(js.runtime_network).forEach(function (a) { addApi(apiMap, a); });
    var apis = Array.from(apiMap.values());

    var cookies = [];
    pages.forEach(function (p) {
      asList(p && p.cookies).forEach(function (c) {
        if (!c) return;
        cookies.push({
          name: c.name || "",
          domain: c.domain || "",
          httpOnly: !!c.httpOnly,
          secure: !!c.secure,
          sameSite: c.sameSite || "",
          page: (p && p.url) || ""
        });
      });
    });

    var observations = [];
    pages.forEach(function (p) {
      asList(p && p.observations).forEach(function (o) {
        if (isNoiseObs(o)) return;
        observations.push({ url: (p && p.url) || "", text: String(o) });
      });
    });

    var third = [];
    var thirdSeen = {};
    pages.forEach(function (p) {
      asList(p && p.third_party_services).forEach(function (s) {
        var label = String(s || "").trim();
        if (isNoiseThird(label) || thirdSeen[label]) return;
        thirdSeen[label] = true;
        third.push(label);
      });
    });

    var missingHeaders = [];
    pages.forEach(function (p) {
      var miss = (p && p.security_headers && p.security_headers.missing) || [];
      asList(miss).forEach(function (h) {
        missingHeaders.push({ url: (p && p.url) || "", header: String(h) });
      });
    });

    var forms = asList(bc.forms).slice();
    crawl.forEach(function (r) {
      asList(r && r.forms).forEach(function (f) { forms.push(f); });
    });

    var urls = asList(bc.urls).slice();
    if (!urls.length) {
      crawl.forEach(function (r) {
        asList(r && r.urls).forEach(function (u) { urls.push(u); });
      });
    }

    var runtimeJs = asList(js.runtime_js_urls);
    var jsFiles = asList(js.js_files);
    var runtimeNetwork = asList(js.runtime_network);
    var pageCount = pages.length;
    var urlCount = Number(bc.url_count || 0) || urls.length;
    var formCount = Number(bc.form_count || 0) || forms.length;
    var shots = Number(co.screenshots_count || 0);
    var has = pageCount > 0 || crawl.length > 0 || urlCount > 0 || apis.length > 0 ||
      runtimeJs.length > 0 || jsFiles.length > 0 || shots > 0;

    return {
      has: has,
      pages: pages,
      crawl: crawl,
      apis: apis,
      cookies: cookies,
      observations: observations,
      third: third,
      missingHeaders: missingHeaders,
      forms: forms,
      urls: urls,
      runtimeJs: runtimeJs,
      runtimeNetwork: runtimeNetwork,
      jsFiles: jsFiles,
      hostsScanned: Number(br.hosts_scanned || pageCount || 0),
      hostsCrawled: Number(bc.hosts_crawled || crawl.length || 0),
      urlCount: urlCount,
      apiCount: apis.length,
      formCount: formCount,
      cookieCount: Number(br.total_cookies || cookies.length || 0),
      insecureCookies: Number(br.insecure_cookies || 0),
      shots: shots,
      scannedAt: br.scanned_at || bc.scanned_at || js.scanned_at || co.last_scan || "",
      badge: pageCount || urlCount || apis.length || runtimeJs.length || shots || 0
    };
  }

  var api = {
    screenshotServeUrl: screenshotServeUrl,
    summarize: summarize
  };

  if (typeof window !== "undefined") window.ASMOperation = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})();
