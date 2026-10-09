/* origin-link.js — resolve a found item to the live origin (http/https only).
 * window.ASMOrigin.originHref / originLinkHtml / originHostChip / isJsPathNoise
 */
(function () {
  "use strict";

  var BLOCK = /^(javascript|data|vbscript|file|about):/i;
  var FS_PATH = /^(\/home\/|\/tmp\/|\/var\/|\/opt\/|\/usr\/|[A-Za-z]:[\\/]|\\\\)/;
  var HOSTISH = /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(:\d+)?$/i;
  var HOST_PATH = /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(:\d+)?(\/.*)?$/i;
  var IPV4 = /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/;
  var FILE_EXT = /\.(js|mjs|cjs|css|map|json|html?|xml|txt|svg|woff2?|ttf|png|jpe?g|gif|webp)(\?.*)?$/i;
  var MIME_RE = /^(text|application|image|audio|video|font|multipart)\/[a-z0-9.+-]+$/i;
  var DATEMASK_RE = /^(?:MM|dd|yyyy|yy|HH|mm|ss|\d{2,4}|9{2,4})[/.\\-](?:MM|dd|yyyy|yy|HH|mm|ss|\d{2,4}|9{2,4})/;
  var TZ_RE = /^[A-Z][a-zA-Z]+\/[A-Z][a-zA-Z_]+$/;
  var SDK_RE = /^(firebase|react|rxjs|vue|angular|@angular|@babel|core-js|lodash)\//;

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function stripHost(host) {
    var h = String(host == null ? "" : host).trim();
    h = h.replace(/^https?:\/\//i, "");
    h = h.split("/")[0];
    h = h.replace(/^\.+/, "").replace(/\.+$/, "");
    return h;
  }

  function isRelModule(s) {
    return s.indexOf("./") === 0 || s.indexOf("../") === 0 || s.indexOf("..") === 0;
  }

  function isJsPathNoise(path) {
    var s = String(path == null ? "" : path).trim();
    if (!s) return true;
    if (/^https?:\/\//i.test(s) || (s.indexOf("//") === 0 && s.length > 3 && s.charAt(2) !== "/")) {
      return false;
    }
    if (s.charAt(0) === "/" && s.charAt(1) !== "/") return false;
    if (MIME_RE.test(s)) return true;
    if (DATEMASK_RE.test(s)) return true;
    if (TZ_RE.test(s)) return true;
    if (s.indexOf("__bundle__") !== -1) return true;
    if (SDK_RE.test(s)) return true;
    if (isRelModule(s) || s.indexOf("/../") !== -1 || s.indexOf("/./") !== -1) return true;
    return false;
  }

  function safeHttpUrl(href) {
    try {
      var u = new URL(href);
      if (u.protocol !== "http:" && u.protocol !== "https:") return "";
      if (BLOCK.test(u.href)) return "";
      if (u.pathname === "/" && !u.search && !u.hash) return u.origin;
      return u.href;
    } catch (e) {
      return "";
    }
  }

  function originHref(raw, host) {
    var s = String(raw == null ? "" : raw).trim();
    var hostRaw = String(host == null ? "" : host).trim();
    var h = stripHost(hostRaw);
    if (s && BLOCK.test(s)) return "";
    if (s && FS_PATH.test(s)) return "";
    if (s && MIME_RE.test(s)) return "";
    if (s && DATEMASK_RE.test(s)) return "";
    if (s && TZ_RE.test(s)) return "";

    var base = "";
    if (/^https?:\/\//i.test(hostRaw)) base = hostRaw;
    else if (h) base = "https://" + h + "/";

    if (s) {
      if (/^https?:\/\//i.test(s)) return safeHttpUrl(s);
      if (s.indexOf("//") === 0 && s.length > 3 && s.charAt(2) !== "/") {
        return safeHttpUrl("https:" + s);
      }
      if (s.charAt(0) === "/" && h) return safeHttpUrl("https://" + h + s);
      if (s.indexOf(" ") === -1 && !isRelModule(s)) {
        var candidate = s.replace(/^\/+/, "").replace(/^\.+/, "");
        if (HOST_PATH.test(candidate) && (candidate.indexOf("/") !== -1 || !FILE_EXT.test(candidate))) {
          return safeHttpUrl("https://" + candidate);
        }
      }
      if (base && s.indexOf(" ") === -1 && /^[\w./?&=%~+-]+$/.test(s)) {
        try {
          return safeHttpUrl(new URL(s, base).href);
        } catch (e) {
          return "";
        }
      }
      return "";
    }
    if (h && (HOSTISH.test(h) || IPV4.test(h))) return "https://" + h;
    return "";
  }

  function originLinkHtml(raw, label, opts) {
    opts = opts || {};
    var href = originHref(raw, opts.host);
    var text = label != null && String(label) !== "" ? String(label) : String(raw || opts.host || "");
    var cls = opts.className || "origin-link";
    var title = opts.title || "Abrir o local em que foi achado";
    if (!href) {
      return '<span class="' + esc(cls) + ' origin-plain">' + esc(text || "—") + "</span>";
    }
    var stop = opts.stop === false ? "" : ' onclick="event.stopPropagation()"';
    return (
      '<a class="' + esc(cls) + '" href="' + esc(href) +
      '" target="_blank" rel="noopener noreferrer" title="' + esc(title) + '"' +
      stop + ">" + esc(text) + "</a>"
    );
  }

  function originHostChip(host, extraClass) {
    var cls = extraClass || "fg-host-chip origin-link";
    if (cls.indexOf("origin-link") === -1) cls += " origin-link";
    return originLinkHtml("", host, {
      host: host,
      className: cls,
      title: "Abrir host"
    });
  }

  var api = {
    originHref: originHref,
    originLinkHtml: originLinkHtml,
    originHostChip: originHostChip,
    isJsPathNoise: isJsPathNoise
  };

  if (typeof window !== "undefined") window.ASMOrigin = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})();
