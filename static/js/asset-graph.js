/* T2/F15 — asset graph (SVG, no D3).
 * ui-ux-pro-max Network Graph: cluster/LOD before >100 SVG nodes, shapes in
 * addition to color, adjacency list fallback, highlight path #F59E0B,
 * edges #90A4AE ~60%. Wheel zoom, pan, search, keyboard on the stage.
 */
(function () {
  "use strict";

  var KIND_META = {
    host:    { label: "Host",  color: "#38BDF8" },
    ip:      { label: "IP",    color: "#A78BFA" },
    cdn:     { label: "CDN",   color: "#FBBF24" },
    ns:      { label: "NS",    color: "#94A3B8" },
    related: { label: "CSP",   color: "#FB7185" },
    tech:    { label: "Tech",  color: "#22C55E" },
    cluster: { label: "Grupo", color: "#7DD3FC" }
  };
  var KIND_ORDER = ["host", "ip", "cdn", "ns", "related", "tech"];
  var MULTI_TLD = {
    "com.br": 1, "net.br": 1, "org.br": 1, "gov.br": 1, "edu.br": 1,
    "co.uk": 1, "org.uk": 1, "ac.uk": 1, "com.au": 1, "net.au": 1,
    "co.jp": 1, "com.mx": 1, "co.za": 1, "com.ar": 1
  };

  var hiddenKinds = {};
  var labelMode = "smart";
  var selectedId = null;
  var view = { x: 0, y: 0, k: 1 };
  var clustered = true;
  var expanded = {};
  var query = "";
  var listMode = false;
  var currentCo = null;
  var lastLayoutKey = "";
  var lastPositions = {};
  var lastGrav = {};
  var dragging = null;
  var nodeIndex = {};

  function tt(key, fallback) {
    if (typeof window !== "undefined" && typeof window.t === "function") {
      var v = window.t(key);
      if (v && v !== key) return v;
    }
    return fallback;
  }

  function wrapLabel(s, n) {
    s = String(s || "");
    if (s.length <= n) return s;
    return s.slice(0, n - 1) + "…";
  }

  function escAttr(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function escHtml(s) { return escAttr(s).replace(/'/g, "&#39;"); }

  function apexDomain(host) {
    var s = String(host || "").toLowerCase().replace(/\.$/, "").trim();
    if (!s) return "";
    s = s.split("/")[0].split(":")[0];
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)) return s;
    var parts = s.split(".").filter(Boolean);
    if (parts.length <= 2) return s;
    var last2 = parts.slice(-2).join(".");
    if (MULTI_TLD[last2] && parts.length >= 3) return parts.slice(-3).join(".");
    return last2;
  }

  function clusterKey(label, kind) {
    var s = String(label || "").toLowerCase().replace(/\.$/, "");
    if (kind === "tech") return "tech";
    if (kind === "ip" || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)) return "ip";
    if (s === "imperva" || /\.impervadns\.net$/.test(s)) return "imperva";
    if (/\.cloudfront\.net$/.test(s) || s === "aws cloudfront") return "cloudfront";
    if (/\.awsdns-[0-9a-z]+\./.test(s) || /^ns-\d+\.awsdns/.test(s)) return "aws-dns";
    if (/\.azurefd\.net$|\.azurewebsites\.net$|\.azure-dns\./.test(s)) return "azure";
    if (kind === "cdn") return "cdn:" + (apexDomain(s) || s);
    if (kind === "ns") return "ns:" + (apexDomain(s) || s);
    if (kind === "related") return "csp:" + (apexDomain(s) || s);
    return apexDomain(s) || s;
  }

  function kindOf(label, rel) {
    var s = String(label || "");
    if (rel === "cname" || /\.cloudfront\.net$|\.azurefd\.net$|\.impervadns\.net$/i.test(s)) return "cdn";
    if (rel === "ns") return "ns";
    if (rel === "csp") return "related";
    if (rel === "a" || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)) return "ip";
    if (rel === "cdn") return "cdn";
    if (rel === "tech") return "tech";
    return "host";
  }

  var CAPTION_ALIAS = {
    ip: "IPs",
    tech: "Tech",
    "related-rest": "CSP",
    "aws-dns": "AWS DNS",
    cloudfront: "CloudFront",
    imperva: "Imperva",
    azure: "Azure",
    "cdn-rest": "CDN",
    "ip-rest": "IPs"
  };

  function captionText(key) {
    var k = String(key || "");
    if (CAPTION_ALIAS[k]) return CAPTION_ALIAS[k];
    return k.replace(/^(cdn:|ns:|csp:)/, "");
  }

  function shortLabel(n) {
    if (!n) return "";
    if (n.kind === "cluster") {
      var m = String(n.label || "").match(/^\+(\d+)/);
      return m ? "+" + m[1] : wrapLabel(n.label, 16);
    }
    if (n.kind === "ip" || n.kind === "tech") return wrapLabel(n.label, 18);
    var apex = n.cluster && n.cluster.indexOf(":") === -1 ? n.cluster : apexDomain(n.label);
    var s = String(n.label || "");
    if (apex && s.toLowerCase() !== apex && s.toLowerCase().slice(-(apex.length + 1)) === "." + apex) {
      return wrapLabel(s.slice(0, s.length - apex.length - 1), 20);
    }
    return wrapLabel(s, 22);
  }

  function addNodeMap(seen, nodes, id, label, kind) {
    if (seen[id]) return seen[id];
    var n = { id: id, label: String(label || ""), kind: kind, cluster: clusterKey(label, kind), degree: 0 };
    seen[id] = n;
    nodes.push(n);
    return n;
  }

  function collectRaw(co) {
    var hosts = (co && co.hosts) || [];
    var intel = (co && co.surface_intel) || {};
    var intelGraph = intel.graph || [];
    var intelRecs = intel.records || [];
    var nodes = [];
    var links = [];
    var seen = {};

    function add(id, label, kind) { return addNodeMap(seen, nodes, id, label, kind); }
    function link(a, b, rel) {
      if (!a || !b || a.id === b.id) return;
      links.push({ a: a.id, b: b.id, rel: rel || "" });
    }

    intelGraph.forEach(function (e) {
      if (!e || !e.from || !e.to) return;
      var a = add("n:" + e.from, e.from, "host");
      var b = add("n:" + e.to, e.to, kindOf(String(e.to), e.rel));
      link(a, b, e.rel || "");
    });
    intelRecs.forEach(function (r) {
      if (!r || !r.host || r.exists === false) return;
      add("n:" + r.host, r.host, "host");
    });
    (intel.related || []).slice(0, 40).forEach(function (r) {
      var rh = (r && (r.host || r)) || "";
      if (!rh) return;
      var n = add("n:" + rh, rh, "related");
      if (r && r.source_host) {
        var src = add("n:" + r.source_host, r.source_host, "host");
        link(src, n, "csp");
      }
    });

    var extra = 0;
    var extraCap = 180;
    var techCount = {};
    hosts.forEach(function (h) {
      if (!h || typeof h !== "object") return;
      var host = h.host || "";
      if (!host) return;
      var already = !!seen["n:" + host];
      if (!already && extra >= extraCap) return;
      if (!already) extra += 1;
      var hn = add("n:" + host, host, "host");
      if (h.cname) link(hn, add("n:" + h.cname, h.cname, "cdn"), "cname");
      if (h.ip) link(hn, add("n:" + h.ip, h.ip, "ip"), "a");
      if (h.cdn) link(hn, add("cdn:" + h.cdn, h.cdn, "cdn"), "cdn");
      (h.technologies || []).slice(0, 2).forEach(function (t) {
        var name = String(t || "");
        if (!name) return;
        techCount[name] = (techCount[name] || 0) + 1;
        if (techCount[name] === 2) {
          var tn = add("t:" + name, name, "tech");
          link(hn, tn, "tech");
        } else if (techCount[name] > 2 && seen["t:" + name]) {
          link(hn, seen["t:" + name], "tech");
        }
      });
    });

    var deg = {};
    links.forEach(function (l) {
      deg[l.a] = (deg[l.a] || 0) + 1;
      deg[l.b] = (deg[l.b] || 0) + 1;
    });
    nodes.forEach(function (n) { n.degree = deg[n.id] || 0; });
    return { nodes: nodes, links: links, seen: seen };
  }

  function collapseLeaves(nodes, links, opts) {
    opts = opts || {};
    var exp = opts.expanded || {};
    var pinned = opts.pinned || {};
    var hostKeep = opts.hostKeep || 7;
    var hostMin = opts.hostMin || 9;
    var ipKeep = opts.ipKeep || 12;
    var ipMin = opts.ipMin || 18;
    var hide = {};
    var supers = [];
    var collapsedKeys = {};
    var cdnKeep = opts.cdnKeep || 5;
    var cdnMin = opts.cdnMin || 8;
    var nsKeep = opts.nsKeep || 4;
    var nsMin = opts.nsMin || 8;
    var relKeep = opts.relKeep || 8;
    var relMin = opts.relMin || 12;
    var techKeep = opts.techKeep || 8;
    var techMin = opts.techMin || 12;

    function collapseGroup(key, members, keepN, minN, superId, superLabel) {
      if (!members || members.length < minN) return;
      var localKeep = keepN;
      if (exp[key] || exp[superId]) localKeep = Math.max(keepN, 36);
      if (members.length <= localKeep) return;
      members = members.slice().sort(function (a, b) {
        return (b.degree || 0) - (a.degree || 0);
      });
      var keep = {};
      members.forEach(function (n) {
        if (pinned[n.id] || pinned[String(n.label || "").toLowerCase()]) keep[n.id] = true;
        if (String(n.label || "").toLowerCase() === String(key).toLowerCase()) keep[n.id] = true;
      });
      members.forEach(function (n) {
        if (Object.keys(keep).length >= localKeep) return;
        keep[n.id] = true;
      });
      var hiddenMembers = members.filter(function (n) { return !keep[n.id]; });
      if (!hiddenMembers.length) return;
      supers.push({
        id: superId,
        label: superLabel.replace("{n}", String(hiddenMembers.length)),
        kind: "cluster",
        cluster: key,
        members: hiddenMembers.map(function (n) { return n.label; }),
        degree: hiddenMembers.length
      });
      hiddenMembers.forEach(function (n) { hide[n.id] = superId; });
      collapsedKeys[key] = true;
    }

    function collapseKind(kind, keepN, minN, superPrefix, labelTpl) {
      var by = {};
      nodes.forEach(function (n) {
        if (n.kind !== kind || hide[n.id]) return;
        var k = n.cluster || clusterKey(n.label, n.kind);
        n.cluster = k;
        (by[k] || (by[k] = [])).push(n);
      });
      Object.keys(by).forEach(function (k) {
        collapseGroup(k, by[k], keepN, minN, superPrefix + k, labelTpl);
      });
    }

    function collapseRemainders(kind, keepN, minN, superId, labelTpl) {
      var leftover = nodes.filter(function (n) {
        if (n.kind !== kind || hide[n.id]) return false;
        var k = n.cluster || clusterKey(n.label, n.kind);
        return !collapsedKeys[k];
      });
      collapseGroup(kind + "-rest", leftover, keepN, minN, superId, labelTpl);
    }

    var byHost = {};
    nodes.forEach(function (n) {
      if (n.kind !== "host") return;
      var k = n.cluster || clusterKey(n.label, n.kind);
      n.cluster = k;
      (byHost[k] || (byHost[k] = [])).push(n);
    });
    Object.keys(byHost).forEach(function (k) {
      collapseGroup(k, byHost[k], hostKeep, hostMin, "cluster:" + k, "+{n} hosts");
    });
    var ips = nodes.filter(function (n) { return n.kind === "ip"; });
    collapseGroup("ip", ips, ipKeep, ipMin, "cluster:ip", "+{n} IPs");
    collapseKind("cdn", cdnKeep, cdnMin, "cluster:cdn:", "+{n} CDN");
    collapseRemainders("cdn", 8, 12, "cluster:cdn-rest", "+{n} CDN");
    collapseKind("ns", nsKeep, nsMin, "cluster:ns:", "+{n} NS");
    collapseRemainders("related", relKeep, relMin, "cluster:csp", "+{n} CSP");
    var techs = nodes.filter(function (n) { return n.kind === "tech" && !hide[n.id]; });
    collapseGroup("tech", techs, techKeep, techMin, "cluster:tech", "+{n} tech");

    var idSet = {};
    var visNodes = [];
    nodes.forEach(function (n) {
      if (hide[n.id]) return;
      visNodes.push(n);
      idSet[n.id] = n;
    });
    supers.forEach(function (s) {
      visNodes.push(s);
      idSet[s.id] = s;
    });

    var visLinks = [];
    var seenL = {};
    links.forEach(function (l) {
      var a = hide[l.a] || l.a;
      var b = hide[l.b] || l.b;
      if (a === b) return;
      if (!idSet[a] || !idSet[b]) return;
      var k = (a < b ? a + "|" + b : b + "|" + a) + "|" + (l.rel || "");
      if (seenL[k]) return;
      seenL[k] = true;
      visLinks.push({ a: a, b: b, rel: l.rel || "" });
    });
    return { nodes: visNodes, links: visLinks, hide: hide };
  }

  function buildGraphModel(co, opts) {
    opts = opts || {};
    var raw = collectRaw(co);
    var useCluster = opts.clustered !== false;
    var exp = opts.expanded || {};
    var pinned = Object.assign({}, opts.pinned || {});
    var q = String(opts.query || "").toLowerCase();
    if (q.length >= 2) {
      var hits = raw.nodes.filter(function (n) {
        return String(n.label || "").toLowerCase().indexOf(q) !== -1;
      });
      hits.slice(0, 12).forEach(function (n) { pinned[n.id] = true; });
    }
    var collapsed = useCluster
      ? collapseLeaves(raw.nodes, raw.links, {
          expanded: exp,
          pinned: pinned,
          hostKeep: opts.hostKeep,
          hostMin: opts.hostMin,
          ipKeep: opts.ipKeep,
          ipMin: opts.ipMin,
          cdnKeep: opts.cdnKeep,
          cdnMin: opts.cdnMin
        })
      : { nodes: raw.nodes.slice(), links: raw.links.slice(), hide: {} };
    if (!useCluster && collapsed.nodes.length > 160) {
      collapsed = collapseLeaves(raw.nodes, raw.links, {
        expanded: exp,
        pinned: pinned,
        hostKeep: 24,
        hostMin: 28,
        ipKeep: 20,
        ipMin: 24,
        cdnKeep: 10,
        cdnMin: 14
      });
    }
    if (collapsed.nodes.length > 100 && !Object.keys(exp).length) {
      collapsed = collapseLeaves(raw.nodes, raw.links, {
        expanded: exp,
        pinned: pinned,
        hostKeep: 5,
        hostMin: 7,
        ipKeep: 8,
        ipMin: 10,
        cdnKeep: 3,
        cdnMin: 5,
        nsKeep: 3,
        nsMin: 6,
        relKeep: 6,
        relMin: 8,
        techKeep: 6,
        techMin: 8
      });
    }
    return {
      nodes: collapsed.nodes,
      links: collapsed.links,
      rawNodeCount: raw.nodes.length,
      rawLinkCount: raw.links.length,
      hide: collapsed.hide || {}
    };
  }

  function layoutNodes(nodes, links, w, h) {
    var cx = w / 2, cy = h / 2;
    var grav = {};
    var hostKeys = [];
    var seenG = {};
    function gravityKey(n) {
      if (n.kind === "host") return n.cluster || "host";
      if (n.kind === "cluster") {
        var k = n.cluster || "";
        if (k === "ip") return "ip";
        if (k === "tech") return "tech";
        if (k === "related-rest" || k.indexOf("csp") === 0) return "related";
        if (k === "aws-dns" || k.indexOf("ns:") === 0) return "ns";
        if (k === "imperva" || k === "cloudfront" || k === "azure" || k.indexOf("cdn") === 0) return "cdn";
        return k;
      }
      if (n.kind === "ip") return "ip";
      return n.kind;
    }
    nodes.forEach(function (n) {
      var g = gravityKey(n);
      n._g = g;
      if (seenG[g]) return;
      seenG[g] = true;
      if (g !== "ip" && g !== "cdn" && g !== "ns" && g !== "related" && g !== "tech") hostKeys.push(g);
    });
    grav.ip = { x: cx, y: cy + 8 };
    grav.cdn = { x: cx + 70, y: cy - 28 };
    grav.ns = { x: cx - 70, y: cy + 36 };
    grav.related = { x: cx + 80, y: cy + 70 };
    grav.tech = { x: cx - 80, y: cy - 40 };
    hostKeys.forEach(function (g, i) {
      var nH = Math.max(hostKeys.length, 1);
      var ang = (nH === 1 ? -0.9 : -Math.PI / 2) + (i / nH) * Math.PI * 2;
      var R = Math.min(w, h) * (nH <= 2 ? 0.36 : 0.40);
      grav[g] = { x: cx + Math.cos(ang) * R, y: cy + Math.sin(ang) * R * 0.88 };
    });

    nodes.forEach(function (n, i) {
      var g = grav[n._g] || { x: cx, y: cy };
      var jitter = 36 + (n.kind === "cluster" ? 12 : 0);
      n._r = n.kind === "cluster" ? 14 : n.kind === "host" ? 8 : 6;
      if (lastPositions[n.id]) {
        n.x = lastPositions[n.id].x;
        n.y = lastPositions[n.id].y;
      } else {
        n.x = g.x + Math.cos(i * 2.399) * jitter;
        n.y = g.y + Math.sin(i * 2.399) * jitter * 0.9;
      }
      n.vx = 0;
      n.vy = 0;
    });

    var byId = {};
    nodes.forEach(function (n) { byId[n.id] = n; });
    var nN = nodes.length;
    var ticks = nN > 100 ? 45 : 70;
    var t;
    for (t = 0; t < ticks; t++) {
      var i, j, a, b, dx, dy, d2, d, minD, f, fx, fy;
      for (i = 0; i < nN; i++) {
        for (j = i + 1; j < nN; j++) {
          a = nodes[i];
          b = nodes[j];
          dx = a.x - b.x;
          dy = a.y - b.y;
          d2 = dx * dx + dy * dy || 0.01;
          d = Math.sqrt(d2);
          minD = (a._r || 8) + (b._r || 8) + (a._g === b._g ? 22 : 34);
          f = (minD * minD) / d2 * 0.7;
          fx = (dx / d) * f;
          fy = (dy / d) * f;
          a.vx += fx; a.vy += fy;
          b.vx -= fx; b.vy -= fy;
        }
      }
      links.forEach(function (l) {
        var na = byId[l.a], nb = byId[l.b];
        if (!na || !nb) return;
        dx = nb.x - na.x;
        dy = nb.y - na.y;
        d = Math.sqrt(dx * dx + dy * dy) || 0.01;
        f = (d - 96) * 0.012;
        fx = (dx / d) * f;
        fy = (dy / d) * f;
        na.vx += fx; na.vy += fy;
        nb.vx -= fx; nb.vy -= fy;
      });
      nodes.forEach(function (n) {
        var g = grav[n._g] || { x: cx, y: cy };
        n.vx += (g.x - n.x) * 0.028;
        n.vy += (g.y - n.y) * 0.028;
        n.vx += (cx - n.x) * 0.0004;
        n.vy += (cy - n.y) * 0.0004;
        n.vx *= 0.74;
        n.vy *= 0.74;
        n.x += n.vx;
        n.y += n.vy;
        n.x = Math.max(28, Math.min(w - 28, n.x));
        n.y = Math.max(28, Math.min(h - 28, n.y));
      });
    }
    lastPositions = {};
    nodes.forEach(function (n) { lastPositions[n.id] = { x: n.x, y: n.y }; });
    return grav;
  }

  function shapeMarkup(kind, x, y, r, fill, extra) {
    extra = extra || "";
    var cls = 'class="node-dot" fill="' + fill + '" ' + extra;
    var s;
    if (kind === "ip") {
      s = r * 1.7;
      return '<rect ' + cls + ' x="' + (x - s / 2).toFixed(1) + '" y="' + (y - s / 2).toFixed(1) +
        '" width="' + s.toFixed(1) + '" height="' + s.toFixed(1) + '" rx="1.5"/>';
    }
    if (kind === "cdn") {
      s = r * 1.55;
      return '<polygon ' + cls + ' points="' +
        x.toFixed(1) + "," + (y - s).toFixed(1) + " " +
        (x + s).toFixed(1) + "," + y.toFixed(1) + " " +
        x.toFixed(1) + "," + (y + s).toFixed(1) + " " +
        (x - s).toFixed(1) + "," + y.toFixed(1) + '"/>';
    }
    if (kind === "ns") {
      s = r * 1.75;
      return '<polygon ' + cls + ' points="' +
        x.toFixed(1) + "," + (y - s).toFixed(1) + " " +
        (x + s).toFixed(1) + "," + (y + s * 0.72).toFixed(1) + " " +
        (x - s).toFixed(1) + "," + (y + s * 0.72).toFixed(1) + '"/>';
    }
    if (kind === "related") {
      s = r * 1.55;
      var pts = [];
      var i;
      for (i = 0; i < 6; i++) {
        var ang = Math.PI / 6 + i * Math.PI / 3;
        pts.push((x + Math.cos(ang) * s).toFixed(1) + "," + (y + Math.sin(ang) * s).toFixed(1));
      }
      return '<polygon ' + cls + ' points="' + pts.join(" ") + '"/>';
    }
    if (kind === "tech") {
      s = r * 1.25;
      return '<rect ' + cls + ' x="' + (x - s).toFixed(1) + '" y="' + (y - s * 0.32).toFixed(1) +
        '" width="' + (s * 2).toFixed(1) + '" height="' + (s * 0.64).toFixed(1) + '" rx="1"/>' +
        '<rect ' + cls + ' x="' + (x - s * 0.32).toFixed(1) + '" y="' + (y - s).toFixed(1) +
        '" width="' + (s * 0.64).toFixed(1) + '" height="' + (s * 2).toFixed(1) + '" rx="1"/>';
    }
    if (kind === "cluster") {
      return '<circle ' + cls + ' cx="' + x.toFixed(1) + '" cy="' + y.toFixed(1) +
        '" r="' + (r * 1.85).toFixed(1) + '" fill-opacity=".2" stroke="' + fill +
        '" stroke-width="1.6" stroke-dasharray="4 3"/>';
    }
    return '<circle ' + cls + ' cx="' + x.toFixed(1) + '" cy="' + y.toFixed(1) + '" r="' + r + '"/>';
  }

  function swatchSvg(kind, color) {
    var c = color || "#94a3b8";
    if (kind === "ip") return '<svg class="graph-swatch" viewBox="0 0 12 12" aria-hidden="true"><rect x="2" y="2" width="8" height="8" rx="1" fill="' + c + '"/></svg>';
    if (kind === "cdn") return '<svg class="graph-swatch" viewBox="0 0 12 12" aria-hidden="true"><polygon points="6,1 11,6 6,11 1,6" fill="' + c + '"/></svg>';
    if (kind === "ns") return '<svg class="graph-swatch" viewBox="0 0 12 12" aria-hidden="true"><polygon points="6,1.5 11,10.5 1,10.5" fill="' + c + '"/></svg>';
    if (kind === "related") return '<svg class="graph-swatch" viewBox="0 0 12 12" aria-hidden="true"><polygon points="6,1 10.5,3.5 10.5,8.5 6,11 1.5,8.5 1.5,3.5" fill="' + c + '"/></svg>';
    if (kind === "tech") return '<svg class="graph-swatch" viewBox="0 0 12 12" aria-hidden="true"><rect x="2" y="5" width="8" height="2" fill="' + c + '"/><rect x="5" y="2" width="2" height="8" fill="' + c + '"/></svg>';
    return '<svg class="graph-swatch" viewBox="0 0 12 12" aria-hidden="true"><circle cx="6" cy="6" r="4" fill="' + c + '"/></svg>';
  }

  function clientToSvg(svg, clientX, clientY) {
    if (!svg.createSVGPoint) return { x: 0, y: 0 };
    var pt = svg.createSVGPoint();
    pt.x = clientX;
    pt.y = clientY;
    var ctm = svg.getScreenCTM();
    if (!ctm) return { x: 0, y: 0 };
    return pt.matrixTransform(ctm.inverse());
  }

  function applyView(svg) {
    var g = svg && svg.querySelector(".graph-viewport");
    if (!g) return;
    g.setAttribute("transform", "translate(" + view.x.toFixed(1) + "," + view.y.toFixed(1) + ") scale(" + view.k.toFixed(3) + ")");
  }

  function focusNode(svg, n, w, h) {
    if (!n || n.x == null || !svg) return;
    var vb = svg.viewBox.baseVal;
    var cx = (vb && vb.width) ? vb.x + vb.width / 2 : w / 2;
    var cy = (vb && vb.height) ? vb.y + vb.height / 2 : h / 2;
    view.k = Math.max(view.k, 1.25);
    view.x = cx - n.x * view.k;
    view.y = cy - n.y * view.k;
    applyView(svg);
  }

  function pickLabels(visNodes, q) {
    var show = {};
    if (labelMode === "none") return show;
    var placed = [];
    var qn = (q || "").toLowerCase();
    var ranked = visNodes.slice().sort(function (a, b) {
      var sa = 0, sb = 0;
      if (a.id === selectedId) sa += 100;
      if (b.id === selectedId) sb += 100;
      if (qn && String(a.label).toLowerCase().indexOf(qn) !== -1) sa += 50;
      if (qn && String(b.label).toLowerCase().indexOf(qn) !== -1) sb += 50;
      if (a.kind === "cluster") sa += 40;
      if (b.kind === "cluster") sb += 40;
      if (a.kind === "host" && a.label && a.cluster && a.label.toLowerCase() === a.cluster) sa += 30;
      if (b.kind === "host" && b.label && b.cluster && b.label.toLowerCase() === b.cluster) sb += 30;
      if (sa !== sb) return sb - sa;
      return (b.degree || 0) - (a.degree || 0);
    });
    var cap = labelMode === "all" ? visNodes.length : 18;
    ranked.forEach(function (n) {
      if (Object.keys(show).length >= cap) return;
      if (labelMode === "smart") {
        if (n.kind === "tech" && n.degree < 3 && n.id !== selectedId) return;
        if (n.kind === "related" && n.degree < 2 && n.id !== selectedId) return;
        if (n.kind === "ip" && n.degree < 3 && n.id !== selectedId && !(qn && String(n.label).toLowerCase().indexOf(qn) !== -1)) return;
        if (n.kind === "host" && n.cluster && String(n.label).toLowerCase() === String(n.cluster).toLowerCase() && n.id !== selectedId && !qn) return;
      }
      var text = shortLabel(n);
      var tw = text.length * 6.4;
      var th = 13;
      var lx = n.kind === "cluster" ? n.x - tw / 2 : n.x + 12;
      var ly = n.kind === "cluster" ? n.y + 4 : n.y - 6;
      var hit = false;
      var i;
      for (i = 0; i < placed.length; i++) {
        var p = placed[i];
        if (!(lx + tw < p.x || lx > p.x + p.w || ly + th < p.y || ly > p.y + p.h)) {
          hit = true;
          break;
        }
      }
      if (hit && labelMode === "smart" && n.id !== selectedId && !(qn && String(n.label).toLowerCase().indexOf(qn) !== -1)) return;
      if (hit && labelMode === "all" && n.kind !== "host" && n.kind !== "cluster") return;
      placed.push({ x: lx, y: ly, w: tw, h: th });
      show[n.id] = text;
    });
    return show;
  }

  function neighborMap(links, selected) {
    var out = [];
    if (!selected) return out;
    links.forEach(function (l) {
      if (l.a.id === selected) out.push({ rel: l.rel, node: l.b });
      else if (l.b.id === selected) out.push({ rel: l.rel, node: l.a });
    });
    return out;
  }

  function chromeHtml(stats) {
    var legend = KIND_ORDER.map(function (k) {
      var m = KIND_META[k];
      var on = !hiddenKinds[k];
      return '<button type="button" class="graph-chip" data-kind="' + k + '" aria-pressed="' + on + '">' +
        swatchSvg(k, m.color) + escHtml(m.label) + "</button>";
    }).join("");
    var modes = [
      { id: "smart", key: "graph_labels_auto", fb: "Rótulos: auto" },
      { id: "all", key: "graph_labels_all", fb: "Todos" },
      { id: "none", key: "graph_labels_none", fb: "Nenhum" }
    ].map(function (m) {
      return '<button type="button" class="graph-chip" data-labels="' + m.id +
        '" aria-pressed="' + (labelMode === m.id) + '">' + escHtml(tt(m.key, m.fb)) + "</button>";
    }).join("");
    var ico = (typeof window !== "undefined" && typeof window.icon === "function") ? window.icon : function () { return ""; };
    return '<div class="section-hdr"><h3>' + escHtml(tt("graph_title", "Grafo de ativos")) +
      '</h3><span class="section-count" id="graph-count">' + escHtml(stats) + "</span></div>" +
      '<p class="modal-hint" id="graph-hint">' +
      escHtml(tt("graph_hint", "Clusters agrupam folhas do mesmo apex. Arraste para mover, role para zoom, busque um host. Forma e cor identificam o tipo (equivalente à aba Relations do VirusTotal, sem a API).")) +
      "</p>" +
      '<div class="graph-toolbar">' +
      '<label class="sr-only" for="graph-search">' + escHtml(tt("graph_search", "Buscar host, IP ou CNAME")) + "</label>" +
      '<input type="search" id="graph-search" class="graph-search" value="' + escAttr(query) +
      '" placeholder="' + escAttr(tt("graph_search", "Buscar host, IP ou CNAME")) +
      '" autocomplete="off" spellcheck="false">' +
      '<div class="graph-zoom" role="group" aria-label="' + escAttr(tt("graph_zoom", "Zoom")) + '">' +
      '<button type="button" class="icon-btn" data-zoom="out" aria-label="' + escAttr(tt("graph_zoom_out", "Reduzir")) + '">−</button>' +
      '<button type="button" class="icon-btn" data-zoom="reset" aria-label="' + escAttr(tt("graph_zoom_reset", "Resetar zoom")) + '">1:1</button>' +
      '<button type="button" class="icon-btn" data-zoom="in" aria-label="' + escAttr(tt("graph_zoom_in", "Ampliar")) + '">+</button>' +
      "</div>" +
      '<button type="button" class="graph-chip" data-cluster="1" aria-pressed="' + clustered + '">' +
      escHtml(tt("graph_cluster", "Agrupar")) + "</button>" +
      '<button type="button" class="graph-chip" data-view="graph" aria-pressed="' + (!listMode) + '">' +
      escHtml(tt("graph_view_graph", "Grafo")) + "</button>" +
      '<button type="button" class="graph-chip" data-view="list" aria-pressed="' + listMode + '">' +
      ico("list", { size: 16 }) + " " + escHtml(tt("graph_view_list", "Lista")) + "</button>" +
      "</div>" +
      '<div class="graph-legend" role="group" aria-label="' + escAttr(tt("graph_filter", "Filtrar tipos de nó")) + '">' +
      legend + '<span class="graph-legend-sep" aria-hidden="true"></span>' + modes + "</div>" +
      '<div class="graph-stage" id="graph-stage">' +
      '<svg class="asset-graph" id="graph-svg" role="img" tabindex="0"></svg>' +
      '<div class="graph-tooltip" id="graph-tooltip" hidden></div>' +
      '<div class="graph-list-wrap" id="graph-list-wrap" hidden></div>' +
      "</div>" +
      '<div class="graph-detail" id="graph-detail" role="status"></div>';
  }

  function statsText(visN, visE, rawN, extra) {
    var s = visN + " visíveis · " + visE + " ligações";
    if (rawN && rawN > visN) s += " · " + rawN + " no inventário";
    if (extra) s += extra;
    return s;
  }

  function setDetail(el, html) {
    var d = el.querySelector("#graph-detail");
    if (d) d.innerHTML = html;
  }

  function detailHtml(sn, neigh, qMiss) {
    if (qMiss) {
      return escHtml(tt("graph_search_none", "Nenhum nó com «{q}». Tente o apex, o IP ou o CNAME.").replace("{q}", qMiss));
    }
    if (!sn) {
      return escHtml(tt("graph_detail_idle", "Clique um nó para o hostname completo e as ligações. Passe o mouse para o rótulo integral. Enter no grupo expande as folhas."));
    }
    var kindLabel = (KIND_META[sn.kind] || {}).label || sn.kind;
    var html = "<strong>" + escHtml(sn.label) + "</strong> · " + escHtml(kindLabel) +
      " · " + (sn.degree || 0) + " ligações";
    if (sn.cluster && sn.kind === "host") html += " · " + escHtml(sn.cluster);
    if (sn.kind === "cluster") {
      html += ' <button type="button" class="graph-chip graph-chip-inline" data-expand="' +
        escAttr(sn.cluster) + '">' + escHtml(tt("graph_expand", "Expandir")) + "</button>";
      if (sn.members && sn.members.length) {
        html += "<br>" + sn.members.slice(0, 12).map(escHtml).join(" · ");
        if (sn.members.length > 12) html += " · +" + (sn.members.length - 12);
      }
    }
    if (neigh.length) {
      html += '<ul class="graph-adj">';
      neigh.slice(0, 10).forEach(function (nb) {
        html += '<li><button type="button" class="graph-adj-btn" data-focus="' + escAttr(nb.node.id) + '">' +
          escHtml((nb.rel || "link") + " → " + nb.node.label) + "</button></li>";
      });
      html += "</ul>";
    }
    return html;
  }

  function paintList(el, visNodes) {
    var wrap = el.querySelector("#graph-list-wrap");
    var svg = el.querySelector("#graph-svg");
    var tip = el.querySelector("#graph-tooltip");
    if (tip) tip.hidden = true;
    if (svg) svg.setAttribute("hidden", "");
    if (!wrap) return;
    wrap.hidden = false;
    var qn = query.toLowerCase();
    var rows = visNodes.filter(function (n) {
      return !qn || String(n.label).toLowerCase().indexOf(qn) !== -1 || String(n.cluster || "").toLowerCase().indexOf(qn) !== -1;
    }).sort(function (a, b) { return (b.degree || 0) - (a.degree || 0); });
    if (!rows.length) {
      wrap.innerHTML = '<p class="diff-empty">' +
        escHtml(tt("graph_search_none", "Nenhum nó com «{q}». Tente o apex, o IP ou o CNAME.").replace("{q}", query)) +
        "</p>";
      return;
    }
    var body = rows.slice(0, 200).map(function (n) {
      var sel = n.id === selectedId ? ' class="is-selected"' : "";
      return "<tr" + sel + ' data-focus="' + escAttr(n.id) + '" tabindex="0">' +
        "<td>" + escHtml(n.label) + "</td>" +
        "<td>" + escHtml((KIND_META[n.kind] || {}).label || n.kind) + "</td>" +
        "<td>" + escHtml(n.cluster ? captionText(n.cluster) : "—") + "</td>" +
        "<td>" + (n.degree || 0) + "</td></tr>";
    }).join("");
    wrap.innerHTML = '<table class="graph-table"><caption class="sr-only">' +
      escHtml(tt("graph_table_cap", "Adjacência dos ativos visíveis")) +
      "</caption><thead><tr><th>" + escHtml(tt("graph_col_asset", "Ativo")) +
      "</th><th>" + escHtml(tt("graph_col_type", "Tipo")) +
      "</th><th>" + escHtml(tt("graph_col_cluster", "Cluster")) +
      "</th><th>" + escHtml(tt("graph_col_degree", "Ligações")) +
      "</th></tr></thead><tbody>" + body + "</tbody></table>";
  }

  function paintSvg(el, visNodes, visLinks, w, h, grav, extra) {
    var svg = el.querySelector("#graph-svg");
    var wrap = el.querySelector("#graph-list-wrap");
    if (wrap) wrap.hidden = true;
    if (!svg) return;
    svg.removeAttribute("hidden");
    var minx = Infinity, miny = Infinity, maxx = -Infinity, maxy = -Infinity;
    visNodes.forEach(function (n) {
      minx = Math.min(minx, n.x);
      miny = Math.min(miny, n.y);
      maxx = Math.max(maxx, n.x);
      maxy = Math.max(maxy, n.y);
    });
    if (!isFinite(minx)) { minx = 0; miny = 0; maxx = w; maxy = h; }
    var pad = 64;
    var bx = minx - pad, by = miny - pad, bw = Math.max(maxx - minx + pad * 2, 320), bh = Math.max(maxy - miny + pad * 2, 240);
    svg.setAttribute("viewBox", bx.toFixed(1) + " " + by.toFixed(1) + " " + bw.toFixed(1) + " " + bh.toFixed(1));
    svg.setAttribute("width", "100%");
    svg.setAttribute("height", String(h));
    svg.setAttribute("aria-label", tt("graph_title", "Grafo de ativos"));

    var qn = query.toLowerCase();
    var byId = {};
    visNodes.forEach(function (n) { byId[n.id] = n; });
    var resolved = visLinks.map(function (l) {
      return { a: byId[l.a], b: byId[l.b], rel: l.rel };
    }).filter(function (l) { return l.a && l.b; });

    var showLabel = pickLabels(visNodes, query);
    var captions = "";
    Object.keys(grav || {}).forEach(function (k) {
      if (k === "ip" || k === "cdn" || k === "ns" || k === "related" || k === "tech") return;
      var g = grav[k];
      if (!g) return;
      captions += '<text class="graph-caption" x="' + g.x.toFixed(1) + '" y="' + (g.y - 58).toFixed(1) +
        '" text-anchor="middle">' + escHtml(wrapLabel(captionText(k), 28)) + "</text>";
    });

    var lines = resolved.map(function (l) {
      var hi = selectedId && (l.a.id === selectedId || l.b.id === selectedId);
      var dim = selectedId && !hi;
      var dash = l.rel === "ns" ? "4 3" : l.rel === "csp" ? "2 3" : "";
      var stroke = hi ? "#F59E0B" : (dim ? "rgba(144,164,174,.12)" : "rgba(144,164,174,.60)");
      var sw = hi ? 2 : 1;
      return '<line x1="' + l.a.x.toFixed(1) + '" y1="' + l.a.y.toFixed(1) +
        '" x2="' + l.b.x.toFixed(1) + '" y2="' + l.b.y.toFixed(1) +
        '" stroke="' + stroke + '" stroke-width="' + sw + '"' +
        (dash ? ' stroke-dasharray="' + dash + '"' : "") + "/>";
    }).join("");

    var dots = visNodes.map(function (n) {
      var title = escAttr(n.label);
      var kindLabel = (KIND_META[n.kind] || {}).label || n.kind;
      var r = n.kind === "cluster" ? 12 : n.kind === "host" ? 6.5 : 5;
      var fill = (KIND_META[n.kind] || {}).color || "#94a3b8";
      var lbl = showLabel[n.id];
      var sel = selectedId === n.id;
      var match = qn && String(n.label).toLowerCase().indexOf(qn) !== -1;
      var extraStroke = sel || match
        ? ' stroke="#F59E0B" stroke-width="2"'
        : "";
      var tab = (sel || match || n.kind === "cluster") ? ' tabindex="0"' : ' tabindex="-1"';
      return '<g class="graph-node" role="button" data-id="' + escAttr(n.id) + '"' + tab +
        ' aria-label="' + title + " (" + kindLabel + ')" aria-pressed="' + sel + '">' +
        '<circle class="node-hit" cx="' + n.x.toFixed(1) + '" cy="' + n.y.toFixed(1) + '" r="18"/>' +
        shapeMarkup(n.kind, n.x, n.y, r, fill, extraStroke) +
        (lbl
          ? (n.kind === "cluster"
            ? '<text class="graph-cluster-lbl" text-anchor="middle" x="' + n.x.toFixed(1) + '" y="' + (n.y + 4).toFixed(1) + '">' + escHtml(lbl) + "</text>"
            : '<text x="' + (n.x + 11).toFixed(1) + '" y="' + (n.y + 3).toFixed(1) + '">' + escHtml(lbl) + "</text>")
          : "") +
        "</g>";
    }).join("");

    svg.innerHTML = '<g class="graph-viewport">' + captions + lines + dots + "</g>";
    applyView(svg);
    void extra;
  }

  function bindStage(el) {
    if (el.getAttribute("data-graph-bound") === "1") return;
    el.setAttribute("data-graph-bound", "1");

    el.addEventListener("click", function (ev) {
      var t = ev.target.closest("[data-kind],[data-labels],[data-cluster],[data-view],[data-zoom],[data-expand],[data-focus],.graph-node");
      if (!t || !el.contains(t)) return;
      if (t.getAttribute("data-kind")) {
        var k = t.getAttribute("data-kind");
        hiddenKinds[k] = !hiddenKinds[k];
        lastLayoutKey = "";
        renderAssetGraph(currentCo);
        return;
      }
      if (t.getAttribute("data-labels")) {
        labelMode = t.getAttribute("data-labels") || "smart";
        renderAssetGraph(currentCo);
        return;
      }
      if (t.getAttribute("data-cluster")) {
        clustered = !clustered;
        expanded = {};
        lastLayoutKey = "";
        view = { x: 0, y: 0, k: 1 };
        renderAssetGraph(currentCo);
        return;
      }
      if (t.getAttribute("data-view")) {
        listMode = t.getAttribute("data-view") === "list";
        renderAssetGraph(currentCo);
        return;
      }
      if (t.getAttribute("data-zoom")) {
        var svg = el.querySelector("#graph-svg");
        var z = t.getAttribute("data-zoom");
        if (z === "reset") view = { x: 0, y: 0, k: 1 };
        else {
          var factor = z === "in" ? 1.2 : 0.83;
          var vb = svg && svg.viewBox.baseVal;
          var cx = vb ? vb.x + vb.width / 2 : 500;
          var cy = vb ? vb.y + vb.height / 2 : 320;
          var k2 = Math.max(0.4, Math.min(4, view.k * factor));
          view.x = cx - ((cx - view.x) / view.k) * k2;
          view.y = cy - ((cy - view.y) / view.k) * k2;
          view.k = k2;
        }
        if (svg) applyView(svg);
        return;
      }
      if (t.getAttribute("data-expand")) {
        expanded[t.getAttribute("data-expand")] = true;
        lastLayoutKey = "";
        view = { x: 0, y: 0, k: 1 };
        renderAssetGraph(currentCo);
        return;
      }
      if (t.getAttribute("data-focus")) {
        selectedId = t.getAttribute("data-focus");
        renderAssetGraph(currentCo);
        return;
      }
      if (t.classList.contains("graph-node") || t.closest(".graph-node")) {
        var g = t.closest(".graph-node");
        var id = g.getAttribute("data-id");
        var node = nodeIndex[id];
        if (node && node.kind === "cluster" && node.cluster) {
          expanded[node.cluster] = true;
          lastLayoutKey = "";
          selectedId = null;
          view = { x: 0, y: 0, k: 1 };
        } else {
          selectedId = selectedId === id ? null : id;
        }
        renderAssetGraph(currentCo);
      }
    });

    el.addEventListener("input", function (ev) {
      if (ev.target && ev.target.id === "graph-search") {
        query = ev.target.value || "";
        renderAssetGraph(currentCo);
      }
    });
    el.addEventListener("keydown", function (ev) {
      if (ev.target && ev.target.getAttribute("data-focus") && (ev.key === "Enter" || ev.key === " ")) {
        ev.preventDefault();
        selectedId = ev.target.getAttribute("data-focus");
        listMode = false;
        renderAssetGraph(currentCo);
        return;
      }
      if (ev.target && ev.target.id === "graph-search" && ev.key === "Enter") {
        ev.preventDefault();
        var first = el.querySelector('.graph-node[tabindex="0"]');
        if (first) {
          selectedId = first.getAttribute("data-id");
          renderAssetGraph(currentCo);
        }
      }
      var svg = el.querySelector("#graph-svg");
      if (!svg || ev.target === el.querySelector("#graph-search")) return;
      if (document.activeElement !== svg && !svg.contains(document.activeElement)) return;
      if (ev.key === "+" || ev.key === "=") {
        ev.preventDefault();
        view.k = Math.min(4, view.k * 1.2);
        applyView(svg);
      } else if (ev.key === "-" || ev.key === "_") {
        ev.preventDefault();
        view.k = Math.max(0.4, view.k * 0.83);
        applyView(svg);
      } else if (ev.key === "0") {
        ev.preventDefault();
        view = { x: 0, y: 0, k: 1 };
        applyView(svg);
      } else if (ev.key === "ArrowLeft") {
        ev.preventDefault(); view.x += 40; applyView(svg);
      } else if (ev.key === "ArrowRight") {
        ev.preventDefault(); view.x -= 40; applyView(svg);
      } else if (ev.key === "ArrowUp") {
        ev.preventDefault(); view.y += 40; applyView(svg);
      } else if (ev.key === "ArrowDown") {
        ev.preventDefault(); view.y -= 40; applyView(svg);
      } else if (ev.key === "Enter" && selectedId) {
        var sn = nodeIndex[selectedId];
        if (sn && sn.kind === "cluster" && sn.cluster) {
          expanded[sn.cluster] = true;
          lastLayoutKey = "";
          renderAssetGraph(currentCo);
        }
      }
    });

    el.addEventListener("pointerdown", function (ev) {
      var svg = el.querySelector("#graph-svg");
      if (!svg || svg.hasAttribute("hidden")) return;
      if (ev.target.closest(".graph-node")) return;
      if (!ev.target.closest("#graph-svg")) return;
      dragging = { x: ev.clientX, y: ev.clientY, vx: view.x, vy: view.y, id: ev.pointerId };
      try { svg.setPointerCapture(ev.pointerId); } catch (err) { void err; }
    });
    el.addEventListener("pointermove", function (ev) {
      var svg = el.querySelector("#graph-svg");
      var tip = el.querySelector("#graph-tooltip");
      var stage = el.querySelector("#graph-stage");
      if (dragging && svg) {
        view.x = dragging.vx + (ev.clientX - dragging.x);
        view.y = dragging.vy + (ev.clientY - dragging.y);
        applyView(svg);
        return;
      }
      var node = ev.target.closest && ev.target.closest(".graph-node");
      if (tip && stage) {
        if (node) {
          var id = node.getAttribute("data-id");
          var n = nodeIndex[id];
          if (n) {
            tip.hidden = false;
            tip.textContent = n.label + " · " + ((KIND_META[n.kind] || {}).label || n.kind);
            var r = stage.getBoundingClientRect();
            tip.style.left = Math.min(r.width - 24, Math.max(8, ev.clientX - r.left + 12)) + "px";
            tip.style.top = Math.min(r.height - 24, Math.max(8, ev.clientY - r.top + 12)) + "px";
          }
        } else {
          tip.hidden = true;
        }
      }
    });
    el.addEventListener("pointerup", function () { dragging = null; });
    el.addEventListener("pointercancel", function () { dragging = null; });
    el.addEventListener("pointerleave", function () {
      var tip = el.querySelector("#graph-tooltip");
      if (tip) tip.hidden = true;
    });
    el.addEventListener("wheel", function (ev) {
      if (ev.ctrlKey) return;
      var svg = el.querySelector("#graph-svg");
      if (!svg || svg.hasAttribute("hidden")) return;
      if (!ev.target.closest("#graph-svg")) return;
      ev.preventDefault();
      var p = clientToSvg(svg, ev.clientX, ev.clientY);
      var factor = ev.deltaY < 0 ? 1.12 : 0.89;
      var k2 = Math.max(0.4, Math.min(4, view.k * factor));
      view.x = p.x - (p.x - view.x) * (k2 / view.k);
      view.y = p.y - (p.y - view.y) * (k2 / view.k);
      view.k = k2;
      applyView(svg);
    }, { passive: false });
  }

  function renderAssetGraph(co) {
    var el = (typeof document !== "undefined") ? document.getElementById("tab-graph") : null;
    if (!el) return;
    currentCo = co;
    var hosts = (co && co.hosts) || [];
    var intel = (co && co.surface_intel) || {};
    if (!hosts.length && !(intel.records || []).length && !(intel.graph || []).length) {
      el.removeAttribute("data-graph-co");
      el.removeAttribute("data-graph-bound");
      el.innerHTML = '<div class="diff-empty">' +
        escHtml(tt("graph_empty", "Nenhum host para montar o grafo. Rode um scan.")) + "</div>";
      return;
    }

    var coKey = String((co && (co.id || co.name)) || "");
    if (el.getAttribute("data-graph-co") !== coKey) {
      selectedId = null;
      view = { x: 0, y: 0, k: 1 };
      expanded = {};
      query = "";
      lastLayoutKey = "";
      lastPositions = {};
      lastGrav = {};
    }

    var model = buildGraphModel(co, { clustered: clustered, expanded: expanded, query: query });
    var visNodes = model.nodes.filter(function (n) {
      if (n.kind === "cluster") return true;
      return !hiddenKinds[n.kind];
    });
    var visSet = {};
    visNodes.forEach(function (n) { visSet[n.id] = true; });
    var visLinks = model.links.filter(function (l) { return visSet[l.a] && visSet[l.b]; });

    nodeIndex = {};
    visNodes.forEach(function (n) { nodeIndex[n.id] = n; });
    var idx = nodeIndex;

    var summary = intel.summary || {};
    var extra = summary.cdn && summary.cdn.length ? " · CDN " + summary.cdn.join(", ") : "";
    var stats = statsText(visNodes.length, visLinks.length, model.rawNodeCount, extra);

    if (el.getAttribute("data-graph-co") !== coKey) {
      el.setAttribute("data-graph-co", coKey);
      el.innerHTML = chromeHtml(stats);
      var searchEl = el.querySelector("#graph-search");
      if (searchEl) searchEl.value = query;
    } else {
      var countEl = el.querySelector("#graph-count");
      if (countEl) countEl.textContent = stats;
      el.querySelectorAll(".graph-chip[data-kind]").forEach(function (btn) {
        btn.setAttribute("aria-pressed", hiddenKinds[btn.getAttribute("data-kind")] ? "false" : "true");
      });
      el.querySelectorAll(".graph-chip[data-labels]").forEach(function (btn) {
        btn.setAttribute("aria-pressed", labelMode === btn.getAttribute("data-labels") ? "true" : "false");
      });
      var cl = el.querySelector("[data-cluster]");
      if (cl) cl.setAttribute("aria-pressed", clustered ? "true" : "false");
      var vg = el.querySelector('[data-view="graph"]');
      var vl = el.querySelector('[data-view="list"]');
      if (vg) vg.setAttribute("aria-pressed", listMode ? "false" : "true");
      if (vl) vl.setAttribute("aria-pressed", listMode ? "true" : "false");
    }
    bindStage(el);

    var qn = query.toLowerCase();
    var matches = qn ? visNodes.filter(function (n) {
      return String(n.label).toLowerCase().indexOf(qn) !== -1 || String(n.cluster || "").toLowerCase().indexOf(qn) !== -1;
    }) : [];
    var qMiss = qn && !matches.length ? query : "";

    if (listMode) {
      paintList(el, visNodes);
    } else {
      var w = Math.max(el.clientWidth || 900, 640);
      var hgt = Math.max(Math.min((typeof window !== "undefined" && window.innerHeight) ? Math.round(window.innerHeight * 0.62) : 640, 720), 480);
      var layoutKey = coKey + "|" + clustered + "|" + Object.keys(expanded).sort().join(",") + "|" +
        KIND_ORDER.map(function (k) { return hiddenKinds[k] ? k : ""; }).join("");
      var missing = visNodes.some(function (n) { return !lastPositions[n.id]; });
      var grav;
      if (layoutKey !== lastLayoutKey) {
        lastLayoutKey = layoutKey;
        lastPositions = {};
        view = { x: 0, y: 0, k: 1 };
        grav = layoutNodes(visNodes, visLinks, w, hgt);
        lastGrav = grav;
      } else if (missing) {
        grav = layoutNodes(visNodes, visLinks, w, hgt);
        lastGrav = grav;
      } else {
        visNodes.forEach(function (n) {
          n.x = lastPositions[n.id].x;
          n.y = lastPositions[n.id].y;
        });
        grav = lastGrav;
      }
      paintSvg(el, visNodes, visLinks, w, hgt, grav, extra);
      if (selectedId && idx[selectedId]) {
        var svg = el.querySelector("#graph-svg");
        if (qn && matches.length === 1) focusNode(svg, idx[selectedId], w, hgt);
      } else if (qn && matches.length === 1) {
        selectedId = matches[0].id;
        paintSvg(el, visNodes, visLinks, w, hgt, grav, extra);
        focusNode(el.querySelector("#graph-svg"), matches[0], w, hgt);
      }
    }

    var sn = selectedId ? idx[selectedId] : null;
    var resolvedLinks = visLinks.map(function (l) {
      return { a: idx[l.a], b: idx[l.b], rel: l.rel };
    }).filter(function (l) { return l.a && l.b; });
    setDetail(el, detailHtml(sn, neighborMap(resolvedLinks, selectedId), qMiss));
  }

  var api = {
    apexDomain: apexDomain,
    clusterKey: clusterKey,
    shortLabel: shortLabel,
    collapseLeaves: collapseLeaves,
    buildGraphModel: buildGraphModel,
    renderAssetGraph: renderAssetGraph
  };

  if (typeof window !== "undefined") {
    window.renderAssetGraph = renderAssetGraph;
    window.ScantrelyGraph = api;
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})();
