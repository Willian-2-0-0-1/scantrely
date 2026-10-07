/* T2/F15 — asset graph (SVG, no D3). Prefers surface_intel CNAME/CDN/NS edges.
 * ui-ux-pro-max: legend is filterable, labels are collision-aware, color is
 * complementary to the chip text, hover/focus exposes the full hostname.
 */
(function () {
  var KIND_META = {
    host:    { label: "Host", color: "#38BDF8", ring: 150 },
    ip:      { label: "IP",   color: "#A78BFA", ring: 220 },
    cdn:     { label: "CDN",  color: "#FBBF24", ring: 260 },
    ns:      { label: "NS",   color: "#94A3B8", ring: 300 },
    related: { label: "CSP",  color: "#FB7185", ring: 330 },
    tech:    { label: "Tech", color: "#22C55E", ring: 360 }
  };
  var KIND_ORDER = ["host", "ip", "cdn", "ns", "related", "tech"];
  var hiddenKinds = {};
  var labelMode = "smart"; // smart | all | none
  var selectedId = null;

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

  function renderAssetGraph(co) {
    var el = document.getElementById("tab-graph");
    if (!el) return;
    var hosts = (co && co.hosts) || [];
    var intel = (co && co.surface_intel) || {};
    var intelGraph = intel.graph || [];
    var intelRecs = intel.records || [];
    if (!hosts.length && !intelRecs.length && !intelGraph.length) {
      el.innerHTML = '<div class="diff-empty">Nenhum host para montar o grafo. Rode um scan.</div>';
      return;
    }
    var nodes = [];
    var links = [];
    var seen = {};
    function addNode(id, label, kind) {
      if (seen[id]) return seen[id];
      var n = { id: id, label: label, kind: kind, degree: 0 };
      seen[id] = n;
      nodes.push(n);
      return n;
    }
    function kindOf(label, rel) {
      if (rel === "cname" || /\.cloudfront\.net$|\.azurefd\.net$|\.impervadns\.net$/i.test(label)) return "cdn";
      if (rel === "ns") return "ns";
      if (rel === "csp") return "related";
      if (rel === "a" || /^\d+\.\d+\.\d+\.\d+$/.test(label)) return "ip";
      if (rel === "cdn") return "cdn";
      return "host";
    }
    intelGraph.slice(0, 160).forEach(function (e) {
      if (!e || !e.from || !e.to) return;
      var a = addNode("n:" + e.from, e.from, "host");
      var b = addNode("n:" + e.to, e.to, kindOf(String(e.to), e.rel));
      links.push({ a: a, b: b, rel: e.rel || "" });
    });
    intelRecs.forEach(function (r) {
      if (!r || !r.host || !r.exists) return;
      addNode("n:" + r.host, r.host, "host");
    });
    hosts.slice(0, 80).forEach(function (h) {
      if (!h || typeof h !== "object") return;
      var host = h.host || "";
      if (!host) return;
      var hn = addNode("n:" + host, host, "host");
      if (h.cname) {
        var cn = addNode("n:" + h.cname, h.cname, "cdn");
        links.push({ a: hn, b: cn, rel: "cname" });
      }
      if (h.ip) {
        var ipn = addNode("n:" + h.ip, h.ip, "ip");
        links.push({ a: hn, b: ipn, rel: "a" });
      }
      if (h.cdn) {
        var cdn = addNode("cdn:" + h.cdn, h.cdn, "cdn");
        links.push({ a: hn, b: cdn, rel: "cdn" });
      }
      (h.technologies || []).slice(0, 3).forEach(function (t) {
        var tn = addNode("t:" + t, String(t), "tech");
        links.push({ a: hn, b: tn, rel: "tech" });
      });
    });
    (intel.related || []).slice(0, 20).forEach(function (r) {
      var rh = r.host || r;
      if (!rh) return;
      var n = addNode("n:" + rh, rh, "related");
      if (r.source_host) {
        var src = addNode("n:" + r.source_host, r.source_host, "host");
        links.push({ a: src, b: n, rel: "csp" });
      }
    });
    if (!nodes.length) {
      el.innerHTML = '<div class="diff-empty">Nenhum host para montar o grafo. Rode um scan.</div>';
      return;
    }

    links.forEach(function (l) {
      l.a.degree += 1;
      l.b.degree += 1;
    });

    var visNodes = nodes.filter(function (n) { return !hiddenKinds[n.kind]; });
    var visSet = {};
    visNodes.forEach(function (n) { visSet[n.id] = true; });
    var visLinks = links.filter(function (l) { return visSet[l.a.id] && visSet[l.b.id]; });

    var w = Math.max(el.clientWidth || 900, 640);
    var hgt = 560;
    var cx = w / 2, cy = hgt / 2;
    var byKind = {};
    visNodes.forEach(function (n) {
      (byKind[n.kind] || (byKind[n.kind] = [])).push(n);
    });
    KIND_ORDER.forEach(function (kind, ki) {
      var group = byKind[kind] || [];
      var ring = (KIND_META[kind] || {}).ring || 200;
      var offset = (ki * 0.37);
      group.forEach(function (n, i) {
        var ang = offset + (i / Math.max(group.length, 1)) * Math.PI * 2;
        n.x = cx + Math.cos(ang) * ring;
        n.y = cy + Math.sin(ang) * ring * 0.70;
      });
    });

    var color = {};
    Object.keys(KIND_META).forEach(function (k) { color[k] = KIND_META[k].color; });

    var showLabel = {};
    if (labelMode !== "none") {
      var placed = [];
      var ranked = visNodes.slice().sort(function (a, b) {
        var pa = KIND_ORDER.indexOf(a.kind);
        var pb = KIND_ORDER.indexOf(b.kind);
        if (a.kind === "host") pa = -1;
        if (b.kind === "host") pb = -1;
        if (pa !== pb) return pa - pb;
        return (b.degree || 0) - (a.degree || 0);
      });
      ranked.forEach(function (n) {
        if (labelMode === "smart") {
          if (n.kind === "tech" && n.degree < 3) return;
          if (n.kind === "related" && n.degree < 2) return;
        }
        var text = wrapLabel(String(n.label), n.kind === "host" ? 22 : 18);
        var tw = text.length * 6.2;
        var th = 12;
        var lx = n.x + 10;
        var ly = n.y - 4;
        var hit = false;
        for (var i = 0; i < placed.length; i++) {
          var p = placed[i];
          if (!(lx + tw < p.x || lx > p.x + p.w || ly + th < p.y || ly > p.y + p.h)) {
            hit = true;
            break;
          }
        }
        if (hit && labelMode === "smart") return;
        if (hit && labelMode === "all" && n.kind !== "host") return;
        placed.push({ x: lx, y: ly, w: tw, h: th });
        showLabel[n.id] = text;
      });
    }

    var lines = visLinks.map(function (l) {
      var dim = selectedId && l.a.id !== selectedId && l.b.id !== selectedId;
      return '<line x1="' + l.a.x.toFixed(1) + '" y1="' + l.a.y.toFixed(1) +
        '" x2="' + l.b.x.toFixed(1) + '" y2="' + l.b.y.toFixed(1) +
        '" stroke="' + (dim ? "rgba(148,163,184,.10)" : "rgba(148,163,184,.32)") +
        '" stroke-width="1"/>';
    }).join("");

    var dots = visNodes.map(function (n) {
      var title = escAttr(n.label);
      var kindLabel = (KIND_META[n.kind] || {}).label || n.kind;
      var r = n.kind === "host" ? 6 : 4.5;
      var lbl = showLabel[n.id];
      var sel = selectedId === n.id;
      return '<g class="graph-node" tabindex="0" role="button" data-id="' + escAttr(n.id) +
        '" aria-label="' + title + " (" + kindLabel + ')" aria-pressed="' + sel + '">' +
        "<title>" + title + " · " + kindLabel + "</title>" +
        '<circle class="node-hit" cx="' + n.x.toFixed(1) + '" cy="' + n.y.toFixed(1) + '" r="14"/>' +
        '<circle class="node-dot" cx="' + n.x.toFixed(1) + '" cy="' + n.y.toFixed(1) +
        '" r="' + r + '" fill="' + (color[n.kind] || "#94a3b8") + '"' +
        (sel ? ' stroke="var(--color-ring)" stroke-width="2"' : "") + "/>" +
        (lbl
          ? '<text x="' + (n.x + 9).toFixed(1) + '" y="' + (n.y + 3).toFixed(1) + '">' +
            escAttr(lbl) + "</text>"
          : "") +
        "</g>";
    }).join("");

    var summary = intel.summary || {};
    var extra = summary.cdn && summary.cdn.length
      ? " · CDN " + summary.cdn.join(", ")
      : "";
    var legend = Object.keys(KIND_META).map(function (k) {
      var m = KIND_META[k];
      var on = !hiddenKinds[k];
      return '<button type="button" class="graph-chip" data-kind="' + k + '" aria-pressed="' + on + '">' +
        '<span class="swatch" style="background:' + m.color + '"></span>' + m.label + "</button>";
    }).join("");

    var modes = [
      { id: "smart", label: "Rótulos: auto" },
      { id: "all", label: "Todos" },
      { id: "none", label: "Nenhum" }
    ].map(function (m) {
      return '<button type="button" class="graph-chip" data-labels="' + m.id +
        '" aria-pressed="' + (labelMode === m.id) + '">' + m.label + "</button>";
    }).join("");

    var detail = "";
    if (selectedId && seen[selectedId]) {
      var sn = seen[selectedId];
      var neigh = visLinks.filter(function (l) {
        return l.a.id === selectedId || l.b.id === selectedId;
      }).map(function (l) {
        var other = l.a.id === selectedId ? l.b : l.a;
        return (l.rel || "link") + " → " + other.label;
      });
      detail = '<div class="graph-detail" role="status">' +
        "<strong>" + escAttr(sn.label) + "</strong> · " +
        escAttr((KIND_META[sn.kind] || {}).label || sn.kind) +
        " · " + sn.degree + " ligações" +
        (neigh.length ? "<br>" + neigh.slice(0, 8).map(escAttr).join(" · ") : "") +
        "</div>";
    } else {
      detail = '<div class="graph-detail" role="status">Clique um nó para ver o hostname completo e as ligações. Passe o mouse para o rótulo integral.</div>';
    }

    el.innerHTML =
      '<div class="section-hdr"><h3>Grafo de ativos</h3><span class="section-count">' +
      visNodes.length + " nós · " + visLinks.length + " ligações" + extra +
      "</span></div>" +
      '<div class="modal-hint">CNAME/CDN/NS e origens do CSP (equivalente à aba Relations do VirusTotal, sem a API). Cor é complementar ao rótulo da legenda.</div>' +
      '<div class="graph-legend" role="group" aria-label="Filtrar tipos de nó">' + legend +
      '<span class="graph-legend-sep" aria-hidden="true"></span>' + modes + "</div>" +
      '<svg class="asset-graph" viewBox="0 0 ' + w + " " + hgt + '" width="100%" height="' + hgt +
      '" role="img" aria-label="Grafo de ativos da superfície">' +
      lines + dots + "</svg>" + detail;

    el.querySelectorAll(".graph-chip[data-kind]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var k = btn.getAttribute("data-kind");
        hiddenKinds[k] = !hiddenKinds[k];
        renderAssetGraph(co);
      });
    });
    el.querySelectorAll(".graph-chip[data-labels]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        labelMode = btn.getAttribute("data-labels") || "smart";
        renderAssetGraph(co);
      });
    });
    el.querySelectorAll(".graph-node").forEach(function (g) {
      function pick() {
        var id = g.getAttribute("data-id");
        selectedId = selectedId === id ? null : id;
        renderAssetGraph(co);
      }
      g.addEventListener("click", pick);
      g.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          pick();
        }
      });
    });
  }
  window.renderAssetGraph = renderAssetGraph;
})();
