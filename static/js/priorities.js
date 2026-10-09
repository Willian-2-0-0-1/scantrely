// Prioridades — "o que fazer agora": lista curta de ações vinda de /api/data/company/<id>/priorities
(function () {
  "use strict";
  var SEV_CLASS = { critical: "crit", high: "high", medium: "med", low: "low", info: "info" };

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function hostsHtml(a) {
    if (!a.hosts.length) return "";
    var more = a.hosts_more ? ' <span class="pr-more">+' + a.hosts_more + "</span>" : "";
    return '<div class="pr-hosts">' + a.hosts.map(function (h) { return "<code>" + esc(h) + "</code>"; }).join(" ") + more + "</div>";
  }

  function card(a) {
    var cls = SEV_CLASS[a.severity] || "info";
    var kev = a.kev ? ' <span class="pr-tag pr-kev" title="Explorada ativamente (CISA KEV)">explorada</span>' : "";
    var n = a.count > 1 ? ' <span class="pr-count">' + a.count + " achados</span>" : "";
    return '<article class="pr-card pr-' + cls + '">' +
      '<div class="pr-rank">' + a.rank + "</div>" +
      '<div class="pr-body">' +
        '<div class="pr-head"><span class="pr-sev pr-sev-' + cls + '">' + esc(a.severity_label) + "</span>" +
        '<h3 class="pr-title">' + esc(a.title) + "</h3>" + kev + n + "</div>" +
        hostsHtml(a) +
        '<p class="pr-why"><b>Por quê:</b> ' + esc(a.why) + "</p>" +
        '<p class="pr-fix"><b>Como corrigir:</b> ' + esc(a.fix) + "</p>" +
      "</div>" +
      '<button type="button" class="btn btn-secondary pr-open" data-tab="' + esc(a.tab) + '" data-q="' + esc(a.type) + '">Ver detalhes</button>' +
    "</article>";
  }

  window.renderPriorities = async function (cid) {
    var el = document.getElementById("ov-priorities");
    if (!el) return;
    el.setAttribute("aria-busy", "true");
    el.innerHTML = '<div class="pr-empty" role="status">Calculando prioridades…</div>';
    try {
      var r = await fetch("/api/data/company/" + encodeURIComponent(cid) + "/priorities", { headers: window._authHeaders ? window._authHeaders() : {} });
      if (!r.ok) throw new Error("HTTP " + r.status);
      var d = await r.json();
      var head = '<div class="pr-title-bar"><h2>O que fazer agora</h2><span class="pr-sub">' +
        (d.actions.length ? d.total + " ações a partir de " + d.findings_total + " achados" : "") + "</span></div>";
      if (!d.actions.length) {
        el.innerHTML = head + '<div class="pr-empty">Nenhuma ação pendente. Rode um scan para atualizar.</div>';
      } else {
        var rest = d.hidden ? '<button type="button" class="btn btn-secondary pr-all" data-tab="vulns">Ver mais ' + d.hidden + " ações e todos os achados</button>" : "";
        el.innerHTML = head + '<div class="pr-list">' + d.actions.map(card).join("") + "</div>" + rest;
      }
      el.onclick = function (ev) {
        var b = ev.target.closest("button[data-tab]");
        if (b && typeof window.switchTab === "function") window.switchTab(b.getAttribute("data-tab"));
      };
    } catch (e) {
      el.innerHTML = '<div class="pr-empty pr-error">Não foi possível calcular as prioridades (' + esc(e.message) + ").</div>";
    } finally {
      el.removeAttribute("aria-busy");
    }
  };
})();

// Fecha os menus <details> (Exportar / ⋯) ao clicar fora.
document.addEventListener("click", function (ev) {
  document.querySelectorAll("details.co-menu[open]").forEach(function (d) {
    if (!d.contains(ev.target)) d.removeAttribute("open");
  });
});
