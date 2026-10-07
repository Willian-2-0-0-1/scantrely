/* Infostealer exposure view — Cavalier-inspired search-first layout.
 * Source note: Hudson Rock Cavalier (public OSINT). Scantrely branding stays.
 */
(function () {
  "use strict";

  function t(key, fallback) {
    if (typeof window.t === "function") {
      var val = window.t(key);
      if (val && val !== key) return val;
    }
    return fallback || key;
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function authHeaders() {
    if (typeof window._authHeaders === "function") return window._authHeaders();
    var tok = null;
    try { tok = localStorage.getItem("asmToken") || localStorage.getItem("asm_token"); } catch (e) {}
    return tok ? { "X-Auth-Token": tok, "x-auth-token": tok } : {};
  }

  function fmtN(n) {
    n = Number(n) || 0;
    try {
      return n.toLocaleString(document.documentElement.lang || "pt-BR");
    } catch (e) {
      return String(n);
    }
  }

  function fmtDate(s) {
    if (!s) return "—";
    var d = new Date(s);
    if (isNaN(d.getTime())) return String(s);
    try {
      return d.toLocaleDateString(document.documentElement.lang || "pt-BR", {
        year: "numeric", month: "short", day: "2-digit"
      });
    } catch (e) {
      return String(s);
    }
  }

  function hydrate(root) {
    if (root && typeof window.hydrateIcons === "function") window.hydrateIcons(root);
    if (typeof window.applyI18n === "function") window.applyI18n();
  }

  function hudsonFrom(payload) {
    if (!payload || typeof payload !== "object") return null;
    if (payload.hudsonrock && typeof payload.hudsonrock === "object") return payload.hudsonrock;
    if (payload.kind || payload.stealer_families || payload.stealers || payload.employees != null) return payload;
    var breach = payload.breach_data;
    if (breach && breach.hudsonrock) return breach.hudsonrock;
    return null;
  }

  function exposureCount(hr) {
    if (!hr || hr.error) return 0;
    return Number(hr.employees || 0) + Number(hr.users || 0) + Number(hr.stealer_count || 0);
  }

  function emptyHtml(title, body, hint) {
    return '<div class="exp-empty" role="status">' +
      '<b>' + esc(title) + '</b>' +
      '<p>' + esc(body) + '</p>' +
      (hint ? '<p class="exp-empty-hint">' + esc(hint) + '</p>' : "") +
      "</div>";
  }

  function kpiCard(label, value, extra) {
    return '<div class="exp-kpi">' +
      '<div class="exp-kpi-value">' + esc(value) + "</div>" +
      '<div class="exp-kpi-label">' + esc(label) + "</div>" +
      (extra ? '<div class="exp-kpi-extra">' + esc(extra) + "</div>" : "") +
      "</div>";
  }

  function barList(title, map, emptyLabel) {
    var entries = Object.entries(map || {}).sort(function (a, b) { return (b[1] || 0) - (a[1] || 0); });
    if (!entries.length) {
      return '<section class="exp-panel"><h3 class="exp-h">' + esc(title) + "</h3>" +
        '<p class="exp-muted">' + esc(emptyLabel) + "</p></section>";
    }
    var max = Math.max.apply(null, entries.map(function (e) { return Number(e[1]) || 0; })) || 1;
    var rows = entries.map(function (e) {
      var pct = Math.max(2, Math.round((Number(e[1]) || 0) / max * 100));
      return '<div class="exp-bar">' +
        '<div class="exp-bar-meta"><span class="exp-bar-name">' + esc(e[0]) +
        '</span><span class="exp-bar-count">' + fmtN(e[1]) + "</span></div>" +
        '<div class="exp-bar-track" role="img" aria-label="' + esc(e[0] + ": " + fmtN(e[1])) + '">' +
        '<span class="exp-bar-fill" style="width:' + pct + '%"></span></div>' +
        "</div>";
    }).join("");
    return '<section class="exp-panel"><h3 class="exp-h">' + esc(title) + "</h3>" +
      '<div class="exp-bars">' + rows + "</div></section>";
  }

  function chipList(title, map, emptyLabel) {
    var entries = Object.entries(map || {});
    if (!entries.length) {
      return '<section class="exp-panel"><h3 class="exp-h">' + esc(title) + "</h3>" +
        '<p class="exp-muted">' + esc(emptyLabel) + "</p></section>";
    }
    var chips = entries.map(function (e) {
      var label = e[0] + (e[1] ? " (" + fmtN(e[1]) + ")" : "");
      return '<li class="exp-chip">' + esc(label) + "</li>";
    }).join("");
    return '<section class="exp-panel"><h3 class="exp-h">' + esc(title) + "</h3>" +
      '<ul class="exp-chips">' + chips + "</ul></section>";
  }

  function domainList(title, rows, emptyLabel) {
    rows = Array.isArray(rows) ? rows : [];
    if (!rows.length) {
      return '<section class="exp-panel"><h3 class="exp-h">' + esc(title) + "</h3>" +
        '<p class="exp-muted">' + esc(emptyLabel) + "</p></section>";
    }
    var items = rows.map(function (row) {
      var name = row.domain || row;
      var count = row.count ? " · " + fmtN(row.count) : "";
      return "<li><span class=\"exp-mono\">" + esc(name) + "</span>" + esc(count) + "</li>";
    }).join("");
    return '<section class="exp-panel"><h3 class="exp-h">' + esc(title) + "</h3>" +
      '<ul class="exp-list">' + items + "</ul></section>";
  }

  function urlTable(title, rows, emptyLabel) {
    rows = Array.isArray(rows) ? rows : [];
    if (!rows.length) {
      return '<section class="exp-panel"><h3 class="exp-h">' + esc(title) + "</h3>" +
        '<p class="exp-muted">' + esc(emptyLabel) + "</p></section>";
    }
    var body = rows.map(function (row) {
      return "<tr><td class=\"exp-mono\">" + esc(row.url) + "</td><td>" +
        esc(row.type || "—") + "</td><td>" + fmtN(row.occurrence) + "</td></tr>";
    }).join("");
    return '<section class="exp-panel"><h3 class="exp-h">' + esc(title) + "</h3>" +
      '<div class="exp-table-wrap"><table class="exp-table">' +
      "<thead><tr><th>" + esc(t("exp_col_url", "URL")) + "</th><th>" +
      esc(t("exp_col_type", "Tipo")) + "</th><th>" +
      esc(t("exp_col_count", "Ocorrências")) + "</th></tr></thead>" +
      "<tbody>" + body + "</tbody></table></div></section>";
  }

  function pwLabel(key) {
    var map = {
      too_weak: t("exp_pw_too_weak", "muito fraca"),
      weak: t("exp_pw_weak", "fraca"),
      medium: t("exp_pw_medium", "média"),
      strong: t("exp_pw_strong", "forte"),
    };
    return map[key] || key;
  }

  function passwordPanel(title, map) {
    var labeled = {};
    Object.keys(map || {}).forEach(function (k) { labeled[pwLabel(k)] = map[k]; });
    return barList(title, labeled, t("exp_pw_empty", "Sem estatística de senha nesta consulta."));
  }

  function renderDomain(hr) {
    var kpis = '<div class="exp-kpis">' +
      kpiCard(t("exp_kpi_employees", "Funcionários"), fmtN(hr.employees),
        t("exp_last_emp", "Último") + ": " + fmtDate(hr.last_employee_compromised)) +
      kpiCard(t("exp_kpi_users", "Usuários"), fmtN(hr.users),
        t("exp_last_user", "Último") + ": " + fmtDate(hr.last_user_compromised)) +
      kpiCard(t("exp_kpi_third", "Terceiros"), fmtN(hr.third_parties), "") +
      kpiCard(t("exp_kpi_total", "Total"), fmtN(hr.total),
        hr.total_urls ? fmtN(hr.total_urls) + " URLs" : "") +
      "</div>";
    return kpis +
      '<p class="exp-summary">' + esc(hr.summary || "") + "</p>" +
      barList(t("exp_families", "Famílias de stealer"), hr.stealer_families,
        t("exp_families_empty", "Nenhuma família reportada.")) +
      '<div class="exp-split">' +
        passwordPanel(t("exp_pw_emp", "Senhas de funcionários (força)"), hr.employee_passwords) +
        passwordPanel(t("exp_pw_user", "Senhas de usuários (força)"), hr.user_passwords) +
      "</div>" +
      domainList(t("exp_third_domains", "Domínios de terceiros"), hr.third_party_domains,
        t("exp_third_empty", "Nenhum domínio de terceiro listado.")) +
      chipList(t("exp_apps", "Aplicações / palavras-chave"), hr.applications,
        t("exp_apps_empty", "Nenhuma aplicação listada.")) +
      chipList(t("exp_av", "Antivírus observados"), hr.antiviruses,
        t("exp_av_empty", "Nenhum antivírus listado.")) +
      urlTable(t("exp_emp_urls", "URLs de funcionários"), hr.employees_urls || hr.internal_urls,
        t("exp_urls_empty", "URLs redigidas ou ausentes nesta faixa pública.")) +
      urlTable(t("exp_client_urls", "URLs de clientes"), hr.clients_urls,
        t("exp_urls_empty", "URLs redigidas ou ausentes nesta faixa pública.")) +
      '<p class="exp-source">' + esc(t("exp_source", "Fonte: Hudson Rock Cavalier (OSINT público). Scantrely não clona a marca.")) + "</p>";
  }

  function renderEmail(hr) {
    var stealers = Array.isArray(hr.stealers) ? hr.stealers : [];
    var cards = stealers.map(function (row, idx) {
      var av = row.antiviruses;
      var avText = Array.isArray(av) ? av.join(", ") : (typeof av === "string" ? av : "");
      var logins = (row.top_logins || []).map(function (x) { return "<li class=\"exp-mono\">" + esc(x) + "</li>"; }).join("");
      var passwords = (row.top_passwords || []).map(function (x) { return "<li class=\"exp-mono\">" + esc(x) + "</li>"; }).join("");
      return '<article class="exp-stealer">' +
        "<h4>" + esc(t("exp_stealer", "Registro")) + " " + (idx + 1) + "</h4>" +
        '<dl class="exp-dl">' +
        "<div><dt>" + esc(t("exp_date", "Data")) + "</dt><dd>" + esc(fmtDate(row.date_compromised)) + "</dd></div>" +
        "<div><dt>" + esc(t("exp_os", "Sistema")) + "</dt><dd>" + esc(row.operating_system || "—") + "</dd></div>" +
        "<div><dt>" + esc(t("exp_computer", "Computador")) + "</dt><dd>" + esc(row.computer_name || "—") + "</dd></div>" +
        "<div><dt>" + esc(t("exp_ip", "IP")) + "</dt><dd class=\"exp-mono\">" + esc(row.ip || "—") + "</dd></div>" +
        "<div><dt>" + esc(t("exp_av", "Antivírus observados")) + "</dt><dd>" + esc(avText || "—") + "</dd></div>" +
        "</dl>" +
        (logins ? "<p class=\"exp-mini\">" + esc(t("exp_logins", "Logins (já mascarados)")) + "</p><ul class=\"exp-list\">" + logins + "</ul>" : "") +
        (passwords ? "<p class=\"exp-mini\">" + esc(t("exp_passwords", "Senhas (já mascaradas)")) + "</p><ul class=\"exp-list\">" + passwords + "</ul>" : "") +
        "</article>";
    }).join("");
    return '<div class="exp-kpis">' +
      kpiCard(t("exp_kpi_stealers", "Registros"), fmtN(hr.stealer_count || stealers.length), "") +
      kpiCard(t("exp_kpi_corp", "Serviços corporativos"), fmtN(hr.total_corporate_services), "") +
      kpiCard(t("exp_kpi_user_svc", "Serviços de usuário"), fmtN(hr.total_user_services), "") +
      "</div>" +
      (hr.message ? '<p class="exp-summary">' + esc(hr.message) + "</p>" : "") +
      (cards || emptyHtml(t("exp_email_empty_title", "Nenhum infostealer neste e-mail"),
        t("exp_email_empty_body", "A consulta pública não devolveu registros para este endereço."),
        t("exp_try_domain", "Tente o domínio da empresa, por exemplo empresa.com"))) +
      '<p class="exp-source">' + esc(t("exp_source", "Fonte: Hudson Rock Cavalier (OSINT público). Scantrely não clona a marca.")) + "</p>";
  }

  function renderResult(payload) {
    var hr = hudsonFrom(payload);
    if (!hr) {
      return emptyHtml(
        t("exp_empty_title", "Nenhuma exposição carregada"),
        t("exp_empty_body", "Busque um domínio ou e-mail para ver funcionários, usuários e famílias de stealer."),
        t("exp_try_domain", "Tente o domínio da empresa, por exemplo empresa.com")
      );
    }
    if (hr.error === "invalid query") {
      return emptyHtml(
        t("exp_invalid_title", "Consulta inválida"),
        t("exp_invalid_body", "Use um domínio (empresa.com) ou um e-mail (nome@empresa.com)."),
        t("exp_try_domain", "Tente o domínio da empresa, por exemplo empresa.com")
      );
    }
    if (hr.error) {
      return emptyHtml(
        t("exp_unavail_title", "Fonte indisponível"),
        t("exp_unavail_body", "O OSINT público de infostealers não respondeu. O circuit breaker pode estar aberto."),
        t("exp_try_later", "Tente de novo em alguns segundos.")
      );
    }
    if (hr.kind === "email" || Array.isArray(hr.stealers)) return renderEmail(hr);
    return renderDomain(hr);
  }

  async function fetchJson(url, opts) {
    opts = opts || {};
    var headers = Object.assign({ "Content-Type": "application/json" }, authHeaders(), opts.headers || {});
    var res = await fetch(url, Object.assign({}, opts, { headers: headers }));
    var data = null;
    try { data = await res.json(); } catch (e) { data = {}; }
    if (!res.ok) {
      var err = new Error((data && data.error) || res.statusText || "error");
      err.status = res.status;
      err.payload = data;
      throw err;
    }
    return data;
  }

  function setBusy(el, busy) {
    if (!el) return;
    el.setAttribute("aria-busy", busy ? "true" : "false");
    if (busy) {
      el.innerHTML = '<div class="exp-loading" role="status">' +
        esc(t("exp_loading", "Consultando exposição…")) + "</div>";
    }
  }

  window.submitExposureSearch = function (ev) {
    if (ev && ev.preventDefault) ev.preventDefault();
    var input = document.getElementById("exp-q");
    var q = input ? String(input.value || "").trim() : "";
    var root = document.getElementById("exposure-workspace-root");
    if (!root) return false;
    if (!q) {
      root.innerHTML = emptyHtml(
        t("exp_invalid_title", "Consulta inválida"),
        t("exp_invalid_body", "Use um domínio (empresa.com) ou um e-mail (nome@empresa.com)."),
        t("exp_try_domain", "Tente o domínio da empresa, por exemplo empresa.com")
      );
      hydrate(root);
      return false;
    }
    var btn = document.getElementById("exp-search-btn");
    if (btn) btn.disabled = true;
    setBusy(root, true);
    fetchJson("/api/intel/exposure", { method: "POST", body: JSON.stringify({ q: q }) })
      .then(function (data) {
        root.innerHTML = renderResult(data);
        hydrate(root);
      })
      .catch(function (err) {
        root.innerHTML = renderResult(err.payload || { error: "hudsonrock unavailable" });
        hydrate(root);
      })
      .finally(function () {
        if (btn) btn.disabled = false;
        if (root) root.setAttribute("aria-busy", "false");
      });
    return false;
  };

  window.renderExposureTab = function (co) {
    var el = document.getElementById("tab-exposure");
    if (!el) return;
    var domain = (co && co.domains && co.domains[0]) || "";
    var stored = hudsonFrom(co) || hudsonFrom(co && co.breach_data);
    var count = exposureCount(stored);
    var tc = document.getElementById("tc-exposure");
    if (tc) tc.textContent = count > 0 ? String(count) : "";
    var toolbar = '<div class="exp-toolbar">' +
      '<p class="exp-toolbar-copy">' + esc(t("exp_company_help", "Dados gravados no último scan, ou atualize agora com o domínio da empresa.")) + "</p>" +
      '<button type="button" class="btn btn-primary" id="exp-refresh-btn">' +
      esc(t("exp_refresh", "Atualizar agora")) + "</button></div>";
    el.innerHTML = toolbar + '<div id="exposure-company-root" class="exp-root">' +
      (stored ? renderResult(stored) : emptyHtml(
        t("exp_company_empty_title", "Sem exposição gravada"),
        t("exp_company_empty_body", "Rode a pipeline (módulo Breach) ou atualize agora pelo domínio da empresa."),
        domain ? t("exp_try_domain", "Tente o domínio da empresa, por exemplo empresa.com") + ": " + domain : ""
      )) + "</div>";
    var btn = document.getElementById("exp-refresh-btn");
    if (btn) {
      btn.addEventListener("click", function () {
        if (!co || !co.id) return;
        var root = document.getElementById("exposure-company-root");
        btn.disabled = true;
        setBusy(root, true);
        fetchJson("/api/recon/" + encodeURIComponent(co.id) + "/exposure", {
          method: "POST",
          body: JSON.stringify({ q: domain })
        }).then(function (data) {
          var hr = hudsonFrom(data);
          if (co && hr) {
            co.breach_data = co.breach_data || {};
            co.breach_data.hudsonrock = hr;
          }
          if (root) root.innerHTML = renderResult(data);
          var n = exposureCount(hr);
          var tcEl = document.getElementById("tc-exposure");
          if (tcEl) tcEl.textContent = n > 0 ? String(n) : "";
          if (typeof updateGroupCounts === "function") updateGroupCounts();
          hydrate(el);
        }).catch(function (err) {
          if (root) root.innerHTML = renderResult(err.payload || { error: "hudsonrock unavailable" });
          hydrate(el);
        }).finally(function () {
          btn.disabled = false;
          if (root) root.setAttribute("aria-busy", "false");
        });
      });
    }
    hydrate(el);
  };

  window.showExposurePage = function () {
    var root = document.getElementById("exposure-workspace-root");
    if (root && !root.innerHTML.trim()) {
      root.innerHTML = emptyHtml(
        t("exp_empty_title", "Nenhuma exposição carregada"),
        t("exp_empty_body", "Busque um domínio ou e-mail para ver funcionários, usuários e famílias de stealer."),
        t("exp_try_domain", "Tente o domínio da empresa, por exemplo empresa.com")
      );
      hydrate(root);
    }
    var input = document.getElementById("exp-q");
    if (input) input.focus();
  };

  window.renderExposureTeaser = function (co) {
    var hr = hudsonFrom(co);
    if (!hr || hr.error) return "";
    var n = exposureCount(hr);
    if (!n) return "";
    return '<button type="button" class="exp-teaser" onclick="switchGroup(\'exposure\', document.querySelector(\'.tab-btn[data-group=exposure]\'))">' +
      '<span class="exp-teaser-k">' + esc(t("tab_exposure", "Exposição")) + "</span>" +
      '<span class="exp-teaser-v">' + fmtN(hr.employees || 0) + " " + esc(t("exp_kpi_employees", "Funcionários")) +
      " · " + fmtN(hr.users || 0) + " " + esc(t("exp_kpi_users", "Usuários")) + "</span></button>";
  };
})();
