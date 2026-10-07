/* T2/F8 — theme module extracted from dashboard.js */
(function () {
  function currentTheme() {
    try { return localStorage.getItem("asm_theme") || "dark"; } catch (e) { return "dark"; }
  }
  function applyTheme(theme) {
    document.body.classList.toggle("theme-light", theme === "light");
    try { localStorage.setItem("asm_theme", theme); } catch (e) {}
    var btn = document.getElementById("theme-toggle-btn");
    if (!btn) return;
    var ico = theme === "light" ? "moon" : "sun";
    btn.setAttribute("aria-pressed", theme === "light" ? "true" : "false");
    btn.setAttribute("aria-label", theme === "light" ? "Ativar tema escuro" : "Ativar tema claro");
    btn.setAttribute("title", "Tema claro/escuro");
    if (typeof window.icon === "function") {
      btn.innerHTML = window.icon(ico, { size: 16, className: "ico" });
    } else {
      btn.innerHTML = '<span data-ico="' + ico + '" data-ico-size="16" aria-hidden="true"></span>';
      if (typeof window.hydrateIcons === "function") window.hydrateIcons(btn);
    }
  }
  window.toggleAsmTheme = function () {
    applyTheme(currentTheme() === "light" ? "dark" : "light");
  };
  window.applyAsmTheme = applyTheme;
  if (document.body) applyTheme(currentTheme());
  else document.addEventListener("DOMContentLoaded", function () { applyTheme(currentTheme()); });
})();
