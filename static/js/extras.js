/* T2 extras: 2FA, invite, push, export SARIF/PDF, module cancel, nuclei templates */
(function () {
  function toast(msg, kind) {
    if (typeof showToast === "function") showToast(msg, kind);
    else if (typeof console !== "undefined") console.log(msg);
  }
  function headers() {
    return typeof _authHeaders === "function" ? _authHeaders() : {};
  }

  window.cancelPipelineModule = async function (cid, module) {
    if (!cid || !module) return;
    try {
      var r = await fetch("/api/recon/" + encodeURIComponent(cid) + "/pipeline/" + encodeURIComponent(module), {
        method: "DELETE",
        headers: headers(),
      });
      var d = await r.json().catch(function () { return {}; });
      if (!r.ok) { toast(d.error || "Falha ao cancelar módulo", "error"); return; }
      toast("Módulo " + module + " cancelado", "ok");
      if (typeof renderPipelineStatus === "function") renderPipelineStatus(cid);
    } catch (e) {
      toast(e.message || String(e), "error");
    }
  };

  window.exportSarif = async function (cid) {
    window.location = "/api/export/" + encodeURIComponent(cid) + "?format=sarif";
  };
  window.exportServerPdf = async function (cid) {
    window.location = "/api/export/" + encodeURIComponent(cid) + "?format=pdf";
  };

  window.enableWebPush = async function () {
    if (!("Notification" in window)) { toast("Notificações não suportadas", "error"); return; }
    var perm = await Notification.requestPermission();
    if (perm !== "granted") { toast("Permissão de notificação recusada", "error"); return; }
    toast("Notificações do browser ativas nesta sessão", "ok");
    try {
      var r = await fetch("/api/push/vapid", { headers: headers() });
      var d = await r.json();
      if (d.publicKey && "serviceWorker" in navigator) {
        /* Optional Web Push subscription when VAPID is configured */
        await fetch("/api/push/subscribe", {
          method: "POST",
          headers: Object.assign({ "Content-Type": "application/json" }, headers()),
          body: JSON.stringify({ endpoint: "browser:" + (navigator.userAgent || "local"), keys: { perm: perm } }),
        });
      }
    } catch (e) {}
  };

  window.notifyAsm = function (title, body) {
    try {
      if (Notification && Notification.permission === "granted") {
        new Notification(title || "Scantrely", { body: body || "" });
      }
    } catch (e) {}
  };

  window.setup2FA = async function () {
    try {
      var r = await fetch("/api/auth/2fa/setup", { method: "POST", headers: headers() });
      var d = await r.json();
      if (!r.ok) { toast(d.error || "Falha no 2FA", "error"); return; }
      var code = prompt("Escaneie o QR no Authenticator.\nSecret: " + d.secret + "\nDigite o código TOTP:");
      if (!code) return;
      var e = await fetch("/api/auth/2fa/enable", {
        method: "POST",
        headers: Object.assign({ "Content-Type": "application/json" }, headers()),
        body: JSON.stringify({ totp_code: code }),
      });
      var ed = await e.json().catch(function () { return {}; });
      if (!e.ok) { toast(ed.error || "Código inválido", "error"); return; }
      toast("2FA ativado", "ok");
    } catch (e) { toast(e.message || String(e), "error"); }
  };

  window.disable2FA = async function () {
    var password = prompt("Senha da conta para desativar 2FA:");
    if (!password) return;
    try {
      var r = await fetch("/api/auth/2fa/disable", {
        method: "POST",
        headers: Object.assign({ "Content-Type": "application/json" }, headers()),
        body: JSON.stringify({ password: password }),
      });
      var d = await r.json().catch(function () { return {}; });
      if (!r.ok) { toast(d.error || "Falha", "error"); return; }
      toast("2FA desativado", "ok");
    } catch (e) { toast(e.message || String(e), "error"); }
  };

  window.inviteAdmin = async function () {
    var username = prompt("Username do convite:");
    if (!username) return;
    var email = prompt("E-mail (opcional):") || "";
    try {
      var r = await fetch("/api/admins/invite", {
        method: "POST",
        headers: Object.assign({ "Content-Type": "application/json" }, headers()),
        body: JSON.stringify({ username: username, email: email, role: "analyst", scoped_companies: [] }),
      });
      var d = await r.json().catch(function () { return {}; });
      if (!r.ok) { toast(d.error || "Falha no convite", "error"); return; }
      prompt("URL de convite (copie):", d.url || d.token);
      toast("Convite criado", "ok");
    } catch (e) { toast(e.message || String(e), "error"); }
  };

  window.uploadNucleiTemplate = async function (cid) {
    var input = document.getElementById("nuclei-template-file");
    if (!input || !input.files || !input.files[0]) { toast("Selecione um arquivo .yaml", "error"); return; }
    var fd = new FormData();
    fd.append("file", input.files[0]);
    try {
      var hdrs = headers();
      var r = await fetch("/api/recon/" + encodeURIComponent(cid) + "/nuclei-templates", {
        method: "POST",
        headers: hdrs,
        body: fd,
      });
      var d = await r.json().catch(function () { return {}; });
      if (!r.ok) { toast(d.error || "Upload falhou", "error"); return; }
      toast("Template " + (d.name || "") + " enviado", "ok");
    } catch (e) { toast(e.message || String(e), "error"); }
  };

  window.pushDefectDojo = async function (cid) {
    try {
      var r = await fetch("/api/export/" + encodeURIComponent(cid) + "/defectdojo", {
        method: "POST",
        headers: Object.assign({ "Content-Type": "application/json" }, headers()),
        body: "{}",
      });
      var d = await r.json().catch(function () { return {}; });
      if (!r.ok) { toast(d.error || "DefectDojo falhou", "error"); return; }
      toast("Enviado ao DefectDojo (" + (d.pushed || 0) + " findings)", "ok");
    } catch (e) { toast(e.message || String(e), "error"); }
  };

  document.addEventListener("DOMContentLoaded", function () {
    try {
      var params = new URLSearchParams(location.search);
      var token = params.get("invite");
      if (token) {
        var pw = prompt("Convite Scantrely — defina a senha (mín. 8):");
        if (pw) {
          fetch("/api/auth/invite/" + encodeURIComponent(token) + "/accept", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: pw }),
          }).then(function (r) { return r.json().then(function (d) { return { r: r, d: d }; }); })
            .then(function (x) {
              if (!x.r.ok) toast(x.d.error || "Convite inválido", "error");
              else toast("Conta criada. Faça login.", "ok");
            });
        }
      }
    } catch (e) {}
  });
})();
