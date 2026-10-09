/* Phosphor-style outline SVG sprite for Scantrely (ui-ux-pro-max).
 * window.icon(name, opts) → SVG string
 * window.hydrateIcons(root) fills [data-ico]
 */
(function () {
  "use strict";

  var PATHS = {
    hexagon: '<polygon points="12 2 20.5 7 20.5 17 12 22 3.5 17 3.5 7"/>',
    shield: '<path d="M12 3l8 4v5c0 5-3.4 8.4-8 9.5C7.4 20.4 4 17 4 12V7z"/>',
    buildings: '<path d="M3 21h18"/><path d="M6 21V6h5v15"/><path d="M11 21V10h7v11"/><path d="M8 9h1"/><path d="M8 13h1"/><path d="M14 13h1"/><path d="M14 17h1"/>',
    queue: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    plus: '<path d="M12 5v14"/><path d="M5 12h14"/>',
    users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    wrench: '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
    target: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    sparkle: '<path d="M12 3l1.6 5.4L19 10l-5.4 1.6L12 17l-1.6-5.4L5 10l5.4-1.6z"/>',
    trophy: '<path d="M8 21h8"/><path d="M12 17v4"/><path d="M7 4h10v5a5 5 0 0 1-10 0V4z"/><path d="M17 6h2a2 2 0 0 1 0 4h-2"/><path d="M7 6H5a2 2 0 0 0 0 4h2"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    bolt: '<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3-3"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/>',
    moon: '<path d="M21 14.5A8.5 8.5 0 1 1 9.5 3 7 7 0 0 0 21 14.5z"/>',
    bell: '<path d="M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10 21a2 2 0 0 0 4 0"/>',
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
    pencil: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
    file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
    printer: '<path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/>',
    trash: '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/>',
    play: '<polygon points="6 4 20 12 6 20"/>',
    pause: '<rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/>',
    stop: '<rect x="6" y="6" width="12" height="12" rx="1"/>',
    check: '<path d="M5 12l5 5L20 7"/>',
    globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15 15 0 0 1 0 20"/><path d="M12 2a15 15 0 0 0 0 20"/>',
    lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "lock-open": '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0"/>',
    envelope: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
    radar: '<circle cx="12" cy="12" r="2"/><path d="M12 12l6-3"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="10"/>',
    cloud: '<path d="M18 18H7a5 5 0 0 1 0-10 7 7 0 0 1 13 3 4 4 0 0 1-2 7z"/>',
    warning: '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="M12 15h9v-3"/><path d="M18 12v3"/>',
    flask: '<path d="M9 3h6"/><path d="M10 3v6L5 19a2 2 0 0 0 1.7 3h10.6A2 2 0 0 0 19 19L14 9V3"/>',
    plug: '<path d="M9 7v4M15 7v4"/><path d="M8 11h8v3a4 4 0 0 1-8 0v-3z"/><path d="M12 18v3"/>',
    camera: '<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/>',
    package: '<path d="M16.5 9.4L7.5 4.21"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.27 6.96L12 12.01l8.73-5.05"/><path d="M12 22.08V12"/>',
    network: '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v4"/><path d="M12 11l-5 6"/><path d="M12 11l5 6"/>',
    house: '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
    monitor: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
    person: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    map: '<path d="M9 18l-6 3V6l6-3 6 3 6-3v15l-6 3-6-3z"/><path d="M9 3v15M15 6v15"/>',
    explosion: '<path d="M12 2l1.5 6 6 .5-5 4 2 6-4.5-3.5L7 19l2-6-5-4 6-.5z"/>',
    folder: '<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    database: '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
    clipboard: '<rect x="8" y="2" width="8" height="4" rx="1"/><path d="M8 4H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2h-2"/>',
    floppy: '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><path d="M17 21v-8H7v8"/><path d="M7 3v5h8"/>',
    git: '<circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><path d="M6 8v4a4 4 0 0 0 4 4h2"/><path d="M18 8v2"/>',
    clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
    eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    robot: '<rect x="5" y="8" width="14" height="10" rx="2"/><path d="M12 8V5"/><circle cx="9" cy="13" r="1"/><circle cx="15" cy="13" r="1"/><path d="M8 18v2M16 18v2"/>',
    code: '<path d="M8 8l-4 4 4 4M16 8l4 4-4 4M14 4l-4 16"/>',
    hash: '<path d="M5 9h14M5 15h14M10 3L8 21M16 3l-2 18"/>',
    card: '<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/>',
    car: '<path d="M3 14h18v4H3z"/><path d="M5 14l2-6h10l2 6"/><circle cx="7.5" cy="18" r="1.5"/><circle cx="16.5" cy="18" r="1.5"/>',
    bank: '<path d="M3 10l9-6 9 6"/><path d="M5 10v8M10 10v8M14 10v8M19 10v8"/><path d="M3 18h18"/>',
    scroll: '<path d="M8 4h8a2 2 0 0 1 2 2v12H8a2 2 0 0 1-2-2V6"/><path d="M6 18a2 2 0 0 0 2 2h10"/>',
    game: '<rect x="2" y="8" width="20" height="10" rx="3"/><path d="M6 13h4M8 11v4"/><path d="M16 12h.01M18 14h.01"/>',
    idcard: '<rect x="2" y="5" width="20" height="14" rx="2"/><circle cx="8" cy="12" r="2"/><path d="M13 10h6M13 14h4"/>',
    store: '<path d="M3 9l1-4h16l1 4"/><path d="M4 9h16v11H4z"/><path d="M9 20v-6h6v6"/>',
    factory: '<path d="M3 21V10l6 4V10l6 4V8l6 3v10z"/>',
    vote: '<path d="M12 3l2 4h4l-3 3 1 4-4-2-4 2 1-4-3-3h4z"/><path d="M5 21h14"/>',
    antenna: '<path d="M12 13v8"/><path d="M5 8a9 9 0 0 1 14 0"/><path d="M8 11a5 5 0 0 1 8 0"/><circle cx="12" cy="13" r="1.5"/>',
    cook: '<path d="M4 12h16v8H4z"/><path d="M8 12V8a4 4 0 0 1 8 0"/>',
    ticket: '<path d="M3 9a2 2 0 0 0 2-2V5h14v2a2 2 0 0 0 2 2v6a2 2 0 0 0-2 2v2H5v-2a2 2 0 0 0-2-2z"/><path d="M12 5v14"/>',
    chat: '<path d="M21 15a4 4 0 0 1-4 4H8l-5 3V7a4 4 0 0 1 4-4h10a4 4 0 0 1 4 4z"/>',
    reload: '<path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/>',
    x: '<path d="M18 6L6 18M6 6l12 12"/>',
    "chevron-left": '<path d="M15 18l-6-6 6-6"/>',
    "chevron-right": '<path d="M9 6l6 6-6 6"/>',
    "chevron-up": '<path d="M18 15l-6-6-6 6"/>',
    "chevron-down": '<path d="M6 9l6 6 6-6"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13"/><path d="M3 6h.01M3 12h.01M3 18h.01"/>',
    "arrow-left": '<path d="M19 12H5M12 19l-7-7 7-7"/>',
    "arrow-right": '<path d="M5 12h14M12 5l7 7-7 7"/>',
    filter: '<path d="M3 5h18l-7 8v5l-4 2v-7z"/>',
    layers: '<path d="M12 2l9 5-9 5-9-5z"/><path d="M3 12l9 5 9-5"/><path d="M3 17l9 5 9-5"/>',
    bug: '<rect x="8" y="6" width="8" height="12" rx="4"/><path d="M8 9h8M8 15h8M4 9h4M16 9h4M4 15h4M16 15h4M12 6V3"/>',
    terminal: '<path d="M4 17l6-5-6-5"/><path d="M12 19h8"/>',
    pulse: '<path d="M3 12h4l2-6 4 12 2-6h6"/>',
    tag: '<path d="M20.6 13.4L12 22l-9-9 8.6-8.6A2 2 0 0 1 13 4h6v6a2 2 0 0 1-.4 1.4z"/><circle cx="16" cy="8" r="1"/>',
    question: '<circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 1 1 4 2.8c-.8.4-1.1.8-1.1 1.7"/><path d="M12 17h.01"/>',
    "check-circle": '<circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-6"/>',
    "x-circle": '<circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/>',
    sliders: '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3"/><path d="M2 14h4M10 8h4M18 16h4"/>',
    cpu: '<rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 1v4M15 1v4M9 19v4M15 19v4M1 9h4M1 15h4M19 9h4M19 15h4"/>',
    broom: '<path d="M19 4l-8 8"/><path d="M11 12l-8 8h10l2-2"/><path d="M15 8l3 3"/>',
    web: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 4 10 15 15 0 0 1-4 10"/><path d="M12 2a15 15 0 0 0-4 10 15 15 0 0 0 4 10"/>',
    inbox: '<path d="M22 12h-6l-2 3H10l-2-3H2"/><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
    scale: '<path d="M12 3v18"/><path d="M5 7h14"/><path d="M5 7l-3 7h6z"/><path d="M19 7l-3 7h6z"/>',
    diamond: '<path d="M12 3l8 9-8 9-8-9z"/>',
    dot: '<circle cx="12" cy="12" r="3"/>',
    archive: '<rect x="3" y="4" width="18" height="4" rx="1"/><path d="M5 8v11a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8"/><path d="M10 12h4"/>',
    film: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 4v16M17 4v16M3 8h4M17 8h4M3 16h4M17 16h4"/>',
    earth: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/>',
    binoculars: '<circle cx="7" cy="14" r="4"/><circle cx="17" cy="14" r="4"/><path d="M7 10V6h3l2 4 2-4h3v4"/>',
    puzzle: '<path d="M12 4a2 2 0 1 1 2 2h4v4a2 2 0 1 1 0 4v4h-4a2 2 0 1 1-4 0H6v-4a2 2 0 1 1 0-4V6h4a2 2 0 0 1 2-2z"/>',
    building: '<path d="M6 21V5h8v16"/><path d="M14 10h5v11"/><path d="M3 21h18"/><path d="M9 8h.01M9 12h.01M9 16h.01"/>',
    mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
    external: '<path d="M14 4h6v6"/><path d="M10 14L20 4"/><path d="M20 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h5"/>',
    numbers: '<path d="M5 6h3v12H5z"/><path d="M11 6h8"/><path d="M11 12h8"/><path d="M11 18h8"/>',
    fingerprint: '<path d="M12 11a3 3 0 0 0-3 3v5"/><path d="M12 8a6 6 0 0 1 6 6v1"/><path d="M9 21v-2"/><path d="M6 11a6 6 0 0 1 12 0"/><path d="M15 21v-5"/>'
  };

  function icon(name, opts) {
    opts = opts || {};
    var size = opts.size || 18;
    var cls = opts.className || "ico";
    var label = opts.label;
    var inner = PATHS[name] || PATHS.dot;
    var aria = label
      ? ' role="img" aria-label="' + String(label).replace(/"/g, "&quot;") + '"'
      : ' aria-hidden="true"';
    return '<svg class="' + cls + '" width="' + size + '" height="' + size +
      '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"' +
      aria + ">" + inner + "</svg>";
  }

  function hydrateIcons(root) {
    var scope = root && root.nodeType === 1 ? root : document;
    var nodes = [];
    if (scope.getAttribute && scope.getAttribute("data-ico")) nodes.push(scope);
    if (scope.querySelectorAll) {
      Array.prototype.forEach.call(scope.querySelectorAll("[data-ico]"), function (n) {
        nodes.push(n);
      });
    }
    nodes.forEach(function (el) {
      var name = el.getAttribute("data-ico");
      if (!name) return;
      el.innerHTML = icon(name, {
        size: el.getAttribute("data-ico-size") || 16,
        className: el.getAttribute("data-ico-class") || "ico",
        label: el.getAttribute("data-ico-label") || undefined
      });
    });
  }

  window.icon = icon;
  window.hydrateIcons = hydrateIcons;
  window.SCANTRELY_ICONS = PATHS;

  function boot() {
    hydrateIcons(document);
    if (typeof MutationObserver === "undefined") return;
    var mo = new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        var nodes = muts[i].addedNodes;
        for (var j = 0; j < nodes.length; j++) {
          var n = nodes[j];
          if (!n || n.nodeType !== 1) continue;
          if (n.getAttribute && n.getAttribute("data-ico")) hydrateIcons(n);
          else if (n.querySelector && n.querySelector("[data-ico]")) hydrateIcons(n);
        }
      }
    });
    mo.observe(document.body, { childList: true, subtree: true });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
