/*! ha-mail-archiver UI inject: Navbar + Chunk-Upload + Ingress + Mobile */
(function () {
  var CHUNK_SIZE = 4 * 1024 * 1024;
  var LARGE_THRESHOLD = 8 * 1024 * 1024;
  var activeXhr = null;

  function go() {
    try {
      if (document.getElementById("ha-sec-nav")) return true;
      var nav = document.querySelector("nav.navbar") || document.querySelector("nav") || document.querySelector("header");
      if (!nav) return false;
      if (!/Benutzer|Users/i.test(nav.textContent || "")) return false;
      var ul = nav.querySelector("ul.navbar-nav") || nav.querySelector("ul");
      if (!ul) return false;
      var anchors = [].slice.call(nav.querySelectorAll("a.nav-link,a"));
      var proto = null;
      for (var i = 0; i < anchors.length; i++) {
        var t = (anchors[i].textContent || "").replace(/\s+/g, " ").trim();
        if (/Protokoll|\bLog\b|Logs/i.test(t)) { proto = anchors[i]; break; }
      }
      var a = document.createElement("a");
      a.id = "ha-sec-nav";
      a.className = proto && proto.className ? proto.className.replace(/\bactive\b/g, "").trim() || "nav-link" : "nav-link";
      if (a.className.indexOf("nav-link") < 0) a.className += " nav-link";
      a.href = "security/";
      a.title = "Sicherheit (Admin)";
      a.innerHTML = '<i class="bi bi-shield-check me-1"></i>Sicherheit';
      var li = document.createElement("li");
      li.className = "nav-item";
      li.appendChild(a);
      if (proto) {
        var p = proto.parentElement;
        if (p && p.tagName === "LI") p.parentElement.insertBefore(li, p.nextSibling);
        else proto.parentElement.insertBefore(a, proto.nextSibling);
      } else ul.appendChild(li);
      return true;
    } catch (e) { return false; }
  }

  function start() {
    if (go()) return;
    var n = 0;
    var t = setInterval(function () { if (go() || ++n > 40) clearInterval(t); }, 250);
    try {
      var mo = new MutationObserver(function () { if (go()) mo.disconnect(); });
      mo.observe(document.documentElement, { childList: true, subtree: true });
      setTimeout(function () { try { mo.disconnect(); } catch (e) {} }, 15000);
    } catch (e) {}
  }

  function fmtSize(b) {
    if (!b || b <= 0) return "0 B";
    var k = 1024, s = ["B", "KB", "MB", "GB"], i = Math.floor(Math.log(b) / Math.log(k));
    return Math.round((b / Math.pow(k, i)) * 100) / 100 + " " + s[i];
  }

  function securityBase() {
    var p = location.pathname.replace(/\/+$/, "");
    var i = p.indexOf("/security");
    if (i >= 0) return p.slice(0, i + "/security".length);
    var m = p.match(/^(.*?\/api\/hassio_ingress\/[^/]+)/);
    return (m ? m[1] : "") + "/security";
  }

  function ensureProgress() {
    var wrap = document.getElementById("ha-eml-progress-wrap");
    if (wrap) return wrap;
    var form = document.getElementById("emlImportForm") || document.querySelector("form");
    if (!form) return null;
    wrap = document.createElement("div");
    wrap.id = "ha-eml-progress-wrap";
    wrap.className = "mt-3";
    wrap.style.display = "none";
    wrap.innerHTML =
      '<div class="d-flex justify-content-between small mb-1">' +
      '<span id="ha-eml-progress-label">Upload</span>' +
      '<span id="ha-eml-progress-pct">0%</span></div>' +
      '<div class="progress" style="height:22px">' +
      '<div id="ha-eml-progress-bar" class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" style="width:0%">0%</div></div>' +
      '<div class="small text-muted mt-1" id="ha-eml-progress-detail"></div>' +
      '<button type="button" class="btn btn-sm btn-outline-danger mt-2" id="ha-eml-abort" style="display:none">Abbrechen</button>';
    form.appendChild(wrap);
    return wrap;
  }

  function setProg(pct, label, detail) {
    var wrap = ensureProgress();
    if (!wrap) return;
    wrap.style.display = "block";
    pct = Math.max(0, Math.min(100, pct || 0));
    var bar = document.getElementById("ha-eml-progress-bar");
    var pctEl = document.getElementById("ha-eml-progress-pct");
    var lab = document.getElementById("ha-eml-progress-label");
    var det = document.getElementById("ha-eml-progress-detail");
    if (bar) { bar.style.width = pct + "%"; bar.textContent = Math.round(pct) + "%"; }
    if (pctEl) pctEl.textContent = Math.round(pct) + "%";
    if (lab && label) lab.textContent = label;
    if (det && detail != null) det.textContent = detail;
  }

  function uploadChunk(file, uploadId, idx, total, onProg) {
    return new Promise(function (resolve, reject) {
      var start = idx * CHUNK_SIZE;
      var end = Math.min(file.size, start + CHUNK_SIZE);
      var blob = file.slice(start, end);
      var xhr = new XMLHttpRequest();
      activeXhr = xhr;
      xhr.open("POST", securityBase() + "/api/upload-chunk");
      xhr.setRequestHeader("X-Upload-Id", uploadId);
      xhr.setRequestHeader("X-File-Name", file.name);
      xhr.setRequestHeader("X-Chunk-Index", String(idx));
      xhr.setRequestHeader("X-Chunk-Total", String(total));
      xhr.upload.onprogress = function (e) {
        if (!e.lengthComputable) return;
        var done = start + e.loaded;
        var pct = (done / file.size) * 100;
        if (onProg) onProg(pct, done, file.size);
      };
      xhr.onload = function () {
        activeXhr = null;
        if (xhr.status >= 200 && xhr.status < 300) {
          try { resolve(JSON.parse(xhr.responseText || "{}")); }
          catch (e) { resolve({ ok: true }); }
        } else reject(new Error("Chunk " + (idx + 1) + " HTTP " + xhr.status));
      };
      xhr.onerror = function () { activeXhr = null; reject(new Error("Netzwerkfehler Chunk " + (idx + 1))); };
      xhr.onabort = function () { activeXhr = null; reject(new Error("abgebrochen")); };
      xhr.send(blob);
    });
  }

  async function chunkedUpload(file, onProg) {
    var total = Math.ceil(file.size / CHUNK_SIZE) || 1;
    var uploadId = (Math.random().toString(16).slice(2) + Date.now().toString(16)).slice(0, 16);
    var last = null;
    for (var i = 0; i < total; i++) {
      last = await uploadChunk(file, uploadId, i, total, onProg);
      if (last && last.ok === false) throw new Error(last.message || "Chunk fehlgeschlagen");
    }
    return last;
  }

  function accountId() {
    var el = document.getElementById("accountSelect") || document.querySelector("[name=TargetAccountId]");
    return el ? el.value : "";
  }

  function startImportLocal(pathOrName) {
    return fetch(securityBase() + "/api/import-local", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ file: pathOrName, account_id: parseInt(accountId() || "0", 10) || 0 })
    }).then(function (r) { return r.json(); });
  }

  function fixEml() {
    try {
      var form = document.getElementById("emlImportForm");
      var input = document.getElementById("emlFileInput") || (form && form.querySelector('input[type=file]'));
      if (!form || !input) return;
      if (form.getAttribute("data-ha-eml-fixed") === "1") return;
      form.setAttribute("data-ha-eml-fixed", "1");
      var btn = form.querySelector('button[type=submit]') || form.querySelector("button.btn-primary");
      if (!btn) {
        btn = document.createElement("button");
        btn.type = "submit";
        btn.className = "btn btn-primary";
        btn.textContent = "Import starten";
        form.appendChild(btn);
      }
      ensureProgress();
      form.addEventListener("submit", function (e) {
        var file = input.files && input.files[0];
        if (!file) return;
        if (file.size < LARGE_THRESHOLD) return;
        e.preventDefault();
        e.stopPropagation();
        var origHtml = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = "Hochladen…";
        setProg(0, "Upload", "0 / " + fmtSize(file.size));
        var abortEl = document.getElementById("ha-eml-abort");
        if (abortEl) {
          abortEl.style.display = "inline-block";
          abortEl.onclick = function () { try { if (activeXhr) activeXhr.abort(); } catch (err) {} };
        }
        chunkedUpload(file, function (pct, done, total) {
          setProg(pct, "Upload " + Math.round(pct) + "%", fmtSize(done) + " / " + fmtSize(total));
          btn.innerHTML = "Hochladen… " + Math.round(pct) + "%";
        }).then(function (res) {
          setProg(100, "Upload fertig", "Starte Import…");
          var name = (res && (res.filename || res.path)) || file.name;
          return startImportLocal(name);
        }).then(function (imp) {
          var bar = document.getElementById("ha-eml-progress-bar");
          if (bar) { bar.classList.remove("progress-bar-animated"); bar.classList.add("bg-success"); }
          setProg(100, "Import gestartet", (imp && imp.message) || "OK");
          if (abortEl) abortEl.style.display = "none";
          var redir = (imp && imp.redirect) || "/Emails/Jobs";
          setTimeout(function () { window.location.href = withPrefix(redir); }, 800);
        }).catch(function (err) {
          var bar = document.getElementById("ha-eml-progress-bar");
          var msg = (err && err.message) || String(err);
          setProg(0, msg === "abgebrochen" ? "Abgebrochen" : "Upload fehlgeschlagen", msg);
          if (bar) { bar.classList.remove("bg-success"); bar.classList.add("bg-danger"); }
          btn.disabled = false; btn.innerHTML = origHtml;
          if (abortEl) abortEl.style.display = "none";
        });
      }, true);
    } catch (e) {}
  }

  function ingressPrefix() {
    var m = (location.pathname || "").match(/^(.*?\/api\/hassio_ingress\/[^/]+)/);
    return m ? m[1] : "";
  }
  function withPrefix(url) {
    if (!url || typeof url !== "string") return url;
    var p = ingressPrefix();
    if (!p) return url;
    if (url.indexOf("http://") === 0 || url.indexOf("https://") === 0) return url;
    if (url.charAt(0) !== "/") return url;
    if (url.indexOf(p) === 0) return url;
    if (url.indexOf("/api/hassio_ingress/") === 0) return url;
    return p + url;
  }
  function fixIngressPaths() {
    var p = ingressPrefix();
    if (!p) return;
    document.querySelectorAll("[data-email-url]").forEach(function (el) {
      var u = el.getAttribute("data-email-url");
      if (u) el.setAttribute("data-email-url", withPrefix(u));
    });
    document.querySelectorAll('a[href^="/"]').forEach(function (a) {
      var h = a.getAttribute("href");
      if (h) a.setAttribute("href", withPrefix(h));
    });
    document.querySelectorAll("form[action^='/']").forEach(function (f) {
      var a = f.getAttribute("action");
      if (a) f.setAttribute("action", withPrefix(a));
    });
  }

  document.addEventListener("click", function (e) {
    var row = e.target && e.target.closest && e.target.closest(".email-row");
    if (!row) return;
    if (e.target.closest(".email-row-no-nav, a, button, input, label, .form-check")) return;
    var url = row.getAttribute("data-email-url");
    if (!url) return;
    e.preventDefault();
    e.stopPropagation();
    window.location.href = withPrefix(url);
  }, true);

  function injectMobileCss() {
    if (document.getElementById("ha-mobile-css")) return;
    var vp = document.querySelector('meta[name="viewport"]');
    if (!vp) {
      vp = document.createElement("meta");
      vp.name = "viewport";
      document.head.appendChild(vp);
    }
    vp.content = "width=device-width, initial-scale=1, maximum-scale=5, viewport-fit=cover";
    var s = document.createElement("style");
    s.id = "ha-mobile-css";
    s.textContent = [
      "html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }",
      "body { overflow-x: hidden; }",
      "@media (max-width: 768px) {",
      "  :root { --ha-touch: 44px; }",
      "  nav.navbar { padding: 0.35rem 0.6rem !important; min-height: 48px !important; }",
      "  nav.navbar .navbar-brand { font-size: 1rem !important; max-width: 55vw; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }",
      "  nav.navbar .navbar-toggler { padding: 0.35rem 0.5rem; }",
      "  .container, .container-fluid, main, .content, .page-content {",
      "    padding-left: 0.75rem !important; padding-right: 0.75rem !important; }",
      "  h1, .h1 { font-size: 1.35rem !important; margin-bottom: 0.75rem !important; }",
      "  h2, .h2 { font-size: 1.15rem !important; }",
      "  h3, .h3 { font-size: 1.05rem !important; }",
      "  .row > [class*=col-] { margin-bottom: 0.65rem; }",
      "  .card { border-radius: 0.75rem; }",
      "  .card-body { padding: 0.85rem !important; }",
      "  .dashboard-stat, .stat-card, .card .display-4, .card .display-5, .card .fs-1, .card h2.display-6 {",
      "    font-size: 1.6rem !important; line-height: 1.15 !important; }",
      "  .email-card-mobile, .email-row.card, .card.email-card-mobile {",
      "    margin-bottom: 0.65rem !important; border-radius: 0.75rem !important; }",
      "  .email-card-mobile .card-body, .email-row.card .card-body { padding: 0.85rem !important; }",
      "  .email-card-mobile .btn, .email-card-actions .btn { min-height: var(--ha-touch); font-size: 0.95rem; }",
      "  .btn { min-height: 42px; border-radius: 0.55rem; }",
      "  .btn-sm { min-height: 38px; }",
      "  .btn-group-vertical > .btn, .d-grid .btn, .btn.w-100 { margin-bottom: 0.4rem; }",
      "  .form-control, .form-select, input.form-control, select.form-select {",
      "    min-height: 42px; font-size: 16px !important; }",
      "  label, .form-label { font-size: 0.9rem; }",
      "  .table-responsive { -webkit-overflow-scrolling: touch; }",
      "  table.table { font-size: 0.85rem; }",
      "  footer, .footer { font-size: 0.7rem !important; padding: 0.4rem 0.5rem !important;",
      "    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }",
      "  .offcanvas, .navbar-collapse { max-width: 88vw; }",
      "  .navbar-nav .nav-link { padding: 0.7rem 1rem !important; font-size: 1rem; min-height: var(--ha-touch);",
      "    display: flex; align-items: center; }",
      "  .badge { font-size: 0.75rem; }",
      "  #ha-eml-progress-wrap .progress { height: 26px !important; }",
      "}",
      "@media (max-width: 400px) {",
      "  h1, .h1 { font-size: 1.2rem !important; }",
      "  .container, .container-fluid, main { padding-left: 0.55rem !important; padding-right: 0.55rem !important; }",
      "  .card-body { padding: 0.7rem !important; }",
      "}",
      "@supports (padding: max(0px)) {",
      "  body { padding-left: max(0px, env(safe-area-inset-left));",
      "         padding-right: max(0px, env(safe-area-inset-right)); }",
      "  footer, .footer { padding-bottom: max(0.4rem, env(safe-area-inset-bottom)) !important; }",
      "}"
    ].join("\n");
    document.head.appendChild(s);
  }

  function startAll() {
    injectMobileCss();
    fixIngressPaths();
    start(); fixEml();
    setTimeout(fixEml, 800);
    setTimeout(fixEml, 2500);
    setTimeout(fixIngressPaths, 500);
    setTimeout(fixIngressPaths, 2000);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", startAll);
  else startAll();
})();
