/*! ha-mail-archiver UI inject: Navbar + Chunk-Upload + Ingress + Mobile */
(function () {
  var CHUNK_SIZE = 4 * 1024 * 1024;
  var LARGE_THRESHOLD = 8 * 1024 * 1024;
  var activeXhr = null;

  function ingressPrefix() {
    try {
      var m = (location.pathname || "").match(/(\/api\/hassio_ingress\/[^/]+)/);
      if (m) return m[1];
      var b = document.querySelector("base");
      if (b && b.href) {
        var u = new URL(b.href, location.origin);
        var mm = u.pathname.match(/(\/api\/hassio_ingress\/[^/]+)/);
        if (mm) return mm[1];
      }
    } catch (e) {}
    return "";
  }

  function withPrefix(path) {
    var p = ingressPrefix();
    if (!p) return path;
    if (path.indexOf(p) === 0) return path;
    if (path.charAt(0) !== "/") path = "/" + path;
    return p + path;
  }

  function ensureProgress() {
    var el = document.getElementById("ha-eml-progress-wrap");
    if (el) return el;
    el = document.createElement("div");
    el.id = "ha-eml-progress-wrap";
    el.style.cssText = "display:none;margin:.75rem 0";
    el.innerHTML =
      '<div class="progress" style="height:22px">' +
      '<div id="ha-eml-progress-bar" class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" style="width:0%">0%</div>' +
      "</div>" +
      '<div id="ha-eml-progress-text" class="small text-muted mt-1"></div>';
    return el;
  }

  function showProgress(pct, text) {
    var wrap = ensureProgress();
    wrap.style.display = "block";
    var bar = document.getElementById("ha-eml-progress-bar");
    var tx = document.getElementById("ha-eml-progress-text");
    if (bar) {
      bar.style.width = pct + "%";
      bar.textContent = Math.round(pct) + "%";
    }
    if (tx) tx.textContent = text || "";
  }

  function hideProgress() {
    var wrap = document.getElementById("ha-eml-progress-wrap");
    if (wrap) wrap.style.display = "none";
  }

  function go() {
    try {
      var nav = document.querySelector(".navbar-nav") || document.querySelector("nav .navbar-nav");
      if (!nav) return;
      if (document.getElementById("ha-nav-security")) return;
      var a = document.createElement("a");
      a.id = "ha-nav-security";
      a.className = "nav-link";
      a.href = withPrefix("/security/");
      a.innerHTML = '<i class="bi bi-shield-lock"></i> Security';
      var li = document.createElement("li");
      li.className = "nav-item";
      li.appendChild(a);
      nav.appendChild(li);
    } catch (e) {}
  }

  function start() {
    go();
    setTimeout(go, 400);
    setTimeout(go, 1500);
  }

  function fixIngressPaths() {
    var p = ingressPrefix();
    if (!p) return;
    try {
      document.querySelectorAll("[data-email-url]").forEach(function (el) {
        var u = el.getAttribute("data-email-url");
        if (u && u.charAt(0) === "/" && u.indexOf(p) !== 0) {
          el.setAttribute("data-email-url", p + u);
        }
      });
      document.querySelectorAll('a[href^="/"]').forEach(function (a) {
        var h = a.getAttribute("href");
        if (h && h.indexOf(p) !== 0 && h.indexOf("/api/") !== 0) {
          a.setAttribute("href", p + h);
        }
      });
    } catch (e) {}
  }

  function chunkedUpload(file, form) {
    return new Promise(function (resolve, reject) {
      var total = file.size;
      var chunks = Math.ceil(total / CHUNK_SIZE);
      var uploadId =
        "u" +
        Date.now().toString(36) +
        Math.random().toString(36).slice(2, 10);
      var idx = 0;

      function next() {
        if (idx >= chunks) {
          showProgress(100, "Upload fertig – Import wird gestartet…");
          resolve(uploadId);
          return;
        }
        var start = idx * CHUNK_SIZE;
        var end = Math.min(start + CHUNK_SIZE, total);
        var blob = file.slice(start, end);
        var xhr = new XMLHttpRequest();
        activeXhr = xhr;
        xhr.open("POST", withPrefix("/security/api/upload-chunk"));
        xhr.setRequestHeader("X-Upload-Id", uploadId);
        xhr.setRequestHeader("X-Chunk-Index", String(idx));
        xhr.setRequestHeader("X-Chunk-Total", String(chunks));
        xhr.setRequestHeader("X-File-Name", encodeURIComponent(file.name));
        xhr.setRequestHeader("X-File-Size", String(total));
        xhr.upload.onprogress = function (ev) {
          if (!ev.lengthComputable) return;
          var done = start + ev.loaded;
          var pct = (done / total) * 100;
          showProgress(pct, "Upload " + Math.round(pct) + "% (" + (idx + 1) + "/" + chunks + ")");
        };
        xhr.onload = function () {
          if (xhr.status >= 200 && xhr.status < 300) {
            idx++;
            next();
          } else {
            reject(new Error("Chunk-Upload fehlgeschlagen: HTTP " + xhr.status));
          }
        };
        xhr.onerror = function () {
          reject(new Error("Netzwerkfehler beim Chunk-Upload"));
        };
        xhr.send(blob);
      }
      next();
    });
  }

  function fixEml() {
    try {
      var form =
        document.querySelector('form[action*="ImportEml"]') ||
        document.querySelector('form[action*="Import"]') ||
        document.querySelector("#importForm");
      if (!form) return;
      var fileInput =
        form.querySelector('input[type="file"]') ||
        document.querySelector('input[type="file"]');
      if (!fileInput) return;

      var btn =
        form.querySelector('button[type="submit"]') ||
        form.querySelector('input[type="submit"]');
      if (!btn) {
        btn = document.createElement("button");
        btn.type = "submit";
        btn.className = "btn btn-primary";
        btn.textContent = "Hochladen";
        form.appendChild(btn);
      }

      var wrap = ensureProgress();
      if (!wrap.parentNode) {
        if (btn.parentNode) btn.parentNode.insertBefore(wrap, btn.nextSibling);
        else form.appendChild(wrap);
      }

      if (form.dataset.haChunkBound === "1") return;
      form.dataset.haChunkBound = "1";

      form.addEventListener(
        "submit",
        function (ev) {
          var f = fileInput.files && fileInput.files[0];
          if (!f) return;
          if (f.size < LARGE_THRESHOLD) return;
          ev.preventDefault();
          ev.stopPropagation();
          showProgress(0, "Starte Upload…");
          chunkedUpload(f, form)
            .then(function (uploadId) {
              return fetch(withPrefix("/security/api/assemble-and-import"), {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  uploadId: uploadId,
                  fileName: f.name,
                  accountId: (form.querySelector('[name*="Account"]') || {}).value || null,
                }),
              });
            })
            .then(function (r) {
              return r.json().catch(function () {
                return {};
              });
            })
            .then(function (data) {
              showProgress(100, (data && data.message) || "Import gestartet");
              if (data && data.redirect) location.href = withPrefix(data.redirect);
              else location.href = withPrefix("/Emails/Jobs");
            })
            .catch(function (err) {
              showProgress(0, String(err && err.message ? err.message : err));
              alert("Upload fehlgeschlagen: " + (err && err.message ? err.message : err));
            });
        },
        true
      );
    } catch (e) {}
  }

  function injectMobileCss() {
    if (document.getElementById("ha-mobile-css")) return;
    var s = document.createElement("style");
    s.id = "ha-mobile-css";
    var underIngress = !!ingressPrefix();
    var forceMobile =
      underIngress ||
      window.matchMedia("(max-width: 900px)").matches ||
      /Android|iPhone|iPad|Mobile/i.test(navigator.userAgent || "");
    var css = [
      "html{ -webkit-text-size-adjust:100%; text-size-adjust:100%; }",
      "body{overflow-x:hidden;max-width:100vw;}",
      ".container,.container-fluid{max-width:100%!important;padding-left:.65rem!important;padding-right:.65rem!important;}",
    ];
    if (forceMobile) {
      css.push(
        ".stat-card-modern .stat-value{font-size:1.35rem!important}",
        ".stat-card-modern .stat-label{font-size:.78rem!important}",
        ".stat-card-modern .stat-icon{font-size:1.25rem!important}",
        ".card{margin-bottom:.65rem!important}",
        ".btn{min-height:40px!important}",
        ".btn-sm{min-height:38px!important}",
        ".btn.w-100,.d-grid .btn{margin-bottom:.35rem!important}",
        ".form-control,.form-select,input.form-control,select.form-select,textarea.form-control{min-height:42px!important;font-size:16px!important}",
        "label,.form-label{font-size:.88rem!important}",
        ".table-responsive{-webkit-overflow-scrolling:touch;max-width:100%}",
        "table.table{font-size:.82rem!important}",
        "footer,.footer{font-size:.65rem!important;padding:.35rem .45rem!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important}",
        ".navbar-nav .nav-link{padding:.65rem .9rem!important;font-size:.98rem!important;min-height:44px!important;display:flex!important;align-items:center!important}",
        ".offcanvas{max-width:86vw!important}",
        ".badge{font-size:.72rem!important}",
        "#ha-eml-progress-wrap .progress{height:26px!important}",
        ".row.g-3,.row.g-4{--bs-gutter-y:.55rem!important;--bs-gutter-x:.55rem!important}"
      );
    }
    css.push(
      "@supports (padding:max(0px)){",
      "body{padding-left:max(0px,env(safe-area-inset-left))!important;padding-right:max(0px,env(safe-area-inset-right))!important}",
      "footer,.footer{padding-bottom:max(.35rem,env(safe-area-inset-bottom))!important}",
      "}"
    );
    s.textContent = css.join("\n");
    document.head.appendChild(s);
    try {
      if (forceMobile) document.body.classList.add("ha-mobile");
      if (underIngress) document.body.classList.add("ha-ingress");
    } catch (e) {}
  }

  function setupDashboardAutoRefresh() {
    try {
      if (!document.querySelector(".stat-card-modern, .stat-value, [data-count-target]")) return;
      var INTERVAL_MS = 60000;
      var last = Date.now();
      function maybeReload() {
        if (document.visibilityState !== "visible") return;
        if (Date.now() - last < INTERVAL_MS - 500) return;
        last = Date.now();
        try { location.reload(); } catch (e) {}
      }
      setInterval(maybeReload, INTERVAL_MS);
      document.addEventListener("visibilitychange", function () {
        if (document.visibilityState === "visible" && Date.now() - last >= INTERVAL_MS) maybeReload();
      });
    } catch (e) {}
  }

  function startAll() {
    injectMobileCss();
    fixIngressPaths();
    setupDashboardAutoRefresh();
    start(); fixEml();
    setTimeout(fixEml, 800);
    setTimeout(fixEml, 2500);
    setTimeout(fixIngressPaths, 500);
    setTimeout(fixIngressPaths, 2000);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", startAll);
  else startAll();
})();
