/*! ha-mail-archiver UI inject: Navbar + Chunk-Upload + Auto-Import */
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
    var base = document.querySelector("base");
    var href = (base && base.getAttribute("href")) || "";
    if (href) return href.replace(/\/+$/, "") + "/security";
    return "security";
  }

  function ensureProgress(btn) {
    var box = document.getElementById("ha-eml-progress");
    if (box) return box;
    box = document.createElement("div");
    box.id = "ha-eml-progress";
    box.style.cssText = "display:none;margin-top:.75rem;max-width:520px";
    box.innerHTML =
      '<div class="d-flex justify-content-between small mb-1">' +
      '<span id="ha-eml-prog-label">Upload</span>' +
      '<span id="ha-eml-prog-pct">0%</span></div>' +
      '<div class="progress" style="height:1.25rem">' +
      '<div id="ha-eml-prog-bar" class="progress-bar progress-bar-striped progress-bar-animated bg-primary" role="progressbar" style="width:0%">0%</div></div>' +
      '<div id="ha-eml-prog-detail" class="small text-muted mt-1"></div>' +
      '<button type="button" class="btn btn-outline-secondary btn-sm mt-2" id="ha-eml-abort" style="display:none">Abbrechen</button>';
    if (btn && btn.parentNode) btn.parentNode.insertBefore(box, btn.nextSibling);
    else document.body.appendChild(box);
    var abortBtn = document.getElementById("ha-eml-abort");
    if (abortBtn) {
      abortBtn.onclick = function () {
        if (activeXhr) { try { activeXhr.abort(); } catch (e) {} activeXhr = null; }
        window._haUploadAborted = true;
        setProg(0, "Abgebrochen", "Upload vom Benutzer abgebrochen");
        abortBtn.style.display = "none";
      };
    }
    return box;
  }

  function setProg(pct, label, detail) {
    var box = document.getElementById("ha-eml-progress");
    if (!box) return;
    box.style.display = "block";
    pct = Math.max(0, Math.min(100, Math.round(pct)));
    var bar = document.getElementById("ha-eml-prog-bar");
    var pctEl = document.getElementById("ha-eml-prog-pct");
    var lab = document.getElementById("ha-eml-prog-label");
    var det = document.getElementById("ha-eml-prog-detail");
    if (bar) { bar.style.width = pct + "%"; bar.textContent = pct + "%"; }
    if (pctEl) pctEl.textContent = pct + "%";
    if (lab && label) lab.textContent = label;
    if (det && detail != null) det.textContent = detail;
  }

  function uid() {
    return "u" + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
  }

  function putChunk(url, uploadId, filename, idx, total, blob) {
    return new Promise(function (resolve, reject) {
      var xhr = new XMLHttpRequest();
      activeXhr = xhr;
      xhr.open("POST", url, true);
      xhr.timeout = 0;
      xhr.setRequestHeader("X-Upload-Id", uploadId);
      xhr.setRequestHeader("X-File-Name", filename);
      xhr.setRequestHeader("X-Chunk-Index", String(idx));
      xhr.setRequestHeader("X-Chunk-Total", String(total));
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
      try { xhr.withCredentials = true; } catch (e) {}
      xhr.onload = function () {
        activeXhr = null;
        if (xhr.status >= 200 && xhr.status < 300) {
          try { resolve(JSON.parse(xhr.responseText || "{}")); }
          catch (e) { reject(new Error("Ungueltige Server-Antwort")); }
        } else {
          var msg = xhr.responseText || ("HTTP " + xhr.status);
          try { var j = JSON.parse(xhr.responseText); if (j.message) msg = j.message; } catch (e) {}
          reject(new Error(msg));
        }
      };
      xhr.onerror = function () { activeXhr = null; reject(new Error("Netzwerkfehler bei Chunk " + (idx + 1))); };
      xhr.onabort = function () { activeXhr = null; reject(new Error("abgebrochen")); };
      xhr.send(blob);
    });
  }

  async function chunkedUpload(file, btn) {
    window._haUploadAborted = false;
    var uploadId = uid();
    var total = Math.ceil(file.size / CHUNK_SIZE) || 1;
    var url = securityBase().replace(/\/+$/, "") + "/api/upload-chunk";
    var abortEl = document.getElementById("ha-eml-abort");
    if (abortEl) abortEl.style.display = "inline-block";
    var bar = document.getElementById("ha-eml-prog-bar");
    if (bar) { bar.classList.remove("bg-danger", "bg-success"); bar.classList.add("bg-primary"); }
    setProg(0, "Chunk-Upload startet...", file.name + " (" + fmtSize(file.size) + "), " + total + " Teile");
    var sent = 0;
    for (var i = 0; i < total; i++) {
      if (window._haUploadAborted) throw new Error("abgebrochen");
      var startB = i * CHUNK_SIZE;
      var end = Math.min(file.size, startB + CHUNK_SIZE);
      var blob = file.slice(startB, end);
      setProg((sent / file.size) * 100, "Hochladen... Teil " + (i + 1) + "/" + total, fmtSize(sent) + " / " + fmtSize(file.size));
      btn.innerHTML = '<i class="bi bi-cloud-upload me-2"></i>Upload ' + Math.round((sent / file.size) * 100) + "%";
      var result = await putChunk(url, uploadId, file.name, i, total, blob);
      if (!result.ok) throw new Error(result.message || "Chunk fehlgeschlagen");
      sent = end;
      uploadId = result.upload_id || uploadId;
      setProg((sent / file.size) * 100, "Hochladen... Teil " + (i + 1) + "/" + total, fmtSize(sent) + " / " + fmtSize(file.size));
      btn.innerHTML = '<i class="bi bi-cloud-upload me-2"></i>Upload ' + Math.round((sent / file.size) * 100) + "%";
      if (result.done) {
        if (bar) { bar.classList.remove("bg-primary"); bar.classList.add("bg-success"); }
        setProg(100, "Upload fertig – starte Import...", result.message || ("Gespeichert: /data/import/" + (result.filename || file.name)));
        if (abortEl) abortEl.style.display = "none";
        btn.innerHTML = '<i class="bi bi-hourglass-split me-2"></i>Import starten...';
        var sel = document.getElementById("accountSelect");
        var accountId = sel && sel.value ? parseInt(sel.value, 10) : 0;
        var fname = result.filename || file.name;
        var importUrl = securityBase().replace(/\/+$/, "") + "/api/import-local";
        try {
          var ir = await fetch(importUrl, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
            body: JSON.stringify({ file: "/data/import/" + fname, account_id: accountId })
          });
          var ij = {};
          try { ij = await ir.json(); } catch (e) {}
          if (ij && ij.ok) {
            setProg(100, "Import gestartet", ij.message || "Job laeuft im Hintergrund");
            btn.innerHTML = '<i class="bi bi-check2-circle me-2"></i>Import gestartet';
            btn.disabled = false;
            var note = document.getElementById("ha-eml-done-note");
            if (!note) {
              note = document.createElement("div");
              note.id = "ha-eml-done-note";
              note.className = "alert alert-success mt-3";
              var box = document.getElementById("ha-eml-progress");
              if (box && box.parentNode) box.parentNode.insertBefore(note, box.nextSibling);
            }
            if (ij.jobs_visible !== false) {
              note.innerHTML = "<strong>Upload + Import-Job gestartet.</strong> Datei <code>/data/import/" +
                fname + "</code>. Weiterleitung zu <a href=\"Emails/Jobs\">EML-Import-Jobs</a>…";
              var dest = ij.redirect || "Emails/Jobs";
              if (dest.charAt(0) === "/") dest = dest.replace(/^\//, "");
              setTimeout(function () { window.location.href = dest; }, 1200);
            } else {
              note.className = "alert alert-warning mt-3";
              note.innerHTML = "<strong>Import laeuft (CLI).</strong> " + (ij.message || "") +
                " Mails erscheinen im <a href=\"Emails\">Archiv</a>; unter Jobs nur bei Web-Import.";
              setTimeout(function () { window.location.href = "Emails"; }, 2500);
            }
          } else {
            setProg(100, "Upload ok – Import manuell noetig", (ij && ij.message) || "Import-API fehlgeschlagen");
            btn.innerHTML = '<i class="bi bi-check2-circle me-2"></i>Datei im Import-Ordner';
            btn.disabled = false;
          }
        } catch (e) {
          setProg(100, "Upload ok – Import-Start fehlgeschlagen", String(e));
          btn.disabled = false;
          btn.innerHTML = '<i class="bi bi-check2-circle me-2"></i>Datei im Import-Ordner';
        }
        return result;
      }
    }
    throw new Error("Upload unvollstaendig");
  }

  function singleXhrUpload(form, file, btn) {
    return new Promise(function (resolve, reject) {
      var fd = new FormData(form);
      var xhr = new XMLHttpRequest();
      activeXhr = xhr;
      xhr.timeout = 0;
      var abortEl = document.getElementById("ha-eml-abort");
      if (abortEl) abortEl.style.display = "inline-block";
      setProg(0, "Upload startet...", file.name + " (" + fmtSize(file.size) + ")");
      xhr.upload.onprogress = function (e) {
        if (e.lengthComputable) {
          var pct = e.total ? (e.loaded / e.total) * 100 : 0;
          setProg(pct, "Hochladen...", fmtSize(e.loaded) + " / " + fmtSize(e.total));
          btn.innerHTML = '<i class="bi bi-cloud-upload me-2"></i>Upload ' + Math.round(pct) + "%";
        }
      };
      xhr.upload.onload = function () {
        setProg(100, "Upload fertig – Server verarbeitet...", "Datei vollstaendig uebertragen");
        btn.innerHTML = '<i class="bi bi-hourglass-split me-2"></i>Verarbeiten...';
      };
      xhr.onerror = function () { activeXhr = null; reject(new Error("Netzwerkfehler")); };
      xhr.onabort = function () { activeXhr = null; reject(new Error("abgebrochen")); };
      xhr.onload = function () {
        activeXhr = null;
        if (abortEl) abortEl.style.display = "none";
        if (xhr.status >= 200 && xhr.status < 400) {
          var loc = xhr.getResponseHeader("Location");
          if (loc) { window.location.href = loc; resolve(); return; }
          var ct = xhr.getResponseHeader("Content-Type") || "";
          if (ct.indexOf("text/html") >= 0 && xhr.responseText) {
            document.open(); document.write(xhr.responseText); document.close(); resolve(); return;
          }
          window.location.reload(); resolve();
        } else reject(new Error("HTTP " + xhr.status));
      };
      xhr.open((form.getAttribute("method") || "POST").toUpperCase(), form.getAttribute("action") || window.location.href, true);
      xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
      try { xhr.withCredentials = true; } catch (e) {}
      xhr.send(fd);
    });
  }

  function fixEml() {
    try {
      var input = document.getElementById("emlFileInput");
      if (!input) return;
      var form = document.getElementById("emlImportForm");
      var btn = document.getElementById("submitBtn");
      if (!form || !btn) return;
      if (!document.getElementById("ha-eml-upload-btn")) {
        var wrap = document.createElement("div");
        wrap.className = "mb-2 d-flex align-items-center gap-2 flex-wrap";
        var uBtn = document.createElement("button");
        uBtn.type = "button"; uBtn.id = "ha-eml-upload-btn"; uBtn.className = "btn btn-outline-primary";
        uBtn.innerHTML = '<i class="bi bi-folder2-open me-1"></i>Datei waehlen (ZIP mit EMLs)';
        uBtn.onclick = function () { input.click(); };
        var nameSpan = document.createElement("span");
        nameSpan.id = "ha-eml-filename"; nameSpan.className = "text-muted small"; nameSpan.style.display = "none";
        input.style.position = "absolute"; input.style.width = "1px"; input.style.height = "1px";
        input.style.opacity = "0"; input.style.overflow = "hidden";
        input.parentNode.insertBefore(wrap, input);
        wrap.appendChild(uBtn); wrap.appendChild(nameSpan); wrap.appendChild(input);
      }
      ensureProgress(btn);
      function update() {
        var hasFile = input.files && input.files.length > 0;
        var sel = document.getElementById("accountSelect");
        var hasAcc = sel && sel.value;
        btn.disabled = !(hasFile && hasAcc);
        var ns = document.getElementById("ha-eml-filename");
        if (ns) {
          if (hasFile) { ns.textContent = input.files[0].name + " (" + fmtSize(input.files[0].size) + ")"; ns.style.display = "inline"; }
          else ns.style.display = "none";
        }
      }
      if (!input._haBound) {
        input._haBound = true;
        input.addEventListener("change", update);
        var sel = document.getElementById("accountSelect");
        if (sel) sel.addEventListener("change", update);
      }
      update();
      if (form._haXhrBound) return;
      form._haXhrBound = true;
      form.addEventListener("submit", function (ev) {
        ev.preventDefault(); ev.stopPropagation();
        if (!input.files || !input.files.length) return;
        var file = input.files[0];
        var origHtml = btn.innerHTML;
        btn.disabled = true;
        var bar = document.getElementById("ha-eml-prog-bar");
        if (bar) { bar.classList.remove("bg-danger", "bg-success"); bar.classList.add("bg-primary"); }
        var run = file.size >= LARGE_THRESHOLD ? chunkedUpload(file, btn) : singleXhrUpload(form, file, btn);
        Promise.resolve(run).catch(function (err) {
          var msg = (err && err.message) || String(err);
          setProg(0, msg === "abgebrochen" ? "Abgebrochen" : "Upload fehlgeschlagen", msg);
          if (bar) { bar.classList.remove("bg-success"); bar.classList.add("bg-danger"); }
          btn.disabled = false; btn.innerHTML = origHtml;
          var abortEl = document.getElementById("ha-eml-abort");
          if (abortEl) abortEl.style.display = "none";
        });
      }, true);
    } catch (e) {}
  }

  function startAll() {
    start(); fixEml();
    setTimeout(fixEml, 800);
    setTimeout(fixEml, 2500);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", startAll);
  else startAll();
})();
