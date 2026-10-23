#!/usr/bin/env python3
"""Security page styled like Mail-Archiver (Bootstrap navbar)."""
from __future__ import annotations

import json
import os
import subprocess
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HOST = "127.0.0.1"
PORT = int(os.environ.get("SECURITY_UI_PORT", "5002"))
DATA = Path("/data")
STATUS = DATA / "security" / "status.json"
SCAN_LOG = DATA / "security" / "last-scan.log"
EVENTS = DATA / "security" / "events.jsonl"
QUAR = DATA / "quarantine"
IMPORT = DATA / "import"
SECURITY_SH = "/security.sh"

_scan_lock = threading.Lock()
_scan_running = False


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_status() -> dict:
    try:
        if STATUS.exists():
            return json.loads(STATUS.read_text(encoding="utf-8"))
    except Exception as e:
        return {"message": f"status read error: {e}"}
    return {"message": "noch kein Status", "virus_scan_enabled": None}


def read_log(max_lines: int = 200) -> str:
    try:
        if not SCAN_LOG.exists():
            return "(noch kein Scan-Log)"
        lines = SCAN_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[-max_lines:])
    except Exception as e:
        return f"Log-Fehler: {e}"


def list_dir_files(root: Path, limit: int = 500) -> list[dict]:
    items: list[dict] = []
    if not root.exists():
        return items
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        try:
            st = p.stat()
            items.append(
                {
                    "path": str(p.relative_to(root)),
                    "size": st.st_size,
                    "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    ),
                }
            )
        except OSError:
            continue
        if len(items) >= limit:
            break
    return items


def read_events(max_n: int = 100) -> list[dict]:
    out: list[dict] = []
    if not EVENTS.exists():
        return out
    try:
        lines = EVENTS.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[-max_n:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"raw": line})
    except Exception:
        pass
    return list(reversed(out))


def append_event(kind: str, detail: str) -> None:
    try:
        EVENTS.parent.mkdir(parents=True, exist_ok=True)
        with EVENTS.open("a", encoding="utf-8") as f:
            f.write(
                json.dumps({"ts": _now(), "kind": kind, "detail": detail}, ensure_ascii=False)
                + "\n"
            )
    except Exception:
        pass


def trigger_scan() -> dict:
    global _scan_running
    with _scan_lock:
        if _scan_running:
            return {"ok": False, "message": "Scan läuft bereits"}
        _scan_running = True

    def _run() -> None:
        global _scan_running
        try:
            append_event("scan_start", "Manueller Scan gestartet")
            r = subprocess.run(
                [SECURITY_SH, "scan"], capture_output=True, text=True, timeout=3600
            )
            out = (r.stdout or "") + (r.stderr or "")
            append_event("scan_end", f"exit={r.returncode}")
            if SCAN_LOG.exists():
                with SCAN_LOG.open("a", encoding="utf-8") as f:
                    f.write(f"\n--- manual scan {_now()} ---\n")
                    f.write(out[-8000:])
        except Exception as e:
            append_event("scan_error", str(e))
        finally:
            with _scan_lock:
                _scan_running = False

    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "message": "Scan gestartet"}


def clamd_alive() -> bool:
    try:
        return subprocess.run(["pgrep", "-x", "clamd"], capture_output=True).returncode == 0
    except Exception:
        return False


# Bootstrap CDN so the page matches Mail-Archiver without depending on app static files under ingress
HTML = r"""<!DOCTYPE html>
<html lang="de" data-theme="dark">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Virenschutz - Mail-Archiver</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"/>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"/>
<style>
  :root, [data-theme="dark"] {
    --bg: #1a1d21; --card: #212529; --text: #e9ecef; --muted: #adb5bd; --border: #343a40;
  }
  body { background: var(--bg); color: var(--text); padding-top: 70px; }
  .card { background: var(--card); border-color: var(--border); color: var(--text); }
  .card-header { background: transparent; border-color: var(--border); font-weight: 600; }
  .table { color: var(--text); }
  .table > :not(caption) > * > * { background: transparent; color: var(--text); border-color: var(--border); }
  pre.log {
    background: #0d1117; color: #c9d1d9; border: 1px solid var(--border);
    border-radius: .375rem; padding: .75rem; max-height: 320px; overflow: auto; font-size: .8rem;
  }
  .stat-val { font-size: 1.5rem; font-weight: 600; }
  .navbar-brand { font-weight: 600; }
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
  <div class="container-fluid">
    <a class="navbar-brand" id="brand-home" href="../">
      <i class="bi bi-envelope-check me-1"></i>Mail-Archiver
    </a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navMain">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navMain">
      <ul class="navbar-nav me-auto">
        <li class="nav-item">
          <a class="nav-link" id="link-dash" href="../"><i class="bi bi-speedometer2 me-1"></i>Dashboard</a>
        </li>
        <li class="nav-item">
          <a class="nav-link active" href="#"><i class="bi bi-shield-check me-1"></i>Virenschutz</a>
        </li>
      </ul>
      <span class="navbar-text me-3" id="header-badge"></span>
    </div>
  </div>
</nav>

<div class="container-fluid body-content px-3 px-lg-4">
  <div class="d-flex flex-wrap justify-content-between align-items-center mb-3 gap-2">
    <h1 class="h3 mb-0"><i class="bi bi-shield-check me-2"></i>Virenschutz</h1>
    <div class="d-flex gap-2">
      <button type="button" class="btn btn-primary" id="btn-scan">
        <i class="bi bi-play-fill me-1"></i>Scan jetzt starten
      </button>
      <button type="button" class="btn btn-outline-light" id="btn-refresh">
        <i class="bi bi-arrow-clockwise me-1"></i>Aktualisieren
      </button>
    </div>
  </div>

  <div class="row g-3 mb-3" id="cards"></div>

  <div class="card mb-3">
    <div class="card-header"><i class="bi bi-activity me-1"></i>Ereignisse &amp; Erkennungen</div>
    <div class="card-body p-0" id="events"></div>
  </div>

  <div class="card mb-3">
    <div class="card-header"><i class="bi bi-exclamation-octagon me-1"></i>Quarantäne <span id="q-count" class="text-muted"></span></div>
    <div class="card-body p-0" id="quarantine"></div>
  </div>

  <div class="card mb-3">
    <div class="card-header"><i class="bi bi-folder me-1"></i>Import-Ordner <code class="ms-1">/data/import</code></div>
    <div class="card-body p-0" id="import"></div>
  </div>

  <div class="card mb-4">
    <div class="card-header"><i class="bi bi-terminal me-1"></i>Scan-Log</div>
    <div class="card-body"><pre class="log mb-0" id="log">Lade…</pre></div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
(function () {
  function securityBase() {
    var p = location.pathname.replace(/\/+$/, '');
    if (p.endsWith('/security')) return p;
    var i = p.lastIndexOf('/security');
    if (i >= 0) return p.slice(0, i + '/security'.length);
    return '/security';
  }
  var base = securityBase();
  var home = base.replace(/\/security\/?$/, '/') || '../';
  document.getElementById('brand-home').href = home;
  document.getElementById('link-dash').href = home;

  function api(path, opts) {
    return fetch(base + path, opts).then(function (r) {
      if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
      var ct = r.headers.get('content-type') || '';
      return ct.indexOf('json') >= 0 ? r.json() : r.text();
    });
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];
    });
  }

  function fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  function table(rows, empty) {
    if (!rows || !rows.length) return '<div class="p-3 text-muted">' + empty + '</div>';
    var h = '<div class="table-responsive"><table class="table table-sm table-hover mb-0"><thead><tr><th>Datei</th><th>Größe</th><th>Geändert</th></tr></thead><tbody>';
    rows.forEach(function (r) {
      h += '<tr><td>' + esc(r.path) + '</td><td>' + fmtSize(r.size) + '</td><td>' + esc(r.mtime) + '</td></tr>';
    });
    return h + '</tbody></table></div>';
  }

  function badge(enabled, clamd, infected) {
    var el = document.getElementById('header-badge');
    if (enabled === false) {
      el.innerHTML = '<span class="badge text-bg-secondary"><i class="bi bi-shield me-1"></i>Scan aus</span>';
    } else if (infected > 0) {
      el.innerHTML = '<span class="badge text-bg-danger"><i class="bi bi-shield-exclamation me-1"></i>Treffer</span>';
    } else if (clamd) {
      el.innerHTML = '<span class="badge text-bg-success"><i class="bi bi-shield-check me-1"></i>Aktiv</span>';
    } else {
      el.innerHTML = '<span class="badge text-bg-warning text-dark"><i class="bi bi-shield me-1"></i>clamscan</span>';
    }
  }

  function refresh() {
    api('/api/status').then(function (data) {
      var s = data.status || {};
      var infected = s.infected_moved || 0;
      badge(s.virus_scan_enabled, s.clamd_running, infected);

      document.getElementById('cards').innerHTML =
        '<div class="col-6 col-md-4 col-xl-2"><div class="card h-100"><div class="card-body">' +
        '<div class="text-muted small">Virenscan</div><div class="stat-val">' +
        (s.virus_scan_enabled === false ? 'Aus' : 'An') + '</div></div></div></div>' +
        '<div class="col-6 col-md-4 col-xl-2"><div class="card h-100"><div class="card-body">' +
        '<div class="text-muted small">ClamAV</div><div class="stat-val">' +
        (s.clamd_running ? 'Daemon' : 'CLI') + '</div></div></div></div>' +
        '<div class="col-6 col-md-4 col-xl-3"><div class="card h-100"><div class="card-body">' +
        '<div class="text-muted small">Letzter Scan</div><div class="stat-val fs-6">' +
        esc(s.last_scan || '—') + '</div></div></div></div>' +
        '<div class="col-6 col-md-4 col-xl-2"><div class="card h-100"><div class="card-body">' +
        '<div class="text-muted small">Treffer</div><div class="stat-val ' +
        (infected ? 'text-danger' : 'text-success') + '">' + infected + '</div></div></div></div>' +
        '<div class="col-6 col-md-4 col-xl-2"><div class="card h-100"><div class="card-body">' +
        '<div class="text-muted small">Scan läuft</div><div class="stat-val">' +
        (data.scan_running ? 'Ja' : 'Nein') + '</div></div></div></div>';

      var ev = data.events || [];
      if (!ev.length) {
        document.getElementById('events').innerHTML = '<div class="p-3 text-muted">Noch keine Ereignisse.</div>';
      } else {
        var h = '<div class="table-responsive"><table class="table table-sm mb-0"><thead><tr><th>Zeit</th><th>Typ</th><th>Detail</th></tr></thead><tbody>';
        ev.forEach(function (e) {
          h += '<tr><td>' + esc(e.ts) + '</td><td>' + esc(e.kind) + '</td><td>' + esc(e.detail || e.raw) + '</td></tr>';
        });
        document.getElementById('events').innerHTML = h + '</tbody></table></div>';
      }

      var q = data.quarantine || [];
      document.getElementById('q-count').textContent = '(' + q.length + ')';
      document.getElementById('quarantine').innerHTML = table(q, 'Quarantäne ist leer.');
      document.getElementById('import').innerHTML = table(data.import_files || [], 'Keine Dateien in /data/import');
      document.getElementById('log').textContent = data.log || '(leer)';
      document.getElementById('btn-scan').disabled = !!data.scan_running;
    }).catch(function (e) {
      document.getElementById('header-badge').innerHTML =
        '<span class="badge text-bg-danger">' + esc(e.message) + '</span>';
    });
  }

  document.getElementById('btn-refresh').onclick = refresh;
  document.getElementById('btn-scan').onclick = function () {
    document.getElementById('btn-scan').disabled = true;
    api('/api/scan', { method: 'POST' }).then(function () {
      setTimeout(refresh, 1500);
    }).catch(function (e) {
      alert('Scan fehlgeschlagen: ' + e.message);
      document.getElementById('btn-scan').disabled = false;
    });
  };

  refresh();
  setInterval(refresh, 10000);
})();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print(f"[security-ui] {self.address_string()} {fmt % args}")

    def _json(self, code: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _strip(self, path: str) -> str:
        path = path.rstrip("/") or "/"
        if path.startswith("/security"):
            path = path[len("/security") :] or "/"
        return path

    def do_GET(self) -> None:
        path = self._strip(urlparse(self.path).path)
        if path in ("/", "/index.html"):
            self._html(200, HTML)
            return
        if path == "/api/status":
            self._json(
                200,
                {
                    "status": read_status(),
                    "scan_running": _scan_running,
                    "clamd_alive": clamd_alive(),
                    "quarantine": list_dir_files(QUAR),
                    "import_files": list_dir_files(IMPORT, 200),
                    "events": read_events(),
                    "log": read_log(),
                    "server_time": _now(),
                },
            )
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = self._strip(urlparse(self.path).path)
        if path == "/api/scan":
            self._json(200, trigger_scan())
            return
        self._json(404, {"error": "not found"})


def main() -> None:
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    QUAR.mkdir(parents=True, exist_ok=True)
    IMPORT.mkdir(parents=True, exist_ok=True)
    print(f"[security-ui] listening on http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
