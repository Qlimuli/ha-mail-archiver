#!/usr/bin/env python3
"""Minimal Security Dashboard for ha-mail-archiver (stdlib only)."""
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


def list_quarantine() -> list[dict]:
    items: list[dict] = []
    if not QUAR.exists():
        return items
    for p in sorted(QUAR.rglob("*")):
        if not p.is_file():
            continue
        try:
            st = p.stat()
            items.append(
                {
                    "path": str(p.relative_to(QUAR)),
                    "size": st.st_size,
                    "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    ),
                }
            )
        except OSError:
            continue
    return items[:500]


def list_import() -> list[dict]:
    items: list[dict] = []
    if not IMPORT.exists():
        return items
    for p in sorted(IMPORT.rglob("*")):
        if not p.is_file():
            continue
        try:
            st = p.stat()
            items.append(
                {
                    "path": str(p.relative_to(IMPORT)),
                    "size": st.st_size,
                    "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    ),
                }
            )
        except OSError:
            continue
    return items[:200]


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
            f.write(json.dumps({"ts": _now(), "kind": kind, "detail": detail}, ensure_ascii=False) + "\n")
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
                [SECURITY_SH, "scan"],
                capture_output=True,
                text=True,
                timeout=3600,
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
        r = subprocess.run(["pgrep", "-x", "clamd"], capture_output=True)
        return r.returncode == 0
    except Exception:
        return False


HTML = """<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Mail Archiver – Virenschutz</title>
<style>
  :root {
    --bg: #0f1419; --card: #1a2332; --text: #e7ecf3; --muted: #8b9bb4;
    --ok: #3dd68c; --warn: #f5a524; --bad: #f31260; --accent: #006fee;
    --border: #2a3548;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.45;
  }
  header {
    padding: 1rem 1.25rem; border-bottom: 1px solid var(--border);
    display: flex; flex-wrap: wrap; gap: .75rem; align-items: center; justify-content: space-between;
  }
  h1 { font-size: 1.15rem; margin: 0; font-weight: 600; }
  .badge {
    display: inline-flex; align-items: center; gap: .35rem;
    padding: .2rem .55rem; border-radius: 999px; font-size: .75rem; font-weight: 600;
  }
  .badge.ok { background: #123526; color: var(--ok); }
  .badge.warn { background: #3a2a10; color: var(--warn); }
  .badge.bad { background: #3a1018; color: var(--bad); }
  .badge.off { background: #2a2a2a; color: var(--muted); }
  main { padding: 1rem 1.25rem 2rem; max-width: 1100px; margin: 0 auto; }
  .grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
  .card {
    background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1rem;
  }
  .card h2 { margin: 0 0 .5rem; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); font-weight: 600; }
  .card .val { font-size: 1.25rem; font-weight: 600; }
  .card .sub { font-size: .8rem; color: var(--muted); margin-top: .25rem; }
  button, .btn {
    background: var(--accent); color: #fff; border: 0; border-radius: 8px;
    padding: .55rem 1rem; font-weight: 600; cursor: pointer; font-size: .9rem;
  }
  button:disabled { opacity: .5; cursor: not-allowed; }
  button.secondary { background: #2a3548; }
  pre, .log {
    background: #0a0e14; border: 1px solid var(--border); border-radius: 8px;
    padding: .75rem; overflow: auto; max-height: 320px; font-size: .75rem;
    white-space: pre-wrap; word-break: break-word; color: #c5d0e0;
  }
  table { width: 100%; border-collapse: collapse; font-size: .85rem; }
  th, td { text-align: left; padding: .45rem .35rem; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; font-size: .75rem; }
  .empty { color: var(--muted); font-size: .9rem; }
  .actions { display: flex; gap: .5rem; flex-wrap: wrap; }
  a.home { color: var(--muted); text-decoration: none; font-size: .85rem; }
  a.home:hover { color: var(--text); }
  .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .dot.ok { background: var(--ok); }
  .dot.bad { background: var(--bad); }
  .dot.warn { background: var(--warn); }
  .dot.off { background: var(--muted); }
</style>
</head>
<body>
<header>
  <div>
    <h1>🛡 Virenschutz – Mail Archiver</h1>
    <div id="header-badge" style="margin-top:.35rem"></div>
  </div>
  <div class="actions">
    <button type="button" id="btn-scan">Scan jetzt starten</button>
    <button type="button" class="secondary" id="btn-refresh">Aktualisieren</button>
    <a class="home" id="link-app" href="../">← Zur App</a>
  </div>
</header>
<main>
  <div class="grid" id="cards"></div>

  <div class="card" style="margin-top:1rem">
    <h2>Erkennungen / Ereignisse</h2>
    <div id="events"></div>
  </div>

  <div class="card" style="margin-top:1rem">
    <h2>Quarantäne <span id="q-count" style="color:var(--muted);font-weight:400"></span></h2>
    <div id="quarantine"></div>
  </div>

  <div class="card" style="margin-top:1rem">
    <h2>Import-Ordner (/data/import)</h2>
    <div id="import"></div>
  </div>

  <div class="card" style="margin-top:1rem">
    <h2>Letztes Scan-Log</h2>
    <pre id="log" class="log">Lade…</pre>
  </div>
</main>
<script>
const base = (function () {
  // works under /security/ and under ingress prefix/security/
  const p = location.pathname.replace(/\/+$/, '');
  if (p.endsWith('/security')) return p;
  const i = p.lastIndexOf('/security');
  if (i >= 0) return p.slice(0, i + '/security'.length);
  return '/security';
})();

async function api(path, opts) {
  const r = await fetch(base + path, opts);
  if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
  const ct = r.headers.get('content-type') || '';
  if (ct.includes('json')) return r.json();
  return r.text();
}

function badge(enabled, clamd, infected) {
  const el = document.getElementById('header-badge');
  if (enabled === false) {
    el.innerHTML = '<span class="badge off"><span class="dot off"></span> Virenscan deaktiviert</span>';
    return;
  }
  if (infected > 0) {
    el.innerHTML = '<span class="badge bad"><span class="dot bad"></span> Treffer in Quarantäne / letzter Scan</span>';
    return;
  }
  if (clamd) {
    el.innerHTML = '<span class="badge ok"><span class="dot ok"></span> Aktiv – clamd läuft</span>';
  } else if (enabled) {
    el.innerHTML = '<span class="badge warn"><span class="dot warn"></span> Aktiv – clamscan (ohne Daemon)</span>';
  } else {
    el.innerHTML = '<span class="badge off"><span class="dot off"></span> Unbekannt</span>';
  }
}

function fmtSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
  return (n/1048576).toFixed(1) + ' MB';
}

function renderTable(rows, emptyMsg) {
  if (!rows || !rows.length) return '<p class="empty">' + emptyMsg + '</p>';
  let h = '<table><thead><tr><th>Datei</th><th>Größe</th><th>Geändert</th></tr></thead><tbody>';
  for (const r of rows) {
    h += '<tr><td>' + escapeHtml(r.path) + '</td><td>' + fmtSize(r.size) + '</td><td>' + escapeHtml(r.mtime) + '</td></tr>';
  }
  return h + '</tbody></table>';
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function refresh() {
  try {
    const data = await api('/api/status');
    const s = data.status || {};
    const infected = s.infected_moved || 0;
    badge(s.virus_scan_enabled, s.clamd_running, infected);

    document.getElementById('cards').innerHTML = `
      <div class="card"><h2>Virenscan</h2><div class="val">${s.virus_scan_enabled === false ? 'Aus' : 'An'}</div>
        <div class="sub">${escapeHtml(s.message || '')}</div></div>
      <div class="card"><h2>ClamAV-Daemon</h2><div class="val">${s.clamd_running ? 'Läuft' : 'Nein'}</div>
        <div class="sub">clamd / clamscan</div></div>
      <div class="card"><h2>Letzter Scan</h2><div class="val" style="font-size:1rem">${escapeHtml(s.last_scan || '—')}</div>
        <div class="sub">UTC / ISO</div></div>
      <div class="card"><h2>Treffer (letzter Lauf)</h2><div class="val" style="color:${infected ? 'var(--bad)' : 'var(--ok)'}">${infected}</div>
        <div class="sub">in Quarantäne verschoben</div></div>
      <div class="card"><h2>Scan läuft</h2><div class="val">${data.scan_running ? 'Ja…' : 'Nein'}</div>
        <div class="sub">Manuell oder Intervall</div></div>
      <div class="card"><h2>Quarantäne-Pfad</h2><div class="val" style="font-size:.95rem">/data/quarantine</div>
        <div class="sub">${(data.quarantine || []).length} Datei(en)</div></div>`;

    const ev = data.events || [];
    if (!ev.length) {
      document.getElementById('events').innerHTML = '<p class="empty">Noch keine Ereignisse.</p>';
    } else {
      let h = '<table><thead><tr><th>Zeit</th><th>Typ</th><th>Detail</th></tr></thead><tbody>';
      for (const e of ev) {
        h += `<tr><td>${escapeHtml(e.ts || '')}</td><td>${escapeHtml(e.kind || '')}</td><td>${escapeHtml(e.detail || e.raw || '')}</td></tr>`;
      }
      document.getElementById('events').innerHTML = h + '</tbody></table>';
    }

    const q = data.quarantine || [];
    document.getElementById('q-count').textContent = '(' + q.length + ')';
    document.getElementById('quarantine').innerHTML = renderTable(q, 'Quarantäne ist leer – gut.');
    document.getElementById('import').innerHTML = renderTable(data.import_files || [], 'Keine Dateien in /data/import');
    document.getElementById('log').textContent = data.log || '(leer)';

    document.getElementById('btn-scan').disabled = !!data.scan_running;
  } catch (e) {
    document.getElementById('header-badge').innerHTML =
      '<span class="badge bad">Fehler: ' + escapeHtml(e.message) + '</span>';
  }
}

document.getElementById('btn-refresh').onclick = refresh;
document.getElementById('btn-scan').onclick = async () => {
  document.getElementById('btn-scan').disabled = true;
  try {
    await api('/api/scan', { method: 'POST' });
    setTimeout(refresh, 1500);
  } catch (e) {
    alert('Scan fehlgeschlagen: ' + e.message);
    document.getElementById('btn-scan').disabled = false;
  }
};

// App-Link relativ halten
document.getElementById('link-app').href = base.replace(/\/security\/?$/, '/') || '../';

refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print(f"[security-ui] {self.address_string()} {fmt % args}")

    def _cors(self) -> None:
        self.send_header("Cache-Control", "no-store")

    def _json(self, code: int, obj: dict | list) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._cors()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._cors()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        # strip optional prefix if proxied oddly
        for prefix in ("/security",):
            if path.startswith(prefix):
                path = path[len(prefix) :] or "/"

        if path in ("/", "/index.html"):
            self._html(200, HTML)
            return
        if path == "/api/status":
            st = read_status()
            self._json(
                200,
                {
                    "status": st,
                    "scan_running": _scan_running,
                    "clamd_alive": clamd_alive(),
                    "quarantine": list_quarantine(),
                    "import_files": list_import(),
                    "events": read_events(),
                    "log": read_log(),
                    "server_time": _now(),
                },
            )
            return
        if path == "/api/log":
            self._json(200, {"log": read_log()})
            return
        if path == "/api/quarantine":
            self._json(200, {"files": list_quarantine()})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        for prefix in ("/security",):
            if path.startswith(prefix):
                path = path[len(prefix) :] or "/"
        if path == "/api/scan":
            self._json(200, trigger_scan())
            return
        self._json(404, {"error": "not found"})


def main() -> None:
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    QUAR.mkdir(parents=True, exist_ok=True)
    IMPORT.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[security-ui] listening on http://{HOST}:{PORT}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
