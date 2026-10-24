#!/usr/bin/env python3
"""Security page (Admin) + chunk upload API."""
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
OPTIONS = Path(os.environ.get("OPTIONS_FILE", "/data/options.json"))
STATUS = DATA / "security" / "status.json"
SCAN_LOG = DATA / "security" / "last-scan.log"
EVENTS = DATA / "security" / "events.jsonl"
QUAR = DATA / "quarantine"
IMPORT = DATA / "import"
UPLOAD_TMP = DATA / "import" / ".upload_tmp"
SECURITY_SH = "/security.sh"

_scan_lock = threading.Lock()
_scan_running = False
_update_lock = threading.Lock()
_update_running = False


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_status() -> dict:
    try:
        if STATUS.exists():
            return json.loads(STATUS.read_text(encoding="utf-8"))
    except Exception as e:
        return {"message": f"status read error: {e}"}
    return {"message": "noch kein Status", "virus_scan_enabled": None}


def read_options() -> dict:
    defaults = {
        "security_virus_scan": True,
        "security_quarantine": True,
        "security_update_signatures_on_start": True,
        "security_scan_on_start": True,
        "security_scan_interval_minutes": 60,
        "security_block_dangerous_extensions": True,
        "security_dangerous_extensions": (
            "exe,dll,bat,cmd,com,scr,ps1,vbs,vbe,js,jse,wsf,wsh,"
            "msi,msp,hta,cpl,inf,reg,jar,iso,img,vhd,lnk"
        ),
    }
    try:
        path = OPTIONS if OPTIONS.exists() else Path("/tmp/options.json")
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            out = dict(defaults)
            for k in defaults:
                if k in data:
                    out[k] = data[k]
            return out
    except Exception:
        pass
    return defaults


def read_log(max_lines: int = 200) -> str:
    try:
        if not SCAN_LOG.exists():
            return "(noch kein Scan-Log)"
        lines = SCAN_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[-max_lines:])
    except Exception as e:
        return f"Log-Fehler: {e}"


def list_dir_files(root: Path, limit: int = 500) -> list:
    items = []
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


def read_events(max_n: int = 100) -> list:
    out = []
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
            return {"ok": False, "message": "Scan laeuft bereits"}
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


def trigger_update() -> dict:
    global _update_running
    with _update_lock:
        if _update_running:
            return {"ok": False, "message": "Signatur-Update laeuft bereits"}
        _update_running = True

    def _run() -> None:
        global _update_running
        try:
            append_event("freshclam_start", "Manuelles Signatur-Update")
            r = subprocess.run(
                [SECURITY_SH, "update"], capture_output=True, text=True, timeout=600
            )
            out = ((r.stdout or "") + (r.stderr or ""))[-2000:]
            append_event("freshclam_end", f"exit={r.returncode} {out[:200]}")
        except Exception as e:
            append_event("freshclam_error", str(e))
        finally:
            with _update_lock:
                _update_running = False

    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "message": "Signatur-Update gestartet"}


def clamd_alive() -> bool:
    try:
        return subprocess.run(["pgrep", "-x", "clamd"], capture_output=True).returncode == 0
    except Exception:
        return False


def _safe_name(name: str) -> str:
    name = (name or "upload.bin").replace("\\", "/").split("/")[-1]
    out = []
    for ch in name:
        if ch.isalnum() or ch in "._- +()[]":
            out.append(ch)
        else:
            out.append("_")
    s = "".join(out).strip("._") or "upload.bin"
    return s[:180]


def handle_chunk(headers, body: bytes) -> dict:
    import hashlib

    upload_id = (headers.get("X-Upload-Id") or "").strip()
    filename = _safe_name(headers.get("X-File-Name") or "upload.bin")
    try:
        idx = int(headers.get("X-Chunk-Index") or "0")
        total = int(headers.get("X-Chunk-Total") or "1")
    except ValueError:
        return {"ok": False, "message": "invalid chunk index/total"}
    if not upload_id or len(upload_id) > 80:
        upload_id = hashlib.sha1(f"{filename}-{_now()}".encode()).hexdigest()[:16]
    if idx < 0 or total < 1 or idx >= total:
        return {"ok": False, "message": f"chunk range invalid idx={idx} total={total}"}
    if len(body) > 16 * 1024 * 1024:
        return {"ok": False, "message": "chunk too large (max 16MB)"}

    UPLOAD_TMP.mkdir(parents=True, exist_ok=True)
    IMPORT.mkdir(parents=True, exist_ok=True)
    part = UPLOAD_TMP / f"{upload_id}.part"
    meta = UPLOAD_TMP / f"{upload_id}.json"

    mode = "wb" if idx == 0 else "ab"
    if idx > 0 and not part.exists():
        return {"ok": False, "message": "missing previous chunks"}
    with part.open(mode) as f:
        f.write(body)

    meta.write_text(
        json.dumps({"filename": filename, "total": total, "last_idx": idx, "ts": _now()}),
        encoding="utf-8",
    )

    if idx + 1 < total:
        return {
            "ok": True,
            "done": False,
            "upload_id": upload_id,
            "received": idx + 1,
            "total": total,
            "bytes": part.stat().st_size,
        }

    dest = IMPORT / filename
    if dest.exists():
        stem = dest.stem
        suf = dest.suffix
        n = 1
        while dest.exists():
            dest = IMPORT / f"{stem}_{n}{suf}"
            n += 1
    part.replace(dest)
    try:
        meta.unlink(missing_ok=True)
    except Exception:
        pass
    append_event("chunk_upload_done", f"{dest.name} size={dest.stat().st_size}")
    return {
        "ok": True,
        "done": True,
        "upload_id": upload_id,
        "path": str(dest),
        "filename": dest.name,
        "size": dest.stat().st_size,
        "message": f"Gespeichert unter /data/import/{dest.name}",
    }


HTML = """<!DOCTYPE html>
<html lang="de" data-bs-theme="dark"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Sicherheit – Mail Archiver</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"/>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"/>
<style>
body{background:#1a1d21;color:#e9ecef;min-height:100vh}
.navbar{background:#212529!important;border-bottom:1px solid #343a40}
.card{background:#212529;border-color:#343a40}
.card-header{background:#2b3035;border-bottom-color:#343a40;font-weight:600}
.stat-val{font-size:1.35rem;font-weight:600}
.log{max-height:320px;overflow:auto;font-size:.8rem;background:#0d1117;padding:.75rem;border-radius:.375rem;white-space:pre-wrap;word-break:break-all}
.table{--bs-table-bg:transparent;--bs-table-color:#e9ecef;--bs-table-border-color:#343a40;--bs-table-hover-bg:#2b3035}
.nav-tabs .nav-link{color:#adb5bd}.nav-tabs .nav-link.active{background:#212529;color:#fff;border-color:#343a40 #343a40 #212529}
.cfg-row{border-bottom:1px solid #343a40;padding:.65rem 0}.cfg-row:last-child{border-bottom:0}
.badge-on{background:#198754}.badge-off{background:#6c757d}.admin-hint{font-size:.85rem;color:#adb5bd}
</style></head><body>
<nav class="navbar navbar-expand-lg navbar-dark mb-3"><div class="container-fluid">
<a class="navbar-brand" href="#" id="brand-home"><i class="bi bi-envelope-fill me-1"></i>Mail Archiver</a>
<div class="collapse navbar-collapse show"><ul class="navbar-nav me-auto">
<li class="nav-item"><a class="nav-link" href="#" id="link-dash">Dashboard</a></li>
<li class="nav-item"><a class="nav-link active" href="#"><i class="bi bi-shield-check me-1"></i>Sicherheit</a></li>
</ul>
<span class="navbar-text me-3" id="header-badge"></span>
<span class="navbar-text admin-hint"><i class="bi bi-person-badge me-1"></i>Nur Admin</span>
</div></div></nav>
<div class="container-fluid px-3 px-lg-4 pb-4">
<div class="d-flex flex-wrap justify-content-between align-items-center mb-3 gap-2">
<div><h1 class="h3 mb-0"><i class="bi bi-shield-lock me-2"></i>Sicherheit</h1>
<p class="text-muted mb-0 small">ClamAV, Quarantäne, Scan (Admin)</p></div>
<div class="d-flex gap-2 flex-wrap">
<button type="button" class="btn btn-primary" id="btn-scan"><i class="bi bi-play-fill me-1"></i>Scan jetzt</button>
<button type="button" class="btn btn-outline-info" id="btn-update"><i class="bi bi-cloud-download me-1"></i>Signaturen</button>
<button type="button" class="btn btn-outline-light" id="btn-refresh"><i class="bi bi-arrow-clockwise me-1"></i>Aktualisieren</button>
</div></div>
<ul class="nav nav-tabs mb-3" role="tablist">
<li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#tab-overview" type="button">Übersicht</button></li>
<li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-config" type="button">Konfiguration</button></li>
</ul>
<div class="tab-content">
<div class="tab-pane fade show active" id="tab-overview">
<div class="row g-3 mb-3" id="cards"></div>
<div class="card mb-3"><div class="card-header">Ereignisse</div><div class="card-body p-0" id="events"></div></div>
<div class="row g-3 mb-3"><div class="col-lg-6"><div class="card h-100"><div class="card-header">Quarantäne <span id="q-count" class="text-muted"></span></div><div class="card-body p-0" id="quarantine"></div></div></div>
<div class="col-lg-6"><div class="card h-100"><div class="card-header">Import <code>/data/import</code></div><div class="card-body p-0" id="import"></div></div></div></div>
<div class="card mb-3"><div class="card-header">Scan-Log</div><div class="card-body"><pre class="log mb-0" id="log">Lade…</pre></div></div>
</div>
<div class="tab-pane fade" id="tab-config">
<div class="alert alert-secondary">Einstellungen in den <strong>Add-on-Optionen</strong>. Hier: aktueller Stand + Aktionen.</div>
<div class="card mb-3"><div class="card-header">Aktuelle Sicherheitseinstellungen</div><div class="card-body" id="config-body"><div class="text-muted">Lade…</div></div></div>
<div class="card mb-3"><div class="card-header">Laufzeit-Aktionen</div><div class="card-body">
<button type="button" class="btn btn-primary btn-sm me-2" id="btn-scan-cfg">Scan starten</button>
<button type="button" class="btn btn-outline-info btn-sm" id="btn-update-cfg">Signaturen aktualisieren</button>
<div id="action-msg" class="mt-3"></div></div></div>
</div></div></div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
(function(){
function securityBase(){var p=location.pathname.replace(/\/+$/,'');if(p.endsWith('/security'))return p;var i=p.lastIndexOf('/security');if(i>=0)return p.slice(0,i+'/security'.length);return '/security';}
var base=securityBase();var home=base.replace(/\/security\/?$/,'/')||'../';
document.getElementById('brand-home').href=home;document.getElementById('link-dash').href=home;
function api(path,opts){return fetch(base+path,opts).then(function(r){if(!r.ok)throw new Error(r.status+' '+r.statusText);var ct=r.headers.get('content-type')||'';return ct.indexOf('json')>=0?r.json():r.text();});}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return({'&':'&','<':'<','>':'>','"':'"',"'":'&#39;'})[c];});}
function fmtSize(n){if(n<1024)return n+' B';if(n<1048576)return(n/1024).toFixed(1)+' KB';return(n/1048576).toFixed(1)+' MB';}
function boolBadge(v){return v?'<span class="badge badge-on">An</span>':'<span class="badge badge-off">Aus</span>';}
function table(rows,empty){if(!rows||!rows.length)return'<div class="p-3 text-muted">'+empty+'</div>';var h='<div class="table-responsive"><table class="table table-sm table-hover mb-0"><thead><tr><th>Datei</th><th>Größe</th><th>Geändert</th></tr></thead><tbody>';rows.forEach(function(r){h+='<tr><td>'+esc(r.path)+'</td><td>'+fmtSize(r.size)+'</td><td>'+esc(r.mtime)+'</td></tr>';});return h+'</tbody></table></div>';}
function badge(enabled,clamd,infected){var el=document.getElementById('header-badge');if(enabled===false)el.innerHTML='<span class="badge text-bg-secondary">Scan aus</span>';else if(infected>0)el.innerHTML='<span class="badge text-bg-danger">Treffer</span>';else if(clamd)el.innerHTML='<span class="badge text-bg-success">Aktiv</span>';else el.innerHTML='<span class="badge text-bg-warning text-dark">clamscan</span>';}
function renderConfig(opts){var rows=[{key:'security_virus_scan',label:'Virenscan',type:'bool'},{key:'security_quarantine',label:'Quarantäne',type:'bool'},{key:'security_update_signatures_on_start',label:'Signaturen beim Start',type:'bool'},{key:'security_scan_on_start',label:'Scan beim Start',type:'bool'},{key:'security_scan_interval_minutes',label:'Scan-Intervall',type:'num'},{key:'security_block_dangerous_extensions',label:'Gefährliche Endungen',type:'bool'},{key:'security_dangerous_extensions',label:'Endungen',type:'text'}];var h='';rows.forEach(function(r){var v=opts[r.key];var val=r.type==='bool'?boolBadge(!!v):(r.type==='num'?'<code>'+esc(v)+'</code> Min.':'<code class="small">'+esc(v)+'</code>');h+='<div class="cfg-row d-flex justify-content-between"><div>'+esc(r.label)+' <code class="small">'+esc(r.key)+'</code></div><div>'+val+'</div></div>';});document.getElementById('config-body').innerHTML=h;}
function refresh(){api('/api/status').then(function(data){var s=data.status||{};var infected=s.infected_moved||0;badge(s.virus_scan_enabled,data.clamd_alive||s.clamd_running,infected);
document.getElementById('cards').innerHTML='<div class="col-6 col-md-3"><div class="card"><div class="card-body"><div class="text-muted small">Virenscan</div><div class="stat-val">'+(s.virus_scan_enabled===false?'Aus':'An')+'</div></div></div></div><div class="col-6 col-md-3"><div class="card"><div class="card-body"><div class="text-muted small">ClamAV</div><div class="stat-val">'+((data.clamd_alive||s.clamd_running)?'Daemon':'CLI')+'</div></div></div></div><div class="col-6 col-md-3"><div class="card"><div class="card-body"><div class="text-muted small">Letzter Scan</div><div class="stat-val fs-6">'+esc(s.last_scan||'—')+'</div></div></div></div><div class="col-6 col-md-3"><div class="card"><div class="card-body"><div class="text-muted small">Infiziert</div><div class="stat-val">'+infected+'</div></div></div></div>';
var ev=data.events||[];if(!ev.length)document.getElementById('events').innerHTML='<div class="p-3 text-muted">Keine Ereignisse</div>';else{var eh='<table class="table table-sm mb-0"><thead><tr><th>Zeit</th><th>Art</th><th>Detail</th></tr></thead><tbody>';ev.slice(0,40).forEach(function(e){eh+='<tr><td>'+esc(e.ts||'')+'</td><td><code>'+esc(e.kind||'')+'</code></td><td>'+esc(e.detail||e.raw||'')+'</td></tr>';});document.getElementById('events').innerHTML=eh+'</tbody></table>';}
var q=data.quarantine||[];document.getElementById('q-count').textContent=q.length?'('+q.length+')':'';document.getElementById('quarantine').innerHTML=table(q,'leer');document.getElementById('import').innerHTML=table(data.import_files||[],'Keine Dateien');document.getElementById('log').textContent=data.log||'';if(data.options)renderConfig(data.options);}).catch(function(err){document.getElementById('log').textContent='Fehler: '+err;});}
function showMsg(ok,msg){var el=document.getElementById('action-msg');if(!el)return;el.innerHTML='<div class="alert alert-'+(ok?'success':'warning')+' py-2 mb-0">'+esc(msg)+'</div>';}
function doScan(){api('/api/scan',{method:'POST'}).then(function(r){showMsg(r.ok,r.message||'OK');setTimeout(refresh,1500);}).catch(function(e){showMsg(false,String(e));});}
function doUpdate(){api('/api/update',{method:'POST'}).then(function(r){showMsg(r.ok,r.message||'OK');setTimeout(refresh,2000);}).catch(function(e){showMsg(false,String(e));});}
document.getElementById('btn-scan').onclick=doScan;document.getElementById('btn-scan-cfg').onclick=doScan;document.getElementById('btn-update').onclick=doUpdate;document.getElementById('btn-update-cfg').onclick=doUpdate;document.getElementById('btn-refresh').onclick=refresh;refresh();setInterval(refresh,10000);
})();
</script></body></html>
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
                    "options": read_options(),
                    "scan_running": _scan_running,
                    "update_running": _update_running,
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
        if path == "/api/update":
            self._json(200, trigger_update())
            return
        if path == "/api/upload-chunk":
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                length = 0
            if length > 16 * 1024 * 1024:
                self._json(413, {"ok": False, "message": "chunk too large"})
                return
            body = self.rfile.read(length) if length else b""
            hdrs = {
                k: self.headers.get(k)
                for k in ("X-Upload-Id", "X-File-Name", "X-Chunk-Index", "X-Chunk-Total")
            }
            try:
                result = handle_chunk(hdrs, body)
                code = 200 if result.get("ok") else 400
                self._json(code, result)
            except Exception as e:
                self._json(500, {"ok": False, "message": str(e)})
            return
        self._json(404, {"error": "not found"})


def main() -> None:
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    QUAR.mkdir(parents=True, exist_ok=True)
    IMPORT.mkdir(parents=True, exist_ok=True)
    UPLOAD_TMP.mkdir(parents=True, exist_ok=True)
    print(f"[security-ui] listening on http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
