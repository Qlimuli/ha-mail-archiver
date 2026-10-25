#!/usr/bin/env python3
"""Security page + chunk upload + web import + mail rules."""
from __future__ import annotations
import json, os, subprocess, threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
try:
    import mail_rules
except ImportError:
    mail_rules = None

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
_scan_lock = threading.Lock(); _scan_running = False
_update_lock = threading.Lock(); _update_running = False

def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def read_status():
    try:
        if STATUS.exists():
            return json.loads(STATUS.read_text(encoding="utf-8"))
    except Exception as e:
        return {"message": str(e)}
    return {"message": "noch kein Status"}

def read_log(max_lines=200):
    try:
        if not SCAN_LOG.exists():
            return "(kein Log)"
        return "\n".join(SCAN_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-max_lines:])
    except Exception as e:
        return str(e)

def list_dir_files(root, limit=200):
    items = []
    if not root.exists():
        return items
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        try:
            st = p.stat()
            items.append({"path": str(p.relative_to(root)), "size": st.st_size})
        except OSError:
            continue
        if len(items) >= limit:
            break
    return items

def read_events(max_n=80):
    out = []
    if not EVENTS.exists():
        return out
    try:
        for line in EVENTS.read_text(encoding="utf-8", errors="replace").splitlines()[-max_n:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                out.append({"raw": line})
    except Exception:
        pass
    return list(reversed(out))

def append_event(kind, detail):
    try:
        EVENTS.parent.mkdir(parents=True, exist_ok=True)
        with EVENTS.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": _now(), "kind": kind, "detail": detail}, ensure_ascii=False) + "\n")
    except Exception:
        pass

def trigger_scan():
    global _scan_running
    with _scan_lock:
        if _scan_running:
            return {"ok": False, "message": "läuft"}
        _scan_running = True
    def _run():
        global _scan_running
        try:
            subprocess.run([SECURITY_SH, "scan"], capture_output=True, text=True, timeout=3600)
        finally:
            with _scan_lock:
                _scan_running = False
    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "message": "Scan gestartet"}

def trigger_update():
    global _update_running
    with _update_lock:
        if _update_running:
            return {"ok": False, "message": "läuft"}
        _update_running = True
    def _run():
        global _update_running
        try:
            subprocess.run([SECURITY_SH, "update"], capture_output=True, text=True, timeout=600)
        finally:
            with _update_lock:
                _update_running = False
    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "message": "Update gestartet"}

def clamd_alive():
    try:
        return subprocess.run(["pgrep", "-x", "clamd"], capture_output=True).returncode == 0
    except Exception:
        return False

def _safe_name(name):
    name = (name or "upload.bin").replace("\\", "/").split("/")[-1]
    out = "".join(ch if ch.isalnum() or ch in "._- +()[]" else "_" for ch in name).strip("._") or "upload.bin"
    return out[:180]

def handle_chunk(headers, body):
    import hashlib
    upload_id = (headers.get("X-Upload-Id") or "").strip()
    filename = _safe_name(headers.get("X-File-Name") or "upload.bin")
    try:
        idx = int(headers.get("X-Chunk-Index") or "0")
        total = int(headers.get("X-Chunk-Total") or "1")
    except ValueError:
        return {"ok": False, "message": "invalid chunk"}
    if not upload_id or len(upload_id) > 80:
        upload_id = hashlib.sha1(f"{filename}-{_now()}".encode()).hexdigest()[:16]
    if idx < 0 or total < 1 or idx >= total:
        return {"ok": False, "message": "range"}
    if len(body) > 16 * 1024 * 1024:
        return {"ok": False, "message": "chunk too large"}
    UPLOAD_TMP.mkdir(parents=True, exist_ok=True)
    IMPORT.mkdir(parents=True, exist_ok=True)
    part = UPLOAD_TMP / f"{upload_id}.part"
    mode = "wb" if idx == 0 else "ab"
    if idx > 0 and not part.exists():
        return {"ok": False, "message": "missing previous"}
    with part.open(mode) as f:
        f.write(body)
    if idx + 1 < total:
        return {"ok": True, "done": False, "upload_id": upload_id, "received": idx + 1, "total": total}
    dest = IMPORT / filename
    n = 1
    while dest.exists():
        dest = IMPORT / f"{Path(filename).stem}_{n}{Path(filename).suffix}"
        n += 1
    part.replace(dest)
    append_event("chunk_upload_done", dest.name)
    return {"ok": True, "done": True, "path": str(dest), "filename": dest.name, "size": dest.stat().st_size}

def trigger_local_import(file_path, account_id, cookie=""):
    path = Path(file_path)
    if not path.is_file():
        alt = IMPORT / Path(file_path).name
        path = alt if alt.is_file() else path
    if not path.is_file():
        return {"ok": False, "message": f"Datei nicht gefunden: {file_path}"}
    if cookie:
        try:
            import re, urllib.request, urllib.error, uuid
            base = os.environ.get("MAIL_ARCHIVER_INTERNAL", "http://127.0.0.1:5001").rstrip("/")
            import_url = base + "/MailAccounts/ImportEml"
            req = urllib.request.Request(import_url, headers={"Cookie": cookie, "User-Agent": "ha-mail-archiver/1.3.15"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                html = resp.read().decode("utf-8", errors="replace")
            m = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', html) or re.search(r'value="([^"]+)"[^>]*name="__RequestVerificationToken"', html)
            if m:
                token = m.group(1)
                boundary = "----Ha" + uuid.uuid4().hex
                file_bytes = path.read_bytes()
                def part(name, value):
                    return (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").encode()
                body = b"".join([
                    part("__RequestVerificationToken", token),
                    part("TargetAccountId", str(account_id)),
                    (f"--{boundary}\r\nContent-Disposition: form-data; name=\"EmlFile\"; filename=\"{path.name}\"\r\nContent-Type: application/zip\r\n\r\n").encode(),
                    file_bytes,
                    f"\r\n--{boundary}--\r\n".encode(),
                ])
                class _NoRedir(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        raise urllib.error.HTTPError(newurl, code, msg, headers, fp)
                req2 = urllib.request.Request(import_url, data=body, method="POST", headers={
                    "Cookie": cookie, "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Content-Length": str(len(body)), "User-Agent": "ha-mail-archiver/1.3.15",
                })
                try:
                    urllib.request.build_opener(_NoRedir).open(req2, timeout=600)
                except urllib.error.HTTPError as he:
                    loc = he.headers.get("Location") or ""
                    if he.code in (301, 302, 303, 307, 308) or "jobId" in loc or "EmlImportStatus" in loc:
                        try:
                            path.unlink(missing_ok=True)
                        except Exception:
                            pass
                        return {"ok": True, "mode": "web", "message": f"Import-Job gestartet fuer {path.name}", "redirect": loc or "/Emails/Jobs", "jobs_visible": True}
        except Exception as e:
            append_event("local_import_web_err", str(e))
    cmd = ["dotnet", "MailArchiver.dll", "--import-eml", "--file", str(path), "--account-id", str(account_id)]
    cwd = "/app" if Path("/app/MailArchiver.dll").exists() else str(Path.cwd())
    try:
        log_path = DATA / "security" / "import-cli.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        logf = open(log_path, "a", encoding="utf-8")
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=logf, stderr=subprocess.STDOUT, env=os.environ.copy())
        return {"ok": True, "mode": "cli", "message": f"CLI-Import PID {proc.pid}", "pid": proc.pid, "jobs_visible": False}
    except Exception as e:
        return {"ok": False, "message": str(e)}

HTML = """<!DOCTYPE html>
<html lang="de" data-bs-theme="dark"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Sicherheit</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"/>
<style>body{background:#1a1d21;color:#e9ecef}.card{background:#212529;border-color:#343a40}
.log{max-height:200px;overflow:auto;font-size:.8rem;background:#0d1117;padding:.75rem;white-space:pre-wrap}</style>
</head><body>
<nav class="navbar navbar-dark bg-dark mb-3 px-3">
<a class="navbar-brand" id="home" href="#">Mail Archiver</a>
<span class="navbar-text">Sicherheit & Regeln</span></nav>
<div class="container-fluid px-3 pb-4">
<div class="d-flex gap-2 mb-3 flex-wrap">
<button class="btn btn-primary btn-sm" id="scan">Scan</button>
<button class="btn btn-outline-info btn-sm" id="upd">Signaturen</button>
<button class="btn btn-outline-light btn-sm" id="ref">Refresh</button>
</div>
<div class="row g-3 mb-3" id="cards"></div>
<div class="card mb-3" id="rules-card"><div class="card-header">Mailregeln (Absender → Auto-Löschen)</div>
<div class="card-body">
<div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" id="rules-enabled"><label class="form-check-label" for="rules-enabled">Regeln aktiv (Hintergrund)</label></div>
<div class="row g-2 mb-2">
<div class="col-auto"><input type="number" class="form-control form-control-sm" id="rules-interval" value="30" style="width:5rem" title="Minuten"></div>
<div class="col-auto"><button class="btn btn-sm btn-outline-light" id="rules-save-set">Einstellungen</button></div>
<div class="col-auto"><button class="btn btn-sm btn-outline-info" id="rules-apply-dry">Vorschau</button></div>
<div class="col-auto"><button class="btn btn-sm btn-danger" id="rules-apply">Jetzt löschen</button></div>
</div>
<div class="row g-2 mb-2">
<div class="col-md-2"><input class="form-control form-control-sm" id="r-name" placeholder="Name"></div>
<div class="col-md-2"><select class="form-select form-select-sm" id="r-mode"><option value="contains">enthält</option><option value="exact">exakt</option><option value="domain">Domain</option></select></div>
<div class="col-md-3"><input class="form-control form-control-sm" id="r-from" placeholder="Absender / Domain"></div>
<div class="col-md-2"><input class="form-control form-control-sm" id="r-subj" placeholder="Betreff (opt.)"></div>
<div class="col-md-1"><input type="number" min="0" class="form-control form-control-sm" id="r-age" placeholder="Tage" title="Nur Mails älter als X Tage (0 = alle)"></div>
<div class="col-md-2"><button class="btn btn-sm btn-primary w-100" id="r-add">Regel speichern</button></div>
</div>
<div class="form-check mb-2">
<input class="form-check-input" type="checkbox" id="r-remote">
<label class="form-check-label" for="r-remote">Auch im Remote-Postfach löschen (IMAP, z.&nbsp;B. GMX/Gmail)</label>
</div>
<div class="small text-muted mb-2">Remote-Löschen nutzt die Kontodaten aus dem Archiv (IMAP). Verschlüsselte Passwörter (enc:…) werden übersprungen.</div>
<div id="rules-list" class="small"></div>
<pre class="log mb-0 mt-2" id="rules-out"></pre>
</div></div>
<div class="card mb-3"><div class="card-header">Ereignisse</div><div class="card-body p-0" id="ev"></div></div>
<div class="card"><div class="card-header">Log</div><div class="card-body"><pre class="log mb-0" id="log"></pre></div></div>
</div>
<script>
(function(){
function base(){var p=location.pathname.replace(/\/+$/,'');var i=p.lastIndexOf('/security');return i>=0?p.slice(0,i+'/security'.length):'/security';}
var B=base(); document.getElementById('home').href=B.replace(/\/security\/?$/,'/')||'../';
function api(p,o){return fetch(B+p,o).then(function(r){return r.json();});}
function esc(s){return String(s||'').replace(/[&<>]/g,function(c){return({'&':'&','<':'<','>':'>'})[c];});}
function refresh(){api('/api/status').then(function(d){
var s=d.status||{};
document.getElementById('cards').innerHTML='<div class="col-md-3"><div class="card"><div class="card-body"><div class="text-muted small">Scan</div><div class="fs-5">'+(s.virus_scan_enabled===false?'Aus':'An')+'</div></div></div></div><div class="col-md-3"><div class="card"><div class="card-body"><div class="text-muted small">ClamAV</div><div class="fs-5">'+(d.clamd_alive?'Daemon':'CLI')+'</div></div></div></div>';
var ev=d.events||[];
document.getElementById('ev').innerHTML=ev.length?'<ul class="list-group list-group-flush">'+ev.slice(0,15).map(function(e){return '<li class="list-group-item bg-transparent text-light small">'+esc(e.ts)+' <code>'+esc(e.kind)+'</code> '+esc(e.detail||'')+'</li>';}).join('')+'</ul>':'<div class="p-3 text-muted">keine</div>';
document.getElementById('log').textContent=d.log||'';}).catch(function(e){document.getElementById('log').textContent=String(e);});}
function loadRules(){api('/api/rules').then(function(d){
document.getElementById('rules-enabled').checked=!!d.enabled;
document.getElementById('rules-interval').value=d.interval_minutes||30;
var rules=d.rules||[], el=document.getElementById('rules-list');
if(!rules.length){el.innerHTML='<div class="text-muted">Keine Regeln – Absender eintragen und speichern.</div>';return;}
el.innerHTML='<ul class="list-group list-group-flush">'+rules.map(function(r){var m=r.match||{};var age=m.min_age_days?(' ≥'+m.min_age_days+'d'):'';var rem=r.delete_remote?' <span class="badge bg-warning text-dark">Remote</span>':'';return '<li class="list-group-item bg-transparent text-light d-flex justify-content-between gap-2"><div><b>'+esc(r.name)+'</b> '+esc(m.from_mode)+': <code>'+esc(m.from_value)+'</code>'+age+rem+(m.subject_contains?(' / '+esc(m.subject_contains)):'')+'</div><button class="btn btn-sm btn-outline-danger" data-del="'+esc(r.id)+'">×</button></li>';}).join('')+'</ul>';
el.querySelectorAll('[data-del]').forEach(function(b){b.onclick=function(){api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'delete',id:b.getAttribute('data-del')})}).then(loadRules);};});
}).catch(function(e){document.getElementById('rules-out').textContent=String(e);});}
document.getElementById('scan').onclick=function(){api('/api/scan',{method:'POST'}).then(function(){setTimeout(refresh,1000);});};
document.getElementById('upd').onclick=function(){api('/api/update',{method:'POST'}).then(function(){setTimeout(refresh,1500);});};
document.getElementById('ref').onclick=function(){refresh();loadRules();};
document.getElementById('rules-save-set').onclick=function(){api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'settings',enabled:document.getElementById('rules-enabled').checked,interval_minutes:parseInt(document.getElementById('rules-interval').value||'30',10)})}).then(loadRules);};
document.getElementById('r-add').onclick=function(){api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'save',rule:{name:document.getElementById('r-name').value,enabled:true,delete_remote:!!document.getElementById('r-remote').checked,match:{from_mode:document.getElementById('r-mode').value,from_value:document.getElementById('r-from').value,subject_contains:document.getElementById('r-subj').value,min_age_days:parseInt(document.getElementById('r-age').value||'0',10)||null}}})}).then(function(r){document.getElementById('rules-out').textContent=JSON.stringify(r);document.getElementById('r-from').value='';loadRules();});};
document.getElementById('rules-apply-dry').onclick=function(){api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'apply',dry_run:true})}).then(function(r){document.getElementById('rules-out').textContent=JSON.stringify(r,null,2);});};
document.getElementById('rules-apply').onclick=function(){if(!confirm('Passende Mails im Archiv jetzt löschen? (Remote-Löschen nur wenn in der Regel aktiviert)'))return;api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'apply',dry_run:false})}).then(function(r){document.getElementById('rules-out').textContent=JSON.stringify(r,null,2);loadRules();});};
refresh();loadRules();setInterval(refresh,15000);
})();
</script></body></html>
"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[security-ui] {self.address_string()} {fmt % args}")
    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def _html(self, code, html):
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def _strip(self, path):
        path = path.rstrip("/") or "/"
        if path.startswith("/security"):
            path = path[len("/security"):] or "/"
        return path
    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return {}
    def do_GET(self):
        path = self._strip(urlparse(self.path).path)
        if path in ("/", "/index.html", ""):
            self._html(200, HTML); return
        if path == "/api/status":
            self._json(200, {"status": read_status(), "clamd_alive": clamd_alive(), "events": read_events(), "log": read_log(),
                             "quarantine": list_dir_files(QUAR, 50), "import": list_dir_files(IMPORT, 50)}); return
        if path == "/api/rules":
            if mail_rules is None:
                self._json(500, {"ok": False, "message": "mail_rules fehlt"}); return
            self._json(200, mail_rules.list_rules()); return
        self._json(404, {"ok": False, "message": "not found"})
    def do_POST(self):
        path = self._strip(urlparse(self.path).path)
        if path == "/api/scan":
            self._json(200, trigger_scan()); return
        if path == "/api/update":
            self._json(200, trigger_update()); return
        if path == "/api/upload-chunk":
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                length = 0
            body = self.rfile.read(length) if length else b""
            self._json(200, handle_chunk(self.headers, body)); return
        if path == "/api/rules":
            if mail_rules is None:
                self._json(500, {"ok": False, "message": "mail_rules fehlt"}); return
            data = self._read_json()
            action = (data.get("action") or "").lower()
            if action == "save":
                self._json(200, mail_rules.upsert_rule(data.get("rule") or data)); return
            if action == "delete":
                self._json(200, mail_rules.delete_rule(str(data.get("id") or ""))); return
            if action == "settings":
                self._json(200, mail_rules.set_settings(data)); return
            if action == "preview":
                self._json(200, mail_rules.preview_rule(data.get("rule") or data)); return
            if action == "apply":
                dry = bool(data.get("dry_run"))
                if data.get("id"):
                    store = mail_rules.load_store()
                    rule = next((r for r in store.get("rules") or [] if r.get("id") == data.get("id")), None)
                    if not rule:
                        self._json(404, {"ok": False, "message": "Regel nicht gefunden"}); return
                    self._json(200, mail_rules.apply_rule(rule, dry_run=dry)); return
                self._json(200, mail_rules.apply_all_rules(dry_run=dry)); return
            self._json(200, mail_rules.list_rules()); return
        if path == "/api/assemble-and-import":
            data = self._read_json()
            cookie = self.headers.get("Cookie") or ""
            self._json(200, trigger_local_import(data.get("path") or data.get("file") or "", data.get("accountId") or data.get("account_id") or 0, cookie)); return
        self._json(404, {"ok": False, "message": "not found"})

def main():
    if mail_rules is not None:
        try:
            mail_rules.start_background_loop()
        except Exception as e:
            print("[security-ui] rules loop:", e)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[security-ui] http://{HOST}:{PORT}/security/")
    httpd.serve_forever()

if __name__ == "__main__":
    main()
