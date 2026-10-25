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
            return {"ok": False, "message": "lauft"}
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
            return {"ok": False, "message": "lauft"}
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
    cmd = ["dotnet", "MailArchiver.dll", "--import-eml", "--file", str(path), "--account-id", str(account_id)]
    cwd = "/app" if Path("/app/MailArchiver.dll").exists() else str(Path.cwd())
    try:
        log_path = DATA / "security" / "import-cli.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        logf = open(log_path, "a", encoding="utf-8")
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=logf, stderr=subprocess.STDOUT, env=os.environ.copy())
        return {"ok": True, "mode": "cli", "message": f"CLI-Import PID {proc.pid}", "pid": proc.pid}
    except Exception as e:
        return {"ok": False, "message": str(e)}

HTML = r"""<!DOCTYPE html>
<html lang="de"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Sicherheit</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"/>
<style>
:root{--bg:#0f1419;--panel:#1a2332;--panel2:#243044;--border:#2d3a4f;--text:#e8eef7;--muted:#8b9bb4;--accent:#3b82f6;--ok:#22c55e;--warn:#f59e0b;--danger:#ef4444}
*{box-sizing:border-box}body{background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;margin:0;min-height:100vh}
.topbar{background:linear-gradient(135deg,#1e293b,#0f172a);border-bottom:1px solid var(--border);padding:.85rem 1.25rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}
.brand{font-weight:700;color:#fff;text-decoration:none;display:flex;align-items:center;gap:.5rem}.brand i{color:var(--accent)}
.tabs{display:flex;gap:.35rem;flex-wrap:wrap}.tabs button{background:transparent;border:0;color:var(--muted);padding:.4rem .85rem;border-radius:999px;font-size:.875rem;cursor:pointer}
.tabs button.active{background:var(--accent);color:#fff}
.wrap{max-width:1100px;margin:0 auto;padding:1.25rem}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:1.15rem 1.25rem;margin-bottom:1rem}
.panel h2{font-size:.95rem;margin:0 0 1rem;color:#fff;display:flex;align-items:center;gap:.45rem}.panel h2 i{color:var(--accent)}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem;margin-bottom:1rem}
.stat{background:var(--panel2);border:1px solid var(--border);border-radius:12px;padding:.9rem 1rem}
.stat .lbl{font-size:.72rem;text-transform:uppercase;color:var(--muted)}.stat .val{font-size:1.25rem;font-weight:700}
.stat .val.ok{color:var(--ok)}.stat .val.warn{color:var(--warn)}.stat .val.danger{color:var(--danger)}.stat .val.muted{color:var(--muted)}
.scan-box{background:var(--panel2);border:1px solid var(--border);border-radius:12px;padding:1rem;margin-bottom:.75rem}
.path{font-family:ui-monospace,monospace;font-size:.82rem;color:#a5b4fc;word-break:break-all;min-height:1.2em}
.progress{height:10px;background:#0b1220;border-radius:999px;overflow:hidden;margin:.6rem 0}.progress>div{height:100%;background:linear-gradient(90deg,var(--accent),#60a5fa);transition:width .3s}
.btn-row{display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem}
.btnx{border:none;border-radius:10px;padding:.5rem 1rem;font-size:.875rem;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:.4rem}
.btnx-primary{background:var(--accent);color:#fff}.btnx-ghost{background:transparent;color:var(--text);border:1px solid var(--border)}.btnx-danger{background:var(--danger);color:#fff}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.55rem;margin-bottom:.75rem}
.form-grid input,.form-grid select{background:#0b1220;border:1px solid var(--border);color:var(--text);border-radius:8px;padding:.45rem .6rem;font-size:.875rem;width:100%}
.form-check{display:flex;align-items:center;gap:.45rem;margin:.4rem 0;font-size:.875rem;color:var(--muted)}
.rule-list{display:flex;flex-direction:column;gap:.5rem}
.rule-item{background:var(--panel2);border:1px solid var(--border);border-radius:10px;padding:.75rem 1rem;display:flex;justify-content:space-between;gap:.75rem}
.rule-item code{background:#0b1220;padding:.1rem .35rem;border-radius:4px;font-size:.8rem}
.badge{display:inline-block;font-size:.68rem;padding:.15rem .4rem;border-radius:6px;font-weight:600}
.badge-remote{background:#f59e0b33;color:var(--warn)}.badge-age{background:#3b82f633;color:#93c5fd}
.rule-actions{display:flex;gap:.35rem}.rule-actions button{background:#0b1220;border:1px solid var(--border);color:var(--text);border-radius:8px;padding:.3rem .55rem;cursor:pointer}
.rule-actions button.del:hover{border-color:var(--danger);color:var(--danger)}
.event-list,.log-box{max-height:280px;overflow:auto;font-size:.8rem}
.event-list .ev{padding:.45rem 0;border-bottom:1px solid var(--border);display:grid;grid-template-columns:140px 110px 1fr;gap:.5rem}
.event-list .ts{color:var(--muted)}.event-list .kind{color:#93c5fd;font-family:ui-monospace,monospace}
.log-box{background:#0b1220;border:1px solid var(--border);border-radius:10px;padding:.75rem;white-space:pre-wrap;font-family:ui-monospace,monospace;color:#cbd5e1}
.hidden{display:none!important}
.edit-banner{background:#1e3a5f;border:1px solid #3b82f6;border-radius:8px;padding:.5rem .75rem;margin-bottom:.75rem;font-size:.85rem;display:none;justify-content:space-between;align-items:center}
.edit-banner.show{display:flex}.empty{color:var(--muted);font-size:.875rem}.footer-note{color:var(--muted);font-size:.75rem;margin-top:.5rem}
@media(max-width:640px){.event-list .ev{grid-template-columns:1fr}}
</style></head><body>
<header class="topbar">
<a class="brand" id="home" href="#"><i class="bi bi-shield-lock-fill"></i> Sicherheit</a>
<nav class="tabs" id="tabs">
<button type="button" data-tab="overview" class="active"><i class="bi bi-speedometer2"></i> Uebersicht</button>
<button type="button" data-tab="rules"><i class="bi bi-funnel"></i> Mailregeln</button>
<button type="button" data-tab="events"><i class="bi bi-activity"></i> Ereignisse</button>
<button type="button" data-tab="log"><i class="bi bi-terminal"></i> Log</button>
</nav></header>
<div class="wrap">
<section id="tab-overview">
<div class="stat-grid" id="stats"></div>
<div class="panel"><h2><i class="bi bi-radar"></i> Virenscan</h2>
<div class="btn-row">
<button class="btnx btnx-primary" id="btn-scan"><i class="bi bi-play-fill"></i> Scan starten</button>
<button class="btnx btnx-ghost" id="btn-upd"><i class="bi bi-cloud-download"></i> Signaturen</button>
<button class="btnx btnx-ghost" id="btn-ref"><i class="bi bi-arrow-clockwise"></i> Aktualisieren</button>
</div>
<div class="scan-box">
<div style="font-size:.72rem;color:var(--muted);text-transform:uppercase">Status</div>
<div id="scan-msg" style="font-weight:600">—</div>
<div class="progress"><div id="scan-bar" style="width:0%"></div></div>
<div class="path" id="scan-path"></div>
<div id="scan-meta" class="footer-note"></div>
</div>
<div class="footer-note">Quarantäne: <code id="quar-path">/data/quarantine</code></div>
</div></section>
<section id="tab-rules" class="hidden">
<div class="panel"><h2><i class="bi bi-sliders"></i> Einstellungen</h2>
<div class="form-check"><input type="checkbox" id="rules-enabled"> <label for="rules-enabled">Regeln im Hintergrund aktiv</label></div>
<div class="form-grid" style="grid-template-columns:120px auto auto auto;max-width:560px">
<input type="number" id="rules-interval" value="30" placeholder="Min"/>
<button class="btnx btnx-ghost" id="rules-save-set">Einstellungen</button>
<button class="btnx btnx-ghost" id="rules-apply-dry">Vorschau</button>
<button class="btnx btnx-danger" id="rules-apply">Jetzt loeschen</button>
</div></div>
<div class="panel"><h2><i class="bi bi-plus-circle"></i> <span id="form-title">Neue Regel</span></h2>
<div class="edit-banner" id="edit-banner"><span>Regel wird bearbeitet</span><button type="button" class="btnx btnx-ghost" id="edit-cancel">Abbrechen</button></div>
<input type="hidden" id="r-id" value=""/>
<div class="form-grid">
<input id="r-name" placeholder="Name"/><select id="r-mode"><option value="contains">enthaelt</option><option value="exact">exakt</option><option value="domain">Domain</option></select>
<input id="r-from" placeholder="Absender / Domain"/><input id="r-subj" placeholder="Betreff (optional)"/>
<input type="number" min="0" id="r-age" placeholder="Min. Alter (Tage)"/>
</div>
<div class="form-check"><input type="checkbox" id="r-remote"> <label for="r-remote">Auch im Remote-Postfach loeschen (IMAP)</label></div>
<button class="btnx btnx-primary" id="r-save"><i class="bi bi-check-lg"></i> Speichern</button>
</div>
<div class="panel"><h2><i class="bi bi-list-ul"></i> Gespeicherte Regeln</h2><div class="rule-list" id="rules-list"></div></div>
<div class="panel"><h2><i class="bi bi-braces"></i> Ergebnis</h2><pre class="log-box" id="rules-out">—</pre></div>
</section>
<section id="tab-events" class="hidden"><div class="panel"><h2><i class="bi bi-activity"></i> Ereignisse</h2><div class="event-list" id="ev"></div></div></section>
<section id="tab-log" class="hidden"><div class="panel"><h2><i class="bi bi-terminal"></i> Scan-Log</h2><pre class="log-box" id="log">—</pre></div></section>
</div>
<script>
(function(){
function base(){var p=location.pathname.replace(/\/+$/,'');var i=p.lastIndexOf('/security');return i>=0?p.slice(0,i+9):'/security';}
var B=base();document.getElementById('home').href=B.replace(/\/security\/?$/,'/')||'../';
function api(p,o){return fetch(B+p,o||{}).then(function(r){return r.json();});}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return({'&':'&','<':'<','>':'>','"':'"',"'":'&#39;'})[c];});}
function showTab(name){['overview','rules','events','log'].forEach(function(t){document.getElementById('tab-'+t).classList.toggle('hidden',t!==name);});document.querySelectorAll('#tabs button').forEach(function(b){b.classList.toggle('active',b.getAttribute('data-tab')===name);});}
document.querySelectorAll('#tabs button').forEach(function(b){b.onclick=function(){showTab(b.getAttribute('data-tab'));};});
function renderStats(d){var s=d.status||{},scanning=!!s.scanning,infected=parseInt(s.infected_moved||0,10)||0,clamd=!!d.clamd_alive||!!s.clamd_running;
var cards=[{lbl:'Virenscan',val:s.virus_scan_enabled===false?'Aus':'An',cls:s.virus_scan_enabled===false?'muted':'ok'},{lbl:'ClamAV',val:clamd?'Daemon aktiv':'CLI / aus',cls:clamd?'ok':'warn'},{lbl:'Scan-Status',val:scanning?'Laeuft…':'Bereit',cls:scanning?'warn':'ok'},{lbl:'Letzte Treffer',val:String(infected),cls:infected>0?'danger':'ok'}];
document.getElementById('stats').innerHTML=cards.map(function(c){return '<div class="stat"><div class="lbl">'+esc(c.lbl)+'</div><div class="val '+c.cls+'">'+esc(c.val)+'</div></div>';}).join('');
document.getElementById('scan-msg').textContent=s.message||(scanning?'Scan laeuft…':'Kein aktiver Scan');
var scanned=parseInt(s.scanned_paths||0,10)||0,total=parseInt(s.total_paths||0,10)||0,pct=total>0?Math.min(100,Math.round(scanned/total*100)):(scanning?15:0);if(!scanning&&total>0)pct=100;
document.getElementById('scan-bar').style.width=pct+'%';document.getElementById('scan-path').textContent=s.current_path||'';
var meta=[];if(total)meta.push(scanned+' / '+total+' Ziele');if(s.last_scan)meta.push('Zuletzt: '+s.last_scan);if(infected)meta.push(infected+' in Quarantäne');
document.getElementById('scan-meta').textContent=meta.join(' · ');if(s.quarantine_dir)document.getElementById('quar-path').textContent=s.quarantine_dir;}
function renderEvents(ev){ev=ev||[];var el=document.getElementById('ev');if(!ev.length){el.innerHTML='<div class="empty">Keine Ereignisse</div>';return;}el.innerHTML=ev.slice(0,40).map(function(e){return '<div class="ev"><span class="ts">'+esc(e.ts)+'</span><span class="kind">'+esc(e.kind)+'</span><span>'+esc(e.detail||'')+'</span></div>';}).join('');}
function clearForm(){document.getElementById('r-id').value='';document.getElementById('r-name').value='';document.getElementById('r-mode').value='contains';document.getElementById('r-from').value='';document.getElementById('r-subj').value='';document.getElementById('r-age').value='';document.getElementById('r-remote').checked=false;document.getElementById('form-title').textContent='Neue Regel';document.getElementById('edit-banner').classList.remove('show');}
function fillForm(r){var m=r.match||{};document.getElementById('r-id').value=r.id||'';document.getElementById('r-name').value=r.name||'';document.getElementById('r-mode').value=m.from_mode||'contains';document.getElementById('r-from').value=m.from_value||'';document.getElementById('r-subj').value=m.subject_contains||'';document.getElementById('r-age').value=m.min_age_days||'';document.getElementById('r-remote').checked=!!r.delete_remote;document.getElementById('form-title').textContent='Regel bearbeiten';document.getElementById('edit-banner').classList.add('show');showTab('rules');}
function loadRules(){api('/api/rules').then(function(d){document.getElementById('rules-enabled').checked=!!d.enabled;document.getElementById('rules-interval').value=d.interval_minutes||30;var rules=d.rules||[],el=document.getElementById('rules-list');
if(!rules.length){el.innerHTML='<div class="empty">Keine Regeln</div>';return;}
el.innerHTML=rules.map(function(r){var m=r.match||{},badges='';if(m.min_age_days)badges+='<span class="badge badge-age">≥'+esc(m.min_age_days)+'d</span> ';if(r.delete_remote)badges+='<span class="badge badge-remote">Remote</span> ';
return '<div class="rule-item"><div><b>'+esc(r.name)+'</b> '+badges+'<div style="margin-top:.25rem">'+esc(m.from_mode)+': <code>'+esc(m.from_value)+'</code>'+(m.subject_contains?' · '+esc(m.subject_contains):'')+'</div></div><div class="rule-actions"><button type="button" data-edit="'+esc(r.id)+'"><i class="bi bi-pencil"></i></button><button type="button" class="del" data-del="'+esc(r.id)+'"><i class="bi bi-trash"></i></button></div></div>';}).join('');
el.querySelectorAll('[data-edit]').forEach(function(b){b.onclick=function(){var rule=rules.find(function(x){return x.id===b.getAttribute('data-edit');});if(rule)fillForm(rule);};});
el.querySelectorAll('[data-del]').forEach(function(b){b.onclick=function(){if(!confirm('Regel loeschen?'))return;api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'delete',id:b.getAttribute('data-del')})}).then(function(){clearForm();loadRules();});};});
}).catch(function(e){document.getElementById('rules-out').textContent=String(e);});}
function refresh(){api('/api/status').then(function(d){renderStats(d);renderEvents(d.events||[]);document.getElementById('log').textContent=d.log||'(kein Log)';}).catch(function(e){document.getElementById('log').textContent=String(e);});}
document.getElementById('btn-scan').onclick=function(){api('/api/scan',{method:'POST'}).then(function(){setTimeout(refresh,800);});};
document.getElementById('btn-upd').onclick=function(){api('/api/update',{method:'POST'}).then(function(){setTimeout(refresh,1200);});};
document.getElementById('btn-ref').onclick=function(){refresh();loadRules();};
document.getElementById('edit-cancel').onclick=clearForm;
document.getElementById('rules-save-set').onclick=function(){api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'settings',enabled:document.getElementById('rules-enabled').checked,interval_minutes:parseInt(document.getElementById('rules-interval').value||'30',10)})}).then(loadRules);};
document.getElementById('r-save').onclick=function(){api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'save',rule:{id:document.getElementById('r-id').value||undefined,name:document.getElementById('r-name').value,enabled:true,delete_remote:!!document.getElementById('r-remote').checked,match:{from_mode:document.getElementById('r-mode').value,from_value:document.getElementById('r-from').value,subject_contains:document.getElementById('r-subj').value,min_age_days:parseInt(document.getElementById('r-age').value||'0',10)||null}}})}).then(function(r){document.getElementById('rules-out').textContent=JSON.stringify(r,null,2);clearForm();loadRules();});};
document.getElementById('rules-apply-dry').onclick=function(){api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'apply',dry_run:true})}).then(function(r){document.getElementById('rules-out').textContent=JSON.stringify(r,null,2);});};
document.getElementById('rules-apply').onclick=function(){if(!confirm('Passende Mails jetzt loeschen?'))return;api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'apply',dry_run:false})}).then(function(r){document.getElementById('rules-out').textContent=JSON.stringify(r,null,2);loadRules();});};
refresh();loadRules();setInterval(refresh,4000);
})();
</script></body></html>
"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[security-ui] " + (fmt % args))
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
            self._json(200, {"status": read_status(), "clamd_alive": clamd_alive(), "events": read_events(), "log": read_log()}); return
        if path == "/api/rules":
            if mail_rules is None:
                self._json(500, {"ok": False, "message": "mail_rules fehlt"}); return
            self._json(200, mail_rules.list_rules()); return
        self._json(404, {"ok": False})
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
                        self._json(404, {"ok": False, "message": "nicht gefunden"}); return
                    self._json(200, mail_rules.apply_rule(rule, dry_run=dry)); return
                self._json(200, mail_rules.apply_all_rules(dry_run=dry)); return
            self._json(200, mail_rules.list_rules()); return
        self._json(404, {"ok": False})

def main():
    if mail_rules is not None:
        try:
            mail_rules.start_background_loop()
        except Exception as e:
            print("[security-ui] rules loop:", e)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print("[security-ui] http://%s:%s/security/" % (HOST, PORT))
    httpd.serve_forever()

if __name__ == "__main__":
    main()
