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

def read_events(max_n=80):
    out = []
    if not EVENTS.exists():
        return out
    try:
        for line in EVENTS.read_text(encoding="utf-8", errors="replace").splitlines()[-max_n:]:
            line = line.strip()
            if not line: continue
            try: out.append(json.loads(line))
            except Exception: out.append({"raw": line})
    except Exception: pass
    return list(reversed(out))

def append_event(kind, detail):
    try:
        EVENTS.parent.mkdir(parents=True, exist_ok=True)
        with EVENTS.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": _now(), "kind": kind, "detail": detail}, ensure_ascii=False) + "\n")
    except Exception: pass

def trigger_scan():
    global _scan_running
    with _scan_lock:
        if _scan_running: return {"ok": False, "message": "lauft"}
        _scan_running = True
    def _run():
        global _scan_running
        try: subprocess.run([SECURITY_SH, "scan"], capture_output=True, text=True, timeout=3600)
        finally:
            with _scan_lock: _scan_running = False
    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "message": "Scan gestartet"}

def trigger_update():
    global _update_running
    with _update_lock:
        if _update_running: return {"ok": False, "message": "lauft"}
        _update_running = True
    def _run():
        global _update_running
        try: subprocess.run([SECURITY_SH, "update"], capture_output=True, text=True, timeout=600)
        finally:
            with _update_lock: _update_running = False
    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "message": "Update gestartet"}

def clamd_alive():
    try: return subprocess.run(["pgrep", "-x", "clamd"], capture_output=True).returncode == 0
    except Exception: return False

def _safe_name(name):
    name = (name or "upload.bin").replace("\\", "/").split("/")[-1]
    out = "".join(ch if ch.isalnum() or ch in "._- +()[]" else "_" for ch in name).strip("._") or "upload.bin"
    return out[:180]

def handle_chunk(headers, body):
    import hashlib
    upload_id = (headers.get("X-Upload-Id") or "").strip()
    filename = _safe_name(headers.get("X-File-Name") or "upload.bin")
    try:
        idx = int(headers.get("X-Chunk-Index") or "0"); total = int(headers.get("X-Chunk-Total") or "1")
    except ValueError:
        return {"ok": False, "message": "invalid chunk"}
    if not upload_id or len(upload_id) > 80:
        upload_id = hashlib.sha1(f"{filename}-{_now()}".encode()).hexdigest()[:16]
    if idx < 0 or total < 1 or idx >= total: return {"ok": False, "message": "range"}
    if len(body) > 16 * 1024 * 1024: return {"ok": False, "message": "chunk too large"}
    UPLOAD_TMP.mkdir(parents=True, exist_ok=True); IMPORT.mkdir(parents=True, exist_ok=True)
    part = UPLOAD_TMP / f"{upload_id}.part"
    mode = "wb" if idx == 0 else "ab"
    if idx > 0 and not part.exists(): return {"ok": False, "message": "missing previous"}
    with part.open(mode) as f: f.write(body)
    if idx + 1 < total:
        return {"ok": True, "done": False, "upload_id": upload_id, "received": idx + 1, "total": total}
    dest = IMPORT / filename; n = 1
    while dest.exists():
        dest = IMPORT / f"{Path(filename).stem}_{n}{Path(filename).suffix}"; n += 1
    part.replace(dest)
    append_event("chunk_upload_done", dest.name)
    return {"ok": True, "done": True, "path": str(dest), "filename": dest.name, "size": dest.stat().st_size}

def trigger_local_import(file_path, account_id, cookie=""):
    path = Path(file_path)
    if not path.is_file():
        alt = IMPORT / Path(file_path).name
        path = alt if alt.is_file() else path
    if not path.is_file(): return {"ok": False, "message": f"Datei nicht gefunden: {file_path}"}
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

# Full UI is large - load from companion if present, else embedded compact+tabs
_UI_FILE = Path(__file__).with_name("security_ui.html")
if _UI_FILE.exists():
    HTML = _UI_FILE.read_text(encoding="utf-8")
else:
    HTML = None

if HTML is None:
    HTML = r'''<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sicherheit · MailArchiver</title>
<style>
:root{--bg:#0b1220;--panel:#121a2b;--card:#182235;--border:#2a3a55;--text:#e8eef7;--muted:#8b9bb4;--accent:#3b82f6;--ok:#22c55e;--warn:#f59e0b;--danger:#ef4444;--radius:14px}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}
.wrap{max-width:1100px;margin:0 auto;padding:1.25rem}
h1{font-size:1.45rem;margin:0 0 1rem}h2{font-size:1.05rem;margin:0 0 .75rem}
.tabs{display:flex;gap:.4rem;flex-wrap:wrap;margin-bottom:1rem}
.tab{background:var(--card);border:1px solid var(--border);color:var(--text);padding:.45rem .9rem;border-radius:999px;cursor:pointer}
.tab.active{background:var(--accent);border-color:var(--accent)}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:1rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.75rem}
.stat{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:.85rem}
.stat b{display:block;font-size:1.35rem}.stat span{color:var(--muted);font-size:.8rem}
.btn{background:var(--accent);color:#fff;border:0;border-radius:10px;padding:.55rem 1rem;cursor:pointer;margin:.2rem .2rem .2rem 0}
.btn.secondary{background:#243044}.btn.danger{background:var(--danger)}.btn.ghost{background:transparent;border:1px solid var(--border);color:var(--text)}
.row{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center}
input,select,textarea{background:#0d1524;border:1px solid var(--border);color:var(--text);border-radius:8px;padding:.45rem .6rem;width:100%;max-width:420px}
label{display:block;color:var(--muted);font-size:.8rem;margin:.35rem 0 .15rem}
.rule{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:.75rem;margin:.4rem 0}
.rule .meta{color:var(--muted);font-size:.85rem}
pre{background:#0a101c;border:1px solid var(--border);border-radius:10px;padding:.75rem;overflow:auto;max-height:320px;font-size:.78rem}
.acc-row{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:.6rem .75rem;margin:.35rem 0}
.busy{opacity:.7;pointer-events:none}
.badge{display:inline-block;padding:.15rem .45rem;border-radius:999px;font-size:.75rem;background:#243044;margin-left:.35rem}
.badge.ok{background:rgba(34,197,94,.2);color:var(--ok)}.badge.warn{background:rgba(245,158,11,.2);color:var(--warn)}
@media (max-width:640px){.wrap{padding:.75rem}.stat b{font-size:1.1rem}}
</style></head><body><div class="wrap">
<h1>Sicherheit</h1>
<div class="tabs">
<button class="tab active" data-tab="overview">Übersicht</button>
<button class="tab" data-tab="rules">Mailregeln</button>
<button class="tab" data-tab="events">Ereignisse</button>
<button class="tab" data-tab="log">Log</button>
</div>

<section id="tab-overview" class="panel">
<div class="row" style="margin-bottom:.75rem">
<button class="btn" id="btn-scan">Scan starten</button>
<button class="btn secondary" id="btn-update">Signaturen aktualisieren</button>
<span id="status-pill" class="badge">—</span>
</div>
<div class="grid" id="status-grid"></div>
<div id="scan-progress" style="margin-top:.75rem;color:var(--muted);font-size:.9rem"></div>
</section>

<section id="tab-rules" class="panel" style="display:none">
<div class="row">
<button class="btn secondary" id="rules-apply-dry">Vorschau</button>
<button class="btn danger" id="rules-apply">Jetzt löschen</button>
<button class="btn ghost" id="rules-reload">Aktualisieren</button>
<span id="rules-busy" class="badge">Bereit</span>
</div>
<div id="rules-summary" style="margin:.75rem 0"></div>
<div id="rules-list"></div>
<details style="margin-top:1rem"><summary>Neue Regel</summary>
<label>Name</label><input id="r-name" placeholder="Regelname">
<label>Absender enthält</label><input id="r-from" placeholder="newsletter@example.com">
<label>Betreff enthält (optional)</label><input id="r-subj">
<label>Min. Alter (Tage, optional)</label><input id="r-age" type="number" min="0" placeholder="30">
<label><input type="checkbox" id="r-remote" checked> Auch remote (IMAP) löschen</label>
<div class="row" style="margin-top:.5rem"><button class="btn" id="r-save">Speichern</button></div>
</details>
<pre id="rules-out">—</pre>
</section>

<section id="tab-events" class="panel" style="display:none"><div id="events-list"></div></section>
<section id="tab-log" class="panel" style="display:none"><pre id="log-out">—</pre></section>
</div>
<script>
function base(){var p=location.pathname.replace(/\/+$/,'');var i=p.lastIndexOf('/security');return i>=0?p.slice(0,i+9):'/security';}
var B=base();
function api(p,o){return fetch(B+p,o||{}).then(function(r){return r.text().then(function(t){try{return JSON.parse(t);}catch(e){return {ok:false,message:'Keine JSON ('+r.status+'): '+(t||'').slice(0,120)};}});});}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];});}
document.querySelectorAll('.tab').forEach(function(t){t.onclick=function(){document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('active');});t.classList.add('active');['overview','rules','events','log'].forEach(function(id){document.getElementById('tab-'+id).style.display=(t.dataset.tab===id)?'':'none';});if(t.dataset.tab==='rules')loadRules();if(t.dataset.tab==='events'||t.dataset.tab==='log'||t.dataset.tab==='overview')refreshStatus();};});
function setBusy(on,msg){var el=document.getElementById('rules-busy');if(el){el.textContent=msg||(on?'Läuft…':'Bereit');el.className='badge'+(on?' warn':'');}}
function renderSummary(r){
var s=r.summary||{},el=document.getElementById('rules-summary');if(!el)return;
if(r.ok===false&&r.message&&!s.rules){el.innerHTML='<div class="acc-row" style="border-color:var(--danger)"><b>Hinweis</b>: '+esc(r.message)+'</div>';document.getElementById('rules-out').textContent=JSON.stringify(r,null,2);return;}
var dry=!!(s.dry_run||r.dry_run);
var html='<div class="grid">';
html+='<div class="stat"><b>'+esc(s.local_deleted||r.deleted||0)+'</b><span>Lokal gelöscht</span></div>';
html+='<div class="stat"><b>'+esc(s.remote_candidates||0)+'</b><span>Remote Kandidaten</span></div>';
html+='<div class="stat"><b>'+esc(s.remote_deleted||0)+'</b><span>Remote gelöscht</span></div>';
html+='<div class="stat"><b>'+esc(s.local_matched||0)+'</b><span>Lokal Treffer'+(dry?' (Vorschau)':'')+'</span></div></div>';
if(s.accounts&&s.accounts.length){html+='<h2 style="margin-top:1rem">Remote-Konten</h2>';s.accounts.forEach(function(a){html+='<div class="acc-row"><b>'+esc(a.account)+'</b> · gelöscht: '+esc(a.remote_deleted||0)+' · Kandidaten: '+esc(a.candidates||a.matched||0);if(a.folders&&a.folders.length){html+='<div class="meta">'+a.folders.map(function(f){return esc(f.folder)+': '+esc(f.count);}).join(' · ')+'</div>';}if(a.scanned_folders&&a.scanned_folders.length){html+='<div class="meta">gescannt: '+a.scanned_folders.map(esc).join(', ')+'</div>';}html+='</div>';});}
if(s.rules&&s.rules.length){html+='<h2 style="margin-top:1rem">Regeln</h2>';s.rules.forEach(function(rr){html+='<div class="acc-row">'+esc(rr.name)+' · Treffer: '+esc(rr.matched||0)+' · remote: '+esc(rr.remote_matched||0)+'</div>';});}
el.innerHTML=html;document.getElementById('rules-out').textContent=JSON.stringify(r,null,2);}
function pollApply(deadline){deadline=deadline||(Date.now()+30*60*1000);return api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'apply_status'})}).then(function(r){var st=(r&&r.status)||{};var msg=st.message||(st.running?'Läuft…':'');if(st.current_rule)msg=(msg?msg+' · ':'')+st.current_rule;if(st.remote_folder)msg+=' · '+st.remote_folder;if(st.progress!=null)msg+=' ('+st.progress+'%)';setBusy(!!st.running,msg||'Bereit');if(st.summary)renderSummary({ok:true,dry_run:!!st.dry_run,summary:st.summary,deleted:(st.summary.local_deleted||0)});if(st.result)renderSummary(st.result);if(st.running&&Date.now()<deadline){return new Promise(function(res){setTimeout(function(){res(pollApply(deadline));},1500);});}setBusy(false,st.phase==='error'?(st.message||'Fehler'):(st.phase==='done'?'Fertig':'Bereit'));if(st.result)renderSummary(st.result);loadRules();return r;});}
function loadRules(){api('/api/rules').then(function(r){var list=document.getElementById('rules-list');var rules=(r&&r.rules)||[];if(!rules.length){list.innerHTML='<div class="meta">Keine Regeln</div>';return;}list.innerHTML=rules.map(function(x){var m=x.match||{};return '<div class="rule"><b>'+esc(x.name||x.id)+'</b> <span class="badge'+(x.enabled===false?'':' ok')+'">'+(x.enabled===false?'aus':'an')+'</span>'+(x.delete_remote!==false?'<span class="badge">remote</span>':'')+'<div class="meta">'+esc(m.from_value||'')+(m.min_age_days?(' · ab '+m.min_age_days+' Tagen'):'')+'</div><div class="row" style="margin-top:.4rem"><button class="btn ghost btn-edit" data-id="'+esc(x.id)+'">Bearbeiten</button><button class="btn danger btn-del" data-id="'+esc(x.id)+'">Löschen</button></div></div>';}).join('');list.querySelectorAll('.btn-del').forEach(function(b){b.onclick=function(){if(!confirm('Regel löschen?'))return;api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'delete',id:b.dataset.id})}).then(loadRules);};});list.querySelectorAll('.btn-edit').forEach(function(b){b.onclick=function(){var rule=rules.find(function(z){return z.id===b.dataset.id;});if(!rule)return;var m=rule.match||{};document.getElementById('r-name').value=rule.name||'';document.getElementById('r-from').value=m.from_value||'';document.getElementById('r-subj').value=m.subject_contains||'';document.getElementById('r-age').value=m.min_age_days||'';document.getElementById('r-remote').checked=rule.delete_remote!==false;document.getElementById('r-save').dataset.id=rule.id;};});});}
function refreshStatus(){api('/api/status').then(function(r){var st=r.status||{};var g=document.getElementById('status-grid');g.innerHTML='<div class="stat"><b>'+(r.clamd_alive?'online':'offline')+'</b><span>ClamAV</span></div><div class="stat"><b>'+esc(st.findings!=null?st.findings:(st.infected||0))+'</b><span>Fundstellen</span></div><div class="stat"><b>'+esc(st.scanned||st.scanned_files||'—')+'</b><span>Gescannt</span></div><div class="stat"><b>'+esc((st.message||'—').toString().slice(0,40))+'</b><span>Status</span></div>';document.getElementById('status-pill').textContent=r.clamd_alive?'ClamAV ok':'ClamAV?';document.getElementById('scan-progress').textContent=st.current_path?('Scan: '+st.current_path): (st.message||'');var ev=document.getElementById('events-list');ev.innerHTML=((r.events)||[]).slice(0,40).map(function(e){return '<div class="acc-row"><span class="meta">'+esc(e.ts||'')+'</span> · <b>'+esc(e.kind||'')+'</b> · '+esc(e.detail||'')+'</div>';}).join('')||'<div class="meta">Keine Ereignisse</div>';document.getElementById('log-out').textContent=r.log||'—';});}
document.getElementById('btn-scan').onclick=function(){api('/api/scan',{method:'POST'}).then(refreshStatus);};
document.getElementById('btn-update').onclick=function(){api('/api/update',{method:'POST'}).then(refreshStatus);};
document.getElementById('rules-apply-dry').onclick=function(){setBusy(true,'Vorschau läuft…');document.getElementById('rules-summary').innerHTML='';api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'apply',dry_run:true})}).then(function(r){document.getElementById('rules-out').textContent=JSON.stringify(r,null,2);if(r.started||r.apply_running)return pollApply();if(r.summary)renderSummary(r);setBusy(false,r.ok?'Vorschau fertig':(r.message||'Fehler'));}).catch(function(e){document.getElementById('rules-out').textContent=String(e);setBusy(false,'Fehler');});};
document.getElementById('rules-apply').onclick=function(){if(!confirm('Passende Mails jetzt lokal UND remote (IMAP) löschen?'))return;setBusy(true,'Löschen gestartet…');document.getElementById('rules-summary').innerHTML='';api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'apply',dry_run:false})}).then(function(r){document.getElementById('rules-out').textContent=JSON.stringify(r,null,2);if(r.started||r.apply_running)return pollApply();if(r.summary)renderSummary(r);setBusy(false,r.ok?'Fertig':(r.message||'Fehler'));loadRules();}).catch(function(e){document.getElementById('rules-out').textContent=String(e);setBusy(false,'Fehler');});};
document.getElementById('rules-reload').onclick=loadRules;
document.getElementById('r-save').onclick=function(){var id=document.getElementById('r-save').dataset.id||'';var body={action:'save',rule:{id:id||undefined,name:document.getElementById('r-name').value,from_value:document.getElementById('r-from').value,subject_contains:document.getElementById('r-subj').value,min_age_days:document.getElementById('r-age').value||null,delete_remote:document.getElementById('r-remote').checked,enabled:true}};api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(){document.getElementById('r-save').dataset.id='';loadRules();});};
refreshStatus();setInterval(refreshStatus,8000);
</script></body></html>'''

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass
    def _strip(self, path):
        if path.startswith("/security"): path = path[len("/security"):] or "/"
        return path
    def _html(self, code, body):
        data = body.encode("utf-8")
        self.send_response(code); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        try: self.wfile.write(body)
        except BrokenPipeError: pass
    def _read_json(self):
        try: length = int(self.headers.get("Content-Length") or "0")
        except ValueError: length = 0
        raw = self.rfile.read(length) if length else b"{}"
        try: return json.loads(raw.decode("utf-8") or "{}")
        except Exception: return {}
    def do_GET(self):
        path = self._strip(urlparse(self.path).path)
        if path in ("/", "/index.html", ""):
            self._html(200, HTML); return
        if path == "/api/status":
            self._json(200, {"status": read_status(), "clamd_alive": clamd_alive(), "events": read_events(), "log": read_log()}); return
        if path == "/api/rules":
            if mail_rules is None:
                self._json(500, {"ok": False, "message": "mail_rules fehlt"}); return
            try: self._json(200, mail_rules.list_rules())
            except Exception as e: self._json(500, {"ok": False, "message": str(e)})
            return
        self._json(404, {"ok": False})
    def do_POST(self):
        path = self._strip(urlparse(self.path).path)
        if path == "/api/scan":
            self._json(200, trigger_scan()); return
        if path == "/api/update":
            self._json(200, trigger_update()); return
        if path == "/api/upload-chunk":
            try: length = int(self.headers.get("Content-Length") or "0")
            except ValueError: length = 0
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
                self._json(200, mail_rules.start_apply_async(dry_run=dry)); return
            if action == "apply_status":
                st = mail_rules.read_apply_status()
                self._json(200, {"ok": True, "apply_running": bool(st.get("running")), "status": st}); return
            try: self._json(200, mail_rules.list_rules())
            except Exception as e: self._json(500, {"ok": False, "message": str(e)})
            return
        self._json(404, {"ok": False})

def main():
    if mail_rules is not None:
        try: mail_rules.start_background_loop()
        except Exception as e: print("[security-ui] rules loop:", e)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print("[security-ui] http://%s:%s/security/" % (HOST, PORT))
    httpd.serve_forever()

if __name__ == "__main__":
    main()
