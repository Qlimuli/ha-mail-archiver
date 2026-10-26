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

_UI_FILE = Path(__file__).with_name("security_ui.html")
HTML = _UI_FILE.read_text(encoding="utf-8") if _UI_FILE.exists() else "<h1>security_ui.html fehlt</h1>"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass
    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
    def _html(self, code, html):
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path in ("/", "/index.html", "/security", "/security/"):
            self._html(200, HTML); return
        if path.endswith("/api/status") or path == "/api/status":
            self._json(200, {"status": read_status(), "clamd_alive": clamd_alive(), "events": read_events(), "log": read_log()}); return
        if path.endswith("/api/rules") or path == "/api/rules":
            if mail_rules is None:
                self._json(500, {"ok": False, "message": "mail_rules fehlt"}); return
            try: self._json(200, mail_rules.list_rules())
            except Exception as e: self._json(500, {"ok": False, "message": str(e)})
            return
        self._json(404, {"ok": False, "message": "not found"})
    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(length) if length else b""
        if path.endswith("/api/scan") or path == "/api/scan":
            self._json(200, trigger_scan()); return
        if path.endswith("/api/update") or path == "/api/update":
            self._json(200, trigger_update()); return
        if path.endswith("/api/chunk") or path == "/api/chunk":
            self._json(200, handle_chunk(self.headers, body)); return
        if path.endswith("/api/rules") or path == "/api/rules":
            if mail_rules is None:
                self._json(500, {"ok": False, "message": "mail_rules fehlt"}); return
            try:
                data = json.loads(body.decode("utf-8") or "{}")
            except Exception:
                self._json(400, {"ok": False, "message": "invalid json"}); return
            action = (data.get("action") or "").strip()
            if action == "upsert":
                self._json(200, mail_rules.upsert_rule(data.get("rule") or data)); return
            if action == "delete":
                self._json(200, mail_rules.delete_rule(str(data.get("id") or ""))); return
            if action == "settings":
                self._json(200, mail_rules.set_settings(data)); return
            if action == "preview":
                self._json(200, mail_rules.preview_rule(data.get("rule") or data)); return
            if action == "apply":
                dry = bool(data.get("dry_run"))
                rid = (data.get("id") or "").strip()
                if rid:
                    store = mail_rules.load_store()
                    rule = next((r for r in (store.get("rules") or []) if r.get("id") == rid), None)
                    if not rule:
                        self._json(404, {"ok": False, "message": "Regel nicht gefunden"}); return
                    self._json(200, mail_rules.apply_rule(rule, dry_run=dry)); return
                self._json(200, mail_rules.start_apply_async(dry_run=dry)); return
            if action == "apply_status":
                st = mail_rules.read_apply_status()
                self._json(200, {"ok": True, "status": st}); return
            try: self._json(200, mail_rules.list_rules())
            except Exception as e: self._json(500, {"ok": False, "message": str(e)})
            return
        self._json(404, {"ok": False, "message": "not found"})

def main():
    if mail_rules is not None:
        try: mail_rules.start_background_loop()
        except Exception: pass
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print("[security-ui] listening on http://%s:%s/security/" % (HOST, PORT))
    httpd.serve_forever()

if __name__ == "__main__":
    main()
