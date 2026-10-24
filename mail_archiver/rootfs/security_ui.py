#!/usr/bin/env python3
"""Security page + chunk upload + web ImportEml job trigger."""
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


def trigger_local_import(file_path: str, account_id: int, cookie: str = "") -> dict:
    """Queue real EML job in running web app (Jobs UI). CLI fallback."""
    import re
    import urllib.request
    import urllib.error
    import uuid

    path = Path(file_path)
    if not path.is_file():
        alt = IMPORT / Path(file_path).name
        if alt.is_file():
            path = alt
        else:
            return {"ok": False, "message": f"Datei nicht gefunden: {file_path}"}
    try:
        path.resolve().relative_to(IMPORT.resolve())
    except Exception:
        return {"ok": False, "message": "Datei muss unter /data/import liegen"}
    if account_id < 1:
        return {"ok": False, "message": "Ungueltige account_id"}

    append_event("local_import_start", f"file={path.name} account_id={account_id}")
    base = os.environ.get("MAIL_ARCHIVER_INTERNAL", "http://127.0.0.1:5001").rstrip("/")
    import_url = base + "/MailAccounts/ImportEml"

    def _cli_fallback(reason: str) -> dict:
        append_event("local_import_cli_fallback", reason)
        cmd = [
            "dotnet", "MailArchiver.dll", "--import-eml",
            "--file", str(path), "--account-id", str(account_id),
        ]
        cwd = "/app" if Path("/app/MailArchiver.dll").exists() else str(Path.cwd())
        try:
            log_path = DATA / "security" / "import-cli.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            logf = open(log_path, "a", encoding="utf-8")
            logf.write(f"\n=== {_now()} CLI fallback {path} account={account_id} reason={reason} ===\n")
            logf.flush()
            proc = subprocess.Popen(cmd, cwd=cwd, stdout=logf, stderr=subprocess.STDOUT, env=os.environ.copy())
            append_event("local_import_spawned", f"pid={proc.pid} file={path.name}")
            return {
                "ok": True,
                "mode": "cli",
                "message": (
                    f"CLI-Import gestartet (PID {proc.pid}). "
                    "CLI-Jobs erscheinen NICHT unter EML-Import-Jobs; "
                    "Mails landen direkt im Archiv. Grund: " + reason
                ),
                "pid": proc.pid,
                "file": path.name,
                "account_id": account_id,
                "jobs_visible": False,
            }
        except Exception as e:
            append_event("local_import_error", str(e))
            return {"ok": False, "message": f"CLI-Fallback fehlgeschlagen: {e} (vorher: {reason})"}

    if not cookie:
        return _cli_fallback("kein Session-Cookie")

    try:
        req = urllib.request.Request(import_url, headers={
            "Cookie": cookie,
            "User-Agent": "ha-mail-archiver-security-ui/1.3.1",
            "Accept": "text/html",
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            html = resp.read().decode("utf-8", errors="replace")
            set_cookies = resp.headers.get_all("Set-Cookie") or []
        extra = []
        for sc in set_cookies:
            part = sc.split(";", 1)[0]
            if "=" in part:
                extra.append(part)
        if extra:
            cookie = cookie + "; " + "; ".join(extra)

        m = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', html)
        if not m:
            m = re.search(r'value="([^"]+)"[^>]*name="__RequestVerificationToken"', html)
        if not m:
            return _cli_fallback("Anti-Forgery-Token nicht gefunden")
        token = m.group(1)

        boundary = "----HaMailArchiver" + uuid.uuid4().hex
        file_bytes = path.read_bytes()
        filename = path.name

        def part(name: str, value: str) -> bytes:
            return (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n"
            ).encode("utf-8")

        body = b"".join([
            part("__RequestVerificationToken", token),
            part("TargetAccountId", str(account_id)),
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="EmlFile"; filename="{filename}"\r\n'
                f"Content-Type: application/zip\r\n\r\n"
            ).encode("utf-8"),
            file_bytes,
            f"\r\n--{boundary}--\r\n".encode("utf-8"),
        ])

        req2 = urllib.request.Request(
            import_url,
            data=body,
            method="POST",
            headers={
                "Cookie": cookie,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(body)),
                "User-Agent": "ha-mail-archiver-security-ui/1.3.1",
                "Accept": "text/html,application/xhtml+xml",
            },
        )
        try:
            class _NoRedir(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    raise urllib.error.HTTPError(newurl, code, msg, headers, fp)
            opener = urllib.request.build_opener(_NoRedir)
            with opener.open(req2, timeout=600) as resp2:
                status = resp2.status
                loc = resp2.headers.get("Location") or ""
                body_txt = resp2.read()[:500].decode("utf-8", errors="replace")
        except urllib.error.HTTPError as he:
            status = he.code
            loc = he.headers.get("Location") or ""
            try:
                body_txt = he.read()[:500].decode("utf-8", errors="replace")
            except Exception:
                body_txt = ""

        if status in (301, 302, 303, 307, 308) or "EmlImportStatus" in loc or "jobId" in loc:
            append_event("local_import_web_ok", f"status={status} loc={loc}")
            return {
                "ok": True,
                "mode": "web",
                "message": f"Import-Job gestartet fuer {filename}",
                "redirect": loc or "/Emails/Jobs",
                "file": filename,
                "account_id": account_id,
                "jobs_visible": True,
            }

        if status == 200 and ("EmlImportStatus" in body_txt or "job" in body_txt.lower()):
            append_event("local_import_web_ok", "status=200 body_hint")
            return {
                "ok": True,
                "mode": "web",
                "message": f"Import-Job gestartet fuer {filename}",
                "redirect": "/Emails/Jobs",
                "file": filename,
                "account_id": account_id,
                "jobs_visible": True,
            }

        return _cli_fallback(f"Web-POST HTTP {status}: {body_txt[:120]}")
    except Exception as e:
        return _cli_fallback(str(e))


HTML = """<!DOCTYPE html>
<html lang="de" data-bs-theme="dark"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Sicherheit</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"/>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"/>
<style>
body{background:#1a1d21;color:#e9ecef}
.card{background:#212529;border-color:#343a40}
.log{max-height:280px;overflow:auto;font-size:.8rem;background:#0d1117;padding:.75rem;white-space:pre-wrap}
</style></head><body>
<nav class="navbar navbar-dark bg-dark mb-3 px-3">
<a class="navbar-brand" id="home" href="#"><i class="bi bi-envelope-fill me-1"></i>Mail Archiver</a>
<span class="navbar-text"><i class="bi bi-shield-check me-1"></i>Sicherheit</span>
</nav>
<div class="container-fluid px-3 pb-4">
<div class="d-flex gap-2 mb-3 flex-wrap">
<button class="btn btn-primary btn-sm" id="scan">Scan jetzt</button>
<button class="btn btn-outline-info btn-sm" id="upd">Signaturen</button>
<button class="btn btn-outline-light btn-sm" id="ref">Aktualisieren</button>
</div>
<div class="row g-3 mb-3" id="cards"></div>
<div class="card mb-3"><div class="card-header">Import /data/import</div><div class="card-body p-0" id="imp"></div></div>
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
document.getElementById('cards').innerHTML='<div class="col-md-3"><div class="card"><div class="card-body"><div class="text-muted small">Scan</div><div class="fs-5">'+(s.virus_scan_enabled===false?'Aus':'An')+'</div></div></div></div><div class="col-md-3"><div class="card"><div class="card-body"><div class="text-muted small">ClamAV</div><div class="fs-5">'+(d.clamd_alive?'Daemon':'CLI')+'</div></div></div></div><div class="col-md-3"><div class="card"><div class="card-body"><div class="text-muted small">Infiziert</div><div class="fs-5">'+(s.infected_moved||0)+'</div></div></div></div><div class="col-md-3"><div class="card"><div class="card-body"><div class="text-muted small">Letzter Scan</div><div class="small">'+esc(s.last_scan||'-')+'</div></div></div></div>';
var files=d.import_files||[];
document.getElementById('imp').innerHTML=files.length?'<ul class="list-group list-group-flush">'+files.map(function(f){return '<li class="list-group-item bg-transparent text-light">'+esc(f.path)+' ('+f.size+')</li>';}).join('')+'</ul>':'<div class="p-3 text-muted">leer</div>';
var ev=d.events||[];
document.getElementById('ev').innerHTML=ev.length?'<ul class="list-group list-group-flush">'+ev.slice(0,20).map(function(e){return '<li class="list-group-item bg-transparent text-light small">'+esc(e.ts)+' <code>'+esc(e.kind)+'</code> '+esc(e.detail||'')+'</li>';}).join('')+'</ul>':'<div class="p-3 text-muted">keine</div>';
document.getElementById('log').textContent=d.log||'';}).catch(function(e){document.getElementById('log').textContent=String(e);});}
document.getElementById('scan').onclick=function(){api('/api/scan',{method:'POST'}).then(function(){setTimeout(refresh,1000);});};
document.getElementById('upd').onclick=function(){api('/api/update',{method:'POST'}).then(function(){setTimeout(refresh,1500);});};
document.getElementById('ref').onclick=refresh; refresh(); setInterval(refresh,15000);
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
        if path == "/api/import-local":
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                length = 0
            raw = self.rfile.read(length) if length else b"{}"
            try:
                data = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                data = {}
            file_path = data.get("file") or data.get("path") or ""
            try:
                account_id = int(data.get("account_id") or 0)
            except (TypeError, ValueError):
                account_id = 0
            cookie = self.headers.get("Cookie") or data.get("cookie") or ""
            result = trigger_local_import(str(file_path), account_id, cookie=cookie)
            self._json(200 if result.get("ok") else 400, result)
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
                self._json(200 if result.get("ok") else 400, result)
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
