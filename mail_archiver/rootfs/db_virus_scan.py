#!/usr/bin/env python3
"""Scan email attachments (and optionally bodies) via ClamAV – incremental & low priority."""
from __future__ import annotations
import json, os, subprocess, time
from datetime import datetime, timezone
from pathlib import Path

try:
    os.nice(12)
except Exception:
    pass

SCHEMA = "public"
DATA = Path("/data")
STATUS = DATA / "security" / "status.json"
EVENTS = DATA / "security" / "events.jsonl"
SCAN_LOG = DATA / "security" / "last-scan.log"
STATE = DATA / "security" / "db_scan_state.json"
QUAR = DATA / "quarantine"
TMP = DATA / "security" / ".scan_tmp"
MAX_BYTES = int(os.environ.get("DB_SCAN_MAX_BYTES", str(25 * 1024 * 1024)))
SCAN_BODIES = os.environ.get("DB_SCAN_BODIES", "false").lower() in ("1", "true", "yes", "on")
BATCH = int(os.environ.get("DB_SCAN_BATCH", "40"))
SLEEP_EVERY = float(os.environ.get("DB_SCAN_SLEEP", "0.15"))
MAX_PER_RUN = int(os.environ.get("DB_SCAN_MAX_PER_RUN", "800"))


def log(msg: str) -> None:
    print(f"[db_virus_scan] {msg}", flush=True)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def event(kind: str, detail: str) -> None:
    try:
        EVENTS.parent.mkdir(parents=True, exist_ok=True)
        with EVENTS.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": _now(), "kind": kind, "detail": detail}, ensure_ascii=False) + "\n")
    except Exception:
        pass


def load_state() -> dict:
    try:
        if STATE.exists():
            return json.loads(STATE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {"last_att_id": 0, "last_legacy_id": 0, "last_email_id": 0}


def save_state(st: dict) -> None:
    try:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(st), encoding="utf-8")
    except Exception as e:
        log(f"state save: {e}")


def write_status(**kw) -> None:
    try:
        STATUS.parent.mkdir(parents=True, exist_ok=True)
        cur = {}
        if STATUS.exists():
            try:
                cur = json.loads(STATUS.read_text(encoding="utf-8"))
            except Exception:
                cur = {}
        cur.update(kw)
        STATUS.write_text(json.dumps(cur, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def clamd_running() -> bool:
    try:
        return subprocess.run(["pgrep", "-x", "clamd"], capture_output=True).returncode == 0
    except Exception:
        return False


def psql(sql: str, timeout: int = 120) -> tuple[int, str]:
    env = os.environ.copy()
    cmd = [
        "psql", "-h", os.environ.get("DB_HOST", "127.0.0.1"),
        "-p", os.environ.get("DB_PORT", "5432"),
        "-U", os.environ.get("DB_USER", "mailuser"),
        "-d", os.environ.get("DB_NAME", "MailArchiver"),
        "-v", "ON_ERROR_STOP=1", "-t", "-A", "-F", "|", "-c", sql,
    ]
    env["PGPASSWORD"] = os.environ.get("DB_PASS", "mailuser")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return 1, str(e)


def scan_file(path: Path) -> tuple[int, str]:
    cmds = []
    if clamd_running():
        cmds.append(["clamdscan", "--no-summary", "--fdpass", str(path)])
    cmds.append(["clamscan", "--no-summary", str(path)])
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            out = (r.stdout or "") + (r.stderr or "")
            if r.returncode == 1 or "FOUND" in out:
                return 1, out
            if r.returncode == 0:
                return 0, out
        except FileNotFoundError:
            continue
        except Exception as e:
            return 0, str(e)
    return 0, "kein Scanner"


def quarantine_bytes(data: bytes, label: str) -> str:
    try:
        QUAR.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in label)[:80]
        dest = QUAR / f"{int(time.time())}_{safe}.bin"
        dest.write_bytes(data)
        return str(dest)
    except Exception:
        return ""


def fetch_bytes_att(content_id: int) -> bytes:
    import base64
    sql = f'SELECT encode(c."Content", \'base64\') FROM public."AttachmentContents" c WHERE c."Id" = {int(content_id)};'
    rc, out = psql(sql, timeout=60)
    if rc != 0 or not out.strip():
        return b""
    try:
        return base64.b64decode(out.strip().splitlines()[0])
    except Exception:
        return b""


def fetch_bytes_legacy(att_id: int) -> bytes:
    import base64
    sql = f'SELECT encode(a."Content", \'base64\') FROM public."EmailAttachments" a WHERE a."Id" = {int(att_id)};'
    rc, out = psql(sql, timeout=60)
    if rc != 0 or not out.strip():
        return b""
    try:
        return base64.b64decode(out.strip().splitlines()[0])
    except Exception:
        return b""


def fetch_body(email_id: int) -> bytes:
    import base64
    sql = f'SELECT encode(convert_to(coalesce(e."Body", \'\'), \'UTF8\'), \'base64\') FROM public."ArchivedEmails" e WHERE e."Id" = {int(email_id)};'
    rc, out = psql(sql, timeout=60)
    if rc != 0 or not out.strip():
        return b""
    try:
        return base64.b64decode(out.strip().splitlines()[0])
    except Exception:
        return b""


def list_attachment_contents(after_id: int) -> list:
    sql = (
        f'SELECT c."Id", coalesce(length(c."Content"), 0) FROM public."AttachmentContents" c '
        f'WHERE c."Id" > {int(after_id)} ORDER BY c."Id" LIMIT {MAX_PER_RUN};'
    )
    rc, out = psql(sql)
    if rc != 0:
        log(f"AttachmentContents list fail: {out[-200:]}")
        return []
    rows = []
    for line in out.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        try:
            rows.append((int(parts[0].strip()), int(parts[1].strip() or 0)))
        except (ValueError, IndexError):
            continue
    return rows


def list_legacy_attachments(after_id: int) -> list:
    sql = (
        f'SELECT a."Id", coalesce(a."FileName", \'att.bin\'), a."ArchivedEmailId", '
        f'coalesce(length(a."Content"), 0) FROM public."EmailAttachments" a '
        f'WHERE a."Content" IS NOT NULL AND a."AttachmentContentId" IS NULL '
        f'AND a."Id" > {int(after_id)} ORDER BY a."Id" LIMIT {MAX_PER_RUN};'
    )
    rc, out = psql(sql)
    if rc != 0:
        return []
    rows = []
    for line in out.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        while len(parts) < 4:
            parts.append("0")
        try:
            rows.append((int(parts[0].strip()), parts[1].strip(), int(parts[2].strip() or 0), int(parts[3].strip() or 0)))
        except ValueError:
            continue
    return rows


def list_emails_for_body(after_id: int) -> list:
    sql = (
        f'SELECT e."Id", left(coalesce(e."Subject", \'\'), 80) FROM public."ArchivedEmails" e '
        f'WHERE e."Id" > {int(after_id)} ORDER BY e."Id" LIMIT {MAX_PER_RUN};'
    )
    rc, out = psql(sql, timeout=180)
    if rc != 0:
        return []
    rows = []
    for line in out.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("|", 1)
        try:
            rows.append((int(parts[0].strip()), (parts[1].strip() if len(parts) > 1 else "")))
        except ValueError:
            continue
    return rows


def scan_blob(data: bytes, label: str) -> int:
    if not data:
        return 0
    if len(data) > MAX_BYTES:
        log(f"skip {label} ({len(data)} > {MAX_BYTES})")
        return 0
    TMP.mkdir(parents=True, exist_ok=True)
    path = TMP / "scan.bin"
    path.write_bytes(data)
    infected, out = scan_file(path)
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass
    if infected:
        q = quarantine_bytes(data, label)
        detail = f"{label} FOUND → {q or 'quarantine'}"
        log(f"HIT: {detail}")
        event("threat_found", detail[:500])
        try:
            with SCAN_LOG.open("a", encoding="utf-8") as f:
                f.write(out + "\n")
        except Exception:
            pass
        return 1
    return 0


def main() -> int:
    st = load_state()
    log(f"start incremental (bodies={SCAN_BODIES} batch={BATCH} max={MAX_PER_RUN} after att={st.get('last_att_id')} email={st.get('last_email_id')})")
    event("db_scan_start", f"incremental bodies={SCAN_BODIES}")
    contents = list_attachment_contents(int(st.get("last_att_id") or 0))
    legacy = list_legacy_attachments(int(st.get("last_legacy_id") or 0))
    emails = list_emails_for_body(int(st.get("last_email_id") or 0)) if SCAN_BODIES else []
    total_targets = len(contents) + len(legacy) + len(emails)
    infected_total = 0
    done = 0
    write_status(
        scanning=True, message=f"DB-Scan (inkrementell) {total_targets} Ziele",
        scanned_paths=0, total_paths=total_targets, db_scan=True,
        clamd_running=clamd_running(), virus_scan_enabled=True,
    )
    for cid, size in contents:
        data = fetch_bytes_att(cid)
        infected_total += scan_blob(data, f"att_content_{cid}")
        st["last_att_id"] = max(int(st.get("last_att_id") or 0), cid)
        done += 1
        if done % BATCH == 0:
            save_state(st)
            write_status(scanning=True, message=f"DB Anhang {done}/{total_targets}", scanned_paths=done, total_paths=total_targets, db_scan=True, infected_moved=infected_total)
            time.sleep(SLEEP_EVERY)
    for aid, name, eid, size in legacy:
        data = fetch_bytes_legacy(aid)
        infected_total += scan_blob(data, f"legacy_{aid}_{name}")
        st["last_legacy_id"] = max(int(st.get("last_legacy_id") or 0), aid)
        done += 1
        if done % BATCH == 0:
            save_state(st)
            time.sleep(SLEEP_EVERY)
    for eid, subj in emails:
        data = fetch_body(eid)
        infected_total += scan_blob(data, f"body_{eid}_{subj[:40]}")
        st["last_email_id"] = max(int(st.get("last_email_id") or 0), eid)
        done += 1
        if done % BATCH == 0:
            save_state(st)
            time.sleep(SLEEP_EVERY)
    save_state(st)
    msg = f"DB-Scan fertig – {infected_total} Treffer ({done}/{total_targets} geprüft, inkrementell)"
    log(msg)
    event("db_scan_end", f"infected={infected_total} scanned={done}")
    write_status(
        scanning=False, message=msg, current_path="", scanned_paths=done,
        total_paths=total_targets, last_scan=_now(), infected_moved=infected_total,
        db_scan=False, clamd_running=clamd_running(), virus_scan_enabled=True,
    )
    return 2 if infected_total else 0


if __name__ == "__main__":
    raise SystemExit(main())
