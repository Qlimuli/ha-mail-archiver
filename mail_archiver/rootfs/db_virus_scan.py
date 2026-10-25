#!/usr/bin/env python3
"""Scan all attachment blobs (and optional email bodies) from PostgreSQL with ClamAV."""
from __future__ import annotations

import base64
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

DATA = Path("/data")
STATUS = DATA / "security" / "status.json"
SCAN_LOG = DATA / "security" / "last-scan.log"
EVENTS = DATA / "security" / "events.jsonl"
QUAR = DATA / "quarantine"
SCHEMA = "mail_archiver"
TMP = Path("/tmp/mail-db-scan")

MAX_BYTES = int(os.environ.get("DB_SCAN_MAX_BYTES", str(40 * 1024 * 1024)))
SCAN_BODIES = os.environ.get("DB_SCAN_BODIES", "1") not in ("0", "false", "no")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    line = f"[mail-archiver:db-scan] {msg}"
    print(line, flush=True)
    try:
        SCAN_LOG.parent.mkdir(parents=True, exist_ok=True)
        with SCAN_LOG.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def event(kind: str, detail: str) -> None:
    try:
        EVENTS.parent.mkdir(parents=True, exist_ok=True)
        with EVENTS.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": _now(), "kind": kind, "detail": detail}, ensure_ascii=False) + "\n")
    except Exception:
        pass


def write_status(**kwargs) -> None:
    base = {}
    try:
        if STATUS.exists():
            base = json.loads(STATUS.read_text(encoding="utf-8"))
    except Exception:
        base = {}
    base.update(kwargs)
    base.setdefault("quarantine_dir", str(QUAR))
    try:
        STATUS.parent.mkdir(parents=True, exist_ok=True)
        STATUS.write_text(json.dumps(base, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass


def parse_conn() -> dict | None:
    cs = os.environ.get("ConnectionStrings__DefaultConnection") or os.environ.get("CONNECTION_STRING", "")
    if not cs:
        return {"host": "127.0.0.1", "port": "5432", "dbname": "MailArchiver", "user": "mailuser", "password": "mailuser"}
    parts = {}
    for bit in cs.split(";"):
        bit = bit.strip()
        if not bit or "=" not in bit:
            continue
        k, v = bit.split("=", 1)
        parts[k.strip().lower()] = v.strip()
    host = parts.get("host") or parts.get("server")
    if not host:
        return None
    return {
        "host": host,
        "port": parts.get("port", "5432"),
        "dbname": parts.get("database") or parts.get("db", "MailArchiver"),
        "user": parts.get("username") or parts.get("user") or "mailuser",
        "password": parts.get("password") or "",
    }


def psql(sql: str, tuples_only: bool = True, timeout: int = 120) -> tuple[int, str]:
    conn = parse_conn()
    if not conn:
        return 1, "keine DB-Verbindung"
    env = os.environ.copy()
    env["PGPASSWORD"] = conn["password"]
    cmd = [
        "psql", "-h", conn["host"], "-p", str(conn["port"]), "-U", conn["user"], "-d", conn["dbname"],
        "-v", "ON_ERROR_STOP=1", "-t" if tuples_only else "-q", "-A", "-c", sql,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return 1, str(e)


def fetch_b64(sql: str, timeout: int = 180) -> bytes | None:
    rc, out = psql(sql, tuples_only=True, timeout=timeout)
    if rc != 0:
        log(f"SQL-Fehler: {out[-200:]}")
        return None
    line = (out.strip().splitlines() or [""])[0].strip()
    if not line or line.lower() == "null":
        return b""
    try:
        return base64.b64decode(line)
    except Exception as e:
        log(f"Base64-Decode Fehler: {e}")
        return None


def clamd_running() -> bool:
    try:
        return subprocess.run(["pgrep", "-x", "clamd"], capture_output=True).returncode == 0
    except Exception:
        return False


def scan_file(path: Path) -> tuple[int, str]:
    out = ""
    try:
        if clamd_running() and subprocess.run(["which", "clamdscan"], capture_output=True).returncode == 0:
            r = subprocess.run(
                ["clamdscan", "--fdpass", "--no-summary", str(path)],
                capture_output=True, text=True, timeout=300,
            )
            out = (r.stdout or "") + (r.stderr or "")
        elif subprocess.run(["which", "clamscan"], capture_output=True).returncode == 0:
            r = subprocess.run(
                ["clamscan", "--no-summary", str(path)],
                capture_output=True, text=True, timeout=300,
            )
            out = (r.stdout or "") + (r.stderr or "")
        else:
            return 0, "kein Scanner"
    except Exception as e:
        return 0, str(e)
    return out.count("FOUND"), out


def quarantine_bytes(data: bytes, label: str) -> str:
    QUAR.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch if ch.isalnum() or ch in "._-+" else "_" for ch in label)[:120] or "infected.bin"
    dest = QUAR / f"db_{_now().replace(':', '')}_{safe}"
    try:
        dest.write_bytes(data)
        return str(dest)
    except Exception as e:
        log(f"Quarantäne schreiben fehlgeschlagen: {e}")
        return ""


def list_content_ids() -> list:
    sql = f'SELECT c."Id", coalesce(c."Size", 0) FROM {SCHEMA}."AttachmentContents" c ORDER BY c."Id";'
    rc, out = psql(sql)
    if rc != 0:
        log(f"AttachmentContents Liste fehlgeschlagen: {out[-200:]}")
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


def list_legacy_attachments() -> list:
    sql = (
        f'SELECT a."Id", coalesce(a."FileName", \'att.bin\'), a."ArchivedEmailId", '
        f'coalesce(length(a."Content"), 0) FROM {SCHEMA}."EmailAttachments" a '
        f'WHERE a."Content" IS NOT NULL AND a."AttachmentContentId" IS NULL ORDER BY a."Id";'
    )
    rc, out = psql(sql)
    if rc != 0:
        log(f"Legacy-Anhänge Liste fehlgeschlagen: {out[-200:]}")
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


def list_emails_for_body() -> list:
    sql = (
        f'SELECT e."Id", left(coalesce(e."Subject", \'\'), 80) FROM {SCHEMA}."ArchivedEmails" e '
        f'ORDER BY e."Id";'
    )
    rc, out = psql(sql, timeout=180)
    if rc != 0:
        log(f"E-Mail-Liste fehlgeschlagen: {out[-200:]}")
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
        log(f"Überspringe {label} ({len(data)} bytes > Limit {MAX_BYTES})")
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
        log(f"TREFFER: {detail}")
        event("threat_found", detail[:500])
        try:
            with SCAN_LOG.open("a", encoding="utf-8") as f:
                f.write(out + "\n")
        except Exception:
            pass
    return infected


def main() -> int:
    log("Starte Datenbank-Virenscan (Anhänge + optional Bodies)…")
    event("db_scan_start", "attachments+bodies" if SCAN_BODIES else "attachments")
    QUAR.mkdir(parents=True, exist_ok=True)

    contents = list_content_ids()
    legacy = list_legacy_attachments()
    emails = list_emails_for_body() if SCAN_BODIES else []

    total_targets = len(contents) + len(legacy) + len(emails)
    log(f"Ziele: {len(contents)} deduplizierte Anhänge, {len(legacy)} Legacy-Anhänge, {len(emails)} E-Mail-Bodies")
    write_status(
        scanning=True,
        message=f"DB-Scan gestartet ({total_targets} Ziele)",
        current_path="database",
        scanned_paths=0,
        total_paths=total_targets,
        db_scan=True,
        infected_moved=0,
        clamd_running=clamd_running(),
        virus_scan_enabled=True,
    )

    infected_total = 0
    done = 0

    for cid, size in contents:
        done += 1
        label = f"AttachmentContent#{cid}"
        write_status(
            scanning=True, message=f"Scanne Anhang-Inhalt {done}/{total_targets}",
            current_path=label, scanned_paths=done, total_paths=total_targets,
            db_scan=True, infected_moved=infected_total,
            clamd_running=clamd_running(), virus_scan_enabled=True,
        )
        if size and size > MAX_BYTES:
            log(f"Überspringe {label} size={size}")
            continue
        data = fetch_b64(
            f'SELECT encode(c."Content", \'base64\') FROM {SCHEMA}."AttachmentContents" c WHERE c."Id" = {cid};'
        )
        if data is None:
            continue
        infected_total += scan_blob(data, label)

    for aid, fname, eid, size in legacy:
        done += 1
        label = f"LegacyAtt#{aid}_{fname}_email{eid}"
        write_status(
            scanning=True, message=f"Scanne Legacy-Anhang {done}/{total_targets}",
            current_path=label[:200], scanned_paths=done, total_paths=total_targets,
            db_scan=True, infected_moved=infected_total,
            clamd_running=clamd_running(), virus_scan_enabled=True,
        )
        if size and size > MAX_BYTES:
            log(f"Überspringe {label} size={size}")
            continue
        data = fetch_b64(
            f'SELECT encode(a."Content", \'base64\') FROM {SCHEMA}."EmailAttachments" a WHERE a."Id" = {aid};'
        )
        if data is None:
            continue
        infected_total += scan_blob(data, label)

    for eid, subj in emails:
        done += 1
        label = f"Email#{eid}"
        write_status(
            scanning=True, message=f"Scanne E-Mail-Body {done}/{total_targets}",
            current_path=f"{label} {subj}"[:200], scanned_paths=done, total_paths=total_targets,
            db_scan=True, infected_moved=infected_total,
            clamd_running=clamd_running(), virus_scan_enabled=True,
        )
        data = fetch_b64(
            f'SELECT encode(convert_to(coalesce(e."Body",\'\') || E\'\\n\' || coalesce(e."HtmlBody",\'\'), \'UTF8\'), \'base64\') '
            f'FROM {SCHEMA}."ArchivedEmails" e WHERE e."Id" = {eid};'
        )
        if data is None or len(data) < 8:
            continue
        infected_total += scan_blob(data, f"{label}_{subj[:40]}")

    try:
        import shutil
        shutil.rmtree(TMP, ignore_errors=True)
    except Exception:
        pass

    msg = (
        f"DB-Scan fertig – {infected_total} Treffer ({total_targets} geprüft)"
        if infected_total
        else f"DB-Scan fertig – keine Treffer ({total_targets} geprüft)"
    )
    log(msg)
    event("db_scan_end", f"infected={infected_total} scanned={total_targets}")
    write_status(
        scanning=False, message=msg, current_path="",
        scanned_paths=total_targets, total_paths=total_targets,
        last_scan=_now(), infected_moved=infected_total, db_scan=False,
        clamd_running=clamd_running(), virus_scan_enabled=True,
    )
    return 0 if infected_total == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
