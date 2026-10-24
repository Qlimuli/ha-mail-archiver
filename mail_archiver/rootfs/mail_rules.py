#!/usr/bin/env python3
"""Mail rules: auto-delete archived mails by sender (and optional subject)."""
from __future__ import annotations

import json
import os
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

DATA = Path("/data")
RULES_FILE = DATA / "security" / "mail_rules.json"
EVENTS = DATA / "security" / "events.jsonl"
SCHEMA = "mail_archiver"

_lock = threading.Lock()
_apply_lock = threading.Lock()
_apply_running = False
_loop_started = False


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_event(kind: str, detail: str) -> None:
    try:
        EVENTS.parent.mkdir(parents=True, exist_ok=True)
        with EVENTS.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": _now(), "kind": kind, "detail": detail}, ensure_ascii=False) + "\n")
    except Exception:
        pass


def default_store() -> dict:
    return {"version": 1, "enabled": True, "interval_minutes": 30, "rules": [], "last_run": None, "last_result": None}


def load_store() -> dict:
    try:
        if RULES_FILE.exists():
            data = json.loads(RULES_FILE.read_text(encoding="utf-8"))
            base = default_store()
            base.update({k: data.get(k, base[k]) for k in base})
            if not isinstance(base.get("rules"), list):
                base["rules"] = []
            return base
    except Exception as e:
        append_event("rules_load_error", str(e))
    return default_store()


def save_store(store: dict) -> None:
    RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    RULES_FILE.write_text(json.dumps(store, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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


def _psql(sql: str, tuples_only: bool = False):
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
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return 1, str(e)


def _sql_escape(s: str) -> str:
    return (s or "").replace("'", "''")


def _rule_where(rule: dict):
    m = rule.get("match") or {}
    clauses = ['e."IsLocked" = false']
    account_id = m.get("account_id")
    if account_id not in (None, "", 0, "0"):
        try:
            clauses.append(f'e."MailAccountId" = {int(account_id)}')
        except (TypeError, ValueError):
            pass
    from_mode = (m.get("from_mode") or "contains").lower()
    from_val = (m.get("from_value") or "").strip()
    if not from_val:
        return None
    fv = _sql_escape(from_val.lower())
    if from_mode == "exact":
        clauses.append(f"lower(e.\"From\") = '{fv}'")
    elif from_mode == "domain":
        dom = fv.lstrip("@")
        clauses.append(f"(lower(e.\"From\") like '%@{dom}' or lower(e.\"From\") like '%@{dom}>%')")
    else:
        clauses.append(f"lower(e.\"From\") like '%{fv}%'")
    subj = (m.get("subject_contains") or "").strip()
    if subj:
        clauses.append(f"lower(coalesce(e.\"Subject\",'')) like '%{_sql_escape(subj.lower())}%'")
    return " AND ".join(clauses)


def preview_rule(rule: dict, limit: int = 20) -> dict:
    where = _rule_where(rule)
    if not where:
        return {"ok": False, "message": "from_value fehlt", "count": 0, "samples": []}
    rc, out = _psql(f'SELECT count(*) FROM {SCHEMA}."ArchivedEmails" e WHERE {where};', tuples_only=True)
    if rc != 0:
        return {"ok": False, "message": out[-300:], "count": 0, "samples": []}
    try:
        count = int((out.strip().splitlines() or ["0"])[0].strip() or "0")
    except ValueError:
        count = 0
    rc2, out2 = _psql(
        f'SELECT e."Id", left(e."From",80), left(coalesce(e."Subject",\'\'),80) '
        f'FROM {SCHEMA}."ArchivedEmails" e WHERE {where} ORDER BY e."ReceivedDate" DESC LIMIT {int(limit)};',
        tuples_only=True,
    )
    samples = []
    if rc2 == 0:
        for line in out2.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) >= 3:
                samples.append({"id": parts[0].strip(), "from": parts[1].strip(), "subject": parts[2].strip()})
    return {"ok": True, "count": count, "samples": samples}


def apply_rule(rule: dict, dry_run: bool = False) -> dict:
    where = _rule_where(rule)
    if not where:
        return {"ok": False, "message": "ungueltige Regel", "deleted": 0}
    prev = preview_rule(rule, limit=5)
    if not prev.get("ok"):
        return {"ok": False, "message": prev.get("message", "preview failed"), "deleted": 0}
    count = int(prev.get("count") or 0)
    if dry_run or count == 0:
        return {"ok": True, "deleted": 0, "matched": count, "dry_run": dry_run, "samples": prev.get("samples") or []}
    sql = f'''BEGIN;
DELETE FROM {SCHEMA}."EmailAttachments" a
 USING {SCHEMA}."ArchivedEmails" e
 WHERE a."ArchivedEmailId" = e."Id" AND {where};
DELETE FROM {SCHEMA}."ArchivedEmails" e WHERE {where};
COMMIT;
'''
    rc, out = _psql(sql)
    if rc != 0:
        append_event("rule_apply_error", f"{rule.get('name')}: {out[-200:]}")
        return {"ok": False, "message": out[-400:], "deleted": 0, "matched": count}
    append_event("rule_apply_ok", f"rule={rule.get('name') or rule.get('id')} deleted≈{count}")
    return {"ok": True, "deleted": count, "matched": count, "dry_run": False, "samples": prev.get("samples") or []}


def apply_all_rules(dry_run: bool = False) -> dict:
    global _apply_running
    with _apply_lock:
        if _apply_running:
            return {"ok": False, "message": "Regeln laufen bereits"}
        _apply_running = True
    try:
        store = load_store()
        if not store.get("enabled", True) and not dry_run:
            return {"ok": True, "message": "Regeln global deaktiviert", "results": []}
        results = []
        total = 0
        for rule in store.get("rules") or []:
            if not rule.get("enabled", True):
                results.append({"id": rule.get("id"), "skipped": True})
                continue
            if (rule.get("action") or "delete_local") != "delete_local":
                results.append({"id": rule.get("id"), "skipped": True, "reason": "unknown action"})
                continue
            r = apply_rule(rule, dry_run=dry_run)
            r["id"] = rule.get("id")
            r["name"] = rule.get("name")
            results.append(r)
            if r.get("ok") and not dry_run:
                total += int(r.get("deleted") or 0)
        store["last_run"] = _now()
        store["last_result"] = {"deleted": total, "dry_run": dry_run, "results": results}
        save_store(store)
        return {"ok": True, "deleted": total, "dry_run": dry_run, "results": results}
    finally:
        with _apply_lock:
            _apply_running = False


def list_rules() -> dict:
    store = load_store()
    return {
        "ok": True,
        "enabled": store.get("enabled", True),
        "interval_minutes": store.get("interval_minutes", 30),
        "last_run": store.get("last_run"),
        "last_result": store.get("last_result"),
        "rules": store.get("rules") or [],
        "apply_running": _apply_running,
    }


def upsert_rule(data: dict) -> dict:
    store = load_store()
    rules = store.get("rules") or []
    rid = (data.get("id") or "").strip()
    name = (data.get("name") or "").strip() or "Regel"
    match = data.get("match") or {}
    from_value = (match.get("from_value") or data.get("from_value") or "").strip()
    if not from_value:
        return {"ok": False, "message": "Absender (from_value) ist Pflicht"}
    rule = {
        "id": rid or str(uuid.uuid4()),
        "name": name,
        "enabled": bool(data.get("enabled", True)),
        "action": data.get("action") or "delete_local",
        "match": {
            "from_mode": (match.get("from_mode") or data.get("from_mode") or "contains").lower(),
            "from_value": from_value,
            "subject_contains": (match.get("subject_contains") or data.get("subject_contains") or "").strip(),
            "account_id": match.get("account_id") if match.get("account_id") not in ("", None) else data.get("account_id"),
        },
        "updated": _now(),
    }
    if not rid:
        rule["created"] = _now()
        rules.append(rule)
    else:
        found = False
        for i, r in enumerate(rules):
            if r.get("id") == rid:
                rule["created"] = r.get("created") or _now()
                rules[i] = rule
                found = True
                break
        if not found:
            rule["created"] = _now()
            rules.append(rule)
    store["rules"] = rules
    save_store(store)
    append_event("rule_saved", rule["name"])
    return {"ok": True, "rule": rule}


def delete_rule(rule_id: str) -> dict:
    store = load_store()
    before = len(store.get("rules") or [])
    store["rules"] = [r for r in (store.get("rules") or []) if r.get("id") != rule_id]
    save_store(store)
    append_event("rule_deleted", rule_id)
    return {"ok": True, "removed": before - len(store["rules"])}


def set_settings(data: dict) -> dict:
    store = load_store()
    if "enabled" in data:
        store["enabled"] = bool(data["enabled"])
    if "interval_minutes" in data:
        try:
            store["interval_minutes"] = max(5, min(24 * 60, int(data["interval_minutes"])))
        except (TypeError, ValueError):
            pass
    save_store(store)
    return {"ok": True, "enabled": store["enabled"], "interval_minutes": store["interval_minutes"]}


def start_background_loop() -> None:
    global _loop_started
    with _lock:
        if _loop_started:
            return
        _loop_started = True

    def _loop() -> None:
        import time
        time.sleep(45)
        while True:
            try:
                store = load_store()
                mins = int(store.get("interval_minutes") or 30)
                if store.get("enabled", True) and (store.get("rules") or []):
                    append_event("rules_loop_tick", f"interval={mins}")
                    apply_all_rules(dry_run=False)
                time.sleep(max(5, mins) * 60)
            except Exception as e:
                append_event("rules_loop_error", str(e))
                time.sleep(120)

    threading.Thread(target=_loop, daemon=True).start()
    append_event("rules_loop_started", "ok")
