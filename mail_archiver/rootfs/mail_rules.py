#!/usr/bin/env python3
"""Mail rules: auto-delete archived mails by sender (and optional subject/age)."""
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


def _parse_min_age(val):
    if val in (None, "", False):
        return None
    try:
        days = int(val)
        return days if days > 0 else None
    except (TypeError, ValueError):
        return None


def _rule_where(rule: dict):
    """Build SQL WHERE for one rule. Returns (where_sql, debug_info)."""
    m = rule.get("match") or {}
    clauses = ['e."IsLocked" = false']
    debug = {}

    account_id = m.get("account_id")
    if account_id not in (None, "", 0, "0"):
        try:
            clauses.append('e."MailAccountId" = %d' % int(account_id))
        except (TypeError, ValueError):
            pass

    from_mode = (m.get("from_mode") or "contains").lower()
    from_val = (m.get("from_value") or "").strip()
    if not from_val:
        return None, {"error": "from_value fehlt"}
    fv = _sql_escape(from_val.lower())

    if from_mode == "exact":
        clauses.append("lower(e.\"From\") = '%s'" % fv)
    elif from_mode == "domain":
        dom = fv.lstrip("@")
        clauses.append(
            "(lower(e.\"From\") LIKE '%%@%s' OR lower(e.\"From\") LIKE '%%@%s>%%')" % (dom, dom)
        )
    else:
        clauses.append("lower(e.\"From\") LIKE '%%%s%%'" % fv)

    subj = (m.get("subject_contains") or "").strip()
    if subj:
        clauses.append(
            "lower(coalesce(e.\"Subject\",'')) LIKE '%%%s%%'" % _sql_escape(subj.lower())
        )

    # Mindestalter: Mails älter als N Tage (Empfangs- oder Sendedatum)
    # Kalendertage, zeitzonenunabhängig über ::date
    min_age = m.get("min_age_days")
    if min_age not in (None, "", 0, "0"):
        try:
            days = max(0, int(min_age))
            if days > 0:
                # COALESCE falls ReceivedDate NULL ist; Vergleich auf Datumsebene
                clauses.append(
                    "(COALESCE(e.\"ReceivedDate\", e.\"SentDate\"))::date <= (CURRENT_DATE - %d)"
                    % days
                )
                debug["min_age_days"] = days
                debug["age_sql"] = "COALESCE(ReceivedDate,SentDate)::date <= CURRENT_DATE - %d" % days
        except (TypeError, ValueError):
            pass

    return " AND ".join(clauses), debug


def preview_rule(rule: dict, limit: int = 20) -> dict:
    where, debug = _rule_where(rule)
    if not where:
        return {"ok": False, "message": (debug or {}).get("error", "from_value fehlt"), "count": 0, "samples": []}

    sql_count = 'SELECT count(*) FROM %s."ArchivedEmails" e WHERE %s;' % (SCHEMA, where)
    rc, out = _psql(sql_count, tuples_only=True)
    if rc != 0:
        return {
            "ok": False,
            "message": out[-400:],
            "count": 0,
            "samples": [],
            "debug": debug,
            "sql": sql_count[:500],
        }
    try:
        count = int((out.strip().splitlines() or ["0"])[0].strip() or "0")
    except ValueError:
        count = 0

    sql_s = (
        'SELECT e."Id", left(e."From",80), left(coalesce(e."Subject",\'\'),60), '
        'COALESCE(e."ReceivedDate", e."SentDate")::date '
        'FROM %s."ArchivedEmails" e WHERE %s '
        'ORDER BY COALESCE(e."ReceivedDate", e."SentDate") DESC LIMIT %d;'
        % (SCHEMA, where, int(limit))
    )
    rc2, out2 = _psql(sql_s, tuples_only=True)
    samples = []
    if rc2 == 0:
        for line in out2.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) >= 3:
                samples.append({
                    "id": parts[0].strip(),
                    "from": parts[1].strip(),
                    "subject": parts[2].strip(),
                    "date": parts[3].strip() if len(parts) > 3 else "",
                })
    return {
        "ok": True,
        "count": count,
        "samples": samples,
        "debug": debug,
    }


def apply_rule(rule: dict, dry_run: bool = False) -> dict:
    where, debug = _rule_where(rule)
    if not where:
        return {"ok": False, "message": "ungueltige Regel", "deleted": 0}
    prev = preview_rule(rule, limit=5)
    if not prev.get("ok"):
        return {"ok": False, "message": prev.get("message", "preview failed"), "deleted": 0}
    count = int(prev.get("count") or 0)
    if dry_run or count == 0:
        return {
            "ok": True,
            "deleted": 0,
            "matched": count,
            "dry_run": dry_run,
            "samples": prev.get("samples") or [],
            "debug": debug,
        }

    sql = (
        "BEGIN;\n"
        "DELETE FROM %s.\"EmailAttachments\" a\n"
        " USING %s.\"ArchivedEmails\" e\n"
        " WHERE a.\"ArchivedEmailId\" = e.\"Id\" AND %s;\n"
        "DELETE FROM %s.\"ArchivedEmails\" e WHERE %s;\n"
        "COMMIT;\n"
    ) % (SCHEMA, SCHEMA, where, SCHEMA, where)

    rc, out = _psql(sql)
    if rc != 0:
        append_event("rule_apply_error", "%s: %s" % (rule.get("name"), out[-200:]))
        return {"ok": False, "message": out[-400:], "deleted": 0, "matched": count}
    append_event(
        "rule_apply_ok",
        "rule=%s deleted≈%d" % (rule.get("name") or rule.get("id"), count),
    )
    return {
        "ok": True,
        "deleted": count,
        "matched": count,
        "dry_run": False,
        "samples": prev.get("samples") or [],
    }


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
            "min_age_days": _parse_min_age(
                match.get("min_age_days") if match.get("min_age_days") not in (None, "") else data.get("min_age_days")
            ),
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
                    append_event("rules_loop_tick", "interval=%d" % mins)
                    apply_all_rules(dry_run=False)
                time.sleep(max(5, mins) * 60)
            except Exception as e:
                append_event("rules_loop_error", str(e))
                time.sleep(120)

    threading.Thread(target=_loop, daemon=True).start()
    append_event("rules_loop_started", "ok")
