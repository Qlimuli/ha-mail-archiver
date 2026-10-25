#!/usr/bin/env python3
"""Mail rules engine with IMAP remote purge by rule criteria."""
from __future__ import annotations
import json, os, re, subprocess, threading, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA = Path("/data")
RULES_FILE = DATA / "security" / "mail_rules.json"
EVENTS = DATA / "security" / "events.jsonl"
APPLY_STATUS = DATA / "security" / "apply_status.json"
SCHEMA = "mail_archiver"
_lock = threading.Lock()
_apply_lock = threading.Lock()
_apply_running = False
_loop_started = False

def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def append_event(kind, detail):
    try:
        EVENTS.parent.mkdir(parents=True, exist_ok=True)
        with EVENTS.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": _now(), "kind": kind, "detail": detail}, ensure_ascii=False) + "\n")
    except Exception:
        pass

def write_apply_status(data):
    try:
        APPLY_STATUS.parent.mkdir(parents=True, exist_ok=True)
        base = {"ts": _now()}; base.update(data)
        APPLY_STATUS.write_text(json.dumps(base, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass

def read_apply_status():
    try:
        if APPLY_STATUS.exists():
            return json.loads(APPLY_STATUS.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {"running": False}

def default_store():
    return {"version": 1, "enabled": True, "interval_minutes": 30, "rules": [], "last_run": None, "last_result": None}

def load_store():
    try:
        if RULES_FILE.exists():
            data = json.loads(RULES_FILE.read_text(encoding="utf-8"))
            base = default_store(); base.update({k: data.get(k, base[k]) for k in base})
            if not isinstance(base.get("rules"), list): base["rules"] = []
            return base
    except Exception as e:
        append_event("rules_load_error", str(e))
    return default_store()

def save_store(store):
    RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    RULES_FILE.write_text(json.dumps(store, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def parse_conn():
    cs = os.environ.get("ConnectionStrings__DefaultConnection") or os.environ.get("CONNECTION_STRING", "")
    if not cs:
        return {"host": "127.0.0.1", "port": "5432", "dbname": "MailArchiver", "user": "mailuser", "password": "mailuser"}
    parts = {}
    for bit in cs.split(";"):
        bit = bit.strip()
        if not bit or "=" not in bit: continue
        k, v = bit.split("=", 1)
        parts[k.strip().lower()] = v.strip()
    host = parts.get("host") or parts.get("server")
    if not host: return None
    return {"host": host, "port": parts.get("port", "5432"),
            "dbname": parts.get("database") or parts.get("db", "MailArchiver"),
            "user": parts.get("username") or parts.get("user") or "mailuser",
            "password": parts.get("password") or ""}

def _psql(sql, tuples_only=False):
    conn = parse_conn()
    if not conn: return 1, "keine DB-Verbindung"
    env = os.environ.copy(); env["PGPASSWORD"] = conn["password"]
    cmd = ["psql", "-h", conn["host"], "-p", str(conn["port"]), "-U", conn["user"], "-d", conn["dbname"],
           "-v", "ON_ERROR_STOP=1", "-t" if tuples_only else "-q", "-A", "-c", sql]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return 1, str(e)

def _sql_escape(s): return (s or "").replace("'", "''")

def _parse_min_age(val):
    if val in (None, "", False): return None
    try:
        days = int(val); return days if days > 0 else None
    except (TypeError, ValueError): return None

def _qident(name): return '"' + name.replace('"', '') + '"'

def _from_clause(from_mode, from_val):
    fv = _sql_escape(from_val.lower()); col = 'lower(e.' + _qident('From') + ')'
    if from_mode == "exact": return col + " = '" + fv + "'"
    if from_mode == "domain":
        dom = fv.lstrip("@")
        return "(" + col + " LIKE '%@" + dom + "' OR " + col + " LIKE '%@" + dom + ">%')"
    return col + " LIKE '%" + fv + "%'"

def _mail_date_expr():
    sent = "e." + _qident("SentDate"); recv = "e." + _qident("ReceivedDate")
    return ("CASE WHEN " + sent + " >= TIMESTAMP '1970-01-01' THEN " + sent +
            " WHEN " + recv + " >= TIMESTAMP '1970-01-01' THEN " + recv + " ELSE NULL END")

def _age_clause(days):
    expr = "(" + _mail_date_expr() + ")"
    return "(" + expr + " IS NOT NULL AND " + expr + " <= (CURRENT_TIMESTAMP - INTERVAL '" + str(int(days)) + " days'))"

def _rule_where(rule, include_age=True):
    m = rule.get("match") or {}; clauses = ["e." + _qident("IsLocked") + " = false"]; debug = {}
    account_id = m.get("account_id")
    if account_id not in (None, "", 0, "0"):
        try: clauses.append("e." + _qident("MailAccountId") + " = " + str(int(account_id)))
        except (TypeError, ValueError): pass
    from_mode = (m.get("from_mode") or "contains").lower()
    from_val = (m.get("from_value") or "").strip()
    if not from_val: return None, {"error": "from_value fehlt"}
    clauses.append(_from_clause(from_mode, from_val))
    subj = (m.get("subject_contains") or "").strip()
    if subj:
        clauses.append("lower(coalesce(e." + _qident("Subject") + ",'')) LIKE '%" + _sql_escape(subj.lower()) + "%'")
    min_age = m.get("min_age_days")
    if include_age and min_age not in (None, "", 0, "0"):
        try:
            days = max(0, int(min_age))
            if days > 0:
                clauses.append(_age_clause(days)); debug["min_age_days"] = days; debug["age_sql"] = _age_clause(days)
        except (TypeError, ValueError): pass
    return " AND ".join(clauses), debug

def _count(where):
    sql = "SELECT count(*) FROM " + SCHEMA + "." + _qident("ArchivedEmails") + " e WHERE " + where + ";"
    rc, out = _psql(sql, tuples_only=True)
    if rc != 0: return None, out[-400:]
    try: return int((out.strip().splitlines() or ["0"])[0].strip() or "0"), ""
    except ValueError: return 0, ""

def diagnose_dates():
    md = _mail_date_expr()
    sql = ("SELECT count(*), min(e." + _qident("ReceivedDate") + "), max(e." + _qident("ReceivedDate") + "), "
           "min(CASE WHEN e." + _qident("SentDate") + " >= TIMESTAMP '1970-01-01' THEN e." + _qident("SentDate") + " END), "
           "max(CASE WHEN e." + _qident("SentDate") + " >= TIMESTAMP '1970-01-01' THEN e." + _qident("SentDate") + " END), "
           "min(" + md + "), max(" + md + "), CURRENT_TIMESTAMP, CURRENT_DATE "
           "FROM " + SCHEMA + "." + _qident("ArchivedEmails") + " e;")
    rc, out = _psql(sql, tuples_only=True)
    if rc != 0: return {"ok": False, "message": out[-400:]}
    parts = (out.strip().splitlines() or [""])[0].split("|")
    while len(parts) < 9: parts.append("")
    return {"ok": True, "total_emails": parts[0].strip(), "min_received": parts[1].strip(), "max_received": parts[2].strip(),
            "min_sent_valid": parts[3].strip(), "max_sent_valid": parts[4].strip(),
            "min_mail_date": parts[5].strip(), "max_mail_date": parts[6].strip(),
            "db_now": parts[7].strip(), "db_current_date": parts[8].strip()}

def preview_rule(rule, limit=20):
    where, debug = _rule_where(rule, include_age=True)
    if not where: return {"ok": False, "message": (debug or {}).get("error", "from_value fehlt"), "count": 0, "samples": []}
    where_no_age, _ = _rule_where(rule, include_age=False)
    matched_no_age = None
    if where_no_age: matched_no_age, _ = _count(where_no_age)
    count, err = _count(where)
    if count is None: return {"ok": False, "message": err, "count": 0, "samples": [], "debug": debug}
    md = _mail_date_expr()
    sql_s = ("SELECT e." + _qident("Id") + ", left(e." + _qident("From") + ",80), "
             "left(coalesce(e." + _qident("Subject") + ",''),60), " + md + " "
             "FROM " + SCHEMA + "." + _qident("ArchivedEmails") + " e WHERE " + where + " "
             "ORDER BY " + md + " DESC NULLS LAST LIMIT " + str(int(limit)) + ";")
    rc2, out2 = _psql(sql_s, tuples_only=True)
    samples = []
    if rc2 == 0:
        for line in out2.strip().splitlines():
            if not line.strip(): continue
            parts = line.split("|")
            if len(parts) >= 3:
                samples.append({"id": parts[0].strip(), "from": parts[1].strip(),
                                "subject": parts[2].strip(), "date": parts[3].strip() if len(parts) > 3 else ""})
    return {"ok": True, "count": count, "matched_without_age": matched_no_age, "samples": samples, "debug": debug}

# PLACEHOLDER_REST_OF_FILE
