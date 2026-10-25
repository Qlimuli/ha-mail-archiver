#!/usr/bin/env python3
"""Mail rules: auto-delete archived mails by sender (subject/age) + optional IMAP remote."""
from __future__ import annotations

import json
import os
import re
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


def _qident(name: str) -> str:
    return '"' + name.replace('"', '') + '"'


def _from_clause(from_mode: str, from_val: str) -> str:
    fv = _sql_escape(from_val.lower())
    col = 'lower(e.' + _qident('From') + ')'
    if from_mode == "exact":
        return col + " = '" + fv + "'"
    if from_mode == "domain":
        dom = fv.lstrip("@")
        return "(" + col + " LIKE '%@" + dom + "' OR " + col + " LIKE '%@" + dom + ">%')"
    return col + " LIKE '%" + fv + "%'"


def _mail_date_expr() -> str:
    sent = "e." + _qident("SentDate")
    recv = "e." + _qident("ReceivedDate")
    return (
        "CASE "
        "WHEN " + sent + " >= TIMESTAMP '1970-01-01' THEN " + sent + " "
        "WHEN " + recv + " >= TIMESTAMP '1970-01-01' THEN " + recv + " "
        "ELSE NULL END"
    )


def _age_clause(days: int) -> str:
    expr = "(" + _mail_date_expr() + ")"
    return (
        "(" + expr + " IS NOT NULL AND "
        + expr + " <= (CURRENT_TIMESTAMP - INTERVAL '" + str(int(days)) + " days'))"
    )


def _rule_where(rule: dict, include_age: bool = True):
    m = rule.get("match") or {}
    clauses = ["e." + _qident("IsLocked") + " = false"]
    debug = {}
    account_id = m.get("account_id")
    if account_id not in (None, "", 0, "0"):
        try:
            clauses.append("e." + _qident("MailAccountId") + " = " + str(int(account_id)))
        except (TypeError, ValueError):
            pass
    from_mode = (m.get("from_mode") or "contains").lower()
    from_val = (m.get("from_value") or "").strip()
    if not from_val:
        return None, {"error": "from_value fehlt"}
    clauses.append(_from_clause(from_mode, from_val))
    subj = (m.get("subject_contains") or "").strip()
    if subj:
        clauses.append(
            "lower(coalesce(e." + _qident("Subject") + ",'')) LIKE '%"
            + _sql_escape(subj.lower()) + "%'"
        )
    min_age = m.get("min_age_days")
    if include_age and min_age not in (None, "", 0, "0"):
        try:
            days = max(0, int(min_age))
            if days > 0:
                clauses.append(_age_clause(days))
                debug["min_age_days"] = days
                debug["age_sql"] = _age_clause(days)
        except (TypeError, ValueError):
            pass
    return " AND ".join(clauses), debug


def _count(where: str):
    sql = "SELECT count(*) FROM " + SCHEMA + "." + _qident("ArchivedEmails") + " e WHERE " + where + ";"
    rc, out = _psql(sql, tuples_only=True)
    if rc != 0:
        return None, out[-400:]
    try:
        return int((out.strip().splitlines() or ["0"])[0].strip() or "0"), ""
    except ValueError:
        return 0, ""


def diagnose_dates() -> dict:
    md = _mail_date_expr()
    sql = (
        "SELECT count(*), "
        "min(e." + _qident("ReceivedDate") + "), max(e." + _qident("ReceivedDate") + "), "
        "min(CASE WHEN e." + _qident("SentDate") + " >= TIMESTAMP '1970-01-01' THEN e." + _qident("SentDate") + " END), "
        "max(CASE WHEN e." + _qident("SentDate") + " >= TIMESTAMP '1970-01-01' THEN e." + _qident("SentDate") + " END), "
        "min(" + md + "), max(" + md + "), "
        "CURRENT_TIMESTAMP, CURRENT_DATE "
        "FROM " + SCHEMA + "." + _qident("ArchivedEmails") + " e;"
    )
    rc, out = _psql(sql, tuples_only=True)
    if rc != 0:
        return {"ok": False, "message": out[-400:]}
    parts = (out.strip().splitlines() or [""])[0].split("|")
    while len(parts) < 9:
        parts.append("")
    return {
        "ok": True, "total_emails": parts[0].strip(),
        "min_received": parts[1].strip(), "max_received": parts[2].strip(),
        "min_sent_valid": parts[3].strip(), "max_sent_valid": parts[4].strip(),
        "min_mail_date": parts[5].strip(), "max_mail_date": parts[6].strip(),
        "db_now": parts[7].strip(), "db_current_date": parts[8].strip(),
    }


def preview_rule(rule: dict, limit: int = 20) -> dict:
    where, debug = _rule_where(rule, include_age=True)
    if not where:
        return {"ok": False, "message": (debug or {}).get("error", "from_value fehlt"), "count": 0, "samples": []}
    where_no_age, _ = _rule_where(rule, include_age=False)
    matched_no_age = None
    if where_no_age:
        matched_no_age, _ = _count(where_no_age)
    count, err = _count(where)
    if count is None:
        return {"ok": False, "message": err, "count": 0, "samples": [], "debug": debug}
    md = _mail_date_expr()
    sql_s = (
        "SELECT e." + _qident("Id") + ", left(e." + _qident("From") + ",80), "
        "left(coalesce(e." + _qident("Subject") + ",''),60), " + md + " "
        "FROM " + SCHEMA + "." + _qident("ArchivedEmails") + " e WHERE " + where + " "
        "ORDER BY " + md + " DESC NULLS LAST LIMIT " + str(int(limit)) + ";"
    )
    rc2, out2 = _psql(sql_s, tuples_only=True)
    samples = []
    if rc2 == 0:
        for line in out2.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) >= 3:
                samples.append({"id": parts[0].strip(), "from": parts[1].strip(),
                                "subject": parts[2].strip(), "date": parts[3].strip() if len(parts) > 3 else ""})
    return {"ok": True, "count": count, "matched_without_age": matched_no_age,
            "samples": samples, "debug": debug}


def _load_account(account_id: int) -> dict | None:
    sql = (
        'SELECT e."Id"::text, coalesce(e."Name",\'\'), coalesce(e."EmailAddress",\'\'), '
        'coalesce(e."ImapServer",\'\'), coalesce(e."ImapPort"::text,\'\'), '
        'coalesce(e."Username",\'\'), coalesce(e."Password",\'\'), '
        'coalesce(e."UseSSL"::text,\'\'), coalesce(e."Provider"::text,\'\') '
        'FROM %s."MailAccounts" e WHERE e."Id" = %d;'
    ) % (SCHEMA, int(account_id))
    rc, out = _psql(sql, tuples_only=True)
    if rc != 0 or not out.strip():
        append_event("remote_account_error", (out or "empty")[-200:])
        return None
    parts = out.strip().splitlines()[0].split("|")
    while len(parts) < 9:
        parts.append("")
    try:
        port = int(parts[4].strip() or 0) or None
    except ValueError:
        port = None
    return {
        "id": int(parts[0].strip() or 0), "name": parts[1].strip(), "email": parts[2].strip(),
        "imap_server": parts[3].strip(), "imap_port": port,
        "username": parts[5].strip(), "password": parts[6].strip(),
        "use_ssl": str(parts[7].strip()).lower() in ("t", "true", "1", "yes"),
        "provider": parts[8].strip(),
    }


def _fetch_match_meta(where: str, limit: int = 5000) -> list:
    sql = (
        'SELECT e."Id", e."MailAccountId", coalesce(e."MessageId",\'\'), '
        'coalesce(e."FolderName",\'INBOX\'), left(e."From",120), left(coalesce(e."Subject",\'\'),120) '
        'FROM %s."ArchivedEmails" e WHERE %s ORDER BY e."Id" LIMIT %d;'
    ) % (SCHEMA, where, int(limit))
    rc, out = _psql(sql, tuples_only=True)
    if rc != 0:
        append_event("remote_meta_error", out[-200:])
        return []
    rows = []
    for line in out.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        while len(parts) < 6:
            parts.append("")
        try:
            rows.append({"id": int(parts[0].strip()), "account_id": int(parts[1].strip() or 0),
                         "message_id": parts[2].strip(), "folder": parts[3].strip() or "INBOX",
                         "from": parts[4].strip(), "subject": parts[5].strip()})
        except ValueError:
            continue
    return rows


def _parse_imap_list_folders(data) -> list:
    folders = []
    if not data:
        return ["INBOX"]
    for item in data:
        if item is None:
            continue
        try:
            s = item.decode("utf-8", errors="replace") if isinstance(item, (bytes, bytearray)) else str(item)
            if s.count('"') >= 2:
                name = s.rsplit('"', 2)[-2]
            else:
                name = s.split()[-1].strip()
            name = name.strip().strip('"')
            if name and name not in folders:
                folders.append(name)
        except Exception:
            continue
    if "INBOX" not in folders:
        folders.insert(0, "INBOX")
    return folders or ["INBOX"]


def _mid_variants(message_id: str) -> list:
    mid = (message_id or "").strip()
    if not mid:
        return []
    bare = mid.strip("<>").strip()
    variants = []
    for v in (mid, bare, "<%s>" % bare):
        if v and v not in variants:
            variants.append(v)
    return variants


def _imap_connect(acc: dict):
    import imaplib
    import ssl
    server = (acc.get("imap_server") or "").strip()
    if not server:
        raise RuntimeError("kein IMAP-Server am Konto")
    password = acc.get("password") or ""
    if password.startswith("enc:"):
        raise RuntimeError("Passwort verschluesselt (enc:) – Konto-Passwort in MailArchiver neu setzen")
    user = (acc.get("username") or acc.get("email") or "").strip()
    if not user:
        raise RuntimeError("kein Benutzername")
    port = int(acc.get("imap_port") or (993 if acc.get("use_ssl") else 143))
    ctx = ssl.create_default_context()
    if acc.get("use_ssl") or port == 993:
        M = imaplib.IMAP4_SSL(server, port, ssl_context=ctx)
    else:
        M = imaplib.IMAP4(server, port)
        try:
            M.starttls(ssl_context=ctx)
        except Exception:
            pass
    try:
        M.login(user, password)
    except Exception:
        email = (acc.get("email") or "").strip()
        if email and email != user:
            M.login(email, password)
        else:
            raise
    return M


def _imap_uid_delete(M, uids) -> int:
    if not uids:
        return 0
    uid_list = []
    for u in uids:
        if isinstance(u, (bytes, bytearray)):
            uid_list.append(u.decode("ascii", errors="ignore"))
        else:
            uid_list.append(str(u))
    uid_list = [u for u in uid_list if u]
    if not uid_list:
        return 0
    seq = ",".join(uid_list)
    M.uid("STORE", seq, "+FLAGS", r"(\Deleted)")
    try:
        M.uid("EXPUNGE", seq)
    except Exception:
        try:
            M.expunge()
        except Exception:
            pass
    return len(uid_list)


def _search_uid_in_folder(M, folder: str, item: dict) -> list:
    try:
        typ, _ = M.select('"%s"' % folder.replace('"', ''), readonly=False)
        if typ != "OK":
            typ, _ = M.select(folder, readonly=False)
        if typ != "OK":
            return []
    except Exception:
        try:
            typ, _ = M.select(folder, readonly=False)
            if typ != "OK":
                return []
        except Exception:
            return []
    for v in _mid_variants(item.get("message_id") or ""):
        try:
            typ, data = M.uid("SEARCH", None, "HEADER", "Message-ID", v)
        except Exception:
            continue
        if typ == "OK" and data and data[0]:
            uids = data[0].split()
            if uids:
                return uids
    subj = (item.get("subject") or "").strip()
    frm = (item.get("from") or "").strip()
    if subj and len(subj) > 3:
        try:
            typ, data = M.uid("SEARCH", None, "HEADER", "Subject", subj[:80])
            if typ == "OK" and data and data[0]:
                uids = data[0].split()
                if len(uids) == 1:
                    return uids
                if frm and "@" in frm:
                    m = re.search(r"[\w.+-]+@[\w.-]+", frm)
                    addr = m.group(0) if m else frm
                    typ2, data2 = M.uid("SEARCH", None, "HEADER", "Subject", subj[:80], "FROM", addr)
                    if typ2 == "OK" and data2 and data2[0]:
                        uids2 = data2[0].split()
                        if uids2:
                            return uids2
        except Exception:
            pass
    return []


def _imap_delete_for_account(acc: dict, items: list) -> dict:
    deleted = 0
    not_found = 0
    errors = []
    tried_folders = []
    try:
        M = _imap_connect(acc)
    except Exception as e:
        return {"ok": False, "deleted": 0, "message": "IMAP login: %s" % e, "account": acc.get("name")}
    try:
        typ, data = M.list()
        folders = _parse_imap_list_folders(data if typ == "OK" else None)
        preferred = []
        for it in items:
            f = (it.get("folder") or "").strip()
            if f and f not in preferred:
                preferred.append(f)
        ordered = []
        for f in preferred + folders:
            if f not in ordered:
                ordered.append(f)
        tried_folders = ordered[:40]
        for it in items:
            found = False
            search_order = []
            if it.get("folder"):
                search_order.append(it["folder"])
            for f in ordered:
                if f not in search_order:
                    search_order.append(f)
            for folder in search_order:
                uids = _search_uid_in_folder(M, folder, it)
                if not uids:
                    continue
                try:
                    n = _imap_uid_delete(M, uids)
                    deleted += n
                    found = True
                    append_event("remote_delete_ok", "acc=%s folder=%s mid=%s n=%d" % (
                        acc.get("name"), folder, (it.get("message_id") or "")[:60], n))
                    break
                except Exception as e:
                    errors.append("delete %s: %s" % (folder, e))
            if not found:
                not_found += 1
        try:
            M.logout()
        except Exception:
            pass
    except Exception as e:
        errors.append(str(e))
        try:
            M.logout()
        except Exception:
            pass
    return {"ok": True, "deleted": deleted, "not_found": not_found, "errors": errors[:8],
            "folders_tried": tried_folders[:15], "account": acc.get("name") or acc.get("email"),
            "candidates": len(items)}


def remote_delete_matched(where: str) -> dict:
    rows = _fetch_match_meta(where, limit=5000)
    if not rows:
        append_event("remote_delete", "no candidates")
        return {"ok": True, "remote_deleted": 0, "accounts": [], "candidates": 0}
    by_acc = {}
    for r in rows:
        by_acc.setdefault(r["account_id"], []).append(r)
    results = []
    total = 0
    for acc_id, items in by_acc.items():
        acc = _load_account(acc_id)
        if not acc:
            results.append({"account_id": acc_id, "ok": False, "message": "Konto nicht gefunden"})
            continue
        if not acc.get("imap_server"):
            results.append({"account_id": acc_id, "ok": False,
                            "message": "Kein IMAP-Server (Provider=%s)" % acc.get("provider"),
                            "account": acc.get("name")})
            continue
        r = _imap_delete_for_account(acc, items)
        r["account_id"] = acc_id
        results.append(r)
        total += int(r.get("deleted") or 0)
        append_event("remote_delete", "account=%s deleted=%s not_found=%s" % (
            acc.get("name"), r.get("deleted"), r.get("not_found")))
    return {"ok": True, "remote_deleted": total, "accounts": results, "candidates": len(rows)}


def apply_rule(rule: dict, dry_run: bool = False) -> dict:
    where, debug = _rule_where(rule, include_age=True)
    if not where:
        return {"ok": False, "message": "ungueltige Regel", "deleted": 0}
    prev = preview_rule(rule, limit=5)
    if not prev.get("ok"):
        return {"ok": False, "message": prev.get("message", "preview failed"), "deleted": 0}
    count = int(prev.get("count") or 0)
    if dry_run or count == 0:
        return {"ok": True, "deleted": 0, "matched": count, "matched_without_age": prev.get("matched_without_age"),
                "dry_run": dry_run, "samples": prev.get("samples") or [], "debug": debug,
                "delete_remote": rule.get("delete_remote") is not False}
    remote_info = None
    if rule.get("delete_remote") is not False:
        try:
            remote_info = remote_delete_matched(where)
            append_event("remote_delete_result", str((remote_info or {}).get("remote_deleted")))
        except Exception as e:
            remote_info = {"ok": False, "message": str(e), "remote_deleted": 0}
            append_event("remote_delete_error", str(e))
    att = SCHEMA + "." + _qident("EmailAttachments")
    em = SCHEMA + "." + _qident("ArchivedEmails")
    sql = (
        "BEGIN;\n"
        "DELETE FROM " + att + " a USING " + em + " e "
        "WHERE a." + _qident("ArchivedEmailId") + " = e." + _qident("Id") + " AND " + where + ";\n"
        "DELETE FROM " + em + " e WHERE " + where + ";\n"
        "COMMIT;\n"
    )
    rc, out = _psql(sql)
    if rc != 0:
        append_event("rule_apply_error", "%s: %s" % (rule.get("name"), out[-200:]))
        return {"ok": False, "message": out[-400:], "deleted": 0, "matched": count, "remote": remote_info}
    append_event("rule_apply_ok", "rule=%s deleted≈%d" % (rule.get("name") or rule.get("id"), count))
    result = {"ok": True, "deleted": count, "matched": count, "dry_run": False,
              "samples": prev.get("samples") or [], "delete_remote": rule.get("delete_remote") is not False}
    if remote_info is not None:
        result["remote"] = remote_info
    return result


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
        return {"ok": True, "deleted": total, "dry_run": dry_run, "results": results, "date_stats": diagnose_dates()}
    finally:
        with _apply_lock:
            _apply_running = False


def list_rules() -> dict:
    store = load_store()
    return {"ok": True, "enabled": store.get("enabled", True),
            "interval_minutes": store.get("interval_minutes", 30),
            "last_run": store.get("last_run"), "last_result": store.get("last_result"),
            "rules": store.get("rules") or [], "apply_running": _apply_running,
            "date_stats": diagnose_dates()}


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
        "delete_remote": bool(data.get("delete_remote", True)),
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
