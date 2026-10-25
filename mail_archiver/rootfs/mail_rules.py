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

def _load_account(account_id):
    sql = ('SELECT e."Id"::text, coalesce(e."Name",\'\'), coalesce(e."EmailAddress",\'\'), '
           'coalesce(e."ImapServer",\'\'), coalesce(e."ImapPort"::text,\'\'), '
           'coalesce(e."Username",\'\'), coalesce(e."Password",\'\'), '
           'coalesce(e."UseSSL"::text,\'\'), coalesce(e."Provider"::text,\'\') '
           'FROM %s."MailAccounts" e WHERE e."Id" = %d;') % (SCHEMA, int(account_id))
    rc, out = _psql(sql, tuples_only=True)
    if rc != 0 or not out.strip():
        append_event("remote_account_error", (out or "empty")[-200:]); return None
    parts = out.strip().splitlines()[0].split("|")
    while len(parts) < 9: parts.append("")
    try: port = int(parts[4].strip() or 0) or None
    except ValueError: port = None
    return {"id": int(parts[0].strip() or 0), "name": parts[1].strip(), "email": parts[2].strip(),
            "imap_server": parts[3].strip(), "imap_port": port, "username": parts[5].strip(),
            "password": parts[6].strip(), "use_ssl": str(parts[7].strip()).lower() in ("t", "true", "1", "yes"),
            "provider": parts[8].strip()}

def _load_all_accounts():
    sql = ('SELECT e."Id"::text, coalesce(e."Name",\'\'), coalesce(e."EmailAddress",\'\'), '
           'coalesce(e."ImapServer",\'\'), coalesce(e."ImapPort"::text,\'\'), '
           'coalesce(e."Username",\'\'), coalesce(e."Password",\'\'), '
           'coalesce(e."UseSSL"::text,\'\'), coalesce(e."Provider"::text,\'\') '
           'FROM %s."MailAccounts" e ORDER BY e."Id";') % SCHEMA
    rc, out = _psql(sql, tuples_only=True)
    if rc != 0 or not out.strip():
        append_event("remote_accounts_error", (out or "empty")[-200:]); return []
    accs = []
    for line in out.strip().splitlines():
        if not line.strip(): continue
        parts = line.split("|");
        while len(parts) < 9: parts.append("")
        try: port = int(parts[4].strip() or 0) or None
        except ValueError: port = None
        accs.append({"id": int(parts[0].strip() or 0), "name": parts[1].strip(), "email": parts[2].strip(),
                     "imap_server": parts[3].strip(), "imap_port": port, "username": parts[5].strip(),
                     "password": parts[6].strip(), "use_ssl": str(parts[7].strip()).lower() in ("t", "true", "1", "yes"),
                     "provider": parts[8].strip()})
    return accs

def _parse_imap_list_folders(data):
    folders = []
    if not data:
        return ["INBOX"]
    for item in data:
        if item is None:
            continue
        try:
            s = item.decode("utf-8", errors="replace") if isinstance(item, (bytes, bytearray)) else str(item)
            name = None
            if s.count('"') >= 2:
                name = s.rsplit('"', 2)[-2]
            else:
                parts = s.split()
                if parts:
                    name = parts[-1].strip()
            if not name:
                continue
            name = name.strip().strip('"')
            if "\\Noselect" in s or "\\NoSelect" in s:
                continue
            if name and name not in folders:
                folders.append(name)
        except Exception:
            continue
    if "INBOX" not in folders:
        folders.insert(0, "INBOX")
    return folders or ["INBOX"]

def _imap_connect(acc):
    import imaplib, ssl
    server = (acc.get("imap_server") or "").strip()
    if not server: raise RuntimeError("kein IMAP-Server am Konto")
    password = acc.get("password") or ""
    if password.startswith("enc:"):
        raise RuntimeError("Passwort verschluesselt (enc:) – Konto-Passwort in MailArchiver neu setzen")
    user = (acc.get("username") or acc.get("email") or "").strip()
    if not user: raise RuntimeError("kein Benutzername")
    port = int(acc.get("imap_port") or (993 if acc.get("use_ssl") else 143))
    ctx = ssl.create_default_context()
    if acc.get("use_ssl") or port == 993:
        M = imaplib.IMAP4_SSL(server, port, ssl_context=ctx)
    else:
        M = imaplib.IMAP4(server, port)
        try: M.starttls(ssl_context=ctx)
        except Exception: pass
    try: M.login(user, password)
    except Exception:
        email = (acc.get("email") or "").strip()
        if email and email != user: M.login(email, password)
        else: raise
    return M

def _imap_uid_delete(M, uids):
    if not uids: return 0
    uid_list = []
    for u in uids:
        uid_list.append(u.decode("ascii", errors="ignore") if isinstance(u, (bytes, bytearray)) else str(u))
    uid_list = [u for u in uid_list if u]
    if not uid_list: return 0
    seq = ",".join(uid_list)
    M.uid("STORE", seq, "+FLAGS", r"(\Deleted)")
    try: M.uid("EXPUNGE", seq)
    except Exception:
        try: M.expunge()
        except Exception: pass
    return len(uid_list)

def _imap_before_date(days):
    d = datetime.now(timezone.utc) - timedelta(days=int(days))
    return d.strftime("%d-%b-%Y")

def _imap_build_search_criteria(rule):
    m = rule.get("match") or {}
    from_mode = (m.get("from_mode") or "contains").lower()
    from_val = (m.get("from_value") or "").strip()
    if not from_val: return []
    criteria = []
    if from_mode == "domain":
        criteria.extend(["FROM", "@" + from_val.lstrip("@")])
    else:
        criteria.extend(["FROM", from_val])
    subj = (m.get("subject_contains") or "").strip()
    if subj: criteria.extend(["SUBJECT", subj[:80]])
    min_age = _parse_min_age(m.get("min_age_days"))
    if min_age: criteria.extend(["BEFORE", _imap_before_date(min_age)])
    return criteria

def _select_folder(M, folder):
    try:
        typ, _ = M.select('"%s"' % folder.replace('"', ''), readonly=False)
        if typ == "OK": return True
        typ, _ = M.select(folder, readonly=False)
        return typ == "OK"
    except Exception:
        try:
            typ, _ = M.select(folder, readonly=False)
            return typ == "OK"
        except Exception:
            return False

def _imap_search_criteria_in_folder(M, folder, criteria):
    if not criteria or not _select_folder(M, folder):
        return []
    attempts = [
        criteria,
        [criteria[i] if i % 2 == 0 else '"%s"' % str(criteria[i]).strip('"')
         for i in range(len(criteria))] if len(criteria) >= 2 else criteria,
    ]
    for crit in attempts:
        try:
            typ, data = M.uid("SEARCH", None, *crit)
        except Exception:
            try:
                typ, data = M.uid("SEARCH", None, " ".join(str(c) for c in crit))
            except Exception:
                continue
        if typ == "OK" and data and data[0]:
            return data[0].split() or []
    return []

def _normalize_folder_list(folders):
    if not folders:
        return ["INBOX"]
    seen = set()
    uniq = []
    for f in folders:
        key = (f or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    gmail_all = None
    for f in uniq:
        fl = f.lower()
        if "[gmail]/all mail" in fl or "[gmail]/alle nachrichten" in fl:
            gmail_all = f
            break
    if gmail_all:
        out = [gmail_all]
        for f in uniq:
            fl = f.lower()
            if f == gmail_all:
                continue
            if fl in ("inbox", "posteingang"):
                continue
            if fl.startswith("[gmail]/"):
                if any(x in fl for x in ("spam", "trash", "papierkorb", "müll", "muell")):
                    out.append(f)
                continue
            out.append(f)
        return out[:40]
    preferred = ["INBOX", "Posteingang"]
    ordered = []
    for f in preferred + uniq:
        key = f.strip().lower()
        if any(x.strip().lower() == key for x in ordered):
            continue
        ordered.append(f)
    return ordered[:40]

def _imap_purge_rule_on_account(acc, rule, dry_run=False):
    criteria = _imap_build_search_criteria(rule)
    if not criteria:
        return {"ok": False, "message": "keine Suchkriterien", "deleted": 0, "matched": 0,
                "account": acc.get("name") or acc.get("email")}
    try:
        M = _imap_connect(acc)
    except Exception as e:
        return {"ok": False, "deleted": 0, "matched": 0, "message": "IMAP login: %s" % e,
                "account": acc.get("name") or acc.get("email")}
    folders_hit, deleted, matched, errors = [], 0, 0, []
    scanned_folders = []
    try:
        folder_raw = []
        for list_cmd in ("list", "lsub"):
            try:
                typ, data = getattr(M, list_cmd)()
                if typ == "OK" and data:
                    folder_raw.extend(data)
            except Exception:
                pass
        try:
            typ, data = M.list("", "*")
            if typ == "OK" and data:
                folder_raw.extend(data)
        except Exception:
            pass
        folders = _parse_imap_list_folders(folder_raw if folder_raw else None)
        ordered = _normalize_folder_list(folders)
        scanned_folders = list(ordered)
        for i_f, folder in enumerate(ordered):
            try:
                write_apply_status({
                    "running": True, "phase": "remote_imap_scan",
                    "message": "IMAP-Scan %s · Ordner %s (%d/%d)" % (
                        acc.get("name") or "?", folder, i_f + 1, len(ordered)),
                    "remote_account": acc.get("name") or acc.get("email"),
                    "remote_folder": folder,
                })
            except Exception:
                pass
            try:
                uids = _imap_search_criteria_in_folder(M, folder, criteria)
            except Exception as e:
                errors.append("%s: %s" % (folder, e))
                continue
            if not uids:
                continue
            uid_set = []
            seen_u = set()
            for u in uids:
                key = u.decode("ascii", errors="ignore") if isinstance(u, (bytes, bytearray)) else str(u)
                if key in seen_u:
                    continue
                seen_u.add(key)
                uid_set.append(u)
            matched += len(uid_set)
            folders_hit.append({"folder": folder, "count": len(uid_set)})
            if dry_run:
                continue
            try:
                n = _imap_uid_delete(M, uid_set)
                deleted += n
                append_event("remote_imap_purge", "acc=%s folder=%s n=%d rule=%s" % (
                    acc.get("name"), folder, n, rule.get("name") or rule.get("id")))
            except Exception as e:
                errors.append("delete %s: %s" % (folder, e))
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
    return {
        "ok": True,
        "deleted": deleted if not dry_run else 0,
        "matched": matched,
        "dry_run": dry_run,
        "folders": folders_hit[:20],
        "scanned_folders": scanned_folders[:30],
        "errors": errors[:8],
        "account": acc.get("name") or acc.get("email"),
        "account_id": acc.get("id"),
        "criteria": " ".join(str(c) for c in criteria),
    }

def remote_purge_by_rule(rule, dry_run=False):
    if rule.get("delete_remote") is False:
        return {"ok": True, "skipped": True, "remote_deleted": 0, "remote_matched": 0, "accounts": []}
    m = rule.get("match") or {}; account_id = m.get("account_id"); accounts = []
    if account_id not in (None, "", 0, "0"):
        try:
            acc = _load_account(int(account_id))
            if acc: accounts = [acc]
        except (TypeError, ValueError): accounts = []
    else:
        accounts = _load_all_accounts()
    if not accounts:
        append_event("remote_purge", "no accounts")
        return {"ok": True, "remote_deleted": 0, "remote_matched": 0, "accounts": [], "message": "keine IMAP-Konten"}
    results, total_del, total_match = [], 0, 0
    for acc in accounts:
        if not acc.get("imap_server"):
            results.append({"ok": False, "account": acc.get("name"), "message": "kein IMAP-Server", "deleted": 0, "matched": 0})
            continue
        r = _imap_purge_rule_on_account(acc, rule, dry_run=dry_run)
        results.append(r)
        total_del += int(r.get("deleted") or 0)
        total_match += int(r.get("matched") or 0)
        append_event("remote_purge", "account=%s matched=%s deleted=%s dry=%s" % (
            acc.get("name"), r.get("matched"), r.get("deleted"), dry_run))
    return {"ok": True, "remote_deleted": total_del, "remote_matched": total_match, "dry_run": dry_run,
            "accounts": results, "candidates": total_match}

def apply_rule(rule, dry_run=False):
    prev = preview_rule(rule, limit=10)
    if not prev.get("ok"):
        return {"ok": False, "message": prev.get("message"), "deleted": 0, "matched": 0}
    count = int(prev.get("count") or 0)
    where, debug = _rule_where(rule, include_age=True)
    if not where: return {"ok": False, "message": "where fehlt", "deleted": 0}
    remote_info = None
    do_remote = rule.get("delete_remote") is not False
    if do_remote:
        try:
            remote_info = remote_purge_by_rule(rule, dry_run=dry_run)
            append_event("remote_purge_result", "matched=%s deleted=%s dry=%s" % (
                (remote_info or {}).get("remote_matched"), (remote_info or {}).get("remote_deleted"), dry_run))
        except Exception as e:
            remote_info = {"ok": False, "message": str(e), "remote_deleted": 0, "remote_matched": 0}
            append_event("remote_purge_error", str(e))
    if dry_run:
        return {"ok": True, "deleted": 0, "matched": count, "matched_without_age": prev.get("matched_without_age"),
                "dry_run": True, "samples": prev.get("samples") or [], "debug": debug,
                "delete_remote": do_remote, "remote": remote_info}
    deleted_local = 0
    if count > 0:
        att = SCHEMA + "." + _qident("EmailAttachments")
        em = SCHEMA + "." + _qident("ArchivedEmails")
        sql = ("BEGIN;\nDELETE FROM " + att + " a USING " + em + " e "
               "WHERE a." + _qident("ArchivedEmailId") + " = e." + _qident("Id") + " AND " + where + ";\n"
               "DELETE FROM " + em + " e WHERE " + where + ";\nCOMMIT;\n")
        rc, out = _psql(sql)
        if rc != 0:
            append_event("rule_apply_error", "%s: %s" % (rule.get("name"), out[-200:]))
            return {"ok": False, "message": out[-400:], "deleted": 0, "matched": count, "remote": remote_info, "delete_remote": do_remote}
        deleted_local = count
        append_event("rule_apply_ok", "rule=%s deleted_local≈%d" % (rule.get("name") or rule.get("id"), count))
    else:
        append_event("rule_apply_ok", "rule=%s local=0 remote_scan=1" % (rule.get("name") or rule.get("id")))
    result = {"ok": True, "deleted": deleted_local, "matched": count, "dry_run": False,
              "matched_without_age": prev.get("matched_without_age"), "samples": prev.get("samples") or [],
              "delete_remote": do_remote, "debug": debug}
    if remote_info is not None: result["remote"] = remote_info
    return result

def apply_all_rules(dry_run=False, force=False):
    global _apply_running
    with _apply_lock:
        if _apply_running and not force:
            st = read_apply_status()
            return {"ok": False, "message": "Regeln laufen bereits", "apply_running": True, "status": st}
        _apply_running = True
    write_apply_status({"running": True, "dry_run": dry_run, "phase": "start",
        "message": "Vorschau…" if dry_run else "Löschen gestartet…", "progress": 0})
    try:
        store = load_store()
        if not store.get("enabled", True) and not dry_run:
            write_apply_status({"running": False, "message": "Regeln global deaktiviert"})
            return {"ok": True, "message": "Regeln global deaktiviert", "results": [], "summary": {}}
        rules = [r for r in (store.get("rules") or []) if r.get("enabled", True)]
        results = []; total = 0
        write_apply_status({"running": True, "dry_run": dry_run, "phase": "rules",
            "message": "%d Regeln" % len(rules), "rules_total": len(rules), "rules_done": 0, "progress": 0})
        for idx, rule in enumerate(rules):
            action = (rule.get("action") or "delete_local").lower()
            if action not in ("delete_local", "delete", "purge"):
                results.append({"id": rule.get("id"), "skipped": True, "reason": "unknown action"}); continue
            write_apply_status({"running": True, "dry_run": dry_run, "phase": "rule",
                "message": "Regel: %s" % (rule.get("name") or rule.get("id")),
                "current_rule": rule.get("name"), "rules_total": len(rules), "rules_done": idx,
                "progress": int(100 * idx / max(1, len(rules)))})
            r = apply_rule(rule, dry_run=dry_run)
            r["id"] = rule.get("id"); r["name"] = rule.get("name"); results.append(r)
            total += int(r.get("deleted") or 0)
            rem = r.get("remote") or {}
            write_apply_status({"running": True, "dry_run": dry_run, "phase": "rule_done",
                "message": "Fertig: %s · lokal≈%s remote≈%s" % (rule.get("name"), r.get("deleted"), rem.get("remote_deleted")),
                "current_rule": rule.get("name"), "rules_total": len(rules), "rules_done": idx + 1,
                "progress": int(100 * (idx + 1) / max(1, len(rules))),
                "last_rule_result": {"name": rule.get("name"), "matched": r.get("matched"), "deleted": r.get("deleted"), "remote": rem}})
        remote_total = remote_candidates = local_matched = 0
        account_map = {}; rule_lines = []
        for r in results:
            if r.get("skipped"): continue
            local_matched += int(r.get("matched") or r.get("deleted") or 0)
            rem = r.get("remote") or {}
            rule_lines.append({"name": r.get("name") or r.get("id"), "matched": r.get("matched"),
                "deleted_local": r.get("deleted") if not dry_run else 0,
                "remote_matched": rem.get("remote_matched"), "remote_deleted": rem.get("remote_deleted"),
                "dry_run": dry_run, "ok": r.get("ok")})
            remote_total += int(rem.get("remote_deleted") or 0)
            remote_candidates += int(rem.get("remote_matched") or rem.get("candidates") or 0)
            for a in rem.get("accounts") or []:
                key = str(a.get("account") or a.get("account_id") or "?")
                row = account_map.setdefault(key, {"account": key, "remote_deleted": 0, "candidates": 0, "matched": 0, "ok": True, "errors": [], "folders": [], "scanned_folders": []})
                row["remote_deleted"] += int(a.get("deleted") or 0)
                row["candidates"] += int(a.get("matched") or a.get("candidates") or 0)
                row["matched"] += int(a.get("matched") or 0)
                if a.get("ok") is False: row["ok"] = False
                for e in (a.get("errors") or [])[:3]:
                    if e not in row["errors"]: row["errors"].append(str(e))
                for f in (a.get("folders") or [])[:5]: row["folders"].append(f)
                for sf in (a.get("scanned_folders") or [])[:15]:
                    if sf not in row["scanned_folders"]: row["scanned_folders"].append(sf)
        summary = {"dry_run": dry_run, "rules_processed": len(results), "local_matched": local_matched,
                   "local_deleted": total if not dry_run else 0, "remote_candidates": remote_candidates,
                   "remote_deleted": remote_total, "accounts": list(account_map.values()), "rules": rule_lines}
        out = {"ok": True, "deleted": total, "dry_run": dry_run, "results": results, "summary": summary,
               "date_stats": diagnose_dates()}
        store["last_run"] = _now(); store["last_result"] = {"deleted": total, "dry_run": dry_run, "summary": summary}
        save_store(store)
        write_apply_status({"running": False, "dry_run": dry_run, "phase": "done",
            "message": "Fertig · lokal %s · remote %s" % (total if not dry_run else local_matched, remote_total),
            "progress": 100, "result": out, "summary": summary})
        append_event("rules_apply", "deleted=%s dry=%s remote=%s" % (total, dry_run, remote_total))
        return out
    except Exception as e:
        write_apply_status({"running": False, "message": "Fehler: %s" % e, "error": str(e)})
        append_event("rules_apply_error", str(e))
        return {"ok": False, "message": str(e), "results": []}
    finally:
        with _apply_lock:
            _apply_running = False

def start_apply_async(dry_run=False):
    global _apply_running
    with _apply_lock:
        if _apply_running:
            return {"ok": False, "message": "Regeln laufen bereits", "apply_running": True, "status": read_apply_status()}
    def _run():
        apply_all_rules(dry_run=dry_run, force=True)
    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "started": True, "dry_run": dry_run, "message": "gestartet"}

def list_rules():
    store = load_store()
    return {
        "ok": True,
        "enabled": bool(store.get("enabled", True)),
        "interval_minutes": int(store.get("interval_minutes") or 30),
        "rules": store.get("rules") or [],
        "last_run": store.get("last_run"),
        "last_result": store.get("last_result"),
        "apply_status": read_apply_status(),
    }

def update_settings(enabled=None, interval_minutes=None):
    store = load_store()
    if enabled is not None: store["enabled"] = bool(enabled)
    if interval_minutes is not None:
        try: store["interval_minutes"] = max(5, int(interval_minutes))
        except (TypeError, ValueError): pass
    save_store(store); return {"ok": True, "store": store}

def set_settings(data):
    data = data or {}
    return update_settings(enabled=data.get("enabled"), interval_minutes=data.get("interval_minutes"))

def upsert_rule(data):
    store = load_store(); rules = store.get("rules") or []; rid = (data.get("id") or "").strip()
    match_in = data.get("match") if isinstance(data.get("match"), dict) else {}
    rule = {"id": rid or str(uuid.uuid4()), "name": (data.get("name") or "Regel").strip() or "Regel",
            "enabled": bool(data.get("enabled", True)),
            "match": {"from_mode": (data.get("from_mode") or match_in.get("from_mode") or "contains"),
                      "from_value": (data.get("from_value") or match_in.get("from_value") or "").strip(),
                      "subject_contains": (data.get("subject_contains") or match_in.get("subject_contains") or "").strip(),
                      "min_age_days": _parse_min_age(data.get("min_age_days") if "min_age_days" in data else match_in.get("min_age_days")),
                      "account_id": (data.get("account_id") if "account_id" in data else match_in.get("account_id"))},
            "action": data.get("action") or "delete_local", "delete_remote": bool(data.get("delete_remote", True))}
    if not rule["match"]["from_value"]: return {"ok": False, "message": "Absender/Domain erforderlich"}
    found = False
    for i, r in enumerate(rules):
        if r.get("id") == rule["id"]:
            rules[i] = rule; found = True; break
    if not found: rules.append(rule)
    store["rules"] = rules; save_store(store)
    return {"ok": True, "rule": rule}

def delete_rule(rule_id):
    store = load_store()
    store["rules"] = [r for r in (store.get("rules") or []) if r.get("id") != rule_id]
    save_store(store); return {"ok": True}

def start_background_loop():
    global _loop_started
    if _loop_started: return
    _loop_started = True
    def _loop():
        import time
        while True:
            try:
                store = load_store()
                mins = int(store.get("interval_minutes") or 30)
                time.sleep(max(60, mins * 60))
                if store.get("enabled", True):
                    apply_all_rules(dry_run=False, force=False)
            except Exception as e:
                append_event("rules_loop_error", str(e))
                time.sleep(120)
    threading.Thread(target=_loop, daemon=True).start()
    append_event("rules_loop_started", "ok")
