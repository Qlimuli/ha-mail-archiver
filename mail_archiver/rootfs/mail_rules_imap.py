"""IMAP helpers for remote mail purge."""
from __future__ import annotations
import re
from datetime import datetime, timedelta, timezone

def _parse_imap_list_folders(data):
    """Parse IMAP LIST/LSUB responses into selectable mailbox names.

    Handles quoted names, hierarchical delimiters and unquoted names.
    Skips \\Noselect parents and pure delimiter placeholders.
    """
    folders = []
    if not data:
        return ["INBOX"]
    re_line = re.compile(
        r'^\s*\((?P<flags>[^)]*)\)\s+'
        r'(?:"(?P<delim>[^"]*)"|NIL)\s+'
        r'(?:"(?P<qname>(?:[^"\\]|\\.)*)"|(?P<uname>\S+))\s*$',
        re.IGNORECASE | re.DOTALL,
    )
    for item in data:
        if item is None:
            continue
        try:
            s = item.decode("utf-8", errors="replace") if isinstance(item, (bytes, bytearray)) else str(item)
            s = s.strip()
            if not s:
                continue
            if "\\noselect" in s.lower():
                continue
            name = None
            m = re_line.match(s)
            if m:
                name = m.group("qname") if m.group("qname") is not None else m.group("uname")
                if name:
                    name = name.replace(r'\"', '"').replace(r'\\', '\\')
            if not name:
                if s.count('"') >= 2:
                    name = s.rsplit('"', 2)[-2]
                else:
                    parts = s.split()
                    if parts:
                        name = parts[-1].strip()
            if not name:
                continue
            name = name.strip().strip('"').strip()
            if not name or name in ("/", ".", "\\"):
                continue
            if name not in folders:
                folders.append(name)
        except Exception:
            continue
    seen = set()
    out = []
    for f in folders:
        key = f.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    if not any(f.lower() == "inbox" for f in out):
        out.insert(0, "INBOX")
    return out or ["INBOX"]

def _normalize_folder_list(folders, max_folders=200):
    """Order folders for remote purge scans.

    Gmail: prefer All Mail (covers labels) + Spam/Trash; skip duplicate Inbox.
    Other providers: scan every selectable mailbox (INBOX first), up to max_folders.
    """
    if not folders:
        return ["INBOX"]
    seen = set()
    uniq = []
    for f in folders:
        key = (f or "").strip().lower()
        if not key or key in seen:
            continue
        if key in ("/", ".", "\\", ""):
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
                if any(x in fl for x in (
                    "spam", "trash", "papierkorb", "müll", "muell", "junk", "bin", "deleted"
                )):
                    out.append(f)
                continue
            out.append(f)
        return out[: max(1, int(max_folders))]
    preferred = ("INBOX", "Posteingang", "Inbox", "INBOX.Spam", "Spam", "Junk",
                 "Trash", "Papierkorb", "Deleted", "Deleted Items", "Spamverdacht")
    ordered = []
    for f in list(preferred) + list(uniq):
        key = (f or "").strip().lower()
        if not key:
            continue
        if any(x.strip().lower() == key for x in ordered):
            continue
        ordered.append(f)
    return ordered[: max(1, int(max_folders))]
