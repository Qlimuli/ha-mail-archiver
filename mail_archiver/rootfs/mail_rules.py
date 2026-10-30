#!/usr/bin/env python3
"""Mail rules engine – loads zlib/base64 parts from same directory (or /)."""
from __future__ import annotations
import base64, zlib, sys
from pathlib import Path

def _load():
    candidates = []
    here = Path(__file__).resolve().parent
    for d in (here, Path("/"), Path("/app")):
        found = sorted(d.glob("mail_rules_part*.b64"))
        if found:
            candidates = found
            break
    if not candidates:
        raise ImportError(
            "mail_rules_part*.b64 missing (next to mail_rules.py or in /). "
            "Rebuild the add-on image so Dockerfile COPY includes the part files."
        )
    b64 = "".join(p.read_text(encoding="ascii").strip() for p in candidates)
    # tolerate whitespace / newlines
    b64 = "".join(b64.split())
    # pad base64 if needed
    pad = (-len(b64)) % 4
    if pad:
        b64 += "=" * pad
    code = zlib.decompress(base64.b64decode(b64)).decode("utf-8")
    exec(compile(code, "mail_rules_body.py", "exec"), globals())

try:
    _load()
except Exception as e:
    # Do not crash security_ui – expose stubs so /security/ still serves
    print("[mail_rules] load failed: %s" % e, file=sys.stderr, flush=True)
    def list_rules():
        return {"ok": False, "message": "mail_rules nicht geladen: %s" % e, "rules": [], "enabled": False}
    def upsert_rule(data):
        return {"ok": False, "message": "mail_rules nicht geladen"}
    def delete_rule(rid):
        return {"ok": False, "message": "mail_rules nicht geladen"}
    def set_settings(data):
        return {"ok": False, "message": "mail_rules nicht geladen"}
    def preview_rule(rule, limit=20):
        return {"ok": False, "message": "mail_rules nicht geladen", "count": 0, "samples": []}
    def apply_rule(rule, dry_run=False):
        return {"ok": False, "message": "mail_rules nicht geladen", "deleted": 0}
    def start_apply_async(dry_run=False):
        return {"ok": False, "message": "mail_rules nicht geladen"}
    def read_apply_status():
        return {"running": False, "message": "mail_rules nicht geladen"}
    def load_store():
        return {"version": 1, "enabled": False, "interval_minutes": 30, "rules": []}
    def start_background_loop():
        pass
