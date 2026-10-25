#!/usr/bin/env python3
"""Mail rules engine – loads zlib/base64 parts from same directory."""
from __future__ import annotations
import base64, zlib
from pathlib import Path

_dir = Path(__file__).resolve().parent
_parts = sorted(_dir.glob("mail_rules_part*.b64"))
if not _parts:
    raise RuntimeError("mail_rules_part*.b64 missing next to mail_rules.py")
_b64 = "".join(p.read_text(encoding="ascii").strip() for p in _parts)
_code = zlib.decompress(base64.b64decode(_b64)).decode("utf-8")
exec(compile(_code, str(_dir / "mail_rules_body.py"), "exec"), globals())
