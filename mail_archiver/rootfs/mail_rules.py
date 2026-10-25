#!/usr/bin/env python3
"""Mail rules engine – loads zlib/base64 parts from same directory (or /)."""
from __future__ import annotations
import base64, zlib
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
    code = zlib.decompress(base64.b64decode(b64)).decode("utf-8")
    exec(compile(code, "mail_rules_body.py", "exec"), globals())

_load()
