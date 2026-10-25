#!/usr/bin/env python3
"""Bootstrap: load full security UI module."""
import runpy
from pathlib import Path
for p in (Path("/security_ui_app.py"), Path(__file__).resolve().parent / "security_ui_app.py"):
    if p.exists():
        runpy.run_path(str(p), run_name="__main__")
        break
else:
    raise SystemExit("security_ui_app.py missing")
