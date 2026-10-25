#!/usr/bin/env python3
"""Bootstrap: load full security UI module (never block on mail_rules)."""
import runpy
import sys
from pathlib import Path

def main():
    for p in (Path("/security_ui_app.py"), Path(__file__).resolve().parent / "security_ui_app.py"):
        if p.exists():
            try:
                runpy.run_path(str(p), run_name="__main__")
                return
            except SystemExit:
                raise
            except Exception as e:
                print("[security_ui] fatal while loading", p, ":", e, file=sys.stderr)
                raise
    raise SystemExit("security_ui_app.py missing")

if __name__ == "__main__":
    main()
