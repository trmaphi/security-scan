#!/usr/bin/env python3
"""Build a self-contained dashboard/index.html — no server required.

Reuses the parsers from server.py and inlines the data, so the page works when opened
straight from Finder (file://), where fetch() of local files is blocked by the browser.

    python3 dashboard/build.py                 # writes dashboard/index.html
    python3 dashboard/build.py --out /tmp/x.html

Regenerate whenever you want fresh numbers; the live server (server.py) remains
available if you prefer a page that re-reads the reports on every request.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from server import AUDIT_DIR, VULN_DIR, collect, render  # noqa: E402


def file_url(path: str | None) -> str:
    return Path(path).as_uri() if path else "#"


def build() -> tuple[str, dict]:
    data = collect()
    page = render(data)

    # Static page: links point at the report files, not at HTTP endpoints.
    page = page.replace('href="/report/audit"', f'href="{file_url(data["audit"]["path"])}"')
    page = page.replace('href="/report/vuln"', f'href="{file_url(data["vuln"]["path"])}"')
    # History tables: /report/<kind>/<file> -> file:// URIs for the static page.
    page = re.sub(r'href="/report/audit/([^"]+)"',
                  lambda m: f'href="{Path(AUDIT_DIR, m.group(1)).as_uri()}"', page)
    page = re.sub(r'href="/report/vuln/([^"]+)"',
                  lambda m: f'href="{Path(VULN_DIR, m.group(1)).as_uri()}"', page)
    page = page.replace("localhost only", "static build")
    page = re.sub(r'<meta http-equiv="refresh"[^>]*>', "", page)
    return page, data


def main() -> None:
    ap = argparse.ArgumentParser(description="Build a static security dashboard page")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "index.html"))
    args = ap.parse_args()

    page, data = build()
    Path(args.out).write_text(page, encoding="utf-8")
    a = data["audit"]["metrics"]
    print(f"wrote {args.out}")
    print(f"  audit {data['audit']['generated'] or 'never'} · "
          f"{a.get('Outdated formulae', 0)} formulae, {a.get('Outdated casks', 0)} casks, "
          f"{a.get('macOS updates available', 0)} OS updates")
    print(f"  vuln  {data['vuln']['generated'] or 'never'} · {data['vuln']['total']} advisories")
    print(f"  open  file://{os.path.abspath(args.out)}")


if __name__ == "__main__":
    main()
