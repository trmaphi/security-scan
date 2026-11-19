#!/usr/bin/env python3
"""Map Trivy-flagged Debian/Ubuntu packages to real apt candidates.

Usage: apt-status.py <trivy-os.json> <out.tsv>

Output columns: package, installed, candidate (empty when apt has no candidate).
A package is genuinely upgradable only when the candidate is non-empty and differs from
the installed version; otherwise it is a legacy/third-party package that apt cannot fix.
"""
import json
import subprocess
import sys


def policy(field: str, pkg: str) -> str:
    try:
        out = subprocess.run(
            ["apt-cache", "policy", pkg],
            capture_output=True, text=True, timeout=20,
        ).stdout
    except Exception:
        return ""
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith(field + ":"):
            return stripped.split(":", 1)[1].strip()
    return ""


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, dst = sys.argv[1], sys.argv[2]
    try:
        with open(src, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        print(f"cannot read {src}: {exc}", file=sys.stderr)
        return 1

    pkgs = set()
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            pkgs.add(vuln["PkgName"])

    with open(dst, "w", encoding="utf-8") as out:
        out.write("package\tinstalled\tcandidate\n")
        for pkg in sorted(pkgs):
            out.write(f"{pkg}\t{policy('Installed', pkg)}\t{policy('Candidate', pkg)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
