#!/usr/bin/env python3
"""Pre-open safety scan for PDF and Office documents on macOS.

Static, offline heuristics that flag the features real malicious documents rely on:
PDF auto-actions / JavaScript / embedded payloads, Office VBA macros, DDE, remote
templates and external relationships. Optionally adds ClamAV signatures and a
VirusTotal hash lookup when available.

Usage:
    ./scan.py FILE [FILE ...]        # or: ./scan.py -r DIR
    ./scan.py --vt FILE              # add VirusTotal hash reputation (VT_API_KEY)
    ./scan.py --json FILE            # machine-readable

Exit codes: 0 clean, 1 suspicious, 2 infected/known-bad, 3 error reading a file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile

PDF_TOKENS = [
    (b"/JavaScript", "high", "embedded JavaScript"),
    (b"/OpenAction", "high", "action runs automatically on open"),
    (b"/Launch", "high", "launches an external program"),
    (b"/EmbeddedFile", "high", "embedded file payload"),
    (b"/AA", "medium", "additional-actions dictionary (auto-run)"),
    (b"/RichMedia", "medium", "RichMedia/Flash content"),
    (b"/XFA", "medium", "XFA form (large parser attack surface)"),
    (b"/GoToR", "low", "remote GoTo action"),
    (b"/URI", "low", "outbound link"),
    (b"/Encrypt", "low", "encrypted (payload may be hidden)"),
    (b"/ObjStm", "low", "object streams (can obfuscate structure)"),
    (b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "high", "EICAR test signature"),
]

MACRO_AUTO = [
    "AutoOpen", "Auto_Open", "AutoExec", "Document_Open", "Document_Close",
    "Workbook_Open", "Workbook_Activate", "DocumentBeforeClose",
]
MACRO_EXEC = [
    "WScript.Shell", "Shell.Application", "CreateObject", "powershell",
    "cmd.exe", "mshta", "URLDownloadToFile", "ADODB.Stream", "Environ(",
    "VirtualAlloc", "Shellcode",
]

OFFICE_EXT = {".doc", ".docx", ".docm", ".dot", ".dotm", ".xls", ".xlsx", ".xlsm",
              ".xlsb", ".ppt", ".pptx", ".pptm", ".pps", ".ppsx"}
MACRO_EXT = {".docm", ".dotm", ".xlsm", ".xlsb", ".pptm"}
PDF_EXT = {".pdf"}

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGIC = b"PK\x03\x04"


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_pdf(data: bytes) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for token, sev, desc in PDF_TOKENS:
        if token in data:
            found.append((sev, f"PDF {token.decode('latin-1')}: {desc}"))
    if found:
        return found
    return []


def scan_ooxml(path: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(sev: str, msg: str) -> None:
        if msg not in seen:
            seen.add(msg)
            out.append((sev, msg))

    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            lowered = [n.lower() for n in names]
            if any(n.endswith("vbaproject.bin") for n in lowered):
                add("high", "VBA macro project present (vbaProject.bin)")
            if any("/embeddings/" in n for n in lowered):
                add("medium", "embedded OLE object(s)")
            for n in names:
                nl = n.lower()
                if not nl.endswith((".rels", ".xml")):
                    continue
                try:
                    text = z.read(n).decode("utf-8", "replace")
                except Exception:
                    continue
                if nl.endswith(".rels"):
                    for tag in re.findall(r"<Relationship\b[^>]*>", text, re.I):
                        if "TargetMode=\"External\"" not in tag and "TargetMode='External'" not in tag:
                            continue
                        typ = re.search(r"Type=\"([^\"]+)\"", tag, re.I)
                        t = typ.group(1) if typ else ""
                        kind = t.rstrip("/").rsplit("/", 1)[-1] or "unknown"
                        if kind == "hyperlink":
                            add("low", "external hyperlink")
                        elif kind == "attachedTemplate":
                            add("medium", "remote document template (template-injection vector, also used legitimately)")
                        else:
                            add("high", f"external relationship ({kind}) in {n}")
                else:
                    up = text.upper()
                    if "DDEAUTO" in up:
                        add("high", "DDEAUTO field (command execution vector)")
    except zipfile.BadZipFile:
        add("low", "not a valid OOXML zip archive")
    return out


def scan_ole(data: bytes) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    hay = data + data.replace(b"\x00", b"")  # ascii + utf-16le-ish
    def has(s: str) -> bool:
        return s.encode("ascii", "ignore") in hay

    auto = [k for k in MACRO_AUTO if has(k)]
    execs = [k for k in MACRO_EXEC if has(k)]
    if auto and execs:
        out.append(("high", f"auto-run macro with execution calls ({', '.join(auto[:2])} + {execs[0]})"))
    elif auto:
        out.append(("high", f"auto-run macro entry point ({auto[0]})"))
    elif execs:
        out.append(("high", f"macro execution primitive ({execs[0]})"))
    if has("VBA") or has("_VBA_PROJECT") or has("Macros"):
        out.append(("medium", "VBA project markers"))
    if has("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"):
        out.append(("high", "EICAR test signature"))
    return out


def scan_generic(path: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    name = os.path.basename(path)
    lower = name.lower()
    for real in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"):
        if lower.endswith(real + ".exe") or lower.endswith(real + ".scr") or lower.endswith(real + ".js"):
            out.append(("high", f"double extension disguising an executable: {name}"))
    if "\u202e" in name:
        out.append(("high", "right-to-left override character in filename"))
    return out


def scan_clamav(path: str) -> str:
    exe = shutil.which("clamscan")
    if not exe:
        return "not installed"
    try:
        res = subprocess.run([exe, "--no-summary", "--stdout", path],
                             capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return "timed out"
    out = (res.stdout + res.stderr).strip()
    if "FOUND" in out:
        line = next((l for l in out.splitlines() if "FOUND" in l), out)
        return "INFECTED: " + line.split(":")[-1].strip()
    if res.returncode == 0:
        return "clean"
    return f"error (rc={res.returncode})"


def scan_virustotal(digest: str, enabled: bool) -> str | None:
    if not enabled:
        return None
    key = os.environ.get("VT_API_KEY")
    if not key:
        return "no VT_API_KEY"
    import urllib.error
    import urllib.request
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{digest}",
        headers={"x-apikey": key, "accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            stats = json.load(r)["data"]["attributes"]["last_analysis_stats"]
    except urllib.error.HTTPError as e:
        return "not in VirusTotal" if e.code == 404 else f"lookup failed ({e.code})"
    except Exception as e:  # noqa: BLE001
        return f"lookup failed ({type(e).__name__})"
    bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(v for k, v in stats.items() if k != "undetected")
    return f"{bad}/{total} engines flagged" + (" — KNOWN BAD" if bad else " — clean")


def analyse(path: str, vt: bool) -> dict:
    result = {"file": path, "size": os.path.getsize(path), "type": "unknown",
              "indicators": [], "clamav": "not run", "virustotal": None, "error": None}
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
            fh.seek(0)
            body = fh.read(64 << 20)
    except OSError as e:
        result["error"] = str(e)
        return result

    result["sha256"] = sha256(path)
    ext = os.path.splitext(path)[1].lower()
    ind: list[tuple[str, str]] = []

    if ext in PDF_EXT or body.startswith(b"%PDF"):
        result["type"] = "PDF"
        ind += scan_pdf(body)
    elif head.startswith(ZIP_MAGIC):
        result["type"] = "OOXML (zip)"
        ind += scan_ooxml(path)
        if ext in MACRO_EXT:
            ind.append(("medium", f"macro-enabled format ({ext})"))
    elif head.startswith(OLE_MAGIC):
        result["type"] = "OLE (legacy Office)"
        ind += scan_ole(body)
    elif ext in OFFICE_EXT:
        result["type"] = f"Office-ish ({ext})"
    else:
        result["type"] = "other"

    ind += scan_generic(path)
    result["indicators"] = [{"severity": s, "detail": d} for s, d in ind]
    result["clamav"] = scan_clamav(path)
    result["virustotal"] = scan_virustotal(result["sha256"], vt)

    highs = sum(1 for s, _ in ind if s == "high")
    mediums = sum(1 for s, _ in ind if s == "medium")
    if result["clamav"].startswith("INFECTED") or (result["virustotal"] or "").endswith("KNOWN BAD"):
        result["verdict"] = "INFECTED"
    elif highs or mediums >= 2:
        result["verdict"] = "SUSPICIOUS"
    elif ind:
        result["verdict"] = "LOW-RISK"
    else:
        result["verdict"] = "CLEAN"
    return result


def print_human(r: dict, verbose: bool) -> None:
    if r["error"]:
        print(f"\n{r['file']}\n  ERROR: {r['error']}")
        return
    print(f"\n{r['file']}")
    print(f"  type:   {r['type']}  ({r['size']} bytes)")
    print(f"  sha256: {r['sha256'][:16]}…")
    print(f"  verdict: {r['verdict']}")
    for i in r["indicators"]:
        print(f"    - [{i['severity']}] {i['detail']}")
    if verbose or r["verdict"] == "INFECTED":
        print(f"  clamav: {r['clamav']}")
        if r["virustotal"]:
            print(f"  virustotal: {r['virustotal']}")
    if r["verdict"] in ("SUSPICIOUS", "INFECTED"):
        print("  advice: do not open in Preview/Word. Upload the hash to VirusTotal, or")
        print("          open inside a disposable VM / sandboxed viewer instead.")


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan PDF/Office documents before opening.")
    ap.add_argument("files", nargs="+", help="files or directories (use -r for dirs)")
    ap.add_argument("-r", "--recursive", action="store_true", help="walk directories")
    ap.add_argument("--vt", action="store_true", help="VirusTotal hash lookup (VT_API_KEY)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args()

    targets: list[str] = []
    exts = PDF_EXT | OFFICE_EXT
    for f in args.files:
        if os.path.isdir(f) and args.recursive:
            for root, _, names in os.walk(f):
                for n in names:
                    if os.path.splitext(n)[1].lower() in exts:
                        targets.append(os.path.join(root, n))
        elif os.path.isdir(f):
            print(f"skipping directory {f} (use -r)", file=sys.stderr)
        else:
            targets.append(f)

    if not targets:
        print("no matching files", file=sys.stderr)
        return 3

    results = [analyse(t, args.vt) for t in targets]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print_human(r, verbose=False)

    ranks = {"CLEAN": 0, "LOW-RISK": 0, "SUSPICIOUS": 1, "INFECTED": 2}
    worst = max(ranks.get(r.get("verdict", "CLEAN"), 0) for r in results)
    if any(r["error"] for r in results):
        return 3
    return worst


if __name__ == "__main__":
    sys.exit(main())
