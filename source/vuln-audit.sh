#!/usr/bin/env bash
#
# vuln-audit.sh — vulnerability scan for source repositories using osv-scanner.
#
# Walks one or more roots, lets osv-scanner find dependency lockfiles (npm, pnpm, yarn,
# Go, Python, Rust, Ruby, PHP, ...), and writes a Markdown report grouped by repository
# with severity, installed version and advisory links.
#
# Advisory data comes from OSV.dev (https://osv.dev) — the same database behind GitHub's
# dependency alerts. Authoritative for dependencies; says nothing about macOS GUI apps,
# which are covered by macos/software-audit.sh.
#
# Usage:
#   ./vuln-audit.sh                          # scan ~/source/trmaphi
#   ./vuln-audit.sh ~/source/foo ~/work/bar  # scan specific roots
#   SCAN_ROOT=~/source ./vuln-audit.sh       # different default root
#   OUT_DIR=/tmp/vuln ./vuln-audit.sh        # custom report dir
#   KEEP=10 ./vuln-audit.sh                  # reports to keep (default 30)
#   SCAN_TIMEOUT=600 ./vuln-audit.sh         # kill scan after N seconds (default 900)
#   ./vuln-audit.sh --no-fail                # always exit 0
#
# Exit codes: 0 = clean, 1 = scanner missing / scan unusable / timed out,
#             2 = findings include HIGH or CRITICAL (disable with --no-fail).

set -uo pipefail

SCAN_ROOT="${SCAN_ROOT:-$HOME/source/trmaphi}"
OUT_DIR="${OUT_DIR:-$HOME/security-scan}"
KEEP="${KEEP:-30}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-900}"
FAIL_ON_FINDINGS=1
[[ "${1:-}" == "--no-fail" ]] && { FAIL_ON_FINDINGS=0; shift; }

ROOTS=("$@")
[[ ${#ROOTS[@]} -eq 0 ]] && ROOTS=("$SCAN_ROOT")

STAMP="$(date +%Y-%m-%d_%H%M%S)"
HUMAN_STAMP="$(date '+%Y-%m-%d %H:%M %Z')"
REPORT_DIR="$OUT_DIR/reports"
REPORT="$REPORT_DIR/vuln-scan-$STAMP.md"
mkdir -p "$REPORT_DIR" || { echo "cannot create $REPORT_DIR" >&2; exit 1; }

OSV="$(command -v osv-scanner || true)"
[[ -z "$OSV" ]] && { echo "osv-scanner not found (brew install osv-scanner)" >&2; exit 1; }
PY="$(command -v python3 || true)"
[[ -z "$PY" ]] && { echo "python3 not found" >&2; exit 1; }

VALID_ROOTS=()
for root in "${ROOTS[@]}"; do
    if [[ -d "$root" ]]; then
        VALID_ROOTS+=("$(cd "$root" && pwd)")
    else
        echo "warning: $root is not a directory, skipping" >&2
    fi
done

if [[ ${#VALID_ROOTS[@]} -eq 0 ]]; then
    echo "no valid roots to scan" >&2
    exit 1
fi

OSV_VERSION="$("$OSV" --version 2>&1 | head -n 1 | tr -d '\r')"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

{
    printf '# Source Vulnerability Scan — %s\n\n' "$HUMAN_STAMP"
    printf -- '- **Scanner:** %s\n' "${OSV_VERSION:-osv-scanner (version unknown)}"
    printf -- '- **Advisory source:** [OSV.dev](https://osv.dev) (CVE / GHSA / Go vulndb)\n'
    for r in "${VALID_ROOTS[@]}"; do
        printf -- '- **Root:** `%s`\n' "$r"
    done
} > "$REPORT"

# ---------- run scan --------------------------------------------------------

"$OSV" scan source -r "${VALID_ROOTS[@]}" --no-call-analysis=go -f json \
    >"$TMP/out.json" 2>"$TMP/err.log" &
pid=$!
( sleep "$SCAN_TIMEOUT"; kill -TERM "$pid" 2>/dev/null; sleep 3; kill -KILL "$pid" 2>/dev/null ) >/dev/null 2>&1 &
watcher=$!
wait "$pid" 2>/dev/null; rc=$?
kill "$watcher" 2>/dev/null
wait "$watcher" 2>/dev/null

TIMED_OUT=0
[[ $rc -eq 143 || $rc -eq 137 ]] && TIMED_OUT=1

if [[ $TIMED_OUT -eq 1 ]]; then
    printf '\n> **Scan killed after %ss — results are incomplete.**\n' "$SCAN_TIMEOUT" >> "$REPORT"
fi

if ! "$PY" -c 'import json,sys; json.load(open(sys.argv[1]))' "$TMP/out.json" 2>/dev/null; then
    {
        printf '\n> **Scan failed — no usable JSON output.**\n\n```\n'
        tail -n 25 "$TMP/err.log"
        printf '```\n'
    } >> "$REPORT"
    echo "Scan failed: see $REPORT"
    exit 1
fi

# ---------- report ----------------------------------------------------------

OUTPUT="$("$PY" - "$TMP/out.json" "${VALID_ROOTS[@]}" <<'PY'
import json, os, sys

data = json.load(open(sys.argv[1]))
roots = [os.path.realpath(r) for r in sys.argv[2:]]
RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

def rel(path):
    p = os.path.realpath(path)
    best = None
    for r in roots:
        if p == r or p.startswith(r + os.sep):
            if best is None or len(r) > len(best):
                best = r
    if best is None:
        return p, "?"
    return os.path.relpath(p, best), os.path.basename(best)

_git_cache = {}

def git_root(path):
    """Nearest enclosing directory containing .git, else None."""
    d = os.path.dirname(os.path.realpath(path))
    orig = d
    if orig in _git_cache:
        return _git_cache[orig]
    found = None
    while d and d != os.sep:
        if os.path.exists(os.path.join(d, ".git")):
            found = d
            break
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    _git_cache[orig] = found
    return found

def repo_of(rel_path, root_name, src):
    g = git_root(src)
    if g:
        return os.path.basename(g)
    parts = rel_path.split(os.sep)
    return parts[0] if len(parts) > 1 else root_name

def severity(vuln, pkg):
    ds = vuln.get("database_specific") or {}
    s = str(ds.get("severity") or "").upper()
    if s == "MODERATE": s = "MEDIUM"
    if s == "IMPORTANT": s = "HIGH"
    if s in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return s
    best = 0.0
    for g in pkg.get("groups", []):
        if vuln.get("id") in g.get("ids", []):
            try:
                best = max(best, float(g.get("max_severity") or 0))
            except ValueError:
                pass
    if best >= 9.0: return "CRITICAL"
    if best >= 7.0: return "HIGH"
    if best >= 4.0: return "MEDIUM"
    if best > 0:    return "LOW"
    return "UNKNOWN"

def esc(s, n=110):
    s = " ".join(str(s or "").split()).replace("|", "\\|")
    return (s[: n - 1] + "…") if len(s) > n else s

rows, seen, lockfiles = [], set(), []
for res in data.get("results", []):
    src = res.get("source", {}).get("path", "?")
    rp, root_name = rel(src)
    repo = repo_of(rp, root_name, src)
    if res.get("packages"):
        lockfiles.append(rp)
    for pkg in res.get("packages", []):
        p = pkg.get("package", {})
        name, ver = p.get("name", "?"), p.get("version", "?")
        for v in pkg.get("vulnerabilities", []):
            key = (repo, name, ver, v.get("id"))
            if key in seen:
                continue
            seen.add(key)
            rows.append((severity(v, pkg), repo, name, ver, v.get("id", "?"),
                         esc(v.get("summary") or v.get("details") or ""), v.get("aliases") or []))

rows.sort(key=lambda r: (RANK.get(r[0], 9), r[1].lower(), r[2].lower(), r[4]))

repos = {}
for r in rows:
    repos.setdefault(r[1], []).append(r)

counts = {k: 0 for k in RANK}
pkgs = {k: set() for k in RANK}
for r in rows:
    counts[r[0]] += 1
    pkgs[r[0]].add((r[2], r[3]))

out = ["\n## Summary\n", "| Severity | Advisories | Affected package versions |", "|---|---|---|"]
for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
    out.append(f"| {k} | {counts[k]} | {len(pkgs[k])} |")
out.append(f"| **Total** | **{len(rows)}** | **{len({(r[2], r[3]) for r in rows})}** |")
out.append("")
out.append(f"Lockfiles with packages: {len(set(lockfiles))}; repositories with findings: {len(repos)}.")
if counts["UNKNOWN"]:
    out.append("")
    out.append("> `UNKNOWN` = advisory without a severity score in OSV (common for Go stdlib entries);")
    out.append("> it is still a real advisory, just unrated.")

if not rows:
    out.append("\n**No known vulnerabilities found in the scanned lockfiles.**")
else:
    for repo in sorted(repos, key=lambda x: (min(RANK.get(r[0], 9) for r in repos[x]), x.lower())):
        rl = repos[repo]
        worst = min(rl, key=lambda r: RANK.get(r[0], 9))[0]
        out.append(f"\n### {repo} — {len(rl)} advisories (worst: {worst})\n")
        out.append("| Severity | Package | Version | Advisory | Summary |")
        out.append("|---|---|---|---|---|")
        for sev, _, name, ver, vid, summ, aliases in rl:
            cves = ", ".join(a for a in aliases if a.startswith("CVE-"))
            extra = f" ({cves})" if cves else ""
            out.append(f"| {sev} | `{name}` | `{ver}` | [{vid}](https://osv.dev/{vid}){extra} | {summ} |")

print("\n".join(out))
print("\n--STATS--")
print(json.dumps({
    "counts": counts,
    "total": len(rows),
    "repos": sorted(repos, key=lambda x: -len(repos[x]))[:3],
}))
PY
)"

BODY="${OUTPUT%%$'\n--STATS--'*}"
STATS="${OUTPUT##*$'\n--STATS--'}"
printf '%s\n' "$BODY" >> "$REPORT"
printf '\n---\n_Report: %s_\n' "$REPORT" >> "$REPORT"

{ ls -1t "$REPORT_DIR"/vuln-scan-*.md 2>/dev/null | tail -n +"$((KEEP + 1))"; } |
    while IFS= read -r old; do rm -f "$old"; done

# ---------- stdout ----------------------------------------------------------

stat() { printf '%s' "$STATS" | "$PY" -c "import json,sys; print(json.dumps(json.load(sys.stdin)$1))" 2>/dev/null || echo 0; }

TOTAL="$(stat '["total"]')"
CRIT="$(stat '["counts"]["CRITICAL"]')"
HIGH="$(stat '["counts"]["HIGH"]')"
MED="$(stat '["counts"]["MEDIUM"]')"
LOW="$(stat '["counts"]["LOW"]')"

echo "Report: $REPORT"
echo "Vulnerabilities: ${TOTAL} total — ${CRIT} critical, ${HIGH} high, ${MED} medium, ${LOW} low"
[[ $TIMED_OUT -eq 1 ]] && echo "Warning: scan timed out after ${SCAN_TIMEOUT}s; results incomplete."
echo "Top repos: $(stat '["repos"]')"

if [[ $FAIL_ON_FINDINGS -eq 1 && $((CRIT + HIGH)) -gt 0 ]]; then
    exit 2
fi
[[ $TIMED_OUT -eq 1 ]] && exit 1
exit 0
