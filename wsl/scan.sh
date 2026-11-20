#!/usr/bin/env bash
# WSL/Linux security scan: OS packages (Trivy) + project dependencies (OSV-Scanner).
#
# Usage:
#   ./scan.sh [output-dir]
#
# Environment:
#   OUT_DIR     report directory (default: ~/security-scan/reports/<timestamp>)
#   PATHS_FILE  file with one project directory per line (default: ./paths.txt)
#   SEVERITY    Trivy severity filter (default: HIGH,CRITICAL)
#   TRIVY       path to trivy   (default: trivy on PATH)
#   OSV         path to osv-scanner (default: osv-scanner on PATH)
#
# Exit code is 0 even when findings exist; the report carries the details.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-$HOME/security-scan/reports/$(date +%Y-%m-%d_%H%M)}"
SEVERITY="${SEVERITY:-HIGH,CRITICAL}"
PATHS_FILE="${PATHS_FILE:-$SCRIPT_DIR/paths.txt}"
TRIVY="${TRIVY:-$(command -v trivy || true)}"
OSV="${OSV:-$(command -v osv-scanner || true)}"
PYTHON="${PYTHON:-python3}"

mkdir -p "$OUT_DIR" || { echo "cannot create $OUT_DIR" >&2; exit 1; }
LOG="$OUT_DIR/run.log"
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

# ---------------------------------------------------------------- OS packages
if [ -z "$TRIVY" ] || [ ! -x "$TRIVY" ]; then
  log "ERROR: trivy not found (run wsl/install.sh or set TRIVY)"
  exit 1
fi

log "Trivy OS scan (severity $SEVERITY, fixed only)"
SKIP_OS="/mnt,/proc,/sys,/dev,/run,/tmp,/var/lib/docker,/var/lib/containerd"

os_json() {
  "$TRIVY" rootfs / --pkg-types os --scanners vuln --severity "$SEVERITY" --ignore-unfixed \
    --skip-dirs "$SKIP_OS" --format json --output "$OUT_DIR/os.json" --quiet 2>>"$LOG"
}

if ! os_json; then
  # Usually a transient OCI/network failure while refreshing the DB; use the cached one.
  log "OS json scan failed; retrying with cached DB (--skip-db-update)"
  "$TRIVY" rootfs / --pkg-types os --scanners vuln --severity "$SEVERITY" --ignore-unfixed \
    --skip-dirs "$SKIP_OS" --skip-db-update \
    --format json --output "$OUT_DIR/os.json" --quiet 2>>"$LOG"
fi

"$TRIVY" rootfs / --pkg-types os --scanners vuln --severity "$SEVERITY" --ignore-unfixed \
  --skip-dirs "$SKIP_OS" --skip-db-update --format table --output "$OUT_DIR/os.txt" --quiet 2>>"$LOG"
log "OS table exit=$?"

if [ -n "$PYTHON" ] && [ -f "$SCRIPT_DIR/apt-status.py" ] && [ -f "$OUT_DIR/os.json" ]; then
  log "apt candidate check for flagged packages"
  "$PYTHON" "$SCRIPT_DIR/apt-status.py" "$OUT_DIR/os.json" "$OUT_DIR/apt-status.tsv" 2>>"$LOG"
  log "apt-status exit=$?"
fi

# ---------------------------------------------------------- project dependencies
targets=()
if [ -f "$PATHS_FILE" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
    line="${line/#\~/$HOME}"
    [ -d "$line" ] && targets+=("$line")
  done < "$PATHS_FILE"
fi
[ ${#targets[@]} -eq 0 ] && targets=("$HOME/source")

if [ -z "$OSV" ] || [ ! -x "$OSV" ]; then
  log "WARN: osv-scanner not found; skipping dependency scan (see wsl/install.sh)"
else
  for t in "${targets[@]}"; do
    safe=$(printf '%s' "$t" | tr -c 'A-Za-z0-9' '_')
    log "OSV scan: $t"
    # Exit 1 just means advisories were found.
    "$OSV" scan source -r "$t" --format markdown \
      --output-file "$OUT_DIR/deps-$safe.md" > "$OUT_DIR/osv-$safe.log" 2>&1
    rc=$?
    log "OSV exit=$rc"
    [ -s "$OUT_DIR/deps-$safe.md" ] || log "WARN: empty OSV report; see osv-$safe.log"
  done
fi

log "done: $OUT_DIR"
exit 0
