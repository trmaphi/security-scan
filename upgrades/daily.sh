#!/usr/bin/env bash
#
# daily.sh — daily CLI upgrade pass (mise tools + Codex CLI).
#
# What `brew autoupdate` does not cover:
#   1. mise tools   (mise upgrade)
#   2. Codex CLI    (codex update)
#
# Usage:
#   ./daily.sh              # upgrade for real
#   DRY_RUN=1 ./daily.sh    # report what would change
#
# Logs: ~/security-scan/logs/daily-YYYY-MM-DD.log
# Exit codes: 0 success (even with nothing to do), 1 at least one step failed.

set -uo pipefail

DRY_RUN="${DRY_RUN:-0}"
LOG_DIR="${LOG_DIR:-$HOME/security-scan/logs}"
mkdir -p "$LOG_DIR" || exit 1
LOG="$LOG_DIR/daily-$(date +%Y-%m-%d).log"

# cron/launchd have a minimal PATH.
for _d in /opt/homebrew/bin /usr/local/bin "$HOME/.local/share/mise/shims" "$HOME/.local/bin" /usr/bin /bin /usr/sbin /sbin; do
    [[ -d "$_d" ]] || continue
    case ":$PATH:" in *":$_d:"*) ;; *) PATH="$_d:$PATH" ;; esac
done
export PATH

exec > >(tee -a "$LOG") 2>&1
echo "=== daily upgrades — $(date '+%Y-%m-%d %H:%M %Z') ==="
[[ "$DRY_RUN" == "1" ]] && echo "DRY RUN: nothing will be changed"

FAILED=0
step() { printf '\n--- %s ---\n' "$1"; }

# 1. mise -------------------------------------------------------------------
step "mise"
if command -v mise >/dev/null 2>&1; then
    if [[ "$DRY_RUN" == "1" ]]; then
        mise upgrade --dry-run || FAILED=1
    else
        mise upgrade || FAILED=1
    fi
else
    echo "mise not installed — skipped"
fi

# 2. Codex CLI ---------------------------------------------------------------
step "codex"
if command -v codex >/dev/null 2>&1; then
    echo "current: $(codex --version 2>/dev/null)"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "would run: codex update"
    else
        codex update || FAILED=1
        echo "after:   $(codex --version 2>/dev/null)"
    fi
else
    echo "codex not installed — skipped"
fi

echo
if [[ $FAILED -eq 0 ]]; then
    echo "=== done — all steps succeeded ==="
else
    echo "=== done — one or more steps FAILED (see above) ==="
fi
exit "$FAILED"
