#!/usr/bin/env bash
#
# weekly.sh — weekly CLI / App Store upgrade pass.
#
# Covers what `brew autoupdate` does not:
#   1. mise tools        (mise upgrade)
#   2. Codex CLI         (codex update)
#   3. App Store apps    (mas outdated + mas upgrade when passwordless sudo exists)
#
# Usage:
#   ./weekly.sh              # upgrade for real
#   DRY_RUN=1 ./weekly.sh    # report what would change
#
# Logs: ~/security-scan/logs/upgrades-YYYY-MM-DD.log
# Exit codes: 0 success (even with nothing to do), 1 at least one step failed.

set -uo pipefail

DRY_RUN="${DRY_RUN:-0}"
LOG_DIR="${LOG_DIR:-$HOME/security-scan/logs}"
mkdir -p "$LOG_DIR" || exit 1
LOG="$LOG_DIR/upgrades-$(date +%Y-%m-%d).log"

# cron/launchd have a minimal PATH.
for _d in /opt/homebrew/bin /usr/local/bin "$HOME/.local/share/mise/shims" "$HOME/.local/bin" /usr/bin /bin /usr/sbin /sbin; do
    [[ -d "$_d" ]] || continue
    case ":$PATH:" in *":$_d:"*) ;; *) PATH="$_d:$PATH" ;; esac
done
export PATH

exec > >(tee -a "$LOG") 2>&1
echo "=== weekly upgrades — $(date '+%Y-%m-%d %H:%M %Z') ==="
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

# 3. App Store ---------------------------------------------------------------
step "App Store (mas)"
if command -v mas >/dev/null 2>&1; then
    echo "outdated apps:"
    mas outdated || true
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "would run: mas upgrade"
    elif sudo -n true 2>/dev/null; then
        sudo -n mas upgrade || FAILED=1
    else
        echo "mas upgrade needs root and passwordless sudo is not available — skipped."
        echo "macOS App Store auto-update (Settings > App Store > Automatic Updates) is the fallback."
    fi
else
    echo "mas not installed — skipped (brew install mas)"
fi

echo
if [[ $FAILED -eq 0 ]]; then
    echo "=== done — all steps succeeded ==="
else
    echo "=== done — one or more steps FAILED (see above) ==="
fi
exit "$FAILED"
