#!/usr/bin/env bash
#
# weekly.sh — weekly App Store upgrade pass.
#
# What neither `brew autoupdate` nor daily.sh covers: App Store apps.
# `mas upgrade` needs root, so it runs only when passwordless sudo exists;
# otherwise the App Store's own automatic-updates toggle is the fallback.
#
# Usage:
#   ./weekly.sh              # upgrade App Store apps (when permitted)
#   DRY_RUN=1 ./weekly.sh    # list what is outdated
#
# Logs: ~/security-scan/logs/appstore-YYYY-MM-DD.log
# Exit codes: 0 success (even with nothing to do), 1 at least one step failed.

set -uo pipefail

DRY_RUN="${DRY_RUN:-0}"
LOG_DIR="${LOG_DIR:-$HOME/security-scan/logs}"
mkdir -p "$LOG_DIR" || exit 1
LOG="$LOG_DIR/appstore-$(date +%Y-%m-%d).log"

# cron/launchd have a minimal PATH.
for _d in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin" /usr/bin /bin /usr/sbin /sbin; do
    [[ -d "$_d" ]] || continue
    case ":$PATH:" in *":$_d:"*) ;; *) PATH="$_d:$PATH" ;; esac
done
export PATH

exec > >(tee -a "$LOG") 2>&1
echo "=== weekly App Store upgrades — $(date '+%Y-%m-%d %H:%M %Z') ==="
[[ "$DRY_RUN" == "1" ]] && echo "DRY RUN: nothing will be changed"

FAILED=0

if command -v mas >/dev/null 2>&1; then
    echo "outdated apps:"
    mas outdated || true
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "would run: mas upgrade"
    elif sudo -n true 2>/dev/null; then
        sudo -n mas upgrade || FAILED=1
    else
        echo "mas upgrade needs root and passwordless sudo is not available — skipped."
        echo "macOS App Store auto-update (System Settings > App Store > Automatic Updates) is the fallback."
    fi
else
    echo "mas not installed — skipped (brew install mas)"
fi

echo
if [[ $FAILED -eq 0 ]]; then
    echo "=== done ==="
else
    echo "=== done — upgrade FAILED (see above) ==="
fi
exit "$FAILED"
