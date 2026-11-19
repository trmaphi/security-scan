#!/usr/bin/env bash
#
# software-audit.sh — snapshot + outdated report for macOS software.
#
# Captures:
#   1. brew outdated --verbose                  (formulae)
#   2. brew outdated --cask --verbose           (casks, non-greedy)
#      brew outdated --cask --greedy --verbose  (casks, incl. self-updating)
#   3. brew list --versions                     (full formula snapshot)
#   4. brew leaves                              (top-level formulae)
#   5. brew list --cask --versions              (cask snapshot)
#   6. mas outdated                             (App Store, if `mas` installed)
#   7. softwareupdate -l                        (macOS updates, with timeout)
#   8. /Applications + ~/Applications diff vs. previous run
#
# Usage:
#   ./software-audit.sh                # update brew index, then report
#   BREW_UPDATE=0 ./software-audit.sh  # skip `brew update` (faster, may be stale)
#   OUT_DIR=/tmp/audit ./...           # custom report dir
#   KEEP=10 ./...                      # keep last 10 reports (default 30)
#   SU_TIMEOUT=45 ./...                # seconds before `softwareupdate -l` is killed
#
# Exit code: 0 on success (even when updates are found); 1 on fatal setup error.

set -uo pipefail

OUT_DIR="${OUT_DIR:-$HOME/software-audit}"
KEEP="${KEEP:-30}"
BREW_UPDATE="${BREW_UPDATE:-1}"   # 1 = run `brew update` first, 0 = skip
SU_TIMEOUT="${SU_TIMEOUT:-90}"    # softwareupdate -l can hang on bad networks

STAMP="$(date +%Y-%m-%d_%H%M%S)"
HUMAN_STAMP="$(date '+%Y-%m-%d %H:%M %Z')"

REPORT_DIR="$OUT_DIR/reports"
SNAP_DIR="$OUT_DIR/snapshots"
REPORT="$REPORT_DIR/software-audit-$STAMP.md"
APPS_FILE="$SNAP_DIR/apps-$STAMP.txt"

mkdir -p "$REPORT_DIR" "$SNAP_DIR" || { echo "cannot create $OUT_DIR" >&2; exit 1; }

# Previous app snapshot (must be resolved before writing the new one).
PREV_APPS="$(ls -1t "$SNAP_DIR"/apps-*.txt 2>/dev/null | head -n 1)"

# cron/launchd start with a minimal PATH; make sure brew and softwareupdate are findable.
for _d in /opt/homebrew/bin /usr/local/bin /usr/sbin; do
    [[ -d "$_d" ]] || continue
    case ":$PATH:" in *":$_d:"*) ;; *) PATH="$_d:$PATH" ;; esac
done
export PATH

# Keep brew quiet and non-interactive: no auto-update inside every command,
# no analytics/hints, no colour codes in the report.
export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_ANALYTICS=1
export HOMEBREW_NO_ENV_HINTS=1
export HOMEBREW_NO_COLOR=1
export HOMEBREW_NO_INTERACTIVE=1
export NO_COLOR=1

BREW="$(command -v brew || true)"
MAS="$(command -v mas || true)"
SU="$(command -v softwareupdate || true)"

# ---------- helpers ---------------------------------------------------------

section() {  # section "Title"
    { printf '\n## %s\n\n' "$1"; } >> "$REPORT"
}

note() {  # note "text" (markdown, outside code fences)
    { printf '%s\n\n' "$1"; } >> "$REPORT"
}

code_block() {  # code_block "output"
    local body="$1"
    body="${body//$'\r'/}"
    {
        printf '```\n'
        if [[ -z "${body//[[:space:]]/}" ]]; then
            printf '(none)\n'
        else
            printf '%s\n' "$body"
        fi
        printf '```\n'
    } >> "$REPORT"
}

list_apps() {
    { find /Applications -maxdepth 1 -name '*.app' 2>/dev/null
      find "$HOME/Applications" -maxdepth 1 -name '*.app' 2>/dev/null
    } | while IFS= read -r p; do basename "$p" .app; done | sort -u
}

count_entries() {  # count brew-style lines, ignoring headers/warnings
    printf '%s\n' "$1" | awk 'NF && $0 !~ /^==>/ && $0 !~ /^Warning:/' | wc -l | tr -d ' '
}

timeout_capture() {  # timeout_capture SECONDS cmd... -> output; kills on timeout
    local secs="$1"; shift
    local tmp pid watcher rc
    tmp="$(mktemp)"
    "$@" >"$tmp" 2>&1 &
    pid=$!
    ( sleep "$secs"; kill -TERM "$pid" 2>/dev/null; sleep 2; kill -KILL "$pid" 2>/dev/null ) >/dev/null 2>&1 &
    watcher=$!
    wait "$pid" 2>/dev/null; rc=$?
    kill "$watcher" 2>/dev/null
    wait "$watcher" 2>/dev/null
    if [[ $rc -eq 143 || $rc -eq 137 ]]; then
        printf '\n[timed out after %ss — results may be incomplete]\n' "$secs"
    fi
    cat "$tmp"
    rm -f "$tmp"
}

cleanup_dir() {  # keep newest $KEEP files matching a glob
    local dir="$1" pattern="$2"
    { ls -1t "$dir"/$pattern 2>/dev/null | tail -n +"$((KEEP + 1))"
    } | while IFS= read -r old; do rm -f "$old"; done
}

# ---------- header ----------------------------------------------------------

OS_NAME="$(sw_vers -productName 2>/dev/null || echo macOS)"
OS_VER="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
OS_BUILD="$(sw_vers -buildVersion 2>/dev/null || echo unknown)"

{
    printf '# macOS Software Audit — %s\n\n' "$HUMAN_STAMP"
    printf -- '- **Host:** %s (%s)\n' "$(hostname)" "$(uname -m)"
    printf -- '- **OS:** %s %s (%s)\n' "$OS_NAME" "$OS_VER" "$OS_BUILD"
    printf -- '- **Homebrew:** %s\n' "${BREW:-not installed}"
    printf -- '- **mas:** %s\n' "${MAS:-not installed}"
} > "$REPORT"

# ---------- refresh metadata ------------------------------------------------

BREW_UPDATE_STATUS="not run (brew missing)"
if [[ -n "$BREW" ]]; then
    if [[ "$BREW_UPDATE" == "1" ]]; then
        if "$BREW" update --quiet >/dev/null 2>&1; then
            BREW_UPDATE_STATUS="ok"
        else
            BREW_UPDATE_STATUS="failed — results may be stale"
        fi
    else
        BREW_UPDATE_STATUS="skipped (BREW_UPDATE=0) — results may be stale"
    fi
fi
printf -- '- **Homebrew metadata:** %s\n' "$BREW_UPDATE_STATUS" >> "$REPORT"

# ---------- gather ----------------------------------------------------------

SU_OUT=""
F_OUTDATED=""; C_OUTDATED=""; C_OUTDATED_GREEDY=""
F_LIST=""; F_LEAVES=""; C_LIST=""; MAS_OUTDATED=""

if [[ -n "$BREW" ]]; then
    F_OUTDATED="$("$BREW" outdated --verbose 2>&1)"
    C_OUTDATED="$("$BREW" outdated --cask --verbose 2>&1)"
    C_OUTDATED_GREEDY="$("$BREW" outdated --cask --greedy --verbose 2>&1)"
    F_LIST="$("$BREW" list --versions 2>&1)"
    F_LEAVES="$("$BREW" leaves 2>&1)"
    C_LIST="$("$BREW" list --cask --versions 2>&1)"
fi

if [[ -n "$MAS" ]]; then
    MAS_OUTDATED="$("$MAS" outdated 2>&1)"
fi

if [[ -n "$SU" ]]; then
    SU_OUT="$(timeout_capture "$SU_TIMEOUT" "$SU" -l)"
fi

# ---------- counts (derived from captured output, no extra brew calls) -------

N_FORMULA=0; N_CASK=0; N_CASK_GREEDY=0
if [[ -n "$BREW" ]]; then
    N_FORMULA="$(count_entries "$F_OUTDATED")"
    N_CASK="$(count_entries "$C_OUTDATED")"
    N_CASK_GREEDY="$(count_entries "$C_OUTDATED_GREEDY")"
fi
N_MAS=0
[[ -n "$MAS" ]] && N_MAS="$(printf '%s\n' "$MAS_OUTDATED" | awk 'NF' | wc -l | tr -d ' ')"
N_SU="$(printf '%s\n' "$SU_OUT" | grep -c '^[[:space:]]*\* Label:' || true)"
N_FORMULA_INSTALLED="$(printf '%s\n' "$F_LIST" | awk 'NF' | wc -l | tr -d ' ')"
N_CASK_INSTALLED="$(printf '%s\n' "$C_LIST" | awk 'NF' | wc -l | tr -d ' ')"

# App diff
list_apps > "$APPS_FILE"
N_APPS="$(wc -l < "$APPS_FILE" | tr -d ' ')"
ADDED=""; REMOVED=""
if [[ -n "$PREV_APPS" && -s "$PREV_APPS" ]]; then
    ADDED="$(comm -13 "$PREV_APPS" "$APPS_FILE" 2>/dev/null)"
    REMOVED="$(comm -23 "$PREV_APPS" "$APPS_FILE" 2>/dev/null)"
fi

N_ADDED=0; N_REMOVED=0
[[ -n "$ADDED" ]] && N_ADDED="$(printf '%s\n' "$ADDED" | wc -l | tr -d ' ')"
[[ -n "$REMOVED" ]] && N_REMOVED="$(printf '%s\n' "$REMOVED" | wc -l | tr -d ' ')"

# ---------- summary ---------------------------------------------------------

{
    printf '\n## Summary\n\n'
    printf '| Check | Count |\n|---|---|\n'
    printf '| Outdated formulae | %s |\n' "$N_FORMULA"
    printf '| Outdated casks | %s |\n' "$N_CASK"
    printf '| Outdated casks (incl. greedy/self-updating) | %s |\n' "$N_CASK_GREEDY"
    printf '| App Store updates (mas) | %s |\n' "$N_MAS"
    printf '| macOS updates available | %s |\n' "$N_SU"
    printf '| Installed formulae (all versions) | %s |\n' "$N_FORMULA_INSTALLED"
    printf '| Installed casks | %s |\n' "$N_CASK_INSTALLED"
    printf '| Apps in /Applications + ~/Applications | %s |\n' "$N_APPS"
    printf '| Apps added / removed since last run | +%s / -%s |\n' "$N_ADDED" "$N_REMOVED"
} >> "$REPORT"

# ---------- body ------------------------------------------------------------

if [[ -n "$BREW" ]]; then
    section "1. Outdated formulae"
    note '`brew outdated --verbose`'
    code_block "$F_OUTDATED"

    section "2. Outdated casks"
    note '`brew outdated --cask --greedy --verbose` — includes apps that update themselves outside Homebrew.'
    code_block "$C_OUTDATED_GREEDY"
    if [[ "$N_CASK_GREEDY" -gt "$N_CASK" ]]; then
        note "$((N_CASK_GREEDY - N_CASK)) of these are greedy/self-updating only; \`brew upgrade --cask\` alone will not move them."
    fi

    section "3. Installed formulae (full snapshot)"
    note '`brew list --versions`'
    code_block "$F_LIST"

    section "4. Top-level formulae"
    note '`brew leaves` — formulae installed directly (no dependencies)'
    code_block "$F_LEAVES"

    section "5. Installed casks"
    note '`brew list --cask --versions`'
    code_block "$C_LIST"
else
    section "1. Homebrew"
    note 'Homebrew is not installed (`brew` not found on PATH) — sections 1–5 skipped.'
fi

section "6. App Store updates"
if [[ -n "$MAS" ]]; then
    note '`mas outdated`'
    code_block "$MAS_OUTDATED"
    note '> **Known bug:** on recent macOS versions `mas outdated` often returns nothing even
> when App Store updates are pending. Treat an empty result as "no data", not "up to date" —
> check the App Store app manually for security updates.'
else
    note '`mas` is not installed — skipped. Install with `brew install mas` to include App Store updates.

> Note: `mas outdated` has a known upstream bug on recent macOS versions (empty output despite
> pending updates), so even with `mas` installed this section is best-effort, not authoritative.'
fi

section "7. macOS updates"
if [[ -n "$SU" ]]; then
    note "\`softwareupdate -l\` (killed after ${SU_TIMEOUT}s if it hangs)"
    code_block "$SU_OUT"
else
    note '`softwareupdate` not found — skipped.'
fi

section "8. Application changes vs. previous run"
if [[ -n "$PREV_APPS" ]]; then
    note "Compared with: \`$(basename "$PREV_APPS")\`"
    if [[ -z "$ADDED" && -z "$REMOVED" ]]; then
        note 'No changes in installed applications.'
    else
        if [[ -n "$ADDED" ]]; then
            note '**Added**'
            code_block "$ADDED"
        fi
        if [[ -n "$REMOVED" ]]; then
            note '**Removed**'
            code_block "$REMOVED"
        fi
    fi
else
    note 'First run — no previous snapshot to compare against. This run becomes the baseline.'
fi

printf '\n---\n_Report: %s_\n' "$REPORT" >> "$REPORT"

# ---------- cleanup ---------------------------------------------------------

cleanup_dir "$REPORT_DIR" 'software-audit-*.md'
cleanup_dir "$SNAP_DIR" 'apps-*.txt'

# ---------- stdout summary --------------------------------------------------

echo "Report: $REPORT"
echo "Homebrew metadata: $BREW_UPDATE_STATUS"
echo "Outdated: ${N_FORMULA} formulae, ${N_CASK} casks (${N_CASK_GREEDY} incl. greedy), ${N_MAS} App Store, ${N_SU} macOS updates"
if [[ -n "$PREV_APPS" ]]; then
    echo "App changes: +${N_ADDED} / -${N_REMOVED}"
fi
