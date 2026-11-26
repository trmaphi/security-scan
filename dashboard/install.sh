#!/usr/bin/env bash
#
# install.sh — run the dashboard as a launchd user agent (127.0.0.1:8787).
#
#   ./dashboard/install.sh              # install + start
#   PORT=9000 ./install.sh              # different port
#   ./dashboard/install.sh uninstall    # stop + remove
#
set -euo pipefail

LABEL="io.trmaphi.security-scan.dashboard"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
PY="${PYTHON:-/usr/bin/python3}"
PORT="${PORT:-8787}"
UID_NUM="$(id -u)"

if [[ "${1:-}" == "uninstall" ]]; then
    launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
    rm -f "$PLIST"
    echo "dashboard uninstalled"
    exit 0
fi

mkdir -p "$HOME/Library/LaunchAgents" "$HOME/security-scan/logs"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PY</string>
        <string>$ROOT/dashboard/server.py</string>
        <string>--port</string>
        <string>$PORT</string>
    </array>
    <key>WorkingDirectory</key><string>$ROOT</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>$HOME/security-scan/logs/dashboard.out.log</string>
    <key>StandardErrorPath</key><string>$HOME/security-scan/logs/dashboard.err.log</string>
</dict>
</plist>
EOF

launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$UID_NUM" "$PLIST"
echo "dashboard: http://127.0.0.1:$PORT"
