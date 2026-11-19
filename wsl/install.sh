#!/usr/bin/env bash
# Install the scanners used by wsl/scan.sh into ~/.local/share/security-scan/bin.
#
# Installs:
#   trivy        (always)
#   osv-scanner  (only when a Go toolchain is available)
#
# No sudo required. Re-run to upgrade.
set -euo pipefail

BIN_DIR="${BIN_DIR:-$HOME/.local/share/security-scan/bin}"
mkdir -p "$BIN_DIR"

log() { printf '[install] %s\n' "$*"; }

# --------------------------------------------------------------------- trivy
log "resolving latest Trivy release"
TAG=$(curl -sI https://github.com/aquasecurity/trivy/releases/latest \
  | tr -d '\r' | awk -F'/tag/' '/^location:/ {print $2}')
[ -n "$TAG" ] || { log "could not resolve Trivy version"; exit 1; }
VER="${TAG#v}"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ASSET="trivy_${VER}_Linux-64bit.tar.gz" ;;
  aarch64) ASSET="trivy_${VER}_Linux-ARM64.tar.gz" ;;
  *) log "unsupported architecture: $ARCH"; exit 1 ;;
esac
log "downloading $TAG ($ASSET)"
TMP=$(mktemp -d)
curl -sL "https://github.com/aquasecurity/trivy/releases/download/${TAG}/${ASSET}" -o "$TMP/trivy.tgz"
tar -xzf "$TMP/trivy.tgz" -C "$TMP" trivy
install -m 0755 "$TMP/trivy" "$BIN_DIR/trivy"
rm -rf "$TMP"
log "trivy installed: $("$BIN_DIR/trivy" --version)"

# --------------------------------------------------------------- osv-scanner
if command -v go >/dev/null 2>&1; then
  log "installing osv-scanner via go install"
  GOBIN="$BIN_DIR" go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
  log "osv-scanner installed: $("$BIN_DIR/osv-scanner" --version | head -1)"
else
  log "go not found; skipping osv-scanner (dependency scan will be disabled)"
fi

log "add to PATH: export PATH=\"$BIN_DIR:\$PATH\""
log "then run: ./scan.sh"
