#!/usr/bin/env bash
# Register the Bastion web-connect native-messaging host with Chromium browsers.
#
# Usage: ./install-host.sh <EXTENSION_ID>
#   <EXTENSION_ID> is the unpacked extension's ID (chrome://extensions → Details).
#
# Writes a launcher that pins the absolute node path (Chrome-spawned hosts get a
# minimal PATH), then installs app.bastion.host.json into each browser's
# NativeMessagingHosts directory with the extension id allow-listed.
set -euo pipefail

EXT_ID="${1:-}"
if [ -z "$EXT_ID" ]; then
  echo "usage: $0 <EXTENSION_ID>" >&2
  exit 1
fi

HOST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_JS="$HOST_DIR/host.mjs"
LAUNCHER="$HOST_DIR/run-host.sh"

NODE_BIN="$(command -v node || true)"
if [ -z "$NODE_BIN" ]; then
  echo "node not found on PATH; install Node 18+ first." >&2
  exit 1
fi

cat > "$LAUNCHER" <<EOF
#!/bin/sh
exec "$NODE_BIN" "$HOST_JS" "\$@"
EOF
chmod +x "$LAUNCHER"

TEMPLATE="$HOST_DIR/app.bastion.host.json.template"
RENDERED="$(sed -e "s#__LAUNCHER_PATH__#$LAUNCHER#" -e "s#__EXTENSION_ID__#$EXT_ID#" "$TEMPLATE")"

# Chromium-family native-messaging host directories on macOS.
TARGETS=(
  "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
  "$HOME/Library/Application Support/Google/Chrome Canary/NativeMessagingHosts"
  "$HOME/Library/Application Support/Chromium/NativeMessagingHosts"
  "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"
  "$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts"
  "$HOME/Library/Application Support/Arc/User Data/NativeMessagingHosts"
)

installed=0
for dir in "${TARGETS[@]}"; do
  parent="$(dirname "$dir")"
  if [ -d "$parent" ]; then
    mkdir -p "$dir"
    printf '%s\n' "$RENDERED" > "$dir/app.bastion.host.json"
    echo "installed: $dir/app.bastion.host.json"
    installed=$((installed + 1))
  fi
done

if [ "$installed" -eq 0 ]; then
  echo "No Chromium-family browser profile dirs found. Is Chrome/Brave/Edge installed?" >&2
  exit 1
fi

echo "Done. Launcher: $LAUNCHER"
echo "Allowed extension: chrome-extension://$EXT_ID/"
