#!/usr/bin/env bash
# Build xiem-agent for Windows x64 and copy to server.
# Usage: ./build_agent.sh [user@server]
# Example: ./build_agent.sh root@xiem.x9.cz

set -euo pipefail

SERVER=${1:-"spravce@xiem.x9.cz"}
REMOTE_BINARY="/var/www/flask_xiem/agent/xiem-agent.exe"
PUBLISH_DIR="agent-src/publish"

echo "==> Building xiem-agent (win-x64, self-contained)..."
dotnet publish agent-src/ \
  -r win-x64 \
  -c Release \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -o "$PUBLISH_DIR"

EXE="$PUBLISH_DIR/XiemAgent.exe"
if [ ! -f "$EXE" ]; then
  echo "ERROR: $EXE not found after build" >&2
  exit 1
fi

SIZE=$(du -h "$EXE" | cut -f1)
echo "==> Built: $EXE ($SIZE)"

echo "==> Copying to $SERVER:$REMOTE_BINARY ..."
ssh "$SERVER" "sudo mkdir -p $(dirname $REMOTE_BINARY) && sudo chmod 777 $(dirname $REMOTE_BINARY) && sudo chmod 666 $REMOTE_BINARY 2>/dev/null || true"
scp "$EXE" "$SERVER:$REMOTE_BINARY"

echo "==> Done. Binary je na serveru, jdi na https://xiem.x9.cz/admin/agent-binary"
