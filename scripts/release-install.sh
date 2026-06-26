#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
OUTPUT_ROOT="${BASTION_RELEASE_OUTPUT_DIR:-${ROOT_DIR}/dist/release}"
SOURCE_APP_PATH="${1:-${OUTPUT_ROOT}/Bastion.app}"
INSTALL_APP_PATH="${BASTION_INSTALL_PATH:-/Applications/Bastion.app}"
INSTALL_PARENT_DIR="$(dirname "${INSTALL_APP_PATH}")"
APP_BIN="${INSTALL_APP_PATH}/Contents/MacOS/bastion"
MCP_BIN="${INSTALL_APP_PATH}/Contents/MacOS/bastion-mcp"
LAUNCH_AGENT_LABEL="com.bastion.xpc"
EXPECTED_TEAM_ID="${BASTION_EXPECTED_TEAM_ID:-926A27BQ7W}"
SERVICE_DOMAIN="gui/$(id -u)/${LAUNCH_AGENT_LABEL}"

verify_app() {
  app_path="$1"
  /usr/bin/codesign --verify --deep --strict --verbose=2 "${app_path}" >/dev/null
  team_id="$(/usr/bin/codesign -dv "${app_path}" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2}')"
  if [ "${team_id}" != "${EXPECTED_TEAM_ID}" ]; then
    echo "Unexpected TeamIdentifier for ${app_path}: ${team_id:-<none>} (expected ${EXPECTED_TEAM_ID})" >&2
    exit 1
  fi
  /usr/sbin/spctl --assess --type execute --verbose "${app_path}" >/dev/null
  /usr/bin/xcrun stapler validate "${app_path}" >/dev/null
}

if [ ! -d "${SOURCE_APP_PATH}" ]; then
  echo "Source app bundle not found at ${SOURCE_APP_PATH}" >&2
  exit 1
fi

echo "==> Verifying source app artifact"
verify_app "${SOURCE_APP_PATH}"

if [ ! -w "${INSTALL_PARENT_DIR}" ] && [ ! -e "${INSTALL_APP_PATH}" ]; then
  echo "No write access to ${INSTALL_PARENT_DIR}. Re-run with sudo or set BASTION_INSTALL_PATH." >&2
  exit 1
fi

if [ -e "${INSTALL_APP_PATH}" ] && [ ! -w "${INSTALL_APP_PATH}" ]; then
  echo "No write access to existing ${INSTALL_APP_PATH}. Re-run with sudo or set BASTION_INSTALL_PATH." >&2
  exit 1
fi

echo "==> Stopping existing Bastion service"
if /bin/launchctl print "${SERVICE_DOMAIN}" >/dev/null 2>&1; then
  /bin/launchctl bootout "${SERVICE_DOMAIN}" >/dev/null
fi
/usr/bin/pkill -f '/bastion-helper.app/Contents/MacOS/bastion-helper($| )' >/dev/null 2>&1 || true
/usr/bin/pkill -f '/Bastion([^/]*)\.app/Contents/MacOS/bastion($| )' >/dev/null 2>&1 || true

echo "==> Installing Bastion to ${INSTALL_APP_PATH}"
/bin/mkdir -p "${INSTALL_PARENT_DIR}"
/bin/rm -rf "${INSTALL_APP_PATH}"
/usr/bin/ditto "${SOURCE_APP_PATH}" "${INSTALL_APP_PATH}"

echo "==> Verifying installed app artifact"
verify_app "${INSTALL_APP_PATH}"

echo "==> Registering app bundle"
/System/Library/Frameworks/CoreServices.framework/Versions/Current/Frameworks/LaunchServices.framework/Versions/Current/Support/lsregister \
  -f -R -trusted "${INSTALL_APP_PATH}" >/dev/null 2>&1 || true

echo "==> Registering background service"
"${APP_BIN}" --register-service
/bin/launchctl kickstart -k "gui/$(id -u)/${LAUNCH_AGENT_LABEL}" >/dev/null 2>&1 || true

if [ ! -x "${MCP_BIN}" ]; then
  echo "Bundled bastion-mcp missing or not executable at ${MCP_BIN}" >&2
  exit 1
fi

echo "==> Verifying XPC reachability"
STATUS_OK=0
STATUS_JSON=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  MCP_RESPONSE="$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bastion_status","arguments":{}}}' | "${MCP_BIN}" 2>/dev/null || true)"
  STATUS_JSON="$(printf '%s' "${MCP_RESPONSE}" | /usr/bin/plutil -extract result.content.0.text raw -o - - 2>/dev/null || true)"
  if [ -n "${STATUS_JSON}" ]; then
    STATUS_OK=1
    break
  fi
  /bin/sleep 1
done

if [ "${STATUS_OK}" -ne 1 ]; then
  echo "Installed Bastion app did not become reachable over XPC." >&2
  exit 1
fi

SERVICE_EXECUTABLE="$(printf '%s' "${STATUS_JSON}" | /usr/bin/plutil -extract executablePath raw -o - - 2>/dev/null || true)"
if [ "${SERVICE_EXECUTABLE}" != "${APP_BIN}" ]; then
  echo "XPC responded from unexpected executable: ${SERVICE_EXECUTABLE:-<unknown>} (expected ${APP_BIN})" >&2
  exit 1
fi

echo "==> Install complete"
echo "App: ${INSTALL_APP_PATH}"
echo "MCP: ${MCP_BIN}"
