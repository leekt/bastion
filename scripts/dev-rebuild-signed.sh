#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
PROJECT_PATH="${ROOT_DIR}/bastion.xcodeproj"
SCHEME="bastion"
DERIVED_DATA_PATH="${HOME}/Library/Developer/Xcode/DerivedData/bastion-dev-signed"
BUILD_APP_PATH="${DERIVED_DATA_PATH}/Build/Products/Debug/bastion.app"
INSTALL_APP_PATH="${HOME}/Applications/Bastion Dev.app"
APP_PATH="${INSTALL_APP_PATH}"
APP_BIN="${INSTALL_APP_PATH}/Contents/MacOS/bastion"
CLI_BIN="${INSTALL_APP_PATH}/Contents/MacOS/bastion-cli"
HELPER_BIN="${INSTALL_APP_PATH}/Contents/Helpers/bastion-helper.app/Contents/MacOS/bastion-helper"
LAUNCH_AGENT_LABEL="com.bastion.xpc"
LAUNCH_AGENT_PLIST="${HOME}/Library/LaunchAgents/${LAUNCH_AGENT_LABEL}.plist"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Versions/Current/Frameworks/LaunchServices.framework/Versions/Current/Support/lsregister"

echo "==> Building signed Bastion app"
xcodebuild \
  -project "${PROJECT_PATH}" \
  -scheme "${SCHEME}" \
  -derivedDataPath "${DERIVED_DATA_PATH}" \
  ENABLE_USER_SCRIPT_SANDBOXING=NO \
  ENABLE_DEBUG_DYLIB=NO \
  ENABLE_PREVIEWS=NO \
  build

if [ ! -x "${APP_BIN}" ]; then
  if [ ! -x "${BUILD_APP_PATH}/Contents/MacOS/bastion" ]; then
    echo "Signed app binary not found at ${BUILD_APP_PATH}" >&2
    exit 1
  fi
fi

echo "==> Unregistering stale Bastion app bundles"
find "${HOME}/Library/Developer/Xcode/DerivedData" -path "*/Build/Products/Debug/bastion.app" -type d | while read -r candidate; do
  if [ "${candidate}" != "${BUILD_APP_PATH}" ]; then
    "${LSREGISTER}" -u "${candidate}" >/dev/null 2>&1 || true
  fi
done

echo "==> Removing legacy LaunchAgent bootstrap"
/bin/launchctl bootout "gui/$(id -u)/${LAUNCH_AGENT_LABEL}" >/dev/null 2>&1 || true
/bin/rm -f "${LAUNCH_AGENT_PLIST}"

echo "==> Stopping stale Bastion processes"
/usr/bin/pkill -f '/bastion.app/Contents/MacOS/bastion($| )' >/dev/null 2>&1 || true
/usr/bin/pkill -f '/bastion-helper.app/Contents/MacOS/bastion-helper($| )' >/dev/null 2>&1 || true

echo "==> Installing signed Bastion app to stable path"
/bin/mkdir -p "${HOME}/Applications"
/bin/rm -rf "${INSTALL_APP_PATH}"
/usr/bin/ditto "${BUILD_APP_PATH}" "${INSTALL_APP_PATH}"

echo "==> Registering signed Bastion app bundle"
"${LSREGISTER}" -f -R -trusted "${APP_PATH}" >/dev/null 2>&1 || true

echo "==> Registering SMAppService agent"
"${APP_BIN}" --register-service
/bin/launchctl kickstart -k "gui/$(id -u)/${LAUNCH_AGENT_LABEL}" >/dev/null 2>&1 || true
/bin/sleep 1

echo "==> Installing CLI symlink"
/bin/mkdir -p /usr/local/bin >/dev/null 2>&1 || true
/bin/ln -sf "${CLI_BIN}" /usr/local/bin/bastion >/dev/null 2>&1 || true

if [ -x "${CLI_BIN}" ]; then
  echo "==> CLI status"
  STATUS_OK=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if "${CLI_BIN}" status; then
      STATUS_OK=1
      break
    fi
    /bin/sleep 1
  done
  if [ "${STATUS_OK}" -ne 1 ]; then
    echo "Bastion helper did not become reachable over XPC." >&2
    exit 1
  fi
fi

echo "==> Active Bastion processes"
/bin/ps aux | /usr/bin/grep -E '/bastion\\.app/Contents/MacOS/bastion|/bastion-helper\\.app/Contents/MacOS/bastion-helper' | /usr/bin/grep -v grep || true

echo "==> Done"
echo "App: ${APP_PATH}"
echo "CLI: ${CLI_BIN}"
echo "Helper: ${HELPER_BIN}"
