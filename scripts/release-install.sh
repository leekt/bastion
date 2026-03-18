#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
OUTPUT_ROOT="${BASTION_RELEASE_OUTPUT_DIR:-${ROOT_DIR}/dist/release}"
SOURCE_APP_PATH="${1:-${OUTPUT_ROOT}/Bastion.app}"
INSTALL_APP_PATH="${BASTION_INSTALL_PATH:-/Applications/Bastion.app}"
INSTALL_PARENT_DIR="$(dirname "${INSTALL_APP_PATH}")"
APP_BIN="${INSTALL_APP_PATH}/Contents/MacOS/bastion"
CLI_BIN="${INSTALL_APP_PATH}/Contents/MacOS/bastion-cli"
LAUNCH_AGENT_LABEL="com.bastion.xpc"

if [ ! -d "${SOURCE_APP_PATH}" ]; then
  echo "Source app bundle not found at ${SOURCE_APP_PATH}" >&2
  exit 1
fi

if [ ! -w "${INSTALL_PARENT_DIR}" ] && [ ! -e "${INSTALL_APP_PATH}" ]; then
  echo "No write access to ${INSTALL_PARENT_DIR}. Re-run with sudo or set BASTION_INSTALL_PATH." >&2
  exit 1
fi

if [ -e "${INSTALL_APP_PATH}" ] && [ ! -w "${INSTALL_APP_PATH}" ]; then
  echo "No write access to existing ${INSTALL_APP_PATH}. Re-run with sudo or set BASTION_INSTALL_PATH." >&2
  exit 1
fi

echo "==> Stopping existing Bastion service"
/bin/launchctl bootout "gui/$(id -u)/${LAUNCH_AGENT_LABEL}" >/dev/null 2>&1 || true
/usr/bin/pkill -f '/bastion-helper.app/Contents/MacOS/bastion-helper($| )' >/dev/null 2>&1 || true
/usr/bin/pkill -f '/bastion.app/Contents/MacOS/bastion($| )' >/dev/null 2>&1 || true

echo "==> Installing Bastion to ${INSTALL_APP_PATH}"
/bin/mkdir -p "${INSTALL_PARENT_DIR}"
/bin/rm -rf "${INSTALL_APP_PATH}"
/usr/bin/ditto "${SOURCE_APP_PATH}" "${INSTALL_APP_PATH}"

echo "==> Registering app bundle"
/System/Library/Frameworks/CoreServices.framework/Versions/Current/Frameworks/LaunchServices.framework/Versions/Current/Support/lsregister \
  -f -R -trusted "${INSTALL_APP_PATH}" >/dev/null 2>&1 || true

echo "==> Registering background service"
"${APP_BIN}" --register-service
/bin/launchctl kickstart -k "gui/$(id -u)/${LAUNCH_AGENT_LABEL}" >/dev/null 2>&1 || true

if [ -x "${CLI_BIN}" ]; then
  echo "==> Installing CLI symlink"
  /bin/mkdir -p /usr/local/bin >/dev/null 2>&1 || true
  /bin/ln -sf "${CLI_BIN}" /usr/local/bin/bastion >/dev/null 2>&1 || true
fi

echo "==> Verifying XPC reachability"
STATUS_OK=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if "${CLI_BIN}" status >/dev/null 2>&1; then
    STATUS_OK=1
    break
  fi
  /bin/sleep 1
done

if [ "${STATUS_OK}" -ne 1 ]; then
  echo "Installed Bastion app did not become reachable over XPC." >&2
  exit 1
fi

echo "==> Install complete"
echo "App: ${INSTALL_APP_PATH}"
echo "CLI: ${CLI_BIN}"
