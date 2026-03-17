#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
OUTPUT_ROOT="${BASTION_RELEASE_OUTPUT_DIR:-${ROOT_DIR}/dist/release}"
APP_PATH="${1:-${OUTPUT_ROOT}/Bastion.app}"

if [ ! -d "${APP_PATH}" ]; then
  echo "App bundle not found at ${APP_PATH}" >&2
  exit 1
fi

VERSION="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleShortVersionString)"
BUILD_NUMBER="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleVersion)"
DMG_PATH="${OUTPUT_ROOT}/Bastion-${VERSION}-${BUILD_NUMBER}-macOS.dmg"
NOTARY_STATUS_PATH="${OUTPUT_ROOT}/Bastion-${VERSION}-${BUILD_NUMBER}-notary-status.json"
STAGING_DIR="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/bastion-release-dmg.XXXXXX")"
VOLUME_NAME="${BASTION_DMG_VOLUME_NAME:-Bastion}"

cleanup() {
  /bin/rm -rf "${STAGING_DIR}"
}
trap cleanup EXIT INT TERM

echo "==> Preparing DMG staging folder"
/usr/bin/ditto "${APP_PATH}" "${STAGING_DIR}/Bastion.app"
/bin/ln -s /Applications "${STAGING_DIR}/Applications"

if [ -f "${NOTARY_STATUS_PATH}" ]; then
  NOTARIZED="$(/usr/bin/plutil -extract notarized raw -expect bool -o - "${NOTARY_STATUS_PATH}" 2>/dev/null || echo false)"
  STAPLED="$(/usr/bin/plutil -extract stapled raw -expect bool -o - "${NOTARY_STATUS_PATH}" 2>/dev/null || echo false)"
  if [ "${NOTARIZED}" != "true" ] || [ "${STAPLED}" != "true" ]; then
    echo "Warning: app is not marked notarized/stapled in ${NOTARY_STATUS_PATH}" >&2
  fi
else
  echo "Warning: notarization status file not found. Creating DMG from current app bundle as-is." >&2
fi

echo "==> Creating drag-and-drop DMG"
/bin/rm -f "${DMG_PATH}"
/usr/bin/hdiutil create \
  -volname "${VOLUME_NAME}" \
  -srcfolder "${STAGING_DIR}" \
  -format UDZO \
  -imagekey zlib-level=9 \
  "${DMG_PATH}" >/dev/null

echo "==> Verifying DMG"
/usr/bin/hdiutil verify "${DMG_PATH}" >/dev/null

SIZE_BYTES="$(/usr/bin/stat -f%z "${DMG_PATH}")"
SHA256="$(/usr/bin/shasum -a 256 "${DMG_PATH}" | /usr/bin/awk '{print $1}')"

echo "==> DMG artifact ready"
echo "DMG: ${DMG_PATH}"
echo "SHA256: ${SHA256}"
echo "Size: ${SIZE_BYTES}"
