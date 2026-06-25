#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
OUTPUT_ROOT="${BASTION_RELEASE_OUTPUT_DIR:-${ROOT_DIR}/dist/release}"
APP_PATH="${1:-${OUTPUT_ROOT}/Bastion.app}"
EXPECTED_TEAM_ID="${BASTION_EXPECTED_TEAM_ID:-926A27BQ7W}"

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

if [ ! -d "${APP_PATH}" ]; then
  echo "App bundle not found at ${APP_PATH}" >&2
  exit 1
fi

if [ -z "${BASTION_RELEASE_DOWNLOAD_URL:-}" ]; then
  echo "Set BASTION_RELEASE_DOWNLOAD_URL before generating a release manifest." >&2
  exit 1
fi

VERSION="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleShortVersionString)"
BUILD_NUMBER="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleVersion)"
BUNDLE_ID="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleIdentifier)"
ZIP_PATH="${OUTPUT_ROOT}/Bastion-${VERSION}-${BUILD_NUMBER}-macOS.zip"
MANIFEST_PATH="${OUTPUT_ROOT}/latest.json"
NOTARY_STATUS_PATH="${OUTPUT_ROOT}/Bastion-${VERSION}-${BUILD_NUMBER}-notary-status.json"

MINIMUM_OS_VERSION="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" LSMinimumSystemVersion 2>/dev/null || echo "11.0")"
PUBLISHED_AT="$(/bin/date -u +"%Y-%m-%dT%H:%M:%SZ")"
RELEASE_NOTES_URL="${BASTION_RELEASE_NOTES_URL:-}"
if [ ! -f "${NOTARY_STATUS_PATH}" ]; then
  echo "Notarization status file not found at ${NOTARY_STATUS_PATH}; refusing to publish manifest." >&2
  exit 1
fi

NOTARIZED="$(/usr/bin/plutil -extract notarized raw -expect bool -o - "${NOTARY_STATUS_PATH}" 2>/dev/null || echo false)"
STAPLED="$(/usr/bin/plutil -extract stapled raw -expect bool -o - "${NOTARY_STATUS_PATH}" 2>/dev/null || echo false)"
if [ "${NOTARIZED}" != "true" ] || [ "${STAPLED}" != "true" ]; then
  echo "App is not marked notarized/stapled in ${NOTARY_STATUS_PATH}; refusing to publish manifest." >&2
  exit 1
fi
STATUS_VERSION="$(/usr/bin/plutil -extract version raw -expect string -o - "${NOTARY_STATUS_PATH}" 2>/dev/null || true)"
STATUS_BUILD="$(/usr/bin/plutil -extract build raw -expect string -o - "${NOTARY_STATUS_PATH}" 2>/dev/null || true)"
STATUS_BUNDLE_ID="$(/usr/bin/plutil -extract bundleIdentifier raw -expect string -o - "${NOTARY_STATUS_PATH}" 2>/dev/null || true)"
STATUS_TEAM_ID="$(/usr/bin/plutil -extract teamIdentifier raw -expect string -o - "${NOTARY_STATUS_PATH}" 2>/dev/null || true)"
if [ "${STATUS_VERSION}" != "${VERSION}" ] || [ "${STATUS_BUILD}" != "${BUILD_NUMBER}" ] || \
   [ "${STATUS_BUNDLE_ID}" != "${BUNDLE_ID}" ] || [ "${STATUS_TEAM_ID}" != "${EXPECTED_TEAM_ID}" ]; then
  echo "Notarization status file does not match the app being published." >&2
  exit 1
fi

echo "==> Verifying notarized/stapled app artifact"
verify_app "${APP_PATH}"

echo "==> Repacking release zip from verified app artifact"
/bin/rm -f "${ZIP_PATH}"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "${APP_PATH}" "${ZIP_PATH}"

SHA256="$(/usr/bin/shasum -a 256 "${ZIP_PATH}" | /usr/bin/awk '{print $1}')"
SIZE_BYTES="$(/usr/bin/stat -f%z "${ZIP_PATH}")"

cat > "${MANIFEST_PATH}" <<EOF
{
  "app": "Bastion",
  "bundleIdentifier": "${BUNDLE_ID}",
  "version": "${VERSION}",
  "build": "${BUILD_NUMBER}",
  "platform": "macOS",
  "minimumOSVersion": "${MINIMUM_OS_VERSION}",
  "publishedAt": "${PUBLISHED_AT}",
  "downloadURL": "${BASTION_RELEASE_DOWNLOAD_URL}",
  "releaseNotesURL": "${RELEASE_NOTES_URL}",
  "sha256": "${SHA256}",
  "sizeBytes": ${SIZE_BYTES},
  "notarized": ${NOTARIZED},
  "stapled": ${STAPLED}
}
EOF

echo "==> Release manifest written"
echo "Manifest: ${MANIFEST_PATH}"
echo "Download URL: ${BASTION_RELEASE_DOWNLOAD_URL}"
