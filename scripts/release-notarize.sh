#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
OUTPUT_ROOT="${BASTION_RELEASE_OUTPUT_DIR:-${ROOT_DIR}/dist/release}"
APP_PATH="${1:-${OUTPUT_ROOT}/Bastion.app}"

if [ ! -d "${APP_PATH}" ]; then
  echo "App bundle not found at ${APP_PATH}" >&2
  exit 1
fi

if [ -z "${BASTION_NOTARY_PROFILE:-}" ]; then
  echo "Set BASTION_NOTARY_PROFILE to a notarytool keychain profile name." >&2
  exit 1
fi

VERSION="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleShortVersionString)"
BUILD_NUMBER="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleVersion)"
ZIP_PATH="${OUTPUT_ROOT}/Bastion-${VERSION}-${BUILD_NUMBER}-macOS.zip"
NOTARY_LOG_PATH="${OUTPUT_ROOT}/Bastion-${VERSION}-${BUILD_NUMBER}-notary.json"
NOTARY_STATUS_PATH="${OUTPUT_ROOT}/Bastion-${VERSION}-${BUILD_NUMBER}-notary-status.json"

if [ ! -f "${ZIP_PATH}" ]; then
  echo "Release zip not found at ${ZIP_PATH}. Run ./scripts/release-build.sh first." >&2
  exit 1
fi

echo "==> Submitting release zip for notarization"
xcrun notarytool submit \
  "${ZIP_PATH}" \
  --keychain-profile "${BASTION_NOTARY_PROFILE}" \
  --wait \
  --output-format json \
  > "${NOTARY_LOG_PATH}"

echo "==> Stapling notarization ticket"
xcrun stapler staple "${APP_PATH}"

echo "==> Validating stapled app"
xcrun stapler validate "${APP_PATH}"
spctl --assess --type execute --verbose=4 "${APP_PATH}"

echo "==> Repacking stapled zip"
/bin/rm -f "${ZIP_PATH}"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "${APP_PATH}" "${ZIP_PATH}"

SHA256="$(/usr/bin/shasum -a 256 "${ZIP_PATH}" | /usr/bin/awk '{print $1}')"
SIZE_BYTES="$(/usr/bin/stat -f%z "${ZIP_PATH}")"

cat > "${NOTARY_STATUS_PATH}" <<EOF
{
  "notarized": true,
  "stapled": true
}
EOF

echo "==> Notarization complete"
echo "Notary log: ${NOTARY_LOG_PATH}"
echo "Notary status: ${NOTARY_STATUS_PATH}"
echo "Zip: ${ZIP_PATH}"
echo "SHA256: ${SHA256}"
echo "Size: ${SIZE_BYTES}"
