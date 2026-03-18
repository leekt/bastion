#!/bin/sh

set -eu

CLI_SOURCE_FILE="${SRCROOT}/bastion-cli/main.swift"
OUTPUT_DIR="${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/MacOS"
OUTPUT_FILE="${OUTPUT_DIR}/bastion-cli"
HELPER_BUNDLE_IDENTIFIER="${PRODUCT_BUNDLE_IDENTIFIER}.helper"
HELPER_SOURCE_APP="${BUILT_PRODUCTS_DIR}/bastion-helper.app"
HELPER_OUTPUT_DIR="${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/Helpers"
HELPER_OUTPUT_APP="${HELPER_OUTPUT_DIR}/bastion-helper.app"
AGENT_PLIST_DIR="${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/Library/LaunchAgents"
AGENT_PLIST_FILE="${AGENT_PLIST_DIR}/com.bastion.xpc.plist"
TEMP_DIR="${TARGET_TEMP_DIR}/bastion-cli"
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
SWIFTC="$(xcrun --find swiftc)"

SWIFT_OPT="-Onone"
if [ "${CONFIGURATION}" = "Release" ]; then
    SWIFT_OPT="-O"
fi

mkdir -p "${OUTPUT_DIR}" "${HELPER_OUTPUT_DIR}" "${AGENT_PLIST_DIR}" "${TEMP_DIR}"

set --
for ARCH in ${ARCHS}; do
    ARCH_OUTPUT="${TEMP_DIR}/bastion-cli-${ARCH}"
    TARGET_TRIPLE="${ARCH}-apple-macos${MACOSX_DEPLOYMENT_TARGET}"

    "${SWIFTC}" \
        "${CLI_SOURCE_FILE}" \
        -sdk "${SDK_PATH}" \
        -target "${TARGET_TRIPLE}" \
        "${SWIFT_OPT}" \
        -o "${ARCH_OUTPUT}"

    set -- "$@" "${ARCH_OUTPUT}"
done

if [ "$#" -eq 1 ]; then
    /bin/cp "$1" "${OUTPUT_FILE}"
else
    /usr/bin/lipo -create "$@" -output "${OUTPUT_FILE}"
fi

/bin/chmod 755 "${OUTPUT_FILE}"

if [ -d "${HELPER_SOURCE_APP}" ]; then
    /bin/rm -rf "${HELPER_OUTPUT_APP}"
    /usr/bin/ditto "${HELPER_SOURCE_APP}" "${HELPER_OUTPUT_APP}"
fi

cat > "${AGENT_PLIST_FILE}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.bastion.xpc</string>
  <key>BundleProgram</key>
  <string>Contents/MacOS/bastion</string>
  <key>AssociatedBundleIdentifiers</key>
  <array>
    <string>${PRODUCT_BUNDLE_IDENTIFIER}</string>
    <string>${HELPER_BUNDLE_IDENTIFIER}</string>
  </array>
  <key>MachServices</key>
  <dict>
    <key>com.bastion.xpc</key>
    <true/>
  </dict>
  <key>KeepAlive</key>
  <true/>
  <key>RunAtLoad</key>
  <true/>
  <key>ProcessType</key>
  <string>Interactive</string>
</dict>
</plist>
EOF

if [ "${CODE_SIGNING_ALLOWED:-NO}" = "YES" ] && [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then
    /usr/bin/codesign --force --sign "${EXPANDED_CODE_SIGN_IDENTITY}" --timestamp=none "${OUTPUT_FILE}"
fi
