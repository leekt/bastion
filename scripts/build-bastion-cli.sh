#!/bin/sh

set -eu

CLI_SOURCE_FILE="${SRCROOT}/bastion-cli/main.swift"
MCP_SOURCE_FILE="${SRCROOT}/bastion-mcp/main.swift"
UPDATE_SOURCE_FILE="${SRCROOT}/bastion/Utilities/ReleaseUpdate.swift"
UPDATE_INSTALLER_SOURCE_FILE="${SRCROOT}/bastion/Utilities/ReleaseUpdateInstaller.swift"
OUTPUT_DIR="${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/MacOS"
CLI_OUTPUT_FILE="${OUTPUT_DIR}/bastion-cli"
MCP_OUTPUT_FILE="${OUTPUT_DIR}/bastion-mcp"
HELPER_BUNDLE_IDENTIFIER="${BASTION_HELPER_BUNDLE_ID:-${PRODUCT_BUNDLE_IDENTIFIER}.helper}"
HELPER_SOURCE_APP="${BUILT_PRODUCTS_DIR}/bastion-helper.app"
HELPER_OUTPUT_DIR="${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/Helpers"
HELPER_OUTPUT_APP="${HELPER_OUTPUT_DIR}/bastion-helper.app"
AGENT_PLIST_DIR="${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/Library/LaunchAgents"
AGENT_PLIST_FILE="${AGENT_PLIST_DIR}/com.bastion.xpc.plist"
TEMP_DIR="${TARGET_TEMP_DIR}/bastion-sidecars"
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
SWIFTC="$(xcrun --find swiftc)"

SWIFT_OPT="-Onone"
if [ "${CONFIGURATION}" = "Release" ]; then
    SWIFT_OPT="-O"
fi

mkdir -p "${OUTPUT_DIR}" "${HELPER_OUTPUT_DIR}" "${AGENT_PLIST_DIR}" "${TEMP_DIR}"

build_sidecar() {
    output_file="$1"
    identifier="$2"
    shift 2

    outputs=""
    for ARCH in ${ARCHS}; do
        arch_output="${TEMP_DIR}/$(basename "${output_file}")-${ARCH}"
        target_triple="${ARCH}-apple-macos${MACOSX_DEPLOYMENT_TARGET}"

        "${SWIFTC}" \
            "$@" \
            -sdk "${SDK_PATH}" \
            -target "${target_triple}" \
            "${SWIFT_OPT}" \
            -o "${arch_output}"

        outputs="${outputs} ${arch_output}"
    done

    arch_count="$(printf '%s\n' ${ARCHS} | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
    if [ "${arch_count}" -eq 1 ]; then
        # shellcheck disable=SC2086
        /bin/cp ${outputs} "${output_file}"
    else
        # shellcheck disable=SC2086
        /usr/bin/lipo -create ${outputs} -output "${output_file}"
    fi

    /bin/chmod 755 "${output_file}"

    if [ "${CODE_SIGNING_ALLOWED:-NO}" = "YES" ] && [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then
        /usr/bin/codesign \
            --force \
            --sign "${EXPANDED_CODE_SIGN_IDENTITY}" \
            --timestamp=none \
            --identifier "${identifier}" \
            "${output_file}"
    fi
}

echo "==> Building bundled bastion-mcp bridge"
build_sidecar "${MCP_OUTPUT_FILE}" "com.bastion.mcp" "${MCP_SOURCE_FILE}"

if [ "${BASTION_BUNDLE_CLI:-1}" != "0" ]; then
    echo "==> Building bundled bastion-cli development bridge"
    build_sidecar \
        "${CLI_OUTPUT_FILE}" \
        "bastion-cli" \
        "${CLI_SOURCE_FILE}" \
        "${UPDATE_SOURCE_FILE}" \
        "${UPDATE_INSTALLER_SOURCE_FILE}"
else
    /bin/rm -f "${CLI_OUTPUT_FILE}"
fi

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
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>ProcessType</key>
  <string>Interactive</string>
</dict>
</plist>
EOF
