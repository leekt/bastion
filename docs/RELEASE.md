# Bastion Release Flow

This document describes the release path that now exists in the repository.

The local release flow covers seven stages:

1. build a signed release app
2. notarize and staple it
3. create a drag-and-drop DMG
4. generate a deterministic update manifest
5. verify the release artifacts as a set
6. check and stage updates from the manifest
7. install and verify the release bundle locally from `/Applications/Bastion.app`

The repository also includes a GitHub Actions signed-release workflow that runs
stages 1-5 on a macOS runner and uploads the verified release set.

## Preconditions

- Apple Developer signing is configured in Xcode for:
  - `com.bastion.app`
  - `com.bastion.helper`
- `xcrun notarytool` credentials have been stored in a keychain profile
- the release machine can sign and notarize macOS apps

For GitHub Actions, configure these required secrets:

- `BASTION_DEVELOPER_ID_APPLICATION_P12_BASE64`
- `BASTION_DEVELOPER_ID_APPLICATION_P12_PASSWORD`
- `BASTION_NOTARY_APPLE_ID`
- `BASTION_NOTARY_TEAM_ID`
- `BASTION_NOTARY_PASSWORD`

Configure these optional secrets when Developer ID provisioning profiles are
required by the app entitlements:

- `BASTION_MAIN_PROVISIONING_PROFILE_BASE64`
- `BASTION_HELPER_PROVISIONING_PROFILE_BASE64`

Optional repository variables:

- `BASTION_EXPECTED_TEAM_ID` defaults to `926A27BQ7W`
- `BASTION_RELEASE_DOWNLOAD_BASE_URL` overrides the default GitHub Release
  download URL used in `latest.json`

## CI Signed Release Pipeline

The workflow at `.github/workflows/signed-release.yml` runs on `v*` tag pushes
and manual dispatch. It imports the Developer ID certificate into a temporary
keychain, installs optional provisioning profiles, stores the notarytool
credentials, and then runs:

```bash
./scripts/release-ci.sh
```

`release-ci.sh` calls the same release scripts used by the local path:

```bash
./scripts/release-build.sh
./scripts/release-notarize.sh
./scripts/release-create-dmg.sh
./scripts/release-generate-manifest.sh
./scripts/release-verify.sh
```

On tag pushes, the workflow uploads the ZIP, DMG, manifest, notarization status,
and notary log JSON files to the matching GitHub Release. On manual dispatch,
it uploads the same release set as a workflow artifact. When
`BASTION_RELEASE_DOWNLOAD_BASE_URL` is unset, `latest.json` is bound to the
GitHub Release asset URL for the tag.

## 1. Build the Release Artifact

```bash
cd <repo-root>
./scripts/release-build.sh
```

Output:

- `dist/release/Bastion.app`
- `dist/release/Bastion-<version>-<build>-macOS.zip`

The script also verifies the code signature and prints:

- version
- build number
- zip SHA-256
- zip size

Release builds set `BASTION_BUNDLE_CLI=0`, so the staged app contains
`Contents/MacOS/bastion-mcp` and intentionally excludes
`Contents/MacOS/bastion-cli`.

## 2. Notarize and Staple

Set the notarytool profile name:

```bash
export BASTION_NOTARY_PROFILE="your-notarytool-profile"
```

When the profile is stored in a non-default keychain, also set
`BASTION_NOTARY_KEYCHAIN` to that keychain path. The CI workflow sets
`BASTION_RELEASE_KEYCHAIN`, which `release-notarize.sh` also honors.

Then run:

```bash
./scripts/release-notarize.sh
```

This will:

- submit the release zip to Apple notarization
- wait for the result
- staple the app bundle
- assess the stapled app with `spctl`
- recreate the zip so the distributed artifact contains the stapled app

Artifacts:

- `dist/release/Bastion-<version>-<build>-notary.json`
- `dist/release/Bastion-<version>-<build>-notary-status.json`
- refreshed stapled zip

The notary status file records the bundle identifier, version, build, team identifier, ZIP SHA-256, and ZIP size so later manifest generation can verify that it is publishing the same app lineage that was notarized.

## 3. Create the DMG Installer

After the app has been notarized and stapled, create a drag-and-drop DMG:

```bash
./scripts/release-create-dmg.sh
```

This writes:

- `dist/release/Bastion-<version>-<build>-macOS.dmg`

The DMG contains:

- `Bastion.app`
- an `Applications` symlink for Finder drag-and-drop install

If notarization status is missing, the app is not stapled, or local signature/Gatekeeper verification fails, the script refuses to create the DMG.

## 4. Generate the Update Manifest

Set the public download URL, and optionally release notes:

```bash
export BASTION_RELEASE_DOWNLOAD_URL="https://downloads.example.com/Bastion-1.0-1-macOS.zip"
export BASTION_RELEASE_NOTES_URL="https://example.com/bastion/releases/1.0"
```

Then run:

```bash
./scripts/release-generate-manifest.sh
```

This writes:

- `dist/release/latest.json`

The manifest currently contains:

- bundle identifier
- version
- build
- minimum OS
- publication timestamp
- download URL
- release notes URL
- SHA-256
- size
- `notarized`
- `stapled`

Manifest generation now refuses to run unless `./scripts/release-notarize.sh` has completed successfully for the same bundle identifier, version, build, and team identifier. It then verifies the local app with signature, Gatekeeper, and stapler checks, repacks the ZIP from that verified app, and publishes the hash and size of the repacked artifact. Published manifests therefore only contain `notarized: true` and `stapled: true`.

This is the repository's current update-distribution contract and the stable
input for the app update monitor and optional development update client.

## 5. Verify the Release Set

After the app, ZIP, DMG, and manifest exist:

```bash
./scripts/release-verify.sh
```

This verifies:

- app bundle identifier, executable, Developer ID signature, Gatekeeper
  assessment, and stapled ticket
- bundled Swift `bastion-mcp` executable, signature, and `com.bastion.mcp`
  signing identifier
- absence of `bastion-cli` in production release bundles
- service LaunchAgent label, Mach service, associated bundle identifiers, and
  `BundleProgram = Contents/MacOS/bastion`
- bundled helper signature when the helper is present
- release ZIP presence plus SHA-256 and size
- DMG integrity
- update manifest identity, download URL, notarized/stapled flags, and ZIP
  SHA-256/size consistency

If any artifact does not match the staged app, the script exits non-zero.

## 6. Check and Stage Updates

Bastion uses the generated `latest.json` as the update contract. The update
client validates:

- bundle identifier
- platform
- minimum macOS version
- notarized/stapled flags
- newer version/build ordering
- ZIP SHA-256 and size after download

Optional development CLI check:

```bash
bastion update check --manifest-url "https://downloads.example.com/latest.json"
```

Optional development CLI download and verification:

```bash
bastion update download --manifest-url "https://downloads.example.com/latest.json"
```

Optional development CLI install from a downloaded or already-staged ZIP:

```bash
bastion update install --manifest-url "https://downloads.example.com/latest.json"
```

Use an explicit staged artifact when automation already downloaded the ZIP:

```bash
bastion update install \
  --manifest-url "https://downloads.example.com/latest.json" \
  --artifact "$HOME/Library/Application Support/Bastion/Updates/Bastion-1.2-3-macOS.zip"
```

By default, verified ZIPs are staged under:

- `~/Library/Application Support/Bastion/Updates`

For QA or scripting:

```bash
bastion update download \
  --manifest-url "https://downloads.example.com/latest.json" \
  --output /tmp/bastion-updates
```

The menu bar app also has an update monitor. It starts when either of these is
configured:

- `BASTION_UPDATE_MANIFEST_URL`
- `UserDefaults.standard.string(forKey: "BastionUpdateManifestURL")`

When an update is available, the monitor logs the result to diagnostics and,
by default, downloads and verifies the ZIP into Application Support. Set
`BASTION_AUTO_DOWNLOAD_UPDATES=0` or UserDefaults
`BastionAutoDownloadUpdates=false` to check without staging downloads.

The installer verifies the staged ZIP hash/size against the manifest, extracts
the app, verifies the app bundle identity, runs codesign/Gatekeeper/stapler
checks by default, moves the previous app to a rollback backup, installs the new
app, registers/kickstarts the `com.bastion.xpc` service, verifies XPC through the
bundled `bastion-mcp` status tool, skips the CLI symlink when production bundles
omit `bastion-cli`, and relaunches Bastion. If install or service recovery fails
after the old app has been moved aside, the updater restores the backup and
recovers the service from the restored app.

Useful install options:

- `--install-path <path>` changes the target app path. The default is the
  inferred host app bundle, then `/Applications/Bastion.app`.
- `--backup-directory <path>` changes where rollback backups are stored.
- `--no-relaunch` installs without reopening Bastion.
- `--skip-service-recovery` installs without registering, kickstarting, or
  verifying XPC.
- `--skip-cli-symlink` leaves `/usr/local/bin/bastion` untouched.
- `--skip-app-verification` skips codesign/Gatekeeper/stapler checks after
  manifest hash and bundle identity verification. Use this only for local QA
  fixtures.

Installing into `/Applications` requires write access to that location. Re-run
with appropriate privileges or use `--install-path` for QA installs.

## 7. Install the Release Locally

To verify the release bundle from the final install path:

```bash
./scripts/release-install.sh
```

Default install target:

- `/Applications/Bastion.app`

This script:

- stops the existing Bastion service
- installs the app into `/Applications`
- registers the app bundle with Launch Services
- registers the bundled `SMAppService` launch target
- kickstarts the registered `com.bastion.xpc` service
- verifies the bundled `/Applications/Bastion.app/Contents/MacOS/bastion-mcp`
  sidecar is present and executable
- verifies XPC reachability with `bastion_status` through `bastion-mcp`
- verifies that the responding XPC service executable is the newly installed bundle, not a stale service
- validates the stapled ticket on the source and installed app bundles

If you want to install somewhere else for QA:

```bash
BASTION_INSTALL_PATH="$HOME/Applications/Bastion QA.app" ./scripts/release-install.sh
```

## What This Solves

This release flow gives Bastion:

- deterministic signed app bundles
- deterministic zip artifacts
- deterministic drag-and-drop DMG artifacts
- notarization and stapling
- deterministic `/Applications` install behavior
- deterministic `SMAppService` registration
- a machine-generated manifest consumed by the app update monitor and optional
  development update client
- manifest-driven update checks and SHA-256/size verified ZIP staging
- verified staged update install with relaunch, service recovery, and rollback
- a single release verification gate for app, service, `bastion-mcp`, DMG, and
  manifest integrity
  integrity

## What Is Still Not Implemented

This is not yet a full multi-channel update product.

Still missing:

- delta updates
- release channel selection
- unattended policy for when the menu bar app should install without operator
  confirmation

The current repository now has the release pipeline, manifest side, update
check/download, verified staging, app replacement, relaunch, service recovery,
and rollback wired up.
