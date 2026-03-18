# Bastion Release Flow

This document describes the release path that now exists in the repository.

It covers five stages:

1. build a signed release app
2. notarize and staple it
3. create a drag-and-drop DMG
4. generate a deterministic update manifest
5. install and verify the release bundle locally from `/Applications/Bastion.app`

## Preconditions

- Apple Developer signing is configured in Xcode for:
  - `taek.bastion`
  - `taek.bastion.helper`
- `xcrun notarytool` credentials have been stored in a keychain profile
- the release machine can sign and notarize macOS apps

## 1. Build the Release Artifact

```bash
cd /Users/taek/workspace/bastion-app/bastion
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

## 2. Notarize and Staple

Set the notarytool profile name:

```bash
export BASTION_NOTARY_PROFILE="your-notarytool-profile"
```

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

If notarization status is missing, the script still creates the DMG but prints a warning.

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

`notarized` and `stapled` are `false` until `./scripts/release-notarize.sh` has completed successfully for the same version/build. The manifest does not claim notarization preemptively.

This is the repository's current update-distribution contract. It is intended as the stable server-side input for a future in-app updater.

## 5. Install the Release Locally

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
- installs `/usr/local/bin/bastion` when writable
- verifies XPC reachability with `bastion-cli status`

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
- a machine-generated manifest that an updater can consume later

## What Is Still Not Implemented

This is not yet a full in-app auto-update system.

Still missing:

- updater client integration
- signature verification for update metadata inside the app
- delta updates
- release channel selection
- automatic rollback behavior

The current repository now has the release pipeline and manifest side of the problem wired up, which is the correct base to add an updater on top of later.
