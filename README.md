# Bastion

Hardware-backed signing guard for AI agents on macOS. Bastion uses the Secure Enclave to hold private keys and enforces configurable rules + user approval before any signing operation can proceed. An agent (or any process) can request signatures through the CLI, but every request must pass the rule engine and (optionally) an explicit user approval popup before the Secure Enclave ever touches the data.

## Why

AI agents that interact with blockchains need to sign transactions. Giving an agent direct access to a private key means a compromised or misbehaving agent can drain funds. Bastion sits between the agent and the key:

- The private key **never leaves the Secure Enclave**. It cannot be exported, copied, or read by software.
- Every signing request goes through a **rule engine** (rate limits, allowed hours, whitelist) and an **approval popup** the user must click.
- Authentication (Touch ID, passcode, or none) is **configurable per-deployment** without recreating the key.
- A tamper-proof **audit log** records every request, approval, and denial.

## Architecture

```
Agent (Python / TypeScript / any process)
  |
  |  subprocess: bastion sign --data <hex>
  v
bastion-cli --- XPC (code-signed) ---> Bastion.app (menu bar)
                                        |
                                        +-- RuleEngine ---> deny / allow
                                        +-- Approval Popup (60s timeout)
                                        +-- LAContext Auth (Touch ID / passcode)
                                        +-- Secure Enclave ---> ECDSA P-256 signature
                                              |
                                              v
                                        JSON response ---> stdout ---> Agent
```

### Two keys, two roles

| | Key A ("Config Key") | Key B ("Signing Key") |
|---|---|---|
| **Tag** | `com.bastion.configkey` | `com.bastion.signingkey` |
| **Purpose** | Encrypt + sign the config file | Sign user data (the actual signing key) |
| **SE access control** | `.privateKeyUsage` + `.userPresence` (always) | `.privateKeyUsage` only (always open) |
| **Auth** | Hardware-enforced -- SE itself demands biometric/passcode on every private-key use | Software-enforced -- `LAContext` runs before calling SE, policy is configurable |

Key A's access control is hardcoded and cannot be changed. This protects the configuration: an attacker who tampers with `config.enc` can't decrypt or re-sign it without passing the Secure Enclave's biometric/passcode check.

Key B's access control is intentionally open (`.privateKeyUsage` only) so the SE signs without prompting. The real gate is the `LAContext` authentication step *before* the SE call, whose policy is stored in the encrypted config. This lets you change auth policy (e.g., from biometric to open for CI) without deleting and recreating the SE key.

### Signing request flow

```
1. bastion-cli sends sign request over XPC
2. OS verifies bastion-cli code signature (XPC built-in)
3. XPCServer receives the request
4. RuleEngine.validate() -- checks rate limits, allowed hours, whitelist
   -> violation? -> deny immediately, log, return error
5. SigningRequestView popup appears (floating panel, always-on-top)
   -> shows data hex prefix, request time, 60s countdown
   -> user clicks [Deny] or timeout expires -> deny, log, return error
   -> user clicks [Approve] -> continue
6. AuthManager.authenticate() -- runs LAContext with configured policy
   -> .open: skip (no prompt)
   -> .biometric: Touch ID only
   -> .passcode: system password only
   -> .biometricOrPasscode: Touch ID or password (default)
   -> failure -> deny, log, return error
7. SecureEnclaveManager.sign() -- Key B signs the 32-byte data
   -> ECDSA P-256 / secp256r1 / SHA-256
   -> DER -> (r, s) parsed to 32-byte each
8. Audit log records success
9. JSON response returned through XPC -> bastion-cli stdout
```

### Configuration storage

Config lives at `~/Library/Application Support/Bastion/config.enc`.

It is encrypted with Key A using ECIES (P-256 + AES-GCM) and signed for integrity:

```
Save:  JSON -> sign(Key A private, triggers biometric) -> encrypt(Key A public) -> write
Load:  read -> decrypt(Key A private, triggers biometric) -> verify(Key A public) -> parse
```

On first launch or if auth is declined, defaults are used (all rules enabled, biometricOrPasscode, explicit approval required).

### Config format (plaintext JSON inside the encrypted blob)

```json
{
  "version": 1,
  "authPolicy": "biometricOrPasscode",
  "rules": {
    "enabled": true,
    "requireExplicitApproval": true,
    "maxAmountPerTx": null,
    "dailyLimit": null,
    "whitelistOnly": false,
    "whitelist": [],
    "allowedHours": null,
    "maxTxPerHour": null
  }
}
```

`authPolicy` options: `open`, `passcode`, `biometric`, `biometricOrPasscode`.

### IPC: XPC with Mach service

The app registers a Mach service (`com.bastion.xpc`) via a LaunchAgent plist. The CLI connects using `NSXPCConnection(machServiceName:)`. macOS verifies the CLI's code signature at the XPC layer -- unsigned or tampered binaries are rejected before any application code runs.

The LaunchAgent plist is installed automatically at `~/Library/LaunchAgents/com.bastion.xpc.plist` on first app launch.

### Audit log

Append-only JSON Lines at `~/Library/Application Support/Bastion/audit.log`. Each line:

```json
{"timestamp":"2026-03-13T12:34:56.789Z","type":"sign_success","dataPrefix":"a3f1c2d4","reason":null}
```

Event types: `sign_success`, `sign_denied`, `rule_violation`, `auth_failed`.

### Menu bar

The app runs as a menu bar agent (`LSUIElement = true`). No Dock icon, no main window.

| Icon | State |
|------|-------|
| `lock.fill` (default color) | Idle |
| `lock.open.fill` (orange) | Request pending |
| `checkmark.shield.fill` (green, 3s) | Signed successfully |
| `xmark.shield.fill` (red, 3s) | Denied |

Menu shows the last 5 audit events, a link to Rules Settings, and Quit.

---

## Requirements

- macOS 13+ (Apple Silicon recommended for Secure Enclave)
- Xcode 16+
- A real Mac -- Secure Enclave does not work in Simulator

## Project structure

```
bastion.xcodeproj
+-- bastion/                          <- Main app target (menu bar)
|   +-- App/BastionApp.swift
|   +-- MenuBar/MenuBarManager.swift
|   +-- Signing/
|   |   +-- SecureEnclaveManager.swift
|   |   +-- SigningManager.swift
|   |   +-- AuthManager.swift
|   +-- Rules/
|   |   +-- RuleEngine.swift
|   |   +-- RuleModels.swift
|   +-- IPC/
|   |   +-- BastionXPCProtocol.swift
|   |   +-- XPCServer.swift
|   +-- UI/
|   |   +-- SigningRequestView.swift
|   |   +-- RulesSettingsView.swift
|   +-- Utilities/
|       +-- CLIInstaller.swift
|       +-- AuditLog.swift
|
+-- bastion-cli/                      <- CLI target (Command Line Tool)
|   +-- main.swift
|   +-- bastion-cli.entitlements
|
+-- BastionShared/                    <- Reference copy of XPC protocol
|   +-- BastionXPCProtocol.swift
|
+-- bastion.entitlements
```

## Build & install

### 1. Open in Xcode

```bash
open bastion.xcodeproj
```

### 2. Configure the main app target (`bastion`)

These should already be set, but verify:

- **Signing & Capabilities -> Keychain Sharing**: group = `com.bastion`
- **Signing & Capabilities -> Hardened Runtime**: enabled
- **Signing & Capabilities -> App Sandbox**: **disabled** (remove if present)
- **Info -> Custom macOS Application Target Properties**: add `Application is agent (UIElement)` = `YES`

### 3. Create the CLI target

1. **File -> New -> Target -> macOS -> Command Line Tool**
2. Product name: `bastion-cli`
3. Move `bastion-cli/main.swift` into the new target (or set its target membership)
4. Set the target's code signing entitlements to `bastion-cli/bastion-cli.entitlements`
5. **Signing & Capabilities -> Keychain Sharing**: group = `com.bastion`
6. **Signing & Capabilities -> Hardened Runtime**: enabled
7. **Signing & Capabilities -> App Sandbox**: disabled

### 4. Build & run

1. Select the **bastion** scheme and build (Cmd+B)
2. Run -- a lock icon appears in the menu bar
3. On first launch the app:
   - Creates Secure Enclave keys (Key A + Key B)
   - Installs `~/Library/LaunchAgents/com.bastion.xpc.plist` for XPC
   - Attempts to symlink `bastion-cli` to `/usr/local/bin/bastion`

### 5. Install the LaunchAgent

The app writes the plist automatically. To activate it:

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.bastion.xpc.plist
```

After this, the Mach service `com.bastion.xpc` is registered and the CLI can connect.

To check it's loaded:

```bash
launchctl print gui/$(id -u)/com.bastion.xpc
```

### 6. Install the CLI manually (if auto-install failed)

If `/usr/local/bin/bastion` wasn't created (permissions), symlink manually:

```bash
# Find the built binary -- path depends on your Xcode derived data
BASTION_CLI=$(find ~/Library/Developer/Xcode/DerivedData -name "bastion-cli" -type f | head -1)
sudo ln -sf "$BASTION_CLI" /usr/local/bin/bastion
```

Or copy the binary directly:

```bash
sudo cp "$BASTION_CLI" /usr/local/bin/bastion
```

---

## CLI usage

```bash
# Check if the app is running
bastion status
# {"status": "running"}

# Get the public key (P-256 uncompressed, x and y as hex)
bastion pubkey
# {"x": "3a2f...", "y": "9b1e..."}

# Request a signature (32 bytes = 64 hex chars)
bastion sign --data a3f1c2d4e5b67890abcdef1234567890abcdef1234567890abcdef1234567890
# approval popup appears in menu bar
# after user approves + authenticates:
# {"pubkeyX": "...", "pubkeyY": "...", "r": "...", "s": "..."}

# View current rules
bastion rules
```

All output is JSON on stdout. Errors go to stderr with exit code 1.

### From an AI agent

**Python:**

```python
import subprocess
import json

result = subprocess.run(
    ["bastion", "sign", "--data", "a3f1c2d4e5b6..."],
    capture_output=True, text=True, timeout=65
)
if result.returncode != 0:
    raise Exception(result.stderr)

sig = json.loads(result.stdout)
# sig["pubkeyX"], sig["pubkeyY"], sig["r"], sig["s"]
```

**TypeScript:**

```typescript
import { execFileSync } from "child_process";

const result = execFileSync(
  "bastion",
  ["sign", "--data", "a3f1c2d4e5b6..."],
  { timeout: 65000 }
);
const sig = JSON.parse(result.toString());
```

---

## Uninstall

```bash
# Remove LaunchAgent
launchctl bootout gui/$(id -u)/com.bastion.xpc
rm ~/Library/LaunchAgents/com.bastion.xpc.plist

# Remove CLI symlink
sudo rm /usr/local/bin/bastion

# Remove data
rm -rf ~/Library/Application\ Support/Bastion/

# Remove the app
# (drag from /Applications to Trash, or delete build products)
```

Secure Enclave keys persist in the hardware keychain. To delete them, use Keychain Access.app and search for `com.bastion.configkey` / `com.bastion.signingkey`.

---

## Security model

| Layer | What it protects | Mechanism |
|-------|-----------------|-----------|
| Secure Enclave | Private key material | Hardware isolation -- keys never leave the SE chip |
| XPC code signing | IPC channel | OS rejects connections from unsigned/tampered binaries |
| Key A access control | Configuration integrity | `.userPresence` -- SE demands biometric/passcode for every config decrypt/sign |
| Rule engine | Operational limits | Rate limits, time windows, address whitelist |
| Approval popup | Human-in-the-loop | 60s timeout, always-on-top floating panel |
| LAContext | Per-request auth | Configurable biometric/passcode/none before SE signing |
| Audit log | Accountability | Append-only JSON Lines, no delete API |
| ECIES + ECDSA on config | Tamper detection | Config encrypted (ECIES AES-GCM) + signed (ECDSA); any modification fails decryption or signature check |

### What Bastion does NOT protect against

- A compromised macOS kernel or bootloader (game over for any userland security)
- Physical access with the device unlocked and auth policy set to `open`
- Social engineering the user into clicking "Approve" on a malicious request
- Denial of service (an attacker can't sign, but could potentially block the XPC service)

---

## Data directories

```
~/Library/Application Support/Bastion/
+-- config.enc        <- Encrypted config (Key A, ECIES + ECDSA)
+-- audit.log         <- JSON Lines audit log (append-only)

~/Library/LaunchAgents/
+-- com.bastion.xpc.plist   <- Mach service registration for XPC
```
