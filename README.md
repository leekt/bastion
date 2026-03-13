# Bastion

Hardware-backed signing guard for AI agents on macOS. Bastion uses Apple Secure Enclave to hold private keys and macOS Keychain for tamper-proof state storage. Agents interact through a CLI that communicates with the app over XPC — they can sign freely within configured rules, but need biometric override to break them.

## Why

AI agents that interact with blockchains need to sign transactions. Giving an agent direct access to a private key means a compromised or misbehaving agent can drain funds. Bastion sits between the agent and the key:

- The private key **never leaves the Secure Enclave**. It cannot be exported, copied, or read — even by Bastion itself.
- Every signing request goes through a **rule engine** (rate limits, allowed hours, whitelist).
- Within rules: signing is **silent and autonomous** — no user interaction needed.
- Breaking rules: requires **biometric authentication** (master key override).
- Config and state are in **macOS Keychain** — agents cannot read, modify, or delete them.
- A tamper-proof **audit log** records every request, approval, and denial.

## Architecture

```
Agent (Python / TypeScript / any process)
  |
  |  subprocess: bastion sign --data <hex>
  v
bastion-cli --- XPC (code-signed) ---> Bastion.app (menu bar)
                                        |
                                        +-- RuleEngine (config from Keychain)
                                        +-- StateStore (counters in Keychain)
                                        +-- Approval Popup (60s timeout)
                                        +-- LAContext Auth (Touch ID / passcode)
                                        +-- Secure Enclave ---> ECDSA P-256 signature
                                              |
                                              v
                                        JSON response ---> stdout ---> Agent
```

### Security model

| Layer | What it protects | Mechanism |
|-------|-----------------|-----------|
| Secure Enclave | Private key material | Hardware isolation — keys never leave the SE chip |
| macOS Keychain | Config + rate limit state | Access group scoping — only Bastion.app can read/write |
| Hardened Runtime | App process integrity | Prevents debugger attachment, dylib injection, memory manipulation |
| XPC code signing | IPC channel | Rejects connections from binaries not signed by the same team |
| Rule engine | Operational limits | Rate limits, time windows, address whitelist |
| Biometric auth | Rule changes + overrides | `LAContext` with `.biometricOrPasscode` for config saves and rule violations |
| Audit log | Accountability | Append-only JSON Lines, no delete API |

### What agents can do

- **Sign data** (`bastion sign`) — within rules, silently; outside rules, with user biometric override
- **Read public key** (`bastion pubkey`) — always allowed
- **Read rules** (`bastion rules`) — always allowed
- **Read state** (`bastion state`) — check remaining daily tx quota
- **Check status** (`bastion status`) — health check

### What agents cannot do

- Access Keychain items (config, state) — wrong code signing identity
- Modify rules — requires biometric auth through the app UI
- Reset rate limit counters — state is in Keychain, survives app restarts
- Forge XPC connections — team ID verification on every connection
- Inject code into Bastion.app — Hardened Runtime blocks it

### Signing key

| | Key B ("Signing Key") |
|---|---|
| **Tag** | `com.bastion.signingkey` |
| **Purpose** | Sign user data (ECDSA P-256 / secp256r1) |
| **SE access control** | `.privateKeyUsage` (silent — no auth prompt) |
| **Auth gate** | Software-enforced via rule engine + `LAContext` |

The key's SE access control is intentionally open so signing doesn't prompt. The real gate is the rule engine and `LAContext` authentication before the SE call. Auth policy is configurable (open, passcode, biometric, biometricOrPasscode).

### Signing flow

```
1. bastion-cli sends sign request over XPC
2. XPCServer verifies client code signature + team ID
3. RuleEngine.validate() — checks rate limits, allowed hours, whitelist
4. StateStore.todayCount() — checks daily transaction limit

   If all rules pass:
     5a. Optional explicit approval popup (if configured)
     5b. Auth per policy (.open skips, .biometric prompts, etc.)
     5c. Sign with Secure Enclave Key B

   If any rule fails:
     5a. Show violation popup (what rule was broken)
     5b. User approves → biometric auth (master key, non-negotiable)
     5c. Sign with Secure Enclave Key B

6. Increment daily counter in Keychain
7. Record audit log entry
8. Return JSON response via XPC → CLI stdout → Agent
```

### Storage

All persistent state is in macOS Keychain (service: `com.bastion`):

| Account | Contents |
|---------|----------|
| `config` | BastionConfig JSON (auth policy, rules, whitelist) |
| `state.ratelimit` | Daily tx counter (date + count) |

Audit log (display only, not security-critical): `~/Library/Application Support/Bastion/audit.log`

---

## Requirements

- macOS 13+ (Apple Silicon recommended for Secure Enclave)
- Xcode 16+
- A real Mac — Secure Enclave does not work in Simulator

## Project structure

```
bastion.xcodeproj
├── bastion/                          # Main app target (menu bar)
│   ├── App/BastionApp.swift
│   ├── MenuBar/MenuBarManager.swift
│   ├── Signing/
│   │   ├── SecureEnclaveManager.swift
│   │   ├── SigningManager.swift
│   │   └── AuthManager.swift
│   ├── Rules/
│   │   ├── RuleEngine.swift
│   │   ├── RuleModels.swift
│   │   └── StateStore.swift
│   ├── IPC/
│   │   ├── BastionXPCProtocol.swift
│   │   └── XPCServer.swift
│   ├── UI/
│   │   ├── SigningRequestView.swift
│   │   └── RulesSettingsView.swift
│   └── Utilities/
│       ├── KeychainStore.swift
│       ├── CLIInstaller.swift
│       └── AuditLog.swift
├── bastion-cli/                      # CLI target (Command Line Tool)
│   └── main.swift
└── bastionTests/                     # Unit tests
    └── StateStoreTests.swift
```

## Build & install

### 1. Open in Xcode

```bash
open bastion.xcodeproj
```

### 2. Verify build settings

These should already be set:

- **Signing & Capabilities → Keychain Sharing**: group = `com.bastion`
- **Signing & Capabilities → Hardened Runtime**: enabled
- **Signing & Capabilities → App Sandbox**: disabled
- **Info → Custom macOS Application Target Properties**: `Application is agent (UIElement)` = `YES`

### 3. Build & run

1. Select the **bastion** scheme and build (Cmd+B)
2. Run — a lock icon appears in the menu bar
3. On first launch the app:
   - Creates Secure Enclave signing key
   - Installs `~/Library/LaunchAgents/com.bastion.xpc.plist` for XPC
   - Attempts to symlink `bastion-cli` to `/usr/local/bin/bastion`

### 4. Activate the LaunchAgent

The app writes the plist automatically. To activate:

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.bastion.xpc.plist
```

Verify it's loaded:

```bash
launchctl print gui/$(id -u)/com.bastion.xpc
```

### 5. Install the CLI manually (if auto-install failed)

```bash
BASTION_CLI=$(find ~/Library/Developer/Xcode/DerivedData -name "bastion-cli" -type f | head -1)
sudo ln -sf "$BASTION_CLI" /usr/local/bin/bastion
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

# Check signing state (daily tx count and remaining quota)
bastion state
# {"todayCount": 3, "dailyLimit": 5, "remaining": 2}

# View current rules
bastion rules

# Request a signature (32 bytes = 64 hex chars)
bastion sign --data a3f1c2d4e5b67890abcdef1234567890abcdef1234567890abcdef1234567890
# {"pubkeyX": "...", "pubkeyY": "...", "r": "...", "s": "..."}
```

All output is JSON on stdout. Errors go to stderr with exit code 1.

### From an AI agent

**Python:**

```python
import subprocess, json

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

# Remove audit log
rm -rf ~/Library/Application\ Support/Bastion/

# Remove the app
# (drag from /Applications to Trash, or delete build products)
```

Secure Enclave keys persist in the hardware keychain. To delete them, use Keychain Access.app and search for `com.bastion.signingkey`.

---

## Documentation

See [OVERVIEW.md](OVERVIEW.md) for the full security model, threat analysis, trust assumptions, and path forward.
