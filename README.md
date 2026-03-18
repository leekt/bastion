# Bastion

Hardware-backed signing guard for AI agents on macOS. Bastion uses Apple Secure Enclave to hold private keys and macOS Keychain for tamper-resistant state storage. Agents interact through a CLI that communicates with the app over XPC. Requests are reviewed against per-client policy, and rule overrides require explicit approval plus owner authentication.

## Why

AI agents that interact with blockchains need to sign transactions. Giving an agent direct access to a private key means a compromised or misbehaving agent can drain funds. Bastion sits between the agent and the key:

- The private key **never leaves the Secure Enclave**. It cannot be exported, copied, or read — even by Bastion itself.
- Every signing request goes through a **rule engine** (rate limits, allowed hours, whitelist).
- Every request is checked against a **per-client rule set** before signing.
- Matching requests can be signed **silently** by the client's own Secure Enclave key when policy allows it.
- Breaking rules requires **explicit approval plus owner authentication** (biometric or passcode).
- Config and state are in **macOS Keychain** — agents cannot read, modify, or delete them.
- A request-level **audit history** records what each client asked Bastion to sign, how it was approved, and whether a submitted UserOperation was confirmed.

## Architecture

Service lifecycle notes and the target migration path are documented in [docs/SERVICE_LIFECYCLE.md](./docs/SERVICE_LIFECYCLE.md). The broader release execution plan is in [PLAN.md](./PLAN.md). The concrete release/notarization/install flow is in [docs/RELEASE.md](./docs/RELEASE.md).

```
Agent (Python / TypeScript / any process)
  |
  |  subprocess: bastion eth userOp --op 0xTarget,0,0x
  v
bastion-cli --- XPC (code-signed) ---> Bastion.app (menu bar)
                                        |
                                        +-- CalldataDecoder (parse UserOp calldata)
                                        +-- RuleEngine (config from Keychain)
                                        +-- StateStore (counters in Keychain)
                                        +-- Approval Popup (60s timeout, decoded calldata)
                                        +-- LAContext Auth (Touch ID / passcode)
                                        +-- Secure Enclave ---> ECDSA P-256 signature
                                        +-- s-normalization (OZ P256 compatibility)
                                              |
                                              v
                                        JSON response ---> stdout ---> Agent / bundler client
                                                                        |
                                                                        +-- Standard RPC fee estimate
                                                                        |     (EIP-1559, 1.2x base fee)
                                                                        |
                                                                        +-- ZeroDev Bundler / Paymaster
                                                                              (optional fallback for floor fees)
                                                                              |
                                                                              v
                                                                        EntryPoint ---> Kernel v3.3
                                                                                          |
                                                                                          v
                                                                                    P256Validator (on-chain)
```

### Security model

| Layer | What it protects | Mechanism |
|-------|-----------------|-----------|
| Secure Enclave | Private key material | Hardware isolation — keys never leave the SE chip |
| macOS Keychain | Config + rate limit state | Access group scoping — only Bastion.app can read/write |
| Hardened Runtime | App process integrity | Prevents debugger attachment, dylib injection, memory manipulation |
| XPC code signing | IPC channel | Rejects connections from binaries not signed by the same team |
| Rule engine | Operational limits | Rate limits, time windows, address whitelist |
| Owner auth | Rule changes + overrides | `LAContext` with `.biometricOrPasscode` for config saves and rule violations |
| Audit history | Accountability | Request-level JSON history with a per-request timeline (`Signed -> Submitted -> Confirmed`) |

### What agents can do

- **Sign raw data** (`bastion sign`) — controlled by a simple on/off raw-message policy
- **Sign Ethereum operations** (`bastion eth message|typedData|userOp`) — structured signing with operation-specific policy:
  - raw / personal-sign: toggle only
  - EIP-712 typed data: domain + primary-type + JSON subset matching
  - UserOperation: chain, target, rate, and spending controls
  Prefer `bastion eth userOp --op <target,value,data>` for normal use. Bastion builds the Kernel `execute()` calldata and final ERC-4337 UserOperation inside the app. Use `--json-file` only for advanced explicit UserOperation debugging. The documented examples are in `docs/CLI_REQUEST_EXAMPLES.md`.
- **Read public key** (`bastion pubkey`) — always allowed
- **Read rules** (`bastion rules`) — always allowed
- **Read state** (`bastion state`) — check remaining quota per rate limit window
- **Check status** (`bastion status`) — health check

### What agents cannot do

- Access Keychain items (config, state) — wrong code signing identity
- Modify rules — requires biometric auth through the app UI
- Reset rate limit counters — state is in Keychain, survives app restarts
- Forge XPC connections — team ID verification on every connection
- Inject code into Bastion.app — Hardened Runtime blocks it
- Bypass direct-call spending checks through simple calldata wrapping — Bastion decodes actual inner call targets and direct ERC-20/native amounts
- Treat spending limits as full protocol simulation — complex protocols can still move assets indirectly, so use target allowlists and explicit approval for higher-risk flows

### Signing key

| Scope | Key tag | Notes |
|---|---|---|
| Default profile | `com.bastion.signingkey.default` | Used before a dedicated client profile exists |
| Client profile | `com.bastion.signingkey.client.<uuid>` | Each client gets its own Secure Enclave key and derived account address |
| Legacy fallback | `com.bastion.signingkey` | Older builds may have created this tag; `bastion reset-keys` removes it too |

### Key feature: silent per-client keys with app-layer owner auth

This is one of Bastion's core design choices.

- Every client profile gets its **own Secure Enclave signing key** and its **own derived account address**.
- These client keys are created with **`.privateKeyUsage` only**. The Secure Enclave signing operation itself is intended to stay silent.
- Bastion does **not** use a separate "owner signing key" for overrides or config changes.
- Owner approval is an **app-layer authentication step** (`LAContext`), not a different hardware key.
- If a request matches policy and does not require interactive review, Bastion signs directly with the client's key with **no approval window and no biometric/passcode prompt**.
- If a request requires manual approval, Bastion may ask for owner authentication **after approval**, then still signs with the same client key.
- If a request breaks policy, Bastion can only proceed through an explicit override flow with owner authentication, and the final signature is still produced by the same client key.

In short: the hardware key stays silent, and Bastion policy decides when user interaction is required.

### Signing flow

```
1. bastion-cli sends sign request over XPC (raw or structured)
2. XPCServer verifies client code signature + team ID
3. Parse operation type (message / typedData / userOperation)
4. CalldataDecoder inspects UserOp calldata → extract inner targets + direct token amounts
5. RuleEngine.validate():
   - Client allowlist
   - Allowed hours
   - Chain ID whitelist
   - Target address check (decoded inner-call targets, not just the smart-account sender)
   - Rate limits (configurable time windows)
   - Spending limits (direct native/ERC-20 amounts from decoded calldata)

   If all rules pass and no interactive review is required:
     6a. Sign immediately with the client's Secure Enclave key
     6b. No approval popup
     6c. No owner auth prompt

   If all rules pass but interactive review is required:
     6a. Show approval popup
     6b. If the client auth policy is not `.open`, ask for owner auth after approval
     6c. Sign with the same client key

   If any rule fails:
     6a. Show violation popup (what rule was broken)
     6b. User approves → owner auth (`.biometricOrPasscode`)
     6c. Sign with the same client key

7. For high-level `eth userOp --op ... --send` requests:
   - Bastion builds the Kernel `execute()` calldata
   - Bastion sponsors / estimates the UserOperation first
   - Bastion only performs the real signature after approval / override is complete
   - Bastion then submits the signed UserOperation to ZeroDev
8. For UserOps: normalize s <= N/2 (OZ P256 on-chain requirement)
9. Increment counters in Keychain (rate limit + spending)
10. Record request-level audit history
11. Return JSON response via XPC → CLI stdout → Agent

For live UserOps, the client can seed gas fees from chain-native EIP-1559 data and only fall back to bundler-specific fee floors when `eth_sendUserOperation` rejects the initial estimate.
```

### Storage

All persistent state is in macOS Keychain (service: `com.bastion`):

| Account | Contents |
|---------|----------|
| `config` | BastionConfig JSON (auth policy, access controls, rate limits, spending limits) |
| `state.*` | Keychain-backed counters for rate limits and spending windows |

Audit log (display only, not security-critical): `~/Library/Application Support/Bastion/audit.log`

---

## Rule settings and approval UI

- **Rules Settings** uses a left sidebar with `Default` plus per-client profiles.
- **Default** is the template copied into a new client profile on first connection.
- **Each client page** edits its own auth policy, signing rules, Secure Enclave key, and account address.
- **App Preferences** live under `Default` and include the ZeroDev project ID plus per-chain RPC endpoints used for `eth_call`, nonce lookup, and fee estimation.
- **Raw / Message Signing** is a simple allow/deny toggle.
- **EIP-712 Signing** supports domain allowlists plus JSON subset matching for struct values, so fields can be pinned or hardened.
- **UserOperation Policy** keeps the calldata-aware chain, target, rate-limit, and spending-limit controls.
- **Audit History** is a separate window that shows one row per request, with full payload detail plus a timeline of `Pending`, `Signed`, `Submitted`, `Confirmed`, or `Failed`.
- **macOS notifications** are used for UserOperation submission results. Clicking the notification opens `Audit History`.
- **Approval Popup** is compact by design and surfaces the request mode, client/account, digest, decoded action summary, and rule-override reasons.

---

## Requirements

- macOS 13+ (Apple Silicon recommended for Secure Enclave)
- Xcode 16+
- A real Mac — Secure Enclave does not work in Simulator

## Project structure

```
bastion.xcodeproj
├── BastionShared/                     # Shared XPC protocol
│   └── BastionXPCProtocol.swift
├── bastion/                           # Main app target (menu bar)
│   ├── App/BastionApp.swift
│   ├── MenuBar/MenuBarManager.swift
│   ├── Signing/
│   │   ├── SecureEnclaveManager.swift # SE key mgmt + signDigest (raw P-256)
│   │   ├── SigningManager.swift       # Two-path flow + s-normalization
│   │   └── AuthManager.swift
│   ├── Ethereum/
│   │   ├── Keccak256.swift            # C-backed Keccak-256 (Ethereum variant)
│   │   ├── EthTypes.swift             # SigningOperation, UserOperation, EIP-712
│   │   ├── EthHashing.swift           # EIP-191, EIP-712, UserOp hash (v0.7/v0.8+)
│   │   ├── EthRPC.swift               # Standard JSON-RPC client
│   │   ├── RLP.swift                  # RLP encoding
│   │   ├── KernelEncoding.swift       # Kernel v3.3 ERC-7579 calldata
│   │   ├── CalldataDecoder.swift      # Decode UserOp calldata for display + rules
│   │   ├── SmartAccount.swift         # Kernel v3.3 account (CREATE2, nonce, factory)
│   │   ├── Validator.swift            # KernelValidator protocol, P256Validator, P256Curve
│   │   ├── TokenConfig.swift          # Token identifiers, USDC addresses, chain config
│   │   └── ZeroDevAPI.swift           # ZeroDev bundler + paymaster API
│   ├── Rules/
│   │   ├── RuleEngine.swift           # Validation with calldata-aware target + spending checks
│   │   ├── RuleModels.swift           # BastionConfig, RuleConfig, rate/spending limits
│   │   └── StateStore.swift           # Time-windowed counters in Keychain
│   ├── IPC/
│   │   └── XPCServer.swift            # XPC listener + code signing verification
│   ├── UI/
│   │   ├── SigningRequestView.swift   # Approval popup with decoded calldata
│   │   └── RulesSettingsView.swift    # Sidebar settings UI + per-client policy pages + audit history
│   └── Utilities/
│       ├── KeychainStore.swift
│       ├── CLIInstaller.swift
│       └── AuditLog.swift
├── bastion-cli/                       # CLI source bundled into bastion.app at build time
│   └── main.swift
└── bastionTests/                      # Unit tests
    ├── StateStoreTests.swift          # RuleEngine + StateStore tests (mock keychain)
    ├── EthHashingTests.swift          # Keccak, EIP-191/712, UserOp hash tests
    ├── LiveTestConfig.swift           # Env-gated live test config
    ├── ZeroDevAPITests.swift          # ZeroDev integration tests (live Sepolia)
    └── P256ValidatorTests.swift       # P256 validator tests + live P256 flow
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
   - Registers the bundled `SMAppService` agent for XPC
   - Registers the main binary as the `SMAppService` launch target (`BundleProgram = Contents/MacOS/bastion`)
   - Attempts to symlink `bastion-cli` to `/usr/local/bin/bastion` when running from `/Applications` or `~/Applications`
   - Bundles the CLI at `bastion.app/Contents/MacOS/bastion-cli`

For day-to-day development, prefer the signed rebuild helper instead of raw `xcodebuild`. It rebuilds to a fixed DerivedData path, copies the signed app to `~/Applications/Bastion Dev.app`, unregisters stale Bastion app bundles, kills stale relay/helper processes, registers the bundled `SMAppService` agent from that stable install path, kickstarts the helper, and verifies the CLI/XPC path cleanly:

```bash
./scripts/dev-rebuild-signed.sh
```

This helper also disables Xcode's debug dylib / previews path for the development build (`ENABLE_DEBUG_DYLIB=NO`, `ENABLE_PREVIEWS=NO`). That reduces extra code-sign steps and avoids stale-service / duplicate-process XPC issues during iteration. If notifications ever seem to open the wrong build, rerun this script.

For release packaging, notarization, installation, and manifest generation, use:

```bash
./scripts/release-build.sh
./scripts/release-notarize.sh
./scripts/release-create-dmg.sh
./scripts/release-generate-manifest.sh
./scripts/release-install.sh
```

### 4. Verify the registered background service

The app now uses `ServiceManagement` (`SMAppService`) rather than a manually bootstrapped LaunchAgent plist. After running `./scripts/dev-rebuild-signed.sh`, verify the registered job:

```bash
launchctl print gui/$(id -u)/com.bastion.xpc
```

You should see a running job managed by `com.apple.xpc.ServiceManagement`. The program identifier should point at the main binary:

```text
Contents/MacOS/bastion
```

### 5. Install the CLI manually (if auto-install failed)

```bash
BASTION_APP="$HOME/Applications/Bastion Dev.app"
sudo ln -sf "$BASTION_APP/Contents/MacOS/bastion-cli" /usr/local/bin/bastion
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

# Check signing state (remaining quota per rate limit window)
bastion state

# View current rules
bastion rules

# Delete all Bastion Secure Enclave signing keys
bastion reset-keys

# Raw signature (32 bytes = 64 hex chars)
bastion sign --data a3f1c2d4e5b67890abcdef1234567890abcdef1234567890abcdef1234567890
# {"pubkeyX": "...", "pubkeyY": "...", "r": "...", "s": "..."}

# Ethereum structured signing
bastion eth message "Hello, world!"
bastion eth typedData --json-file /tmp/typed-data.json
bastion eth userOp --op 0x0000000000000000000000000000000000000001,0,0x
bastion eth userOp --send --op 0x0000000000000000000000000000000000000001,0,0x
bastion eth userOp --json-file /tmp/userop.json
bastion eth userOp --send --json-file /tmp/userop.json
```

All output is JSON on stdout. Errors go to stderr with exit code 1.

For structured requests, `--json-file` is the most reliable path for large JSON payloads.

For `bastion eth userOp --op`, each action is `target,value,data`, where `value` is decimal or `0x` hex and `data` is `0x`-prefixed hex.

For `bastion eth userOp --json-file`, the byte fields `callData`, `factoryData`, and `paymasterData` must be passed as `0x`-prefixed hex strings. Base64-encoded values are rejected.

`--send` is the preferred flag. `--submit` is still accepted as a legacy alias.

For high-level `eth userOp --op ... --send` requests, Bastion first builds and sponsors the UserOperation, then shows any required approval or rule-override UI, then produces the real signature, and finally submits the signed operation. The ZeroDev project ID defaults to the value stored in `Default -> App Preferences`. Chain RPC endpoints for `eth_call` and fee lookup are also read from `Default -> App Preferences`. Receipt updates are written to `Audit History` asynchronously and grouped under the same request row.

See `docs/CLI_REQUEST_EXAMPLES.md` for validated `message`, `typedData`, and `userOp` examples.

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

### Live integration tests

Use `.env.test.example` as a template, then export the values before running the live Sepolia flows:

```bash
BASTION_RUN_LIVE_AA_TESTS=1 \
BASTION_ZERODEV_PROJECT_ID=... \
BASTION_SEPOLIA_RPC_URL=... \
xcodebuild -project bastion.xcodeproj -scheme bastion test
```

---

## Uninstall

```bash
# Stop the registered background service
launchctl bootout gui/$(id -u)/com.bastion.xpc

# Remove CLI symlink
sudo rm /usr/local/bin/bastion

# Remove audit log
rm -rf ~/Library/Application\ Support/Bastion/

# Remove the app
# (drag /Applications/Bastion.app or ~/Applications/Bastion\ Dev.app to Trash)
```

Secure Enclave keys persist in the hardware keychain. The recommended way to clear all Bastion-managed signing keys is:

```bash
bastion reset-keys
```

If you need to inspect them manually, search Keychain Access for `com.bastion.signingkey`.

---

## On-chain component

The P256Validator Solidity contract lives in [`contracts/`](contracts/). It's an ERC-7579 validator module for Kernel v3.3 that verifies P-256 signatures on-chain via the RIP-7212 precompile. Bastion currently expects the validator at `0x9906AB44fF795883C5a725687A2705BE4118B0f3` on chains where P-256 UserOperation signing is enabled; the validator must actually be deployed at that address on the target chain for sponsorship and account initialization to succeed.

## Documentation

See [OVERVIEW.md](OVERVIEW.md) for the full security model, threat analysis, trust assumptions, and path forward.

Full specifications, audits, and design docs are in Obsidian: `~/Documents/Obsidian/projects/bastion/`
