# Bastion

Hardware-backed signing guard for AI agents on macOS. Bastion uses Apple Secure Enclave to hold private keys and macOS Keychain for tamper-resistant state storage. Agents interact through a CLI that communicates with the app over XPC. Requests that stay within policy can be signed autonomously; requests outside policy require explicit approval plus owner authentication.

## Why

AI agents that interact with blockchains need to sign transactions. Giving an agent direct access to a private key means a compromised or misbehaving agent can drain funds. Bastion sits between the agent and the key:

- The private key **never leaves the Secure Enclave**. It cannot be exported, copied, or read — even by Bastion itself.
- Every signing request goes through a **rule engine** (rate limits, allowed hours, whitelist).
- Within rules: signing is **silent and autonomous** — no user interaction needed.
- Breaking rules: requires **explicit approval plus owner authentication** (biometric or passcode).
- Config and state are in **macOS Keychain** — agents cannot read, modify, or delete them.
- A tamper-proof **audit log** records every request, approval, and denial.

## Architecture

```
Agent (Python / TypeScript / any process)
  |
  |  subprocess: bastion eth userOp --json-file /tmp/userop.json
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
| Audit log | Accountability | Append-only JSON Lines, no delete API |

### What agents can do

- **Sign raw data** (`bastion sign`) — within rules, silently; outside rules, with user biometric override
- **Sign Ethereum operations** (`bastion eth message|typedData|userOp`) — structured signing with calldata decoding
  Use `--json-file` for `typedData` and `userOp` payloads; the documented examples are in `docs/CLI_REQUEST_EXAMPLES.md`.
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

| | Key B ("Signing Key") |
|---|---|
| **Tag** | `com.bastion.signingkey` |
| **Purpose** | Sign user data (ECDSA P-256 / secp256r1) |
| **SE access control** | `.privateKeyUsage` (silent — no auth prompt) |
| **Auth gate** | Software-enforced via rule engine + `LAContext` |

The key's SE access control is intentionally open so signing doesn't prompt. The real gate is the rule engine and `LAContext` authentication before the SE call. Auth policy is configurable (open, passcode, biometric, biometricOrPasscode).

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

   If all rules pass:
     6a. Optional explicit approval popup (shows decoded calldata)
     6b. Auth per policy (.open skips, .biometric prompts, etc.)
     6c. Sign with Secure Enclave Key B

   If any rule fails:
     6a. Show violation popup (what rule was broken)
     6b. User approves → owner auth (`.biometricOrPasscode`)
     6c. Sign with Secure Enclave Key B

7. For UserOps: normalize s <= N/2 (OZ P256 on-chain requirement)
8. Increment counters in Keychain (rate limit + spending)
9. Record audit log entry
10. Return JSON response via XPC → CLI stdout → Agent

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

- **Rules Settings** is split into Authentication, Access Controls, Allowed XPC Clients, Rate Limits, and Spending Limits.
- **Allowed Targets** matches decoded inner destinations from Kernel `execute()` calldata, not just the smart-account address.
- **Spending Limits** enforce direct native value plus ERC-20 `transfer`, `approve`, and `transferFrom` amounts decoded from UserOps.
- **Approval Popup** shows request metadata, the exact digest to sign, decoded action summaries, and rule-override reasons when Bastion blocks a request.

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
│   │   └── RulesSettingsView.swift    # Full settings UI (rules, targets, spending)
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
   - Installs `~/Library/LaunchAgents/com.bastion.xpc.plist` for XPC
   - Attempts to symlink `bastion-cli` to `/usr/local/bin/bastion`
   - Bundles the CLI at `bastion.app/Contents/MacOS/bastion-cli`

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
BASTION_APP=$(find ~/Library/Developer/Xcode/DerivedData -path "*/Build/Products/*/bastion.app" -type d | head -1)
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

# Raw signature (32 bytes = 64 hex chars)
bastion sign --data a3f1c2d4e5b67890abcdef1234567890abcdef1234567890abcdef1234567890
# {"pubkeyX": "...", "pubkeyY": "...", "r": "...", "s": "..."}

# Ethereum structured signing
bastion eth message "Hello, world!"
bastion eth typedData --json-file /tmp/typed-data.json
bastion eth userOp --json-file /tmp/userop.json
```

All output is JSON on stdout. Errors go to stderr with exit code 1.

For structured requests, `--json-file` is the most reliable path for large JSON payloads.

For `bastion eth userOp`, the byte fields `callData`, `factoryData`, and `paymasterData` must be passed as `0x`-prefixed hex strings. Base64-encoded values are rejected.

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

## On-chain component

The P256Validator Solidity contract lives in [`contracts/`](contracts/). It's an ERC-7579 validator module for Kernel v3.3 that verifies P-256 signatures on-chain via the RIP-7212 precompile. Deployed at `0x9906AB44fF795883C5a725687A2705BE4118B0f3`.

## Documentation

See [OVERVIEW.md](OVERVIEW.md) for the full security model, threat analysis, trust assumptions, and path forward.

Full specifications, audits, and design docs are in Obsidian: `~/Documents/Obsidian/projects/bastion/`
