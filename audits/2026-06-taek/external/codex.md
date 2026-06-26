# Codex cold-pass (verbatim)

codex CLI: AVAILABLE and AUTHENTICATED (non-interactive). Binary: /opt/homebrew/bin/codex, codex-cli 0.140.0, model gpt-5.5, sandbox=read-only, reasoning effort xhigh, ~529,206 tokens used. Audit ran against repo root at commit 390de476fc9bb049622b5b9e72d50c77ca00bf56. (Note: MDM forced approval_policy OnRequest; ran fine under -s read-only with no interactive prompts blocking.)

All 3 codex findings were independently re-verified against the source after the run.

## FINDINGS (verbatim codex output)

Read-only audit at commit `390de476`. I did not find a separate high-confidence comment-vs-code security contradiction worth reporting beyond the bridge identity issue below.

### 1. Bundled MCP Bridge Lets Any Launcher Select Any Paired Agent Profile

Severity: High
Files: XPCServer.swift:283, XPCServer.swift:1964, bastion-mcp/main.swift:354

Mechanism: XPC authenticates only that the connecting process is the bundled `bastion-mcp` binary by bundle id and executable path. Once that is true, `bridgeProfileBundleId` trusts the caller-supplied `agentProfileId`, maps it to a stored profile, and signs as that profile. The Swift bridge accepts that profile id from MCP args, `BASTION_AGENT_PROFILE_ID`, REST body, or `X-Bastion-Agent-Profile`.

This breaks the direct-XPC invariant where policy identity comes from the client audit-token bundle id. Here, any local process that can launch `/Applications/Bastion.app/Contents/MacOS/bastion-mcp` and knows a paired profile id can act as that agent. If the profile policy permits silent signing, signatures complete without approval UI or owner auth.

PoC/trigger:
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bastion_sign_message","arguments":{"agentProfileId":"<victim-profile-id>","message":"audit-poc"}}}' | /Applications/Bastion.app/Contents/MacOS/bastion-mcp

Expected security property: only the paired agent instance can use its profile.
Actual: possession of the generic bundled bridge plus profile id is enough.

### 2. Support Bundle Bypasses The Paired-Profile Read Gate And Exports Profile Identifiers

Severity: Medium
Files: XPCServer.swift:510, XPCServer.swift:1426, XPCServer.swift:1478, SupportBundleExporter.swift:56, SupportBundleExporter.swift:238

Mechanism: `getRules` and `getState` call `existingClientContext()`, which requires a paired profile. `exportSupportBundle` does not call that gate or owner auth; it loads the full config and emits `clientProfiles[].id`, `bundleId`, labels, auth policy, group ids, and membership ids.

That is a sibling-path read bypass. The exported profile ids are especially sensitive because the bridge path above treats profile id as the profile selector for signing.

PoC/trigger: any accepted direct XPC client can call `exportSupportBundle(requestData:)`; the repo CLI does this through `bastion support-bundle --output /tmp/bastion-support.json`. The resulting JSON contains clientProfiles[] with id/bundleId/authPolicy.

Expected: profile-scoped read APIs and diagnostic exports should enforce the same read gate or redact profile ids.
Actual: support export returns the profile id inventory without the paired-profile gate.

### 3. `agentNotInstalled` Is Dead; Uninstall Builds UserOps For Pending/Revoked Agents

Severity: Low
Files: WalletGroupOnChain.swift:18, WalletGroupOnChain.swift:100, WalletGroupOnChain.swift:185

Mechanism: `WalletGroupChainError.agentNotInstalled` is defined but never thrown. The install path checks `member.installStatus` and rejects already-installed agents. The uninstall sibling path authenticates the owner, but never checks that the member is actually `.installed`; it builds an `uninstallModule` UserOp for pending or revoked members.

(Output truncated in source feed at PoC line.)

## Disposition
- codex #1 → confirmed, consolidated into AC-01 (Critical, raised from codex's High because of the additional REST single-token vector).
- codex #2 → confirmed as AC-04 (Medium).
- codex #3 → dismissed (CDX-3): owner-authenticated path, no-op on-chain, code-hygiene only. See reconciliation.md.

Gemini cold pass: not run / no output provided in this audit feed.
