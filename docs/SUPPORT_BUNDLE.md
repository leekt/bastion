# Support Bundles

Bastion can export a redacted JSON support bundle from the running XPC service:

```sh
bastion support-bundle --output /tmp/bastion-support.json
```

Without `--output`, the command prints the JSON bundle to stdout. The optional
limits are clamped by the service:

```sh
bastion support-bundle --audit-limit 25 --diagnostics-limit 100 --crash-limit 5
```

Operators can also open **Diagnostics…** from the menu bar. The in-app panel
shows current service registration metadata, config/audit/diagnostic/crash
health, recent structured diagnostics, recent Bastion crash reports, and a save
button for the same redacted support bundle.

## Included

- Service status: app version, registration status, config corruption state,
  process ID, launch mode, bundle path, executable path, Mach service name, and
  LaunchAgent plist name.
- Sanitized config: schema version, auth policy, audit redaction level, whether
  a ZeroDev project ID is configured, RPC hosts, client profile identifiers,
  wallet-group counts, and pause/lockdown state.
- Recent audit records re-redacted with `redactPayloads`.
- Redacted operational artifacts extracted from recent audit context:
  preflight summaries and provider response summaries.
- Recent structured diagnostics from
  `~/Library/Application Support/Bastion/diagnostics.jsonl`.
  Update check and staging events are included when the release manifest URL is
  configured.
- Recent Bastion crash report metadata from macOS DiagnosticReports.

## Excluded

- Secure Enclave private keys and key tags.
- ZeroDev project IDs.
- Full RPC URLs, paths, and query strings.
- Raw config bytes.
- Raw request payloads.
- Raw preflight debug bundles.
- Full audit payload details, summaries, reasons, account addresses, provider
  hashes, and transaction hashes after support-export redaction.
- Raw crash report bodies and stack traces.

## Diagnostic Events

Diagnostics are JSONL entries intended for lifecycle and support triage rather
than full request replay. They currently cover:

- service lock acquisition, duplicate-service exits, service start, relay
  handoff, and XPC listener state
- XPC connection acceptance/rejection and structured-signing decode failures
- approval window opens, approval denials, owner-auth failures, local signing
  completion, and UserOperation submission/receipt outcomes
- notification authorization, delivery, failure, and click routing
- support bundle export success/failure
- diagnostics-panel support bundle saves

Detailed preflight replay artifacts are still exported through the request debug
flow. Folding those artifacts directly into support bundles is a remaining
supportability item.
