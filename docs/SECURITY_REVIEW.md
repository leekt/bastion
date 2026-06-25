# Bastion Security Review Notes

Last updated: 2026-06-03

This review is scoped to the private-beta release baseline in `PLAN.md`. It is
not a substitute for an external audit, but it records the current trust
boundaries and the remaining security posture for release decisions.

## XPC Trust Boundary

- XPC connections are accepted only after code-signature validation. Release
  builds require the configured Bastion Team ID; debug builds allow the
  bundled `bastion-cli` sidecar only when both its signing identifier and app
  bundle path match.
- The client bundle ID used for policy and pairing is read from the verified
  code-signing identity. Pairing rejects missing identities and rejects any
  mismatch between the wire-supplied bundle ID and the verified identity.
- `allowedClients` is enforced at connection acceptance and again before
  signing. `nil` means no global client restriction, while an empty array is a
  deny-all sentinel.
- Active XPC connections are tracked behind a lock and reconciled when client
  policy changes so removed clients do not keep signing through an old
  connection.

## Policy And Fail-Closed Paths

- Signing requires an existing paired client profile; unknown clients are
  blocked instead of auto-provisioned on the signing path.
- Config corruption, pause, lockdown, missing wallet-group membership, pending
  validators, and revoked validators block signing before user approval.
- Policy validation distinguishes non-overrideable blocked states from
  owner-overridable denials. The sender account for UserOperations is checked
  against the profile account before signing.
- State counter IDs for copied scoped rules are regenerated to avoid shared
  rate-limit or spending-limit counters across agents.

## Audit, Notification, And History Exposure

- Audit records are bounded by age and count, written owner-readable only, and
  protected with an HMAC plus a hash chain. Missing MACs, unreadable keys, HMAC
  mismatches, and broken chains stop append/rewrite until owner recovery.
- Audit redaction levels remove payloads, account addresses, provider hashes,
  transaction hashes, and sensitive reason/detail text when configured.
- Support bundles re-redact recent audit context before export and exclude raw
  request payloads, full rule bodies, key tags, and full provider artifacts.
- Notifications carry only title/subtitle/body text and route clicks to Audit
  History. Click routing passes only a fixed UI target through XPC, validates
  the target enum, and rate-limits UI-open requests.

## Concurrency And Undefined-Behavior Review

- The debug-only auth bypass is compiled out of release builds and is now
  guarded by a lock-backed accessor instead of unsafe shared mutable state.
- Notification authorization idempotence is guarded by a lock so repeated
  startup/configuration calls cannot race the singleton flag.
- Remaining `@unchecked Sendable` and lock-backed singletons are intentional
  compatibility boundaries around XPC, diagnostic logging, audit logging, and
  stores that cross actor or callback queues.

## Remaining Security Caveats

- This review did not include live install/reboot lifecycle testing, dynamic
  XPC fuzzing, or an external cryptographic audit.
- Audit redaction remains policy-configured. The least-sensitive production
  posture is to enable payload redaction or full redaction before distributing
  to untrusted operators.
- The manifest-driven update client now installs verified staged ZIP artifacts
  with rollback and service recovery. Delta updates and unattended release
  channel policy are still out of scope for this review.
