# Provider Resilience

## Scope

Bastion is ZeroDev-first for ERC-4337 submission. That does not mean every
chain call should use the ZeroDev bundler endpoint.

- `EthRPC` owns normal chain reads such as nonce, code, fees, balances, calls,
  and traces.
- `ZeroDevAPI` owns account-abstraction provider calls such as sponsorship,
  bundler gas price, simulation, send, and receipt lookup.
- `BundlerTrustResolver` decides which ZeroDev project ID is trusted before a
  request reaches the provider client.

## Failure Taxonomy

Provider-facing failures are classified before they are shown to users or
written to audit history.

- `configuration`: missing or invalid provider settings.
- `chain_rpc`: non-AA chain RPC read failure.
- `zerodev_api`: ZeroDev transport, HTTP, malformed response, or transient API
  failure.
- `paymaster`: sponsorship or paymaster validation failure.
- `bundler_validation`: deterministic ERC-4337 validation failure, including
  AAxx errors.
- `submission`: signed UserOperation send failure.
- `receipt_timeout`: submitted UserOperation did not produce a receipt before
  the polling deadline.
- `minimum_fee_mismatch`: the signed UserOperation was built with stale fees.
- `on_chain_execution`: bundler accepted the UserOperation but the receipt
  reports execution failure.
- `simulation`: pre-submit simulation failure.

These fields are exposed through `UserOperationSubmissionResponse` as
`failureStage`, `failureCategory`, `retryable`, and `recoverySuggestion`.

## Retry Policy

`ZeroDevAPI` retries only transient failures:

- network transport errors
- HTTP `408`, `425`, `429`, and `5xx`
- RPC errors whose message indicates timeout, temporary unavailability, rate
  limiting, overload, or retryable service failure
- empty provider results

Default retry bounds:

- `eth_sendUserOperation`: 2 attempts
- `eth_getUserOperationReceipt`: 2 attempts per polling iteration
- other ZeroDev calls: 3 attempts

Deterministic bundler validation errors, AAxx errors, minimum-fee mismatches,
request encoding errors, and malformed provider responses do not retry.

## Degraded Behavior

When ZeroDev is missing, unavailable, slow, or returns partial results, Bastion
does not silently downgrade into a permissive signing path.

- Missing project ID: fail before submission with a configuration diagnostic.
- Sponsorship failure: fail before approval when a direct UserOperation needs
  paymaster data.
- Preflight simulation failure: show the preflight diagnostic and allow the
  operator to export the debug bundle.
- Send failure after signing: return `send_failed`, write the provider
  diagnostic into audit history, and notify the operator.
- Receipt timeout: preserve the submitted UserOperation hash in audit history
  and mark the request as still pending instead of inventing a success/failure
  result.
- Minimum fee mismatch: do not mutate a signed UserOperation. Rebuild with fresh
  fees, then approve and sign again.
- On-chain execution failure: record the failed receipt and require operator
  review before retrying.

This keeps provider degradation explicit and recoverable without hiding whether
the failure came from policy, signing, chain RPC, ZeroDev, paymaster, bundler
validation, or on-chain execution.
