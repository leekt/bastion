import Foundation

// PR1 (architectural cleanup): single source of truth for bundler / project
// trust resolution.
//
// Pre-cleanup, three signing/submission paths each rolled their own:
//   - SigningManager.submitUserOperationIfRequested trusted `submission.projectId`
//     from the agent's request verbatim (no app-config check at all)
//   - WalletGroupOnChain.resolveZeroDevProjectId used app-config first, explicit
//     argument as fallback (correct, post-PR23)
//   - PreflightSimulator used `submission?.projectId ?? preferences.zeroDevProjectId`
//     — wire-supplied first, config as fallback (wrong direction)
//
// The bug class: an agent could redirect a sponsored UserOp through an
// attacker-controlled bundler by passing a different projectId in the
// signing envelope, even when Bastion was explicitly configured otherwise.
//
// The unified rule, used by every path:
//
//   1. If Bastion has an explicit `bundlerPreferences.zeroDevProjectId`,
//      use it. Always. The wire-supplied value is ignored.
//   2. Otherwise, fall back to the wire-supplied value (typically from an
//      agent's signing envelope) — handy for fresh installs that haven't
//      configured a project yet.
//   3. Otherwise, throw — submission/signing can't proceed without a
//      bundler.
//
// `ResolvedBundler.source` records which branch resolved so callers can
// surface the decision in audit logs and approval UIs (e.g. "Bastion
// overrode the request's project ID with the configured one").

nonisolated struct ResolvedBundler: Sendable, Equatable {
    let projectId: String
    let source: Source

    enum Source: String, Sendable {
        /// App config matched what the agent requested.
        case configMatchedRequest = "config_matched_request"
        /// Agent requested a different project; app config won.
        case configOverrodeRequest = "config_overrode_request"
        /// App config absent; wire-supplied value used as fallback.
        case requestFallback = "request_fallback"
    }
}

nonisolated enum BundlerTrustResolver {
    /// Resolve a ZeroDev project ID to use for submission. See module
    /// docs for the precedence rule. Throws BastionError.invalidInput
    /// when neither side supplies a usable value.
    static func resolveZeroDevProjectId(
        wireSupplied: String?,
        config: BastionConfig
    ) throws -> ResolvedBundler {
        try resolveZeroDevProjectId(
            wireSupplied: wireSupplied,
            configured: config.bundlerPreferences.zeroDevProjectId
        )
    }

    /// Convenience overload for callers that already hold a flat
    /// `BundlerPreferences` rather than the full `BastionConfig` —
    /// PreflightSimulator's hot path doesn't carry the full config.
    /// Behaviour is identical to the BastionConfig variant.
    static func resolveZeroDevProjectId(
        wireSupplied: String?,
        preferences: BundlerPreferences
    ) throws -> ResolvedBundler {
        try resolveZeroDevProjectId(
            wireSupplied: wireSupplied,
            configured: preferences.zeroDevProjectId
        )
    }

    private static func resolveZeroDevProjectId(
        wireSupplied: String?,
        configured: String?
    ) throws -> ResolvedBundler {
        let trimmedWire = wireSupplied?.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedConfigured = configured?.trimmingCharacters(in: .whitespacesAndNewlines)

        if let trimmedConfigured, !trimmedConfigured.isEmpty {
            let source: ResolvedBundler.Source
            if let trimmedWire, !trimmedWire.isEmpty, trimmedWire == trimmedConfigured {
                source = .configMatchedRequest
            } else {
                source = .configOverrodeRequest
            }
            return ResolvedBundler(projectId: trimmedConfigured, source: source)
        }

        if let trimmedWire, !trimmedWire.isEmpty {
            return ResolvedBundler(projectId: trimmedWire, source: .requestFallback)
        }

        throw BastionError.invalidInput
    }
}
