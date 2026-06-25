import Foundation

// PairingBroker — app-side state for the first-run pairing handshake.
//
// CLI side (out of scope here) calls into the XPC layer with its bundleId +
// process info; the broker mints a 6-character pairing code and surfaces the
// pending request to the UI. The owner accepts (matching code), and the
// broker materialises a ClientProfile (optionally pre-filled from a
// RuleTemplate) plus a Secure Enclave key.
//
// While the XPC pair() endpoint is implemented in the Service layer, the
// in-process broker is the single source of truth for pending requests so the
// PairingFlowView can drive the handshake step end-to-end during development.

nonisolated struct PendingPairingRequest: Sendable, Identifiable, Hashable {
    let id: UUID
    let bundleId: String
    let processName: String
    let pairingCode: String
    let createdAt: Date
    let expiresAt: Date

    var defaultProfileLabel: String? {
        let trimmed = processName.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

/// Outcome of a pairing handshake. Terminal states (accepted, rejected,
/// expired) live in the broker for a short window after resolution so the
/// CLI's polling can read them before they're garbage-collected.
nonisolated struct PairingOutcome: Sendable {
    enum State: Sendable, Equatable {
        case pending
        case accepted(profileId: String)
        case rejected
        case expired
    }

    let state: State
    let resolvedAt: Date?
    let reason: String?
}

nonisolated enum PairingBrokerError: Error, LocalizedError, Equatable, Sendable {
    case requestAlreadyResolving
    case requestNoLongerPending

    var errorDescription: String? {
        switch self {
        case .requestAlreadyResolving:
            return "Pairing request is already being resolved."
        case .requestNoLongerPending:
            return "Pairing request is no longer pending."
        }
    }
}

@MainActor
protocol PairingConfigUpdating: AnyObject {
    var pairingConfig: BastionConfig { get }
    func applyPairingConfig(_ config: BastionConfig) async throws
}

extension RuleEngine: PairingConfigUpdating {
    var pairingConfig: BastionConfig { config }

    func applyPairingConfig(_ config: BastionConfig) async throws {
        try await updateConfig(config)
    }
}

@MainActor
@Observable
final class PairingBroker {
    static let shared = PairingBroker()
    private(set) var pending: [PendingPairingRequest] = []
    private let configUpdater: any PairingConfigUpdating

    /// Resolved outcomes by request id. Pruned aggressively — see
    /// `outcomeRetention`. Lookup is O(n) but n is bounded by `maxPending`.
    private var outcomes: [UUID: PairingOutcome] = [:]

    /// Requests currently being accepted. Accept persists config asynchronously,
    /// so this closes duplicate-click/stale-callback races while preserving retry
    /// after a persistence failure.
    private var acceptingRequestIDs: Set<UUID> = []

    /// Maximum pending requests. Excess older entries are dropped. Prevents a
    /// flood of stale handshakes from filling memory.
    private let maxPending = 8

    /// Expiry for unaccepted requests. After this window the request is
    /// discarded silently — the CLI will retry on its next attempt.
    private let expiry: TimeInterval

    /// How long resolved outcomes stick around so the CLI poll can pick them
    /// up. After this they are discarded; a slow CLI would need to retry the
    /// pairing handshake from scratch.
    private let outcomeRetention: TimeInterval

    init(
        configUpdater: any PairingConfigUpdating = RuleEngine.shared,
        expiry: TimeInterval = 5 * 60,
        outcomeRetention: TimeInterval = 60
    ) {
        self.configUpdater = configUpdater
        self.expiry = expiry
        self.outcomeRetention = outcomeRetention
    }

    /// Called from the IPC layer when a CLI process starts pairing. Returns
    /// the freshly minted pairing code, which the CLI prints to the terminal.
    func registerIncoming(bundleId: String, processName: String) -> PendingPairingRequest {
        prune()
        let now = Date()
        let request = PendingPairingRequest(
            id: UUID(),
            bundleId: bundleId,
            processName: processName,
            pairingCode: Self.makeCode(),
            createdAt: now,
            expiresAt: now.addingTimeInterval(expiry)
        )
        pending.append(request)
        if pending.count > maxPending {
            // Mark dropped entries as expired so callers polling them get a
            // clear answer rather than `.pending` until their own timeout.
            let dropped = pending.prefix(pending.count - maxPending)
            for d in dropped {
                outcomes[d.id] = PairingOutcome(state: .expired, resolvedAt: now, reason: "Too many pending pairs — superseded")
            }
            pending.removeFirst(pending.count - maxPending)
        }
        return request
    }

    /// Accepts the pending request, creates a ClientProfile (with optional
    /// template), and persists the resulting BastionConfig.
    func accept(_ request: PendingPairingRequest, label: String?, template: RuleTemplate?) async throws {
        prune()
        guard pending.contains(where: { $0.id == request.id }) else {
            throw PairingBrokerError.requestNoLongerPending
        }
        guard acceptingRequestIDs.insert(request.id).inserted else {
            throw PairingBrokerError.requestAlreadyResolving
        }
        defer { acceptingRequestIDs.remove(request.id) }

        var config = configUpdater.pairingConfig
        let normalizedLabel = label?.trimmingCharacters(in: .whitespacesAndNewlines)
        let profile = ClientProfile(
            id: UUID().uuidString,
            bundleId: request.bundleId,
            label: normalizedLabel?.isEmpty == false ? normalizedLabel : nil,
            authPolicy: template?.authPolicy ?? config.authPolicy,
            keyTag: ClientProfile.makeKeyTag(),
            rules: template?.rules ?? config.rules
        )
        config.clientProfiles.append(profile)
        try await configUpdater.applyPairingConfig(config)
        pending.removeAll { $0.id == request.id }
        outcomes[request.id] = PairingOutcome(state: .accepted(profileId: profile.id), resolvedAt: Date(), reason: nil)
    }

    /// Reject and discard a pending request without creating a profile.
    @discardableResult
    func reject(_ request: PendingPairingRequest, reason: String? = nil) -> Bool {
        prune()
        guard pending.contains(where: { $0.id == request.id }) else {
            return false
        }
        guard !acceptingRequestIDs.contains(request.id) else {
            return false
        }
        pending.removeAll { $0.id == request.id }
        outcomes[request.id] = PairingOutcome(state: .rejected, resolvedAt: Date(), reason: reason)
        return true
    }

    /// Polls the current state of a pairing handshake. Used by the XPC
    /// pollPairing endpoint.
    func poll(requestId: UUID) -> PairingOutcome {
        prune()
        if let outcome = outcomes[requestId] {
            return outcome
        }
        if pending.contains(where: { $0.id == requestId }) {
            return PairingOutcome(state: .pending, resolvedAt: nil, reason: nil)
        }
        // Unknown id — treat as expired so the CLI exits its poll loop.
        return PairingOutcome(state: .expired, resolvedAt: Date(), reason: "Unknown pairing request")
    }

    private func prune() {
        let now = Date()
        // Move expired pendings into the outcome cache before we drop them so
        // ongoing pollers see a clear .expired rather than .pending forever.
        let expired = pending.filter { $0.expiresAt < now }
        for request in expired {
            outcomes[request.id] = PairingOutcome(state: .expired, resolvedAt: now, reason: "Pairing window elapsed")
        }
        pending.removeAll { $0.expiresAt < now }
        // GC outcome entries past their retention window.
        let outcomeCutoff = now.addingTimeInterval(-outcomeRetention)
        for (id, outcome) in outcomes {
            if let resolvedAt = outcome.resolvedAt, resolvedAt < outcomeCutoff {
                outcomes.removeValue(forKey: id)
            }
        }
    }

    /// Generates a pairing code in the form `7F · 4K · 9B`. Uses an
    /// alphanumeric set excluding visually-confusable chars (O/0, I/1, l).
    static func makeCode() -> String {
        let chars = Array("ABCDEFGHJKMNPQRSTUVWXYZ23456789")
        func pick(_ n: Int) -> String {
            String((0..<n).map { _ in chars.randomElement()! })
        }
        return "\(pick(2)) · \(pick(2)) · \(pick(2))"
    }
}
