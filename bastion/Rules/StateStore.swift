import Foundation

// MARK: - Keychain Backend Protocol

nonisolated protocol KeychainBackend: Sendable {
    func read(account: String) -> Data?
    func write(account: String, data: Data)
    func delete(account: String)
}

// MARK: - State Store

/// Tamper-proof state storage backed by macOS Keychain.
/// Tracks rate limit counters and spending amounts per time window.
nonisolated final class StateStore: @unchecked Sendable {
    static let shared = StateStore(keychain: SystemKeychainBackend())

    private let keychain: KeychainBackend
    private let queue = DispatchQueue(label: "com.bastion.statestore")

    // Keychain account keys
    private nonisolated static let rateLimitPrefix = "state.ratelimit."
    private nonisolated static let spendingPrefix = "state.spending."

    init(keychain: KeychainBackend) {
        self.keychain = keychain
    }

    // MARK: - Rate Limit

    /// Returns the current count for a rate limit rule within its time window.
    nonisolated func rateLimitCount(ruleId: String, windowSeconds: Int) -> Int {
        queue.sync {
            guard let state = loadRateLimitState(ruleId: ruleId) else { return 0 }
            let now = Date()
            let windowStart = now.addingTimeInterval(-Double(windowSeconds))
            // Filter entries within the window
            return state.entries.filter { $0.timestamp > windowStart.timeIntervalSince1970 }.count
        }
    }

    /// Records a request for a rate limit rule.
    nonisolated func recordRequest(ruleId: String, windowSeconds: Int) {
        queue.sync {
            var state = loadRateLimitState(ruleId: ruleId) ?? RateLimitWindowState(entries: [])
            let now = Date()
            let windowStart = now.addingTimeInterval(-Double(windowSeconds))

            // Prune expired entries
            state.entries.removeAll { $0.timestamp <= windowStart.timeIntervalSince1970 }
            // Add new entry
            state.entries.append(TimestampEntry(timestamp: now.timeIntervalSince1970))

            saveRateLimitState(ruleId: ruleId, state: state)
        }
    }

    /// Returns status for a rate limit rule.
    nonisolated func rateLimitStatus(rule: RateLimitRule) -> RateLimitStatus {
        queue.sync {
            let state = loadRateLimitState(ruleId: rule.id)
            let now = Date()
            let windowStart = now.addingTimeInterval(-Double(rule.windowSeconds))
            let entries = state?.entries.filter { $0.timestamp > windowStart.timeIntervalSince1970 } ?? []
            let count = entries.count
            let oldest = entries.min(by: { $0.timestamp < $1.timestamp })
            let resetsAt = oldest.map { Date(timeIntervalSince1970: $0.timestamp + Double(rule.windowSeconds)) }

            return RateLimitStatus(
                maxRequests: rule.maxRequests,
                windowSeconds: rule.windowSeconds,
                currentCount: count,
                remaining: max(0, rule.maxRequests - count),
                windowResetsAt: resetsAt.map(Self.iso8601String)
            )
        }
    }

    // MARK: - Spending Limit

    /// Returns the cumulative spend for a spending rule within its time window.
    nonisolated func spentAmount(ruleId: String, windowSeconds: Int?) -> UInt128 {
        queue.sync {
            guard let state = loadSpendingState(ruleId: ruleId) else { return 0 }
            let now = Date()

            if let windowSeconds {
                let windowStart = now.addingTimeInterval(-Double(windowSeconds))
                return state.entries
                    .filter { $0.timestamp > windowStart.timeIntervalSince1970 }
                    .compactMap { UInt128($0.amount) }
                    .reduce(0, +)
            } else {
                // Lifetime — sum everything
                return state.entries
                    .compactMap { UInt128($0.amount) }
                    .reduce(0, +)
            }
        }
    }

    /// Records a spend for a spending limit rule.
    nonisolated func recordSpend(ruleId: String, amount: String, windowSeconds: Int?) {
        queue.sync {
            var state = loadSpendingState(ruleId: ruleId) ?? SpendingWindowState(entries: [])
            let now = Date()

            // Prune expired entries if windowed
            if let windowSeconds {
                let windowStart = now.addingTimeInterval(-Double(windowSeconds))
                state.entries.removeAll { $0.timestamp <= windowStart.timeIntervalSince1970 }
            }

            state.entries.append(SpendEntry(timestamp: now.timeIntervalSince1970, amount: amount))
            saveSpendingState(ruleId: ruleId, state: state)
        }
    }

    /// Returns status for a spending limit rule.
    nonisolated func spendingLimitStatus(rule: SpendingLimitRule) -> SpendingLimitStatus {
        let spent = spentAmount(ruleId: rule.id, windowSeconds: rule.windowSeconds)
        let allowance = UInt128(rule.allowance) ?? 0
        let remaining = spent >= allowance ? UInt128(0) : allowance - spent

        return SpendingLimitStatus(
            token: rule.token.displayName,
            allowance: rule.allowance,
            spent: String(spent),
            remaining: String(remaining),
            windowSeconds: rule.windowSeconds,
            windowResetsAt: nil // TODO: compute from oldest entry
        )
    }

    // MARK: - Persistence

    private func loadRateLimitState(ruleId: String) -> RateLimitWindowState? {
        guard let data = keychain.read(account: Self.rateLimitPrefix + ruleId),
              let state = try? JSONDecoder().decode(RateLimitWindowState.self, from: data) else {
            return nil
        }
        return state
    }

    private func saveRateLimitState(ruleId: String, state: RateLimitWindowState) {
        guard let data = try? JSONEncoder().encode(state) else { return }
        keychain.write(account: Self.rateLimitPrefix + ruleId, data: data)
    }

    private func loadSpendingState(ruleId: String) -> SpendingWindowState? {
        guard let data = keychain.read(account: Self.spendingPrefix + ruleId),
              let state = try? JSONDecoder().decode(SpendingWindowState.self, from: data) else {
            return nil
        }
        return state
    }

    private func saveSpendingState(ruleId: String, state: SpendingWindowState) {
        guard let data = try? JSONEncoder().encode(state) else { return }
        keychain.write(account: Self.spendingPrefix + ruleId, data: data)
    }

    // MARK: - Helpers

    static func iso8601String(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }
}

// MARK: - State Models

nonisolated struct TimestampEntry: Codable, Sendable {
    let timestamp: TimeInterval
}

nonisolated struct RateLimitWindowState: Codable, Sendable {
    var entries: [TimestampEntry]
}

nonisolated struct SpendEntry: Codable, Sendable {
    let timestamp: TimeInterval
    let amount: String // smallest unit as decimal string
}

nonisolated struct SpendingWindowState: Codable, Sendable {
    var entries: [SpendEntry]
}
