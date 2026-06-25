import Foundation

// MARK: - Keychain Backend Protocol

nonisolated protocol KeychainBackend: Sendable {
    func read(account: String) -> Data?
    func readResult(account: String) -> KeychainReadResult
    @discardableResult func write(account: String, data: Data) -> Bool
    @discardableResult func delete(account: String) -> Bool
}

nonisolated enum KeychainReadResult: Sendable {
    case found(Data)
    case missing
    case failure
}

extension KeychainBackend {
    func readResult(account: String) -> KeychainReadResult {
        if let data = read(account: account) {
            return .found(data)
        }
        return .missing
    }
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

    private enum LoadResult<T> {
        case missing
        case corrupted
        case value(T)
    }

    init(keychain: KeychainBackend) {
        self.keychain = keychain
    }

    // MARK: - Rate Limit

    /// Returns the current count for a rate limit rule within its time window.
    nonisolated func rateLimitCount(ruleId: String, windowSeconds: Int) -> Int {
        guard windowSeconds > 0 else {
            return Int.max
        }
        return queue.sync {
            let state: RateLimitWindowState
            switch loadRateLimitState(ruleId: ruleId) {
            case .missing:
                return 0
            case .corrupted:
                return Int.max
            case .value(let loaded):
                state = loaded
            }
            let now = Date()
            let windowStart = now.addingTimeInterval(-Double(windowSeconds))
            // Filter entries within the window
            return state.entries.filter { $0.timestamp > windowStart.timeIntervalSince1970 }.count
        }
    }

    /// Records a request for a rate limit rule.
    @discardableResult
    nonisolated func recordRequest(ruleId: String, windowSeconds: Int) -> Bool {
        guard windowSeconds > 0 else {
            return false
        }
        return queue.sync {
            var state: RateLimitWindowState
            switch loadRateLimitState(ruleId: ruleId) {
            case .missing:
                state = RateLimitWindowState(entries: [])
            case .corrupted:
                return false
            case .value(let loaded):
                state = loaded
            }
            let now = Date()
            let windowStart = now.addingTimeInterval(-Double(windowSeconds))

            // Prune expired entries
            state.entries.removeAll { $0.timestamp <= windowStart.timeIntervalSince1970 }
            // Add new entry
            state.entries.append(TimestampEntry(timestamp: now.timeIntervalSince1970))

            return saveRateLimitState(ruleId: ruleId, state: state)
        }
    }

    /// Returns status for a rate limit rule.
    nonisolated func rateLimitStatus(rule: RateLimitRule) -> RateLimitStatus {
        guard rule.windowSeconds > 0, rule.maxRequests > 0 else {
            return RateLimitStatus(
                maxRequests: rule.maxRequests,
                windowSeconds: rule.windowSeconds,
                currentCount: Int.max,
                remaining: 0,
                windowResetsAt: nil
            )
        }
        return queue.sync {
            let state: RateLimitWindowState?
            switch loadRateLimitState(ruleId: rule.id) {
            case .missing:
                state = nil
            case .corrupted:
                return RateLimitStatus(
                    maxRequests: rule.maxRequests,
                    windowSeconds: rule.windowSeconds,
                    currentCount: Int.max,
                    remaining: 0,
                    windowResetsAt: nil
                )
            case .value(let loaded):
                state = loaded
            }
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
        if let windowSeconds, windowSeconds <= 0 {
            return UInt128.max
        }
        return queue.sync {
            let state: SpendingWindowState
            switch loadSpendingState(ruleId: ruleId) {
            case .missing:
                return 0
            case .corrupted:
                return UInt128.max
            case .value(let loaded):
                state = loaded
            }
            let now = Date()

            // Use overflow-safe summation to prevent wrapping on UInt128.
            let entries: [SpendEntry]
            if let windowSeconds {
                let windowStart = now.addingTimeInterval(-Double(windowSeconds))
                entries = state.entries.filter { $0.timestamp > windowStart.timeIntervalSince1970 }
            } else {
                entries = state.entries
            }
            var total: UInt128 = 0
            for entry in entries {
                guard let amount = UInt128(entry.amount) else { return UInt128.max }
                let (newTotal, overflow) = total.addingReportingOverflow(amount)
                if overflow { return UInt128.max }
                total = newTotal
            }
            return total
        }
    }

    /// Records a spend for a spending limit rule.
    @discardableResult
    nonisolated func recordSpend(ruleId: String, amount: String, windowSeconds: Int?) -> Bool {
        if let windowSeconds, windowSeconds <= 0 {
            return false
        }
        return queue.sync {
            var state: SpendingWindowState
            switch loadSpendingState(ruleId: ruleId) {
            case .missing:
                state = SpendingWindowState(entries: [])
            case .corrupted:
                return false
            case .value(let loaded):
                state = loaded
            }
            let now = Date()

            // Prune expired entries if windowed
            if let windowSeconds {
                let windowStart = now.addingTimeInterval(-Double(windowSeconds))
                state.entries.removeAll { $0.timestamp <= windowStart.timeIntervalSince1970 }
            }

            state.entries.append(SpendEntry(timestamp: now.timeIntervalSince1970, amount: amount))
            return saveSpendingState(ruleId: ruleId, state: state)
        }
    }

    /// Returns status for a spending limit rule.
    nonisolated func spendingLimitStatus(rule: SpendingLimitRule) -> SpendingLimitStatus {
        if let windowSeconds = rule.windowSeconds, windowSeconds <= 0 {
            return SpendingLimitStatus(
                token: rule.token.displayName,
                allowance: rule.allowance,
                spent: String(UInt128.max),
                remaining: "0",
                windowSeconds: rule.windowSeconds,
                windowResetsAt: nil
            )
        }

        return queue.sync {
            let state: SpendingWindowState?
            switch loadSpendingState(ruleId: rule.id) {
            case .missing:
                state = nil
            case .corrupted:
                return SpendingLimitStatus(
                    token: rule.token.displayName,
                    allowance: rule.allowance,
                    spent: String(UInt128.max),
                    remaining: "0",
                    windowSeconds: rule.windowSeconds,
                    windowResetsAt: nil
                )
            case .value(let loaded):
                state = loaded
            }

            let now = Date()
            let entries: [SpendEntry]
            if let windowSeconds = rule.windowSeconds {
                let windowStart = now.addingTimeInterval(-Double(windowSeconds))
                entries = state?.entries.filter { $0.timestamp > windowStart.timeIntervalSince1970 } ?? []
            } else {
                entries = state?.entries ?? []
            }

            var spent: UInt128 = 0
            for entry in entries {
                guard let amount = UInt128(entry.amount) else {
                    return SpendingLimitStatus(
                        token: rule.token.displayName,
                        allowance: rule.allowance,
                        spent: String(UInt128.max),
                        remaining: "0",
                        windowSeconds: rule.windowSeconds,
                        windowResetsAt: nil
                    )
                }
                let (newTotal, overflow) = spent.addingReportingOverflow(amount)
                if overflow {
                    return SpendingLimitStatus(
                        token: rule.token.displayName,
                        allowance: rule.allowance,
                        spent: String(UInt128.max),
                        remaining: "0",
                        windowSeconds: rule.windowSeconds,
                        windowResetsAt: nil
                    )
                }
                spent = newTotal
            }

            let allowance = UInt128(rule.allowance) ?? 0
            let remaining = spent >= allowance ? UInt128(0) : allowance - spent
            let oldest = entries.min(by: { $0.timestamp < $1.timestamp })
            let resetsAt = rule.windowSeconds.flatMap { windowSeconds in
                oldest.map { Date(timeIntervalSince1970: $0.timestamp + Double(windowSeconds)) }
            }

            return SpendingLimitStatus(
                token: rule.token.displayName,
                allowance: rule.allowance,
                spent: String(spent),
                remaining: String(remaining),
                windowSeconds: rule.windowSeconds,
                windowResetsAt: resetsAt.map(Self.iso8601String)
            )
        }
    }

    // MARK: - Persistence

    private func loadRateLimitState(ruleId: String) -> LoadResult<RateLimitWindowState> {
        switch keychain.readResult(account: Self.rateLimitPrefix + ruleId) {
        case .missing:
            return .missing
        case .failure:
            return .corrupted
        case .found(let data):
            guard let state = try? JSONDecoder().decode(RateLimitWindowState.self, from: data) else {
                return .corrupted
            }
            return .value(state)
        }
    }

    private func saveRateLimitState(ruleId: String, state: RateLimitWindowState) -> Bool {
        guard let data = try? JSONEncoder().encode(state) else { return false }
        return keychain.write(account: Self.rateLimitPrefix + ruleId, data: data)
    }

    private func loadSpendingState(ruleId: String) -> LoadResult<SpendingWindowState> {
        switch keychain.readResult(account: Self.spendingPrefix + ruleId) {
        case .missing:
            return .missing
        case .failure:
            return .corrupted
        case .found(let data):
            guard let state = try? JSONDecoder().decode(SpendingWindowState.self, from: data) else {
                return .corrupted
            }
            return .value(state)
        }
    }

    private func saveSpendingState(ruleId: String, state: SpendingWindowState) -> Bool {
        guard let data = try? JSONEncoder().encode(state) else { return false }
        return keychain.write(account: Self.spendingPrefix + ruleId, data: data)
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
