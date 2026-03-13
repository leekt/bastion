import Foundation

// MARK: - Keychain Backend Protocol

nonisolated protocol KeychainBackend: Sendable {
    func read(account: String) -> Data?
    func write(account: String, data: Data)
    func delete(account: String)
}

// MARK: - State Store

/// Tamper-proof state storage backed by macOS Keychain.
/// Agents cannot read, write, or delete Keychain items scoped to com.bastion.
/// Stores daily transaction counter and any future state that needs protection.
nonisolated final class StateStore: @unchecked Sendable {
    static let shared = StateStore(keychain: SystemKeychainBackend())

    private let keychain: KeychainBackend
    private let queue = DispatchQueue(label: "com.bastion.statestore")

    // Keychain account keys
    private static let rateLimitAccount = "state.ratelimit"

    // In-memory cache
    private var currentDate: String = ""
    private var currentCount: Int = 0

    init(keychain: KeychainBackend) {
        self.keychain = keychain
        loadFromKeychain()
    }

    /// Returns today's successful sign count.
    nonisolated func todayCount() -> Int {
        queue.sync {
            let today = Self.todayString()
            if currentDate == today {
                return currentCount
            }
            return 0
        }
    }

    /// Increments today's counter and persists to Keychain.
    nonisolated func increment() {
        queue.sync {
            let today = Self.todayString()
            if currentDate == today {
                currentCount += 1
            } else {
                currentDate = today
                currentCount = 1
            }
            saveToKeychain()
        }
    }

    // MARK: - Persistence

    private func loadFromKeychain() {
        queue.sync {
            guard let data = keychain.read(account: Self.rateLimitAccount),
                  let state = try? JSONDecoder().decode(RateLimitState.self, from: data) else {
                currentDate = Self.todayString()
                currentCount = 0
                return
            }

            let today = Self.todayString()
            if state.date == today {
                currentDate = state.date
                currentCount = state.count
            } else {
                currentDate = today
                currentCount = 0
            }
        }
    }

    private func saveToKeychain() {
        let state = RateLimitState(date: currentDate, count: currentCount)
        guard let data = try? JSONEncoder().encode(state) else { return }
        keychain.write(account: Self.rateLimitAccount, data: data)
    }

    static func todayString() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = .current
        return formatter.string(from: Date())
    }
}

nonisolated struct RateLimitState: Codable, Sendable {
    let date: String
    let count: Int
}
