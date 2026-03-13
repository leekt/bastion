import Foundation
import Testing
@testable import bastion

// MARK: - Mock Keychain Backend

/// In-memory keychain backend for testing without real Keychain.
nonisolated final class MockKeychainBackend: KeychainBackend, @unchecked Sendable {
    private var storage: [String: Data] = [:]
    private let lock = NSLock()

    nonisolated func read(account: String) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return storage[account]
    }

    nonisolated func write(account: String, data: Data) {
        lock.lock()
        defer { lock.unlock() }
        storage[account] = data
    }

    nonisolated func delete(account: String) {
        lock.lock()
        defer { lock.unlock() }
        storage.removeValue(forKey: account)
    }
}

// MARK: - StateStore Tests

@Suite("StateStore")
struct StateStoreTests {

    @Test("Fresh store starts at count 0")
    func freshStoreStartsAtZero() {
        let store = StateStore(keychain: MockKeychainBackend())
        #expect(store.todayCount() == 0)
    }

    @Test("Increment increases count")
    func incrementIncreasesCount() {
        let store = StateStore(keychain: MockKeychainBackend())
        store.increment()
        #expect(store.todayCount() == 1)
        store.increment()
        #expect(store.todayCount() == 2)
        store.increment()
        store.increment()
        store.increment()
        #expect(store.todayCount() == 5)
    }

    @Test("Persists across instances via shared keychain")
    func persistsAcrossInstances() {
        let keychain = MockKeychainBackend()

        let store1 = StateStore(keychain: keychain)
        store1.increment()
        store1.increment()
        store1.increment()
        #expect(store1.todayCount() == 3)

        // Create new instance from same keychain
        let store2 = StateStore(keychain: keychain)
        #expect(store2.todayCount() == 3)
    }

    @Test("Corrupted keychain data starts fresh at 0")
    func corruptedDataStartsFresh() {
        let keychain = MockKeychainBackend()

        // Write garbage data
        keychain.write(account: "state.ratelimit", data: Data("garbage".utf8))

        let store = StateStore(keychain: keychain)
        #expect(store.todayCount() == 0)
    }

    @Test("No keychain data means fresh start at 0")
    func noDataMeansFreshStart() {
        let store = StateStore(keychain: MockKeychainBackend())
        #expect(store.todayCount() == 0)
    }

    @Test("Rate limit boundary: exactly at limit")
    func rateLimitBoundary() {
        let limit = 5
        let store = StateStore(keychain: MockKeychainBackend())

        for _ in 0..<limit {
            store.increment()
        }
        #expect(store.todayCount() == limit)

        // One more pushes over
        store.increment()
        #expect(store.todayCount() == limit + 1)
    }
}

// MARK: - RuleEngine Config Tests

@Suite("RuleEngine Config")
struct RuleEngineConfigTests {

    @Test("Load default config when keychain empty")
    func loadDefaultConfig() {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)
        let config = engine.loadConfig()
        #expect(config.authPolicy == .open)
        #expect(config.rules.enabled == true)
    }

    @Test("Save and load config via keychain")
    func saveAndLoadConfig() throws {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)

        var newConfig = BastionConfig.default
        newConfig.authPolicy = .biometric
        newConfig.rules.maxTxPerDayWithoutAuth = 10
        newConfig.rules.requireExplicitApproval = true

        try engine.saveConfig(newConfig)

        let loaded = engine.loadConfig()
        #expect(loaded.authPolicy == .biometric)
        #expect(loaded.rules.maxTxPerDayWithoutAuth == 10)
        #expect(loaded.rules.requireExplicitApproval == true)
    }
}

@Suite("RuleEngine Validation")
struct RuleEngineValidationTests {

    private func makeRequest() -> SignRequest {
        SignRequest(
            data: Data(repeating: 0xAB, count: 32),
            requestID: UUID().uuidString,
            timestamp: Date()
        )
    }

    @Test("Disabled rules allow everything")
    func disabledRulesAllowAll() {
        let engine = RuleEngine.shared
        var config = BastionConfig.default
        config.rules.enabled = false
        let result = engine.validate(makeRequest(), config: config)
        if case .allowed = result { } else {
            Issue.record("Expected .allowed")
        }
    }

    @Test("Allowed hours within range passes")
    func allowedHoursWithinRange() {
        let engine = RuleEngine.shared
        let hour = Calendar.current.component(.hour, from: Date())
        var config = BastionConfig.default
        config.rules.allowedHours = AllowedHours(start: hour, end: (hour + 1) % 24)
        let result = engine.validate(makeRequest(), config: config)
        if case .allowed = result { } else {
            Issue.record("Expected .allowed within allowed hours")
        }
    }

    @Test("Allowed hours outside range denies")
    func allowedHoursOutsideRange() {
        let engine = RuleEngine.shared
        let hour = Calendar.current.component(.hour, from: Date())
        // Set allowed hours to a window that excludes current hour
        let start = (hour + 2) % 24
        let end = (hour + 3) % 24
        var config = BastionConfig.default
        config.rules.allowedHours = AllowedHours(start: start, end: end)
        let result = engine.validate(makeRequest(), config: config)
        if case .denied = result { } else {
            Issue.record("Expected .denied outside allowed hours")
        }
    }
}
