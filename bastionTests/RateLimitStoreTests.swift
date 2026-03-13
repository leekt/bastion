import Foundation
import Testing
@testable import bastion

// MARK: - Mock Signer

/// HMAC-based mock signer for testing without Secure Enclave.
nonisolated final class MockStateSigner: StateSigner, @unchecked Sendable {
    private let key = "test-secret-key".data(using: .utf8)!
    var shouldFailVerification = false

    nonisolated func signState(_ data: Data) throws -> Data {
        // Simple HMAC-like signature: SHA256(key + data)
        var combined = key
        combined.append(data)
        // Use a basic hash as "signature"
        return Data(SHA256Hash(combined))
    }

    nonisolated func verifyState(_ data: Data, signature: Data) throws -> Bool {
        if shouldFailVerification { return false }
        let expected = try signState(data)
        return signature == expected
    }

    private func SHA256Hash(_ data: Data) -> [UInt8] {
        // Simple deterministic hash for testing (not cryptographic)
        var hash = [UInt8](repeating: 0, count: 32)
        let bytes = [UInt8](data)
        for (i, byte) in bytes.enumerated() {
            hash[i % 32] ^= byte &+ UInt8(i % 256)
        }
        return hash
    }
}

// MARK: - Tests

@Suite("RateLimitStore")
struct RateLimitStoreTests {

    private func makeTempURL() -> URL {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("bastion-test-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        return tmp.appendingPathComponent("ratelimit.signed")
    }

    @Test("Fresh store starts at count 0")
    func freshStoreStartsAtZero() {
        let store = RateLimitStore(fileURL: makeTempURL(), signer: MockStateSigner())
        #expect(store.todayCount() == 0)
    }

    @Test("Increment increases count")
    func incrementIncreasesCount() {
        let store = RateLimitStore(fileURL: makeTempURL(), signer: MockStateSigner())
        store.increment()
        #expect(store.todayCount() == 1)
        store.increment()
        #expect(store.todayCount() == 2)
        store.increment()
        store.increment()
        store.increment()
        #expect(store.todayCount() == 5)
    }

    @Test("Persists across instances")
    func persistsAcrossInstances() {
        let url = makeTempURL()
        let signer = MockStateSigner()

        let store1 = RateLimitStore(fileURL: url, signer: signer)
        store1.increment()
        store1.increment()
        store1.increment()
        #expect(store1.todayCount() == 3)

        // Create new instance from same file
        let store2 = RateLimitStore(fileURL: url, signer: signer)
        #expect(store2.todayCount() == 3)
    }

    @Test("Tampered file triggers max count (conservative)")
    func tamperedFileTriggersMaxCount() {
        let url = makeTempURL()
        let signer = MockStateSigner()

        // Write valid state
        let store1 = RateLimitStore(fileURL: url, signer: signer)
        store1.increment()
        store1.increment()
        #expect(store1.todayCount() == 2)

        // Tamper with the file
        let garbage = Data("tampered data".utf8)
        try! garbage.write(to: url, options: .atomic)

        // New instance should detect tampering
        let store2 = RateLimitStore(fileURL: url, signer: signer)
        #expect(store2.todayCount() == Int.max)
    }

    @Test("Invalid signature triggers max count")
    func invalidSignatureTriggersMaxCount() {
        let url = makeTempURL()
        let signer = MockStateSigner()

        // Write valid state
        let store1 = RateLimitStore(fileURL: url, signer: signer)
        store1.increment()

        // Load with signer that rejects all signatures
        let badSigner = MockStateSigner()
        badSigner.shouldFailVerification = true
        let store2 = RateLimitStore(fileURL: url, signer: badSigner)
        #expect(store2.todayCount() == Int.max)
    }

    @Test("No file means fresh start at 0")
    func noFileMeansFreshStart() {
        let url = makeTempURL()
        // Don't write anything — file doesn't exist
        let store = RateLimitStore(fileURL: url, signer: MockStateSigner())
        #expect(store.todayCount() == 0)
    }

    @Test("Rate limit boundary: exactly at limit")
    func rateLimitBoundary() {
        let limit = 5
        let store = RateLimitStore(fileURL: makeTempURL(), signer: MockStateSigner())

        for _ in 0..<limit {
            store.increment()
        }
        #expect(store.todayCount() == limit)

        // One more pushes over
        store.increment()
        #expect(store.todayCount() == limit + 1)
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
