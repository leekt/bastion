import Foundation
import Testing
@testable import bastion

// MARK: - In-memory keychain for testing

private nonisolated final class TestKeychain: KeychainBackend, @unchecked Sendable {
    private var storage: [String: Data] = [:]
    private let lock = NSLock()

    nonisolated func read(account: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return storage[account]
    }

    nonisolated func write(account: String, data: Data) {
        lock.lock(); defer { lock.unlock() }
        storage[account] = data
    }

    nonisolated func delete(account: String) {
        lock.lock(); defer { lock.unlock() }
        storage.removeValue(forKey: account)
    }
}

// MARK: - Helpers

private func makeTempLog() throws -> (AuditLog, URL, TestKeychain) {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let url = dir.appendingPathComponent("audit.log")
    let keychain = TestKeychain()
    let log = AuditLog(logURL: url, keychain: keychain)
    return (log, url, keychain)
}

private func makeRequest(id: String) -> SignRequest {
    SignRequest(
        operation: .message("hello bastion"),
        requestID: id,
        timestamp: Date(timeIntervalSince1970: 1_710_000_000),
        clientBundleId: "com.example.agent"
    )
}

private func makeContext() -> ClientSigningContext {
    ClientSigningContext(
        bundleId: "com.example.agent",
        profileId: "com.example.agent",
        profileLabel: nil,
        authPolicy: .biometricOrPasscode,
        keyTag: "com.bastion.signingkey.test",
        accountAddress: "0x1234567890abcdef1234567890abcdef12345678",
        rules: .default
    )
}

// MARK: - HMAC Tamper Evidence Tests

@Suite("AuditLog HMAC Tamper Evidence")
struct AuditLogHMACTests {

    @Test("normal write+read cycle leaves logTampered false")
    func normalCycleNotTampered() throws {
        let (log, _, _) = try makeTempLog()
        let request = makeRequest(id: "req-hmac-1")
        let client = makeContext()

        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-hmac-1", request: request, clientContext: client))

        let records = log.recentRequestRecords(limit: 10)
        #expect(records.count == 1)
        #expect(log.logTampered == false)
    }

    @Test("tampering the file sets logTampered to true")
    func tamperedFileDetected() throws {
        let (log, url, _) = try makeTempLog()
        let request = makeRequest(id: "req-hmac-2")
        let client = makeContext()

        // Write a legitimate record so a MAC is stored.
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-hmac-2", request: request, clientContext: client))
        #expect(log.logTampered == false)

        // Tamper: overwrite the file with modified content.
        var fileData = try Data(contentsOf: url)
        // Flip the first byte to corrupt the content.
        fileData[0] = fileData[0] ^ 0xFF
        try fileData.write(to: url)

        // A subsequent read should detect the mismatch.
        _ = log.recentRequestRecords(limit: 10)
        #expect(log.logTampered == true)
    }

    @Test("missing MAC on existing file does not set logTampered")
    func missingMACNoTamperFlag() throws {
        let (log, url, keychain) = try makeTempLog()
        let request = makeRequest(id: "req-hmac-3")
        let client = makeContext()

        // Write a record (MAC gets stored).
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-hmac-3", request: request, clientContext: client))

        // Delete the stored MAC to simulate migration from older version.
        keychain.delete(account: "auditlog.mac")

        // Read should succeed without setting tampered flag (no stored MAC to compare against).
        _ = log.recentRequestRecords(limit: 10)
        #expect(log.logTampered == false)
    }

    @Test("empty file clears stored MAC and leaves logTampered false")
    func emptyFileCleanState() throws {
        let (log, url, keychain) = try makeTempLog()
        let request = makeRequest(id: "req-hmac-4")
        let client = makeContext()

        // Write then delete the file to simulate fresh start.
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-hmac-4", request: request, clientContext: client))
        try FileManager.default.removeItem(at: url)

        _ = log.recentRequestRecords(limit: 10)
        #expect(log.logTampered == false)
        #expect(keychain.read(account: "auditlog.mac") == nil)
    }

    @Test("second log instance using same keychain re-verifies MAC")
    func sharedKeychainVerification() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("audit.log")
        defer { try? FileManager.default.removeItem(at: dir) }

        let keychain = TestKeychain()
        let log1 = AuditLog(logURL: url, keychain: keychain)
        let request = makeRequest(id: "req-hmac-5")
        log1.record(AuditEvent(type: .signSuccess, dataPrefix: "req-hmac-5", request: request, clientContext: makeContext()))

        // Second instance reading the same file + keychain should pass.
        let log2 = AuditLog(logURL: url, keychain: keychain)
        _ = log2.recentRequestRecords(limit: 10)
        #expect(log2.logTampered == false)
    }
}

// MARK: - Field-Level Redaction Tests

@Suite("AuditLog Field-Level Redaction")
struct AuditLogRedactionTests {

    @Test("redactionLevel .none keeps payloads and details intact")
    func noneRedactionKeepsAll() throws {
        let (log, url, _) = try makeTempLog()
        log.redactionLevel = .none

        let request = makeRequest(id: "req-red-1")
        log.record(AuditEvent(
            type: .signSuccess,
            dataPrefix: "req-red-1",
            request: request,
            clientContext: makeContext(),
            redactionLevel: .none
        ))

        let data = try Data(contentsOf: url)
        let records = try JSONDecoder().decode([AuditRequestRecord].self, from: data)
        let snapshot = try #require(records.first?.request)

        #expect(snapshot.payloads != nil)
        #expect(snapshot.digestHex.hasPrefix("0x"))
        #expect(snapshot.digestHex != "[REDACTED]")
    }

    @Test("redactionLevel .redactPayloads removes payloads array")
    func redactPayloadsRemovesPayloads() throws {
        let request = makeRequest(id: "req-red-2")
        let event = AuditEvent(
            type: .signSuccess,
            dataPrefix: "req-red-2",
            request: request,
            clientContext: makeContext(),
            redactionLevel: .redactPayloads
        )
        let snapshot = try #require(event.request)
        #expect(snapshot.payloads == nil)
        // Details should not all be [REDACTED] for a simple message (no address/amount)
        #expect(!snapshot.details.isEmpty)
        // Digest is kept
        #expect(snapshot.digestHex.hasPrefix("0x"))
    }

    @Test("redactionLevel .redactPayloads redacts address-containing detail lines")
    func redactPayloadsRedactsAddressDetails() throws {
        // Build a userOp-like request so details contain an Ethereum address.
        let userOp = UserOperation(
            sender: "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF",
            nonce: "0x1",
            callData: Data(),
            verificationGasLimit: "0x5208",
            callGasLimit: "0x5208",
            preVerificationGas: "0x5208",
            maxPriorityFeePerGas: "0x3b9aca00",
            maxFeePerGas: "0x3b9aca00",
            chainId: 1,
            entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
            entryPointVersion: .v0_7
        )
        let request = SignRequest(
            operation: .userOperation(userOp),
            requestID: "req-red-addr",
            timestamp: Date(),
            clientBundleId: "com.example.agent"
        )
        let event = AuditEvent(
            type: .signSuccess,
            dataPrefix: "req-red-addr",
            request: request,
            clientContext: makeContext(),
            redactionLevel: .redactPayloads
        )
        let snapshot = try #require(event.request)
        // "Smart Account: 0xDeaD..." detail should be redacted
        let hasUnredactedAddress = snapshot.details.contains { detail in
            detail.contains("0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF")
        }
        #expect(!hasUnredactedAddress)
        #expect(snapshot.payloads == nil)
    }

    @Test("redactionLevel .redactAll removes details, digest, and payloads")
    func redactAllRemovesEverything() throws {
        let request = makeRequest(id: "req-red-3")
        let event = AuditEvent(
            type: .signSuccess,
            dataPrefix: "req-red-3",
            request: request,
            clientContext: makeContext(),
            redactionLevel: .redactAll
        )
        let snapshot = try #require(event.request)
        #expect(snapshot.payloads == nil)
        #expect(snapshot.digestHex == "[REDACTED]")
        #expect(snapshot.details == ["[REDACTED]"])
    }

    @Test("redactionLevel .redactAll preserves requestID, operationKind, title, summary")
    func redactAllPreservesMetadata() throws {
        let request = makeRequest(id: "req-red-4")
        let event = AuditEvent(
            type: .signSuccess,
            dataPrefix: "req-red-4",
            request: request,
            clientContext: makeContext(),
            redactionLevel: .redactAll
        )
        let snapshot = try #require(event.request)
        #expect(snapshot.requestID == "req-red-4")
        #expect(snapshot.operationKind == "raw_message")
        #expect(!snapshot.title.isEmpty)
        #expect(!snapshot.summary.isEmpty)
    }

    @Test("AuditRedactionLevel round-trips through BastionConfig encoding")
    func redactionLevelRoundTrips() throws {
        for level in AuditRedactionLevel.allCases {
            var config = BastionConfig.default
            config.auditRedactionLevel = level

            let encoder = JSONEncoder()
            let data = try encoder.encode(config)
            let decoded = try JSONDecoder().decode(BastionConfig.self, from: data)
            #expect(decoded.auditRedactionLevel == level)
        }
    }

    @Test("BastionConfig without auditRedactionLevel key defaults to .none")
    func missingKeyDefaultsToNone() throws {
        // Encode a config without the new field by using raw JSON.
        let json = """
        {"version":7,"authPolicy":"biometricOrPasscode","rules":{"enabled":true,"requireExplicitApproval":false,"rateLimits":[],"spendingLimits":[],"rawMessagePolicy":{"enabled":true,"allowRawSigning":false},"typedDataPolicy":{"enabled":true,"requireExplicitApproval":false,"domainRules":[],"structRules":[]}},"bundlerPreferences":{"chainRPCs":[]},"clientProfiles":[]}
        """.data(using: .utf8)!
        let config = try JSONDecoder().decode(BastionConfig.self, from: json)
        #expect(config.auditRedactionLevel == .none)
    }
}
