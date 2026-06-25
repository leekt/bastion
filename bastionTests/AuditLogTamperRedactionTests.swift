import Foundation
import CryptoKit
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

    @discardableResult
    nonisolated func write(account: String, data: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        storage[account] = data
        return true
    }

    @discardableResult
    nonisolated func delete(account: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        storage.removeValue(forKey: account)
        return true
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

    @Test("tampered log is not rewritten by later record attempts")
    func tamperedLogNotRewrittenByRecord() throws {
        let (log, url, _) = try makeTempLog()
        let request = makeRequest(id: "req-hmac-no-rewrite")
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-hmac-no-rewrite", request: request, clientContext: makeContext()))

        var text = try String(contentsOf: url, encoding: .utf8)
        if text.contains("hello bastion") {
            text = text.replacingOccurrences(of: "hello bastion", with: "hello altered")
        } else {
            text += "\n"
        }
        let tamperedData = Data(text.utf8)
        try tamperedData.write(to: url)

        log.record(AuditEvent(type: .signDenied, dataPrefix: "req-hmac-new", reason: "should not append"))

        let after = try Data(contentsOf: url)
        #expect(after == tamperedData)
        #expect(log.logTampered == true)
    }

    @Test("missing MAC on existing file sets logTampered")
    func missingMACTampers() throws {
        let (log, _, keychain) = try makeTempLog()
        let request = makeRequest(id: "req-hmac-3")
        let client = makeContext()

        // Write a record (MAC gets stored).
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-hmac-3", request: request, clientContext: client))

        // Delete the stored MAC. Pre-release builds do not accept unsealed logs.
        keychain.delete(account: "auditlog.mac")

        // Read should fail closed because the log is no longer sealed.
        _ = log.recentRequestRecords(limit: 10)
        #expect(log.logTampered == true)
    }

    @Test("missing file with stored MAC leaves tamper state sticky")
    func missingFileWithStoredMACTampers() throws {
        let (log, url, keychain) = try makeTempLog()
        let request = makeRequest(id: "req-hmac-4")
        let client = makeContext()

        // Write then delete the file to simulate fresh start.
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-hmac-4", request: request, clientContext: client))
        try FileManager.default.removeItem(at: url)

        _ = log.recentRequestRecords(limit: 10)
        #expect(log.logTampered == true)
        #expect(keychain.read(account: "auditlog.mac") != nil)
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

    @Test("tamper recovery archives broken file and allows a fresh audit chain")
    func tamperRecoveryArchivesAndAllowsFreshWrites() throws {
        let (log, url, _) = try makeTempLog()
        let request = makeRequest(id: "req-hmac-recover")
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-hmac-recover", request: request, clientContext: makeContext()))

        var tamperedData = try Data(contentsOf: url)
        tamperedData.append(0x0a)
        try tamperedData.write(to: url)

        _ = log.recentRequestRecords(limit: 10)
        #expect(log.logTampered == true)

        let result = try log.archiveAndResetTamperedLog()
        let archivedPath = try #require(result.archivedLogPath)
        #expect(result.recovered == true)
        #expect(FileManager.default.fileExists(atPath: archivedPath))
        #expect((try? Data(contentsOf: URL(fileURLWithPath: archivedPath))) == tamperedData)
        #expect(FileManager.default.fileExists(atPath: url.path) == false)
        #expect(log.logTampered == false)
        #expect(log.chainBroken == false)

        let next = makeRequest(id: "req-hmac-after-recover")
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-hmac-after-recover", request: next, clientContext: makeContext()))
        let records = log.recentRequestRecords(limit: 10)
        #expect(records.count == 1)
        #expect(records.first?.requestID == "req-hmac-after-recover")
        #expect(log.logTampered == false)
    }

    @Test("tamper recovery clears missing-file stored MAC state")
    func tamperRecoveryClearsMissingFileStoredMAC() throws {
        let (log, url, _) = try makeTempLog()
        let request = makeRequest(id: "req-hmac-missing-recover")
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-hmac-missing-recover", request: request, clientContext: makeContext()))
        try FileManager.default.removeItem(at: url)

        _ = log.recentRequestRecords(limit: 10)
        #expect(log.logTampered == true)

        let result = try log.archiveAndResetTamperedLog()
        #expect(result.recovered == true)
        #expect(result.archivedLogPath == nil)
        #expect(log.logTampered == false)

        let next = makeRequest(id: "req-hmac-missing-after-recover")
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-hmac-missing-after-recover", request: next, clientContext: makeContext()))
        #expect(log.recentRequestRecords(limit: 10).first?.requestID == "req-hmac-missing-after-recover")
        #expect(log.logTampered == false)
    }

    @Test("tamper recovery archives hash-chain break and allows fresh writes")
    func tamperRecoveryArchivesHashChainBreak() throws {
        let (log, url, keychain) = try makeTempLog()
        let oldRequest = makeRequest(id: "req-chain-old")
        let newRequest = makeRequest(id: "req-chain-new")
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-chain-old", request: oldRequest, clientContext: makeContext()))
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-chain-new", request: newRequest, clientContext: makeContext()))

        let records = try JSONDecoder().decode([AuditRequestRecord].self, from: Data(contentsOf: url))
        #expect(records.count == 2)

        let brokenRecords = [
            AuditRequestRecord(events: records[0].events, chainHash: "broken-chain-hash"),
            records[1]
        ]
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let brokenData = try encoder.encode(brokenRecords)
        try brokenData.write(to: url, options: .atomic)
        try resealAuditLog(data: brokenData, keychain: keychain)

        _ = log.recentRequestRecords(limit: 10)
        #expect(log.logTampered == false)
        #expect(log.chainBroken == true)

        let result = try log.archiveAndResetTamperedLog()
        let archivedPath = try #require(result.archivedLogPath)
        #expect(result.recovered == true)
        #expect((try? Data(contentsOf: URL(fileURLWithPath: archivedPath))) == brokenData)
        #expect(FileManager.default.fileExists(atPath: url.path) == false)
        #expect(log.logTampered == false)
        #expect(log.chainBroken == false)

        let next = makeRequest(id: "req-chain-after-recover")
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "req-chain-after-recover", request: next, clientContext: makeContext()))
        #expect(log.recentRequestRecords(limit: 10).first?.requestID == "req-chain-after-recover")
        #expect(log.logTampered == false)
        #expect(log.chainBroken == false)
    }

    @Test("tamper recovery banner presentation covers broken, recovering, recovered, and error states")
    func tamperRecoveryBannerPresentationCoversStates() {
        let broken = AuditTamperRecoveryBannerPresentation.make(
            auditIntegrityBroken: true,
            isRecovering: false,
            recoveryMessage: "Archived broken audit log",
            recoveryError: "Recovery failed: earlier attempt"
        )
        #expect(broken == AuditTamperRecoveryBannerPresentation(
            tone: .bad,
            title: "Audit log integrity check failed",
            message: "Export the visible records if needed, then archive and reset the broken log to resume audit writes.",
            recoveryError: "Recovery failed: earlier attempt",
            recoveryDetail: nil,
            showsRecoveryActions: true,
            exportButtonTitle: "Export…",
            recoverButtonTitle: "Archive and reset",
            dismissButtonTitle: nil,
            disablesActions: false
        ))

        let recovering = AuditTamperRecoveryBannerPresentation.make(
            auditIntegrityBroken: true,
            isRecovering: true,
            recoveryMessage: nil,
            recoveryError: nil
        )
        #expect(recovering.recoverButtonTitle == "Resetting…")
        #expect(recovering.disablesActions == true)
        #expect(recovering.exportButtonTitle == "Export…")
        #expect(recovering.showsRecoveryActions == true)

        let recovered = AuditTamperRecoveryBannerPresentation.make(
            auditIntegrityBroken: false,
            isRecovering: false,
            recoveryMessage: "Archived broken audit log to /tmp/audit.log",
            recoveryError: nil
        )
        #expect(recovered == AuditTamperRecoveryBannerPresentation(
            tone: .ok,
            title: "Audit log recovery complete",
            message: "Archived broken audit log to /tmp/audit.log",
            recoveryError: nil,
            recoveryDetail: "Archived broken audit log to /tmp/audit.log",
            showsRecoveryActions: false,
            exportButtonTitle: nil,
            recoverButtonTitle: nil,
            dismissButtonTitle: "Dismiss",
            disablesActions: false
        ))

        let recoveredWithError = AuditTamperRecoveryBannerPresentation.make(
            auditIntegrityBroken: false,
            isRecovering: false,
            recoveryMessage: nil,
            recoveryError: "Recovery failed: permission denied"
        )
        #expect(recoveredWithError.tone == .ok)
        #expect(recoveredWithError.message == "Audit logging can resume with a fresh integrity chain.")
        #expect(recoveredWithError.recoveryError == "Recovery failed: permission denied")
        #expect(recoveredWithError.dismissButtonTitle == "Dismiss")
    }

    private func resealAuditLog(data: Data, keychain: TestKeychain) throws {
        let key = try #require(keychain.read(account: "auditlog.hmackey"))
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
        keychain.write(account: "auditlog.mac", data: Data(mac))
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

    @Test("AuditLog.record applies configured redaction to direct AuditEvent values")
    func recordAppliesConfiguredRedaction() throws {
        let (log, url, _) = try makeTempLog()
        log.redactionLevel = .redactAll

        let request = makeRequest(id: "req-red-direct")
        log.record(AuditEvent(
            type: .signSuccess,
            dataPrefix: "req-red-direct",
            request: request,
            clientContext: makeContext()
        ))

        let data = try Data(contentsOf: url)
        let records = try JSONDecoder().decode([AuditRequestRecord].self, from: data)
        let snapshot = try #require(records.first?.request)
        #expect(snapshot.summary == "[REDACTED]")
        #expect(snapshot.digestHex == "[REDACTED]")
        #expect(snapshot.payloads == nil)
    }

    @Test("redaction covers reason, client address, and submission metadata")
    func redactionCoversReasonClientAndSubmission() throws {
        let (log, url, _) = try makeTempLog()
        log.redactionLevel = .redactAll

        log.record(AuditEvent(
            type: .userOpSendFailed,
            dataPrefix: "req-red-meta",
            reason: "RPC failed for 0x1234567890abcdef1234567890abcdef12345678",
            clientContext: makeContext(),
            submission: AuditSubmissionSnapshot(
                provider: "zerodev",
                status: "failed",
                userOpHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                transactionHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                detail: "project 0x1234567890abcdef1234567890abcdef12345678"
            )
        ))

        let data = try Data(contentsOf: url)
        let records = try JSONDecoder().decode([AuditRequestRecord].self, from: data)
        let event = try #require(records.first?.latestEvent)
        #expect(event.reason == "[REDACTED]")
        #expect(event.client?.accountAddress == "[REDACTED]")
        #expect(event.submission?.userOpHash == "[REDACTED]")
        #expect(event.submission?.transactionHash == "[REDACTED]")
        #expect(event.submission?.detail == "[REDACTED]")
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

    @Test("redactionLevel .redactAll preserves non-sensitive metadata only")
    func redactAllPreservesNonSensitiveMetadata() throws {
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
        #expect(snapshot.summary == "[REDACTED]")
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
