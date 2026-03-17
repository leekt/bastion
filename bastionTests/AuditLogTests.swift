import Foundation
import Testing
@testable import bastion

@Suite("Audit Log")
struct AuditLogTests {

    @Test("same request is stored as one record")
    func storesSingleRecordPerRequest() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let log = AuditLog(logURL: directory.appendingPathComponent("audit.log"))
        let request = makeRequest(id: "request-1")
        let client = makeContext(bundleId: "com.example.agent")

        log.record(AuditEvent(
            type: .signSuccess,
            dataPrefix: "request-1",
            request: request,
            clientContext: client
        ))
        log.record(AuditEvent(
            type: .userOpSubmitted,
            dataPrefix: "request-1",
            request: request,
            clientContext: client,
            submission: AuditSubmissionSnapshot(
                provider: "ZeroDev",
                status: "submitted",
                userOpHash: "0x1234",
                transactionHash: nil,
                detail: "Accepted by bundler"
            )
        ))

        let data = try Data(contentsOf: directory.appendingPathComponent("audit.log"))
        let records = try JSONDecoder().decode([AuditRequestRecord].self, from: data)

        #expect(records.count == 1)
        #expect(records[0].requestID == "request-1")
        #expect(records[0].events.count == 2)
        #expect(records[0].latestResultLabel == "Submitted")
    }

    @Test("legacy event log is grouped into request records")
    func groupsLegacyEventLog() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let logURL = directory.appendingPathComponent("audit.log")
        let request = makeRequest(id: "request-legacy")
        let client = makeContext(bundleId: "com.example.agent")
        let encoder = JSONEncoder()
        let eventOne = try encoder.encode(AuditEvent(
            type: .signSuccess,
            dataPrefix: "legacy",
            request: request,
            clientContext: client
        ))
        let eventTwo = try encoder.encode(AuditEvent(
            type: .userOpReceiptSuccess,
            dataPrefix: "legacy",
            request: request,
            clientContext: client,
            submission: AuditSubmissionSnapshot(
                provider: "ZeroDev",
                status: "receipt_success",
                userOpHash: "0x9999",
                transactionHash: "0xabcd",
                detail: "Confirmed"
            )
        ))
        var legacyData = Data()
        legacyData.append(eventOne)
        legacyData.append(contentsOf: [0x0a])
        legacyData.append(eventTwo)
        legacyData.append(contentsOf: [0x0a])
        try legacyData.write(to: logURL)

        let log = AuditLog(logURL: logURL)
        let records = log.recentRequestRecords(limit: 10)
        let migratedData = try Data(contentsOf: logURL)
        let migratedRecords = try JSONDecoder().decode([AuditRequestRecord].self, from: migratedData)

        #expect(records.count == 1)
        #expect(records[0].events.count == 2)
        #expect(records[0].latestResultLabel == "Confirmed")
        #expect(migratedRecords.count == 1)
    }

    private func makeRequest(id: String) -> SignRequest {
        SignRequest(
            operation: .message("hello bastion"),
            requestID: id,
            timestamp: Date(timeIntervalSince1970: 1_710_000_000),
            clientBundleId: "com.example.agent"
        )
    }

    private func makeContext(bundleId: String?) -> ClientSigningContext {
        ClientSigningContext(
            bundleId: bundleId,
            profileId: bundleId,
            profileLabel: nil,
            authPolicy: .biometricOrPasscode,
            keyTag: "com.bastion.signingkey.test",
            accountAddress: "0x1234567890abcdef1234567890abcdef12345678",
            rules: .default
        )
    }
}
