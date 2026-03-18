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

    @Test("signPending followed by signSuccess is one record with final outcome")
    func pendingThenSuccessIsOneRecord() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let log = AuditLog(logURL: directory.appendingPathComponent("audit.log"))
        let request = makeRequest(id: "request-pending")
        let client = makeContext(bundleId: "com.example.agent")

        log.record(AuditEvent(type: .signPending, dataPrefix: "request-pending", request: request, clientContext: client))
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "request-pending", approvalMode: .policyReview, request: request, clientContext: client))

        let records = log.recentRequestRecords(limit: 10)
        #expect(records.count == 1)
        #expect(records[0].events.count == 2)
        #expect(records[0].latestResultLabel == "Signed (Approved)")
    }

    @Test("standalone signPending shows Pending Approval label")
    func standalonePendingShowsLabel() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let log = AuditLog(logURL: directory.appendingPathComponent("audit.log"))
        let request = makeRequest(id: "request-orphan")
        let client = makeContext(bundleId: "com.example.agent")

        log.record(AuditEvent(type: .signPending, dataPrefix: "request-orphan", request: request, clientContext: client))

        let records = log.recentRequestRecords(limit: 10)
        #expect(records.count == 1)
        #expect(records[0].latestResultLabel == "Pending Approval")
    }

    @Test("records older than 90 days are dropped on next write")
    func dropsExpiredRecords() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let log = AuditLog(logURL: directory.appendingPathComponent("audit.log"))

        // Write a recent record
        let recentRequest = makeRequest(id: "recent-1")
        let client = makeContext(bundleId: "com.example.agent")
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "recent-1", request: recentRequest, clientContext: client))

        // Directly inject an old record by writing raw JSON with an old timestamp.
        // Must use fractional seconds so AuditEvent.timestampDate returns non-nil.
        let oldFormatter = ISO8601DateFormatter()
        oldFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let oldTimestamp = oldFormatter.string(from: Date().addingTimeInterval(-100 * 24 * 3600))
        let oldEvent = """
        {"id":"old-event-id","timestamp":"\(oldTimestamp)","type":"sign_success","dataPrefix":"old-1","request":{"requestID":"old-1","operationKind":"raw_message","title":"Old","summary":"Old","details":[],"digestHex":"0x","payloads":null}}
        """
        let oldRecord = """
        {"id":"old-1","events":[\(oldEvent)]}
        """
        let recentData = try Data(contentsOf: directory.appendingPathComponent("audit.log"))
        let existing = try JSONDecoder().decode([AuditRequestRecord].self, from: recentData)
        var oldRecords = existing
        let oldRecordDecoded = try JSONDecoder().decode(AuditRequestRecord.self, from: Data(oldRecord.utf8))
        oldRecords.append(oldRecordDecoded)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(oldRecords).write(to: directory.appendingPathComponent("audit.log"))

        // Writing a new event triggers rotation
        let request2 = makeRequest(id: "recent-2")
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "recent-2", request: request2, clientContext: client))

        let records = log.recentRequestRecords(limit: 100)
        #expect(records.allSatisfy { $0.requestID != "old-1" })
        #expect(records.contains { $0.requestID == "recent-1" })
        #expect(records.contains { $0.requestID == "recent-2" })
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
