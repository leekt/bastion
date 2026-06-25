import Foundation
import CryptoKit
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

        let log = AuditLog(logURL: directory.appendingPathComponent("audit.log"), keychain: MockKeychainBackend())
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

        let keychain = MockKeychainBackend()
        sealAuditFixture(legacyData, keychain: keychain)

        let log = AuditLog(logURL: logURL, keychain: keychain)
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

        let log = AuditLog(logURL: directory.appendingPathComponent("audit.log"), keychain: MockKeychainBackend())
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

        let log = AuditLog(logURL: directory.appendingPathComponent("audit.log"), keychain: MockKeychainBackend())
        let request = makeRequest(id: "request-orphan")
        let client = makeContext(bundleId: "com.example.agent")

        log.record(AuditEvent(type: .signPending, dataPrefix: "request-orphan", request: request, clientContext: client))

        let records = log.recentRequestRecords(limit: 10)
        #expect(records.count == 1)
        #expect(records[0].latestResultLabel == "Pending Approval")
    }

    @Test("approval mode totals count all today's successes")
    func approvalModeTotalsCountAllTodaySuccesses() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let log = AuditLog(logURL: directory.appendingPathComponent("audit.log"), keychain: MockKeychainBackend())
        let client = makeContext(bundleId: "com.example.agent")

        for idx in 0..<60 {
            let request = makeRequest(id: "auto-\(idx)")
            log.record(AuditEvent(type: .signSuccess, dataPrefix: "auto-\(idx)", approvalMode: .auto, request: request, clientContext: client))
        }
        let overrideRequest = makeRequest(id: "override-1")
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "override-1", approvalMode: .ruleOverride, request: overrideRequest, clientContext: client))

        #expect(log.totalCountToday(approvalMode: .auto) == 60)
        #expect(log.totalCountToday(approvalMode: .ruleOverride) == 1)
        #expect(log.recentRequestRecords(limit: 50).count == 50)
    }

    @Test("client latest timestamp searches beyond recent display limit")
    func clientLatestTimestampSearchesBeyondRecentDisplayLimit() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let log = AuditLog(logURL: directory.appendingPathComponent("audit.log"), keychain: MockKeychainBackend())
        let targetClient = makeContext(bundleId: "com.example.target")
        let otherClient = makeContext(bundleId: "com.example.other")

        let targetRequest = makeRequest(id: "target-activity")
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "target-activity", request: targetRequest, clientContext: targetClient))
        for idx in 0..<60 {
            let request = makeRequest(id: "other-\(idx)")
            log.record(AuditEvent(type: .signSuccess, dataPrefix: "other-\(idx)", request: request, clientContext: otherClient))
        }

        #expect(log.recentRequestRecords(limit: 50).allSatisfy { $0.clientDisplayName != "com.example.target" })
        #expect(log.latestTimestamp(forClientDisplayName: "com.example.target") != nil)
    }

    @Test("records older than 90 days are dropped on next write")
    func dropsExpiredRecords() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let logURL = directory.appendingPathComponent("audit.log")
        let client = makeContext(bundleId: "com.example.agent")
        let oldFormatter = ISO8601DateFormatter()
        oldFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let oldTimestamp = oldFormatter.string(from: Date().addingTimeInterval(-100 * 24 * 3600))

        let recentRecord = AuditRequestRecord(events: [
            AuditEvent(type: .signSuccess, dataPrefix: "recent-1", request: makeRequest(id: "recent-1"), clientContext: client)
        ])
        let oldRecord = try JSONDecoder().decode(AuditRequestRecord.self, from: Data("""
        {"id":"old-1","events":[{"id":"old-event-id","timestamp":"\(oldTimestamp)","type":"sign_success","dataPrefix":"old-1","request":{"requestID":"old-1","operationKind":"raw_message","title":"Old","summary":"Old","details":[],"digestHex":"0x","payloads":null}}]}
        """.utf8))

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        var legacyRecordsData = Data()
        legacyRecordsData.append(try encoder.encode(recentRecord))
        legacyRecordsData.append(contentsOf: [0x0a])
        legacyRecordsData.append(try encoder.encode(oldRecord))
        legacyRecordsData.append(contentsOf: [0x0a])
        try legacyRecordsData.write(to: logURL)

        let keychain = MockKeychainBackend()
        sealAuditFixture(legacyRecordsData, keychain: keychain)
        let log = AuditLog(logURL: logURL, keychain: keychain)

        // Writing a new event triggers rotation
        let request2 = makeRequest(id: "recent-2")
        log.record(AuditEvent(type: .signSuccess, dataPrefix: "recent-2", request: request2, clientContext: client))

        let records = log.recentRequestRecords(limit: 100)
        #expect(records.allSatisfy { $0.requestID != "old-1" })
        #expect(records.contains { $0.requestID == "recent-1" })
        #expect(records.contains { $0.requestID == "recent-2" })
    }

    @Test("plain JSON audit export round-trips records")
    func plainJSONExportRoundTripsRecords() throws {
        let record = AuditRequestRecord(events: [
            AuditEvent(
                type: .signSuccess,
                dataPrefix: "plain-json-1",
                approvalMode: .policyReview,
                request: makeRequest(id: "plain-json-1"),
                clientContext: makeContext(bundleId: "com.example.agent", profileLabel: "Example Agent")
            )
        ])

        let rendered = try AuditExporter.shared.render(records: [record], format: .plainJSON)
        #expect(rendered.suggestedFilename.hasPrefix("bastion-audit-"))
        #expect(rendered.suggestedFilename.hasSuffix(".json"))
        #expect(rendered.suggestedFilename.hasSuffix(".signed.json") == false)

        let decoded = try JSONDecoder().decode([AuditRequestRecord].self, from: rendered.data)
        let exported = try #require(decoded.first)
        #expect(decoded.count == 1)
        #expect(exported.requestID == "plain-json-1")
        #expect(exported.clientDisplayName == "Example Agent")
        #expect(exported.operationTitle == "Raw / Message Signing")
        #expect(exported.latestResultLabel == "Signed (Approved)")

        let json = try #require(String(data: rendered.data, encoding: .utf8))
        #expect(json.contains("\"signature\"") == false)
    }

    @Test("signed JSON audit export wraps records with install ID and signature")
    func signedJSONExportWrapsRecordsWithInstallIDAndSignature() throws {
        let record = AuditRequestRecord(events: [
            AuditEvent(
                type: .signSuccess,
                dataPrefix: "signed-json-1",
                approvalMode: .policyReview,
                request: makeRequest(id: "signed-json-1"),
                clientContext: makeContext(bundleId: "com.example.agent", profileLabel: "Example Agent")
            )
        ])
        let exporter = AuditExporter(
            installIdentifier: { "test-install-id" },
            computeExportHMAC: { "test-signature-\($0.count)" }
        )

        let rendered = try exporter.render(records: [record], format: .signedJSON)
        #expect(rendered.suggestedFilename.hasPrefix("bastion-audit-"))
        #expect(rendered.suggestedFilename.hasSuffix(".signed.json"))

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let bundle = try decoder.decode(AuditExportBundle.self, from: rendered.data)
        let exported = try #require(bundle.records.first)
        #expect(bundle.installId == "test-install-id")
        #expect(bundle.recordCount == 1)
        #expect(bundle.signature?.hasPrefix("test-signature-") == true)
        #expect(exported.requestID == "signed-json-1")
        #expect(exported.clientDisplayName == "Example Agent")
    }

    @Test("CSV audit export escapes fields")
    func csvExportEscapesFields() throws {
        let record = AuditRequestRecord(events: [
            AuditEvent(
                type: .signDenied,
                dataPrefix: "csv-1",
                reason: "Denied, \"needs review\"\nRetry later",
                request: makeRequest(id: "csv-1"),
                clientContext: makeContext(bundleId: "com.example.csv", profileLabel: "Agent, \"Alpha\"")
            )
        ])

        let rendered = try AuditExporter.shared.render(records: [record], format: .csv)
        #expect(rendered.suggestedFilename.hasPrefix("bastion-audit-"))
        #expect(rendered.suggestedFilename.hasSuffix(".csv"))

        let csv = try #require(String(data: rendered.data, encoding: .utf8))
        let timestamp = try #require(record.latestEvent?.timestamp)
        let expected = [
            "timestamp,client,operation,result,reason,request_id",
            "\(timestamp),\"Agent, \"\"Alpha\"\"\",Raw / Message Signing,Denied,\"Denied, \"\"needs review\"\"\nRetry later\",csv-1"
        ].joined(separator: "\n")
        #expect(csv == expected)
    }

    @Test("Audit export sheet presentation covers formats, errors, and duplicate save guard")
    func auditExportSheetPresentationCoversFormatsErrorsAndDuplicateSaveGuard() {
        var state = AuditExportSheetState()
        var presentation = AuditExportSheetPresentation.make(count: 7, state: state)

        #expect(presentation.title == "Export audit log")
        #expect(presentation.subtitle == "7 requests · signed by your Bastion installation")
        #expect(presentation.cancelButtonTitle == "Cancel")
        #expect(presentation.saveButtonTitle == "Save…")
        #expect(presentation.disablesFormatSelection == false)
        #expect(presentation.disablesCancel == false)
        #expect(presentation.disablesSave == false)
        #expect(presentation.errorMessage == nil)
        #expect(presentation.options == [
            AuditExportSheetOptionPresentation(
                format: .signedJSON,
                label: "Signed JSON bundle",
                hint: "Tamper-evident · for compliance review",
                isSelected: true
            ),
            AuditExportSheetOptionPresentation(
                format: .plainJSON,
                label: "Plain JSON",
                hint: "For your own scripts",
                isSelected: false
            ),
            AuditExportSheetOptionPresentation(
                format: .csv,
                label: "CSV",
                hint: "Spreadsheet-friendly · less detail",
                isSelected: false
            ),
        ])
        #expect(AuditExportSheetFormat.signedJSON.auditFormat == .signedJSON)
        #expect(AuditExportSheetFormat.plainJSON.auditFormat == .plainJSON)
        #expect(AuditExportSheetFormat.csv.auditFormat == .csv)

        state.failSave("disk full")
        presentation = AuditExportSheetPresentation.make(count: 7, state: state)
        #expect(presentation.errorMessage == "Save failed: disk full")
        #expect(presentation.saveButtonTitle == "Save…")
        #expect(presentation.disablesSave == false)

        state.selectFormat(.csv)
        presentation = AuditExportSheetPresentation.make(count: 7, state: state)
        #expect(state.format == .csv)
        #expect(presentation.errorMessage == nil)
        #expect(presentation.options.first(where: { $0.format == .csv })?.isSelected == true)
        #expect(presentation.options.first(where: { $0.format == .signedJSON })?.isSelected == false)

        #expect(state.beginSave() == true)
        #expect(state.beginSave() == false)
        presentation = AuditExportSheetPresentation.make(count: 7, state: state)
        #expect(presentation.saveButtonTitle == "Saving…")
        #expect(presentation.disablesFormatSelection == true)
        #expect(presentation.disablesCancel == true)
        #expect(presentation.disablesSave == true)

        state.selectFormat(.plainJSON)
        #expect(state.format == .csv)

        state.failExport("bad record")
        presentation = AuditExportSheetPresentation.make(count: 7, state: state)
        #expect(presentation.errorMessage == "Export failed: bad record")
        #expect(presentation.saveButtonTitle == "Save…")
        #expect(presentation.disablesSave == false)
    }

    private func sealAuditFixture(_ data: Data, keychain: MockKeychainBackend) {
        let key = Data("test-audit-hmac-key".utf8)
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
        keychain.write(account: "auditlog.hmackey", data: key)
        keychain.write(account: "auditlog.mac", data: Data(mac))
    }

    private func makeRequest(id: String) -> SignRequest {
        SignRequest(
            operation: .message("hello bastion"),
            requestID: id,
            timestamp: Date(timeIntervalSince1970: 1_710_000_000),
            clientBundleId: "com.example.agent"
        )
    }

    private func makeContext(bundleId: String?, profileLabel: String? = nil) -> ClientSigningContext {
        ClientSigningContext(
            bundleId: bundleId,
            profileId: bundleId,
            profileLabel: profileLabel,
            authPolicy: .biometricOrPasscode,
            keyTag: "com.bastion.signingkey.test",
            accountAddress: "0x1234567890abcdef1234567890abcdef12345678",
            rules: .default
        )
    }
}
