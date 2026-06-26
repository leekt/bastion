import Foundation
import Testing
@testable import bastion

@Suite("Diagnostics and support bundle")
struct SupportBundleTests {

    @Test("DiagnosticLog records and tails JSONL entries")
    func diagnosticLogRecordsEntries() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = DiagnosticLog(logURL: dir.appendingPathComponent("diagnostics.jsonl"))

        log.record(category: .lifecycle, event: "service_started", message: "started")
        log.record(level: .warning, category: .xpc, event: "rate_limited", message: "limited")

        let entries = log.recentEntries(limit: 1)

        #expect(entries.count == 1)
        #expect(entries[0].level == .warning)
        #expect(entries[0].category == .xpc)
        #expect(entries[0].event == "rate_limited")
    }

    // AC-04 (audit 2026-06-taek): the support bundle must not leak the raw
    // profile UUID / membership id — those are the selectors the MCP bridge
    // accepts (AC-01), so leaking them turns the bundle into an
    // enumerate-then-impersonate primitive.
    @Test("Support bundle redacts profile id and membership id selectors")
    func supportBundleRedactsProfileSelectors() throws {
        let rawProfileId = "11111111-aaaa-bbbb-cccc-222222222222"
        let rawMembershipId = "33333333-dddd-eeee-ffff-444444444444"
        let rawGroupId = "55555555-0000-1111-2222-666666666666"
        var config = BastionConfig.default
        config.clientProfiles = [
            ClientProfile(
                id: rawProfileId,
                bundleId: "com.example.agent",
                label: "Agent",
                keyTag: "com.bastion.signingkey.client.x",
                rules: .default,
                walletGroupId: rawGroupId,
                membershipId: rawMembershipId
            )
        ]

        let bundle = SupportBundleExporter.makeBundle(
            config: config,
            service: serviceSnapshot(),
            records: [],
            auditLogTampered: false,
            auditChainBroken: false,
            diagnostics: []
        )
        let json = try #require(String(data: try JSONEncoder().encode(bundle), encoding: .utf8))

        // Raw selectors must be absent from the serialized bundle.
        #expect(json.contains(rawProfileId) == false)
        #expect(json.contains(rawMembershipId) == false)
        // Stable per-bundle placeholders preserve diagnostic distinctness.
        let snapshot = try #require(bundle.config.clientProfiles.first)
        #expect(snapshot.id == "profile-1")
        #expect(snapshot.membershipId == "member-1")
        // Non-selector diagnostic fields are retained.
        #expect(snapshot.bundleId == "com.example.agent")
        #expect(snapshot.isGroupMember == true)
    }

    @Test("Support bundle sanitizes config secrets")
    func supportBundleSanitizesConfigSecrets() throws {
        var config = BastionConfig.default
        config.bundlerPreferences = BundlerPreferences(
            zeroDevProjectId: "secret-project-id",
            chainRPCs: [
                ChainRPCPreference(chainId: 11155111, rpcURL: "https://rpc.example.com/secret/path?token=abc")
            ]
        )
        config.clientProfiles = [
            ClientProfile(
                id: "profile-1",
                bundleId: "com.example.agent",
                label: "Agent",
                keyTag: "com.bastion.signingkey.client.secret",
                rules: .default
            )
        ]

        let bundle = SupportBundleExporter.makeBundle(
            config: config,
            service: serviceSnapshot(),
            records: [],
            auditLogTampered: false,
            auditChainBroken: false,
            diagnostics: []
        )
        let data = try JSONEncoder().encode(bundle)
        let json = try #require(String(data: data, encoding: .utf8))

        #expect(bundle.config.zeroDevProjectConfigured == true)
        #expect(bundle.config.chainRPCs.first?.host == "rpc.example.com")
        #expect(json.contains("secret-project-id") == false)
        #expect(json.contains("token=abc") == false)
        #expect(json.contains("com.bastion.signingkey.client.secret") == false)
    }

    @Test("Support bundle re-redacts recent audit records")
    func supportBundleRedactsAuditRecords() {
        let sensitiveReason = "Transfer to 0x1234567890abcdef1234567890abcdef12345678 amount 1234567890123"
        let record = AuditRequestRecord(events: [
            AuditEvent(
                type: .userOpSendFailed,
                dataPrefix: "req",
                reason: sensitiveReason,
                submission: AuditSubmissionSnapshot(
                    provider: "ZeroDev",
                    status: "send_failed",
                    userOpHash: "0xabcdef",
                    transactionHash: "0x123456",
                    detail: sensitiveReason
                )
            )
        ])

        let bundle = SupportBundleExporter.makeBundle(
            config: .default,
            service: serviceSnapshot(),
            records: [record],
            auditLogTampered: false,
            auditChainBroken: false,
            diagnostics: []
        )
        let event = bundle.audit.recentRecords.first?.events.first

        #expect(event?.reason == "[REDACTED]")
        #expect(event?.submission?.userOpHash == "[REDACTED]")
        #expect(event?.submission?.transactionHash == "[REDACTED]")
        #expect(event?.submission?.detail == "[REDACTED]")
    }

    @Test("CrashReportCollector extracts bounded Bastion crash metadata")
    func crashReportCollectorExtractsMetadata() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let reportURL = dir.appendingPathComponent("bastion-2026-06-03-120000.crash")
        let body = """
        Process:               bastion [1234]
        Identifier:            com.bastion.app
        Incident Identifier:   ABCD-1234
        Date/Time:             2026-06-03 12:00:00.000 +0900
        Exception Type:        EXC_BAD_ACCESS (SIGSEGV)
        Exception Codes:       KERN_INVALID_ADDRESS at 0x0000000000000000
        Termination Reason:    Namespace SIGNAL, Code 11 Segmentation fault: 11
        Sensitive stack body that should not be copied wholesale
        """
        try Data(body.utf8).write(to: reportURL)

        let reports = CrashReportCollector(directories: [dir]).recentReports(limit: 5)

        #expect(reports.count == 1)
        #expect(reports[0].filename == reportURL.lastPathComponent)
        #expect(reports[0].process == "bastion [1234]")
        #expect(reports[0].identifier == "com.bastion.app")
        #expect(reports[0].exceptionType == "EXC_BAD_ACCESS (SIGSEGV)")
        #expect(reports[0].summary.contains("Exception: EXC_BAD_ACCESS (SIGSEGV)"))
        #expect(reports[0].summary.joined(separator: "\n").contains("Sensitive stack body") == false)
    }

    @Test("Support bundle includes crash report metadata")
    func supportBundleIncludesCrashMetadata() {
        let crash = CrashReportSummary(
            id: "crash-1",
            filename: "bastion.crash",
            modifiedAt: "2026-06-03T03:00:00.000Z",
            reportType: "crash",
            process: "bastion",
            identifier: "com.bastion.app",
            incidentIdentifier: "incident",
            dateTime: "2026-06-03 12:00:00",
            exceptionType: "EXC_CRASH",
            exceptionCodes: nil,
            terminationReason: "Namespace SIGNAL, Code 6",
            summary: ["Process: bastion", "Exception: EXC_CRASH"]
        )

        let bundle = SupportBundleExporter.makeBundle(
            config: .default,
            service: serviceSnapshot(),
            records: [],
            auditLogTampered: false,
            auditChainBroken: false,
            diagnostics: [],
            crashReports: [crash]
        )

        #expect(bundle.crashes.count == 1)
        #expect(bundle.crashes[0].filename == "bastion.crash")
        #expect(bundle.notes.contains { $0.contains("raw crash report bodies are not included") })
    }

    @Test("Support bundle extracts redacted preflight and provider artifacts")
    func supportBundleExtractsOperationalArtifacts() {
        let diagnostic = ProviderFailureDiagnostic.configuration(message: "ZeroDev project ID is not configured.")
        let record = AuditRequestRecord(events: [
            AuditEvent(
                type: .preflightCompleted,
                dataPrefix: "req",
                reason: "AA24 signature validation failed"
            ),
            AuditEvent(
                type: .userOpSendFailed,
                dataPrefix: "req",
                reason: diagnostic.userFacingMessage,
                submission: AuditSubmissionSnapshot(
                    provider: "ZeroDev",
                    status: "send_failed",
                    userOpHash: "0xabcdef",
                    transactionHash: nil,
                    detail: diagnostic.userFacingMessage,
                    diagnostic: diagnostic
                )
            )
        ])

        let bundle = SupportBundleExporter.makeBundle(
            config: .default,
            service: serviceSnapshot(),
            records: [record],
            auditLogTampered: false,
            auditChainBroken: false,
            diagnostics: []
        )

        #expect(bundle.artifacts.preflight.count == 1)
        #expect(bundle.artifacts.preflight[0].result == "completed_with_failure")
        #expect(bundle.artifacts.providerResponses.count == 1)
        #expect(bundle.artifacts.providerResponses[0].provider == "ZeroDev")
        #expect(bundle.artifacts.providerResponses[0].failureStage == diagnostic.stage.rawValue)
        #expect(bundle.artifacts.providerResponses[0].failureCategory == diagnostic.category.rawValue)
        #expect(bundle.artifacts.providerResponses[0].retryable == diagnostic.retryable)
        #expect(bundle.artifacts.providerResponses[0].userOpHash == "[REDACTED]")
    }

    @Test("Support bundle data encodes bounded export payload")
    func supportBundleDataEncodesBoundedExportPayload() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let crashDir = dir.appendingPathComponent("crashes", isDirectory: true)
        try FileManager.default.createDirectory(at: crashDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let auditLog = AuditLog(
            logURL: dir.appendingPathComponent("audit.log"),
            keychain: MockKeychainBackend()
        )
        auditLog.record(AuditEvent(
            type: .signSuccess,
            dataPrefix: "support-record",
            request: makeRequest(id: "support-record")
        ))

        let diagnosticLog = DiagnosticLog(logURL: dir.appendingPathComponent("diagnostics.jsonl"))
        diagnosticLog.record(category: .support, event: "excluded", message: "older diagnostic")
        diagnosticLog.record(
            level: .warning,
            category: .support,
            event: "included",
            message: "newer diagnostic",
            context: ["phase": "export"]
        )

        let oldCrash = crashDir.appendingPathComponent("bastion-old.crash")
        let newerCrash = crashDir.appendingPathComponent("bastion-new.crash")
        try writeCrashReport("Old Crash", to: oldCrash)
        try writeCrashReport("New Crash", to: newerCrash)
        try FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSince1970: 1_700_000_000)],
            ofItemAtPath: oldCrash.path
        )
        try FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSince1970: 1_710_000_000)],
            ofItemAtPath: newerCrash.path
        )

        var config = BastionConfig.default
        config.bundlerPreferences = BundlerPreferences(
            zeroDevProjectId: "secret-project-id",
            chainRPCs: [
                ChainRPCPreference(chainId: 1, rpcURL: "https://mainnet.example.com/secret?token=abc")
            ]
        )

        let data = try SupportBundleExporter.makeBundleData(
            config: config,
            service: serviceSnapshot(status: "enabled"),
            auditLog: auditLog,
            diagnosticLog: diagnosticLog,
            crashReportCollector: CrashReportCollector(directories: [crashDir]),
            request: SupportBundleRequest(maxAuditRecords: 1, maxDiagnosticEntries: 1, maxCrashReports: 1)
        )
        let bundle = try JSONDecoder().decode(SupportBundle.self, from: data)
        let json = try #require(String(data: data, encoding: .utf8))

        #expect(bundle.schemaVersion == SupportBundleExporter.schemaVersion)
        #expect(bundle.service.serviceRegistrationStatus == "enabled")
        #expect(bundle.config.zeroDevProjectConfigured == true)
        #expect(bundle.config.chainRPCs == [SupportChainRPCSnapshot(chainId: 1, host: "mainnet.example.com")])
        #expect(bundle.audit.recentRecords.count == 1)
        #expect(bundle.audit.recentRecords.first?.requestID == "support-record")
        #expect(bundle.audit.redactionApplied == AuditRedactionLevel.redactPayloads.rawValue)
        #expect(bundle.diagnostics.count == 1)
        #expect(bundle.diagnostics[0].event == "included")
        #expect(bundle.diagnostics[0].context["phase"] == "export")
        #expect(bundle.crashes.count == 1)
        #expect(bundle.crashes[0].filename == "bastion-new.crash")
        #expect(bundle.notes.contains { $0.contains("raw crash report bodies are not included") })
        #expect(json.contains("secret-project-id") == false)
        #expect(json.contains("token=abc") == false)
    }

    @Test("Diagnostics snapshot reports healthy dashboard state when no issues are present")
    func diagnosticsSnapshotHealthyState() {
        let snapshot = diagnosticsSnapshot()

        #expect(snapshot.warningCount == 0)
        #expect(snapshot.errorCount == 0)
        #expect(snapshot.serviceState == .ok)
        #expect(snapshot.auditState == .ok)
        #expect(snapshot.auditStateLabel == "Healthy")
        #expect(snapshot.diagnosticsState == .ok)
        #expect(snapshot.crashState == .ok)
        #expect(snapshot.crashStateLabel == "None found")
        #expect(snapshot.overallDot == .ok)
        #expect(snapshot.subtitle == "No recent support issues detected")
    }

    @Test("Diagnostics snapshot escalates warnings, crashes, audit, config, and diagnostic errors")
    func diagnosticsSnapshotSeverityOrdering() {
        let warning = diagnosticsSnapshot(diagnostics: [
            diagnostic(level: .warning, event: "rate_limited")
        ])
        #expect(warning.warningCount == 1)
        #expect(warning.diagnosticsState == .warn)
        #expect(warning.overallDot == .warn)
        #expect(warning.subtitle == "1 recent diagnostic warnings")

        let crash = diagnosticsSnapshot(crashReports: [crashReport()])
        #expect(crash.crashState == .warn)
        #expect(crash.crashStateLabel == "1 found")
        #expect(crash.overallDot == .warn)
        #expect(crash.subtitle == "1 recent crash reports available")

        let auditTampered = diagnosticsSnapshot(auditTampered: true)
        #expect(auditTampered.auditState == .bad)
        #expect(auditTampered.auditStateLabel == "Tampered")
        #expect(auditTampered.overallDot == .bad)
        #expect(auditTampered.subtitle == "Audit integrity needs recovery")

        let auditChainBroken = diagnosticsSnapshot(auditChainBroken: true)
        #expect(auditChainBroken.auditStateLabel == "Chain broken")
        #expect(auditChainBroken.overallDot == .bad)
        #expect(auditChainBroken.subtitle == "Audit integrity needs recovery")

        let diagnosticError = diagnosticsSnapshot(diagnostics: [
            diagnostic(level: .error, event: "service_failed"),
            diagnostic(level: .warning, event: "retrying")
        ])
        #expect(diagnosticError.errorCount == 1)
        #expect(diagnosticError.warningCount == 1)
        #expect(diagnosticError.diagnosticsState == .bad)
        #expect(diagnosticError.overallDot == .bad)
        #expect(diagnosticError.subtitle == "1 recent diagnostic errors")

        let configCorrupted = diagnosticsSnapshot(configCorrupted: true, diagnostics: [
            diagnostic(level: .error, event: "later_error")
        ])
        #expect(configCorrupted.overallDot == .bad)
        #expect(configCorrupted.subtitle == "Config recovery required")
    }

    @Test("Diagnostics snapshot marks non-enabled service registration as warning")
    func diagnosticsSnapshotWarnsWhenServiceIsNotEnabled() {
        let snapshot = diagnosticsSnapshot(serviceStatus: "requires_approval")

        #expect(snapshot.serviceState == .warn)
        #expect(snapshot.overallDot == .warn)
        #expect(snapshot.subtitle == "Service registration needs attention")
    }

    @Test("Diagnostics dashboard presentation covers header, tiles, sections, and refresh state")
    func diagnosticsDashboardPresentationCoversHeaderTilesSectionsAndRefreshState() {
        let snapshot = diagnosticsSnapshot(
            serviceStatus: "requires_approval",
            auditChainBroken: true,
            diagnostics: [
                diagnostic(level: .error, event: "xpc_failed"),
                diagnostic(level: .warning, event: "notification_skipped"),
            ],
            crashReports: [crashReport()]
        )

        let presentation = DiagnosticsDashboardPresentation.make(
            snapshot: snapshot,
            isExporting: false,
            exportStatus: "bastion-support.json",
            exportError: "Export failed: disk full"
        )

        #expect(presentation.title == "Diagnostics")
        #expect(presentation.subtitle == "Audit integrity needs recovery")
        #expect(presentation.overallDot == .bad)
        #expect(presentation.refreshButtonTitle == "Refresh")
        #expect(presentation.exportButtonTitle == "Export Bundle")
        #expect(presentation.disablesRefresh == false)
        #expect(presentation.disablesExport == false)
        #expect(presentation.exportStatus == "bastion-support.json")
        #expect(presentation.exportError == "Export failed: disk full")
        #expect(presentation.metricTiles == [
            DiagnosticsMetricTilePresentation(title: "Service", value: "requires_approval", state: .warn),
            DiagnosticsMetricTilePresentation(title: "Config", value: "Healthy", state: .ok),
            DiagnosticsMetricTilePresentation(title: "Audit", value: "Chain broken", state: .bad),
            DiagnosticsMetricTilePresentation(title: "Diagnostics", value: "1 errors · 1 warnings", state: .bad),
            DiagnosticsMetricTilePresentation(title: "Crashes", value: "1 found", state: .warn),
        ])
        #expect(presentation.serviceSectionTitle == "Service Snapshot")
        #expect(presentation.serviceSectionSubtitle == "Current process and registration context included in support exports.")
        #expect(presentation.serviceFields == [
            DiagnosticsFieldPresentation(label: "Version", value: "test"),
            DiagnosticsFieldPresentation(label: "Launch mode", value: "service"),
            DiagnosticsFieldPresentation(label: "Process ID", value: "123"),
            DiagnosticsFieldPresentation(label: "Bundle ID", value: "com.bastion.app"),
            DiagnosticsFieldPresentation(label: "Mach service", value: "com.bastion.xpc"),
            DiagnosticsFieldPresentation(label: "LaunchAgent plist", value: "com.bastion.xpc.plist"),
            DiagnosticsFieldPresentation(label: "Bundle path", value: "/tmp/Bastion.app"),
            DiagnosticsFieldPresentation(label: "Executable", value: "/tmp/Bastion.app/Contents/MacOS/bastion"),
        ])
        #expect(presentation.crashSectionTitle == "Crash Reports")
        #expect(presentation.crashSectionSubtitle == "Recent macOS DiagnosticReports for Bastion. Raw crash bodies are excluded from support bundles.")
        #expect(presentation.emptyCrashMessage == "No recent Bastion crash reports found.")
        #expect(presentation.diagnosticsSectionTitle == "Recent Diagnostics")
        #expect(presentation.diagnosticsSectionSubtitle == "2 newest lifecycle, XPC, approval, submission, notification, support, and update events.")
        #expect(presentation.emptyDiagnosticsMessage == "No diagnostic events recorded yet.")

        let exporting = DiagnosticsDashboardPresentation.make(
            snapshot: snapshot,
            isExporting: true,
            exportStatus: nil,
            exportError: nil
        )
        #expect(exporting.exportButtonTitle == "Exporting…")
        #expect(exporting.disablesRefresh == true)
        #expect(exporting.disablesExport == true)
    }

    @Test("Diagnostics support export state covers limits, duplicate guard, status, errors, and saved diagnostic")
    func diagnosticsSupportExportStateCoversFlow() {
        #expect(DiagnosticsSupportExportState.bundleRequest.maxAuditRecords == 100)
        #expect(DiagnosticsSupportExportState.bundleRequest.maxDiagnosticEntries == 500)
        #expect(DiagnosticsSupportExportState.bundleRequest.maxCrashReports == 20)
        #expect(DiagnosticsSupportExportState.savePanelTitle == "Export Bastion support bundle")

        var state = DiagnosticsSupportExportState(status: "old.json", error: "Export failed: stale", isExporting: false)
        #expect(state.beginExport() == true)
        #expect(state.status == nil)
        #expect(state.error == nil)
        #expect(state.isExporting == true)
        #expect(state.beginExport() == false)

        state.cancelExport()
        #expect(state.isExporting == false)

        #expect(state.beginExport() == true)
        state.succeed(filename: "bastion-support-20260622.json")
        #expect(state.status == "bastion-support-20260622.json")
        #expect(state.error == nil)
        #expect(state.isExporting == false)

        #expect(state.beginExport() == true)
        state.fail("disk full")
        #expect(state.status == nil)
        #expect(state.error == "Export failed: disk full")
        #expect(state.isExporting == false)

        state.clearError()
        #expect(state.error == nil)

        #expect(DiagnosticsSupportExportState.savedDiagnostic(filename: "bundle.json") == DiagnosticsSupportExportDiagnostic(
            category: .support,
            event: "support_bundle_saved",
            message: "Support bundle saved from diagnostics panel",
            context: ["filename": "bundle.json"]
        ))
    }

    private func diagnosticsSnapshot(
        serviceStatus: String = "enabled",
        configCorrupted: Bool = false,
        auditTampered: Bool = false,
        auditChainBroken: Bool = false,
        diagnostics: [DiagnosticLogEntry] = [],
        crashReports: [CrashReportSummary] = []
    ) -> DiagnosticsSnapshot {
        DiagnosticsSnapshot(
            service: serviceSnapshot(status: serviceStatus, configCorrupted: configCorrupted),
            auditTampered: auditTampered,
            auditChainBroken: auditChainBroken,
            diagnostics: diagnostics,
            crashReports: crashReports
        )
    }

    private func diagnostic(level: DiagnosticLevel, event: String) -> DiagnosticLogEntry {
        DiagnosticLogEntry(
            timestamp: "2026-06-22T00:00:00.000Z",
            level: level,
            category: .lifecycle,
            event: event,
            message: event,
            context: [:]
        )
    }

    private func crashReport() -> CrashReportSummary {
        CrashReportSummary(
            id: "crash-1",
            filename: "bastion.crash",
            modifiedAt: "2026-06-22T00:00:00.000Z",
            reportType: "crash",
            process: "bastion",
            identifier: "com.bastion.app",
            incidentIdentifier: "incident",
            dateTime: "2026-06-22 09:00:00",
            exceptionType: "EXC_CRASH",
            exceptionCodes: nil,
            terminationReason: nil,
            summary: ["Process: bastion", "Exception: EXC_CRASH"]
        )
    }

    private func makeRequest(id: String) -> SignRequest {
        SignRequest(
            operation: .message("support bundle payload"),
            requestID: id,
            timestamp: Date(timeIntervalSince1970: 1_710_000_000),
            clientBundleId: "com.example.support"
        )
    }

    private func writeCrashReport(_ processName: String, to url: URL) throws {
        let body = """
        Process:               \(processName) [1234]
        Identifier:            com.bastion.app
        Incident Identifier:   ABCD-1234
        Date/Time:             2026-06-03 12:00:00.000 +0900
        Exception Type:        EXC_CRASH
        Termination Reason:    Namespace SIGNAL, Code 6 Abort trap: 6
        Raw stack body omitted from support bundle.
        """
        try Data(body.utf8).write(to: url)
    }

    private func serviceSnapshot(
        status: String = "notRegistered",
        configCorrupted: Bool = false
    ) -> SupportServiceSnapshot {
        SupportServiceSnapshot(
            version: "test",
            serviceRegistrationStatus: status,
            configCorrupted: configCorrupted,
            bundlePath: "/tmp/Bastion.app",
            executablePath: "/tmp/Bastion.app/Contents/MacOS/bastion",
            bundleIdentifier: "com.bastion.app",
            processIdentifier: 123,
            launchMode: "service",
            machServiceName: "com.bastion.xpc",
            launchAgentPlistName: "com.bastion.xpc.plist"
        )
    }
}
