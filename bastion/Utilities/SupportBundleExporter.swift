import Foundation

nonisolated struct SupportBundleRequest: Codable, Sendable {
    let maxAuditRecords: Int?
    let maxDiagnosticEntries: Int?
    let maxCrashReports: Int?

    init(maxAuditRecords: Int? = nil, maxDiagnosticEntries: Int? = nil, maxCrashReports: Int? = nil) {
        self.maxAuditRecords = maxAuditRecords
        self.maxDiagnosticEntries = maxDiagnosticEntries
        self.maxCrashReports = maxCrashReports
    }
}

nonisolated struct SupportBundle: Codable, Sendable {
    let schemaVersion: Int
    let exportedAt: String
    let service: SupportServiceSnapshot
    let config: SupportConfigSnapshot
    let audit: SupportAuditSnapshot
    let diagnostics: [DiagnosticLogEntry]
    let crashes: [CrashReportSummary]
    let artifacts: SupportOperationalArtifacts
    let notes: [String]
}

nonisolated struct SupportServiceSnapshot: Codable, Sendable, Equatable {
    let version: String
    let serviceRegistrationStatus: String
    let configCorrupted: Bool
    let bundlePath: String
    let executablePath: String
    let bundleIdentifier: String?
    let processIdentifier: Int32
    let launchMode: String
    let machServiceName: String
    let launchAgentPlistName: String
}

nonisolated struct SupportConfigSnapshot: Codable, Sendable, Equatable {
    let version: Int
    let authPolicy: String
    let auditRedactionLevel: String
    let zeroDevProjectConfigured: Bool
    let chainRPCs: [SupportChainRPCSnapshot]
    let clientProfiles: [SupportClientProfileSnapshot]
    let walletGroups: [SupportWalletGroupSnapshot]
    let pauseState: SupportPauseStateSnapshot
}

nonisolated struct SupportChainRPCSnapshot: Codable, Sendable, Equatable {
    let chainId: Int
    let host: String?
}

nonisolated struct SupportClientProfileSnapshot: Codable, Sendable, Equatable {
    let id: String
    let bundleId: String
    let label: String?
    let authPolicy: String?
    let isGroupMember: Bool
    let walletGroupId: String?
    let membershipId: String?
}

nonisolated struct SupportWalletGroupSnapshot: Codable, Sendable, Equatable {
    let id: String
    let label: String
    let chainIds: [Int]
    let hasAccountAddress: Bool
    let memberCount: Int
    let activeMemberCount: Int
}

nonisolated struct SupportPauseStateSnapshot: Codable, Sendable, Equatable {
    let paused: Bool
    let lockedDown: Bool
    let hasReason: Bool
}

nonisolated struct SupportAuditSnapshot: Codable, Sendable {
    let logTampered: Bool
    let chainBroken: Bool
    let redactionApplied: String
    let recentRecords: [AuditRequestRecord]
}

nonisolated struct SupportOperationalArtifacts: Codable, Sendable, Equatable {
    let preflight: [SupportPreflightArtifact]
    let providerResponses: [SupportProviderArtifact]
}

nonisolated struct SupportPreflightArtifact: Codable, Sendable, Equatable {
    let requestID: String
    let dataPrefix: String
    let client: String
    let operationKind: String?
    let title: String
    let summary: String?
    let details: [String]
    let result: String
    let reason: String?
}

nonisolated struct SupportProviderArtifact: Codable, Sendable, Equatable {
    let requestID: String
    let dataPrefix: String
    let client: String
    let provider: String
    let status: String
    let detail: String?
    let failureStage: String?
    let failureCategory: String?
    let retryable: Bool?
    let recoverySuggestion: String?
    let userOpHash: String?
    let transactionHash: String?
}

nonisolated enum SupportBundleExporter {
    static let schemaVersion = 1

    static func makeBundleData(
        config: BastionConfig,
        service: SupportServiceSnapshot,
        auditLog: AuditLog = .shared,
        diagnosticLog: DiagnosticLog = .shared,
        crashReportCollector: CrashReportCollector = .shared,
        request: SupportBundleRequest = SupportBundleRequest()
    ) throws -> Data {
        let auditLimit = min(max(request.maxAuditRecords ?? 50, 1), 200)
        let diagnosticsLimit = min(max(request.maxDiagnosticEntries ?? 200, 1), 1000)
        let crashLimit = min(max(request.maxCrashReports ?? 10, 1), 50)
        let bundle = makeBundle(
            config: config,
            service: service,
            records: auditLog.recentRequestRecords(limit: auditLimit),
            auditLogTampered: auditLog.logTampered,
            auditChainBroken: auditLog.chainBroken,
            diagnostics: diagnosticLog.recentEntries(limit: diagnosticsLimit),
            crashReports: crashReportCollector.recentReports(limit: crashLimit)
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(bundle)
    }

    static func makeBundle(
        config: BastionConfig,
        service: SupportServiceSnapshot,
        records: [AuditRequestRecord],
        auditLogTampered: Bool,
        auditChainBroken: Bool,
        diagnostics: [DiagnosticLogEntry],
        crashReports: [CrashReportSummary] = [],
        exportedAt: Date = Date()
    ) -> SupportBundle {
        let sanitizedRecords = records.map { sanitize(record: $0) }
        return SupportBundle(
            schemaVersion: schemaVersion,
            exportedAt: timestamp(exportedAt),
            service: service,
            config: sanitize(config),
            audit: SupportAuditSnapshot(
                logTampered: auditLogTampered,
                chainBroken: auditChainBroken,
                redactionApplied: AuditRedactionLevel.redactPayloads.rawValue,
                recentRecords: sanitizedRecords
            ),
            diagnostics: diagnostics,
            crashes: crashReports,
            artifacts: artifacts(from: sanitizedRecords),
            notes: [
                "Secure Enclave private keys, ZeroDev project IDs, RPC URLs, and raw config bytes are not included.",
                "Recent audit records are re-redacted with redactPayloads for support export.",
                "Crash report metadata is included, but raw crash report bodies are not included."
            ]
        )
    }

    static func serviceSnapshot(
        version: String,
        serviceRegistrationStatus: String,
        configCorrupted: Bool,
        bundlePath: String,
        executablePath: String,
        bundleIdentifier: String?,
        processIdentifier: Int32,
        launchMode: String,
        machServiceName: String,
        launchAgentPlistName: String
    ) -> SupportServiceSnapshot {
        SupportServiceSnapshot(
            version: version,
            serviceRegistrationStatus: serviceRegistrationStatus,
            configCorrupted: configCorrupted,
            bundlePath: bundlePath,
            executablePath: executablePath,
            bundleIdentifier: bundleIdentifier,
            processIdentifier: processIdentifier,
            launchMode: launchMode,
            machServiceName: machServiceName,
            launchAgentPlistName: launchAgentPlistName
        )
    }

    @MainActor
    static func currentServiceSnapshot(configCorrupted: Bool) -> SupportServiceSnapshot {
        let launchMode: String = {
            switch BastionLaunchController.resolveLaunchMode() {
            case .service: return "service"
            case .relay: return "relay"
            }
        }()
        return serviceSnapshot(
            version: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown",
            serviceRegistrationStatus: ServiceRegistration.statusDescription(),
            configCorrupted: configCorrupted,
            bundlePath: Bundle.main.bundlePath,
            executablePath: CommandLine.arguments.first ?? "",
            bundleIdentifier: Bundle.main.bundleIdentifier,
            processIdentifier: ProcessInfo.processInfo.processIdentifier,
            launchMode: launchMode,
            machServiceName: xpcServiceName,
            launchAgentPlistName: ServiceRegistration.launchAgentPlistName
        )
    }

    private static func sanitize(_ config: BastionConfig) -> SupportConfigSnapshot {
        SupportConfigSnapshot(
            version: config.version,
            authPolicy: config.authPolicy.rawValue,
            auditRedactionLevel: config.auditRedactionLevel.rawValue,
            zeroDevProjectConfigured: config.bundlerPreferences.zeroDevProjectId?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false,
            chainRPCs: config.bundlerPreferences.chainRPCs.map {
                SupportChainRPCSnapshot(chainId: $0.chainId, host: URL(string: $0.rpcURL)?.host)
            },
            clientProfiles: config.clientProfiles.map {
                SupportClientProfileSnapshot(
                    id: $0.id,
                    bundleId: $0.bundleId,
                    label: $0.label,
                    authPolicy: $0.authPolicy?.rawValue,
                    isGroupMember: $0.isGroupMember,
                    walletGroupId: $0.walletGroupId,
                    membershipId: $0.membershipId
                )
            },
            walletGroups: config.walletGroups.map {
                SupportWalletGroupSnapshot(
                    id: $0.id,
                    label: $0.label,
                    chainIds: $0.chainIds,
                    hasAccountAddress: $0.accountAddress?.isEmpty == false,
                    memberCount: $0.members.count,
                    activeMemberCount: $0.activeMembers.count
                )
            },
            pauseState: SupportPauseStateSnapshot(
                paused: config.pauseState.paused,
                lockedDown: config.pauseState.lockedDown,
                hasReason: config.pauseState.reason?.isEmpty == false
            )
        )
    }

    private static func sanitize(record: AuditRequestRecord) -> AuditRequestRecord {
        AuditRequestRecord(
            events: record.events.map { $0.applyingRedaction(.redactPayloads) },
            chainHash: record.chainHash
        )
    }

    private static func artifacts(from records: [AuditRequestRecord]) -> SupportOperationalArtifacts {
        SupportOperationalArtifacts(
            preflight: records.flatMap(preflightArtifacts),
            providerResponses: records.flatMap(providerArtifacts)
        )
    }

    private static func preflightArtifacts(from record: AuditRequestRecord) -> [SupportPreflightArtifact] {
        record.events.compactMap { event in
            guard event.type == .preflightCompleted else { return nil }
            return SupportPreflightArtifact(
                requestID: event.request?.requestID ?? record.id,
                dataPrefix: event.dataPrefix,
                client: event.clientDisplayName,
                operationKind: event.request?.operationKind,
                title: event.request?.title ?? event.operationTitle,
                summary: event.request?.summary,
                details: event.request?.details ?? [],
                result: event.reason == nil ? "completed" : "completed_with_failure",
                reason: event.reason
            )
        }
    }

    private static func providerArtifacts(from record: AuditRequestRecord) -> [SupportProviderArtifact] {
        record.events.compactMap { event in
            guard let submission = event.submission else { return nil }
            return SupportProviderArtifact(
                requestID: event.request?.requestID ?? record.id,
                dataPrefix: event.dataPrefix,
                client: event.clientDisplayName,
                provider: submission.provider,
                status: submission.status,
                detail: submission.detail,
                failureStage: submission.failureStage,
                failureCategory: submission.failureCategory,
                retryable: submission.retryable,
                recoverySuggestion: submission.recoverySuggestion,
                userOpHash: submission.userOpHash,
                transactionHash: submission.transactionHash
            )
        }
    }

    private static func timestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}
