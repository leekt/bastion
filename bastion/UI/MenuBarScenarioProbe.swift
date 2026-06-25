import Foundation

nonisolated struct MenuBarStatusSnapshot: Codable, Equatable, Sendable {
    let mode: String
    let headerTitle: String
    let subtitle: String
    let showsStats: Bool
    let showsPolicyStatusWarning: Bool
    let pauseButtonTitle: String?

    init(_ presentation: MenuBarStatusPresentation) {
        switch presentation.mode {
        case .lockedDown: mode = "lockedDown"
        case .paused: mode = "paused"
        case .empty: mode = "empty"
        case .configCorrupt: mode = "configCorrupt"
        case .active: mode = "active"
        }
        headerTitle = presentation.headerTitle
        subtitle = presentation.subtitle
        showsStats = presentation.showsStats
        showsPolicyStatusWarning = presentation.showsPolicyStatusWarning
        pauseButtonTitle = presentation.pauseButtonTitle
    }
}

nonisolated struct MenuBarStatTileSnapshot: Codable, Equatable, Sendable {
    let value: Int
    let label: String
    let warn: Bool

    init(_ presentation: MenuBarStatTilePresentation) {
        value = presentation.value
        label = presentation.label
        warn = presentation.warn
    }
}

nonisolated struct MenuBarPairingPromptSnapshot: Codable, Equatable, Sendable {
    let title: String
    let errorMessage: String?
    let visibleRequestCount: Int
    let processName: String
    let bundleId: String
    let pairingCode: String
    let rejectButtonTitle: String
    let acceptButtonTitle: String
    let rowHelp: String

    init(
        prompt: PendingPairingPromptPresentation,
        visibleRequestCount: Int,
        request: PendingPairingRequestPresentation
    ) {
        title = prompt.title
        errorMessage = prompt.errorMessage
        self.visibleRequestCount = visibleRequestCount
        processName = request.processName
        bundleId = request.bundleId
        pairingCode = request.pairingCode
        rejectButtonTitle = request.rejectButtonTitle
        acceptButtonTitle = request.acceptButtonTitle
        rowHelp = request.rowHelp
    }
}

nonisolated struct MenuBarLockdownSnapshot: Codable, Equatable, Sendable {
    let title: String
    let subtitle: String
    let detail: String
    let installedValidators: Int
    let installedValidatorsWarn: Bool
    let installedValidatorsLabel: String
    let activeSessions: Int
    let activeSessionsWarn: Bool
    let activeSessionsLabel: String
    let leaveButtonTitle: String

    init(_ presentation: MenuBarLockdownPresentation) {
        title = presentation.title
        subtitle = presentation.subtitle
        detail = presentation.detail
        installedValidators = presentation.installedValidators
        installedValidatorsWarn = presentation.installedValidatorsWarn
        installedValidatorsLabel = presentation.installedValidatorsLabel
        activeSessions = presentation.activeSessions
        activeSessionsWarn = presentation.activeSessionsWarn
        activeSessionsLabel = presentation.activeSessionsLabel
        leaveButtonTitle = presentation.leaveButtonTitle
    }
}

nonisolated struct MenuBarPendingSubmissionSnapshot: Codable, Equatable, Sendable {
    let sectionTitle: String
    let auditButtonTitle: String
    let rowCount: Int
    let clientDisplayName: String
    let provider: String
    let chainId: Int
    let statusLabel: String
    let userOpHash: String
    let userOpHashShort: String
    let rowHelp: String

    init(_ presentation: MenuBarPendingSubmissionsPresentation) {
        sectionTitle = presentation.sectionTitle
        auditButtonTitle = presentation.auditButtonTitle
        rowCount = presentation.rows.count
        let row = presentation.rows.first
        clientDisplayName = row?.clientDisplayName ?? ""
        provider = row?.provider ?? ""
        chainId = row?.chainId ?? 0
        statusLabel = row?.statusLabel ?? ""
        userOpHash = row?.userOpHash ?? ""
        userOpHashShort = row?.userOpHashShort ?? ""
        rowHelp = row?.rowHelp ?? ""
    }
}

nonisolated struct MenuBarRecentActivitySnapshot: Codable, Equatable, Sendable {
    let sectionTitle: String
    let viewAllButtonTitle: String
    let emptyMessage: String
    let rowCount: Int
    let firstTitle: String
    let firstClient: String
    let firstMode: String
    let firstTrailingTag: String?
    let firstRowHelp: String
    let limitedToThreeRows: Bool

    init(_ presentation: MenuBarRecentActivityPresentation) {
        sectionTitle = presentation.sectionTitle
        viewAllButtonTitle = presentation.viewAllButtonTitle
        emptyMessage = presentation.emptyMessage
        rowCount = presentation.rows.count
        let row = presentation.rows.first
        firstTitle = row?.title ?? ""
        firstClient = row?.client ?? ""
        firstMode = row?.mode.rawValue ?? ""
        firstTrailingTag = row?.trailingTag
        firstRowHelp = row?.rowHelp ?? ""
        limitedToThreeRows = presentation.rows.count == 3
    }
}

nonisolated struct MenuBarScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let activeStatus: MenuBarStatusSnapshot
    let emptyStatus: MenuBarStatusSnapshot
    let pausedStatus: MenuBarStatusSnapshot
    let lockedStatus: MenuBarStatusSnapshot
    let corruptStatus: MenuBarStatusSnapshot
    let statsTiles: [MenuBarStatTileSnapshot]
    let pairingPrompt: MenuBarPairingPromptSnapshot
    let pauseFailureMessage: String?
    let resumeFailureMessage: String?
    let lockdownPresentation: MenuBarLockdownSnapshot
    let pendingSubmissions: MenuBarPendingSubmissionSnapshot
    let recentActivity: MenuBarRecentActivitySnapshot
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct MenuBarScenarioEncodedProbeResponse: Sendable {
    let scenario: String
    let passed: Bool
    let diagnosticContext: [String: String]
    let data: Data
}

nonisolated enum MenuBarScenarioProbe {
    static let overviewScenario = "overview"

    static func run(scenario: String) throws -> MenuBarScenarioEncodedProbeResponse {
        let encoder = JSONEncoder()
        switch scenario {
        case overviewScenario:
            let response = overview()
            return MenuBarScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "statsTileCount": String(response.statsTiles.count),
                    "pairingVisibleRequestCount": String(response.pairingPrompt.visibleRequestCount),
                    "recentRowCount": String(response.recentActivity.rowCount),
                ],
                data: try encoder.encode(response)
            )
        default:
            throw NSError(
                domain: "com.bastion.menu-scenario-probe",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey: "Unknown menu scenario: \(scenario). Use \(overviewScenario)."
                ]
            )
        }
    }

    static func overview() -> MenuBarScenarioProbeResponse {
        let activeStatus = MenuBarStatusSnapshot(MenuBarStatusPresentation.make(
            armed: true,
            activeClients: 2,
            pauseState: .default
        ))
        let emptyStatus = MenuBarStatusSnapshot(MenuBarStatusPresentation.make(
            armed: true,
            activeClients: 0,
            pauseState: .default
        ))
        let pausedStatus = MenuBarStatusSnapshot(MenuBarStatusPresentation.make(
            armed: true,
            activeClients: 1,
            pauseState: PauseState(paused: true, lockedDown: false, pausedAt: Date(timeIntervalSince1970: 1), reason: "Maintenance")
        ))
        let lockedStatus = MenuBarStatusSnapshot(MenuBarStatusPresentation.make(
            armed: false,
            activeClients: 3,
            pauseState: PauseState(paused: true, lockedDown: true, pausedAt: Date(timeIntervalSince1970: 2), reason: "Emergency")
        ))
        let corruptStatus = MenuBarStatusSnapshot(MenuBarStatusPresentation.make(
            armed: false,
            activeClients: 1,
            pauseState: .default
        ))

        let stats = MenuBarStatsPresentation.make(totalToday: 61, silentToday: 60, overridesToday: 1)
        let statsTiles = stats.tiles.map(MenuBarStatTileSnapshot.init)

        let now = Date(timeIntervalSince1970: 1_710_000_000)
        let pairingRequest = PendingPairingRequest(
            id: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
            bundleId: "com.example.preview-agent",
            processName: "Preview Agent",
            pairingCode: "A1B2C3",
            createdAt: now,
            expiresAt: now.addingTimeInterval(60)
        )
        let expiredPairingRequest = PendingPairingRequest(
            id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            bundleId: "com.example.expired-agent",
            processName: "Expired Agent",
            pairingCode: "ZZ9999",
            createdAt: now.addingTimeInterval(-120),
            expiresAt: now.addingTimeInterval(-1)
        )
        let visibleRequests = PendingPairingPromptPresentation.visibleRequests(
            [pairingRequest, expiredPairingRequest],
            now: now
        )
        let pairingPrompt = MenuBarPairingPromptSnapshot(
            prompt: PendingPairingPromptPresentation.make(errorMessage: "Pairing request is already being resolved."),
            visibleRequestCount: visibleRequests.count,
            request: PendingPairingRequestPresentation.make(pairingRequest)
        )

        let pauseFailure = MenuBarStatusActionController.pauseFailureMessage(pausing: true, succeeded: false)
        let resumeFailure = MenuBarStatusActionController.resumeFailureMessage(succeeded: false)
        let lockdown = MenuBarLockdownSnapshot(MenuBarLockdownPresentation.make(
            reason: "Emergency",
            installedValidators: 2,
            activeSessions: 3
        ))

        let pendingStatus = PendingUserOperationStatus(
            requestID: "userop-1",
            clientDisplayName: "Bundler Agent",
            provider: "ZeroDev",
            chainId: 8453,
            userOpHash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            submittedAt: now
        )
        let pending = MenuBarPendingSubmissionSnapshot(MenuBarPendingSubmissionsPresentation.make([pendingStatus]))

        let recent = MenuBarRecentActivitySnapshot(MenuBarRecentActivityPresentation.make(
            records: [
                auditRecord(id: "recent-1", approvalMode: .ruleOverride, eventType: .signSuccess),
                auditRecord(id: "recent-2", approvalMode: .auto, eventType: .signSuccess),
                auditRecord(id: "recent-3", approvalMode: .policyReview, eventType: .userOpSubmitted),
                auditRecord(id: "recent-4", approvalMode: nil, eventType: .signDenied),
            ],
            limit: 3
        ))

        let checks = [
            SettingsScenarioProbeCheck(
                name: "status_overview_covers_active_empty_paused_locked_and_corrupt_modes",
                passed: activeStatus.mode == "active"
                    && activeStatus.subtitle == "Armed · 2 agents configured"
                    && activeStatus.showsStats
                    && activeStatus.pauseButtonTitle == "Pause"
                    && emptyStatus.mode == "empty"
                    && emptyStatus.subtitle == "Idle · no agents paired"
                    && !emptyStatus.showsStats
                    && pausedStatus.mode == "paused"
                    && pausedStatus.pauseButtonTitle == "Resume"
                    && lockedStatus.mode == "lockedDown"
                    && lockedStatus.headerTitle == "Lockdown active"
                    && !lockedStatus.showsStats
                    && corruptStatus.mode == "configCorrupt"
                    && corruptStatus.showsPolicyStatusWarning
            ),
            SettingsScenarioProbeCheck(
                name: "daily_totals_show_signed_silent_and_override_tiles",
                passed: statsTiles == [
                    MenuBarStatTileSnapshot(MenuBarStatTilePresentation(value: 61, label: "signed today", warn: false)),
                    MenuBarStatTileSnapshot(MenuBarStatTilePresentation(value: 60, label: "silent", warn: false)),
                    MenuBarStatTileSnapshot(MenuBarStatTilePresentation(value: 1, label: "overrides", warn: true)),
                ]
            ),
            SettingsScenarioProbeCheck(
                name: "incoming_pairing_prompt_exposes_full_request_and_filters_expired_entries",
                passed: pairingPrompt.visibleRequestCount == 1
                    && pairingPrompt.title == "Incoming pair request"
                    && pairingPrompt.processName == "Preview Agent"
                    && pairingPrompt.bundleId == "com.example.preview-agent"
                    && pairingPrompt.pairingCode == "A1B2C3"
                    && pairingPrompt.acceptButtonTitle == "Accept"
                    && pairingPrompt.rejectButtonTitle == "Reject"
                    && pairingPrompt.rowHelp.contains("Process: Preview Agent")
                    && pairingPrompt.rowHelp.contains("Bundle ID: com.example.preview-agent")
                    && pairingPrompt.rowHelp.contains("Pairing code: A1B2C3")
                    && pairingPrompt.errorMessage == "Pairing request is already being resolved."
            ),
            SettingsScenarioProbeCheck(
                name: "pause_resume_and_lockdown_copy_is_explicit_and_warns_about_residual_surface",
                passed: pauseFailure == "Pause is active in memory, but the paused state could not be saved."
                    && resumeFailure == "Could not fully resume signing. Authentication may have been cancelled or the updated state could not be saved."
                    && lockdown.installedValidators == 2
                    && lockdown.installedValidatorsWarn
                    && lockdown.activeSessions == 3
                    && lockdown.activeSessionsWarn
                    && lockdown.detail.contains("Validators left installed on-chain")
                    && lockdown.leaveButtonTitle == "Leave lockdown"
            ),
            SettingsScenarioProbeCheck(
                name: "pending_confirmations_expose_client_chain_hash_and_audit_navigation",
                passed: pending.sectionTitle == "Pending confirmations"
                    && pending.auditButtonTitle == "Audit"
                    && pending.rowCount == 1
                    && pending.clientDisplayName == "Bundler Agent"
                    && pending.provider == "ZeroDev"
                    && pending.chainId == 8453
                    && pending.statusLabel == "Awaiting receipt"
                    && pending.userOpHashShort == "0x12345678…abcdef"
                    && pending.rowHelp.contains("Client: Bundler Agent")
                    && pending.rowHelp.contains("Provider: ZeroDev")
                    && pending.rowHelp.contains("Chain: 8453")
                    && pending.rowHelp.contains(pending.userOpHash)
            ),
            SettingsScenarioProbeCheck(
                name: "recent_activity_limits_to_three_rows_and_exposes_full_help",
                passed: recent.sectionTitle == "Recent activity"
                    && recent.viewAllButtonTitle == "View all"
                    && recent.emptyMessage == "No recent activity"
                    && recent.rowCount == 3
                    && recent.limitedToThreeRows
                    && recent.firstClient == "Preview Agent"
                    && recent.firstMode == RequestExecutionMode.signOnly.rawValue
                    && recent.firstTrailingTag == "override"
                    && recent.firstRowHelp.contains("Activity: Raw / Message Signing")
                    && recent.firstRowHelp.contains("Personal-sign UTF-8 message")
                    && recent.firstRowHelp.contains("Client: Preview Agent")
                    && recent.firstRowHelp.contains("Mode: Sign only")
                    && recent.firstRowHelp.contains("Tag: override")
            ),
        ]

        return MenuBarScenarioProbeResponse(
            scenario: overviewScenario,
            passed: checks.allSatisfy(\.passed),
            activeStatus: activeStatus,
            emptyStatus: emptyStatus,
            pausedStatus: pausedStatus,
            lockedStatus: lockedStatus,
            corruptStatus: corruptStatus,
            statsTiles: statsTiles,
            pairingPrompt: pairingPrompt,
            pauseFailureMessage: pauseFailure,
            resumeFailureMessage: resumeFailure,
            lockdownPresentation: lockdown,
            pendingSubmissions: pending,
            recentActivity: recent,
            checks: checks
        )
    }

    private static func auditRecord(
        id: String,
        approvalMode: AuditEvent.ApprovalMode?,
        eventType: AuditEvent.EventType
    ) -> AuditRequestRecord {
        let request = SignRequest(
            operation: .message("hello bastion"),
            requestID: id,
            timestamp: Date(timeIntervalSince1970: 1_710_000_000),
            clientBundleId: "com.example.preview-agent"
        )
        let client = ClientSigningContext(
            bundleId: "com.example.preview-agent",
            profileId: "preview-agent",
            profileLabel: "Preview Agent",
            authPolicy: .biometricOrPasscode,
            keyTag: "com.bastion.signingkey.client.preview-agent",
            accountAddress: "0x1234567890abcdef1234567890abcdef12345678",
            rules: .default
        )
        return AuditRequestRecord(events: [
            AuditEvent(
                type: eventType,
                dataPrefix: id,
                approvalMode: approvalMode,
                request: request,
                clientContext: client
            )
        ])
    }
}
