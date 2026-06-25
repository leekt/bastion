import AppKit
import Combine
import SwiftUI

// Redesigned menu bar dropdown — calm 340pt status panel.
// Renders inside MenuBarExtra(style: .window).

nonisolated enum MenuBarPanelMode: Equatable, Sendable {
    case lockedDown
    case paused
    case empty
    case configCorrupt
    case active
}

nonisolated struct MenuBarStatusPresentation: Equatable, Sendable {
    let mode: MenuBarPanelMode
    let headerTitle: String
    let subtitle: String
    let showsStats: Bool
    let showsPolicyStatusWarning: Bool
    let pauseButtonTitle: String?

    static func make(armed: Bool, activeClients: Int, pauseState: PauseState) -> MenuBarStatusPresentation {
        if pauseState.lockedDown {
            return MenuBarStatusPresentation(
                mode: .lockedDown,
                headerTitle: "Lockdown active",
                subtitle: pauseState.reason ?? "All signing rejected",
                showsStats: false,
                showsPolicyStatusWarning: false,
                pauseButtonTitle: nil
            )
        }
        if pauseState.paused {
            return MenuBarStatusPresentation(
                mode: .paused,
                headerTitle: "Bastion paused",
                subtitle: "Approval UI is in review-only mode",
                showsStats: true,
                showsPolicyStatusWarning: false,
                pauseButtonTitle: "Resume"
            )
        }
        if activeClients == 0 {
            return MenuBarStatusPresentation(
                mode: .empty,
                headerTitle: "Bastion",
                subtitle: "Idle · no agents paired",
                showsStats: false,
                showsPolicyStatusWarning: false,
                pauseButtonTitle: nil
            )
        }

        let subtitle = armedSubtitle(armed: armed, activeClients: activeClients)
        return MenuBarStatusPresentation(
            mode: armed ? .active : .configCorrupt,
            headerTitle: "Bastion",
            subtitle: subtitle,
            showsStats: true,
            showsPolicyStatusWarning: !armed,
            pauseButtonTitle: "Pause"
        )
    }

    static func armedSubtitle(armed: Bool, activeClients: Int) -> String {
        if !armed {
            return "Rules config corrupt"
        }
        if activeClients == 0 {
            return "Armed · default rules"
        }
        return "Armed · \(activeClients) \(activeClients == 1 ? "agent" : "agents") configured"
    }
}

nonisolated struct PendingPairingPromptPresentation: Equatable, Sendable {
    let title: String
    let errorMessage: String?

    static func make(errorMessage: String?) -> PendingPairingPromptPresentation {
        PendingPairingPromptPresentation(
            title: "Incoming pair request",
            errorMessage: errorMessage
        )
    }

    static func visibleRequests(_ requests: [PendingPairingRequest], now: Date) -> [PendingPairingRequest] {
        requests.filter { $0.expiresAt > now }
    }
}

nonisolated struct PendingPairingRequestPresentation: Equatable, Sendable {
    let id: UUID
    let processName: String
    let bundleId: String
    let pairingCode: String
    let rejectButtonTitle: String
    let acceptButtonTitle: String
    let rowHelp: String

    static func make(_ request: PendingPairingRequest) -> PendingPairingRequestPresentation {
        PendingPairingRequestPresentation(
            id: request.id,
            processName: request.processName,
            bundleId: request.bundleId,
            pairingCode: request.pairingCode,
            rejectButtonTitle: "Reject",
            acceptButtonTitle: "Accept",
            rowHelp: "Process: \(request.processName)\nBundle ID: \(request.bundleId)\nPairing code: \(request.pairingCode)"
        )
    }
}

enum MenuBarPanelRefreshScheduler {
    static let refreshInterval: Duration = .seconds(1)

    @MainActor
    static func run(
        interval: Duration = refreshInterval,
        sleep: (Duration) async throws -> Void = { delay in
            try await Task.sleep(for: delay)
        },
        refresh: () -> Void
    ) async {
        refresh()

        while !Task.isCancelled {
            do {
                try await sleep(interval)
            } catch {
                return
            }
            guard !Task.isCancelled else { return }
            refresh()
        }
    }
}

nonisolated enum MenuBarApprovalPreviewTiming {
    static let presentationDelay: TimeInterval = 0.15
}

@MainActor
enum MenuBarApprovalPreviewPresenter {
    static func hideMenuBarWindowBeforePreview(_ window: NSWindow?) {
        ApprovalPreviewWindowHider.hideHostWindowsBeforePreview(primary: window)
    }
}

@MainActor
protocol MenuBarLockdownManaging: AnyObject {
    func setPaused(_ paused: Bool, reason: String?) async -> Bool
    func enterLockdown(reason: String) async -> Bool
    func leaveLockdown() async -> Bool
    func residualSurface() -> LockdownManager.ResidualSurface
}

extension LockdownManager: MenuBarLockdownManaging {}

nonisolated struct MenuBarStatusActionOutcome: Equatable, Sendable {
    let errorMessage: String?
}

nonisolated struct MenuBarLockdownPresentation: Equatable, Sendable {
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

    static func make(
        reason: String?,
        installedValidators: Int,
        activeSessions: Int
    ) -> MenuBarLockdownPresentation {
        MenuBarLockdownPresentation(
            title: "Lockdown active",
            subtitle: reason ?? "All signing rejected",
            detail: "New requests are denied. Validators left installed on-chain remain part of the attack surface — uninstall to fully revoke.",
            installedValidators: installedValidators,
            installedValidatorsWarn: installedValidators > 0,
            installedValidatorsLabel: "validators on-chain",
            activeSessions: activeSessions,
            activeSessionsWarn: activeSessions > 0,
            activeSessionsLabel: "active sessions",
            leaveButtonTitle: "Leave lockdown"
        )
    }
}

nonisolated struct MenuBarStatTilePresentation: Equatable, Sendable {
    let value: Int
    let label: String
    let warn: Bool
}

nonisolated struct MenuBarStatsPresentation: Equatable, Sendable {
    let tiles: [MenuBarStatTilePresentation]

    static func make(totalToday: Int, silentToday: Int, overridesToday: Int) -> MenuBarStatsPresentation {
        MenuBarStatsPresentation(tiles: [
            MenuBarStatTilePresentation(value: totalToday, label: "signed today", warn: false),
            MenuBarStatTilePresentation(value: silentToday, label: "silent", warn: false),
            MenuBarStatTilePresentation(value: overridesToday, label: "overrides", warn: overridesToday > 0),
        ])
    }
}

nonisolated struct MenuBarPendingSubmissionsPresentation: Equatable, Sendable {
    let sectionTitle: String
    let auditButtonTitle: String
    let rows: [MenuBarPendingSubmissionRowPresentation]

    static func make(_ statuses: [PendingUserOperationStatus]) -> MenuBarPendingSubmissionsPresentation {
        MenuBarPendingSubmissionsPresentation(
            sectionTitle: "Pending confirmations",
            auditButtonTitle: "Audit",
            rows: statuses.map(MenuBarPendingSubmissionRowPresentation.make)
        )
    }
}

nonisolated struct MenuBarPendingSubmissionRowPresentation: Identifiable, Equatable, Sendable {
    let id: String
    let clientDisplayName: String
    let provider: String
    let chainId: Int
    let statusLabel: String
    let submittedAt: Date
    let userOpHash: String
    let userOpHashShort: String
    let rowHelp: String

    static func make(_ status: PendingUserOperationStatus) -> MenuBarPendingSubmissionRowPresentation {
        MenuBarPendingSubmissionRowPresentation(
            id: status.id,
            clientDisplayName: status.clientDisplayName,
            provider: status.provider,
            chainId: status.chainId,
            statusLabel: "Awaiting receipt",
            submittedAt: status.submittedAt,
            userOpHash: status.userOpHash,
            userOpHashShort: BastionFormat.shortHex(status.userOpHash, head: 8, tail: 6),
            rowHelp: "Client: \(status.clientDisplayName)\nProvider: \(status.provider)\nChain: \(status.chainId)\nUserOperation: \(status.userOpHash)"
        )
    }
}

nonisolated enum MenuBarRecentActivityDot: Equatable, Sendable {
    case ok
    case bad
    case warn
    case idle
}

nonisolated struct MenuBarRecentActivityPresentation: Equatable, Sendable {
    let sectionTitle: String
    let viewAllButtonTitle: String
    let emptyMessage: String
    let rows: [MenuBarRecentActivityRowPresentation]

    static func make(records: [AuditRequestRecord], limit: Int = 3) -> MenuBarRecentActivityPresentation {
        MenuBarRecentActivityPresentation(
            sectionTitle: "Recent activity",
            viewAllButtonTitle: "View all",
            emptyMessage: "No recent activity",
            rows: records.prefix(limit).map(MenuBarRecentActivityRowPresentation.make)
        )
    }
}

nonisolated struct MenuBarRecentActivityRowPresentation: Identifiable, Equatable, Sendable {
    let id: String
    let title: String
    let client: String
    let timestamp: Date?
    let mode: RequestExecutionMode
    let dot: MenuBarRecentActivityDot
    let trailingTag: String?
    let trailingTagDot: MenuBarRecentActivityDot
    let rowHelp: String

    static func make(_ record: AuditRequestRecord) -> MenuBarRecentActivityRowPresentation {
        let title = record.request?.title ?? record.latestEvent?.operationTitle ?? "Signing request"
        let summary = record.request?.summary ?? ""
        let displayTitle = summary.isEmpty ? title : "\(title) · \(summary)"
        let client = record.clientDisplayName
        let mode = record.executionMode
        let tag = trailingTag(for: record.latestEvent?.approvalMode)
        return MenuBarRecentActivityRowPresentation(
            id: record.id,
            title: displayTitle,
            client: client,
            timestamp: record.latestTimestamp,
            mode: mode,
            dot: dot(for: record.latestEvent?.type),
            trailingTag: tag,
            trailingTagDot: trailingTagDot(for: record.latestEvent?.approvalMode),
            rowHelp: Self.rowHelp(title: displayTitle, client: client, mode: mode, tag: tag)
        )
    }

    private static func rowHelp(
        title: String,
        client: String,
        mode: RequestExecutionMode,
        tag: String?
    ) -> String {
        var lines = [
            "Activity: \(title)",
            "Client: \(client)",
            "Mode: \(mode.label)",
        ]
        if let tag {
            lines.append("Tag: \(tag)")
        }
        return lines.joined(separator: "\n")
    }

    private static func dot(for eventType: AuditEvent.EventType?) -> MenuBarRecentActivityDot {
        switch eventType {
        case .signSuccess, .userOpReceiptSuccess, .userOpSubmitted, .preflightCompleted:
            return .ok
        case .signDenied, .ruleViolation, .authFailed, .userOpSendFailed, .userOpReceiptFailed:
            return .bad
        case .userOpReceiptTimeout, .signPending:
            return .warn
        default:
            return .idle
        }
    }

    private static func trailingTag(for approvalMode: AuditEvent.ApprovalMode?) -> String? {
        switch approvalMode {
        case .ruleOverride:
            return "override"
        case .auto:
            return "silent"
        default:
            return nil
        }
    }

    private static func trailingTagDot(for approvalMode: AuditEvent.ApprovalMode?) -> MenuBarRecentActivityDot {
        switch approvalMode {
        case .ruleOverride:
            return .warn
        case .auto:
            return .idle
        default:
            return .idle
        }
    }
}

struct MenuBarStatusActionController {
    let lockdownManager: any MenuBarLockdownManaging

    @MainActor
    init() {
        self.init(lockdownManager: LockdownManager.shared)
    }

    @MainActor
    init(lockdownManager: any MenuBarLockdownManaging) {
        self.lockdownManager = lockdownManager
    }

    @MainActor
    func togglePause(current pauseState: PauseState) async -> MenuBarStatusActionOutcome {
        let targetPaused = !pauseState.paused
        let ok = await lockdownManager.setPaused(targetPaused, reason: nil)
        return MenuBarStatusActionOutcome(errorMessage: Self.pauseFailureMessage(pausing: targetPaused, succeeded: ok))
    }

    @MainActor
    func resumeSigning() async -> MenuBarStatusActionOutcome {
        let ok = await lockdownManager.setPaused(false, reason: nil)
        return MenuBarStatusActionOutcome(errorMessage: Self.resumeFailureMessage(succeeded: ok))
    }

    @MainActor
    func enterLockdown(reason: String) async -> MenuBarStatusActionOutcome {
        let ok = await lockdownManager.enterLockdown(reason: reason)
        return MenuBarStatusActionOutcome(errorMessage: ok ? nil : "Lockdown is active in memory, but some lockdown state or session revocation could not be saved.")
    }

    @MainActor
    func leaveLockdown() async -> MenuBarStatusActionOutcome {
        let ok = await lockdownManager.leaveLockdown()
        return MenuBarStatusActionOutcome(errorMessage: ok ? nil : "Could not fully leave lockdown. Authentication may have been cancelled or the updated state could not be saved.")
    }

    nonisolated static func pauseFailureMessage(pausing: Bool, succeeded: Bool) -> String? {
        guard !succeeded else { return nil }
        return pausing
            ? "Pause is active in memory, but the paused state could not be saved."
            : "Could not fully resume signing. Authentication may have been cancelled or the updated state could not be saved."
    }

    nonisolated static func resumeFailureMessage(succeeded: Bool) -> String? {
        succeeded ? nil : "Could not fully resume signing. Authentication may have been cancelled or the updated state could not be saved."
    }
}

struct MenuBarPanelView: View {
    private let lockdownManager: any MenuBarLockdownManaging
    private let statusActions: MenuBarStatusActionController

    @MainActor
    init() {
        self.init(lockdownManager: LockdownManager.shared)
    }

    @MainActor
    init(lockdownManager: any MenuBarLockdownManaging) {
        self.lockdownManager = lockdownManager
        self.statusActions = MenuBarStatusActionController(lockdownManager: lockdownManager)
    }

    @Environment(\.openSettings) private var openSettings
    @Environment(\.dismiss) private var dismissMenuBarPanel

    // Cache the snapshot in @State so body doesn't perform I/O (audit log
    // reads) or mutate Observable state on every redraw. Refresh happens
    // exclusively via the .task loop below — this keeps the panel snappy
    // and avoids the layout-animation feedback loop that made the popover
    // slide out continuously.
    @State private var snapshot: Snapshot = .empty
    @State private var activeSessions: [AgentSession] = []
    @State private var pauseStateCached: PauseState = .default
    @State private var pendingPairings: [PendingPairingRequest] = []
    @State private var pendingSubmissions: [PendingUserOperationStatus] = []
    @State private var pendingPairingError: String? = nil
    @State private var statusActionError: String? = nil

    var body: some View {
        let status = MenuBarStatusPresentation.make(
            armed: snapshot.armed,
            activeClients: snapshot.activeClients,
            pauseState: pauseStateCached
        )

        return VStack(spacing: 0) {
            // Pending pair requests jump to the top — confirming or rejecting
            // them is time-sensitive (CLI process is blocked polling for the
            // outcome). Rendered inline rather than a sheet so the menu bar
            // popover stays snappy.
            if !pendingPairings.isEmpty {
                pendingPairingsBlock
                BastionDivider()
            }
            if let statusActionError {
                menuErrorBanner(statusActionError)
                BastionDivider()
            }
            if status.mode == .lockedDown {
                lockdownState(snapshot: snapshot, reason: pauseStateCached.reason)
                BastionDivider()
                footer
            } else if status.mode == .paused {
                pausedState(snapshot: snapshot)
                BastionDivider()
                footer
            } else if status.mode == .empty {
                emptyState(snapshot: snapshot)
                BastionDivider()
                footer
            } else {
                header(snapshot: snapshot, presentation: status)
                if status.showsPolicyStatusWarning {
                    BastionDivider()
                    rpcErrorBanner(snapshot: snapshot)
                }
                BastionDivider()
                statsGrid(snapshot: snapshot)
                if !activeSessions.isEmpty {
                    BastionDivider()
                    activeSessionsBlock
                }
                if !pendingSubmissions.isEmpty {
                    BastionDivider()
                    pendingSubmissionsBlock
                }
                BastionDivider()
                recentActivity(snapshot: snapshot)
                BastionDivider()
                footer
            }
        }
        .frame(width: 340)
        // Note: the surrounding rounded background / clipShape were dropped
        // intentionally — MenuBarExtra(.window) already paints its own
        // popover chrome and the inner clipShape was causing AppKit to
        // animate every frame as it tried to reconcile two clip layers.
        .task {
            // Initial paint, then refresh on a slow cadence. SwiftUI cancels
            // this task automatically when the panel closes. Pending
            // pairings refresh on a tighter cadence so a pair request
            // surfaces within ~1 second of the CLI calling startPairing.
            await MenuBarPanelRefreshScheduler.run {
                refresh()
            }
        }
    }

    private func refresh() {
        snapshot = Self.computeSnapshot()
        // Filter expired sessions WITHOUT mutating the store from inside
        // body. Cleanup happens lazily on grant/revoke; here we just hide
        // expired entries from the UI so render is purely read-only.
        let now = Date()
        activeSessions = SessionStore.shared.sessions.filter { $0.expiresAt > now }
        pauseStateCached = RuleEngine.shared.config.pauseState
        pendingPairings = PendingPairingPromptPresentation.visibleRequests(PairingBroker.shared.pending, now: now)
        pendingSubmissions = SubmissionStatusStore.shared.active()
    }

    // MARK: - Pending pairings

    @ViewBuilder
    private var pendingPairingsBlock: some View {
        let presentation = PendingPairingPromptPresentation.make(errorMessage: pendingPairingError)
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                ShieldGlyph(size: 13, color: .bastionAccentDeep)
                BastionSectionLabel(text: presentation.title)
            }
            if let errorMessage = presentation.errorMessage {
                Text(errorMessage)
                    .font(.system(size: 11.5, weight: .medium))
                    .foregroundStyle(Color.bastionBad)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ForEach(pendingPairings) { request in
                PendingPairingRow(presentation: .make(request)) {
                    Task { await accept(request) }
                } onReject: {
                    pendingPairingError = nil
                    PairingBroker.shared.reject(request)
                    refresh()
                }
            }
        }
        .padding(EdgeInsets(top: 12, leading: 14, bottom: 12, trailing: 14))
        .background(Color.bastionAccentSoft.opacity(0.45))
    }

    private func accept(_ request: PendingPairingRequest) async {
        // Default to the verified requester display name plus global default
        // rules. Future: launch the 4-step flow with the live request, but
        // inline accept is the fast path that lets the CLI return without the
        // operator clicking through 4 screens.
        do {
            try await PairingBroker.shared.accept(request, label: request.defaultProfileLabel, template: nil)
            pendingPairingError = nil
        } catch {
            pendingPairingError = "Pairing failed: \(error.localizedDescription)"
            NSLog("[Bastion] Pair accept failed: %@", String(describing: error))
        }
        refresh()
    }


    // MARK: - Header

    @ViewBuilder
    private func header(snapshot: Snapshot, presentation: MenuBarStatusPresentation) -> some View {
        HStack(spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 7).fill(Color.ink900)
                // .paper instead of .white — ink900 inverts to off-white
                // in dark mode, and a literal-white glyph on a near-white
                // fill is invisible. paper inverts inversely so contrast
                // holds in both themes.
                ShieldGlyph(size: 15, color: .paper)
            }
            .frame(width: 28, height: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text("Bastion")
                    .font(.system(size: 13, weight: .semibold))
                    .kerning(-0.13)
                HStack(spacing: 5) {
                    // Static dot only — PulseDot's repeatForever animation
                    // told AppKit the popover was still in motion, which
                    // caused the dropdown to slide endlessly.
                    Circle()
                        .fill(snapshot.armed ? Color.bastionOk : Color.ink300)
                        .frame(width: 6, height: 6)
                    Text(presentation.subtitle)
                        .font(.system(size: 11))
                        .foregroundStyle(Color.ink500)
                }
            }
            Spacer()
            Button {
                Task { @MainActor in await togglePause() }
            } label: {
                Text(presentation.pauseButtonTitle ?? "Pause")
                    .font(.system(size: 11))
                    .padding(.horizontal, 8).padding(.vertical, 4)
            }
            .bastionButton(.ghost, size: .small)
            .help("Pause all signing")
        }
        .padding(EdgeInsets(top: 14, leading: 16, bottom: 14, trailing: 12))
        .background(Color.ink50)
    }

    // MARK: - Empty / paused / error states

    @ViewBuilder
    private func emptyState(snapshot: Snapshot) -> some View {
        VStack(spacing: 0) {
            compactHeader(title: "Bastion", subtitle: "Idle · no agents paired", iconColor: .ink900, dot: .idle)
            VStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 10)
                        .fill(Color.ink100)
                    ShieldGlyph(size: 20, color: .ink500)
                }
                .frame(width: 44, height: 44)

                VStack(spacing: 4) {
                    Text("No agents paired")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(Color.ink900)
                    Text("Run bastion pair in a terminal, or open Settings to create the first client policy.")
                        .font(.system(size: 12))
                        .foregroundStyle(Color.ink500)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Button {
                    openSettings()
                    NSApp.activate(ignoringOtherApps: true)
                } label: {
                    Text("Pair an agent")
                }
                .bastionButton(.primary, size: .small)
            }
            .padding(EdgeInsets(top: 22, leading: 22, bottom: 22, trailing: 22))
        }
    }

    @ViewBuilder
    private func pausedState(snapshot: Snapshot) -> some View {
        VStack(spacing: 0) {
            compactHeader(title: "Bastion paused", subtitle: "Approval UI is in review-only mode", iconColor: .bastionWarn, dot: .warn, pausedIcon: true)
            VStack(alignment: .leading, spacing: 10) {
                Text("Use this state when stepping away from active agent work. Existing requests remain visible in Audit History.")
                    .font(.system(size: 12))
                    .foregroundStyle(Color.ink500)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: 8) {
                    StatTile(value: snapshot.totalToday, label: "today")
                    StatTile(value: snapshot.overridesToday, label: "overrides", warn: snapshot.overridesToday > 0)
                }

                Button {
                    Task { @MainActor in await resumeSigning() }
                } label: {
                    Text("Resume signing").frame(maxWidth: .infinity)
                }
                .bastionButton(.primary, size: .small)
            }
            .padding(EdgeInsets(top: 12, leading: 16, bottom: 14, trailing: 16))
        }
    }

    @ViewBuilder
    private func lockdownState(snapshot: Snapshot, reason: String?) -> some View {
        let surface = lockdownManager.residualSurface()
        let presentation = MenuBarLockdownPresentation.make(
            reason: reason,
            installedValidators: surface.installedValidators,
            activeSessions: surface.activeSessions
        )
        VStack(spacing: 0) {
            compactHeader(title: presentation.title, subtitle: presentation.subtitle, iconColor: .bastionBad, dot: .bad, pausedIcon: true)
            VStack(alignment: .leading, spacing: 12) {
                Text(presentation.detail)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.ink500)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: 8) {
                    StatTile(value: presentation.installedValidators, label: presentation.installedValidatorsLabel, warn: presentation.installedValidatorsWarn)
                    StatTile(value: presentation.activeSessions, label: presentation.activeSessionsLabel, warn: presentation.activeSessionsWarn)
                }

                Button {
                    Task { @MainActor in await leaveLockdown() }
                } label: {
                    Text(presentation.leaveButtonTitle).frame(maxWidth: .infinity)
                }
                .bastionButton(.danger, size: .small)
            }
            .padding(EdgeInsets(top: 12, leading: 16, bottom: 14, trailing: 16))
        }
    }

    @ViewBuilder
    private func rpcErrorBanner(snapshot: Snapshot) -> some View {
        HStack(alignment: .top, spacing: 10) {
            CloseGlyph(size: 12, color: .bastionBad)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 3) {
                Text("Policy status needs attention")
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundStyle(Color.bastionBad)
                Text(snapshot.armedSubtitle)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.bastionBad.opacity(0.85))
                    .fixedSize(horizontal: false, vertical: true)
                Button {
                    openSettings()
                    NSApp.activate(ignoringOtherApps: true)
                } label: {
                    Text("Open settings")
                }
                .bastionButton(.default, size: .small)
                .padding(.top, 5)
            }
            Spacer(minLength: 0)
        }
        .padding(.m)
        .background(Color.bastionBadSoft)
    }

    private func menuErrorBanner(_ message: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Color.bastionBad)
                .padding(.top, 1)
            Text(message)
                .font(.system(size: 11.5, weight: .medium))
                .foregroundStyle(Color.bastionBad)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            Button("Dismiss") {
                statusActionError = nil
            }
            .bastionButton(.ghost, size: .small)
        }
        .padding(.m)
        .background(Color.bastionBadSoft)
    }

    private func compactHeader(title: String, subtitle: String, iconColor: Color, dot: StatusDot.State, pausedIcon: Bool = false) -> some View {
        HStack(spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 7)
                    .fill(iconColor)
                if pausedIcon {
                    Image(systemName: "pause.fill")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundStyle(Color.paper)
                } else {
                    // .paper for the same dark-mode reason as the idle
                    // header above — paused/lockdown branches already use
                    // Color.paper for consistency.
                    ShieldGlyph(size: 15, color: .paper, filled: true)
                }
            }
            .frame(width: 28, height: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Color.ink900)
                HStack(spacing: 6) {
                    StatusDot(state: dot)
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundStyle(Color.ink500)
                }
            }
            Spacer()
        }
        .padding(EdgeInsets(top: 14, leading: 16, bottom: 14, trailing: 16))
        .background(Color.ink50)
    }

    // MARK: - Stats grid

    @ViewBuilder
    private func statsGrid(snapshot: Snapshot) -> some View {
        let presentation = MenuBarStatsPresentation.make(
            totalToday: snapshot.totalToday,
            silentToday: snapshot.silentToday,
            overridesToday: snapshot.overridesToday
        )
        HStack(spacing: 8) {
            ForEach(Array(presentation.tiles.enumerated()), id: \.offset) { _, tile in
                StatTile(value: tile.value, label: tile.label, warn: tile.warn)
            }
        }
        .padding(EdgeInsets(top: 12, leading: 16, bottom: 12, trailing: 16))
    }

    // MARK: - Recent activity

    @ViewBuilder
    private func recentActivity(snapshot: Snapshot) -> some View {
        let presentation = MenuBarRecentActivityPresentation(
            sectionTitle: "Recent activity",
            viewAllButtonTitle: "View all",
            emptyMessage: "No recent activity",
            rows: snapshot.recent
        )
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                BastionSectionLabel(text: presentation.sectionTitle)
                Spacer()
                Button {
                    AuditHistoryWindowManager.shared.showWindow()
                } label: {
                    Text(presentation.viewAllButtonTitle).font(.system(size: 10)).padding(.horizontal, 6).padding(.vertical, 2)
                }
                .bastionButton(.ghost, size: .small)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)

            if presentation.rows.isEmpty {
                Text(presentation.emptyMessage)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.ink500)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 14)
            } else {
                ForEach(presentation.rows) { row in
                    RecentRow(presentation: row)
                }
                .padding(.horizontal, 8)
            }
        }
        .padding(.vertical, 6)
    }

    // MARK: - Active sessions

    @ViewBuilder
    private var activeSessionsBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                BastionSectionLabel(text: "Active sessions")
                Spacer()
                Button {
                    GrantSessionWindowManager.shared.showWindow()
                } label: {
                    Text("Grant…").font(.system(size: 10))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                }
                .bastionButton(.ghost, size: .small)
            }
            // Use the @State-cached list — calling sessionStore.active()
            // here would mutate Observable state during render, which is
            // what produced the slide-out feedback loop.
            ForEach(activeSessions) { session in
                ActiveSessionRow(store: SessionStore.shared, session: session)
            }
        }
        .padding(EdgeInsets(top: 10, leading: 12, bottom: 10, trailing: 12))
    }

    // MARK: - Pending submissions

    @ViewBuilder
    private var pendingSubmissionsBlock: some View {
        let presentation = MenuBarPendingSubmissionsPresentation.make(pendingSubmissions)
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                BastionSectionLabel(text: presentation.sectionTitle)
                Spacer()
                Button {
                    AuditHistoryWindowManager.shared.showWindow()
                } label: {
                    Text(presentation.auditButtonTitle).font(.system(size: 10))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                }
                .bastionButton(.ghost, size: .small)
            }
            ForEach(presentation.rows) { status in
                PendingSubmissionRow(presentation: status)
            }
        }
        .padding(EdgeInsets(top: 10, leading: 12, bottom: 10, trailing: 12))
        .background(Color.bastionWarnSoft.opacity(0.5))
    }

    // MARK: - Footer

    @ViewBuilder
    private var footer: some View {
        VStack(spacing: 1) {
            MenuRow(label: "Grant temporary session…", shortcut: nil) {
                GrantSessionWindowManager.shared.showWindow()
            }
            MenuRow(label: "Emergency lockdown", shortcut: "⌘⇧L") {
                Task { @MainActor in await enterLockdown() }
            }
            MenuRow(label: "Settings…", shortcut: "⌘,") {
                openSettings()
                NSApp.activate(ignoringOtherApps: true)
            }
            MenuRow(label: "Audit History…", shortcut: "⌘⇧H") {
                AuditHistoryWindowManager.shared.showWindow()
            }
            MenuRow(label: "Diagnostics…", shortcut: nil) {
                DiagnosticsWindowManager.shared.showWindow()
            }
            #if DEBUG && !BASTION_HELPER
            Menu {
                Button("Policy Review Sample") {
                    showApprovalPreview(SigningRequestPreviewFactory.policyReview())
                }
                Button("Rule Override Sample") {
                    showApprovalPreview(SigningRequestPreviewFactory.ruleOverride())
                }
            } label: {
                HStack {
                    Text("Preview Approval UI")
                        .font(.system(size: 13))
                        .foregroundStyle(Color.ink900)
                    Spacer()
                    ChevronRightGlyph(size: 11)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
            }
            .buttonStyle(.plain)
            .menuStyle(.borderlessButton)
            #endif
            Rectangle().fill(Color.ink150).frame(height: 1).padding(.horizontal, 6).padding(.vertical, 4)
            MenuRow(label: "Quit Bastion", shortcut: "⌘Q", muted: true) {
                quitBastion()
            }
        }
        .padding(.s)
    }

    #if DEBUG && !BASTION_HELPER
    @MainActor
    private func showApprovalPreview(_ approval: ApprovalRequest) {
        let menuBarWindow = NSApp.keyWindow
        dismissMenuBarPanel()
        MenuBarApprovalPreviewPresenter.hideMenuBarWindowBeforePreview(menuBarWindow)
        DispatchQueue.main.asyncAfter(deadline: .now() + MenuBarApprovalPreviewTiming.presentationDelay) {
            SigningRequestPanelManager.shared.showRequest(
                approval,
                onApprove: {},
                onDeny: {}
            )
        }
    }
    #endif

    @MainActor
    private func togglePause() async {
        let outcome = await statusActions.togglePause(current: pauseStateCached)
        statusActionError = outcome.errorMessage
        refresh()
    }

    @MainActor
    private func resumeSigning() async {
        let outcome = await statusActions.resumeSigning()
        statusActionError = outcome.errorMessage
        refresh()
    }

    @MainActor
    private func enterLockdown() async {
        let outcome = await statusActions.enterLockdown(reason: "Emergency lockdown triggered from menu bar")
        statusActionError = outcome.errorMessage
        refresh()
    }

    @MainActor
    private func leaveLockdown() async {
        let outcome = await statusActions.leaveLockdown()
        statusActionError = outcome.errorMessage
        refresh()
    }

    @MainActor
    private func quitBastion() {
        BastionUserQuitController.requestQuit { message in
            statusActionError = message
        }
    }

    // MARK: - Snapshot

    private struct Snapshot {
        var armed: Bool
        var armedSubtitle: String
        var activeClients: Int
        var totalToday: Int
        var silentToday: Int
        var overridesToday: Int
        var recent: [MenuBarRecentActivityRowPresentation]

        static let empty = Snapshot(
            armed: true,
            armedSubtitle: "",
            activeClients: 0,
            totalToday: 0,
            silentToday: 0,
            overridesToday: 0,
            recent: []
        )
    }

    private static func computeSnapshot() -> Snapshot {
        let activeClients = RuleEngine.shared.config.clientProfiles.count
        let totalToday = AuditLog.shared.totalCountToday(type: .signSuccess)
        let recent = MenuBarRecentActivityPresentation.make(
            records: AuditLog.shared.recentRequestRecords(limit: 3)
        ).rows

        let armed = !RuleEngine.shared.configCorrupted
        let subtitle = MenuBarStatusPresentation.armedSubtitle(armed: armed, activeClients: activeClients)

        let silentToday = AuditLog.shared.totalCountToday(approvalMode: .auto)
        let overridesToday = AuditLog.shared.totalCountToday(approvalMode: .ruleOverride)

        return Snapshot(
            armed: armed,
            armedSubtitle: subtitle,
            activeClients: activeClients,
            totalToday: totalToday,
            silentToday: silentToday,
            overridesToday: overridesToday,
            recent: recent
        )
    }
}

// MARK: - Stat tile

private struct PendingPairingRow: View {
    let presentation: PendingPairingRequestPresentation
    let onAccept: () -> Void
    let onReject: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top, spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(presentation.processName)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Color.ink900)
                        .lineLimit(1)
                    Text(presentation.bundleId)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Color.ink500)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
            }
            HStack {
                BastionSectionLabel(text: "Code")
                Text(presentation.pairingCode)
                    .font(.system(size: 14, weight: .semibold, design: .monospaced))
                    .tracking(1.2)
                    .foregroundStyle(Color.ink900)
            }
            HStack(spacing: 8) {
                Button(presentation.rejectButtonTitle, action: onReject)
                    .bastionButton(.ghost, size: .small)
                Spacer()
                Button(presentation.acceptButtonTitle) { onAccept() }
                    .bastionButton(.primary, size: .small)
            }
        }
        .padding(EdgeInsets(top: 10, leading: 12, bottom: 10, trailing: 12))
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.paper)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(Color.bastionAccent.opacity(0.4), lineWidth: 1)
                )
        )
        .help(presentation.rowHelp)
    }
}

private struct PendingSubmissionRow: View {
    let presentation: MenuBarPendingSubmissionRowPresentation

    var body: some View {
        HStack(alignment: .top, spacing: 9) {
            StatusDot(state: .warn)
                .padding(.top, 4)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(presentation.clientDisplayName)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Color.ink900)
                        .lineLimit(1)
                    Spacer(minLength: 8)
                    ChainBadge(chainId: presentation.chainId, size: .small)
                }
                HStack(spacing: 5) {
                    Text(presentation.statusLabel)
                        .foregroundStyle(Color.bastionWarn)
                    Text("·")
                    Text(presentation.provider)
                    Text("·")
                    Text(BastionFormat.relative(presentation.submittedAt))
                }
                .font(.system(size: 11))
                .foregroundStyle(Color.ink500)
                Text(presentation.userOpHashShort)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Color.ink700)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(EdgeInsets(top: 9, leading: 10, bottom: 9, trailing: 10))
        .background(
            RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                .fill(Color.paper)
                .overlay(
                    RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                        .strokeBorder(Color.bastionWarn.opacity(0.25), lineWidth: 1)
                )
        )
        .help(presentation.rowHelp)
    }
}

private struct StatTile: View {
    let value: Int
    let label: String
    var warn: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text("\(value)")
                .font(.system(size: 18, weight: .semibold, design: .monospaced))
                .kerning(-0.36)
                .foregroundStyle(warn ? Color.bastionWarn : Color.ink900)
            Text(label)
                .font(.system(size: 10.5))
                .foregroundStyle(Color.ink500)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(EdgeInsets(top: 8, leading: 10, bottom: 8, trailing: 10))
        .background(
            RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                .fill(Color.ink50)
                .overlay(
                    RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                        .strokeBorder(Color.ink150, lineWidth: 1)
                )
        )
    }
}

// MARK: - Recent activity row

private struct RecentRow: View {
    let presentation: MenuBarRecentActivityRowPresentation
    @State private var hovered: Bool = false

    var body: some View {
        HStack(spacing: 10) {
            Circle().fill(color(for: presentation.dot)).frame(width: 6, height: 6)
            VStack(alignment: .leading, spacing: 1) {
                Text(presentation.title)
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundStyle(Color.ink900)
                    .lineLimit(1)
                    .truncationMode(.tail)
                HStack(spacing: 5) {
                    Text(presentation.client)
                    Text("·")
                    Text(BastionFormat.relative(presentation.timestamp))
                    Text("·")
                    Text(presentation.mode.label)
                        .foregroundStyle(presentation.mode == .approveAndSend ? Color.bastionAccentDeep : Color.ink400)
                    if let tag = presentation.trailingTag {
                        Text("·")
                        Text(tag).foregroundStyle(color(for: presentation.trailingTagDot))
                    }
                }
                .font(.system(size: 11))
                .foregroundStyle(Color.ink500)
            }
            Spacer(minLength: 0)
            ChevronRightGlyph(size: 11)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 7)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(hovered ? Color.ink50 : .clear)
        )
        .contentShape(Rectangle())
        .onHover { hovered = $0 }
        .help(presentation.rowHelp)
    }

    private func color(for dot: MenuBarRecentActivityDot) -> Color {
        switch dot {
        case .ok:
            return .bastionOk
        case .bad:
            return .bastionBad
        case .warn:
            return .bastionWarn
        case .idle:
            return .ink400
        }
    }
}

// MARK: - Footer menu row

private struct MenuRow: View {
    let label: String
    var shortcut: String? = nil
    var muted: Bool = false
    let action: () -> Void

    @State private var hovered: Bool = false

    var body: some View {
        Button(action: action) {
            HStack {
                Text(label)
                    .font(.system(size: 13))
                    .foregroundStyle(muted ? Color.ink500 : Color.ink900)
                Spacer()
                if let shortcut {
                    Text(shortcut)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Color.ink400)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(hovered ? Color.ink100 : .clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovered = $0 }
    }
}
