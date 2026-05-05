import AppKit
import Combine
import SwiftUI

// Redesigned menu bar dropdown — calm 340pt status panel.
// Renders inside MenuBarExtra(style: .window).

struct MenuBarPanelView: View {
    @Environment(\.openSettings) private var openSettings

    // Cache the snapshot in @State so body doesn't perform I/O (audit log
    // reads) or mutate Observable state on every redraw. Refresh happens
    // exclusively via the .task loop below — this keeps the panel snappy
    // and avoids the layout-animation feedback loop that made the popover
    // slide out continuously.
    @State private var snapshot: Snapshot = .empty
    @State private var activeSessions: [AgentSession] = []
    @State private var pauseStateCached: PauseState = .default
    @State private var pendingPairings: [PendingPairingRequest] = []

    var body: some View {
        VStack(spacing: 0) {
            // Pending pair requests jump to the top — confirming or rejecting
            // them is time-sensitive (CLI process is blocked polling for the
            // outcome). Rendered inline rather than a sheet so the menu bar
            // popover stays snappy.
            if !pendingPairings.isEmpty {
                pendingPairingsBlock
                BastionDivider()
            }
            if pauseStateCached.lockedDown {
                lockdownState(snapshot: snapshot, reason: pauseStateCached.reason)
                BastionDivider()
                footer
            } else if pauseStateCached.paused {
                pausedState(snapshot: snapshot)
                BastionDivider()
                footer
            } else if snapshot.activeClients == 0 {
                emptyState(snapshot: snapshot)
                BastionDivider()
                footer
            } else {
                header(snapshot: snapshot)
                if !snapshot.armed {
                    BastionDivider()
                    rpcErrorBanner(snapshot: snapshot)
                }
                BastionDivider()
                statsGrid(snapshot: snapshot)
                if !activeSessions.isEmpty {
                    BastionDivider()
                    activeSessionsBlock
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
            refresh()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
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
        pendingPairings = PairingBroker.shared.pending.filter { $0.expiresAt > now }
    }

    // MARK: - Pending pairings

    @ViewBuilder
    private var pendingPairingsBlock: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                ShieldGlyph(size: 13, color: .bastionAccentDeep)
                LabelXS(text: "Incoming pair request")
            }
            ForEach(pendingPairings) { request in
                PendingPairingRow(request: request) {
                    Task { await accept(request) }
                } onReject: {
                    PairingBroker.shared.reject(request)
                    refresh()
                }
            }
        }
        .padding(EdgeInsets(top: 12, leading: 14, bottom: 12, trailing: 14))
        .background(Color.bastionAccentSoft.opacity(0.45))
    }

    private func accept(_ request: PendingPairingRequest) async {
        // Default to no template / no custom label — that creates a profile
        // with the global default rules. Future: launch the 4-step flow with
        // the live request, but inline accept is the fast path that lets the
        // CLI return without the operator clicking through 4 screens.
        do {
            try await PairingBroker.shared.accept(request, label: nil, template: nil)
        } catch {
            NSLog("[Bastion] Pair accept failed: %@", String(describing: error))
        }
        refresh()
    }


    // MARK: - Header

    @ViewBuilder
    private func header(snapshot: Snapshot) -> some View {
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
                    Text(snapshot.armedSubtitle)
                        .font(.system(size: 11))
                        .foregroundStyle(Color.ink500)
                }
            }
            Spacer()
            Button {
                Task { @MainActor in
                    let isPausedNow = pauseStateCached.paused
                    await LockdownManager.shared.setPaused(!isPausedNow)
                    refresh()
                }
            } label: {
                Text(pauseStateCached.paused ? "Resume" : "Pause")
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
                    Task { @MainActor in
                        await LockdownManager.shared.setPaused(false)
                        refresh()
                    }
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
        let surface = LockdownManager.shared.residualSurface()
        VStack(spacing: 0) {
            compactHeader(title: "Lockdown active", subtitle: reason ?? "All signing rejected", iconColor: .bastionBad, dot: .bad, pausedIcon: true)
            VStack(alignment: .leading, spacing: 12) {
                Text("New requests are denied. Validators left installed on-chain remain part of the attack surface — uninstall to fully revoke.")
                    .font(.system(size: 12))
                    .foregroundStyle(Color.ink500)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: 8) {
                    StatTile(value: surface.installedValidators, label: "validators on-chain", warn: surface.installedValidators > 0)
                    StatTile(value: surface.activeSessions, label: "active sessions", warn: surface.activeSessions > 0)
                }

                Button {
                    Task { @MainActor in
                        await LockdownManager.shared.leaveLockdown()
                        refresh()
                    }
                } label: {
                    Text("Leave lockdown").frame(maxWidth: .infinity)
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
        .padding(12)
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
        HStack(spacing: 8) {
            StatTile(value: snapshot.totalToday, label: "signed today")
            StatTile(value: snapshot.silentToday, label: "silent")
            StatTile(value: snapshot.overridesToday, label: "overrides", warn: snapshot.overridesToday > 0)
        }
        .padding(EdgeInsets(top: 12, leading: 16, bottom: 12, trailing: 16))
    }

    // MARK: - Recent activity

    @ViewBuilder
    private func recentActivity(snapshot: Snapshot) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                LabelXS(text: "Recent activity")
                Spacer()
                Button {
                    AuditHistoryWindowManager.shared.showWindow()
                } label: {
                    Text("View all").font(.system(size: 10)).padding(.horizontal, 6).padding(.vertical, 2)
                }
                .bastionButton(.ghost, size: .small)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)

            if snapshot.recent.isEmpty {
                Text("No recent activity")
                    .font(.system(size: 12))
                    .foregroundStyle(Color.ink500)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 14)
            } else {
                ForEach(snapshot.recent) { row in
                    RecentRow(row: row)
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
                LabelXS(text: "Active sessions")
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

    // MARK: - Footer

    @ViewBuilder
    private var footer: some View {
        VStack(spacing: 1) {
            MenuRow(label: "Grant temporary session…", shortcut: nil) {
                GrantSessionWindowManager.shared.showWindow()
            }
            MenuRow(label: "Emergency lockdown", shortcut: "⌘⇧L") {
                Task { @MainActor in
                    await LockdownManager.shared.enterLockdown(reason: "Emergency lockdown triggered from menu bar")
                    refresh()
                }
            }
            MenuRow(label: "Settings…", shortcut: "⌘,") {
                openSettings()
                NSApp.activate(ignoringOtherApps: true)
            }
            MenuRow(label: "Audit History…", shortcut: "⌘⇧H") {
                AuditHistoryWindowManager.shared.showWindow()
            }
            #if DEBUG && !BASTION_HELPER
            Menu {
                Button("Policy Review Sample") {
                    SigningRequestPanelManager.shared.showRequest(
                        SigningRequestPreviewFactory.policyReview(),
                        onApprove: {}, onDeny: {}
                    )
                }
                Button("Rule Override Sample") {
                    SigningRequestPanelManager.shared.showRequest(
                        SigningRequestPreviewFactory.ruleOverride(),
                        onApprove: {}, onDeny: {}
                    )
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
                NSApplication.shared.terminate(nil)
            }
        }
        .padding(8)
    }

    // MARK: - Snapshot

    private struct Snapshot {
        var armed: Bool
        var armedSubtitle: String
        var activeClients: Int
        var totalToday: Int
        var silentToday: Int
        var overridesToday: Int
        var recent: [RecentRowModel]

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
        let recent = Array(AuditLog.shared.recentRequestRecords(limit: 3).map(RecentRowModel.init))

        let armed = !RuleEngine.shared.configCorrupted
        let subtitle: String
        if !armed {
            subtitle = "Rules config corrupt"
        } else if activeClients == 0 {
            subtitle = "Armed · default rules"
        } else {
            subtitle = "Armed · \(activeClients) \(activeClients == 1 ? "agent" : "agents") configured"
        }

        // Audit query results are bounded to recent 50 records — reasonable
        // for the menu bar's at-a-glance UX. A high-throughput install with
        // 50+ signs/day would want a dedicated counter here.
        let startOfToday = Calendar.current.startOfDay(for: Date())
        let recentToday = AuditLog.shared.recentRequestRecords(limit: 50).filter {
            ($0.latestTimestamp ?? .distantPast) >= startOfToday
        }
        let silentToday = recentToday.filter { $0.latestEvent?.approvalMode == .auto }.count
        let overridesToday = recentToday.filter { $0.latestEvent?.approvalMode == .ruleOverride }.count

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
    let request: PendingPairingRequest
    let onAccept: () -> Void
    let onReject: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top, spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(request.processName)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Color.ink900)
                        .lineLimit(1)
                    Text(request.bundleId)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Color.ink500)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
            }
            HStack {
                Text("Code")
                    .font(.system(size: 10.5, weight: .semibold))
                    .kerning(0.6)
                    .foregroundStyle(Color.ink500)
                Text(request.pairingCode)
                    .font(.system(size: 14, weight: .semibold, design: .monospaced))
                    .tracking(1.2)
                    .foregroundStyle(Color.ink900)
            }
            HStack(spacing: 8) {
                Button("Reject", action: onReject)
                    .bastionButton(.ghost, size: .small)
                Spacer()
                Button("Accept") { onAccept() }
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

private struct RecentRowModel: Identifiable {
    let id: String
    let title: String
    let client: String
    let timestamp: Date?
    let dotColor: Color
    let trailingTag: String?
    let trailingTagColor: Color

    @MainActor init(record: AuditRequestRecord) {
        self.id = record.id
        let title = record.request?.title ?? record.latestEvent?.operationTitle ?? "Signing request"
        let summary = record.request?.summary ?? ""
        self.title = summary.isEmpty ? title : "\(title) · \(summary)"
        self.client = record.clientDisplayName
        self.timestamp = record.latestTimestamp
        switch record.latestEvent?.type {
        case .signSuccess, .userOpReceiptSuccess, .userOpSubmitted, .preflightCompleted:
            self.dotColor = .bastionOk
        case .signDenied, .ruleViolation, .authFailed, .userOpSendFailed, .userOpReceiptFailed:
            self.dotColor = .bastionBad
        case .userOpReceiptTimeout, .signPending:
            self.dotColor = .bastionWarn
        default:
            self.dotColor = .ink400
        }
        switch record.latestEvent?.approvalMode {
        case .ruleOverride:
            self.trailingTag = "override"
            self.trailingTagColor = .bastionWarn
        case .auto:
            self.trailingTag = "silent"
            self.trailingTagColor = .ink400
        default:
            self.trailingTag = nil
            self.trailingTagColor = .ink400
        }
    }
}

private struct RecentRow: View {
    let row: RecentRowModel
    @State private var hovered: Bool = false

    var body: some View {
        HStack(spacing: 10) {
            Circle().fill(row.dotColor).frame(width: 6, height: 6)
            VStack(alignment: .leading, spacing: 1) {
                Text(row.title)
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundStyle(Color.ink900)
                    .lineLimit(1)
                    .truncationMode(.tail)
                HStack(spacing: 5) {
                    Text(row.client)
                    Text("·")
                    Text(BastionFormat.relative(row.timestamp))
                    if let tag = row.trailingTag {
                        Text("·")
                        Text(tag).foregroundStyle(row.trailingTagColor)
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
