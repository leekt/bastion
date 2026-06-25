import AppKit
import Combine
import SwiftUI

// Temporary scoped agent sessions — UI for the user's #1 missing feature.
// "Let Claude Code sign on Base for 30 minutes, max 50 USDC, only these targets."
//
// SessionStore persists active grants, keeps a thread-safe validation snapshot,
// and the rule engine consults that snapshot to tighten matching requests until
// the session expires or is revoked.

// MARK: - Model

nonisolated struct AgentSession: Identifiable, Hashable, Sendable, Codable {
    let id: UUID
    let clientLabel: String
    let clientId: String?
    /// Bundle ID of the agent this session applies to. Stored alongside the
    /// profile id so the rule engine can match incoming requests by bundleId
    /// (the only identity it has at validate-time) without doing a profile
    /// lookup.
    let clientBundleId: String?
    let chains: [Int]
    let usdcLimit: Double?
    let ethLimit: Double?
    let allowedTargets: [String]
    let startedAt: Date
    let expiresAt: Date
    let intent: String?

    init(
        id: UUID = UUID(),
        clientLabel: String,
        clientId: String?,
        clientBundleId: String? = nil,
        chains: [Int],
        usdcLimit: Double?,
        ethLimit: Double?,
        allowedTargets: [String],
        startedAt: Date = Date(),
        expiresAt: Date,
        intent: String?
    ) {
        self.id = id
        self.clientLabel = clientLabel
        self.clientId = clientId
        self.clientBundleId = clientBundleId
        self.chains = chains
        self.usdcLimit = usdcLimit
        self.ethLimit = ethLimit
        self.allowedTargets = allowedTargets
        self.startedAt = startedAt
        self.expiresAt = expiresAt
        self.intent = intent
    }

    var isActive: Bool { Date() < expiresAt }
    var remainingSeconds: Int { max(0, Int(expiresAt.timeIntervalSinceNow)) }

    var remainingLabel: String {
        let s = remainingSeconds
        if s >= 3600 { return "\(s / 3600)h \((s % 3600) / 60)m" }
        if s >= 60 { return "\(s / 60)m \(s % 60)s" }
        return "\(s)s"
    }
}

/// PR4: Per-session result of a `SessionStore.reconcile` pass. The
/// caller (typically `RuleEngine.updateConfig`) audits these so the
/// owner can see exactly what happened to which session when the
/// allowlist tightened.
nonisolated struct SessionReconciliationEntry: Sendable, Equatable {
    let sessionId: UUID
    let outcome: SessionReconciler.Outcome
}

/// Thread-safe shadow of active sessions, readable from any actor context.
/// Maintained alongside the @MainActor SessionStore; the rule engine reads
/// this snapshot during validation.
nonisolated final class SessionSnapshotStore: @unchecked Sendable {
    static let shared = SessionSnapshotStore()
    private let lock = NSLock()
    private var sessions: [AgentSession] = []
    private var unhealthyReason: String?

    func update(_ sessions: [AgentSession]) {
        lock.lock(); defer { lock.unlock() }
        self.sessions = sessions
    }

    func markUnhealthy(_ reason: String) {
        lock.lock(); defer { lock.unlock() }
        unhealthyReason = reason
    }

    func clearUnhealthy() {
        lock.lock(); defer { lock.unlock() }
        unhealthyReason = nil
    }

    func storageHealthFailure() -> String? {
        lock.lock(); defer { lock.unlock() }
        return unhealthyReason
    }

    /// Returns all sessions currently in-window for the given client. Match
    /// keys (any of bundleId / profile id / label) are case-insensitive for
    /// bundleId. Empty array means no constraints — caller should fall back
    /// to the profile's stored rules.
    func activeSessions(forBundleId bundleId: String?, profileId: String? = nil, label: String? = nil) -> [AgentSession] {
        lock.lock(); defer { lock.unlock() }
        let now = Date()
        return sessions.filter { session in
            guard session.expiresAt > now else { return false }
            if let bundle = bundleId,
               let sessionBundle = session.clientBundleId,
               bundle.caseInsensitiveCompare(sessionBundle) == .orderedSame {
                return true
            }
            if let pid = profileId, let sid = session.clientId, pid == sid { return true }
            if let label, session.clientLabel == label { return true }
            return false
        }
    }

    func anyActive() -> Bool {
        lock.lock(); defer { lock.unlock() }
        let now = Date()
        return sessions.contains { $0.expiresAt > now }
    }
}

// MARK: - Grant session window

/// Hosts the GrantSessionSheet inside a real NSWindow instead of a popover
/// attached to MenuBarExtra. Popovers anchored to MenuBarExtra(.window)
/// triggered an AppKit animation feedback loop where the menu bar dropdown
/// would slide endlessly. A standalone window is snappy and dismisses
/// cleanly.
@MainActor
final class GrantSessionWindowManager {
    static let shared = GrantSessionWindowManager()
    private var window: NSWindow?
    private init() {}

    func showWindow() {
        if let window {
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            return
        }
        let options = RuleEngine.shared.config.clientProfiles.map {
            GrantSessionSheet.ClientOption(
                id: $0.id,
                label: $0.label ?? $0.bundleId,
                bundleId: $0.bundleId
            )
        }
        let view = GrantSessionSheet(
            initialClient: options.first,
            availableClients: options,
            onClose: { [weak self] in self?.window?.close() },
            onGrant: { [weak self] session in
                if SessionStore.shared.grant(session) {
                    self?.window?.close()
                    return true
                } else {
                    AuditLog.shared.record(AuditEvent(
                        type: .authFailed,
                        dataPrefix: "session.grant",
                        reason: "Session grant could not be persisted; refusing memory-only grant"
                    ))
                    return false
                }
            }
        )
        let host = NSHostingView(rootView: view)
        let new = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 600),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        new.contentView = host
        new.title = "Grant temporary session"
        new.titleVisibility = .hidden
        new.titlebarAppearsTransparent = true
        new.isReleasedWhenClosed = false
        new.center()
        NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification,
            object: new,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in self?.window = nil }
        }
        window = new
        NSApp.activate(ignoringOtherApps: true)
        new.makeKeyAndOrderFront(nil)
    }
}

@MainActor
@Observable
final class SessionStore {
    static let shared = SessionStore()
    private(set) var sessions: [AgentSession] = []

    /// Keychain account where active sessions are persisted. Stored under the
    /// same access group as the rest of Bastion's Keychain items, so agent
    /// processes can't read or mutate them.
    private static let keychainAccount = "sessions.active"
    private let keychain: KeychainBackend

    init(keychain: KeychainBackend = SystemKeychainBackend()) {
        self.keychain = keychain
        load()
    }

    @discardableResult
    func grant(_ session: AgentSession) -> Bool {
        let previous = sessions
        sessions.append(session)
        guard persist() else {
            sessions = previous
            SessionSnapshotStore.shared.update(sessions)
            return false
        }
        return true
    }

    @discardableResult
    func revoke(_ id: UUID) -> Bool {
        let previous = sessions
        sessions.removeAll { $0.id == id }
        guard persist() else {
            sessions = previous
            SessionSnapshotStore.shared.update(sessions)
            return false
        }
        return true
    }

    /// Removes every active session — used by emergency lockdown.
    @discardableResult
    func revokeAll() -> Bool {
        let previous = sessions
        sessions.removeAll()
        guard persist() else {
            sessions = previous
            SessionSnapshotStore.shared.update(sessions)
            return false
        }
        return true
    }

    /// Emergency lockdown needs memory to revoke immediately even if durable
    /// deletion fails. Marking the snapshot unhealthy keeps signing blocked
    /// until Keychain storage recovers.
    @discardableResult
    func revokeAllFailClosed() -> Bool {
        sessions.removeAll()
        if keychain.delete(account: Self.keychainAccount) {
            SessionSnapshotStore.shared.clearUnhealthy()
            SessionSnapshotStore.shared.update(sessions)
            return true
        }
        SessionSnapshotStore.shared.markUnhealthy("Session revocation could not be persisted; signing is locked down until recovery")
        SessionSnapshotStore.shared.update(sessions)
        return false
    }

    /// PR4: Reconcile every active session against the rules currently in
    /// effect for its agent. Sessions that exceed the new policy are
    /// downgraded (chains/targets narrowed to the surviving intersection)
    /// or revoked when nothing survives. Returns a report of every
    /// outcome so the caller (typically `RuleEngine.updateConfig`) can
    /// audit the change. The reconciler defers the actual rule lookup to
    /// the closure so this method stays decoupled from `RuleEngine`.
    @discardableResult
    func reconcile(rulesProvider: (String?) -> RuleConfig) -> [SessionReconciliationEntry] {
        var results: [SessionReconciliationEntry] = []
        var newSessions: [AgentSession] = []
        var anyChange = false
        for session in sessions {
            let rules = rulesProvider(session.clientBundleId)
            let outcome = SessionReconciler.reconcile(session, against: rules)
            results.append(SessionReconciliationEntry(sessionId: session.id, outcome: outcome))
            switch outcome {
            case .unchanged:
                newSessions.append(session)
            case .downgraded(let updated, _):
                newSessions.append(updated)
                anyChange = true
            case .revoked:
                anyChange = true
            }
        }
        if anyChange {
            let previous = sessions
            sessions = newSessions
            if !persist() {
                sessions = previous
                SessionSnapshotStore.shared.update(sessions)
            }
        }
        return results
    }

    func active() -> [AgentSession] {
        let now = Date()
        let before = sessions.count
        sessions.removeAll { $0.expiresAt < now }
        if sessions.count != before {
            _ = persist()
        } else {
            // Still push the snapshot so the rule engine can see freshly
            // expired entries even when no mutation occurred this tick.
            SessionSnapshotStore.shared.update(sessions)
        }
        return sessions
    }

    /// Pushes the snapshot to the rule engine and writes a Keychain copy so
    /// active sessions survive app restarts.
    @discardableResult
    private func persist() -> Bool {
        if sessions.isEmpty {
            guard keychain.delete(account: Self.keychainAccount) else {
                SessionSnapshotStore.shared.markUnhealthy("Session storage delete failed")
                return false
            }
            SessionSnapshotStore.shared.clearUnhealthy()
            SessionSnapshotStore.shared.update(sessions)
            return true
        }
        guard let data = try? JSONEncoder().encode(sessions),
              keychain.write(account: Self.keychainAccount, data: data) else {
            SessionSnapshotStore.shared.markUnhealthy("Session storage write failed")
            return false
        }
        SessionSnapshotStore.shared.clearUnhealthy()
        SessionSnapshotStore.shared.update(sessions)
        return true
    }

    /// Reads the persisted session list at startup. Expired entries are
    /// pruned during the load — they don't get a chance to live again.
    private func load() {
        let data: Data
        switch keychain.readResult(account: Self.keychainAccount) {
        case .missing:
            SessionSnapshotStore.shared.clearUnhealthy()
            SessionSnapshotStore.shared.update([])
            return
        case .failure:
            SessionSnapshotStore.shared.markUnhealthy("Session storage is unavailable")
            return
        case .found(let found):
            data = found
        }
        guard let stored = try? JSONDecoder().decode([AgentSession].self, from: data) else {
            SessionSnapshotStore.shared.markUnhealthy("Session storage is corrupt")
            return
        }
        let now = Date()
        sessions = stored.filter { $0.expiresAt > now }
        SessionSnapshotStore.shared.clearUnhealthy()
        SessionSnapshotStore.shared.update(sessions)
        // If pruning removed expired sessions, write the trimmed list back.
        if sessions.count != stored.count {
            persist()
        }
    }
}

// MARK: - Grant sheet

nonisolated struct GrantSessionDraft: Equatable, Sendable {
    static let grantPersistenceErrorMessage = "Session grant could not be saved. Signing was not widened."

    static func grantResultError(didPersist: Bool) -> String? {
        didPersist ? nil : grantPersistenceErrorMessage
    }

    var clientLabel: String
    var clientId: String?
    var clientBundleId: String?
    var durationMinutes: Int
    var usdcCap: String
    var ethCap: String
    var allowedTargets: String
    var intent: String
    var selectedChains: Set<Int>

    var canGrant: Bool {
        validationMessage == nil
    }

    var validationMessage: String? {
        if clientLabel.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return "Choose an agent before granting a session."
        }
        if selectedChains.isEmpty {
            return "Select at least one allowed chain."
        }
        if !Self.capIsValid(usdcCap) {
            return "USDC cap must be empty or a non-negative number."
        }
        if !Self.capIsValid(ethCap) {
            return "ETH cap must be empty or a non-negative number."
        }
        if invalidTarget != nil {
            return "Allowed targets must be comma-separated 20-byte Ethereum addresses."
        }
        return nil
    }

    var parsedTargets: [String] {
        allowedTargets
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .map(Self.canonicalEthAddress)
    }

    var invalidTarget: String? {
        allowedTargets
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .first { !$0.isEmpty && !Self.isValidEthAddress($0) }
    }

    func capValue(_ text: String) -> Double? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        guard Self.capIsValid(trimmed) else { return nil }
        return Double(trimmed)
    }

    func makeSession(startedAt: Date = Date()) -> AgentSession? {
        guard canGrant else { return nil }
        let trimmedIntent = intent.trimmingCharacters(in: .whitespacesAndNewlines)
        return AgentSession(
            clientLabel: clientLabel.trimmingCharacters(in: .whitespacesAndNewlines),
            clientId: clientId,
            clientBundleId: clientBundleId,
            chains: selectedChains.sorted(),
            usdcLimit: capValue(usdcCap),
            ethLimit: capValue(ethCap),
            allowedTargets: parsedTargets,
            startedAt: startedAt,
            expiresAt: startedAt.addingTimeInterval(TimeInterval(durationMinutes * 60)),
            intent: trimmedIntent.isEmpty ? nil : trimmedIntent
        )
    }

    private static func capIsValid(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return true }
        guard let value = Double(trimmed) else { return false }
        return value.isFinite && value >= 0
    }

    static func canonicalEthAddress(_ s: String) -> String {
        let lower = s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let stripped = lower.hasPrefix("0x") ? String(lower.dropFirst(2)) : lower
        return "0x\(stripped)"
    }

    static func isValidEthAddress(_ s: String) -> Bool {
        let stripped = s.hasPrefix("0x") ? String(s.dropFirst(2)) : s
        guard stripped.count == 40 else { return false }
        return stripped.allSatisfy { $0.isHexDigit }
    }
}

struct GrantSessionSheet: View {
    /// Available clients to grant a session to. `bundleId` is required so the
    /// rule engine can match incoming requests by bundleId at validate-time.
    struct ClientOption: Identifiable, Hashable {
        let id: String       // ClientProfile.id
        let label: String
        let bundleId: String
    }

    let initialClient: ClientOption?
    let availableClients: [ClientOption]
    let onClose: () -> Void
    let onGrant: (AgentSession) -> Bool

    @State private var clientLabel: String
    @State private var clientId: String?
    @State private var clientBundleId: String?
    @State private var durationMinutes: Int = 30
    @State private var usdcCap: String = "50"
    @State private var ethCap: String = ""
    @State private var allowedTargets: String = ""
    @State private var intent: String = ""
    @State private var selectedChains: Set<Int> = [8453]
    @State private var grantError: String? = nil

    private let chainOptions: [(id: Int, name: String)] = [
        (8453, "Base"),
        (1, "Ethereum"),
        (42_161, "Arbitrum"),
        (10, "Optimism"),
    ]

    init(
        initialClient: ClientOption?,
        availableClients: [ClientOption],
        onClose: @escaping () -> Void,
        onGrant: @escaping (AgentSession) -> Bool
    ) {
        self.initialClient = initialClient
        self.availableClients = availableClients
        self.onClose = onClose
        self.onGrant = onGrant
        _clientLabel = State(initialValue: initialClient?.label ?? availableClients.first?.label ?? "")
        _clientId = State(initialValue: initialClient?.id ?? availableClients.first?.id)
        _clientBundleId = State(initialValue: initialClient?.bundleId ?? availableClients.first?.bundleId)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            BastionDivider()
            scrollContent
            BastionDivider()
            actions
        }
        .frame(width: 480)
        .background(Color.paper)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Grant temporary session")
                .font(.system(size: 14, weight: .semibold))
                .kerning(-0.14)
            Text("Time-bounded scope, automatically revoked when it expires.")
                .font(.system(size: 12))
                .foregroundStyle(Color.ink500)
        }
        .padding(EdgeInsets(top: 16, leading: 18, bottom: 14, trailing: 18))
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var scrollContent: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                clientPicker
                durationPicker
                limitsRow
                chainsPicker
                targetsField
                intentField
                if let validationMessage {
                    Text(validationMessage)
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundStyle(Color.bastionBad)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let grantError {
                    Text(grantError)
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundStyle(Color.bastionBad)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(EdgeInsets(top: 16, leading: 18, bottom: 16, trailing: 18))
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .frame(maxHeight: 480)
    }

    private var clientPicker: some View {
        VStack(alignment: .leading, spacing: 6) {
            BastionSectionLabel(text: "Agent")
            Menu {
                ForEach(availableClients) { client in
                    Button(client.label) {
                        clientLabel = client.label
                        clientId = client.id
                        clientBundleId = client.bundleId
                    }
                }
            } label: {
                HStack {
                    Text(clientLabel)
                        .font(.system(size: 13))
                        .foregroundStyle(Color.ink900)
                    Spacer()
                    Text("▾").font(.system(size: 10))
                }
                .padding(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                .background(
                    RoundedRectangle(cornerRadius: 7)
                        .fill(Color.paper)
                        .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Color.ink200, lineWidth: 1))
                )
            }
            .menuStyle(.borderlessButton)
        }
    }

    private var durationPicker: some View {
        VStack(alignment: .leading, spacing: 6) {
            BastionSectionLabel(text: "Duration")
            HStack(spacing: 6) {
                ForEach([5, 15, 30, 60, 120], id: \.self) { mins in
                    Button {
                        durationMinutes = mins
                    } label: {
                        Text(durationLabel(mins))
                            .font(.system(size: 12, weight: .medium))
                            .padding(.horizontal, 10).padding(.vertical, 5)
                            .foregroundStyle(durationMinutes == mins ? Color.paper : Color.ink700)
                            .background(
                                RoundedRectangle(cornerRadius: 6)
                                    .fill(durationMinutes == mins ? Color.ink900 : Color.paper)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 6)
                                            .strokeBorder(durationMinutes == mins ? .clear : Color.ink200, lineWidth: 1)
                                    )
                            )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private func durationLabel(_ mins: Int) -> String {
        if mins >= 60 { return "\(mins / 60)h" }
        return "\(mins)m"
    }

    private var limitsRow: some View {
        VStack(alignment: .leading, spacing: 6) {
            BastionSectionLabel(text: "Spending caps")
            HStack(spacing: 8) {
                limitField(label: "USDC max", binding: $usdcCap, placeholder: "0", suffix: "USDC")
                limitField(label: "ETH max", binding: $ethCap, placeholder: "0", suffix: "ETH")
            }
        }
    }

    private func limitField(label: String, binding: Binding<String>, placeholder: String, suffix: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.system(size: 11.5))
                .foregroundStyle(Color.ink500)
            HStack {
                TextField(placeholder, text: binding)
                    .textFieldStyle(.plain)
                    .font(.system(size: 13, design: .monospaced))
                Text(suffix)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.ink500)
            }
            .padding(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
            .background(
                RoundedRectangle(cornerRadius: 7)
                    .fill(Color.paper)
                    .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Color.ink200, lineWidth: 1))
            )
        }
        .frame(maxWidth: .infinity)
    }

    private var draft: GrantSessionDraft {
        GrantSessionDraft(
            clientLabel: clientLabel,
            clientId: clientId,
            clientBundleId: clientBundleId,
            durationMinutes: durationMinutes,
            usdcCap: usdcCap,
            ethCap: ethCap,
            allowedTargets: allowedTargets,
            intent: intent,
            selectedChains: selectedChains
        )
    }

    private var canGrant: Bool {
        draft.canGrant
    }

    private var validationMessage: String? {
        draft.validationMessage
    }

    private var chainsPicker: some View {
        VStack(alignment: .leading, spacing: 6) {
            BastionSectionLabel(text: "Allowed chains")
            HStack(spacing: 6) {
                ForEach(chainOptions, id: \.id) { option in
                    let on = selectedChains.contains(option.id)
                    Button {
                        if on { selectedChains.remove(option.id) }
                        else { selectedChains.insert(option.id) }
                    } label: {
                        HStack(spacing: 4) {
                            ChainBadge(chainId: option.id, size: .small)
                            if on { CheckGlyph(size: 10, color: .bastionOk) }
                        }
                        .padding(.horizontal, 10).padding(.vertical, 5)
                        .background(
                            RoundedRectangle(cornerRadius: 6)
                                .fill(on ? Color.ink50 : Color.paper)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .strokeBorder(on ? Color.ink700 : Color.ink200, lineWidth: 1)
                                )
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var targetsField: some View {
        VStack(alignment: .leading, spacing: 6) {
            BastionSectionLabel(text: "Allowed targets (optional)")
            TextField("0xa0b8…, 0xf39f…", text: $allowedTargets, axis: .vertical)
                .textFieldStyle(.plain)
                .lineLimit(3, reservesSpace: true)
                .font(.system(size: 12, design: .monospaced))
                .padding(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                .background(
                    RoundedRectangle(cornerRadius: 7)
                        .fill(Color.paper)
                        .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Color.ink200, lineWidth: 1))
                )
            Text("Comma-separated. Empty = inherit profile allowlist.")
                .font(.system(size: 11))
                .foregroundStyle(Color.ink500)
        }
    }

    private var intentField: some View {
        VStack(alignment: .leading, spacing: 6) {
            BastionSectionLabel(text: "Intent (shown in audit)")
            TextField("Rebalancing Base USDC into treasury…", text: $intent)
                .textFieldStyle(.plain)
                .font(.system(size: 13))
                .padding(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                .background(
                    RoundedRectangle(cornerRadius: 7)
                        .fill(Color.paper)
                        .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Color.ink200, lineWidth: 1))
                )
        }
    }

    private var actions: some View {
        HStack {
            Spacer()
            Button("Cancel", action: onClose).bastionButton(.default)
            Button("Grant for \(durationLabel(durationMinutes))") {
                grantSession()
            }
            .bastionButton(.primary)
            .disabled(!canGrant)
        }
        .padding(EdgeInsets(top: 12, leading: 18, bottom: 12, trailing: 18))
        .background(Color.ink50)
    }

    private func grantSession() {
        guard let session = draft.makeSession() else { return }
        grantError = GrantSessionDraft.grantResultError(didPersist: onGrant(session))
    }
}

// MARK: - Active session row (for menu bar / settings)

nonisolated struct ActiveSessionRowPresentation: Identifiable, Equatable, Sendable {
    let id: UUID
    let clientLabel: String
    let remainingShort: String
    let scopeSummary: String
    let revokeButtonTitle: String

    static func make(_ session: AgentSession, now: Date = Date()) -> ActiveSessionRowPresentation {
        ActiveSessionRowPresentation(
            id: session.id,
            clientLabel: session.clientLabel,
            remainingShort: remainingShort(expiresAt: session.expiresAt, now: now),
            scopeSummary: scopeSummary(for: session, now: now),
            revokeButtonTitle: "Revoke"
        )
    }

    static func revokeErrorMessage(showExpiredMessage: Bool) -> String {
        showExpiredMessage
            ? "Session expired, but removal could not be saved."
            : "Could not revoke this session. Try again."
    }

    private static func remainingShort(expiresAt: Date, now: Date) -> String {
        let s = max(0, Int(expiresAt.timeIntervalSince(now)))
        if s >= 3600 { return "\(s / 3600)h" }
        if s >= 60 { return "\(s / 60)m" }
        return "\(s)s"
    }

    private static func remainingLabel(expiresAt: Date, now: Date) -> String {
        let s = max(0, Int(expiresAt.timeIntervalSince(now)))
        if s >= 3600 { return "\(s / 3600)h \((s % 3600) / 60)m" }
        if s >= 60 { return "\(s / 60)m \(s % 60)s" }
        return "\(s)s"
    }

    private static func scopeSummary(for session: AgentSession, now: Date) -> String {
        var parts: [String] = []
        if !session.chains.isEmpty {
            parts.append(session.chains.map { ChainConfig.name(for: $0) }.joined(separator: ", "))
        }
        if let usdc = session.usdcLimit, usdc > 0 {
            parts.append("\(Int(usdc)) USDC")
        }
        if let eth = session.ethLimit, eth > 0 {
            parts.append("\(eth) ETH")
        }
        parts.append(remainingLabel(expiresAt: session.expiresAt, now: now))
        return parts.joined(separator: " · ")
    }
}

struct ActiveSessionRow: View {
    @Bindable var store: SessionStore
    let session: AgentSession

    @State private var tick = 0
    @State private var revokeError: String? = nil
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        let row = presentation
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                ZStack {
                    Circle()
                        .strokeBorder(Color.bastionAccent, lineWidth: 2)
                        .frame(width: 28, height: 28)
                    Text(row.remainingShort)
                        .font(.system(size: 9, weight: .semibold, design: .monospaced))
                        .foregroundStyle(Color.bastionAccent)
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(row.clientLabel)
                        .font(.system(size: 12.5, weight: .medium))
                    Text(row.scopeSummary)
                        .font(.system(size: 11))
                        .foregroundStyle(Color.ink500)
                        .lineLimit(1)
                }
                Spacer()
                Button(row.revokeButtonTitle) {
                    revokeSession(showExpiredMessage: false)
                }
                .bastionButton(.danger, size: .small)
            }
            if let revokeError {
                Text(revokeError)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.bastionBad)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.bastionAccentSoft.opacity(0.5))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(Color.bastionAccent.opacity(0.4), lineWidth: 1)
                )
        )
        .onReceive(timer) { _ in
            tick &+= 1
            if !session.isActive { revokeSession(showExpiredMessage: true) }
        }
    }

    private func revokeSession(showExpiredMessage: Bool) {
        if store.revoke(session.id) {
            revokeError = nil
        } else {
            revokeError = ActiveSessionRowPresentation.revokeErrorMessage(showExpiredMessage: showExpiredMessage)
        }
    }

    private var presentation: ActiveSessionRowPresentation {
        _ = tick
        return ActiveSessionRowPresentation.make(session)
    }
}
