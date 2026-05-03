import AppKit
import Combine
import SwiftUI

// Temporary scoped agent sessions — UI for the user's #1 missing feature.
// "Let Claude Code sign on Base for 30 minutes, max 50 USDC, only these targets."
//
// This file provides the full visual surface; the backend (see task #20) needs
// to materialize SessionGrant in BastionConfig and consult it from the rule
// engine. For now SessionStore is a session-only in-memory @Observable that
// drives both the menu bar countdown and the per-profile session chip.

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

/// Thread-safe shadow of active sessions, readable from any actor context.
/// Maintained alongside the @MainActor SessionStore; the rule engine reads
/// this snapshot during validation.
nonisolated final class SessionSnapshotStore: @unchecked Sendable {
    static let shared = SessionSnapshotStore()
    private let lock = NSLock()
    private var sessions: [AgentSession] = []

    func update(_ sessions: [AgentSession]) {
        lock.lock(); defer { lock.unlock() }
        self.sessions = sessions
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

    func grant(_ session: AgentSession) {
        sessions.append(session)
        persist()
    }

    func revoke(_ id: UUID) {
        sessions.removeAll { $0.id == id }
        persist()
    }

    /// Removes every active session — used by emergency lockdown.
    func revokeAll() {
        sessions.removeAll()
        persist()
    }

    func active() -> [AgentSession] {
        let now = Date()
        let before = sessions.count
        sessions.removeAll { $0.expiresAt < now }
        if sessions.count != before {
            persist()
        } else {
            // Still push the snapshot so the rule engine can see freshly
            // expired entries even when no mutation occurred this tick.
            SessionSnapshotStore.shared.update(sessions)
        }
        return sessions
    }

    /// Pushes the snapshot to the rule engine and writes a Keychain copy so
    /// active sessions survive app restarts.
    private func persist() {
        SessionSnapshotStore.shared.update(sessions)
        if sessions.isEmpty {
            keychain.delete(account: Self.keychainAccount)
            return
        }
        guard let data = try? JSONEncoder().encode(sessions) else { return }
        keychain.write(account: Self.keychainAccount, data: data)
    }

    /// Reads the persisted session list at startup. Expired entries are
    /// pruned during the load — they don't get a chance to live again.
    private func load() {
        guard let data = keychain.read(account: Self.keychainAccount),
              let stored = try? JSONDecoder().decode([AgentSession].self, from: data) else {
            return
        }
        let now = Date()
        sessions = stored.filter { $0.expiresAt > now }
        SessionSnapshotStore.shared.update(sessions)
        // If pruning removed expired sessions, write the trimmed list back.
        if sessions.count != stored.count {
            persist()
        }
    }
}

// MARK: - Grant sheet

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
    let onGrant: (AgentSession) -> Void

    @State private var clientLabel: String
    @State private var clientId: String?
    @State private var clientBundleId: String?
    @State private var durationMinutes: Int = 30
    @State private var usdcCap: String = "50"
    @State private var ethCap: String = ""
    @State private var allowedTargets: String = ""
    @State private var intent: String = ""
    @State private var selectedChains: Set<Int> = [8453]

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
        onGrant: @escaping (AgentSession) -> Void
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
            }
            .padding(EdgeInsets(top: 16, leading: 18, bottom: 16, trailing: 18))
        }
        .frame(maxHeight: 480)
    }

    private var clientPicker: some View {
        VStack(alignment: .leading, spacing: 6) {
            LabelXS(text: "Agent")
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
            LabelXS(text: "Duration")
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
            LabelXS(text: "Spending caps")
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

    private var chainsPicker: some View {
        VStack(alignment: .leading, spacing: 6) {
            LabelXS(text: "Allowed chains")
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
            LabelXS(text: "Allowed targets (optional)")
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
            LabelXS(text: "Intent (shown in audit)")
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
                let session = AgentSession(
                    clientLabel: clientLabel,
                    clientId: clientId,
                    clientBundleId: clientBundleId,
                    chains: selectedChains.sorted(),
                    usdcLimit: Double(usdcCap),
                    ethLimit: Double(ethCap),
                    allowedTargets: allowedTargets
                        .split(separator: ",")
                        .map { $0.trimmingCharacters(in: .whitespaces) }
                        .filter { !$0.isEmpty },
                    expiresAt: Date().addingTimeInterval(TimeInterval(durationMinutes * 60)),
                    intent: intent.isEmpty ? nil : intent
                )
                onGrant(session)
            }
            .bastionButton(.primary)
        }
        .padding(EdgeInsets(top: 12, leading: 18, bottom: 12, trailing: 18))
        .background(Color.ink50)
    }
}

// MARK: - Active session row (for menu bar / settings)

struct ActiveSessionRow: View {
    @Bindable var store: SessionStore
    let session: AgentSession

    @State private var tick = 0
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        HStack(spacing: 10) {
            ZStack {
                Circle()
                    .strokeBorder(Color.bastionAccent, lineWidth: 2)
                    .frame(width: 28, height: 28)
                Text(remainingShort)
                    .font(.system(size: 9, weight: .semibold, design: .monospaced))
                    .foregroundStyle(Color.bastionAccent)
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(session.clientLabel)
                    .font(.system(size: 12.5, weight: .medium))
                Text(scopeSummary)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.ink500)
                    .lineLimit(1)
            }
            Spacer()
            Button("Revoke") {
                store.revoke(session.id)
            }
            .bastionButton(.danger, size: .small)
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
            if !session.isActive { store.revoke(session.id) }
        }
    }

    private var remainingShort: String {
        _ = tick
        let s = session.remainingSeconds
        if s >= 3600 { return "\(s / 3600)h" }
        if s >= 60 { return "\(s / 60)m" }
        return "\(s)s"
    }

    private var scopeSummary: String {
        _ = tick
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
        parts.append(session.remainingLabel)
        return parts.joined(separator: " · ")
    }
}
