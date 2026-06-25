import Testing
@testable import bastion
import Foundation

// PR4 tests: SessionReconciler is the canonical "does this session
// still fit the rules?" decision. When the owner tightens the
// allowlist, every active session must either be downgraded to the
// surviving intersection or revoked. Without these guarantees, a
// session granted under broader rules would survive until expiry.

private func session(
    chains: [Int] = [8453],
    targets: [String] = [],
    bundleId: String? = "com.example.agent"
) -> AgentSession {
    AgentSession(
        clientLabel: "Example",
        clientId: "client-1",
        clientBundleId: bundleId,
        chains: chains,
        usdcLimit: 50,
        ethLimit: nil,
        allowedTargets: targets,
        expiresAt: Date().addingTimeInterval(900),
        intent: nil
    )
}

private func rules(
    allowedChains: [Int]? = nil,
    allowedTargets: [String: [String]]? = nil,
    allowedClients: [AllowedClient]? = nil
) -> RuleConfig {
    RuleConfig(
        userOpPosture: .enforceRulesAndAutoSign,
        allowedHours: nil,
        allowedChains: allowedChains,
        allowedTargets: allowedTargets,
        allowedSelectors: nil,
        denySelectors: nil,
        allowedClients: allowedClients,
        rateLimits: [],
        spendingLimits: []
    )
}

private nonisolated final class DeleteFailingSessionKeychainBackend: KeychainBackend, @unchecked Sendable {
    private var storage: [String: Data] = [:]
    private let lock = NSLock()

    nonisolated func read(account: String) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return storage[account]
    }

    @discardableResult
    nonisolated func write(account: String, data: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        storage[account] = data
        return true
    }

    @discardableResult
    nonisolated func delete(account: String) -> Bool {
        false
    }
}

@Suite("SessionReconciler — downgrade & revoke semantics")
struct SessionReconcilerTests {

    // MARK: - allowedClients gate

    @Test("Bundle removed from allowedClients revokes session")
    func bundleRemovedRevokes() {
        let s = session(bundleId: "com.example.agent")
        let r = rules(allowedClients: [
            AllowedClient(id: "1", bundleId: "com.other.app", label: nil)
        ])
        guard case .revoked(let reason) = SessionReconciler.reconcile(s, against: r) else {
            Issue.record("Expected revoked")
            return
        }
        #expect(reason.contains("bundle"))
    }

    @Test("Bundle still in allowedClients, scope unchanged → unchanged")
    func bundlePresentUnchanged() {
        let s = session(bundleId: "com.example.agent")
        let r = rules(
            allowedChains: [8453],
            allowedClients: [AllowedClient(id: "1", bundleId: "com.example.agent", label: nil)]
        )
        let outcome = SessionReconciler.reconcile(s, against: r)
        #expect(outcome == .unchanged)
    }

    @Test("Empty allowedClients (deny-all sentinel) revokes the session")
    func emptyAllowlistRevokes() {
        let s = session(bundleId: "com.example.agent")
        let r = rules(allowedClients: [])
        let outcome = SessionReconciler.reconcile(s, against: r)
        if case .revoked(let reason) = outcome {
            #expect(reason.contains("allowlist is empty"))
        } else {
            Issue.record("Expected empty allowedClients to revoke the session")
        }
    }

    @Test("Case-insensitive bundle id match")
    func bundleCaseInsensitive() {
        let s = session(bundleId: "Com.Example.Agent")
        let r = rules(allowedClients: [
            AllowedClient(id: "1", bundleId: "com.example.agent", label: nil)
        ])
        let outcome = SessionReconciler.reconcile(s, against: r)
        #expect(outcome == .unchanged)
    }

    // MARK: - Chain intersection

    @Test("Chain intersection downgrades session")
    func chainsDowngrade() {
        let s = session(chains: [8453, 1])
        let r = rules(allowedChains: [8453])
        guard case .downgraded(let updated, let reason) = SessionReconciler.reconcile(s, against: r) else {
            Issue.record("Expected downgraded")
            return
        }
        #expect(updated.chains == [8453])
        #expect(reason.contains("chains"))
    }

    @Test("Disjoint chains revoke session")
    func chainsDisjointRevokes() {
        let s = session(chains: [1, 8453])
        let r = rules(allowedChains: [42_161])
        guard case .revoked(let reason) = SessionReconciler.reconcile(s, against: r) else {
            Issue.record("Expected revoked")
            return
        }
        #expect(reason.contains("chains"))
    }

    @Test("Nil allowedChains preserves full session scope")
    func nilChainsKeepsAll() {
        let s = session(chains: [1, 8453, 42_161])
        let r = rules(allowedChains: nil)
        let outcome = SessionReconciler.reconcile(s, against: r)
        #expect(outcome == .unchanged)
    }

    // MARK: - Target intersection

    @Test("Targets filter — sub-allowlist on an active chain narrows session")
    func targetsDowngrade() {
        let s = session(
            chains: [8453],
            targets: ["0xAAA", "0xBBB"]
        )
        let r = rules(
            allowedChains: [8453],
            allowedTargets: ["8453": ["0xaaa"]]
        )
        guard case .downgraded(let updated, _) = SessionReconciler.reconcile(s, against: r) else {
            Issue.record("Expected downgraded")
            return
        }
        #expect(updated.allowedTargets == ["0xAAA"])
    }

    @Test("Disjoint targets revoke session")
    func targetsDisjointRevoke() {
        let s = session(
            chains: [8453],
            targets: ["0xAAA"]
        )
        let r = rules(
            allowedChains: [8453],
            allowedTargets: ["8453": ["0xCCC"]]
        )
        guard case .revoked = SessionReconciler.reconcile(s, against: r) else {
            Issue.record("Expected revoked")
            return
        }
    }

    @Test("Targets unrestricted on session's chain — session keeps targets")
    func targetsUnrestrictedKeepsAll() {
        // Rules restrict targets on chain 1 but not on 8453. Session
        // operates on 8453 so its targets are unrestricted.
        let s = session(
            chains: [8453],
            targets: ["0xAAA", "0xBBB"]
        )
        let r = rules(
            allowedChains: [8453],
            allowedTargets: ["1": ["0xCCC"]]
        )
        let outcome = SessionReconciler.reconcile(s, against: r)
        #expect(outcome == .unchanged)
    }

    // MARK: - Combined

    @Test("Chain + target downgrade combine in one outcome")
    func chainAndTargetDowngrade() {
        let s = session(
            chains: [8453, 1],
            targets: ["0xAAA", "0xBBB"]
        )
        let r = rules(
            allowedChains: [8453],
            allowedTargets: ["8453": ["0xaaa"]]
        )
        guard case .downgraded(let updated, let reason) = SessionReconciler.reconcile(s, against: r) else {
            Issue.record("Expected downgraded")
            return
        }
        #expect(updated.chains == [8453])
        #expect(updated.allowedTargets == ["0xAAA"])
        #expect(reason.contains("chains"))
        #expect(reason.contains("targets"))
    }

    @Test("Empty session targets stay empty after reconcile")
    func emptyTargetsStayEmpty() {
        let s = session(chains: [8453], targets: [])
        let r = rules(
            allowedChains: [8453],
            allowedTargets: ["8453": ["0xaaa"]]
        )
        let outcome = SessionReconciler.reconcile(s, against: r)
        #expect(outcome == .unchanged)
    }

    @Test("Reconciliation entry equality holds across same outcomes")
    func entryEquatable() {
        let session1 = session()
        let entry1 = SessionReconciliationEntry(sessionId: session1.id, outcome: .unchanged)
        let entry2 = SessionReconciliationEntry(sessionId: session1.id, outcome: .unchanged)
        #expect(entry1 == entry2)
    }

    @Test("Session preserves identity (id + expiresAt) after downgrade")
    func downgradePreservesIdentity() {
        let original = session(chains: [8453, 1])
        let r = rules(allowedChains: [8453])
        guard case .downgraded(let updated, _) = SessionReconciler.reconcile(original, against: r) else {
            Issue.record("Expected downgraded")
            return
        }
        // Critically: id/expiresAt must survive so the session keeps
        // counting down toward its original expiry, not get extended.
        #expect(updated.id == original.id)
        #expect(updated.expiresAt == original.expiresAt)
        #expect(updated.startedAt == original.startedAt)
    }

    @Test("Grant session draft validates inline blockers and builds canonical session scope")
    func grantSessionDraftValidationAndCanonicalScope() throws {
        var draft = GrantSessionDraft(
            clientLabel: " Example Agent ",
            clientId: "profile-1",
            clientBundleId: "com.example.agent",
            durationMinutes: 30,
            usdcCap: " 50.5 ",
            ethCap: "",
            allowedTargets: "0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD, abcdefabcdefabcdefabcdefabcdefabcdefabcd",
            intent: " Rebalance treasury ",
            selectedChains: [8453, 1]
        )

        #expect(draft.validationMessage == nil)
        #expect(draft.canGrant)
        #expect(draft.parsedTargets == [
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        ])

        let startedAt = Date(timeIntervalSince1970: 1_710_000_000)
        let session = try #require(draft.makeSession(startedAt: startedAt))
        #expect(session.clientLabel == "Example Agent")
        #expect(session.clientId == "profile-1")
        #expect(session.clientBundleId == "com.example.agent")
        #expect(session.chains == [1, 8453])
        #expect(session.usdcLimit == 50.5)
        #expect(session.ethLimit == nil)
        #expect(session.allowedTargets == draft.parsedTargets)
        #expect(session.startedAt == startedAt)
        #expect(session.expiresAt == startedAt.addingTimeInterval(1_800))
        #expect(session.intent == "Rebalance treasury")

        draft.clientLabel = "   "
        #expect(draft.validationMessage == "Choose an agent before granting a session.")
        draft.clientLabel = "Example Agent"
        draft.selectedChains = []
        #expect(draft.validationMessage == "Select at least one allowed chain.")
        draft.selectedChains = [8453]
        draft.usdcCap = "-1"
        #expect(draft.validationMessage == "USDC cap must be empty or a non-negative number.")
        draft.usdcCap = ""
        draft.ethCap = "nan"
        #expect(draft.validationMessage == "ETH cap must be empty or a non-negative number.")
        draft.ethCap = ""
        draft.allowedTargets = "0x123"
        #expect(draft.validationMessage == "Allowed targets must be comma-separated 20-byte Ethereum addresses.")
        #expect(draft.makeSession(startedAt: startedAt) == nil)

        #expect(GrantSessionDraft.grantResultError(didPersist: true) == nil)
        #expect(GrantSessionDraft.grantResultError(didPersist: false) == "Session grant could not be saved. Signing was not widened.")
    }
}

@MainActor
@Suite("SessionStore — reconcile loop integration", .serialized)
struct SessionStoreReconcileTests {

    @MainActor
    @Test("Load failure marks session snapshot unhealthy and fail-closed")
    func loadFailureMarksSnapshotUnhealthy() {
        SessionSnapshotStore.shared.clearUnhealthy()
        SessionSnapshotStore.shared.update([])
        defer {
            SessionSnapshotStore.shared.clearUnhealthy()
            SessionSnapshotStore.shared.update([])
        }

        let store = SessionStore(keychain: FailingReadKeychainBackend())

        #expect(store.sessions.isEmpty)
        #expect(SessionSnapshotStore.shared.storageHealthFailure() == "Session storage is unavailable")
        #expect(SessionSnapshotStore.shared.anyActive() == false)
    }

    @MainActor
    @Test("Corrupt persisted sessions mark snapshot unhealthy and do not revive stale data")
    func corruptPersistedSessionsMarkSnapshotUnhealthy() {
        let keychain = MockKeychainBackend()
        keychain.write(account: "sessions.active", data: Data("not json".utf8))
        SessionSnapshotStore.shared.clearUnhealthy()
        SessionSnapshotStore.shared.update([])
        defer {
            SessionSnapshotStore.shared.clearUnhealthy()
            SessionSnapshotStore.shared.update([])
        }

        let store = SessionStore(keychain: keychain)

        #expect(store.sessions.isEmpty)
        #expect(SessionSnapshotStore.shared.storageHealthFailure() == "Session storage is corrupt")
        #expect(SessionSnapshotStore.shared.anyActive() == false)
    }

    @MainActor
    @Test("Expired persisted sessions are pruned on load and persisted")
    func expiredPersistedSessionsArePrunedOnLoad() throws {
        let keychain = MockKeychainBackend()
        let active = AgentSession(
            clientLabel: "Active", clientId: "active", clientBundleId: "com.active",
            chains: [8453], usdcLimit: nil, ethLimit: nil, allowedTargets: [],
            expiresAt: Date().addingTimeInterval(900), intent: nil
        )
        let expired = AgentSession(
            clientLabel: "Expired", clientId: "expired", clientBundleId: "com.expired",
            chains: [1], usdcLimit: nil, ethLimit: nil, allowedTargets: [],
            expiresAt: Date().addingTimeInterval(-900), intent: nil
        )
        let stored = try JSONEncoder().encode([active, expired])
        keychain.write(account: "sessions.active", data: stored)
        SessionSnapshotStore.shared.clearUnhealthy()
        SessionSnapshotStore.shared.update([])
        defer {
            SessionSnapshotStore.shared.clearUnhealthy()
            SessionSnapshotStore.shared.update([])
        }

        let store = SessionStore(keychain: keychain)
        let persisted = try #require(keychain.read(account: "sessions.active"))
        let decoded = try JSONDecoder().decode([AgentSession].self, from: persisted)

        #expect(store.sessions.map(\.id) == [active.id])
        #expect(SessionSnapshotStore.shared.storageHealthFailure() == nil)
        #expect(SessionSnapshotStore.shared.activeSessions(forBundleId: "com.active").map(\.id) == [active.id])
        #expect(decoded.map(\.id) == [active.id])
    }

    @Test("Reconcile downgrades, revokes, and preserves unchanged sessions in one pass")
    func mixedReconcile() {
        let store = SessionStore(keychain: MockKeychainBackend())
        let toDowngrade = AgentSession(
            clientLabel: "A", clientId: "a", clientBundleId: "com.a",
            chains: [8453, 1], usdcLimit: nil, ethLimit: nil, allowedTargets: [],
            expiresAt: Date().addingTimeInterval(900), intent: nil
        )
        let toRevoke = AgentSession(
            clientLabel: "B", clientId: "b", clientBundleId: "com.b",
            chains: [42_161], usdcLimit: nil, ethLimit: nil, allowedTargets: [],
            expiresAt: Date().addingTimeInterval(900), intent: nil
        )
        let unchanged = AgentSession(
            clientLabel: "C", clientId: "c", clientBundleId: "com.c",
            chains: [8453], usdcLimit: nil, ethLimit: nil, allowedTargets: [],
            expiresAt: Date().addingTimeInterval(900), intent: nil
        )
        store.grant(toDowngrade)
        store.grant(toRevoke)
        store.grant(unchanged)

        let entries = store.reconcile { _ in
            RuleConfig(
                userOpPosture: .enforceRulesAndAutoSign,
                allowedHours: nil,
                allowedChains: [8453],
                allowedTargets: nil,
                allowedSelectors: nil,
                denySelectors: nil,
                allowedClients: nil,
                rateLimits: [],
                spendingLimits: []
            )
        }

        #expect(entries.count == 3)
        // Downgraded session survives, with chains narrowed.
        let surviving = store.sessions
        #expect(surviving.count == 2)
        let downgradedAfter = surviving.first { $0.id == toDowngrade.id }
        #expect(downgradedAfter?.chains == [8453])
        // Revoked session is gone.
        #expect(surviving.contains(where: { $0.id == toRevoke.id }) == false)
        // Unchanged session still present, unchanged.
        let unchangedAfter = surviving.first { $0.id == unchanged.id }
        #expect(unchangedAfter?.chains == [8453])
    }

    @Test("Reconcile with no policy change returns unchanged for every session")
    func noChange() {
        let store = SessionStore(keychain: MockKeychainBackend())
        store.grant(AgentSession(
            clientLabel: "A", clientId: "a", clientBundleId: "com.a",
            chains: [8453], usdcLimit: nil, ethLimit: nil, allowedTargets: [],
            expiresAt: Date().addingTimeInterval(900), intent: nil
        ))
        let entries = store.reconcile { _ in RuleConfig.default }
        #expect(entries.allSatisfy { $0.outcome == .unchanged })
        #expect(store.sessions.count == 1)
    }

    @Test("Reconcile dispatches per-session lookup keyed by bundle id")
    func perBundleDispatch() {
        let store = SessionStore(keychain: MockKeychainBackend())
        store.grant(AgentSession(
            clientLabel: "A", clientId: "a", clientBundleId: "com.a",
            chains: [8453], usdcLimit: nil, ethLimit: nil, allowedTargets: [],
            expiresAt: Date().addingTimeInterval(900), intent: nil
        ))
        store.grant(AgentSession(
            clientLabel: "B", clientId: "b", clientBundleId: "com.b",
            chains: [8453], usdcLimit: nil, ethLimit: nil, allowedTargets: [],
            expiresAt: Date().addingTimeInterval(900), intent: nil
        ))
        var seen: [String?] = []
        _ = store.reconcile { bundleId in
            seen.append(bundleId)
            return RuleConfig.default
        }
        #expect(Set(seen.compactMap { $0 }) == Set(["com.a", "com.b"]))
    }

    @Test("Active session row presentation and revoke persistence are deterministic")
    func activeSessionPresentationAndRevokePersistence() throws {
        let now = Date(timeIntervalSince1970: 1_710_000_000)
        let presentationSession = AgentSession(
            clientLabel: "Treasury Agent",
            clientId: "treasury",
            clientBundleId: "com.example.treasury",
            chains: [8453, 1],
            usdcLimit: 50,
            ethLimit: 0.25,
            allowedTargets: [],
            startedAt: now,
            expiresAt: now.addingTimeInterval(3_725),
            intent: "Rebalance"
        )

        let presentation = ActiveSessionRowPresentation.make(presentationSession, now: now)
        #expect(presentation.id == presentationSession.id)
        #expect(presentation.clientLabel == "Treasury Agent")
        #expect(presentation.remainingShort == "1h")
        #expect(presentation.scopeSummary == "Base, Ethereum · 50 USDC · 0.25 ETH · 1h 2m")
        #expect(presentation.revokeButtonTitle == "Revoke")
        #expect(ActiveSessionRowPresentation.make(presentationSession, now: now.addingTimeInterval(3_710)).remainingShort == "15s")
        #expect(ActiveSessionRowPresentation.revokeErrorMessage(showExpiredMessage: false) == "Could not revoke this session. Try again.")
        #expect(ActiveSessionRowPresentation.revokeErrorMessage(showExpiredMessage: true) == "Session expired, but removal could not be saved.")

        SessionSnapshotStore.shared.clearUnhealthy()
        SessionSnapshotStore.shared.update([])
        defer {
            SessionSnapshotStore.shared.clearUnhealthy()
            SessionSnapshotStore.shared.update([])
        }

        let active = AgentSession(
            clientLabel: "Treasury Agent",
            clientId: "treasury",
            clientBundleId: "com.example.treasury",
            chains: [8453, 1],
            usdcLimit: 50,
            ethLimit: 0.25,
            allowedTargets: [],
            startedAt: Date(),
            expiresAt: Date().addingTimeInterval(3_600),
            intent: "Rebalance"
        )
        let successKeychain = MockKeychainBackend()
        let successStore = SessionStore(keychain: successKeychain)
        #expect(successStore.grant(active) == true)
        #expect(successStore.revoke(active.id) == true)
        #expect(successStore.sessions.isEmpty)
        #expect(successKeychain.read(account: "sessions.active") == nil)
        #expect(SessionSnapshotStore.shared.activeSessions(forBundleId: "com.example.treasury").isEmpty)

        let failingKeychain = DeleteFailingSessionKeychainBackend()
        let failingStore = SessionStore(keychain: failingKeychain)
        #expect(failingStore.grant(active) == true)
        #expect(failingStore.revoke(active.id) == false)
        #expect(failingStore.sessions.map(\.id) == [active.id])
        #expect(SessionSnapshotStore.shared.storageHealthFailure() == "Session storage delete failed")
        #expect(SessionSnapshotStore.shared.activeSessions(forBundleId: "com.example.treasury").map(\.id) == [active.id])
        let persisted = try #require(failingKeychain.read(account: "sessions.active"))
        let decoded = try JSONDecoder().decode([AgentSession].self, from: persisted)
        #expect(decoded.map(\.id) == [active.id])
    }
}
