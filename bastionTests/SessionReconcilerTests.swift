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

    @Test("Empty allowedClients (deny-all sentinel) does NOT skip the gate")
    func emptyAllowlistFallsThrough() {
        // Empty allowedClients is the unsatisfiable-merge sentinel — but
        // *fields* in RuleConfig only deny if the validator sees them.
        // The reconciler treats empty as "no client gate to enforce" so
        // it doesn't double-deny here; the validator will block any
        // sign request because of the empty list. The session just
        // doesn't get revoked by *the bundle gate* alone.
        let s = session(bundleId: "com.example.agent")
        let r = rules(allowedClients: [])
        let outcome = SessionReconciler.reconcile(s, against: r)
        #expect(outcome == .unchanged)
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
}

@MainActor
@Suite("SessionStore — reconcile loop integration")
struct SessionStoreReconcileTests {

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
}
