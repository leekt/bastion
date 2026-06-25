import Testing
@testable import bastion
import Foundation

// PR3 tests: MergedPolicyComposer is the canonical wallet-group ∩ member
// merge. Each field's typed `MergedConstraint` makes overlap, single-side
// restriction, and empty-intersection cases distinguishable — the
// pre-PR3 sentinels (`AllowedHours(0,0)`, `[]` for clients, etc.) made
// these cases visually identical to "intentional empty" values.

private func makeRules(
    allowedHours: AllowedHours? = nil,
    allowedChains: [Int]? = nil,
    allowedTargets: [String: [String]]? = nil,
    allowedSelectors: [String: [String]]? = nil,
    denySelectors: [String]? = nil,
    allowedClients: [AllowedClient]? = nil,
    rateLimits: [RateLimitRule] = [],
    spendingLimits: [SpendingLimitRule] = []
) -> RuleConfig {
    RuleConfig(
        userOpPosture: .enforceRulesAndAutoSign,
        allowedHours: allowedHours,
        allowedChains: allowedChains,
        allowedTargets: allowedTargets,
        allowedSelectors: allowedSelectors,
        denySelectors: denySelectors,
        allowedClients: allowedClients,
        rateLimits: rateLimits,
        spendingLimits: spendingLimits
    )
}

@Suite("MergedPolicy — typed unsatisfiability")
struct MergedPolicyTests {

    // MARK: - Hours

    @Test("Same-day overlapping hour windows produce a restricted intersection")
    func hoursOverlap() {
        let merged = MergedPolicyComposer.compose(
            group: makeRules(allowedHours: AllowedHours(start: 9, end: 18)),
            member: makeRules(allowedHours: AllowedHours(start: 12, end: 14))
        )
        guard case .restricted(let h) = merged.allowedHours else {
            Issue.record("Expected .restricted, got \(merged.allowedHours)")
            return
        }
        #expect(h.start == 12 && h.end == 14)
        #expect(merged.isUnsatisfiable == false)
    }

    @Test("Same-day non-overlapping hours produce an unsatisfiable constraint")
    func hoursNoOverlap() {
        let merged = MergedPolicyComposer.compose(
            group: makeRules(allowedHours: AllowedHours(start: 9, end: 12)),
            member: makeRules(allowedHours: AllowedHours(start: 14, end: 18))
        )
        guard case .unsatisfiable(let reason) = merged.allowedHours else {
            Issue.record("Expected .unsatisfiable, got \(merged.allowedHours)")
            return
        }
        #expect(reason.contains("no overlap"))
        #expect(merged.isUnsatisfiable == true)
        #expect(merged.unsatisfiabilityReasons.count == 1)
    }

    @Test("One-sided hours restriction falls through to .restricted")
    func hoursOneSided() {
        let merged = MergedPolicyComposer.compose(
            group: makeRules(allowedHours: AllowedHours(start: 9, end: 18)),
            member: makeRules() // no allowedHours
        )
        guard case .restricted(let h) = merged.allowedHours else {
            Issue.record("Expected .restricted, got \(merged.allowedHours)")
            return
        }
        #expect(h.start == 9 && h.end == 18)
    }

    @Test("Both sides nil hours → unrestricted")
    func hoursBothNil() {
        let merged = MergedPolicyComposer.compose(
            group: makeRules(),
            member: makeRules()
        )
        guard case .unrestricted = merged.allowedHours else {
            Issue.record("Expected .unrestricted, got \(merged.allowedHours)")
            return
        }
    }

    // MARK: - Chains

    @Test("allowedChains intersects to a non-empty set")
    func chainsOverlap() {
        let merged = MergedPolicyComposer.compose(
            group: makeRules(allowedChains: [1, 8453, 11155111]),
            member: makeRules(allowedChains: [8453, 42161])
        )
        guard case .restricted(let chains) = merged.allowedChains else {
            Issue.record("Expected .restricted, got \(merged.allowedChains)")
            return
        }
        #expect(chains == [8453])
    }

    @Test("allowedChains disjoint sets → unsatisfiable")
    func chainsDisjoint() {
        let merged = MergedPolicyComposer.compose(
            group: makeRules(allowedChains: [1, 8453]),
            member: makeRules(allowedChains: [42161, 10])
        )
        guard case .unsatisfiable = merged.allowedChains else {
            Issue.record("Expected .unsatisfiable, got \(merged.allowedChains)")
            return
        }
        #expect(merged.unsatisfiabilityReasons.contains { $0.contains("allowed chains") })
    }

    // MARK: - allowedClients

    @Test("allowedClients intersects by bundleId, case-insensitive")
    func clientsOverlap() {
        let group = makeRules(allowedClients: [
            AllowedClient(id: "1", bundleId: "Com.Cursor.App", label: nil),
            AllowedClient(id: "2", bundleId: "com.anthropic.claude-code", label: nil),
        ])
        let member = makeRules(allowedClients: [
            AllowedClient(id: "3", bundleId: "com.anthropic.claude-code", label: nil),
        ])
        let merged = MergedPolicyComposer.compose(group: group, member: member)
        guard case .restricted(let clients) = merged.allowedClients else {
            Issue.record("Expected .restricted, got \(merged.allowedClients)")
            return
        }
        #expect(clients.count == 1)
        #expect(clients.first?.bundleId.lowercased() == "com.anthropic.claude-code")
    }

    @Test("allowedClients disjoint → unsatisfiable")
    func clientsDisjoint() {
        let group = makeRules(allowedClients: [
            AllowedClient(id: "1", bundleId: "com.cursor.app", label: nil),
        ])
        let member = makeRules(allowedClients: [
            AllowedClient(id: "2", bundleId: "com.anthropic.claude-code", label: nil),
        ])
        let merged = MergedPolicyComposer.compose(group: group, member: member)
        guard case .unsatisfiable = merged.allowedClients else {
            Issue.record("Expected .unsatisfiable, got \(merged.allowedClients)")
            return
        }
    }

    // MARK: - Targets per chain key

    @Test("allowedTargets intersects per chain — case-insensitive matching")
    func targetsOverlap() {
        let merged = MergedPolicyComposer.compose(
            group: makeRules(allowedTargets: ["8453": ["0xAAA", "0xBBB"]]),
            member: makeRules(allowedTargets: ["8453": ["0xbbb", "0xCCC"]])
        )
        guard case .restricted(let dict) = merged.allowedTargets else {
            Issue.record("Expected .restricted, got \(merged.allowedTargets)")
            return
        }
        #expect(dict["8453"]?.map { $0.lowercased() } == ["0xbbb"])
    }

    @Test("allowedTargets disjoint per chain → unsatisfiable with key listed")
    func targetsDisjointPerChain() {
        let merged = MergedPolicyComposer.compose(
            group: makeRules(allowedTargets: ["8453": ["0xAAA"]]),
            member: makeRules(allowedTargets: ["8453": ["0xBBB"]])
        )
        guard case .unsatisfiable(let reason) = merged.allowedTargets else {
            Issue.record("Expected .unsatisfiable, got \(merged.allowedTargets)")
            return
        }
        #expect(reason.contains("8453"))
    }

    @Test("allowedTargets — single chain restriction one-sided falls through")
    func targetsOneSidedPerChain() {
        let merged = MergedPolicyComposer.compose(
            group: makeRules(allowedTargets: ["8453": ["0xAAA"]]),
            member: makeRules(allowedTargets: ["1": ["0xBBB"]])
        )
        // No conflict — each chain only restricted on one side.
        guard case .restricted(let dict) = merged.allowedTargets else {
            Issue.record("Expected .restricted, got \(merged.allowedTargets)")
            return
        }
        #expect(dict.keys.sorted() == ["1", "8453"])
        #expect(merged.isUnsatisfiable == false)
    }

    // MARK: - Multiple unsatisfiable fields stack

    @Test("Multiple unsatisfiable fields surface independently in unsatisfiabilityReasons")
    func multipleUnsatisfiable() {
        let group = makeRules(
            allowedHours: AllowedHours(start: 9, end: 12),
            allowedChains: [1],
            allowedClients: [AllowedClient(id: "1", bundleId: "com.x", label: nil)]
        )
        let member = makeRules(
            allowedHours: AllowedHours(start: 14, end: 18),
            allowedChains: [42161],
            allowedClients: [AllowedClient(id: "2", bundleId: "com.y", label: nil)]
        )
        let merged = MergedPolicyComposer.compose(group: group, member: member)
        // 3 fields conflict → 3 reasons.
        #expect(merged.unsatisfiabilityReasons.count == 3)
        #expect(merged.isUnsatisfiable == true)
    }

    // MARK: - toRuleConfig sentinel encoding

    @Test("Unsatisfiable hours flatten to AllowedHours(0, 0) sentinel")
    func unsatisfiableHoursFlattenToSentinel() {
        let merged = MergedPolicyComposer.compose(
            group: makeRules(allowedHours: AllowedHours(start: 9, end: 12)),
            member: makeRules(allowedHours: AllowedHours(start: 14, end: 18))
        )
        let flattened = merged.toRuleConfig()
        #expect(flattened.allowedHours?.start == 0)
        #expect(flattened.allowedHours?.end == 0)
    }

    @Test("Unsatisfiable allowedClients flatten to empty array sentinel (deny-all)")
    func unsatisfiableClientsFlatten() {
        let group = makeRules(allowedClients: [AllowedClient(id: "1", bundleId: "com.x", label: nil)])
        let member = makeRules(allowedClients: [AllowedClient(id: "2", bundleId: "com.y", label: nil)])
        let merged = MergedPolicyComposer.compose(group: group, member: member)
        let flattened = merged.toRuleConfig()
        #expect(flattened.allowedClients?.isEmpty == true)
    }

    @Test("Unsatisfiable allowedTargets flatten to present empty dictionary sentinel")
    func unsatisfiableTargetsFlattenToDenyAllSentinel() {
        let group = makeRules(allowedTargets: ["8453": ["0xAAA"]])
        let member = makeRules(allowedTargets: ["8453": ["0xBBB"]])
        let merged = MergedPolicyComposer.compose(group: group, member: member)
        let flattened = merged.toRuleConfig()
        #expect(flattened.allowedTargets?.isEmpty == true)
    }

    @Test("Unsatisfiable allowedSelectors flatten to present empty dictionary sentinel")
    func unsatisfiableSelectorsFlattenToDenyAllSentinel() {
        let group = makeRules(allowedSelectors: ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": ["0x095ea7b3"]])
        let member = makeRules(allowedSelectors: ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": ["0xa9059cbb"]])
        let merged = MergedPolicyComposer.compose(group: group, member: member)
        let flattened = merged.toRuleConfig()
        #expect(flattened.allowedSelectors?.isEmpty == true)
    }

    // MARK: - Posture merge (delegated to composer)

    @Test("Posture merge: any side requiring approval forces approval")
    func posturesMergeStricter() {
        let group = makeRules()
        var member = makeRules()
        member.userOpPosture = .enforceRulesAndRequireApproval
        let merged = MergedPolicyComposer.compose(group: group, member: member)
        #expect(merged.userOpPosture == .enforceRulesAndRequireApproval)
    }

    @Test("Posture merge: skip-rules + auto-sign → enforceRulesAndRequireApproval")
    func posturesSkipPlusAuto() {
        var group = makeRules()
        group.userOpPosture = .requireApprovalWithoutRuleEvaluation
        var member = makeRules()
        member.userOpPosture = .enforceRulesAndAutoSign
        let merged = MergedPolicyComposer.compose(group: group, member: member)
        // Group asks "always approve"; member asks "evaluate then sign". Strict-OR:
        // evaluate=true, popup=true → enforceRulesAndRequireApproval. Both sides
        // get what they wanted: rules are evaluated AND popup is shown.
        #expect(merged.userOpPosture == .enforceRulesAndRequireApproval)
    }

    /// PR follow-up #53: pin the full 3×3 truth table for `stricterPosture`.
    /// The previous formulation (`SigningPosture.from(strict-OR booleans)`)
    /// only landed in a valid case because (evaluates=false, popup=false)
    /// is unreachable under strict-OR; an exhaustive switch makes that a
    /// compile-time property. This test guards every cell so any future
    /// behavioural change is a red CI run, not a silent semantic shift.
    @Test("Posture merge truth table is exhaustive and stable")
    func postureMergeTruthTable() {
        let auto = SigningPosture.enforceRulesAndAutoSign
        let approval = SigningPosture.enforceRulesAndRequireApproval
        let skip = SigningPosture.requireApprovalWithoutRuleEvaluation

        // (a, b, expected) — read as "merging a with b yields expected".
        let table: [(SigningPosture, SigningPosture, SigningPosture)] = [
            (auto, auto, auto),
            (auto, approval, approval),
            (approval, auto, approval),
            (approval, approval, approval),
            (auto, skip, approval),
            (skip, auto, approval),
            (approval, skip, approval),
            (skip, approval, approval),
            (skip, skip, skip),
        ]
        for (a, b, expected) in table {
            #expect(MergedPolicyComposer.stricterPosture(a, b) == expected)
        }
    }

    @Test("Posture merge is symmetric (commutative)")
    func postureMergeSymmetric() {
        for a in SigningPosture.allCases {
            for b in SigningPosture.allCases {
                #expect(
                    MergedPolicyComposer.stricterPosture(a, b)
                        == MergedPolicyComposer.stricterPosture(b, a)
                )
            }
        }
    }
}
