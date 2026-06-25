import Foundation

nonisolated struct WalletGroupScenarioMemberSnapshot: Codable, Equatable, Sendable {
    let id: String
    let label: String
    let avatar: String
    let statusLabel: String
    let statusTone: String

    init(_ row: WalletGroupMemberRowPresentation) {
        id = row.id
        label = row.label
        avatar = row.avatar
        statusLabel = row.statusLabel
        switch row.statusTone {
        case .ok: statusTone = "ok"
        case .warn: statusTone = "warn"
        case .bad: statusTone = "bad"
        }
    }
}

nonisolated struct WalletGroupScenarioUnsatisfiableSnapshot: Codable, Equatable, Sendable {
    let id: String
    let label: String
    let reasons: [String]

    init(_ row: WalletGroupUnsatisfiableMemberPresentation) {
        id = row.id
        label = row.label
        reasons = row.reasons
    }
}

nonisolated struct WalletGroupScenarioMergedPolicySnapshot: Codable, Equatable, Sendable {
    let isUnsatisfiable: Bool
    let reasons: [String]
    let flattenedAllowedHoursStart: Int?
    let flattenedAllowedHoursEnd: Int?
    let flattenedAllowedChains: [Int]?
    let flattenedAllowedTargets: [String: [String]]?
    let flattenedRateLimitCount: Int
    let flattenedSpendingLimitCount: Int

    init(_ merged: MergedPolicy) {
        let flattened = merged.toRuleConfig()
        isUnsatisfiable = merged.isUnsatisfiable
        reasons = merged.unsatisfiabilityReasons
        flattenedAllowedHoursStart = flattened.allowedHours?.start
        flattenedAllowedHoursEnd = flattened.allowedHours?.end
        flattenedAllowedChains = flattened.allowedChains
        flattenedAllowedTargets = flattened.allowedTargets
        flattenedRateLimitCount = flattened.rateLimits.count
        flattenedSpendingLimitCount = flattened.spendingLimits.count
    }
}

nonisolated struct WalletGroupScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let title: String
    let badgeLabel: String
    let membersTitle: String
    let membersSubtitle: String
    let emptyMembersTitle: String?
    let emptyMembersMessage: String?
    let showsAddAgentControl: Bool
    let showsEditScopeControls: Bool
    let memberRows: [WalletGroupScenarioMemberSnapshot]
    let unsatisfiableTitle: String?
    let unsatisfiableMessage: String?
    let unsatisfiableMembers: [WalletGroupScenarioUnsatisfiableSnapshot]
    let emptyGroupTitle: String
    let emptyGroupMembersTitle: String?
    let emptyGroupMembersMessage: String?
    let compatibleMerge: WalletGroupScenarioMergedPolicySnapshot
    let conflictingMerge: WalletGroupScenarioMergedPolicySnapshot
    let activeMemberIds: [String]
    let ownerKeyTag: String
    let agentKeyTag: String
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct WalletGroupScenarioEncodedProbeResponse: Sendable {
    let scenario: String
    let passed: Bool
    let diagnosticContext: [String: String]
    let data: Data
}

nonisolated enum WalletGroupScenarioProbe {
    static let overviewScenario = "overview"

    static func run(scenario: String) throws -> WalletGroupScenarioEncodedProbeResponse {
        let encoder = JSONEncoder()
        switch scenario {
        case overviewScenario:
            let response = overview()
            return WalletGroupScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "memberRows": String(response.memberRows.count),
                    "unsatisfiableMembers": String(response.unsatisfiableMembers.count),
                    "activeMembers": String(response.activeMemberIds.count),
                    "conflictingReasons": String(response.conflictingMerge.reasons.count),
                ],
                data: try encoder.encode(response)
            )
        default:
            throw NSError(
                domain: "com.bastion.wallet-group-scenario-probe",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey: "Unknown wallet-group scenario: \(scenario). Use \(overviewScenario)."
                ]
            )
        }
    }

    static func overview() -> WalletGroupScenarioProbeResponse {
        var sharedRules = RuleConfig.default
        sharedRules.allowedHours = AllowedHours(start: 9, end: 12)
        sharedRules.allowedChains = [1]
        sharedRules.allowedTargets = [
            "1": ["0x1111111111111111111111111111111111111111"]
        ]

        var conflictingScopedRules = RuleConfig.default
        conflictingScopedRules.allowedHours = AllowedHours(start: 14, end: 18)
        conflictingScopedRules.allowedChains = [8453]
        conflictingScopedRules.allowedTargets = [
            "1": ["0x2222222222222222222222222222222222222222"]
        ]

        var compatibleScopedRules = RuleConfig.default
        compatibleScopedRules.allowedHours = AllowedHours(start: 10, end: 11)
        compatibleScopedRules.allowedChains = [1, 8453]
        compatibleScopedRules.allowedTargets = [
            "1": [
                "0x1111111111111111111111111111111111111111",
                "0x3333333333333333333333333333333333333333",
            ]
        ]

        let installed = AgentMembership(
            id: "installed",
            label: "Alpha Agent",
            keyTag: WalletGroup.makeAgentKeyTag(groupId: "group-1", memberId: "installed"),
            scopedRules: conflictingScopedRules,
            installStatus: .installed(txHash: "0xaaa")
        )
        let pending = AgentMembership(
            id: "pending",
            label: nil,
            keyTag: WalletGroup.makeAgentKeyTag(groupId: "group-1", memberId: "pending"),
            scopedRules: compatibleScopedRules,
            installStatus: .pending
        )
        let revoked = AgentMembership(
            id: "revoked",
            label: "Retired Bot",
            keyTag: WalletGroup.makeAgentKeyTag(groupId: "group-1", memberId: "revoked"),
            scopedRules: conflictingScopedRules,
            installStatus: .revoked(txHash: "0xbbb")
        )
        let group = WalletGroup(
            id: "group-1",
            label: "",
            sharedRules: sharedRules,
            members: [installed, pending, revoked]
        )
        let presentation = WalletGroupPanelPresentation.make(group)
        let emptyPresentation = WalletGroupPanelPresentation.make(WalletGroup(id: "empty", label: "Ops", members: []))
        let compatibleMerge = MergedPolicyComposer.compose(group: sharedRules, member: compatibleScopedRules)
        let conflictingMerge = MergedPolicyComposer.compose(group: sharedRules, member: conflictingScopedRules)
        let ownerKeyTag = WalletGroup.makeOwnerKeyTag(groupId: "ABC-123")
        let agentKeyTag = WalletGroup.makeAgentKeyTag(groupId: "ABC-123", memberId: "DEF-456")

        let checks = [
            SettingsScenarioProbeCheck(name: "fallback title and shared badge", passed: presentation.title == "Wallet Group" && presentation.badgeLabel == "Shared smart account"),
            SettingsScenarioProbeCheck(name: "member section copy", passed: presentation.membersTitle == "Members" && presentation.membersSubtitle == "Owner is sudo. Each agent has its own validator."),
            SettingsScenarioProbeCheck(name: "management controls hidden", passed: !presentation.showsAddAgentControl && !presentation.showsEditScopeControls),
            SettingsScenarioProbeCheck(name: "member status rows", passed: presentation.memberRows.map(\.statusLabel) == ["Installed", "Pending", "Revoked"]),
            SettingsScenarioProbeCheck(name: "member status tones", passed: presentation.memberRows.map(\.statusTone) == [.ok, .warn, .bad]),
            SettingsScenarioProbeCheck(name: "empty group copy", passed: emptyPresentation.emptyMembersTitle == "No agent members" && emptyPresentation.emptyMembersMessage == "Pair an agent into this wallet group before it can sign for the shared smart account."),
            SettingsScenarioProbeCheck(name: "revoked members excluded from conflict banner", passed: presentation.unsatisfiableMembers.map(\.id) == ["installed"]),
            SettingsScenarioProbeCheck(name: "unsatisfiable banner copy", passed: presentation.unsatisfiableTitle == "Unsatisfiable merged policy" && presentation.unsatisfiableMessage == "These members will be denied any signing request because their scoped rules conflict with the group's shared rules."),
            SettingsScenarioProbeCheck(name: "conflict reasons", passed: conflictingMerge.unsatisfiabilityReasons == [
                "Wallet group and agent allowed-hours have no overlap",
                "Wallet group and agent allowed chains have no overlap",
                "Wallet group and agent allowed targets disagree on 1",
            ]),
            SettingsScenarioProbeCheck(
                name: "compatible merge narrows scope",
                passed: {
                    let flattened = compatibleMerge.toRuleConfig()
                    return !compatibleMerge.isUnsatisfiable
                        && flattened.allowedHours?.start == 10
                        && flattened.allowedHours?.end == 11
                        && flattened.allowedChains == [1]
                        && flattened.allowedTargets == ["1": ["0x1111111111111111111111111111111111111111"]]
                }()
            ),
            SettingsScenarioProbeCheck(name: "active members exclude pending and revoked", passed: group.activeMembers.map(\.id) == ["installed"]),
            SettingsScenarioProbeCheck(name: "key tag derivation lowercases ids", passed: ownerKeyTag == "com.bastion.walletgroup.abc-123.owner" && agentKeyTag == "com.bastion.walletgroup.abc-123.agent.def-456"),
        ]

        return WalletGroupScenarioProbeResponse(
            scenario: overviewScenario,
            passed: checks.allSatisfy { $0.passed },
            title: presentation.title,
            badgeLabel: presentation.badgeLabel,
            membersTitle: presentation.membersTitle,
            membersSubtitle: presentation.membersSubtitle,
            emptyMembersTitle: presentation.emptyMembersTitle,
            emptyMembersMessage: presentation.emptyMembersMessage,
            showsAddAgentControl: presentation.showsAddAgentControl,
            showsEditScopeControls: presentation.showsEditScopeControls,
            memberRows: presentation.memberRows.map(WalletGroupScenarioMemberSnapshot.init),
            unsatisfiableTitle: presentation.unsatisfiableTitle,
            unsatisfiableMessage: presentation.unsatisfiableMessage,
            unsatisfiableMembers: presentation.unsatisfiableMembers.map(WalletGroupScenarioUnsatisfiableSnapshot.init),
            emptyGroupTitle: emptyPresentation.title,
            emptyGroupMembersTitle: emptyPresentation.emptyMembersTitle,
            emptyGroupMembersMessage: emptyPresentation.emptyMembersMessage,
            compatibleMerge: WalletGroupScenarioMergedPolicySnapshot(compatibleMerge),
            conflictingMerge: WalletGroupScenarioMergedPolicySnapshot(conflictingMerge),
            activeMemberIds: group.activeMembers.map(\.id),
            ownerKeyTag: ownerKeyTag,
            agentKeyTag: agentKeyTag,
            checks: checks
        )
    }
}
