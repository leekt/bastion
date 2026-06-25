import Foundation
import Testing
@testable import bastion

// MARK: - Pure Data-Model Tests

@Suite("Wallet Group Models")
struct WalletGroupModelTests {
    @Test("owner and agent key tags derive from group + member ids")
    func keyTagDerivation() {
        let groupId = "ABC-123"
        let memberId = "DEF-456"

        let ownerTag = WalletGroup.makeOwnerKeyTag(groupId: groupId)
        let agentTag = WalletGroup.makeAgentKeyTag(groupId: groupId, memberId: memberId)

        #expect(ownerTag == "com.bastion.walletgroup.abc-123.owner")
        #expect(agentTag == "com.bastion.walletgroup.abc-123.agent.def-456")
        #expect(ownerTag != agentTag)
    }

    @Test("activeMembers includes only installed members")
    func activeMembersIncludesOnlyInstalledMembers() {
        let active1 = AgentMembership(
            id: "m1",
            keyTag: "k1",
            installStatus: .installed(txHash: "0xabc")
        )
        let pending = AgentMembership(
            id: "m2",
            keyTag: "k2",
            installStatus: .pending
        )
        let revoked = AgentMembership(
            id: "m3",
            keyTag: "k3",
            installStatus: .revoked(txHash: "0xdead")
        )

        let group = WalletGroup(
            label: "Team",
            members: [active1, pending, revoked]
        )

        #expect(group.members.count == 3)
        #expect(group.activeMembers.count == 1)
        #expect(group.activeMembers.map(\.id) == ["m1"])
    }

    @Test("Wallet group panel presentation lists members, status, empty state, and policy warnings")
    func walletGroupPanelPresentationListsMembersAndPolicyWarnings() {
        var sharedRules = RuleConfig.default
        sharedRules.allowedHours = AllowedHours(start: 9, end: 12)
        sharedRules.allowedChains = [1]

        var conflictingScopedRules = RuleConfig.default
        conflictingScopedRules.allowedHours = AllowedHours(start: 14, end: 18)
        conflictingScopedRules.allowedChains = [8453]

        var compatibleScopedRules = RuleConfig.default
        compatibleScopedRules.allowedHours = AllowedHours(start: 10, end: 11)
        compatibleScopedRules.allowedChains = [1]

        let group = WalletGroup(
            id: "group-1",
            label: "",
            sharedRules: sharedRules,
            members: [
                AgentMembership(
                    id: "installed",
                    label: "Alpha Agent",
                    keyTag: "k1",
                    scopedRules: conflictingScopedRules,
                    installStatus: .installed(txHash: "0xaaa")
                ),
                AgentMembership(
                    id: "pending",
                    label: nil,
                    keyTag: "k2",
                    scopedRules: compatibleScopedRules,
                    installStatus: .pending
                ),
                AgentMembership(
                    id: "revoked",
                    label: "Retired Bot",
                    keyTag: "k3",
                    scopedRules: conflictingScopedRules,
                    installStatus: .revoked(txHash: "0xbbb")
                ),
            ]
        )

        let presentation = WalletGroupPanelPresentation.make(group)
        #expect(presentation.title == "Wallet Group")
        #expect(presentation.badgeLabel == "Shared smart account")
        #expect(presentation.membersTitle == "Members")
        #expect(presentation.membersSubtitle == "Owner is sudo. Each agent has its own validator.")
        #expect(presentation.emptyMembersTitle == nil)
        #expect(presentation.emptyMembersMessage == nil)
        #expect(presentation.showsAddAgentControl == false)
        #expect(presentation.showsEditScopeControls == false)
        #expect(presentation.memberRows == [
            WalletGroupMemberRowPresentation(
                id: "installed",
                label: "Alpha Agent",
                avatar: "A",
                statusLabel: "Installed",
                statusTone: .ok
            ),
            WalletGroupMemberRowPresentation(
                id: "pending",
                label: "Agent",
                avatar: "?",
                statusLabel: "Pending",
                statusTone: .warn
            ),
            WalletGroupMemberRowPresentation(
                id: "revoked",
                label: "Retired Bot",
                avatar: "R",
                statusLabel: "Revoked",
                statusTone: .bad
            ),
        ])
        #expect(presentation.unsatisfiableTitle == "Unsatisfiable merged policy")
        #expect(presentation.unsatisfiableMessage == "These members will be denied any signing request because their scoped rules conflict with the group's shared rules.")
        #expect(presentation.unsatisfiableMembers == [
            WalletGroupUnsatisfiableMemberPresentation(
                id: "installed",
                label: "Alpha Agent",
                reasons: [
                    "Wallet group and agent allowed-hours have no overlap",
                    "Wallet group and agent allowed chains have no overlap",
                ]
            )
        ])

        let empty = WalletGroupPanelPresentation.make(WalletGroup(id: "empty", label: "Ops", members: []))
        #expect(empty.title == "Ops")
        #expect(empty.memberRows.isEmpty)
        #expect(empty.emptyMembersTitle == "No agent members")
        #expect(empty.emptyMembersMessage == "Pair an agent into this wallet group before it can sign for the shared smart account.")
        #expect(empty.unsatisfiableTitle == nil)
        #expect(empty.unsatisfiableMessage == nil)
        #expect(empty.unsatisfiableMembers.isEmpty)
        #expect(WalletGroupMemberRowPresentation.make(group.members[0]).statusTone == .ok)
        #expect(WalletGroupMemberRowPresentation.make(group.members[1]).statusTone == .warn)
        #expect(WalletGroupMemberRowPresentation.make(group.members[2]).statusTone == .bad)
    }

    @Test("ValidatorInstallStatus round-trips through Codable")
    func installStatusCodable() throws {
        let cases: [ValidatorInstallStatus] = [
            .pending,
            .installed(txHash: "0xaaa"),
            .revoked(txHash: "0xbbb")
        ]

        for status in cases {
            let data = try JSONEncoder().encode(status)
            let decoded = try JSONDecoder().decode(ValidatorInstallStatus.self, from: data)
            #expect(decoded == status)
        }
    }

    @Test("AgentMembership round-trips through Codable with all fields")
    func agentMembershipCodable() throws {
        let member = AgentMembership(
            id: "member-1",
            clientProfileId: "profile-xyz",
            label: "Research bot",
            keyTag: "com.bastion.walletgroup.g1.agent.m1",
            scopedRules: .default,
            validatorAddress: "0x0000000000000000000000000000000000001234",
            installStatus: .installed(txHash: "0xfeed"),
            installedAt: Date(timeIntervalSince1970: 1_700_000_000),
            createdAt: Date(timeIntervalSince1970: 1_699_999_999)
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970

        let data = try encoder.encode(member)
        let decoded = try decoder.decode(AgentMembership.self, from: data)

        #expect(decoded.id == member.id)
        #expect(decoded.clientProfileId == member.clientProfileId)
        #expect(decoded.label == member.label)
        #expect(decoded.keyTag == member.keyTag)
        #expect(decoded.validatorAddress == member.validatorAddress)
        #expect(decoded.installStatus == member.installStatus)
        #expect(decoded.installedAt?.timeIntervalSince1970 == 1_700_000_000)
    }

    @Test("ClientProfile.isGroupMember is true only when both ids set")
    func clientProfileGroupMembership() {
        let plain = ClientProfile(bundleId: "com.example.cli", rules: .default)
        #expect(plain.isGroupMember == false)

        let partial = ClientProfile(
            bundleId: "com.example.cli",
            rules: .default,
            walletGroupId: "g1",
            membershipId: nil
        )
        #expect(partial.isGroupMember == false)

        let full = ClientProfile(
            bundleId: "com.example.cli",
            rules: .default,
            walletGroupId: "g1",
            membershipId: "m1"
        )
        #expect(full.isGroupMember == true)
    }

    @Test("validator uninstall preflight surfaces inline blocker before submission")
    func validatorUninstallPreflightSurfacesInlineBlocker() {
        let profile = ClientProfile(
            bundleId: "com.example.agent",
            rules: .default,
            walletGroupId: "group-1",
            membershipId: "member-1"
        )

        let missingGroup = ValidatorUninstallPreflight.evaluate(profile: profile, walletGroups: [])
        #expect(missingGroup == .blocked(message: ValidatorUninstallPreflight.missingWalletGroupMessage))

        let groupWithoutChain = WalletGroup(id: "group-1", label: "Team", chainIds: [])
        let missingChain = ValidatorUninstallPreflight.evaluate(profile: profile, walletGroups: [groupWithoutChain])
        #expect(missingChain == .blocked(message: ValidatorUninstallPreflight.missingWalletGroupMessage))

        let readyGroup = WalletGroup(id: "group-1", label: "Team", chainIds: [8453, 11155111])
        let ready = ValidatorUninstallPreflight.evaluate(profile: profile, walletGroups: [readyGroup])
        #expect(ready == .ready(groupId: "group-1", memberId: "member-1", chainId: 8453))

        #expect(ValidatorActionFeedback.revokeAuthCancelled == ValidatorActionFeedback(
            message: "Revoke cancelled.",
            isError: false
        ))
        #expect(ValidatorActionFeedback.noLocalKey(profileName: "Agent").isError == true)
        #expect(ValidatorActionFeedback.revokedLocalKey(profileName: "Agent") == ValidatorActionFeedback(
            message: "Revoked local key for Agent.",
            isError: false
        ))
        #expect(ValidatorActionFeedback.uninstallSubmitted(profileName: "Agent", chainName: "Base") == ValidatorActionFeedback(
            message: "Submitted validator uninstall for Agent on Base.",
            isError: false
        ))

        struct UninstallFailure: LocalizedError {
            var errorDescription: String? { "network down" }
        }
        #expect(ValidatorActionFeedback.uninstallFailed(UninstallFailure()) == ValidatorActionFeedback(
            message: "Uninstall failed: network down",
            isError: true
        ))
    }

    @Test("private client key lifecycle plan is locally actionable")
    func privateClientKeyLifecyclePlan() {
        let profile = ClientProfile(
            id: "profile-rotate",
            bundleId: "com.example.cli",
            keyTag: "com.bastion.signingkey.client.old",
            rules: .default
        )

        let plan = KeyLifecyclePlanner.privateClientRotationPlan(profile: profile)

        #expect(plan.subject == .privateClient)
        #expect(plan.disposition == .ready)
        #expect(plan.requiresOnChainAction == false)
        #expect(plan.signingAvailableAfterLocalStep == true)
        #expect(plan.actions == [
            .authenticateOwner,
            .createReplacementSecureEnclaveKey,
            .updateClientProfileKeyTag,
            .deleteOldLocalKey
        ])
    }

    @Test("group member rotation plan requires validator reinstall")
    func groupMemberKeyLifecyclePlanRequiresOnChainWork() {
        let profile = ClientProfile(
            id: "profile-agent",
            bundleId: "com.example.agent",
            keyTag: "com.bastion.signingkey.client.agent",
            rules: .default,
            walletGroupId: "group-1",
            membershipId: "member-1"
        )

        let plan = KeyLifecyclePlanner.privateClientRotationPlan(profile: profile)

        #expect(plan.subject == .walletGroupAgent)
        #expect(plan.disposition == .requiresOnChainInstall)
        #expect(plan.requiresOnChainAction == true)
        #expect(plan.signingAvailableAfterLocalStep == false)
        #expect(plan.actions.contains(.reinstallAgentValidatorOnChain))
        #expect(plan.actions.contains(.revokeOldAgentValidatorOnChain))
    }

    @Test("wallet group owner key loss is blocked locally")
    func ownerKeyLossIsBlockedLocally() {
        let group = WalletGroup(
            id: "group-1",
            label: "Team",
            ownerKeyTag: "com.bastion.walletgroup.group-1.owner",
            accountAddress: "0x0000000000000000000000000000000000001234"
        )

        let plan = KeyLifecyclePlanner.walletGroupOwnerRecoveryPlan(group: group)

        #expect(plan.subject == .walletGroupOwner)
        #expect(plan.disposition == .blocked)
        #expect(plan.isActionable == false)
        #expect(plan.blockingReason?.contains("non-exportable") == true)
        #expect(plan.actions.contains(.createReplacementWalletGroup))
    }

    @Test("device replacement plan requires config backup for deterministic recovery")
    func deviceReplacementPlanDependsOnBackup() {
        let withBackup = KeyLifecyclePlanner.deviceReplacementPlan(hasConfigBackup: true)
        let withoutBackup = KeyLifecyclePlanner.deviceReplacementPlan(hasConfigBackup: false)

        #expect(withBackup.disposition == .requiresReEnrollment)
        #expect(withBackup.actions.contains(.restoreConfigBackup))
        #expect(withBackup.actions.contains(.reinstallAgentValidatorOnChain))
        #expect(withoutBackup.disposition == .blocked)
        #expect(withoutBackup.blockingReason?.contains("No config backup") == true)
    }

    @Test("wallet group receipt polling stops when delay sleep is cancelled")
    func walletGroupReceiptPollingStopsWhenDelaySleepIsCancelled() async {
        let recorder = WalletGroupReceiptPollDelayRecorder()

        let shouldContinue = await RuleEngine.shouldContinueWalletGroupReceiptPollingAfterDelay(
            sleep: { interval in
                await recorder.record(interval)
                throw CancellationError()
            }
        )

        #expect(shouldContinue == false)
        #expect(await recorder.snapshot() == [RuleEngine.walletGroupReceiptPollIntervalNanoseconds])
    }
}

private actor WalletGroupReceiptPollDelayRecorder {
    private var intervals: [UInt64] = []

    func record(_ interval: UInt64) {
        intervals.append(interval)
    }

    func snapshot() -> [UInt64] {
        intervals
    }
}

// MARK: - Config Migration Tests

@Suite("BastionConfig v7 → v8 Migration")
struct BastionConfigMigrationTests {
    @Test("v7 config without walletGroups decodes with empty array")
    func v7DecodesWithEmptyWalletGroups() throws {
        let v7JSON = """
        {
            "version": 7,
            "authPolicy": "biometricOrPasscode",
            "rules": {
                "enabled": true,
                "requireExplicitApproval": false,
                "rateLimits": [],
                "spendingLimits": [],
                "rawMessagePolicy": {"enabled": true, "allowRawSigning": false},
                "typedDataPolicy": {
                    "enabled": true,
                    "requireExplicitApproval": false,
                    "domainRules": [],
                    "structRules": []
                }
            },
            "bundlerPreferences": {"chainRPCs": []},
            "clientProfiles": [],
            "auditRedactionLevel": "none"
        }
        """.data(using: .utf8)!

        let decoded = try JSONDecoder().decode(BastionConfig.self, from: v7JSON)

        #expect(decoded.version == 7)
        #expect(decoded.walletGroups.isEmpty)
        #expect(decoded.clientProfiles.isEmpty)
    }

    @Test("v8 config round-trips preserving wallet groups")
    func v8RoundTrip() throws {
        let group = WalletGroup(
            id: "g1",
            label: "Team Alpha",
            ownerKeyTag: "com.bastion.walletgroup.g1.owner",
            accountAddress: "0xabc",
            chainIds: [8453, 11155111],
            sharedRules: .default,
            members: [
                AgentMembership(id: "m1", keyTag: "com.bastion.walletgroup.g1.agent.m1", scopedRules: .default)
            ],
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let original = BastionConfig(
            authPolicy: .biometricOrPasscode,
            rules: .default,
            walletGroups: [group]
        )

        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(BastionConfig.self, from: data)

        // BastionConfig has bumped past v8 — what this test cares about is
        // that wallet groups round-trip, not the version pin. Use >= so this
        // assertion stays correct across future schema bumps.
        #expect(decoded.version >= 8)
        #expect(decoded.walletGroups.count == 1)
        #expect(decoded.walletGroups[0].label == "Team Alpha")
        #expect(decoded.walletGroups[0].members.count == 1)
        #expect(decoded.walletGroups[0].chainIds == [8453, 11155111])
    }

    @Test("ClientProfile v7 without walletGroupId decodes to private wallet")
    func v7ClientProfileDecodes() throws {
        let v7Profile = """
        {
            "id": "p1",
            "bundleId": "com.example.cli",
            "authPolicy": "biometricOrPasscode",
            "keyTag": "com.bastion.signingkey.client.abc",
            "rules": {
                "enabled": true,
                "requireExplicitApproval": false,
                "rateLimits": [],
                "spendingLimits": [],
                "rawMessagePolicy": {"enabled": true, "allowRawSigning": false},
                "typedDataPolicy": {
                    "enabled": true,
                    "requireExplicitApproval": false,
                    "domainRules": [],
                    "structRules": []
                }
            }
        }
        """.data(using: .utf8)!

        let decoded = try JSONDecoder().decode(ClientProfile.self, from: v7Profile)
        #expect(decoded.walletGroupId == nil)
        #expect(decoded.membershipId == nil)
        #expect(decoded.isGroupMember == false)
    }
}

// MARK: - Rule Merge Tests (group ∩ member)

@Suite("Rule Merging — Group Intersect Agent")
struct RuleMergeTests {
    private func engine() -> RuleEngine {
        RuleEngine(keychain: MockKeychainBackend())
    }

    @Test("allowedChains intersects both sides")
    func intersectChains() {
        let group = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: [1, 8453, 11155111],
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )
        let member = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: [8453, 42161],
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )

        let merged = engine().mergeGroupRules(group: group, member: member)
        #expect(Set(merged.allowedChains ?? []) == Set([8453]))
    }

    @Test("nil on one side yields the other side's restriction")
    func nilSideFallthrough() {
        let group = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )
        let member = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: [8453],
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )

        let merged = engine().mergeGroupRules(group: group, member: member)
        #expect(merged.allowedChains == [8453])
    }

    @Test("allowedTargets intersects per chain key")
    func intersectTargets() {
        let group = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: ["8453": ["0xAAA", "0xBBB"]],
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )
        let member = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: ["8453": ["0xbbb", "0xCCC"]],
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )

        let merged = engine().mergeGroupRules(group: group, member: member)
        let targets = merged.allowedTargets?["8453"] ?? []
        #expect(targets.map { $0.lowercased() } == ["0xbbb"])
    }

    @Test("rate limits and spending limits concatenate so both counters increment")
    func limitsConcatenate() {
        let groupRate = RateLimitRule(id: "group-rate", maxRequests: 100, windowSeconds: 3600)
        let memberRate = RateLimitRule(id: "member-rate", maxRequests: 10, windowSeconds: 60)
        let groupSpend = SpendingLimitRule(id: "group-spend", token: .usdc, allowance: "1000000000", windowSeconds: 86400)
        let memberSpend = SpendingLimitRule(id: "member-spend", token: .usdc, allowance: "50000000", windowSeconds: 86400)

        let group = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [groupRate],
            spendingLimits: [groupSpend]
        )
        let member = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [memberRate],
            spendingLimits: [memberSpend]
        )

        let merged = engine().mergeGroupRules(group: group, member: member)

        #expect(merged.rateLimits.count == 2)
        #expect(Set(merged.rateLimits.map(\.id)) == Set(["group-rate", "member-rate"]))
        #expect(merged.spendingLimits.count == 2)
        #expect(Set(merged.spendingLimits.map(\.id)) == Set(["group-spend", "member-spend"]))
    }

    @Test("denySelectors union — any side denying wins")
    func denySelectorsUnion() {
        let group = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            denySelectors: ["0x11111111"],
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )
        let member = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            denySelectors: ["0x22222222"],
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )

        let merged = engine().mergeGroupRules(group: group, member: member)
        let denies = Set(merged.denySelectors ?? [])
        #expect(denies.contains("0x11111111"))
        #expect(denies.contains("0x22222222"))
    }

    @Test("rawMessagePolicy AND-reduces — both sides must allow")
    func rawMessagePolicyAnds() {
        let group = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: [],
            rawMessagePolicy: RawMessagePolicy(enabled: true, allowRawSigning: true)
        )
        let member = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: [],
            rawMessagePolicy: RawMessagePolicy(enabled: true, allowRawSigning: false)
        )

        let merged = engine().mergeGroupRules(group: group, member: member)
        #expect(merged.rawMessagePolicy.enabled == true)
        #expect(merged.rawMessagePolicy.allowRawSigning == false) // tighter wins
    }
}

// MARK: - RuleEngine Group Lifecycle Tests

@Suite("RuleEngine Wallet Group Lifecycle")
struct RuleEngineGroupLifecycleTests {
    private func engine() -> RuleEngine {
        #if DEBUG
        AuthManager._bypassForTests = true
        #endif
        return RuleEngine(keychain: MockKeychainBackend())
    }

    @Test("listWalletGroups is empty on fresh install")
    func initiallyEmpty() {
        #expect(engine().listWalletGroups().isEmpty)
    }

    @Test("walletGroupKeyTags empty when no groups exist")
    func walletGroupKeyTagsEmpty() {
        #expect(engine().walletGroupKeyTags().isEmpty)
    }

    @Test("wallet group and member labels are normalized without provisioning keys")
    func walletGroupAndMemberLabelsAreNormalized() throws {
        #expect(try RuleEngine.normalizedWalletGroupLabel("  Treasury  ") == "Treasury")
        #expect(throws: BastionError.invalidInput) {
            _ = try RuleEngine.normalizedWalletGroupLabel("   ")
        }
        #expect(RuleEngine.normalizedWalletGroupMemberLabel("  Ops Bot  ") == "Ops Bot")
        #expect(RuleEngine.normalizedWalletGroupMemberLabel("   ") == nil)
        #expect(RuleEngine.normalizedWalletGroupMemberLabel(nil) == nil)
    }

    @Test("private client key rotation updates profile key tag")
    func privateClientKeyRotationUpdatesProfile() throws {
        let engine = self.engine()
        let profile = ClientProfile(
            id: "profile-1",
            bundleId: "com.example.cli",
            keyTag: "com.bastion.signingkey.client.old",
            rules: .default
        )
        try engine.saveConfig(BastionConfig(authPolicy: .biometric, rules: .default, clientProfiles: [profile]))
        engine.loadConfigOnStartup()

        let result = try engine.rotatePrivateClientKey(
            profileId: "profile-1",
            replacementKeyTag: "com.bastion.signingkey.client.new",
            replacementAccountAddress: "0x0000000000000000000000000000000000009999",
            deleteOldKeyAfterSave: false
        )

        #expect(result.oldKeyTag == "com.bastion.signingkey.client.old")
        #expect(result.newKeyTag == "com.bastion.signingkey.client.new")
        #expect(result.newAccountAddress == "0x0000000000000000000000000000000000009999")
        #expect(engine.clientProfile(id: "profile-1")?.keyTag == "com.bastion.signingkey.client.new")
    }

    @Test("private client key rotation rejects wallet group members")
    func privateClientKeyRotationRejectsGroupMember() throws {
        let engine = self.engine()
        let profile = ClientProfile(
            id: "profile-2",
            bundleId: "com.example.agent",
            keyTag: "com.bastion.signingkey.client.agent",
            rules: .default,
            walletGroupId: "group-1",
            membershipId: "member-1"
        )
        try engine.saveConfig(BastionConfig(authPolicy: .biometric, rules: .default, clientProfiles: [profile]))
        engine.loadConfigOnStartup()

        #expect(throws: BastionError.ruleViolation) {
            _ = try engine.rotatePrivateClientKey(
                profileId: "profile-2",
                replacementKeyTag: "com.bastion.signingkey.client.replacement",
                deleteOldKeyAfterSave: false
            )
        }
    }
}
