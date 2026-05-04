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

    @Test("activeMembers filters revoked members")
    func activeMembersFiltersRevoked() {
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
        #expect(group.activeMembers.count == 2)
        #expect(group.activeMembers.map(\.id) == ["m1", "m2"])
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
}
