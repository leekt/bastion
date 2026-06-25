import Foundation

nonisolated struct KeyLifecycleScenarioSnapshot: Codable, Equatable, Sendable {
    let resetRequestedKeyTags: [String]
    let resetDeletedKeyTags: [String]
    let rotationProfileId: String
    let oldKeyTag: String
    let newKeyTag: String
    let oldAccountAddress: String?
    let newAccountAddress: String?
    let persistedRotatedKeyTag: String?
    let groupMemberRotationRejected: Bool
    let privateRotationActions: [String]
    let keychainConfigUntouched: Bool
    let runtimeQAOverrideUsed: Bool
}

nonisolated struct KeyLifecycleScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let lifecycle: KeyLifecycleScenarioSnapshot
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct KeyLifecycleScenarioEncodedProbeResponse: Sendable {
    let scenario: String
    let passed: Bool
    let diagnosticContext: [String: String]
    let data: Data
}

private final class KeyLifecycleScenarioMemoryKeychain: KeychainBackend, @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.bastion.key-lifecycle-scenario-memory-keychain")
    private var storage: [String: Data] = [:]

    func read(account: String) -> Data? {
        queue.sync { storage[account] }
    }

    func readResult(account: String) -> KeychainReadResult {
        queue.sync {
            if let data = storage[account] {
                return .found(data)
            }
            return .missing
        }
    }

    @discardableResult
    func write(account: String, data: Data) -> Bool {
        queue.sync {
            storage[account] = data
            return true
        }
    }

    @discardableResult
    func delete(account: String) -> Bool {
        queue.sync {
            storage.removeValue(forKey: account) != nil
        }
    }
}

nonisolated enum KeyLifecycleScenarioProbe {
    static let overviewScenario = "overview"

    private static let privateProfileId = "runtime-qa-private-profile"
    private static let groupProfileId = "runtime-qa-group-profile"
    private static let groupId = "runtime-qa-wallet-group"
    private static let installedMemberId = "runtime-qa-installed-agent"
    private static let pendingMemberId = "runtime-qa-pending-agent"
    private static let revokedMemberId = "runtime-qa-revoked-agent"
    private static let runtimeQAKeyTagPrefix = "com.bastion.signingkey.client.runtime-qa."

    private static var privateOldKeyTag: String {
        "\(runtimeQAKeyTagPrefix)cli.old"
    }

    private static var privateNewKeyTag: String {
        "\(runtimeQAKeyTagPrefix)cli.new"
    }

    private static var groupMemberProfileKeyTag: String {
        "\(runtimeQAKeyTagPrefix)cli.group"
    }

    static func run(scenario: String) async throws -> KeyLifecycleScenarioEncodedProbeResponse {
        let encoder = JSONEncoder()
        switch scenario {
        case overviewScenario:
            let response = try await overview()
            return KeyLifecycleScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "requested": String(response.lifecycle.resetRequestedKeyTags.count),
                    "oldKey": response.lifecycle.oldKeyTag,
                    "newKey": response.lifecycle.newKeyTag,
                    "groupMemberRejected": String(response.lifecycle.groupMemberRotationRejected),
                    "keychainUntouched": String(response.lifecycle.keychainConfigUntouched),
                ],
                data: try encoder.encode(response)
            )
        default:
            throw NSError(
                domain: "com.bastion.key-lifecycle-scenario-probe",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey: "Unknown key lifecycle scenario: \(scenario). Use \(overviewScenario)."
                ]
            )
        }
    }

    @MainActor
    static func overview() throws -> KeyLifecycleScenarioProbeResponse {
        let fileManager = FileManager.default
        let directory = fileManager.temporaryDirectory
            .appendingPathComponent("BastionKeyLifecycleScenario-\(UUID().uuidString)", isDirectory: true)
        defer {
            #if DEBUG
            _ = RuntimeQAConfigOverride.clear(directory: directory)
            #endif
            try? fileManager.removeItem(at: directory)
        }

        let protectedConfig = BastionConfig(authPolicy: .biometricOrPasscode, rules: .default)
        let protectedData = try JSONEncoder().encode(protectedConfig)
        let keychain = KeyLifecycleScenarioMemoryKeychain()
        keychain.write(account: "config", data: protectedData)

        let fixtureConfig = makeFixtureConfig()
        let fixtureData = try JSONEncoder().encode(fixtureConfig)

        #if DEBUG
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        guard RuntimeQAConfigOverride.writeData(fixtureData, directory: directory) else {
            throw NSError(
                domain: "com.bastion.key-lifecycle-scenario-probe",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Failed to write runtime QA lifecycle fixture"]
            )
        }
        let engine = RuleEngine(
            keychain: keychain,
            runtimeQAConfigOverride: .directory(directory)
        )
        let replacementPublicKey = try RuntimeQASigningProvider.shared.publicKeyIfEnabled(
            keyTag: privateNewKeyTag,
            directory: directory
        )
        let runtimeQAOverrideUsed = true
        #else
        keychain.write(account: "config", data: fixtureData)
        let engine = RuleEngine(keychain: keychain)
        let replacementPublicKey: PublicKeyResponse? = nil
        let runtimeQAOverrideUsed = false
        #endif

        let initialConfig = engine.loadConfig()
        let resetRequested = SigningKeyLifecyclePlan.resetRequestedKeyTags(
            config: initialConfig,
            walletGroupKeyTags: engine.walletGroupKeyTags()
        )
        let resetResponse = ResetSigningKeysResponse(
            deletedKeyTags: [privateOldKeyTag, WalletGroup.makeAgentKeyTag(groupId: groupId, memberId: pendingMemberId)].sorted(),
            requestedKeyTags: resetRequested
        )

        let plan = try require(engine.keyLifecyclePlan(forProfileId: privateProfileId))
        let rotation = try engine.rotatePrivateClientKey(
            profileId: privateProfileId,
            replacementKeyTag: privateNewKeyTag,
            replacementAccountAddress: replacementPublicKey?.accountAddress,
            deleteOldKeyAfterSave: false
        )
        let persistedRotatedKeyTag = engine.clientProfile(id: privateProfileId)?.keyTag
        let groupMemberRotationRejected = rejectsGroupMemberRotation(engine: engine)

        let snapshot = KeyLifecycleScenarioSnapshot(
            resetRequestedKeyTags: resetResponse.requestedKeyTags,
            resetDeletedKeyTags: resetResponse.deletedKeyTags,
            rotationProfileId: rotation.profileId,
            oldKeyTag: rotation.oldKeyTag,
            newKeyTag: rotation.newKeyTag,
            oldAccountAddress: rotation.oldAccountAddress,
            newAccountAddress: rotation.newAccountAddress,
            persistedRotatedKeyTag: persistedRotatedKeyTag,
            groupMemberRotationRejected: groupMemberRotationRejected,
            privateRotationActions: plan.actions.map(\.rawValue),
            keychainConfigUntouched: keychain.read(account: "config") == protectedData,
            runtimeQAOverrideUsed: runtimeQAOverrideUsed
        )

        let expectedResetTags = [
            SecureEnclaveManager.defaultSigningKeyIdentifier,
            SecureEnclaveManager.legacySigningKeyIdentifier,
            privateOldKeyTag,
            groupMemberProfileKeyTag,
            WalletGroup.makeOwnerKeyTag(groupId: groupId),
            WalletGroup.makeAgentKeyTag(groupId: groupId, memberId: installedMemberId),
            WalletGroup.makeAgentKeyTag(groupId: groupId, memberId: pendingMemberId),
        ].sorted()
        let revokedKeyTag = WalletGroup.makeAgentKeyTag(groupId: groupId, memberId: revokedMemberId)

        let privateRotationActions = [
            KeyLifecycleAction.authenticateOwner.rawValue,
            KeyLifecycleAction.createReplacementSecureEnclaveKey.rawValue,
            KeyLifecycleAction.updateClientProfileKeyTag.rawValue,
            KeyLifecycleAction.deleteOldLocalKey.rawValue,
        ]
        let checks = [
            SettingsScenarioProbeCheck(
                name: "reset planner requests default legacy client and non-revoked group key tags",
                passed: snapshot.resetRequestedKeyTags == expectedResetTags
                    && !snapshot.resetRequestedKeyTags.contains(revokedKeyTag)
            ),
            SettingsScenarioProbeCheck(
                name: "reset response keeps requested and deleted key tags sorted and explicit",
                passed: snapshot.resetDeletedKeyTags == [privateOldKeyTag, WalletGroup.makeAgentKeyTag(groupId: groupId, memberId: pendingMemberId)].sorted()
                    && snapshot.resetRequestedKeyTags == resetRequested
            ),
            SettingsScenarioProbeCheck(
                name: "private client rotation plan is local owner-auth key replacement",
                passed: plan.subject == .privateClient
                    && plan.disposition == .ready
                    && !plan.requiresOnChainAction
                    && plan.signingAvailableAfterLocalStep
                    && snapshot.privateRotationActions == privateRotationActions
            ),
            SettingsScenarioProbeCheck(
                name: "private client rotation mutates only isolated runtime QA config",
                passed: snapshot.rotationProfileId == privateProfileId
                    && snapshot.oldKeyTag == privateOldKeyTag
                    && snapshot.newKeyTag == privateNewKeyTag
                    && snapshot.persistedRotatedKeyTag == privateNewKeyTag
                    && snapshot.keychainConfigUntouched
            ),
            SettingsScenarioProbeCheck(
                name: "wallet group member rotation is rejected from private-client path",
                passed: snapshot.groupMemberRotationRejected
            ),
        ]

        return KeyLifecycleScenarioProbeResponse(
            scenario: overviewScenario,
            passed: checks.allSatisfy(\.passed),
            lifecycle: snapshot,
            checks: checks
        )
    }

    private static func makeFixtureConfig() -> BastionConfig {
        let privateProfile = ClientProfile(
            id: privateProfileId,
            bundleId: "bastion-cli",
            label: "Runtime QA CLI",
            authPolicy: .open,
            keyTag: privateOldKeyTag,
            rules: .default
        )
        let groupProfile = ClientProfile(
            id: groupProfileId,
            bundleId: "bastion-cli.group",
            label: "Runtime QA Group CLI",
            authPolicy: .open,
            keyTag: groupMemberProfileKeyTag,
            rules: .default,
            walletGroupId: groupId,
            membershipId: installedMemberId
        )
        let group = WalletGroup(
            id: groupId,
            label: "Runtime QA Group",
            chainIds: [8453],
            members: [
                AgentMembership(
                    id: installedMemberId,
                    clientProfileId: groupProfileId,
                    label: "Installed",
                    keyTag: WalletGroup.makeAgentKeyTag(groupId: groupId, memberId: installedMemberId),
                    installStatus: .installed(txHash: "0xinstalled")
                ),
                AgentMembership(
                    id: pendingMemberId,
                    label: "Pending",
                    keyTag: WalletGroup.makeAgentKeyTag(groupId: groupId, memberId: pendingMemberId),
                    installStatus: .pending
                ),
                AgentMembership(
                    id: revokedMemberId,
                    label: "Revoked",
                    keyTag: WalletGroup.makeAgentKeyTag(groupId: groupId, memberId: revokedMemberId),
                    installStatus: .revoked(txHash: "0xrevoked")
                ),
            ]
        )
        return BastionConfig(
            authPolicy: .open,
            rules: .default,
            clientProfiles: [privateProfile, groupProfile],
            walletGroups: [group]
        )
    }

    @MainActor
    private static func rejectsGroupMemberRotation(engine: RuleEngine) -> Bool {
        do {
            _ = try engine.rotatePrivateClientKey(
                profileId: groupProfileId,
                replacementKeyTag: "\(runtimeQAKeyTagPrefix)cli.group.replacement",
                deleteOldKeyAfterSave: false
            )
            return false
        } catch let error as BastionError {
            return error == .ruleViolation
        } catch {
            return false
        }
    }

    private static func require<T>(_ value: T?) throws -> T {
        guard let value else {
            throw NSError(
                domain: "com.bastion.key-lifecycle-scenario-probe",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "Missing key lifecycle fixture value"]
            )
        }
        return value
    }
}
