import Foundation
import LocalAuthentication
import Security
import Testing
@testable import bastion

@Suite("Security configuration")
struct SecurityConfigurationTests {
    @Test("Keychain and Secure Enclave access groups stay aligned")
    func keychainAndSecureEnclaveAccessGroupsStayAligned() {
        #expect(KeychainStore.accessGroup == "926A27BQ7W.com.bastion")
        #expect(SecureEnclaveManager.keychainAccessGroup == KeychainStore.accessGroup)
    }

    @Test("App and CLI entitlements declare the Bastion keychain group")
    func entitlementsDeclareBastionKeychainGroup() throws {
        for path in ["bastion/bastion.entitlements", "bastion-cli/bastion-cli.entitlements"] {
            let entitlements = try loadEntitlements(path)
            let groups = try #require(entitlements["keychain-access-groups"] as? [String])
            #expect(groups.contains("$(AppIdentifierPrefix)com.bastion"))
        }
    }

    @Test("Xcode project points app targets at Bastion entitlements")
    func xcodeProjectPointsAtBastionEntitlements() throws {
        let project = try String(contentsOf: repoFileURL("bastion.xcodeproj/project.pbxproj"), encoding: .utf8)
        #expect(project.contains("CODE_SIGN_ENTITLEMENTS = bastion/bastion.entitlements;"))
    }

    @Test("Keychain queries use data-protection keychain and scoped access group")
    func keychainQueriesUseDataProtectionAndAccessGroup() {
        let data = Data("config".utf8)
        let base = KeychainStore.baseQuery(account: "config")
        let add = KeychainStore.addQuery(account: "config", data: data)

        #expect(securityString(base, kSecClass) == securityString(kSecClassGenericPassword))
        #expect(securityString(base, kSecAttrService) == "com.bastion")
        #expect(securityString(base, kSecAttrAccessGroup) == KeychainStore.accessGroup)
        #expect(base[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(securityString(base, kSecAttrAccount) == "config")

        #expect(add[kSecValueData as String] as? Data == data)
        #expect(securityString(add, kSecAttrAccessible) == securityString(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly))
    }

    @Test("Secure Enclave key queries use scoped data-protection keychain")
    func secureEnclaveKeyQueriesUseScopedDataProtectionKeychain() {
        let tag = Data("com.bastion.signingkey.test".utf8)
        let scoped = SecureEnclaveManager.keyQuery(tag: tag, scoped: true)
        let legacy = SecureEnclaveManager.keyQuery(tag: tag, scoped: false)

        #expect(securityString(scoped, kSecClass) == securityString(kSecClassKey))
        #expect(scoped[kSecAttrApplicationTag as String] as? Data == tag)
        #expect(securityString(scoped, kSecAttrTokenID) == securityString(kSecAttrTokenIDSecureEnclave))
        #expect(securityString(scoped, kSecAttrAccessGroup) == KeychainStore.accessGroup)
        #expect(scoped[kSecUseDataProtectionKeychain as String] as? Bool == true)

        #expect(legacy[kSecAttrAccessGroup as String] == nil)
        #expect(legacy[kSecUseDataProtectionKeychain as String] == nil)
    }

    @Test("Secure Enclave key creation attributes are scoped and silent")
    func secureEnclaveKeyCreationAttributesAreScopedAndSilent() throws {
        var error: Unmanaged<CFError>?
        let access = try #require(SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage,
            &error
        ))
        let context = LAContext()
        let tag = Data("com.bastion.signingkey.creation-test".utf8)
        let attrs = SecureEnclaveManager.keyCreationAttributes(
            tag: tag,
            access: access,
            context: context
        )
        let privateAttrs = try #require(attrs[kSecPrivateKeyAttrs as String] as? [String: Any])

        #expect(securityString(attrs, kSecAttrKeyType) == securityString(kSecAttrKeyTypeECSECPrimeRandom))
        #expect(attrs[kSecAttrKeySizeInBits as String] as? Int == 256)
        #expect(securityString(attrs, kSecAttrTokenID) == securityString(kSecAttrTokenIDSecureEnclave))
        #expect(attrs[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect((attrs[kSecUseAuthenticationContext as String] as? LAContext) === context)

        #expect(privateAttrs[kSecAttrIsPermanent as String] as? Bool == true)
        #expect(privateAttrs[kSecAttrApplicationTag as String] as? Data == tag)
        #expect(securityString(privateAttrs, kSecAttrAccessGroup) == KeychainStore.accessGroup)
        #expect((privateAttrs[kSecAttrAccessControl as String] as! SecAccessControl) === access)
    }

    @Test("Secure Enclave keychain item conversion fails closed for unexpected objects")
    func secureEnclaveKeychainItemConversionFailsClosed() throws {
        #expect(throws: BastionError.invalidInput) {
            _ = try SecureEnclaveManager.secKey(fromKeychainItem: nil)
        }

        #expect(throws: BastionError.invalidInput) {
            _ = try SecureEnclaveManager.secKey(fromKeychainItem: "not-a-key" as CFString)
        }
    }

    private func loadEntitlements(_ path: String) throws -> [String: Any] {
        let data = try Data(contentsOf: repoFileURL(path))
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        return try #require(plist as? [String: Any])
    }

    private func repoFileURL(_ relativePath: String) -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent(relativePath)
    }

    private func securityString(_ dictionary: [String: Any], _ key: CFString) -> String? {
        dictionary[key as String] as? String
    }

    private func securityString(_ value: CFString) -> String {
        value as String
    }
}

#if DEBUG
@Suite("Runtime QA config override", .serialized)
struct RuntimeQAConfigOverrideTests {
    @Test("Runtime QA override requires explicit marker and can be cleared")
    func runtimeQAOverrideRequiresMarkerAndCanBeCleared() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let config = try encodedConfig(.default)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try config.write(to: RuntimeQAConfigOverride.configURL(directory: directory), options: [.atomic])

        #expect(RuntimeQAConfigOverride.readDataIfEnabled(directory: directory) == nil)
        #expect(RuntimeQAConfigOverride.writeData(config, directory: directory))
        #expect(RuntimeQAConfigOverride.isEnabled(directory: directory))
        #expect(RuntimeQAConfigOverride.readDataIfEnabled(directory: directory) == config)
        #expect(RuntimeQAConfigOverride.clear(directory: directory))
        #expect(!RuntimeQAConfigOverride.isEnabled(directory: directory))
        #expect(RuntimeQAConfigOverride.readDataIfEnabled(directory: directory) == nil)
    }

    @Test("RuleEngine uses runtime QA override without mutating Keychain config")
    func ruleEngineUsesRuntimeQAOverrideWithoutMutatingKeychainConfig() throws {
        let directory = try temporaryDirectory()
        defer {
            _ = RuntimeQAConfigOverride.clear(directory: directory)
            try? FileManager.default.removeItem(at: directory)
        }

        var keychainConfig = BastionConfig.default
        keychainConfig.authPolicy = .biometric
        let keychainData = try encodedConfig(keychainConfig)
        let keychain = MockKeychainBackend()
        keychain.write(account: "config", data: keychainData)

        var overrideConfig = BastionConfig.default
        overrideConfig.authPolicy = .open
        overrideConfig.clientProfiles = [
            ClientProfile(
                id: "runtime-qa-profile",
                bundleId: "bastion-cli",
                label: "Runtime QA CLI",
                authPolicy: .open,
                keyTag: "com.bastion.signingkey.client.runtime-qa.bastion-cli",
                rules: RuleConfig.default
            )
        ]
        #expect(RuntimeQAConfigOverride.writeData(try encodedConfig(overrideConfig), directory: directory))

        let engine = RuleEngine(
            keychain: keychain,
            runtimeQAConfigOverride: .directory(directory)
        )
        let loaded = engine.loadConfig()
        #expect(loaded.authPolicy == .open)
        #expect(loaded.clientProfiles.map(\.bundleId) == ["bastion-cli"])

        var saved = loaded
        saved.auditRedactionLevel = .redactPayloads
        try engine.saveConfig(saved)

        #expect(keychain.read(account: "config") == keychainData)
        let overrideData = try #require(RuntimeQAConfigOverride.readDataIfEnabled(directory: directory))
        let decodedOverride = try JSONDecoder().decode(BastionConfig.self, from: overrideData)
        #expect(decodedOverride.auditRedactionLevel == .redactPayloads)
        #expect(decodedOverride.clientProfiles.map(\.bundleId) == ["bastion-cli"])
    }

    @Test("Runtime QA software signer is gated by override marker and QA key tag")
    func runtimeQASoftwareSignerIsGatedByOverrideMarkerAndQAKeyTag() throws {
        let directory = try temporaryDirectory()
        defer {
            _ = RuntimeQAConfigOverride.clear(directory: directory)
            try? FileManager.default.removeItem(at: directory)
        }

        let provider = RuntimeQASigningProvider.shared
        let keyTag = "com.bastion.signingkey.client.runtime-qa.bastion-cli"
        let nonQAKeyTag = "com.bastion.signingkey.client.production"
        let digest = Data(repeating: 0x42, count: 32)

        #expect(try provider.publicKeyIfEnabled(keyTag: keyTag, directory: directory) == nil)
        #expect(try provider.signDigestIfEnabled(hash: digest, keyTag: keyTag, directory: directory) == nil)
        #expect(RuntimeQAConfigOverride.writeData(try encodedConfig(.default), directory: directory))
        #expect(try provider.publicKeyIfEnabled(keyTag: nonQAKeyTag, directory: directory) == nil)
        #expect(try provider.signDigestIfEnabled(hash: digest, keyTag: nonQAKeyTag, directory: directory) == nil)

        let publicKey = try #require(try provider.publicKeyIfEnabled(keyTag: keyTag, directory: directory))
        let signature = try #require(try provider.signDigestIfEnabled(hash: digest, keyTag: keyTag, directory: directory))

        #expect(publicKey.x.count == 64)
        #expect(publicKey.y.count == 64)
        #expect(publicKey.accountAddress?.hasPrefix("0x") == true)
        #expect(signature.pubkeyX == publicKey.x)
        #expect(signature.pubkeyY == publicKey.y)
        #expect(signature.r.count == 64)
        #expect(signature.s.count == 64)
        #expect(signature.accountAddress == publicKey.accountAddress)
    }

    private func temporaryDirectory() throws -> URL {
        let base = FileManager.default.temporaryDirectory
        let directory = base.appendingPathComponent("BastionRuntimeQA-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private func encodedConfig(_ config: BastionConfig) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(config)
    }
}
#endif
