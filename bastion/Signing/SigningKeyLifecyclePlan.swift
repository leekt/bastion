import Foundation

nonisolated enum SigningKeyLifecyclePlan {
    static func resetRequestedKeyTags(
        config: BastionConfig,
        walletGroupKeyTags: [String]
    ) -> [String] {
        var keyTags: [String] = [
            SecureEnclaveManager.defaultSigningKeyIdentifier,
            SecureEnclaveManager.legacySigningKeyIdentifier,
        ]
        keyTags.append(contentsOf: config.clientProfiles.map(\.keyTag))
        keyTags.append(contentsOf: walletGroupKeyTags)
        return Array(Set(keyTags)).sorted()
    }
}
