import Foundation
import Security

/// Generic Keychain CRUD scoped to the com.bastion access group.
/// Agent processes cannot read, write, or delete these items.
///
/// M-01: Uses explicit access group to prevent other same-team apps from
/// accessing Bastion config/state. Requires the matching Keychain Access Group
/// entitlement: "926A27BQ7W.com.bastion" in the app's .entitlements file.
///
/// M-08 (the "infinite Keychain prompt" bug): we set
/// `kSecUseDataProtectionKeychain = true` on every query so items live in
/// the iOS-style data-protection keychain instead of the legacy macOS
/// keychain. The legacy keychain bakes the *exact* code signature into a
/// per-item ACL, so re-signing the app (e.g. dev rebuilds with a refreshed
/// provisioning profile) makes every read prompt the user with
/// `[App] wants to use [Item] in your keychain`. The data-protection
/// keychain replaces that ACL model with access-group entitlement gating
/// alone — any process with the matching entitlement reads silently and
/// re-signing with the same team ID is transparent.
///
/// Pre-release builds do not trust or migrate legacy keychain items. Missing
/// scoped data is handled as a first-run state and read failures fail closed.
nonisolated enum KeychainStore: Sendable {
    private static let service = "com.bastion"
    static let accessGroup = "926A27BQ7W.com.bastion"

    /// Common keychain query attributes. Always include
    /// `kSecUseDataProtectionKeychain` so we hit the modern keychain that
    /// gates by access group rather than per-item code-signature ACL.
    static func baseQuery(account: String? = nil) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let account { q[kSecAttrAccount as String] = account }
        return q
    }

    static func addQuery(account: String, data: Data) -> [String: Any] {
        var query = baseQuery(account: account)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return query
    }

    nonisolated static func read(account: String) -> Data? {
        guard case .found(let data) = readResult(account: account) else {
            return nil
        }
        return data
    }

    nonisolated static func readResult(account: String) -> KeychainReadResult {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return .missing
        }
        guard status == errSecSuccess, let data = item as? Data else {
            return .failure
        }
        return .found(data)
    }

    @discardableResult
    nonisolated static func write(account: String, data: Data) -> Bool {
        let query = baseQuery(account: account)
        switch readResult(account: account) {
        case .found:
            let attrs: [String: Any] = [kSecValueData as String: data]
            return SecItemUpdate(query as CFDictionary, attrs as CFDictionary) == errSecSuccess
        case .missing:
            let addQuery = Self.addQuery(account: account, data: data)
            return SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess
        case .failure:
            return false
        }
    }

    @discardableResult
    nonisolated static func delete(account: String) -> Bool {
        let query = baseQuery(account: account)
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    /// Pre-release builds do not migrate legacy items. Leaving this as a no-op
    /// keeps older startup call sites harmless without trusting stale data.
    nonisolated static func migrateLegacyItems() {
    }
}

/// Wrapper that bridges KeychainStore's static API to the KeychainBackend protocol.
nonisolated struct SystemKeychainBackend: KeychainBackend, Sendable {
    nonisolated func read(account: String) -> Data? {
        KeychainStore.read(account: account)
    }

    nonisolated func readResult(account: String) -> KeychainReadResult {
        KeychainStore.readResult(account: account)
    }

    @discardableResult
    nonisolated func write(account: String, data: Data) -> Bool {
        KeychainStore.write(account: account, data: data)
    }

    @discardableResult
    nonisolated func delete(account: String) -> Bool {
        KeychainStore.delete(account: account)
    }
}
