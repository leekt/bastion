import Foundation
import Security

/// Generic Keychain CRUD scoped to the com.bastion access group.
/// Agent processes cannot read, write, or delete these items.
nonisolated enum KeychainStore: Sendable {
    private static let service = "com.bastion"

    nonisolated static func read(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
            return nil
        }
        return item as? Data
    }

    nonisolated static func write(account: String, data: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]

        if read(account: account) != nil {
            let attrs: [String: Any] = [kSecValueData as String: data]
            SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
        } else {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            SecItemAdd(addQuery as CFDictionary, nil)
        }
    }

    nonisolated static func delete(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}

/// Wrapper that bridges KeychainStore's static API to the KeychainBackend protocol.
nonisolated struct SystemKeychainBackend: KeychainBackend, Sendable {
    nonisolated func read(account: String) -> Data? {
        KeychainStore.read(account: account)
    }

    nonisolated func write(account: String, data: Data) {
        KeychainStore.write(account: account, data: data)
    }

    nonisolated func delete(account: String) {
        KeychainStore.delete(account: account)
    }
}
