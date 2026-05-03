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
/// Migration: items written by older builds in the legacy keychain are
/// invisible to the new queries; `migrateLegacyItems(accounts:)` is called
/// at startup to move them across. Failures are best-effort and logged —
/// a failed migration leaves the legacy item behind, which is no worse
/// than the pre-migration state.
nonisolated enum KeychainStore: Sendable {
    private static let service = "com.bastion"
    private static let accessGroup = "926A27BQ7W.com.bastion"

    /// Common keychain query attributes. Always include
    /// `kSecUseDataProtectionKeychain` so we hit the modern keychain that
    /// gates by access group rather than per-item code-signature ACL.
    private static func baseQuery(account: String? = nil) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let account { q[kSecAttrAccount as String] = account }
        return q
    }

    nonisolated static func read(account: String) -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
            return nil
        }
        return item as? Data
    }

    nonisolated static func write(account: String, data: Data) {
        let query = baseQuery(account: account)
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
        let query = baseQuery(account: account)
        SecItemDelete(query as CFDictionary)
    }

    /// One-shot migration from the legacy macOS keychain (which is what
    /// pre-M-08 builds wrote to). Enumerates every generic-password item
    /// under our service + access group in the legacy keychain, copies it
    /// into the data-protection keychain, and deletes the legacy original.
    /// Idempotent — safe (and cheap) to run on every launch.
    ///
    /// This catches the static accounts (config, audit HMAC, sessions,
    /// rest-token, etc.) and the dynamically-named StateStore counters
    /// (`state.ratelimit.<ruleId>`, `state.spending.<ruleId>`) without the
    /// caller needing to enumerate them.
    nonisolated static func migrateLegacyItems() {
        let listQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            // Note: NOT setting kSecUseDataProtectionKeychain — we want the
            // legacy items.
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(listQuery as CFDictionary, &result)
        guard status == errSecSuccess,
              let entries = result as? [[String: Any]] else {
            return
        }
        for entry in entries {
            guard let account = entry[kSecAttrAccount as String] as? String,
                  let data = entry[kSecValueData as String] as? Data else {
                continue
            }
            // If the data-protection keychain already has this account, skip
            // (avoid clobbering newer writes with stale legacy ones).
            if read(account: account) == nil {
                write(account: account, data: data)
            }
            // Best-effort delete from the legacy keychain so the prompt
            // cascade stops on subsequent launches.
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccessGroup as String: accessGroup,
                kSecAttrAccount as String: account,
            ]
            SecItemDelete(deleteQuery as CFDictionary)
        }
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
