import Foundation
import LocalAuthentication
import Security

nonisolated final class SecureEnclaveManager: Sendable {
    static let shared = SecureEnclaveManager()

    private let configKeyTag = "com.bastion.configkey".data(using: .utf8)!
    private let signingKeyTag = "com.bastion.signingkey".data(using: .utf8)!
    private let stateKeyTag = "com.bastion.statekey".data(using: .utf8)!

    private init() {}

    // MARK: - Key Management

    nonisolated func loadOrCreateConfigKey() throws -> SecKey {
        if let existing = try? loadKey(tag: configKeyTag) {
            return existing
        }
        return try createKey(
            tag: configKeyTag,
            accessControlFlags: [.privateKeyUsage, .userPresence]
        )
    }

    nonisolated func loadOrCreateSigningKey() throws -> SecKey {
        if let existing = try? loadKey(tag: signingKeyTag, context: silentContext()) {
            return existing
        }
        return try createSilentKey(tag: signingKeyTag)
    }

    nonisolated func loadOrCreateStateKey() throws -> SecKey {
        if let existing = try? loadKey(tag: stateKeyTag, context: silentContext()) {
            return existing
        }
        return try createSilentKey(tag: stateKeyTag)
    }

    // MARK: - State Signing (Key C)

    nonisolated func signState(_ data: Data) throws -> Data {
        let privateKey = try loadOrCreateStateKey()
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return signature
    }

    nonisolated func verifyState(_ data: Data, signature: Data) throws -> Bool {
        let privateKey = try loadOrCreateStateKey()
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw BastionError.keyNotFound
        }
        var error: Unmanaged<CFError>?
        return SecKeyVerifySignature(
            publicKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            signature as CFData,
            &error
        )
    }

    // MARK: - Signing (Key B)

    nonisolated func sign(data: Data) throws -> SignResponse {
        let privateKey = try loadOrCreateSigningKey()

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw BastionError.keyNotFound
        }

        var error: Unmanaged<CFError>?
        guard let pubData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        let (r, s) = try parseDER(signature)

        return SignResponse(
            pubkeyX: pubData.subdata(in: 1..<33).hex,
            pubkeyY: pubData.subdata(in: 33..<65).hex,
            r: r.hex,
            s: s.hex
        )
    }

    nonisolated func getPublicKey() throws -> PublicKeyResponse {
        let privateKey = try loadOrCreateSigningKey()

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw BastionError.keyNotFound
        }

        var error: Unmanaged<CFError>?
        guard let pubData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        return PublicKeyResponse(
            x: pubData.subdata(in: 1..<33).hex,
            y: pubData.subdata(in: 33..<65).hex
        )
    }

    // MARK: - Config Encryption (Key A)

    nonisolated func encryptConfig(_ plaintext: Data) throws -> Data {
        let privateKey = try loadOrCreateConfigKey()

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw BastionError.keyNotFound
        }

        // Sign the plaintext with Key A (triggers userPresence auth)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            plaintext as CFData,
            &error
        ) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        // Build payload: [4 bytes sig length][signature][plaintext]
        var sigLen = UInt32(signature.count).bigEndian
        var payload = Data(bytes: &sigLen, count: 4)
        payload.append(signature)
        payload.append(plaintext)

        // Encrypt with Key A public key (no auth needed)
        guard let encrypted = SecKeyCreateEncryptedData(
            publicKey,
            .eciesEncryptionStandardVariableIVX963SHA256AESGCM,
            payload as CFData,
            &error
        ) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        return encrypted
    }

    nonisolated func decryptConfig(_ encrypted: Data) throws -> Data {
        let privateKey = try loadOrCreateConfigKey()

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw BastionError.keyNotFound
        }

        // Decrypt with Key A private key (triggers userPresence auth)
        var error: Unmanaged<CFError>?
        guard let payload = SecKeyCreateDecryptedData(
            privateKey,
            .eciesEncryptionStandardVariableIVX963SHA256AESGCM,
            encrypted as CFData,
            &error
        ) as Data? else {
            throw BastionError.configCorrupted
        }

        // Parse payload: [4 bytes sig length][signature][plaintext]
        guard payload.count > 4 else { throw BastionError.configCorrupted }

        let sigLen = Int(payload.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
        guard payload.count > 4 + sigLen else { throw BastionError.configCorrupted }

        let signature = payload.subdata(in: 4..<4 + sigLen)
        let plaintext = payload.subdata(in: 4 + sigLen..<payload.count)

        // Verify signature with Key A public key (no auth needed)
        guard SecKeyVerifySignature(
            publicKey,
            .ecdsaSignatureMessageX962SHA256,
            plaintext as CFData,
            signature as CFData,
            &error
        ) else {
            throw BastionError.configCorrupted
        }

        return plaintext
    }

    // MARK: - DER Parsing

    nonisolated func parseDER(_ der: Data) throws -> (r: Data, s: Data) {
        let bytes = [UInt8](der)
        var i = 0

        guard bytes.count > 2, bytes[i] == 0x30 else {
            throw NSError(domain: "DER", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid DER sequence"])
        }
        i += 1

        // Skip length byte(s)
        if bytes[i] & 0x80 != 0 {
            i += 1 + Int(bytes[i] & 0x7F)
        } else {
            i += 1
        }

        // Parse r
        guard i < bytes.count, bytes[i] == 0x02 else {
            throw NSError(domain: "DER", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid DER integer tag for r"])
        }
        i += 1
        let rLen = Int(bytes[i]); i += 1
        guard i + rLen <= bytes.count else {
            throw NSError(domain: "DER", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid r length"])
        }
        var r = Data(bytes[i..<i + rLen]); i += rLen
        if r.first == 0x00 && r.count > 1 { r = r.dropFirst() }
        while r.count < 32 { r.insert(0x00, at: 0) }

        // Parse s
        guard i < bytes.count, bytes[i] == 0x02 else {
            throw NSError(domain: "DER", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid DER integer tag for s"])
        }
        i += 1
        let sLen = Int(bytes[i]); i += 1
        guard i + sLen <= bytes.count else {
            throw NSError(domain: "DER", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid s length"])
        }
        var s = Data(bytes[i..<i + sLen])
        if s.first == 0x00 && s.count > 1 { s = s.dropFirst() }
        while s.count < 32 { s.insert(0x00, at: 0) }

        return (r, s)
    }

    // MARK: - Private Helpers

    private nonisolated func loadKey(tag: Data, context: LAContext? = nil) throws -> SecKey {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecReturnRef as String: true
        ]
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw BastionError.keyNotFound
        }
        return item as! SecKey
    }

    /// Creates an LAContext that pre-satisfies `.privateKeyUsage` access control
    /// so the system doesn't show a Touch ID / password dialog.
    nonisolated func silentContext() -> LAContext {
        let ctx = LAContext()
        ctx.setCredential(Data(), type: .applicationPassword)
        return ctx
    }

    /// Delete a key from the Keychain by tag.
    nonisolated func deleteKey(tag: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Recreate Key B and Key C as silent keys (no auth prompt).
    /// Call once if keys were previously created with wrong access controls.
    nonisolated func resetSilentKeys() throws {
        deleteKey(tag: signingKeyTag)
        deleteKey(tag: stateKeyTag)
        _ = try createSilentKey(tag: signingKeyTag)
        _ = try createSilentKey(tag: stateKeyTag)
    }

    private nonisolated func createKey(
        tag: Data,
        accessControlFlags: SecAccessControlCreateFlags
    ) throws -> SecKey {
        var error: Unmanaged<CFError>?

        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessControlFlags,
            &error
        ) else {
            throw error!.takeRetainedValue() as Error
        }

        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access
            ]
        ]

        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return key
    }

    /// Creates an SE key that does NOT trigger any user authentication dialog.
    /// Uses `.applicationPassword` credential to pre-satisfy access control.
    private nonisolated func createSilentKey(tag: Data) throws -> SecKey {
        var error: Unmanaged<CFError>?

        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            &error
        ) else {
            throw error!.takeRetainedValue() as Error
        }

        let context = LAContext()
        context.setCredential(Data(), type: .applicationPassword)

        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access
            ],
            kSecUseAuthenticationContext as String: context
        ]

        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return key
    }
}
