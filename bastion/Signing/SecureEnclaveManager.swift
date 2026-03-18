import Foundation
import LocalAuthentication
import Security

nonisolated final class SecureEnclaveManager: Sendable {
    static let shared = SecureEnclaveManager()
    nonisolated static let defaultSigningKeyIdentifier = "com.bastion.signingkey.default"
    nonisolated static let legacySigningKeyIdentifier = "com.bastion.signingkey"

    private let defaultSigningKeyTag = SecureEnclaveManager.defaultSigningKeyIdentifier.data(using: .utf8)!
    private let legacySigningKeyTag = SecureEnclaveManager.legacySigningKeyIdentifier.data(using: .utf8)!

    private init() {}

    // MARK: - Key Management

    nonisolated func loadOrCreateSigningKey() throws -> SecKey {
        try loadOrCreateSigningKey(keyTag: Self.defaultSigningKeyIdentifier, allowLegacyFallback: true)
    }

    nonisolated func loadOrCreateSigningKey(keyTag: String) throws -> SecKey {
        try loadOrCreateSigningKey(keyTag: keyTag, allowLegacyFallback: false)
    }

    // MARK: - Signing (Key B)

    /// Sign an arbitrary message payload using SHA-256 inside the Secure Enclave.
    /// This is not appropriate for Ethereum signing flows because those requests
    /// already provide a finalized 32-byte Keccak digest.
    nonisolated func sign(data: Data) throws -> SignResponse {
        try sign(data: data, keyTag: Self.defaultSigningKeyIdentifier)
    }

    nonisolated func sign(data: Data, keyTag: String) throws -> SignResponse {
        let privateKey = try loadOrCreateSigningKey(
            keyTag: keyTag,
            allowLegacyFallback: keyTag == Self.defaultSigningKeyIdentifier
        )

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
            s: s.hex,
            accountAddress: accountAddress(for: pubData),
            clientBundleId: nil,
            submission: nil
        )
    }

    /// Sign a raw 32-byte digest directly with P-256 ECDSA.
    /// Uses `.ecdsaSignatureDigestX962SHA256` so the Secure Enclave signs the digest as-is.
    /// This is the correct path for Ethereum message, typed-data, and UserOperation signing.
    nonisolated func signDigest(hash: Data) throws -> SignResponse {
        try signDigest(hash: hash, keyTag: Self.defaultSigningKeyIdentifier)
    }

    nonisolated func signDigest(hash: Data, keyTag: String) throws -> SignResponse {
        let privateKey = try loadOrCreateSigningKey(
            keyTag: keyTag,
            allowLegacyFallback: keyTag == Self.defaultSigningKeyIdentifier
        )

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw BastionError.keyNotFound
        }

        var error: Unmanaged<CFError>?
        guard let pubData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureDigestX962SHA256,
            hash as CFData,
            &error
        ) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        let (r, s) = try parseDER(signature)

        return SignResponse(
            pubkeyX: pubData.subdata(in: 1..<33).hex,
            pubkeyY: pubData.subdata(in: 33..<65).hex,
            r: r.hex,
            s: s.hex,
            accountAddress: accountAddress(for: pubData),
            clientBundleId: nil,
            submission: nil
        )
    }

    nonisolated func getPublicKey() throws -> PublicKeyResponse {
        try getPublicKey(keyTag: Self.defaultSigningKeyIdentifier)
    }

    nonisolated func getPublicKey(keyTag: String) throws -> PublicKeyResponse {
        let privateKey = try loadOrCreateSigningKey(
            keyTag: keyTag,
            allowLegacyFallback: keyTag == Self.defaultSigningKeyIdentifier
        )

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw BastionError.keyNotFound
        }

        var error: Unmanaged<CFError>?
        guard let pubData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        return PublicKeyResponse(
            x: pubData.subdata(in: 1..<33).hex,
            y: pubData.subdata(in: 33..<65).hex,
            accountAddress: accountAddress(for: pubData)
        )
    }

    nonisolated func deleteSigningKeys(keyTags: [String]) -> [String] {
        let uniqueTags = Array(Set(keyTags))
        return uniqueTags.filter { deleteSigningKey(keyTag: $0) }
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

    private nonisolated func loadOrCreateSigningKey(keyTag: String, allowLegacyFallback: Bool) throws -> SecKey {
        let tag = keyTag.data(using: .utf8) ?? defaultSigningKeyTag
        if let existing = try? loadKey(tag: tag, context: silentContext()) {
            return existing
        }
        if allowLegacyFallback,
           let existing = try? loadKey(tag: legacySigningKeyTag, context: silentContext()) {
            return existing
        }
        return try createSilentKey(tag: tag)
    }

    private nonisolated func accountAddress(for publicKeyData: Data) -> String? {
        guard publicKeyData.count == 65 else {
            return nil
        }

        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: publicKeyData.subdata(in: 1..<33),
            publicKeyY: publicKeyData.subdata(in: 33..<65),
            sign: { _ in Data(repeating: 0, count: 64) }
        )
        return SmartAccount(validator: validator).computeAddress()
    }

    private nonisolated func deleteSigningKey(keyTag: String) -> Bool {
        guard let tag = keyTag.data(using: .utf8) else {
            return false
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }

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
