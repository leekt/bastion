import Foundation
import LocalAuthentication
import Security

nonisolated final class SecureEnclaveManager: Sendable {
    static let shared = SecureEnclaveManager()

    private let signingKeyTag = "com.bastion.signingkey".data(using: .utf8)!

    private init() {}

    // MARK: - Key Management

    nonisolated func loadOrCreateSigningKey() throws -> SecKey {
        if let existing = try? loadKey(tag: signingKeyTag, context: silentContext()) {
            return existing
        }
        return try createSilentKey(tag: signingKeyTag)
    }

    // MARK: - Signing (Key B)

    /// Sign an arbitrary message payload using SHA-256 inside the Secure Enclave.
    /// This is not appropriate for Ethereum signing flows because those requests
    /// already provide a finalized 32-byte Keccak digest.
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

    /// Sign a raw 32-byte digest directly with P-256 ECDSA.
    /// Uses `.ecdsaSignatureDigestX962SHA256` so the Secure Enclave signs the digest as-is.
    /// This is the correct path for Ethereum message, typed-data, and UserOperation signing.
    nonisolated func signDigest(hash: Data) throws -> SignResponse {
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
