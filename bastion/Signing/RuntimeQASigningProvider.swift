#if DEBUG
import Foundation
import Security

nonisolated final class RuntimeQASigningProvider: @unchecked Sendable {
    static let shared = RuntimeQASigningProvider()
    static let keyTagPrefix = "com.bastion.signingkey.client.runtime-qa."

    private let lock = NSLock()
    private var keys: [String: SecKey] = [:]

    private init() {}

    func isEnabled(keyTag: String, directory: URL? = nil) -> Bool {
        guard keyTag.hasPrefix(Self.keyTagPrefix) else {
            return false
        }
        if let directory {
            return RuntimeQAConfigOverride.isEnabled(directory: directory)
        }
        return RuntimeQAConfigOverride.isEnabled()
    }

    func publicKeyIfEnabled(keyTag: String, directory: URL? = nil) throws -> PublicKeyResponse? {
        guard isEnabled(keyTag: keyTag, directory: directory) else {
            return nil
        }
        return try publicKey(keyTag: keyTag)
    }

    func signDigestIfEnabled(hash: Data, keyTag: String, directory: URL? = nil) throws -> SignResponse? {
        guard isEnabled(keyTag: keyTag, directory: directory) else {
            return nil
        }
        return try signDigest(hash: hash, keyTag: keyTag)
    }

    private func publicKey(keyTag: String) throws -> PublicKeyResponse {
        let pubData = try publicKeyData(for: try key(for: keyTag))
        return PublicKeyResponse(
            x: pubData.subdata(in: 1..<33).hex,
            y: pubData.subdata(in: 33..<65).hex,
            accountAddress: accountAddress(for: pubData)
        )
    }

    private func signDigest(hash: Data, keyTag: String) throws -> SignResponse {
        guard hash.count == 32 else {
            throw BastionError.invalidInput
        }
        let privateKey = try key(for: keyTag)
        let pubData = try publicKeyData(for: privateKey)

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureDigestX962SHA256,
            hash as CFData,
            &error
        ) as Data? else {
            throw securityError(error, fallback: .signingFailed)
        }
        let (r, s) = try SecureEnclaveManager.shared.parseDER(signature)

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

    private func key(for keyTag: String) throws -> SecKey {
        lock.lock()
        defer { lock.unlock() }

        if let existing = keys[keyTag] {
            return existing
        }

        var error: Unmanaged<CFError>?
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw securityError(error, fallback: .keyCreationFailed)
        }
        keys[keyTag] = key
        return key
    }

    private func publicKeyData(for privateKey: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw BastionError.keyNotFound
        }

        var error: Unmanaged<CFError>?
        guard let pubData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?,
              pubData.count >= 65 else {
            throw securityError(error, fallback: .keyNotFound)
        }
        return pubData
    }

    private func accountAddress(for publicKeyData: Data) -> String? {
        guard publicKeyData.count >= 65 else {
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

    private func securityError(
        _ error: Unmanaged<CFError>?,
        fallback: BastionError
    ) -> Error {
        guard let error else {
            return fallback
        }
        return error.takeRetainedValue() as Error
    }
}
#endif
