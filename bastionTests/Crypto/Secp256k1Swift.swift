import Foundation
@testable import bastion

// MARK: - secp256k1 Swift Wrapper (test-only)

/// Swift wrapper around the OpenSSL-based C secp256k1 helper.
/// Only available in the test target.
nonisolated enum Secp256k1 {

    /// Derive uncompressed public key (65 bytes) and Ethereum address (20 bytes) from private key.
    static func derivePublicKey(privateKey: Data) throws -> (publicKey: Data, ethAddress: Data) {
        guard privateKey.count == 32 else {
            throw ValidatorError.invalidPrivateKey
        }

        var pubkey = Data(repeating: 0, count: 65)
        var address = Data(repeating: 0, count: 20)

        let privBytes = [UInt8](privateKey)
        let pubResult = pubkey.withUnsafeMutableBytes { pubPtr -> Int32 in
            secp256k1_derive_pubkey(privBytes, pubPtr.bindMemory(to: UInt8.self).baseAddress!)
        }
        guard pubResult == 0 else {
            throw ValidatorError.signingFailed("Failed to derive public key")
        }

        let pubBytes = [UInt8](pubkey)
        let addrResult = address.withUnsafeMutableBytes { addrPtr -> Int32 in
            secp256k1_eth_address(pubBytes, addrPtr.bindMemory(to: UInt8.self).baseAddress!)
        }
        guard addrResult == 0 else {
            throw ValidatorError.signingFailed("Failed to derive Ethereum address")
        }

        return (pubkey, address)
    }

    /// Sign a 32-byte hash with secp256k1 ECDSA. Returns r[32] + s[32] + v[1] = 65 bytes.
    static func sign(hash: Data, privateKey: Data) throws -> Data {
        guard hash.count == 32, privateKey.count == 32 else {
            throw ValidatorError.signingFailed("Hash must be 32 bytes, private key must be 32 bytes")
        }

        var sig = Data(repeating: 0, count: 65)
        let privBytes = [UInt8](privateKey)
        let hashBytes = [UInt8](hash)

        let result = sig.withUnsafeMutableBytes { sigPtr -> Int32 in
            secp256k1_sign_hash(privBytes, hashBytes, sigPtr.bindMemory(to: UInt8.self).baseAddress!)
        }
        guard result == 0 else {
            throw ValidatorError.signingFailed("secp256k1 signing failed")
        }

        return sig
    }
}

// MARK: - ECDSA Validator (test-only)

/// Kernel v3.3 ECDSA validator using secp256k1.
/// Only used for testing ZeroDev integration — not included in production app.
nonisolated final class ECDSAValidator: KernelValidator, @unchecked Sendable {
    let validatorAddress = ValidatorAddress.ecdsaValidator

    private let privateKeyData: Data
    let publicKeyData: Data
    let ethereumAddress: Data

    init(privateKey: Data) throws {
        guard privateKey.count == 32 else {
            throw ValidatorError.invalidPrivateKey
        }
        self.privateKeyData = privateKey
        let (pubKey, ethAddr) = try Secp256k1.derivePublicKey(privateKey: privateKey)
        self.publicKeyData = pubKey
        self.ethereumAddress = ethAddr
    }

    /// Convenience: create from hex private key string.
    convenience init(privateKeyHex: String) throws {
        guard let data = Data(hexString: privateKeyHex) else {
            throw ValidatorError.invalidPrivateKey
        }
        try self.init(privateKey: data)
    }

    var installData: Data {
        // ECDSA validator expects owner address (20 bytes)
        ethereumAddress
    }

    func sign(hash: Data) throws -> Data {
        try Secp256k1.sign(hash: hash, privateKey: privateKeyData)
    }

    var dummySignature: Data {
        // ZeroDev-compatible dummy signature for gas estimation
        // Must be valid for ecrecover (r < secp256k1n, s < secp256k1n/2)
        // but won't match the actual owner — bundler uses this for simulation
        Data(hexString: "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c")!
    }

    /// Ethereum address as checksummed hex string.
    var addressHex: String {
        "0x" + ethereumAddress.map { String(format: "%02x", $0) }.joined()
    }
}
