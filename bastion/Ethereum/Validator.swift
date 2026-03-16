import Foundation

// MARK: - Validator Protocol

/// A modular validator for Kernel v3.3 smart accounts.
/// Implementors provide signing, signature encoding, and install data
/// for a specific signature scheme (ECDSA, P-256, etc.).
nonisolated protocol KernelValidator: Sendable {
    /// Validator contract address (deployed on-chain).
    var validatorAddress: String { get }

    /// Returns the 21-byte ValidationId: `0x01` (VALIDATOR type) + address (20 bytes).
    var validationId: Data { get }

    /// Install data passed to `Kernel.initialize(validationId, hook, validatorData, ...)`.
    /// For ECDSA: owner address (20 bytes). For P256: pubkey x,y (64 bytes).
    var installData: Data { get }

    /// Sign a 32-byte hash and return the raw signature bytes expected by the on-chain validator.
    /// - For ECDSA: 65 bytes (r[32] + s[32] + v[1])
    /// - For P256: 64 bytes (r[32] + s[32])
    func sign(hash: Data) throws -> Data

    /// Dummy signature for gas estimation (must be valid format but doesn't need to verify).
    var dummySignature: Data { get }
}

extension KernelValidator {
    var validationId: Data {
        var id = Data([0x01])
        id += Data(hexString: validatorAddress) ?? Data(repeating: 0, count: 20)
        return id
    }

    var dummySignature: Data {
        Data(repeating: 0xff, count: 65)
    }
}

// MARK: - P256 Validator (Secure Enclave) — Production

/// Kernel v3.3 P256 validator using Apple Secure Enclave.
nonisolated final class P256Validator: KernelValidator, Sendable {
    let validatorAddress: String

    private let publicKeyX: Data
    private let publicKeyY: Data
    private let signClosure: @Sendable (Data) throws -> Data

    init(
        validatorAddress: String,
        publicKeyX: Data,
        publicKeyY: Data,
        sign: @escaping @Sendable (Data) throws -> Data
    ) {
        self.validatorAddress = validatorAddress
        self.publicKeyX = publicKeyX
        self.publicKeyY = publicKeyY
        self.signClosure = sign
    }

    var installData: Data {
        // P256 validator expects (x, y) = 64 bytes
        publicKeyX + publicKeyY
    }

    func sign(hash: Data) throws -> Data {
        try signClosure(hash)
    }

    var dummySignature: Data {
        // P256: r[32] + s[32] (no v)
        Data(repeating: 0xff, count: 64)
    }
}

// MARK: - Known Validator Addresses

nonisolated enum ValidatorAddress {
    static let ecdsaValidator = "0x845ADb2C711129d4f3966735eD98a9F09fC4cE57"
}

// MARK: - Validator Errors

nonisolated enum ValidatorError: Error, CustomStringConvertible {
    case invalidPrivateKey
    case signingFailed(String)

    var description: String {
        switch self {
        case .invalidPrivateKey: return "Invalid private key"
        case .signingFailed(let msg): return "Signing failed: \(msg)"
        }
    }
}
