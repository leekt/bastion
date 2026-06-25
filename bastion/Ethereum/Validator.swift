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

nonisolated extension KernelValidator {
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
final class P256Validator: KernelValidator, @unchecked Sendable {
    nonisolated let validatorAddress: String

    private nonisolated let publicKeyX: Data
    private nonisolated let publicKeyY: Data
    private nonisolated let signClosure: @Sendable (Data) throws -> Data

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

    nonisolated var installData: Data {
        // P256 validator expects (x, y) = 64 bytes
        publicKeyX + publicKeyY
    }

    nonisolated func sign(hash: Data) throws -> Data {
        let rawSig = try signClosure(hash) // 64 bytes: r[32] + s[32]
        let r = Data(rawSig.prefix(32))
        let s = P256Curve.normalizeS(Data(rawSig.suffix(32)))
        return r + s
    }

    nonisolated var dummySignature: Data {
        // P256: r[32] + s[32] (no v). Mirror the known-good dummy values used
        // in the TypeScript Kernel flow so sponsor/paymaster simulation sees the
        // same signature shape.
        let r = Data(hexString: "0x635bc6d0f68ff895cae8a288ecf7542a6a9cd555df784b73e1e2ea7e9104b1db")!
        let s = Data(hexString: "0x15e9015d280cb19527881c625fee43fd3a405d5b0d199a8c8e6589a7381209e4")!
        return r + s
    }
}

// MARK: - Known Validator Addresses

nonisolated enum ValidatorAddress {
    static let ecdsaValidator = "0x845ADb2C711129d4f3966735eD98a9F09fC4cE57"
    static let p256Validator = "0x9906AB44fF795883C5a725687A2705BE4118B0f3"
}

// MARK: - P-256 Curve Constants (for s-normalization)

nonisolated enum P256Curve {
    /// P-256 curve order N
    static let N = Data(hexString: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")!
    /// floor(N/2) — signatures must have s <= halfN (OZ P256 requirement)
    static let halfN = Data(hexString: "7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8")!

    /// If s > N/2, return N - s; otherwise return s unchanged.
    static func normalizeS(_ s: Data) -> Data {
        if compareBigEndian(s, halfN) > 0 {
            return subtractBigEndian(N, s)
        }
        return s
    }

    /// Compare two 32-byte big-endian unsigned integers. Returns -1, 0, or 1.
    static func compareBigEndian(_ a: Data, _ b: Data) -> Int {
        let aBytes = [UInt8](a)
        let bBytes = [UInt8](b)
        for i in 0..<min(aBytes.count, bBytes.count) {
            if aBytes[i] < bBytes[i] { return -1 }
            if aBytes[i] > bBytes[i] { return 1 }
        }
        return 0
    }

    /// Subtract two 32-byte big-endian unsigned integers: a - b.
    private static func subtractBigEndian(_ a: Data, _ b: Data) -> Data {
        var result = [UInt8](repeating: 0, count: 32)
        var borrow: Int = 0
        let aBytes = [UInt8](a)
        let bBytes = [UInt8](b)
        for i in stride(from: 31, through: 0, by: -1) {
            let diff = Int(aBytes[i]) - Int(bBytes[i]) - borrow
            if diff < 0 {
                result[i] = UInt8((diff + 256) & 0xFF)
                borrow = 1
            } else {
                result[i] = UInt8(diff)
                borrow = 0
            }
        }
        return Data(result)
    }
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
