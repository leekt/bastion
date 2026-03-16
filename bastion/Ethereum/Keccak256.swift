import Foundation

// MARK: - Keccak-256

/// Swift wrapper around the C Keccak-256 implementation.
/// Produces the 32-byte hash used throughout Ethereum for addresses, tx hashes, etc.
/// This is Keccak-256 (NOT NIST SHA-3 — Ethereum uses the pre-NIST variant with 0x01 padding).
nonisolated enum Keccak256 {

    static func hash(_ data: Data) -> Data {
        var output = Data(repeating: 0, count: 32)
        data.withUnsafeBytes { inputPtr in
            output.withUnsafeMutableBytes { outputPtr in
                keccak256(
                    inputPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    data.count,
                    outputPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        return output
    }

    static func hash(_ bytes: [UInt8]) -> Data {
        hash(Data(bytes))
    }
}
