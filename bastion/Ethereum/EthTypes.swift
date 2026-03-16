import Foundation

// MARK: - Signing Operation

/// Typed signing operations that Bastion understands.
/// Each variant knows its semantics and can be validated by the rule engine.
nonisolated enum SigningOperation: Sendable {
    case message(String)
    case typedData(EIP712TypedData)
    case userOperation(UserOperation)

    var displayDescription: String {
        switch self {
        case .message(let text):
            let preview = text.count > 80 ? "\(text.prefix(80))..." : text
            return "Sign message: \"\(preview)\""
        case .typedData(let data):
            return "Sign typed data: \(data.domain.name ?? "unknown")"
        case .userOperation(let op):
            let sender = "\(op.sender.prefix(10))..."
            let chain = ChainConfig.name(for: op.chainId)
            return "Sign UserOp from \(sender) on \(chain) (EP \(op.entryPointVersion.rawValue))"
        }
    }

    var chainId: Int? {
        switch self {
        case .message: return nil
        case .typedData(let data): return data.domain.chainId
        case .userOperation(let op): return op.chainId
        }
    }

    var targetAddress: String? {
        switch self {
        case .message: return nil
        case .typedData(let data): return data.domain.verifyingContract
        case .userOperation(let op): return op.sender
        }
    }

    var ethValue: String? {
        switch self {
        case .message: return nil
        case .typedData: return nil
        case .userOperation: return nil
        }
    }

    var calldata: Data? {
        switch self {
        case .message: return nil
        case .typedData: return nil
        case .userOperation(let op): return op.callData
        }
    }

    var selector: Data? {
        guard let data = calldata, data.count >= 4 else { return nil }
        return data.prefix(4)
    }
}

// MARK: - EIP-712 Typed Data

nonisolated struct EIP712TypedData: Codable, Sendable {
    let types: [String: [EIP712Field]]
    let primaryType: String
    let domain: EIP712Domain
    let message: [String: AnyCodable]
}

nonisolated struct EIP712Field: Codable, Sendable {
    let name: String
    let type: String
}

nonisolated struct EIP712Domain: Codable, Sendable {
    let name: String?
    let version: String?
    let chainId: Int?
    let verifyingContract: String?
    let salt: String?
}

// MARK: - EntryPoint Version

/// Supported EntryPoint versions. v0.7/v0.8/v0.9 share the same PackedUserOperation struct.
nonisolated enum EntryPointVersion: String, Codable, Sendable {
    case v0_7 = "v0.7"
    case v0_8 = "v0.8"
    case v0_9 = "v0.9"
}

// MARK: - ERC-4337 PackedUserOperation (v0.7+)

/// Represents an ERC-4337 PackedUserOperation as defined in EntryPoint v0.7+.
/// All numeric fields are hex-encoded strings (with 0x prefix).
/// Hash computation: keccak256(abi.encode(userOpHash, entryPoint, chainId))
nonisolated struct UserOperation: Codable, Sendable {
    let sender: String                  // address
    let nonce: String                   // uint256 hex
    let callData: Data                  // bytes

    // Account deployment (optional)
    let factory: String?                // address — nil if not deploying
    let factoryData: Data?              // bytes

    // Gas (packed into bytes32 on-chain, but separate here for readability)
    let verificationGasLimit: String    // uint128 hex
    let callGasLimit: String            // uint128 hex
    let preVerificationGas: String      // uint256 hex
    let maxPriorityFeePerGas: String    // uint128 hex
    let maxFeePerGas: String            // uint128 hex

    // Paymaster (optional)
    let paymaster: String?              // address — nil if no paymaster
    let paymasterVerificationGasLimit: String?  // uint128 hex
    let paymasterPostOpGasLimit: String?        // uint128 hex
    let paymasterData: Data?            // bytes

    // Bastion metadata (not part of on-chain struct)
    let chainId: Int
    let entryPoint: String              // entrypoint contract address
    let entryPointVersion: EntryPointVersion
}

// MARK: - AnyCodable (for EIP-712 message values)

nonisolated struct AnyCodable: Codable, Sendable {
    let value: Any

    nonisolated init(_ value: Any) {
        self.value = value
    }

    nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let string = try? container.decode(String.self) {
            value = string
        } else if let int = try? container.decode(Int.self) {
            value = int
        } else if let bool = try? container.decode(Bool.self) {
            value = bool
        } else if let double = try? container.decode(Double.self) {
            value = double
        } else if let array = try? container.decode([AnyCodable].self) {
            value = array.map(\.value)
        } else if let dict = try? container.decode([String: AnyCodable].self) {
            value = dict.mapValues(\.value)
        } else {
            value = NSNull()
        }
    }

    nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch value {
        case let string as String: try container.encode(string)
        case let int as Int: try container.encode(int)
        case let bool as Bool: try container.encode(bool)
        case let double as Double: try container.encode(double)
        default: try container.encodeNil()
        }
    }
}
