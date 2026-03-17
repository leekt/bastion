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

// MARK: - UserOperation Submission

nonisolated enum UserOperationSubmissionProvider: String, Codable, Sendable {
    case zeroDev = "zerodev"

    var displayName: String {
        switch self {
        case .zeroDev:
            return "ZeroDev"
        }
    }
}

nonisolated struct UserOperationSubmissionRequest: Codable, Sendable {
    let provider: UserOperationSubmissionProvider
    let projectId: String?

    init(
        provider: UserOperationSubmissionProvider = .zeroDev,
        projectId: String? = nil
    ) {
        self.provider = provider
        self.projectId = projectId
    }

    private enum CodingKeys: String, CodingKey {
        case provider
        case projectId
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        provider = try container.decodeIfPresent(UserOperationSubmissionProvider.self, forKey: .provider) ?? .zeroDev
        projectId = try container.decodeIfPresent(String.self, forKey: .projectId)
    }
}

nonisolated struct UserOperationRequestEnvelope: Codable, Sendable {
    let userOperation: UserOperation
    let submission: UserOperationSubmissionRequest?
}

nonisolated struct SelfUserOperationRequest: Codable, Sendable {
    let projectId: String?
    let chainId: Int

    init(projectId: String? = nil, chainId: Int = 11155111) {
        self.projectId = projectId
        self.chainId = chainId
    }
}

nonisolated struct RequestedExecution: Codable, Sendable {
    let target: String
    let value: String
    let data: Data

    private enum CodingKeys: String, CodingKey {
        case target
        case value
        case data
    }

    init(target: String, value: String, data: Data) {
        self.target = target
        self.value = value
        self.data = data
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        target = try container.decode(String.self, forKey: .target)
        value = try container.decode(String.self, forKey: .value)
        data = try container.decodeHexData(forKey: .data)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
        try container.encode(value, forKey: .value)
        try container.encodeHexData(data, forKey: .data)
    }
}

nonisolated struct UserOperationIntentRequestEnvelope: Codable, Sendable {
    let projectId: String?
    let chainId: Int
    let executions: [RequestedExecution]
    let submit: Bool

    init(
        projectId: String? = nil,
        chainId: Int = 11155111,
        executions: [RequestedExecution],
        submit: Bool = false
    ) {
        self.projectId = projectId
        self.chainId = chainId
        self.executions = executions
        self.submit = submit
    }
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

    enum CodingKeys: String, CodingKey {
        case sender
        case nonce
        case callData
        case factory
        case factoryData
        case verificationGasLimit
        case callGasLimit
        case preVerificationGas
        case maxPriorityFeePerGas
        case maxFeePerGas
        case paymaster
        case paymasterVerificationGasLimit
        case paymasterPostOpGasLimit
        case paymasterData
        case chainId
        case entryPoint
        case entryPointVersion
    }

    nonisolated init(
        sender: String,
        nonce: String,
        callData: Data,
        factory: String? = nil,
        factoryData: Data? = nil,
        verificationGasLimit: String,
        callGasLimit: String,
        preVerificationGas: String,
        maxPriorityFeePerGas: String,
        maxFeePerGas: String,
        paymaster: String? = nil,
        paymasterVerificationGasLimit: String? = nil,
        paymasterPostOpGasLimit: String? = nil,
        paymasterData: Data? = nil,
        chainId: Int,
        entryPoint: String,
        entryPointVersion: EntryPointVersion
    ) {
        self.sender = sender
        self.nonce = nonce
        self.callData = callData
        self.factory = factory
        self.factoryData = factoryData
        self.verificationGasLimit = verificationGasLimit
        self.callGasLimit = callGasLimit
        self.preVerificationGas = preVerificationGas
        self.maxPriorityFeePerGas = maxPriorityFeePerGas
        self.maxFeePerGas = maxFeePerGas
        self.paymaster = paymaster
        self.paymasterVerificationGasLimit = paymasterVerificationGasLimit
        self.paymasterPostOpGasLimit = paymasterPostOpGasLimit
        self.paymasterData = paymasterData
        self.chainId = chainId
        self.entryPoint = entryPoint
        self.entryPointVersion = entryPointVersion
    }

    nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sender = try container.decode(String.self, forKey: .sender)
        nonce = try container.decode(String.self, forKey: .nonce)
        callData = try container.decodeHexData(forKey: .callData)
        factory = try container.decodeIfPresent(String.self, forKey: .factory)
        factoryData = try container.decodeHexDataIfPresent(forKey: .factoryData)
        verificationGasLimit = try container.decode(String.self, forKey: .verificationGasLimit)
        callGasLimit = try container.decode(String.self, forKey: .callGasLimit)
        preVerificationGas = try container.decode(String.self, forKey: .preVerificationGas)
        maxPriorityFeePerGas = try container.decode(String.self, forKey: .maxPriorityFeePerGas)
        maxFeePerGas = try container.decode(String.self, forKey: .maxFeePerGas)
        paymaster = try container.decodeIfPresent(String.self, forKey: .paymaster)
        paymasterVerificationGasLimit = try container.decodeIfPresent(String.self, forKey: .paymasterVerificationGasLimit)
        paymasterPostOpGasLimit = try container.decodeIfPresent(String.self, forKey: .paymasterPostOpGasLimit)
        paymasterData = try container.decodeHexDataIfPresent(forKey: .paymasterData)
        chainId = try container.decode(Int.self, forKey: .chainId)
        entryPoint = try container.decode(String.self, forKey: .entryPoint)
        entryPointVersion = try container.decode(EntryPointVersion.self, forKey: .entryPointVersion)
    }

    nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(sender, forKey: .sender)
        try container.encode(nonce, forKey: .nonce)
        try container.encodeHexData(callData, forKey: .callData)
        try container.encodeIfPresent(factory, forKey: .factory)
        try container.encodeHexDataIfPresent(factoryData, forKey: .factoryData)
        try container.encode(verificationGasLimit, forKey: .verificationGasLimit)
        try container.encode(callGasLimit, forKey: .callGasLimit)
        try container.encode(preVerificationGas, forKey: .preVerificationGas)
        try container.encode(maxPriorityFeePerGas, forKey: .maxPriorityFeePerGas)
        try container.encode(maxFeePerGas, forKey: .maxFeePerGas)
        try container.encodeIfPresent(paymaster, forKey: .paymaster)
        try container.encodeIfPresent(paymasterVerificationGasLimit, forKey: .paymasterVerificationGasLimit)
        try container.encodeIfPresent(paymasterPostOpGasLimit, forKey: .paymasterPostOpGasLimit)
        try container.encodeHexDataIfPresent(paymasterData, forKey: .paymasterData)
        try container.encode(chainId, forKey: .chainId)
        try container.encode(entryPoint, forKey: .entryPoint)
        try container.encode(entryPointVersion, forKey: .entryPointVersion)
    }
}

private nonisolated extension KeyedDecodingContainer {
    func decodeHexData(forKey key: Key) throws -> Data {
        let value = try decode(String.self, forKey: key)
        if let data = Data(hexString: value) {
            return data
        }
        throw DecodingError.dataCorruptedError(
            forKey: key,
            in: self,
            debugDescription: "Expected hex string for \(key.stringValue). Base64 is not supported."
        )
    }

    func decodeHexDataIfPresent(forKey key: Key) throws -> Data? {
        guard let value = try decodeIfPresent(String.self, forKey: key) else {
            return nil
        }
        if let data = Data(hexString: value) {
            return data
        }
        throw DecodingError.dataCorruptedError(
            forKey: key,
            in: self,
            debugDescription: "Expected hex string for \(key.stringValue). Base64 is not supported."
        )
    }
}

private nonisolated extension KeyedEncodingContainer {
    mutating func encodeHexData(_ data: Data, forKey key: Key) throws {
        try encode("0x" + data.hex, forKey: key)
    }

    mutating func encodeHexDataIfPresent(_ data: Data?, forKey key: Key) throws {
        guard let data else { return }
        try encode("0x" + data.hex, forKey: key)
    }
}

// MARK: - AnyCodable (for EIP-712 message values)

nonisolated struct AnyCodable: Codable, @unchecked Sendable {
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
