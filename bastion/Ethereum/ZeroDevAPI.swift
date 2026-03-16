import Foundation

// MARK: - ZeroDev Bundler API Client

/// Client for the ZeroDev bundler API (ERC-4337 bundler + paymaster).
/// Uses project-based RPC endpoint: `https://rpc.zerodev.app/api/v3/{projectId}/chain/{chainId}`
nonisolated final class ZeroDevAPI: Sendable {

    let projectId: String

    init(projectId: String) {
        if projectId.hasPrefix("0x") {
            self.projectId = String(projectId.dropFirst(2))
        } else {
            self.projectId = projectId
        }
    }

    // MARK: - RPC Endpoint

    func rpcURL(chainId: Int) -> URL {
        URL(string: "https://rpc.zerodev.app/api/v3/\(projectId)/chain/\(chainId)")!
    }

    // MARK: - Bundler Methods

    /// Get supported EntryPoint addresses.
    func supportedEntryPoints(chainId: Int) async throws -> [String] {
        let result: [String] = try await jsonRPC(
            method: "eth_supportedEntryPoints",
            params: [] as [String],
            chainId: chainId
        )
        return result
    }

    /// Estimate gas for a UserOperation.
    func estimateUserOperationGas(
        _ op: UserOperationRPC,
        entryPoint: String,
        chainId: Int
    ) async throws -> GasEstimate {
        try await jsonRPC(
            method: "eth_estimateUserOperationGas",
            params: [AnyCodableRPC(op), AnyCodableRPC(entryPoint)],
            chainId: chainId
        )
    }

    /// Get bundler-recommended gas prices for UserOperations.
    func userOperationGasPrice(chainId: Int) async throws -> UserOperationGasPriceResult {
        try await jsonRPC(
            method: "pimlico_getUserOperationGasPrice",
            params: [] as [String],
            chainId: chainId
        )
    }

    /// Send a signed UserOperation to the bundler.
    func sendUserOperation(
        _ op: UserOperationRPC,
        entryPoint: String,
        chainId: Int
    ) async throws -> String {
        try await jsonRPC(
            method: "eth_sendUserOperation",
            params: [AnyCodableRPC(op), AnyCodableRPC(entryPoint)],
            chainId: chainId
        )
    }

    /// Get UserOperation receipt by hash.
    func getUserOperationReceipt(
        userOpHash: String,
        chainId: Int
    ) async throws -> UserOperationReceipt? {
        try await jsonRPCOptional(
            method: "eth_getUserOperationReceipt",
            params: [userOpHash],
            chainId: chainId
        )
    }

    // MARK: - Paymaster Methods

    /// Sponsor a UserOperation via ZeroDev's paymaster.
    /// Returns paymaster data and gas estimates. Uses the same v3 RPC endpoint.
    func sponsorUserOperation(
        _ op: UserOperationRPC,
        entryPoint: String,
        chainId: Int
    ) async throws -> SponsorResult {
        let params = SponsorParams(
            chainId: chainId,
            userOp: op,
            entryPointAddress: entryPoint
        )
        return try await jsonRPC(
            method: "zd_sponsorUserOperation",
            params: [AnyCodableRPC(params)],
            chainId: chainId
        )
    }

    // MARK: - JSON-RPC Transport

    private func jsonRPC<T: Decodable>(
        method: String,
        params: [any Encodable],
        chainId: Int
    ) async throws -> T {
        let url = rpcURL(chainId: chainId)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body = JSONRPCRequest(
            jsonrpc: "2.0",
            id: 1,
            method: method,
            params: params.map { AnyCodableRPC($0) }
        )
        request.httpBody = try JSONEncoder().encode(body)

        #if DEBUG
        if method == "eth_sendUserOperation" || method == "eth_estimateUserOperationGas",
           let jsonStr = String(data: request.httpBody!, encoding: .utf8) {
            print("[\(method)] JSON payload:\n\(jsonStr)")
        }
        #endif

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ZeroDevError.networkError("Invalid response")
        }

        guard httpResponse.statusCode == 200 else {
            let body = String(data: data, encoding: .utf8) ?? "unknown"
            throw ZeroDevError.httpError(httpResponse.statusCode, body)
        }

        let rpcResponse = try JSONDecoder().decode(JSONRPCResponse<T>.self, from: data)

        if let error = rpcResponse.error {
            throw ZeroDevError.rpcError(error.code, error.message)
        }

        guard let result = rpcResponse.result else {
            throw ZeroDevError.emptyResult
        }

        return result
    }

    private func jsonRPCOptional<T: Decodable>(
        method: String,
        params: [any Encodable],
        chainId: Int
    ) async throws -> T? {
        let url = rpcURL(chainId: chainId)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body = JSONRPCRequest(
            jsonrpc: "2.0",
            id: 1,
            method: method,
            params: params.map { AnyCodableRPC($0) }
        )
        request.httpBody = try JSONEncoder().encode(body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ZeroDevError.networkError("Invalid response")
        }

        guard httpResponse.statusCode == 200 else {
            let body = String(data: data, encoding: .utf8) ?? "unknown"
            throw ZeroDevError.httpError(httpResponse.statusCode, body)
        }

        let rpcResponse = try JSONDecoder().decode(JSONRPCResponse<T>.self, from: data)

        if let error = rpcResponse.error {
            throw ZeroDevError.rpcError(error.code, error.message)
        }

        return rpcResponse.result
    }
}

// MARK: - RPC Types

nonisolated struct UserOperationRPC: Codable, Sendable {
    let sender: String
    let nonce: String
    let callData: String         // hex-encoded
    let initCode: String?        // hex-encoded (v0.7 legacy), or nil
    let factory: String?         // v0.7+ field
    let factoryData: String?     // v0.7+ field, hex-encoded
    let callGasLimit: String
    let verificationGasLimit: String
    let preVerificationGas: String
    let maxFeePerGas: String
    let maxPriorityFeePerGas: String
    let paymaster: String?
    let paymasterVerificationGasLimit: String?
    let paymasterPostOpGasLimit: String?
    let paymasterData: String?   // hex-encoded
    let signature: String        // hex-encoded

    /// Convert from our internal UserOperation (with signature).
    static func from(_ op: UserOperation, signature: Data) -> UserOperationRPC {
        UserOperationRPC(
            sender: op.sender,
            nonce: op.nonce,
            callData: "0x" + op.callData.hex,
            initCode: nil,
            factory: op.factory,
            factoryData: op.factoryData.map { "0x" + $0.hex },
            callGasLimit: op.callGasLimit,
            verificationGasLimit: op.verificationGasLimit,
            preVerificationGas: op.preVerificationGas,
            maxFeePerGas: op.maxFeePerGas,
            maxPriorityFeePerGas: op.maxPriorityFeePerGas,
            paymaster: op.paymaster,
            paymasterVerificationGasLimit: op.paymasterVerificationGasLimit,
            paymasterPostOpGasLimit: op.paymasterPostOpGasLimit,
            paymasterData: op.paymasterData.map { "0x" + $0.hex },
            signature: "0x" + signature.hex
        )
    }
}

nonisolated struct SponsorParams: Encodable, Sendable {
    let chainId: Int
    let userOp: UserOperationRPC
    let entryPointAddress: String
}

nonisolated struct SponsorResult: Codable, Sendable {
    let paymaster: String?
    let paymasterData: String?
    let paymasterVerificationGasLimit: String?
    let paymasterPostOpGasLimit: String?
    let preVerificationGas: String?
    let verificationGasLimit: String?
    let callGasLimit: String?
    let maxFeePerGas: String?
    let maxPriorityFeePerGas: String?
}

nonisolated struct GasEstimate: Codable, Sendable {
    let callGasLimit: String
    let verificationGasLimit: String
    let preVerificationGas: String
    let paymasterVerificationGasLimit: String?
    let paymasterPostOpGasLimit: String?
}

nonisolated struct UserOperationGasPriceTier: Codable, Sendable {
    let maxFeePerGas: String
    let maxPriorityFeePerGas: String
}

nonisolated struct UserOperationGasPriceResult: Codable, Sendable {
    let slow: UserOperationGasPriceTier
    let standard: UserOperationGasPriceTier
    let fast: UserOperationGasPriceTier
}

nonisolated struct UserOperationReceipt: Codable, Sendable {
    let userOpHash: String
    let success: Bool
    let actualGasCost: String?
    let actualGasUsed: String?
    let receipt: TransactionReceipt?
}

nonisolated struct TransactionReceipt: Codable, Sendable {
    let transactionHash: String
    let blockNumber: String?
    let status: String?
}

// MARK: - JSON-RPC Envelope

private nonisolated struct JSONRPCRequest: Encodable, Sendable {
    let jsonrpc: String
    let id: Int
    let method: String
    let params: [AnyCodableRPC]
}

private nonisolated struct JSONRPCResponse<T: Decodable>: Decodable, Sendable where T: Sendable {
    let jsonrpc: String?
    let id: Int?
    let result: T?
    let error: JSONRPCError?
}

private nonisolated struct JSONRPCError: Decodable, Sendable {
    let code: Int
    let message: String
}

// MARK: - AnyCodable for RPC params

private nonisolated struct AnyCodableRPC: Encodable, Sendable {
    private let _encode: @Sendable (Encoder) throws -> Void

    init<T: Encodable & Sendable>(_ value: T) {
        _encode = { encoder in
            try value.encode(to: encoder)
        }
    }

    func encode(to encoder: Encoder) throws {
        try _encode(encoder)
    }
}

// MARK: - Errors

nonisolated enum ZeroDevError: Error, CustomStringConvertible {
    case networkError(String)
    case httpError(Int, String)
    case rpcError(Int, String)
    case emptyResult

    var description: String {
        switch self {
        case .networkError(let msg): return "Network error: \(msg)"
        case .httpError(let code, let body): return "HTTP \(code): \(body)"
        case .rpcError(let code, let msg): return "RPC error \(code): \(msg)"
        case .emptyResult: return "Empty RPC result"
        }
    }
}

// MARK: - Known EntryPoint Addresses

nonisolated enum EntryPointAddress {
    static let v0_7 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
    static let v0_8 = "0x4337084d9e255ff0702461cf8895ce9e3b5ff108"
    static let v0_9 = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"

    static func address(for version: EntryPointVersion) -> String {
        switch version {
        case .v0_7: return v0_7
        case .v0_8: return v0_8
        case .v0_9: return v0_9
        }
    }
}

// MARK: - Known Kernel v3.3 Addresses

nonisolated enum KernelAddress {
    static let metaFactory = "0xd703aaE79538628d27099B8c4f621bE4CCd142d5"
    static let factory = "0x2577507b78c2008Ff367261CB6285d44ba5eF2E9"
    static let implementation = "0xd6CEDDe84be40893d153Be9d467CD6aD37875b28"
}

nonisolated enum KernelV3_3 {
    /// ERC-1967 proxy init code hash for Kernel v3.3 factory (for CREATE2 address computation)
    static let initCodeHash = "0xc452397f1e7518f8cea0566ac057e243bb1643f6298aba8eec8cdee78ee3b3dd"
}
