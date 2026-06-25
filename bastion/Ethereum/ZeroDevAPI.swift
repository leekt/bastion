import Foundation

// MARK: - ZeroDev Bundler API Client

/// Client for the ZeroDev bundler API (ERC-4337 bundler + paymaster).
/// Uses project-based RPC endpoint: `https://rpc.zerodev.app/api/v3/{projectId}/chain/{chainId}`
nonisolated final class ZeroDevAPI: Sendable {

    typealias Transport = @Sendable (URLRequest) async throws -> (Data, URLResponse)

    let projectId: String
    private let transport: Transport
    private let retryPolicyOverride: ZeroDevRetryPolicy?
    private let sleep: @Sendable (UInt64) async throws -> Void

    init(
        projectId: String,
        transport: @escaping Transport = { request in try await URLSession.shared.data(for: request) },
        retryPolicyOverride: ZeroDevRetryPolicy? = nil,
        sleep: @escaping @Sendable (UInt64) async throws -> Void = { nanoseconds in
            try await Task.sleep(nanoseconds: nanoseconds)
        }
    ) {
        if projectId.hasPrefix("0x") {
            self.projectId = String(projectId.dropFirst(2))
        } else {
            self.projectId = projectId
        }
        self.transport = transport
        self.retryPolicyOverride = retryPolicyOverride
        self.sleep = sleep
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
        try await withRetry(method: method) {
            try await executeJSONRPC(method: method, params: params, chainId: chainId)
        }
    }

    private func jsonRPCOptional<T: Decodable>(
        method: String,
        params: [any Encodable],
        chainId: Int
    ) async throws -> T? {
        try await withRetry(method: method) {
            try await executeJSONRPCOptional(method: method, params: params, chainId: chainId)
        }
    }

    private func executeJSONRPC<T: Decodable>(
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
        do {
            request.httpBody = try JSONEncoder().encode(body)
        } catch {
            throw ZeroDevError.requestEncodingError(error.localizedDescription)
        }

        #if DEBUG
        if method == "eth_sendUserOperation" || method == "eth_estimateUserOperationGas",
           let jsonStr = String(data: request.httpBody!, encoding: .utf8) {
            print("[\(method)] JSON payload:\n\(jsonStr)")
        }
        #endif

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await transport(request)
        } catch let error as ZeroDevError {
            throw error
        } catch let error as URLError {
            throw ZeroDevError.networkError(error.localizedDescription)
        } catch {
            throw ZeroDevError.networkError(String(describing: error))
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ZeroDevError.networkError("Invalid response")
        }

        guard httpResponse.statusCode == 200 else {
            let body = String(data: data, encoding: .utf8) ?? "unknown"
            throw ZeroDevError.httpError(httpResponse.statusCode, body)
        }

        let rpcResponse: JSONRPCResponse<T>
        do {
            rpcResponse = try JSONDecoder().decode(JSONRPCResponse<T>.self, from: data)
        } catch {
            throw ZeroDevError.responseDecodingError(error.localizedDescription)
        }

        if let error = rpcResponse.error {
            throw ZeroDevError.rpcError(error.code, error.message)
        }

        guard let result = rpcResponse.result else {
            throw ZeroDevError.emptyResult
        }

        return result
    }

    private func executeJSONRPCOptional<T: Decodable>(
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
        do {
            request.httpBody = try JSONEncoder().encode(body)
        } catch {
            throw ZeroDevError.requestEncodingError(error.localizedDescription)
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await transport(request)
        } catch let error as ZeroDevError {
            throw error
        } catch let error as URLError {
            throw ZeroDevError.networkError(error.localizedDescription)
        } catch {
            throw ZeroDevError.networkError(String(describing: error))
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ZeroDevError.networkError("Invalid response")
        }

        guard httpResponse.statusCode == 200 else {
            let body = String(data: data, encoding: .utf8) ?? "unknown"
            throw ZeroDevError.httpError(httpResponse.statusCode, body)
        }

        let rpcResponse: JSONRPCResponse<T>
        do {
            rpcResponse = try JSONDecoder().decode(JSONRPCResponse<T>.self, from: data)
        } catch {
            throw ZeroDevError.responseDecodingError(error.localizedDescription)
        }

        if let error = rpcResponse.error {
            throw ZeroDevError.rpcError(error.code, error.message)
        }

        return rpcResponse.result
    }

    private func withRetry<T>(
        method: String,
        operation: () async throws -> T
    ) async throws -> T {
        let policy = retryPolicyOverride ?? ZeroDevRetryPolicy.defaultPolicy(for: method)
        let maxAttempts = max(1, policy.maxAttempts)
        var attempt = 1

        while true {
            do {
                return try await operation()
            } catch {
                let normalized = Self.normalized(error)
                guard attempt < maxAttempts,
                      Self.shouldRetry(normalized, method: method) else {
                    throw normalized
                }
                try await sleep(policy.delayNanoseconds(forFailedAttempt: attempt))
                attempt += 1
            }
        }
    }

    private static func normalized(_ error: Error) -> Error {
        if error is ZeroDevError {
            return error
        }
        if let urlError = error as? URLError {
            return ZeroDevError.networkError(urlError.localizedDescription)
        }
        return error
    }

    private static func shouldRetry(_ error: Error, method: String) -> Bool {
        guard let error = error as? ZeroDevError, error.isTransient else {
            return false
        }
        // Sending an identical UserOperation is normally idempotent at the
        // bundler, but keep it tighter than read/simulation calls.
        if method == "eth_sendUserOperation" {
            return true
        }
        return true
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
    case requestEncodingError(String)
    case responseDecodingError(String)

    var rawMessage: String {
        switch self {
        case .networkError(let msg): return msg
        case .httpError(let code, let body): return "HTTP \(code): \(body)"
        case .rpcError(_, let msg): return msg
        case .emptyResult: return "Bundler returned empty result"
        case .requestEncodingError(let msg): return msg
        case .responseDecodingError(let msg): return msg
        }
    }

    var isTransient: Bool {
        switch self {
        case .networkError, .emptyResult:
            return true
        case .httpError(let code, _):
            return code == 408 || code == 425 || code == 429 || (500...599).contains(code)
        case .rpcError(_, let msg):
            let lower = msg.lowercased()
            return lower.contains("timeout") ||
                lower.contains("temporarily") ||
                lower.contains("rate limit") ||
                lower.contains("too many requests") ||
                lower.contains("server overloaded") ||
                lower.contains("try again")
        case .requestEncodingError, .responseDecodingError:
            return false
        }
    }

    var isMinimumFeeMismatch: Bool {
        switch self {
        case .rpcError(_, let msg):
            let lower = msg.lowercased()
            return lower.contains("maxfeepergas must be at least") ||
                lower.contains("fee too low") ||
                lower.contains("underpriced") ||
                lower.contains("minimum fee")
        default:
            return false
        }
    }

    var containsAAError: Bool {
        rawMessage.range(of: #"AA\d{2}"#, options: .regularExpression) != nil
    }

    var mentionsPaymaster: Bool {
        rawMessage.lowercased().contains("paymaster")
    }

    var description: String {
        switch self {
        case .networkError(let msg): return "Network error: \(msg)"
        case .httpError(let code, let body): return "HTTP \(code): \(body)"
        case .rpcError(let code, let msg): return "RPC error \(code): \(msg)"
        case .emptyResult: return "Empty RPC result"
        case .requestEncodingError(let msg): return "Request encoding error: \(msg)"
        case .responseDecodingError(let msg): return "Response decoding error: \(msg)"
        }
    }
}

nonisolated struct ZeroDevRetryPolicy: Sendable, Equatable {
    let maxAttempts: Int
    let baseDelayNanoseconds: UInt64

    static func defaultPolicy(for method: String) -> ZeroDevRetryPolicy {
        switch method {
        case "eth_sendUserOperation":
            return ZeroDevRetryPolicy(maxAttempts: 2, baseDelayNanoseconds: 250_000_000)
        case "eth_getUserOperationReceipt":
            return ZeroDevRetryPolicy(maxAttempts: 2, baseDelayNanoseconds: 150_000_000)
        default:
            return ZeroDevRetryPolicy(maxAttempts: 3, baseDelayNanoseconds: 200_000_000)
        }
    }

    func delayNanoseconds(forFailedAttempt attempt: Int) -> UInt64 {
        guard baseDelayNanoseconds > 0 else { return 0 }
        let exponent = min(max(0, attempt - 1), 4)
        return baseDelayNanoseconds * UInt64(1 << exponent)
    }
}

nonisolated enum ProviderFailureStage: String, Codable, Sendable, Equatable {
    case configuration
    case chainRPC = "chain_rpc"
    case feeEstimation = "fee_estimation"
    case sponsorship
    case simulation
    case submission
    case receiptTracking = "receipt_tracking"
    case onChainExecution = "on_chain_execution"

    var displayName: String {
        switch self {
        case .configuration: return "configuration"
        case .chainRPC: return "chain RPC"
        case .feeEstimation: return "fee estimation"
        case .sponsorship: return "paymaster sponsorship"
        case .simulation: return "simulation"
        case .submission: return "submission"
        case .receiptTracking: return "receipt tracking"
        case .onChainExecution: return "on-chain execution"
        }
    }
}

nonisolated enum ProviderFailureCategory: String, Codable, Sendable, Equatable {
    case configuration
    case chainRPC = "chain_rpc"
    case zeroDevAPI = "zerodev_api"
    case paymaster
    case bundlerValidation = "bundler_validation"
    case submission
    case receiptTimeout = "receipt_timeout"
    case minimumFeeMismatch = "minimum_fee_mismatch"
    case onChainExecution = "on_chain_execution"
    case simulation
    case unknown

    var displayName: String {
        switch self {
        case .configuration: return "configuration"
        case .chainRPC: return "chain RPC"
        case .zeroDevAPI: return "ZeroDev API"
        case .paymaster: return "paymaster"
        case .bundlerValidation: return "bundler validation"
        case .submission: return "submission"
        case .receiptTimeout: return "receipt timeout"
        case .minimumFeeMismatch: return "minimum fee mismatch"
        case .onChainExecution: return "on-chain execution"
        case .simulation: return "simulation"
        case .unknown: return "unknown"
        }
    }
}

nonisolated struct ProviderFailureDiagnostic: Codable, Sendable, Equatable {
    let provider: String
    let stage: ProviderFailureStage
    let category: ProviderFailureCategory
    let retryable: Bool
    let message: String
    let recoverySuggestion: String

    var userFacingMessage: String {
        "\(provider) \(stage.displayName) failed (\(category.displayName)): \(message). \(recoverySuggestion)"
    }

    var nsError: NSError {
        NSError(
            domain: "com.bastion.provider",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: userFacingMessage]
        )
    }

    static func configuration(
        provider: UserOperationSubmissionProvider = .zeroDev,
        message: String
    ) -> ProviderFailureDiagnostic {
        ProviderFailureDiagnostic(
            provider: provider.displayName,
            stage: .configuration,
            category: .configuration,
            retryable: false,
            message: message,
            recoverySuggestion: "Open Bastion settings and configure the provider before submitting."
        )
    }

    static func receiptTimeout(
        provider: UserOperationSubmissionProvider = .zeroDev,
        lastError: String?
    ) -> ProviderFailureDiagnostic {
        ProviderFailureDiagnostic(
            provider: provider.displayName,
            stage: .receiptTracking,
            category: .receiptTimeout,
            retryable: true,
            message: lastError ?? "No receipt returned before the polling deadline",
            recoverySuggestion: "Check the UserOperation hash in the bundler dashboard or retry receipt lookup later."
        )
    }

    static func onChainFailure(
        provider: UserOperationSubmissionProvider = .zeroDev,
        detail: String
    ) -> ProviderFailureDiagnostic {
        ProviderFailureDiagnostic(
            provider: provider.displayName,
            stage: .onChainExecution,
            category: .onChainExecution,
            retryable: false,
            message: detail,
            recoverySuggestion: "Inspect the transaction receipt and contract trace before retrying the operation."
        )
    }

    static func from(
        error: Error,
        provider: UserOperationSubmissionProvider = .zeroDev,
        stage: ProviderFailureStage
    ) -> ProviderFailureDiagnostic {
        if let zeroDevError = error as? ZeroDevError {
            return zeroDev(error: zeroDevError, provider: provider, stage: stage)
        }
        if let ethError = error as? EthRPCError {
            return ethRPC(error: ethError, provider: provider, stage: stage)
        }
        return ProviderFailureDiagnostic(
            provider: provider.displayName,
            stage: stage,
            category: .unknown,
            retryable: false,
            message: String(describing: error),
            recoverySuggestion: "Collect a support bundle with the request and provider context."
        )
    }

    private static func zeroDev(
        error: ZeroDevError,
        provider: UserOperationSubmissionProvider,
        stage: ProviderFailureStage
    ) -> ProviderFailureDiagnostic {
        let category: ProviderFailureCategory
        let suggestion: String

        if error.isMinimumFeeMismatch {
            category = .minimumFeeMismatch
            suggestion = "Rebuild the UserOperation with fresh ZeroDev fee estimates, then approve and sign again."
        } else if error.mentionsPaymaster || stage == .sponsorship {
            category = .paymaster
            suggestion = "Check paymaster policy, deposit, sponsorship limits, and the configured ZeroDev project."
        } else if error.containsAAError {
            category = .bundlerValidation
            suggestion = "Review the AA error diagnosis, account nonce, signature, factory data, and paymaster fields."
        } else {
            switch stage {
            case .simulation:
                category = .simulation
                suggestion = "Retry after a short delay; if it repeats, export the preflight debug bundle."
            case .submission:
                category = .submission
                suggestion = error.isTransient ? "Bastion retried the transient submission failure; retry later if the bundler remains unavailable." : "Review the signed UserOperation and bundler response before retrying."
            case .receiptTracking:
                category = .zeroDevAPI
                suggestion = "Receipt polling can be retried later with the same UserOperation hash."
            case .feeEstimation:
                category = .zeroDevAPI
                suggestion = "Retry fee estimation or configure a separate chain RPC endpoint for non-AA reads."
            default:
                category = .zeroDevAPI
                suggestion = "Retry after a short delay; if it repeats, verify ZeroDev project health and network access."
            }
        }

        return ProviderFailureDiagnostic(
            provider: provider.displayName,
            stage: stage,
            category: category,
            retryable: error.isTransient,
            message: error.rawMessage,
            recoverySuggestion: suggestion
        )
    }

    private static func ethRPC(
        error: EthRPCError,
        provider: UserOperationSubmissionProvider,
        stage: ProviderFailureStage
    ) -> ProviderFailureDiagnostic {
        ProviderFailureDiagnostic(
            provider: provider.displayName,
            stage: stage == .chainRPC ? .chainRPC : stage,
            category: .chainRPC,
            retryable: error.isTransient,
            message: error.rawMessage,
            recoverySuggestion: "Check the configured chain RPC endpoint for this chain, then retry when it is healthy."
        )
    }
}

extension EthRPCError {
    var rawMessage: String {
        switch self {
        case .networkError(let msg): return msg
        case .httpError(let code, let body): return "HTTP \(code): \(body)"
        case .rpcError(_, let msg): return msg
        case .debugTraceUnsupported: return "debug_traceCall is not supported by this RPC provider"
        }
    }

    var isTransient: Bool {
        switch self {
        case .networkError:
            return true
        case .httpError(let code, _):
            return code == 408 || code == 425 || code == 429 || (500...599).contains(code)
        case .rpcError(_, let msg):
            let lower = msg.lowercased()
            return lower.contains("timeout") ||
                lower.contains("temporarily") ||
                lower.contains("rate limit") ||
                lower.contains("too many requests") ||
                lower.contains("try again")
        case .debugTraceUnsupported:
            return false
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
