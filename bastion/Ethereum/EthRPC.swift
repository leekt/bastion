import Foundation

// MARK: - Ethereum JSON-RPC Client (non-AA calls)

/// Standard Ethereum JSON-RPC client for non-AA operations.
/// ZeroDev's bundler RPC should only be used for AA-specific calls
/// (eth_sendUserOperation, eth_estimateUserOperationGas, etc.).
/// Regular eth_* calls go through a standard RPC provider.
nonisolated final class EthRPC: Sendable {
    let rpcURL: URL

    init(rpcURL: URL) {
        self.rpcURL = rpcURL
    }

    /// Convenience init from URL string.
    init(rpcURLString: String) {
        self.rpcURL = URL(string: rpcURLString)!
    }

    // MARK: - Account Methods

    /// Get the bytecode at an address. Returns "0x" if no code deployed.
    func getCode(address: String) async throws -> String {
        try await call(method: "eth_getCode", params: [address, "latest"])
    }

    /// Get the ETH balance of an address (hex string in wei).
    func getBalance(address: String) async throws -> String {
        try await call(method: "eth_getBalance", params: [address, "latest"])
    }

    // MARK: - EntryPoint Methods

    /// Get the nonce from EntryPoint's `getNonce(address, uint192)`.
    func getNonce(sender: String, key: String, entryPoint: String) async throws -> String {
        // Encode getNonce(address,uint192) call
        let selector = "0x35567e1a"
        let paddedSender = leftPadHex(sender, to: 64)
        let paddedKey = leftPadHex(key, to: 64)
        let calldata = selector + paddedSender + paddedKey

        let result: String = try await call(
            method: "eth_call",
            params: [
                ["to": entryPoint, "data": calldata] as [String: String],
                "latest"
            ] as [Any]
        )
        return result
    }

    /// Get the counterfactual sender address via EntryPoint `getSenderAddress(initCode)`.
    /// For v0.7+: calls the factory directly to compute the address.
    func getSenderAddress(factory: String, factoryData: String, entryPoint: String) async throws -> String {
        // For v0.7+, we call the factory with the factoryData to get the CREATE2 address.
        // The factory's createAccount returns the address even if already deployed.
        // We encode a staticcall to metaFactory.deployWithFactory(...)
        let result: String = try await call(
            method: "eth_call",
            params: [
                ["to": factory, "data": factoryData] as [String: String],
                "latest"
            ] as [Any]
        )
        // Result is ABI-encoded address (32 bytes, left-padded)
        let clean = result.hasPrefix("0x") ? String(result.dropFirst(2)) : result
        if clean.count >= 64 {
            let addrHex = String(clean.suffix(40))
            return "0x" + addrHex
        }
        return result
    }

    /// Ask the EntryPoint to compute the canonical v0.7/v0.8+ UserOperation hash.
    func getUserOpHash(_ op: UserOperation, signature: Data = Data()) async throws -> Data {
        let selector = Keccak256.hash(
            Data("getUserOpHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes))".utf8)
        ).prefix(4)

        let initCode = packedInitCode(for: op)
        let paymasterAndData = packedPaymasterAndData(for: op)
        let tuple = abiEncodeUserOperationTuple(
            sender: op.sender,
            nonce: op.nonce,
            initCode: initCode,
            callData: op.callData,
            accountGasLimits: packTwo128(op.verificationGasLimit, op.callGasLimit),
            preVerificationGas: op.preVerificationGas,
            gasFees: packTwo128(op.maxPriorityFeePerGas, op.maxFeePerGas),
            paymasterAndData: paymasterAndData,
            signature: signature
        )

        var calldata = Data(selector)
        calldata += abiEncodeUInt256(32)
        calldata += tuple

        #if DEBUG
        print("[getUserOpHash] initCode (\(initCode.count) bytes): 0x\(initCode.hex)")
        print("[getUserOpHash] paymasterAndData (\(paymasterAndData.count) bytes): 0x\(paymasterAndData.hex)")
        print("[getUserOpHash] accountGasLimits: 0x\(packTwo128(op.verificationGasLimit, op.callGasLimit).hex)")
        print("[getUserOpHash] gasFees: 0x\(packTwo128(op.maxPriorityFeePerGas, op.maxFeePerGas).hex)")
        print("[getUserOpHash] full calldata (\(calldata.count) bytes): 0x\(calldata.hex)")
        #endif

        let result = try await ethCall(to: op.entryPoint, data: "0x" + calldata.hex)
        guard let hash = Data(hexString: result), hash.count == 32 else {
            throw EthRPCError.networkError("Invalid getUserOpHash response: \(result)")
        }
        return hash
    }

    // MARK: - Generic eth_call

    /// Perform a raw `eth_call` and return the hex result.
    func ethCall(to: String, data: String, from: String? = nil) async throws -> String {
        var callObj: [String: String] = ["to": to, "data": data]
        if let from { callObj["from"] = from }
        return try await call(method: "eth_call", params: [callObj, "latest"] as [Any])
    }

    // MARK: - Debug Trace

    /// Simulate a call using `debug_traceCall` with the `callTracer` and log collection.
    ///
    /// This is used to trace ERC-20 Transfer events and all addresses touched during
    /// UserOperation execution. Not all RPC providers support this method — callers
    /// should handle `EthRPCError.debugTraceUnsupported` gracefully.
    func debugTraceCall(
        to: String,
        from: String,
        data: String,
        value: String = "0x0"
    ) async throws -> TraceCallResult {
        let txObject: [String: String] = [
            "to": to,
            "from": from,
            "data": data,
            "value": value
        ]
        let tracerConfig: [String: Any] = [
            "tracer": "callTracer",
            "tracerConfig": ["withLog": true] as [String: Bool]
        ]
        do {
            return try await call(
                method: "debug_traceCall",
                params: [txObject, "latest", tracerConfig] as [Any]
            )
        } catch let error as EthRPCError {
            // Detect unsupported method and wrap in a specific error type.
            switch error {
            case .rpcError(let code, let msg):
                let lower = msg.lowercased()
                if lower.contains("method not found") ||
                    lower.contains("not supported") ||
                    lower.contains("does not exist") ||
                    lower.contains("method not available") ||
                    code == -32601 {
                    throw EthRPCError.debugTraceUnsupported
                }
                throw error
            default:
                throw error
            }
        }
    }

    // MARK: - Chain Methods

    func chainId() async throws -> String {
        try await call(method: "eth_chainId", params: [] as [String])
    }

    func gasPrice() async throws -> String {
        try await call(method: "eth_gasPrice", params: [] as [String])
    }

    func maxPriorityFeePerGas() async throws -> String {
        try await call(method: "eth_maxPriorityFeePerGas", params: [] as [String])
    }

    func getBlock(tag: String = "latest") async throws -> EthBlock {
        try await call(method: "eth_getBlockByNumber", params: [tag, false] as [Any])
    }

    /// Estimate EIP-1559 fees for a UserOperation using viem's default strategy:
    /// maxFeePerGas = floor(baseFeePerGas * baseFeeMultiplier) + maxPriorityFeePerGas
    /// with a default baseFeeMultiplier of 1.2.
    func estimateUserOperationFeesPerGas(baseFeeMultiplier: Double = 1.2) async throws -> UserOperationFeeEstimate {
        let block = try await getBlock()
        guard
            let baseFeeHex = block.baseFeePerGas,
            let baseFeePerGas = Self.hexToUInt128(baseFeeHex)
        else {
            throw EthRPCError.networkError("EIP-1559 fees not supported by this RPC")
        }

        let estimatedPriorityFeePerGas: UInt128
        do {
            let priorityHex = try await self.maxPriorityFeePerGas()
            guard let priority = Self.hexToUInt128(priorityHex) else {
                throw EthRPCError.networkError("Invalid eth_maxPriorityFeePerGas response: \(priorityHex)")
            }
            estimatedPriorityFeePerGas = priority
        } catch {
            let gasPriceHex = try await gasPrice()
            guard let gasPrice = Self.hexToUInt128(gasPriceHex) else {
                throw EthRPCError.networkError("Invalid eth_gasPrice response: \(gasPriceHex)")
            }
            estimatedPriorityFeePerGas = Self.fallbackMaxPriorityFeePerGas(
                gasPrice: gasPrice,
                baseFeePerGas: baseFeePerGas
            )
        }

        return try Self.computeUserOperationFees(
            baseFeePerGas: baseFeePerGas,
            maxPriorityFeePerGas: estimatedPriorityFeePerGas,
            baseFeeMultiplier: baseFeeMultiplier
        )
    }

    static func computeUserOperationFees(
        baseFeePerGas: UInt128,
        maxPriorityFeePerGas: UInt128,
        baseFeeMultiplier: Double = 1.2
    ) throws -> UserOperationFeeEstimate {
        guard baseFeeMultiplier >= 1 else {
            throw EthRPCError.networkError("baseFeeMultiplier must be >= 1")
        }

        let adjustedBaseFee = try multiply(baseFeePerGas, by: baseFeeMultiplier)
        let maxFeePerGas = adjustedBaseFee + maxPriorityFeePerGas

        return UserOperationFeeEstimate(
            maxPriorityFeePerGas: hexString(maxPriorityFeePerGas),
            maxFeePerGas: hexString(maxFeePerGas)
        )
    }

    // MARK: - JSON-RPC Transport

    private func call<T: Decodable>(method: String, params: [Any]) async throws -> T {
        var request = URLRequest(url: rpcURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: Any] = [
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw EthRPCError.networkError("Invalid response")
        }

        guard httpResponse.statusCode == 200 else {
            let body = String(data: data, encoding: .utf8) ?? "unknown"
            throw EthRPCError.httpError(httpResponse.statusCode, body)
        }

        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]

        if let error = json?["error"] as? [String: Any] {
            let code = error["code"] as? Int ?? -1
            let message = error["message"] as? String ?? "unknown"
            throw EthRPCError.rpcError(code, message)
        }

        // For simple string results, return directly
        if T.self == String.self, let result = json?["result"] as? String {
            return result as! T
        }

        // For complex types, decode from the result field
        let resultData = try JSONSerialization.data(
            withJSONObject: json?["result"] as Any
        )
        return try JSONDecoder().decode(T.self, from: resultData)
    }

    // MARK: - Helpers

    private func leftPadHex(_ hex: String, to length: Int) -> String {
        let clean = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        let paddingNeeded = max(0, length - clean.count)
        return String(repeating: "0", count: paddingNeeded) + clean
    }

    private static func hexToUInt128(_ hex: String) -> UInt128? {
        guard let data = Data(hexString: hex) else { return nil }
        let highByteCount = max(0, data.count - 16)
        guard !data.prefix(highByteCount).contains(where: { $0 != 0 }) else { return nil }

        var result: UInt128 = 0
        for byte in data.suffix(16) {
            result = (result << 8) | UInt128(byte)
        }
        return result
    }

    private static func fallbackMaxPriorityFeePerGas(
        gasPrice: UInt128,
        baseFeePerGas: UInt128
    ) -> UInt128 {
        gasPrice > baseFeePerGas ? gasPrice - baseFeePerGas : 0
    }

    private static func multiply(_ base: UInt128, by multiplier: Double) throws -> UInt128 {
        let multiplierString = String(multiplier)
        let decimals = multiplierString.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false)
        let fractionDigits = decimals.count == 2 ? decimals[1].count : 0
        let denominatorInt = UInt64(pow(10.0, Double(fractionDigits)))
        let scaledMultiplierInt = UInt64((multiplier * Double(denominatorInt)).rounded(.up))
        let denominator = UInt128(denominatorInt)
        let scaledMultiplier = UInt128(scaledMultiplierInt)
        return (base * scaledMultiplier) / denominator
    }

    private static func hexString(_ value: UInt128) -> String {
        "0x" + String(value, radix: 16)
    }

    private func packedInitCode(for op: UserOperation) -> Data {
        var initCode = Data()
        if let factory = op.factory {
            initCode += Data(hexString: factory) ?? Data()
            initCode += op.factoryData ?? Data()
        }
        return initCode
    }

    private func packedPaymasterAndData(for op: UserOperation) -> Data {
        var paymasterAndData = Data()
        if let paymaster = op.paymaster {
            paymasterAndData += Data(hexString: paymaster) ?? Data()
            paymasterAndData += leftPad(Data(hexString: op.paymasterVerificationGasLimit ?? "0x0") ?? Data(), to: 16)
            paymasterAndData += leftPad(Data(hexString: op.paymasterPostOpGasLimit ?? "0x0") ?? Data(), to: 16)
            paymasterAndData += op.paymasterData ?? Data()
        }
        return paymasterAndData
    }

    private func packTwo128(_ high: String, _ low: String) -> Data {
        leftPad(Data(hexString: high) ?? Data(), to: 16) + leftPad(Data(hexString: low) ?? Data(), to: 16)
    }

    private func abiEncodeUserOperationTuple(
        sender: String,
        nonce: String,
        initCode: Data,
        callData: Data,
        accountGasLimits: Data,
        preVerificationGas: String,
        gasFees: Data,
        paymasterAndData: Data,
        signature: Data
    ) -> Data {
        let headWords = 9
        let headSize = headWords * 32

        let initCodeData = abiEncodeBytes(initCode)
        let callDataData = abiEncodeBytes(callData)
        let paymasterData = abiEncodeBytes(paymasterAndData)
        let signatureData = abiEncodeBytes(signature)

        let initCodeOffset = headSize
        let callDataOffset = initCodeOffset + initCodeData.count
        let paymasterOffset = callDataOffset + callDataData.count
        let signatureOffset = paymasterOffset + paymasterData.count

        var encoded = Data()
        encoded += abiEncodeAddress(sender)
        encoded += abiEncodeUInt256FromHex(nonce)
        encoded += abiEncodeUInt256(UInt64(initCodeOffset))
        encoded += abiEncodeUInt256(UInt64(callDataOffset))
        encoded += leftPad(accountGasLimits, to: 32)
        encoded += abiEncodeUInt256FromHex(preVerificationGas)
        encoded += leftPad(gasFees, to: 32)
        encoded += abiEncodeUInt256(UInt64(paymasterOffset))
        encoded += abiEncodeUInt256(UInt64(signatureOffset))
        encoded += initCodeData
        encoded += callDataData
        encoded += paymasterData
        encoded += signatureData
        return encoded
    }

    private func abiEncodeBytes(_ data: Data) -> Data {
        var encoded = abiEncodeUInt256(UInt64(data.count))
        encoded += data
        let padding = (32 - data.count % 32) % 32
        if padding > 0 {
            encoded += Data(repeating: 0, count: padding)
        }
        return encoded
    }

    private func abiEncodeAddress(_ address: String) -> Data {
        leftPad(Data(hexString: address) ?? Data(), to: 32)
    }

    private func abiEncodeUInt256(_ value: UInt64) -> Data {
        var result = Data(repeating: 0, count: 32)
        var v = value
        for i in stride(from: 31, through: 24, by: -1) {
            result[i] = UInt8(v & 0xFF)
            v >>= 8
        }
        return result
    }

    private func abiEncodeUInt256FromHex(_ hex: String) -> Data {
        leftPad(Data(hexString: hex) ?? Data(), to: 32)
    }

    private func leftPad(_ data: Data, to size: Int) -> Data {
        if data.count >= size { return Data(data.suffix(size)) }
        return Data(repeating: 0, count: size - data.count) + data
    }
}

// MARK: - Response Types

nonisolated struct EthBlock: Decodable, Sendable {
    let baseFeePerGas: String?
    let number: String?
    let timestamp: String?
}

nonisolated struct UserOperationFeeEstimate: Sendable, Equatable {
    let maxPriorityFeePerGas: String
    let maxFeePerGas: String
}

// MARK: - Trace Types

/// A single call frame returned by `debug_traceCall` with `callTracer` + `withLog: true`.
/// The structure is recursive: each frame may contain nested `calls`.
nonisolated struct TraceCallResult: Codable, Sendable {
    let type: String
    let from: String
    let to: String?
    let value: String?
    let gas: String?
    let gasUsed: String?
    let input: String?
    let output: String?
    let calls: [TraceCallResult]?
    let logs: [TraceLog]?
}

/// A log entry emitted during a traced call frame.
nonisolated struct TraceLog: Codable, Sendable {
    let address: String
    let topics: [String]
    let data: String
}

// MARK: - Errors

nonisolated enum EthRPCError: Error, CustomStringConvertible {
    case networkError(String)
    case httpError(Int, String)
    case rpcError(Int, String)
    /// The RPC provider does not support `debug_traceCall`.
    case debugTraceUnsupported

    var description: String {
        switch self {
        case .networkError(let msg): return "ETH RPC network error: \(msg)"
        case .httpError(let code, let body): return "ETH RPC HTTP \(code): \(body)"
        case .rpcError(let code, let msg): return "ETH RPC error \(code): \(msg)"
        case .debugTraceUnsupported: return "debug_traceCall is not supported by this RPC provider"
        }
    }
}
