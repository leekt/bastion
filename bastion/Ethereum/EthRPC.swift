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
}

// MARK: - Response Types

nonisolated struct EthBlock: Decodable, Sendable {
    let baseFeePerGas: String?
    let number: String?
    let timestamp: String?
}

// MARK: - Errors

nonisolated enum EthRPCError: Error, CustomStringConvertible {
    case networkError(String)
    case httpError(Int, String)
    case rpcError(Int, String)

    var description: String {
        switch self {
        case .networkError(let msg): return "ETH RPC network error: \(msg)"
        case .httpError(let code, let body): return "ETH RPC HTTP \(code): \(body)"
        case .rpcError(let code, let msg): return "ETH RPC error \(code): \(msg)"
        }
    }
}
