import Foundation

// MARK: - Preflight Result

nonisolated struct PreflightResult: Codable, Sendable {
    enum Severity: String, Codable, Sendable {
        case success, warning, error
    }

    /// true if the bundler accepted the UserOp for simulation (gas estimation succeeded).
    let passed: Bool
    /// Gas estimates from the bundler, when simulation succeeded.
    let gasEstimate: GasEstimate?
    /// AA error code extracted from a bundler failure ("AA24", "AA25", etc.).
    let aaError: String?
    /// Raw failure message from the bundler or static analysis.
    let failureReason: String?
    /// Warnings from local static checks (dummy sig, fee mismatch, etc.).
    let staticWarnings: [String]
    /// Human-readable summary of what happened.
    let diagnosis: String
    /// Actionable recommendations shown in the approval UI.
    let recommendations: [String]
    /// Overall severity: success, warning (passed but with caveats), error (failed).
    let severity: Severity
}

// MARK: - Debug Bundle

/// Serializable snapshot of a preflight run — useful for bug reports and support.
nonisolated struct PreflightDebugBundle: Codable, Sendable {
    /// Wire-format representation of the UserOperation that was simulated.
    let userOperation: UserOperationRPC
    /// Full preflight result including gas estimates, warnings, and diagnosis.
    let preflightResult: PreflightResult
    /// Human-readable decoded calldata summary, if decoding succeeded.
    let decodedCalldata: String?
    /// ISO-8601 timestamp when the bundle was exported.
    let exportedAt: String
}

// MARK: - Preflight Simulator

/// Runs preflight checks on a UserOperation before the approval window opens.
///
/// Two-tier approach:
///   1. Static local checks (always run): gas sanity, fee ordering, live fee sanity.
///   2. Bundler simulation (when project ID and chain ID are available):
///      calls `eth_estimateUserOperationGas` with the bundler, which internally
///      runs `simulateHandleOp`. Success means account + paymaster validation
///      and calldata execution are all expected to pass.
///   3. Calldata simulation: per-execution eth_call against the chain RPC to catch
///      application-level reverts before the approval window opens.
nonisolated final class PreflightSimulator: Sendable {
    static let shared = PreflightSimulator()
    private init() {}

    func simulate(
        op: UserOperation,
        submission: UserOperationSubmissionRequest?,
        preferences: BundlerPreferences
    ) async -> PreflightResult {
        var staticWarnings: [String] = []

        // ─── Static checks ──────────────────────────────────────────────────
        if let warn = gasWarning(op) {
            staticWarnings.append(warn)
        }
        if let warn = feeWarning(op) {
            staticWarnings.append(warn)
        }

        // ─── Live fee sanity (non-blocking) ─────────────────────────────────
        let chainRPCURL = rpcURL(for: op.chainId, preferences: preferences)
        if let rpcURL = chainRPCURL {
            let feeWarnings = await liveFeeWarnings(op: op, rpcURL: rpcURL)
            staticWarnings.append(contentsOf: feeWarnings)
        }

        // ─── Bundler simulation ──────────────────────────────────────────────
        let projectId = submission?.projectId ?? preferences.zeroDevProjectId
        guard let projectId, !projectId.isEmpty else {
            // Still run calldata simulation if we have an RPC URL.
            if let rpcURL = chainRPCURL {
                let calldataWarnings = await calldataSimulation(op, rpcURL: rpcURL)
                staticWarnings.append(contentsOf: calldataWarnings)
            }
            return buildStaticOnlyResult(staticWarnings: staticWarnings)
        }

        let api = ZeroDevAPI(projectId: projectId)

        // ─── Bundler fee sanity via pimlico_getUserOperationGasPrice ────────
        let bundlerFeeWarns = await bundlerFeeWarnings(op: op, api: api)
        staticWarnings.append(contentsOf: bundlerFeeWarns)

        // ─── Calldata simulation (non-blocking) ──────────────────────────────
        if let rpcURL = chainRPCURL {
            let calldataWarnings = await calldataSimulation(op, rpcURL: rpcURL)
            staticWarnings.append(contentsOf: calldataWarnings)
        }

        // Use a dummy zero signature for gas estimation — most bundlers don't validate
        // the signature during eth_estimateUserOperationGas.
        let dummySignature = Data(repeating: 0, count: 64)
        let rpcOp = UserOperationRPC.from(op, signature: dummySignature)
        let entryPoint = EntryPointAddress.address(for: op.entryPointVersion)

        do {
            let estimate = try await api.estimateUserOperationGas(
                rpcOp,
                entryPoint: entryPoint,
                chainId: op.chainId
            )
            return PreflightResult(
                passed: true,
                gasEstimate: estimate,
                aaError: nil,
                failureReason: nil,
                staticWarnings: staticWarnings,
                diagnosis: "Preflight simulation passed. Gas estimates retrieved from bundler.",
                recommendations: staticWarnings.isEmpty ? [] : ["Review the warnings above before approving"],
                severity: staticWarnings.isEmpty ? .success : .warning
            )
        } catch let error as ZeroDevError {
            return buildBundlerFailure(error: error, staticWarnings: staticWarnings)
        } catch {
            let msg = String(describing: error)
            return PreflightResult(
                passed: false,
                gasEstimate: nil,
                aaError: nil,
                failureReason: msg,
                staticWarnings: staticWarnings,
                diagnosis: "Preflight simulation could not complete: \(msg)",
                recommendations: ["Check your network connection and RPC configuration"],
                severity: .error
            )
        }
    }

    // MARK: - Debug Export

    /// Produce a pretty-printed JSON snapshot of this preflight run for debugging.
    ///
    /// Intended to be attached to bug reports or shown in a "Copy debug info" UI action.
    /// Returns nil if serialization fails (should not happen in practice).
    func debugBundle(op: UserOperation, signature: Data?, result: PreflightResult) -> Data? {
        let sig = signature ?? Data(repeating: 0, count: 64)
        let rpcOp = UserOperationRPC.from(op, signature: sig)

        // Produce a human-readable calldata summary using the existing decoder.
        let decodedCalldata: String?
        switch CalldataDecoder.inspect(op) {
        case .decoded(let executions):
            decodedCalldata = executions.map(\.description).joined(separator: "; ")
        case .opaque(let reason):
            decodedCalldata = "opaque: \(reason)"
        }

        let formatter = ISO8601DateFormatter()
        let bundle = PreflightDebugBundle(
            userOperation: rpcOp,
            preflightResult: result,
            decodedCalldata: decodedCalldata,
            exportedAt: formatter.string(from: Date())
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try? encoder.encode(bundle)
    }

    // MARK: - Static Checks

    // Note: isDummySignature is intentionally absent. PreflightSimulator always
    // substitutes its own dummy zero-signature when calling the bundler, so there
    // is no caller-supplied signature to inspect here.

    // MARK: - Live Fee Sanity

    /// Resolve the chain RPC URL from BundlerPreferences for the given chain ID.
    private nonisolated func rpcURL(for chainId: Int, preferences: BundlerPreferences) -> URL? {
        guard let pref = preferences.chainRPCs.first(where: { $0.chainId == chainId }),
              !pref.rpcURL.isEmpty,
              let url = URL(string: pref.rpcURL) else {
            return nil
        }
        return url
    }

    /// Compare the op's maxFeePerGas against the current on-chain gas price.
    /// Returns warning strings; never throws (catches all errors and returns empty).
    private nonisolated func liveFeeWarnings(op: UserOperation, rpcURL: URL) async -> [String] {
        do {
            let rpc = EthRPC(rpcURL: rpcURL)
            let gasPriceHex = try await rpc.gasPrice()
            guard let networkGasPrice = hexToUInt64(gasPriceHex),
                  let opMaxFee = hexToUInt64(op.maxFeePerGas),
                  networkGasPrice > 0 else {
                return []
            }
            // Warn if the op fee is below 70% of current network gas price.
            let threshold = (networkGasPrice * 70) / 100
            if opMaxFee < threshold {
                let opGwei = formatGwei(opMaxFee)
                let netGwei = formatGwei(networkGasPrice)
                return ["maxFeePerGas (\(opGwei)) is below current network gas price (\(netGwei)) — transaction may be dropped or delayed"]
            }
            return []
        } catch {
            // Non-blocking: RPC unavailable or chain doesn't support eth_gasPrice.
            return []
        }
    }

    /// Compare the op's fees against the bundler's recommended fee tiers
    /// via pimlico_getUserOperationGasPrice. Returns warning strings; never throws.
    private nonisolated func bundlerFeeWarnings(op: UserOperation, api: ZeroDevAPI) async -> [String] {
        do {
            let tiers = try await api.userOperationGasPrice(chainId: op.chainId)
            guard let slowMaxFee = hexToUInt64(tiers.slow.maxFeePerGas),
                  let opMaxFee = hexToUInt64(op.maxFeePerGas),
                  slowMaxFee > 0 else {
                return []
            }
            if opMaxFee < slowMaxFee {
                let opGwei = formatGwei(opMaxFee)
                let slowGwei = formatGwei(slowMaxFee)
                return ["maxFeePerGas (\(opGwei)) is below the bundler's slow tier (\(slowGwei)) — the UserOp may not be included"]
            }
            return []
        } catch {
            // Non-blocking: bundler may not support this method.
            return []
        }
    }

    /// Format a fee value (in wei, as UInt64) as a human-readable Gwei string.
    private nonisolated func formatGwei(_ wei: UInt64) -> String {
        let gwei = Double(wei) / 1e9
        if gwei >= 1 {
            return String(format: "%.2f gwei", gwei)
        }
        return "\(wei) wei"
    }

    // MARK: - Calldata Simulation

    /// For each decoded execution inside the UserOp, run eth_call against the chain RPC
    /// to detect application-level reverts before the approval window opens.
    ///
    /// Returns warning strings for any reverts; never throws.
    private nonisolated func calldataSimulation(_ op: UserOperation, rpcURL: URL) async -> [String] {
        let executions: [CalldataDecoder.DecodedExecution]
        switch CalldataDecoder.inspect(op) {
        case .decoded(let decoded):
            executions = decoded
        case .opaque:
            // Can't simulate what we can't decode.
            return []
        }

        let rpc = EthRPC(rpcURL: rpcURL)
        var warnings: [String] = []

        for execution in executions {
            // Skip plain ETH transfers (no calldata to simulate).
            guard let selector = execution.selector else { continue }

            // Reconstruct the full calldata: we need the raw bytes, not just the selector.
            // Use CalldataDecoder's output to identify the target and re-derive the calldata
            // from the original op.callData for this specific execution.
            // Since we only have the decoded description and selector here, we build a
            // minimal eth_call using the selector as a 4-byte probe to check reachability.
            // For a full revert check we would need the original inner calldata per execution;
            // the decoder does not currently expose that, so we call with selector-only
            // calldata as a lightweight revert probe.
            let calldataHex = "0x" + selector.hex

            do {
                _ = try await rpc.ethCall(to: execution.to, data: calldataHex, from: op.sender)
            } catch let rpcErr as EthRPCError {
                if let revertWarning = revertWarning(from: rpcErr, target: execution.to) {
                    warnings.append(revertWarning)
                }
            } catch {
                // Non-blocking: network errors or unsupported eth_call — skip.
            }
        }

        return warnings
    }

    /// Extract and decode a revert reason from an RPC error, if present.
    private nonisolated func revertWarning(from error: EthRPCError, target: String) -> String? {
        let message: String
        switch error {
        case .rpcError(_, let msg): message = msg
        case .httpError(_, let body): message = body
        case .networkError: return nil
        }

        let lower = message.lowercased()
        guard lower.contains("revert") || lower.contains("execution reverted") else { return nil }

        let shortTarget = "\(target.prefix(8))...\(target.suffix(4))"

        // Try to ABI-decode Error(string): selector 0x08c379a0
        // Layout: selector(4) + offset(32) + length(32) + string bytes
        if let dataRange = message.range(of: "0x", options: .caseInsensitive),
           let revertData = Data(hexString: String(message[dataRange.lowerBound...])),
           revertData.count >= 4 {
            let selector = revertData.prefix(4)
            if selector == Data([0x08, 0xc3, 0x79, 0xa0]), revertData.count >= 100 {
                // offset is bytes 4..<36, always 0x20; length is bytes 68..<100
                let lengthData = revertData[68..<100]
                let length = Int(lengthData.reduce(0 as UInt64) { ($0 << 8) | UInt64($1) })
                let stringStart = 100
                if stringStart + length <= revertData.count,
                   let reason = String(bytes: revertData[stringStart ..< stringStart + length], encoding: .utf8) {
                    return "Call to \(shortTarget) would revert: \"\(reason)\""
                }
            }
            // Unknown revert data — include raw hex (truncated).
            let rawHex = "0x" + revertData.hex
            let truncated = rawHex.count > 66 ? String(rawHex.prefix(66)) + "…" : rawHex
            return "Call to \(shortTarget) would revert (raw: \(truncated))"
        }

        return "Call to \(shortTarget) would revert"
    }

    private nonisolated func gasWarning(_ op: UserOperation) -> String? {
        let fields: [(String, String)] = [
            ("verificationGasLimit", op.verificationGasLimit),
            ("callGasLimit", op.callGasLimit),
            ("preVerificationGas", op.preVerificationGas),
        ]
        let zeros = fields.filter { _, v in
            let stripped = v.hasPrefix("0x") ? String(v.dropFirst(2)) : v
            return stripped.allSatisfy { $0 == "0" } || stripped.isEmpty
        }.map { k, _ in k }

        if !zeros.isEmpty {
            return "Gas limits are zero: \(zeros.joined(separator: ", "))"
        }
        return nil
    }

    private nonisolated func feeWarning(_ op: UserOperation) -> String? {
        guard let maxFee = hexToUInt64(op.maxFeePerGas),
              let maxPriorityFee = hexToUInt64(op.maxPriorityFeePerGas) else {
            return nil
        }
        if maxPriorityFee > maxFee {
            return "maxPriorityFeePerGas (\(op.maxPriorityFeePerGas)) exceeds maxFeePerGas (\(op.maxFeePerGas))"
        }
        return nil
    }

    private nonisolated func hexToUInt64(_ hex: String) -> UInt64? {
        let s = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        return UInt64(s, radix: 16)
    }

    // MARK: - Result builders

    private nonisolated func buildStaticOnlyResult(staticWarnings: [String]) -> PreflightResult {
        if staticWarnings.isEmpty {
            return PreflightResult(
                passed: true,
                gasEstimate: nil,
                aaError: nil,
                failureReason: nil,
                staticWarnings: [],
                diagnosis: "Basic checks passed. No bundler configured — gas simulation skipped.",
                recommendations: ["Configure a ZeroDev project ID to enable bundler simulation"],
                severity: .warning
            )
        }
        return PreflightResult(
            passed: false,
            gasEstimate: nil,
            aaError: nil,
            failureReason: staticWarnings.first,
            staticWarnings: staticWarnings,
            diagnosis: "Static checks found issues before simulation.",
            recommendations: staticWarnings,
            severity: .error
        )
    }

    private nonisolated func buildBundlerFailure(
        error: ZeroDevError,
        staticWarnings: [String]
    ) -> PreflightResult {
        let message: String
        switch error {
        case .rpcError(_, let msg): message = msg
        case .httpError(let code, let body): message = "HTTP \(code): \(body)"
        case .networkError(let msg): message = msg
        case .emptyResult: message = "Bundler returned empty result"
        }

        let aaError = extractAAError(from: message)
        let (diagnosis, recommendations) = diagnose(aaError: aaError, rawMessage: message)

        return PreflightResult(
            passed: false,
            gasEstimate: nil,
            aaError: aaError,
            failureReason: message,
            staticWarnings: staticWarnings,
            diagnosis: diagnosis,
            recommendations: recommendations,
            severity: .error
        )
    }

    // MARK: - AA Error Diagnosis

    private nonisolated func extractAAError(from message: String) -> String? {
        // Match AA00–AA99
        if let range = message.range(of: #"AA\d{2}"#, options: .regularExpression) {
            return String(message[range])
        }
        return nil
    }

    private nonisolated func diagnose(
        aaError: String?,
        rawMessage: String
    ) -> (diagnosis: String, recommendations: [String]) {
        switch aaError {
        case "AA10", "AA13", "AA14":
            return (
                "Account initialization failed (\(aaError!)). The account factory or init code is invalid.",
                ["Check that the factory address and factoryData are correct",
                 "Verify the salt and account parameters match an existing or deployable account"]
            )
        case "AA20":
            return (
                "Account not deployed and no factory provided (AA20).",
                ["Provide factory and factoryData to deploy the account on first use",
                 "Or verify that the account is already deployed on this chain"]
            )
        case "AA21":
            return (
                "Account does not have enough ETH to cover prefunding (AA21).",
                ["Deposit ETH into the account or use a paymaster for gas sponsorship",
                 "Check account balance on chain \u{2014} it may be below the required deposit"]
            )
        case "AA22":
            return (
                "Account expired or not yet valid (AA22).",
                ["Check validAfter/validBefore in your account's validation logic",
                 "Ensure the system clock on the signing machine is correct"]
            )
        case "AA23":
            return (
                "Account reverted during validateUserOp (AA23).",
                ["The account's validateUserOp() function threw an unexpected error",
                 "Check the account contract logic for panics or invalid state assumptions"]
            )
        case "AA24":
            return (
                "Invalid signature (AA24). The signature does not match the UserOp hash.",
                ["Verify the UserOp hash is computed correctly for this chain and EntryPoint version",
                 "Check that the signing key matches the account's installed validator"]
            )
        case "AA25":
            return (
                "Invalid account nonce (AA25). The nonce in the UserOp does not match the account.",
                ["Fetch the current nonce from the EntryPoint using getNonce(sender, key)",
                 "Update the UserOp nonce before signing and submitting"]
            )
        case "AA31":
            return (
                "Paymaster deposit too low (AA31). The paymaster cannot cover the required prefund.",
                ["Top up the paymaster's deposit in the EntryPoint",
                 "Contact the paymaster operator if using a third-party service"]
            )
        case "AA33":
            return (
                "Paymaster reverted during validatePaymasterUserOp (AA33).",
                ["Verify that paymasterData is correctly formatted for this paymaster",
                 "Check that the paymaster signature is valid and not expired"]
            )
        case "AA34":
            return (
                "Paymaster signature or data expired (AA34).",
                ["Request fresh paymasterData from the paymaster service",
                 "The paymasterData timestamp has likely expired — regenerate it"]
            )
        case "AA40", "AA41":
            return (
                "verificationGasLimit too low (\(aaError!)). Account + paymaster validation consumed more gas than allowed.",
                ["Increase verificationGasLimit in the UserOp",
                 "Use eth_estimateUserOperationGas to get accurate bounds",
                 "Cold storage slots (first access) cost 2,100 gas each — account for them"]
            )
        case "AA50", "AA51":
            return (
                "Paymaster postOp failed (\(aaError!)). Execution succeeded but paymaster cleanup reverted.",
                ["For ERC-20 paymasters: ensure the account approved enough tokens for fee collection",
                 "AA51: postOp gas limit too low — increase it in paymasterAndData"]
            )
        default:
            if rawMessage.lowercased().contains("execution reverted") {
                return (
                    "The UserOp would revert during execution. The callData encountered a revert on the target contract.",
                    ["Check that the target contract and function exist on this chain",
                     "Verify the callData parameters are correct (types, values, approvals)",
                     "Make sure required token balances or allowances are in place"]
                )
            }
            return (
                "Bundler simulation failed: \(rawMessage)",
                ["Check the error message for details",
                 "Verify the UserOp fields are correctly encoded for this EntryPoint version"]
            )
        }
    }
}
