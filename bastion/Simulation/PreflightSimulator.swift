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
    /// Trace analysis from `debug_traceCall`, if the RPC supports it.
    /// Contains ERC-20 Transfer events, touched addresses, and native ETH spending.
    let traceAnalysis: TraceAnalysis?
    /// Spend observations derived from the trace analysis.
    /// When available, these represent the *actual* on-chain spending detected via simulation
    /// and are more accurate than the static calldata-based observations.
    let simulatedSpendObservations: [SimulatedSpendObservation]?

    init(
        passed: Bool,
        gasEstimate: GasEstimate?,
        aaError: String?,
        failureReason: String?,
        staticWarnings: [String],
        diagnosis: String,
        recommendations: [String],
        severity: Severity,
        traceAnalysis: TraceAnalysis? = nil,
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
    ) {
        self.passed = passed
        self.gasEstimate = gasEstimate
        self.aaError = aaError
        self.failureReason = failureReason
        self.staticWarnings = staticWarnings
        self.diagnosis = diagnosis
        self.recommendations = recommendations
        self.severity = severity
        self.traceAnalysis = traceAnalysis
        self.simulatedSpendObservations = simulatedSpendObservations
    }
}

/// A spend observation derived from trace simulation.
/// Similar to the internal `SpendObservation` in RuleEngine, but public and Codable
/// so it can be attached to `PreflightResult`.
nonisolated struct SimulatedSpendObservation: Codable, Sendable {
    let token: TokenIdentifier
    let amount: String  // decimal string in smallest unit (wei, 6-decimal for USDC)
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

        // ─── Trace-based simulation (non-blocking) ──────────────────────────
        // Run debug_traceCall to detect actual ERC-20 transfers and touched addresses.
        // Falls back silently when the RPC doesn't support debug_traceCall.
        var traceAnalysis: TraceAnalysis? = nil
        var simulatedSpendObservations: [SimulatedSpendObservation]? = nil
        if let rpcURL = chainRPCURL {
            let traceResult = await traceSimulation(op: op, rpcURL: rpcURL)
            traceAnalysis = traceResult.analysis
            simulatedSpendObservations = traceResult.observations
        }

        // ─── Bundler simulation ──────────────────────────────────────────────
        let projectId = submission?.projectId ?? preferences.zeroDevProjectId
        guard let projectId, !projectId.isEmpty else {
            // Still run calldata simulation if we have an RPC URL.
            if let rpcURL = chainRPCURL {
                let calldataWarnings = await calldataSimulation(op, rpcURL: rpcURL)
                staticWarnings.append(contentsOf: calldataWarnings)
            }
            return buildStaticOnlyResult(
                staticWarnings: staticWarnings,
                traceAnalysis: traceAnalysis,
                simulatedSpendObservations: simulatedSpendObservations
            )
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
                severity: staticWarnings.isEmpty ? .success : .warning,
                traceAnalysis: traceAnalysis,
                simulatedSpendObservations: simulatedSpendObservations
            )
        } catch let error as ZeroDevError {
            return buildBundlerFailure(
                error: error,
                staticWarnings: staticWarnings,
                traceAnalysis: traceAnalysis,
                simulatedSpendObservations: simulatedSpendObservations
            )
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
                severity: .error,
                traceAnalysis: traceAnalysis,
                simulatedSpendObservations: simulatedSpendObservations
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
    /// Multicall wrappers are transparently flattened via `allLeafExecutions` so each
    /// inner call is simulated individually with its exact calldata.
    ///
    /// Returns warning strings for any reverts; never throws.
    private nonisolated func calldataSimulation(_ op: UserOperation, rpcURL: URL) async -> [String] {
        let topLevelExecutions: [CalldataDecoder.DecodedExecution]
        switch CalldataDecoder.inspect(op) {
        case .decoded(let decoded):
            topLevelExecutions = decoded
        case .opaque:
            // Can't simulate what we can't decode.
            return []
        }

        // Flatten multicall wrappers so each leaf execution is simulated independently.
        let executions = topLevelExecutions.flatMap(\.allLeafExecutions)

        let rpc = EthRPC(rpcURL: rpcURL)
        var warnings: [String] = []

        for execution in executions {
            // Skip plain ETH transfers (no calldata to simulate).
            guard !execution.rawCalldata.isEmpty else { continue }

            // Use the full rawCalldata (selector + args) for an accurate revert check.
            // Previously only the 4-byte selector was sent, which caused false passes
            // because contracts would receive a malformed call and revert for the wrong
            // reason (or not revert at all if they have a fallback).
            let calldataHex = "0x" + execution.rawCalldata.hex

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
        case .networkError, .debugTraceUnsupported: return nil
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

    // MARK: - Trace Simulation

    private struct TraceSimulationResult {
        let analysis: TraceAnalysis?
        let observations: [SimulatedSpendObservation]?
    }

    /// Run `debug_traceCall` on the UserOp's calldata to detect actual ERC-20 transfers
    /// and native ETH spending. Falls back silently when the RPC doesn't support it.
    private nonisolated func traceSimulation(op: UserOperation, rpcURL: URL) async -> TraceSimulationResult {
        let rpc = EthRPC(rpcURL: rpcURL)
        let entryPoint = EntryPointAddress.address(for: op.entryPointVersion)
        let calldataHex = "0x" + op.callData.hex

        do {
            let trace = try await rpc.debugTraceCall(
                to: op.sender,
                from: entryPoint,
                data: calldataHex
            )

            let analysis = TraceAnalyzer.analyze(trace, accountAddress: op.sender)
            let observations = buildSimulatedSpendObservations(
                from: analysis,
                accountAddress: op.sender,
                chainId: op.chainId
            )
            return TraceSimulationResult(analysis: analysis, observations: observations)
        } catch let rpcError as EthRPCError {
            if case .debugTraceUnsupported = rpcError {
                // Expected: many RPC providers don't support debug_traceCall. Skip silently.
            }
            // Non-blocking: any RPC error — skip.
            return TraceSimulationResult(analysis: nil, observations: nil)
        } catch {
            // Non-blocking: any other error (network, timeout, etc.) — skip.
            return TraceSimulationResult(analysis: nil, observations: nil)
        }
    }

    /// Convert trace analysis into spend observations for spending limit validation.
    private nonisolated func buildSimulatedSpendObservations(
        from analysis: TraceAnalysis,
        accountAddress: String,
        chainId: Int
    ) -> [SimulatedSpendObservation] {
        var observations: [SimulatedSpendObservation] = []
        let normalizedAccount = accountAddress.lowercased()

        // Native ETH spending (from call value fields).
        if analysis.nativeSpend != "0" {
            observations.append(SimulatedSpendObservation(token: .eth, amount: analysis.nativeSpend))
        }

        // ERC-20 Transfer events where the account is the sender.
        for transfer in analysis.transfers {
            guard transfer.from == normalizedAccount else { continue }
            guard transfer.amount != "0" else { continue }

            let token: TokenIdentifier
            if let usdcAddress = USDCAddresses.address(for: chainId),
               usdcAddress.lowercased() == transfer.token {
                token = .usdc
            } else {
                token = .erc20(address: transfer.token, chainId: chainId)
            }
            observations.append(SimulatedSpendObservation(token: token, amount: transfer.amount))
        }

        return observations
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

    private nonisolated func buildStaticOnlyResult(
        staticWarnings: [String],
        traceAnalysis: TraceAnalysis? = nil,
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
    ) -> PreflightResult {
        if staticWarnings.isEmpty {
            return PreflightResult(
                passed: true,
                gasEstimate: nil,
                aaError: nil,
                failureReason: nil,
                staticWarnings: [],
                diagnosis: "Basic checks passed. No bundler configured — gas simulation skipped.",
                recommendations: ["Configure a ZeroDev project ID to enable bundler simulation"],
                severity: .warning,
                traceAnalysis: traceAnalysis,
                simulatedSpendObservations: simulatedSpendObservations
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
            severity: .error,
            traceAnalysis: traceAnalysis,
            simulatedSpendObservations: simulatedSpendObservations
        )
    }

    private nonisolated func buildBundlerFailure(
        error: ZeroDevError,
        staticWarnings: [String],
        traceAnalysis: TraceAnalysis? = nil,
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
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
            severity: .error,
            traceAnalysis: traceAnalysis,
            simulatedSpendObservations: simulatedSpendObservations
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
