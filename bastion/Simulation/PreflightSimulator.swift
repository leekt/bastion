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

// MARK: - Preflight Simulator

/// Runs preflight checks on a UserOperation before the approval window opens.
///
/// Two-tier approach:
///   1. Static local checks (always run): dummy sig, gas sanity, fee sanity.
///   2. Bundler simulation (when project ID and chain ID are available):
///      calls `eth_estimateUserOperationGas` with the bundler, which internally
///      runs `simulateHandleOp`. Success means account + paymaster validation
///      and calldata execution are all expected to pass.
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
        if isDummySignature(op) {
            staticWarnings.append("Signature looks like a placeholder — make sure a real signature is used before submitting")
        }
        if let warn = gasWarning(op) {
            staticWarnings.append(warn)
        }
        if let warn = feeWarning(op) {
            staticWarnings.append(warn)
        }

        // ─── Bundler simulation ──────────────────────────────────────────────
        let projectId = submission?.projectId ?? preferences.zeroDevProjectId
        guard let projectId, !projectId.isEmpty else {
            return buildStaticOnlyResult(staticWarnings: staticWarnings)
        }

        let api = ZeroDevAPI(projectId: projectId)
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

    // MARK: - Static Checks

    private nonisolated func isDummySignature(_ op: UserOperation) -> Bool {
        // If the request doesn't carry a pre-built signature there is nothing to warn about.
        // The signature is not part of UserOperation in Bastion's internal model.
        // This check is reserved for cases where signature data is embedded in the op.
        false
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
