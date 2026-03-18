import Foundation

@Observable
@MainActor
final class SigningManager {
    static let shared = SigningManager()
    private nonisolated static let userOpReceiptPollIntervalSeconds: UInt64 = 3
    private nonisolated static let userOpReceiptTimeoutSeconds: TimeInterval = 90
    private nonisolated static let approvalTimeoutSeconds: UInt64 = 60

    enum SigningState {
        case idle
        case pendingApproval(ApprovalRequest)
        case signing
    }

    private enum ApprovalDecision {
        case approved
        case denied
        case timedOut
    }

    private(set) var state: SigningState = .idle
    private var pendingContinuation: CheckedContinuation<ApprovalDecision, Never>?
    private var isProcessing = false

    private let seManager = SecureEnclaveManager.shared
    private let authManager = AuthManager.shared
    private let ruleEngine = RuleEngine.shared
    private let auditLog = AuditLog.shared
    private let notificationManager = BastionNotificationManager.shared
    private let preflightSimulator = PreflightSimulator.shared

    private init() {}

    func processSignRequest(_ request: SignRequest) async throws -> SignResponse {
        // H-01 + H-02: Serialize all signing requests. Only one request may be
        // in-flight at a time, preventing both TOCTOU counter bypass and
        // approval-hijack via continuation overwrite.
        guard !isProcessing else {
            throw BastionError.signingFailed
        }
        isProcessing = true
        defer { isProcessing = false }

        let dataPrefix = request.requestID.prefix(8).description

        // M-05: Check global allowedClients list before per-client rule routing.
        // Per-client profiles have allowedClients = nil, so the global check must
        // happen here to avoid bypass.
        if ruleEngine.config.rules.enabled,
           let globalAllowedClients = ruleEngine.config.rules.allowedClients,
           !globalAllowedClients.isEmpty {
            if let clientId = request.clientBundleId {
                if !globalAllowedClients.contains(where: { $0.bundleId == clientId }) {
                    auditLog.record(AuditEvent(
                        type: .signDenied,
                        dataPrefix: dataPrefix,
                        reason: "Client \(clientId) not in global allowlist"
                    ))
                    throw BastionError.ruleViolation
                }
            } else {
                auditLog.record(AuditEvent(
                    type: .signDenied,
                    dataPrefix: dataPrefix,
                    reason: "Unknown client — global allowlist is configured"
                ))
                throw BastionError.ruleViolation
            }
        }

        let clientContext = ruleEngine.signingContext(for: request.clientBundleId)
        let effectiveConfig = BastionConfig(
            version: ruleEngine.config.version,
            authPolicy: clientContext.authPolicy,
            rules: clientContext.rules,
            bundlerPreferences: ruleEngine.config.bundlerPreferences,
            clientProfiles: ruleEngine.config.clientProfiles
        )

        // 1. Check all rules — determine if master key (biometric) is needed
        var requiresMasterKey = false
        var violations: [String] = []
        var approvalMode: AuditEvent.ApprovalMode = .auto

        let validation = ruleEngine.validate(request, config: effectiveConfig)
        if case .denied(let reasons) = validation {
            requiresMasterKey = true
            violations.append(contentsOf: reasons)
        }

        // 1b. Run preflight simulation for UserOperation requests.
        // Runs concurrently with rule validation result; does not block signing if it fails.
        var preflightResult: PreflightResult? = nil
        if case .userOperation(let op) = request.operation {
            preflightResult = await preflightSimulator.simulate(
                op: op,
                submission: request.userOperationSubmission,
                preferences: ruleEngine.config.bundlerPreferences
            )
            auditLog.record(AuditEvent(
                type: .preflightCompleted,
                dataPrefix: dataPrefix,
                reason: preflightResult?.passed == false ? preflightResult?.failureReason : nil,
                request: request,
                clientContext: clientContext
            ))
        }

        if requiresMasterKey {
            let reason = violations.joined(separator: "; ")
            auditLog.record(AuditEvent(
                type: .ruleViolation,
                dataPrefix: dataPrefix,
                reason: reason,
                request: request,
                clientContext: clientContext
            ))

            approvalMode = .ruleOverride
            state = .pendingApproval(ApprovalRequest(
                request: request,
                mode: .ruleOverride(violations),
                clientContext: clientContext,
                preflightResult: preflightResult
            ))

            let decision = await awaitApprovalDecision()

            state = .idle

            guard decision == .approved else {
                auditLog.record(AuditEvent(
                    type: .signDenied,
                    dataPrefix: dataPrefix,
                    reason: approvalFailureReason(for: decision),
                    request: request,
                    clientContext: clientContext
                ))
                throw approvalError(for: decision)
            }

            do {
                try await authManager.authenticate(
                    policy: .biometricOrPasscode,
                    reason: "Master key required: \(reason)"
                )
            } catch {
                auditLog.record(AuditEvent(
                    type: .authFailed,
                    dataPrefix: dataPrefix,
                    request: request,
                    clientContext: clientContext
                ))
                throw BastionError.authFailed
            }
        } else {
            let requiresInteractiveReview = requiresInteractivePolicyReview(for: request, config: effectiveConfig)

            if requiresInteractiveReview {
                approvalMode = .policyReview
                // Record that this request reached the approval window. This ensures there is
                // always an audit entry even if the process is killed while the window is open.
                auditLog.record(AuditEvent(
                    type: .signPending,
                    dataPrefix: dataPrefix,
                    request: request,
                    clientContext: clientContext
                ))
                state = .pendingApproval(ApprovalRequest(
                    request: request,
                    mode: .policyReview,
                    clientContext: clientContext,
                    preflightResult: preflightResult
                ))

                let decision = await awaitApprovalDecision()

                state = .idle

                guard decision == .approved else {
                    auditLog.record(AuditEvent(
                        type: .signDenied,
                        dataPrefix: dataPrefix,
                        reason: approvalFailureReason(for: decision),
                        request: request,
                        clientContext: clientContext
                    ))
                    throw approvalError(for: decision)
                }
            }

            if Self.requiresOwnerAuthenticationAfterApproval(
                requiresInteractiveReview: requiresInteractiveReview,
                authPolicy: clientContext.authPolicy
            ) {
                do {
                    try await authManager.authenticate(
                        policy: clientContext.authPolicy,
                        reason: "Authorize signing request"
                    )
                } catch {
                    auditLog.record(AuditEvent(
                        type: .authFailed,
                        dataPrefix: dataPrefix,
                        request: request,
                        clientContext: clientContext
                    ))
                    throw BastionError.authFailed
                }
            }
        }

        // Sign with Secure Enclave (Key B)
        state = .signing
        defer { state = .idle }

        // `request.data` is already the Ethereum-standard 32-byte digest for every operation type.
        // Feed that digest directly into the Secure Enclave to avoid double-hashing message requests.
        let hash = request.data
        let raw = try seManager.signDigest(hash: hash, keyTag: clientContext.keyTag)
        let normalizedS = Data(hexString: raw.s).map { P256Curve.normalizeS($0).hex } ?? raw.s
        let signature = try signatureData(r: raw.r, s: normalizedS)

        // Record local signing success before optional bundler submission.
        auditLog.record(AuditEvent(
            type: .signSuccess,
            dataPrefix: dataPrefix,
            approvalMode: approvalMode,
            request: request,
            clientContext: clientContext
        ))
        ruleEngine.recordSuccess(request: request, config: effectiveConfig)

        // Notify for silently auto-approved requests (no approval window was shown).
        if !requiresMasterKey && !Self.requiresOwnerAuthenticationAfterApproval(
            requiresInteractiveReview: requiresInteractivePolicyReview(for: request, config: effectiveConfig),
            authPolicy: clientContext.authPolicy
        ) {
            notificationManager.notify(
                title: "Request Signed",
                subtitle: clientContext.displayName,
                body: request.operation.displayDescription
            )
        }

        let submission = await submitUserOperationIfRequested(
            for: request,
            signature: signature,
            dataPrefix: dataPrefix,
            clientContext: clientContext
        )

        let result = SignResponse(
            pubkeyX: raw.pubkeyX,
            pubkeyY: raw.pubkeyY,
            r: raw.r,
            s: normalizedS,
            accountAddress: clientContext.accountAddress,
            clientBundleId: clientContext.bundleId,
            submission: submission
        )

        return result
    }

    func approveCurrentRequest() {
        completePendingApproval(with: .approved)
    }

    func denyCurrentRequest() {
        completePendingApproval(with: .denied)
    }

    private func signatureData(r: String, s: String) throws -> Data {
        guard let rData = Data(hexString: r), let sData = Data(hexString: s) else {
            throw BastionError.signingFailed
        }
        var signature = Data()
        signature.append(rData)
        signature.append(sData)
        return signature
    }

    private func awaitApprovalDecision() async -> ApprovalDecision {
        await withCheckedContinuation { continuation in
            pendingContinuation = continuation

            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: Self.approvalTimeoutSeconds * 1_000_000_000)
                guard let self else { return }
                self.completePendingApproval(with: .timedOut)
            }
        }
    }

    private func completePendingApproval(with decision: ApprovalDecision) {
        guard let pendingContinuation else {
            return
        }
        self.pendingContinuation = nil
        pendingContinuation.resume(returning: decision)
    }

    private func approvalFailureReason(for decision: ApprovalDecision) -> String {
        switch decision {
        case .approved:
            return "approved"
        case .denied:
            return "user_denied"
        case .timedOut:
            return "approval_timeout"
        }
    }

    private func approvalError(for decision: ApprovalDecision) -> BastionError {
        switch decision {
        case .approved:
            return .signingFailed
        case .denied:
            return .userDenied
        case .timedOut:
            return .timeout
        }
    }

    private func requiresInteractivePolicyReview(for request: SignRequest, config: BastionConfig) -> Bool {
        return ruleEngine.requiresExplicitApproval(for: request, config: config)
    }

    private func submitUserOperationIfRequested(
        for request: SignRequest,
        signature: Data,
        dataPrefix: String,
        clientContext: ClientSigningContext
    ) async -> UserOperationSubmissionResponse? {
        guard case .userOperation(let op) = request.operation,
              let submission = request.userOperationSubmission else {
            return nil
        }

        switch submission.provider {
        case .zeroDev:
            guard let projectId = submission.projectId, !projectId.isEmpty else {
                let message = "ZeroDev project ID is not configured."
                let response = UserOperationSubmissionResponse(
                    provider: submission.provider.rawValue,
                    status: .sendFailed,
                    userOpHash: nil,
                    transactionHash: nil,
                    error: message
                )
                auditLog.record(AuditEvent(
                    type: .userOpSendFailed,
                    dataPrefix: dataPrefix,
                    reason: message,
                    request: request,
                    clientContext: clientContext,
                    submission: AuditSubmissionSnapshot(
                        provider: submission.provider.displayName,
                        status: response.status.rawValue,
                        userOpHash: nil,
                        transactionHash: nil,
                        detail: message
                    )
                ))
                return response
            }

            let api = ZeroDevAPI(projectId: projectId)
            let rpcOp = UserOperationRPC.from(op, signature: signature)

            do {
                let userOpHash = try await api.sendUserOperation(
                    rpcOp,
                    entryPoint: op.entryPoint,
                    chainId: op.chainId
                )
                let response = UserOperationSubmissionResponse(
                    provider: submission.provider.rawValue,
                    status: .submitted,
                    userOpHash: userOpHash,
                    transactionHash: nil,
                    error: nil
                )
                auditLog.record(AuditEvent(
                    type: .userOpSubmitted,
                    dataPrefix: dataPrefix,
                    request: request,
                    clientContext: clientContext,
                    submission: AuditSubmissionSnapshot(
                        provider: submission.provider.displayName,
                        status: response.status.rawValue,
                        userOpHash: userOpHash,
                        transactionHash: nil,
                        detail: "Submission accepted by bundler"
                    )
                ))
                startReceiptPolling(
                    api: api,
                    request: request,
                    submission: submission,
                    clientContext: clientContext,
                    dataPrefix: dataPrefix,
                    userOpHash: userOpHash
                )
                return response
            } catch {
                let message = String(describing: error)
                let response = UserOperationSubmissionResponse(
                    provider: submission.provider.rawValue,
                    status: .sendFailed,
                    userOpHash: nil,
                    transactionHash: nil,
                    error: message
                )
                auditLog.record(AuditEvent(
                    type: .userOpSendFailed,
                    dataPrefix: dataPrefix,
                    reason: message,
                    request: request,
                    clientContext: clientContext,
                    submission: AuditSubmissionSnapshot(
                        provider: submission.provider.displayName,
                        status: response.status.rawValue,
                        userOpHash: nil,
                        transactionHash: nil,
                        detail: message
                    )
                ))
                notificationManager.notify(
                    title: "UserOperation Send Failed",
                    subtitle: clientContext.displayName,
                    body: message
                )
                return response
            }
        }
    }

    private func startReceiptPolling(
        api: ZeroDevAPI,
        request: SignRequest,
        submission: UserOperationSubmissionRequest,
        clientContext: ClientSigningContext,
        dataPrefix: String,
        userOpHash: String
    ) {
        guard case .userOperation(let op) = request.operation else {
            return
        }

        let auditLog = self.auditLog
        let notificationManager = self.notificationManager
        Task.detached(priority: .utility) {
            let deadline = Date().addingTimeInterval(Self.userOpReceiptTimeoutSeconds)
            var lastError: String?

            while Date() < deadline {
                do {
                    if let receipt = try await api.getUserOperationReceipt(
                        userOpHash: userOpHash,
                        chainId: op.chainId
                    ) {
                        let detail = Self.receiptDetail(receipt)
                        auditLog.record(AuditEvent(
                            type: receipt.success ? .userOpReceiptSuccess : .userOpReceiptFailed,
                            dataPrefix: dataPrefix,
                            reason: receipt.success ? nil : "Bundler receipt reported failure",
                            request: request,
                            clientContext: clientContext,
                            submission: AuditSubmissionSnapshot(
                                provider: submission.provider.displayName,
                                status: receipt.success ? "receipt_success" : "receipt_failed",
                                userOpHash: userOpHash,
                                transactionHash: receipt.receipt?.transactionHash,
                                detail: detail
                            )
                        ))

                        if receipt.success {
                            let transactionHash = receipt.receipt?.transactionHash
                            let body = transactionHash.map { "Confirmed in transaction \($0)" }
                                ?? "The UserOperation was confirmed on-chain."
                            notificationManager.notify(
                                title: "UserOperation Confirmed",
                                subtitle: clientContext.displayName,
                                body: body
                            )
                        } else {
                            notificationManager.notify(
                                title: "UserOperation Failed",
                                subtitle: clientContext.displayName,
                                body: detail
                            )
                        }
                        return
                    }
                } catch {
                    lastError = String(describing: error)
                }

                try? await Task.sleep(nanoseconds: Self.userOpReceiptPollIntervalSeconds * 1_000_000_000)
            }

            auditLog.record(AuditEvent(
                type: .userOpReceiptTimeout,
                dataPrefix: dataPrefix,
                reason: lastError ?? "No receipt returned before timeout",
                request: request,
                clientContext: clientContext,
                submission: AuditSubmissionSnapshot(
                    provider: submission.provider.displayName,
                    status: "receipt_timeout",
                    userOpHash: userOpHash,
                    transactionHash: nil,
                    detail: lastError ?? "Timed out while polling bundler receipt"
                )
            ))
            notificationManager.notify(
                title: "UserOperation Still Pending",
                subtitle: clientContext.displayName,
                body: lastError ?? "Timed out while polling the bundler receipt."
            )
        }
    }

    private nonisolated static func receiptDetail(_ receipt: UserOperationReceipt) -> String {
        var lines = ["Success: \(receipt.success ? "true" : "false")"]
        if let transactionHash = receipt.receipt?.transactionHash {
            lines.append("Transaction Hash: \(transactionHash)")
        }
        if let actualGasCost = receipt.actualGasCost {
            lines.append("Actual Gas Cost: \(actualGasCost)")
        }
        if let actualGasUsed = receipt.actualGasUsed {
            lines.append("Actual Gas Used: \(actualGasUsed)")
        }
        return lines.joined(separator: "\n")
    }

    nonisolated static func requiresOwnerAuthenticationAfterApproval(
        requiresInteractiveReview: Bool,
        authPolicy: AuthPolicy
    ) -> Bool {
        requiresInteractiveReview && authPolicy != .open
    }
}
