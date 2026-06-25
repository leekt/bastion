import Foundation

@Observable
@MainActor
final class SigningManager {
    static let shared = SigningManager()
    nonisolated static let userOpReceiptPollIntervalNanoseconds: UInt64 = 3_000_000_000
    private nonisolated static let userOpReceiptTimeoutSeconds: TimeInterval = 90
    private nonisolated static let approvalTimeoutSeconds: UInt64 = 60
    nonisolated static let approvalTimeoutNanoseconds: UInt64 = approvalTimeoutSeconds * 1_000_000_000

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
    private var approvalTimeoutTask: Task<Void, Never>?
    private var isProcessing = false

    private let seManager = SecureEnclaveManager.shared
    private let authManager = AuthManager.shared
    private let ruleEngine = RuleEngine.shared
    private let auditLog = AuditLog.shared
    private let notificationManager = BastionNotificationManager.shared
    private let preflightSimulator = PreflightSimulator.shared

    // L-02: Notification rate limiting — max 3 notifications per 30 seconds.
    private static let notificationRateLimit = 3
    private static let notificationWindowSeconds: TimeInterval = 30.0
    private var notificationTimestamps: [Date] = []

    private init() {}

    nonisolated static func shouldContinueUserOpReceiptPollingAfterDelay(
        intervalNanoseconds: UInt64 = userOpReceiptPollIntervalNanoseconds,
        sleep: @Sendable (UInt64) async throws -> Void = { nanoseconds in
            try await Task.sleep(nanoseconds: nanoseconds)
        }
    ) async -> Bool {
        do {
            try await sleep(intervalNanoseconds)
        } catch {
            return false
        }
        return !Task.isCancelled
    }

    nonisolated static func shouldTimeoutApprovalAfterDelay(
        timeoutNanoseconds: UInt64 = approvalTimeoutNanoseconds,
        sleep: @Sendable (UInt64) async throws -> Void = { nanoseconds in
            try await Task.sleep(nanoseconds: nanoseconds)
        }
    ) async -> Bool {
        do {
            try await sleep(timeoutNanoseconds)
        } catch {
            return false
        }
        return !Task.isCancelled
    }

    func processSignRequest(_ request: SignRequest) async throws -> SignResponse {
        // H-01 + H-02: Serialize all signing requests. Only one request may be
        // in-flight at a time, preventing both TOCTOU counter bypass and
        // approval-hijack via continuation overwrite.
        guard !isProcessing else {
            throw BastionError.signingFailed
        }
        isProcessing = true
        defer { isProcessing = false }

        // M-05 + R2-M-02: Server-generated requestID prevents audit log manipulation.
        // Replace the client-provided requestID with a server-generated UUID so that ALL
        // audit events and audit record grouping use the server ID, not the client's.
        let serverRequestID = UUID().uuidString
        let request = SignRequest(
            operation: request.operation,
            requestID: serverRequestID,
            timestamp: request.timestamp,
            clientBundleId: request.clientBundleId,
            userOperationSubmission: request.userOperationSubmission,
            intent: request.intent
        )
        let dataPrefix = serverRequestID.prefix(8).description
        DiagnosticLog.shared.record(
            category: .approval,
            event: "sign_request_started",
            message: "Signing request processing started",
            context: [
                "requestID": serverRequestID,
                "operationKind": operationKind(request.operation),
                "bundleId": request.clientBundleId ?? "<unknown>",
                "hasSubmission": String(request.userOperationSubmission != nil)
            ]
        )

        ruleEngine.ensureConfigLoadedIfNeeded()

        // M-05: Check global allowedClients list before per-client rule routing.
        // Per-client profiles have allowedClients = nil, so the global check must
        // happen here to avoid bypass.
        if let denial = ruleEngine.globalClientAllowlistDenial(bundleId: request.clientBundleId) {
            DiagnosticLog.shared.record(
                level: .warning,
                category: .approval,
                event: "sign_request_denied",
                message: "Global client allowlist denied signing request",
                context: ["requestID": serverRequestID]
            )
            auditLog.record(AuditEvent(
                type: .signDenied,
                dataPrefix: dataPrefix,
                reason: denial
            ))
            throw BastionError.ruleViolation
        }

        if let denial = ruleEngine.signingBlockedReason(for: request.clientBundleId) {
            DiagnosticLog.shared.record(
                level: .warning,
                category: .approval,
                event: "sign_request_blocked",
                message: denial,
                context: ["requestID": serverRequestID]
            )
            auditLog.record(AuditEvent(
                type: .signDenied,
                dataPrefix: dataPrefix,
                reason: denial,
                request: request
            ))
            throw BastionError.ruleViolation
        }

        let clientContext = ruleEngine.signingContext(for: request.clientBundleId, createProfile: false)
        var effectiveConfig = ruleEngine.config
        effectiveConfig.authPolicy = clientContext.authPolicy
        effectiveConfig.rules = clientContext.rules
        effectiveConfig.clientProfiles = ruleEngine.config.clientProfiles

        if let senderViolation = userOperationSenderViolation(request: request, clientContext: clientContext) {
            DiagnosticLog.shared.record(
                level: .warning,
                category: .approval,
                event: "sign_request_denied",
                message: "UserOperation sender did not match client account",
                context: ["requestID": serverRequestID]
            )
            auditLog.record(AuditEvent(
                type: .signDenied,
                dataPrefix: dataPrefix,
                reason: senderViolation,
                request: request,
                clientContext: clientContext
            ))
            throw BastionError.ruleViolation
        }

        var requiresMasterKey = false
        var violations: [String] = []
        var approvalMode: AuditEvent.ApprovalMode = .auto

        let staticValidation = ruleEngine.validate(
            request,
            config: effectiveConfig
        )
        if case .blocked(let reasons) = staticValidation {
            let reason = reasons.joined(separator: "; ")
            DiagnosticLog.shared.record(
                level: .warning,
                category: .approval,
                event: "sign_request_blocked",
                message: reason,
                context: ["requestID": serverRequestID]
            )
            auditLog.record(AuditEvent(
                type: .signDenied,
                dataPrefix: dataPrefix,
                reason: reason,
                request: request,
                clientContext: clientContext
            ))
            throw BastionError.ruleViolation
        } else if case .denied(let reasons) = staticValidation {
            requiresMasterKey = true
            violations.append(contentsOf: reasons)
        }

        // Run preflight only after hard/static policy gates have passed. Trace
        // data from the simulation can still tighten validation afterward.
        var preflightResult: PreflightResult? = nil
        if !requiresMasterKey, case .userOperation(let op) = request.operation {
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
            let tracedValidation = ruleEngine.validate(
                request,
                config: effectiveConfig,
                traceAnalysis: preflightResult?.traceAnalysis,
                simulatedSpendObservations: preflightResult?.simulatedSpendObservations
            )
            if case .blocked(let reasons) = tracedValidation {
                let reason = reasons.joined(separator: "; ")
                DiagnosticLog.shared.record(
                    level: .warning,
                    category: .approval,
                    event: "sign_request_blocked_after_preflight",
                    message: reason,
                    context: ["requestID": serverRequestID]
                )
                auditLog.record(AuditEvent(
                    type: .signDenied,
                    dataPrefix: dataPrefix,
                    reason: reason,
                    request: request,
                    clientContext: clientContext
                ))
                throw BastionError.ruleViolation
            } else if case .denied(let reasons) = tracedValidation {
                requiresMasterKey = true
                violations.append(contentsOf: reasons)
            }
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
            DiagnosticLog.shared.record(
                category: .approval,
                event: "approval_window_opened",
                message: "Approval window opened for rule override",
                context: ["requestID": serverRequestID, "mode": "rule_override"]
            )
            state = .pendingApproval(ApprovalRequest(
                request: request,
                mode: .ruleOverride(violations),
                clientContext: clientContext,
                preflightResult: preflightResult,
                typedConfirmationPhrase: typedConfirmationPhrase(
                    for: request,
                    config: effectiveConfig,
                    violations: violations,
                    simulatedSpendObservations: preflightResult?.simulatedSpendObservations
                )
            ))

            let decision = await awaitApprovalDecision()

            state = .idle

            guard decision == .approved else {
                DiagnosticLog.shared.record(
                    level: .warning,
                    category: .approval,
                    event: "approval_decision_rejected",
                    message: approvalFailureReason(for: decision),
                    context: ["requestID": serverRequestID, "mode": "rule_override"]
                )
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
                DiagnosticLog.shared.record(
                    level: .warning,
                    category: .approval,
                    event: "owner_auth_failed",
                    message: "Owner authentication failed after rule override approval",
                    context: ["requestID": serverRequestID]
                )
                auditLog.record(AuditEvent(
                    type: .authFailed,
                    dataPrefix: dataPrefix,
                    request: request,
                    clientContext: clientContext
                ))
                throw BastionError.authFailed
            }
        } else {
                let requiresInteractiveReview = requiresInteractivePolicyReview(
                    for: request,
                    config: effectiveConfig,
                    simulatedSpendObservations: preflightResult?.simulatedSpendObservations
                )

            if requiresInteractiveReview {
                approvalMode = .policyReview
                DiagnosticLog.shared.record(
                    category: .approval,
                    event: "approval_window_opened",
                    message: "Approval window opened for policy review",
                    context: ["requestID": serverRequestID, "mode": "policy_review"]
                )
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
                    preflightResult: preflightResult,
                    typedConfirmationPhrase: typedConfirmationPhrase(
                        for: request,
                        config: effectiveConfig,
                        violations: [],
                        simulatedSpendObservations: preflightResult?.simulatedSpendObservations
                    )
                ))

                let decision = await awaitApprovalDecision()

                state = .idle

                guard decision == .approved else {
                    DiagnosticLog.shared.record(
                        level: .warning,
                        category: .approval,
                        event: "approval_decision_rejected",
                        message: approvalFailureReason(for: decision),
                        context: ["requestID": serverRequestID, "mode": "policy_review"]
                    )
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
                    DiagnosticLog.shared.record(
                        level: .warning,
                        category: .approval,
                        event: "owner_auth_failed",
                        message: "Owner authentication failed after policy review approval",
                        context: ["requestID": serverRequestID]
                    )
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

        // C-02: Record rate limit and spending counters BEFORE signing. This ensures a
        // concurrent request that arrives between validation and signing sees the updated
        // counters and cannot bypass limits via TOCTOU. If signing fails, the counter is
        // "wasted" (one phantom request counted) which is the safe/conservative direction —
        // better to over-count than under-count and allow a limit bypass.
        try ruleEngine.recordSuccess(
            request: request,
            config: effectiveConfig,
            simulatedSpendObservations: preflightResult?.simulatedSpendObservations
        )

        // `request.data` is already the Ethereum-standard 32-byte digest for every operation type.
        // Feed that digest directly into the Secure Enclave to avoid double-hashing message requests.
        let hash = request.data
        let raw: SignResponse
        #if DEBUG
        if let qaRaw = try RuntimeQASigningProvider.shared.signDigestIfEnabled(
            hash: hash,
            keyTag: clientContext.keyTag
        ) {
            raw = qaRaw
        } else {
            raw = try seManager.signDigest(hash: hash, keyTag: clientContext.keyTag)
        }
        #else
        raw = try seManager.signDigest(hash: hash, keyTag: clientContext.keyTag)
        #endif
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
        DiagnosticLog.shared.record(
            category: .approval,
            event: "sign_request_signed",
            message: "Signing request completed locally",
            context: ["requestID": serverRequestID, "approvalMode": approvalMode.rawValue]
        )

        // Notify for silently auto-approved requests (no approval window was shown).
        // L-02: Rate-limited to prevent notification flood.
        if !requiresMasterKey && !Self.requiresOwnerAuthenticationAfterApproval(
            requiresInteractiveReview: requiresInteractivePolicyReview(
                for: request,
                config: effectiveConfig,
                simulatedSpendObservations: preflightResult?.simulatedSpendObservations
            ),
            authPolicy: clientContext.authPolicy
        ) {
            rateLimitedNotify(
                title: request.executionMode.completedNotificationTitle,
                subtitle: clientContext.displayName,
                body: request.operation.displayDescription
            )

            // v9: in-app quiet receipt toast for silent signs. Only shown for
            // userOperations (where there's a meaningful action to summarise).
            if case .userOperation(let op) = request.operation {
                let decoded = CalldataDecoder.decode(op)
                let leaves = decoded.executions.flatMap(\.allLeafExecutions)
                let title: String
                if let token = leaves.compactMap(\.tokenOperation).first,
                   let counterparty = token.counterparty {
                    title = "Signed: \(token.kind.rawValue.capitalized) \(token.amount) to \(counterparty.prefix(8))…"
                } else {
                    title = "Signed: Contract call"
                }
                Task { @MainActor in
                    SilentBannerManager.shared.show(
                        title: title,
                        subtitle: "\(clientContext.displayName) · silent · just now"
                    )
                }
            }
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
            accountAddress: clientContext.accountAddress ?? raw.accountAddress,
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
            approvalTimeoutTask?.cancel()
            pendingContinuation = continuation

            approvalTimeoutTask = Task { @MainActor [weak self] in
                guard await Self.shouldTimeoutApprovalAfterDelay() else { return }
                guard let self else { return }
                self.completePendingApproval(with: .timedOut)
            }
        }
    }

    private func completePendingApproval(with decision: ApprovalDecision) {
        guard let pendingContinuation else {
            return
        }
        approvalTimeoutTask?.cancel()
        approvalTimeoutTask = nil
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

    private nonisolated func operationKind(_ operation: SigningOperation) -> String {
        switch operation {
        case .message: return "message"
        case .rawBytes: return "rawBytes"
        case .typedData: return "typedData"
        case .userOperation: return "userOperation"
        }
    }

    private func requiresInteractivePolicyReview(
        for request: SignRequest,
        config: BastionConfig,
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
    ) -> Bool {
        return ruleEngine.requiresExplicitApproval(
            for: request,
            config: config,
            simulatedSpendObservations: simulatedSpendObservations
        )
    }

    private func userOperationSenderViolation(
        request: SignRequest,
        clientContext: ClientSigningContext
    ) -> String? {
        guard case .userOperation(let op) = request.operation,
              let expected = clientContext.accountAddress,
              normalizedAddress(op.sender) != normalizedAddress(expected) else {
            return nil
        }
        return "UserOperation sender \(shortAddress(op.sender)) does not match client account \(shortAddress(expected))"
    }

    private func typedConfirmationPhrase(
        for request: SignRequest,
        config: BastionConfig,
        violations: [String],
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
    ) -> String? {
        if let highValuePhrase = ruleEngine.highValueConfirmationPhrase(
            for: request,
            config: config,
            simulatedSpendObservations: simulatedSpendObservations
        ) {
            return highValuePhrase
        }
        let riskyOverride = violations.contains { reason in
            let lower = reason.lowercased()
            return lower.contains("spending limit") ||
                   lower.contains("high-value") ||
                   lower.contains("exceeded")
        }
        return riskyOverride ? "SIGN" : nil
    }

    private func normalizedAddress(_ address: String) -> String {
        address.lowercased()
    }

    private func shortAddress(_ address: String) -> String {
        "\(address.prefix(10))…"
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
            // PR1: every signing/submission path goes through
            // BundlerTrustResolver. Pre-cleanup, this site trusted whatever
            // the agent put in submission.projectId — letting an agent
            // redirect a sponsored UserOp through an attacker-controlled
            // bundler. Now app-config wins; wire-supplied is a fallback
            // only when no project is configured.
            let resolved: ResolvedBundler
            do {
                resolved = try BundlerTrustResolver.resolveZeroDevProjectId(
                    wireSupplied: submission.projectId,
                    config: ruleEngine.config
                )
            } catch {
                let diagnostic = ProviderFailureDiagnostic.configuration(
                    provider: submission.provider,
                    message: "ZeroDev project ID is not configured."
                )
                let message = diagnostic.userFacingMessage
                DiagnosticLog.shared.record(
                    level: .warning,
                    category: .submission,
                    event: "userop_submission_configuration_failed",
                    message: message,
                    context: ["requestID": request.requestID, "provider": submission.provider.rawValue]
                )
                let response = UserOperationSubmissionResponse(
                    provider: submission.provider.rawValue,
                    status: .sendFailed,
                    userOpHash: nil,
                    transactionHash: nil,
                    error: message,
                    diagnostic: diagnostic
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
                        detail: message,
                        diagnostic: diagnostic
                    )
                ))
                return response
            }

            // Surface override decisions in the audit log so a
            // post-incident review can spot agents probing alternate
            // bundlers.
            if resolved.source == .configOverrodeRequest {
                auditLog.record(AuditEvent(
                    type: .ruleViolation,
                    dataPrefix: dataPrefix,
                    reason: "Bundler override: app-configured ZeroDev project used instead of \(submission.projectId ?? "unset")",
                    request: request,
                    clientContext: clientContext
                ))
            }

            let api = ZeroDevAPI(projectId: resolved.projectId)
            let rpcOp = UserOperationRPC.from(op, signature: signature)
            DiagnosticLog.shared.record(
                category: .submission,
                event: "userop_submission_started",
                message: "Submitting UserOperation to provider",
                context: [
                    "requestID": request.requestID,
                    "provider": submission.provider.rawValue,
                    "chainId": String(op.chainId)
                ]
            )

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
                DiagnosticLog.shared.record(
                    category: .submission,
                    event: "userop_submission_accepted",
                    message: "Provider accepted UserOperation",
                    context: [
                        "requestID": request.requestID,
                        "provider": submission.provider.rawValue
                    ]
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
                SubmissionStatusStore.shared.markSubmitted(
                    requestID: request.requestID,
                    clientDisplayName: clientContext.displayName,
                    provider: submission.provider.displayName,
                    chainId: op.chainId,
                    userOpHash: userOpHash
                )
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
                let diagnostic = ProviderFailureDiagnostic.from(
                    error: error,
                    provider: submission.provider,
                    stage: .submission
                )
                let message = diagnostic.userFacingMessage
                DiagnosticLog.shared.record(
                    level: diagnostic.retryable ? .warning : .error,
                    category: .submission,
                    event: "userop_submission_failed",
                    message: message,
                    context: [
                        "requestID": request.requestID,
                        "provider": submission.provider.rawValue,
                        "stage": diagnostic.stage.rawValue,
                        "category": diagnostic.category.rawValue,
                        "retryable": String(diagnostic.retryable)
                    ]
                )
                let response = UserOperationSubmissionResponse(
                    provider: submission.provider.rawValue,
                    status: .sendFailed,
                    userOpHash: nil,
                    transactionHash: nil,
                    error: message,
                    diagnostic: diagnostic
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
                        detail: message,
                        diagnostic: diagnostic
                    )
                ))
                notificationManager.notify(
                    title: request.executionMode.failedNotificationTitle,
                    subtitle: clientContext.displayName,
                    body: message,
                    identifier: Self.notificationIdentifier(
                        requestID: request.requestID,
                        stage: "send-failed"
                    ),
                    userInfo: Self.notificationUserInfo(
                        request: request,
                        clientContext: clientContext,
                        stage: "send_failed",
                        provider: submission.provider.displayName
                    )
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
            var lastDiagnostic: ProviderFailureDiagnostic?

            while Date() < deadline {
                do {
                    if let receipt = try await api.getUserOperationReceipt(
                        userOpHash: userOpHash,
                        chainId: op.chainId
                    ) {
                        let detail = Self.receiptDetail(receipt)
                        let failureDiagnostic = receipt.success ? nil : ProviderFailureDiagnostic.onChainFailure(
                            provider: submission.provider,
                            detail: detail
                        )
                        auditLog.record(AuditEvent(
                            type: receipt.success ? .userOpReceiptSuccess : .userOpReceiptFailed,
                            dataPrefix: dataPrefix,
                            reason: receipt.success ? nil : failureDiagnostic?.userFacingMessage,
                            request: request,
                            clientContext: clientContext,
                            submission: AuditSubmissionSnapshot(
                                provider: submission.provider.displayName,
                                status: receipt.success ? "receipt_success" : "receipt_failed",
                                userOpHash: userOpHash,
                                transactionHash: receipt.receipt?.transactionHash,
                                detail: failureDiagnostic?.userFacingMessage ?? detail,
                                diagnostic: failureDiagnostic
                            )
                        ))
                        SubmissionStatusStore.shared.markFinished(requestID: request.requestID)

                        if receipt.success {
                            DiagnosticLog.shared.record(
                                category: .submission,
                                event: "userop_receipt_success",
                                message: "UserOperation receipt reported success",
                                context: ["requestID": request.requestID]
                            )
                            let transactionHash = receipt.receipt?.transactionHash
                            let body = transactionHash.map { "Confirmed in transaction \($0)" }
                                ?? "The UserOperation was confirmed on-chain."
                            notificationManager.notify(
                                title: request.executionMode.confirmedNotificationTitle,
                                subtitle: clientContext.displayName,
                                body: body,
                                identifier: Self.notificationIdentifier(
                                    requestID: request.requestID,
                                    stage: "confirmed"
                                ),
                                userInfo: Self.notificationUserInfo(
                                    request: request,
                                    clientContext: clientContext,
                                    stage: "confirmed",
                                    provider: submission.provider.displayName,
                                    userOpHash: userOpHash,
                                    transactionHash: transactionHash
                                )
                            )
                        } else {
                            DiagnosticLog.shared.record(
                                level: .error,
                                category: .submission,
                                event: "userop_receipt_failed",
                                message: failureDiagnostic?.userFacingMessage ?? detail,
                                context: ["requestID": request.requestID]
                            )
                            notificationManager.notify(
                                title: request.executionMode.failedNotificationTitle,
                                subtitle: clientContext.displayName,
                                body: failureDiagnostic?.userFacingMessage ?? detail,
                                identifier: Self.notificationIdentifier(
                                    requestID: request.requestID,
                                    stage: "receipt-failed"
                                ),
                                userInfo: Self.notificationUserInfo(
                                    request: request,
                                    clientContext: clientContext,
                                    stage: "receipt_failed",
                                    provider: submission.provider.displayName,
                                    userOpHash: userOpHash,
                                    transactionHash: receipt.receipt?.transactionHash
                                )
                            )
                        }
                        return
                    }
                } catch {
                    let diagnostic = ProviderFailureDiagnostic.from(
                        error: error,
                        provider: submission.provider,
                        stage: .receiptTracking
                    )
                    lastDiagnostic = diagnostic
                    lastError = diagnostic.userFacingMessage
                }

                guard await Self.shouldContinueUserOpReceiptPollingAfterDelay() else { return }
            }

            let timeoutDiagnostic = ProviderFailureDiagnostic.receiptTimeout(
                provider: submission.provider,
                lastError: lastDiagnostic?.userFacingMessage ?? lastError
            )
            DiagnosticLog.shared.record(
                level: .warning,
                category: .submission,
                event: "userop_receipt_timeout",
                message: timeoutDiagnostic.userFacingMessage,
                context: ["requestID": request.requestID]
            )
            auditLog.record(AuditEvent(
                type: .userOpReceiptTimeout,
                dataPrefix: dataPrefix,
                reason: timeoutDiagnostic.userFacingMessage,
                request: request,
                clientContext: clientContext,
                submission: AuditSubmissionSnapshot(
                    provider: submission.provider.displayName,
                    status: "receipt_timeout",
                    userOpHash: userOpHash,
                    transactionHash: nil,
                    detail: timeoutDiagnostic.userFacingMessage,
                    diagnostic: timeoutDiagnostic
                )
            ))
            SubmissionStatusStore.shared.markFinished(requestID: request.requestID)
            notificationManager.notify(
                title: request.executionMode.pendingNotificationTitle,
                subtitle: clientContext.displayName,
                body: timeoutDiagnostic.userFacingMessage,
                identifier: Self.notificationIdentifier(
                    requestID: request.requestID,
                    stage: "receipt-timeout"
                ),
                userInfo: Self.notificationUserInfo(
                    request: request,
                    clientContext: clientContext,
                    stage: "receipt_timeout",
                    provider: submission.provider.displayName,
                    userOpHash: userOpHash
                )
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

    // L-02: Rate-limited notification delivery.
    private func rateLimitedNotify(title: String, subtitle: String? = nil, body: String) {
        let now = Date()
        let cutoff = now.addingTimeInterval(-Self.notificationWindowSeconds)
        notificationTimestamps.removeAll { $0 < cutoff }
        guard notificationTimestamps.count < Self.notificationRateLimit else { return }
        notificationTimestamps.append(now)
        notificationManager.notify(title: title, subtitle: subtitle, body: body)
    }

    nonisolated static func notificationIdentifier(
        requestID: String,
        stage: String
    ) -> String {
        "bastion.signing.\(requestID).\(stage)"
    }

    nonisolated static func notificationUserInfo(
        request: SignRequest,
        clientContext: ClientSigningContext,
        stage: String,
        provider: String? = nil,
        userOpHash: String? = nil,
        transactionHash: String? = nil
    ) -> [String: String] {
        var userInfo = [
            "requestID": request.requestID,
            "clientDisplayName": clientContext.displayName,
            "executionMode": request.executionMode.rawValue,
            "operationKind": request.operationKindLabel,
            "stage": stage
        ]
        if let provider {
            userInfo["provider"] = provider
        }
        if let userOpHash {
            userInfo["userOpHash"] = userOpHash
        }
        if let transactionHash {
            userInfo["transactionHash"] = transactionHash
        }
        return userInfo
    }

    nonisolated static func requiresOwnerAuthenticationAfterApproval(
        requiresInteractiveReview: Bool,
        authPolicy: AuthPolicy
    ) -> Bool {
        requiresInteractiveReview && authPolicy != .open
    }
}
