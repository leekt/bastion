import Foundation
import Darwin

final class XPCServer: NSObject, NSXPCListenerDelegate {
    static let shared = XPCServer()

    private var listener: NSXPCListener?
    private let signingManager = SigningManager.shared
    private let ruleEngine = RuleEngine.shared

    private override init() {
        super.init()
    }

    func start() {
        listener = NSXPCListener(machServiceName: xpcServiceName)
        listener?.delegate = self
        listener?.resume()
    }

    func stop() {
        listener?.invalidate()
        listener = nil
    }

    // MARK: - NSXPCListenerDelegate

    nonisolated func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        if !verifyClientCodeSignature(connection: newConnection) {
            return false
        }

        let clientBundleId = bundleIdentifier(for: newConnection.processIdentifier)

        newConnection.exportedInterface = NSXPCInterface(with: BastionXPCProtocol.self)
        newConnection.exportedObject = XPCHandler(
            signingManager: signingManager,
            ruleEngine: ruleEngine,
            clientBundleId: clientBundleId
        )
        newConnection.invalidationHandler = {}
        newConnection.resume()
        return true
    }

    // MARK: - Client Identification

    /// Extracts the bundle identifier from a running process via its code signature.
    private nonisolated func bundleIdentifier(for pid: Int32) -> String? {
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess,
              let secCode = code else {
            return nil
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(secCode, [], &staticCode) == errSecSuccess,
              let sCode = staticCode else {
            return nil
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(sCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let signingInfo = info as? [String: Any],
              let plist = signingInfo[kSecCodeInfoPList as String] as? [String: Any],
              let bundleId = plist["CFBundleIdentifier"] as? String else {
            // CLI tools may not have a bundle identifier — try the identifier from code signing
            if let info = info as? [String: Any],
               let identifier = info[kSecCodeInfoIdentifier as String] as? String {
                return identifier
            }
            return nil
        }
        return bundleId
    }

    // MARK: - Code Signing Verification

    /// Team ID that signed Bastion.app — only clients signed by the same team are accepted.
    private nonisolated static let requiredTeamID = "926A27BQ7W"
    private nonisolated static let untrustedDevSignatureStatus = OSStatus(CSSMERR_TP_NOT_TRUSTED)

    private nonisolated func verifyClientCodeSignature(connection: NSXPCConnection) -> Bool {
        let pid = connection.processIdentifier
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess,
              let secCode = code else {
            return false
        }

        // Require valid code signature
        let validityStatus = SecCodeCheckValidity(secCode, [], nil)
#if DEBUG
        let allowUntrustedDevSignature = validityStatus == Self.untrustedDevSignatureStatus
#else
        let allowUntrustedDevSignature = false
#endif
        guard validityStatus == errSecSuccess || allowUntrustedDevSignature else {
            return false
        }

        // Verify the client is signed by the same team
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(secCode, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return false
        }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &info
        ) == errSecSuccess,
              let signingInfo = info as? [String: Any] else {
            return false
        }

        if let teamID = signingInfo[kSecCodeInfoTeamIdentifier as String] as? String {
            return teamID == Self.requiredTeamID
        }

#if DEBUG
        return isAllowedDebugSidecar(pid: pid, signingInfo: signingInfo)
#else
        return false
#endif
    }

#if DEBUG
    // L-04: Require both identifier match AND path check. The previous
    // fallback accepted any binary at the CLI path regardless of identity.
    private nonisolated func isAllowedDebugSidecar(pid: Int32, signingInfo: [String: Any]) -> Bool {
        guard let identifier = signingInfo[kSecCodeInfoIdentifier as String] as? String,
              identifier == "bastion-cli-arm64" else {
            return false
        }
        return executablePath(for: pid)?.hasSuffix("/bastion.app/Contents/MacOS/bastion-cli") == true
    }

    private nonisolated func executablePath(for pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        let result = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard result > 0 else {
            return nil
        }
        return String(cString: buffer)
    }
#endif
}

// Separate handler class for XPC callbacks (runs on XPC queue, not MainActor)
private nonisolated final class XPCHandler: NSObject, BastionXPCProtocol, @unchecked Sendable {
    private enum ResolvedUserOperationRequest {
        case direct(UserOperation, UserOperationSubmissionRequest?)
        case intent(UserOperationIntentRequestEnvelope)
    }

    private let signingManager: SigningManager
    private let ruleEngine: RuleEngine
    private let clientBundleId: String?

    nonisolated init(signingManager: SigningManager, ruleEngine: RuleEngine, clientBundleId: String?) {
        self.signingManager = signingManager
        self.ruleEngine = ruleEngine
        self.clientBundleId = clientBundleId
        super.init()
    }

    nonisolated func sign(
        data: Data,
        requestID: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        guard data.count == 32 else {
            reply(nil, BastionError.invalidInput.nsError)
            return
        }

        Task { @MainActor in
            do {
                // Legacy: wrap raw data as a message signing operation
                // TODO: replace with structured signing when CLI sends typed operations
                let request = SignRequest(
                    operation: .message(data.hex),
                    requestID: requestID,
                    timestamp: Date(),
                    clientBundleId: self.clientBundleId
                )
                let result = try await signingManager.processSignRequest(request)
                let jsonData = try JSONEncoder().encode(result)
                reply(jsonData, nil)
            } catch let error as BastionError {
                reply(nil, error.nsError)
            } catch {
                reply(nil, error)
            }
        }
    }

    nonisolated func getPublicKey(withReply reply: @escaping (Data?, Error?) -> Void) {
        Task { @MainActor in
            do {
                let context = ruleEngine.signingContext(for: self.clientBundleId)
                let raw = try SecureEnclaveManager.shared.getPublicKey(keyTag: context.keyTag)
                let result = PublicKeyResponse(
                    x: raw.x,
                    y: raw.y,
                    accountAddress: context.accountAddress ?? raw.accountAddress
                )
                let jsonData = try JSONEncoder().encode(result)
                reply(jsonData, nil)
            } catch {
                reply(nil, error)
            }
        }
    }

    nonisolated func ping(withReply reply: @escaping (Bool) -> Void) {
        reply(true)
    }

    nonisolated func openUI(
        target: String,
        withReply reply: @escaping (Bool, Error?) -> Void
    ) {
        Task { @MainActor in
            guard let uiTarget = ServiceUITarget(rawValue: target) else {
                reply(false, BastionError.invalidInput.nsError)
                return
            }

            ServiceUIBridge.openInCurrentProcess(uiTarget)
            reply(true, nil)
        }
    }

    nonisolated func getRules(withReply reply: @escaping (Data?, Error?) -> Void) {
        Task { @MainActor in
            let config = ruleEngine.config
            let context = ruleEngine.signingContext(for: self.clientBundleId)
            let response = RulesResponse(
                authPolicy: context.authPolicy.rawValue,
                globalAuthPolicy: config.authPolicy.rawValue,
                rules: context.rules,
                globalRules: config.rules,
                clientProfile: ruleEngine.clientProfileInfo(bundleId: self.clientBundleId),
                accountAddress: context.accountAddress
            )
            do {
                let jsonData = try JSONEncoder().encode(response)
                reply(jsonData, nil)
            } catch {
                reply(nil, error)
            }
        }
    }

    nonisolated func getState(withReply reply: @escaping (Data?, Error?) -> Void) {
        Task { @MainActor in
            let effectiveRules = ruleEngine.effectiveRules(for: self.clientBundleId)

            let rateLimits = effectiveRules.rateLimits.map { ruleEngine.stateStore.rateLimitStatus(rule: $0) }
            let spendingLimits = effectiveRules.spendingLimits.map { ruleEngine.stateStore.spendingLimitStatus(rule: $0) }
            let context = ruleEngine.signingContext(for: self.clientBundleId)

            let response = StateResponse(
                rateLimits: rateLimits,
                spendingLimits: spendingLimits,
                clientProfile: ruleEngine.clientProfileInfo(bundleId: self.clientBundleId),
                accountAddress: context.accountAddress
            )
            do {
                let jsonData = try JSONEncoder().encode(response)
                reply(jsonData, nil)
            } catch {
                reply(nil, error)
            }
        }
    }

    nonisolated func prepareSelfUserOperation(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        let request: SelfUserOperationRequest
        do {
            request = try JSONDecoder().decode(SelfUserOperationRequest.self, from: requestData)
        } catch {
            reply(nil, BastionError.invalidInput.nsError)
            return
        }

        Task { @MainActor in
            do {
                // M-03: Check rate limits before building sponsored operations.
                // Prevents agents from draining paymaster credits without signing.
                let context = ruleEngine.signingContext(for: self.clientBundleId)
                if context.rules.enabled {
                    for rule in context.rules.rateLimits {
                        let count = ruleEngine.stateStore.rateLimitCount(ruleId: rule.id, windowSeconds: rule.windowSeconds)
                        if count >= rule.maxRequests {
                            reply(nil, BastionError.ruleViolation.nsError)
                            return
                        }
                    }
                }

                let projectId = try self.resolvedZeroDevProjectId(from: request.projectId)
                let (account, _) = try self.currentClientSmartAccount()
                let bundler = ZeroDevAPI(projectId: projectId)
                let rpc = self.resolvedEthRPC(chainId: request.chainId, bundler: bundler)
                let op = try await account.buildSponsoredSelfUserOperation(
                    using: rpc,
                    bundler: bundler,
                    chainId: request.chainId
                )
                let jsonData = try JSONEncoder().encode(op)
                reply(jsonData, nil)
            } catch let error as BastionError {
                reply(nil, error.nsError)
            } catch {
                reply(nil, error)
            }
        }
    }

    @MainActor
    private func resolvedZeroDevProjectId(from explicitProjectId: String?) throws -> String {
        // M-08: App-configured project ID takes priority over client-specified.
        // Prevents agents from redirecting UserOps to attacker-controlled bundlers.
        if let configured = ruleEngine.config.bundlerPreferences.zeroDevProjectId?.trimmingCharacters(in: .whitespacesAndNewlines),
           !configured.isEmpty {
            return configured
        }

        if let explicitProjectId = explicitProjectId?.trimmingCharacters(in: .whitespacesAndNewlines),
           !explicitProjectId.isEmpty {
            return explicitProjectId
        }

        throw NSError(
            domain: "com.bastion.error",
            code: BastionError.invalidInput.rawValue,
            userInfo: [NSLocalizedDescriptionKey: "ZeroDev project ID is not configured in Bastion settings."]
        )
    }

    @MainActor
    private func resolvedSubmissionRequest(_ submission: UserOperationSubmissionRequest?) throws -> UserOperationSubmissionRequest? {
        guard let submission else {
            return nil
        }

        switch submission.provider {
        case .zeroDev:
            return UserOperationSubmissionRequest(
                provider: .zeroDev,
                projectId: try resolvedZeroDevProjectId(from: submission.projectId)
            )
        }
    }

    @MainActor
    private func resolvedEthRPC(chainId: Int, bundler: ZeroDevAPI) -> EthRPC {
        if let endpoint = ruleEngine.config.bundlerPreferences.chainRPCs.first(where: { $0.chainId == chainId }),
           let url = URL(string: endpoint.rpcURL) {
            return EthRPC(rpcURL: url)
        }
        return EthRPC(rpcURL: bundler.rpcURL(chainId: chainId))
    }

    @MainActor
    private func currentClientSmartAccount() throws -> (SmartAccount, ClientSigningContext) {
        let context = ruleEngine.signingContext(for: clientBundleId)
        let publicKey = try SecureEnclaveManager.shared.getPublicKey(keyTag: context.keyTag)
        guard
            let publicKeyX = Data(hexString: publicKey.x),
            let publicKeyY = Data(hexString: publicKey.y)
        else {
            throw BastionError.invalidInput
        }

        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: publicKeyX,
            publicKeyY: publicKeyY,
            sign: { _ in Data(repeating: 0, count: 64) }
        )
        let account = SmartAccount(validator: validator)
        if let accountAddress = context.accountAddress {
            account.setAddress(accountAddress)
        }
        return (account, context)
    }

    private func kernelExecutions(from requestedExecutions: [RequestedExecution]) throws -> [KernelEncoding.Execution] {
        guard !requestedExecutions.isEmpty else {
            throw BastionError.invalidInput
        }

        return try requestedExecutions.map { requested in
            guard KernelEncoding.isValidAddress(requested.target),
                  KernelEncoding.isValidUInt256(requested.value) else {
                throw BastionError.invalidInput
            }
            return KernelEncoding.Execution(
                to: requested.target,
                value: requested.value,
                data: requested.data
            )
        }
    }

    @MainActor
    private func buildUserOperation(from intent: UserOperationIntentRequestEnvelope) async throws -> (UserOperation, UserOperationSubmissionRequest?) {
        let projectId = try resolvedZeroDevProjectId(from: intent.projectId)
        let (account, _) = try currentClientSmartAccount()
        let bundler = ZeroDevAPI(projectId: projectId)
        let rpc = resolvedEthRPC(chainId: intent.chainId, bundler: bundler)
        let executions = try kernelExecutions(from: intent.executions)
        let callData: Data
        if executions.count == 1, let single = executions.first {
            callData = KernelEncoding.executeCalldata(single: single)
        } else {
            callData = KernelEncoding.executeCalldata(batch: executions)
        }

        let op = try await account.buildSponsoredUserOperation(
            callData: callData,
            using: rpc,
            bundler: bundler,
            chainId: intent.chainId
        )
        let submission = intent.submit ? UserOperationSubmissionRequest(projectId: projectId) : nil
        return (op, submission)
    }

    nonisolated func signStructured(
        operationType: String,
        operationData: Data,
        requestID: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        let resolvedUserOperationRequest: ResolvedUserOperationRequest?
        let immediateOperation: SigningOperation?
        do {
            let decoder = JSONDecoder()
            switch operationType {
            case "message":
                guard let text = String(data: operationData, encoding: .utf8) else {
                    reply(nil, BastionError.invalidInput.nsError)
                    return
                }
                immediateOperation = .message(text)
                resolvedUserOperationRequest = nil
            case "typedData":
                let typed = try decoder.decode(EIP712TypedData.self, from: operationData)
                immediateOperation = .typedData(typed)
                resolvedUserOperationRequest = nil
            case "userOperation":
                if let envelope = try? decoder.decode(UserOperationIntentRequestEnvelope.self, from: operationData) {
                    resolvedUserOperationRequest = .intent(envelope)
                    immediateOperation = nil
                } else if let envelope = try? decoder.decode(UserOperationRequestEnvelope.self, from: operationData) {
                    resolvedUserOperationRequest = .direct(envelope.userOperation, envelope.submission)
                    immediateOperation = nil
                } else {
                    let op = try decoder.decode(UserOperation.self, from: operationData)
                    resolvedUserOperationRequest = .direct(op, nil)
                    immediateOperation = nil
                }
            default:
                reply(nil, BastionError.invalidInput.nsError)
                return
            }
        } catch {
            reply(nil, BastionError.invalidInput.nsError)
            return
        }

        Task { @MainActor in
            do {
                let operation: SigningOperation
                let userOperationSubmission: UserOperationSubmissionRequest?
                if let immediateOperation {
                    operation = immediateOperation
                    userOperationSubmission = nil
                } else {
                    guard let resolvedUserOperationRequest else {
                        throw BastionError.invalidInput
                    }
                    switch resolvedUserOperationRequest {
                    case .direct(let userOperation, let submission):
                        operation = .userOperation(userOperation)
                        userOperationSubmission = try self.resolvedSubmissionRequest(submission)
                    case .intent(let intent):
                        let built = try await self.buildUserOperation(from: intent)
                        operation = .userOperation(built.0)
                        userOperationSubmission = built.1
                    }
                }

                let request = SignRequest(
                    operation: operation,
                    requestID: requestID,
                    timestamp: Date(),
                    clientBundleId: self.clientBundleId,
                    userOperationSubmission: userOperationSubmission
                )
                let result = try await signingManager.processSignRequest(request)
                let jsonData = try JSONEncoder().encode(result)
                reply(jsonData, nil)
            } catch let error as BastionError {
                reply(nil, error.nsError)
            } catch {
                reply(nil, error)
            }
        }
    }
}
